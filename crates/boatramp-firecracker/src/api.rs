//! The Firecracker REST API request sequence.
//!
//! Firecracker is configured over an HTTP API on a unix domain socket: a series
//! of `PUT`s (machine-config, boot-source, drives, network interfaces) then a
//! `PUT /actions` `InstanceStart`. This module builds that ordered sequence from
//! an [`FcMachine`] (pure + unit-tested) and provides a minimal HTTP/1.1
//! transport over the socket (the live round-trip is the KVM-host seam, gated to
//! Unix).

use crate::config::FcMachine;

/// One Firecracker API request: a method, a path, and a JSON body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRequest {
    /// HTTP method (always `PUT` for the provisioning + action calls).
    pub method: &'static str,
    /// Request path (e.g. `/boot-source`, `/drives/rootfs`, `/actions`).
    pub path: String,
    /// JSON request body.
    pub body: String,
}

impl ApiRequest {
    /// A `PUT path` with a JSON `body`.
    pub fn put(path: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            method: "PUT",
            path: path.into(),
            body: body.into(),
        }
    }

    /// A `PATCH path` with a JSON `body` (used for the `/vm` state transitions).
    pub fn patch(path: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            method: "PATCH",
            path: path.into(),
            body: body.into(),
        }
    }
}

/// Serialize a value to compact JSON for an API body.
fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("FcMachine components serialize")
}

/// The ordered requests that provision and start `machine`.
///
/// Order matters: machine-config and boot-source first, then every drive and
/// network interface, then `InstanceStart`. Each body reuses the [`FcMachine`]
/// sub-structs, whose field names already match the API.
pub fn boot_sequence(machine: &FcMachine) -> Vec<ApiRequest> {
    let mut reqs = Vec::with_capacity(3 + machine.drives.len() + machine.network_interfaces.len());
    reqs.push(ApiRequest::put(
        "/machine-config",
        json(&machine.machine_config),
    ));
    reqs.push(ApiRequest::put("/boot-source", json(&machine.boot_source)));
    for drive in &machine.drives {
        reqs.push(ApiRequest::put(
            format!("/drives/{}", drive.drive_id),
            json(drive),
        ));
    }
    for iface in &machine.network_interfaces {
        reqs.push(ApiRequest::put(
            format!("/network-interfaces/{}", iface.iface_id),
            json(iface),
        ));
    }
    reqs.push(start_request());
    reqs
}

/// The `InstanceStart` action that boots a fully-provisioned VM.
pub fn start_request() -> ApiRequest {
    ApiRequest::put("/actions", r#"{"action_type":"InstanceStart"}"#)
}

/// A graceful-shutdown action (Ctrl-Alt-Del → the guest init halts). Falls back
/// to a process kill if the guest ignores it.
pub fn shutdown_request() -> ApiRequest {
    ApiRequest::put("/actions", r#"{"action_type":"SendCtrlAltDel"}"#)
}

/// Pause a running VM (`PATCH /vm` → `Paused`) — required before snapshotting so
/// the captured state is consistent.
pub fn pause_request() -> ApiRequest {
    ApiRequest::patch("/vm", r#"{"state":"Paused"}"#)
}

/// Resume a paused VM (`PATCH /vm` → `Resumed`).
pub fn resume_request() -> ApiRequest {
    ApiRequest::patch("/vm", r#"{"state":"Resumed"}"#)
}

/// Create a **full** snapshot of a *paused* VM: the device/vCPU state to
/// `snapshot_path`, the guest RAM to `mem_file_path`.
pub fn snapshot_create_request(snapshot_path: &str, mem_file_path: &str) -> ApiRequest {
    ApiRequest::put(
        "/snapshot/create",
        serde_json::json!({
            "snapshot_path": snapshot_path,
            "mem_file_path": mem_file_path,
            "snapshot_type": "Full",
        })
        .to_string(),
    )
}

/// Load a snapshot into a **fresh** (unprovisioned) VMM. `resume_vm` resumes the
/// guest immediately after loading. The snapshot carries the machine config, so
/// no boot-source/drive/iface calls precede it — only the tap must already exist
/// (same host_dev_name as when the snapshot was taken).
pub fn snapshot_load_request(
    snapshot_path: &str,
    mem_file_path: &str,
    resume_vm: bool,
) -> ApiRequest {
    ApiRequest::put(
        "/snapshot/load",
        serde_json::json!({
            "snapshot_path": snapshot_path,
            "mem_backend": { "backend_type": "File", "backend_path": mem_file_path },
            "resume_vm": resume_vm,
        })
        .to_string(),
    )
}

/// The non-disruptive snapshot sequence for a *running* VM: pause → create →
/// resume (the VM keeps serving after).
pub fn snapshot_sequence(snapshot_path: &str, mem_file_path: &str) -> Vec<ApiRequest> {
    vec![
        pause_request(),
        snapshot_create_request(snapshot_path, mem_file_path),
        resume_request(),
    ]
}

/// Send one [`ApiRequest`] over the Firecracker API unix socket at `socket`,
/// returning `Err(detail)` on a transport error or a non-2xx response. The
/// `timeout` bounds both connect and read. **Unix-only** (the API socket is a
/// `AF_UNIX` stream); the live round-trip is exercised only on a KVM host.
#[cfg(unix)]
pub fn send_over_unix_socket(
    socket: &std::path::Path,
    req: &ApiRequest,
    timeout: std::time::Duration,
) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;

    let mut stream =
        UnixStream::connect(socket).map_err(|e| format!("connect {}: {e}", socket.display()))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: localhost\r\n\
         Accept: application/json\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {len}\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        method = req.method,
        path = req.path,
        len = req.body.len(),
        body = req.body,
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write {}: {e}", req.path))?;
    stream.flush().ok();

    let mut response = Vec::new();
    // `Connection: close` makes Firecracker close after responding, so read to
    // EOF; the read timeout is the backstop.
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("read {}: {e}", req.path))?;
    check_response(&req.path, &response)
}

/// Parse the HTTP status line and accept only 2xx; otherwise surface the status
/// and any `fault_message` body Firecracker returned.
#[cfg(unix)]
fn check_response(path: &str, response: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(response);
    let status_line = text.lines().next().unwrap_or_default();
    // "HTTP/1.1 204 No Content" → the middle token is the code.
    let code: Option<u16> = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok());
    match code {
        Some(c) if (200..300).contains(&c) => Ok(()),
        Some(c) => {
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("").trim();
            Err(format!(
                "{path}: HTTP {c}{}",
                if body.is_empty() {
                    String::new()
                } else {
                    format!(" — {body}")
                }
            ))
        }
        None => Err(format!("{path}: unparsable response: {status_line:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::MachineResources;
    use boatramp_types::compute::{ComputeSpec, RestartPolicy};
    use std::collections::BTreeMap;

    fn machine() -> FcMachine {
        let spec = ComputeSpec {
            version: 1,
            rootfs: "r".repeat(64),
            kernel: "k".repeat(64),
            kernel_cmdline: None,
            vcpus: 2,
            mem_mib: 512,
            entrypoint: vec!["/app".into()],
            env: BTreeMap::new(),
            port: 8080,
            restart: RestartPolicy::Always,
            scale_to_zero: false,
            volumes: vec![],
            isolation: boatramp_types::compute::IsolationRequirement::Trusted,
            prefer_backend: None,
        };
        let resources = MachineResources {
            kernel_path: "/k/vmlinux".into(),
            rootfs_path: "/r/app.ext4".into(),
            scratch_path: "/s/vm1.ext4".into(),
            tap_name: "tap-vm1".into(),
            guest_mac: "02:00:0a:00:00:05".into(),
            guest_ip: "10.0.0.5".into(),
        };
        FcMachine::from_spec(&spec, &resources)
    }

    #[test]
    fn boot_sequence_is_ordered_config_drives_ifaces_then_start() {
        let reqs = boot_sequence(&machine());
        let paths: Vec<&str> = reqs.iter().map(|r| r.path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                "/machine-config",
                "/boot-source",
                "/drives/rootfs",
                "/drives/scratch",
                "/network-interfaces/eth0",
                "/actions",
            ]
        );
        assert!(reqs.iter().all(|r| r.method == "PUT"));
        // The final action is InstanceStart.
        assert!(reqs.last().unwrap().body.contains("InstanceStart"));
    }

    #[test]
    fn request_bodies_carry_the_firecracker_fields() {
        let reqs = boot_sequence(&machine());
        let by_path = |p: &str| reqs.iter().find(|r| r.path == p).unwrap();
        assert!(by_path("/machine-config").body.contains("\"vcpu_count\":2"));
        assert!(by_path("/boot-source").body.contains("kernel_image_path"));
        assert!(by_path("/drives/rootfs")
            .body
            .contains("\"is_root_device\":true"));
        assert!(by_path("/network-interfaces/eth0")
            .body
            .contains("host_dev_name"));
    }

    #[test]
    fn shutdown_is_ctrl_alt_del() {
        assert_eq!(shutdown_request().path, "/actions");
        assert!(shutdown_request().body.contains("SendCtrlAltDel"));
    }

    #[test]
    fn pause_resume_are_vm_state_patches() {
        let p = pause_request();
        assert_eq!((p.method, p.path.as_str()), ("PATCH", "/vm"));
        assert!(p.body.contains("Paused"));
        let r = resume_request();
        assert_eq!((r.method, r.path.as_str()), ("PATCH", "/vm"));
        assert!(r.body.contains("Resumed"));
    }

    #[test]
    fn snapshot_create_carries_paths_and_full_type() {
        let req = snapshot_create_request("/s/web-0.snap", "/s/web-0.mem");
        assert_eq!((req.method, req.path.as_str()), ("PUT", "/snapshot/create"));
        assert!(req.body.contains("\"snapshot_path\":\"/s/web-0.snap\""));
        assert!(req.body.contains("\"mem_file_path\":\"/s/web-0.mem\""));
        assert!(req.body.contains("\"snapshot_type\":\"Full\""));
        // Valid JSON.
        serde_json::from_str::<serde_json::Value>(&req.body).unwrap();
    }

    #[test]
    fn snapshot_load_uses_mem_backend_and_resume_flag() {
        let req = snapshot_load_request("/s/web-0.snap", "/s/web-0.mem", true);
        assert_eq!((req.method, req.path.as_str()), ("PUT", "/snapshot/load"));
        let v: serde_json::Value = serde_json::from_str(&req.body).unwrap();
        assert_eq!(v["snapshot_path"], "/s/web-0.snap");
        assert_eq!(v["mem_backend"]["backend_type"], "File");
        assert_eq!(v["mem_backend"]["backend_path"], "/s/web-0.mem");
        assert_eq!(v["resume_vm"], true);
    }

    #[test]
    fn snapshot_sequence_pauses_creates_then_resumes() {
        let seq = snapshot_sequence("/s/a.snap", "/s/a.mem");
        let kinds: Vec<(&str, &str)> = seq.iter().map(|r| (r.method, r.path.as_str())).collect();
        assert_eq!(
            kinds,
            vec![
                ("PATCH", "/vm"), // pause
                ("PUT", "/snapshot/create"),
                ("PATCH", "/vm"), // resume
            ]
        );
        assert!(seq[0].body.contains("Paused"));
        assert!(seq[2].body.contains("Resumed"));
    }

    #[cfg(unix)]
    #[test]
    fn check_response_accepts_2xx_rejects_others() {
        assert!(check_response("/x", b"HTTP/1.1 204 No Content\r\n\r\n").is_ok());
        assert!(check_response("/x", b"HTTP/1.1 200 OK\r\n\r\n").is_ok());
        let err = check_response(
            "/boot-source",
            b"HTTP/1.1 400 Bad Request\r\n\r\n{\"fault_message\":\"bad kernel\"}",
        )
        .unwrap_err();
        assert!(err.contains("400"));
        assert!(err.contains("bad kernel"));
    }
}
