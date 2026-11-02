//! Substrate 4: **VM (vsock).** Two variants, both driving the SAME request/response exchange
//! (`wire::client_exchange`/`server_loop`) as byte-relay/container, so only the transport
//! differs:
//!
//! - **4a `vsock-loopback`**: a real `AF_VSOCK` round trip between two host processes via the
//!   kernel's `vsock_loopback` transport (`VMADDR_CID_LOCAL`) — no hypervisor involved. This is
//!   the task spec's sanctioned LOWER BOUND when a real guest isn't stood up: it proves the
//!   `AF_VSOCK` syscall path itself is real and measured, but excludes any hypervisor-exit cost.
//! - **4b `vsock-firecracker`**: a REAL firecracker microVM, booted directly from a kernel +
//!   initramfs (no root block device — the guest's `/init` IS `privsep-vsock-guest`, chain-exec'd
//!   via `rdinit=/init`), with a `vsock` device. The host dials it through firecracker's own
//!   Unix-domain-socket vsock bridge (`CONNECT <port>\n` handshake — see `docs/vsock.md` in the
//!   firecracker repo), then the connection is a plain byte stream carrying the exact same
//!   exchange protocol. Needs `--fc-bin`/`--fc-kernel`/`--fc-initramfs`; if any is missing this
//!   substrate reports N/A rather than guessing at paths.

use std::io;
use std::os::fd::{IntoRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::exchange_runner::{self, ExchangeOutcome};
use crate::vsock_raw;
use crate::wire;

// ---- 4a: host<->host AF_VSOCK loopback ----

pub fn run_loopback(
    current_exe: &Path,
    head: &[u8],
    response_len: usize,
    warm_iterations: usize,
    cold_iterations: usize,
    core_backend: Option<usize>,
    port_base: u32,
) -> io::Result<ExchangeOutcome> {
    let mut next_port = port_base;
    let connect = move || -> io::Result<(Child, RawFd)> {
        let port = next_port;
        next_port += 1;
        let mut cmd = Command::new(current_exe);
        cmd.args([
            "_worker",
            "vsock-loopback-backend",
            "--port",
            &port.to_string(),
        ]);
        if let Some(core) = core_backend {
            cmd.env("PRIVSEP_BENCH_PIN_CORE", core.to_string());
        }
        let child = cmd.spawn()?;

        let fd = vsock_raw::socket_vsock()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match vsock_raw::connect_vsock(fd, vsock_raw::VMADDR_CID_LOCAL, port) {
                Ok(()) => break,
                Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(2)),
                Err(e) => return Err(e),
            }
        }
        Ok((child, fd))
    };
    exchange_runner::measure(
        connect,
        head,
        response_len,
        warm_iterations,
        cold_iterations,
    )
}

// ---- 4b: real firecracker guest over vsock ----

#[derive(Clone, Debug)]
pub struct FirecrackerConfig {
    pub firecracker_bin: PathBuf,
    pub kernel: PathBuf,
    pub initramfs: PathBuf,
    pub guest_cid: u32,
    pub guest_port: u32,
    pub vcpus: u8,
    pub mem_mib: u32,
    pub work_dir: PathBuf,
}

struct FirecrackerVm {
    child: Child,
    uds_path: PathBuf,
}

fn boot_firecracker(cfg: &FirecrackerConfig, idx: usize) -> io::Result<FirecrackerVm> {
    let work = cfg.work_dir.join(format!("vm-{idx}"));
    std::fs::create_dir_all(&work)?;
    let uds_path = work.join("vsock.sock");
    let api_sock = work.join("api.sock");
    let config_path = work.join("config.json");
    let config = format!(
        r#"{{
  "boot-source": {{
    "kernel_image_path": "{kernel}",
    "initrd_path": "{initrd}",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off ro rdinit=/init"
  }},
  "drives": [],
  "machine-config": {{ "vcpu_count": {vcpus}, "mem_size_mib": {mem} }},
  "vsock": {{ "guest_cid": {cid}, "uds_path": "{uds}" }}
}}"#,
        kernel = cfg.kernel.display(),
        initrd = cfg.initramfs.display(),
        vcpus = cfg.vcpus,
        mem = cfg.mem_mib,
        cid = cfg.guest_cid,
        uds = uds_path.display(),
    );
    std::fs::write(&config_path, config)?;
    let child = Command::new(&cfg.firecracker_bin)
        .arg("--api-sock")
        .arg(&api_sock)
        .arg("--config-file")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !uds_path.exists() {
        if Instant::now() > deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "firecracker's vsock uds never appeared within 10s",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(FirecrackerVm { child, uds_path })
}

/// Firecracker's own host-side vsock bridge protocol (docs/vsock.md): connect to the device's
/// `uds_path`, send `CONNECT <port>\n`; on success it replies `OK <port>\n` and the connection
/// becomes a raw byte stream mirroring the guest's `AF_VSOCK` connection on that port.
fn dial_firecracker_vsock(uds_path: &Path, guest_port: u32) -> io::Result<RawFd> {
    let stream = UnixStream::connect(uds_path)?;
    let fd = stream.into_raw_fd();
    wire::write_all(fd, format!("CONNECT {guest_port}\n").as_bytes())?;
    let mut line = Vec::new();
    loop {
        let mut b = [0u8; 1];
        wire::read_exact(fd, &mut b)?;
        if b[0] == b'\n' {
            break;
        }
        line.push(b[0]);
        if line.len() > 256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "vsock CONNECT handshake line too long",
            ));
        }
    }
    if !line.starts_with(b"OK") {
        return Err(io::Error::other(format!(
            "firecracker vsock CONNECT refused: {}",
            String::from_utf8_lossy(&line)
        )));
    }
    Ok(fd)
}

pub fn run_firecracker(
    cfg: &FirecrackerConfig,
    head: &[u8],
    response_len: usize,
    warm_iterations: usize,
    cold_iterations: usize,
) -> io::Result<ExchangeOutcome> {
    std::fs::create_dir_all(&cfg.work_dir)?;
    let mut idx = 0usize;
    let connect = || -> io::Result<(Child, RawFd)> {
        idx += 1;
        let vm = boot_firecracker(cfg, idx)?;
        let deadline = Instant::now() + Duration::from_secs(10);
        let fd = loop {
            match dial_firecracker_vsock(&vm.uds_path, cfg.guest_port) {
                Ok(fd) => break fd,
                Err(_) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => return Err(e),
            }
        };
        Ok((vm.child, fd))
    };
    let outcome = exchange_runner::measure(
        connect,
        head,
        response_len,
        warm_iterations,
        cold_iterations,
    );
    let _ = std::fs::remove_dir_all(&cfg.work_dir);
    outcome
}
