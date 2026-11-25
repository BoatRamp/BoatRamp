//! The self-jail **sandbox plan**.
//!
//! A fully-resolved, serializable description of one container's jail: the
//! rootfs to `pivot_root` into, the namespaces to unshare, the mounts to set up,
//! the cgroup v2 limits, the dropped uid/gid, and the entrypoint to `execve`.
//! Building it from a [`ComputeSpec`] is pure + unit-tested; **applying** it (the
//! real `unshare`/`mount`/`pivot_root`/seccomp syscalls) is the Linux worker.
//! The plan is `serde`-serializable so it can be handed to the re-exec'd
//! `boatramp __sandbox` worker as JSON.

use boatramp_types::compute::ComputeSpec;
use serde::{Deserialize, Serialize};

/// A persistent volume bind-mounted into the container. Applied **before**
/// `pivot_root` (the host `source` lives outside the rootfs, so it must be bound
/// in while the host tree is still reachable; after the pivot it appears at
/// `mount`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeMount {
    /// Host path to the volume's backing directory.
    pub source: String,
    /// Absolute in-guest mount point.
    pub mount: String,
}

/// A mount set up inside the sandbox before `pivot_root`/exec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mount {
    /// Source (device/fs name for virtual fs, or host path for a bind).
    pub source: String,
    /// In-sandbox target path.
    pub target: String,
    /// Filesystem type (`proc`, `sysfs`, `tmpfs`, or `bind`).
    pub fstype: String,
    /// Mount flags (`ro`, `nosuid`, `nodev`, `noexec`, …).
    pub flags: Vec<String>,
}

impl Mount {
    fn virt(source: &str, target: &str, fstype: &str, flags: &[&str]) -> Self {
        Self {
            source: source.to_string(),
            target: target.to_string(),
            fstype: fstype.to_string(),
            flags: flags.iter().map(std::string::ToString::to_string).collect(),
        }
    }
}

/// cgroup v2 resource limits for the container's cgroup.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CgroupLimits {
    /// `cpu.max` value (`"<quota_us> <period_us>"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_max: Option<String>,
    /// `memory.max` in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_max_bytes: Option<u64>,
    /// `pids.max` (fork-bomb guard).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids_max: Option<u64>,
}

/// The Linux namespaces to unshare for the sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Namespaces {
    /// Mount namespace (always — required for `pivot_root`).
    pub mount: bool,
    /// PID namespace (the container's processes are isolated; its init is PID 1).
    pub pid: bool,
    /// Network namespace (its own veth `eth0`).
    pub net: bool,
    /// UTS namespace (its own hostname).
    pub uts: bool,
    /// IPC namespace.
    pub ipc: bool,
    /// User namespace (uid/gid remap). **On by default**: the
    /// container's ids are mapped onto an unprivileged host range, so even
    /// in-container `root` (uid 0) is an ordinary unprivileged user on the host.
    pub user: bool,
}

impl Default for Namespaces {
    fn default() -> Self {
        Self {
            mount: true,
            pid: true,
            net: true,
            uts: true,
            ipc: true,
            user: true,
        }
    }
}

/// A fully-resolved plan to run one container in a self-jailing sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxPlan {
    /// Host path to the unpacked rootfs to `pivot_root` into.
    pub root: String,
    /// The container's hostname (UTS namespace).
    pub hostname: String,
    /// uid the entrypoint drops to.
    pub uid: u32,
    /// gid the entrypoint drops to.
    pub gid: u32,
    /// The entrypoint argv to `execve`.
    pub argv: Vec<String>,
    /// Environment for the entrypoint (`KEY`, `VALUE`).
    pub env: Vec<(String, String)>,
    /// Mounts to set up inside the sandbox.
    pub mounts: Vec<Mount>,
    /// Persistent volumes bind-mounted in before `pivot_root` (populated by the
    /// backend, which knows each volume's host backing dir).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<VolumeMount>,
    /// cgroup v2 limits.
    pub cgroup: CgroupLimits,
    /// Linux capabilities to retain on top of the dropped-`ALL` default (short names,
    /// no `CAP_` prefix, e.g. `"CHOWN"`). Populated by the backend after the
    /// single-tenant posture gate; empty ⇒ drop every capability (the default). Because
    /// the worker runs in a user namespace, a retained capability is bounded by that
    /// namespace.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cap_add: Vec<String>,
    /// The allowed-syscall seccomp profile (default-deny: everything not listed
    /// is denied). [`for_spec`](SandboxPlan::for_spec) populates it from
    /// [`seccomp::default_allowlist`](crate::seccomp::default_allowlist); the
    /// worker compiles it to BPF and installs it before `execve`. `None` ⇒ no
    /// filter installed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp_allow: Option<Vec<String>>,
    /// **One-shot ephemeral mode only** — a raw file descriptor the launcher has
    /// already arranged for this worker to inherit, which the worker `dup2`s onto the
    /// guest's standard input (fd 0) immediately before `execve`. `None` (the normal
    /// launch) leaves the guest's fd 0 as whatever the worker inherited (the EOF'd
    /// launcher handshake pipe), exactly as before — so the launch path is byte-for-byte
    /// unchanged and the schema stays v1.
    ///
    /// It exists so [`ContainerBackend::run_ephemeral`](crate::backend::ContainerBackend)
    /// can stream a multi-gigabyte `pg_restore`/`mysql` payload into the guest over a
    /// **dedicated** pipe that is decoupled from the launcher↔worker handshake (which
    /// uses the worker's own fd 0 for the `plan`/`go` lines). Routing the payload over
    /// the handshake fd instead would race the worker's `read_line("go")` buffered read,
    /// which could swallow the first chunk of the payload — silent dump corruption. A
    /// dedicated inherited fd removes that race entirely. The fd number is meaningful
    /// only inside the worker process that inherited it; it is never a host path or a
    /// credential. Ignored unless this plan is run by the ephemeral path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exec_stdin_fd: Option<i32>,
    /// Remount the pivoted container **root filesystem read-only** just before dropping
    /// privileges (the standard-mount `/proc`·`/sys`·`/tmp`·`/run`·`/dev` are separate
    /// mounts set up first, so they stay as configured — a writable `/tmp` + `/run`
    /// remain). `false` (the default, every launched workload) leaves the rootfs writable
    /// and is omitted from the serialized plan, so the launch path is byte-identical.
    ///
    /// Set `true` by [`ContainerBackend::run_ephemeral`](crate::backend::ContainerBackend)
    /// for a one-shot client: the client never needs to write its rootfs (dumps go to the
    /// streamed stdout, scratch to `/tmp`), and a one-shot pivots into the SHARED, cached
    /// staged-image directory that sibling ephemeral runs reuse — a read-only root keeps a
    /// buggy or hostile client from mutating that shared cache, matching the docker
    /// backend's `readonly_rootfs` hardening.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub readonly_root: bool,
    /// The working directory to `chdir` into just before `execve` (the image's OCI
    /// `WorkingDir`). Empty (the default, every launched workload) leaves the cwd at the
    /// pivoted root `/` and is omitted from the serialized plan, so the launch path is
    /// byte-identical. Set by [`ContainerBackend::run_ephemeral`](crate::backend::ContainerBackend)
    /// from the pulled image's config so a one-shot client starts where the image expects;
    /// honored best-effort (a missing dir does not fail the run).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub workdir: String,
    /// The `/etc/resolv.conf` body to write into the jail (after `pivot_root`, into
    /// the container rootfs) so the guest resolves through boatramp's internal DNS on
    /// the bridge gateway. Populated by the backend from the container's project +
    /// the gateway (see [`crate::resolvconf::render`]). Written **per-container** by
    /// the worker (not into the shared staged rootfs, which several projects' same
    /// image reuse), so each container gets its own project's `search` domain. `None`
    /// ⇒ leave whatever the image shipped (the internal-DNS feature disabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolv_conf: Option<String>,
    /// Namespaces to unshare.
    pub namespaces: Namespaces,
}

/// cgroup v2 `cpu.max` quota period (microseconds).
const CPU_PERIOD_US: u32 = 100_000;
/// Default fork/pid cap (fork-bomb guard).
const DEFAULT_PIDS_MAX: u64 = 1024;

impl SandboxPlan {
    /// Build the plan for `spec`, rooted at the unpacked `root` rootfs, with
    /// `hostname`, dropping to `uid`/`gid`. Standard container mounts (`/proc`,
    /// `/sys` ro, `/dev` + `/tmp` tmpfs), cgroup limits derived from the spec's
    /// vCPU/memory ask, and the default namespace set.
    pub fn for_spec(
        spec: &ComputeSpec,
        root: impl Into<String>,
        hostname: impl Into<String>,
        uid: u32,
        gid: u32,
    ) -> Self {
        let mut mounts = vec![
            Mount::virt("proc", "/proc", "proc", &["nosuid", "nodev", "noexec"]),
            Mount::virt(
                "sysfs",
                "/sys",
                "sysfs",
                &["nosuid", "nodev", "noexec", "ro"],
            ),
            Mount::virt("tmpfs", "/dev", "tmpfs", &["nosuid", "mode=0755"]),
            Mount::virt("tmpfs", "/tmp", "tmpfs", &["nosuid", "nodev"]),
            // `/run` (sticky, world-writable like `/tmp`) so a stock image can create
            // its runtime dir — e.g. Postgres makes `/run/postgresql` for its unix
            // socket during init. Without it, a rootless entrypoint can't write `/run`
            // and init fails. Mirrors the docker backend's `mode=1777` `/run` tmpfs.
            Mount::virt("tmpfs", "/run", "tmpfs", &["nosuid", "nodev", "mode=1777"]),
        ];
        // Declared per-workload **ephemeral** mounts: a sized `tmpfs` at each requested path
        // (e.g. `/cache`), so a workload gets a writable scratch/cache dir on the hardened
        // read-only root WITHOUT a persistent volume. Added AFTER the standard mounts and as
        // their own tmpfs mounts, so — exactly like `/tmp` — they stay writable even when the
        // backend remounts the container root read-only. The worker `create_dir_all`s each
        // target before mounting, so an arbitrary path works. Each is `nosuid,nodev` + a
        // `size=<N>m` cap (the tmpfs limit); `size_mib` is validated at set time
        // (`ComputeSpec::validate_ephemeral_mounts`) so it is always bounded here. Honored
        // under ANY isolation posture — a per-workload, size-capped tmpfs in the workload's own
        // mount namespace is multi-tenant-SAFE (unlike `writable_root`, which the backend
        // strips under the multi-tenant guard).
        for em in &spec.ephemeral_mounts {
            let size_opt = format!("size={}m", em.size_mib.max(1));
            mounts.push(Mount::virt(
                "tmpfs",
                &em.mount,
                "tmpfs",
                &["nosuid", "nodev", &size_opt],
            ));
        }
        let cgroup = CgroupLimits {
            cpu_max: Some(format!(
                "{} {CPU_PERIOD_US}",
                spec.vcpus.max(1) * CPU_PERIOD_US
            )),
            memory_max_bytes: Some(u64::from(spec.mem_mib.max(1)) * 1024 * 1024),
            pids_max: Some(DEFAULT_PIDS_MAX),
        };
        Self {
            root: root.into(),
            hostname: hostname.into(),
            uid,
            gid,
            argv: spec.entrypoint.clone(),
            env: spec
                .env
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            mounts,
            volumes: Vec::new(),
            cgroup,
            cap_add: Vec::new(),
            seccomp_allow: Some(crate::seccomp::default_allowlist()),
            exec_stdin_fd: None,
            readonly_root: false,
            workdir: String::new(),
            resolv_conf: None,
            namespaces: Namespaces::default(),
        }
    }

    /// Overlay an image's OCI runtime config (`Env` + `WorkingDir`) onto this plan —
    /// the SINGLE shared seam the long-running **launch** AND the one-shot **ephemeral**
    /// paths both call, so the guest sees the image's `PATH`/env + cwd on BOTH (U24
    /// parity; before this the launch path dropped the image `Env`/`WorkingDir` entirely,
    /// so a bare entrypoint had no image `PATH` and the image cwd was ignored).
    ///
    /// The image `Env` is the BASE (notably `PATH`); the plan's EXISTING env (seeded from
    /// the spec / the ephemeral caller — e.g. `PG*`/`MYSQL*` connection vars, operator
    /// overrides) WINS on a key conflict. `WorkingDir` is applied only when the plan has
    /// none set, so an explicit spec workdir wins. A malformed image env entry (no `=`) is
    /// skipped. `image_env` empty AND `image_workdir` empty ⇒ a no-op (a tar/rootfs source
    /// or a default/empty image config leaves behavior exactly as before).
    pub fn apply_image_config(&mut self, image_env: &[String], image_workdir: &str) {
        if !image_env.is_empty() {
            // Build the image base, de-duplicating repeated keys (keep the FIRST occurrence —
            // `getenv` semantics) so a malformed image `Env` with two `PATH=` entries can't leave
            // a shadow key a guest iterating `environ` would see after the spec overwrites only the
            // first (INFO-1). The spec/caller env then overlays and WINS per key.
            let mut merged: Vec<(String, String)> = Vec::with_capacity(image_env.len());
            for kv in image_env {
                if let Some((k, v)) = kv.split_once('=')
                    && !merged.iter().any(|(ek, _)| ek == k)
                {
                    merged.push((k.to_string(), v.to_string()));
                }
            }
            for (k, v) in &self.env {
                match merged.iter_mut().find(|(ek, _)| ek == k) {
                    Some(slot) => slot.1 = v.clone(),
                    None => merged.push((k.clone(), v.clone())),
                }
            }
            self.env = merged;
        }
        if self.workdir.is_empty() && !image_workdir.is_empty() {
            self.workdir = image_workdir.to_string();
        }
    }
}

/// The OCI runtime-spec default `PATH` — the search path for a bare (non-absolute)
/// container entrypoint when the image config's `Env` carries no `PATH`. Matches the
/// `runtime-spec` default so resolution agrees with a conformant OCI runtime.
pub const DEFAULT_OCI_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Resolve a container entrypoint `argv0` to an absolute (or verbatim) path, searching
/// the **container's** `PATH` (`path_env`) when `argv0` is a bare name — NOT the host
/// worker process's `PATH`.
///
/// This exists because glibc `execvpe(file, argv, envp)` performs its `PATH` search over
/// the CALLER's environment (`getenv("PATH")`), **ignoring the `PATH` in `envp`** — so a
/// bare entrypoint (`sh`, `pg_dump`) resolved against the worker's host `PATH` fails on a
/// host (e.g. NixOS) whose `PATH` does not contain `/bin` (U23). We do the search
/// ourselves over `path_env` (the image/spec `PATH`, falling back to [`DEFAULT_OCI_PATH`]
/// when empty) and the worker then `execve`s the resolved path (no glibc `PATH` search).
///
/// `argv0` containing a `/` is returned verbatim (absolute or cwd-relative — no search),
/// exactly as `execve` treats it. `exists` probes whether a candidate is a runnable file
/// IN THE CONTAINER filesystem (the worker calls this AFTER `pivot_root`, so the paths are
/// container paths). Returns `None` when a bare name is on no `PATH` entry.
pub fn resolve_entrypoint(
    argv0: &str,
    path_env: &str,
    exists: impl Fn(&std::path::Path) -> bool,
) -> Option<std::path::PathBuf> {
    use std::path::{Path, PathBuf};
    if argv0.is_empty() {
        return None;
    }
    if argv0.contains('/') {
        // Already a path — used verbatim, no PATH search (matches `execve`).
        return Some(PathBuf::from(argv0));
    }
    let path = if path_env.is_empty() {
        DEFAULT_OCI_PATH
    } else {
        path_env
    };
    for dir in path.split(':') {
        // POSIX: an empty PATH element means the current directory.
        let base: &Path = if dir.is_empty() {
            Path::new(".")
        } else {
            Path::new(dir)
        };
        let candidate = base.join(argv0);
        if exists(&candidate) {
            return Some(candidate);
        }
    }
    None
}

/// Probe for [`resolve_entrypoint`]: is `p` a runnable (regular, any execute bit) file?
/// Follows symlinks (a `PATH` entry is often a symlink to the real binary). The worker's
/// concrete probe; the pure resolver is tested with an in-memory probe.
#[cfg(unix)]
pub fn is_executable_file(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_types::compute::RootSource;
    use std::collections::BTreeMap;

    fn spec(vcpus: u32, mem_mib: u32) -> ComputeSpec {
        ComputeSpec::builder(RootSource::Tar("r".repeat(64)), vcpus, mem_mib, 8080)
            .kernel("k".repeat(64))
            .entrypoint(vec!["/app".into(), "--serve".into()])
            .env(BTreeMap::from([("PORT".to_string(), "8080".to_string())]))
            .build()
    }

    #[test]
    fn carries_entrypoint_env_root_and_hostname() {
        let plan = SandboxPlan::for_spec(&spec(2, 512), "/run/c/web-0/rootfs", "web-0", 1000, 1000);
        assert_eq!(plan.argv, vec!["/app".to_string(), "--serve".to_string()]);
        assert_eq!(plan.env, vec![("PORT".to_string(), "8080".to_string())]);
        assert_eq!(plan.root, "/run/c/web-0/rootfs");
        assert_eq!(plan.hostname, "web-0");
        assert_eq!((plan.uid, plan.gid), (1000, 1000));
    }

    #[test]
    fn cap_add_defaults_empty_and_the_backend_fills_it() {
        // `for_spec` never grants capabilities itself — the backend sets `cap_add`
        // after the single-tenant posture gate.
        let mut plan = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0);
        assert!(plan.cap_add.is_empty());
        plan.cap_add = vec!["CHOWN".into(), "SETUID".into()];
        assert_eq!(
            plan.cap_add,
            vec!["CHOWN".to_string(), "SETUID".to_string()]
        );
    }

    #[test]
    fn cgroup_limits_track_the_spec() {
        let plan = SandboxPlan::for_spec(&spec(4, 256), "/r", "h", 0, 0);
        // 4 vCPUs → quota 4×period.
        assert_eq!(plan.cgroup.cpu_max.as_deref(), Some("400000 100000"));
        assert_eq!(plan.cgroup.memory_max_bytes, Some(256 * 1024 * 1024));
        assert_eq!(plan.cgroup.pids_max, Some(1024));
    }

    #[test]
    fn cpu_and_mem_floored_at_one() {
        let plan = SandboxPlan::for_spec(&spec(0, 0), "/r", "h", 0, 0);
        assert_eq!(plan.cgroup.cpu_max.as_deref(), Some("100000 100000"));
        assert_eq!(plan.cgroup.memory_max_bytes, Some(1024 * 1024));
    }

    #[test]
    fn standard_mounts_are_present_and_sys_is_readonly() {
        let plan = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0);
        let proc = plan.mounts.iter().find(|m| m.target == "/proc").unwrap();
        assert_eq!(proc.fstype, "proc");
        assert!(proc.flags.contains(&"noexec".to_string()));
        let sys = plan.mounts.iter().find(|m| m.target == "/sys").unwrap();
        assert!(sys.flags.contains(&"ro".to_string()), "/sys is read-only");
        assert!(
            plan.mounts
                .iter()
                .any(|m| m.target == "/tmp" && m.fstype == "tmpfs")
        );
        assert!(plan.mounts.iter().any(|m| m.target == "/dev"));
        // `/run` is a sticky, world-writable tmpfs so a stock image (e.g. Postgres
        // creating `/run/postgresql`) can write its runtime dir under a rootless uid.
        let run = plan
            .mounts
            .iter()
            .find(|m| m.target == "/run")
            .expect("/run tmpfs is mounted");
        assert_eq!(run.fstype, "tmpfs");
        assert!(
            run.flags.iter().any(|f| f == "mode=1777"),
            "/run is world-writable + sticky (mode=1777)"
        );
    }

    #[test]
    fn default_namespaces_isolate_including_user() {
        let ns = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0).namespaces;
        assert!(ns.mount && ns.pid && ns.net && ns.uts && ns.ipc);
        assert!(
            ns.user,
            "user namespace is on by default — in-container root is unprivileged on the host"
        );
    }

    #[test]
    fn plan_is_serde_round_trippable() {
        // The worker receives the plan as JSON, so it must round-trip.
        let plan = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0);
        let json = serde_json::to_string(&plan).unwrap();
        assert_eq!(serde_json::from_str::<SandboxPlan>(&json).unwrap(), plan);
    }

    #[test]
    fn for_spec_installs_the_default_seccomp_allowlist() {
        let plan = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0);
        let allow = plan.seccomp_allow.expect("default profile present");
        assert_eq!(allow, crate::seccomp::default_allowlist());
        assert!(allow.iter().any(|s| s == "execve"));
        for danger in crate::seccomp::DANGEROUS_DENIED {
            assert!(!allow.iter().any(|s| s == danger), "denies {danger}");
        }
    }

    #[test]
    fn exec_stdin_fd_defaults_none_and_is_omitted_then_round_trips() {
        // The normal launch leaves it None, and None is NOT serialized — so the launch
        // path's plan JSON is byte-identical to before (schema stays v1).
        let mut plan = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0);
        assert_eq!(plan.exec_stdin_fd, None);
        // Default: a writable rootfs, and both one-shot fields omitted — so the launch
        // path's plan JSON is byte-identical to before (schema stays v1).
        assert!(!plan.readonly_root);
        assert!(plan.workdir.is_empty());
        let json = serde_json::to_string(&plan).unwrap();
        assert!(
            !json.contains("exec_stdin_fd")
                && !json.contains("readonly_root")
                && !json.contains("workdir"),
            "the one-shot fields must be omitted at their defaults: {json}"
        );
        // The one-shot ephemeral path sets them; they then round-trip through the worker.
        plan.exec_stdin_fd = Some(7);
        plan.readonly_root = true;
        plan.workdir = "/var/lib/postgresql".to_string();
        let json = serde_json::to_string(&plan).unwrap();
        assert!(json.contains("\"exec_stdin_fd\":7"));
        assert!(json.contains("\"readonly_root\":true"));
        assert!(json.contains("\"workdir\":\"/var/lib/postgresql\""));
        let back = serde_json::from_str::<SandboxPlan>(&json).unwrap();
        assert_eq!(back.exec_stdin_fd, Some(7));
        assert!(back.readonly_root);
        assert_eq!(back.workdir, "/var/lib/postgresql");
    }

    #[test]
    fn volumes_default_empty_and_round_trip_in_the_plan() {
        let mut plan = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0);
        assert!(plan.volumes.is_empty(), "no volumes by default");
        plan.volumes.push(VolumeMount {
            source: "/srv/data/db".into(),
            mount: "/data".into(),
        });
        let json = serde_json::to_string(&plan).unwrap();
        assert!(
            json.contains("\"volumes\""),
            "volumes serialized when present"
        );
        let back: SandboxPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(back, plan);
        assert_eq!(back.volumes[0].mount, "/data");
    }

    #[test]
    fn ephemeral_mounts_become_sized_tmpfs_mounts_and_survive_a_readonly_root() {
        use boatramp_types::compute::EphemeralMount;
        let mut s = spec(1, 128);
        s.ephemeral_mounts = vec![
            EphemeralMount::new("/cache", 128),
            EphemeralMount::new("/var/scratch", 64),
        ];
        let plan = SandboxPlan::for_spec(&s, "/r", "h", 1000, 1000);
        let cache = plan
            .mounts
            .iter()
            .find(|m| m.target == "/cache")
            .expect("ephemeral /cache is a mount");
        assert_eq!(cache.fstype, "tmpfs");
        assert_eq!(cache.source, "tmpfs");
        assert!(cache.flags.iter().any(|f| f == "nosuid"));
        assert!(cache.flags.iter().any(|f| f == "nodev"));
        assert!(
            cache.flags.iter().any(|f| f == "size=128m"),
            "the tmpfs carries its size cap: {:?}",
            cache.flags
        );
        let scratch = plan
            .mounts
            .iter()
            .find(|m| m.target == "/var/scratch")
            .expect("ephemeral /var/scratch is a mount");
        assert!(scratch.flags.iter().any(|f| f == "size=64m"));
        // They are declared AFTER the standard mounts, so they are set up as their own
        // writable tmpfs — like `/tmp`, they outlive a read-only-root remount of `/`.
        let std_count = plan
            .mounts
            .iter()
            .filter(|m| ["/proc", "/sys", "/dev", "/tmp", "/run"].contains(&m.target.as_str()))
            .count();
        assert_eq!(std_count, 5, "the five standard mounts are still present");
        // No ephemeral mounts ⇒ only the standard five.
        let bare = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0);
        assert_eq!(bare.mounts.len(), 5, "no ephemeral mounts by default");
    }

    // ---- U23: resolve a bare entrypoint against the CONTAINER's PATH ----

    /// A probe standing in for the container filesystem: only the listed paths "exist".
    fn present(paths: &[&str]) -> impl Fn(&std::path::Path) -> bool {
        let owned: Vec<std::path::PathBuf> = paths.iter().map(std::path::PathBuf::from).collect();
        move |p| owned.iter().any(|x| x == p)
    }

    #[test]
    fn bare_entrypoint_resolves_against_the_container_path_not_the_host() {
        // The image/spec PATH places `sh` in `/bin`; the resolver must find `/bin/sh`
        // from THIS path, never the worker's host PATH (which `execvpe`'s getenv would
        // use — the U23 bug on a NixOS host where `sh` is not on the host PATH).
        let container_path = "/usr/local/bin:/usr/bin:/bin";
        let got = resolve_entrypoint("sh", container_path, present(&["/bin/sh"]));
        assert_eq!(got, Some(std::path::PathBuf::from("/bin/sh")));

        // Earlier PATH entries win: `psql` present under the image's own non-default dir.
        let image_path = "/usr/lib/postgresql/16/bin:/usr/bin:/bin";
        let got = resolve_entrypoint(
            "psql",
            image_path,
            present(&["/usr/lib/postgresql/16/bin/psql", "/usr/bin/psql"]),
        );
        assert_eq!(
            got,
            Some(std::path::PathBuf::from("/usr/lib/postgresql/16/bin/psql")),
            "the first matching PATH entry wins"
        );
    }

    #[test]
    fn absent_path_env_falls_back_to_the_oci_default() {
        // No PATH in the (image/spec) env ⇒ search the OCI runtime-spec default, so a bare
        // `sh` is still found at `/bin/sh` even on a host whose own PATH lacks `/bin`.
        let got = resolve_entrypoint("sh", "", present(&["/bin/sh"]));
        assert_eq!(got, Some(std::path::PathBuf::from("/bin/sh")));
        assert!(DEFAULT_OCI_PATH.split(':').any(|d| d == "/bin"));
    }

    #[test]
    fn slash_entrypoint_is_used_verbatim_with_no_search() {
        // An absolute (or cwd-relative) argv0 is returned verbatim — no PATH search, and
        // the probe is never consulted (so an existing-but-irrelevant PATH can't shadow it).
        let never = |_: &std::path::Path| panic!("must not probe a slash entrypoint");
        assert_eq!(
            resolve_entrypoint("/usr/local/bin/app", "/bin", never),
            Some(std::path::PathBuf::from("/usr/local/bin/app"))
        );
        assert_eq!(
            resolve_entrypoint("./run.sh", "/bin", never),
            Some(std::path::PathBuf::from("./run.sh"))
        );
    }

    #[test]
    fn bare_entrypoint_absent_everywhere_is_unresolved() {
        assert_eq!(
            resolve_entrypoint("nope", "/usr/bin:/bin", present(&[])),
            None
        );
        assert_eq!(resolve_entrypoint("", "/bin", present(&["/bin/"])), None);
    }

    // ---- U24: the image config's Env/WorkingDir apply on BOTH plan paths ----

    #[test]
    fn apply_image_config_merges_env_image_base_spec_overrides_win() {
        let mut plan = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0);
        // The spec seeded PORT=8080; the image supplies PATH + a PORT the spec must override.
        let image_env = vec![
            "PATH=/usr/lib/postgresql/16/bin:/usr/bin:/bin".to_string(),
            "PORT=5432".to_string(),
            "LANG=C.UTF-8".to_string(),
            "MALFORMED".to_string(), // no '=' — skipped
        ];
        plan.apply_image_config(&image_env, "/var/lib/postgresql");
        let lookup = |k: &str| {
            plan.env
                .iter()
                .find(|(ek, _)| ek == k)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(
            lookup("PATH").as_deref(),
            Some("/usr/lib/postgresql/16/bin:/usr/bin:/bin"),
            "the image PATH survives so the entrypoint resolves against it"
        );
        assert_eq!(lookup("PORT").as_deref(), Some("8080"), "the spec env WINS");
        assert_eq!(lookup("LANG").as_deref(), Some("C.UTF-8"));
        assert!(
            lookup("MALFORMED").is_none(),
            "a no-`=` image entry is skipped"
        );
        assert_eq!(plan.workdir, "/var/lib/postgresql");
    }

    #[test]
    fn launch_and_ephemeral_apply_the_same_image_config_identically() {
        // U24 parity: the launch path and the ephemeral one-shot both reach `plan.env`/
        // `plan.workdir` through the SAME `for_spec` → `apply_image_config` sequence, so a
        // workload with the same spec env sees the same result on either path (before this
        // the launch path dropped the image config, so only the ephemeral path had the PATH).
        let image_env = vec!["PATH=/opt/app/bin:/usr/bin:/bin".to_string()];
        let image_workdir = "/opt/app";

        // Launch path: for_spec(spec) then apply_image_config.
        let mut launch = SandboxPlan::for_spec(&spec(2, 512), "/r", "web-0", 1000, 1000);
        launch.apply_image_config(&image_env, image_workdir);

        // Ephemeral path: same spec env seeded, same seam.
        let mut ephemeral = SandboxPlan::for_spec(&spec(2, 512), "/r2", "eph", 1000, 1000);
        ephemeral.apply_image_config(&image_env, image_workdir);

        assert_eq!(
            launch.env, ephemeral.env,
            "env is applied identically on both paths"
        );
        assert_eq!(launch.workdir, ephemeral.workdir, "/opt/app");
        assert_eq!(launch.workdir, "/opt/app");
        assert!(
            launch
                .env
                .iter()
                .any(|(k, v)| k == "PATH" && v == "/opt/app/bin:/usr/bin:/bin"),
            "the image PATH is present on the launch path (U24)"
        );
    }

    #[test]
    fn apply_image_config_keeps_an_explicit_workdir_and_is_a_noop_when_empty() {
        // An explicit (spec/ephemeral) workdir is never overwritten by the image's.
        let mut plan = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0);
        plan.workdir = "/srv".to_string();
        plan.apply_image_config(&["PATH=/bin".to_string()], "/var/lib/postgresql");
        assert_eq!(
            plan.workdir, "/srv",
            "an explicit workdir wins over the image's"
        );

        // Empty image config ⇒ a pure no-op (tar/rootfs source / default config).
        let mut plan2 = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0);
        let before = plan2.clone();
        plan2.apply_image_config(&[], "");
        assert_eq!(plan2, before, "an empty image config changes nothing");
    }

    #[test]
    fn apply_image_config_dedups_shadowed_image_env_keys() {
        // INFO-1: a malformed image `Env` with a repeated key must not leave a SHADOW entry
        // after the spec overwrites only the first occurrence — a guest iterating `environ`
        // would otherwise see both. De-dup keeps ONE entry per key, with the spec value winning.
        let mut plan = SandboxPlan::for_spec(&spec(1, 128), "/r", "h", 0, 0); // spec sets PORT=8080
        let image_env = vec![
            "PATH=/a".to_string(),
            "PATH=/b".to_string(),   // duplicate image key (shadow)
            "PORT=5432".to_string(), // overwritten by the spec's PORT=8080
            "PORT=6000".to_string(), // duplicate of an overwritten key
        ];
        plan.apply_image_config(&image_env, "");
        assert_eq!(
            plan.env.iter().filter(|(k, _)| k == "PATH").count(),
            1,
            "no shadow PATH key remains"
        );
        assert_eq!(
            plan.env.iter().filter(|(k, _)| k == "PORT").count(),
            1,
            "no shadow PORT key remains"
        );
        let get = |k: &str| {
            plan.env
                .iter()
                .find(|(ek, _)| ek == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(
            get("PATH"),
            Some("/a"),
            "first image occurrence kept (getenv semantics)"
        );
        assert_eq!(get("PORT"), Some("8080"), "the spec value wins");
    }
}
