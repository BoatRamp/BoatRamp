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
    /// The allowed-syscall seccomp profile (default-deny: everything not listed
    /// is denied). [`for_spec`](SandboxPlan::for_spec) populates it from
    /// [`seccomp::default_allowlist`](crate::seccomp::default_allowlist); the
    /// worker compiles it to BPF and installs it before `execve`. `None` ⇒ no
    /// filter installed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp_allow: Option<Vec<String>>,
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
        let mounts = vec![
            Mount::virt("proc", "/proc", "proc", &["nosuid", "nodev", "noexec"]),
            Mount::virt(
                "sysfs",
                "/sys",
                "sysfs",
                &["nosuid", "nodev", "noexec", "ro"],
            ),
            Mount::virt("tmpfs", "/dev", "tmpfs", &["nosuid", "mode=0755"]),
            Mount::virt("tmpfs", "/tmp", "tmpfs", &["nosuid", "nodev"]),
        ];
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
            seccomp_allow: Some(crate::seccomp::default_allowlist()),
            namespaces: Namespaces::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_types::compute::{IsolationRequirement, RestartPolicy};
    use std::collections::BTreeMap;

    fn spec(vcpus: u32, mem_mib: u32) -> ComputeSpec {
        ComputeSpec {
            version: 1,
            rootfs: "r".repeat(64),
            kernel: "k".repeat(64),
            kernel_cmdline: None,
            vcpus,
            mem_mib,
            entrypoint: vec!["/app".into(), "--serve".into()],
            env: BTreeMap::from([("PORT".to_string(), "8080".to_string())]),
            port: 8080,
            restart: RestartPolicy::Always,
            scale_to_zero: false,
            volumes: vec![],
            isolation: IsolationRequirement::Trusted,
            prefer_backend: None,
        }
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
        assert!(plan
            .mounts
            .iter()
            .any(|m| m.target == "/tmp" && m.fstype == "tmpfs"));
        assert!(plan.mounts.iter().any(|m| m.target == "/dev"));
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
}
