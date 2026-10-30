//! The **whole-process OS sandbox** (privsep Phase 0, WS1): a seccomp-bpf
//! default-deny syscall allow-list **plus** a Landlock filesystem restriction,
//! installed on the running `boatramp` server process **after** startup is complete
//! (listeners bound, backends connected) so the allow-list can exclude boot-only
//! syscalls.
//!
//! This is the server-process analog of the container backend's per-worker seccomp
//! filter (`boatramp-container`'s `seccomp` module), with two deliberate differences:
//!
//!   1. **`exec*` is DENIED.** The container filter *allows* `execve`/`execveat`
//!      because the worker execs the guest entrypoint under the filter; the server
//!      process, once serving, never legitimately execs, so the whole-process
//!      allow-list omits the exec family (and `fork`/`vfork`) — an RCE that lands in
//!      the server address space cannot spawn a shell or a new binary.
//!   2. **Landlock** confines the process's filesystem view to the node's `data_dir`
//!      (+ the system temp dir) for writes, and a conservative set of system read
//!      roots (so the server can still read `/etc/resolv.conf`, load shared objects,
//!      read `/proc`, …) for reads — everything else is denied.
//!
//! **Platform:** Linux only, and only when the crate is built with the `sandbox`
//! feature. On macOS / other platforms, or a build without the feature,
//! [`install`] is a documented no-op that logs a warning and returns
//! [`SandboxStatus::Unsupported`] — it never fails startup.
//!
//! **Best-effort on older kernels:** the Landlock layer uses the `landlock` crate's
//! ABI-compatibility handling (`CompatLevel::BestEffort`), so a kernel without (full)
//! Landlock support degrades to a partial/absent FS restriction + a logged warning
//! rather than a hard failure. The seccomp layer skips any allow-list name the
//! running kernel/arch doesn't know (logged at debug) rather than refusing the whole
//! filter.
//!
//! The default action for an unlisted syscall is `EPERM` (errno), matching the
//! container backend's trusted-tier action — a denied syscall fails the call rather
//! than killing the process. (A `SECCOMP_RET_KILL_PROCESS` variant is a possible
//! hardening follow-up; see the WS1 notes.)

use std::path::PathBuf;

/// What [`install`] actually did, for logging + the live gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// Turned off by config (`[serve.sandbox] enabled = false`).
    Disabled,
    /// This platform/build has no OS sandbox — non-Linux, or built without the
    /// `sandbox` feature. A logged no-op; startup continues unsandboxed.
    Unsupported,
    /// seccomp installed and Landlock **fully** enforced.
    Enforced,
    /// seccomp installed, but Landlock was only partially enforced (or not enforced)
    /// because the running kernel is older than the ruleset's ABI — best-effort.
    Partial,
}

/// A failure compiling or installing one of the sandbox layers. Returned only on a
/// genuine error (a filter that won't compile, a Landlock syscall that errored); a
/// *capability* gap (an old kernel) degrades to [`SandboxStatus::Partial`] instead.
#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    /// Compiling or applying the seccomp-bpf filter failed.
    #[error("seccomp: {0}")]
    Seccomp(String),
    /// Building or applying the Landlock ruleset failed.
    #[error("landlock: {0}")]
    Landlock(String),
}

/// The resolved filesystem + enable decision handed to [`install`]. Built by the
/// serve path from `[serve.sandbox]` + the node's `data_dir` + the config/cert paths
/// the server reads at runtime.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
    /// Install the sandbox at all. `false` ⇒ [`install`] logs + returns
    /// [`SandboxStatus::Disabled`].
    pub enabled: bool,
    /// The node data directory — the primary read+write root.
    pub data_dir: PathBuf,
    /// Filesystem roots the process may **read** (recursively). Non-existent paths are
    /// skipped at install time (best-effort).
    pub read_only_paths: Vec<PathBuf>,
    /// Filesystem roots the process may **read and write** (recursively). Non-existent
    /// paths are skipped at install time.
    pub read_write_paths: Vec<PathBuf>,
}

impl SandboxPolicy {
    /// A sensible default server policy: `data_dir` + the system temp dirs are
    /// read-write; a conservative set of system roots (`/usr`, `/lib*`, `/etc`,
    /// `/proc`, `/sys`, `/dev`, `/run`, …) are read-only so the server keeps working
    /// (DNS resolution, shared-object loading, `/proc` reads). Everything else is
    /// denied. Callers layer the config-file dir + cert/TLS paths on with
    /// [`allow_read`](Self::allow_read) / [`allow_write`](Self::allow_write).
    pub fn for_server(enabled: bool, data_dir: impl Into<PathBuf>) -> Self {
        let data_dir = data_dir.into();
        let read_only_paths = [
            "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/sys", "/dev", "/run",
            "/var/run",
        ]
        .into_iter()
        .map(PathBuf::from)
        .collect();
        let mut read_write_paths = vec![data_dir.clone()];
        for p in ["/tmp", "/var/tmp"] {
            read_write_paths.push(PathBuf::from(p));
        }
        if let Some(tmp) = std::env::var_os("TMPDIR") {
            let tmp = PathBuf::from(tmp);
            if !tmp.as_os_str().is_empty() {
                read_write_paths.push(tmp);
            }
        }
        Self {
            enabled,
            data_dir,
            read_only_paths,
            read_write_paths,
        }
    }

    /// Allow reads under `path` (a no-op for an empty path).
    pub fn allow_read(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        if !path.as_os_str().is_empty() {
            self.read_only_paths.push(path);
        }
        self
    }

    /// Allow reads + writes under `path` (a no-op for an empty path).
    pub fn allow_write(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        if !path.as_os_str().is_empty() {
            self.read_write_paths.push(path);
        }
        self
    }
}

/// Install the whole-process sandbox per `policy`. See the module docs for the
/// platform/kernel behaviour. Never panics; returns [`SandboxStatus`] on success and
/// [`SandboxError`] only on a genuine (non-capability) failure.
pub fn install(policy: &SandboxPolicy) -> Result<SandboxStatus, SandboxError> {
    if !policy.enabled {
        tracing::info!("process sandbox disabled by config ([serve.sandbox] enabled = false)");
        return Ok(SandboxStatus::Disabled);
    }
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    {
        linux::install(policy)
    }
    #[cfg(not(all(target_os = "linux", feature = "sandbox")))]
    {
        let _ = policy;
        #[cfg(not(target_os = "linux"))]
        tracing::warn!(
            "sandbox unsupported on this platform (seccomp-bpf + Landlock are Linux-only); \
             continuing WITHOUT a process sandbox"
        );
        #[cfg(target_os = "linux")]
        tracing::warn!(
            "process sandbox requested but this build lacks the `sandbox` feature; \
             continuing WITHOUT a process sandbox"
        );
        Ok(SandboxStatus::Unsupported)
    }
}

/// The Linux seccomp + Landlock implementation. Compiled only with
/// `cfg(all(target_os = "linux", feature = "sandbox"))`; the live gate drives the
/// `prepare_*` primitives directly (it installs them in a forked child).
#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub mod linux {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use landlock::{
        Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreated, RulesetCreatedAttr, RulesetStatus,
    };

    use super::{SandboxError, SandboxPolicy, SandboxStatus};

    /// The seccomp target arch for the current build (the filter runs on this
    /// process, so it matches the host arch).
    #[cfg(target_arch = "x86_64")]
    const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;

    /// The Landlock ABI the ruleset handles. `V1` is the universally-available floor
    /// (Linux 5.13+); `CompatLevel::BestEffort` upgrades confinement on newer kernels
    /// and downgrades gracefully on older ones. (Handling a higher ABI — to also
    /// confine `refer`/`truncate`/`ioctl_dev` — is a cheap follow-up.)
    const LANDLOCK_ABI: landlock::ABI = landlock::ABI::V1;

    /// Syscalls that must NEVER appear in the whole-process allow-list — the exec
    /// family + the kernel-attack / escape surface. A regression guard (see the unit
    /// test); `exec*` denial is the headline WS1 property.
    pub const DENIED: &[&str] = &[
        // exec family — the headline deny (an RCE in-process cannot spawn a binary).
        "execve",
        "execveat",
        "fork",
        "vfork",
        // kernel-attack / container-escape surface (mirrors the container tier).
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "mount",
        "umount2",
        "pivot_root",
        "chroot",
        "bpf",
        "kexec_load",
        "kexec_file_load",
        "init_module",
        "finit_module",
        "delete_module",
        "keyctl",
        "add_key",
        "request_key",
        "reboot",
        "swapon",
        "swapoff",
        "settimeofday",
        "clock_settime",
        "setns",
        "unshare",
        "perf_event_open",
        "acct",
        "quotactl",
    ];

    /// The whole-process allow-list: the syscalls a running `boatramp` server needs
    /// (default-deny — everything else is `EPERM`). Derived from the container
    /// backend's trusted-tier list (`boatramp-container`'s `seccomp::default_allowlist`),
    /// MINUS the exec family (`execve`/`execveat`/`fork`/`vfork`), plus a couple of
    /// newer event-loop/futex syscalls a long-lived tokio server may issue. Returned
    /// sorted + de-duplicated. Names the kernel/arch doesn't know are skipped at
    /// compile time, so including a newer syscall is safe across kernels.
    pub fn whole_process_allowlist() -> Vec<String> {
        let mut names: Vec<String> = ALLOWED
            .iter()
            .map(|s| (*s).to_string())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        names.sort();
        names
    }

    /// The curated allow-list (deduplicated/sorted by [`whole_process_allowlist`]).
    const ALLOWED: &[&str] = &[
        // process / threads / scheduling (NO exec*, NO fork/vfork — those are denied).
        "clone",
        "clone3",
        "exit",
        "exit_group",
        "wait4",
        "waitid",
        "futex",
        // newer glibc futex multi-wait (skipped on kernels/arches that lack it).
        "futex_waitv",
        "set_robust_list",
        "get_robust_list",
        "set_tid_address",
        "gettid",
        "getpid",
        "getppid",
        "setsid",
        "setpgid",
        "getpgid",
        "getsid",
        "getpgrp",
        "sched_getaffinity",
        "sched_setaffinity",
        "sched_yield",
        "sched_getparam",
        "sched_getscheduler",
        "sched_get_priority_max",
        "sched_get_priority_min",
        "getrusage",
        "prctl",
        "arch_prctl",
        "rseq",
        // identity (read-only)
        "getuid",
        "geteuid",
        "getgid",
        "getegid",
        "getgroups",
        "getresuid",
        "getresgid",
        // memory
        "brk",
        "mmap",
        "munmap",
        "mremap",
        "mprotect",
        "madvise",
        "mlock",
        "munlock",
        "membarrier",
        // file I/O
        "open",
        "openat",
        "openat2",
        "close",
        "close_range",
        "read",
        "pread64",
        "readv",
        "preadv",
        "write",
        "pwrite64",
        "writev",
        "pwritev",
        "lseek",
        "fsync",
        "fdatasync",
        "sync",
        "syncfs",
        "sync_file_range",
        "msync",
        "fadvise64",
        "ftruncate",
        "fallocate",
        "stat",
        "fstat",
        "lstat",
        "newfstatat",
        "statx",
        "statfs",
        "fstatfs",
        "access",
        "faccessat",
        "faccessat2",
        "readlink",
        "readlinkat",
        "getdents64",
        "getcwd",
        "chdir",
        "fchdir",
        "dup",
        "dup2",
        "dup3",
        "pipe",
        "pipe2",
        "fcntl",
        "ioctl",
        "flock",
        "umask",
        "fchmod",
        "fchmodat",
        "chmod",
        "fchown",
        "fchownat",
        "chown",
        "lchown",
        "mkdir",
        "mkdirat",
        "unlink",
        "unlinkat",
        "rmdir",
        "creat",
        "rename",
        "renameat",
        "renameat2",
        "symlink",
        "symlinkat",
        "link",
        "linkat",
        "truncate",
        "utimensat",
        "utime",
        "utimes",
        // event loops / multiplexing
        "poll",
        "ppoll",
        "select",
        "pselect6",
        "epoll_create",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "epoll_pwait",
        // newer epoll wait (skipped where unknown).
        "epoll_pwait2",
        "eventfd",
        "eventfd2",
        "timerfd_create",
        "timerfd_settime",
        "timerfd_gettime",
        "signalfd",
        "signalfd4",
        "inotify_init",
        "inotify_init1",
        "inotify_add_watch",
        "inotify_rm_watch",
        // networking (bind/listen/accept/connect stay allowed — the server still opens
        // listeners + outbound connections after the sandbox is installed).
        "socket",
        "socketpair",
        "bind",
        "listen",
        "accept",
        "accept4",
        "connect",
        "getsockname",
        "getpeername",
        "getsockopt",
        "setsockopt",
        "shutdown",
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "sendmmsg",
        "recvmmsg",
        // time
        "clock_gettime",
        "clock_getres",
        "clock_nanosleep",
        "gettimeofday",
        "nanosleep",
        "times",
        "setitimer",
        "getitimer",
        "alarm",
        "timer_create",
        "timer_settime",
        "timer_gettime",
        "timer_delete",
        "timer_getoverrun",
        // signals
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "rt_sigpending",
        "rt_sigtimedwait",
        "rt_sigsuspend",
        "sigaltstack",
        "kill",
        "tkill",
        "tgkill",
        "pause",
        // misc
        "uname",
        "sysinfo",
        "getrandom",
        "getrlimit",
        "setrlimit",
        "prlimit64",
        "getpriority",
        "setpriority",
        "restart_syscall",
    ];

    /// Set `PR_SET_NO_NEW_PRIVS` on the calling process — required so an unprivileged
    /// process can install a seccomp filter + a Landlock ruleset without
    /// `CAP_SYS_ADMIN`.
    pub fn set_no_new_privs() -> Result<(), SandboxError> {
        // SAFETY: `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)` takes no pointers and only
        // tightens the calling process's own privilege state.
        let rc = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if rc != 0 {
            return Err(SandboxError::Seccomp(format!(
                "PR_SET_NO_NEW_PRIVS failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Query the running kernel's Landlock ABI (the version `landlock_create_ruleset`
    /// with `LANDLOCK_CREATE_RULESET_VERSION` reports). `> 0` ⇒ Landlock is available.
    /// Used by the live gate to fail with a clear message on a kernel without Landlock
    /// rather than a confusing assertion mismatch.
    pub fn landlock_kernel_abi() -> i64 {
        const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
        // SAFETY: a NULL attr + size 0 with the VERSION flag is the documented ABI
        // probe; it allocates no ruleset and touches no caller memory.
        unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        }
    }

    /// Compile the whole-process allow-list to a seccomp-bpf program (default action
    /// `EPERM`; listed syscalls allowed). Unknown names are skipped (logged at debug).
    fn compile_filter(allow: &[String]) -> Result<seccompiler::BpfProgram, SandboxError> {
        use seccompiler::{SeccompAction, SeccompFilter};

        let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
        for name in allow {
            match name.parse::<syscalls::Sysno>() {
                Ok(sysno) => {
                    // Empty rule list ⇒ match unconditionally → the match action (Allow).
                    rules.insert(i64::from(sysno.id()), Vec::new());
                }
                Err(_) => {
                    tracing::debug!(syscall = %name, "sandbox: allow-list name unknown on this kernel/arch — skipping");
                }
            }
        }
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Errno(libc::EPERM as u32), // unlisted → EPERM
            SeccompAction::Allow,                     // listed → allow
            ARCH,
        )
        .map_err(|e| SandboxError::Seccomp(e.to_string()))?;
        filter
            .try_into()
            .map_err(|e: seccompiler::BackendError| SandboxError::Seccomp(e.to_string()))
    }

    /// Build a Landlock ruleset confining reads to `read_only` (+ `read_write`) and
    /// writes to `read_write`. Non-existent paths are skipped (best-effort).
    /// `CompatLevel::BestEffort` degrades gracefully on a kernel without full Landlock.
    fn build_ruleset(
        read_only: &[PathBuf],
        read_write: &[PathBuf],
    ) -> Result<RulesetCreated, SandboxError> {
        let ro_access = AccessFs::from_read(LANDLOCK_ABI);
        let rw_access = AccessFs::from_all(LANDLOCK_ABI);
        let mut created = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(LANDLOCK_ABI))
            .map_err(|e| SandboxError::Landlock(e.to_string()))?
            .create()
            .map_err(|e| SandboxError::Landlock(e.to_string()))?;
        for (paths, access) in [(read_only, ro_access), (read_write, rw_access)] {
            for p in paths {
                if !p.exists() {
                    continue;
                }
                let fd = PathFd::new(p)
                    .map_err(|e| SandboxError::Landlock(format!("{}: {e}", p.display())))?;
                created = created
                    .add_rule(PathBeneath::new(fd, access))
                    .map_err(|e| SandboxError::Landlock(e.to_string()))?;
            }
        }
        Ok(created)
    }

    fn status_of(ruleset: RulesetStatus) -> SandboxStatus {
        match ruleset {
            RulesetStatus::FullyEnforced => SandboxStatus::Enforced,
            // Partially enforced (newer ABI on an older kernel) or not enforced at all
            // (no Landlock): seccomp is still installed, so the process is partially
            // sandboxed either way.
            RulesetStatus::PartiallyEnforced | RulesetStatus::NotEnforced => SandboxStatus::Partial,
        }
    }

    /// A compiled-but-not-yet-installed seccomp filter. Built in advance so a caller
    /// (e.g. the live gate, which installs it in a `fork`ed child) applies it with no
    /// heap allocation after the fork.
    pub struct PreparedSeccomp {
        program: seccompiler::BpfProgram,
    }

    impl PreparedSeccomp {
        /// Apply the filter to the calling process (sets `no_new_privs` first). After
        /// this returns, any unlisted syscall (notably `execve`) fails with `EPERM`.
        pub fn apply(&self) -> Result<(), SandboxError> {
            set_no_new_privs()?;
            seccompiler::apply_filter(&self.program)
                .map_err(|e| SandboxError::Seccomp(e.to_string()))
        }
    }

    /// A built-but-not-yet-restricted Landlock ruleset (holds its ruleset fd, which is
    /// inherited across `fork`). [`apply`](Self::apply) restricts the calling process.
    pub struct PreparedLandlock {
        created: RulesetCreated,
    }

    impl PreparedLandlock {
        /// Restrict the calling process to the ruleset's paths. Returns
        /// [`SandboxStatus::Enforced`] / [`SandboxStatus::Partial`].
        pub fn apply(self) -> Result<SandboxStatus, SandboxError> {
            let status = self
                .created
                .restrict_self()
                .map_err(|e| SandboxError::Landlock(e.to_string()))?;
            Ok(status_of(status.ruleset))
        }
    }

    /// Compile the whole-process seccomp filter (no allocation after this is cheap to
    /// carry across a `fork`).
    pub fn prepare_seccomp() -> Result<PreparedSeccomp, SandboxError> {
        Ok(PreparedSeccomp {
            program: compile_filter(&whole_process_allowlist())?,
        })
    }

    /// Build the Landlock ruleset for the given read-only / read-write roots.
    pub fn prepare_landlock(
        read_only: &[PathBuf],
        read_write: &[PathBuf],
    ) -> Result<PreparedLandlock, SandboxError> {
        Ok(PreparedLandlock {
            created: build_ruleset(read_only, read_write)?,
        })
    }

    /// Install both layers on the current process: Landlock first (it needs its own
    /// syscalls + `openat`), then the seccomp filter (which denies `exec*`).
    pub fn install(policy: &SandboxPolicy) -> Result<SandboxStatus, SandboxError> {
        set_no_new_privs()?;
        let landlock_status = prepare_landlock(&policy.read_only_paths, &policy.read_write_paths)?
            .apply()
            .inspect_err(|e| tracing::warn!(error = %e, "Landlock restriction failed"))?;
        prepare_seccomp()?.apply()?;
        tracing::info!(
            landlock = ?landlock_status,
            read_only_roots = policy.read_only_paths.len(),
            read_write_roots = policy.read_write_paths.len(),
            "process sandbox installed: seccomp-bpf default-deny allow-list (exec* DENIED) + \
             Landlock filesystem confinement to data_dir"
        );
        Ok(landlock_status)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::BTreeSet;

        #[test]
        fn allowlist_is_sorted_deduped_and_nonempty() {
            let list = whole_process_allowlist();
            assert!(!list.is_empty());
            let mut sorted = list.clone();
            sorted.sort();
            assert_eq!(list, sorted, "allow-list must be sorted");
            let unique: BTreeSet<_> = list.iter().collect();
            assert_eq!(unique.len(), list.len(), "allow-list must be deduplicated");
        }

        #[test]
        fn never_allows_exec_or_the_escape_surface() {
            let list: BTreeSet<String> = whole_process_allowlist().into_iter().collect();
            for danger in DENIED {
                assert!(
                    !list.contains(*danger),
                    "whole-process allow-list must NOT contain {danger} (exec*/escape surface)"
                );
            }
            // The headline WS1 property, asserted explicitly.
            for exec in ["execve", "execveat", "fork", "vfork"] {
                assert!(!list.contains(exec), "exec* must be denied: {exec}");
            }
        }

        #[test]
        fn covers_the_core_server_syscalls() {
            let list: BTreeSet<String> = whole_process_allowlist().into_iter().collect();
            for needed in [
                "read",
                "write",
                "openat",
                "close",
                "mmap",
                "mprotect",
                "futex",
                "clone",
                "exit_group",
                "socket",
                "bind",
                "listen",
                "accept4",
                "connect",
                "epoll_wait",
                "clock_gettime",
                "getrandom",
                "rt_sigaction",
                "newfstatat",
            ] {
                assert!(
                    list.contains(needed),
                    "allow-list missing core syscall {needed}"
                );
            }
        }

        // Every allow-list entry that the kernel knows must resolve to a syscall number
        // (a typo'd name would be silently skipped, so this guards the common names).
        #[test]
        fn core_names_resolve_to_syscall_numbers() {
            for name in [
                "read",
                "write",
                "openat",
                "close",
                "clone",
                "exit_group",
                "socket",
                "epoll_wait",
            ] {
                assert!(
                    name.parse::<syscalls::Sysno>().is_ok(),
                    "core allow-list name does not resolve on this arch: {name}"
                );
            }
        }
    }
}
