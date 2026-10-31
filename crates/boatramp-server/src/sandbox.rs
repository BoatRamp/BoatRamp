//! The **whole-process OS sandbox** (privsep Phase 0, WS1): a seccomp-bpf
//! default-deny syscall allow-list **plus** a Landlock filesystem restriction,
//! installed on the `boatramp` server process **before the Tokio runtime starts**.
//!
//! WHOLE-PROCESS COVERAGE (the critical property). The install runs on the single
//! main thread, *before* the multi-threaded runtime spawns its workers, so every
//! worker thread inherits the seccomp filter + the Landlock domain via `clone`. A
//! late install (on one worker thread while its siblings already exist) would leave
//! those sibling request-handler threads unsandboxed — the escape an RCE would use.
//! For belt-and-suspenders the seccomp layer additionally uses TSYNC
//! (`apply_filter_all_threads`), so even a late install would cover every thread;
//! Landlock has no TSYNC equivalent, hence the pre-runtime (single-threaded) install.
//!
//! This is the server-process analog of the container backend's per-worker seccomp
//! filter (`boatramp-container`'s `seccomp` module), with two deliberate differences:
//!
//!   1. **`exec*` is KILLED.** The container filter *allows* `execve` because the
//!      worker execs the guest entrypoint under the filter; the server process, once
//!      serving, never legitimately execs, so the whole-process allow-list omits the
//!      exec family. `execve`/`execveat` — plus the kernel-escape surface (`ptrace`,
//!      `mount`, `setns`, `bpf`, `init_module`, …) — are given an explicit
//!      `SECCOMP_RET_KILL_PROCESS` action, so an RCE that lands in the server address
//!      space cannot spawn a shell or a new binary: it is killed hard (not merely
//!      `EPERM`'d) and is alertable. A benign allow-list *miss* still degrades to
//!      `EPERM` (soft). (`fork`/`vfork` are also killed, but as DEFENSE-IN-DEPTH only,
//!      NOT a guarantee that process creation is blocked: musl's `fork()` is issued as
//!      `clone` — which stays allowed because the tokio runtime creates its threads with
//!      it — so on a musl build the `fork`/`vfork` syscall kills are inert. The
//!      load-bearing barrier is the exec family: a child without `exec` cannot become a
//!      new program.)
//!   2. **Landlock** confines the process's filesystem view to the node's `data_dir`
//!      (+ the system temp dirs) for writes, and a conservative set of system read
//!      roots (so the server can still read `/etc/resolv.conf`, load shared objects,
//!      read `/proc`, …) for reads — everything else is denied.
//!
//! **Platform:** Linux only, and only when the crate is built with the `sandbox`
//! feature. On macOS / other platforms, or a build without the feature, [`install`]
//! is a documented no-op that logs a warning and returns
//! [`SandboxStatus::Unsupported`] — it never fails startup itself (the *caller*
//! decides, per posture, whether an unsupported platform is a hard error).
//!
//! **Best-effort on older kernels:** the Landlock layer uses the `landlock` crate's
//! ABI-compatibility handling (`CompatLevel::BestEffort`), so a kernel without (full)
//! Landlock support degrades to a partial/absent FS restriction (reported as
//! [`SandboxStatus::Partial`]) rather than a hard failure. The seccomp layer skips any
//! allow-list name the running kernel/arch doesn't know (logged at debug).
//!
//! The POSTURE decision (install / skip / fail-closed, and the per-backend
//! native-compute skip) lives in the caller (`boatramp`'s `serve::install_presandbox`,
//! called from `main::run` before the runtime is built) — this module is the pure
//! mechanism.

use std::path::PathBuf;

/// What [`install`] actually did, for logging + the caller's posture handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// The caller decided not to install (kept for API symmetry; `install` itself
    /// never returns this — the posture decision is made before `install` is called).
    Disabled,
    /// This platform/build has no OS sandbox — non-Linux, or built without the
    /// `sandbox` feature. A logged no-op; whether that is fatal is the caller's call
    /// (fail-closed under `strict`).
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

/// The resolved filesystem roots handed to [`install`]. Built by the caller from
/// `[serve.sandbox]` + the node's `data_dir` + the config/cert paths the server reads.
/// Whether to install at all (posture / native-compute skip) is the caller's decision,
/// so this carries no `enabled` flag.
#[derive(Debug, Clone)]
pub struct SandboxPolicy {
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
    /// `/proc`, `/sys`, `/dev`, `/run`) are read-only so the server keeps working
    /// (DNS resolution, shared-object loading, `/proc` reads). Everything else is
    /// denied. Callers layer the config-file dir + cert/TLS paths on with
    /// [`allow_read`](Self::allow_read) / [`allow_write`](Self::allow_write).
    pub fn for_server(data_dir: impl Into<PathBuf>) -> Self {
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

/// Install the whole-process sandbox per `policy`. MUST be called before the Tokio
/// runtime spawns its worker threads (so they inherit the domain via `clone`). See the
/// module docs for the platform/kernel behaviour. Never panics; returns
/// [`SandboxStatus`] on success and [`SandboxError`] only on a genuine (non-capability)
/// failure.
pub fn install(policy: &SandboxPolicy) -> Result<SandboxStatus, SandboxError> {
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    {
        linux::install(policy)
    }
    #[cfg(not(all(target_os = "linux", feature = "sandbox")))]
    {
        let _ = policy;
        #[cfg(not(target_os = "linux"))]
        tracing::warn!(
            "process sandbox unsupported on this platform (seccomp-bpf + Landlock are Linux-only); \
             continuing WITHOUT a process sandbox"
        );
        #[cfg(target_os = "linux")]
        tracing::warn!(
            "process sandbox requested but this build lacks the `sandbox` feature; continuing \
             WITHOUT a process sandbox"
        );
        Ok(SandboxStatus::Unsupported)
    }
}

/// The Linux seccomp + Landlock implementation. Compiled only with
/// `cfg(all(target_os = "linux", feature = "sandbox"))`; the live gate drives the
/// `prepare_*` primitives directly (it installs them in a forked child, on a
/// non-installing thread).
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
    /// and downgrades gracefully on older ones.
    const LANDLOCK_ABI: landlock::ABI = landlock::ABI::V1;

    /// Syscalls that must NEVER appear in the whole-process allow-list — the exec
    /// family + the kernel-attack / escape surface. A regression guard (see the unit
    /// tests); the [`KILL_SURFACE`] subset additionally gets `KILL_PROCESS`.
    pub const DENIED: &[&str] = &[
        "execve",
        "execveat",
        "fork",
        "vfork",
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

    /// The high-severity subset of [`DENIED`] given an explicit `SECCOMP_RET_KILL_PROCESS`
    /// action (Change 4 of the WS1 review): the exec family + the sharpest escape /
    /// code-injection primitives. An attempt to use one of these kills the process hard
    /// (`SIGSYS`) rather than returning `EPERM` — turning an exploit attempt into a loud,
    /// alertable crash. (Everything else not in the allow-list still returns `EPERM`, so a
    /// benign allow-list bug degrades softly.)
    ///
    /// `fork`/`vfork` are listed as DEFENSE-IN-DEPTH, not a guarantee that process creation is
    /// blocked: musl issues `fork()` as `clone` (allowed for the tokio runtime's threads), so on a
    /// musl build these two kills are inert. The load-bearing barrier is `execve`/`execveat` — a
    /// forked child that cannot `exec` cannot become a new program.
    pub const KILL_SURFACE: &[&str] = &[
        "execve",
        "execveat",
        "fork",
        "vfork",
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "mount",
        "pivot_root",
        "setns",
        "unshare",
        "bpf",
        "kexec_load",
        "kexec_file_load",
        "init_module",
        "finit_module",
        "keyctl",
    ];

    /// The whole-process allow-list: the syscalls a running `boatramp` server needs
    /// (default-deny — everything else is `EPERM`, with the [`KILL_SURFACE`] killed).
    /// Derived from the container backend's trusted-tier list
    /// (`boatramp-container`'s `seccomp::default_allowlist`), MINUS the exec family
    /// (`execve`/`execveat`/`fork`/`vfork`), plus a couple of newer event-loop/futex
    /// syscalls a long-lived tokio server may issue. Returned sorted + de-duplicated.
    /// Names the kernel/arch doesn't know are skipped at compile time.
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
        // process / threads / scheduling (NO exec*, NO fork/vfork — those are killed).
        // `clone`/`clone3` stay allowed: tokio spawns worker + blocking threads with them.
        "clone",
        "clone3",
        "exit",
        "exit_group",
        "wait4",
        "waitid",
        "futex",
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
        // fd-to-fd byte movers (H1): the HTTP/1.1 file-body hot path (`boatramp-http`'s `sendfile`)
        // and the plaintext reverse-proxy data plane (`boatramp-server`'s `splice`) commit to these
        // AFTER the response head is flushed, with no userspace fallback for a non-WouldBlock errno —
        // so an EPERM here truncates the body + drops the connection. They only move bytes between fds
        // the process already holds (no exec/escape/module-load/cross-process read), so the blast
        // radius is unchanged. (`tee`/`vmsplice` added for completeness.)
        "sendfile",
        "sendfile64",
        "splice",
        "copy_file_range",
        "tee",
        "vmsplice",
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
        // networking (bind/listen/accept/connect stay allowed — the server opens its
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
    /// process can install a seccomp filter + a Landlock ruleset without `CAP_SYS_ADMIN`.
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
    /// Used by the live gate to fail with a clear message on a kernel without Landlock.
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

    /// Resolve a list of syscall names to numbers, skipping (at debug) any the running
    /// kernel/arch doesn't know — so including a newer syscall is safe across kernels.
    fn resolve(
        names: impl IntoIterator<Item = String>,
    ) -> BTreeMap<i64, Vec<seccompiler::SeccompRule>> {
        let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
        for name in names {
            match name.parse::<syscalls::Sysno>() {
                Ok(sysno) => {
                    rules.insert(i64::from(sysno.id()), Vec::new());
                }
                Err(_) => {
                    tracing::debug!(syscall = %name, "sandbox: syscall name unknown on this kernel/arch — skipping");
                }
            }
        }
        rules
    }

    /// Compile a filter with the given matched/unmatched actions.
    fn compile(
        names: impl IntoIterator<Item = String>,
        match_action: seccompiler::SeccompAction,
        mismatch_action: seccompiler::SeccompAction,
    ) -> Result<seccompiler::BpfProgram, SandboxError> {
        let filter =
            seccompiler::SeccompFilter::new(resolve(names), mismatch_action, match_action, ARCH)
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
            RulesetStatus::PartiallyEnforced | RulesetStatus::NotEnforced => SandboxStatus::Partial,
        }
    }

    /// Two compiled-but-not-yet-installed seccomp filters: a KILL filter (the
    /// [`KILL_SURFACE`] → `KILL_PROCESS`, everything else → allow) stacked over the
    /// allow-list filter (allow-list → allow, everything else → `EPERM`). Built in
    /// advance so a caller (e.g. the live gate, which installs it in a `fork`ed child)
    /// applies it with no heap allocation after the fork. The kernel evaluates stacked
    /// filters and takes the most-severe action, so a [`KILL_SURFACE`] syscall is
    /// killed, a listed syscall is allowed, and any other miss returns `EPERM`.
    pub struct PreparedSeccomp {
        kill: seccompiler::BpfProgram,
        allow: seccompiler::BpfProgram,
    }

    impl PreparedSeccomp {
        /// Apply both filters to **every thread** of the calling process (TSYNC), after
        /// setting `no_new_privs`. After this returns, a [`KILL_SURFACE`] syscall
        /// (notably `execve`) kills the process with `SIGSYS`; any other unlisted
        /// syscall returns `EPERM`.
        pub fn apply(&self) -> Result<(), SandboxError> {
            set_no_new_privs()?;
            seccompiler::apply_filter_all_threads(&self.kill)
                .map_err(|e| SandboxError::Seccomp(e.to_string()))?;
            seccompiler::apply_filter_all_threads(&self.allow)
                .map_err(|e| SandboxError::Seccomp(e.to_string()))
        }
    }

    /// A built-but-not-yet-restricted Landlock ruleset (holds its ruleset fd, which is
    /// inherited across `fork`). [`apply`](Self::apply) restricts the calling process
    /// (and every thread it later `clone`s).
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

    /// Compile the whole-process seccomp filters (KILL + allow-list).
    pub fn prepare_seccomp() -> Result<PreparedSeccomp, SandboxError> {
        use seccompiler::SeccompAction;
        let kill = compile(
            KILL_SURFACE.iter().map(|s| (*s).to_string()),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
        )?;
        let allow = compile(
            whole_process_allowlist(),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
        )?;
        Ok(PreparedSeccomp { kill, allow })
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

    /// Install both layers on the current process, INDEPENDENTLY (M1): Landlock first (it needs its
    /// own syscalls + `openat`), then the seccomp filters (which kill `exec*`) — a FAILURE of ONE layer
    /// never skips the other. The returned [`SandboxStatus`] is the coarse enforcement level the
    /// caller's posture gate consumes ([`crate::serve`]'s `install_presandbox`). `Enforced` means
    /// seccomp applied AND Landlock fully enforced. `Partial` means `no_new_privs` is set but NOT both
    /// layers are fully enforced (Landlock only partial, or one layer failed to apply); the specifics
    /// are logged WARN/ERROR here. `Err` is reserved for the precondition failure (`no_new_privs`),
    /// where neither layer can apply. Under `auto` the caller fails OPEN on `Partial` (serve on; the
    /// ERROR log is alertable); under `strict` it fails CLOSED on anything less than `Enforced`. The
    /// high-value exec-kill (seccomp) is therefore installed even when Landlock cannot be — closing the
    /// hole where a Landlock error used to drop the whole sandbox under `auto`.
    pub fn install(policy: &SandboxPolicy) -> Result<SandboxStatus, SandboxError> {
        // Precondition for BOTH layers; if it fails, neither can apply → propagate.
        set_no_new_privs()?;

        // Landlock (independent). A genuine error is captured, logged, and does NOT skip seccomp.
        let landlock = match prepare_landlock(&policy.read_only_paths, &policy.read_write_paths)
            .and_then(PreparedLandlock::apply)
        {
            Ok(status) => Some(status),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "Landlock FS confinement FAILED to apply — the serving process is NOT filesystem-\
                     confined (seccomp exec-kill is still attempted below)"
                );
                None
            }
        };

        // seccomp (independent — the cheaper, higher-value layer carrying the exec-kill).
        let seccomp_ok = match prepare_seccomp().and_then(|p| p.apply()) {
            Ok(()) => true,
            Err(e) => {
                tracing::error!(error = %e, "seccomp filter FAILED to apply — exec* is NOT killed");
                false
            }
        };

        let status = match (seccomp_ok, landlock) {
            (true, Some(SandboxStatus::Enforced)) => {
                tracing::info!(
                    read_only_roots = policy.read_only_paths.len(),
                    read_write_roots = policy.read_write_paths.len(),
                    "process sandbox installed: seccomp-bpf allow-list (exec* + escape surface KILLED, \
                     other misses EPERM) + Landlock filesystem confinement to data_dir"
                );
                SandboxStatus::Enforced
            }
            (true, Some(_)) => {
                tracing::warn!(
                    "process sandbox PARTIAL: seccomp exec-kill active, but Landlock FS confinement is \
                     only partially enforced on this kernel"
                );
                SandboxStatus::Partial
            }
            (true, None) => {
                tracing::warn!(
                    "process sandbox PARTIAL: seccomp exec-kill active, but Landlock FS confinement is \
                     MISSING (see the error above)"
                );
                SandboxStatus::Partial
            }
            (false, Some(_)) => {
                tracing::warn!(
                    "process sandbox PARTIAL: Landlock FS confinement active, but the seccomp filter is \
                     MISSING — exec* is NOT killed"
                );
                SandboxStatus::Partial
            }
            (false, None) => {
                tracing::error!(
                    "process sandbox NOT installed: BOTH seccomp and Landlock failed to apply"
                );
                SandboxStatus::Partial
            }
        };
        Ok(status)
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
            for exec in ["execve", "execveat", "fork", "vfork"] {
                assert!(!list.contains(exec), "exec* must be denied: {exec}");
            }
        }

        #[test]
        fn kill_surface_is_a_subset_of_denied_and_covers_exec() {
            let denied: BTreeSet<&str> = DENIED.iter().copied().collect();
            for k in KILL_SURFACE {
                assert!(
                    denied.contains(k),
                    "KILL_SURFACE entry {k} must also be in DENIED"
                );
            }
            for exec in ["execve", "execveat", "fork", "vfork"] {
                assert!(
                    KILL_SURFACE.contains(&exec),
                    "exec* must be in the KILL_SURFACE: {exec}"
                );
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

        // H1 regression guard: the fd-to-fd byte movers MUST stay in the allow-list, or the HTTP/1.1
        // sendfile file-body path + the plaintext reverse-proxy splice path EPERM mid-response (no
        // userspace fallback). The `sandbox_live` SERVE smoke proves this against the real filter.
        #[test]
        fn covers_the_fd_byte_movers() {
            let list: BTreeSet<String> = whole_process_allowlist().into_iter().collect();
            for needed in [
                "sendfile",
                "sendfile64",
                "splice",
                "copy_file_range",
                "tee",
                "vmsplice",
            ] {
                assert!(
                    list.contains(needed),
                    "allow-list missing fd byte-mover {needed} (H1): file-serving + reverse-proxy break"
                );
            }
        }

        // Every allow-list + KILL_SURFACE entry the kernel knows must resolve (a typo'd
        // name would be silently skipped, so this guards the common names).
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
                "execve",
                "setns",
                "mount",
            ] {
                assert!(
                    name.parse::<syscalls::Sysno>().is_ok(),
                    "core syscall name does not resolve on this arch: {name}"
                );
            }
        }
    }
}
