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
//!      `EPERM` (soft). (`fork`/`vfork` are also killed. This is NOT merely inert
//!      defense-in-depth: while the tokio runtime creates its THREADS via `clone` (allowed),
//!      a `std::process::Command` with a `pre_exec` hook cannot use `posix_spawn`, so Rust's
//!      fork+exec path issues a BARE `fork(2)` — which the kill-surface `SIGSYS`-kills. So the
//!      fork-kill really does block process creation here, and an `exec.compute` instance that
//!      legitimately forks children at serve time has `fork`/`vfork` un-killed in its derived
//!      profile ([`FORK_SPAWN`]). The other load-bearing barrier is the exec family: a child
//!      without `exec` cannot become a new program.)
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use boatramp_core::privsep::{HostAuthority, ProfileEnforcement, SandboxPosture};

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// The node data directory — the primary read+write root.
    pub data_dir: PathBuf,
    /// Filesystem roots the process may **read** (recursively). Non-existent paths are
    /// skipped at install time (best-effort).
    pub read_only_paths: Vec<PathBuf>,
    /// Filesystem roots the process may **read and write** (recursively). Non-existent
    /// paths are skipped at install time.
    pub read_write_paths: Vec<PathBuf>,
    /// Filesystem paths this process may **execute** (`execve`), in addition to reading them —
    /// the execute-pin. `AccessFs::from_read` (which [`linux::build_ruleset`] grants the general
    /// read/write roots) INCLUDES `Execute`, so Execute is STRIPPED from those general grants and
    /// re-granted ONLY on this list. EMPTY for every instance whose `execve` is seccomp-killed
    /// (which is all of them except the `exec.compute` router + the root supervisor, each of which
    /// pins EXACTLY its own binary so a fork can only re-exec that one trusted path). Non-existent
    /// paths are skipped at install time.
    pub execute_paths: Vec<PathBuf>,
    /// **Deny ALL TCP via Landlock `AccessNet` (F1 — the separate VM relay ONLY).** When set,
    /// [`linux::build_ruleset`] additionally handles `AccessNet` (`BindTcp | ConnectTcp`) with
    /// ZERO `NetPort` allow-rules, so every TCP bind AND every TCP connect is denied. AF_UNIX
    /// sockets (the firecracker vsock UDS the relay dials) are NOT governed by `AccessNet`, so the
    /// relay's one legitimate dial is unaffected. `AccessNet` is a Landlock V4 right and the
    /// privsep floor is `MIN_LANDLOCK_ABI` = V5 (⊇ V4), so the net wall is
    /// always available at the floor; on a kernel whose Landlock ABI predates V4 the install FAILS
    /// CLOSED (`build_ruleset` returns `Err` rather than silently omit the wall — and the V5 floor
    /// already refuses such a kernel). `false` for EVERY other profile (monolith / root /
    /// per-capability instance) — a strict no-op there, so no regression to any network-serving
    /// instance or the root self-profile.
    pub deny_all_tcp: bool,
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
        let read_only_paths = SYSTEM_READ_ROOTS.iter().map(PathBuf::from).collect();
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
            // The monolith never `execve`s once serving (its exec family is seccomp-killed), so it
            // pins nothing executable — Execute is confined to the (empty) list.
            execute_paths: Vec::new(),
            // The monolith binds + dials freely (it IS the network server); never wall off TCP.
            deny_all_tcp: false,
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

// =============================================================================
// Phase-0 syscall-name data (relocated to module top-level in privsep Phase 1 WS-D
// so the cross-platform per-capability DERIVATION below can reference the same
// authoritative lists the Linux install uses — no second source of truth). The
// install machinery that consumes them stays Linux-gated in `mod linux`.
// =============================================================================

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
/// `fork`/`vfork` are killed too, and NOT merely inert: the tokio runtime makes its threads via
/// `clone` (allowed), but a `std::process::Command` with a `pre_exec` hook takes Rust's fork+exec
/// path, which issues a BARE `fork(2)` — so this kill really does stop process creation (a real,
/// audited `SIGSYS` when the per-tenant router tries to spawn). The exec family
/// (`execve`/`execveat`) is the other barrier — a forked child that cannot `exec` cannot become a
/// new program. An `exec.compute` instance, which legitimately forks+execs children, has BOTH
/// families un-killed in its derived profile ([`EXEC_SPAWN`] + [`FORK_SPAWN`]).
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

// =============================================================================
// Per-capability profile DERIVATION (privsep Phase 1 WS-D, design §2 F6 / §5 inv1,7)
// =============================================================================
//
// Phase 0 installs ONE fixed whole-process profile ([`whole_process_allowlist`] +
// [`KILL_SURFACE`] + a `data_dir` Landlock view). Under `[privsep]` an instance holds a
// DROPPED authority subset, so its profile is the load-bearing WALL: a memory break that
// bypasses the in-process construction gate is still denied the dropped authority's
// syscalls + FS paths by the profile. These functions DERIVE that per-instance profile
// from the instance's `HostAuthority` set — the union of what the held capabilities
// legitimately need, everything else default-denied.
//
// The derivation is pure DATA (syscall names + paths), so it is unit-tested cross-platform
// (this host); the Linux install that consumes a [`DerivedProfile`] is `mod linux`'s
// [`linux::install_derived`], exercised by the `sandbox-live` CI gate / lighthouse.

/// Syscalls removed from the derived BASE (so an instance without the owning capability is
/// denied them) and re-added ONLY for the capabilities that legitimately need them. Their
/// union is exactly the capability-attributable subset of [`ALLOWED`]; [`EXEC_SPAWN`] is the
/// one group that is NOT in [`ALLOWED`] (the Phase-0 monolith never execs once serving), so
/// it is added ONLY for an `exec.compute` instance and simultaneously dropped from that
/// instance's kill-list.
const NET_INBOUND: &[&str] = &["socket", "bind", "listen", "accept", "accept4"];
/// Outbound dialing (`connect`) — a backend pool, an ACME/KMS/Vault endpoint, a relay/gateway.
const NET_OUTBOUND: &[&str] = &["socket", "connect"];
/// Memory-locking the live key material (the `keyguard::MlockedKey` pattern). Only an
/// instance that holds a crown-jewel key or the live TLS cert key legitimately mlocks.
const KEY_LOCK: &[&str] = &["mlock", "munlock"];
/// Re-execing the compute workers (`__sandbox`/`__vmm-run`/`__vz-run`). Allowed ONLY for an
/// `exec.compute` instance; for every other instance `execve`/`execveat` stay in the
/// kill-list (hard `SIGSYS`, inherited from Phase 0).
const EXEC_SPAWN: &[&str] = &["execve", "execveat"];

/// The process-CREATION syscalls an `exec.compute` instance needs to fork a child BEFORE it
/// `execve`s it. Allowed ONLY for an `exec.compute` instance; killed (hard `SIGSYS`) for every
/// other. These were previously assumed inert on the fork-kill (the belief that libc routes
/// `fork()` through `clone`, which stays allowed for the tokio runtime's threads) — but that is
/// FALSE for the per-tenant router's spawn: `std::process::Command` with a `pre_exec` hook cannot
/// use `posix_spawn`, so Rust's fork+exec path issues a BARE `fork(2)` (syscall 57), which the
/// kill-surface `SIGSYS`-kills. A per-tenant router (`exec.compute`) forks children at SERVE time
/// UNDER its installed sandbox (unlike the root, which forks at boot while still UNCONFINED), so it
/// must be allowed to `fork`/`vfork`. Bounded: the Landlock view EXECUTE-pins ONLY its own binary
/// — [`linux::build_ruleset`] STRIPS `Execute` from the general read/write grants (which otherwise
/// carry it via `AccessFs::from_read`, including on the WRITABLE `backend.kv` state subtree) and
/// re-grants it ONLY on [`SandboxPolicy::execute_paths`], populated with this router's own binary
/// alone. So a fork can `execve` that ONE path and nothing else — not a shell, not an ELF dropped
/// into writable state — and WS-C's cold-start admission (token bucket + backoff) caps the spawn
/// rate, so this does not open a fork-bomb or an arbitrary-exec surface.
const FORK_SPAWN: &[&str] = &["fork", "vfork"];

/// The syscalls that INSTALL a per-instance sandbox — the seccomp filter + the Landlock ruleset.
/// Allowed ONLY for an `exec.compute` instance (the per-tenant router); every other instance keeps
/// them default-denied (`EPERM`).
///
/// **Why only exec.compute needs these, and why it is SAFE.** A per-tenant child is `fork`ed from
/// the already-confined router (not from the UNCONFINED root, the way boot-forked instances are),
/// so it INHERITS the router's seccomp filter before it can install its OWN nested per-instance
/// profile. The router's derived allow-list does not list these install syscalls, so the inherited
/// filter `EPERM`s the child's attempt to confine itself — and the node refuses closed, serving no
/// tenant. Two symptoms, ONE cause: (1) `seccomp(2)` is `EPERM`'d, so the child cannot apply its own
/// seccomp filter; (2) the child's Landlock ABI probe ([`linux::landlock_kernel_abi`], a
/// `landlock_create_ruleset` version query) is `EPERM`'d and returns `-1`, which
/// [`linux::handled_fs_abi`] maps to `ABI::Unsupported`, whose `AccessFs::from_all` is EMPTY — so
/// `handle_access` rejects it as `empty access-right` and the child's whole FS confinement fails.
/// Permitting these four on the router un-blocks the child's install of its own, STRICTLY TIGHTER
/// nested sandbox. seccomp + Landlock are MONOTONIC (a child can only ADD restrictions across the
/// inherited layers, never drop one), so allowing the install syscalls cannot be used to escape:
/// the router's own confinement still bounds every child, and each child only narrows further.
/// `prctl` (the `no_new_privs` precondition) is already in [`ALLOWED`], so it is not repeated here.
const SANDBOX_INSTALL: &[&str] = &[
    "seccomp",
    "landlock_create_ruleset",
    "landlock_add_rule",
    "landlock_restrict_self",
];

/// The conservative system read roots every instance (and the monolith) needs so the process
/// keeps working (shared-object loading, `/etc/resolv.conf` + CA bundle, `/proc`). Single
/// source of truth for [`SandboxPolicy::for_server`] and [`SandboxDerivationInputs`].
///
/// **`/proc` is granted BROAD by design (HIGH-1 defense-in-depth decision).** The final privsep
/// Security re-review flagged that this whole-`/proc` read grant leaves the VFS path to a sibling's
/// `/proc/<pid>/mem` open. We deliberately keep the grant broad rather than narrow it to the instance's
/// own `/proc/self` subtree, because the cross-instance memory-disclosure hole is closed COMPLETELY and
/// more robustly at its source by `set_process_undumpable` (`prctl(PR_SET_DUMPABLE, 0)` in
/// `run_instance` / `run_vm_relay_confined`): a non-dumpable target's `/proc/<pid>/{mem,maps,…}` are
/// root-owned and `ptrace_may_access`-gated, so the broad VFS read grant can no longer reach a sibling's
/// memory regardless of this allow-list. Narrowing to `/proc/self` was rejected as risky and incomplete:
/// the runtime + its dependencies + glibc legitimately read numerous NON-pid `/proc` entries
/// (`/proc/cpuinfo`, `/proc/meminfo`, `/proc/stat`, `/proc/sys/...`, `/proc/net/...`, `/proc/config.gz`,
/// …) whose exact set is kernel- and configuration-dependent, and a Landlock ALLOW-list that missed one
/// would deny it SILENTLY (`EACCES`) in a way the non-Linux dev build cannot catch — trading a
/// fully-closed hole for a fragile startup regression. (`/proc/self/*` own-access is unaffected by
/// either choice — the kernel short-circuits same-thread-group access — so the Container
/// `/proc/self/ns` self-check and `/proc/self/fd/N` magic symlinks work under both.)
pub const SYSTEM_READ_ROOTS: &[&str] = &[
    "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/proc", "/sys", "/dev", "/run", "/var/run",
];

/// The capability-attributable syscalls (the union of [`NET_INBOUND`], [`NET_OUTBOUND`],
/// [`KEY_LOCK`]) that the derived BASE strips out of [`ALLOWED`] and re-adds per capability.
/// [`EXEC_SPAWN`] is deliberately excluded here (it is not in [`ALLOWED`] to begin with).
fn capability_gated_syscalls() -> BTreeSet<&'static str> {
    NET_INBOUND
        .iter()
        .chain(NET_OUTBOUND)
        .chain(KEY_LOCK)
        .copied()
        .collect()
}

/// Whether any held capability binds an inbound listener (needs `bind`/`listen`/`accept`).
fn needs_inbound(caps: &BTreeSet<HostAuthority>) -> bool {
    caps.iter().any(|a| a.is_listener())
}

/// Whether any held capability legitimately dials OUTBOUND (`connect`): a backend pool
/// (`backend.*`), cert issuance (`acme.dns-control`), image pulls / worker orchestration
/// (`exec.compute`), the overlay/gateway edges that dial relays, or a crown-jewel key that
/// may be KMS/Vault-backed (so it must reach its remote key service). A pure file-KEK signer
/// does not strictly need it, but granting it is safe (it holds no listener) and keeps a
/// KMS-backed signer working; `Strict` operators can tighten per-instance in WS-B.
fn needs_outbound(caps: &BTreeSet<HostAuthority>) -> bool {
    caps.iter().any(|a| {
        a.is_backend()
            || a.is_crown_jewel()
            || matches!(
                a,
                HostAuthority::AcmeDnsControl
                    | HostAuthority::ExecCompute
                    | HostAuthority::ListenOverlay
                    | HostAuthority::ListenGateway
            )
    })
}

/// Whether any held capability holds long-lived key material in memory that is mlocked: a
/// crown jewel (its sealing/signing key) or `listen.public-tls` (the live private cert key).
fn holds_key_material(caps: &BTreeSet<HostAuthority>) -> bool {
    caps.iter()
        .any(|a| a.is_crown_jewel() || *a == HostAuthority::ListenPublicTls)
}

/// Whether this instance re-execs compute workers (`exec.compute`) — the ONLY instance whose
/// derived profile allows `execve` (and drops it from the kill-list).
fn holds_exec_spawn(caps: &BTreeSet<HostAuthority>) -> bool {
    caps.contains(&HostAuthority::ExecCompute)
}

/// Derive the per-instance seccomp ALLOW-set from the capability set: the Phase-0 [`ALLOWED`]
/// baseline MINUS the capability-gated syscalls, then re-add only the groups the held
/// capabilities need. Everything not in the result is `EPERM` (or killed, see
/// [`derive_seccomp_killlist`]). Sorted + de-duplicated.
///
/// Invariant (regression-guarded cross-platform): for the full monolith set
/// [`HostAuthority::ALL`] this returns a SUPERSET of [`whole_process_allowlist`] (so the
/// `all`-composition never loses a syscall the monolith needs); the ONLY extras it adds are
/// [`EXEC_SPAWN`] + [`FORK_SPAWN`] + [`SANDBOX_INSTALL`], present solely because `ALL` includes
/// `exec.compute`.
pub fn derive_seccomp_allowlist(caps: &BTreeSet<HostAuthority>) -> Vec<String> {
    let gated = capability_gated_syscalls();
    let mut set: BTreeSet<String> = ALLOWED
        .iter()
        .copied()
        .filter(|s| !gated.contains(s))
        .map(str::to_string)
        .collect();
    if needs_inbound(caps) {
        set.extend(NET_INBOUND.iter().copied().map(str::to_string));
    }
    if needs_outbound(caps) {
        set.extend(NET_OUTBOUND.iter().copied().map(str::to_string));
    }
    if holds_key_material(caps) {
        set.extend(KEY_LOCK.iter().copied().map(str::to_string));
    }
    if holds_exec_spawn(caps) {
        set.extend(EXEC_SPAWN.iter().copied().map(str::to_string));
        // An exec.compute instance forks its child (musl's `Command`+`pre_exec` uses bare `fork`)
        // before `execve`ing it — allow the fork family too, or the per-tenant router dies with
        // `SIGSYS` on `fork(2)` the instant it tries to cold-start a tenant. See [`FORK_SPAWN`].
        set.extend(FORK_SPAWN.iter().copied().map(str::to_string));
        // ...and the sandbox-install syscalls: a per-tenant child is forked from THIS already-
        // confined router, so it inherits this filter and must be able to `seccomp`/`landlock_*`
        // its OWN nested (strictly tighter) profile over the inherited one. Without these the child
        // is `EPERM`'d — its seccomp install fails AND its Landlock ABI probe returns `-1` →
        // `ABI::Unsupported` → an EMPTY access set → `empty access-right`. Monotonic, so safe. See
        // [`SANDBOX_INSTALL`].
        set.extend(SANDBOX_INSTALL.iter().copied().map(str::to_string));
    }
    set.into_iter().collect()
}

/// Derive the per-instance seccomp KILL-set (hard `SECCOMP_RET_KILL_PROCESS`): the Phase-0
/// [`KILL_SURFACE`], EXCEPT that an `exec.compute` instance does NOT kill `execve`/`execveat`
/// (it re-execs the compute workers) NOR `fork`/`vfork` (it must fork the child first — see
/// [`FORK_SPAWN`]; the per-tenant router's `fork(2)` is a real, audited `SIGSYS` without this).
/// Every non-`exec.compute` instance kills the exec + fork family — the load-bearing containment
/// for a dropped execution authority. Sorted + de-duplicated.
pub fn derive_seccomp_killlist(caps: &BTreeSet<HostAuthority>) -> Vec<String> {
    let exec_spawner = holds_exec_spawn(caps);
    let set: BTreeSet<String> = KILL_SURFACE
        .iter()
        .copied()
        .filter(|s| !(exec_spawner && (EXEC_SPAWN.contains(s) || FORK_SPAWN.contains(s))))
        .map(str::to_string)
        .collect();
    set.into_iter().collect()
}

// =============================================================================
// The root supervisor's OWN self-profile (design §4.3 — the TCB floor)
// =============================================================================
//
// The privsep root (design §4) is the irreducible minimal-TCB supervisor: it resolves the
// topology, binds the privileged listeners, creates the `socketpair(2)` links, fork+execs the
// instances, then SUPERVISES for the rest of the node's life. It parses no untrusted bytes,
// opens no pool, unseals no KEK, and materializes no §1.2 key input — so it has no RCE vector
// TODAY, but its self-profile is load-bearing defence-in-depth the moment the supervisor gains
// an input surface (a health endpoint, a restart signal path). This is the TIGHTEST profile on
// the node — tighter than any instance's derived profile.
//
// It is BESPOKE (the root is the supervisor, not a `HostAuthority` instance), NOT forced through
// the per-capability [`derive_profile`]: the root holds no capability set, so its allow-set and
// Landlock view are derived directly from what the supervise code does.
//
// **Installation point (SECURITY-CRITICAL — see `boatramp::privsep::supervise`).** seccomp and
// Landlock are BOTH inherited across `fork`+`execve` and STACK as an INTERSECTION (a child can
// only ever LOSE access a parent layer dropped, never regain it). So the root MUST install this
// profile AFTER it has fork+exec'd every instance (each instance forked from an UNCONFINED root
// and installs its own, broader, per-capability profile post-exec) — installing it BEFORE the
// spawn loop would cripple every child (no `connect` for a backend, no `accept4` for a frontend,
// no `mlock` for a signer, no `data_dir`/`kek_file` in the Landlock view). The spawn loop parses
// no untrusted input, so the one-shot window before the profile installs carries no attack
// surface; the long-lived supervise loop — where the security value is — runs fully confined.

/// Networking syscalls stripped from the root supervisor's allow-set. After the root has bound
/// its listeners and created its `socketpair(2)` links (BOTH before the self-profile installs,
/// and the fd-pass to children is `dup2`-inheritance in the child's `pre_exec`, NOT an
/// `SCM_RIGHTS` `sendmsg` from the root), the supervise loop does NO network or socket I/O at all
/// — it only `wait4`s on and signals its children. So the root needs none of the socket family
/// (`bind`/`listen`/`accept`/`connect` and the send/recv/sockopt verbs), the tightening design
/// §4.3 calls for ("no network except the socketpairs/listener fds it created").
const ROOT_NET_STRIP: &[&str] = &[
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
];

/// Derive the root supervisor's seccomp ALLOW-set (design §4.3): the Phase-0 [`ALLOWED`] baseline
/// MINUS all networking ([`ROOT_NET_STRIP`]) MINUS key-locking ([`KEY_LOCK`] — the root unseals /
/// `mlock`s no key material), PLUS [`EXEC_SPAWN`] (`execve`/`execveat` stay ALLOWED — the root is
/// the long-lived supervisor whose single retained privileged primitive is re-execing
/// `boatramp __instance`; it is confined NOT by killing `execve` but by the Landlock EXECUTE-pin
/// to its own binary, see [`root_supervisor_policy`]). Everything else is `EPERM`. The result is
/// a STRICT SUBSET of `[`whole_process_allowlist`] ∪ {execve, execveat}` and contains none of
/// `bind`/`listen`/`accept`/`connect`/`mlock`. Sorted + de-duplicated.
///
/// The kept groups (process lifecycle, child wiring `dup2`/`fcntl`/`prctl`, memory, signals,
/// time/sleep, `futex`, event loops, and file-read I/O for tracing + the Landlock-governed config
/// re-read) cover the supervise loop (`wait4`/`waitid` + sleep), the fail-closed teardown
/// (`kill` + `wait4`), tracing, and the `fork`(via `clone`)+`execve`+`dup2` re-exec primitive the
/// restart path needs. The file-read group is kept because Landlock — not seccomp — is the real
/// FS wall (it confines WHICH files `open` can reach to the config file + own binary only).
pub fn root_supervisor_allowlist() -> Vec<String> {
    let strip: BTreeSet<&str> = ROOT_NET_STRIP
        .iter()
        .copied()
        .chain(KEY_LOCK.iter().copied())
        .collect();
    let mut set: BTreeSet<String> = ALLOWED
        .iter()
        .copied()
        .filter(|s| !strip.contains(s))
        .map(str::to_string)
        .collect();
    set.extend(EXEC_SPAWN.iter().copied().map(str::to_string));
    set.into_iter().collect()
}

/// Derive the root supervisor's seccomp KILL-set (hard `SECCOMP_RET_KILL_PROCESS`): the Phase-0
/// [`KILL_SURFACE`] EXCEPT `execve`/`execveat`. The root is the long-lived supervisor that
/// re-execs `boatramp __instance` (on spawn and, when wired, on restart), so killing `execve`
/// would break it; instead it is Landlock-pinned to its own binary (see [`root_supervisor_policy`])
/// — a compromised root can re-exec ONLY its own fixed, trusted path, never a shell or arbitrary
/// binary. The rest of the escape surface (`ptrace`/`mount`/`pivot_root`/`setns`/`unshare`/`bpf`/
/// the module-load + `keyctl` + `kexec` primitives, and `fork`/`vfork`) stays hard-killed. The
/// root does its boot fork+exec of every instance while still UNCONFINED (the self-profile is
/// installed AFTER that loop), so killing `fork` here does not block boot; it is defence-in-depth
/// against a post-boot RCE. NOTE: a `fork` kill is NOT inert (a `Command`+`pre_exec` spawn issues a
/// bare `fork(2)`, as the per-tenant router's audited `SIGSYS` proved) — so IF a future wired
/// root-side RESTART ever re-execs an instance AFTER the self-profile is up, it must un-kill
/// [`FORK_SPAWN`] here too (today restart is not that path; the Phase-4 WS-C per-tenant spawn forks
/// inside the exec.compute ROUTER, not the root). Sorted + de-duplicated.
pub fn root_supervisor_killlist() -> Vec<String> {
    let set: BTreeSet<String> = KILL_SURFACE
        .iter()
        .copied()
        .filter(|s| !EXEC_SPAWN.contains(s))
        .map(str::to_string)
        .collect();
    set.into_iter().collect()
}

/// The root supervisor's Landlock FS policy (design §4.3): READ on the root's OWN binary +
/// EXECUTE on it (so it can re-exec `boatramp __instance`) plus READ on the config FILE, and
/// NOTHING else. The EXECUTE right is carried on [`SandboxPolicy::execute_paths`] (the own binary
/// ALONE), NOT on the general read grant: [`linux::build_ruleset`] STRIPS `Execute` from the
/// read/write roots (which `AccessFs::from_read`/`from_all` would otherwise grant it) and
/// re-grants it only on `execute_paths` — so a compromised root can `execve` ONLY its own fixed,
/// trusted path, never the config file nor anything else readable. No §1.2 key input path (KEK /
/// signer key / overlay seed / s3ingress root / cluster root / cert key), no `data_dir`, no
/// instance state is in the FS view, so the root cannot open a crown-jewel key file even by
/// accident (design F1/F11-A). The config FILE is granted (not its parent DIR — the WS-C
/// config-file-grant lesson: a config dir containing `data_dir` would be an over-broad grant).
///
/// Both paths MUST already be made absolute + normalized by the caller (the WS-C contract:
/// [`lexically_normalize`] / `fs::canonicalize`) so the fd-based install grants the real paths.
/// `read_write_paths` is empty — the root writes nothing. The own binary appears in BOTH
/// `read_only_paths` (its read grant) and `execute_paths` (its execute grant); Landlock unions the
/// two rules to read+execute on that one path. `data_dir` here is INFORMATIONAL only (carried on
/// [`SandboxPolicy`]; [`install_derived`] grants only `read_only`/`read_write`/`execute`), set to
/// the config file so the log line reflects "the root only reads its own config".
///
/// NOTE: the EXECUTE-pin is sufficient for a STATICALLY-linked binary (the musl release build) to
/// re-exec; a dynamically-linked re-exec would additionally need the loader + shared-library paths,
/// which this profile deliberately excludes. That matters only for a future restart path (not
/// wired in Phase 1) — see `boatramp::privsep::supervise`.
pub fn root_supervisor_policy(current_exe: &Path, config_file: &Path) -> SandboxPolicy {
    SandboxPolicy {
        // Informational (not granted by `install_derived`); names the only file the root reads.
        data_dir: config_file.to_path_buf(),
        read_only_paths: vec![current_exe.to_path_buf(), config_file.to_path_buf()],
        read_write_paths: Vec::new(),
        // The execute-pin: the root re-execs its own binary (and ONLY it) — read+EXECUTE on this
        // one path, while the general read grant above no longer carries Execute.
        execute_paths: vec![current_exe.to_path_buf()],
        // The root's own TCP confinement is the seccomp `ROOT_NET_STRIP` (it does no socket I/O);
        // the Landlock net wall is the RELAY's tool, not the root's — so it is OFF here.
        deny_all_tcp: false,
    }
}

/// Derive the root supervisor's complete bespoke self-profile (design §4.3): the tight seccomp
/// allow/kill lists ([`root_supervisor_allowlist`] / [`root_supervisor_killlist`]) + the Landlock
/// policy ([`root_supervisor_policy`]). Carried as a [`DerivedProfile`] so the root installs it
/// through the SAME [`install_derived`] + [`enforce_privsep_status`] machinery every instance uses
/// (no second install mechanism); the `posture` is [`SandboxPosture::Strict`] (the root's profile
/// is categorically the tightest). `current_exe` + `config_file` MUST already be normalized.
pub fn derive_root_profile(current_exe: &Path, config_file: &Path) -> DerivedProfile {
    DerivedProfile {
        posture: SandboxPosture::Strict,
        seccomp_allow: root_supervisor_allowlist(),
        seccomp_kill: root_supervisor_killlist(),
        policy: root_supervisor_policy(current_exe, config_file),
    }
}

// =============================================================================
// The separate VM client-byte RELAY's OWN bespoke self-profile (scoped privsep VM substrate, S1 —
// owner-resolved 2026-11-14; `crates/boatramp/DESIGN-privsep-phase3-vm-scoped.md` §S1 item 1)
// =============================================================================
//
// The scoped VM substrate needs a HOST-side client-byte relay: the root binds the privileged public
// TCP listener, and a process accepts each client and splices its bytes to the frontend-in-guest over
// firecracker's vsock UDS bridge (Model A). That relay needs `accept4`/`connect`/`read`/`write` —
// which the secret-blind root's networkless TCB-floor self-profile ([`ROOT_NET_STRIP`]) forbids. The
// owner RESOLVED the placement as a SEPARATE least-authority relay process (`__vm-relay`), NOT a
// widening of the root (a relay bug, parsing untrusted client bytes, stays OUT of the root's TCB
// floor). The relay carries ONLY untrusted client bytes — NEVER key material (a scoped static-parser
// frontend holds no key; `check_vm_secret_blindness_closure` refuses any other VM shape before spawn),
// so the relay is itself secret-blind.
//
// Like the root ([`derive_root_profile`]), the relay is the supervisor's OWN non-`HostAuthority`
// process, so its profile is BESPOKE — derived directly from what the relay code does, NOT forced
// through the per-capability [`derive_profile`] — and carried as a [`DerivedProfile`] installed through
// the SAME [`install_derived`] + [`enforce_privsep_status`] machinery (no second install mechanism).
// It is the TCB-critical surface in the VM path (new least-authority code parsing untrusted bytes), so
// it is the tightest shape that still lets the relay accept+dial+splice: strictly narrower than any
// instance (no `bind`/`listen`/`socketpair`, no key-lock, `execve`/`fork` hard-killed) and, on the
// exec dimension, tighter than the root (the root retains `execve` for its re-exec primitive; the relay
// re-execs NOTHING, so `execve`/`execveat` stay denied AND killed).

/// Networking syscalls stripped from the relay's allow-set. The relay NEVER binds a listener
/// (`bind`/`listen` — the root passes the public listener pre-bound and `dup2`s the fd in) and NEVER
/// opens a `socketpair(2)` link (it holds no feature-links — unlike a host-side instance, whose
/// `local` link is a socketpair). It DOES `socket`+`connect` the firecracker vsock UDS and
/// `accept`/`accept4` clients on the inherited listener, and reads/writes/`shutdown`s both ends — so
/// this strips ONLY the listener-bind + socketpair verbs, a SUBSET of [`ROOT_NET_STRIP`] (the root
/// strips ALL networking because its supervise loop does no socket I/O; the relay is the opposite
/// shape — it is all socket I/O). [`KEY_LOCK`] is stripped too (the relay holds no key to `mlock`).
const RELAY_NET_STRIP: &[&str] = &["bind", "listen", "socketpair"];

/// Derive the separate VM client-byte relay's seccomp ALLOW-set (design §S1 item 1): the Phase-0
/// [`ALLOWED`] baseline MINUS the listener-bind + socketpair verbs ([`RELAY_NET_STRIP`]) MINUS
/// key-locking ([`KEY_LOCK`]). Unlike [`root_supervisor_allowlist`] it does NOT re-add [`EXEC_SPAWN`]
/// — the relay is `exec`'d ONCE by the root and then re-execs NOTHING, so `execve`/`execveat` stay
/// default-denied AND hard-killed (see [`relay_supervisor_killlist`]), making the relay strictly
/// tighter than the root on the exec dimension. The result keeps exactly the socket verbs the relay
/// needs (`socket`/`connect`/`accept`/`accept4`/`shutdown` + the read/write + send/recv/sockopt
/// family) and is a STRICT SUBSET of [`ALLOWED`] (it adds no syscall the monolith lacks — no `execve`
/// like the root, no sandbox-install family like `exec.compute`). Everything else is `EPERM`. Sorted +
/// de-duplicated.
pub fn relay_supervisor_allowlist() -> Vec<String> {
    let strip: BTreeSet<&str> = RELAY_NET_STRIP
        .iter()
        .copied()
        .chain(KEY_LOCK.iter().copied())
        .collect();
    let set: BTreeSet<String> = ALLOWED
        .iter()
        .copied()
        .filter(|s| !strip.contains(s))
        .map(str::to_string)
        .collect();
    set.into_iter().collect()
}

/// Derive the separate VM client-byte relay's seccomp KILL-set (hard `SECCOMP_RET_KILL_PROCESS`): the
/// FULL [`KILL_SURFACE`], `execve`/`execveat` + `fork`/`vfork` INCLUDED. The relay spawns nothing and
/// execs nothing — its per-client worker threads use `clone`/`CLONE_THREAD` (which stays allowed via
/// [`ALLOWED`]), so killing the process-creation + exec families is a real, audited `SIGSYS` wall with
/// no legitimate use to block. Neither the root's `execve` carve-out ([`root_supervisor_killlist`])
/// nor the `exec.compute` fork carve-out ([`derive_seccomp_killlist`]) applies — the relay kills the
/// whole surface, so its kill-set is a SUPERSET of every instance's. Sorted + de-duplicated.
pub fn relay_supervisor_killlist() -> Vec<String> {
    let set: BTreeSet<String> = KILL_SURFACE.iter().copied().map(str::to_string).collect();
    set.into_iter().collect()
}

/// The separate VM client-byte relay's Landlock FS policy (design §S1 item 1): READ + EXECUTE on its
/// OWN binary (the execute-pin, the SAME `current_exe` shape as [`root_supervisor_policy`] — defence
/// in depth, since `execve` is also seccomp-killed) plus READ on the DIRECTORY holding the ONE
/// firecracker vsock UDS it dials, and NOTHING else — NO config, NO `data_dir`, NO §1.2 key input, NO
/// instance state. The relay holds no backend authority, so (WS-C contract #2) there is no
/// `authority_state_dirs` to grant; the view is categorically narrower than any instance's.
///
/// **Why the UDS DIRECTORY, not the socket inode.** Landlock rules are built by O_PATH-opening the
/// granted path. The `landlock` crate cannot open a SOCKET inode on every target (on the shipped
/// static-musl build the open returns `ENXIO` → the whole per-instance Landlock layer fails to apply →
/// `install_derived` reports `Partial` → `enforce_privsep_status` REFUSES → the relay would never
/// serve). Granting the uds's PARENT DIRECTORY (a regular directory, which opens everywhere) avoids
/// that AND lets the install's O_PATH open of the IN-view grant succeed, so the relay can read exactly
/// its own vsock dir. The relay boots its guest with the UDS in a DEDICATED per-VM directory
/// ([`crate::privsep_vm`]'s `boot_firecracker`) that holds ONLY that socket, so the grant stays tight.
///
/// NOTE — the dir grant does NOT, by itself, block an OUT-of-view pathname-UDS `connect(2)`. Landlock's
/// `AccessFs` vocabulary does not mediate `connect(2)` to an `AF_UNIX` socket at all: the dir grant
/// governs the O_PATH opens the INSTALL makes, not the kernel's internal `unix_find_other()` path walk
/// that a later `connect(2)` performs. So this view is NOT the wall that stops a compromised relay from
/// pivoting to a host UDS (`/run/docker.sock`, …) — that is **settled empirically** by the
/// `relay_mount_ns_contains_pathname_uds_pivot` live gate, whose no-mount-ns mutation arm connects an
/// out-of-view host UDS SUCCESSFULLY under the netns + this dir-view alone. The pathname-UDS pivot is
/// closed instead by the relay's minimal mount-ns `pivot_root` ([`enter_minimal_mount_ns`]), layered in
/// `run_vm_relay_confined`; reaching the GUEST is governed by the hypervisor boundary + the seccomp
/// socket-verb set. The EXECUTE-pin is on the own binary ALONE: [`linux::build_ruleset`] STRIPS
/// `Execute` from the read grant and re-grants it only on `execute_paths`. `read_write_paths` is empty
/// — the relay writes no file. `current_exe` + `vsock_uds` MUST already be absolute + normalized by the
/// caller (WS-C contract #1: [`lexically_normalize`] / `fs::canonicalize`) so the fd-based install
/// grants the real paths; the uds dir is its lexical parent.
///
/// **F1 — deny ALL TCP via Landlock `AccessNet`.** [`SandboxPolicy::deny_all_tcp`] is `true` ONLY on
/// the relay: `AccessFs` does not govern network ops, so the FS view alone does not stop the relay
/// (which legitimately holds `socket`/`connect` in its seccomp set to dial the vsock UDS) from
/// `connect`-ing to an arbitrary TCP endpoint. Handling `AccessNet` with zero `NetPort` allow-rules
/// walls off every TCP bind + connect while leaving the AF_UNIX vsock dial (not an `AccessNet`
/// subject) untouched. See the field doc on [`SandboxPolicy::deny_all_tcp`] and
/// [`linux::build_ruleset`] for the fail-closed sub-V4 behaviour. (netns is the LOAD-BEARING egress
/// wall — see [`enter_empty_netns`]; this AccessNet wall + the seccomp set are defence-in-depth.)
pub fn relay_supervisor_policy(current_exe: &Path, vsock_uds: &Path) -> SandboxPolicy {
    // Grant the uds's DIRECTORY (a regular dir opens on every target; a socket inode does not — ENXIO
    // on static-musl). The parent is the relay's dedicated per-VM vsock dir, holding only this socket.
    let uds_dir = vsock_uds
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| vsock_uds.to_path_buf());
    SandboxPolicy {
        // Informational (not granted by `install_derived`); names the one path the relay dials.
        data_dir: vsock_uds.to_path_buf(),
        read_only_paths: vec![current_exe.to_path_buf(), uds_dir],
        read_write_paths: Vec::new(),
        execute_paths: vec![current_exe.to_path_buf()],
        // F1: the relay's ONLY legitimate dial is the AF_UNIX vsock UDS (NOT an AccessNet subject);
        // wall off ALL TCP bind + connect so a compromised relay cannot reach the network. This is
        // the ONE profile that sets it (strict no-op everywhere else).
        deny_all_tcp: true,
    }
}

/// Derive the separate VM client-byte relay's complete bespoke self-profile (design §S1 item 1): the
/// tight seccomp allow/kill lists ([`relay_supervisor_allowlist`] / [`relay_supervisor_killlist`]) +
/// the Landlock policy ([`relay_supervisor_policy`]). Carried as a [`DerivedProfile`] so the relay
/// installs it through the SAME [`install_derived`] + [`enforce_privsep_status`] machinery every
/// instance (and the root) uses (no second install mechanism); the `posture` is
/// [`SandboxPosture::Strict`] (categorically the tightest). `current_exe` + `vsock_uds` MUST already be
/// normalized.
pub fn derive_relay_profile(current_exe: &Path, vsock_uds: &Path) -> DerivedProfile {
    DerivedProfile {
        posture: SandboxPosture::Strict,
        seccomp_allow: relay_supervisor_allowlist(),
        seccomp_kill: relay_supervisor_killlist(),
        policy: relay_supervisor_policy(current_exe, vsock_uds),
    }
}

// =============================================================================
// The VM relay's EGRESS CONTAINMENT — an empty network namespace (MED-1) + an
// explicit capability-bounding-set drop (INFO). Scoped privsep VM substrate, S1
// follow-ups from the F1/F2 Security review (2026-11-18).
// =============================================================================
//
// F1 (the relay's Landlock `AccessNet` deny-all-TCP wall — [`relay_supervisor_policy`]) governs ONLY
// TCP bind/connect. It leaves **UDP** egress (`socket(AF_INET, SOCK_DGRAM)` + `sendto`) open — and the
// relay's seccomp set legitimately KEEPS `socket`/`sendto`/`connect` (it dials the AF_UNIX vsock UDS
// and reads/writes both ends), filtering by NAME only, not by the socket's domain argument. So a
// compromised relay could exfiltrate the spliced client byte-stream (or C2 / pivot to an internal
// service) over UDP (MED-1), and could open a raw/packet socket if it held `CAP_NET_RAW` (INFO).
//
// The robust containment (Security reviewer's recommendation; the strongest primitive) is to run the
// **netless** relay in a FRESH, EMPTY network namespace: no interfaces, loopback-only (and `lo` DOWN),
// no route anywhere — which closes UDP **and** TCP **and** raw/packet **and** abstract-namespace-UDS
// egress in one move, with no route to 169.254.169.254 at all. The **pathname** AF_UNIX vsock UDS
// still dials (AF_UNIX pathname sockets are NOT netns-scoped), and the inherited, root-netns-bound
// public TCP listener still `accept`s (a socket keeps the netns it was CREATED in). The netns is the
// PRIMARY egress wall; F1's Landlock-TCP wall + the relay seccomp set stay ON as defence-in-depth
// layers UNDER it (layered sandboxing, not a duplicate path).
//
// These two primitives are the one place that setup lives; the relay
// ([`crate::privsep::run_vm_relay_confined`], in the `boatramp` crate) and its Linux live gate BOTH
// call them, so the production path and the gate can never drift.

/// Compute the inclusive `[lo, hi]` file-descriptor ranges to close so that ONLY the fds in `keep`
/// (plus the three standard streams 0/1/2, which carry the relay's tracing to stderr) survive. The
/// ranges are the gaps BELOW, BETWEEN, and ABOVE the kept fds; the final range runs up to `u32::MAX`
/// (`~0`) so that EVERY higher fd is foreclosed. Negative `keep` entries (an absent optional fd) are
/// ignored. Pure + host-testable — the syscall application is [`close_inherited_fds_except`]; this
/// split keeps the gap arithmetic unit-testable without actually closing the test harness's own fds.
#[cfg(target_os = "linux")]
pub(crate) fn fd_close_ranges(keep: &[i32]) -> Vec<(u32, u32)> {
    let mut kept: Vec<u32> = keep
        .iter()
        .copied()
        .filter(|&f| f >= 0)
        .map(|f| f as u32)
        .collect();
    // The three standard streams are ALWAYS preserved.
    kept.extend_from_slice(&[0, 1, 2]);
    kept.sort_unstable();
    kept.dedup();
    let mut ranges = Vec::new();
    let mut lo: u32 = 0;
    for k in kept {
        if k > lo {
            ranges.push((lo, k - 1));
        }
        // Advance past this kept fd; if it is the maximum fd, nothing higher remains to close.
        match k.checked_add(1) {
            Some(next) => lo = next,
            None => return ranges,
        }
    }
    ranges.push((lo, u32::MAX));
    ranges
}

/// Close EVERY inherited file descriptor except the three standard streams (0/1/2) and the ones in
/// `keep`, via `close_range(2)`. The VM relay calls this FIRST — right after the `__vm-relay`
/// re-exec, BEFORE it enters any namespace — so that no stray host fd (a **directory** fd in
/// particular, which an `fchdir`/`openat` could pivot through to escape the minimal mount-ns root)
/// survives CLOEXEC discipline + the re-exec into the confined relay. `keep` MUST list exactly the
/// fds the root deliberately handed the relay ([`crate::privsep`-side `PrivsepChildFds`] — the
/// pre-bound listener + any link fds); those are adopted LATER (the relay `accept`s the listener), so
/// closing them would break it. Fail-closed: a `close_range` error returns `Err` and the relay then
/// refuses to serve (never relay a client byte with a leaked host fd still open).
#[cfg(target_os = "linux")]
pub fn close_inherited_fds_except(keep: &[i32]) -> std::io::Result<()> {
    for (lo, hi) in fd_close_ranges(keep) {
        // SAFETY: `close_range(2)` takes three scalars + no pointers. It closes the OPEN fds in the
        // inclusive range [lo, hi], silently skipping fd numbers that are not open, and returns 0 on
        // success. `flags = 0` actually closes them (not CLOSE_RANGE_CLOEXEC).
        let rc = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                lo as libc::c_uint,
                hi as libc::c_uint,
                0 as libc::c_uint,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::other(format!(
                "close_range({lo}, {hi}) foreclosing stray inherited relay fds failed: {} — refusing \
                 fail-closed (a leaked host fd must not survive into the client-byte relay)",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// Move the calling process into a FRESH, EMPTY (loopback-only) network namespace and VERIFY it is
/// empty, fail-closed. The VM relay's PRIMARY egress containment (MED-1); see the section comment.
///
/// **Why netns is load-bearing, not Landlock `AccessNet` (F1).** F1's `AccessNet` net hook can be
/// SILENTLY non-enforced on a kernel that REPORTS supporting it (observed on a virtualized CI runner:
/// Landlock's FS hook enforces but the net hook is a no-op, and `restrict_self` still reports success).
/// An empty network namespace contains egress by a different mechanism — there is simply NO route /
/// interface, so every `connect`/`sendto` fails `ENETUNREACH` — which does NOT depend on any LSM hook
/// actually firing. So netns is the correctness wall; F1 + the relay seccomp set are defence-in-depth.
///
/// **Privilege (two paths; the production relay only ever takes the first).** The preferred path is a
/// userns-FREE `unshare(CLONE_NEWNET)`, which needs `CAP_SYS_ADMIN` — the SAME userns-free model the
/// Container substrate's `unshare(NS/IPC/UTS/CGROUP)` uses. The relay is `fork`+`exec`'d by the
/// privileged root and INHERITS `CAP_SYS_ADMIN`, so it ALWAYS takes this path and NEVER adds a user
/// namespace; it uses the capability ONCE here, then drops ALL capabilities ([`drop_all_capabilities`])
/// before installing its profile / touching a client byte. Only an UNPRIVILEGED caller (never the
/// production relay — e.g. the CI live gate on an unprivileged runner, or a rootless node) falls back
/// to `unshare(CLONE_NEWUSER | CLONE_NEWNET)`, which obtains the SAME empty, loopback-only netns
/// (the user namespace is merely the unprivileged *mechanism* to unshare the netns; it is mapped back
/// to the real uid so file access is unchanged). Both paths yield an egress-equivalent netns and are
/// VERIFIED loopback-only. Fail-closed: if NEITHER can enter an empty netns, return `Err` — the relay
/// then REFUSES to serve (never a silent fall-back to a full-network relay).
///
/// **Ordering (load-bearing).** Call this BEFORE installing the relay's seccomp profile: the profile
/// hard-KILLS `unshare`/`setns` (they are in [`KILL_SURFACE`]), so once the wall is up the relay can
/// never (re-)enter or leave a namespace — this is the pre-profile window, and the only one. The
/// inherited listener fd is adopted (`accept`ed) and the vsock UDS is dialed AFTER this, from inside
/// the empty netns.
#[cfg(target_os = "linux")]
pub fn enter_empty_netns() -> std::io::Result<()> {
    // Preferred, userns-FREE path (the production relay's path — it holds CAP_SYS_ADMIN from the root).
    // SAFETY: `unshare(2)` with a scalar flag takes no pointers; it creates a new network namespace for
    // THIS process and makes it the caller's immediately (no fork needed — unlike CLONE_NEWPID).
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0 {
        // Fail-closed VERIFY: a freshly unshared netns must be loopback-only. If anything else is
        // present (impossible absent a kernel bug), REFUSE rather than serve with a route.
        return verify_netns_loopback_only();
    }
    let privileged_err = std::io::Error::last_os_error();
    // Fallback for an UNPRIVILEGED caller (never the production relay): a user namespace grants
    // CAP_SYS_ADMIN *within* the new userns, permitting the simultaneous netns unshare.
    enter_empty_netns_via_userns().map_err(|fallback_err| {
        std::io::Error::other(format!(
            "could not enter an empty network namespace for the relay's egress wall: the userns-free \
             unshare(CLONE_NEWNET) failed ({privileged_err}) AND the unprivileged userns+netns fallback \
             failed ({fallback_err}) — refusing fail-closed (a relay never serves with a full network)"
        ))
    })
}

/// The unprivileged fallback for [`enter_empty_netns`]: enter a new user namespace + net namespace
/// together (CLONE_NEWUSER makes the simultaneous CLONE_NEWNET permitted without host `CAP_SYS_ADMIN`),
/// then map userns-root back to the real uid/gid so file access (the Landlock execute-pin's `PathFd`
/// opens, even under a `0700` home) is unchanged. The resulting netns is egress-equivalent to the
/// userns-free one. NEVER reached by the production relay (which is root). Fail-closed on any step.
#[cfg(target_os = "linux")]
fn enter_empty_netns_via_userns() -> std::io::Result<()> {
    // Capture the real ids BEFORE the unshare — they become the single-id map targets.
    // SAFETY: geteuid/getegid take no args and cannot fail.
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    // SAFETY: `unshare(2)` with scalar flags, no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // `setgroups=deny` is required before an unprivileged `gid_map` write; then map userns id 0 → the
    // real uid/gid (a single-id self-map, always permitted to the userns creator).
    std::fs::write("/proc/self/setgroups", "deny")?;
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1"))?;
    verify_netns_loopback_only()
}

/// Confirm the current network namespace is EMPTY: its ONLY interface is loopback (`lo`). Used to
/// fail-closed after [`enter_empty_netns`] — proof the netns is truly empty / loopback-only (the
/// property the Security review asks us to assert, not assume).
#[cfg(target_os = "linux")]
fn verify_netns_loopback_only() -> std::io::Result<()> {
    // SAFETY: `if_nameindex()` returns an owned, NUL-terminated (if_index==0 && if_name==null) array
    // that we free with `if_freenameindex`; we only read its entries.
    let list = unsafe { libc::if_nameindex() };
    if list.is_null() {
        return Err(std::io::Error::other(format!(
            "if_nameindex() failed while verifying the relay's empty netns is loopback-only: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut non_loopback: Vec<String> = Vec::new();
    // SAFETY: walk the array until the terminating zero entry; each `if_name` is a valid C string.
    let mut p = list;
    unsafe {
        while (*p).if_index != 0 || !(*p).if_name.is_null() {
            if (*p).if_name.is_null() {
                break;
            }
            let name = std::ffi::CStr::from_ptr((*p).if_name)
                .to_string_lossy()
                .into_owned();
            if name != "lo" {
                non_loopback.push(name);
            }
            p = p.add(1);
        }
        libc::if_freenameindex(list);
    }
    if non_loopback.is_empty() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "the relay's network namespace is NOT empty: it exposes interface(s) {non_loopback:?} \
             besides loopback — refusing fail-closed (the egress wall assumes a loopback-only netns)"
        )))
    }
}

/// Harden the calling process's capabilities against RE-acquisition, fail-closed on the load-bearing
/// step: set `SECBIT_NOROOT` (+`_LOCKED`) so uid 0 gains NO capability at the next `execve`, EMPTY the
/// capability BOUNDING set (every cap 0..=63, so `CAP_NET_RAW` — raw/packet sockets — and
/// `CAP_SYS_ADMIN` cannot be regained via a file-capability `execve`), and CLEAR the ambient set.
///
/// **This does NOT drop the running thread's EFFECTIVE/PERMITTED caps** — `prctl` cannot. A privsep
/// INSTANCE relies on the `execve` that FOLLOWS its `pre_exec`: with `SECBIT_NOROOT` + an empty bounding
/// set, the post-`execve` process gets ZERO caps (the container gate's Finding-2 probe confirms this).
/// A caller that does NOT `execve` (the VM relay) MUST additionally call [`clear_current_capabilities`]
/// to drop the effective/permitted sets in-process.
///
/// Mechanism is `prctl`-only here (so it stays async-signal-safe and callable from a `pre_exec`
/// closure, and needs no `capset` which a per-tenant child's router-seccomp filter would `EPERM`).
/// Returns `Err` ONLY if `PR_SET_SECUREBITS` fails (the load-bearing bit); the bounding-set + ambient
/// ops are best-effort (a high cap number `EINVAL`s on an older kernel — harmless). The ONE such
/// sequence: both the relay ([`crate::privsep::run_vm_relay_confined`]) and every privsep instance
/// (`spawn_wired_instance`'s `pre_exec`) call it (consolidated). A caller that still needs a capability
/// (e.g. the relay's own `unshare`) MUST have used it BEFORE calling this (`PR_CAPBSET_DROP` /
/// `PR_SET_SECUREBITS` themselves need `CAP_SETPCAP`, still held here).
#[cfg(target_os = "linux")]
pub fn drop_all_capabilities() -> std::io::Result<()> {
    // `SECBIT_NOROOT` makes uid 0 no longer special at execve; `_LOCKED` prevents it being cleared.
    const SECBIT_NOROOT: libc::c_ulong = 1 << 0;
    const SECBIT_NOROOT_LOCKED: libc::c_ulong = 1 << 1;
    // SAFETY: `prctl` with scalar args only (no pointers).
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECUREBITS,
            SECBIT_NOROOT | SECBIT_NOROOT_LOCKED,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    // Empty the capability BOUNDING set (best-effort: a cap number the kernel doesn't know `EINVAL`s).
    let mut cap: libc::c_ulong = 0;
    while cap <= 63 {
        // SAFETY: `prctl(PR_CAPBSET_DROP, cap, …)` — scalar args, no pointers.
        unsafe {
            libc::prctl(
                libc::PR_CAPBSET_DROP,
                cap,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            );
        }
        cap += 1;
    }
    // Clear the ambient set (ambient caps otherwise survive execve).
    // SAFETY: `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, …)` — scalar args, no pointers.
    unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        );
    }
    Ok(())
}

/// Clear the calling thread's EFFECTIVE, PERMITTED and INHERITABLE capability sets IN-PROCESS via
/// `capset(2)` — the drop the VM relay needs because, unlike a privsep instance, it does NOT `execve`
/// after dropping privileges, so [`drop_all_capabilities`]' `prctl` securebits/bounding (which only
/// gate RE-acquisition at the next `execve`) would otherwise leave the relay serving with its full
/// inherited root caps (incl. `CAP_SYS_ADMIN`/`CAP_NET_RAW`). Call it AFTER [`drop_all_capabilities`]
/// (whose `PR_SET_SECUREBITS` / `PR_CAPBSET_DROP` need `CAP_SETPCAP`, still held at that point) and
/// BEFORE installing the relay's seccomp profile (so `capset` is not yet filtered) — but AFTER the
/// relay's one privileged op (`unshare(CLONE_NEWNET)`). Reducing one's OWN capability sets needs no
/// privilege. Fail-closed on error.
#[cfg(target_os = "linux")]
pub fn clear_current_capabilities() -> std::io::Result<()> {
    // The `capset(2)` ABI structs (the libc crate does not re-export them by name, so declare them —
    // this is the stable kernel ABI). Header + two 32-bit data words = the 64-bit v3 layout.
    #[repr(C)]
    struct CapUserHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapUserData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    // `_LINUX_CAPABILITY_VERSION_3`: 64-bit caps, carried as two 32-bit data words.
    const CAP_VERSION_3: u32 = 0x2008_0522;
    let hdr = CapUserHeader {
        version: CAP_VERSION_3,
        pid: 0, // 0 == the calling thread
    };
    let data = [
        CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    // SAFETY: `capset(2)` with a valid v3 header + the required 2-element data array; all-zero sets are
    // a pure capability DROP (always permitted on one's own thread), no pointers escape the call.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &hdr as *const CapUserHeader,
            data.as_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::other(format!(
            "capset(clear all capability sets) failed: {} — the relay refuses to serve with \
             undropped effective capabilities",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Mark the calling process NON-dumpable (`prctl(PR_SET_DUMPABLE, 0)`) — the HIGH-1 (final privsep
/// Security re-review) cross-instance memory-disclosure wall for the SAME-KERNEL instance substrates
/// (`OsProcess` + the Container "simple model"). All instances run as the same node uid at euid 0
/// (capability-reduced only) in the SHARED host pid namespace, so a compromised frontend instance
/// (`listen.http-parse`) could otherwise `openat("/proc/<signer-pid>/mem")` + `pread64` a crown-jewel
/// `secrets.sealer` / `token.signer` key straight out of a holder's mlocked address space. That read is
/// a pure VFS access — it issues NO `ptrace`/`process_vm_readv` syscall, so the seccomp KILL on those
/// verbs never fires, and the `/proc` read grant + `openat`/`pread64` are allowed. Setting the TARGET
/// non-dumpable makes the kernel reparent its `/proc/<pid>/{mem,maps,environ,pagemap,…}` to root:root
/// and gates access behind `ptrace_may_access`, which — for a non-dumpable target — demands
/// `CAP_SYS_PTRACE` in the target's user namespace. A capless sibling has none, so it gets `EPERM`
/// REGARDLESS of `kernel.yama.ptrace_scope` (this does not rely on Yama being present/configured).
///
/// **MUST be called POST-`execve`, in the served process itself — NOT from a `pre_exec` closure.** A
/// non-privilege-elevating `execve` RESETS the dumpable flag to `SUID_DUMP_USER` (1): the kernel's
/// `begin_new_exec` runs `set_dumpable(mm, SUID_DUMP_USER)` on any non-`secureexec` (non-setuid /
/// no-gained-file-caps) exec, so a value set before the re-exec would be silently clobbered by the exec
/// that follows. Our instance / relay re-exec is non-setuid with no file capabilities (confirmed by the
/// reviewer), so once set HERE — after the exec, in `run_instance` / `run_vm_relay_confined` — it
/// persists for the process's life (the serving path performs no further `execve`). This is WHY the
/// dumpable step is deliberately NOT consolidated into `spawn_wired_instance`'s `pre_exec` next to the
/// Finding-2 capability drop (whose `SECBIT_NOROOT` is the OPPOSITE case — it MUST precede the execve to
/// take effect at it): the two hardening steps have opposite exec-ordering requirements.
///
/// `prctl(PR_SET_DUMPABLE, …)` needs NO capability, so this works for a capless per-tenant child exactly
/// as for a full-cap boot child. Own-process access is UNAFFECTED: the kernel short-circuits
/// `ptrace_may_access` for a same-thread-group caller, so this process keeps full access to its OWN
/// `/proc/self/*` — the Container `/proc/self/ns` self-check and every `/proc/self/fd/N` magic symlink
/// still resolve. Load-bearing for HIGH-1, so callers treat a failure as fail-closed (refuse to serve).
#[cfg(target_os = "linux")]
pub fn set_process_undumpable() -> std::io::Result<()> {
    // SAFETY: `prctl(PR_SET_DUMPABLE, 0, …)` — scalar args only, no pointers; async-signal-safe. Sets
    // this process's mm dumpable flag to SUID_DUMP_DISABLE (0).
    if unsafe {
        libc::prctl(
            libc::PR_SET_DUMPABLE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Enter a fresh MOUNT namespace and `pivot_root` into a minimal, private tmpfs root that holds ONLY
/// the relay's own binary (for the Landlock execute-pin's O_PATH open) and its one vsock-UDS directory
/// (to dial the frontend-in-guest), each bind-mounted back at its REAL absolute path. Every OTHER
/// filesystem path — in particular every host **pathname** `AF_UNIX` socket a compromised relay could
/// pivot to (`/run/docker.sock`, `/run/dbus/system_bus_socket`, `/run/systemd/private`, a
/// `/var/lib/<svc>/*.sock`, `/tmp/.X11-unix/X0`, …) — ceases to resolve, so a `connect(2)` to it fails
/// `ENOENT`. The VM relay's PATHNAME-UDS egress containment (INFO-1); see below.
///
/// **Why this is needed on TOP of the empty netns + the Landlock dir-view.** The empty netns
/// ([`enter_empty_netns`]) closes every IP egress and every ABSTRACT-namespace `AF_UNIX` socket, but a
/// **pathname** `AF_UNIX` socket is NOT netns-scoped — `connect(2)` to a host UDS still resolves through
/// the shared mount tree. And Landlock's `AccessFs` vocabulary does NOT mediate `connect(2)` to an
/// `AF_UNIX` socket: the relay's directory grant governs the O_PATH opens the profile INSTALL makes, not
/// the kernel's internal `unix_find_other()` path walk that `connect(2)` performs. That the narrow
/// dir-view does NOT by itself block an out-of-view pathname-UDS `connect(2)` is settled EMPIRICALLY by
/// the `relay_mount_ns_contains_pathname_uds_pivot` live gate (its no-mount-ns mutation arm connects an
/// out-of-view host UDS successfully). A private mount namespace whose root contains nothing but the two
/// paths the relay legitimately touches removes the host-UDS paths entirely — the robust wall, by a
/// different mechanism than the netns (no LSM hook, no route), layered under both.
///
/// **Ordering / privilege (load-bearing).** `unshare(CLONE_NEWNS)` + `mount` + `pivot_root` all need
/// `CAP_SYS_ADMIN`, which the production relay inherits from the privileged root; call this in the SAME
/// pre-profile window as [`enter_empty_netns`], BEFORE [`drop_all_capabilities`] /
/// [`clear_current_capabilities`] / the profile install (the relay's Enforced profile hard-KILLs
/// `unshare`/`mount`/`pivot_root` — they are in [`KILL_SURFACE`]). The relay then drops ALL capabilities
/// and installs its profile from INSIDE this minimal root (so the install's O_PATH opens of
/// `own_binary` + `vsock_dir` resolve to the bind-mounts here). Fail-closed: ANY step failing returns
/// `Err` and the relay REFUSES to serve — never a fallback to the full host mount tree.
///
/// `own_binary` + `vsock_dir` MUST be absolute + normalized by the caller (the SAME WS-C contract #1
/// paths the relay's Landlock policy grants — [`relay_supervisor_policy`]'s own binary + the uds's
/// parent dir), so the binds land at the exact paths the install opens and the dial resolves. Reuses the
/// `boatramp-container` worker's mount-ns + `pivot_root` idiom (one namespace model, not a second).
///
/// **Staging root + bind mechanics (hardening).** The fresh tmpfs new-root is overmounted on a DEDICATED
/// staging mountpoint the relay controls (the vsock-dir's parent, in the relay's own runtime area), NOT
/// on the shared `/tmp`; and the two real paths are bound from O_PATH fds opened BEFORE that overmount
/// (through their `/proc/self/fd/N` magic symlinks). So the minimal root's correctness does not couple to
/// WHERE the own-binary / vsock-dir live (the old `/tmp` overmount silently assumed neither was under
/// `/tmp`), and nothing is written to any host-shared filesystem. The own-binary bind is additionally
/// remounted `MS_RDONLY` at the mount layer (defence-in-depth over the Landlock + `execve`-seccomp block).
#[cfg(target_os = "linux")]
pub fn enter_minimal_mount_ns(own_binary: &Path, vsock_dir: &Path) -> std::io::Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    fn cstr(p: &Path) -> std::io::Result<std::ffi::CString> {
        std::ffi::CString::new(p.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::other("a relay mount path contains an interior NUL byte"))
    }
    // One thin wrapper over `mount(2)`; `src`/`data` may be empty C-strings where the call ignores them.
    fn do_mount(
        src: &std::ffi::CStr,
        target: &std::ffi::CStr,
        fstype: Option<&std::ffi::CStr>,
        flags: libc::c_ulong,
        data: Option<&std::ffi::CStr>,
        what: &str,
    ) -> std::io::Result<()> {
        // SAFETY: all pointers are valid NUL-terminated C-strings (or NULL where unused); `mount(2)`
        // reads them and returns a status — no pointer escapes.
        let rc = unsafe {
            libc::mount(
                src.as_ptr(),
                target.as_ptr(),
                fstype.map_or(std::ptr::null(), std::ffi::CStr::as_ptr),
                flags,
                data.map_or(std::ptr::null(), |d| d.as_ptr().cast()),
            )
        };
        if rc != 0 {
            return Err(std::io::Error::other(format!(
                "mount({what}) building the relay's minimal root failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }
    // O_PATH-open a bind source so it can later be bound from its `/proc/self/fd/N` magic symlink,
    // which resolves to the real inode even once the staging overmount hides the path — decoupling the
    // bind from WHERE the source lives. O_PATH yields a resolve-only handle (no read/write authority).
    fn open_opath(p: &Path) -> std::io::Result<std::os::fd::OwnedFd> {
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::other("a relay bind path contains an interior NUL byte")
        })?;
        // SAFETY: `open(2)` with a valid NUL-terminated path + scalar flags; returns a fd or -1.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::other(format!(
                "O_PATH-opening the relay bind source {} failed: {}",
                p.display(),
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `fd` is a fresh, exclusively-owned descriptor.
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
    }
    // Bind the real inode behind `src_fd` into `newroot` at `real_src`'s SAME absolute path (creating
    // the target), via the fd's `/proc/self/fd/N` magic symlink so a path the staging overmount hid
    // still resolves. `read_only` additionally remounts the bind READ-ONLY at the mount layer.
    fn bind_fd_into_root(
        newroot: &Path,
        src_fd: std::os::fd::RawFd,
        real_src: &Path,
        is_dir: bool,
        read_only: bool,
    ) -> std::io::Result<()> {
        let rel = real_src
            .strip_prefix("/")
            .map_err(|_| std::io::Error::other("a relay bind source is not absolute"))?;
        let target = newroot.join(rel);
        if is_dir {
            std::fs::create_dir_all(&target).map_err(|e| {
                std::io::Error::other(format!("creating a relay bind-dir target: {e}"))
            })?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    std::io::Error::other(format!(
                        "creating a relay bind-file target's parent: {e}"
                    ))
                })?;
            }
            std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&target)
                .map_err(|e| {
                    std::io::Error::other(format!("creating a relay bind-file target: {e}"))
                })?;
        }
        let src_c = std::ffi::CString::new(format!("/proc/self/fd/{src_fd}"))
            .map_err(|_| std::io::Error::other("a /proc/self/fd path contains an interior NUL"))?;
        let target_c = cstr(&target)?;
        let flags = libc::MS_BIND | if is_dir { libc::MS_REC } else { 0 };
        do_mount(&src_c, &target_c, None, flags, None, "bind")?;
        // Nit (b): remount the own-binary bind READ-ONLY at the mount layer (defence-in-depth — write is
        // already Landlock- + `execve`-seccomp-blocked). The source is ignored on an `MS_REMOUNT`.
        // Fail-closed: if the RO remount does not take, REFUSE (never serve with a writable own-binary).
        if read_only {
            let ignored = std::ffi::CString::new("none").expect("no interior NUL");
            do_mount(
                &ignored,
                &target_c,
                None,
                libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
                None,
                "ro-remount",
            )?;
        }
        Ok(())
    }

    // A relative/empty grant path would bind the WRONG inode — refuse fail-closed.
    if !own_binary.is_absolute() || !vsock_dir.is_absolute() {
        return Err(std::io::Error::other(
            "the relay's own-binary + vsock-dir paths must be absolute to build its minimal mount-ns root",
        ));
    }

    let empty = std::ffi::CString::new("").expect("no interior NUL in an empty string");
    let slash = cstr(Path::new("/"))?;
    let tmpfs = std::ffi::CString::new("tmpfs").expect("no interior NUL");

    // (1) New mount namespace — the relay's mount tree becomes private to it.
    // SAFETY: `unshare(2)` with a scalar flag takes no pointers.
    if unsafe { libc::unshare(libc::CLONE_NEWNS) } != 0 {
        return Err(std::io::Error::other(format!(
            "unshare(CLONE_NEWNS) for the relay's minimal mount root failed: {} (needs CAP_SYS_ADMIN, \
             held in the pre-cap-drop window)",
            std::io::Error::last_os_error()
        )));
    }
    // (2) Make the whole tree recursively PRIVATE so our mounts don't propagate to the host (a
    //     `pivot_root` precondition, and it keeps the overmount from leaking).
    do_mount(
        &empty,
        &slash,
        None,
        libc::MS_REC | libc::MS_PRIVATE,
        None,
        "make-rprivate",
    )?;

    // (3) Open O_PATH handles to the two real paths NOW, on the full tree, BEFORE the staging overmount
    //     below. Each path is bound into the new root through its `/proc/self/fd/N` magic symlink, which
    //     resolves to the real inode even once the overmount hides the path — so the minimal root's
    //     correctness no longer couples to WHERE the own-binary / vsock-dir live (the previous `/tmp`
    //     overmount silently assumed neither was under `/tmp`). Fail-closed on either open.
    let exe_fd = open_opath(own_binary)?;
    let dir_fd = open_opath(vsock_dir)?;

    // (4) A fresh, PRIVATE `MS_NOSUID|MS_NODEV` tmpfs to be the new root, overmounted on a DEDICATED
    //     staging mountpoint the relay controls: the vsock-dir's PARENT. It is guaranteed to exist (the
    //     vsock dir does), it is the relay's OWN runtime area (not the shared, world-writable `/tmp`),
    //     and — because the two real paths are bound from the O_PATH fds above — hiding its subtree
    //     cannot break the binds (no path-collision coupling). Step (2) made the tree rprivate, so the
    //     overmount does NOT propagate to the host, and everything created below lands on this ephemeral
    //     tmpfs, so nothing is written to any host-shared filesystem (no leaked staging dir). After
    //     `pivot_root` this tmpfs IS `/`; it and everything on it vanish with the ns. Fail-closed if
    //     there is no suitable parent to anchor it.
    let new_root = vsock_dir.parent().ok_or_else(|| {
        std::io::Error::other(
            "the relay's vsock dir has no parent to anchor its private staging root — refusing fail-closed",
        )
    })?;
    if new_root == Path::new("/") || new_root.as_os_str().is_empty() {
        return Err(std::io::Error::other(
            "refusing `/` (or an empty path) as the relay's staging mountpoint — pivot_root needs a \
             non-root new_root carved from the relay's own runtime area",
        ));
    }
    let new_root_c = cstr(new_root)?;
    let tmpfs_opts =
        std::ffi::CString::new("mode=0700,size=1m,nr_inodes=4k").expect("no interior NUL");
    do_mount(
        &tmpfs,
        &new_root_c,
        Some(&tmpfs),
        libc::MS_NOSUID | libc::MS_NODEV,
        Some(&tmpfs_opts),
        "tmpfs-newroot",
    )?;

    // (5) Bind the ONLY two paths the relay needs into the new root at their REAL absolute paths, from
    //     the O_PATH fds (so a path the overmount hid still binds): the own binary (a FILE — the
    //     execute-pin O_PATH grant, remounted READ-ONLY, nit (b)) and the vsock-UDS directory (a DIR —
    //     the RO grant plus the one socket it dials, left writable as the relay dials it). The binds +
    //     put_old land on the fresh tmpfs, consuming no shared-fs storage.
    bind_fd_into_root(new_root, exe_fd.as_raw_fd(), own_binary, false, true)?;
    bind_fd_into_root(new_root, dir_fd.as_raw_fd(), vsock_dir, true, false)?;
    // The O_PATH handles have served their purpose; drop them BEFORE the pivot — a lingering directory
    // O_PATH fd is itself `fchdir`-able, exactly the leaked-dir-fd surface the relay otherwise forecloses.
    drop(exe_fd);
    drop(dir_fd);

    // (6) pivot_root: new_root becomes `/`, the old root moves to new_root/.put_old; then detach it so
    //     the host tree (and every host UDS path) is unreachable from the relay.
    let put_old = new_root.join(".put_old");
    std::fs::create_dir_all(&put_old)
        .map_err(|e| std::io::Error::other(format!("creating the relay pivot put_old dir: {e}")))?;
    let put_old_c = cstr(&put_old)?;
    // SAFETY: `pivot_root(2)` with two valid NUL-terminated absolute directory paths; new_root is a
    // fresh tmpfs mount point and put_old lives beneath it (the syscall's preconditions).
    if unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            new_root_c.as_ptr(),
            put_old_c.as_ptr(),
        )
    } != 0
    {
        return Err(std::io::Error::other(format!(
            "pivot_root into the relay's minimal root failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `chdir("/")` repoints cwd at the new root (an fd on the old cwd would otherwise pin it).
    if unsafe { libc::chdir(slash.as_ptr()) } != 0 {
        return Err(std::io::Error::other(format!(
            "chdir(/) after the relay pivot_root failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // Detach the old root (now at `/.put_old`) lazily — fail-closed: the host tree must NOT remain
    // reachable. `MNT_DETACH` succeeds even with the cwd/root fds just repointed.
    let put_old_after = cstr(Path::new("/.put_old"))?;
    // SAFETY: `umount2(2)` with `MNT_DETACH` on the old-root mount point.
    if unsafe { libc::umount2(put_old_after.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(std::io::Error::other(format!(
            "detaching the old root after the relay pivot_root failed: {} — refusing (the host mount \
             tree, and every host UDS path on it, must not remain reachable)",
            std::io::Error::last_os_error()
        )));
    }
    let _ = std::fs::remove_dir(Path::new("/.put_old"));

    // VERIFY fail-closed: the two paths the relay legitimately needs must still resolve inside the
    // minimal root (a bind that silently did not take would otherwise surface only as a later serve
    // failure). The CONTAINMENT itself is structural (`pivot_root` + the detach of the old root).
    if !own_binary.exists() {
        return Err(std::io::Error::other(
            "after the relay pivot_root its own-binary execute-pin path does not resolve in the \
             minimal root — refusing fail-closed",
        ));
    }
    if !vsock_dir.exists() {
        return Err(std::io::Error::other(
            "after the relay pivot_root its vsock-UDS directory does not resolve in the minimal root \
             — refusing fail-closed (the guest dial would break)",
        ));
    }
    Ok(())
}

/// The access an instance's held crown-jewel key path needs under Landlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAccess {
    /// Read-only (a signer/HKDF root the instance only reads).
    ReadOnly,
    /// Read + write (the `secrets.sealer` KEK, which the signer instance also generates
    /// `0600` on first run — design §2 step 4 / clarification 3).
    ReadWrite,
}

/// The resolved on-disk paths of the crown-jewel key inputs (design §1.2 A). Each is granted
/// under Landlock ONLY to the instance that holds the owning [`HostAuthority`]; for every
/// instance that does NOT hold it, the path is absent from the FS view entirely (design §2
/// step 3 / §5 inv7), and [`derive_profile`] REFUSES (fail-closed) any composition in which a
/// non-holder's granted subtree would transitively expose one.
///
/// WS-B (the root) populates this from the resolved `[secrets]`/`[serve]`/`[overlay]`/
/// `[cluster]` config, passing each instance only the refs its set needs; the root itself
/// never dereferences them (design §4.1 F1). All are paths — an inline value for any §1.2 key
/// is a hard load refusal under `[privsep]` (design F11), so a key input is always a file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyInputPaths {
    /// `secrets.sealer` — the AES-256-GCM KEK file (`[secrets].kek_file`); read + first-run gen.
    pub kek_file: Option<PathBuf>,
    /// `secrets.sealer` — a KEK-SEALED signer-key blob FILE the SEALER reads + unwraps to serve the
    /// `token.signer`'s unseal request over the feature-link (the "signer-key unlock" owner decision
    /// with a `[serve.signer] = Sealed { key_ref: "path:<file>" }` source). Granted READ-ONLY to the
    /// SEALER — NOT to the `token.signer` holder: the signer never has its key on disk, it receives
    /// the plaintext over the link. `None` for a `boatramp:<name>` (sealed-store) source or any
    /// non-sealed signer.
    pub sealed_signer_key_file: Option<PathBuf>,
    /// `token.signer` — the control-plane auth-root private key file.
    pub token_signer_key: Option<PathBuf>,
    /// `image.signer` — the key-based image-signing key file.
    pub image_signer_key: Option<PathBuf>,
    /// `overlay.dial-signer` — the node overlay Ed25519 seed file (`OverlayServeConfig.identity`).
    pub overlay_seed: Option<PathBuf>,
    /// `s3ingress.root` — the S3-ingress HKDF root file (`s3_ingress_secret_file`).
    pub s3_ingress_secret: Option<PathBuf>,
    /// `cluster.join-signer` — the cluster root key file.
    pub cluster_root_key: Option<PathBuf>,
}

impl KeyInputPaths {
    /// Every present key input as `(owning authority, path, access)`. Each `&Path` borrows a
    /// field of `self`, so it lives as long as the borrow of `self` (no closure — a closure
    /// parameter's lifetime would not outlive its body).
    fn entries(&self) -> Vec<(HostAuthority, &Path, KeyAccess)> {
        let fields: [(HostAuthority, &Option<PathBuf>, KeyAccess); 7] = [
            (
                HostAuthority::SecretsSealer,
                &self.kek_file,
                KeyAccess::ReadWrite,
            ),
            // The sealer custodies the sealed signer-key blob (read-only); the token.signer holder
            // never has it on disk (it gets the plaintext over the link).
            (
                HostAuthority::SecretsSealer,
                &self.sealed_signer_key_file,
                KeyAccess::ReadOnly,
            ),
            (
                HostAuthority::TokenSigner,
                &self.token_signer_key,
                KeyAccess::ReadOnly,
            ),
            (
                HostAuthority::ImageSigner,
                &self.image_signer_key,
                KeyAccess::ReadOnly,
            ),
            (
                HostAuthority::OverlayDialSigner,
                &self.overlay_seed,
                KeyAccess::ReadOnly,
            ),
            (
                HostAuthority::S3IngressRoot,
                &self.s3_ingress_secret,
                KeyAccess::ReadOnly,
            ),
            (
                HostAuthority::ClusterJoinSigner,
                &self.cluster_root_key,
                KeyAccess::ReadOnly,
            ),
        ];
        fields
            .into_iter()
            .filter_map(|(auth, p, access)| p.as_deref().map(|path| (auth, path, access)))
            .collect()
    }
}

/// The non-key filesystem grants + the crown-jewel key paths an instance's Landlock profile
/// is derived from. WS-B computes the non-key grants per instance (the instance's OWN state
/// subtrees — NOT the shared `data_dir` root — plus the read-only config slice); WS-D gates
/// the crown-jewel key paths holder-only and runs the fail-closed leak check.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxDerivationInputs {
    /// Informational: the node data dir (recorded on [`SandboxPolicy::data_dir`]; NOT itself
    /// granted — grants come only from the fields below, so a key under `data_dir` is never
    /// exposed by accident).
    pub data_dir: PathBuf,
    /// Read-only roots granted to every instance: [`SYSTEM_READ_ROOTS`] + the config-file dir.
    pub base_read_only: Vec<PathBuf>,
    /// Read-write subtrees this instance legitimately needs (its OWN KV/SQL/blob/wasm-cache
    /// state subtree, the ACME cache, …) — WS-B supplies the narrow per-instance set.
    pub base_read_write: Vec<PathBuf>,
    /// The shared system temp dirs (`/tmp`, `/var/tmp`, `$TMPDIR`): granted read-write under
    /// `Derived`, DROPPED under `Strict` (the Phase-1 extra clamp — a `Strict` instance writes
    /// only under its own state subtree, never shared world-writable temp).
    pub shared_temp: Vec<PathBuf>,
    /// The crown-jewel key inputs (holder-only, leak-checked).
    pub keys: KeyInputPaths,
    /// Per-authority backend STATE subtrees (the non-crown-jewel `backend.kv`/`backend.sql`/
    /// `backend.blob`/… state dirs under `data_dir`). WS-B supplies this map; [`derive_profile`]
    /// refuses (fail-closed) any grant that overlaps a subtree whose owning authority this
    /// instance does NOT hold — the non-key analogue of the crown-jewel key leak check
    /// (Security-review Finding 3).
    ///
    /// **WS-C LOAD-BEARING CONTRACT (Security re-review residual #2):** empty ⇒ the
    /// cross-authority check is INERT, and the `OverbroadStateGrant` floor alone does NOT stop a
    /// narrow sibling-subtree leak (a frontend granted `/data/kv` is not refused while this map
    /// is empty). So WS-C MUST populate this with EVERY backend authority's state subtree before
    /// wiring real grants, and the composition layer (which alone sees all instances) MUST
    /// additionally enforce that the per-instance grants are mutually disjoint and the map
    /// covers every hosted backend authority — a check `derive_profile` cannot make from a
    /// single instance's view. Phase-1-as-merged is safe only because serving is not wired
    /// (`run_instance` fail-closes before any derivation/install and WS-B supplies no grants).
    pub authority_state_dirs: BTreeMap<HostAuthority, Vec<PathBuf>>,
    /// The execute-pin: paths this instance may `execve` (read + EXECUTE). WS-C populates it with
    /// the instance's OWN binary ONLY for the `exec.compute` holder (the per-tenant router that
    /// forks+re-execs itself); EMPTY for every other instance (whose `execve` is seccomp-killed).
    /// Carried verbatim into [`SandboxPolicy::execute_paths`] by [`derive_profile`] (and
    /// leak-checked like any other readable grant); [`linux::build_ruleset`] grants Execute ONLY
    /// here, having stripped it from the general read/write roots.
    pub execute_paths: Vec<PathBuf>,
}

impl SandboxDerivationInputs {
    /// Sane defaults for an instance: [`SYSTEM_READ_ROOTS`] + the config FILE read-only, the
    /// system temp dirs as `shared_temp`, no state writes and no key paths (WS-B layers those
    /// on per the instance's capability set). `config_read` is the config FILE the instance
    /// re-reads at boot, granted read-only as a single-file Landlock rule (like the crown-jewel
    /// key files) — NOT its parent DIRECTORY: a config dir that CONTAINS `data_dir` (the common
    /// `/var/lib/boatramp/{boatramp.toml,data/}` layout) would be an ancestor of `data_dir` and
    /// so refused by `derive_profile`'s `OverbroadStateGrant` check (it would expose all backend
    /// state read-only). Granting the file alone is both correct and strictly tighter.
    pub fn for_instance(data_dir: impl Into<PathBuf>, config_read: Option<PathBuf>) -> Self {
        let mut base_read_only: Vec<PathBuf> =
            SYSTEM_READ_ROOTS.iter().map(PathBuf::from).collect();
        if let Some(file) = config_read.filter(|p| !p.as_os_str().is_empty()) {
            base_read_only.push(file);
        }
        let mut shared_temp = vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")];
        if let Some(tmp) = std::env::var_os("TMPDIR") {
            let tmp = PathBuf::from(tmp);
            if !tmp.as_os_str().is_empty() {
                shared_temp.push(tmp);
            }
        }
        Self {
            data_dir: data_dir.into(),
            base_read_only,
            base_read_write: Vec::new(),
            shared_temp,
            keys: KeyInputPaths::default(),
            authority_state_dirs: BTreeMap::new(),
            // No execute-pin by default; WS-C adds the own binary for an `exec.compute` holder.
            execute_paths: Vec::new(),
        }
    }

    /// Normalize every path this carries so [`derive_profile`]'s LEXICAL FS checks match what
    /// the fd-based Landlock install will actually grant (**WS-C LOAD-BEARING CONTRACT #1**; see
    /// [`lexically_normalize`] + [`path_contains`]). For each path: make it absolute (a relative
    /// path is joined onto `cwd` — the install resolves a relative `PathFd` against the same
    /// process CWD) and run it through [`lexically_normalize`] to resolve `..`/`.`/separators;
    /// then, if the resulting path already EXISTS on disk, replace it with its
    /// [`std::fs::canonicalize`]d form (which additionally resolves symlinks). A path that does
    /// not exist yet (a first-run state dir) keeps its lexical form — WS-C pre-creates an
    /// instance's OWN state dirs before deriving, so a holder's own grant canonicalizes through
    /// symlinks, while a non-holder's never-created sibling path stays lexical (and is still
    /// leak-checked lexically). The caller MUST invoke this before [`derive_profile`].
    #[must_use]
    pub fn into_normalized(self, cwd: &Path) -> Self {
        let norm = |p: &Path| -> PathBuf {
            let abs = if p.is_absolute() {
                p.to_path_buf()
            } else {
                cwd.join(p)
            };
            let lexical = lexically_normalize(&abs);
            // Resolve symlinks for a path that already exists; keep the lexical form otherwise.
            std::fs::canonicalize(&lexical).unwrap_or(lexical)
        };
        let norm_vec = |v: &[PathBuf]| -> Vec<PathBuf> { v.iter().map(|p| norm(p)).collect() };
        let norm_key = |o: &Option<PathBuf>| -> Option<PathBuf> { o.as_deref().map(norm) };
        Self {
            data_dir: norm(&self.data_dir),
            base_read_only: norm_vec(&self.base_read_only),
            base_read_write: norm_vec(&self.base_read_write),
            shared_temp: norm_vec(&self.shared_temp),
            keys: KeyInputPaths {
                kek_file: norm_key(&self.keys.kek_file),
                sealed_signer_key_file: norm_key(&self.keys.sealed_signer_key_file),
                token_signer_key: norm_key(&self.keys.token_signer_key),
                image_signer_key: norm_key(&self.keys.image_signer_key),
                overlay_seed: norm_key(&self.keys.overlay_seed),
                s3_ingress_secret: norm_key(&self.keys.s3_ingress_secret),
                cluster_root_key: norm_key(&self.keys.cluster_root_key),
            },
            authority_state_dirs: self
                .authority_state_dirs
                .iter()
                .map(|(a, dirs)| (*a, norm_vec(dirs)))
                .collect(),
            execute_paths: norm_vec(&self.execute_paths),
        }
    }
}

/// A fully-derived per-instance profile: the seccomp allow/kill lists + the Landlock policy,
/// ready for [`linux::install_derived`]. The `posture` it was derived under is retained so the
/// install + fail-closed decision ([`enforce_privsep_status`]) can be logged against it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedProfile {
    /// The per-instance posture this profile was derived under (`Derived`/`Strict`/`Off`).
    pub posture: SandboxPosture,
    /// The derived seccomp allow-set (default-deny → `EPERM`).
    pub seccomp_allow: Vec<String>,
    /// The derived seccomp kill-set (hard `SIGSYS`).
    pub seccomp_kill: Vec<String>,
    /// The derived Landlock filesystem policy (holder-only key paths; leak-checked).
    pub policy: SandboxPolicy,
}

/// A fail-closed refusal from [`derive_profile`] — in every case the derivation spawns
/// NOTHING; WS-B must narrow the grant so a non-holder's FS view never reaches another
/// authority's secrets or state (design §2 step 3 / §5 inv7).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProfileDerivationError {
    /// A granted FS subtree would transitively expose a crown-jewel KEY path the instance
    /// does not hold (design §1.2 A) — "the path is not in the FS view at all". Narrow the
    /// grant to the instance's own subtree, not a parent containing a sibling's key.
    #[error(
        "privsep sandbox derivation refused: a granted FS subtree {via:?} would expose the \
         {authority} key path {key_path:?}, which this instance does not hold — narrow the \
         grant so a non-holder's FS view never contains a crown-jewel key path"
    )]
    CrownJewelKeyLeak {
        /// The crown-jewel authority whose key path would leak.
        authority: HostAuthority,
        /// The leaking key path.
        key_path: PathBuf,
        /// The granted subtree that is an ancestor of (or equal to) `key_path`.
        via: PathBuf,
    },
    /// A granted state/config subtree is the node `data_dir` itself or an ANCESTOR of it —
    /// an over-broad grant that exposes EVERY authority's backend state (KV tokens-at-rest,
    /// sealed-cred ciphertext, SQL files, deploy manifests), not just this instance's
    /// (Security-review Finding 3 / flag #6). An instance must be granted its OWN narrow
    /// subtree UNDER `data_dir`, never `data_dir` or a parent (shared system temp is exempt
    /// — it is the declared shared set, checked separately).
    #[error(
        "privsep sandbox derivation refused: granted subtree {via:?} is the node data_dir \
         {data_dir:?} or an ancestor of it — an instance must be granted its own narrow \
         subtree under data_dir, never the shared state root (it would expose every \
         authority's backend state)"
    )]
    OverbroadStateGrant {
        /// The over-broad granted subtree.
        via: PathBuf,
        /// The node data dir it contains (or equals).
        data_dir: PathBuf,
    },
    /// A granted subtree OVERLAPS a non-held authority's declared state subtree (one
    /// contains the other) — the instance would reach another authority's backend data
    /// without holding it. The non-key analogue of [`Self::CrownJewelKeyLeak`]
    /// (Security-review Finding 3); the per-authority state map is supplied by WS-B via
    /// [`SandboxDerivationInputs::authority_state_dirs`].
    #[error(
        "privsep sandbox derivation refused: granted subtree {via:?} overlaps the {authority} \
         state subtree {state_dir:?}, which this instance does not hold — a non-holder's FS \
         view must not reach another authority's backend state"
    )]
    CrossAuthorityStateLeak {
        /// The non-held authority whose state would be exposed.
        authority: HostAuthority,
        /// That authority's state subtree.
        state_dir: PathBuf,
        /// The overlapping granted subtree.
        via: PathBuf,
    },
}

/// `ancestor` contains (or equals) `descendant` LEXICALLY (`Path::starts_with` is component-wise,
/// so `/data/kv` does not match `/data/kv-frontend`). `..`/symlinks are not resolved here.
///
/// **WS-C LOAD-BEARING CONTRACT (Security re-review residual #1):** all THREE fail-closed FS
/// checks in [`derive_profile`] (`CrownJewelKeyLeak`, `OverbroadStateGrant`,
/// `CrossAuthorityStateLeak`) are lexical, so a non-canonical input (`/weird/../data/kv`, a
/// symlink, a relative path) could pass the lexical check while the fd-based Landlock install
/// grants the real, sensitive path. WS-C MUST normalize/canonicalize `data_dir`, every grant,
/// every key path, and every `authority_state_dirs` entry BEFORE calling [`derive_profile`]
/// (note `std::fs::canonicalize` needs the path to exist, so a first-run node needs lexical
/// normalization — resolve `..`, collapse separators/trailing slashes — or dir pre-creation).
fn path_contains(ancestor: &Path, descendant: &Path) -> bool {
    descendant == ancestor || descendant.starts_with(ancestor)
}

/// Lexically normalize `path` — resolve `.`/`..`, collapse repeated + trailing separators —
/// PURELY, without touching the filesystem (so it works for a first-run node whose state dirs
/// do not exist yet, unlike [`std::fs::canonicalize`], which requires the path to exist). The
/// absolute/relative character is preserved; a leading `..` on a relative path is kept (there
/// is no known root to resolve it against), while a `..` at the root of an absolute path is
/// dropped (root's parent is root).
///
/// This is the lexical FLOOR of **WS-C LOAD-BEARING CONTRACT #1** (the doc on [`path_contains`]):
/// every path handed to [`derive_profile`] (`data_dir`, grants, key paths, `authority_state_dirs`
/// entries) MUST be run through [`SandboxDerivationInputs::into_normalized`] first, so the three
/// LEXICAL FS checks can never be evaded by a `..`/relative spelling that the fd-based Landlock
/// install would resolve to a different, sensitive path. It does NOT resolve symlinks (that needs
/// existence); [`SandboxDerivationInputs::into_normalized`] additionally `fs::canonicalize`s a
/// path that already exists, which does resolve symlinks, and the Landlock install is fd-based.
pub fn lexically_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut stack: Vec<std::ffi::OsString> = Vec::new();
    let mut root: Option<std::ffi::OsString> = None; // the Prefix/RootDir prefix, if absolute
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => root = Some(p.as_os_str().to_os_string()),
            Component::RootDir => {
                // Preserve any Windows prefix already captured, then mark absolute.
                let mut r = root.take().unwrap_or_default();
                r.push(std::path::MAIN_SEPARATOR_STR);
                root = Some(r);
            }
            Component::CurDir => {}
            Component::ParentDir => match stack.last().map(std::ffi::OsString::as_os_str) {
                // Pop a real component.
                Some(last) if last != ".." => {
                    stack.pop();
                }
                // A leading `..` on a relative path is kept; at an absolute root it is dropped.
                _ if root.is_none() => stack.push(std::ffi::OsString::from("..")),
                _ => {}
            },
            Component::Normal(seg) => stack.push(seg.to_os_string()),
        }
    }
    let mut out = PathBuf::new();
    if let Some(r) = root {
        out.push(r);
    }
    for seg in stack {
        out.push(seg);
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    out
}

/// DERIVE the per-capability profile for an instance holding `caps`, under `posture`, from
/// `inputs`. The seccomp allow/kill lists come from [`derive_seccomp_allowlist`] /
/// [`derive_seccomp_killlist`]; the Landlock policy is the non-key grants (temp dropped under
/// `Strict`) PLUS only the crown-jewel key paths this instance holds — after a fail-closed
/// leak check that a non-held key path is not transitively exposed by a granted subtree.
///
/// `Off` derives the same data as `Derived` (so a caller that ignores the plan still gets a
/// sane profile); whether to actually install is [`privsep_install_plan`]'s decision.
pub fn derive_profile(
    caps: &BTreeSet<HostAuthority>,
    posture: SandboxPosture,
    inputs: &SandboxDerivationInputs,
) -> Result<DerivedProfile, ProfileDerivationError> {
    let mut read_only = inputs.base_read_only.clone();
    let mut read_write = inputs.base_read_write.clone();
    // The execute-pin (read + EXECUTE). Carried verbatim into the policy; also leak-checked below
    // like any other readable grant (an execute path IS readable — `AccessFs::from_read`).
    let execute = inputs.execute_paths.clone();
    // The shared system temp dirs are a `Derived`/`Off` convenience; `Strict` drops them.
    if posture != SandboxPosture::Strict {
        read_write.extend(inputs.shared_temp.iter().cloned());
    }

    // Fail-closed Finding-3 checks over the instance's STATE/CONFIG grants (`base_read_only` +
    // `base_read_write` — NOT `shared_temp`, the declared shared world-writable set, which is
    // exempt): no grant may be the `data_dir` root or an ancestor of it (an over-broad grant
    // exposing every authority's state), and no grant may overlap a non-held authority's
    // declared state subtree. WS-B must give each instance its OWN narrow subtree under
    // `data_dir`; a config dir that is an ancestor of `data_dir` is likewise refused here.
    for granted in inputs
        .base_read_only
        .iter()
        .chain(inputs.base_read_write.iter())
        .chain(inputs.execute_paths.iter())
    {
        if path_contains(granted, &inputs.data_dir) {
            return Err(ProfileDerivationError::OverbroadStateGrant {
                via: granted.clone(),
                data_dir: inputs.data_dir.clone(),
            });
        }
        for (authority, dirs) in &inputs.authority_state_dirs {
            if caps.contains(authority) {
                continue; // the holder legitimately reaches its own state
            }
            for state_dir in dirs {
                // Overlap in EITHER direction leaks: the grant contains the state subtree, OR
                // the grant lies INSIDE another authority's state subtree.
                if path_contains(granted, state_dir) || path_contains(state_dir, granted) {
                    return Err(ProfileDerivationError::CrossAuthorityStateLeak {
                        authority: *authority,
                        state_dir: state_dir.clone(),
                        via: granted.clone(),
                    });
                }
            }
        }
    }

    // Fail-closed (Security re-review residual #3): `data_dir` must not be placed UNDER a
    // declared `shared_temp` dir — a `data_dir=/tmp/…` with `shared_temp=[/tmp]` would expose
    // the whole state root to every instance through the (exempt) world-writable temp grant.
    // Refused regardless of posture (the layout is categorically wrong; `Strict` happens to
    // drop shared_temp, but a sibling `Derived` instance in the same composition would not).
    for tmp in &inputs.shared_temp {
        if path_contains(tmp, &inputs.data_dir) {
            return Err(ProfileDerivationError::OverbroadStateGrant {
                via: tmp.clone(),
                data_dir: inputs.data_dir.clone(),
            });
        }
    }

    // Fail-closed leak check: every subtree granted to this instance (the NON-key grants) must
    // not be an ancestor of a crown-jewel key path whose capability the instance does NOT hold.
    for (authority, key_path, _access) in inputs.keys.entries() {
        if caps.contains(&authority) {
            continue; // the holder legitimately reaches its own key
        }
        for granted in read_only
            .iter()
            .chain(read_write.iter())
            .chain(execute.iter())
        {
            if path_contains(granted, key_path) {
                return Err(ProfileDerivationError::CrownJewelKeyLeak {
                    authority,
                    key_path: key_path.to_path_buf(),
                    via: granted.clone(),
                });
            }
        }
    }

    // Add this instance's OWN crown-jewel key paths (holder-only).
    for (authority, key_path, access) in inputs.keys.entries() {
        if !caps.contains(&authority) {
            continue;
        }
        match access {
            KeyAccess::ReadOnly => read_only.push(key_path.to_path_buf()),
            KeyAccess::ReadWrite => read_write.push(key_path.to_path_buf()),
        }
    }

    Ok(DerivedProfile {
        posture,
        seccomp_allow: derive_seccomp_allowlist(caps),
        seccomp_kill: derive_seccomp_killlist(caps),
        policy: SandboxPolicy {
            data_dir: inputs.data_dir.clone(),
            read_only_paths: read_only,
            read_write_paths: read_write,
            execute_paths: execute,
            // A per-capability instance's network posture is its seccomp set (a `listen.*` instance
            // binds; a backend instance dials its pools) — the TCP-deny net wall is the relay's
            // tool alone, never applied to an instance. OFF here (no regression).
            deny_all_tcp: false,
        },
    })
}

// =============================================================================
// Backend-authority state layout + the composition-layer grant check (WS-C CONTRACT #2)
// =============================================================================
//
// **WS-C LOAD-BEARING CONTRACT #2** (the doc on [`SandboxDerivationInputs::authority_state_dirs`]):
// `authority_state_dirs` must be POPULATED with every backend authority's state subtree (else the
// cross-authority leak check in [`derive_profile`] is INERT), AND the composition layer — which
// alone sees ALL instances, unlike a single-instance [`derive_profile`] call — must enforce that
// the per-instance state grants are mutually DISJOINT and that the map COVERS every hosted backend
// authority. These functions are the single source of truth for the backend-state layout + that
// composition-layer check; WS-B/WS-C call them in the root before any spawn, and each instance
// builds its own `authority_state_dirs` from [`backend_authority_state_dirs`].

/// The narrow state subdirectory (under `data_dir`) a backend authority (group B) owns. Each
/// backend authority gets its OWN disjoint subtree so a composition can wall one backend's data
/// from another's. Non-backend authorities return `None` (crown-jewel keys are handled separately
/// by [`KeyInputPaths`]; listeners/exec/control hold no node-base state subtree here).
///
/// Phase-1 canonical layout. `backend.kv` maps to `<data_dir>/kv-slate` — the control-plane
/// SlateDB store's REAL on-disk location (`SlateKv::open_local_with_flush_policy(data_dir.join(
/// "kv-slate"))` in `boatramp_node::backends::build_slatedb_kv`). This MUST match the store path:
/// a mismatch Landlock-EACCES-denies the store open, and SlateDB's retrying object store then
/// spins on the permission error forever — a SILENT HANG, not a loud failure. The WS-C per-tenant
/// router (the first privsep instance to actually OPEN `backend.kv` under the Derived sandbox) was
/// bitten by exactly this when this mapped to the sibling `<data_dir>/kv`. `sql`/`blob`/`messaging`
/// are the canonical privsep names whose
/// reconciliation with each monolith backend's exact open path is part of the authority-serve
/// follow-on (the SECURITY property — a non-inert, disjoint cross-authority map — holds regardless
/// of the exact leaf names, because every backend authority maps to a distinct subtree).
pub const fn backend_state_subdir(authority: HostAuthority) -> Option<&'static str> {
    match authority {
        HostAuthority::BackendKv => Some("kv-slate"),
        HostAuthority::BackendSql => Some("sql"),
        HostAuthority::BackendBlob => Some("blob"),
        HostAuthority::BackendMessaging => Some("messaging"),
        _ => None,
    }
}

/// The node-own `exec.wasmtime` **compile-cache** subtree name under `data_dir` (privsep **Phase-5
/// P5-6** — the owner-gated self-host flip; see `crates/boatramp/DESIGN-privsep-phase5-selfhost.md`
/// §2 P5-6). This is the on-disk persistent wasmtime compile cache that
/// `boatramp_handlers::engine`'s `build_persistent_cache` creates at `<data_dir>/wasmtime-cache`
/// (mode `0o700`).
///
/// It is deliberately **NOT** a [`backend_state_subdir`] entry — it is an EXEC (group-D) authority's
/// subtree, not a backend-state one — and it is **NOT granted to any instance today**: granting it is
/// the P5-6 increment, which stays refused behind `NodeServeMode::is_wired(NodeSelfHost) == false`. It
/// is named here, beside the backend-state layout, for ONE property the composition-layer disjointness
/// check ([`check_grant_disjointness`]) enforces NOW as a P5-6 precondition.
///
/// WHY it is a grant precondition, not a perf detail: the cache holds EXECUTABLE native artifacts that
/// `wasmtime::component::Component::deserialize` loads as host code with only a version-string +
/// compiler-config *compatibility* check (`ModuleVersionStrategy`, wasmtime's `engine/serialization.rs`)
/// — **NOT** a cryptographic MAC over the cache contents. (The cluster-distributed AOT artifact path's
/// HMAC gate in [`crate::aot`] authenticates a DIFFERENT source — blobs fetched from the shared blob
/// store — and does NOT cover this local on-disk cache.) A crafted same-version entry is "trivially …
/// arbitrary code execution", so an attacker-WRITABLE cache entry is a cache-poisoning → RCE vector.
/// The only integrity defense today is filesystem perms (`0o700`); under self-hosting the eventual
/// grant MUST additionally be Landlock-EXCLUSIVE to the node-own `exec.wasmtime` instance and writable
/// ONLY by it. A necessary precondition for that exclusivity is that this subtree never COLLIDES with
/// any backend's state subtree — else granting it read-write to the node-own instance would overlap a
/// backend-state grant and silently share a state root across the wall. [`check_grant_disjointness`]
/// refuses that collision fail-closed; this const is the single source of truth it reserves.
///
/// NB: the literal must stay in lockstep with `boatramp_handlers::engine::build_persistent_cache`'s
/// `data_dir.join("wasmtime-cache")` — that crate is a layer DOWN (`boatramp-server` → `boatramp-handlers`)
/// and cannot name this const.
pub const NODE_OWN_EXEC_CACHE_SUBDIR: &str = "wasmtime-cache";

/// The node-own `exec.wasmtime` compile-cache directory under `data_dir` (see
/// [`NODE_OWN_EXEC_CACHE_SUBDIR`]). A PURE path helper: it neither creates nor grants the directory
/// (both are the owner-gated Phase-5 P5-6 flip). Used by [`check_grant_disjointness`] to reserve the
/// subtree and by the eventual P5-6 grant-derivation as the single source of truth for WHAT it grants.
#[must_use]
pub fn node_own_exec_cache_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(NODE_OWN_EXEC_CACHE_SUBDIR)
}

/// The full per-backend-authority state map under `data_dir` — EVERY group-B authority's state
/// subtree. This is what an instance passes as [`SandboxDerivationInputs::authority_state_dirs`]
/// so [`derive_profile`]'s cross-authority leak check is not inert (Contract #2). `data_dir` must
/// already be normalized ([`SandboxDerivationInputs::into_normalized`]).
pub fn backend_authority_state_dirs(data_dir: &Path) -> BTreeMap<HostAuthority, Vec<PathBuf>> {
    HostAuthority::ALL
        .iter()
        .copied()
        .filter_map(|a| backend_state_subdir(a).map(|sub| (a, vec![data_dir.join(sub)])))
        .collect()
}

/// The backend-state subtrees ONE instance legitimately writes — its OWN group-B authorities'
/// state dirs under `data_dir` (the narrow [`SandboxDerivationInputs::base_read_write`] grant WS-C
/// hands a backend instance). A non-backend instance gets an empty set. `data_dir` must already be
/// normalized.
pub fn instance_backend_state_grants(
    caps: &BTreeSet<HostAuthority>,
    data_dir: &Path,
) -> Vec<PathBuf> {
    caps.iter()
        .filter_map(|a| backend_state_subdir(*a).map(|sub| data_dir.join(sub)))
        .collect()
}

/// A fail-closed composition-layer grant violation (**WS-C CONTRACT #2**). The root refuses the
/// node closed and spawns nothing on any of these — each is a hole a single-instance
/// [`derive_profile`] cannot see.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompositionGrantError {
    /// Two instances' backend-state grants OVERLAP (the same authority is on both, or one's
    /// subtree contains the other's) — a shared state root across a privsep boundary, which the
    /// wall is meant to prevent. Hold each backend authority on exactly ONE instance.
    #[error(
        "privsep composition refused: instances {a:?} and {b:?} have overlapping backend-state \
         grants ({a_dir:?} vs {b_dir:?}) — each backend authority's state subtree must belong to \
         exactly one instance (a shared state root defeats the isolation wall)"
    )]
    OverlappingGrants {
        /// One instance label.
        a: String,
        /// The other instance label.
        b: String,
        /// `a`'s overlapping grant.
        a_dir: PathBuf,
        /// `b`'s overlapping grant.
        b_dir: PathBuf,
    },
    /// A hosted backend authority has no entry in the state-dir layout — the cross-authority leak
    /// check would be INERT for it (a non-holder's grant could overlap its state undetected). A
    /// guard against a new backend authority being added without a [`backend_state_subdir`] entry.
    #[error(
        "privsep composition refused: hosted backend authority {authority} has no state-dir layout \
         entry — the cross-authority leak check would be inert for it (add a backend_state_subdir mapping)"
    )]
    UncoveredBackendAuthority {
        /// The hosted backend authority missing from the layout.
        authority: HostAuthority,
    },
    /// A hosted backend authority's state subtree COLLIDES with the reserved node-own
    /// `exec.wasmtime` compile-cache subtree ([`NODE_OWN_EXEC_CACHE_SUBDIR`]). The cache is not a
    /// backend-state grant, but it IS a sibling subtree under `data_dir` that the owner-gated
    /// **Phase-5 P5-6** self-host flip will grant read-write EXCLUSIVELY to the node-own exec
    /// instance. If a backend's state subtree ever shared that path, granting the cache RW would
    /// overlap the backend-state grant and silently defeat the isolation wall — and because the
    /// cache is loaded as executable code WITHOUT a content MAC, that overlap is a
    /// cache-poisoning → RCE seam. Keep the reserved subtree disjoint from every backend-state
    /// subtree. (Inert today — no backend maps to it — a fail-closed tripwire against a future
    /// [`backend_state_subdir`] mis-edit.)
    #[error(
        "privsep composition refused: hosted backend authority {authority} is mapped onto the \
         reserved node-own exec.wasmtime compile-cache subtree {reserved:?} — a backend's state \
         subtree must never collide with the (Phase-5 P5-6) node-own exec cache grant"
    )]
    BackendCollidesWithReservedExecCache {
        /// The offending backend authority.
        authority: HostAuthority,
        /// The reserved node-own exec-cache subtree it collides with.
        reserved: PathBuf,
    },
}

/// The composition-layer grant check (**WS-C CONTRACT #2**), run IN THE ROOT, fail-closed, BEFORE
/// any spawn — the companion to [`boatramp_core::privsep::check_composition_closure`] that
/// [`derive_profile`] cannot make from a single instance's view. `instances` maps each label to
/// its capability set; `data_dir` is the normalized node data dir. Refuses if any two instances'
/// backend-state grants overlap, or if any hosted backend authority lacks a layout entry.
///
/// This GUARANTEES the premise [`derive_profile`]'s per-instance cross-authority check relies on:
/// that a backend authority's state subtree belongs to exactly one instance, so passing every
/// instance the full [`backend_authority_state_dirs`] map and granting each only its OWN subtree
/// yields real, mutually-disjoint isolation.
pub fn check_grant_disjointness(
    instances: &BTreeMap<String, BTreeSet<HostAuthority>>,
    data_dir: &Path,
) -> Result<(), CompositionGrantError> {
    // Coverage: every hosted backend authority must have a layout entry (else the map is inert).
    // Phase-5 P5-6 precondition (SAME pass): a backend's state subtree must never collide with the
    // reserved node-own exec.wasmtime compile-cache subtree the owner-gated self-host flip will grant
    // RW EXCLUSIVELY to the node-own exec instance. Inert today — no backend maps to it
    // ([`backend_state_subdir`] has no exec entry) — a fail-closed tripwire that keeps the future
    // exclusive cache grant from ever overlapping a backend-state grant (which, because the cache is
    // loaded as executable code without a content MAC, would be a cache-poisoning → RCE seam).
    let reserved_cache = node_own_exec_cache_dir(data_dir);
    for caps in instances.values() {
        for a in caps.iter().copied().filter(|a| a.is_backend()) {
            let Some(sub) = backend_state_subdir(a) else {
                return Err(CompositionGrantError::UncoveredBackendAuthority { authority: a });
            };
            let backend_dir = data_dir.join(sub);
            if path_contains(&backend_dir, &reserved_cache)
                || path_contains(&reserved_cache, &backend_dir)
            {
                return Err(CompositionGrantError::BackendCollidesWithReservedExecCache {
                    authority: a,
                    reserved: reserved_cache,
                });
            }
        }
    }
    // Disjointness: no two instances' backend-state grants may overlap (either direction).
    let grants: Vec<(&String, Vec<PathBuf>)> = instances
        .iter()
        .map(|(label, caps)| (label, instance_backend_state_grants(caps, data_dir)))
        .collect();
    for i in 0..grants.len() {
        for j in (i + 1)..grants.len() {
            let (a_label, a_dirs) = &grants[i];
            let (b_label, b_dirs) = &grants[j];
            for a_dir in a_dirs {
                for b_dir in b_dirs {
                    if path_contains(a_dir, b_dir) || path_contains(b_dir, a_dir) {
                        return Err(CompositionGrantError::OverlappingGrants {
                            a: (*a_label).clone(),
                            b: (*b_label).clone(),
                            a_dir: a_dir.clone(),
                            b_dir: b_dir.clone(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

// =============================================================================
// SandboxPosture reconciliation + the fail-closed-FLEETWIDE install decision (F6)
// =============================================================================
//
// RECONCILIATION (design call — flagged for owner review). There are two `SandboxPosture`
// concepts and they are DISTINCT AXES, kept as two types with ONE explicit bridge (this
// section) rather than merged into a single mixed-meaning enum:
//
//   * `boatramp_node::config::SandboxPosture` (Auto|Strict|Permissive|Off) — the canonical
//     NODE-WIDE install-DECISION posture (`[serve.sandbox].posture`): "install the
//     whole-process sandbox for the monolith serve path? how strict? skip on a native-compute
//     node?". Released in Phase 0, consumed by `boatramp`'s `serve::install_presandbox`.
//     UNCHANGED.
//   * `boatramp_core::privsep::SandboxPosture` (Derived|Strict|Off) — the PER-INSTANCE profile
//     DERIVATION posture (`[privsep].instances.<name>.sandbox`): "how is THIS instance's
//     per-capability profile shaped?". Under `[privsep]` enforcement is ALWAYS fail-closed
//     `Enforced` (F6) — NOT operator-tunable — except `Off`, which is dev-only.
//
// The bridge: a privsep instance posture DRIVES a Phase-0 install of a DERIVED profile,
// reusing Phase-0's `SandboxPolicy` + `SandboxStatus` + `install` machinery verbatim (no
// second mechanism). `SandboxPosture::enforcement()` (in `boatramp-types`) encodes the F6
// rule purely from the privsep posture; [`privsep_install_plan`] + [`enforce_privsep_status`]
// implement the fail-closed-FLEETWIDE decision. The final "Off is legal only on a dev node"
// cross-check needs `config::SandboxPosture`, which is not visible here (dependency
// direction), so it is passed in as `node_allows_unsandboxed` (computed by WS-B in
// `boatramp`, where both postures are in scope).

/// What to do for one privsep instance's sandbox, resolved from its posture + the node posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivsepInstallPlan {
    /// Derive + install the per-capability profile; it MUST report [`SandboxStatus::Enforced`]
    /// (fail-closed, fleetwide — [`enforce_privsep_status`]). Carries the derivation posture
    /// (`Derived`|`Strict`).
    InstallEnforced(SandboxPosture),
    /// Dev-only `Off` on a dev node (`[serve.sandbox].posture` is `off`/`permissive`): install
    /// NO profile for this instance.
    SkipDevOff,
}

/// A fail-closed privsep sandbox refusal (design §2 F6 / §5 inv7). Under `[privsep]` the wall
/// is load-bearing, so — unlike Phase-0 `auto`, which fails OPEN on `Partial` — anything less
/// than a fully-`Enforced` profile, and a non-dev `Off`, REFUSE the node closed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrivsepSandboxError {
    /// `sandbox: Off` in a real `[privsep]` composition on a NON-dev node — refused (the wall
    /// is load-bearing; `Off` is dev-only, design §2 F6).
    #[error(
        "privsep instance sandbox posture `Off` is refused: it is dev-only, and this node's \
         [serve.sandbox] posture is not a dev posture (off/permissive) — the per-instance \
         profile is the load-bearing wall under [privsep]"
    )]
    DevOffOnEnforcedNode,
    /// The derived profile did not reach `Enforced` (an old/non-Landlock kernel delivered
    /// `Partial`, or the platform/build is unsupported) — refused FLEETWIDE, not just for
    /// crown-jewel instances (a degraded FS wall anywhere is a hole in the load-bearing wall).
    #[error(
        "privsep requires an ENFORCED per-instance profile fleetwide, but the install reported \
         {status:?} (an old/non-Landlock kernel or an unsupported platform/build) — refusing \
         the node closed (privsep does not fail open like Phase-0 `auto`)"
    )]
    NotEnforced {
        /// The best status the kernel/platform could deliver.
        status: SandboxStatus,
    },
    /// The install itself errored (a filter that would not compile, a Landlock syscall error).
    #[error("privsep per-instance profile install failed: {0}")]
    InstallFailed(String),
}

/// Resolve what to do for one instance's sandbox from its per-instance privsep posture + the
/// node's dev-posture flag. `Derived`/`Strict` ⇒ install + require `Enforced`; `Off` ⇒ skip,
/// but ONLY on a dev node (else fail-closed). `node_allows_unsandboxed` is `true` iff the node
/// `[serve.sandbox].posture` is `off`/`permissive` (computed by WS-B).
pub fn privsep_install_plan(
    posture: SandboxPosture,
    node_allows_unsandboxed: bool,
) -> Result<PrivsepInstallPlan, PrivsepSandboxError> {
    match posture.enforcement() {
        ProfileEnforcement::RequireEnforced => Ok(PrivsepInstallPlan::InstallEnforced(posture)),
        ProfileEnforcement::DevOnlyOff => {
            if node_allows_unsandboxed {
                Ok(PrivsepInstallPlan::SkipDevOff)
            } else {
                Err(PrivsepSandboxError::DevOffOnEnforcedNode)
            }
        }
    }
}

/// The fail-closed-FLEETWIDE gate (design §2 F6 / §5 inv7): a privsep per-instance profile
/// install is accepted ONLY if it reports [`SandboxStatus::Enforced`]. A `Partial`
/// (old/non-Landlock kernel), `Unsupported`/`Disabled`, or an install error all REFUSE — the
/// opposite of Phase-0 `install_presandbox`'s `auto`, which serves on `Partial`. This is what
/// makes the per-instance profile the load-bearing wall.
pub fn enforce_privsep_status(
    result: Result<SandboxStatus, SandboxError>,
) -> Result<SandboxStatus, PrivsepSandboxError> {
    match result {
        Ok(SandboxStatus::Enforced) => Ok(SandboxStatus::Enforced),
        Ok(status) => Err(PrivsepSandboxError::NotEnforced { status }),
        Err(e) => Err(PrivsepSandboxError::InstallFailed(e.to_string())),
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

/// Install a DERIVED per-instance privsep profile (WS-C), the cross-platform entry mirroring
/// [`install`]: on Linux with the `sandbox` feature it drives [`linux::install_derived`]; on any
/// other platform/build it is a no-op returning [`SandboxStatus::Unsupported`]. Under `[privsep]`
/// the caller MUST pass the result through [`enforce_privsep_status`], which refuses anything less
/// than `Enforced` — so a non-Linux / non-`sandbox` instance fails CLOSED (privsep never serves
/// without the load-bearing wall). MUST be called on the single main thread of the `__instance`
/// worker BEFORE the Tokio runtime is built.
pub fn install_derived(profile: &DerivedProfile) -> Result<SandboxStatus, SandboxError> {
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    {
        linux::install_derived(profile)
    }
    #[cfg(not(all(target_os = "linux", feature = "sandbox")))]
    {
        let _ = profile;
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
        Access, AccessFs, AccessNet, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetStatus,
    };

    use super::{
        KILL_SURFACE, SandboxError, SandboxPolicy, SandboxStatus, whole_process_allowlist,
    };

    /// The seccomp target arch for the current build (the filter runs on this
    /// process, so it matches the host arch).
    #[cfg(target_arch = "x86_64")]
    const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;

    /// The MINIMUM Landlock ABI privsep requires for its FS wall — a POLICY floor, decoupled
    /// from the set of rights we handle. `V5` (Linux 6.10) guarantees the wall includes
    /// `Truncate` (V3) and `IoctlDev` (V5) confinement; a kernel below it is refused by
    /// [`status_of`] (its wall is genuinely weaker than privsep needs — e.g. a process with
    /// `/dev` read could `ioctl` a device file that `IoctlDev` would otherwise deny). Raise or
    /// lower this to trade confinement breadth against older-kernel support.
    const MIN_LANDLOCK_ABI: landlock::ABI = landlock::ABI::V5;

    /// The FS ABI to actually HANDLE for a given running-kernel ABI: the kernel's own ABI,
    /// clamped to the highest this `landlock` crate knows (`ABI::from` saturates — e.g.
    /// `from(999) == V9` in 0.4.7). Handling exactly what the kernel supports (rather than a
    /// fixed ABI) is the fix for landlock-0.4.7's behavior that `restrict_self` reports
    /// `PartiallyEnforced` whenever the kernel's ABI is NEWER than the handled ABI: by tracking
    /// the kernel we govern EVERY FS right it supports (so nothing is left ungoverned — closing
    /// the latent `ResolveUnix`/V9 gap a hardcoded lower ABI would leave) AND we get
    /// `FullyEnforced` on any kernel the crate fully knows. On a kernel NEWER than this crate
    /// (`kernel_abi > crate max`), the handled set saturates at the crate's max FS vocabulary and
    /// `restrict_self` reports `PartiallyEnforced` — [`status_of`] accepts that (we govern the
    /// crate's full FS set; the residual is rights the crate does not yet know → a crate-bump
    /// maintenance item, surfaced by [`handled_fs_abi_tracks_crate_max`]).
    fn handled_fs_abi(kernel_abi: i64) -> landlock::ABI {
        landlock::ABI::from(kernel_abi.clamp(0, i32::MAX as i64) as i32)
    }

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

    /// Build a Landlock ruleset confining reads to `read_only` (+ `read_write`), writes to
    /// `read_write`, and EXECUTE to `execute` ONLY. Non-existent paths are skipped (best-effort).
    /// `CompatLevel::BestEffort` degrades gracefully on a kernel without full Landlock.
    ///
    /// **Execute-pin (SECURITY-CRITICAL).** `AccessFs::from_read` includes [`AccessFs::Execute`]
    /// (`Execute | ReadFile | ReadDir`) and `from_all ⊇ from_read`, so granting them verbatim would
    /// make EVERY read-only AND read-write root `execve`-able — including the WRITABLE backend-state
    /// subtrees (e.g. `kv-slate`). An `exec.compute` router (whose seccomp permits `execve`+`fork`)
    /// could then write an ELF into writable state and run it, defeating the own-binary execute-pin
    /// the fork-grant's safety argument depends on ([`FORK_SPAWN`]). So Execute is STRIPPED from the
    /// general read/write grants here and re-granted ONLY on `execute` — the caller's explicit
    /// execute-pin list (the own binary for an `exec.compute` router / the root supervisor; EMPTY
    /// for every other instance, whose `execve` is seccomp-killed regardless). `handle_access` still
    /// governs the FULL FS vocabulary (`from_all`, Execute included), so a path NOT in `execute` is
    /// DENIED execute.
    fn build_ruleset(
        read_only: &[PathBuf],
        read_write: &[PathBuf],
        execute: &[PathBuf],
        deny_all_tcp: bool,
    ) -> Result<RulesetCreated, SandboxError> {
        // Handle the FS rights the RUNNING kernel supports (clamped to the crate's max), not a
        // fixed ABI — so every FS right the kernel has is governed and `restrict_self` reports
        // `FullyEnforced` on a kernel the crate fully knows (see [`handled_fs_abi`]). The same ABI
        // LEVEL drives the net vocabulary below (`AccessNet::from_all` reads the ABI enum), so the
        // dynamic-ABI handling that governs every FS right the kernel has governs every NET right
        // too — no second kernel probe, no hardcoded ABI.
        let abi = handled_fs_abi(landlock_kernel_abi());
        // Execute STRIPPED from the general grants; re-granted below ONLY on the `execute` pin.
        let ro_access = AccessFs::from_read(abi) & !AccessFs::Execute;
        let rw_access = AccessFs::from_all(abi) & !AccessFs::Execute;
        // The execute-pin access: read + EXECUTE (so the pinned binary is readable AND runnable).
        let exec_access = AccessFs::from_read(abi);
        let mut ruleset = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| SandboxError::Landlock(e.to_string()))?;
        // F1 (the separate VM relay ONLY): HANDLE `AccessNet` (`BindTcp | ConnectTcp`) so that —
        // with NO `NetPort` allow-rule added below — every TCP bind AND every TCP connect is
        // DENIED. AF_UNIX (the firecracker vsock UDS the relay dials) is NOT an `AccessNet`
        // subject, so the relay's one legitimate dial is unaffected.
        if deny_all_tcp {
            let net_access = AccessNet::from_all(abi);
            if net_access.is_empty() {
                // The running kernel's Landlock ABI predates `AccessNet` (V4, Linux 6.7), so the
                // requested TCP wall CANNOT be installed. FAIL CLOSED: return `Err` rather than
                // build a relay ruleset that silently omits the net confinement (a `None` Landlock
                // layer → `finalize_status` → `Partial` → `enforce_privsep_status` refuses). NOTE
                // for the Security reviewer: the privsep `MIN_LANDLOCK_ABI` = V5 (⊇ V4) floor in
                // `status_for` ALREADY refuses any sub-V5 kernel, so a relay never actually runs on
                // a kernel that lacks `AccessNet`; this explicit guard is defence-in-depth + a clear
                // message (and it does not depend on the landlock crate's empty-access-right error).
                return Err(SandboxError::Landlock(
                    "deny-all-TCP net wall requested but this kernel's Landlock ABI predates \
                     AccessNet (V4/Linux-6.7); refusing to build a relay ruleset without the \
                     requested TCP confinement (the V5 privsep floor already rejects this kernel)"
                        .to_string(),
                ));
            }
            ruleset = ruleset
                .handle_access(net_access)
                .map_err(|e| SandboxError::Landlock(e.to_string()))?;
        }
        let mut created = ruleset
            .create()
            .map_err(|e| SandboxError::Landlock(e.to_string()))?;
        for (paths, access) in [
            (read_only, ro_access),
            (read_write, rw_access),
            (execute, exec_access),
        ] {
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
        // NO `NetPort` rule is ever added: when `deny_all_tcp` handled `AccessNet` above, the
        // absence of any allow-rule is exactly what denies ALL TCP (bind + connect).
        Ok(created)
    }

    /// Map the landlock crate's `RulesetStatus` + the running-kernel ABI to our coarse
    /// [`SandboxStatus`]. Thin wrapper over the pure [`status_for`] (unit-tested) using the live
    /// [`landlock_kernel_abi`] probe.
    fn status_of(ruleset: RulesetStatus) -> SandboxStatus {
        status_for(ruleset, landlock_kernel_abi())
    }

    /// Pure status decision from a `RulesetStatus` + the running-kernel Landlock ABI. Two rules:
    ///
    /// 1. **Policy floor.** A kernel below [`MIN_LANDLOCK_ABI`] is refused (`Partial`) even if it
    ///    reports `FullyEnforced` for its older ABI — privsep's wall must include the V3/V5 FS
    ///    rights (`Truncate`/`IoctlDev`), which an older kernel cannot enforce.
    ///
    /// 2. **Status.** At/above the floor we [`handle the kernel's own FS ABI`](handled_fs_abi), so
    ///    NO handled FS right is ever dropped (the request is a subset of what the kernel supports)
    ///    — `FullyEnforced` on any kernel the crate fully knows. `restrict_self` can still report
    ///    `PartiallyEnforced` on a kernel NEWER than this crate (`kernel_abi > crate max`): the
    ///    crate conservatively won't claim coverage of rights it does not know. We ACCEPT that as
    ///    `Enforced` — we already govern the crate's FULL FS vocabulary (nothing we *could* govern
    ///    is ungoverned); the only residual is FS rights a future kernel adds that this crate
    ///    version doesn't define, a crate-bump maintenance item (guarded by
    ///    [`handled_fs_abi_tracks_crate_max`]). `NotEnforced` (Landlock absent / a failed layer)
    ///    is always `Partial` → refused.
    fn status_for(ruleset: RulesetStatus, kernel_abi: i64) -> SandboxStatus {
        if kernel_abi < MIN_LANDLOCK_ABI as i64 {
            return SandboxStatus::Partial;
        }
        match ruleset {
            RulesetStatus::FullyEnforced => SandboxStatus::Enforced,
            RulesetStatus::PartiallyEnforced => SandboxStatus::Enforced,
            RulesetStatus::NotEnforced => SandboxStatus::Partial,
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

    /// Compile the whole-process (monolith) seccomp filters (KILL + allow-list). Thin wrapper
    /// over [`prepare_seccomp_from`] with the Phase-0 [`whole_process_allowlist`] + [`KILL_SURFACE`].
    pub fn prepare_seccomp() -> Result<PreparedSeccomp, SandboxError> {
        let kill: Vec<String> = KILL_SURFACE.iter().map(|s| (*s).to_string()).collect();
        prepare_seccomp_from(&whole_process_allowlist(), &kill)
    }

    /// Compile a seccomp filter pair from an EXPLICIT allow-list + kill-list — the primitive
    /// behind both the monolith [`prepare_seccomp`] and the privsep per-capability
    /// [`install_derived`] (which passes the derivation output of
    /// [`super::derive_seccomp_allowlist`] / [`super::derive_seccomp_killlist`]). The kill
    /// filter is stacked over the allow filter, so the kernel takes the most-severe action: a
    /// kill-list syscall is `SIGSYS`-killed, an allow-list syscall is allowed, any other miss
    /// is `EPERM`.
    pub fn prepare_seccomp_from(
        allow: &[String],
        kill: &[String],
    ) -> Result<PreparedSeccomp, SandboxError> {
        use seccompiler::SeccompAction;
        let kill = compile(
            kill.iter().cloned(),
            SeccompAction::KillProcess,
            SeccompAction::Allow,
        )?;
        let allow = compile(
            allow.iter().cloned(),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
        )?;
        Ok(PreparedSeccomp { kill, allow })
    }

    /// Build the Landlock ruleset for the given read-only / read-write roots + the execute-pin
    /// paths (read + EXECUTE; see [`build_ruleset`] — Execute is stripped from the general roots).
    /// `deny_all_tcp` additionally walls off ALL TCP via `AccessNet` (F1 — the VM relay only; a
    /// no-op for every other profile, which passes `false`).
    pub fn prepare_landlock(
        read_only: &[PathBuf],
        read_write: &[PathBuf],
        execute: &[PathBuf],
        deny_all_tcp: bool,
    ) -> Result<PreparedLandlock, SandboxError> {
        Ok(PreparedLandlock {
            created: build_ruleset(read_only, read_write, execute, deny_all_tcp)?,
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
        let landlock = match prepare_landlock(
            &policy.read_only_paths,
            &policy.read_write_paths,
            &policy.execute_paths,
            policy.deny_all_tcp,
        )
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

        Ok(finalize_status(
            seccomp_ok,
            landlock,
            policy.read_only_paths.len(),
            policy.read_write_paths.len(),
        ))
    }

    /// Map the two independent layers' outcomes to the coarse [`SandboxStatus`] the caller's
    /// posture gate consumes, logging the specifics. Shared by [`install`] (the monolith) and
    /// [`install_derived`] (a privsep per-capability profile) so both report identically.
    /// `Enforced` requires BOTH seccomp applied AND Landlock fully enforced; anything less is
    /// `Partial` (which Phase-0 `auto` tolerates but privsep [`super::enforce_privsep_status`]
    /// REFUSES).
    fn finalize_status(
        seccomp_ok: bool,
        landlock: Option<SandboxStatus>,
        read_only_roots: usize,
        read_write_roots: usize,
    ) -> SandboxStatus {
        match (seccomp_ok, landlock) {
            (true, Some(SandboxStatus::Enforced)) => {
                tracing::info!(
                    read_only_roots,
                    read_write_roots,
                    "process sandbox installed: seccomp-bpf allow-list (exec* + escape surface KILLED, \
                     other misses EPERM) + Landlock filesystem confinement"
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
        }
    }

    /// Install a DERIVED per-capability profile (privsep Phase 1 WS-D) on the current process,
    /// reusing the SAME machinery as the monolith [`install`]: Landlock first, then the derived
    /// seccomp filters, each independent. Returns the coarse [`SandboxStatus`]; the caller
    /// applies the fail-closed-fleetwide gate ([`super::enforce_privsep_status`]) — under
    /// `[privsep]` only `Enforced` is accepted. MUST be called on the single main thread of the
    /// `__instance` worker BEFORE the Tokio runtime is built (same coverage property as
    /// [`install`]).
    pub fn install_derived(profile: &super::DerivedProfile) -> Result<SandboxStatus, SandboxError> {
        set_no_new_privs()?;

        let landlock = match prepare_landlock(
            &profile.policy.read_only_paths,
            &profile.policy.read_write_paths,
            &profile.policy.execute_paths,
            profile.policy.deny_all_tcp,
        )
        .and_then(PreparedLandlock::apply)
        {
            Ok(status) => Some(status),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    posture = ?profile.posture,
                    deny_all_tcp = profile.policy.deny_all_tcp,
                    "privsep per-instance Landlock FS/net confinement FAILED to apply"
                );
                None
            }
        };

        let seccomp_ok = match prepare_seccomp_from(&profile.seccomp_allow, &profile.seccomp_kill)
            .and_then(|p| p.apply())
        {
            Ok(()) => true,
            Err(e) => {
                tracing::error!(error = %e, posture = ?profile.posture, "privsep per-instance seccomp filter FAILED to apply");
                false
            }
        };

        Ok(finalize_status(
            seccomp_ok,
            landlock,
            profile.policy.read_only_paths.len(),
            profile.policy.read_write_paths.len(),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::super::DENIED;
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
                // The exec.compute sandbox-install family (Fix A / [`SANDBOX_INSTALL`]): a typo'd
                // name is silently skipped at install, so the per-tenant child would fail to confine
                // itself and refuse closed — guard the exact names the kernel/arch must know.
                "seccomp",
                "landlock_create_ruleset",
                "landlock_add_rule",
                "landlock_restrict_self",
            ] {
                assert!(
                    name.parse::<syscalls::Sysno>().is_ok(),
                    "core syscall name does not resolve on this arch: {name}"
                );
            }
        }

        // ---- Landlock Enforced determination (privsep fail-closed gate) ----

        #[test]
        fn status_for_refuses_below_the_min_abi_floor_even_if_fully_enforced() {
            // A kernel below MIN_LANDLOCK_ABI is refused regardless of the reported status — its
            // wall lacks the V3/V5 FS rights privsep requires.
            for abi in 1..(MIN_LANDLOCK_ABI as i64) {
                assert_eq!(
                    status_for(RulesetStatus::FullyEnforced, abi),
                    SandboxStatus::Partial,
                    "kernel ABI {abi} is below the floor and must be refused"
                );
            }
            // ABI 0 (Landlock unsupported) is likewise refused.
            assert_eq!(
                status_for(RulesetStatus::FullyEnforced, 0),
                SandboxStatus::Partial
            );
        }

        #[test]
        fn status_for_accepts_at_or_above_the_floor() {
            let floor = MIN_LANDLOCK_ABI as i64;
            // FullyEnforced at/above the floor → Enforced.
            assert_eq!(
                status_for(RulesetStatus::FullyEnforced, floor),
                SandboxStatus::Enforced
            );
            // PartiallyEnforced at/above the floor (kernel newer than the crate) → Enforced: we
            // handle the kernel's own FS ABI, so nothing we could govern is dropped.
            assert_eq!(
                status_for(RulesetStatus::PartiallyEnforced, floor),
                SandboxStatus::Enforced
            );
            assert_eq!(
                status_for(RulesetStatus::PartiallyEnforced, floor + 100),
                SandboxStatus::Enforced
            );
            // NotEnforced is always a refusal.
            assert_eq!(
                status_for(RulesetStatus::NotEnforced, floor + 100),
                SandboxStatus::Partial
            );
        }

        #[test]
        fn handled_fs_abi_tracks_kernel_and_saturates_at_crate_max() {
            use landlock::{ABI, AccessFs};
            // We handle exactly the kernel's ABI up to the crate's max, so every FS right the
            // kernel supports is governed (no silent under-governing).
            assert_eq!(handled_fs_abi(5), ABI::V5);
            assert_eq!(handled_fs_abi(6), ABI::V6);
            // Saturates at the crate's highest known ABI for a kernel newer than the crate.
            let crate_max = ABI::from(i32::MAX);
            assert_eq!(handled_fs_abi(i64::MAX), crate_max);
            // Negative / zero clamp to Unsupported (no panic on the cast).
            assert_eq!(handled_fs_abi(0), ABI::Unsupported);
            assert_eq!(handled_fs_abi(-1), ABI::Unsupported);

            // FS-COMPLETENESS GUARD: handling the crate's max ABI governs the crate's FULL FS
            // vocabulary — so a future crate bump that adds a new AccessFs right (e.g. a higher
            // ABI) is caught here (this equality breaks) rather than silently leaving it
            // ungoverned. If it breaks: confirm `handled_fs_abi` saturates at the NEW max.
            assert_eq!(
                AccessFs::from_all(handled_fs_abi(i64::MAX)),
                AccessFs::from_all(crate_max),
                "handled_fs_abi must saturate at the crate's max so from_all governs every FS right"
            );
        }

        /// F1: the deny-ALL-TCP wall rests on `AccessNet` being governable at the privsep floor.
        /// Prove (pure ABI math, no live kernel) that `AccessNet` governs BOTH TCP bind + connect
        /// from the V5 floor up through the crate's max, and is EMPTY below V4 — the exact edge
        /// `build_ruleset` fails closed on. If this reddens, the net wall is unavailable at the
        /// floor and `build_ruleset`'s `deny_all_tcp` branch would wrongly refuse (or under-govern).
        #[test]
        fn accessnet_governs_all_tcp_from_the_privsep_floor_and_is_absent_below_v4() {
            use landlock::{ABI, AccessNet};
            // Governable at the V5 privsep floor and at every ABI the crate knows at/above it.
            for abi in [MIN_LANDLOCK_ABI, ABI::V5, ABI::V6, ABI::from(i32::MAX)] {
                let net = AccessNet::from_all(abi);
                assert!(
                    !net.is_empty(),
                    "AccessNet must be governable at/above the V5 floor (abi={abi:?})"
                );
                assert!(
                    net.contains(AccessNet::BindTcp) && net.contains(AccessNet::ConnectTcp),
                    "the deny-all-TCP wall must govern BOTH TCP bind AND connect (abi={abi:?})"
                );
            }
            // Below V4 there is no AccessNet — `from_all` is empty, which is the sub-V4 edge
            // `build_ruleset` detects and FAILS CLOSED on (rather than silently omit the wall).
            for abi in [ABI::V1, ABI::V2, ABI::V3, ABI::Unsupported] {
                assert!(
                    AccessNet::from_all(abi).is_empty(),
                    "AccessNet must be ABSENT below V4 (abi={abi:?}) — build_ruleset fails closed here"
                );
            }
            // The privsep floor is >= the ABI that introduced AccessNet (V4), so the net wall is
            // always available at the floor — a regression guard on MIN_LANDLOCK_ABI.
            assert!(
                (MIN_LANDLOCK_ABI as i64) >= (ABI::V4 as i64),
                "MIN_LANDLOCK_ABI must be >= V4 so the relay's AccessNet wall is always available"
            );
        }
    }
}

// =============================================================================
// Cross-platform tests for the privsep Phase 1 WS-D per-capability DERIVATION, the
// SandboxPosture reconciliation bridge, and the fail-closed-fleetwide decision. These test
// PURE data + decisions (no live kernel), so they run on every host; the LIVE seccomp/Landlock
// install of a derived profile is proven by the `sandbox-live` CI gate / lighthouse.
// =============================================================================
#[cfg(test)]
mod privsep_derivation_tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::path::PathBuf;

    fn caps(list: &[HostAuthority]) -> BTreeSet<HostAuthority> {
        list.iter().copied().collect()
    }

    fn all_caps() -> BTreeSet<HostAuthority> {
        HostAuthority::ALL.iter().copied().collect()
    }

    fn has(set: &[String], name: &str) -> bool {
        set.iter().any(|s| s == name)
    }

    // The Phase-3 frontend (design §7): listeners + the JIT, NO keys, NO backends, NO compute.
    fn frontend() -> BTreeSet<HostAuthority> {
        caps(&[
            HostAuthority::ListenPublicTls,
            HostAuthority::ListenHttpParse,
            HostAuthority::ExecWasmtime,
        ])
    }

    fn signer() -> BTreeSet<HostAuthority> {
        caps(&[
            HostAuthority::SecretsSealer,
            HostAuthority::TokenSigner,
            HostAuthority::ImageSigner,
            HostAuthority::OverlayDialSigner,
            HostAuthority::S3IngressRoot,
            HostAuthority::ClusterJoinSigner,
        ])
    }

    fn storage() -> BTreeSet<HostAuthority> {
        caps(&[
            HostAuthority::BackendKv,
            HostAuthority::BackendSql,
            HostAuthority::BackendBlob,
            HostAuthority::BackendMessaging,
        ])
    }

    // ---- VM relay: inherited-fd foreclosure (nit a) range arithmetic ----

    /// The gap ranges preserve stdio + the kept fds, and the final range runs to `u32::MAX` so every
    /// higher fd is foreclosed; a fd kept inside a would-be gap splits it (no kept fd is ever closed).
    #[cfg(target_os = "linux")]
    #[test]
    fn fd_close_ranges_preserve_stdio_and_kept_and_close_the_rest() {
        // No extra kept fds ⇒ keep only 0/1/2, then close everything from 3 up.
        assert_eq!(fd_close_ranges(&[]), vec![(3, u32::MAX)]);
        // A listener on fd 7 (the relay's real shape): close 3..=6 and 8..=MAX, preserve 0/1/2 + 7.
        let r = fd_close_ranges(&[7]);
        assert_eq!(r, vec![(3, 6), (8, u32::MAX)]);
        // The kept fd must NEVER fall inside a closed range.
        for &(lo, hi) in &r {
            assert!(
                !(lo <= 7 && 7 <= hi),
                "fd 7 must be preserved, not in [{lo},{hi}]"
            );
        }
        // A listener + two link fds, given unsorted + with a duplicate and a negative (absent) fd.
        assert_eq!(
            fd_close_ranges(&[9, 4, 4, -1, 7]),
            vec![(3, 3), (5, 6), (8, 8), (10, u32::MAX)]
        );
        // Keeping fd 3 (adjacent to stdio) leaves no 3..low gap — just close 4.. up.
        assert_eq!(fd_close_ranges(&[3]), vec![(4, u32::MAX)]);
        // A negative-only keep set behaves like an empty one (the optional fd was absent).
        assert_eq!(fd_close_ranges(&[-1]), vec![(3, u32::MAX)]);
    }

    // ---- HIGH-1: PR_SET_DUMPABLE(0) (cross-instance /proc/<pid>/mem wall) ----

    /// [`set_process_undumpable`] actually flips the calling process's dumpable flag to 0 (the
    /// mechanism the HIGH-1 fix relies on: a non-dumpable target's `/proc/<pid>/mem` becomes
    /// root-owned + `ptrace_may_access`-gated, so a capless same-uid sibling gets `EPERM`). Reads it
    /// back via `prctl(PR_GET_DUMPABLE)` and RESTORES the prior value so sibling tests in this process
    /// are unaffected. This unit test only guards the PRIMITIVE against an args regression — the full
    /// cross-instance read→`EPERM`/`EACCES` attack is proven LIVE by the `PRIVSEP PROC-MEM WALL OK`
    /// assertion in `crates/boatramp/tests/privsep_live.rs`: while a real `__root` composition is
    /// serving, it forks a capless same-uid sibling that is DENIED reading the crown-jewel `core`
    /// instance's `/proc/<pid>/mem`, and is mutation-verified (revert `set_process_undumpable` ⇒ the
    /// same read SUCCEEDS and the assertion fails).
    #[cfg(target_os = "linux")]
    #[test]
    fn set_process_undumpable_clears_the_dumpable_flag() {
        // SAFETY: `prctl(PR_GET_DUMPABLE)` takes no pointers; it returns the current flag (0/1/2).
        let prior = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        assert!(prior >= 0, "PR_GET_DUMPABLE should not fail: {prior}");
        set_process_undumpable()
            .expect("set_process_undumpable must succeed (needs no capability)");
        // SAFETY: as above.
        let after = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        assert_eq!(after, 0, "the process must be NON-dumpable after the call");
        // Restore the prior dumpable so core-dump/ptrace behavior of other tests is unchanged.
        // SAFETY: scalar args only.
        let _ = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, prior as libc::c_ulong) };
    }

    // ---- Seccomp allow/kill derivation ----

    #[test]
    fn frontend_allows_inbound_but_denies_connect_exec_and_keylock() {
        let allow = derive_seccomp_allowlist(&frontend());
        // Has listeners ⇒ inbound bind/listen/accept allowed.
        for s in NET_INBOUND {
            assert!(has(&allow, s), "frontend must allow inbound {s}");
        }
        // No backend / acme / overlay / gateway / crown jewel ⇒ NO outbound dial.
        assert!(
            !has(&allow, "connect"),
            "frontend must DENY connect (no outbound authority — it forwards inward over the link)"
        );
        // No exec.compute ⇒ execve is NOT in the allow-list AND is KILLED.
        assert!(!has(&allow, "execve") && !has(&allow, "execveat"));
        // ...and the sandbox-install syscalls stay DENIED: only the per-tenant router (exec.compute),
        // which forks children that must self-confine, is granted these (Fix A is scoped).
        for s in [
            "seccomp",
            "landlock_create_ruleset",
            "landlock_add_rule",
            "landlock_restrict_self",
        ] {
            assert!(
                !has(&allow, s),
                "a non-exec.compute instance must NOT be granted the sandbox-install syscall {s}"
            );
        }
        let kill = derive_seccomp_killlist(&frontend());
        assert!(
            has(&kill, "execve") && has(&kill, "execveat"),
            "a non-exec.compute instance hard-kills the exec family"
        );
    }

    #[test]
    fn wsd_finding2_public_parser_cannot_spawn_or_touch_kv_slate() {
        use std::path::Path;
        // The most-exposed public parser, DE-COUPLED (WS-D Finding-2): the SHIPPED parser cap-set
        // `{listen.public-tls, listen.http-parse}` (the public-tls+parse co-location the live gate
        // runs), holding NO `exec.compute` and NO `backend.kv` (the composition-closure lint
        // guarantees this). The per-capability profile must make the containment physical.
        let parser = caps(&[
            HostAuthority::ListenPublicTls,
            HostAuthority::ListenHttpParse,
        ]);
        // (1) It CANNOT spawn: execve/execveat/fork/vfork are NOT in the allow-list, and ARE killed.
        let allow = derive_seccomp_allowlist(&parser);
        let kill = derive_seccomp_killlist(&parser);
        for s in ["execve", "execveat", "fork", "vfork"] {
            assert!(
                !has(&allow, s),
                "the public parser must not be allowed to {s} (it holds no exec.compute)"
            );
            assert!(
                has(&kill, s),
                "the public parser hard-kills {s} (the Finding-2 spawn wall)"
            );
        }
        // (2) It gets NO backend-state grant: holding no backend.kv, the kv-slate subtree is not in
        // its FS view at all (so a parser RCE cannot even open the control-plane KV).
        let data_dir = Path::new("/data");
        assert!(
            instance_backend_state_grants(&parser, data_dir).is_empty(),
            "the public parser must get no backend-state grant (no backend.kv ⇒ no kv-slate subtree)"
        );
        // (3) Complement: the non-public SUPERVISOR — where the split PUT spawn + KV — DOES get both.
        let supervisor = caps(&[HostAuthority::BackendKv, HostAuthority::ExecCompute]);
        let sup_allow = derive_seccomp_allowlist(&supervisor);
        assert!(
            has(&sup_allow, "execve") && has(&sup_allow, "fork"),
            "the supervisor (exec.compute) MAY fork/execve — the spawn authority lives on it, off \
             the public parser"
        );
        let grants = instance_backend_state_grants(&supervisor, data_dir);
        assert!(
            grants.iter().any(|p| p.ends_with("kv-slate")),
            "the supervisor (backend.kv) gets the kv-slate rw subtree — the KV authority lives on \
             it, off the public parser; got {grants:?}"
        );
    }

    #[test]
    fn no_listener_instance_denies_bind_and_listen() {
        for set in [signer(), storage()] {
            let allow = derive_seccomp_allowlist(&set);
            for s in ["bind", "listen", "accept", "accept4"] {
                assert!(
                    !has(&allow, s),
                    "a no-listener instance must DENY {s} (derived: {allow:?})"
                );
            }
        }
    }

    #[test]
    fn signer_only_allows_keylock_and_outbound_denies_listeners_and_exec() {
        let allow = derive_seccomp_allowlist(&signer());
        // Crown jewels hold mlocked key material.
        assert!(has(&allow, "mlock") && has(&allow, "munlock"));
        // A KMS/Vault-backed signer may dial out.
        assert!(has(&allow, "connect"));
        // No listeners, no compute spawn.
        assert!(!has(&allow, "bind") && !has(&allow, "listen"));
        assert!(!has(&allow, "execve"));
        assert!(has(&derive_seccomp_killlist(&signer()), "execve"));
    }

    #[test]
    fn storage_allows_outbound_but_denies_keylock_listeners_and_exec() {
        let allow = derive_seccomp_allowlist(&storage());
        assert!(has(&allow, "connect"), "backends dial their pools");
        // Holds no key material ⇒ mlock denied.
        assert!(
            !has(&allow, "mlock"),
            "a pure data-plane instance locks no key ⇒ mlock denied"
        );
        assert!(!has(&allow, "bind") && !has(&allow, "listen"));
        assert!(!has(&allow, "execve"));
        assert!(has(&derive_seccomp_killlist(&storage()), "execve"));
    }

    #[test]
    fn exec_compute_allows_the_spawn_family_and_drops_it_from_the_kill_list() {
        let set = caps(&[HostAuthority::ExecCompute]);
        let allow = derive_seccomp_allowlist(&set);
        assert!(
            has(&allow, "execve") && has(&allow, "execveat"),
            "the compute-supervisor must be able to re-exec its workers"
        );
        // ...and `fork`/`vfork`: the per-tenant router forks the child (musl `Command`+`pre_exec`
        // issues a BARE `fork(2)`) UNDER its installed sandbox before it `execve`s — without this it
        // dies with a real `SIGSYS` on `fork(2)` at cold-start (regression against the audited bug).
        assert!(
            has(&allow, "fork") && has(&allow, "vfork"),
            "the compute-supervisor must be able to fork its child before exec"
        );
        // ...and the sandbox-install syscalls: a per-tenant child forked from this confined router
        // inherits THIS filter and must be able to install its own nested seccomp + Landlock profile
        // over it (else its `seccomp` install is `EPERM`'d AND its Landlock ABI probe degrades to an
        // empty access set → `empty access-right`). Monotonic, so safe. See [`SANDBOX_INSTALL`].
        for s in [
            "seccomp",
            "landlock_create_ruleset",
            "landlock_add_rule",
            "landlock_restrict_self",
        ] {
            assert!(
                has(&allow, s),
                "the compute-supervisor must be able to install its child's nested sandbox: {s}"
            );
        }
        let kill = derive_seccomp_killlist(&set);
        assert!(
            !has(&kill, "execve") && !has(&kill, "execveat"),
            "exec.compute must NOT kill the exec family it legitimately uses"
        );
        assert!(
            !has(&kill, "fork") && !has(&kill, "vfork"),
            "exec.compute must NOT kill the fork family it legitimately uses"
        );
        // Every OTHER instance still kills both — proven by the frontend/signer/storage tests.
    }

    #[test]
    fn monolith_derivation_is_a_superset_of_the_phase0_allowlist() {
        // The `all` composition (design §5.5 default-monolith invariant) must never LOSE a
        // syscall the released Phase-0 monolith allow-list has; the ONLY extras it adds are the
        // exec + fork spawn families and the sandbox-install syscalls, present solely because `all`
        // includes exec.compute.
        let allow: BTreeSet<String> = derive_seccomp_allowlist(&all_caps()).into_iter().collect();
        let phase0: BTreeSet<String> = whole_process_allowlist().into_iter().collect();
        assert!(
            phase0.is_subset(&allow),
            "derive(ALL) must cover the Phase-0 monolith allow-list; missing: {:?}",
            phase0.difference(&allow).collect::<Vec<_>>()
        );
        let extra: BTreeSet<String> = allow.difference(&phase0).cloned().collect();
        let expected: BTreeSet<String> = [
            "execve",
            "execveat",
            "fork",
            "vfork",
            "seccomp",
            "landlock_create_ruleset",
            "landlock_add_rule",
            "landlock_restrict_self",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        assert_eq!(
            extra, expected,
            "derive(ALL) adds exactly the exec + fork spawn families + the sandbox-install syscalls \
             over Phase-0 (exec.compute ∈ ALL)"
        );
    }

    // ---- Landlock key-path gating + the fail-closed leak check ----

    fn inputs_with_keys(data_dir: &str) -> SandboxDerivationInputs {
        let mut inp = SandboxDerivationInputs::for_instance(data_dir, None);
        // Keys deliberately placed OUTSIDE the granted subtrees (a dedicated keystore).
        inp.keys = KeyInputPaths {
            kek_file: Some(PathBuf::from("/keys/kek")),
            sealed_signer_key_file: None,
            token_signer_key: Some(PathBuf::from("/keys/token-signer.pem")),
            image_signer_key: Some(PathBuf::from("/keys/image-signer.pem")),
            overlay_seed: Some(PathBuf::from("/keys/overlay.seed")),
            s3_ingress_secret: Some(PathBuf::from("/keys/s3ingress.root")),
            cluster_root_key: Some(PathBuf::from("/keys/cluster.root")),
        };
        inp
    }

    fn all_fs_paths(p: &SandboxPolicy) -> Vec<PathBuf> {
        p.read_only_paths
            .iter()
            .chain(p.read_write_paths.iter())
            .cloned()
            .collect()
    }

    #[test]
    fn frontend_profile_has_no_grant_to_any_crown_jewel_key_path() {
        let inp = inputs_with_keys("/data");
        let profile = derive_profile(&frontend(), SandboxPosture::Derived, &inp)
            .expect("frontend derivation is clean (keys live outside its grants)");
        let fs = all_fs_paths(&profile.policy);
        for key in [
            "/keys/kek",
            "/keys/token-signer.pem",
            "/keys/image-signer.pem",
            "/keys/overlay.seed",
            "/keys/s3ingress.root",
            "/keys/cluster.root",
        ] {
            assert!(
                !fs.contains(&PathBuf::from(key)),
                "a frontend (no crown jewels) must have NO FS grant to {key}; grants: {fs:?}"
            );
        }
    }

    #[test]
    fn signer_profile_grants_exactly_its_own_key_paths() {
        let inp = inputs_with_keys("/data");
        let profile =
            derive_profile(&signer(), SandboxPosture::Derived, &inp).expect("signer derivation");
        // The KEK is read-WRITE (first-run gen); the rest read-only.
        assert!(
            profile
                .policy
                .read_write_paths
                .contains(&PathBuf::from("/keys/kek"))
        );
        for ro in [
            "/keys/token-signer.pem",
            "/keys/image-signer.pem",
            "/keys/overlay.seed",
            "/keys/s3ingress.root",
            "/keys/cluster.root",
        ] {
            assert!(
                profile.policy.read_only_paths.contains(&PathBuf::from(ro)),
                "the signer must hold its own key {ro} read-only"
            );
        }
    }

    #[test]
    fn execute_is_confined_to_the_execute_pin_not_the_general_grants() {
        // An exec.compute router: SYSTEM_READ_ROOTS read-only, a kv-slate backend subtree
        // read-write, and its OWN binary as the execute-pin. The derived policy must carry Execute
        // ONLY on the own binary — NEVER on a system read root, NEVER on the writable kv-slate.
        let exe = PathBuf::from("/opt/boatramp/bin/boatramp");
        let kv_slate = PathBuf::from("/data/kv-slate");
        let mut inp = SandboxDerivationInputs::for_instance("/data", None);
        inp.base_read_write = vec![kv_slate.clone()];
        inp.execute_paths = vec![exe.clone()];
        let profile = derive_profile(
            &caps(&[HostAuthority::ExecCompute]),
            SandboxPosture::Derived,
            &inp,
        )
        .expect("exec.compute router derives a clean profile");

        // The execute-pin is EXACTLY the own binary.
        assert_eq!(
            profile.policy.execute_paths,
            vec![exe.clone()],
            "Execute is pinned to the own binary alone"
        );
        // NOT the system read roots.
        for root in SYSTEM_READ_ROOTS {
            assert!(
                !profile.policy.execute_paths.contains(&PathBuf::from(root)),
                "a system read root ({root}) must NOT be executable"
            );
        }
        // NOT the writable kv-slate backend state (the finding's core: no ELF-drop-then-exec).
        assert!(
            !profile.policy.execute_paths.contains(&kv_slate),
            "the writable kv-slate backend state must NOT be executable"
        );

        // A non-exec.compute instance (no execute-pin supplied) gets Execute NOWHERE.
        let mut backend = SandboxDerivationInputs::for_instance("/data", None);
        backend.base_read_write = vec![kv_slate.clone()];
        let backend_profile = derive_profile(
            &caps(&[HostAuthority::BackendKv]),
            SandboxPosture::Derived,
            &backend,
        )
        .expect("backend derives a clean profile");
        assert!(
            backend_profile.policy.execute_paths.is_empty(),
            "a non-exec.compute instance has Execute granted NOWHERE"
        );
    }

    #[test]
    fn a_granted_subtree_that_would_expose_a_non_held_key_is_fail_closed() {
        // A frontend granted `/data/shared` (a narrow subtree under data_dir) while a sibling's
        // KEK lives UNDER it would transitively expose it — the derivation REFUSES (design §2
        // step 3), spawning nothing. (The grant is a subtree of data_dir, NOT data_dir itself,
        // so this isolates the crown-jewel-key check from the OverbroadStateGrant check below.)
        let mut inp = SandboxDerivationInputs::for_instance("/data", None);
        inp.base_read_write = vec![PathBuf::from("/data/shared")];
        inp.keys.kek_file = Some(PathBuf::from("/data/shared/kek"));
        let err = derive_profile(&frontend(), SandboxPosture::Derived, &inp)
            .expect_err("a non-holder's grant must not transitively expose a key path");
        match err {
            ProfileDerivationError::CrownJewelKeyLeak {
                authority,
                key_path,
                via,
            } => {
                assert_eq!(authority, HostAuthority::SecretsSealer);
                assert_eq!(key_path, PathBuf::from("/data/shared/kek"));
                assert_eq!(via, PathBuf::from("/data/shared"));
            }
            other => panic!("expected CrownJewelKeyLeak, got {other:?}"),
        }

        // The HOLDER (a sealer) with the SAME overlapping grant is fine — it legitimately
        // reaches its own key.
        let sealer = caps(&[HostAuthority::SecretsSealer]);
        derive_profile(&sealer, SandboxPosture::Derived, &inp)
            .expect("the key's own holder may be granted a subtree containing it");
    }

    #[test]
    fn an_overbroad_grant_of_the_data_dir_root_is_fail_closed_for_everyone() {
        // Finding 3 / flag #6: granting the whole data_dir exposes EVERY authority's backend
        // state — refused for a non-holder AND even for a crown-jewel holder (nobody gets the
        // shared state root; each instance gets its own narrow subtree under it).
        let mut inp = SandboxDerivationInputs::for_instance("/data", None);
        inp.base_read_write = vec![PathBuf::from("/data")];
        for who in [frontend(), caps(&[HostAuthority::SecretsSealer]), storage()] {
            let err = derive_profile(&who, SandboxPosture::Derived, &inp)
                .expect_err("granting the data_dir root is over-broad for any instance");
            match err {
                ProfileDerivationError::OverbroadStateGrant { via, data_dir } => {
                    assert_eq!(via, PathBuf::from("/data"));
                    assert_eq!(data_dir, PathBuf::from("/data"));
                }
                other => panic!("expected OverbroadStateGrant, got {other:?}"),
            }
        }

        // An ANCESTOR of data_dir is equally refused.
        let mut ancestor = SandboxDerivationInputs::for_instance("/data/node", None);
        ancestor.base_read_only.push(PathBuf::from("/data"));
        assert!(
            matches!(
                derive_profile(&frontend(), SandboxPosture::Derived, &ancestor),
                Err(ProfileDerivationError::OverbroadStateGrant { .. })
            ),
            "a grant that is an ancestor of data_dir is over-broad"
        );
    }

    #[test]
    fn a_data_dir_placed_under_a_shared_temp_dir_is_fail_closed() {
        // Security re-review residual #3: data_dir UNDER a declared shared_temp dir would be
        // exposed to every instance via the (exempt) world-writable temp grant — refused for
        // any instance, regardless of posture.
        let mut inp = SandboxDerivationInputs::for_instance("/tmp/boatramp", None);
        inp.shared_temp = vec![PathBuf::from("/tmp")];
        for posture in [SandboxPosture::Derived, SandboxPosture::Strict] {
            assert!(
                matches!(
                    derive_profile(&frontend(), posture, &inp),
                    Err(ProfileDerivationError::OverbroadStateGrant { .. })
                ),
                "data_dir under a shared_temp dir must be refused (posture {posture:?})"
            );
        }
        // A data_dir NOT under shared_temp is fine.
        let ok = SandboxDerivationInputs::for_instance("/var/lib/boatramp", None);
        derive_profile(&frontend(), SandboxPosture::Derived, &ok)
            .expect("a data_dir outside the temp dirs derives cleanly");
    }

    #[test]
    fn a_grant_overlapping_a_non_held_authority_state_subtree_is_fail_closed() {
        // Finding 3 (non-key data subtrees): a frontend (no backend.kv) granted a subtree that
        // overlaps the declared backend.kv state dir must be refused; the backend.kv HOLDER is
        // fine. Overlap is checked in BOTH directions (grant ⊇ state, and grant ⊆ state).
        let mut inp = SandboxDerivationInputs::for_instance("/data", None);
        inp.authority_state_dirs
            .insert(HostAuthority::BackendKv, vec![PathBuf::from("/data/kv")]);

        // (a) grant equals the kv state dir.
        inp.base_read_write = vec![PathBuf::from("/data/kv")];
        let err = derive_profile(&frontend(), SandboxPosture::Derived, &inp)
            .expect_err("a non-holder must not reach the backend.kv state");
        assert!(matches!(
            err,
            ProfileDerivationError::CrossAuthorityStateLeak { authority, .. }
                if authority == HostAuthority::BackendKv
        ));
        // The kv holder (storage) legitimately reaches it.
        derive_profile(&storage(), SandboxPosture::Derived, &inp)
            .expect("the backend.kv holder may be granted its own state subtree");

        // (b) grant lies INSIDE the kv state dir (a sub-path) — still a leak for a non-holder.
        inp.base_read_write = vec![PathBuf::from("/data/kv/tenant-a")];
        assert!(matches!(
            derive_profile(&frontend(), SandboxPosture::Derived, &inp),
            Err(ProfileDerivationError::CrossAuthorityStateLeak { .. })
        ));
    }

    #[test]
    fn strict_drops_shared_temp_derived_keeps_it() {
        let mut inp = SandboxDerivationInputs::for_instance("/data", None);
        inp.shared_temp = vec![PathBuf::from("/tmp")];
        let derived = derive_profile(&storage(), SandboxPosture::Derived, &inp).unwrap();
        assert!(
            derived
                .policy
                .read_write_paths
                .contains(&PathBuf::from("/tmp"))
        );
        let strict = derive_profile(&storage(), SandboxPosture::Strict, &inp).unwrap();
        assert!(
            !strict
                .policy
                .read_write_paths
                .contains(&PathBuf::from("/tmp")),
            "Strict drops the shared system temp dirs"
        );
    }

    // ---- SandboxPosture reconciliation + fail-closed-fleetwide decision ----

    #[test]
    fn posture_enforcement_mapping() {
        assert_eq!(
            SandboxPosture::Derived.enforcement(),
            ProfileEnforcement::RequireEnforced
        );
        assert_eq!(
            SandboxPosture::Strict.enforcement(),
            ProfileEnforcement::RequireEnforced
        );
        assert_eq!(
            SandboxPosture::Off.enforcement(),
            ProfileEnforcement::DevOnlyOff
        );
        assert!(SandboxPosture::Derived.installs_profile());
        assert!(!SandboxPosture::Off.installs_profile());
    }

    #[test]
    fn install_plan_enforces_fail_closed_rules() {
        // Derived / Strict ⇒ install + require Enforced.
        assert_eq!(
            privsep_install_plan(SandboxPosture::Derived, false).unwrap(),
            PrivsepInstallPlan::InstallEnforced(SandboxPosture::Derived)
        );
        assert_eq!(
            privsep_install_plan(SandboxPosture::Strict, true).unwrap(),
            PrivsepInstallPlan::InstallEnforced(SandboxPosture::Strict)
        );
        // Off on a dev node ⇒ skip; Off on a non-dev node ⇒ fail-closed REFUSAL.
        assert_eq!(
            privsep_install_plan(SandboxPosture::Off, true).unwrap(),
            PrivsepInstallPlan::SkipDevOff
        );
        assert_eq!(
            privsep_install_plan(SandboxPosture::Off, false).unwrap_err(),
            PrivsepSandboxError::DevOffOnEnforcedNode
        );
    }

    #[test]
    fn enforce_status_refuses_anything_less_than_enforced() {
        // The load-bearing contrast with Phase-0 `auto`: Partial is REFUSED under [privsep].
        assert_eq!(
            enforce_privsep_status(Ok(SandboxStatus::Enforced)).unwrap(),
            SandboxStatus::Enforced
        );
        assert_eq!(
            enforce_privsep_status(Ok(SandboxStatus::Partial)).unwrap_err(),
            PrivsepSandboxError::NotEnforced {
                status: SandboxStatus::Partial
            }
        );
        assert_eq!(
            enforce_privsep_status(Ok(SandboxStatus::Unsupported)).unwrap_err(),
            PrivsepSandboxError::NotEnforced {
                status: SandboxStatus::Unsupported
            }
        );
        assert_eq!(
            enforce_privsep_status(Ok(SandboxStatus::Disabled)).unwrap_err(),
            PrivsepSandboxError::NotEnforced {
                status: SandboxStatus::Disabled
            }
        );
        match enforce_privsep_status(Err(SandboxError::Seccomp("boom".into()))) {
            Err(PrivsepSandboxError::InstallFailed(msg)) => assert!(msg.contains("boom")),
            other => panic!("expected InstallFailed, got {other:?}"),
        }
    }

    // ---- WS-C CONTRACT #1: lexical path normalization (evasion cases) ----

    #[test]
    fn lexically_normalize_resolves_dotdot_dot_and_separators() {
        // `..` is resolved against the preceding real component.
        assert_eq!(
            lexically_normalize(Path::new("/weird/../data/kv")),
            PathBuf::from("/data/kv")
        );
        // `.` and repeated/trailing separators collapse.
        assert_eq!(
            lexically_normalize(Path::new("/data/./kv/")),
            PathBuf::from("/data/kv")
        );
        assert_eq!(
            lexically_normalize(Path::new("/data//kv///")),
            PathBuf::from("/data/kv")
        );
        // A `..` at the absolute root is dropped (root's parent is root).
        assert_eq!(
            lexically_normalize(Path::new("/../../etc")),
            PathBuf::from("/etc")
        );
        // A relative path keeps a leading `..` (no known root), but resolves interior `..`.
        assert_eq!(
            lexically_normalize(Path::new("../a/../b")),
            PathBuf::from("../b")
        );
        // The crux: a `..` escape that would land on data_dir is normalized to data_dir, so the
        // lexical leak check in derive_profile can no longer be dodged by a non-canonical spelling.
        assert_eq!(
            lexically_normalize(Path::new("/data/kv/../../data/kv")),
            PathBuf::from("/data/kv")
        );
    }

    #[test]
    fn into_normalized_makes_grants_absolute_and_canonical_before_derive() {
        // A relative data_dir (the `./data` default) + a `..`-spelled grant both normalize so the
        // OverbroadStateGrant floor fires: without normalization the lexical `starts_with` check
        // would miss `/srv/data/../data` ⊇ `/srv/data`.
        let cwd = Path::new("/srv");
        let mut inp = SandboxDerivationInputs::for_instance("data", None); // relative → /srv/data
        inp.base_read_write = vec![PathBuf::from("/srv/data/../data")]; // == /srv/data (the root!)
        let normalized = inp.into_normalized(cwd);
        assert_eq!(normalized.data_dir, PathBuf::from("/srv/data"));
        assert_eq!(
            normalized.base_read_write,
            vec![PathBuf::from("/srv/data")],
            "the `..` spelling must normalize to the data_dir root"
        );
        let err = derive_profile(&frontend(), SandboxPosture::Derived, &normalized)
            .expect_err("a `..`-spelled data_dir-root grant must be caught after normalization");
        assert!(matches!(
            err,
            ProfileDerivationError::OverbroadStateGrant { .. }
        ));
    }

    // ---- WS-C CONTRACT #2: backend-state layout + composition-layer grant check ----

    #[test]
    fn backend_state_layout_is_total_and_disjoint() {
        let dirs = backend_authority_state_dirs(Path::new("/data"));
        // Every backend authority (and ONLY backend authorities) has a state subtree.
        for a in HostAuthority::ALL.iter().copied() {
            assert_eq!(
                dirs.contains_key(&a),
                a.is_backend(),
                "{} coverage mismatch",
                a.tag()
            );
        }
        // The subtrees are pairwise disjoint.
        let all: Vec<&PathBuf> = dirs.values().flatten().collect();
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert!(
                    !path_contains(all[i], all[j]) && !path_contains(all[j], all[i]),
                    "backend state dirs must be disjoint: {:?} vs {:?}",
                    all[i],
                    all[j]
                );
            }
        }
    }

    #[test]
    fn grant_disjointness_passes_a_clean_split_and_refuses_a_duplicated_backend() {
        let data = Path::new("/data");
        // Clean: edge (listeners/exec/control, no backends), storage (all four backends), signer.
        let mut clean = BTreeMap::new();
        clean.insert("edge".to_string(), frontend());
        clean.insert("storage".to_string(), storage());
        clean.insert("signer".to_string(), signer());
        check_grant_disjointness(&clean, data).expect("a clean least-authority split is disjoint");

        // A backend held by TWO instances ⇒ their state grants collide ⇒ fail-closed.
        let mut dup = BTreeMap::new();
        dup.insert("a".to_string(), caps(&[HostAuthority::BackendKv]));
        dup.insert("b".to_string(), caps(&[HostAuthority::BackendKv]));
        let err = check_grant_disjointness(&dup, data).unwrap_err();
        assert!(matches!(
            err,
            CompositionGrantError::OverlappingGrants { .. }
        ));
    }

    // Phase-5 P5-6 precondition (owner-gated grant, NOT wired): the node-own `exec.wasmtime`
    // compile-cache subtree the self-host flip will grant RW EXCLUSIVELY to the node-own exec
    // instance must stay disjoint from EVERY backend-state subtree. If it ever collided, granting it
    // RW would overlap a backend-state grant and silently share a state root across the wall — and
    // because the cache is loaded as executable code WITHOUT a content MAC (the `aot` HMAC gate covers
    // only the cluster/blob path, not this local cache), that overlap is a cache-poisoning → RCE seam.
    #[test]
    fn reserved_exec_cache_subtree_is_disjoint_from_every_backend_state_grant_and_ungranted_today() {
        let data = Path::new("/data");
        let reserved = node_own_exec_cache_dir(data);
        assert_eq!(
            reserved,
            data.join("wasmtime-cache"),
            "the reserved subtree must stay in lockstep with build_persistent_cache's literal"
        );

        // The reserved cache subtree collides with NO backend's state subtree (the invariant the
        // disjointness tripwire protects), and NO exec authority owns a backend-state subtree — so
        // the cache stays UNGRANTED today (the grant is the owner-gated P5-6 flip).
        for a in HostAuthority::ALL.iter().copied() {
            match backend_state_subdir(a) {
                Some(sub) => {
                    let backend_dir = data.join(sub);
                    assert!(
                        !path_contains(&backend_dir, &reserved)
                            && !path_contains(&reserved, &backend_dir),
                        "backend {} state subtree {backend_dir:?} collides with reserved exec cache {reserved:?}",
                        a.tag()
                    );
                }
                None => assert!(
                    !a.is_backend(),
                    "backend {} lacks a state-dir layout entry",
                    a.tag()
                ),
            }
        }
        assert_eq!(
            backend_state_subdir(HostAuthority::ExecWasmtime),
            None,
            "exec.wasmtime holds no backend-state subtree — the cache grant is the P5-6 flip, not a live grant"
        );

        // The tripwire is INERT for a real all-backends composition (the one that also holds
        // exec.wasmtime on a sibling frontend), so this safe groundwork regresses no composition.
        let mut clean = BTreeMap::new();
        clean.insert("storage".to_string(), storage());
        clean.insert("edge".to_string(), frontend());
        check_grant_disjointness(&clean, data)
            .expect("the reserved exec-cache tripwire is inert for the canonical backend layout");

        // The tripwire's predicate DOES fire for a (hypothetical) backend mapped onto the reserved
        // name — exercising the exact `path_contains` condition the check evaluates per backend.
        let hypothetical_collision = data.join(NODE_OWN_EXEC_CACHE_SUBDIR);
        assert!(
            path_contains(&hypothetical_collision, &reserved)
                && path_contains(&reserved, &hypothetical_collision),
            "a backend mapped onto the reserved subtree must trip the P5-6 collision guard"
        );
    }

    // ---- The root supervisor's bespoke self-profile (design §4.3) ----

    #[test]
    fn root_allowlist_is_a_tight_subset_with_execve_but_no_net_or_keylock() {
        let allow = root_supervisor_allowlist();

        // `execve`/`execveat` stay ALLOWED — the re-exec of `boatramp __instance` is the root's
        // single retained privileged primitive (Landlock-pinned, not killed).
        assert!(
            has(&allow, "execve") && has(&allow, "execveat"),
            "the root must retain execve/execveat (Landlock-pinned re-exec primitive)"
        );

        // No networking at all (the root binds its listeners + creates its socketpairs BEFORE
        // the profile installs; the supervise loop does no socket I/O) and no key-locking (the
        // root unseals/mlocks no key material — it is secret-blind).
        for s in ROOT_NET_STRIP {
            assert!(
                !has(&allow, s),
                "the root must DENY the networking syscall {s}"
            );
        }
        for s in KEY_LOCK {
            assert!(
                !has(&allow, s),
                "the root must DENY the key-lock syscall {s}"
            );
        }

        // The supervise loop + fail-closed teardown + tracing + the re-exec wiring all survive.
        for s in [
            "wait4",
            "waitid", // supervise poll + reap
            "kill",   // teardown SIGKILL
            "clone",
            "clone3", // fork(via clone) for spawn/restart
            "dup2",
            "dup3",
            "fcntl", // child pre_exec wiring
            "prctl", // PR_SET_PDEATHSIG + no_new_privs
            "close",
            "read",
            "write", // tracing + fd close + config re-read
            "nanosleep",
            "clock_nanosleep",
            "futex",
            "exit_group",
        ] {
            assert!(has(&allow, s), "the root supervise/teardown path needs {s}");
        }

        // Every allowed name is in the Phase-0 baseline ∪ {execve, execveat} — a STRICT SUBSET,
        // never a superset (the root adds no syscall the monolith doesn't already have except the
        // deliberately-retained exec family).
        let baseline: BTreeSet<String> = whole_process_allowlist()
            .into_iter()
            .chain(EXEC_SPAWN.iter().map(|s| (*s).to_string()))
            .collect();
        for s in &allow {
            assert!(
                baseline.contains(s),
                "the root allow-set must stay within the Phase-0 baseline ∪ exec: {s} is foreign"
            );
        }
        // And it is strictly SMALLER than the baseline (it drops the whole networking + key-lock
        // surface), proving it is genuinely tighter than Phase 0.
        assert!(
            allow.len() < baseline.len(),
            "the root allow-set must be strictly tighter than the Phase-0 baseline"
        );
    }

    #[test]
    fn root_killlist_keeps_the_escape_surface_but_not_execve() {
        let kill = root_supervisor_killlist();
        // execve/execveat are NOT killed (the root re-execs instances) — the exception design
        // §4.3 carves out.
        assert!(
            !has(&kill, "execve") && !has(&kill, "execveat"),
            "the root must NOT kill execve/execveat (it would break the re-exec primitive)"
        );
        // The rest of the escape / code-injection surface stays hard-SIGSYS.
        for s in [
            "ptrace",
            "mount",
            "pivot_root",
            "setns",
            "unshare",
            "bpf",
            "keyctl",
        ] {
            assert!(
                has(&kill, s),
                "the root must still hard-kill the escape syscall {s}"
            );
        }
        // It is exactly KILL_SURFACE minus the exec family.
        let expected: BTreeSet<String> = KILL_SURFACE
            .iter()
            .copied()
            .filter(|s| !EXEC_SPAWN.contains(s))
            .map(str::to_string)
            .collect();
        assert_eq!(kill.into_iter().collect::<BTreeSet<_>>(), expected);
    }

    #[test]
    fn root_policy_grants_only_config_and_own_binary_no_key_no_data_dir() {
        let exe = PathBuf::from("/usr/local/bin/boatramp");
        let config = PathBuf::from("/etc/boatramp/boatramp.cfg");
        let policy = root_supervisor_policy(&exe, &config);

        // The FS view is EXACTLY the own binary (RO + execute) + the config FILE (RO). Nothing
        // is read-write — the root writes nothing.
        assert_eq!(policy.read_only_paths, vec![exe.clone(), config.clone()]);
        assert!(policy.read_write_paths.is_empty());

        // EXECUTE is pinned to the own binary ALONE (never the config file): `build_ruleset`
        // strips Execute from the read grant and re-grants it only on `execute_paths`.
        assert_eq!(
            policy.execute_paths,
            vec![exe.clone()],
            "the root's EXECUTE pin is its own binary and nothing else"
        );
        assert!(
            !policy.execute_paths.contains(&config),
            "the config file must never be executable"
        );

        // No §1.2 key input path, no data_dir, no instance state is anywhere in the view — the
        // root cannot open a crown-jewel key file even by accident (design F1/F11-A).
        let forbidden = [
            PathBuf::from("/srv/node/secrets/kek"),
            PathBuf::from("/srv/node/secrets/signer.sealed"),
            PathBuf::from("/srv/node/overlay/seed"),
            PathBuf::from("/var/lib/boatramp/data"), // a data_dir
            PathBuf::from("/var/lib/boatramp/data/kv"), // a backend state subtree
        ];
        let granted: BTreeSet<&PathBuf> = policy
            .read_only_paths
            .iter()
            .chain(policy.read_write_paths.iter())
            .collect();
        for f in &forbidden {
            assert!(
                !granted.contains(f),
                "a key/data_dir path must be ABSENT from the root's FS view: {f:?}"
            );
            // And not merely absent as an exact entry — no granted path is an ancestor of it.
            for g in &granted {
                assert!(
                    !path_contains(g, f),
                    "no root grant {g:?} may be an ancestor of the forbidden path {f:?}"
                );
            }
        }

        // The config file is granted as the FILE, not its parent directory (the WS-C
        // config-file-grant lesson — a config dir could contain data_dir).
        assert!(policy.read_only_paths.contains(&config));
        assert!(
            !policy
                .read_only_paths
                .contains(&config.parent().unwrap().to_path_buf())
        );
    }

    #[test]
    fn derive_root_profile_ties_the_bespoke_lists_and_policy_together() {
        let exe = PathBuf::from("/usr/local/bin/boatramp");
        let config = PathBuf::from("/etc/boatramp/boatramp.cfg");
        let profile = derive_root_profile(&exe, &config);
        assert_eq!(profile.posture, SandboxPosture::Strict);
        assert_eq!(profile.seccomp_allow, root_supervisor_allowlist());
        assert_eq!(profile.seccomp_kill, root_supervisor_killlist());
        assert_eq!(profile.policy, root_supervisor_policy(&exe, &config));
        // The profile install path ([`install_derived`]) grants only read_only/read_write — so the
        // bespoke policy's two RO paths are the complete FS view.
        assert_eq!(profile.policy.read_only_paths.len(), 2);
    }

    // ---- The separate VM client-byte relay's bespoke self-profile (scoped VM substrate, S1) ----

    #[test]
    fn relay_allowlist_keeps_accept_connect_but_no_bind_listen_socketpair_keylock_or_exec() {
        let allow = relay_supervisor_allowlist();

        // The relay DOES accept clients on the inherited listener + dial the guest over the vsock UDS,
        // and splice bytes both ways — so the connecting/accepting/byte verbs it needs survive.
        for s in [
            "socket", "connect", "accept", "accept4", "shutdown", "read", "write",
        ] {
            assert!(has(&allow, s), "the relay byte-pipe needs {s}");
        }

        // NO listener-bind verbs: the root binds the privileged public listener and passes the fd
        // pre-bound — the relay never binds/listens. NO `socketpair`: the relay holds no feature-link
        // (unlike a host-side instance's `local` socketpair). NO key-locking: the relay holds no key
        // material (the HARD EXCLUSION). NO exec: it is exec'd ONCE by the root and re-execs NOTHING.
        //
        // These are LITERAL names, NOT a loop over `RELAY_NET_STRIP` — a tautology (every element of
        // the strip set is denied by construction) would not bind, so dropping a name from the strip
        // set could silently re-admit it. With the literals, removing (say) `bind` from
        // `RELAY_NET_STRIP` re-admits it to the allow-set and REDDENS this test (the mutation guard).
        for denied in [
            "bind",       // listener-bind: the fd arrives pre-bound
            "listen",     // ditto
            "socketpair", // no feature-link
            "mlock",      // KEY_LOCK: holds no key material
            "munlock",    // KEY_LOCK
            "execve",     // re-execs nothing (tighter than the root, which retains execve)
            "execveat",   // ditto
        ] {
            assert!(
                !has(&allow, denied),
                "the relay must DENY {denied} (least-authority, secret-blind, re-execs nothing)"
            );
        }
        // And the literal forbidden set is EXACTLY the authority dimensions the profile strips (so the
        // guard above tracks the real strip set, not a stale hand-list): the net/socketpair strip +
        // key-lock, with exec deliberately never re-added (unlike the root).
        let stripped: BTreeSet<&str> = RELAY_NET_STRIP
            .iter()
            .copied()
            .chain(KEY_LOCK.iter().copied())
            .collect();
        assert_eq!(
            stripped,
            ["bind", "listen", "socketpair", "mlock", "munlock"]
                .into_iter()
                .collect::<BTreeSet<&str>>(),
            "the relay strip set (RELAY_NET_STRIP ∪ KEY_LOCK) must stay exactly these five verbs"
        );

        // Every allowed name is in the Phase-0 baseline — a STRICT SUBSET, adding NOTHING (no execve
        // like the root, no sandbox-install family like exec.compute).
        let baseline: BTreeSet<String> = ALLOWED.iter().map(|s| (*s).to_string()).collect();
        for s in &allow {
            assert!(
                baseline.contains(s),
                "the relay allow-set must stay within the Phase-0 ALLOWED baseline: {s} is foreign"
            );
        }
        assert!(
            allow.len() < baseline.len(),
            "the relay allow-set must be strictly tighter than the Phase-0 baseline"
        );

        // Strictly narrower than the BROADEST instance profile (the monolith `ALL`): the relay's allow
        // is a strict subset of what an instance holding every capability gets (it drops the
        // listener-bind + socketpair + key-lock verbs the monolith keeps, and adds none of the
        // exec/fork/sandbox-install family an `exec.compute` instance gains).
        let broadest: BTreeSet<String> =
            derive_seccomp_allowlist(&all_caps()).into_iter().collect();
        let relay: BTreeSet<String> = allow.iter().cloned().collect();
        assert!(
            relay.is_subset(&broadest) && relay.len() < broadest.len(),
            "the relay allow-set must be a STRICT subset of the broadest instance profile"
        );
    }

    #[test]
    fn relay_killlist_is_the_full_surface_including_exec_and_fork() {
        let kill = relay_supervisor_killlist();
        // The relay execs + forks NOTHING — unlike the root (keeps execve) and exec.compute (keeps
        // execve + fork), the relay hard-SIGSYS-kills the whole exec + process-creation surface.
        for s in ["execve", "execveat", "fork", "vfork"] {
            assert!(
                has(&kill, s),
                "the relay must hard-kill {s} (it spawns + execs nothing)"
            );
        }
        // And the rest of the escape / code-injection surface.
        for s in [
            "ptrace",
            "mount",
            "pivot_root",
            "setns",
            "unshare",
            "bpf",
            "keyctl",
        ] {
            assert!(
                has(&kill, s),
                "the relay must still hard-kill the escape syscall {s}"
            );
        }
        // It is EXACTLY the full, unmodified KILL_SURFACE (no carve-out).
        let expected: BTreeSet<String> = KILL_SURFACE.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(kill.iter().cloned().collect::<BTreeSet<_>>(), expected);

        // A SUPERSET of every instance's kill-set (strictly so for an exec.compute instance, which
        // carves execve + fork OUT of its kill-set). No instance kills more than the relay.
        for caps in [frontend(), all_caps(), caps(&[HostAuthority::ExecCompute])] {
            let inst: BTreeSet<String> = derive_seccomp_killlist(&caps).into_iter().collect();
            let relay: BTreeSet<String> = kill.iter().cloned().collect();
            assert!(
                inst.is_subset(&relay),
                "the relay must kill at least as much as every instance (missing coverage vs {caps:?})"
            );
        }
    }

    #[test]
    fn relay_policy_grants_only_own_binary_and_the_one_uds_dir_no_config_no_data_dir_no_key() {
        let exe = PathBuf::from("/usr/local/bin/boatramp");
        // The UDS lives in a DEDICATED per-VM directory holding only that socket (boot_firecracker).
        let uds = PathBuf::from("/run/brvsk-3-4242/vsock.sock");
        let uds_dir = PathBuf::from("/run/brvsk-3-4242");
        let policy = relay_supervisor_policy(&exe, &uds);

        // The FS view is EXACTLY the own binary (RO + execute) + the DIRECTORY holding the ONE vsock
        // UDS (RO — the landlock crate can't O_PATH-open a socket inode on static-musl, so the relay
        // grants the uds's dedicated dir, which holds only that socket). Nothing is read-write.
        assert_eq!(policy.read_only_paths, vec![exe.clone(), uds_dir.clone()]);
        assert!(policy.read_write_paths.is_empty());
        assert!(
            !policy.read_only_paths.contains(&uds),
            "the relay grants the uds's DIRECTORY, not the socket inode (musl O_PATH-ENXIO)"
        );

        // EXECUTE is pinned to the own binary ALONE (never the UDS/its dir): `build_ruleset` strips
        // Execute from the read grant and re-grants it only on `execute_paths`.
        assert_eq!(policy.execute_paths, vec![exe.clone()]);
        assert!(
            !policy.execute_paths.contains(&uds) && !policy.execute_paths.contains(&uds_dir),
            "the vsock UDS / its dir must never be executable"
        );

        // No config, no data_dir, no §1.2 key input, no instance state is anywhere in the view — the
        // relay cannot open a crown-jewel key file even by accident (it is secret-blind).
        let forbidden = [
            PathBuf::from("/srv/node/secrets/kek"),
            PathBuf::from("/srv/node/secrets/signer.sealed"),
            PathBuf::from("/etc/boatramp/boatramp.cfg"), // config
            PathBuf::from("/var/lib/boatramp/data"),     // a data_dir
            PathBuf::from("/var/lib/boatramp/data/kv"),  // a backend state subtree
        ];
        let granted: BTreeSet<&PathBuf> = policy
            .read_only_paths
            .iter()
            .chain(policy.read_write_paths.iter())
            .collect();
        for f in &forbidden {
            assert!(
                !granted.contains(f),
                "a key/config/data_dir path must be ABSENT from the relay's FS view: {f:?}"
            );
            for g in &granted {
                assert!(
                    !path_contains(g, f),
                    "no relay grant {g:?} may be an ancestor of the forbidden path {f:?}"
                );
            }
        }
    }

    #[test]
    fn derive_relay_profile_ties_the_bespoke_lists_and_policy_together() {
        let exe = PathBuf::from("/usr/local/bin/boatramp");
        let uds = PathBuf::from("/run/brvsk-3-4242.sock");
        let profile = derive_relay_profile(&exe, &uds);
        assert_eq!(profile.posture, SandboxPosture::Strict);
        assert_eq!(profile.seccomp_allow, relay_supervisor_allowlist());
        assert_eq!(profile.seccomp_kill, relay_supervisor_killlist());
        assert_eq!(profile.policy, relay_supervisor_policy(&exe, &uds));
        // The install path grants only read_only/read_write — the two RO paths are the full FS view.
        assert_eq!(profile.policy.read_only_paths.len(), 2);
    }

    /// **F1 mutation guard (mirrors the `RELAY_NET_STRIP` "drop a verb → test reddens" pattern).**
    /// The relay profile — and ONLY the relay profile — carries the deny-ALL-TCP `AccessNet`
    /// posture (`SandboxPolicy::deny_all_tcp`). `build_ruleset` then handles `AccessNet` with ZERO
    /// `NetPort` allow-rules, walling off every TCP bind + connect while leaving the AF_UNIX vsock
    /// dial untouched. This asserts the POSTURE (the cross-platform, no-kernel proof); the LIVE
    /// kernel proof that a TCP `connect` is actually EACCES'd under the installed profile — while
    /// an AF_UNIX `connect` still succeeds — is the `sandbox-live` gate
    /// (`relay_accessnet_walls_off_tcp_but_not_af_unix`).
    ///
    /// MUTATION: flip `relay_supervisor_policy`'s `deny_all_tcp` to `false` and the first assert
    /// reddens; set it `true` on ANY non-relay profile (root / monolith / instance) and the
    /// no-regression asserts redden.
    #[test]
    fn only_the_relay_profile_walls_off_all_tcp_via_accessnet() {
        let exe = PathBuf::from("/usr/local/bin/boatramp");
        let uds = PathBuf::from("/run/brvsk-3-4242.sock");

        // The relay profile sets the deny-ALL-TCP posture.
        assert!(
            derive_relay_profile(&exe, &uds).policy.deny_all_tcp,
            "the VM relay profile MUST wall off all TCP via AccessNet (F1)"
        );
        assert!(
            relay_supervisor_policy(&exe, &uds).deny_all_tcp,
            "relay_supervisor_policy MUST set deny_all_tcp"
        );

        // NO OTHER profile does — a strict no-op everywhere else (no regression to a network-
        // serving instance, the root self-profile, or the monolith).
        assert!(
            !derive_root_profile(&exe, &uds).policy.deny_all_tcp,
            "the root self-profile must NOT wall off TCP (it does no socket I/O; its net posture is \
             the seccomp ROOT_NET_STRIP, and a net wall here would be an unrelated regression)"
        );
        assert!(
            !SandboxPolicy::for_server("/var/lib/boatramp").deny_all_tcp,
            "the monolith server (which binds + dials freely) must NOT wall off TCP"
        );
        // A per-capability instance — whether a listener frontend or an outbound-dialing backend —
        // never gets the relay's net wall.
        let inputs = SandboxDerivationInputs::for_instance("/var/lib/boatramp-x", None);
        for caps in [frontend(), storage(), all_caps(), signer()] {
            let profile = derive_profile(&caps, SandboxPosture::Derived, &inputs)
                .expect("derive a per-capability profile");
            assert!(
                !profile.policy.deny_all_tcp,
                "a per-capability instance ({caps:?}) must NOT carry the relay's TCP wall"
            );
        }
    }
}
