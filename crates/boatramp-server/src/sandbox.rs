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
    for caps in instances.values() {
        for a in caps.iter().copied().filter(|a| a.is_backend()) {
            if backend_state_subdir(a).is_none() {
                return Err(CompositionGrantError::UncoveredBackendAuthority { authority: a });
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
        Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset, RulesetAttr,
        RulesetCreated, RulesetCreatedAttr, RulesetStatus,
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
    ) -> Result<RulesetCreated, SandboxError> {
        // Handle the FS rights the RUNNING kernel supports (clamped to the crate's max), not a
        // fixed ABI — so every FS right the kernel has is governed and `restrict_self` reports
        // `FullyEnforced` on a kernel the crate fully knows (see [`handled_fs_abi`]).
        let abi = handled_fs_abi(landlock_kernel_abi());
        // Execute STRIPPED from the general grants; re-granted below ONLY on the `execute` pin.
        let ro_access = AccessFs::from_read(abi) & !AccessFs::Execute;
        let rw_access = AccessFs::from_all(abi) & !AccessFs::Execute;
        // The execute-pin access: read + EXECUTE (so the pinned binary is readable AND runnable).
        let exec_access = AccessFs::from_read(abi);
        let mut created = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| SandboxError::Landlock(e.to_string()))?
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
    pub fn prepare_landlock(
        read_only: &[PathBuf],
        read_write: &[PathBuf],
        execute: &[PathBuf],
    ) -> Result<PreparedLandlock, SandboxError> {
        Ok(PreparedLandlock {
            created: build_ruleset(read_only, read_write, execute)?,
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
        )
        .and_then(PreparedLandlock::apply)
        {
            Ok(status) => Some(status),
            Err(e) => {
                tracing::error!(
                    error = %e,
                    posture = ?profile.posture,
                    "privsep per-instance Landlock FS confinement FAILED to apply"
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
        // The most-exposed public parser, DE-COUPLED (WS-D Finding-2): `listen.http-parse` alone,
        // holding NO `exec.compute` and NO `backend.kv` (the composition-closure lint guarantees
        // this). The per-capability profile must make the containment physical.
        let parser = caps(&[HostAuthority::ListenHttpParse]);
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
}
