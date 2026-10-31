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
/// `all`-composition never loses a syscall the monolith needs); the ONLY extra it adds is
/// [`EXEC_SPAWN`], present solely because `ALL` includes `exec.compute`.
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
    }
    set.into_iter().collect()
}

/// Derive the per-instance seccomp KILL-set (hard `SECCOMP_RET_KILL_PROCESS`): the Phase-0
/// [`KILL_SURFACE`], EXCEPT that an `exec.compute` instance does NOT kill `execve`/`execveat`
/// (it re-execs the compute workers). Every non-`exec.compute` instance kills the exec family
/// — the load-bearing containment for a dropped execution authority. Sorted + de-duplicated.
pub fn derive_seccomp_killlist(caps: &BTreeSet<HostAuthority>) -> Vec<String> {
    let exec_spawner = holds_exec_spawn(caps);
    let set: BTreeSet<String> = KILL_SURFACE
        .iter()
        .copied()
        .filter(|s| !(exec_spawner && EXEC_SPAWN.contains(s)))
        .map(str::to_string)
        .collect();
    set.into_iter().collect()
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
        let fields: [(HostAuthority, &Option<PathBuf>, KeyAccess); 6] = [
            (
                HostAuthority::SecretsSealer,
                &self.kek_file,
                KeyAccess::ReadWrite,
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
}

impl SandboxDerivationInputs {
    /// Sane defaults for an instance: [`SYSTEM_READ_ROOTS`] + `config_dir` read-only, the
    /// system temp dirs as `shared_temp`, no state writes and no key paths (WS-B layers those
    /// on per the instance's capability set).
    pub fn for_instance(data_dir: impl Into<PathBuf>, config_dir: Option<PathBuf>) -> Self {
        let mut base_read_only: Vec<PathBuf> =
            SYSTEM_READ_ROOTS.iter().map(PathBuf::from).collect();
        if let Some(dir) = config_dir.filter(|p| !p.as_os_str().is_empty()) {
            base_read_only.push(dir);
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
        for granted in read_only.iter().chain(read_write.iter()) {
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
        },
    })
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

    /// The Landlock ABI the ruleset handles. `V1` is the universally-available floor
    /// (Linux 5.13+); `CompatLevel::BestEffort` upgrades confinement on newer kernels
    /// and downgrades gracefully on older ones.
    const LANDLOCK_ABI: landlock::ABI = landlock::ABI::V1;

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
            ] {
                assert!(
                    name.parse::<syscalls::Sysno>().is_ok(),
                    "core syscall name does not resolve on this arch: {name}"
                );
            }
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
        let kill = derive_seccomp_killlist(&frontend());
        assert!(
            has(&kill, "execve") && has(&kill, "execveat"),
            "a non-exec.compute instance hard-kills the exec family"
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
    fn exec_compute_allows_execve_and_drops_it_from_the_kill_list() {
        let set = caps(&[HostAuthority::ExecCompute]);
        let allow = derive_seccomp_allowlist(&set);
        assert!(
            has(&allow, "execve") && has(&allow, "execveat"),
            "the compute-supervisor must be able to re-exec its workers"
        );
        let kill = derive_seccomp_killlist(&set);
        assert!(
            !has(&kill, "execve") && !has(&kill, "execveat"),
            "exec.compute must NOT kill the exec family it legitimately uses"
        );
        // Every OTHER instance still kills it — proven by the frontend/signer/storage tests.
    }

    #[test]
    fn monolith_derivation_is_a_superset_of_the_phase0_allowlist() {
        // The `all` composition (design §5.5 default-monolith invariant) must never LOSE a
        // syscall the released Phase-0 monolith allow-list has; the ONLY extra it adds is the
        // exec family, present solely because `all` includes exec.compute.
        let allow: BTreeSet<String> = derive_seccomp_allowlist(&all_caps()).into_iter().collect();
        let phase0: BTreeSet<String> = whole_process_allowlist().into_iter().collect();
        assert!(
            phase0.is_subset(&allow),
            "derive(ALL) must cover the Phase-0 monolith allow-list; missing: {:?}",
            phase0.difference(&allow).collect::<Vec<_>>()
        );
        let extra: BTreeSet<String> = allow.difference(&phase0).cloned().collect();
        let expected: BTreeSet<String> = ["execve", "execveat"]
            .into_iter()
            .map(str::to_string)
            .collect();
        assert_eq!(
            extra, expected,
            "derive(ALL) adds exactly the exec family over Phase-0 (exec.compute ∈ ALL)"
        );
    }

    // ---- Landlock key-path gating + the fail-closed leak check ----

    fn inputs_with_keys(data_dir: &str) -> SandboxDerivationInputs {
        let mut inp = SandboxDerivationInputs::for_instance(data_dir, None);
        // Keys deliberately placed OUTSIDE the granted subtrees (a dedicated keystore).
        inp.keys = KeyInputPaths {
            kek_file: Some(PathBuf::from("/keys/kek")),
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
}
