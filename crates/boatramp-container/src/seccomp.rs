//! The container sandbox's **seccomp allow-list**.
//!
//! A default-deny syscall policy: the worker compiles this allow-list to a BPF
//! program (via `seccompiler`) and installs it with `seccomp(2)` just before
//! `execve`, so the entrypoint runs with everything *not* listed denied. This
//! module is the **pure** half — the curated syscall name set, built and
//! unit-tested cross-platform; compiling + installing the filter is the Linux
//! seam in the worker.
//!
//! Scope: this is the *trusted-tier* default (single-tenant workloads on the
//! container backend, per the isolation matrix) — broad enough that a normal
//! statically- or dynamically-linked server runs unmodified, while still denying
//! the kernel-attack-surface and container-escape syscalls (`ptrace`, `mount`,
//! `pivot_root`, `bpf`, `kexec_load`, `init_module`, `keyctl`, `reboot`, …). The
//! exhaustive, minimized profile for *untrusted* multi-tenant use is a dedicated
//! security audit; until then untrusted workloads go to the VMM/cloudflare
//! backends (the policy gate enforces this).
//!
//! The list is the union of:
//! - **process/threads**: `clone`, `clone3`, `execve`, `exit`, `wait4`, `futex`…
//! - **memory**: `mmap`, `mprotect`, `brk`, `madvise`…
//! - **file I/O**: `openat`, `read`, `write`, `close`, `statx`, `fcntl`…
//! - **networking**: `socket`, `bind`, `listen`, `accept4`, `connect`,
//!   `sendmsg`, `recvmsg`, `epoll_*`, `poll`…
//! - **time/signals/misc**: `clock_gettime`, `nanosleep`, `rt_sigaction`,
//!   `getrandom`, `uname`…
//!
//! Syscalls are listed by name (architecture-independent); the worker resolves
//! them to per-arch numbers when it compiles the filter.

/// The default-deny seccomp allow-list for the container backend's trusted tier.
///
/// Returned sorted + de-duplicated so the result is deterministic (stable across
/// runs, friendly to snapshotting and to the worker's compiled-filter cache).
pub fn default_allowlist() -> Vec<String> {
    let mut names: Vec<String> = ALLOWED
        .iter()
        .map(|s| (*s).to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    names.sort();
    names
}

/// Syscalls that must **never** appear in the allow-list: the kernel-attack /
/// container-escape surface. Used to assert the allow-list stays default-safe
/// (a regression guard for the audit boundary).
pub const DANGEROUS_DENIED: &[&str] = &[
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

/// The curated allow-list. Kept as a flat `&[&str]` (deduplicated/sorted by
/// [`default_allowlist`]) so it reads as a single audit-able surface.
const ALLOWED: &[&str] = &[
    // process / threads / scheduling
    "clone",
    "clone3",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "wait4",
    "waitid",
    "futex",
    "set_robust_list",
    "get_robust_list",
    "set_tid_address",
    "gettid",
    "getpid",
    "getppid",
    // process session / group management (self-scoped, within the PID namespace
    // — no host effect, no privilege gain; common in servers that supervise
    // children or detach a session).
    "setsid",
    "setpgid",
    "getpgid",
    "getsid",
    "getpgrp",
    "sched_getaffinity",
    "sched_setaffinity",
    "sched_yield",
    // read-only scheduler queries (no privilege change; `sched_setscheduler` is
    // deliberately *not* listed — it can raise real-time priority).
    "sched_getparam",
    "sched_getscheduler",
    "sched_get_priority_max",
    "sched_get_priority_min",
    "getrusage",
    "prctl",
    "arch_prctl",
    "rseq",
    // identity (read-only; the worker has already dropped privileges)
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
    "fchown",
    "fchownat",
    "mkdir",
    "mkdirat",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "symlink",
    "symlinkat",
    "link",
    "linkat",
    "truncate",
    "utimensat",
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
    // networking
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

/// Compile `allow` to a BPF seccomp program (default-deny: any syscall not in
/// the list returns `EPERM`) and install it on the current process via
/// `seccomp(2)`. Linux-only; call **after** `no_new_privs` is set (the worker
/// does so while dropping privileges) so it works without `CAP_SYS_ADMIN`, and
/// just before `execve` so only the entrypoint runs under the filter.
#[cfg(target_os = "linux")]
pub fn install(allow: &[String]) -> Result<(), InstallError> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
    use std::collections::BTreeMap;

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for name in allow {
        let sysno: syscalls::Sysno = name
            .parse()
            .map_err(|_| InstallError::UnknownSyscall(name.clone()))?;
        // An empty rule list = match the syscall unconditionally → the match
        // action (Allow).
        rules.insert(i64::from(sysno.id()), Vec::new());
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(nix::libc::EPERM as u32), // unlisted → EPERM
        SeccompAction::Allow,                          // listed → allow
        ARCH,
    )
    .map_err(|e| InstallError::Seccomp(e.to_string()))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| InstallError::Seccomp(e.to_string()))?;
    seccompiler::apply_filter(&program).map_err(|e| InstallError::Seccomp(e.to_string()))?;
    Ok(())
}

/// The seccomp target arch for the current build (the filter is installed on the
/// running process, so it matches the host arch).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;

/// A failure compiling or installing the seccomp filter.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub enum InstallError {
    /// A name in the allow-list isn't a known syscall on this arch.
    UnknownSyscall(String),
    /// `seccompiler` failed to compile or apply the filter.
    Seccomp(String),
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::UnknownSyscall(n) => write!(f, "unknown syscall in allow-list: {n}"),
            InstallError::Seccomp(m) => write!(f, "seccomp filter error: {m}"),
        }
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for InstallError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn allowlist_is_sorted_deduped_and_nonempty() {
        let list = default_allowlist();
        assert!(!list.is_empty());
        let mut sorted = list.clone();
        sorted.sort();
        assert_eq!(list, sorted, "allow-list must be sorted");
        let unique: BTreeSet<_> = list.iter().collect();
        assert_eq!(unique.len(), list.len(), "allow-list must be deduplicated");
    }

    #[test]
    fn covers_the_core_server_syscalls() {
        let list: BTreeSet<String> = default_allowlist().into_iter().collect();
        for needed in [
            "read",
            "write",
            "openat",
            "close",
            "mmap",
            "mprotect",
            "futex",
            "clone",
            "execve",
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

    #[test]
    fn allows_common_benign_process_and_fs_syscalls() {
        // Surfaced as false-deny risks for ordinary servers; all self-scoped
        // and non-escalating, so added to the trusted-tier allow-list.
        let list: BTreeSet<String> = default_allowlist().into_iter().collect();
        for needed in [
            "setsid",
            "setpgid",
            "getpgid",
            "getsid",
            "getpgrp",
            "getrusage",
            "statfs",
            "fstatfs",
            "sync",
            "syncfs",
            "fadvise64",
            "sched_getparam",
            "sched_getscheduler",
            "sched_get_priority_max",
            "sched_get_priority_min",
        ] {
            assert!(
                list.contains(needed),
                "allow-list missing benign syscall {needed}"
            );
        }
        // But never the privilege-raising scheduler setter.
        assert!(
            !list.contains("sched_setscheduler"),
            "must not allow sched_setscheduler"
        );
    }

    #[test]
    fn never_allows_the_escape_surface() {
        let list: BTreeSet<String> = default_allowlist().into_iter().collect();
        for danger in DANGEROUS_DENIED {
            assert!(
                !list.contains(*danger),
                "allow-list must NOT contain the dangerous syscall {danger}"
            );
        }
    }

    // Every allow-list entry must resolve to a real syscall number, or the worker
    // would fail at `install` time (runtime). Guards against a typo'd name — runs
    // on Linux where the `syscalls` table is available.
    #[cfg(target_os = "linux")]
    #[test]
    fn every_allowed_name_resolves_to_a_syscall_number() {
        for name in default_allowlist() {
            assert!(
                name.parse::<syscalls::Sysno>().is_ok(),
                "allow-list entry is not a known syscall on this arch: {name}"
            );
        }
    }
}
