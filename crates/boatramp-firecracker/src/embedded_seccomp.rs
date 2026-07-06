//! A **seccomp allow-list** for the embedded VMM's run loop. The VM thread
//! executes a guest's kernel under KVM; a
//! guest/virtio/KVM escape that reaches the VMM should be confined to the handful
//! of syscalls the run loop actually makes — not the host's full syscall surface.
//!
//! This is a **default-deny** policy: only the run-loop + RX-poller + Rust-runtime
//! syscalls are allowed; everything else (notably `execve`, `open*`, `socket`,
//! `ptrace`, `mount`, `clone`-into-new-namespaces, `bpf`, …) returns `EPERM`. It's
//! deliberately *much* tighter than the container backend's trusted-tier list:
//! once the VM is built the run loop opens no files + no sockets + spawns no
//! processes, so the list is just KVM `ioctl`, the tap/disk/eventfd I/O, `ppoll`,
//! futex, memory, signals, and thread spawn.
//!
//! The allow-list is **pure** (a curated name set, unit-tested cross-platform);
//! compiling it to BPF + installing it via `seccomp(2)` is the Linux seam,
//! applied to the VM thread just before it enters the run loop.
//!
//! Note: the embedded VMM runs in-process, so seccomp confines *syscalls*
//! but not access to the host process's address space. Running the VM in a
//! re-exec'd jailed subprocess (separate address space + dropped caps) is the
//! companion step; this filter applies in either model.

/// The default-deny seccomp allow-list for the embedded VMM's run loop, sorted +
/// de-duplicated (deterministic). Covers: KVM (`ioctl`), the virtio backends'
/// disk/tap/eventfd I/O, the RX `ppoll`, thread + futex + memory + signal
/// primitives the Rust runtime needs, and clean exit — nothing that opens files,
/// sockets, or spawns processes.
pub fn run_loop_allowlist() -> Vec<String> {
    let mut names: Vec<String> = ALLOWED
        .iter()
        .map(|s| (*s).to_string())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    names.sort();
    names
}

/// Syscalls that must **never** be in the VMM allow-list — the host-escape /
/// kernel-attack surface a confined VMM thread has no business making. A
/// regression guard (the unit test asserts none appear).
pub const DANGEROUS_DENIED: &[&str] = &[
    "execve",
    "execveat",
    "fork",
    "vfork",
    "open",
    "openat",
    "openat2",
    "socket",
    "socketpair",
    "connect",
    "bind",
    "listen",
    "accept",
    "accept4",
    "ptrace",
    "process_vm_readv",
    "process_vm_writev",
    "mount",
    "umount2",
    "pivot_root",
    "chroot",
    "bpf",
    "kexec_load",
    "init_module",
    "finit_module",
    "keyctl",
    "add_key",
    "reboot",
    "setns",
    "unshare",
];

/// The curated run-loop syscall set (resolved to per-arch numbers at install).
const ALLOWED: &[&str] = &[
    // KVM + virtio device I/O: `KVM_RUN`/`KVM_IRQ_LINE` ioctls, the rootfs disk
    // (read/write/seek/flush), the tap (read/write), and the irqfd (write).
    "ioctl",
    "read",
    "write",
    "readv",
    "writev",
    "pread64",
    "pwrite64",
    "lseek",
    "fsync",
    "fdatasync",
    "close",
    "dup",
    "dup3",
    "fcntl",
    // The virtio-net RX poller waits on the tap with `ppoll` (nix `poll`).
    "ppoll",
    "poll",
    // Thread spawn (the RX poller) + synchronization + clean exit.
    "clone",
    "clone3",
    "futex",
    "futex_waitv",
    "set_robust_list",
    "rseq",
    "sched_yield",
    "sched_getaffinity",
    "gettid",
    "exit",
    "exit_group",
    "restart_syscall",
    "tgkill", // panic/abort path
    // Signals: the vCPU-stop handler + the Rust runtime's signal bookkeeping.
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    // Memory: guest RAM is already mapped; these are the allocator + stacks.
    "mmap",
    "mremap",
    "munmap",
    "mprotect",
    "madvise",
    "brk",
    // Time + entropy.
    "clock_gettime",
    "clock_nanosleep",
    "nanosleep",
    "gettimeofday",
    "getrandom",
];

/// Why installing the VMM seccomp filter failed.
#[derive(Debug)]
pub enum SeccompError {
    /// `prctl(PR_SET_NO_NEW_PRIVS)` failed.
    Prctl(String),
    /// An allow-list entry isn't a known syscall name (a typo guard).
    UnknownSyscall(String),
    /// `seccompiler` failed to compile or apply the filter.
    Seccomp(String),
}

impl std::fmt::Display for SeccompError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SeccompError::Prctl(e) => write!(f, "prctl no_new_privs: {e}"),
            SeccompError::UnknownSyscall(s) => write!(f, "unknown syscall in allow-list: {s}"),
            SeccompError::Seccomp(e) => write!(f, "seccomp: {e}"),
        }
    }
}

impl std::error::Error for SeccompError {}

/// The seccomp target arch for this build.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::x86_64;
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
const ARCH: seccompiler::TargetArch = seccompiler::TargetArch::aarch64;

/// Set `no_new_privs` and install the [`run_loop_allowlist`] as a default-deny
/// BPF seccomp filter on the **calling thread** (and threads it later spawns, so
/// install before the RX poller). Call once the VM is built (all setup syscalls
/// done) and just before the run loop. A disallowed syscall returns `EPERM`.
#[cfg(target_os = "linux")]
pub fn install() -> Result<(), SeccompError> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
    use std::collections::BTreeMap;

    // seccomp(SET_MODE_FILTER) needs no_new_privs (or CAP_SYS_ADMIN); set it so
    // the filter installs regardless of the process's capabilities.
    nix::sys::prctl::set_no_new_privs().map_err(|e| SeccompError::Prctl(e.to_string()))?;

    let mut rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
    for name in run_loop_allowlist() {
        let sysno: syscalls::Sysno = name
            .parse()
            .map_err(|_| SeccompError::UnknownSyscall(name.clone()))?;
        rules.insert(i64::from(sysno.id()), Vec::new());
    }
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(nix::libc::EPERM as u32), // unlisted → EPERM
        SeccompAction::Allow,                          // listed → allow
        ARCH,
    )
    .map_err(|e| SeccompError::Seccomp(e.to_string()))?;
    let program: BpfProgram = filter
        .try_into()
        .map_err(|e: seccompiler::BackendError| SeccompError::Seccomp(e.to_string()))?;
    seccompiler::apply_filter(&program).map_err(|e| SeccompError::Seccomp(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_is_nonempty_sorted_and_deduped() {
        let allow = run_loop_allowlist();
        assert!(allow.len() > 20, "covers the run-loop syscall set");
        let mut sorted = allow.clone();
        sorted.sort();
        assert_eq!(allow, sorted, "deterministic (sorted)");
        let unique: std::collections::BTreeSet<_> = allow.iter().collect();
        assert_eq!(unique.len(), allow.len(), "de-duplicated");
    }

    #[test]
    fn allowlist_has_the_run_loop_essentials() {
        let allow = run_loop_allowlist();
        for must in ["ioctl", "ppoll", "read", "write", "futex", "clone", "mmap"] {
            assert!(allow.contains(&must.to_string()), "missing {must}");
        }
    }

    #[test]
    fn allowlist_excludes_the_host_escape_surface() {
        let allow = run_loop_allowlist();
        for denied in DANGEROUS_DENIED {
            assert!(
                !allow.contains(&denied.to_string()),
                "{denied} must not be allowed for the VMM"
            );
        }
    }
}
