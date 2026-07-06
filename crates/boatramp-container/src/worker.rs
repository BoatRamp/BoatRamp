//! The self-jailing sandbox **worker**, Linux-only.
//!
//! Applies a [`SandboxPlan`](crate::sandbox::SandboxPlan) in the current process:
//! set up the cgroup, unshare namespaces, fork the container init (PID 1 of the
//! new PID namespace), build the jail (private mounts → `pivot_root` into the
//! rootfs → standard mounts → hostname), apply cgroup limits, drop capabilities,
//! drop to the unprivileged uid/gid, and `execve` the entrypoint. This is the
//! security boundary boatramp owns (no external runc/jailer).
//!
//! Order matters and follows the standard OCI-runtime sequence. The seccomp
//! filter (the final hardening step, just before `execve`) is installed by
//! [`seccomp`](crate::seccomp) once compiled — wired in the next slice; the hook
//! is marked below. Network setup (moving a veth peer into the worker's netns)
//! is the launcher's job (it has the worker PID) and lands with the
//! `ComputeBackend` launch path; here we bring up loopback only.
//!
//! **Running** this is the live seam (the `container_live` test on real Linux);
//! the code is compiled + linted on the Linux builder.

use crate::sandbox::{Mount, SandboxPlan, VolumeMount};
use nix::mount::{MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{
    chdir, execve, fork, pivot_root, setgroups, sethostname, setresgid, setresuid, ForkResult, Gid,
    Uid,
};
use std::convert::Infallible;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::path::Path;

/// A failure applying a [`SandboxPlan`].
#[derive(Debug)]
pub enum WorkerError {
    /// A syscall failed (with the step that failed).
    Syscall(&'static str, nix::errno::Errno),
    /// A filesystem op failed (cgroup write, dir create, …).
    Io(&'static str, std::io::Error),
    /// The plan was malformed (e.g. an empty argv, or a non-UTF8 path/arg).
    Plan(String),
    /// Compiling or installing the seccomp filter failed.
    Seccomp(crate::seccomp::InstallError),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WorkerError::Syscall(step, e) => write!(f, "sandbox syscall {step} failed: {e}"),
            WorkerError::Io(step, e) => write!(f, "sandbox {step} failed: {e}"),
            WorkerError::Plan(m) => write!(f, "invalid sandbox plan: {m}"),
            WorkerError::Seccomp(e) => write!(f, "sandbox seccomp: {e}"),
        }
    }
}

impl std::error::Error for WorkerError {}

/// Set up the cgroup and `unshare` the namespaces, but do **not** fork yet.
///
/// Split from [`jail_and_run`] so the caller (the `boatramp __sandbox`
/// subcommand) can run the **network handshake** in between: after this returns,
/// the process is in its new netns (`/proc/self/ns/net`), so the launcher can
/// move the veth peer in + configure `eth0` before the entrypoint starts.
pub fn prepare(plan: &SandboxPlan) -> Result<(), WorkerError> {
    if plan.argv.is_empty() {
        return Err(WorkerError::Plan("empty entrypoint argv".into()));
    }
    // The cgroup is created + populated here (pre-fork) so the child is born
    // already constrained (limits inherited through the cgroup hierarchy).
    setup_cgroup(plan)?;
    unshare(clone_flags(&plan.namespaces)).map_err(|e| WorkerError::Syscall("unshare", e))?;
    // A user namespace is inert until its uid/gid maps are written; do it right
    // after unshare, before any mount/`pivot_root`/id-drop.
    if plan.namespaces.user {
        setup_userns_maps()?;
    }
    Ok(())
}

/// The unprivileged host id the container's id range maps onto: container
/// uid/gid `0` → host `100000`, so in-container `root` is unprivileged on the
/// host. 65536 ids cover a full container uid/gid range.
const USERNS_HOST_BASE: u32 = 100_000;
/// The number of ids mapped from the container into the host range.
const USERNS_COUNT: u32 = 65_536;

/// The `/proc/self/{uid,gid}_map` line mapping container id `0` onto the
/// unprivileged host base for [`USERNS_COUNT`] ids.
fn userns_map_line() -> String {
    format!("0 {USERNS_HOST_BASE} {USERNS_COUNT}\n")
}

/// Write the user-namespace uid/gid maps. The worker runs as **real root**
/// (`CAP_SETUID`/`CAP_SETGID` in the parent namespace), so it writes the maps
/// directly — no `setgroups=deny` dance, which also keeps `drop_privileges`'
/// `setgroups()` working (deny would forbid it).
fn setup_userns_maps() -> Result<(), WorkerError> {
    let line = userns_map_line();
    fs::write("/proc/self/uid_map", &line).map_err(|e| WorkerError::Io("write uid_map", e))?;
    fs::write("/proc/self/gid_map", &line).map_err(|e| WorkerError::Io("write gid_map", e))?;
    Ok(())
}

/// Fork the container init and run the jail. In the parent, returns the init's
/// exit code once it exits; the forked child never returns to the caller (it
/// `execve`s the entrypoint, or the process exits non-zero on failure).
///
/// Call [`prepare`] first. Must run as root (or with the needed capabilities);
/// the entrypoint itself runs unprivileged after the drop.
pub fn jail_and_run(plan: &SandboxPlan) -> Result<i32, WorkerError> {
    // unshare(CLONE_NEWPID) does not move the caller into the new PID namespace —
    // only its children. Fork so the child becomes PID 1 there; the parent stays
    // as the monitor and reaps it.
    match unsafe { fork() }.map_err(|e| WorkerError::Syscall("fork", e))? {
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).map_err(|e| WorkerError::Syscall("waitpid", e))?;
            Ok(exit_code(status))
        }
        ForkResult::Child => match jail_and_exec(plan) {
            // `execve` does not return on success, so `Ok` is unreachable; the
            // never type makes that explicit.
            Ok(never) => match never {},
            Err(e) => {
                eprintln!("boatramp __sandbox: {e}");
                std::process::exit(127);
            }
        },
    }
}

/// Convenience: [`prepare`] then [`jail_and_run`] with no network handshake (for
/// a sandbox that needs no veth set up by a launcher).
pub fn run(plan: &SandboxPlan) -> Result<i32, WorkerError> {
    prepare(plan)?;
    jail_and_run(plan)
}

/// The cgroup v2 root the worker creates per-instance cgroups under.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// Create `boatramp/<hostname>` under the cgroup v2 root, write the plan's
/// limits, and move the current process (and thus its forked child) into it.
fn setup_cgroup(plan: &SandboxPlan) -> Result<(), WorkerError> {
    let dir = format!("{CGROUP_ROOT}/boatramp/{}", plan.hostname);
    fs::create_dir_all(&dir).map_err(|e| WorkerError::Io("create cgroup", e))?;
    let limits = &plan.cgroup;
    if let Some(cpu_max) = &limits.cpu_max {
        write_cgroup(&dir, "cpu.max", cpu_max)?;
    }
    if let Some(mem) = limits.memory_max_bytes {
        write_cgroup(&dir, "memory.max", &mem.to_string())?;
    }
    if let Some(pids) = limits.pids_max {
        write_cgroup(&dir, "pids.max", &pids.to_string())?;
    }
    // Joining the cgroup must come last: once populated, some controller files
    // become unwritable for the membership-changing process.
    write_cgroup(&dir, "cgroup.procs", &std::process::id().to_string())
}

fn write_cgroup(dir: &str, file: &str, value: &str) -> Result<(), WorkerError> {
    fs::write(format!("{dir}/{file}"), value).map_err(|e| WorkerError::Io("write cgroup", e))
}

/// Map the plan's [`Namespaces`](crate::sandbox::Namespaces) to clone flags.
fn clone_flags(ns: &crate::sandbox::Namespaces) -> CloneFlags {
    let mut f = CloneFlags::empty();
    if ns.mount {
        f |= CloneFlags::CLONE_NEWNS;
    }
    if ns.pid {
        f |= CloneFlags::CLONE_NEWPID;
    }
    if ns.net {
        f |= CloneFlags::CLONE_NEWNET;
    }
    if ns.uts {
        f |= CloneFlags::CLONE_NEWUTS;
    }
    if ns.ipc {
        f |= CloneFlags::CLONE_NEWIPC;
    }
    if ns.user {
        f |= CloneFlags::CLONE_NEWUSER;
    }
    f
}

/// In the forked child: build the jail and `execve`. Never returns on success.
fn jail_and_exec(plan: &SandboxPlan) -> Result<Infallible, WorkerError> {
    pivot_into_root(&plan.root, &plan.volumes)?;
    apply_mounts(&plan.mounts)?;

    sethostname(&plan.hostname).map_err(|e| WorkerError::Syscall("sethostname", e))?;

    // Drop privileges first (sets `no_new_privs`), then install seccomp — so the
    // filter can be applied without CAP_SYS_ADMIN and only the entrypoint (and
    // the `execve` to reach it) runs under it.
    drop_privileges(plan.uid, plan.gid)?;
    if let Some(allow) = &plan.seccomp_allow {
        crate::seccomp::install(allow).map_err(WorkerError::Seccomp)?;
    }

    let path = CString::new(plan.argv[0].as_str())
        .map_err(|_| WorkerError::Plan("argv[0] has an interior NUL".into()))?;
    let argv = cstrings(&plan.argv)?;
    let env: Vec<String> = plan.env.iter().map(|(k, v)| format!("{k}={v}")).collect();
    let envp = cstrings(&env)?;
    execve(&path, &argv, &envp).map_err(|e| WorkerError::Syscall("execve", e))?;
    unreachable!("execve returned without error");
}

/// Make the mount tree private, then `pivot_root` into `root`, detaching the old
/// root. After this the process's `/` is the container rootfs. Persistent
/// `volumes` are bind-mounted **into `root`** first (while the host tree is still
/// reachable), so after the pivot each appears at its in-guest mount point.
fn pivot_into_root(root: &str, volumes: &[VolumeMount]) -> Result<(), WorkerError> {
    let root = Path::new(root);
    // Don't propagate our mounts back to the host (and vice versa).
    nix::mount::mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| WorkerError::Syscall("make-rprivate", e))?;
    // `pivot_root` needs the new root to be a mount point: bind it onto itself.
    nix::mount::mount(
        Some(root),
        root,
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| WorkerError::Syscall("bind-root", e))?;
    bind_volumes(root, volumes)?;
    let put_old = root.join(".put_old");
    fs::create_dir_all(&put_old).map_err(|e| WorkerError::Io("create put_old", e))?;
    pivot_root(root, &put_old).map_err(|e| WorkerError::Syscall("pivot_root", e))?;
    chdir("/").map_err(|e| WorkerError::Syscall("chdir", e))?;
    nix::mount::umount2("/.put_old", MntFlags::MNT_DETACH)
        .map_err(|e| WorkerError::Syscall("umount put_old", e))?;
    fs::remove_dir("/.put_old").map_err(|e| WorkerError::Io("remove put_old", e))?;
    Ok(())
}

/// Bind each persistent volume's host `source` onto `<root>/<mount>` (recursive
/// bind), creating the in-rootfs target if missing. Runs **before** `pivot_root`
/// while the host source paths are still reachable; after the pivot the volume
/// is visible at its in-guest `mount`.
fn bind_volumes(root: &Path, volumes: &[VolumeMount]) -> Result<(), WorkerError> {
    for v in volumes {
        // Join the (absolute) in-guest mount onto the new root.
        let rel = Path::new(&v.mount)
            .strip_prefix("/")
            .unwrap_or(Path::new(&v.mount));
        let target = root.join(rel);
        fs::create_dir_all(&target).map_err(|e| WorkerError::Io("create volume target", e))?;
        nix::mount::mount(
            Some(v.source.as_str()),
            &target,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| WorkerError::Syscall("bind-volume", e))?;
    }
    Ok(())
}

/// Set up the container's standard mounts (`/proc`, `/sys`, `/dev`, `/tmp`).
fn apply_mounts(mounts: &[Mount]) -> Result<(), WorkerError> {
    for m in mounts {
        let (flags, data) = mount_flags(&m.flags);
        fs::create_dir_all(&m.target).map_err(|e| WorkerError::Io("create mount target", e))?;
        let fstype = if m.fstype == "bind" {
            None
        } else {
            Some(m.fstype.as_str())
        };
        let mut flags = flags;
        if m.fstype == "bind" {
            flags |= MsFlags::MS_BIND;
        }
        nix::mount::mount(
            Some(m.source.as_str()),
            m.target.as_str(),
            fstype,
            flags,
            data.as_deref(),
        )
        .map_err(|e| WorkerError::Syscall("mount", e))?;
    }
    Ok(())
}

/// Translate the plan's textual mount flags into [`MsFlags`] + an optional data
/// string (e.g. `mode=0755` for tmpfs).
fn mount_flags(flags: &[String]) -> (MsFlags, Option<String>) {
    let mut ms = MsFlags::empty();
    let mut data: Vec<&str> = Vec::new();
    for f in flags {
        match f.as_str() {
            "ro" => ms |= MsFlags::MS_RDONLY,
            "nosuid" => ms |= MsFlags::MS_NOSUID,
            "nodev" => ms |= MsFlags::MS_NODEV,
            "noexec" => ms |= MsFlags::MS_NOEXEC,
            "relatime" => ms |= MsFlags::MS_RELATIME,
            other => data.push(other), // mount(2) data option, e.g. `mode=0755`
        }
    }
    let data = if data.is_empty() {
        None
    } else {
        Some(data.join(","))
    };
    (ms, data)
}

/// Drop all capabilities and switch to the unprivileged `uid`/`gid`. gids first
/// (a uid-first switch would lose the privilege needed to set gids), supplementary
/// groups cleared, and `no_new_privs` set so a later `execve` of a setuid binary
/// can't regain privilege.
fn drop_privileges(uid: u32, gid: u32) -> Result<(), WorkerError> {
    nix::sys::prctl::set_no_new_privs().map_err(|e| WorkerError::Syscall("no_new_privs", e))?;
    // Clear every capability set so the entrypoint starts with none.
    for set in [
        caps::CapSet::Ambient,
        caps::CapSet::Bounding,
        caps::CapSet::Inheritable,
    ] {
        caps::clear(None, set).map_err(|e| WorkerError::Io("clear caps", to_io(e)))?;
    }
    setgroups(&[]).map_err(|e| WorkerError::Syscall("setgroups", e))?;
    let gid = Gid::from_raw(gid);
    setresgid(gid, gid, gid).map_err(|e| WorkerError::Syscall("setresgid", e))?;
    let uid = Uid::from_raw(uid);
    setresuid(uid, uid, uid).map_err(|e| WorkerError::Syscall("setresuid", e))?;
    // Effective/Permitted are emptied as a side effect of the uid switch with an
    // empty permitted set; clear explicitly to be unambiguous.
    caps::clear(None, caps::CapSet::Effective)
        .map_err(|e| WorkerError::Io("clear caps", to_io(e)))?;
    caps::clear(None, caps::CapSet::Permitted)
        .map_err(|e| WorkerError::Io("clear caps", to_io(e)))?;
    Ok(())
}

fn to_io(e: caps::errors::CapsError) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

fn cstrings(items: &[String]) -> Result<Vec<CString>, WorkerError> {
    items
        .iter()
        .map(|s| CString::new(s.as_str()).map_err(|_| WorkerError::Plan("interior NUL".into())))
        .collect()
}

/// The exit code to surface from a reaped child.
fn exit_code(status: WaitStatus) -> i32 {
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_flags_match_default_namespaces() {
        let f = clone_flags(&crate::sandbox::Namespaces::default());
        assert!(f.contains(CloneFlags::CLONE_NEWNS));
        assert!(f.contains(CloneFlags::CLONE_NEWPID));
        assert!(f.contains(CloneFlags::CLONE_NEWNET));
        assert!(f.contains(CloneFlags::CLONE_NEWUTS));
        assert!(f.contains(CloneFlags::CLONE_NEWIPC));
        // The user namespace is on by default.
        assert!(f.contains(CloneFlags::CLONE_NEWUSER));
    }

    #[test]
    fn userns_maps_container_root_onto_an_unprivileged_host_id() {
        // Container id 0 maps to the unprivileged host base, over a full range —
        // so even in-container `root` has no host privilege.
        assert_eq!(userns_map_line(), "0 100000 65536\n");
        assert_ne!(USERNS_HOST_BASE, 0, "the host base must not be host root");
    }

    #[test]
    fn mount_flags_parse_options_and_data() {
        let (ms, data) = mount_flags(&[
            "nosuid".into(),
            "nodev".into(),
            "noexec".into(),
            "ro".into(),
        ]);
        assert!(ms.contains(MsFlags::MS_NOSUID));
        assert!(ms.contains(MsFlags::MS_NODEV));
        assert!(ms.contains(MsFlags::MS_NOEXEC));
        assert!(ms.contains(MsFlags::MS_RDONLY));
        assert_eq!(data, None);

        let (ms, data) = mount_flags(&["nosuid".into(), "mode=0755".into()]);
        assert!(ms.contains(MsFlags::MS_NOSUID));
        assert_eq!(data.as_deref(), Some("mode=0755"));
    }

    #[test]
    fn exit_code_maps_exit_and_signal() {
        use nix::unistd::Pid;
        assert_eq!(exit_code(WaitStatus::Exited(Pid::from_raw(1), 0)), 0);
        assert_eq!(exit_code(WaitStatus::Exited(Pid::from_raw(1), 42)), 42);
        assert_eq!(
            exit_code(WaitStatus::Signaled(
                Pid::from_raw(1),
                nix::sys::signal::Signal::SIGKILL,
                false
            )),
            128 + 9
        );
    }
}
