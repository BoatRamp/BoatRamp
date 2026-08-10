//! CRIU checkpoint/restore for the container backend's scale-to-zero, **Linux-only**.
//!
//! Parks an idle container by dumping its process tree to a CRIU image (freeing all
//! its resources), and wakes it by restoring that image. The container analog of the
//! microVM backends' snapshot/restore — the same mechanism runc/Podman `checkpoint`
//! use. State-preserving: the restored container resumes with its exact in-RAM state
//! (validated by a per-process tmpfs nonce surviving the round-trip).
//!
//! The recipe (found empirically against boatramp's exact container shape — userns +
//! pidns + `pivot_root` + external bind mounts + a veth netns):
//! - target the container **pid1** (the pidns init), not the `__sandbox` monitor
//!   (which lives in the host pidns → CRIU can't dump a nested pidns from outside);
//! - `--root <rootfs> --ext-mount-map auto --enable-external-masters` so CRIU
//!   isolates to the container root instead of choking on the host mount tree;
//! - `--empty-ns net` because the launcher manages networking — CRIU restores into
//!   an empty net namespace and the backend re-attaches the veth + `eth0` afterward
//!   from the host (using the restored pid), reusing the launch-time netns wiring.
//!   (A CRIU `--action-script` can't do this: it runs inside the container's own
//!   namespaces at restore, where the host veth isn't reachable.)

use std::path::{Path, PathBuf};
use std::process::Command;

/// A resolved `criu` binary that passed `criu check` on this host.
#[derive(Debug, Clone)]
pub struct Criu {
    bin: PathBuf,
}

impl Criu {
    /// Probe for a usable CRIU: the `criu` binary on `PATH` (or `$BOATRAMP_CRIU`)
    /// whose `criu check` passes (kernel features present). `None` disables
    /// scale-to-zero for the container backend (the scheduler then routes a
    /// `scale_to_zero` workload to a capable backend). Runs once at backend build.
    pub fn detect() -> Option<Self> {
        let bin = std::env::var_os("BOATRAMP_CRIU")
            .map(PathBuf::from)
            .or_else(|| which("criu"))?;
        let ok = Command::new(&bin)
            .arg("check")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        ok.then_some(Self { bin })
    }

    /// The resolved binary path (for tests / diagnostics).
    pub fn bin(&self) -> &Path {
        &self.bin
    }

    /// Dump the container tree rooted at `pid1` into `image_dir`, killing it (park).
    /// `rootfs` is the host directory the container `pivot_root`ed into.
    pub fn dump(&self, pid1: u32, rootfs: &str, image_dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(image_dir).map_err(|e| format!("create image dir: {e}"))?;
        let args = dump_args(pid1, rootfs, image_dir);
        self.run("dump", &args, image_dir)
    }

    /// Restore the container from `image_dir` (created by [`dump`](Self::dump)),
    /// detached, into an **empty** net namespace (`--empty-ns net`) — the caller
    /// re-attaches the veth + configures `eth0` afterward from the host, using the
    /// returned pid. Returns the restored container's host pid (from the pidfile
    /// CRIU writes).
    pub fn restore(&self, image_dir: &Path, rootfs: &str) -> Result<u32, String> {
        let pidfile = image_dir.join("restore.pid");
        let _ = std::fs::remove_file(&pidfile);
        let args = restore_args(image_dir, rootfs, &pidfile);
        self.run("restore", &args, image_dir)?;
        let pid = std::fs::read_to_string(&pidfile)
            .map_err(|e| format!("read restore pidfile: {e}"))?
            .trim()
            .parse()
            .map_err(|e| format!("parse restore pid: {e}"))?;
        Ok(pid)
    }

    /// Run `criu <args>`, surfacing the tail of the CRIU log on failure.
    fn run(&self, sub: &str, args: &[String], image_dir: &Path) -> Result<(), String> {
        let out = Command::new(&self.bin)
            .args(args)
            .output()
            .map_err(|e| format!("spawn criu {sub}: {e}"))?;
        if out.status.success() {
            return Ok(());
        }
        let log = std::fs::read_to_string(image_dir.join(format!("{sub}.log"))).unwrap_or_default();
        let errs: Vec<&str> = log.lines().filter(|l| l.contains("Error (")).collect();
        let tail = errs
            .iter()
            .rev()
            .take(4)
            .rev()
            .cloned()
            .collect::<Vec<_>>()
            .join("; ");
        Err(format!("criu {sub} failed ({}): {tail}", out.status))
    }
}

/// The flags shared by dump + restore (order-independent). See the module doc for
/// why each is needed. Kept as a pure builder so the wiring is unit-testable
/// off a privileged host.
fn common_args(rootfs: &str) -> Vec<String> {
    vec![
        "--root".into(),
        rootfs.into(),
        "--ext-mount-map".into(),
        "auto".into(),
        "--enable-external-masters".into(),
        "--manage-cgroups=full".into(),
        "--tcp-established".into(),
        "--file-locks".into(),
        "--empty-ns".into(),
        "net".into(),
        "--shell-job".into(),
    ]
}

/// `criu dump` argv (without the leading `criu`).
pub fn dump_args(pid1: u32, rootfs: &str, image_dir: &Path) -> Vec<String> {
    let mut a = vec![
        "dump".into(),
        "--tree".into(),
        pid1.to_string(),
        "-D".into(),
        image_dir.display().to_string(),
        "-o".into(),
        "dump.log".into(),
    ];
    a.extend(common_args(rootfs));
    a
}

/// `criu restore` argv (without the leading `criu`).
pub fn restore_args(image_dir: &Path, rootfs: &str, pidfile: &Path) -> Vec<String> {
    let mut a = vec![
        "restore".into(),
        "-D".into(),
        image_dir.display().to_string(),
        "-o".into(),
        "restore.log".into(),
        "--restore-detached".into(),
        "--pidfile".into(),
        pidfile.display().to_string(),
    ];
    a.extend(common_args(rootfs));
    a
}

/// Find the container's **pid1** (the pidns init) among a cgroup's member pids: the
/// process whose `/proc/<pid>/status` `NSpid:` innermost value is `1`. Returns the
/// host pid. `None` if the cgroup is empty / no pidns-init found.
pub fn find_pid1(cgroup_procs: &Path) -> Option<u32> {
    let procs = std::fs::read_to_string(cgroup_procs).ok()?;
    for pid in procs.split_whitespace() {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        if let Some(line) = status.lines().find(|l| l.starts_with("NSpid:")) {
            // `NSpid: <host> [<inner> ...]` — pidns init has innermost == 1.
            if line.split_whitespace().next_back() == Some("1") {
                return pid.parse().ok();
            }
        }
    }
    None
}

/// The host directory the container at `pid1` `pivot_root`ed into: the source (mount
/// root, field 4) of its `/` mount in `/proc/<pid1>/mountinfo`.
pub fn rootfs_of(pid1: u32) -> Option<String> {
    let mi = std::fs::read_to_string(format!("/proc/{pid1}/mountinfo")).ok()?;
    for line in mi.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // mountinfo: ... f[3]=root-in-fs f[4]=mountpoint ...
        if f.len() > 4 && f[4] == "/" {
            return Some(f[3].to_string());
        }
    }
    None
}

/// Locate a binary on `PATH`.
fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|d| d.join(bin))
            .find(|p| p.is_file())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dump_args_target_pid1_with_root_and_external_maps() {
        let a = dump_args(4242, "/data/rootfs/abc", Path::new("/img"));
        assert_eq!(a[0], "dump");
        // targets the pid1 tree
        let ti = a.iter().position(|x| x == "--tree").unwrap();
        assert_eq!(a[ti + 1], "4242");
        // the mount-isolation trio that made restore work
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--root" && w[1] == "/data/rootfs/abc"));
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--ext-mount-map" && w[1] == "auto"));
        assert!(a.iter().any(|x| x == "--enable-external-masters"));
        // networking is managed by the launcher, not CRIU
        assert!(a.windows(2).any(|w| w[0] == "--empty-ns" && w[1] == "net"));
    }

    #[test]
    fn restore_args_detach_pidfile_and_empty_net() {
        let a = restore_args(
            Path::new("/img"),
            "/data/rootfs/abc",
            Path::new("/img/restore.pid"),
        );
        assert_eq!(a[0], "restore");
        assert!(a.iter().any(|x| x == "--restore-detached"));
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--pidfile" && w[1] == "/img/restore.pid"));
        // net ns is left empty; the backend re-attaches the veth afterward
        assert!(a.windows(2).any(|w| w[0] == "--empty-ns" && w[1] == "net"));
        // same isolation flags as dump, so the mount tree matches
        assert!(a
            .windows(2)
            .any(|w| w[0] == "--root" && w[1] == "/data/rootfs/abc"));
    }
}
