//! The plan §3.9 "single most important robustness requirement": a dirty-state marker file,
//! written to disk BEFORE (and updated as) each host mutation happens, listing enough for a FRESH
//! process to revert a crashed run's leftovers — the scenario [`super::frontend::TunFrontend`]'s own
//! explicit `shutdown()` and its [`super::resolver::ResolverGuard`]'s [`Drop`] fallback cannot cover,
//! because neither runs at all on SIGKILL, a lost power cord, or a `panic = "abort"` build.
//!
//! **Why the resolver override is the only thing tracked here**: plan §3.9's own text — "routes
//! bound to the TUN vanish when the device dies" — so a route needs no cross-process revert
//! bookkeeping; the `resolvectl`/`resolv.conf` mutation ([`super::resolver`]) is genuinely
//! persistent and is the one state a half-cleaned-up run would otherwise leave silently broken.

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::resolver::Method as ResolverMethod;

/// The on-disk marker (plan §3.9). Written as pretty JSON — small, human-inspectable if an
/// operator ever needs to look at it by hand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Marker {
    pub pid: u32,
    pub started_at_unix: u64,
    pub tun_name: String,
    pub cidr: String,
    /// `None` until the resolver override is actually applied (plan §3.6) — a marker written
    /// between "TUN opened" and "resolver applied" correctly records "nothing persistent to revert
    /// yet", so a crash in that narrow window costs nothing to clean up.
    pub resolver: Option<ResolverMethod>,
    /// The zone suffix the resolver override was scoped to — needed to revert the macOS
    /// [`ResolverMethod::EtcResolver`] backend (which names its `/etc/resolver/<zone>` file by the
    /// zone) from a FRESH process. `#[serde(default)]` so a marker written by a pre-R3 binary (no
    /// such field) still deserializes; `None`/`""` is harmless for the Linux methods, which revert
    /// by interface name / the fixed `/etc/resolv.conf` path instead.
    #[serde(default)]
    pub resolver_zone: Option<String>,
}

impl Marker {
    #[must_use]
    pub fn new(tun_name: String, cidr: String) -> Self {
        Self {
            pid: std::process::id(),
            started_at_unix: now_unix(),
            tun_name,
            cidr,
            resolver: None,
            resolver_zone: None,
        }
    }

    pub fn write(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self).map_err(io::Error::other)?;
        std::fs::write(path, json)
    }

    /// `Ok(None)` if no marker file exists — the common case (a prior run shut down cleanly, or
    /// this is the first run ever).
    pub fn read(path: &Path) -> io::Result<Option<Self>> {
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                let marker: Self = serde_json::from_str(&contents).map_err(io::Error::other)?;
                Ok(Some(marker))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Idempotent — removing an already-absent marker is success, not an error.
    pub fn remove(path: &Path) -> io::Result<()> {
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Best-effort liveness check: `kill(pid, None)` (a POSIX idiom — no signal is actually delivered,
/// only existence/permission is checked), portable across Linux and macOS (unlike parsing a
/// Linux-only `/proc/<pid>`, which this crate's dev platform doesn't even have). A SAFE `nix`
/// wrapper — this crate is `#![forbid(unsafe_code)]`. `EPERM` (the process exists but belongs to
/// another user) still counts as alive; any other error (most commonly `ESRCH`, no such process)
/// counts as dead. **Documented limitation, not a hard safety mechanism**: PIDs are reused after a
/// reboot/enough churn, so this can (rarely) say "still alive" about an unrelated process that
/// happens to reuse the old PID — the failure mode of a false positive here is simply "skip
/// reverting this time", never a wrong revert, since [`cleanup_stale`] only ever acts on the
/// `tun_name`/`resolver` method already recorded in the marker, never on anything read back out of
/// the (possibly-unrelated) live process.
fn process_alive(pid: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::kill;
    use nix::unistd::Pid;
    let Ok(pid) = i32::try_from(pid) else {
        return false; // not a representable real PID at all
    };
    matches!(kill(Pid::from_raw(pid), None), Ok(()) | Err(Errno::EPERM))
}

/// What [`cleanup_stale`] actually did — surfaced so [`super::frontend::TunFrontend::bind`] and
/// `boatramp tunnel --cleanup` can both log something meaningful.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    pub found_marker: bool,
    pub reverted_resolver: bool,
    /// The marker's recorded PID is still alive — nothing was touched (module doc: never revert
    /// out from under a live owner).
    pub owner_still_running: bool,
}

/// Detect + best-effort-revert a stale marker from a crashed previous run (plan §3.9). Called by
/// [`super::frontend::TunFrontend::bind`] before writing THIS run's own marker, and by
/// `boatramp tunnel --cleanup`.
pub fn cleanup_stale(path: &Path) -> io::Result<CleanupReport> {
    let mut report = CleanupReport::default();
    let Some(marker) = Marker::read(path)? else {
        return Ok(report);
    };
    report.found_marker = true;

    if process_alive(marker.pid) {
        report.owner_still_running = true;
        return Ok(report);
    }

    if let Some(method) = marker.resolver {
        super::resolver::revert_by_method(
            method,
            &marker.tun_name,
            marker.resolver_zone.as_deref().unwrap_or_default(),
        );
        report.reverted_resolver = true;
    }
    Marker::remove(path)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_marker_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "br-tunnel-marker-{tag}-{}.json",
            std::process::id()
        ))
    }

    #[test]
    fn write_then_read_round_trips() {
        let path = temp_marker_path("roundtrip");
        let mut marker = Marker::new("tun-test0".to_string(), "100.64.0.0/10".to_string());
        marker.resolver = Some(ResolverMethod::Resolvectl);
        marker.write(&path).unwrap();

        let read_back = Marker::read(&path).unwrap().unwrap();
        assert_eq!(read_back.tun_name, "tun-test0");
        assert_eq!(read_back.cidr, "100.64.0.0/10");
        assert_eq!(read_back.resolver, Some(ResolverMethod::Resolvectl));
        assert_eq!(read_back.pid, std::process::id());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn reading_a_missing_marker_is_ok_none_not_an_error() {
        let path = temp_marker_path("absent");
        let _ = std::fs::remove_file(&path);
        assert!(Marker::read(&path).unwrap().is_none());
    }

    #[test]
    fn removing_a_missing_marker_is_a_harmless_no_op() {
        let path = temp_marker_path("remove-absent");
        let _ = std::fs::remove_file(&path);
        assert!(Marker::remove(&path).is_ok());
    }

    #[test]
    fn cleanup_stale_with_no_marker_reports_nothing_found() {
        let path = temp_marker_path("cleanup-none");
        let _ = std::fs::remove_file(&path);
        let report = cleanup_stale(&path).unwrap();
        assert_eq!(report, CleanupReport::default());
    }

    /// The headline plan §3.9 scenario: a marker left by a PID that is (verifiably — a child
    /// process this test itself spawned and already reaped) no longer running must be reverted and
    /// removed.
    #[test]
    fn cleanup_stale_reverts_and_removes_a_marker_from_a_dead_pid() {
        let path = temp_marker_path("cleanup-dead");
        let mut marker = Marker::new("tun-dead0".to_string(), "100.64.0.0/10".to_string());
        // A genuinely dead PID, not a guessed "probably unused" constant: spawn a trivial child,
        // wait for it to exit (reaping it), then use ITS pid — guaranteed not running any more.
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("the `true` binary must exist on any Unix test runner");
        marker.pid = child.id();
        child.wait().expect("the child must exit");
        marker.resolver = None; // no resolver mutation recorded — nothing to revert, just remove
        marker.write(&path).unwrap();

        let report = cleanup_stale(&path).unwrap();
        assert!(report.found_marker);
        assert!(!report.owner_still_running);
        assert!(!report.reverted_resolver, "no resolver method was recorded");
        assert!(
            Marker::read(&path).unwrap().is_none(),
            "the marker must be removed after cleanup"
        );
    }

    /// The safety half of the same scenario: a marker whose PID IS this very test process must be
    /// left entirely alone (module doc — never revert out from under a live owner).
    #[test]
    fn cleanup_stale_leaves_a_marker_from_a_live_pid_untouched() {
        let path = temp_marker_path("cleanup-live");
        let marker = Marker::new("tun-live0".to_string(), "100.64.0.0/10".to_string());
        marker.write(&path).unwrap();

        let report = cleanup_stale(&path).unwrap();
        assert!(report.owner_still_running);
        assert!(!report.reverted_resolver);
        assert!(
            Marker::read(&path).unwrap().is_some(),
            "a live owner's marker must survive"
        );

        let _ = std::fs::remove_file(&path);
    }
}
