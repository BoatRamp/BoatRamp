//! Best-effort privilege drop after setup (plan §3.7): "open TUN + install routes, then drop
//! privileges for the splice loop where feasible." On Linux there are two realistic ways this
//! front-end ends up privileged, and they have DIFFERENT residual exposure after setup:
//!
//! - **`CAP_NET_ADMIN` via `setcap cap_net_admin+ep`** (the plan's own recommended operator setup,
//!   `device.rs`'s doc) — the process runs as an ordinary, non-root user the whole time, so
//!   [`drop_to_unprivileged`] is correctly a no-op here (there is no root to drop FROM). **Security
//!   review MEDIUM-2 — stated honestly, not understated:** this posture is NOT "already
//!   unprivileged by the measure that matters". `CAP_NET_ADMIN` itself is a broad, host-wide
//!   capability (arbitrary interface/route/netns manipulation) that stays in the process's
//!   EFFECTIVE set for its entire lifetime — including the whole time the netstack parses
//!   attacker-controlled packets and the embedded DNS responder parses attacker-controlled queries.
//!   This module does not currently drop that capability (e.g. via `prctl(PR_CAPBSET_DROP)` /
//!   clearing the effective set post-setup while keeping it in the permitted set only long enough
//!   to reacquire if ever needed) — that is real residual exposure, deliberately deferred to R5
//!   ("the real effective-`CAP_NET_ADMIN` drop"), not solved by this module.
//! - **Root, via `sudo`** — `sudo` conventionally exports `SUDO_UID`/`SUDO_GID` naming the invoking
//!   user; once the TUN device is open and the route is installed (both need root/`CAP_NET_ADMIN`),
//!   [`drop_to_unprivileged`] drops to that identity — group membership (`setgroups`), GID, then
//!   UID, in that order — for everything after: the DNS responder, the netstack poll loop, the
//!   catalog/cap-cache/dial path. This path's drop IS real and complete (full `root` → an
//!   unprivileged uid/gid with no supplementary groups), unlike the `CAP_NET_ADMIN` path above.
//!
//! Uses `nix`'s SAFE wrappers over `geteuid`/`setgroups`/`setgid`/`setuid` — this crate is
//! `#![forbid(unsafe_code)]` (`lib.rs`), so a raw `libc` call is not an option here.
//!
//! **A drop failure is treated as FATAL by the caller** ([`super::frontend::TunFrontend::bind`]):
//! this module only ever returns the error, never swallows it — failing a security control closed,
//! not open, is the caller's job and is covered by that module's own tests.

use nix::unistd::{Gid, Uid, geteuid, setgid, setuid};
// `nix::unistd::setgroups` isn't exposed on apple targets at all (this crate's `tun` feature is
// Linux-only in scope — plan §3 — so that's fine for the real deployment target; the cfg below
// just keeps this module, and its tests, compiling on a non-Linux dev machine too).
#[cfg(target_os = "linux")]
use nix::unistd::setgroups;

/// A failure dropping privileges.
#[derive(Debug, thiserror::Error)]
pub enum PrivilegeError {
    #[error("setgroups({0}): {1}")]
    SetGroups(u32, #[source] nix::Error),
    #[error("setgid({0}): {1}")]
    SetGid(u32, #[source] nix::Error),
    #[error("setuid({0}): {1}")]
    SetUid(u32, #[source] nix::Error),
}

/// If this process is effectively root AND was invoked via `sudo` (i.e. `SUDO_UID`/`SUDO_GID` are
/// both set and parse as integers), drop to that uid/gid — **supplementary groups first** (Security
/// review MEDIUM-1: `setgroups` needs `CAP_SETGID`, which is only still held before the group/user
/// drop below; skipping it would leave root's supplementary groups — `wheel`/`docker`/`disk`/`adm`,
/// whatever this host granted root — attached to the "dropped" process), **then the primary group**
/// (`setgid`), **then the user** (`setuid`) — the conventional order: dropping the user first would
/// make dropping the group fail, since only root may change the group once the effective user is no
/// longer root. A no-op, returning `Ok(false)`, in every other case: not root, or root but with no
/// `SUDO_UID`/`SUDO_GID` to drop to (e.g. the `CAP_NET_ADMIN` posture — see the module doc for its
/// OWN, different residual exposure).
///
/// # Errors
/// If this process IS root with a `sudo`-provided target identity, and `setgroups`/`setgid`/
/// `setuid` themselves fail — which should not happen for a legitimate root process dropping to a
/// valid uid/gid, but is surfaced (and, by the caller, treated as fatal) rather than ignored: a
/// failed drop silently staying privileged would be the opposite of this function's whole point.
pub fn drop_to_unprivileged() -> Result<bool, PrivilegeError> {
    drop_to_unprivileged_with(
        geteuid().is_root(),
        sudo_env("SUDO_UID"),
        sudo_env("SUDO_GID"),
        &RealSyscalls,
    )
}

fn sudo_env(name: &str) -> Option<u32> {
    std::env::var(name).ok()?.parse().ok()
}

/// The three syscalls [`drop_to_unprivileged_with`] drives, abstracted behind a trait so the
/// exact sequence/arguments/fatal-on-first-error behavior are unit-testable WITHOUT actually
/// running as root (which doing so for real in a test would alter the whole test *process's*
/// identity for every other test sharing that binary — not an option).
trait Syscalls {
    fn setgroups(&self, groups: &[Gid]) -> nix::Result<()>;
    fn setgid(&self, gid: Gid) -> nix::Result<()>;
    fn setuid(&self, uid: Uid) -> nix::Result<()>;
}

struct RealSyscalls;

impl Syscalls for RealSyscalls {
    #[cfg(target_os = "linux")]
    fn setgroups(&self, groups: &[Gid]) -> nix::Result<()> {
        setgroups(groups)
    }
    #[cfg(not(target_os = "linux"))]
    fn setgroups(&self, _groups: &[Gid]) -> nix::Result<()> {
        // Never reached in practice (module doc: this crate's `tun` feature is Linux-only) — kept
        // so this module builds on a non-Linux dev machine, where `nix::unistd::setgroups` isn't
        // even exposed.
        Ok(())
    }
    fn setgid(&self, gid: Gid) -> nix::Result<()> {
        setgid(gid)
    }
    fn setuid(&self, uid: Uid) -> nix::Result<()> {
        setuid(uid)
    }
}

/// [`drop_to_unprivileged`]'s actual logic, with "am I root" / "what does `sudo` say the target
/// identity is" / the syscalls themselves all passed in — see the module-level test
/// `the_sudo_drop_path_calls_setgroups_before_setgid_before_setuid` and
/// `a_setgroups_failure_is_fatal_and_stops_before_setgid` for what this buys.
fn drop_to_unprivileged_with(
    is_root: bool,
    sudo_uid: Option<u32>,
    sudo_gid: Option<u32>,
    syscalls: &impl Syscalls,
) -> Result<bool, PrivilegeError> {
    if !is_root {
        return Ok(false); // not root — e.g. CAP_NET_ADMIN — nothing to drop
    }
    let (Some(uid), Some(gid)) = (sudo_uid, sudo_gid) else {
        return Ok(false); // root with no sudo-provided target identity to drop to
    };
    syscalls
        .setgroups(&[Gid::from_raw(gid)])
        .map_err(|e| PrivilegeError::SetGroups(gid, e))?;
    syscalls
        .setgid(Gid::from_raw(gid))
        .map_err(|e| PrivilegeError::SetGid(gid, e))?;
    syscalls
        .setuid(Uid::from_raw(uid))
        .map_err(|e| PrivilegeError::SetUid(uid, e))?;
    tracing::info!(
        uid,
        gid,
        "boatramp tunnel: dropped root privileges (incl. supplementary groups) after TUN/route setup"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    /// The one branch this test suite can exercise against the REAL `drop_to_unprivileged` without
    /// actually running as root: confirm the function is callable and, for the overwhelmingly
    /// common case (a non-root test runner), returns `Ok(false)` rather than attempting (and
    /// failing) a privilege drop.
    #[test]
    fn is_a_no_op_when_not_root() {
        if geteuid().is_root() {
            // This suite runs as root in some CI sandboxes — skip rather than assert the wrong
            // thing (dropping root here would be real and would affect the rest of the test run).
            return;
        }
        assert!(!drop_to_unprivileged().unwrap());
    }

    #[test]
    fn sudo_env_rejects_missing_values() {
        // Exercises the parse path directly rather than mutating real process env vars (which
        // `std::env::set_var` on a multi-threaded test binary is its own hazard) — `sudo_env` is a
        // thin wrapper, so this just confirms the missing-var path returns `None` rather than
        // panicking.
        assert_eq!(sudo_env("BR_TUNNEL_TEST_VAR_DEFINITELY_UNSET"), None);
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Call {
        Groups(Vec<u32>),
        Gid(u32),
        Uid(u32),
    }

    /// Records every call made to it (in order) instead of touching real process identity —
    /// `RefCell` is enough since `drop_to_unprivileged_with` never calls it from more than one
    /// thread.
    #[derive(Default)]
    struct RecordingSyscalls {
        calls: RefCell<Vec<Call>>,
        /// If set, `setgroups` returns this error instead of recording success — for the
        /// fatal-on-first-error test below.
        fail_setgroups: bool,
    }

    impl Syscalls for RecordingSyscalls {
        fn setgroups(&self, groups: &[Gid]) -> nix::Result<()> {
            self.calls
                .borrow_mut()
                .push(Call::Groups(groups.iter().map(|g| g.as_raw()).collect()));
            if self.fail_setgroups {
                return Err(nix::errno::Errno::EPERM);
            }
            Ok(())
        }
        fn setgid(&self, gid: Gid) -> nix::Result<()> {
            self.calls.borrow_mut().push(Call::Gid(gid.as_raw()));
            Ok(())
        }
        fn setuid(&self, uid: Uid) -> nix::Result<()> {
            self.calls.borrow_mut().push(Call::Uid(uid.as_raw()));
            Ok(())
        }
    }

    /// Security review MEDIUM-1, directly: the sudo-drop path must call `setgroups` — with EXACTLY
    /// the target gid, as the sole supplementary group — strictly BEFORE `setgid`, strictly before
    /// `setuid`. Drives the real decision logic (`is_root`/`sudo_uid`/`sudo_gid` all supplied as
    /// plain arguments) against a recording double, so this needs no actual root.
    #[test]
    fn the_sudo_drop_path_calls_setgroups_before_setgid_before_setuid() {
        let syscalls = RecordingSyscalls::default();
        let dropped = drop_to_unprivileged_with(true, Some(1000), Some(1000), &syscalls).unwrap();
        assert!(dropped);
        assert_eq!(
            syscalls.calls.into_inner(),
            vec![Call::Groups(vec![1000]), Call::Gid(1000), Call::Uid(1000),]
        );
    }

    /// Security review MEDIUM-1 (the failure half): a `setgroups` failure must be propagated as an
    /// error — never silently ignored with the drop continuing (which would leave root's
    /// supplementary groups attached) — and must stop BEFORE `setgid`/`setuid` run at all.
    #[test]
    fn a_setgroups_failure_is_fatal_and_stops_before_setgid() {
        let syscalls = RecordingSyscalls {
            fail_setgroups: true,
            ..Default::default()
        };
        let err = drop_to_unprivileged_with(true, Some(1000), Some(1000), &syscalls).unwrap_err();
        assert!(matches!(err, PrivilegeError::SetGroups(1000, _)));
        assert_eq!(
            syscalls.calls.into_inner(),
            vec![Call::Groups(vec![1000])],
            "setgid/setuid must never run after setgroups fails"
        );
    }

    /// Not root ⇒ a no-op regardless of what `sudo_uid`/`sudo_gid` claim — and, in particular, NO
    /// syscall is ever attempted.
    #[test]
    fn not_root_is_a_no_op_even_with_sudo_vars_present() {
        let syscalls = RecordingSyscalls::default();
        let dropped = drop_to_unprivileged_with(false, Some(1000), Some(1000), &syscalls).unwrap();
        assert!(!dropped);
        assert!(syscalls.calls.into_inner().is_empty());
    }

    /// Root but no `sudo` target identity (the `CAP_NET_ADMIN` posture, module doc) ⇒ a no-op, no
    /// syscall attempted.
    #[test]
    fn root_with_no_sudo_target_is_a_no_op() {
        let syscalls = RecordingSyscalls::default();
        assert!(!drop_to_unprivileged_with(true, None, None, &syscalls).unwrap());
        assert!(syscalls.calls.into_inner().is_empty());
    }
}
