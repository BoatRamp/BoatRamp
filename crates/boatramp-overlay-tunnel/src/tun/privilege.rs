//! Best-effort privilege drop after setup (plan §3.7): "open TUN + install routes, then drop
//! privileges for the splice loop where feasible." On Linux there are two realistic ways this
//! front-end ends up privileged, and only one of them has anything left to drop:
//!
//! - **`CAP_NET_ADMIN` via `setcap cap_net_admin+ep`** (the plan's own recommended operator setup,
//!   `device.rs`'s doc) — the process runs as an ordinary, non-root user the whole time; there is
//!   no root to drop FROM, so [`drop_to_unprivileged`] is correctly a no-op here.
//! - **Root, via `sudo`** — `sudo` conventionally exports `SUDO_UID`/`SUDO_GID` naming the invoking
//!   user; once the TUN device is open and the route is installed (both need root/`CAP_NET_ADMIN`),
//!   [`drop_to_unprivileged`] drops to that identity for everything after — the DNS responder, the
//!   netstack poll loop, the catalog/cap-cache/dial path.
//!
//! Uses `nix`'s SAFE wrappers over `geteuid`/`setgid`/`setuid` — this crate is
//! `#![forbid(unsafe_code)]` (`lib.rs`), so a raw `libc` call is not an option here.
//!
//! **This is best-effort, not a sandbox**: it is one `setgid`+`setuid` pair, not a full capability
//! bounding-set drop, chroot, or seccomp filter. Documented here rather than oversold.

use nix::unistd::{Gid, Uid, geteuid, setgid, setuid};

/// A failure dropping privileges.
#[derive(Debug, thiserror::Error)]
pub enum PrivilegeError {
    #[error("setgid({0}): {1}")]
    SetGid(u32, #[source] nix::Error),
    #[error("setuid({0}): {1}")]
    SetUid(u32, #[source] nix::Error),
}

/// If this process is effectively root AND was invoked via `sudo` (i.e. `SUDO_UID`/`SUDO_GID` are
/// both set and parse as integers), drop to that uid/gid — group first, then user (the conventional
/// order: dropping the user first would make dropping the group fail, since only root may change
/// the group once the effective user is no longer root). A no-op, returning `Ok(false)`, in every
/// other case: not root, or root but with no `SUDO_UID`/`SUDO_GID` to drop to (e.g. a `CAP_NET_ADMIN`
/// invocation, which is already unprivileged by the measure that matters here).
///
/// # Errors
/// Only if this process IS root with a `sudo`-provided target identity, and the `setgid`/`setuid`
/// syscalls themselves fail — which should not happen for a legitimate root process dropping to a
/// valid uid/gid, but is surfaced rather than ignored since a failed drop silently staying
/// privileged would be the opposite of this function's whole point.
pub fn drop_to_unprivileged() -> Result<bool, PrivilegeError> {
    if !geteuid().is_root() {
        return Ok(false); // not root — e.g. CAP_NET_ADMIN — nothing to drop
    }
    let (Some(uid), Some(gid)) = (sudo_env("SUDO_UID"), sudo_env("SUDO_GID")) else {
        return Ok(false); // root with no sudo-provided target identity to drop to
    };
    setgid(Gid::from_raw(gid)).map_err(|e| PrivilegeError::SetGid(gid, e))?;
    setuid(Uid::from_raw(uid)).map_err(|e| PrivilegeError::SetUid(uid, e))?;
    tracing::info!(
        uid,
        gid,
        "boatramp tunnel: dropped root privileges after TUN/route setup"
    );
    Ok(true)
}

fn sudo_env(name: &str) -> Option<u32> {
    std::env::var(name).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one branch this test suite can exercise without actually running as root: confirm the
    /// function is callable and, for the overwhelmingly common case (a non-root test runner),
    /// returns `Ok(false)` rather than attempting (and failing) a privilege drop.
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
}
