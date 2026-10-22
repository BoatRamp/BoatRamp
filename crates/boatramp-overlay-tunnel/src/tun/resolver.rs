//! Host DNS split-horizon integration, Linux (plan §3.6): point ONLY the configured zone suffix at
//! the embedded DNS responder (plan §3.3), never the whole system — so every other hostname on the
//! box keeps resolving exactly as it did before this front-end ran.
//!
//! **This is the plan §3.9 robustness requirement that actually bites**: a kernel route vanishes
//! the instant the TUN device's file descriptor closes (plan §3.9 — "routes bound to the TUN vanish
//! when the device dies"), so [`super::device`]'s route needs no Drop-time revert. The resolver
//! configuration below is NOT like that — `resolvectl`'s per-link override and the `/etc/resolv.conf`
//! stanza both outlive the process that set them, so [`ResolverGuard`] carries an explicit
//! [`ResolverGuard::revert`] AND a [`Drop`] fallback (best-effort, synchronous — Drop cannot run
//! async code, so this shells out blocking, which is fine for a once-per-shutdown cleanup), AND
//! [`super::teardown`]'s on-disk marker records enough to revert it again from a FRESH process after
//! a crash where Drop never ran at all (SIGKILL, `panic = "abort"`, a lost power cord).

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;

/// Which mechanism [`ResolverGuard::apply`] used — persisted in the plan §3.9 marker so a FRESH
/// process (after a crash) knows how to revert without ever having held the original guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Method {
    /// `resolvectl` (systemd-resolved) per-link DNS + routing-domain override — the preferred path:
    /// genuinely scoped to the zone suffix, nothing else on the host is touched.
    Resolvectl,
    /// A managed, marker-delimited stanza appended to `/etc/resolv.conf` — the fallback when
    /// systemd-resolved is unavailable. **Caveat, documented rather than hidden:** classic
    /// `/etc/resolv.conf` has no per-domain scoping, so this fallback adds `127.0.0.1` as A
    /// nameserver for the WHOLE host, not just the zone — acceptable only because the embedded
    /// responder itself still REFUSES (never answers, never recurses) anything outside the zone
    /// (plan §3.3/§5), so no query is ever mis-answered, but other resolvers on the same host do get
    /// one extra (first-tried) nameserver in their list for the front-end's lifetime.
    ResolvConfStanza,
}

const STANZA_BEGIN: &str = "# BEGIN boatramp-tunnel (managed — do not edit by hand)";
const STANZA_END: &str = "# END boatramp-tunnel";

fn resolv_conf_path() -> PathBuf {
    PathBuf::from("/etc/resolv.conf")
}

/// Try `resolvectl` first (plan §3.6): scope DNS + the routing-only domain to EXACTLY the zone
/// suffix on the TUN interface. Returns `Ok(true)` on success, `Ok(false)` if `resolvectl` itself
/// isn't usable (not installed / no systemd-resolved) so the caller falls back, and `Err` only for
/// an unexpected I/O failure launching the process at all.
fn try_resolvectl(tun_name: &str, dns_addr: SocketAddr, zone_suffix: &str) -> io::Result<bool> {
    let dns = run(Command::new("resolvectl").args(["dns", tun_name, &dns_addr.to_string()]))?;
    if !dns {
        return Ok(false);
    }
    // The leading `~` marks this a ROUTING-ONLY domain (per `resolvectl`'s own syntax): queries for
    // the zone go to this link's DNS server, but the zone is NOT added as a search suffix and no
    // OTHER domain's resolution is affected — exactly the split-horizon plan §3.3/§3.6 wants.
    let domain =
        run(Command::new("resolvectl").args(["domain", tun_name, &format!("~{zone_suffix}")]))?;
    Ok(domain)
}

/// Run `cmd`, returning `Ok(true)` on a successful exit, `Ok(false)` on a clean non-zero exit (the
/// caller falls back), and `Err` only if the process could not even be spawned (e.g. the binary
/// doesn't exist) — also treated as "fall back" by [`try_resolvectl`]'s caller, never a panic.
fn run(cmd: &mut Command) -> io::Result<bool> {
    match cmd.status() {
        Ok(status) => Ok(status.success()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}

fn revert_resolvectl(tun_name: &str) {
    if let Err(err) = Command::new("resolvectl")
        .args(["revert", tun_name])
        .status()
    {
        tracing::warn!(
            %tun_name, error = %err,
            "boatramp tunnel: `resolvectl revert` failed — the DNS override may still be in \
             place; fix manually with `resolvectl revert <iface>` if `resolv.conf`/name \
             resolution looks wrong after this process exits"
        );
    }
}

/// Fallback (plan §3.6): append a marker-delimited stanza pointing the WHOLE host at the embedded
/// responder (see [`Method::ResolvConfStanza`]'s doc for the caveat). Idempotent: if a stanza from
/// an earlier, uncleanly-terminated run is already present, it is removed first so this never
/// nests/duplicates.
fn append_resolv_conf_stanza(dns_addr: SocketAddr) -> io::Result<()> {
    remove_resolv_conf_stanza()?; // idempotent — see above
    let path = resolv_conf_path();
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut new_contents = existing;
    if !new_contents.is_empty() && !new_contents.ends_with('\n') {
        new_contents.push('\n');
    }
    new_contents.push_str(STANZA_BEGIN);
    new_contents.push('\n');
    new_contents.push_str(&format!("nameserver {}\n", dns_addr.ip()));
    new_contents.push_str(STANZA_END);
    new_contents.push('\n');
    std::fs::write(&path, new_contents)
}

/// Strip a previously-appended stanza (identified by its begin/end markers) back out of
/// `/etc/resolv.conf`. A no-op (not an error) if no stanza is present — this is called
/// unconditionally on EVERY revert path, including a fresh-process [`cleanup_stale`] where the
/// stanza may or may not actually be there.
fn remove_resolv_conf_stanza() -> io::Result<()> {
    let path = resolv_conf_path();
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Ok(()); // no resolv.conf at all — nothing to strip
    };
    if !contents.contains(STANZA_BEGIN) {
        return Ok(());
    }
    let mut out = String::with_capacity(contents.len());
    let mut inside = false;
    for line in contents.lines() {
        if line == STANZA_BEGIN {
            inside = true;
            continue;
        }
        if line == STANZA_END {
            inside = false;
            continue;
        }
        if inside {
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    std::fs::write(&path, out)
}

/// A failure applying the host resolver override.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    #[error("neither `resolvectl` nor a managed /etc/resolv.conf stanza could be applied: {0}")]
    Io(#[from] io::Error),
}

/// An applied host-resolver override (plan §3.6), reverted on [`ResolverGuard::revert`] or
/// (best-effort, synchronous — module doc) on [`Drop`].
pub struct ResolverGuard {
    method: Method,
    tun_name: String,
    reverted: bool,
}

impl ResolverGuard {
    /// Apply the override: `resolvectl` first, the `/etc/resolv.conf` stanza if that isn't usable.
    pub fn apply(
        tun_name: &str,
        dns_addr: SocketAddr,
        zone_suffix: &str,
    ) -> Result<Self, ResolverError> {
        let method = if try_resolvectl(tun_name, dns_addr, zone_suffix)? {
            Method::Resolvectl
        } else {
            append_resolv_conf_stanza(dns_addr)?;
            Method::ResolvConfStanza
        };
        Ok(Self {
            method,
            tun_name: tun_name.to_string(),
            reverted: false,
        })
    }

    #[must_use]
    pub fn method(&self) -> Method {
        self.method
    }

    /// Explicitly revert — the normal shutdown path calls this (then [`super::teardown`] removes
    /// the marker); idempotent, so a later [`Drop`] calling it again is harmless.
    pub fn revert(&mut self) {
        if self.reverted {
            return;
        }
        revert_by_method(self.method, &self.tun_name);
        self.reverted = true;
    }
}

impl Drop for ResolverGuard {
    fn drop(&mut self) {
        self.revert();
    }
}

/// Revert by method + interface name alone — what [`super::teardown::cleanup_stale`] calls from a
/// FRESH process reverting a crashed run's marker, with no live [`ResolverGuard`] to call.
pub fn revert_by_method(method: Method, tun_name: &str) {
    match method {
        Method::Resolvectl => revert_resolvectl(tun_name),
        Method::ResolvConfStanza => {
            if let Err(err) = remove_resolv_conf_stanza() {
                tracing::warn!(
                    error = %err,
                    "boatramp tunnel: failed to remove the managed /etc/resolv.conf stanza — \
                     check /etc/resolv.conf by hand"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Exercises the stanza add/remove pair directly against a throwaway file (NOT the real
    /// `/etc/resolv.conf` — `resolv_conf_path` is not parameterized for production code's sake, so
    /// this test duplicates the exact append/strip logic against a temp path instead of calling the
    /// real functions, which would require root and would mutate this host's actual DNS config).
    fn append_stanza_at(path: &Path, dns_addr: SocketAddr) -> io::Result<()> {
        let existing = std::fs::read_to_string(path).unwrap_or_default();
        let mut new_contents = existing;
        if !new_contents.is_empty() && !new_contents.ends_with('\n') {
            new_contents.push('\n');
        }
        new_contents.push_str(STANZA_BEGIN);
        new_contents.push('\n');
        new_contents.push_str(&format!("nameserver {}\n", dns_addr.ip()));
        new_contents.push_str(STANZA_END);
        new_contents.push('\n');
        std::fs::write(path, new_contents)
    }

    fn remove_stanza_at(path: &Path) -> io::Result<()> {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return Ok(());
        };
        if !contents.contains(STANZA_BEGIN) {
            return Ok(());
        }
        let mut out = String::new();
        let mut inside = false;
        for line in contents.lines() {
            if line == STANZA_BEGIN {
                inside = true;
                continue;
            }
            if line == STANZA_END {
                inside = false;
                continue;
            }
            if inside {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        std::fs::write(path, out)
    }

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("br-tunnel-resolv-{tag}-{}", std::process::id()))
    }

    #[test]
    fn appending_then_removing_the_stanza_restores_the_original_content() {
        let path = temp_path("roundtrip");
        let original = "nameserver 8.8.8.8\nsearch example.com\n";
        std::fs::write(&path, original).unwrap();

        append_stanza_at(&path, "127.0.0.1:5353".parse().unwrap()).unwrap();
        let with_stanza = std::fs::read_to_string(&path).unwrap();
        assert!(with_stanza.contains(STANZA_BEGIN));
        assert!(with_stanza.contains("nameserver 127.0.0.1"));
        assert!(
            with_stanza.contains("nameserver 8.8.8.8"),
            "original content must be kept"
        );

        remove_stanza_at(&path).unwrap();
        let restored = std::fs::read_to_string(&path).unwrap();
        assert_eq!(restored, original);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn appending_twice_does_not_nest_or_duplicate() {
        let path = temp_path("idempotent");
        std::fs::write(&path, "nameserver 8.8.8.8\n").unwrap();

        append_stanza_at(&path, "127.0.0.1:5353".parse().unwrap()).unwrap();
        remove_stanza_at(&path).unwrap(); // mirrors `append_resolv_conf_stanza`'s own idempotency
        append_stanza_at(&path, "127.0.0.1:5353".parse().unwrap()).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.matches(STANZA_BEGIN).count(), 1);
        assert_eq!(contents.matches(STANZA_END).count(), 1);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn removing_when_no_stanza_is_present_is_a_harmless_no_op() {
        let path = temp_path("absent");
        std::fs::write(&path, "nameserver 8.8.8.8\n").unwrap();
        remove_stanza_at(&path).unwrap();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "nameserver 8.8.8.8\n"
        );
        let _ = std::fs::remove_file(&path);
    }

    /// `resolvectl`/`resolv.conf` interaction needs root + a real link, so this only proves the
    /// non-privileged, always-safe part: `try_resolvectl` on a bogus interface name falls back
    /// (`Ok(false)`) rather than erroring, because either `resolvectl` isn't installed in this test
    /// sandbox (`NotFound` → `Ok(false)`) or it IS installed and cleanly rejects the bogus
    /// interface (non-zero exit → `Ok(false)`) — either way, never an `Err` from a missing binary.
    #[test]
    fn try_resolvectl_falls_back_cleanly_when_unusable() {
        let result = try_resolvectl(
            "br-test-nonexistent-iface-xyz",
            "127.0.0.1:5353".parse().unwrap(),
            "svc.test.internal.",
        );
        assert!(
            result.is_ok(),
            "a missing binary must fall back, not error: {result:?}"
        );
    }
}
