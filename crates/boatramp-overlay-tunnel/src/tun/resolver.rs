//! Host DNS split-horizon integration (plan §3.6) — Linux (`resolvectl`, falling back to an
//! `/etc/resolv.conf` stanza) and macOS (`/etc/resolver/<zone>`, R3): point ONLY the configured zone
//! suffix at the embedded DNS responder (plan §3.3), never the whole system — so every other
//! hostname on the box keeps resolving exactly as it did before this front-end ran. The per-OS
//! mechanism is chosen in [`apply_override`] (the one `#[cfg(target_os)]` branch in this module);
//! everything else is portable. Windows (NRPT) is a later increment (plan §8, R4).
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
use std::path::{Path, PathBuf};
use std::process::Command;

/// Which mechanism [`ResolverGuard::apply`] used — persisted in the plan §3.9 marker so a FRESH
/// process (after a crash) knows how to revert without ever having held the original guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Method {
    /// `resolvectl` (systemd-resolved) per-link DNS + routing-domain override — the preferred path:
    /// genuinely scoped to the zone suffix, nothing else on the host is touched.
    Resolvectl,
    /// A managed, marker-delimited stanza appended to `/etc/resolv.conf` — the fallback when
    /// systemd-resolved is unavailable. **Caveats, documented rather than hidden:**
    /// - Classic `/etc/resolv.conf` has no per-domain scoping, so this fallback adds `127.0.0.1` as
    ///   a nameserver for the WHOLE host, not just the zone — acceptable only because the embedded
    ///   responder itself still REFUSES (never answers, never recurses) anything outside the zone
    ///   (plan §3.3/§5), so no query is ever wrongly answered.
    /// - This stanza is APPENDED — i.e. added LAST, not first-tried: glibc's resolver tries
    ///   `nameserver` lines in the ORDER they appear, so an existing nameserver is still consulted
    ///   first for every query (this zone's own names included, until that first nameserver times
    ///   out or refuses — which it will, since it has never heard of them).
    /// - glibc additionally caps resolv.conf at `MAXNS = 3` nameserver lines — if the file already
    ///   has 3 (or more), this appended line is SILENTLY IGNORED by glibc's resolver (though a
    ///   `getaddrinfo` caller linked against a different resolver, e.g. systemd's own, may behave
    ///   differently). Not solvable by this fallback itself (no per-domain scoping to fall back to
    ///   further); `resolvectl` (this enum's other variant) doesn't share either caveat.
    ResolvConfStanza,
    /// macOS (plan §3.6, R3): a per-domain resolver file `/etc/resolver/<zone>` (resolver(5)) with
    /// `nameserver <loopback>` + `port <port>`. macOS's system resolver sends queries for the zone
    /// (and its subdomains) to EXACTLY that address — genuinely scoped split-DNS, like `resolvectl`
    /// and unlike the whole-host `/etc/resolv.conf` fallback. Needs root to write `/etc/resolver/`;
    /// reverted by removing the file we created (a loopback-nameserver ownership check guards against
    /// deleting a file an operator later repurposed). The zone names the file, so the plan §3.9
    /// marker records it ([`super::teardown::Marker::resolver_zone`]) for a fresh-process revert.
    EtcResolver,
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
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux apply path only (see apply_override)
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
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // only `try_resolvectl` (Linux) calls this
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

/// Resolve `/etc/resolv.conf` (or whatever `path` is) to the REAL file a write should land on —
/// following any symlink. This matters because `/etc/resolv.conf` is ubiquitously a symlink in
/// practice (systemd-resolved → `/run/systemd/resolve/stub-resolv.conf`, NetworkManager →
/// `/run/NetworkManager/resolv.conf`, `resolvconf` → `/run/resolvconf/resolv.conf`, …): Security
/// review LOW — writing straight through `path` with a non-atomic `std::fs::write` would (a) risk
/// a reader observing a partially-written file (no atomicity), and worse, (b) if ever done via a
/// rename-based replace WITHOUT resolving first, would replace the SYMLINK ITSELF with a plain
/// file, breaking whatever system owns it. Falls back to `path` unchanged if it doesn't exist (or
/// is a broken symlink) — the same permissive "no resolv.conf yet" posture this module has always
/// taken for a first-ever write.
fn resolve_target(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Replace `target`'s contents atomically: write a sibling temp file in the SAME directory (so the
/// rename below is a same-filesystem, atomic rename — no partial-write window, and no TOCTOU
/// between resolving a symlink via [`resolve_target`] and writing through it), then rename it over
/// `target`. `target` should already be the RESOLVED path (the symlink's target, not the symlink
/// itself) — renaming onto the symlink path directly would replace the symlink with a plain file.
fn write_atomically(target: &Path, contents: &str) -> io::Result<()> {
    let dir = target.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} has no parent directory", target.display()),
        )
    })?;
    let tmp_path = dir.join(format!(
        ".resolv.conf.boatramp-tunnel.{}.tmp",
        std::process::id()
    ));
    std::fs::write(&tmp_path, contents)?;
    std::fs::rename(&tmp_path, target)
}

/// Pure: the new file content with the stanza present, pointing at `dns_addr` — idempotent by
/// construction (always rebuilt from [`strip_stanza_from`]'s output, so appending onto an already-
/// stanza'd file never nests/duplicates). No I/O — directly unit-tested below.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux apply path + its unit tests only
fn add_stanza_to(contents: &str, dns_addr: SocketAddr) -> String {
    let mut new_contents = strip_stanza_from(contents);
    if !new_contents.is_empty() && !new_contents.ends_with('\n') {
        new_contents.push('\n');
    }
    new_contents.push_str(STANZA_BEGIN);
    new_contents.push('\n');
    new_contents.push_str(&format!("nameserver {}\n", dns_addr.ip()));
    new_contents.push_str(STANZA_END);
    new_contents.push('\n');
    new_contents
}

/// Pure: `contents` with any previously-appended stanza (identified by its begin/end markers)
/// stripped back out — a no-op (returns `contents` unchanged) if no stanza is present. No I/O —
/// directly unit-tested below.
fn strip_stanza_from(contents: &str) -> String {
    if !contents.contains(STANZA_BEGIN) {
        return contents.to_string();
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
    out
}

/// Fallback (plan §3.6): append a marker-delimited stanza pointing the WHOLE host at the embedded
/// responder (see [`Method::ResolvConfStanza`]'s doc for the caveats). Idempotent via
/// [`add_stanza_to`]. Writes through [`resolve_target`]/[`write_atomically`] so a symlinked
/// `/etc/resolv.conf` (the common case) is followed, not replaced.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))] // Linux apply path only (see apply_override)
fn append_resolv_conf_stanza(dns_addr: SocketAddr) -> io::Result<()> {
    let path = resolv_conf_path();
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let new_contents = add_stanza_to(&existing, dns_addr);
    write_atomically(&resolve_target(&path), &new_contents)
}

/// Strip a previously-appended stanza back out of `/etc/resolv.conf` (via [`strip_stanza_from`]).
/// A no-op (not an error) if no stanza is present — this is called unconditionally on EVERY revert
/// path, including a fresh-process [`cleanup_stale`] where the stanza may or may not actually be
/// there. Writes through [`resolve_target`]/[`write_atomically`], same as the append path.
fn remove_resolv_conf_stanza() -> io::Result<()> {
    let path = resolv_conf_path();
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return Ok(()); // no resolv.conf at all — nothing to strip
    };
    if !contents.contains(STANZA_BEGIN) {
        return Ok(());
    }
    let stripped = strip_stanza_from(&contents);
    write_atomically(&resolve_target(&path), &stripped)
}

// --- macOS `/etc/resolver/<zone>` split-DNS (plan §3.6, R3) ---------------------------------------
//
// These functions use only `std::fs`, so they COMPILE on every platform; they are reached at
// runtime ONLY via [`ResolverGuard::apply`]'s `#[cfg(target_os = "macos")]` dispatch (and the
// matching [`revert_by_method`] arm), so a Linux box never creates or removes an `/etc/resolver`
// file even though the code is present.

/// `/etc/resolver/<zone>`, where `<zone>` is the suffix with its trailing dot stripped (resolver(5)
/// matches a bare domain). e.g. `svc.prod.internal.` → `/etc/resolver/svc.prod.internal`.
fn etc_resolver_path(zone_suffix: &str) -> PathBuf {
    PathBuf::from("/etc/resolver").join(zone_suffix.trim_end_matches('.'))
}

/// Pure: the resolver(5) file body pointing the zone at `dns_addr` — unit-tested below. Only
/// `nameserver` + `port` (no `#` comments: resolver(5)'s parser does not define them, so we keep the
/// file strictly to the documented directives and track ownership by path + loopback check instead).
/// `#[cfg(macos)]`: only the macOS apply path produces this (and its macOS unit test); the revert
/// path never needs it, so it would be dead code — and a dead-code `-D warnings` failure — elsewhere.
#[cfg(target_os = "macos")]
fn etc_resolver_contents(dns_addr: SocketAddr) -> String {
    format!("nameserver {}\nport {}\n", dns_addr.ip(), dns_addr.port())
}

/// Write `/etc/resolver/<zone>` (creating `/etc/resolver/` if absent), via the same atomic
/// resolve-symlink-then-rename path the resolv.conf writer uses, so a partially-written file is
/// never observed by the system resolver. `#[cfg(macos)]` for the same reason as
/// [`etc_resolver_contents`] — only the macOS apply path calls it.
#[cfg(target_os = "macos")]
fn write_etc_resolver(zone_suffix: &str, dns_addr: SocketAddr) -> io::Result<()> {
    let path = etc_resolver_path(zone_suffix);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    write_atomically(&resolve_target(&path), &etc_resolver_contents(dns_addr))
}

/// Remove `/etc/resolver/<zone>` — but only a file that still points at a LOOPBACK nameserver (i.e.
/// one we plausibly created, pointing at the embedded responder). If it exists but was repurposed to
/// a non-loopback nameserver, leave it and warn rather than delete an operator's own split-DNS file.
/// Absent ⇒ a harmless no-op (the revert path is called unconditionally, including from a fresh
/// process where the file may or may not be there).
fn remove_etc_resolver(zone_suffix: &str) -> io::Result<()> {
    let path = etc_resolver_path(zone_suffix);
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if !file_points_at_loopback(&contents) {
        tracing::warn!(
            path = %path.display(),
            "boatramp tunnel: {} does not point at a loopback nameserver — leaving it in place \
             rather than deleting a resolver file this run did not own; remove it by hand if the \
             tunnel's split-DNS is no longer wanted",
            path.display()
        );
        return Ok(());
    }
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Does this resolver(5) body name a loopback (`127.0.0.0/8` or `::1`) nameserver? The ownership
/// check [`remove_etc_resolver`] uses before deleting.
fn file_points_at_loopback(contents: &str) -> bool {
    contents.lines().any(|line| {
        let line = line.trim();
        line.strip_prefix("nameserver")
            .map(str::trim)
            .and_then(|addr| addr.parse::<std::net::IpAddr>().ok())
            .is_some_and(|ip| ip.is_loopback())
    })
}

/// A failure applying the host resolver override.
#[derive(Debug, thiserror::Error)]
pub enum ResolverError {
    #[error("neither `resolvectl` nor a managed /etc/resolv.conf stanza could be applied: {0}")]
    Io(#[from] io::Error),
    #[error(
        "the TUN front-end's host-DNS split-horizon integration (plan §3.6) has no implementation \
         for this operating system yet — Linux (resolvectl / /etc/resolv.conf) and macOS \
         (/etc/resolver) are supported; Windows (NRPT) is a later increment (plan §8, R4)"
    )]
    Unsupported,
}

/// An applied host-resolver override (plan §3.6), reverted on [`ResolverGuard::revert`] or
/// (best-effort, synchronous — module doc) on [`Drop`].
pub struct ResolverGuard {
    method: Method,
    tun_name: String,
    zone_suffix: String,
    reverted: bool,
}

impl ResolverGuard {
    /// Apply the override via the per-OS mechanism ([`apply_override`]): Linux `resolvectl` (falling
    /// back to the `/etc/resolv.conf` stanza), macOS `/etc/resolver/<zone>`.
    pub fn apply(
        tun_name: &str,
        dns_addr: SocketAddr,
        zone_suffix: &str,
    ) -> Result<Self, ResolverError> {
        let method = apply_override(tun_name, dns_addr, zone_suffix)?;
        Ok(Self {
            method,
            tun_name: tun_name.to_string(),
            zone_suffix: zone_suffix.to_string(),
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
        revert_by_method(self.method, &self.tun_name, &self.zone_suffix);
        self.reverted = true;
    }
}

/// The per-OS "point the zone at the embedded responder" mechanism (plan §3.6). The `#[cfg]` here is
/// the ONLY place this module branches on the target OS: Linux prefers `resolvectl` and falls back
/// to the `/etc/resolv.conf` stanza; macOS writes `/etc/resolver/<zone>`; any other target has no
/// implementation yet (Windows NRPT is plan §8 R4).
#[cfg(target_os = "linux")]
fn apply_override(
    tun_name: &str,
    dns_addr: SocketAddr,
    zone_suffix: &str,
) -> Result<Method, ResolverError> {
    Ok(if try_resolvectl(tun_name, dns_addr, zone_suffix)? {
        Method::Resolvectl
    } else {
        append_resolv_conf_stanza(dns_addr)?;
        Method::ResolvConfStanza
    })
}

#[cfg(target_os = "macos")]
fn apply_override(
    _tun_name: &str,
    dns_addr: SocketAddr,
    zone_suffix: &str,
) -> Result<Method, ResolverError> {
    write_etc_resolver(zone_suffix, dns_addr)?;
    Ok(Method::EtcResolver)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn apply_override(
    _tun_name: &str,
    _dns_addr: SocketAddr,
    _zone_suffix: &str,
) -> Result<Method, ResolverError> {
    Err(ResolverError::Unsupported)
}

impl Drop for ResolverGuard {
    fn drop(&mut self) {
        self.revert();
    }
}

/// Revert by method + interface name alone — what [`super::teardown::cleanup_stale`] calls from a
/// FRESH process reverting a crashed run's marker, with no live [`ResolverGuard`] to call.
pub fn revert_by_method(method: Method, tun_name: &str, zone_suffix: &str) {
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
        Method::EtcResolver => {
            if let Err(err) = remove_etc_resolver(zone_suffix) {
                tracing::warn!(
                    error = %err, %zone_suffix,
                    "boatramp tunnel: failed to remove /etc/resolver/<zone> — check \
                     /etc/resolver by hand"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("br-tunnel-resolv-{tag}-{}", std::process::id()))
    }

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("br-tunnel-resolv-dir-{tag}-{}", std::process::id()))
    }

    // --- `add_stanza_to`/`strip_stanza_from`: pure, no I/O (Security review LOW fix — these now
    // ARE the real production functions, not a duplicated stand-in; see their own doc comments). ---

    #[test]
    fn appending_then_removing_the_stanza_restores_the_original_content() {
        let original = "nameserver 8.8.8.8\nsearch example.com\n";
        let with_stanza = add_stanza_to(original, "127.0.0.1:5353".parse().unwrap());
        assert!(with_stanza.contains(STANZA_BEGIN));
        assert!(with_stanza.contains("nameserver 127.0.0.1"));
        assert!(
            with_stanza.contains("nameserver 8.8.8.8"),
            "original content must be kept"
        );

        let restored = strip_stanza_from(&with_stanza);
        assert_eq!(restored, original);
    }

    #[test]
    fn appending_twice_does_not_nest_or_duplicate() {
        let dns_addr: SocketAddr = "127.0.0.1:5353".parse().unwrap();
        let once = add_stanza_to("nameserver 8.8.8.8\n", dns_addr);
        let twice = add_stanza_to(&once, dns_addr);
        assert_eq!(twice.matches(STANZA_BEGIN).count(), 1);
        assert_eq!(twice.matches(STANZA_END).count(), 1);
        // Idempotent in the stronger sense too: appending twice produces the SAME content as
        // appending once (not just "no duplicate marker").
        assert_eq!(once, twice);
    }

    #[test]
    fn removing_when_no_stanza_is_present_is_a_harmless_no_op() {
        let input = "nameserver 8.8.8.8\n";
        assert_eq!(strip_stanza_from(input), input);
    }

    // --- `resolve_target`/`write_atomically`: real filesystem I/O against temp paths (never the
    // real `/etc/resolv.conf`), proving the Security review LOW fix (symlink-followed, atomic). ---

    #[test]
    fn resolve_target_falls_back_to_the_plain_path_when_nothing_exists_yet() {
        let path = temp_path("resolve-missing");
        let _ = std::fs::remove_file(&path);
        assert_eq!(resolve_target(&path), path);
    }

    #[test]
    fn write_atomically_writes_a_plain_non_symlink_path_in_place() {
        let path = temp_path("write-plain");
        let _ = std::fs::remove_file(&path);
        write_atomically(&path, "hello\n").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello\n");
        // No leftover temp file next to it.
        let dir = path.parent().unwrap();
        let stray = std::fs::read_dir(dir)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| {
                e.file_name().to_string_lossy().contains("boatramp-tunnel") && e.path() != path
            });
        assert!(!stray, "no stray temp file should be left behind");
        let _ = std::fs::remove_file(&path);
    }

    /// Security review LOW, directly: a symlinked `/etc/resolv.conf` (the common case — systemd-
    /// resolved/NetworkManager/resolvconf all manage it that way) must have the REAL target file
    /// updated, with the symlink itself left completely alone (never replaced by a plain file).
    #[test]
    fn write_through_a_symlink_updates_the_target_and_preserves_the_symlink() {
        let dir = temp_dir("symlink");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let real_file = dir.join("real-resolv.conf");
        std::fs::write(&real_file, "placeholder\n").unwrap();
        let link_path = dir.join("resolv.conf"); // stands in for `/etc/resolv.conf`
        std::os::unix::fs::symlink(&real_file, &link_path).unwrap();

        let target = resolve_target(&link_path);
        assert_eq!(target, real_file.canonicalize().unwrap());

        let new_contents = add_stanza_to(
            &std::fs::read_to_string(&link_path).unwrap(),
            "127.0.0.1:5353".parse().unwrap(),
        );
        write_atomically(&target, &new_contents).unwrap();

        assert!(
            std::fs::symlink_metadata(&link_path)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink itself must survive — never replaced by a plain file"
        );
        let real_contents = std::fs::read_to_string(&real_file).unwrap();
        assert!(real_contents.contains(STANZA_BEGIN));
        assert!(real_contents.contains("placeholder"));

        let _ = std::fs::remove_dir_all(&dir);
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

    /// macOS (R3): the `/etc/resolver/<zone>` body is exactly the two resolver(5) directives pointing
    /// the zone at the loopback responder; the file is named by the dot-stripped zone; and the
    /// loopback-ownership guard (which [`remove_etc_resolver`] uses before deleting) accepts a
    /// loopback nameserver but refuses a non-loopback one.
    #[cfg(target_os = "macos")]
    #[test]
    fn etc_resolver_file_is_scoped_nameserver_port_and_loopback_guarded() {
        let body = etc_resolver_contents("127.0.0.1:5353".parse().unwrap());
        assert_eq!(body, "nameserver 127.0.0.1\nport 5353\n");
        assert_eq!(
            etc_resolver_path("svc.prod.internal."),
            std::path::Path::new("/etc/resolver/svc.prod.internal")
        );
        assert!(file_points_at_loopback(&body));
        assert!(!file_points_at_loopback("nameserver 8.8.8.8\nport 53\n"));
    }
}
