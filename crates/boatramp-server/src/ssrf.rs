//! The shared, always-compiled SSRF guard: the single source of truth for fetching an
//! operator-/tenant-influenceable URL from inside the node without being tricked into reaching
//! internal services, cloud metadata (169.254.169.254), or another tenant.
//!
//! Two primitives, used by BOTH the OIDC/JWKS multi-issuer fetch (`graphql_data::token`, behind the
//! `handlers` feature) and the project-clone pull (`admin_api::clone_from`, always compiled):
//!
//! - [`resolve_pin`] — the DECISION (no fetch): parse the URL, require `https`, reject userinfo,
//!   DNS-resolve, require every resolved address globally routable ([`is_global_ip`]), and return one
//!   address to PIN (so a DNS rebind can't swap in a private target between the resolve and the
//!   connect). Split out from the fetch so it is deterministically testable (an IP-literal URL needs
//!   no network).
//! - [`pinned_client`] — build a reqwest client PINNED to that address, `https_only`, redirects
//!   refused (a 3xx off the pinned host would re-resolve an un-guarded host and escape — the caller
//!   treats any 3xx as failure), with connect + idle-`read` timeouts.
//!
//! `is_global_ip` rejects loopback / private (RFC1918) / link-local / IPv6 ULA / documentation and
//! other non-global ranges, so the whole internal network + the cloud-metadata endpoint are refused.

use std::net::SocketAddr;
use std::time::Duration;

/// The SSRF guard DECISION (no fetch). Returns `(host, pinned_addr)` to connect to, or `None` when
/// the URL is refused. `allow_non_global` (a test/mutation seam — the caller passes `false` in
/// production) drops the globally-routable requirement; `allow_loopback_http` (a live-gate fixture —
/// `false` in production) additionally permits an `http` loopback mock. A userinfo-bearing URL, a
/// non-`https` scheme, or any address failing [`is_global_ip`](boatramp_core::access::is_global_ip)
/// is refused fail-closed.
pub(crate) async fn resolve_pin(
    url: &str,
    allow_non_global: bool,
    allow_loopback_http: bool,
) -> Option<(String, SocketAddr)> {
    let parsed = reqwest::Url::parse(url).ok()?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_loopback_http => {} // the live-gate loopback mock (test fixture only)
        _ => return None,
    }
    // A bearer must never ride in the URL, and userinfo is an SSRF-credential-smuggling vector.
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let mut pinned: Option<SocketAddr> = None;
    for addr in tokio::net::lookup_host((host.as_str(), port)).await.ok()? {
        // Reject a URL that resolves to ANY non-global address (loopback / private / link-local /
        // ULA / cloud-metadata). `allow_non_global` / `allow_loopback_http` relax this ONLY in
        // test/live-gate fixtures (both `false` in a shipped build).
        if !allow_non_global
            && !allow_loopback_http
            && !boatramp_core::access::is_global_ip(addr.ip())
        {
            return None;
        }
        pinned.get_or_insert(addr);
    }
    pinned.map(|addr| (host, addr))
}

/// Build an SSRF-hardened reqwest client PINNED to `(host, addr)` from [`resolve_pin`]: the resolved
/// address is pinned on the client (so a DNS REBIND cannot swap in a private target between resolve
/// and connect), redirects are NOT followed (a 3xx off the pinned host would escape — the caller
/// treats any 3xx as failure), and a connect + idle-`read` timeout bound a stalled/slow peer. The
/// caller adds a per-request total `.timeout()` for a small bounded body; a large STREAMED body
/// relies on the idle `read_timeout` instead of a total cap so a legitimate long transfer is not
/// killed. `https_only` is enforced except where a live-gate fixture reaches a loopback mock.
pub(crate) fn pinned_client(
    host: &str,
    addr: SocketAddr,
    https_only: bool,
) -> Option<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .resolve(host, addr)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(60));
    if https_only {
        builder = builder.https_only(true);
    }
    builder.build().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The guard REFUSES every non-global target class an attacker-influenceable URL could name —
    /// loopback, private, link-local (incl. the cloud-metadata endpoint 169.254.169.254), IPv6
    /// loopback / link-local / ULA — plus a non-https scheme (a forwarded bearer must not ride
    /// cleartext) and a userinfo-bearing URL. Only a public https IP-literal pins. This is the exact
    /// production call the project-clone pull makes (`resolve_pin(url, false, false)`). IP literals
    /// resolve locally, so no network is needed.
    #[tokio::test]
    async fn resolve_pin_refuses_every_non_global_target() {
        for refused in [
            "https://127.0.0.1/x",                       // IPv4 loopback
            "https://10.0.0.1/x",                        // RFC1918 private
            "https://192.168.1.1/x",                     // RFC1918 private
            "https://169.254.169.254/latest/meta-data/", // link-local = cloud metadata
            "https://[::1]/x",                           // IPv6 loopback
            "https://[fe80::1]/x",                       // IPv6 link-local
            "https://[fc00::1]/x",                       // IPv6 ULA
            "http://1.1.1.1/x",                          // non-https (cleartext bearer)
            "https://user:pass@1.1.1.1/x",               // userinfo
            "ftp://1.1.1.1/x",                           // non-http(s) scheme
            "not a url",                                 // unparseable
        ] {
            assert!(
                resolve_pin(refused, false, false).await.is_none(),
                "SSRF guard must refuse {refused:?}"
            );
        }
        // Only a public https target pins (and carries its resolved address forward).
        let pinned = resolve_pin("https://1.1.1.1/x", false, false).await;
        assert!(pinned.is_some(), "a public https target resolves + pins");
        assert_eq!(pinned.unwrap().0, "1.1.1.1");
    }

    /// The test/live-gate relaxations are opt-in: `allow_loopback_http` lets the loopback mock
    /// through (so the end-to-end live gate can run), and `allow_non_global` (the mutation seam)
    /// lets a private address pin — both `false` in production (asserted above).
    #[tokio::test]
    async fn resolve_pin_relaxations_are_opt_in() {
        assert!(
            resolve_pin("http://127.0.0.1:8080/x", false, true)
                .await
                .is_some(),
            "allow_loopback_http permits the http loopback mock"
        );
        assert!(
            resolve_pin("https://10.0.0.1/x", true, false)
                .await
                .is_some(),
            "allow_non_global (mutation) permits a private target"
        );
    }
}
