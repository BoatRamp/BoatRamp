//! Small, pure helpers for the client-supplied `Host` header: strip a port,
//! decide whether a name is local (verification-exempt), and recognize the
//! wildcard preview host form. Kept together (and unit-tested here) so the host
//! rules live in one place rather than scattered through the router.

/// Strip a trailing `:port` from a `Host` value.
pub(crate) fn strip_port(host: &str) -> &str {
    match host.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        _ => host,
    }
}

/// Is `host` a **local** name exempt from mandatory domain verification? The
/// `Host` header is client-controlled, so this must not trust a spoofable public
/// value:
/// - a **non-global** IP literal (loopback / private / link-local — incl. `[::1]`)
///   is local and has no domain to verify; a **global** IP literal is an attacker
///   artifact in a public `Host` and stays gated;
/// - `localhost` / `*.localhost` / `*.local` are honored **only when implicit
///   routing is enabled** (a loopback bind / dev / single-tenant posture) — a
///   public multi-tenant server must not let a spoofed `Host: x.localhost` skip
///   the gate.
pub(crate) fn is_local_host(host: &str, implicit: bool) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let unbracketed = h.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
        return !boatramp_core::access::is_global_ip(ip);
    }
    implicit && (h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local"))
}

/// Parse the wildcard preview host form `<id>.deploy.<site-host>` into
/// `(id-prefix, site-host)`. The reserved `deploy` label plus the requirement
/// that the id label be hex (a content-hash prefix) keep ordinary subdomains
/// from matching. `None` for any non-preview host. (The label is `deploy`, not
/// `_deploy` like the path form `/_deploy/<id>/`: an underscore is valid in DNS
/// but illegal in a TLS-cert SAN, so the `*.deploy.<host>` wildcard cert needs
/// an underscore-free label.)
pub(crate) fn parse_deploy_host(host: &str) -> Option<(&str, &str)> {
    let (id, after) = host.split_once('.')?;
    let site_host = after.strip_prefix("deploy.")?;
    if id.is_empty() || site_host.is_empty() || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((id, site_host))
}

#[cfg(test)]
mod tests {
    use super::{is_local_host, parse_deploy_host};

    #[test]
    fn local_hosts_are_exempt_from_verification() {
        // Non-global IP literals are local regardless of posture (can't verify an
        // IP; a private/loopback IP is local access).
        for h in ["127.0.0.1", "::1", "[::1]", "192.168.1.10", "169.254.0.1"] {
            assert!(
                is_local_host(h, false),
                "{h} should be local (non-global IP)"
            );
            assert!(
                is_local_host(h, true),
                "{h} should be local (non-global IP)"
            );
        }

        // On a PUBLIC bind (implicit routing off), a spoofable client `Host` must
        // NOT skip the gate: a global IP literal or a `.localhost`/`.local` name is
        // an attacker artifact, not local access.
        for h in [
            "8.8.8.8",        // global IP literal
            "[2606:4700::1]", // global IPv6 literal
            "localhost",      // spoofed
            "blog.localhost", // spoofed suffix
            "printer.local",  // spoofed mDNS
            "example.com",
            "localhost.evil.com", // classic suffix-confusion attempt
        ] {
            assert!(
                !is_local_host(h, false),
                "{h} must be gated on a public bind"
            );
        }

        // On a loopback / dev bind (implicit routing on), the local names ARE
        // honored (and remain case-insensitive).
        for h in ["localhost", "LocalHost", "blog.localhost", "printer.local"] {
            assert!(
                is_local_host(h, true),
                "{h} should be local under implicit routing"
            );
        }
        // …but a real public DNS name is never local, even in dev.
        assert!(!is_local_host("boatramp.dev", true));
    }

    #[test]
    fn parses_preview_host_form() {
        assert_eq!(
            parse_deploy_host("abc123.deploy.example.com"),
            Some(("abc123", "example.com"))
        );
        // Deeper site host is preserved verbatim.
        assert_eq!(
            parse_deploy_host("deadbeef.deploy.staging.example.com"),
            Some(("deadbeef", "staging.example.com"))
        );
    }

    #[test]
    fn rejects_non_preview_hosts() {
        // No `deploy` label.
        assert_eq!(parse_deploy_host("www.example.com"), None);
        // Non-hex id label (a real subdomain).
        assert_eq!(parse_deploy_host("blog.deploy.example.com"), None);
        // Bare host / missing parts.
        assert_eq!(parse_deploy_host("example.com"), None);
        assert_eq!(parse_deploy_host("abc.deploy."), None);
        // The path-form label (`_deploy`, with the underscore) is NOT the host
        // form and must not match.
        assert_eq!(parse_deploy_host("abc._deploy.example.com"), None);
    }
}
