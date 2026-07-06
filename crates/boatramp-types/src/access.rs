//! Visitor access control: HTTP Basic auth, IP allow/deny (CIDR), and rate
//! limiting. These are **site-scoped** policies — they live in [`SiteConfig`]
//! (the mutable KV tier) and are evaluated by the server before serving any
//! content.
//!
//! This module holds the configuration types and the *pure* decision logic
//! (CIDR matching, credential verification, client-IP resolution). The stateful
//! rate-limit token buckets live in the server, since they need a clock and
//! shared mutable state; this module only defines the [`RateLimit`] budget.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use argon2::password_hash::{PasswordHash, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Site-scoped visitor access control. All fields are optional/empty by
/// default, so an unset policy allows everyone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccessConfig {
    /// HTTP Basic auth — when set, visitors must present valid credentials.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub basic_auth: Option<BasicAuth>,
    /// IP allow/deny rules (CIDR).
    pub ip: IpRules,
    /// Per-client rate limiting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    /// CIDRs of trusted reverse proxies. Only when the direct peer matches one
    /// of these is an `X-Forwarded-For` header believed (see
    /// [`resolve_client_ip`]); otherwise the socket peer is the client.
    pub trusted_proxies: Vec<String>,
    /// Configurable WAF (user-agent rules + anomaly scoring). Off by
    /// default.
    #[serde(default, skip_serializing_if = "waf_disabled")]
    pub waf: crate::waf::WafConfig,
}

fn waf_disabled(waf: &crate::waf::WafConfig) -> bool {
    !waf.is_enabled()
}

impl AccessConfig {
    /// Whether any access-control policy is configured (a fast pre-check so the
    /// hot serving path can skip work when nothing is set).
    pub fn is_enforced(&self) -> bool {
        self.basic_auth.is_some()
            || self.rate_limit.is_some()
            || !self.ip.allow.is_empty()
            || !self.ip.deny.is_empty()
            || self.waf.is_enabled()
    }

    /// Whether `ip` is one of the configured `trusted_proxies` — i.e. forwarded
    /// headers (`X-Forwarded-For`, `X-Forwarded-Proto`) from this peer may be
    /// honored. A direct (untrusted) client's forwarded headers must be ignored.
    pub fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        ip_in_any(ip, &self.trusted_proxies)
    }
}

/// HTTP Basic auth credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicAuth {
    /// Realm shown in the browser credential prompt.
    #[serde(default = "default_realm")]
    pub realm: String,
    /// `username → argon2id password hash` (a PHC string).
    #[serde(default)]
    pub users: BTreeMap<String, String>,
}

fn default_realm() -> String {
    "Restricted".to_string()
}

impl BasicAuth {
    /// Verify a `username`/`password` pair against the configured argon2 hashes.
    ///
    /// On an unknown user it still performs one argon2 verification against a
    /// throwaway hash, so the response time does not reveal whether the user
    /// exists.
    pub fn verify(&self, username: &str, password: &str) -> bool {
        match self.users.get(username) {
            Some(hash) => verify_password(password, hash),
            None => {
                let _ = verify_password(password, dummy_hash());
                false
            }
        }
    }
}

/// Hash a plaintext password for storage as an argon2id PHC string (used when an
/// operator sets a visitor Basic-auth password). Salted per call.
pub fn hash_password(password: &str) -> String {
    // Salt via the system RNG (reusing core's `getrandom`, like token gen) — no
    // extra `rand_core`/`OsRng` feature, which keeps the dep wasm-friendly.
    let mut salt_bytes = [0u8; 16];
    getrandom::getrandom(&mut salt_bytes).expect("system RNG");
    let salt = SaltString::encode_b64(&salt_bytes).expect("salt encode");
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .expect("argon2 hashing")
        .to_string()
}

/// Verify `password` against a stored argon2 PHC `hash`. A hash that doesn't
/// parse (or doesn't match) is a non-match — never an error.
fn verify_password(password: &str, hash: &str) -> bool {
    PasswordHash::new(hash)
        .map(|parsed| {
            Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

/// A valid argon2 hash, computed once, used to equalize timing for unknown
/// users. Its plaintext is irrelevant — it is never expected to match.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password("dummy"))
}

/// IP allow/deny rules. Entries are CIDR blocks (`10.0.0.0/8`, `2001:db8::/32`)
/// or bare addresses (treated as `/32`/`/128`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IpRules {
    /// If non-empty, only clients matching one of these are allowed.
    pub allow: Vec<String>,
    /// Clients matching any of these are always denied (deny wins over allow).
    pub deny: Vec<String>,
}

impl IpRules {
    /// Whether `ip` is allowed: denied if it matches any `deny` entry; otherwise
    /// allowed if `allow` is empty or `ip` matches an `allow` entry. Unparsable
    /// entries are ignored.
    pub fn allows(&self, ip: IpAddr) -> bool {
        if ip_in_any(ip, &self.deny) {
            return false;
        }
        if self.allow.is_empty() {
            return true;
        }
        ip_in_any(ip, &self.allow)
    }
}

/// Token-bucket rate-limit budget (the per-client *policy*; the buckets
/// themselves are kept by the server's stateful limiter).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimit {
    /// Sustained requests per second per client.
    pub rps: u32,
    /// Burst capacity (bucket size); defaults to `rps` when omitted.
    #[serde(default)]
    pub burst: u32,
}

impl RateLimit {
    /// Effective burst capacity (at least 1, defaulting to `rps`).
    pub fn burst_capacity(&self) -> u32 {
        if self.burst == 0 {
            self.rps.max(1)
        } else {
            self.burst
        }
    }
}

/// Parse a CIDR or bare-IP string into an [`IpNet`].
fn parse_net(spec: &str) -> Option<IpNet> {
    let spec = spec.trim();
    if let Ok(net) = spec.parse::<IpNet>() {
        return Some(net);
    }
    if let Ok(ip) = spec.parse::<IpAddr>() {
        let prefix = if ip.is_ipv4() { 32 } else { 128 };
        return IpNet::new(ip, prefix).ok();
    }
    None
}

/// Whether `ip` falls within any of the CIDR/bare-IP specs.
fn ip_in_any(ip: IpAddr, specs: &[String]) -> bool {
    specs
        .iter()
        .filter_map(|spec| parse_net(spec))
        .any(|net| net.contains(&ip))
}

/// Resolve the real client IP given the socket `peer`, an optional
/// `X-Forwarded-For` value, and the configured trusted-proxy CIDRs.
///
/// `X-Forwarded-For` is honored **only** when `peer` itself is a trusted proxy;
/// then the chain is walked right-to-left and the first address that is not a
/// trusted proxy is returned as the client. This prevents a client from
/// spoofing its address by sending a forged header.
pub fn resolve_client_ip(
    peer: IpAddr,
    forwarded_for: Option<&str>,
    trusted_proxies: &[String],
) -> IpAddr {
    if trusted_proxies.is_empty() || !ip_in_any(peer, trusted_proxies) {
        return peer;
    }
    if let Some(chain) = forwarded_for {
        for hop in chain.split(',').rev() {
            if let Ok(ip) = hop.trim().parse::<IpAddr>() {
                if !ip_in_any(ip, trusted_proxies) {
                    return ip;
                }
            }
        }
    }
    peer
}

/// Whether `ip` is a globally-routable (public) address — i.e. **not** a
/// private, loopback, link-local, unique-local, shared (CGNAT), unspecified, or
/// otherwise internal address. Used as an SSRF guard on proxy targets so a
/// rewrite can never reach internal services (e.g. cloud metadata at
/// `169.254.169.254`, `127.0.0.1`, `10.0.0.0/8`).
pub fn is_global_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => ipv4_is_global(v4),
        IpAddr::V6(v6) => ipv6_is_global(v6),
    }
}

fn ipv4_is_global(a: Ipv4Addr) -> bool {
    let [o0, o1, ..] = a.octets();
    !(a.is_private()
        || a.is_loopback()
        || a.is_link_local() // 169.254/16 (cloud metadata)
        || a.is_unspecified()
        || a.is_broadcast()
        || a.is_documentation()
        || o0 == 0
        || (o0 == 100 && (64..128).contains(&o1)) // 100.64/10 CGNAT
        || o0 >= 240) // 240/4 reserved
}

fn ipv6_is_global(a: Ipv6Addr) -> bool {
    if a.is_loopback() || a.is_unspecified() || a.is_multicast() {
        return false;
    }
    if let Some(v4) = a.to_ipv4_mapped() {
        return ipv4_is_global(v4);
    }
    let first = a.segments()[0];
    if (first & 0xfe00) == 0xfc00 {
        return false; // fc00::/7 unique local
    }
    if (first & 0xffc0) == 0xfe80 {
        return false; // fe80::/10 link-local
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_ip_blocks_internal_ranges() {
        let public = ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"];
        let internal = [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.5.5",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1", // v4-mapped loopback
        ];
        for ip in public {
            assert!(is_global_ip(ip.parse().unwrap()), "{ip} should be global");
        }
        for ip in internal {
            assert!(
                !is_global_ip(ip.parse().unwrap()),
                "{ip} should be internal"
            );
        }
    }

    #[test]
    fn ip_rules_deny_wins_and_allow_list_gates() {
        let rules = IpRules {
            allow: vec!["10.0.0.0/8".into()],
            deny: vec!["10.1.2.3".into()],
        };
        assert!(rules.allows("10.5.5.5".parse().unwrap())); // in allow
        assert!(!rules.allows("10.1.2.3".parse().unwrap())); // denied explicitly
        assert!(!rules.allows("192.168.0.1".parse().unwrap())); // not in allow-list
    }

    #[test]
    fn ip_rules_default_allows_all() {
        assert!(IpRules::default().allows("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn ipv6_cidr_matches() {
        let rules = IpRules {
            allow: vec!["2001:db8::/32".into()],
            deny: vec![],
        };
        assert!(rules.allows("2001:db8::1".parse().unwrap()));
        assert!(!rules.allows("2001:dead::1".parse().unwrap()));
    }

    #[test]
    fn xff_only_trusted_from_a_trusted_peer() {
        let trusted = vec!["10.0.0.0/8".into()];
        // Peer is a trusted proxy → believe the rightmost non-proxy hop.
        assert_eq!(
            resolve_client_ip(
                "10.0.0.5".parse().unwrap(),
                Some("203.0.113.7, 10.0.0.9"),
                &trusted,
            ),
            "203.0.113.7".parse::<IpAddr>().unwrap()
        );
        // Peer is NOT trusted → header is ignored, peer wins (anti-spoof).
        assert_eq!(
            resolve_client_ip(
                "198.51.100.2".parse().unwrap(),
                Some("203.0.113.7"),
                &trusted,
            ),
            "198.51.100.2".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn basic_auth_verifies_argon2() {
        let hash = hash_password("hunter2");
        assert!(
            hash.starts_with("$argon2"),
            "stored as an argon2 PHC string"
        );
        let auth = BasicAuth {
            realm: "x".into(),
            users: BTreeMap::from([("alice".to_string(), hash)]),
        };
        assert!(auth.verify("alice", "hunter2"));
        assert!(!auth.verify("alice", "wrong"));
        assert!(!auth.verify("bob", "hunter2")); // unknown user
    }
}
