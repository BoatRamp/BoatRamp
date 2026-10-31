//! The DNS-provider abstraction: a typed record model + an async trait that
//! cloud providers implement, plus the naming and ACME DNS-01 challenge math
//! (pure, network-free, fully tested). A [`ManualDnsProvider`] is always
//! available — it records the changes an operator must apply by hand, so the
//! whole flow works with no cloud credentials.
//!
//! # Record model (capability #24, WS1)
//!
//! [`RecordKind`] is a **typed sum** carrying each type's rdata (an MX's
//! preference, an SRV's four fields, a CAA's triple, …). This is the only shape
//! in which MX/SRV/CAA/HTTPS/SVCB are representable at all, and it is cleaner
//! than the previous flat enum + loose `value: String`.
//!
//! The model is deliberately **not** "write everything everywhere":
//! - **Writable, first-class (Tier 1/2):** the [`RecordKind`] variants below.
//! - **Provider-managed, refused *by construction* (Tier 3):** SOA, the zone
//!   **apex** NS set, and the DNSSEC family (DNSKEY/DS/RRSIG/NSEC/NSEC3) are
//!   **not** variants of the writable sum — no caller can express one, so the
//!   writer can never clobber a zone's authority. They appear only as
//!   [`RecordKindTag`] values, for capability declarations and error messages.
//! - **Per-adapter honest refusal:** each adapter declares the tags it can write
//!   ([`DnsProvider::supported_kinds`]); the central [`validate_writable`]
//!   guardrail refuses an unsupported `(provider, type)` with a clear typed
//!   error — never a silent drop.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use async_trait::async_trait;

/// The `tag` of a CAA record's property. CAA (RFC 8659) controls which CA may
/// issue certificates for a name; because boatramp runs its own ACME, publishing
/// CAA lets an operator lock issuance to the CA boatramp uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaaTag {
    /// `issue` — authorize a CA to issue for the exact name.
    Issue,
    /// `issuewild` — authorize a CA to issue wildcard certs for the name.
    IssueWild,
    /// `iodef` — a URL for the CA to report policy-violation incidents to.
    Iodef,
}

impl CaaTag {
    /// The on-the-wire property token (`issue`, `issuewild`, `iodef`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Issue => "issue",
            Self::IssueWild => "issuewild",
            Self::Iodef => "iodef",
        }
    }
}

impl std::fmt::Display for CaaTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One HTTPS/SVCB **SvcParam** (RFC 9460): a key (`alpn`, `port`, `ipv4hint`,
/// `ech`, or a numeric `keyNNNNN`) and its presentation-form value. Modeled
/// opaquely (key + value strings) in WS1; the per-provider wire encoding of the
/// value set is a WS2 concern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SvcParam {
    /// The parameter key, e.g. `alpn`, `port`, `ipv4hint`, `ech`, `key65280`.
    pub key: String,
    /// The parameter's presentation-form value (opaque in WS1).
    pub value: String,
}

/// The identity of a DNS record type, independent of its rdata. Used for
/// per-adapter capability declarations ([`DnsProvider::supported_kinds`]) and for
/// clear refusal messages. Includes the **Tier-3** provider-managed types (SOA,
/// the DNSSEC family) that are deliberately NOT writable [`RecordKind`] variants,
/// so this enum can name them in an error without any caller being able to build
/// a record of that type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKindTag {
    // Tier 1 — first-class, writable.
    A,
    Aaaa,
    Cname,
    Txt,
    Mx,
    Srv,
    Caa,
    Https,
    Svcb,
    /// Sub-zone delegation only (apex NS is Tier 3 — see [`validate_writable`]).
    Ns,
    // Tier 2 — modeled, capability-gated per provider.
    Ptr,
    Tlsa,
    // Tier 3 — provider-managed, never writable (present for declarations/errors
    // only; there is no corresponding `RecordKind` variant).
    Soa,
    Dnskey,
    Ds,
    Rrsig,
    Nsec,
    Nsec3,
}

impl RecordKindTag {
    /// The DNS type token (`A`, `AAAA`, `MX`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Txt => "TXT",
            Self::Mx => "MX",
            Self::Srv => "SRV",
            Self::Caa => "CAA",
            Self::Https => "HTTPS",
            Self::Svcb => "SVCB",
            Self::Ns => "NS",
            Self::Ptr => "PTR",
            Self::Tlsa => "TLSA",
            Self::Soa => "SOA",
            Self::Dnskey => "DNSKEY",
            Self::Ds => "DS",
            Self::Rrsig => "RRSIG",
            Self::Nsec => "NSEC",
            Self::Nsec3 => "NSEC3",
        }
    }
}

impl std::fmt::Display for RecordKindTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A DNS record type with its typed rdata — the write-side record model.
///
/// Names (CNAME/MX/SRV/NS/PTR targets and HTTPS/SVCB targets) reuse the crate's
/// `String` convention for DNS names; they are fully-qualified, trailing dot
/// optional (each adapter normalizes to its provider's form). Tier-3 types (SOA,
/// apex NS, DNSSEC) are intentionally absent — they are unrepresentable, so the
/// writer refuses them by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordKind {
    /// IPv4 address record.
    A(Ipv4Addr),
    /// IPv6 address record.
    Aaaa(Ipv6Addr),
    /// Canonical-name alias (one target name).
    Cname(String),
    /// Text record as **multiple** character-strings (each ≤255 bytes), so
    /// SPF/DKIM/DMARC and long verification values work. The ACME DNS-01
    /// challenge uses a single-element vec.
    Txt(Vec<String>),
    /// Mail exchange: a preference and the mail host.
    Mx { preference: u16, exchange: String },
    /// Service location (RFC 2782): SIP/XMPP/autodiscover/`_minecraft`/…
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    /// Certification Authority Authorization (RFC 8659).
    Caa {
        flags: u8,
        tag: CaaTag,
        value: String,
    },
    /// HTTPS service binding (RFC 9460).
    Https {
        priority: u16,
        target: String,
        params: Vec<SvcParam>,
    },
    /// Generic service binding (RFC 9460).
    Svcb {
        priority: u16,
        target: String,
        params: Vec<SvcParam>,
    },
    /// **Sub-zone** delegation only. An `Ns` at the zone apex is refused by
    /// [`validate_writable`] (the zone's authority NS set is provider-managed).
    Ns(String),
    /// Reverse-DNS pointer (Tier 2).
    Ptr(String),
    /// DANE TLSA (Tier 2).
    Tlsa {
        usage: u8,
        selector: u8,
        matching: u8,
        data: String,
    },
}

impl RecordKind {
    /// The DNS type token (`A`, `AAAA`, `CNAME`, `TXT`, `MX`, …).
    pub fn as_str(&self) -> &'static str {
        self.tag().as_str()
    }

    /// This record's type identity (its [`RecordKindTag`]).
    pub fn tag(&self) -> RecordKindTag {
        match self {
            Self::A(_) => RecordKindTag::A,
            Self::Aaaa(_) => RecordKindTag::Aaaa,
            Self::Cname(_) => RecordKindTag::Cname,
            Self::Txt(_) => RecordKindTag::Txt,
            Self::Mx { .. } => RecordKindTag::Mx,
            Self::Srv { .. } => RecordKindTag::Srv,
            Self::Caa { .. } => RecordKindTag::Caa,
            Self::Https { .. } => RecordKindTag::Https,
            Self::Svcb { .. } => RecordKindTag::Svcb,
            Self::Ns(_) => RecordKindTag::Ns,
            Self::Ptr(_) => RecordKindTag::Ptr,
            Self::Tlsa { .. } => RecordKindTag::Tlsa,
        }
    }

    /// The single-string rdata the provider adapters consume for the four
    /// originally-writable kinds (A/AAAA/CNAME/TXT), preserved byte-for-byte so
    /// the existing adapters render identically to before the typed-model change.
    /// For A/AAAA it is the address; for CNAME the target name; for TXT the
    /// character-strings concatenated (a single-element vec — the only shape used
    /// today — yields exactly that one string).
    ///
    /// The WS1 record types (MX/SRV/CAA/HTTPS/SVCB/NS/PTR/TLSA) have **no** single
    /// flat value and return an empty string. They are refused by the per-adapter
    /// capability guardrail ([`validate_writable`]) before any adapter formats
    /// them, so this empty value is never sent; their real per-provider rdata
    /// encoding is wired per adapter in WS2.
    pub fn flat_value(&self) -> String {
        match self {
            Self::A(ip) => ip.to_string(),
            Self::Aaaa(ip) => ip.to_string(),
            Self::Cname(name) => name.clone(),
            Self::Txt(strings) => strings.concat(),
            _ => String::new(),
        }
    }

    /// Validate the rdata that can be malformed independently of the provider:
    /// each TXT character-string must be ≤255 bytes and a TXT must have at least
    /// one string; a CAA value must be non-empty. Other variants are valid by
    /// construction (typed fields). Called by [`validate_writable`].
    pub fn validate_rdata(&self) -> Result<(), DnsError> {
        match self {
            Self::Txt(strings) => {
                if strings.is_empty() {
                    return Err(DnsError::InvalidRecord(
                        "TXT record has no character-strings".to_string(),
                    ));
                }
                for s in strings {
                    if s.len() > 255 {
                        return Err(DnsError::InvalidRecord(format!(
                            "TXT character-string is {} bytes; DNS limits each to 255",
                            s.len()
                        )));
                    }
                }
                Ok(())
            }
            Self::Caa { value, .. } => {
                if value.trim().is_empty() {
                    return Err(DnsError::InvalidRecord(
                        "CAA record value must not be empty".to_string(),
                    ));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl std::fmt::Display for RecordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single DNS record to upsert or delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    /// The record type with its typed rdata.
    pub kind: RecordKind,
    /// Fully-qualified record name / owner (no trailing dot), e.g.
    /// `*.deploy.example.com` or `_acme-challenge.example.com`.
    pub name: String,
    /// Time-to-live in seconds.
    pub ttl: u32,
}

/// Why a DNS operation failed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DnsError {
    /// Bad/absent credentials or configuration.
    #[error("dns config error: {0}")]
    Config(String),
    /// The provider's API rejected the request or was unreachable.
    #[error("dns backend error: {0}")]
    Backend(String),
    /// The record to delete does not exist. `delete` treats this as success (a
    /// retried teardown converges), so providers return it structurally instead
    /// of encoding "already gone" in a `Backend` message that the caller then has
    /// to string-match.
    #[error("dns record not found")]
    NotFound,
    /// The target provider cannot write this record type (it is not in the
    /// adapter's [`DnsProvider::supported_kinds`]). Refused up front rather than
    /// silently dropped or best-effort applied.
    #[error("dns provider '{provider}' cannot write {kind} records")]
    UnsupportedRecordType {
        provider: &'static str,
        kind: RecordKindTag,
    },
    /// An `NS` record was targeted at the zone apex. The apex NS set is the
    /// zone's authority and is provider-/registrar-managed; writing it can
    /// clobber the zone, so the writer refuses it. Sub-zone `NS` delegation is
    /// allowed.
    #[error(
        "refusing to write apex NS for zone '{zone}' (name '{name}'): the zone's authority NS set is provider-managed"
    )]
    ApexNsRefused { zone: String, name: String },
    /// The record's rdata is malformed (e.g. a TXT character-string over 255
    /// bytes, or an empty CAA value).
    #[error("invalid dns record: {0}")]
    InvalidRecord(String),
}

/// A DNS zone editor. Implementations are per-provider (Cloudflare, Route 53,
/// Oracle Cloud, …); the manual one just records what an operator must do.
///
/// `upsert` must be **idempotent** (create-or-replace the record), so a retried
/// ACME challenge or a re-run auto-config converges rather than duplicating.
///
/// # Capability + refusal
///
/// An adapter declares the record-kind tags it can write via
/// [`supported_kinds`](Self::supported_kinds). Write entrypoints MUST call
/// [`validate_writable`] before dispatching to `upsert`/`delete`; it refuses an
/// unsupported `(provider, type)`, an apex `NS`, and malformed rdata with a clear
/// typed [`DnsError`], so no adapter is ever asked to best-effort a type it does
/// not model.
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Create or replace `record`.
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError>;
    /// Remove `record` (best-effort; absent is success).
    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError>;

    /// The record-kind tags this adapter can write.
    ///
    /// **WS1:** every adapter inherits this default — the original writable set
    /// `{A, AAAA, CNAME, TXT}` — so all newly-modeled types are refused
    /// everywhere until WS2 widens each provider individually by overriding this
    /// method.
    fn supported_kinds(&self) -> &'static [RecordKindTag] {
        &[
            RecordKindTag::A,
            RecordKindTag::Aaaa,
            RecordKindTag::Cname,
            RecordKindTag::Txt,
        ]
    }

    /// Whether this adapter can write a record of `tag` (derived from
    /// [`supported_kinds`](Self::supported_kinds)).
    fn supports_kind(&self, tag: RecordKindTag) -> bool {
        self.supported_kinds().contains(&tag)
    }

    /// A short, stable provider name for refusal messages and audit
    /// (e.g. `"cloudflare"`). Overridden per adapter.
    fn name(&self) -> &'static str {
        "dns"
    }
}

/// Whether two DNS names refer to the same owner (trailing dot and ASCII case
/// insensitive).
fn names_equal(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// The central write guardrail: refuse a record `provider` must not (or cannot)
/// write, **before** any adapter is dispatched. The native and (future) guest
/// write entrypoints call this first; it never silently drops a record.
///
/// `zone_root` is the apex of the zone the write targets (e.g. `example.com`),
/// needed to recognize an apex `NS`.
///
/// Refuses:
/// - malformed rdata (TXT > 255-byte chunk, empty CAA value) →
///   [`DnsError::InvalidRecord`];
/// - an `NS` at the zone apex (`name == zone_root`) → [`DnsError::ApexNsRefused`]
///   (sub-zone `NS` delegation is allowed);
/// - a kind the target adapter does not list in
///   [`DnsProvider::supported_kinds`] → [`DnsError::UnsupportedRecordType`].
///
/// SOA and the DNSSEC family (DNSKEY/DS/RRSIG/NSEC/NSEC3) need no check here:
/// they are not variants of the writable [`RecordKind`] sum, so a caller cannot
/// construct one — they are refused by construction.
pub fn validate_writable(
    provider: &dyn DnsProvider,
    record: &DnsRecord,
    zone_root: &str,
) -> Result<(), DnsError> {
    record.kind.validate_rdata()?;

    if matches!(record.kind, RecordKind::Ns(_)) && names_equal(&record.name, zone_root) {
        return Err(DnsError::ApexNsRefused {
            zone: zone_root.to_string(),
            name: record.name.clone(),
        });
    }

    let tag = record.kind.tag();
    if !provider.supports_kind(tag) {
        return Err(DnsError::UnsupportedRecordType {
            provider: provider.name(),
            kind: tag,
        });
    }
    Ok(())
}

/// Reads DNS **TXT** records, for the DNS-01 **propagation pre-check**: after a
/// solver writes the `_acme-challenge` TXT via a [`DnsProvider`], the ACME driver
/// polls one of these until the expected value is actually visible BEFORE telling
/// the CA to validate (the CA validates immediately on that signal, so the record
/// must already be live at the zone's nameservers — see
/// [`acme::wait_for_propagation`](crate::acme::wait_for_propagation)).
///
/// Injected (like [`DnsProvider`]) so the issuance driver stays resolver-agnostic
/// and unit-testable with a fake. A hickory-backed default,
/// [`HickoryTxtResolver`](crate::acme::HickoryTxtResolver), ships behind the
/// `acme` feature.
#[async_trait]
pub trait TxtResolver: Send + Sync {
    /// The TXT values currently visible at `name` (each record's ≤255-byte chunks
    /// joined into one string). An **empty** result means "nothing visible yet"
    /// (the caller keeps waiting), which is NOT an error — a name with no TXT
    /// records resolves to an empty vec, not `Err`. A genuine resolver/transport
    /// failure is an `Err` (the caller treats it as "not visible yet" and retries
    /// within the deadline).
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, DnsError>;
}

/// The wildcard host that serves a site's by-id previews: `*.deploy.{host}`.
/// One wildcard cert for this name covers every `<id>.deploy.{host}` preview.
/// The label is `deploy` (not `_deploy`): an underscore is valid in a DNS name
/// but **illegal in a TLS certificate SAN**, so a CA would refuse a
/// `*._deploy.x` wildcard.
pub fn preview_wildcard(site_host: &str) -> String {
    format!("*.deploy.{site_host}")
}

/// The ACME DNS-01 challenge record name for `domain`. A wildcard authorization
/// (`*.x`) is validated at the base name, so the leading `*.` is stripped:
/// `*.deploy.example.com` → `_acme-challenge.deploy.example.com` (the underscore
/// in `_acme-challenge` is fine — it's a TXT record name, not a cert SAN).
pub fn acme_challenge_name(domain: &str) -> String {
    let base = domain.strip_prefix("*.").unwrap_or(domain);
    format!("_acme-challenge.{base}")
}

/// The DNS-01 TXT record value for an ACME `key_authorization`:
/// base64url(SHA-256(key_authorization)), unpadded (RFC 8555 §8.4).
pub fn dns01_txt_value(key_authorization: &str) -> String {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(key_authorization.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Where a site's preview wildcard host should point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreviewTarget {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    /// Point at another hostname (e.g. a load balancer) via `CNAME`.
    Cname(String),
}

/// The DNS record that points `name` at `target` — the record kind follows the
/// target (address → `A`/`AAAA`, hostname → `CNAME`).
fn record_at(name: String, target: &PreviewTarget, ttl: u32) -> DnsRecord {
    let kind = match target {
        PreviewTarget::Ipv4(ip) => RecordKind::A(*ip),
        PreviewTarget::Ipv6(ip) => RecordKind::Aaaa(*ip),
        PreviewTarget::Cname(target) => RecordKind::Cname(target.clone()),
    };
    DnsRecord { kind, name, ttl }
}

/// The single DNS record that makes a site's preview wildcard host resolve to
/// `target` (the "auto-config" record).
pub fn preview_record(site_host: &str, target: &PreviewTarget, ttl: u32) -> DnsRecord {
    record_at(preview_wildcard(site_host), target, ttl)
}

/// The single DNS record that points a **verified custom host** (an apex or a
/// sub-domain) at `target` — the custom-domain analogue of [`preview_record`].
/// `host` becomes the record name verbatim (a trailing dot is trimmed); the kind
/// follows the target. A `CNAME` is invalid at a true apex, so point apex hosts
/// at an address target (`A`/`AAAA`).
pub fn domain_record(host: &str, target: &PreviewTarget, ttl: u32) -> DnsRecord {
    record_at(host.trim_end_matches('.').to_string(), target, ttl)
}

/// Which operation a [`ManualDnsProvider`] recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsOp {
    Upsert,
    Delete,
}

/// A [`DnsProvider`] that performs no network calls — it logs and records the
/// changes the operator must apply themselves. The universal fallback when no
/// cloud provider is configured, and the test double for the ACME flow.
#[derive(Default)]
pub struct ManualDnsProvider {
    ops: Mutex<Vec<(DnsOp, DnsRecord)>>,
}

impl ManualDnsProvider {
    pub fn new() -> Self {
        Self::default()
    }

    /// The operations recorded so far (for inspection / tests).
    pub fn recorded(&self) -> Vec<(DnsOp, DnsRecord)> {
        self.ops.lock().unwrap().clone()
    }
}

#[async_trait]
impl DnsProvider for ManualDnsProvider {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        tracing::info!(
            target: "boatramp::dns",
            op = "upsert", kind = record.kind.as_str(), name = %record.name,
            value = %record.kind.flat_value(), ttl = record.ttl,
            "manual DNS: create this record"
        );
        self.ops
            .lock()
            .unwrap()
            .push((DnsOp::Upsert, record.clone()));
        Ok(())
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        tracing::info!(
            target: "boatramp::dns",
            op = "delete", kind = record.kind.as_str(), name = %record.name,
            "manual DNS: remove this record"
        );
        self.ops
            .lock()
            .unwrap()
            .push((DnsOp::Delete, record.clone()));
        Ok(())
    }

    fn name(&self) -> &'static str {
        "manual"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_wildcard_and_challenge_naming() {
        assert_eq!(preview_wildcard("example.com"), "*.deploy.example.com");
        // The challenge name strips the wildcard label and prefixes the base.
        assert_eq!(
            acme_challenge_name("*.deploy.example.com"),
            "_acme-challenge.deploy.example.com"
        );
        // A non-wildcard domain is prefixed directly.
        assert_eq!(
            acme_challenge_name("example.com"),
            "_acme-challenge.example.com"
        );
    }

    #[test]
    fn dns01_value_is_base64url_sha256_unpadded() {
        // RFC 8555 §8.4 worked example: the SHA-256 of the key authorization,
        // base64url without padding. Verify determinism + the no-pad/url-safe
        // alphabet (no '+', '/', or '=').
        let value = dns01_txt_value("token.thumbprint");
        assert_eq!(value, dns01_txt_value("token.thumbprint"));
        assert!(!value.contains('+') && !value.contains('/') && !value.contains('='));
        // SHA-256 → 32 bytes → 43 base64url chars unpadded.
        assert_eq!(value.len(), 43);
        // Known-answer vector: base64url_nopad(SHA-256("token.thumbprint")). Pins the
        // exact bytes — determinism + length + alphabet alone would not catch a
        // double-hash or a swapped digest that preserved the shape.
        assert_eq!(value, "61rBZ_4knHblO0MNoxFsXZ_eTFUHum0B6IVRbhvUn5I");
    }

    #[test]
    fn preview_record_picks_kind_by_target() {
        let a = preview_record(
            "example.com",
            &PreviewTarget::Ipv4("203.0.113.7".parse().unwrap()),
            120,
        );
        assert_eq!(a.kind, RecordKind::A("203.0.113.7".parse().unwrap()));
        assert_eq!(a.name, "*.deploy.example.com");
        assert_eq!(a.kind.flat_value(), "203.0.113.7");

        let c = preview_record(
            "example.com",
            &PreviewTarget::Cname("lb.example.net".into()),
            300,
        );
        assert_eq!(c.kind, RecordKind::Cname("lb.example.net".into()));
        assert_eq!(c.kind.flat_value(), "lb.example.net");
    }

    #[test]
    fn domain_record_points_an_exact_host() {
        // Apex host at an address → A at the apex name (no wildcard prefix).
        let a = domain_record(
            "example.com",
            &PreviewTarget::Ipv4("203.0.113.7".parse().unwrap()),
            300,
        );
        assert_eq!(a.kind, RecordKind::A("203.0.113.7".parse().unwrap()));
        assert_eq!(a.name, "example.com");
        assert_eq!(a.kind.flat_value(), "203.0.113.7");

        // Sub-domain at a hostname → CNAME; a trailing dot on the host is trimmed.
        let c = domain_record(
            "www.example.com.",
            &PreviewTarget::Cname("lb.example.net".into()),
            60,
        );
        assert_eq!(c.kind, RecordKind::Cname("lb.example.net".into()));
        assert_eq!(c.name, "www.example.com");
        assert_eq!(c.kind.flat_value(), "lb.example.net");
    }

    #[tokio::test]
    async fn manual_provider_records_ops() {
        let provider = ManualDnsProvider::new();
        let record = DnsRecord {
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.example.com".into(),
            ttl: 60,
        };
        provider.upsert(&record).await.unwrap();
        provider.delete(&record).await.unwrap();
        let ops = provider.recorded();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].0, DnsOp::Upsert);
        assert_eq!(ops[1].0, DnsOp::Delete);
        assert_eq!(ops[0].1.name, "_acme-challenge.example.com");
    }

    // ---- WS1 typed-model + guardrail -------------------------------------

    /// Every writable type round-trips: builds, carries its typed rdata, reports
    /// the right tag + DNS token, and clones/compares by value.
    #[test]
    fn typed_variants_round_trip() {
        let cases: Vec<(RecordKind, RecordKindTag, &str)> = vec![
            (
                RecordKind::A("203.0.113.7".parse().unwrap()),
                RecordKindTag::A,
                "A",
            ),
            (
                RecordKind::Aaaa("2001:db8::1".parse().unwrap()),
                RecordKindTag::Aaaa,
                "AAAA",
            ),
            (
                RecordKind::Cname("lb.example.net".into()),
                RecordKindTag::Cname,
                "CNAME",
            ),
            (
                RecordKind::Txt(vec!["v=spf1 -all".into()]),
                RecordKindTag::Txt,
                "TXT",
            ),
            (
                RecordKind::Mx {
                    preference: 10,
                    exchange: "mx.example.com".into(),
                },
                RecordKindTag::Mx,
                "MX",
            ),
            (
                RecordKind::Srv {
                    priority: 1,
                    weight: 5,
                    port: 443,
                    target: "svc.example.com".into(),
                },
                RecordKindTag::Srv,
                "SRV",
            ),
            (
                RecordKind::Caa {
                    flags: 0,
                    tag: CaaTag::Issue,
                    value: "letsencrypt.org".into(),
                },
                RecordKindTag::Caa,
                "CAA",
            ),
            (
                RecordKind::Https {
                    priority: 1,
                    target: ".".into(),
                    params: vec![SvcParam {
                        key: "alpn".into(),
                        value: "h2,h3".into(),
                    }],
                },
                RecordKindTag::Https,
                "HTTPS",
            ),
            (
                RecordKind::Svcb {
                    priority: 0,
                    target: "svc.example.net".into(),
                    params: vec![],
                },
                RecordKindTag::Svcb,
                "SVCB",
            ),
            (
                RecordKind::Ns("ns1.example.net".into()),
                RecordKindTag::Ns,
                "NS",
            ),
            (
                RecordKind::Ptr("host.example.com".into()),
                RecordKindTag::Ptr,
                "PTR",
            ),
            (
                RecordKind::Tlsa {
                    usage: 3,
                    selector: 1,
                    matching: 1,
                    data: "abcdef".into(),
                },
                RecordKindTag::Tlsa,
                "TLSA",
            ),
        ];
        for (kind, tag, token) in cases {
            assert_eq!(kind.tag(), tag, "tag for {token}");
            assert_eq!(kind.as_str(), token, "token for {token}");
            assert_eq!(tag.as_str(), token);
            assert_eq!(kind.clone(), kind, "clone/eq for {token}");
        }
    }

    /// The three Tier-3 provider-managed families have a tag (for errors) but no
    /// writable `RecordKind` variant — refused by construction.
    #[test]
    fn tier3_types_have_tags_but_no_writable_variant() {
        for (tag, token) in [
            (RecordKindTag::Soa, "SOA"),
            (RecordKindTag::Dnskey, "DNSKEY"),
            (RecordKindTag::Ds, "DS"),
            (RecordKindTag::Rrsig, "RRSIG"),
            (RecordKindTag::Nsec, "NSEC"),
            (RecordKindTag::Nsec3, "NSEC3"),
        ] {
            assert_eq!(tag.as_str(), token);
        }
        // (There is no `RecordKind::Soa` etc.; absence is enforced at compile time.)
    }

    /// A test provider that declares it can write every tag, used to prove the
    /// apex-NS guardrail is independent of the capability check.
    struct AllKinds;
    #[async_trait]
    impl DnsProvider for AllKinds {
        async fn upsert(&self, _record: &DnsRecord) -> Result<(), DnsError> {
            Ok(())
        }
        async fn delete(&self, _record: &DnsRecord) -> Result<(), DnsError> {
            Ok(())
        }
        fn supported_kinds(&self) -> &'static [RecordKindTag] {
            &[
                RecordKindTag::A,
                RecordKindTag::Aaaa,
                RecordKindTag::Cname,
                RecordKindTag::Txt,
                RecordKindTag::Mx,
                RecordKindTag::Srv,
                RecordKindTag::Caa,
                RecordKindTag::Https,
                RecordKindTag::Svcb,
                RecordKindTag::Ns,
                RecordKindTag::Ptr,
                RecordKindTag::Tlsa,
            ]
        }
        fn name(&self) -> &'static str {
            "allkinds"
        }
    }

    #[test]
    fn guardrail_allows_supported_kinds() {
        let p = ManualDnsProvider::new();
        for kind in [
            RecordKind::A("203.0.113.7".parse().unwrap()),
            RecordKind::Aaaa("2001:db8::1".parse().unwrap()),
            RecordKind::Cname("lb.example.net".into()),
            RecordKind::Txt(vec!["tok".into()]),
        ] {
            let rec = DnsRecord {
                kind,
                name: "x.example.com".into(),
                ttl: 60,
            };
            validate_writable(&p, &rec, "example.com").unwrap();
        }
    }

    #[test]
    fn guardrail_refuses_unsupported_kind() {
        // The default adapter capability is {A, AAAA, CNAME, TXT}; MX is refused.
        let p = ManualDnsProvider::new();
        let rec = DnsRecord {
            kind: RecordKind::Mx {
                preference: 10,
                exchange: "mx.example.com".into(),
            },
            name: "example.com".into(),
            ttl: 300,
        };
        let err = validate_writable(&p, &rec, "example.com").unwrap_err();
        match err {
            DnsError::UnsupportedRecordType { provider, kind } => {
                assert_eq!(provider, "manual");
                assert_eq!(kind, RecordKindTag::Mx);
            }
            other => panic!("expected UnsupportedRecordType, got {other:?}"),
        }
    }

    #[test]
    fn guardrail_refuses_apex_ns_but_allows_subzone_ns() {
        let p = AllKinds; // supports NS, so only the apex rule can refuse it
        // Apex NS (owner == zone root) is refused specifically.
        let apex = DnsRecord {
            kind: RecordKind::Ns("ns1.example.net".into()),
            name: "example.com".into(),
            ttl: 3600,
        };
        match validate_writable(&p, &apex, "example.com").unwrap_err() {
            DnsError::ApexNsRefused { zone, name } => {
                assert_eq!(zone, "example.com");
                assert_eq!(name, "example.com");
            }
            other => panic!("expected ApexNsRefused, got {other:?}"),
        }
        // A trailing dot on the owner name does not sneak past the apex rule.
        let apex_dotted = DnsRecord {
            name: "example.com.".into(),
            ..apex.clone()
        };
        assert!(matches!(
            validate_writable(&p, &apex_dotted, "example.com").unwrap_err(),
            DnsError::ApexNsRefused { .. }
        ));
        // Sub-zone NS delegation is allowed.
        let subzone = DnsRecord {
            kind: RecordKind::Ns("ns1.example.net".into()),
            name: "sub.example.com".into(),
            ttl: 3600,
        };
        validate_writable(&p, &subzone, "example.com").unwrap();
    }

    #[test]
    fn guardrail_on_default_adapter_refuses_subzone_ns_as_unsupported() {
        // On a WS1 adapter (NS not yet supported), even a valid sub-zone NS is
        // refused — but as UnsupportedRecordType, not the apex rule.
        let p = ManualDnsProvider::new();
        let subzone = DnsRecord {
            kind: RecordKind::Ns("ns1.example.net".into()),
            name: "sub.example.com".into(),
            ttl: 3600,
        };
        assert!(matches!(
            validate_writable(&p, &subzone, "example.com").unwrap_err(),
            DnsError::UnsupportedRecordType {
                kind: RecordKindTag::Ns,
                ..
            }
        ));
    }

    #[test]
    fn txt_validation_rejects_overlong_and_empty() {
        // A 256-byte character-string exceeds the 255-byte DNS limit.
        let overlong = RecordKind::Txt(vec!["a".repeat(256)]);
        assert!(matches!(
            overlong.validate_rdata(),
            Err(DnsError::InvalidRecord(_))
        ));
        // Exactly 255 bytes is fine.
        RecordKind::Txt(vec!["a".repeat(255)])
            .validate_rdata()
            .unwrap();
        // A multi-string TXT with every chunk in-bounds is fine.
        RecordKind::Txt(vec!["a".repeat(255), "b".repeat(10)])
            .validate_rdata()
            .unwrap();
        // A TXT with no character-strings has no rdata.
        assert!(matches!(
            RecordKind::Txt(vec![]).validate_rdata(),
            Err(DnsError::InvalidRecord(_))
        ));
        // And the guardrail surfaces the same refusal.
        let p = ManualDnsProvider::new();
        let rec = DnsRecord {
            kind: RecordKind::Txt(vec!["a".repeat(256)]),
            name: "x.example.com".into(),
            ttl: 60,
        };
        assert!(matches!(
            validate_writable(&p, &rec, "example.com").unwrap_err(),
            DnsError::InvalidRecord(_)
        ));
    }

    #[test]
    fn caa_validation_rejects_empty_value() {
        assert!(matches!(
            RecordKind::Caa {
                flags: 0,
                tag: CaaTag::Issue,
                value: "   ".into(),
            }
            .validate_rdata(),
            Err(DnsError::InvalidRecord(_))
        ));
        // A real CAA value passes, and the tag renders to its wire token.
        let caa = RecordKind::Caa {
            flags: 0,
            tag: CaaTag::IssueWild,
            value: "letsencrypt.org".into(),
        };
        caa.validate_rdata().unwrap();
        assert_eq!(CaaTag::IssueWild.as_str(), "issuewild");
        assert_eq!(CaaTag::Iodef.as_str(), "iodef");
    }
}
