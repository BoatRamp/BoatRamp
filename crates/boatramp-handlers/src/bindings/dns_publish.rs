//! The host-side **DNS publish** (write) binding (`boatramp:handlers/dns-publish`, cap-req #24 WS3):
//! the WRITE counterpart to the read-only `dns-resolve` capability. A granted guest NAMES a
//! zone/record; the HOST performs the mutation through an operator-configured, host-held
//! [`DnsProvider`] credential. **No secret ever crosses to the guest** — the guest holds no zone-write
//! token, only the ability to invoke `upsert`/`delete`/`upsert-set` within its authorized zones.
//!
//! # Three-layer gate, FAIL-CLOSED (the security core)
//! 1. **Node posture `allow_guest_dns_publish`** (carried here as `posture_enabled`, OFF by default in
//!    every profile): posture off ⇒ every call is `access-denied`, exactly like `dns-resolve` under its
//!    egress posture. Deny-by-default per grant too — the binding is `None` when `dns-publish` was not
//!    conferred.
//! 2. **Per-grant writable-zone allowlist** (`DnsPublishBinding::writable_zones`): the host REJECTS any
//!    record whose OWN `name`/owner falls outside the operator's authorized zone suffixes. **Empty ⇒
//!    deny-all** (fail-closed). The scope constrains the record's OWN name ONLY — an rdata TARGET (a
//!    CNAME/MX/SRV/NS exchange/target) legitimately points elsewhere and is NEVER constrained, so a
//!    normal mail/service record set is not broken. Suffix/glob matching is kept consistent with the
//!    egress-host allowlist ([`boatramp_types::gateway::gateway_host_matches`]) — re-implemented here
//!    ([`zone_glob_matches`]) because this crate does not depend on `boatramp-types`.
//! 3. **Rate budget + audit** — a per-invocation publish budget (mirrors `dns_resolve_budget`) and a
//!    REDACTED audit log of every mutation (name, type, provider, outcome — never a credential/secret).
//!
//! Above the adapter, the central `boatramp-acme` [`validate_writable`] guardrail refuses an apex `NS`,
//! a kind the target provider cannot write, and malformed rdata — BEFORE any provider is dispatched.
//! Never a silent drop, never a partial/best-effort apply.
//!
//! # STORE-RESIDENT state (a previously-bitten footgun)
//! wasmtime REBUILDS this host view on EVERY host call (the `add_to_linker` getter), so any MUTABLE
//! per-invocation state kept as a view field would reset every call and never enforce anything (the
//! `DnsResolveHost` HIGH-1 lesson). The publish budget is therefore a BORROW of a store-resident
//! `AtomicU32` (`HostState.dns_publish_budget`), not a view field; the allowlist, provider, zone-root
//! and audit sink live in the store-resident [`DnsPublishBinding`] (a field of `HostState.bindings`)
//! and are BORROWED by the view. An `AtomicU32` (not a `Cell`) because the async host-call future must
//! be `Send`.

use std::sync::Arc;
use std::sync::atomic::AtomicU32;

use boatramp_acme::dns::{
    DnsError, DnsProvider, DnsRecord as AcmeRecord, RecordKind, RecordKindTag, SvcParam,
    ZoneResolution, canonicalize_owner_name, validate_writable,
};
use boatramp_core::project::ProjectRef;
use boatramp_core::secret_store::{SecretError, TenantDnsCredStore};

use crate::engine::GuestDnsPublishNs;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/dns-publish-host",
        imports: { default: async },
    });
}

use generated::boatramp::handlers::dns_publish;

/// Which mutation a [`DnsPublishAuditEntry`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPublishOp {
    Upsert,
    Delete,
}

impl DnsPublishOp {
    /// The audit token (`upsert` / `delete`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Delete => "delete",
        }
    }
}

/// The outcome of a mutation, for the audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPublishOutcome {
    /// The provider accepted the write (or a delete of an absent record converged).
    Applied,
    /// The provider rejected the write / was unreachable.
    Failed,
}

impl DnsPublishOutcome {
    /// The audit token (`applied` / `failed`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Failed => "failed",
        }
    }
}

/// One audit record for a guest DNS mutation. Deliberately carries only the record's NAME, TYPE, the
/// PROVIDER name, and the OUTCOME — **never** the rdata value (a TXT could carry a token) and never any
/// credential. This is the "redacted" audit contract.
pub struct DnsPublishAuditEntry<'a> {
    pub op: DnsPublishOp,
    pub name: &'a str,
    pub kind: RecordKindTag,
    pub provider: &'static str,
    pub outcome: DnsPublishOutcome,
}

/// Where the audit log of guest DNS mutations is written. Injected (like the provider) so the host
/// (boatramp-server) decides the sink; the default [`TracingDnsPublishSink`] emits a `tracing` event.
pub trait DnsPublishAuditSink: Send + Sync {
    /// Record one mutation. Called for EVERY admitted write attempt (its outcome included).
    fn record(&self, entry: &DnsPublishAuditEntry<'_>);
}

/// The default audit sink: a structured `tracing` event per mutation. Redacted by construction — it
/// logs only name/type/provider/outcome, never the rdata value or any credential.
pub struct TracingDnsPublishSink;

impl DnsPublishAuditSink for TracingDnsPublishSink {
    fn record(&self, e: &DnsPublishAuditEntry<'_>) {
        tracing::info!(
            target: "boatramp::dns::publish",
            op = e.op.as_str(),
            name = %e.name,
            kind = %e.kind,
            provider = e.provider,
            outcome = e.outcome.as_str(),
            "guest dns-publish mutation",
        );
    }
}

/// The operator **serve-static** DNS writer for a grant (cap-req #24, UNCHANGED): the host-held
/// provider, the zone it is authoritative over (for the apex-NS guardrail), the own-name writable-zone
/// allowlist (layer 2), and the NS-target allowlist. The guest never sees any of this — it only names
/// records.
#[derive(Clone)]
struct OperatorWriter {
    /// The host-held writer whose adapter credential performs the mutation.
    provider: Arc<dyn DnsProvider>,
    /// The apex of the zone the provider is authoritative over (e.g. `example.com`), passed to
    /// [`validate_writable`] so an apex `NS` is refused. Not guest-supplied.
    zone_root: String,
    /// The authorized writable-zone suffixes (globs). Empty ⇒ deny-all. Matched against the record's
    /// OWN name only.
    writable_zones: Arc<[String]>,
    /// The authorized **NS-target** suffixes (globs) for a sub-zone `NS` delegation (Security review
    /// MEDIUM-3). Consulted ONLY under the `Allowlist` NS posture, and matched against the NS record's
    /// rdata TARGET nameserver (NOT its own name). **Empty ⇒ deny-all** under `Allowlist` (fail-closed).
    ns_targets: Arc<[String]>,
}

/// The provider kind a RUNTIME-registered credential names (cap-req #31) — the FULL operator
/// serve-static adapter set. Mapped into this crate-local enum so the server-side
/// [`RuntimeDnsProviderFactory`] impl need not depend on the generated bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeDnsProviderKind {
    Cloudflare,
    Route53,
    Oci,
    Akamai,
    Dnsimple,
    Gcp,
    Azure,
    DigitalOcean,
    Hetzner,
    Ns1,
}

impl RuntimeDnsProviderKind {
    /// The stable string token stored (clear) in the sealed record + echoed in the audit log.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cloudflare => "cloudflare",
            Self::Route53 => "route53",
            Self::Oci => "oci",
            Self::Akamai => "akamai",
            Self::Dnsimple => "dnsimple",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
            Self::DigitalOcean => "digitalocean",
            Self::Hetzner => "hetzner",
            Self::Ns1 => "ns1",
        }
    }

    /// Parse back from the stored string token. `None` ⇒ an unknown/foreign kind (fail-closed).
    #[must_use]
    pub fn from_stored(s: &str) -> Option<Self> {
        Some(match s {
            "cloudflare" => Self::Cloudflare,
            "route53" => Self::Route53,
            "oci" => Self::Oci,
            "akamai" => Self::Akamai,
            "dnsimple" => Self::Dnsimple,
            "gcp" => Self::Gcp,
            "azure" => Self::Azure,
            "digitalocean" => Self::DigitalOcean,
            "hetzner" => Self::Hetzner,
            "ns1" => Self::Ns1,
            _ => return None,
        })
    }

    /// The per-provider credential-field schema (Security review #31-wide): the fields this provider's
    /// adapter is constructed from, each with a shape (defense-in-depth beyond length) and whether it is
    /// required. The ZONE is always the registered `zone-root` (never a field), except where the
    /// provider addresses its zone by an opaque id (`zone_id` / `hosted_zone_id`), which IS a field. This
    /// is the single source of truth the host validates a bundle against before sealing; the server
    /// factory consumes the same field names to build the adapter.
    #[must_use]
    fn field_rules(self) -> &'static [CredentialFieldRule] {
        match self {
            Self::Cloudflare => CLOUDFLARE_FIELDS,
            Self::Route53 => ROUTE53_FIELDS,
            Self::Oci => OCI_FIELDS,
            Self::Akamai => AKAMAI_FIELDS,
            Self::Dnsimple => DNSIMPLE_FIELDS,
            Self::Gcp => GCP_FIELDS,
            Self::Azure => AZURE_FIELDS,
            Self::DigitalOcean => TOKEN_ONLY_FIELDS,
            Self::Hetzner => TOKEN_ONLY_FIELDS,
            Self::Ns1 => API_KEY_FIELDS,
        }
    }
}

const fn req(name: &'static str, shape: CredentialFieldShape) -> CredentialFieldRule {
    CredentialFieldRule {
        name,
        shape,
        required: true,
    }
}
const fn opt(name: &'static str, shape: CredentialFieldShape) -> CredentialFieldRule {
    CredentialFieldRule {
        name,
        shape,
        required: false,
    }
}

use CredentialFieldShape::{
    AkamaiHost, Guid, Identifier, OciKeyId, OpaqueId, Pem, Region, Secret, ServiceAccountJson,
};

const CLOUDFLARE_FIELDS: &[CredentialFieldRule] = &[req("zone_id", OpaqueId), req("token", Secret)];
const ROUTE53_FIELDS: &[CredentialFieldRule] = &[
    req("access_key_id", Identifier),
    req("secret_access_key", Secret),
    req("region", Region),
    req("hosted_zone_id", OpaqueId),
    opt("session_token", Secret),
];
const OCI_FIELDS: &[CredentialFieldRule] = &[
    req("region", Region),
    req("key_id", OciKeyId),
    req("private_key_pem", Pem),
];
const AKAMAI_FIELDS: &[CredentialFieldRule] = &[
    req("host", AkamaiHost),
    req("client_token", Secret),
    req("client_secret", Secret),
    req("access_token", Secret),
];
const DNSIMPLE_FIELDS: &[CredentialFieldRule] =
    &[req("account_id", Identifier), req("token", Secret)];
// cap-req #31: GCP takes a LONG-LIVED service-account JSON (project read from it) + the managed-zone
// resource name (GCP addresses its zone by resource name, not the domain). The adapter exchanges the SA
// key host-side for a cached short-lived token.
const GCP_FIELDS: &[CredentialFieldRule] = &[
    req("service_account_json", ServiceAccountJson),
    req("managed_zone", Identifier),
];
// cap-req #31: Azure takes a LONG-LIVED service principal (GUID tenant/client ids + secret) + the
// subscription/resource-group that scope the zone. The adapter runs client-credentials host-side.
const AZURE_FIELDS: &[CredentialFieldRule] = &[
    req("tenant_id", Guid),
    req("client_id", Guid),
    req("client_secret", Secret),
    req("subscription_id", Guid),
    req("resource_group", Identifier),
];
const TOKEN_ONLY_FIELDS: &[CredentialFieldRule] = &[req("token", Secret)];
const API_KEY_FIELDS: &[CredentialFieldRule] = &[req("api_key", Secret)];

/// How one credential-field value is shape-validated before sealing (defense-in-depth beyond the length
/// bound; the authoritative security property is that NO value can inject into a provider URL path or an
/// auth header). Each shape maps to an interpolation context of the provider adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialFieldShape {
    /// A bearer/API secret carried in an auth header. Reject CR/LF/control + `"` (header injection);
    /// bounded.
    Secret,
    /// A PEM private key (OCI). Multi-line; must contain a PEM header; reject NUL/other control except
    /// `\r`/`\n`/`\t`; larger bound.
    Pem,
    /// An opaque id interpolated into a URL path (Cloudflare zone id, Route53 hosted-zone id):
    /// `[A-Za-z0-9]` only, bounded — so a `/`/`..` can never escape the path segment.
    OpaqueId,
    /// A dotted/hyphenated id interpolated into a URL path (account/project/subscription/resource-group,
    /// AWS access-key-id): `[A-Za-z0-9._-]`, bounded (rejects `/ : % space`).
    Identifier,
    /// A cloud region interpolated into a URL host/path (`[a-z0-9-]`, short).
    Region,
    /// The Akamai API `host` — the ONLY credential field that becomes a request's AUTHORITY
    /// (`AkamaiDns`: `https://{host}{path}`), so it is a blind-SSRF vector if unconstrained (Security
    /// review M1). PINNED to the Akamai EdgeGrid API domain: lowercase `[a-z0-9.-]` with no empty label,
    /// NOT an IP literal (v4/v6), and REQUIRED to be a non-empty subdomain of `.akamaiapis.net` — so a
    /// tenant can never aim the dial at `localhost` / `10.0.0.5` / `169.254.169.254` / any non-Akamai
    /// host. A `host` outside the Akamai API domain is `invalid-record` at register.
    AkamaiHost,
    /// An OCI `key_id` (`<tenancy_ocid>/<user_ocid>/<fingerprint>`) placed in the Authorization signing
    /// string's `keyId="..."`: allow its real charset `[A-Za-z0-9._:/-]` but reject CR/LF/`"`/space so
    /// it cannot break the header/signature.
    OciKeyId,
    /// A strict UUID/GUID (Azure `tenant_id`/`client_id`/`subscription_id`) — the `tenant_id` fills a
    /// path segment of the FIXED Azure AD token endpoint, so it is held to the exact
    /// `8-4-4-4-12` hex form (36 chars) and can never reshape the URL.
    Guid,
    /// A GCP service-account JSON key (cap-req #31): must parse as a JSON object carrying `client_email`,
    /// `project_id`, and a `private_key` with a PEM `-----BEGIN` header. The whole bundle is sealed; the
    /// adapter signs a JWT with the key host-side. Larger bound (the key file is a few KB).
    ServiceAccountJson,
}

/// One rule in a provider's credential-field schema: the field `name`, its [`CredentialFieldShape`], and
/// whether it is required.
#[derive(Debug, Clone, Copy)]
struct CredentialFieldRule {
    name: &'static str,
    shape: CredentialFieldShape,
    required: bool,
}

/// Max number of fields in a credential bundle (bounds a guest spamming a huge field list).
const MAX_CREDENTIAL_FIELDS: usize = 16;
/// Max length of a single secret/header field value.
const MAX_SECRET_FIELD_LEN: usize = 8 * 1024;
/// Max length of a PEM field value (multi-line private key).
const MAX_PEM_FIELD_LEN: usize = 16 * 1024;
/// The Akamai EdgeGrid API domain the tenant `host` field is PINNED under (Security review M1). EdgeGrid
/// API hosts are `<account>-<id>.luna.akamaiapis.net` (and siblings) — all under `.akamaiapis.net` (the
/// `boatramp-acme` Akamai adapter's own example host is `akab-h.luna.akamaiapis.net`).
const AKAMAI_API_DOMAIN_SUFFIX: &str = ".akamaiapis.net";

/// Validate ONE field value against its shape (Security review #31-wide): every shape rejects the bytes
/// that would let the value escape its interpolation context, and bounds its length. Returns a
/// client-safe reason on failure (never the value).
fn validate_field_value(
    name: &str,
    shape: CredentialFieldShape,
    value: &str,
) -> Result<(), String> {
    use CredentialFieldShape::*;
    let max = match shape {
        Pem | ServiceAccountJson => MAX_PEM_FIELD_LEN,
        Secret | OciKeyId => MAX_SECRET_FIELD_LEN,
        OpaqueId | Identifier | Region => 128,
        AkamaiHost => 253,
        Guid => 36,
    };
    if value.is_empty() {
        return Err(format!("field `{name}` must not be empty"));
    }
    if value.len() > max {
        return Err(format!("field `{name}` is too long"));
    }
    let ok = match shape {
        // No CR/LF/control (header injection) and no `"` (breaks a quoted header param).
        Secret => value.bytes().all(|b| !b.is_ascii_control() && b != b'"'),
        Pem => {
            value.contains("-----BEGIN")
                && value
                    .bytes()
                    .all(|b| !b.is_ascii_control() || matches!(b, b'\r' | b'\n' | b'\t'))
        }
        OpaqueId => value.bytes().all(|b| b.is_ascii_alphanumeric()),
        // i1: `[A-Za-z0-9._-]` AND no empty dot-segment (rejects `..`, a leading/trailing dot, and the
        // value being `.`/`..`) — mirrors `validate_name`'s dot rule.
        Identifier => {
            value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
                && !value.split('.').any(str::is_empty)
        }
        Region => value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
        // M1: the Akamai host is PINNED to the EdgeGrid API domain — lowercase hostname charset, no
        // empty label, NOT an IP literal, and a non-empty subdomain of `.akamaiapis.net`. This closes
        // the only tenant-controlled request-authority (blind SSRF) in the adapter set.
        AkamaiHost => {
            value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
                && !value.split('.').any(str::is_empty)
                && value.parse::<std::net::IpAddr>().is_err()
                && value
                    .strip_suffix(AKAMAI_API_DOMAIN_SUFFIX)
                    .is_some_and(|prefix| !prefix.is_empty())
        }
        OciKeyId => value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-')),
        // A strict `8-4-4-4-12` hex GUID — nothing that could reshape the Azure token-endpoint path.
        Guid => is_guid(value),
        // Must parse as a JSON object with the service-account fields + a PEM private key.
        ServiceAccountJson => is_service_account_json(value),
    };
    if ok {
        Ok(())
    } else {
        Err(format!("field `{name}` has an invalid value shape"))
    }
}

/// Whether `s` is a strict `8-4-4-4-12` lowercase/uppercase hex GUID (36 chars; dashes at 8/13/18/23).
fn is_guid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    s.bytes().enumerate().all(|(i, b)| {
        if matches!(i, 8 | 13 | 18 | 23) {
            b == b'-'
        } else {
            b.is_ascii_hexdigit()
        }
    })
}

/// Whether `s` is a usable GCP service-account JSON key: a JSON object with non-empty string
/// `client_email` + `project_id`, and a `private_key` string carrying a PEM `-----BEGIN` header.
fn is_service_account_json(s: &str) -> bool {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(s) else {
        return false;
    };
    let Some(obj) = v.as_object() else {
        return false;
    };
    let str_field = |k: &str| obj.get(k).and_then(serde_json::Value::as_str);
    let nonempty = |k: &str| str_field(k).is_some_and(|x| !x.is_empty());
    nonempty("client_email")
        && nonempty("project_id")
        && str_field("private_key").is_some_and(|k| k.contains("-----BEGIN"))
}

/// Encode a validated field map as an opaque, self-delimiting blob (dependency-free; robust for
/// arbitrary values incl. multi-line PEM, unlike a naive `k=v` format): each entry is
/// `u32-le len(name) · name · u32-le len(value) · value`. The whole blob is then sealed.
fn encode_fields(map: &std::collections::BTreeMap<String, String>) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in map {
        out.extend_from_slice(&(k.len() as u32).to_le_bytes());
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v.as_bytes());
    }
    out
}

/// Decode a blob produced by [`encode_fields`]. `None` on any truncation / bad length / non-UTF-8
/// (fail-closed — a corrupt sealed credential never routes).
fn decode_fields(bytes: &[u8]) -> Option<std::collections::BTreeMap<String, String>> {
    let mut map = std::collections::BTreeMap::new();
    let mut i = 0usize;
    let read_len = |b: &[u8], i: usize| -> Option<usize> {
        let end = i.checked_add(4)?;
        if end > b.len() {
            return None;
        }
        Some(u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as usize)
    };
    while i < bytes.len() {
        let klen = read_len(bytes, i)?;
        i += 4;
        let k_end = i.checked_add(klen)?;
        if k_end > bytes.len() {
            return None;
        }
        let k = std::str::from_utf8(&bytes[i..k_end]).ok()?.to_string();
        i = k_end;
        let vlen = read_len(bytes, i)?;
        i += 4;
        let v_end = i.checked_add(vlen)?;
        if v_end > bytes.len() {
            return None;
        }
        let v = std::str::from_utf8(&bytes[i..v_end]).ok()?.to_string();
        i = v_end;
        map.insert(k, v);
    }
    Some(map)
}

/// Validate a guest-supplied credential bundle against `kind`'s schema and return it as a field map
/// (Security review #31-wide): reject a duplicate/unknown field name, a missing required field, too many
/// fields, or a value that fails its shape/length check — ALL before sealing. The returned
/// `BTreeMap` carries exactly the known fields (unknowns are rejected, so nothing extra is sealed).
fn validate_credential_bundle(
    kind: RuntimeDnsProviderKind,
    fields: Vec<(String, String)>,
) -> Result<std::collections::BTreeMap<String, String>, dns_publish::PublishError> {
    use dns_publish::PublishError as P;
    if fields.len() > MAX_CREDENTIAL_FIELDS {
        return Err(P::InvalidRecord("too many credential fields".into()));
    }
    let rules = kind.field_rules();
    let mut map = std::collections::BTreeMap::new();
    for (name, value) in fields {
        let Some(rule) = rules.iter().find(|r| r.name == name) else {
            return Err(P::InvalidRecord(format!(
                "unknown credential field `{name}` for this provider"
            )));
        };
        if map.contains_key(&name) {
            return Err(P::InvalidRecord(format!(
                "duplicate credential field `{name}`"
            )));
        }
        validate_field_value(&name, rule.shape, &value).map_err(P::InvalidRecord)?;
        map.insert(name, value);
    }
    // Every required field must be present.
    for rule in rules.iter().filter(|r| r.required) {
        if !map.contains_key(rule.name) {
            return Err(P::InvalidRecord(format!(
                "missing required credential field `{}`",
                rule.name
            )));
        }
    }
    Ok(map)
}

/// Builds a live [`DnsProvider`] adapter from an UNSEALED runtime credential bundle, authoritative over
/// `zone_root` (cap-req #31). Injected (the real impl, over the `boatramp-acme` adapters, lives in
/// `boatramp-server`) so a gate can supply a FAKE factory that never touches a real DNS provider. The
/// bundle reaches the factory but NEVER crosses back to the guest or into a log/error.
pub trait RuntimeDnsProviderFactory: Send + Sync {
    /// Build the provider for `kind` authoritative over `zone_root` from the validated `fields` bundle.
    /// `cache_scope` is THIS invocation's tenancy identity (`project` + resolved `tenant`); the factory
    /// may key a per-tenancy adapter/token cache on it so a minted OAuth token is reused across calls
    /// but NEVER shared across tenants. An `Err(reason)` is logged host-side and surfaced to the guest
    /// only as a GENERIC `backend` error (the reason may name provider internals).
    fn build(
        &self,
        kind: RuntimeDnsProviderKind,
        fields: &std::collections::BTreeMap<String, String>,
        zone_root: &str,
        cache_scope: &str,
    ) -> Result<Arc<dyn DnsProvider>, String>;
}

/// The per-invocation RUNTIME per-tenant DNS-credential registry (cap-req #31): the host-sealed store,
/// the provider factory, and THIS invocation's host-resolved `(project, tenant)` + the per-component
/// `dynamic_dns_zones` allowlist of registerable zone-roots. All host-owned — the guest supplies only a
/// `zone-root` + provider + token to register, and names records to route; it never names a tenant and
/// never sees a stored token. `None` on the binding ⇒ the dynamic path is not wired for this invocation.
#[derive(Clone)]
pub struct RuntimeDnsRegistry {
    store: TenantDnsCredStore,
    factory: Arc<dyn RuntimeDnsProviderFactory>,
    project: String,
    /// THIS invocation's host-resolved own tenant (never guest-supplied). The registry is only built
    /// when a single tenant resolved, so this is always present here.
    tenant: String,
    /// The per-component host-authoritative allowlist of registerable zone-root globs. **Empty ⇒
    /// deny-all** (fail-closed). `register-zone-credential(zone-root)` is admitted only if `zone-root`
    /// matches an entry (same glob semantics as the own-name `writable_zones` allowlist).
    dynamic_zones: Arc<[String]>,
}

impl RuntimeDnsRegistry {
    /// Build the registry handle. `tenant` is THIS invocation's host-resolved own tenant;
    /// `dynamic_zones` is the per-component registerable-zone allowlist (empty ⇒ deny-all).
    pub fn new(
        store: TenantDnsCredStore,
        factory: Arc<dyn RuntimeDnsProviderFactory>,
        project: impl Into<String>,
        tenant: impl Into<String>,
        dynamic_zones: Vec<String>,
    ) -> Self {
        Self {
            store,
            factory,
            project: project.into(),
            tenant: tenant.into(),
            dynamic_zones: Arc::from(dynamic_zones),
        }
    }

    fn project(&self) -> ProjectRef<'_> {
        ProjectRef::new(&self.project)
    }
}

/// The per-invocation `dns-publish` grant: an OPTIONAL operator serve-static writer (cap-req #24,
/// unchanged) AND an OPTIONAL runtime per-tenant credential registry (cap-req #31), plus the redacted
/// audit sink. `None` on the binding ⇒ not granted. At least one of operator/runtime is present when
/// attached. The guest never sees any of this — it only names records (and, for the runtime path,
/// registers a token the host seals and never returns).
#[derive(Clone)]
pub struct DnsPublishBinding {
    /// The operator serve-static writer (cap-req #24). `None` for a runtime-only (tenant-credential)
    /// grant whose scope has no operator provider.
    operator: Option<OperatorWriter>,
    /// The runtime per-tenant credential registry (cap-req #31). `None` when the dynamic path is not
    /// wired for this invocation.
    runtime: Option<RuntimeDnsRegistry>,
    /// Where each mutation is audited (redacted).
    audit: Arc<dyn DnsPublishAuditSink>,
}

impl DnsPublishBinding {
    /// Build an OPERATOR serve-static grant (cap-req #24, UNCHANGED). `zone_root` is the provider's
    /// authoritative zone apex; `writable_zones` is the per-grant own-name allowlist (empty ⇒
    /// deny-all); `ns_targets` is the per-grant NS-target allowlist for a sub-zone NS delegation (empty
    /// ⇒ deny-all under the `Allowlist` posture); `audit` is the redacted sink.
    pub fn new(
        provider: Arc<dyn DnsProvider>,
        zone_root: impl Into<String>,
        writable_zones: Vec<String>,
        ns_targets: Vec<String>,
        audit: Arc<dyn DnsPublishAuditSink>,
    ) -> Self {
        Self {
            operator: Some(OperatorWriter {
                provider,
                zone_root: zone_root.into(),
                writable_zones: Arc::from(writable_zones),
                ns_targets: Arc::from(ns_targets),
            }),
            runtime: None,
            audit,
        }
    }

    /// Build a RUNTIME-only grant (cap-req #31): no operator provider for this scope, only the
    /// per-tenant credential registry. Used when a tenant's own zone is reachable through runtime
    /// credentials but the operator wired no serve-static provider for this `(project, site)`.
    pub fn runtime_only(runtime: RuntimeDnsRegistry, audit: Arc<dyn DnsPublishAuditSink>) -> Self {
        Self {
            operator: None,
            runtime: Some(runtime),
            audit,
        }
    }

    /// Add (or replace) the runtime per-tenant credential registry on an existing (operator) grant, so
    /// both paths coexist on one binding and route per-zone (cap-req #31).
    #[must_use]
    pub fn with_runtime(mut self, runtime: RuntimeDnsRegistry) -> Self {
        self.runtime = Some(runtime);
        self
    }
}

/// Whether the **already-canonical** owner `name` matches a writable-zone glob.
/// Semantics match [`boatramp_types::gateway::gateway_host_matches`]
/// (case-insensitive; trailing dot ignored; `*.sfx` is a single label, `**.sfx`
/// any depth incl. the apex, bare `**` anything). Re-implemented here because
/// `boatramp-handlers` does not depend on `boatramp-types`.
///
/// **Security invariant (CRITICAL-1 / MEDIUM-2):** `name` MUST be the output of
/// [`canonicalize_owner_name`] (lowercased, no trailing dot, syntactically
/// validated). The matcher does **not** re-normalize `name`, so the string
/// authorized here is byte-identical to the string later dispatched to the
/// adapter — it never authorizes a normalized *copy* of a different raw name.
/// Only the operator-configured `glob` is normalized (case + surrounding
/// whitespace).
fn zone_glob_matches(glob: &str, name: &str) -> bool {
    let glob = glob.trim().to_ascii_lowercase();
    if name.is_empty() {
        return false;
    }
    if glob == "**" {
        return true;
    }
    if let Some(suffix) = glob.strip_prefix("**.") {
        return name == suffix || name.ends_with(&format!(".{suffix}"));
    }
    if let Some(suffix) = glob.strip_prefix("*.") {
        return match name.strip_suffix(&format!(".{suffix}")) {
            Some(label) => !label.is_empty() && !label.contains('.'),
            None => false,
        };
    }
    glob == name
}

/// Whether the record's OWN `name` is authorized by this grant's writable-zone allowlist. **Empty ⇒
/// deny-all** (fail-closed) — note this deliberately differs from `gateway_host_allowed`'s "empty ⇒
/// permitted": a WRITE capability must never default-open. Constrains the OWN name ONLY; the rdata
/// target is never passed here.
fn zone_authorized(allowlist: &[String], name: &str) -> bool {
    !allowlist.is_empty() && allowlist.iter().any(|g| zone_glob_matches(g, name))
}

/// The sub-zone `NS` delegation gate (Security review MEDIUM-3, cap-req #24), applied ONLY to a
/// **non-apex `NS`** record (the apex NS is already refused by [`validate_writable`] before this runs).
/// A sub-zone NS delegates that subtree to an arbitrary nameserver — a persistent, post-revocation,
/// unaudited authority handoff — so its rdata TARGET is constrained here. This is the ONE place an
/// rdata target is ever constrained; the own-name writable-zone allowlist (checked separately in
/// [`DnsPublishHost::prepare`]) is unchanged and still own-name-only.
///
/// - [`GuestDnsPublishNs::None`]  ⇒ refuse every sub-zone NS (`not-authorized`).
/// - [`GuestDnsPublishNs::Allowlist`] ⇒ the NS `target` (canonicalized with the SAME
///   [`canonicalize_owner_name`] used for the owner name, so a syntactically-illegal target is
///   `invalid-record`) must match the per-grant `ns_targets` allowlist; **empty ⇒ deny-all**.
/// - [`GuestDnsPublishNs::Any`] ⇒ allow (today's behavior); the target is neither canonicalized nor
///   constrained.
fn ns_delegation_authorized(
    posture: GuestDnsPublishNs,
    ns_targets: &[String],
    target: &str,
) -> Result<(), dns_publish::PublishError> {
    match posture {
        GuestDnsPublishNs::Any => Ok(()),
        GuestDnsPublishNs::None => Err(dns_publish::PublishError::NotAuthorized(format!(
            "sub-zone NS delegation is disabled by node posture (guest_dns_publish_ns = none); \
             NS target '{target}'"
        ))),
        GuestDnsPublishNs::Allowlist => {
            // Canonicalize the NS target with the SAME validator used for the owner name, so the string
            // matched against the allowlist is syntactically valid + normalized (an illegal target is
            // `invalid-record`, never silently authorized as a normalized copy).
            let canonical = canonicalize_owner_name(target).map_err(map_guardrail_err)?;
            if zone_authorized(ns_targets, &canonical) {
                Ok(())
            } else {
                Err(dns_publish::PublishError::NotAuthorized(format!(
                    "NS target '{canonical}' is not in the dns_publish_ns_targets allowlist"
                )))
            }
        }
    }
}

/// Map a WIT CAA tag to the acme model.
fn map_caa_tag(tag: dns_publish::CaaTag) -> boatramp_acme::dns::CaaTag {
    match tag {
        dns_publish::CaaTag::Issue => boatramp_acme::dns::CaaTag::Issue,
        dns_publish::CaaTag::IssueWild => boatramp_acme::dns::CaaTag::IssueWild,
        dns_publish::CaaTag::Iodef => boatramp_acme::dns::CaaTag::Iodef,
    }
}

/// Map WIT SvcParams to the acme model.
fn map_params(params: Vec<dns_publish::SvcParam>) -> Vec<SvcParam> {
    params
        .into_iter()
        .map(|p| SvcParam {
            key: p.key,
            value: p.value,
        })
        .collect()
}

/// Build the typed [`RecordKind`] from the guest's WIT rdata, parsing the textual A/AAAA addresses.
/// A malformed IP literal is `invalid-record` (the only rdata that can fail to build here; the rest is
/// validated by [`validate_writable`]).
fn build_kind(data: dns_publish::Rdata) -> Result<RecordKind, dns_publish::PublishError> {
    use dns_publish::Rdata;
    Ok(match data {
        Rdata::A(s) => RecordKind::A(s.parse().map_err(|_| {
            dns_publish::PublishError::InvalidRecord("invalid IPv4 literal".into())
        })?),
        Rdata::Aaaa(s) => RecordKind::Aaaa(s.parse().map_err(|_| {
            dns_publish::PublishError::InvalidRecord("invalid IPv6 literal".into())
        })?),
        Rdata::Cname(s) => RecordKind::Cname(s),
        Rdata::Txt(v) => RecordKind::Txt(v),
        Rdata::Mx(m) => RecordKind::Mx {
            preference: m.preference,
            exchange: m.exchange,
        },
        Rdata::Srv(s) => RecordKind::Srv {
            priority: s.priority,
            weight: s.weight,
            port: s.port,
            target: s.target,
        },
        Rdata::Caa(c) => RecordKind::Caa {
            flags: c.flags,
            tag: map_caa_tag(c.tag),
            value: c.value,
        },
        Rdata::Https(h) => RecordKind::Https {
            priority: h.priority,
            target: h.target,
            params: map_params(h.params),
        },
        Rdata::Svcb(s) => RecordKind::Svcb {
            priority: s.priority,
            target: s.target,
            params: map_params(s.params),
        },
        Rdata::Ns(s) => RecordKind::Ns(s),
        Rdata::Ptr(s) => RecordKind::Ptr(s),
        Rdata::Tlsa(t) => RecordKind::Tlsa {
            usage: t.usage,
            selector: t.selector,
            matching: t.matching,
            data: t.data,
        },
    })
}

/// Map a guardrail refusal ([`validate_writable`]) to the guest-visible wire error. These are the
/// typed, actionable refusals (apex / unsupported / malformed) — never a silent drop.
fn map_guardrail_err(e: DnsError) -> dns_publish::PublishError {
    use dns_publish::PublishError as P;
    match e {
        // INFORMATIONAL-6: do NOT disclose the operator's DNS provider name to the guest — a generic
        // message only (the provider name is not the guest's to know).
        DnsError::UnsupportedRecordType { .. } => {
            P::Unsupported("unsupported record type for this zone".into())
        }
        DnsError::ApexNsRefused { zone, name } => P::ApexRefused(format!(
            "refusing apex NS for zone '{zone}' (name '{name}')"
        )),
        DnsError::InvalidRecord(m) => P::InvalidRecord(m),
        // `validate_writable` never returns these — map defensively to a generic backend error.
        DnsError::NotFound | DnsError::Config(_) | DnsError::Backend(_) => {
            P::Backend("dns write rejected".into())
        }
    }
}

/// Map a PROVIDER write failure to a GENERIC client-safe wire error — the provider's own message may
/// name an internal zone id, so it is logged host-side (by the caller) and never surfaced.
fn map_write_err(e: &DnsError) -> dns_publish::PublishError {
    use dns_publish::PublishError as P;
    match e {
        DnsError::Config(_) => P::Backend("dns provider not configured".into()),
        _ => P::Backend("dns backend write failed".into()),
    }
}

/// The per-invocation host view of the `dns-publish` capability. The binding, posture flag and budget
/// are all BORROWED from the store-resident `HostState` (see the module's STORE-RESIDENT note) — this
/// view is rebuilt on every host call, so it owns no mutable state of its own.
pub struct DnsPublishHost<'a> {
    binding: Option<&'a DnsPublishBinding>,
    /// The operator serve-static posture (`allow_guest_dns_publish`), carried from the store-resident
    /// `HostState`. Gates the operator path only (cap-req #24).
    posture_enabled: bool,
    /// The RUNTIME per-tenant posture (`allow_guest_dynamic_dns_publish`, cap-req #31), carried from the
    /// store-resident `HostState` exactly like `posture_enabled`. Gates `register`/`unregister` and the
    /// runtime routing path. INDEPENDENT of `posture_enabled`. `false` (the default) ⇒ the dynamic path
    /// is entirely inert (every register/unregister is `access-denied`; no record routes to a runtime
    /// credential — records fall through to the operator path).
    dynamic_posture_enabled: bool,
    /// The sub-zone `NS` delegation posture (Security review MEDIUM-3), carried from the store-resident
    /// `HostState` exactly like `posture_enabled`. Applied by [`prepare`] ONLY to a non-apex NS.
    ns_posture: GuestDnsPublishNs,
    budget: &'a AtomicU32,
}

impl<'a> DnsPublishHost<'a> {
    pub fn new(
        binding: Option<&'a DnsPublishBinding>,
        posture_enabled: bool,
        ns_posture: GuestDnsPublishNs,
        budget: &'a AtomicU32,
    ) -> Self {
        Self {
            binding,
            posture_enabled,
            dynamic_posture_enabled: false,
            ns_posture,
            budget,
        }
    }

    /// Set the RUNTIME per-tenant posture (`allow_guest_dynamic_dns_publish`, cap-req #31) for this view.
    /// Default (`false`) ⇒ the dynamic path is inert. The engine threads the resolved node posture here.
    #[must_use]
    pub fn with_dynamic_posture(mut self, enabled: bool) -> Self {
        self.dynamic_posture_enabled = enabled;
        self
    }

    /// Layer 1 (combined): the grant must be present AND at least one path is admissible — the operator
    /// path (operator writer present AND `allow_guest_dns_publish` on) OR the runtime path (registry
    /// present AND `allow_guest_dynamic_dns_publish` on). Deny-by-default, fail-closed. Checked BEFORE
    /// the budget, so a denied call can never burn a victim invocation's budget.
    fn admit_any(&self) -> Result<&'a DnsPublishBinding, dns_publish::PublishError> {
        let b = self
            .binding
            .ok_or(dns_publish::PublishError::AccessDenied)?;
        let operator_ok = b.operator.is_some() && self.posture_enabled;
        let runtime_ok = b.runtime.is_some() && self.dynamic_posture_enabled;
        if operator_ok || runtime_ok {
            Ok(b)
        } else {
            Err(dns_publish::PublishError::AccessDenied)
        }
    }

    /// Admit the RUNTIME path for `register`/`unregister` (cap-req #31): the registry must be present
    /// AND `allow_guest_dynamic_dns_publish` on. Fail-closed `access-denied` otherwise (no registry
    /// wired — e.g. no `[secrets]` envelope — reads as not-granted, exactly like the operator path).
    fn admit_runtime(&self) -> Result<&'a RuntimeDnsRegistry, dns_publish::PublishError> {
        let b = self
            .binding
            .ok_or(dns_publish::PublishError::AccessDenied)?;
        match b.runtime.as_ref() {
            Some(reg) if self.dynamic_posture_enabled => Ok(reg),
            _ => Err(dns_publish::PublishError::AccessDenied),
        }
    }

    /// If the runtime path is admitted and a registered credential covers `name` (already canonical),
    /// build the provider + return it with its authoritative registered `zone_root`. `Ok(None)` ⇒ no
    /// runtime credential covers this name (fall through to the operator path). An error is a hard
    /// store/seal/factory failure, surfaced generically.
    ///
    /// **Allowlist-removal is an effective revocation (Security review F1).** Routing re-checks the
    /// covering `zone_root` against the UPSERTING component's CURRENT `dynamic_dns_zones` allowlist
    /// before building the provider: if the operator has SHRUNK the allowlist to revoke a zone, an
    /// already-registered credential stops routing immediately (fall through — the sealed registration
    /// stays, but writes nothing until the zone is re-allowlisted). Without this re-check a de-allowlist
    /// would only take effect once the tenant itself unregistered.
    async fn runtime_route(
        &self,
        reg: &RuntimeDnsRegistry,
        name: &str,
    ) -> Result<Option<(Arc<dyn DnsProvider>, String)>, dns_publish::PublishError> {
        let roots = reg
            .store
            .registered_zone_roots(reg.project(), &reg.tenant)
            .await
            .map_err(map_store_err)?;
        let Some(zone_root) = longest_covering_zone_root(&roots, name).map(str::to_string) else {
            return Ok(None);
        };
        // F1: the registered zone-root must STILL be covered by this component's current allowlist — so
        // removing it from `dynamic_dns_zones` revokes routing without waiting on an unregister.
        if !zone_authorized(&reg.dynamic_zones, &zone_root) {
            return Ok(None);
        }
        let Some(cred) = reg
            .store
            .lookup(reg.project(), &reg.tenant, &zone_root)
            .await
            .map_err(map_store_err)?
        else {
            // Raced an unregister between the list and the lookup — treat as no runtime route.
            return Ok(None);
        };
        let kind = RuntimeDnsProviderKind::from_stored(&cred.provider_kind).ok_or_else(|| {
            dns_publish::PublishError::Backend("stored dns provider kind is unknown".into())
        })?;
        // The sealed bundle is the validated field map; deserialize it back for the factory.
        let fields = decode_fields(&cred.credential).ok_or_else(|| {
            dns_publish::PublishError::Backend("corrupt sealed dns credential".into())
        })?;
        // The per-tenancy cache scope — the project + resolved tenant — so a per-adapter token cache the
        // factory keys on it is reused across this tenant's calls but NEVER shared across tenants.
        let cache_scope = format!("{}\u{1f}{}", reg.project, reg.tenant);
        let provider = reg
            .factory
            .build(kind, &fields, &zone_root, &cache_scope)
            .map_err(|reason| {
                tracing::warn!(
                    target: "boatramp::dns::publish",
                    zone_root = %zone_root,
                    error = %reason,
                    "dns-publish runtime provider build failed",
                );
                dns_publish::PublishError::Backend("dns provider unavailable".into())
            })?;
        Ok(Some((provider, zone_root)))
    }

    /// Resolve ONE guest record to the provider that will write it + the validated [`AcmeRecord`],
    /// trying the RUNTIME path first (a registered credential covering the record's own name), then the
    /// OPERATOR serve-static path. Performs NO write and NO budget spend. The runtime path's own-name
    /// allowlist is the registered `zone_root` itself (`**.<zone_root>`, so the record must land at or
    /// under the zone the tenant proved it holds); its NS-target allowlist is empty (a runtime grant may
    /// not delegate a sub-zone NS under the `Allowlist` posture — deny-by-default for the tenant path).
    async fn resolve_one(
        &self,
        b: &'a DnsPublishBinding,
        wit: dns_publish::DnsRecord,
    ) -> Result<(Arc<dyn DnsProvider>, AcmeRecord), dns_publish::PublishError> {
        // Canonicalize once for routing (invalid ⇒ invalid-record before any path decision).
        let name = canonicalize_owner_name(&wit.name).map_err(map_guardrail_err)?;
        // RUNTIME path first (cap-req #31): a registered credential covering the name routes to it.
        if self.dynamic_posture_enabled
            && let Some(reg) = b.runtime.as_ref()
            && let Some((provider, zone_root)) = self.runtime_route(reg, &name).await?
        {
            let writable = [format!("**.{zone_root}")];
            let record = prepare(
                provider.as_ref(),
                &zone_root,
                &writable,
                &[],
                self.ns_posture,
                wit,
            )?;
            return Ok((provider, record));
        }
        // OPERATOR serve-static path (cap-req #24, UNCHANGED).
        if self.posture_enabled
            && let Some(op) = b.operator.as_ref()
        {
            let record = prepare(
                op.provider.as_ref(),
                &op.zone_root,
                &op.writable_zones,
                &op.ns_targets,
                self.ns_posture,
                wit,
            )?;
            return Ok((Arc::clone(&op.provider), record));
        }
        // Neither path is admissible for this record (posture off, or no operator provider and no
        // runtime credential covers it) ⇒ fail-closed.
        Err(dns_publish::PublishError::NotAuthorized(name))
    }

    /// Reserve `n` units of this invocation's (store-resident) publish budget, all-or-nothing.
    /// `rate-limited` once it cannot cover the request. `checked_sub` floors at 0 (no underflow/wrap);
    /// `Relaxed` is fine — a soft per-invocation bound, not a synchronization point. Spelled as an
    /// explicit CAS loop (not `fetch_update`) so it compiles clean on BOTH the pinned stable toolchain
    /// (`fetch_update` is deprecation-warned → a `-D warnings` error) and the declared MSRV.
    fn spend(&self, n: u32) -> Result<(), dns_publish::PublishError> {
        if n == 0 {
            return Ok(());
        }
        use std::sync::atomic::Ordering;
        let mut cur = self.budget.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_sub(n) else {
                return Err(dns_publish::PublishError::RateLimited);
            };
            match self
                .budget
                .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }
}

/// Layer 2 + the central guardrail for ONE record against a SELECTED provider + zone, with NO write and
/// NO budget spend (a failure here means NOTHING is written). Shared by BOTH the operator serve-static
/// path (cap-req #24) and the runtime per-tenant path (cap-req #31): the caller supplies the selected
/// `provider`, its authoritative `zone_root` (for the apex-NS guardrail), the own-name `writable_zones`
/// allowlist (empty ⇒ deny-all), and the `ns_targets` NS-target allowlist — so the two paths run the
/// IDENTICAL canonicalize → own-name-allowlist → build → `validate_writable` → NS-delegation gate.
///
/// **CRITICAL-1 / MEDIUM-2 — one canonical string for authorize AND dispatch.** The guest-supplied
/// owner `name` is [`canonicalize_owner_name`]'d FIRST (a syntactically-illegal name is `invalid-record`
/// BEFORE the allowlist); that canonical string is then used for BOTH the allowlist check and the
/// [`AcmeRecord::name`] dispatched to the adapter — byte-identical, so a name can never be authorized as
/// a normalized copy of a different raw string that escapes to another zone. The rdata TARGET is never
/// canonicalized or constrained here (it legitimately points elsewhere).
fn prepare(
    provider: &dyn DnsProvider,
    zone_root: &str,
    writable_zones: &[String],
    ns_targets: &[String],
    ns_posture: GuestDnsPublishNs,
    wit: dns_publish::DnsRecord,
) -> Result<AcmeRecord, dns_publish::PublishError> {
    // Canonicalize the guest name up front — invalid ⇒ invalid-record, before the allowlist.
    let name = canonicalize_owner_name(&wit.name).map_err(map_guardrail_err)?;
    // Layer 2: own-name allowlist (deny-empty), on the canonical name. The rdata TARGET is never
    // passed here.
    if !zone_authorized(writable_zones, &name) {
        return Err(dns_publish::PublishError::NotAuthorized(name));
    }
    let kind = build_kind(wit.data)?;
    let record = AcmeRecord {
        kind,
        name,
        ttl: wit.ttl,
    };
    // cap-req #27: the apex-NS guardrail needs the apex of the zone THIS record lands in. A single
    // provider has one configured `zone_root` (`UseConfigured`); a multi-zone routing provider selects
    // the per-record apex (`Zone`), or reports no authoritative zone (`NoZone` ⇒ fail closed). The write
    // dispatched below routes to the SAME selected zone, so the apex checked here matches the adapter.
    let selected_zone: std::borrow::Cow<'_, str> = match provider.resolve_zone_root(&record.name) {
        ZoneResolution::UseConfigured => std::borrow::Cow::Borrowed(zone_root),
        ZoneResolution::Zone(z) => std::borrow::Cow::Owned(z),
        ZoneResolution::NoZone => {
            return Err(dns_publish::PublishError::NotAuthorized(
                record.name.clone(),
            ));
        }
    };
    validate_writable(provider, &record, &selected_zone).map_err(map_guardrail_err)?;
    // MEDIUM-3: a surviving (non-apex) NS is gated by the sub-zone-delegation posture. The apex NS was
    // already refused by `validate_writable`, so this only ever sees a sub-zone NS.
    if let RecordKind::Ns(ref target) = record.kind {
        ns_delegation_authorized(ns_posture, ns_targets, target)?;
    }
    Ok(record)
}

/// Map a [`TenantDnsCredStore`] error to the guest-visible wire error (cap-req #31). A client error
/// (bad zone-root/tenant, oversized/absent token, too-many-zones) is surfaced as `invalid-record` with
/// its client-safe message; a conflict or backend failure is a GENERIC `backend` (its detail — KV key
/// shapes, a KMS status — is never surfaced).
fn map_store_err(e: SecretError) -> dns_publish::PublishError {
    use dns_publish::PublishError as P;
    match e {
        SecretError::InvalidName(m) | SecretError::InvalidTenant(m) => P::InvalidRecord(m),
        SecretError::ValueTooLarge { .. } => {
            P::InvalidRecord("dns credential token is too large".into())
        }
        SecretError::TooManyNames { max } => P::Backend(format!(
            "too many registered dns zone credentials for this tenant (max {max})"
        )),
        SecretError::Conflict(_) => {
            P::Backend("the dns credential store is contended; retry".into())
        }
        SecretError::Backend(_) => P::Backend("dns credential store error".into()),
    }
}

/// The registered zone-root (from `roots`) whose apex is the LONGEST label-boundary suffix of the
/// already-canonical owner `name` — i.e. the most specific registered zone the record falls under. The
/// DNS zone-containment used by the operator `RoutingDnsProvider`: `name` equals the apex, or `name`
/// ends with `.<root>`. `None` ⇒ no registered zone covers this name (the router falls through to the
/// operator path). `roots` are the tenant's own canonical registered zone-roots.
fn longest_covering_zone_root<'a>(roots: &'a [String], name: &str) -> Option<&'a str> {
    roots
        .iter()
        .map(String::as_str)
        .filter(|root| name == *root || name.ends_with(&format!(".{root}")))
        .max_by_key(|root| root.len())
}

/// Dispatch one prepared mutation to the provider and audit the outcome (redacted). A `delete` of an
/// already-absent record converges (idempotent teardown → `ok`). A backend failure is logged
/// host-side (detail) and surfaced generically.
async fn write_one(
    provider: &dyn DnsProvider,
    audit: &dyn DnsPublishAuditSink,
    record: &AcmeRecord,
    op: DnsPublishOp,
) -> Result<(), dns_publish::PublishError> {
    let res = match op {
        DnsPublishOp::Upsert => provider.upsert(record).await,
        DnsPublishOp::Delete => provider.delete(record).await,
    };
    let mapped = match res {
        Ok(()) => Ok(()),
        // A delete of an absent record is success (a retried teardown converges).
        Err(DnsError::NotFound) if matches!(op, DnsPublishOp::Delete) => Ok(()),
        Err(e) => {
            tracing::warn!(
                target: "boatramp::dns::publish",
                op = op.as_str(),
                name = %record.name,
                provider = provider.name(),
                error = %e,
                "dns-publish backend write failed",
            );
            Err(map_write_err(&e))
        }
    };
    let outcome = if mapped.is_ok() {
        DnsPublishOutcome::Applied
    } else {
        DnsPublishOutcome::Failed
    };
    audit.record(&DnsPublishAuditEntry {
        op,
        name: &record.name,
        kind: record.kind.tag(),
        provider: provider.name(),
        outcome,
    });
    mapped
}

/// Map the generated WIT `provider-kind` to the crate-local [`RuntimeDnsProviderKind`].
fn map_provider_kind(p: dns_publish::ProviderKind) -> RuntimeDnsProviderKind {
    match p {
        dns_publish::ProviderKind::Cloudflare => RuntimeDnsProviderKind::Cloudflare,
        dns_publish::ProviderKind::Route53 => RuntimeDnsProviderKind::Route53,
        dns_publish::ProviderKind::Oci => RuntimeDnsProviderKind::Oci,
        dns_publish::ProviderKind::Akamai => RuntimeDnsProviderKind::Akamai,
        dns_publish::ProviderKind::Dnsimple => RuntimeDnsProviderKind::Dnsimple,
        dns_publish::ProviderKind::Gcp => RuntimeDnsProviderKind::Gcp,
        dns_publish::ProviderKind::Azure => RuntimeDnsProviderKind::Azure,
        dns_publish::ProviderKind::Digitalocean => RuntimeDnsProviderKind::DigitalOcean,
        dns_publish::ProviderKind::Hetzner => RuntimeDnsProviderKind::Hetzner,
        dns_publish::ProviderKind::Ns1 => RuntimeDnsProviderKind::Ns1,
    }
}

impl dns_publish::Host for DnsPublishHost<'_> {
    async fn register_zone_credential(
        &mut self,
        zone_root: String,
        provider: dns_publish::ProviderKind,
        credential: Vec<dns_publish::CredentialField>,
    ) -> Result<(), dns_publish::PublishError> {
        // Layer 1: runtime registry present AND the dynamic posture on (fail-closed otherwise — no
        // registry wired, e.g. no `[secrets]` envelope, reads as not-granted).
        let reg = self.admit_runtime()?;
        // Canonicalize the zone-root with the SAME validator used for record owner names — one canonical
        // string for BOTH the allowlist check and the store key (the CRITICAL-1 invariant). A
        // syntactically-illegal zone-root is `invalid-record` before the allowlist.
        let canonical = canonicalize_owner_name(&zone_root).map_err(map_guardrail_err)?;
        // Layer 2: the zone-root must be in this component's `dynamic_dns_zones` allowlist (empty ⇒
        // deny-all), matched with the SAME glob semantics as the own-name `writable_zones` allowlist.
        if !zone_authorized(&reg.dynamic_zones, &canonical) {
            return Err(dns_publish::PublishError::AccessDenied);
        }
        let kind = map_provider_kind(provider);
        // Validate the bundle against the provider's field schema BEFORE sealing: reject unknown /
        // duplicate / missing-required fields and any value that fails its shape (a URL-path id carrying
        // `/`/`..`, a header secret carrying CR/LF/`"`, an oversized value). The guest-controlled values
        // never escape their interpolation context in the adapter.
        let fields: Vec<(String, String)> =
            credential.into_iter().map(|f| (f.name, f.value)).collect();
        let map = validate_credential_bundle(kind, fields)?;
        // Serialize the validated bundle to a compact blob and seal the WHOLE thing, keyed to THIS
        // invocation's resolved (project, tenant). No value is ever returned, logged, or echoed.
        let blob = encode_fields(&map);
        reg.store
            .register(reg.project(), &reg.tenant, &canonical, kind.as_str(), &blob)
            .await
            .map_err(map_store_err)?;
        tracing::info!(
            target: "boatramp::dns::publish",
            zone_root = %canonical,
            provider = kind.as_str(),
            "dns-publish: runtime zone credential registered (bundle sealed; no value surfaced)",
        );
        Ok(())
    }

    async fn unregister_zone_credential(
        &mut self,
        zone_root: String,
    ) -> Result<(), dns_publish::PublishError> {
        let reg = self.admit_runtime()?;
        let canonical = canonicalize_owner_name(&zone_root).map_err(map_guardrail_err)?;
        // The allowlist gates unregister too — a guest can only ever touch a zone it could have
        // registered (and only within its OWN resolved tenant's keyspace).
        if !zone_authorized(&reg.dynamic_zones, &canonical) {
            return Err(dns_publish::PublishError::AccessDenied);
        }
        // Idempotent: an already-absent credential is `ok` (existed/not is not surfaced).
        reg.store
            .unregister(reg.project(), &reg.tenant, &canonical)
            .await
            .map_err(map_store_err)?;
        Ok(())
    }

    async fn upsert(
        &mut self,
        record: dns_publish::DnsRecord,
    ) -> Result<(), dns_publish::PublishError> {
        let b = self.admit_any()?;
        let (provider, prepared) = self.resolve_one(b, record).await?;
        self.spend(1)?;
        write_one(
            provider.as_ref(),
            b.audit.as_ref(),
            &prepared,
            DnsPublishOp::Upsert,
        )
        .await
    }

    async fn delete(
        &mut self,
        record: dns_publish::DnsRecord,
    ) -> Result<(), dns_publish::PublishError> {
        let b = self.admit_any()?;
        let (provider, prepared) = self.resolve_one(b, record).await?;
        self.spend(1)?;
        write_one(
            provider.as_ref(),
            b.audit.as_ref(),
            &prepared,
            DnsPublishOp::Delete,
        )
        .await
    }

    async fn upsert_set(
        &mut self,
        records: Vec<dns_publish::DnsRecord>,
    ) -> Result<(), dns_publish::PublishError> {
        let b = self.admit_any()?;
        // LOW-4: fast-fail an over-budget set BEFORE the O(N) resolve/validate loop, so a guest cannot
        // force the host to do per-record work (incl. per-record store round-trips) for a set it could
        // never afford to write. Only an early-out; `spend` below is still the authoritative
        // all-or-nothing reservation.
        let remaining = self.budget.load(std::sync::atomic::Ordering::Relaxed);
        if records.len() as u64 > u64::from(remaining) {
            return Err(dns_publish::PublishError::RateLimited);
        }
        // Resolve + validate + gate EVERY record (routing each to its runtime or operator provider)
        // BEFORE writing any (fail-closed, all-or-nothing on validation): one bad record refuses the
        // whole set and nothing is written.
        let mut prepared: Vec<(Arc<dyn DnsProvider>, AcmeRecord)> =
            Vec::with_capacity(records.len());
        for r in records {
            prepared.push(self.resolve_one(b, r).await?);
        }
        // Reserve the whole set's budget up front — a set that cannot fit the budget writes NOTHING.
        self.spend(prepared.len() as u32)?;
        // Apply in order; upserts are idempotent, so a backend failure mid-set converges on retry.
        for (provider, record) in &prepared {
            write_one(
                provider.as_ref(),
                b.audit.as_ref(),
                record,
                DnsPublishOp::Upsert,
            )
            .await?;
        }
        Ok(())
    }
}

/// Add the `dns-publish` interface to `linker`, resolving the per-invocation [`DnsPublishHost`] view
/// via `host`.
struct LinkData;
impl wasmtime::component::HasData for LinkData {
    type Data<'a> = DnsPublishHost<'a>;
}

pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: fn(&mut T) -> DnsPublishHost<'_>,
) -> wasmtime::Result<()> {
    dns_publish::add_to_linker::<T, LinkData>(linker, host)
}

#[cfg(test)]
mod tests {
    use super::dns_publish::Host;
    use super::*;
    use boatramp_acme::dns::{DnsOp, DnsRecord as AcmeRecord};
    use std::sync::Mutex;
    use std::sync::atomic::Ordering;

    /// A test [`DnsProvider`] recording its ops, with a configurable supported-kind set and an optional
    /// forced backend failure.
    struct StubProvider {
        ops: Mutex<Vec<(DnsOp, AcmeRecord)>>,
        kinds: &'static [RecordKindTag],
        fail: bool,
        not_found: bool,
    }

    impl StubProvider {
        fn new(kinds: &'static [RecordKindTag]) -> Self {
            Self {
                ops: Mutex::new(Vec::new()),
                kinds,
                fail: false,
                not_found: false,
            }
        }
        fn count(&self) -> usize {
            self.ops.lock().unwrap().len()
        }
    }

    #[async_trait::async_trait]
    impl DnsProvider for StubProvider {
        async fn upsert(&self, record: &AcmeRecord) -> Result<(), DnsError> {
            if self.fail {
                return Err(DnsError::Backend("boom".into()));
            }
            self.ops
                .lock()
                .unwrap()
                .push((DnsOp::Upsert, record.clone()));
            Ok(())
        }
        async fn delete(&self, record: &AcmeRecord) -> Result<(), DnsError> {
            if self.not_found {
                return Err(DnsError::NotFound);
            }
            self.ops
                .lock()
                .unwrap()
                .push((DnsOp::Delete, record.clone()));
            Ok(())
        }
        fn supported_kinds(&self) -> &'static [RecordKindTag] {
            self.kinds
        }
        fn name(&self) -> &'static str {
            "stub"
        }
    }

    const FIRST_CLASS: &[RecordKindTag] = &[
        RecordKindTag::A,
        RecordKindTag::Aaaa,
        RecordKindTag::Cname,
        RecordKindTag::Txt,
        RecordKindTag::Mx,
        RecordKindTag::Ns,
    ];
    const BASIC: &[RecordKindTag] = &[
        RecordKindTag::A,
        RecordKindTag::Aaaa,
        RecordKindTag::Cname,
        RecordKindTag::Txt,
    ];

    /// One collected audit row (op, record name, type, provider, outcome) — never the rdata value.
    type AuditRow = (
        DnsPublishOp,
        String,
        RecordKindTag,
        &'static str,
        DnsPublishOutcome,
    );

    /// A collecting audit sink: records every entry as an owned tuple so a test can assert what was
    /// logged (and that it is redacted — no rdata value is ever present to log).
    #[derive(Default)]
    struct CollectingSink {
        entries: Mutex<Vec<AuditRow>>,
    }
    impl DnsPublishAuditSink for CollectingSink {
        fn record(&self, e: &DnsPublishAuditEntry<'_>) {
            self.entries.lock().unwrap().push((
                e.op,
                e.name.to_string(),
                e.kind,
                e.provider,
                e.outcome,
            ));
        }
    }

    fn binding_with(
        provider: Arc<StubProvider>,
        zone_root: &str,
        zones: &[&str],
    ) -> DnsPublishBinding {
        // No NS-target allowlist by default (the non-NS tests + the `Any`-posture NS test don't need
        // one; `Any` ignores it and `None` refuses regardless).
        binding_with_ns(provider, zone_root, zones, &[])
    }

    /// Like [`binding_with`] but with an explicit NS-target allowlist, for the MEDIUM-3 sub-zone-NS
    /// delegation tests under the `Allowlist` posture.
    fn binding_with_ns(
        provider: Arc<StubProvider>,
        zone_root: &str,
        zones: &[&str],
        ns_targets: &[&str],
    ) -> DnsPublishBinding {
        DnsPublishBinding::new(
            provider,
            zone_root,
            zones.iter().map(|s| (*s).to_string()).collect(),
            ns_targets.iter().map(|s| (*s).to_string()).collect(),
            Arc::new(TracingDnsPublishSink),
        )
    }

    fn rec(name: &str, data: dns_publish::Rdata) -> dns_publish::DnsRecord {
        dns_publish::DnsRecord {
            name: name.into(),
            ttl: 300,
            data,
        }
    }

    fn a_record(name: &str, ip: &str) -> dns_publish::DnsRecord {
        rec(name, dns_publish::Rdata::A(ip.into()))
    }

    fn budget(n: u32) -> AtomicU32 {
        AtomicU32::new(n)
    }

    /// The default redacted audit sink, as the host installs it.
    fn audit_sink() -> Arc<dyn DnsPublishAuditSink> {
        Arc::new(TracingDnsPublishSink)
    }

    /// A host view over `b` + `bud` with the runtime posture ON and operator posture `op_posture`
    /// (a free fn rather than a closure so the shared `'a` lifetime is expressible).
    fn dyn_host<'a>(
        b: &'a DnsPublishBinding,
        op_posture: bool,
        bud: &'a AtomicU32,
    ) -> DnsPublishHost<'a> {
        DnsPublishHost::new(Some(b), op_posture, GuestDnsPublishNs::Any, bud)
            .with_dynamic_posture(true)
    }

    #[tokio::test]
    async fn ungranted_is_access_denied() {
        let bud = budget(16);
        let mut host = DnsPublishHost::new(None, true, GuestDnsPublishNs::Any, &bud);
        assert!(matches!(
            host.upsert(a_record("x.example.com", "203.0.113.7")).await,
            Err(dns_publish::PublishError::AccessDenied)
        ));
        // A denied call must not consume the budget (can't be a denial-amplifier).
        assert_eq!(bud.load(Ordering::Relaxed), 16);
    }

    #[tokio::test]
    async fn posture_off_is_access_denied_even_when_granted() {
        let p = Arc::new(StubProvider::new(BASIC));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        // granted (Some) but posture OFF ⇒ denied, fail-closed.
        let mut host = DnsPublishHost::new(Some(&b), false, GuestDnsPublishNs::Any, &bud);
        assert!(matches!(
            host.upsert(a_record("x.example.com", "203.0.113.7")).await,
            Err(dns_publish::PublishError::AccessDenied)
        ));
        assert_eq!(p.count(), 0, "nothing written when posture off");
        assert_eq!(bud.load(Ordering::Relaxed), 16, "denied call keeps budget");
    }

    #[tokio::test]
    async fn allowlist_allows_in_zone_rejects_out_of_zone() {
        let p = Arc::new(StubProvider::new(BASIC));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        // In-zone own name is allowed and written.
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            host.upsert(a_record("www.example.com", "203.0.113.7"))
                .await
                .expect("in-zone upsert ok");
        }
        assert_eq!(p.count(), 1);
        // An out-of-zone own name is refused (and nothing more is written).
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            let err = host
                .upsert(a_record("www.evil.com", "203.0.113.7"))
                .await
                .unwrap_err();
            assert!(
                matches!(err, dns_publish::PublishError::NotAuthorized(ref n) if n == "www.evil.com"),
                "out-of-zone own name refused: {err:?}"
            );
        }
        assert_eq!(p.count(), 1, "out-of-zone write never reached the provider");
    }

    #[tokio::test]
    async fn rdata_target_out_of_zone_is_allowed() {
        // The SECURITY-CRITICAL scoping property: the allowlist constrains the record's OWN name only.
        // A CNAME/MX whose TARGET points outside the zone is a NORMAL record and must be ALLOWED.
        let p = Arc::new(StubProvider::new(FIRST_CLASS));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        // CNAME at an in-zone name pointing to an out-of-zone target.
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            host.upsert(rec(
                "www.example.com",
                dns_publish::Rdata::Cname("lb.other-domain.net".into()),
            ))
            .await
            .expect("CNAME to foreign target allowed");
        }
        // MX at the apex pointing to another domain's mail host (the direct-MX relay shape).
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            host.upsert(rec(
                "example.com",
                dns_publish::Rdata::Mx(dns_publish::MxData {
                    preference: 10,
                    exchange: "mail.shared-host.net".into(),
                }),
            ))
            .await
            .expect("MX to foreign exchange allowed");
        }
        assert_eq!(p.count(), 2, "both foreign-target records were written");
    }

    #[tokio::test]
    async fn empty_allowlist_denies_all() {
        let p = Arc::new(StubProvider::new(BASIC));
        let b = binding_with(p.clone(), "example.com", &[]); // empty ⇒ deny-all
        let bud = budget(16);
        let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
        assert!(matches!(
            host.upsert(a_record("www.example.com", "203.0.113.7"))
                .await,
            Err(dns_publish::PublishError::NotAuthorized(_))
        ));
        assert_eq!(p.count(), 0);
    }

    #[tokio::test]
    async fn unsupported_kind_is_refused_not_dropped() {
        // BASIC provider cannot write MX; the guardrail refuses it explicitly (never a silent drop).
        let p = Arc::new(StubProvider::new(BASIC));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
        let err = host
            .upsert(rec(
                "example.com",
                dns_publish::Rdata::Mx(dns_publish::MxData {
                    preference: 10,
                    exchange: "mail.example.com".into(),
                }),
            ))
            .await
            .unwrap_err();
        assert!(
            matches!(err, dns_publish::PublishError::Unsupported(_)),
            "unsupported kind: {err:?}"
        );
        assert_eq!(p.count(), 0);
        assert_eq!(
            bud.load(Ordering::Relaxed),
            16,
            "refused record keeps budget"
        );
    }

    #[tokio::test]
    async fn apex_ns_is_refused_but_subzone_ns_allowed() {
        let p = Arc::new(StubProvider::new(FIRST_CLASS)); // supports NS, so only the apex rule can refuse
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        // Apex NS (name == zone_root) is refused.
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            let err = host
                .upsert(rec(
                    "example.com",
                    dns_publish::Rdata::Ns("ns1.example.net".into()),
                ))
                .await
                .unwrap_err();
            assert!(
                matches!(err, dns_publish::PublishError::ApexRefused(_)),
                "apex NS refused: {err:?}"
            );
        }
        // Sub-zone NS delegation is allowed.
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            host.upsert(rec(
                "sub.example.com",
                dns_publish::Rdata::Ns("ns1.example.net".into()),
            ))
            .await
            .expect("subzone NS allowed");
        }
        assert_eq!(p.count(), 1, "only the subzone NS was written");
    }

    // ---- MEDIUM-3: sub-zone NS delegation posture --------------------------

    /// Posture `None`: a sub-zone NS is refused even though the grant is present, the posture is on,
    /// and the record's OWN name is squarely inside the writable-zone allowlist. Nothing is written and
    /// no budget is spent (the refusal is pre-write). An NS is a persistent delegation handoff, so a
    /// multi-tenant guest may not create one at all.
    #[tokio::test]
    async fn ns_posture_none_refuses_subzone_ns() {
        let p = Arc::new(StubProvider::new(FIRST_CLASS)); // provider supports NS — only the posture can refuse
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::None, &bud);
        let err = host
            .upsert(rec(
                "sub.example.com", // own name IS in the zone allowlist
                dns_publish::Rdata::Ns("ns1.example.net".into()),
            ))
            .await
            .unwrap_err();
        assert!(
            matches!(err, dns_publish::PublishError::NotAuthorized(ref m) if m.contains("none")),
            "sub-zone NS refused under posture none: {err:?}"
        );
        assert_eq!(p.count(), 0, "no NS written under posture none");
        assert_eq!(
            bud.load(Ordering::Relaxed),
            16,
            "a pre-write NS refusal burns no budget"
        );
    }

    /// Posture `Allowlist`: a sub-zone NS whose rdata TARGET is on the per-grant `dns_publish_ns_targets`
    /// allowlist is written; one whose target is outside it is refused (nothing written). The OWN name
    /// is in the writable-zone allowlist in BOTH cases — only the NS TARGET differs — so this isolates
    /// the new NS-target constraint from the unchanged own-name allowlist.
    #[tokio::test]
    async fn ns_posture_allowlist_gates_the_ns_target() {
        let p = Arc::new(StubProvider::new(FIRST_CLASS));
        // The operator sanctions only its own nameservers (any depth under example.net).
        let b = binding_with_ns(
            p.clone(),
            "example.com",
            &["**.example.com"],
            &["**.example.net"],
        );
        let bud = budget(16);
        // In-allowlist NS target ⇒ delegation written.
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Allowlist, &bud);
            host.upsert(rec(
                "sub.example.com",
                dns_publish::Rdata::Ns("ns1.example.net".into()),
            ))
            .await
            .expect("NS to an allowlisted target is written");
        }
        assert_eq!(p.count(), 1);
        // Out-of-allowlist NS target ⇒ refused, nothing further written.
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Allowlist, &bud);
            let err = host
                .upsert(rec(
                    "sub.example.com", // same (allowed) own name
                    dns_publish::Rdata::Ns("ns1.attacker.test".into()),
                ))
                .await
                .unwrap_err();
            assert!(
                matches!(err, dns_publish::PublishError::NotAuthorized(ref m) if m.contains("attacker.test")),
                "NS to a non-allowlisted target refused: {err:?}"
            );
        }
        assert_eq!(
            p.count(),
            1,
            "the out-of-allowlist NS never reached the provider"
        );
    }

    /// Posture `Allowlist` with an EMPTY `dns_publish_ns_targets` ⇒ deny-all for sub-zone NS
    /// (fail-closed), even when the record's own name is in the writable-zone allowlist. A grant that
    /// names no NS targets can delegate to none.
    #[tokio::test]
    async fn ns_posture_allowlist_empty_denies_all_ns() {
        let p = Arc::new(StubProvider::new(FIRST_CLASS));
        let b = binding_with_ns(p.clone(), "example.com", &["**.example.com"], &[]); // empty NS allowlist
        let bud = budget(16);
        let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Allowlist, &bud);
        let err = host
            .upsert(rec(
                "sub.example.com",
                dns_publish::Rdata::Ns("ns1.example.net".into()),
            ))
            .await
            .unwrap_err();
        assert!(
            matches!(err, dns_publish::PublishError::NotAuthorized(_)),
            "empty NS allowlist + posture allowlist ⇒ deny-all: {err:?}"
        );
        assert_eq!(p.count(), 0);
    }

    /// Non-NS records (A/MX/CNAME/…) are UNAFFECTED by the NS posture: even under the strictest NS
    /// posture (`None`) they are gated solely by the own-name writable-zone allowlist, exactly as
    /// before. An A record and a CNAME whose target points outside the zone both still pass.
    #[tokio::test]
    async fn ns_posture_does_not_affect_non_ns_records() {
        let p = Arc::new(StubProvider::new(FIRST_CLASS));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        // An A record at an in-zone name — allowed under posture None (NS posture is irrelevant to A).
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::None, &bud);
            host.upsert(a_record("www.example.com", "203.0.113.7"))
                .await
                .expect("A record unaffected by the NS posture");
        }
        // A CNAME whose TARGET points outside the zone — still allowed under posture None (the NS
        // posture gates only NS targets, never a CNAME target).
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::None, &bud);
            host.upsert(rec(
                "www.example.com",
                dns_publish::Rdata::Cname("lb.other-domain.net".into()),
            ))
            .await
            .expect("CNAME to a foreign target unaffected by the NS posture");
        }
        assert_eq!(
            p.count(),
            2,
            "both non-NS records were written under posture none"
        );
    }

    /// The NS target is canonicalized with the SAME validator used for the owner name before matching,
    /// so a legitimate-but-non-canonical target (uppercase + trailing dot) matches the allowlist, while
    /// a syntactically-illegal target is `invalid-record` (never silently authorized).
    #[tokio::test]
    async fn ns_posture_allowlist_canonicalizes_the_target() {
        let p = Arc::new(StubProvider::new(FIRST_CLASS));
        let b = binding_with_ns(
            p.clone(),
            "example.com",
            &["**.example.com"],
            &["**.example.net"],
        );
        let bud = budget(16);
        // Uppercase + trailing dot canonicalizes to `ns1.example.net`, which the allowlist matches.
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Allowlist, &bud);
            host.upsert(rec(
                "sub.example.com",
                dns_publish::Rdata::Ns("NS1.Example.NET.".into()),
            ))
            .await
            .expect("non-canonical allowlisted NS target is authorized");
        }
        // A syntactically-illegal target is invalid-record (before any allowlist decision).
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Allowlist, &bud);
            let err = host
                .upsert(rec(
                    "sub.example.com",
                    dns_publish::Rdata::Ns("../../evil.example.net".into()),
                ))
                .await
                .unwrap_err();
            assert!(
                matches!(err, dns_publish::PublishError::InvalidRecord(_)),
                "an illegal NS target is invalid-record: {err:?}"
            );
        }
        assert_eq!(
            p.count(),
            1,
            "only the canonical, allowlisted NS was written"
        );
    }

    #[tokio::test]
    async fn malformed_rdata_is_refused() {
        let p = Arc::new(StubProvider::new(BASIC));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        // A bad IPv4 literal → invalid-record (build fails).
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            assert!(matches!(
                host.upsert(a_record("www.example.com", "not-an-ip")).await,
                Err(dns_publish::PublishError::InvalidRecord(_))
            ));
        }
        // An over-long TXT character-string → invalid-record (validate_writable).
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            assert!(matches!(
                host.upsert(rec(
                    "www.example.com",
                    dns_publish::Rdata::Txt(vec!["a".repeat(256)])
                ))
                .await,
                Err(dns_publish::PublishError::InvalidRecord(_))
            ));
        }
        assert_eq!(p.count(), 0);
    }

    /// STORE-RESIDENCE proof (the HIGH-1 footgun): the budget MUST persist across the per-call REBUILD
    /// of the view. Reproduce it exactly — ONE store-resident budget cell + ONE store-resident binding,
    /// a NEW `DnsPublishHost` view per call — and assert the cap holds ACROSS ≥2 views. A view-local
    /// counter would restart every call and never limit, so this goes RED against that regression.
    #[tokio::test]
    async fn budget_caps_across_view_rebuilds() {
        const N: u32 = 4;
        let p = Arc::new(StubProvider::new(BASIC));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(N); // the store-resident cell, shared across rebuilt views
        for i in 0..N {
            let mut view = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud); // rebuilt per call
            view.upsert(a_record(&format!("r{i}.example.com"), "203.0.113.7"))
                .await
                .unwrap_or_else(|e| panic!("call {i} within budget: {e:?}"));
        }
        // A FRESH view on the SAME cell is now exhausted — proves the counter is store-resident (and the
        // allowlist, held in the shared binding, kept authorizing every one of the ≥2 calls).
        let mut view = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
        assert!(matches!(
            view.upsert(a_record("over.example.com", "203.0.113.7"))
                .await,
            Err(dns_publish::PublishError::RateLimited)
        ));
        assert_eq!(
            p.count(),
            N as usize,
            "exactly N writes reached the provider"
        );
        // A DIFFERENT cell (a new invocation) gets a fresh budget.
        let bud2 = budget(N);
        let mut other = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud2);
        other
            .upsert(a_record("fresh.example.com", "203.0.113.7"))
            .await
            .expect("a new invocation's budget is fresh");
    }

    #[tokio::test]
    async fn upsert_set_reserves_whole_budget_up_front() {
        // A set larger than the remaining budget writes NOTHING (all-or-nothing reservation).
        let p = Arc::new(StubProvider::new(BASIC));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(2);
        let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
        let set = vec![
            a_record("a.example.com", "203.0.113.1"),
            a_record("b.example.com", "203.0.113.2"),
            a_record("c.example.com", "203.0.113.3"),
        ];
        assert!(matches!(
            host.upsert_set(set).await,
            Err(dns_publish::PublishError::RateLimited)
        ));
        assert_eq!(p.count(), 0, "an over-budget set writes nothing");
        assert_eq!(
            bud.load(Ordering::Relaxed),
            2,
            "budget untouched on refusal"
        );
    }

    #[tokio::test]
    async fn upsert_set_is_all_or_nothing_on_validation() {
        // One unsupported record in the set refuses the whole set; nothing is written.
        let p = Arc::new(StubProvider::new(BASIC)); // no MX
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
        let set = vec![
            a_record("a.example.com", "203.0.113.1"),
            rec(
                "b.example.com",
                dns_publish::Rdata::Mx(dns_publish::MxData {
                    preference: 10,
                    exchange: "mx.example.com".into(),
                }),
            ),
        ];
        assert!(matches!(
            host.upsert_set(set).await,
            Err(dns_publish::PublishError::Unsupported(_))
        ));
        assert_eq!(p.count(), 0, "a set with one bad record writes nothing");
        assert_eq!(
            bud.load(Ordering::Relaxed),
            16,
            "budget untouched on validation failure"
        );
    }

    #[tokio::test]
    async fn delete_of_absent_record_is_success() {
        let mut provider = StubProvider::new(BASIC);
        provider.not_found = true;
        let p = Arc::new(provider);
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
        host.delete(a_record("gone.example.com", "203.0.113.7"))
            .await
            .expect("delete of absent record converges to ok");
    }

    #[tokio::test]
    async fn backend_failure_is_generic_and_audited_failed() {
        let mut provider = StubProvider::new(BASIC);
        provider.fail = true;
        let p = Arc::new(provider);
        let sink = Arc::new(CollectingSink::default());
        let b = DnsPublishBinding::new(
            p.clone(),
            "example.com",
            vec!["**.example.com".into()],
            Vec::new(),
            sink.clone(),
        );
        let bud = budget(16);
        let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
        let err = host
            .upsert(a_record("www.example.com", "203.0.113.7"))
            .await
            .unwrap_err();
        // The provider's raw "boom" never surfaces — only a generic backend reason.
        match err {
            dns_publish::PublishError::Backend(m) => assert!(!m.contains("boom"), "redacted: {m}"),
            other => panic!("expected Backend, got {other:?}"),
        }
        let entries = sink.entries.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].4, DnsPublishOutcome::Failed, "audited as failed");
    }

    /// The audit log records every mutation, REDACTED (name + type + provider + outcome, never rdata),
    /// and the sink (store-resident in the binding) accumulates across ≥2 rebuilt views.
    #[tokio::test]
    async fn audit_records_redacted_mutations_across_calls() {
        let p = Arc::new(StubProvider::new(BASIC));
        let sink = Arc::new(CollectingSink::default());
        let b = DnsPublishBinding::new(
            p.clone(),
            "example.com",
            vec!["**.example.com".into()],
            Vec::new(),
            sink.clone(),
        );
        let bud = budget(16);
        // Two calls through two REBUILT views sharing the one store-resident binding + sink.
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            host.upsert(rec(
                "_dmarc.example.com",
                // A TXT whose VALUE must never appear in the audit log (redaction proof).
                dns_publish::Rdata::Txt(vec!["v=DMARC1; p=reject; secret-token=abc123".into()]),
            ))
            .await
            .unwrap();
        }
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            host.delete(a_record("old.example.com", "203.0.113.9"))
                .await
                .unwrap();
        }
        let entries = sink.entries.lock().unwrap();
        assert_eq!(
            entries.len(),
            2,
            "both mutations audited across rebuilt views"
        );
        assert_eq!(entries[0].0, DnsPublishOp::Upsert);
        assert_eq!(entries[0].1, "_dmarc.example.com");
        assert_eq!(entries[0].2, RecordKindTag::Txt);
        assert_eq!(entries[0].3, "stub");
        assert_eq!(entries[0].4, DnsPublishOutcome::Applied);
        assert_eq!(entries[1].0, DnsPublishOp::Delete);
        // Redaction: no audited field carries the rdata value.
        for e in entries.iter() {
            assert!(!e.1.contains("secret-token"), "name never carries rdata");
        }
    }

    // ---- CRITICAL-1 / MEDIUM-2: owner-name canonicalization gate ----------

    /// The cross-tenant zone-escape proof. Every attack owner name — notably the
    /// `../../zones/victim.com/evil.example.com` traversal that the raw dispatch
    /// would have normalized into another zone's URL path, plus whitespace and the
    /// URL-structural bytes — is refused as `invalid-record` and NEVER reaches the
    /// provider. Each name ENDS with `.example.com`, so the `**.example.com`
    /// allowlist WOULD have authorized it had canonicalization not refused it
    /// first.
    #[tokio::test]
    async fn attack_names_are_invalid_record_and_never_dispatched() {
        let p = Arc::new(StubProvider::new(BASIC));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(64);
        let attacks = [
            "../../zones/victim.com/evil.example.com",
            "evil/../example.com",
            " example.com",
            "example.com ",
            "evil?x.example.com",
            "evil#x.example.com",
            "evil%2e.example.com",
            "evil@x.example.com",
            "evil:8080.example.com",
            "evil..example.com",
            ".example.com",
        ];
        for a in attacks {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            let err = host
                .upsert(a_record(a, "203.0.113.7"))
                .await
                .expect_err("attack name must be refused");
            assert!(
                matches!(err, dns_publish::PublishError::InvalidRecord(_)),
                "attack {a:?} must be invalid-record, got {err:?}"
            );
        }
        // An overlong label is likewise invalid-record.
        {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            let overlong = format!("{}.example.com", "a".repeat(64));
            assert!(matches!(
                host.upsert(a_record(&overlong, "203.0.113.7")).await,
                Err(dns_publish::PublishError::InvalidRecord(_))
            ));
        }
        assert_eq!(p.count(), 0, "no attack name ever reached the provider");
        assert_eq!(
            bud.load(Ordering::Relaxed),
            64,
            "a refused (pre-write) call burns no budget"
        );
    }

    /// The authorized string is byte-identical to the dispatched string: a
    /// legitimate-but-non-canonical name (uppercase + trailing dot) is authorized
    /// and the provider is handed the SAME canonical form the allowlist matched —
    /// never the raw `wit.name`. This is the invariant that closes the
    /// authorize-a-copy / dispatch-the-raw split.
    #[tokio::test]
    async fn authorized_name_is_byte_identical_to_dispatched_name() {
        let p = Arc::new(StubProvider::new(BASIC));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
        host.upsert(a_record("WWW.Example.COM.", "203.0.113.7"))
            .await
            .expect("legit non-canonical name is authorized");
        let ops = p.ops.lock().unwrap();
        assert_eq!(ops.len(), 1);
        // The dispatched record carries the canonical name — not "WWW.Example.COM.".
        assert_eq!(ops[0].1.name, "www.example.com");
    }

    /// Legitimate names across the real shapes still pass end-to-end: an ACME
    /// challenge owner (underscore labels), a wildcard, and a trailing-dot apex-ish
    /// name are each authorized and dispatched in canonical form.
    #[tokio::test]
    async fn legitimate_names_still_pass() {
        let p = Arc::new(StubProvider::new(BASIC));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        for (raw, want) in [
            (
                "_acme-challenge.deploy.example.com",
                "_acme-challenge.deploy.example.com",
            ),
            ("*.example.com", "*.example.com"),
            ("mail.example.com.", "mail.example.com"),
        ] {
            let mut host = DnsPublishHost::new(Some(&b), true, GuestDnsPublishNs::Any, &bud);
            host.upsert(a_record(raw, "203.0.113.7"))
                .await
                .unwrap_or_else(|e| panic!("legit name {raw:?} should pass: {e:?}"));
            let ops = p.ops.lock().unwrap();
            assert_eq!(
                ops.last().unwrap().1.name,
                want,
                "dispatched name for {raw:?}"
            );
        }
        assert_eq!(p.count(), 3);
    }

    // ---- cap-req #31: RUNTIME per-tenant credential path -------------------

    use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::project::ProjectRef;
    use boatramp_core::secret_store::TenantDnsCredStore;

    /// A reversible test envelope (XOR) — so a sealed token is visibly different at rest yet round-trips.
    struct XorEnvelope;
    #[async_trait::async_trait]
    impl KeyEnvelope for XorEnvelope {
        async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(p.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn unwrap(&self, w: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(w.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    /// A fake provider factory: records every `(kind, fields, zone_root)` it is asked to build (so a
    /// test can prove routing handed the registered credential bundle to the adapter) and returns a
    /// shared capturing [`StubProvider`] regardless — it NEVER touches a real DNS provider.
    /// One recorded factory build: `(kind, fields, zone_root)`.
    type FactoryBuild = (
        RuntimeDnsProviderKind,
        std::collections::BTreeMap<String, String>,
        String,
    );

    struct FakeFactory {
        provider: Arc<StubProvider>,
        builds: Mutex<Vec<FactoryBuild>>,
        /// The `cache_scope` passed on each build — so a test can assert two tenants get DISTINCT scopes
        /// (the token-cache-isolation invariant).
        scopes: Mutex<Vec<String>>,
    }
    impl FakeFactory {
        fn new(provider: Arc<StubProvider>) -> Self {
            Self {
                provider,
                builds: Mutex::new(Vec::new()),
                scopes: Mutex::new(Vec::new()),
            }
        }
    }
    impl RuntimeDnsProviderFactory for FakeFactory {
        fn build(
            &self,
            kind: RuntimeDnsProviderKind,
            fields: &std::collections::BTreeMap<String, String>,
            zone_root: &str,
            cache_scope: &str,
        ) -> Result<Arc<dyn DnsProvider>, String> {
            self.scopes.lock().unwrap().push(cache_scope.to_string());
            self.builds
                .lock()
                .unwrap()
                .push((kind, fields.clone(), zone_root.to_string()));
            Ok(Arc::clone(&self.provider) as Arc<dyn DnsProvider>)
        }
    }

    /// Build one WIT credential field.
    fn cfield(name: &str, value: &str) -> dns_publish::CredentialField {
        dns_publish::CredentialField {
            name: name.into(),
            value: value.into(),
        }
    }
    /// A Cloudflare credential bundle (`zone_id` + `token`).
    fn cloudflare_cred(zone_id: &str, token: &str) -> Vec<dns_publish::CredentialField> {
        vec![cfield("zone_id", zone_id), cfield("token", token)]
    }
    /// A single-`token` bundle (hetzner / digitalocean).
    fn token_cred(token: &str) -> Vec<dns_publish::CredentialField> {
        vec![cfield("token", token)]
    }
    /// An NS1 bundle (`api_key`).
    fn apikey_cred(key: &str) -> Vec<dns_publish::CredentialField> {
        vec![cfield("api_key", key)]
    }
    /// An Akamai bundle with a given `host` (the fields the EdgeGrid adapter needs).
    fn akamai_cred(host: &str) -> Vec<dns_publish::CredentialField> {
        vec![
            cfield("host", host),
            cfield("client_token", "ct"),
            cfield("client_secret", "cs"),
            cfield("access_token", "at"),
        ]
    }
    /// A minimal, VALID GCP service-account JSON (parseable, with the required keys + a PEM key marker).
    const VALID_SA_JSON: &str = concat!(
        r#"{"client_email":"dns@acme.iam.gserviceaccount.com","project_id":"acme-proj","#,
        r#""private_key":"-----BEGIN PRIVATE KEY-----\nMIIBVAIB\n-----END PRIVATE KEY-----\n"}"#,
    );
    /// A GCP bundle (`service_account_json` + `managed_zone`) with a given SA JSON.
    fn gcp_cred(sa_json: &str) -> Vec<dns_publish::CredentialField> {
        vec![
            cfield("service_account_json", sa_json),
            cfield("managed_zone", "acme-managed-zone"),
        ]
    }
    /// An Azure bundle (service principal) with a given `tenant_id`.
    fn azure_cred(tenant_id: &str) -> Vec<dns_publish::CredentialField> {
        vec![
            cfield("tenant_id", tenant_id),
            cfield("client_id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            cfield("client_secret", "sp-secret"),
            cfield("subscription_id", "99999999-8888-7777-6666-555555555555"),
            cfield("resource_group", "rg-1"),
        ]
    }

    fn cred_store() -> TenantDnsCredStore {
        TenantDnsCredStore::new(Arc::new(MemoryKv::new()), Arc::new(XorEnvelope))
    }

    /// A runtime registry for `tenant` over `store`, registerable zones = `["**.{zone}"]`, with a fake
    /// factory wrapping `provider`. Returns the registry + a handle to the factory (to read its builds).
    fn registry(
        store: TenantDnsCredStore,
        tenant: &str,
        zone: &str,
        provider: Arc<StubProvider>,
    ) -> (RuntimeDnsRegistry, Arc<FakeFactory>) {
        let factory = Arc::new(FakeFactory::new(provider));
        let reg = RuntimeDnsRegistry::new(
            store,
            factory.clone() as Arc<dyn RuntimeDnsProviderFactory>,
            "proj",
            tenant,
            vec![format!("**.{zone}")],
        );
        (reg, factory)
    }

    /// Posture ON: a guest registers a Cloudflare runtime credential for an ALLOWLISTED zone-root, then
    /// an `upsert` to a name under it ROUTES to the registered credential (the fake factory is handed
    /// the sealed token + zone-id) and the record reaches the (fake) provider. The WIT returns carry no
    /// token.
    #[tokio::test]
    async fn dynamic_register_then_upsert_routes_to_runtime_cred() {
        let store = cred_store();
        let provider = Arc::new(StubProvider::new(BASIC));
        let (reg, factory) = registry(store, "tenant-a", "acme.com", provider.clone());
        let b = DnsPublishBinding::runtime_only(reg, audit_sink());
        let bud = budget(16);

        // Register (posture on).
        {
            let mut host = DnsPublishHost::new(Some(&b), false, GuestDnsPublishNs::Any, &bud)
                .with_dynamic_posture(true);
            host.register_zone_credential(
                "acme.com".into(),
                dns_publish::ProviderKind::Cloudflare,
                cloudflare_cred("cfzoneid01", "cf-secret-token"),
            )
            .await
            .expect("register an allowlisted zone");
        }
        // Upsert under the registered zone → routes to the runtime credential.
        {
            let mut host = DnsPublishHost::new(Some(&b), false, GuestDnsPublishNs::Any, &bud)
                .with_dynamic_posture(true);
            host.upsert(a_record("www.acme.com", "203.0.113.7"))
                .await
                .expect("in-zone runtime-routed upsert ok");
        }
        assert_eq!(
            provider.count(),
            1,
            "the record reached the runtime provider"
        );
        assert_eq!(provider.ops.lock().unwrap()[0].1.name, "www.acme.com");
        // The factory was handed the SEALED-then-unsealed registered credential.
        let builds = factory.builds.lock().unwrap();
        assert_eq!(builds.len(), 1);
        assert_eq!(builds[0].0, RuntimeDnsProviderKind::Cloudflare);
        assert_eq!(
            builds[0].1.get("zone_id").map(String::as_str),
            Some("cfzoneid01")
        );
        assert_eq!(
            builds[0].1.get("token").map(String::as_str),
            Some("cf-secret-token")
        );
        assert_eq!(builds[0].2, "acme.com");
    }

    /// Posture OFF: `register` is `access-denied` (nothing stored) AND a record that WOULD route to a
    /// runtime credential does not — it falls through (here to no operator ⇒ `not-authorized`).
    #[tokio::test]
    async fn dynamic_posture_off_denies_register_and_route() {
        let store = cred_store();
        let provider = Arc::new(StubProvider::new(BASIC));
        let (reg, _f) = registry(store.clone(), "tenant-a", "acme.com", provider.clone());
        let b = DnsPublishBinding::runtime_only(reg, audit_sink());
        let bud = budget(16);
        // register with dynamic posture OFF ⇒ access-denied.
        let mut host = DnsPublishHost::new(Some(&b), false, GuestDnsPublishNs::Any, &bud); // dynamic=false
        assert!(matches!(
            host.register_zone_credential(
                "acme.com".into(),
                dns_publish::ProviderKind::Hetzner,
                token_cred("tok"),
            )
            .await,
            Err(dns_publish::PublishError::AccessDenied)
        ));
        // Nothing was stored.
        assert!(
            store
                .registered_zone_roots(ProjectRef::new("proj"), "tenant-a")
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// A zone-root OUTSIDE the per-component `dynamic_dns_zones` allowlist ⇒ `access-denied` (even with
    /// the posture on), and nothing is stored.
    #[tokio::test]
    async fn register_disallowed_zone_is_access_denied() {
        let store = cred_store();
        let (reg, _f) = registry(
            store.clone(),
            "tenant-a",
            "acme.com",
            Arc::new(StubProvider::new(BASIC)),
        );
        let b = DnsPublishBinding::runtime_only(reg, audit_sink());
        let bud = budget(16);
        let mut host = DnsPublishHost::new(Some(&b), false, GuestDnsPublishNs::Any, &bud)
            .with_dynamic_posture(true);
        assert!(matches!(
            host.register_zone_credential(
                "evil.example".into(), // not under **.acme.com
                dns_publish::ProviderKind::Hetzner,
                token_cred("tok"),
            )
            .await,
            Err(dns_publish::PublishError::AccessDenied)
        ));
        assert!(
            store
                .registered_zone_roots(ProjectRef::new("proj"), "tenant-a")
                .await
                .unwrap()
                .is_empty()
        );
    }

    /// `unregister` removes the credential; a subsequent `upsert` falls through (here, with no operator
    /// writer, to `not-authorized`).
    #[tokio::test]
    async fn unregister_removes_and_upsert_falls_through() {
        let store = cred_store();
        let provider = Arc::new(StubProvider::new(BASIC));
        let (reg, _f) = registry(store, "tenant-a", "acme.com", provider.clone());
        let b = DnsPublishBinding::runtime_only(reg, audit_sink());
        let bud = budget(16);
        // Distinct host views, one shared binding + budget (store-resident).
        {
            let mut h = dyn_host(&b, false, &bud);
            h.register_zone_credential(
                "acme.com".into(),
                dns_publish::ProviderKind::Ns1,
                apikey_cred("tok"),
            )
            .await
            .unwrap();
        }
        {
            let mut h = dyn_host(&b, false, &bud);
            h.upsert(a_record("www.acme.com", "203.0.113.7"))
                .await
                .expect("routes while registered");
        }
        assert_eq!(provider.count(), 1);
        {
            let mut h = dyn_host(&b, false, &bud);
            h.unregister_zone_credential("acme.com".into())
                .await
                .expect("unregister ok");
        }
        {
            let mut h = dyn_host(&b, false, &bud);
            let err = h
                .upsert(a_record("www.acme.com", "203.0.113.7"))
                .await
                .unwrap_err();
            assert!(
                matches!(err, dns_publish::PublishError::NotAuthorized(_)),
                "after unregister, no runtime cred and no operator ⇒ fall-through fail-closed: {err:?}"
            );
        }
        assert_eq!(provider.count(), 1, "nothing published after unregister");
    }

    /// THE tenancy isolation property at the host seam: tenant-b (a SECOND host view over the SAME store,
    /// resolved to a different tenant) can neither ROUTE through nor UNREGISTER tenant-a's credential.
    #[tokio::test]
    async fn cross_tenant_cannot_route_or_unregister() {
        let store = cred_store();
        let provider_a = Arc::new(StubProvider::new(BASIC));
        let provider_b = Arc::new(StubProvider::new(BASIC));
        let (reg_a, _fa) = registry(store.clone(), "tenant-a", "acme.com", provider_a.clone());
        let (reg_b, _fb) = registry(store.clone(), "tenant-b", "acme.com", provider_b.clone());
        let b_a = DnsPublishBinding::runtime_only(reg_a, audit_sink());
        let b_b = DnsPublishBinding::runtime_only(reg_b, audit_sink());
        let bud = budget(16);

        // tenant-a registers its own credential.
        {
            let mut h = DnsPublishHost::new(Some(&b_a), false, GuestDnsPublishNs::Any, &bud)
                .with_dynamic_posture(true);
            h.register_zone_credential(
                "acme.com".into(),
                dns_publish::ProviderKind::Hetzner,
                token_cred("a-secret"),
            )
            .await
            .unwrap();
        }
        // tenant-b cannot ROUTE an upsert to acme.com (it has no credential of its own) → falls through
        // to no-operator ⇒ not-authorized. Nothing reaches tenant-b's provider.
        {
            let mut h = DnsPublishHost::new(Some(&b_b), false, GuestDnsPublishNs::Any, &bud)
                .with_dynamic_posture(true);
            let err = h
                .upsert(a_record("www.acme.com", "203.0.113.7"))
                .await
                .unwrap_err();
            assert!(matches!(err, dns_publish::PublishError::NotAuthorized(_)));
        }
        assert_eq!(provider_b.count(), 0, "tenant-b published nothing");
        // tenant-b "unregistering" acme.com touches only its OWN (empty) keyspace — tenant-a's cred
        // survives, and tenant-a can still route.
        {
            let mut h = DnsPublishHost::new(Some(&b_b), false, GuestDnsPublishNs::Any, &bud)
                .with_dynamic_posture(true);
            h.unregister_zone_credential("acme.com".into())
                .await
                .expect("idempotent no-op on tenant-b's own keyspace");
        }
        {
            let mut h = DnsPublishHost::new(Some(&b_a), false, GuestDnsPublishNs::Any, &bud)
                .with_dynamic_posture(true);
            h.upsert(a_record("mx.acme.com", "203.0.113.9"))
                .await
                .expect("tenant-a's credential survives tenant-b's unregister");
        }
        assert_eq!(
            provider_a.count(),
            1,
            "tenant-a still routes after tenant-b's attempt"
        );
    }

    /// Operator serve-static + runtime per-tenant coexist on ONE binding and route PER ZONE: a record in
    /// F1: removing a zone from `dynamic_dns_zones` revokes routing immediately, even while the sealed
    /// credential is still registered — and re-allowlisting restores it (the registration survived).
    #[tokio::test]
    async fn f1_allowlist_removal_revokes_routing() {
        let store = cred_store();
        let provider = Arc::new(StubProvider::new(BASIC));
        // Register through an allowlisting registry.
        let (reg_ok, _f) = registry(store.clone(), "t", "acme.com", provider.clone());
        let b_ok = DnsPublishBinding::runtime_only(reg_ok, audit_sink());
        let bud = budget(16);
        {
            let mut h = dyn_host(&b_ok, false, &bud);
            h.register_zone_credential(
                "acme.com".into(),
                dns_publish::ProviderKind::Ns1,
                apikey_cred("k"),
            )
            .await
            .unwrap();
            h.upsert(a_record("www.acme.com", "203.0.113.1"))
                .await
                .expect("routes");
        }
        assert_eq!(provider.count(), 1);
        // A registry whose allowlist no longer covers acme.com ⇒ the SAME upsert no longer routes.
        let revoked_provider = Arc::new(StubProvider::new(BASIC));
        let factory = Arc::new(FakeFactory::new(revoked_provider.clone()));
        let reg_revoked = RuntimeDnsRegistry::new(
            store.clone(),
            factory as Arc<dyn RuntimeDnsProviderFactory>,
            "proj",
            "t",
            vec!["**.other.example".to_string()],
        );
        let b_revoked = DnsPublishBinding::runtime_only(reg_revoked, audit_sink());
        {
            let mut h = dyn_host(&b_revoked, false, &bud);
            assert!(matches!(
                h.upsert(a_record("www.acme.com", "203.0.113.1")).await,
                Err(dns_publish::PublishError::NotAuthorized(_))
            ));
        }
        assert_eq!(
            revoked_provider.count(),
            0,
            "de-allowlisted zone wrote nothing"
        );
        // Re-allowlisting restores routing (the credential was never unregistered).
        {
            let mut h = dyn_host(&b_ok, false, &bud);
            h.upsert(a_record("mx.acme.com", "203.0.113.2"))
                .await
                .expect("routes again");
        }
        assert_eq!(provider.count(), 2);
    }

    /// F2: a malformed (path-traversal / separator-bearing) zone-id is refused at register, before
    /// sealing; a well-formed alphanumeric one (Cloudflare's 32-hex shape) is accepted.
    #[tokio::test]
    async fn f2_zone_id_shape_is_validated() {
        let store = cred_store();
        let (reg, _f) = registry(
            store.clone(),
            "t",
            "acme.com",
            Arc::new(StubProvider::new(BASIC)),
        );
        let b = DnsPublishBinding::runtime_only(reg, audit_sink());
        let bud = budget(16);
        for bad in [
            "../../evil",
            "a/b",
            "a.b",
            "a:b",
            "a%2e",
            "has space",
            &"z".repeat(200), // over the 128-byte OpaqueId bound
        ] {
            let mut h = dyn_host(&b, true, &bud);
            assert!(
                matches!(
                    h.register_zone_credential(
                        "acme.com".into(),
                        dns_publish::ProviderKind::Cloudflare,
                        cloudflare_cred(bad, "tok"),
                    )
                    .await,
                    Err(dns_publish::PublishError::InvalidRecord(_))
                ),
                "zone-id {bad:?} must be refused"
            );
        }
        // Nothing was stored by any refused register.
        assert!(
            store
                .registered_zone_roots(ProjectRef::new("proj"), "t")
                .await
                .unwrap()
                .is_empty()
        );
        // A canonical 32-hex zone-id is accepted.
        {
            let mut h = dyn_host(&b, true, &bud);
            h.register_zone_credential(
                "acme.com".into(),
                dns_publish::ProviderKind::Cloudflare,
                cloudflare_cred("da8e3fe9a1b24c6f90ab12cd34ef5678", "tok"),
            )
            .await
            .expect("a well-formed zone-id is accepted");
        }
    }

    /// M1: the Akamai `host` (the only tenant-controlled request AUTHORITY) is PINNED to the EdgeGrid
    /// API domain — internal hosts / IP literals / non-akamaiapis.net hosts are refused at register
    /// (blind-SSRF closed), while a real `*.akamaiapis.net` host is accepted.
    #[tokio::test]
    async fn m1_akamai_host_pinned_to_edgegrid_domain() {
        let store = cred_store();
        let (reg, _f) = registry(
            store.clone(),
            "t",
            "acme.com",
            Arc::new(StubProvider::new(BASIC)),
        );
        let b = DnsPublishBinding::runtime_only(reg, audit_sink());
        let bud = budget(16);
        for bad in [
            "localhost",
            "10.0.0.5",
            "169.254.169.254",
            "metadata.google.internal",
            "evil.attacker.com",
            "akamaiapis.net",                // bare apex, no subdomain
            "x.akamaiapis.net.attacker.com", // suffix not at the end
            "akab-h.luna.akamaiapis.net.",   // trailing dot ⇒ empty last label
            "::1",
            "[::1]",
        ] {
            let mut h = dyn_host(&b, true, &bud);
            assert!(
                matches!(
                    h.register_zone_credential(
                        "acme.com".into(),
                        dns_publish::ProviderKind::Akamai,
                        akamai_cred(bad),
                    )
                    .await,
                    Err(dns_publish::PublishError::InvalidRecord(_))
                ),
                "akamai host {bad:?} must be refused (SSRF pin)"
            );
        }
        // A real EdgeGrid API host is accepted.
        {
            let mut h = dyn_host(&b, true, &bud);
            h.register_zone_credential(
                "acme.com".into(),
                dns_publish::ProviderKind::Akamai,
                akamai_cred("akab-h.luna.akamaiapis.net"),
            )
            .await
            .expect("a valid *.akamaiapis.net host is accepted");
        }
    }

    /// i1: the `Identifier` shape rejects an empty dot-segment (`..`, a leading/trailing dot) for
    /// `account_id`/`project`/`subscription_id`/`resource_group`.
    #[test]
    fn i1_identifier_rejects_empty_dot_segment() {
        for bad in ["..", ".", "a..b", ".a", "a."] {
            assert!(
                validate_field_value("account_id", CredentialFieldShape::Identifier, bad).is_err(),
                "identifier {bad:?} must be refused"
            );
        }
        // A legitimate dotted/hyphenated id is still fine.
        assert!(
            validate_field_value("project", CredentialFieldShape::Identifier, "my-proj.1").is_ok()
        );
    }

    /// The PER-PROVIDER FIELD CONTRACT (#31-wide): for EVERY provider kind, a representative valid
    /// bundle passes `validate_credential_bundle` and round-trips through the `encode_fields`/
    /// `decode_fields` codec, AND dropping any one required field is refused. Locks the field-name set
    /// the host validates + the server factory consumes (they must stay in sync).
    #[test]
    fn every_provider_field_contract_validates_and_round_trips() {
        use RuntimeDnsProviderKind::*;
        // (kind, a representative valid bundle of (name,value) — required fields only).
        let cases: &[(RuntimeDnsProviderKind, &[(&str, &str)])] = &[
            (Cloudflare, &[("zone_id", "abc123"), ("token", "t")]),
            (
                Route53,
                &[
                    ("access_key_id", "AKIAEXAMPLE"),
                    ("secret_access_key", "s"),
                    ("region", "us-east-1"),
                    ("hosted_zone_id", "Z123"),
                ],
            ),
            (
                Oci,
                &[
                    ("region", "us-ashburn-1"),
                    (
                        "key_id",
                        "ocid1.tenancy.oc1..aaaa/ocid1.user.oc1..bbbb/aa:bb:cc",
                    ),
                    (
                        "private_key_pem",
                        "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
                    ),
                ],
            ),
            (
                Akamai,
                &[
                    ("host", "akab-xxx.luna.akamaiapis.net"),
                    ("client_token", "ct"),
                    ("client_secret", "cs"),
                    ("access_token", "at"),
                ],
            ),
            (Dnsimple, &[("account_id", "12345"), ("token", "t")]),
            (
                Gcp,
                &[
                    (
                        "service_account_json",
                        r#"{"client_email":"d@p.iam.gserviceaccount.com","project_id":"p","private_key":"-----BEGIN PRIVATE KEY-----\nMII\n-----END PRIVATE KEY-----\n"}"#,
                    ),
                    ("managed_zone", "my-zone-1"),
                ],
            ),
            (
                Azure,
                &[
                    ("tenant_id", "11111111-2222-3333-4444-555555555555"),
                    ("client_id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                    ("client_secret", "cs"),
                    ("subscription_id", "99999999-8888-7777-6666-555555555555"),
                    ("resource_group", "rg_1"),
                ],
            ),
            (DigitalOcean, &[("token", "t")]),
            (Hetzner, &[("token", "t")]),
            (Ns1, &[("api_key", "k")]),
        ];
        for (kind, fields) in cases {
            let bundle: Vec<(String, String)> = fields
                .iter()
                .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
                .collect();
            let map = validate_credential_bundle(*kind, bundle)
                .unwrap_or_else(|e| panic!("{kind:?} valid bundle should pass: {e:?}"));
            // Codec round-trips.
            let decoded = decode_fields(&encode_fields(&map)).expect("decode");
            assert_eq!(decoded, map, "{kind:?} codec round-trip");
            // Dropping each required field is refused.
            for drop in *fields {
                let partial: Vec<(String, String)> = fields
                    .iter()
                    .filter(|(n, _)| *n != drop.0)
                    .map(|(n, v)| ((*n).to_string(), (*v).to_string()))
                    .collect();
                assert!(
                    validate_credential_bundle(*kind, partial).is_err(),
                    "{kind:?} missing required `{}` must be refused",
                    drop.0
                );
            }
        }
    }

    /// F4: `DnsZoneCred`'s `Debug` redacts the WHOLE credential bundle (a stray `{:?}` can never leak
    /// any sealed value).
    #[test]
    fn f4_dns_zone_cred_debug_redacts_token() {
        let cred = boatramp_core::secret_store::DnsZoneCred {
            provider_kind: "cloudflare".into(),
            credential: b"token=SUPER-SECRET".to_vec(),
        };
        let shown = format!("{cred:?}");
        assert!(
            !shown.contains("SUPER-SECRET"),
            "credential must be redacted: {shown}"
        );
        assert!(shown.contains("redacted"));
    }

    /// Operator serve-static + runtime per-tenant coexist on ONE binding and route PER ZONE: a record in
    /// the operator's zone uses the operator writer; a record in a registered runtime zone uses the
    /// runtime credential. Neither path leaks into the other.
    #[tokio::test]
    async fn operator_and_runtime_coexist_route_per_zone() {
        let op_provider = Arc::new(StubProvider::new(BASIC));
        let rt_provider = Arc::new(StubProvider::new(BASIC));
        let store = cred_store();
        let (reg, _f) = registry(store, "tenant-a", "tenant.example", rt_provider.clone());
        // Operator writer over op.example + the runtime registry over **.tenant.example.
        let b = DnsPublishBinding::new(
            op_provider.clone() as Arc<dyn DnsProvider>,
            "op.example",
            vec!["**.op.example".to_string()],
            Vec::new(),
            audit_sink(),
        )
        .with_runtime(reg);
        let bud = budget(16);
        // Register the runtime credential.
        {
            let mut h = dyn_host(&b, true, &bud);
            h.register_zone_credential(
                "tenant.example".into(),
                dns_publish::ProviderKind::Ns1,
                apikey_cred("rt-tok"),
            )
            .await
            .unwrap();
        }
        // A record in the operator zone → operator provider.
        {
            let mut h = dyn_host(&b, true, &bud);
            h.upsert(a_record("www.op.example", "203.0.113.1"))
                .await
                .expect("operator-zone upsert ok");
        }
        // A record in the registered runtime zone → runtime provider.
        {
            let mut h = dyn_host(&b, true, &bud);
            h.upsert(a_record("mx.tenant.example", "203.0.113.2"))
                .await
                .expect("runtime-zone upsert ok");
        }
        assert_eq!(op_provider.count(), 1, "exactly the operator-zone record");
        assert_eq!(op_provider.ops.lock().unwrap()[0].1.name, "www.op.example");
        assert_eq!(rt_provider.count(), 1, "exactly the runtime-zone record");
        assert_eq!(
            rt_provider.ops.lock().unwrap()[0].1.name,
            "mx.tenant.example"
        );
    }

    /// The cap-req #31 LIVE CAPABILITY GATE (marker: `DNS-PUBLISH TENANT-CREDS LIVE OK`). One end-to-end
    /// run over the REAL `TenantDnsCredStore` (a contract-faithful sealing envelope — production uses the
    /// `[secrets]` LocalKek/Vault AEAD) + a FAKE provider factory (NO real DNS provider is contacted),
    /// proving every promised property AND structured so each required MUTATION turns it RED:
    ///  - posture-gated register of an ALLOWLISTED zone-root → a subsequent `upsert` ROUTES to the
    ///    registered credential (the fake factory is handed the unsealed token);
    ///  - the sealed token is NEVER cleartext at rest and never returned;
    ///  - `unregister` removes it → the next `upsert` falls through / fail-closes;
    ///  - a DISALLOWED zone-root register → `access-denied` (DROP the allowlist check ⇒ RED);
    ///  - posture OFF → `access-denied` (DROP the posture check ⇒ RED);
    ///  - a SECOND tenant cannot see/use/unregister tenant-1's credential (DROP the tenancy key ⇒ RED);
    ///  - the operator serve-static path is unchanged.
    #[tokio::test(flavor = "multi_thread")]
    async fn tenant_creds_live_gate() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let store = TenantDnsCredStore::new(kv.clone(), Arc::new(XorEnvelope));
        let project = ProjectRef::new("proj");
        let bud = budget(64);

        // Operator serve-static writer (op.example) + a runtime registry for tenant-1 (**.t1.example).
        let op_provider = Arc::new(StubProvider::new(BASIC));
        let t1_provider = Arc::new(StubProvider::new(BASIC));
        let (reg1, factory1) =
            registry(store.clone(), "tenant-1", "t1.example", t1_provider.clone());
        let b1 = DnsPublishBinding::new(
            op_provider.clone() as Arc<dyn DnsProvider>,
            "op.example",
            vec!["**.op.example".to_string()],
            Vec::new(),
            audit_sink(),
        )
        .with_runtime(reg1);

        // (1) Posture OFF ⇒ register is access-denied (DROP the posture check ⇒ this assertion RED).
        {
            let mut h = DnsPublishHost::new(Some(&b1), true, GuestDnsPublishNs::Any, &bud); // dynamic OFF
            assert!(matches!(
                h.register_zone_credential(
                    "t1.example".into(),
                    dns_publish::ProviderKind::Cloudflare,
                    cloudflare_cred("zid", "should-not-store"),
                )
                .await,
                Err(dns_publish::PublishError::AccessDenied)
            ));
        }
        assert!(
            store
                .registered_zone_roots(project, "tenant-1")
                .await
                .unwrap()
                .is_empty(),
            "posture-off register stored nothing"
        );

        // (2) A DISALLOWED zone-root register ⇒ access-denied (DROP the allowlist check ⇒ RED).
        {
            let mut h = dyn_host(&b1, true, &bud);
            assert!(matches!(
                h.register_zone_credential(
                    "evil.example".into(),
                    dns_publish::ProviderKind::Hetzner,
                    token_cred("should-not-store"),
                )
                .await,
                Err(dns_publish::PublishError::AccessDenied)
            ));
        }

        // (3) Posture ON + allowlisted zone ⇒ register seals the token.
        {
            let mut h = dyn_host(&b1, true, &bud);
            h.register_zone_credential(
                "t1.example".into(),
                dns_publish::ProviderKind::Cloudflare,
                cloudflare_cred("cfzoneid01", "SECRET-cf-token"),
            )
            .await
            .expect("register an allowlisted zone");
        }
        // Sealed at rest: NO raw KV value anywhere contains the cleartext token.
        {
            let all = kv.scan_prefix("project/").await.unwrap();
            assert!(!all.is_empty(), "the credential was stored");
            for (_k, v) in &all {
                assert!(
                    !String::from_utf8_lossy(v).contains("SECRET-cf-token"),
                    "the provider token must be sealed at rest (never cleartext in any KV value)"
                );
            }
        }

        // (4) An upsert under the registered zone ROUTES to the runtime credential (fake provider), and
        // the factory was handed the unsealed token.
        {
            let mut h = dyn_host(&b1, true, &bud);
            h.upsert(rec(
                "_dmarc.t1.example",
                dns_publish::Rdata::Txt(vec!["v=DMARC1; p=reject".into()]),
            ))
            .await
            .expect("runtime-routed upsert ok");
        }
        assert_eq!(
            t1_provider.count(),
            1,
            "the record reached the runtime provider"
        );
        {
            let builds = factory1.builds.lock().unwrap();
            assert_eq!(builds.len(), 1);
            assert_eq!(builds[0].0, RuntimeDnsProviderKind::Cloudflare);
            assert_eq!(
                builds[0].1.get("zone_id").map(String::as_str),
                Some("cfzoneid01")
            );
            assert_eq!(
                builds[0].1.get("token").map(String::as_str),
                Some("SECRET-cf-token"),
                "the factory got the unsealed token"
            );
        }

        // (5) The operator serve-static path is UNCHANGED (a record in op.example uses op_provider).
        {
            let mut h = dyn_host(&b1, true, &bud);
            h.upsert(a_record("www.op.example", "203.0.113.1"))
                .await
                .expect("operator-zone upsert ok");
        }
        assert_eq!(op_provider.count(), 1, "operator path unchanged");

        // (6) A SECOND tenant cannot ROUTE or UNREGISTER tenant-1's credential (DROP the tenancy key ⇒
        // RED). tenant-2's registry shares the SAME store but a different resolved tenant.
        let t2_provider = Arc::new(StubProvider::new(BASIC));
        let (reg2, _f2) = registry(store.clone(), "tenant-2", "t1.example", t2_provider.clone());
        let b2 = DnsPublishBinding::runtime_only(reg2, audit_sink());
        {
            let mut h = dyn_host(&b2, false, &bud);
            // tenant-2 has no credential for t1.example ⇒ falls through to no-operator ⇒ not-authorized.
            assert!(matches!(
                h.upsert(a_record("www.t1.example", "203.0.113.9")).await,
                Err(dns_publish::PublishError::NotAuthorized(_))
            ));
        }
        assert_eq!(
            t2_provider.count(),
            0,
            "tenant-2 published nothing of tenant-1's"
        );
        {
            let mut h = dyn_host(&b2, false, &bud);
            h.unregister_zone_credential("t1.example".into())
                .await
                .expect("idempotent no-op on tenant-2's own keyspace");
        }
        // tenant-1's credential survived.
        assert!(
            store
                .lookup(project, "tenant-1", "t1.example")
                .await
                .unwrap()
                .is_some(),
            "tenant-1's credential survives tenant-2's unregister attempt"
        );

        // (7) tenant-1 unregisters → a subsequent upsert falls through / fail-closes.
        {
            let mut h = dyn_host(&b1, false, &bud); // operator posture off to isolate the runtime path
            h.unregister_zone_credential("t1.example".into())
                .await
                .expect("unregister ok");
        }
        {
            let mut h = dyn_host(&b1, false, &bud);
            assert!(matches!(
                h.upsert(a_record("mx.t1.example", "203.0.113.7")).await,
                Err(dns_publish::PublishError::NotAuthorized(_))
            ));
        }
        assert_eq!(
            t1_provider.count(),
            1,
            "nothing more published after unregister"
        );

        // (8) F1 — allowlist removal is an effective revocation. Re-register the credential, confirm it
        // routes, then over a registry whose `dynamic_dns_zones` NO LONGER covers the zone (operator
        // shrank the allowlist) the SAME upsert stops routing — WITHOUT any unregister. (DROP the
        // route-time re-check ⇒ this assertion RED.)
        {
            let mut h = dyn_host(&b1, false, &bud);
            h.register_zone_credential(
                "t1.example".into(),
                dns_publish::ProviderKind::Hetzner,
                token_cred("re-registered"),
            )
            .await
            .expect("re-register ok");
        }
        {
            let mut h = dyn_host(&b1, false, &bud);
            h.upsert(a_record("mx.t1.example", "203.0.113.7"))
                .await
                .expect("routes while allowlisted");
        }
        assert_eq!(t1_provider.count(), 2, "routed after re-register");
        // A registry (same store + tenant) whose allowlist no longer covers t1.example.
        let t1_revoked_provider = Arc::new(StubProvider::new(BASIC));
        let (reg_revoked, _fr) = {
            let factory = Arc::new(FakeFactory::new(t1_revoked_provider.clone()));
            (
                RuntimeDnsRegistry::new(
                    store.clone(),
                    factory.clone() as Arc<dyn RuntimeDnsProviderFactory>,
                    "proj",
                    "tenant-1",
                    vec!["**.other.example".to_string()], // t1.example REMOVED
                ),
                factory,
            )
        };
        let b1_revoked = DnsPublishBinding::runtime_only(reg_revoked, audit_sink());
        {
            let mut h = dyn_host(&b1_revoked, false, &bud);
            assert!(
                matches!(
                    h.upsert(a_record("mx.t1.example", "203.0.113.7")).await,
                    Err(dns_publish::PublishError::NotAuthorized(_))
                ),
                "a de-allowlisted zone must stop routing even though the credential is still registered"
            );
        }
        assert_eq!(
            t1_revoked_provider.count(),
            0,
            "revoked-allowlist wrote nothing"
        );

        // (9) F2 — a malformed (path-traversal) zone-id is refused at register, before sealing. (DROP
        // the zone-id shape check ⇒ this assertion RED.)
        {
            let mut h = dyn_host(&b1, true, &bud);
            assert!(matches!(
                h.register_zone_credential(
                    "t1.example".into(),
                    dns_publish::ProviderKind::Cloudflare,
                    cloudflare_cred("../../evil", "tok"),
                )
                .await,
                Err(dns_publish::PublishError::InvalidRecord(_))
            ));
        }

        // (10) A REPRESENTATIVE MULTI-SECRET provider (Route 53): a full 4-field bundle registers →
        // seals → routes, and the factory is handed every field. Proves the credential-field-map shape
        // (not just a single token) end-to-end.
        let r53_fields = vec![
            cfield("access_key_id", "AKIAIOSFODNN7EXAMPLE"),
            cfield(
                "secret_access_key",
                "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY",
            ),
            cfield("region", "us-east-1"),
            cfield("hosted_zone_id", "Z1234567890ABC"),
        ];
        {
            let mut h = dyn_host(&b1, false, &bud);
            h.register_zone_credential(
                "rt.t1.example".into(),
                dns_publish::ProviderKind::Route53,
                r53_fields.clone(),
            )
            .await
            .expect("a multi-secret route53 bundle registers");
            h.upsert(a_record("mx.rt.t1.example", "203.0.113.5"))
                .await
                .expect("route53-routed upsert ok");
        }
        {
            let builds = factory1.builds.lock().unwrap();
            let last = builds.last().expect("a route53 build was recorded");
            assert_eq!(last.0, RuntimeDnsProviderKind::Route53);
            assert_eq!(
                last.1.get("secret_access_key").map(String::as_str),
                Some("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"),
                "the factory got the unsealed multi-secret bundle"
            );
            assert_eq!(last.1.get("region").map(String::as_str), Some("us-east-1"));
            assert_eq!(last.2, "rt.t1.example");
        }
        // The whole multi-secret bundle is sealed at rest (no value appears in any KV plaintext).
        {
            let all = kv.scan_prefix("project/").await.unwrap();
            for (_k, v) in &all {
                let s = String::from_utf8_lossy(v);
                assert!(
                    !s.contains("wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY")
                        && !s.contains("AKIAIOSFODNN7EXAMPLE"),
                    "every route53 secret must be sealed at rest"
                );
            }
        }

        // (11) PER-PROVIDER VALIDATION — a route53 bundle MISSING a required field, carrying an UNKNOWN
        // field, or an OVERSIZED field is `invalid-record` before sealing. (DROP the bundle validation ⇒
        // these turn RED.)
        {
            let missing: Vec<_> = r53_fields
                .iter()
                .filter(|f| f.name != "region")
                .cloned()
                .collect();
            let mut unknown = r53_fields.clone();
            unknown.push(cfield("not_a_field", "x"));
            let mut oversized = r53_fields.clone();
            oversized[0].value = "A".repeat(200); // access_key_id over the 128-byte Identifier bound
            for bad in [missing, unknown, oversized] {
                let mut h = dyn_host(&b1, true, &bud);
                assert!(
                    matches!(
                        h.register_zone_credential(
                            "rt.t1.example".into(),
                            dns_publish::ProviderKind::Route53,
                            bad,
                        )
                        .await,
                        Err(dns_publish::PublishError::InvalidRecord(_))
                    ),
                    "an invalid route53 bundle must be refused"
                );
            }
        }

        // (12) M1 — the Akamai `host` (the only tenant-controlled request AUTHORITY) is PINNED to the
        // EdgeGrid API domain: an internal host / IP / metadata address is refused at register (blind
        // SSRF closed), a real `*.akamaiapis.net` host is accepted. (DROP the Akamai host-pin ⇒ the
        // internal-host case turns RED.)
        for bad in [
            "10.0.0.5",
            "localhost",
            "169.254.169.254",
            "evil.example.com",
        ] {
            let mut h = dyn_host(&b1, true, &bud);
            assert!(
                matches!(
                    h.register_zone_credential(
                        "t1.example".into(),
                        dns_publish::ProviderKind::Akamai,
                        akamai_cred(bad),
                    )
                    .await,
                    Err(dns_publish::PublishError::InvalidRecord(_))
                ),
                "akamai host {bad:?} must be refused at register (SSRF pin)"
            );
        }
        {
            let mut h = dyn_host(&b1, true, &bud);
            h.register_zone_credential(
                "t1.example".into(),
                dns_publish::ProviderKind::Akamai,
                akamai_cred("akab-h.luna.akamaiapis.net"),
            )
            .await
            .expect("a valid *.akamaiapis.net akamai host is accepted");
        }

        // (13) GCP (service-account JSON) + Azure (service principal) LONG-LIVED credentials register
        // and seal; a malformed SA JSON or a bad-GUID Azure tenant_id is refused at register. (DROP the
        // service-account-json / GUID validation ⇒ these turn RED.)
        {
            let mut h = dyn_host(&b1, false, &bud);
            h.register_zone_credential(
                "t1.example".into(),
                dns_publish::ProviderKind::Gcp,
                gcp_cred(VALID_SA_JSON),
            )
            .await
            .expect("a valid GCP service-account bundle registers");
            h.register_zone_credential(
                "t1.example".into(),
                dns_publish::ProviderKind::Azure,
                azure_cred("11111111-2222-3333-4444-555555555555"),
            )
            .await
            .expect("a valid Azure service-principal bundle registers");
        }
        // The long-lived GCP private key is sealed at rest (its PEM marker never appears in cleartext).
        {
            let all = kv.scan_prefix("project/").await.unwrap();
            for (_k, v) in &all {
                assert!(
                    !String::from_utf8_lossy(v).contains("BEGIN PRIVATE KEY"),
                    "the GCP service-account key must be sealed at rest"
                );
            }
        }
        // A malformed SA JSON / a non-GUID Azure tenant_id is refused at register.
        {
            let mut h = dyn_host(&b1, true, &bud);
            assert!(matches!(
                h.register_zone_credential(
                    "t1.example".into(),
                    dns_publish::ProviderKind::Gcp,
                    gcp_cred("{not valid json"),
                )
                .await,
                Err(dns_publish::PublishError::InvalidRecord(_))
            ));
            assert!(matches!(
                h.register_zone_credential(
                    "t1.example".into(),
                    dns_publish::ProviderKind::Azure,
                    azure_cred("not-a-guid"),
                )
                .await,
                Err(dns_publish::PublishError::InvalidRecord(_))
            ));
        }

        println!(
            "DNS-PUBLISH TENANT-CREDS LIVE OK: posture-gated register of an allowlisted zone sealed a \
             tenant token; a routed upsert reached the registered credential; the token was sealed at \
             rest and never returned; unregister fell the zone through; disallowed-zone + posture-off \
             both access-denied; a second tenant had zero cross-tenant access; removing the zone from \
             the allowlist revoked routing without an unregister (F1); a malformed zone-id was refused \
             at register (F2); a multi-secret route53 bundle registered/sealed/routed with every field \
             delivered, and a missing/unknown/oversized field was refused; an internal Akamai host was \
             refused by the EdgeGrid-domain pin while a real *.akamaiapis.net host was accepted (M1); \
             long-lived GCP service-account + Azure service-principal bundles registered + sealed (key \
             never in cleartext) while a malformed SA JSON / bad-GUID tenant were refused; the operator \
             path was unchanged"
        );
    }
}
