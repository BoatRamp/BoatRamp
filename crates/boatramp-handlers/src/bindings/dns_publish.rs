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
    validate_writable,
};

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

/// The per-invocation `dns-publish` grant: the host-held DNS writer, the zone it is authoritative over
/// (for the apex-NS guardrail), the writable-zone allowlist (layer 2), and the audit sink. `None` ⇒
/// not granted. The guest never sees any of this — it only names records.
#[derive(Clone)]
pub struct DnsPublishBinding {
    /// The host-held writer whose adapter credential performs the mutation.
    provider: Arc<dyn DnsProvider>,
    /// The apex of the zone the provider is authoritative over (e.g. `example.com`), passed to
    /// [`validate_writable`] so an apex `NS` is refused. Not guest-supplied.
    zone_root: String,
    /// The authorized writable-zone suffixes (globs). Empty ⇒ deny-all. Matched against the record's
    /// OWN name only.
    writable_zones: Arc<[String]>,
    /// Where each mutation is audited (redacted).
    audit: Arc<dyn DnsPublishAuditSink>,
}

impl DnsPublishBinding {
    /// Build the grant. `zone_root` is the provider's authoritative zone apex; `writable_zones` is the
    /// per-grant allowlist (empty ⇒ deny-all); `audit` is the redacted sink (use
    /// [`TracingDnsPublishSink`] for the default).
    pub fn new(
        provider: Arc<dyn DnsProvider>,
        zone_root: impl Into<String>,
        writable_zones: Vec<String>,
        audit: Arc<dyn DnsPublishAuditSink>,
    ) -> Self {
        Self {
            provider,
            zone_root: zone_root.into(),
            writable_zones: Arc::from(writable_zones),
            audit,
        }
    }
}

/// Whether `name` matches a writable-zone glob. Semantics match
/// [`boatramp_types::gateway::gateway_host_matches`] (case-insensitive; trailing dot ignored; `*.sfx`
/// is a single label, `**.sfx` any depth incl. the apex, bare `**` anything). Re-implemented here
/// because `boatramp-handlers` does not depend on `boatramp-types`.
fn zone_glob_matches(glob: &str, name: &str) -> bool {
    let glob = glob.trim().to_ascii_lowercase();
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
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
        DnsError::UnsupportedRecordType { provider, kind } => {
            P::Unsupported(format!("provider '{provider}' cannot write {kind} records"))
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
    posture_enabled: bool,
    budget: &'a AtomicU32,
}

impl<'a> DnsPublishHost<'a> {
    pub fn new(
        binding: Option<&'a DnsPublishBinding>,
        posture_enabled: bool,
        budget: &'a AtomicU32,
    ) -> Self {
        Self {
            binding,
            posture_enabled,
            budget,
        }
    }

    /// Layer 1: the grant must be present AND the node posture on. Deny-by-default, fail-closed
    /// (posture off ⇒ denied even when granted). Checked BEFORE the budget, so a denied call can never
    /// burn a victim invocation's budget.
    fn admit(&self) -> Result<&'a DnsPublishBinding, dns_publish::PublishError> {
        match self.binding {
            Some(b) if self.posture_enabled => Ok(b),
            _ => Err(dns_publish::PublishError::AccessDenied),
        }
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

    /// Layer 2 + the central guardrail, with NO write and NO budget spend: check the record's OWN name
    /// against the writable-zone allowlist (the rdata target is deliberately NOT checked), build the
    /// typed record, then run [`validate_writable`] (apex-NS / supported-kind / malformed-rdata). A
    /// failure here means NOTHING is written.
    fn prepare(
        b: &DnsPublishBinding,
        wit: dns_publish::DnsRecord,
    ) -> Result<AcmeRecord, dns_publish::PublishError> {
        // Layer 2: own-name allowlist (deny-empty). The TARGET in the rdata is never constrained.
        if !zone_authorized(&b.writable_zones, &wit.name) {
            return Err(dns_publish::PublishError::NotAuthorized(wit.name));
        }
        let kind = build_kind(wit.data)?;
        let record = AcmeRecord {
            kind,
            name: wit.name,
            ttl: wit.ttl,
        };
        validate_writable(b.provider.as_ref(), &record, &b.zone_root).map_err(map_guardrail_err)?;
        Ok(record)
    }
}

/// Dispatch one prepared mutation to the provider and audit the outcome (redacted). A `delete` of an
/// already-absent record converges (idempotent teardown → `ok`). A backend failure is logged
/// host-side (detail) and surfaced generically.
async fn write_one(
    b: &DnsPublishBinding,
    record: &AcmeRecord,
    op: DnsPublishOp,
) -> Result<(), dns_publish::PublishError> {
    let res = match op {
        DnsPublishOp::Upsert => b.provider.upsert(record).await,
        DnsPublishOp::Delete => b.provider.delete(record).await,
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
                provider = b.provider.name(),
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
    b.audit.record(&DnsPublishAuditEntry {
        op,
        name: &record.name,
        kind: record.kind.tag(),
        provider: b.provider.name(),
        outcome,
    });
    mapped
}

impl dns_publish::Host for DnsPublishHost<'_> {
    async fn upsert(
        &mut self,
        record: dns_publish::DnsRecord,
    ) -> Result<(), dns_publish::PublishError> {
        let b = self.admit()?;
        let prepared = Self::prepare(b, record)?;
        self.spend(1)?;
        write_one(b, &prepared, DnsPublishOp::Upsert).await
    }

    async fn delete(
        &mut self,
        record: dns_publish::DnsRecord,
    ) -> Result<(), dns_publish::PublishError> {
        let b = self.admit()?;
        let prepared = Self::prepare(b, record)?;
        self.spend(1)?;
        write_one(b, &prepared, DnsPublishOp::Delete).await
    }

    async fn upsert_set(
        &mut self,
        records: Vec<dns_publish::DnsRecord>,
    ) -> Result<(), dns_publish::PublishError> {
        let b = self.admit()?;
        // Validate + gate EVERY record BEFORE writing any (fail-closed, all-or-nothing on validation):
        // one bad record refuses the whole set and nothing is written.
        let mut prepared = Vec::with_capacity(records.len());
        for r in records {
            prepared.push(Self::prepare(b, r)?);
        }
        // Reserve the whole set's budget up front — a set that cannot fit the budget writes NOTHING.
        self.spend(prepared.len() as u32)?;
        // Apply in order; upserts are idempotent, so a backend failure mid-set converges on retry.
        for record in &prepared {
            write_one(b, record, DnsPublishOp::Upsert).await?;
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
        DnsPublishBinding::new(
            provider,
            zone_root,
            zones.iter().map(|s| (*s).to_string()).collect(),
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

    #[tokio::test]
    async fn ungranted_is_access_denied() {
        let bud = budget(16);
        let mut host = DnsPublishHost::new(None, true, &bud);
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
        let mut host = DnsPublishHost::new(Some(&b), false, &bud);
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
            let mut host = DnsPublishHost::new(Some(&b), true, &bud);
            host.upsert(a_record("www.example.com", "203.0.113.7"))
                .await
                .expect("in-zone upsert ok");
        }
        assert_eq!(p.count(), 1);
        // An out-of-zone own name is refused (and nothing more is written).
        {
            let mut host = DnsPublishHost::new(Some(&b), true, &bud);
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
            let mut host = DnsPublishHost::new(Some(&b), true, &bud);
            host.upsert(rec(
                "www.example.com",
                dns_publish::Rdata::Cname("lb.other-domain.net".into()),
            ))
            .await
            .expect("CNAME to foreign target allowed");
        }
        // MX at the apex pointing to another domain's mail host (the direct-MX relay shape).
        {
            let mut host = DnsPublishHost::new(Some(&b), true, &bud);
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
        let mut host = DnsPublishHost::new(Some(&b), true, &bud);
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
        let mut host = DnsPublishHost::new(Some(&b), true, &bud);
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
            let mut host = DnsPublishHost::new(Some(&b), true, &bud);
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
            let mut host = DnsPublishHost::new(Some(&b), true, &bud);
            host.upsert(rec(
                "sub.example.com",
                dns_publish::Rdata::Ns("ns1.example.net".into()),
            ))
            .await
            .expect("subzone NS allowed");
        }
        assert_eq!(p.count(), 1, "only the subzone NS was written");
    }

    #[tokio::test]
    async fn malformed_rdata_is_refused() {
        let p = Arc::new(StubProvider::new(BASIC));
        let b = binding_with(p.clone(), "example.com", &["**.example.com"]);
        let bud = budget(16);
        // A bad IPv4 literal → invalid-record (build fails).
        {
            let mut host = DnsPublishHost::new(Some(&b), true, &bud);
            assert!(matches!(
                host.upsert(a_record("www.example.com", "not-an-ip")).await,
                Err(dns_publish::PublishError::InvalidRecord(_))
            ));
        }
        // An over-long TXT character-string → invalid-record (validate_writable).
        {
            let mut host = DnsPublishHost::new(Some(&b), true, &bud);
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
            let mut view = DnsPublishHost::new(Some(&b), true, &bud); // rebuilt per call
            view.upsert(a_record(&format!("r{i}.example.com"), "203.0.113.7"))
                .await
                .unwrap_or_else(|e| panic!("call {i} within budget: {e:?}"));
        }
        // A FRESH view on the SAME cell is now exhausted — proves the counter is store-resident (and the
        // allowlist, held in the shared binding, kept authorizing every one of the ≥2 calls).
        let mut view = DnsPublishHost::new(Some(&b), true, &bud);
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
        let mut other = DnsPublishHost::new(Some(&b), true, &bud2);
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
        let mut host = DnsPublishHost::new(Some(&b), true, &bud);
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
        let mut host = DnsPublishHost::new(Some(&b), true, &bud);
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
        let mut host = DnsPublishHost::new(Some(&b), true, &bud);
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
            sink.clone(),
        );
        let bud = budget(16);
        let mut host = DnsPublishHost::new(Some(&b), true, &bud);
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
            sink.clone(),
        );
        let bud = budget(16);
        // Two calls through two REBUILT views sharing the one store-resident binding + sink.
        {
            let mut host = DnsPublishHost::new(Some(&b), true, &bud);
            host.upsert(rec(
                "_dmarc.example.com",
                // A TXT whose VALUE must never appear in the audit log (redaction proof).
                dns_publish::Rdata::Txt(vec!["v=DMARC1; p=reject; secret-token=abc123".into()]),
            ))
            .await
            .unwrap();
        }
        {
            let mut host = DnsPublishHost::new(Some(&b), true, &bud);
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
}
