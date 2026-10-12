//! Generic multi-record DNS verification — Phase 1 of the DNS record-set
//! verification primitive (mailroom #2).
//!
//! This is the **operator-facing** half: given a set of expected DNS records
//! ([`RecordSpec`]s), resolve each `(kind, name)` over DNS and report, per
//! record, whether what's published matches what's expected. It is deliberately
//! **separate** from the ownership-challenge flow in [`crate::domain_verify`]:
//! that proves control of a single host via one random token (single-token
//! exact-equality, a version-pinned KV schema); this is a stateless, read-only
//! diagnostic over an arbitrary record set and persists nothing.
//!
//! As with `domain_verify`, the match logic is **pure** and lives here — the
//! network side ([`RecordProbe`]) is injected, so [`evaluate`] is fully testable
//! with a fake probe and no live DNS. The real probe (hickory DoH) lives in the
//! server.
//!
//! ## Match semantics
//!
//! For each spec, every value published at `(kind, name)` is resolved. A spec is
//! [`RecordState::Ok`] if **any** resolved value satisfies the spec's
//! [`MatchMode`] against its expected `value`; [`RecordState::Missing`] if the
//! name has **no** records of that kind at all; otherwise
//! [`RecordState::Mismatch`]. The whole report's [`VerifyReport::verified`] is
//! `true` only when every record is `Ok`.
//!
//! ## Per-kind normalization + legal modes
//!
//! * **TXT** — compared after trimming; a single record's ≤255-byte wire chunks
//!   are joined by the probe (mirroring [`crate::domain_verify`]'s TXT handling).
//!   TXT is the only kind that accepts [`MatchMode::Contains`] /
//!   [`MatchMode::Prefix`] (a free-form value).
//! * **CNAME / MX** — the target / exchange host is compared case- and
//!   trailing-dot-insensitively (via [`crate::domain_verify::normalize_host`]).
//!   A CNAME spec reports the CNAME target **verbatim** and is never chased to an
//!   address.
//! * **A** — compared as a parsed [`IpAddr`], so textual spelling differences
//!   (e.g. IPv6 zero-compression) don't cause a false mismatch.
//!
//! [`MatchMode::Contains`] / [`MatchMode::Prefix`] are **rejected for A / CNAME /
//! MX** — a structured record (an address, a hostname) must match exactly.
//! [`RecordSpec::validate`] enforces this at the request boundary; [`evaluate`]
//! additionally refuses an illegal `(kind, mode)` pair so it can never silently
//! pass (the anti-hollow gate target).

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::ConfigError;
use crate::domain_verify::{VerifyError, normalize_host};

/// The DNS record type a [`RecordSpec`] targets.
///
/// Defined **here**, in `boatramp-types`, deliberately — not reused from
/// `boatramp-acme`'s `RecordKind`, which would introduce a `types → acme`
/// dependency cycle (acme already depends on the shared types layer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordKind {
    /// A `TXT` record (free-form text; the only kind accepting substring matching).
    Txt,
    /// An `MX` record — the mail-exchange host is compared (preference ignored).
    Mx,
    /// A `CNAME` record — the canonical-name target, reported verbatim, never chased.
    Cname,
    /// An `A` record — an IPv4 address, compared as a parsed [`IpAddr`].
    A,
}

impl RecordKind {
    /// The stable wire/CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Txt => "txt",
            Self::Mx => "mx",
            Self::Cname => "cname",
            Self::A => "a",
        }
    }
}

impl std::str::FromStr for RecordKind {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "txt" => Ok(Self::Txt),
            "mx" => Ok(Self::Mx),
            "cname" => Ok(Self::Cname),
            "a" => Ok(Self::A),
            other => Err(ConfigError::parse(format!(
                "unknown DNS record kind `{other}` (expected `txt`, `mx`, `cname`, or `a`)"
            ))),
        }
    }
}

impl std::fmt::Display for RecordKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How an expected value is matched against an observed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchMode {
    /// The observed value must equal the expected value (after per-kind
    /// normalization). The default, and the **only** mode legal for A/CNAME/MX.
    #[default]
    Exact,
    /// The observed value must contain the expected value as a substring
    /// (TXT only).
    Contains,
    /// The observed value must start with the expected value (TXT only).
    Prefix,
}

impl MatchMode {
    /// The stable wire/CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Contains => "contains",
            Self::Prefix => "prefix",
        }
    }
}

impl std::str::FromStr for MatchMode {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "exact" | "" => Ok(Self::Exact),
            "contains" => Ok(Self::Contains),
            "prefix" => Ok(Self::Prefix),
            other => Err(ConfigError::parse(format!(
                "unknown match mode `{other}` (expected `exact`, `contains`, or `prefix`)"
            ))),
        }
    }
}

impl std::fmt::Display for MatchMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One expected DNS record: resolve `kind` records at `name` and check that one
/// of them satisfies `match_mode` against `value`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordSpec {
    /// The record type to resolve.
    pub kind: RecordKind,
    /// The DNS name to query (an FQDN; not normalized here).
    pub name: String,
    /// The expected value (a TXT string, a host for CNAME/MX, an IP for A).
    pub value: String,
    /// How `value` is matched against the observed records (default [`MatchMode::Exact`]).
    #[serde(default)]
    pub match_mode: MatchMode,
}

impl RecordSpec {
    /// Whether this spec's [`MatchMode`] is legal for its [`RecordKind`]:
    /// [`MatchMode::Contains`] / [`MatchMode::Prefix`] are substring tests that
    /// only make sense for a free-form TXT value; A/CNAME/MX are structured and
    /// must match exactly.
    pub fn mode_is_legal(&self) -> bool {
        mode_legal(self.kind, self.match_mode)
    }

    /// Reject an illegal `(kind, mode)` pair at the request boundary. The server
    /// calls this on every spec before resolving, so a client gets a clear 400
    /// rather than a silently-never-matching record.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.mode_is_legal() {
            return Err(ConfigError::parse(format!(
                "match mode `{}` is only valid for TXT records, not `{}`",
                self.match_mode, self.kind
            )));
        }
        Ok(())
    }
}

/// The verdict for one resolved record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecordState {
    /// At least one published value satisfied the spec.
    Ok,
    /// Records of this kind exist at the name, but none satisfied the spec.
    Mismatch,
    /// The name has no records of this kind at all.
    Missing,
}

/// The per-record result: the verdict plus the values actually observed (so the
/// operator can see what *is* published when it doesn't match).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordStatus {
    /// Whether the spec was satisfied, and if not, why.
    pub status: RecordState,
    /// The values observed at `(kind, name)` (empty when the record is missing).
    pub found: Vec<String>,
}

/// The whole verification report: one [`RecordStatus`] per spec (parallel order)
/// plus the aggregate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyReport {
    /// Per-spec results, in the order the specs were given.
    pub records: Vec<RecordStatus>,
    /// `true` only when **every** record is [`RecordState::Ok`].
    pub verified: bool,
}

/// Whether `mode` is legal for `kind`: every kind accepts [`MatchMode::Exact`];
/// only TXT additionally accepts [`MatchMode::Contains`] / [`MatchMode::Prefix`].
fn mode_legal(kind: RecordKind, mode: MatchMode) -> bool {
    matches!(mode, MatchMode::Exact) || matches!(kind, RecordKind::Txt)
}

/// The network side of record verification: resolve each record type at a name.
/// A name with no records of the queried kind resolves to an **empty** list (which
/// [`evaluate`] reports as [`RecordState::Missing`]), never an error. Injected so
/// [`evaluate`] stays pure and testable with a fake probe — mirroring
/// [`crate::domain_verify::DomainProbe`].
#[async_trait]
pub trait RecordProbe: Send + Sync {
    /// All TXT values at `name` (each a single record's joined ≤255-byte chunks).
    async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, VerifyError>;
    /// The mail-exchange host of each MX record at `name`.
    async fn lookup_mx(&self, name: &str) -> Result<Vec<String>, VerifyError>;
    /// The canonical-name target of each CNAME record at `name` (not chased to A).
    async fn lookup_cname(&self, name: &str) -> Result<Vec<String>, VerifyError>;
    /// The address of each A record at `name`.
    async fn lookup_a(&self, name: &str) -> Result<Vec<String>, VerifyError>;
}

/// Resolve every spec through `probe`, returning the observed values **parallel to
/// `specs`** (`resolved[i]` is what was published for `specs[i]`; an empty inner
/// list means the name has no records of that kind). Feed the result to
/// [`evaluate`]. Kept separate from [`evaluate`] so the match logic is pure and
/// the gate can exercise it with canned values.
pub async fn resolve_specs(
    probe: &dyn RecordProbe,
    specs: &[RecordSpec],
) -> Result<Vec<Vec<String>>, VerifyError> {
    let mut resolved = Vec::with_capacity(specs.len());
    for spec in specs {
        let found = match spec.kind {
            RecordKind::Txt => probe.lookup_txt(&spec.name).await?,
            RecordKind::Mx => probe.lookup_mx(&spec.name).await?,
            RecordKind::Cname => probe.lookup_cname(&spec.name).await?,
            RecordKind::A => probe.lookup_a(&spec.name).await?,
        };
        resolved.push(found);
    }
    Ok(resolved)
}

/// Evaluate `specs` against the values `resolved` for them (parallel order, as
/// [`resolve_specs`] returns). Pure — no IO. This is the anti-hollow gate target.
pub fn evaluate(specs: &[RecordSpec], resolved: &[Vec<String>]) -> VerifyReport {
    let mut records = Vec::with_capacity(specs.len());
    let mut verified = specs.len() == resolved.len();
    for (spec, found) in specs.iter().zip(resolved.iter()) {
        let status = evaluate_one(spec, found);
        if status != RecordState::Ok {
            verified = false;
        }
        records.push(RecordStatus {
            status,
            found: found.clone(),
        });
    }
    VerifyReport { records, verified }
}

/// The verdict for one spec given the values `found` at its `(kind, name)`.
fn evaluate_one(spec: &RecordSpec, found: &[String]) -> RecordState {
    if found.is_empty() {
        // The name has no records of this kind.
        //
        // GATE MUTATION SEAM (`missing_is_ok`): report an absent record as Ok,
        // so the anti-hollow gate — which asserts a missing record is Missing —
        // goes RED. A shipped build's `record_verify_mutation()` is always `None`.
        if record_verify_mutation().as_deref() == Some("missing_is_ok") {
            return RecordState::Ok;
        }
        return RecordState::Missing;
    }
    if found.iter().any(|value| value_satisfies(spec, value)) {
        return RecordState::Ok;
    }
    // Records exist, but none satisfied the spec.
    //
    // GATE MUTATION SEAM (`mismatch_is_ok`): report a mismatch as Ok, so the gate
    // — which asserts a present-but-wrong value is Mismatch — goes RED.
    if record_verify_mutation().as_deref() == Some("mismatch_is_ok") {
        return RecordState::Ok;
    }
    RecordState::Mismatch
}

/// Whether one observed `found_value` satisfies `spec` under its match mode, with
/// per-kind normalization.
fn value_satisfies(spec: &RecordSpec, found_value: &str) -> bool {
    // Mode legality is a hard floor: an illegal `(kind, mode)` pair (e.g. Contains
    // on an A record) can NEVER satisfy — a structured record matches exactly or
    // not at all. The boundary validator ([`RecordSpec::validate`]) rejects such a
    // request up front; this second check means a spec that somehow reaches here
    // still can't silently pass.
    //
    // GATE MUTATION SEAM (`accept_illegal_mode`): skip the floor, so Contains/Prefix
    // on A/CNAME/MX is honored and can wrongly match — turning the gate RED.
    let skip_legality = record_verify_mutation().as_deref() == Some("accept_illegal_mode");
    if !skip_legality && !mode_legal(spec.kind, spec.match_mode) {
        return false;
    }
    match spec.kind {
        RecordKind::Txt => {
            // Trim both sides (mirrors the ownership TXT handling); the probe has
            // already joined a single record's ≤255-byte wire chunks.
            let found = found_value.trim();
            let expected = spec.value.trim();
            match spec.match_mode {
                MatchMode::Exact => found == expected,
                MatchMode::Contains => !expected.is_empty() && found.contains(expected),
                MatchMode::Prefix => found.starts_with(expected),
            }
        }
        // CNAME target / MX exchange: case- and trailing-dot-insensitive host
        // comparison (Exact only — a non-Exact mode is refused by the floor above).
        RecordKind::Cname | RecordKind::Mx => {
            normalize_host(found_value) == normalize_host(&spec.value)
        }
        // A: compare as parsed addresses so textual spelling doesn't matter. Both
        // sides must parse — two un-parseable strings never match.
        RecordKind::A => {
            match (
                found_value.trim().parse::<IpAddr>(),
                spec.value.trim().parse::<IpAddr>(),
            ) {
                (Ok(found), Ok(expected)) => found == expected,
                _ => false,
            }
        }
    }
}

// Defense-in-depth: the match-mutation seam is for `cargo test` only. Fail the
// build loudly if the gate feature is ever enabled in a non-test RELEASE profile
// (scoped to this seam), so it can never ship.
#[cfg(all(
    feature = "record-verify-gate-mutation",
    not(test),
    not(debug_assertions)
))]
compile_error!(
    "record-verify-gate-mutation is a test-only anti-hollow seam and must never be compiled into a \
     release build — remove it from the feature set"
);

/// The active match mutation (anti-hollow gate), or `None`. Present ONLY under
/// `cfg(test)` or the `record-verify-gate-mutation` feature; a shipped build has
/// neither, so [`evaluate`] runs unconditionally and this is a dead `None`. Not a
/// backdoor — it only exposes a test env var.
#[cfg(any(test, feature = "record-verify-gate-mutation"))]
fn record_verify_mutation() -> Option<String> {
    std::env::var("BOATRAMP_RECORDVERIFY_MUTATION").ok()
}
#[cfg(not(any(test, feature = "record-verify-gate-mutation")))]
#[inline]
fn record_verify_mutation() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn txt(name: &str, value: &str, mode: MatchMode) -> RecordSpec {
        RecordSpec {
            kind: RecordKind::Txt,
            name: name.into(),
            value: value.into(),
            match_mode: mode,
        }
    }

    /// A scripted probe: returns canned values per kind, recording the queries.
    #[derive(Default)]
    struct FakeProbe {
        txt: Vec<String>,
        mx: Vec<String>,
        cname: Vec<String>,
        a: Vec<String>,
        queried: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl RecordProbe for FakeProbe {
        async fn lookup_txt(&self, name: &str) -> Result<Vec<String>, VerifyError> {
            self.queried.lock().unwrap().push(format!("txt:{name}"));
            Ok(self.txt.clone())
        }
        async fn lookup_mx(&self, name: &str) -> Result<Vec<String>, VerifyError> {
            self.queried.lock().unwrap().push(format!("mx:{name}"));
            Ok(self.mx.clone())
        }
        async fn lookup_cname(&self, name: &str) -> Result<Vec<String>, VerifyError> {
            self.queried.lock().unwrap().push(format!("cname:{name}"));
            Ok(self.cname.clone())
        }
        async fn lookup_a(&self, name: &str) -> Result<Vec<String>, VerifyError> {
            self.queried.lock().unwrap().push(format!("a:{name}"));
            Ok(self.a.clone())
        }
    }

    #[test]
    fn txt_exact_matches_one_of_several_values() {
        let specs = vec![txt("_x.example.com", "tok", MatchMode::Exact)];
        let report = evaluate(&specs, &[vec!["unrelated".into(), " tok ".into()]]);
        assert_eq!(report.records[0].status, RecordState::Ok);
        assert!(report.verified);
    }

    #[test]
    fn txt_contains_and_prefix() {
        let contains = vec![txt("_d.example.com", "p=reject", MatchMode::Contains)];
        let report = evaluate(&contains, &[vec!["v=DMARC1; p=reject; rua=...".into()]]);
        assert_eq!(report.records[0].status, RecordState::Ok);

        let prefix = vec![txt("_d.example.com", "v=DMARC1", MatchMode::Prefix)];
        let report = evaluate(&prefix, &[vec!["v=DMARC1; p=reject".into()]]);
        assert_eq!(report.records[0].status, RecordState::Ok);

        // A contains that isn't present is a mismatch, not a pass.
        let report = evaluate(&contains, &[vec!["v=DMARC1; p=none".into()]]);
        assert_eq!(report.records[0].status, RecordState::Mismatch);
    }

    #[test]
    fn missing_vs_mismatch_are_distinct() {
        let specs = vec![txt("_x.example.com", "tok", MatchMode::Exact)];
        assert_eq!(
            evaluate(&specs, &[vec![]]).records[0].status,
            RecordState::Missing
        );
        assert_eq!(
            evaluate(&specs, &[vec!["nope".into()]]).records[0].status,
            RecordState::Mismatch
        );
    }

    #[test]
    fn cname_is_case_and_dot_insensitive() {
        let specs = vec![RecordSpec {
            kind: RecordKind::Cname,
            name: "www.example.com".into(),
            value: "Target.Example.COM".into(),
            match_mode: MatchMode::Exact,
        }];
        let report = evaluate(&specs, &[vec!["target.example.com.".into()]]);
        assert_eq!(report.records[0].status, RecordState::Ok);
    }

    #[test]
    fn mx_compares_the_exchange_host() {
        let specs = vec![RecordSpec {
            kind: RecordKind::Mx,
            name: "example.com".into(),
            value: "mail.example.com".into(),
            match_mode: MatchMode::Exact,
        }];
        let report = evaluate(&specs, &[vec!["mail.example.com.".into()]]);
        assert_eq!(report.records[0].status, RecordState::Ok);
    }

    #[test]
    fn a_compares_parsed_addresses() {
        let specs = vec![RecordSpec {
            kind: RecordKind::A,
            name: "example.com".into(),
            value: "192.0.2.1".into(),
            match_mode: MatchMode::Exact,
        }];
        assert_eq!(
            evaluate(&specs, &[vec!["192.0.2.1".into()]]).records[0].status,
            RecordState::Ok
        );
        assert_eq!(
            evaluate(&specs, &[vec!["192.0.2.2".into()]]).records[0].status,
            RecordState::Mismatch
        );
    }

    #[test]
    fn illegal_modes_are_rejected_at_the_boundary() {
        for kind in [RecordKind::A, RecordKind::Cname, RecordKind::Mx] {
            for mode in [MatchMode::Contains, MatchMode::Prefix] {
                let spec = RecordSpec {
                    kind,
                    name: "x".into(),
                    value: "y".into(),
                    match_mode: mode,
                };
                assert!(
                    spec.validate().is_err(),
                    "{kind:?}/{mode:?} must be refused"
                );
            }
            // Exact stays legal on every kind.
            assert!(
                RecordSpec {
                    kind,
                    name: "x".into(),
                    value: "y".into(),
                    match_mode: MatchMode::Exact,
                }
                .validate()
                .is_ok()
            );
        }
    }

    #[test]
    fn verified_requires_every_record_ok() {
        let specs = vec![
            txt("_a.example.com", "tok", MatchMode::Exact),
            txt("_b.example.com", "tok2", MatchMode::Exact),
        ];
        let report = evaluate(&specs, &[vec!["tok".into()], vec!["wrong".into()]]);
        assert!(!report.verified);
        assert_eq!(report.records[0].status, RecordState::Ok);
        assert_eq!(report.records[1].status, RecordState::Mismatch);
    }

    #[tokio::test]
    async fn resolve_specs_dispatches_per_kind() {
        let probe = FakeProbe {
            txt: vec!["tok".into()],
            a: vec!["192.0.2.1".into()],
            ..Default::default()
        };
        let specs = vec![
            txt("_x.example.com", "tok", MatchMode::Exact),
            RecordSpec {
                kind: RecordKind::A,
                name: "example.com".into(),
                value: "192.0.2.1".into(),
                match_mode: MatchMode::Exact,
            },
        ];
        let resolved = resolve_specs(&probe, &specs).await.unwrap();
        let report = evaluate(&specs, &resolved);
        assert!(report.verified);
        let q = probe.queried.lock().unwrap();
        assert!(q.contains(&"txt:_x.example.com".to_string()));
        assert!(q.contains(&"a:example.com".to_string()));
    }

    /// ANTI-HOLLOW GATE (marker `RECORD-VERIFY MATCH OK`). Drives the pure matcher
    /// across the three security-critical properties and prints the marker only if
    /// all hold. Re-run under each `BOATRAMP_RECORDVERIFY_MUTATION` the matcher
    /// must FAIL (CI asserts that): `missing_is_ok` (absent record passes),
    /// `mismatch_is_ok` (wrong value passes), `accept_illegal_mode` (Contains/Prefix
    /// honored for A/CNAME/MX). Deterministic — no live DNS.
    #[test]
    fn record_verify_match_gate() {
        // (i) An absent record is Missing, never Ok.
        let specs = vec![txt("_x.example.com", "tok", MatchMode::Exact)];
        let report = evaluate(&specs, &[vec![]]);
        assert_eq!(
            report.records[0].status,
            RecordState::Missing,
            "an absent record must report Missing, not Ok"
        );
        assert!(!report.verified, "a missing record must not verify");

        // (iii) A present-but-wrong value is Mismatch, never Ok.
        let report = evaluate(&specs, &[vec!["the-wrong-token".into()]]);
        assert_eq!(
            report.records[0].status,
            RecordState::Mismatch,
            "a mismatched value must report Mismatch, not Ok"
        );
        assert!(!report.verified, "a mismatched record must not verify");

        // Positive control: an exact TXT match verifies.
        let report = evaluate(&specs, &[vec!["tok".into()]]);
        assert_eq!(report.records[0].status, RecordState::Ok);
        assert!(report.verified);

        // (ii) Contains/Prefix is illegal for A/CNAME/MX — never Ok, even when the
        // value would otherwise match under that mode.
        let a_contains = vec![RecordSpec {
            kind: RecordKind::A,
            name: "example.com".into(),
            value: "192.0.2.1".into(),
            match_mode: MatchMode::Contains,
        }];
        assert_ne!(
            evaluate(&a_contains, &[vec!["192.0.2.1".into()]]).records[0].status,
            RecordState::Ok,
            "Contains on an A record must not pass"
        );
        let cname_prefix = vec![RecordSpec {
            kind: RecordKind::Cname,
            name: "www.example.com".into(),
            value: "mail.example.com".into(),
            match_mode: MatchMode::Prefix,
        }];
        assert_ne!(
            evaluate(&cname_prefix, &[vec!["mail.example.com.".into()]]).records[0].status,
            RecordState::Ok,
            "Prefix on a CNAME record must not pass"
        );
        let mx_contains = vec![RecordSpec {
            kind: RecordKind::Mx,
            name: "example.com".into(),
            value: "mail.example.com".into(),
            match_mode: MatchMode::Contains,
        }];
        assert_ne!(
            evaluate(&mx_contains, &[vec!["mail.example.com.".into()]]).records[0].status,
            RecordState::Ok,
            "Contains on an MX record must not pass"
        );

        println!("RECORD-VERIFY MATCH OK");
    }
}
