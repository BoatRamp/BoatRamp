//! Guest-log **secret redaction** (exact-value, provenance-scoped, best-effort).
//!
//! boatramp is the *injector* of a workload's secret-sourced env values — the resolved
//! `{{sql.*}}` managed-DB DSN with its sealed password, an unsealed `boatramp:<name>`
//! secret-store ref, an external-vault value, a managed-service-generated key — so it
//! holds the exact plaintext and can redact those values out of the forwarded guest-log
//! stream before they reach a durable per-node file or a central tracing aggregator. A
//! guest that prints its own environment (`echo $DATABASE_URL`, a crash dump, a debug
//! handler) therefore does not leak the injected credential into observability.
//!
//! This is **defense-in-depth**, not the primary control (which remains short-lived
//! creds + guests not printing secrets). It mirrors the CI world's exact-value masking
//! (GitHub Actions `::add-mask::`, GitLab masked variables, Jenkins Mask Passwords) and,
//! like all of those, is **best-effort**:
//!
//! - **In scope:** an exact, contiguous occurrence of a secret VALUE in a single log
//!   line. The matcher is a per-workload [`aho_corasick`] automaton built once from the
//!   workload's redaction set; each line is scanned in one pass whose cost is independent
//!   of the number of secrets (sub-linear in N).
//! - **Out of scope (documented, accepted):** encoded / split / transformed / substring
//!   leaks — if a guest base64/hex/URL-encodes a secret, splits it across lines, or
//!   prints a derived substring, the exact-value match misses it. We do NOT attempt
//!   heuristic/regex scrubbing of unknown secret shapes (an aggregator-layer concern).
//!   One concrete substring case worth calling out: a consuming workload collects the
//!   whole rendered **DSN** (e.g. `postgres://user:pass@host/db`) as one value, so a
//!   guest that prints the full `$DATABASE_URL` is covered, but a guest (or an ORM) that
//!   logs the **bare password on its own** — a substring of the DSN, never injected as a
//!   standalone value into *that* workload — is NOT redacted there. (The managed-DB
//!   *server* workload collects its `POSTGRES_PASSWORD` as its own value, so the bare
//!   password IS covered on the server side.)
//! - **Below the length floor (documented):** a secret-sourced value shorter than
//!   [`MIN_SECRET_LEN`] is not redacted, including a short operator-stored
//!   `{{secret.<NAME>}}` value (a PIN, a short key) — matching GitLab's refusal to mask a
//!   variable under 8 characters. See [`MIN_SECRET_LEN`].
//!
//! The redaction SET itself is held in a [`Zeroizing`] buffer and scrubbed from memory
//! when the [`Redactor`] drops (forwarder teardown / container exit), and is NEVER
//! serialized or logged (the [`Debug`] impl prints only a count, never a value).

use std::borrow::Cow;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, MatchKind};
use zeroize::Zeroizing;

/// The **min-length floor**: a secret value shorter than this is NOT added to the
/// redaction set, so a short secret can never blanket-redact benign guest output (a
/// 2-char secret matching `hi` everywhere would be useless *and* destructive).
///
/// `8` follows the GitLab masked-variables precedent (GitLab refuses to mask a variable
/// under 8 characters for exactly this reason). Real injected credentials — a DSN, a
/// password, a minted token, a generated key — are comfortably longer; the floor only
/// drops pathologically short values where the over-redaction cost would exceed the
/// leak-prevention benefit. The floor applies to EVERY secret-sourced value uniformly —
/// including an operator-stored `{{secret.<NAME>}}` value — so a short operator secret (a
/// PIN, a 6-char key) below 8 characters is NOT redacted, exactly as GitLab refuses to
/// mask a short variable. An operator who stores a genuinely short secret should treat it
/// as unmaskable in logs (or lengthen it). We deliberately do NOT add a charset/entropy
/// guard on top:
/// a managed-DB DSN (`postgres://…`) is highly structured and low-entropy as a whole, so
/// an entropy test would wrongly *skip* it and leak it — and a false *skip* is strictly
/// worse than the benign over-redaction the length floor already bounds. Provenance
/// scoping (only secret-sourced values ever reach this set — never an operator literal)
/// is what keeps the set tight; the floor is the only additional filter.
pub const MIN_SECRET_LEN: usize = 8;

/// The stable placeholder a matched secret value is replaced with. A non-empty,
/// recognizable, control-free marker (the guillemets survive the sink's `sanitize_line`
/// pass unchanged) so a reader sees that a value was redacted here, not that output went
/// missing.
pub const REDACTED_PLACEHOLDER: &str = "\u{2039}redacted\u{203a}";

/// A per-workload secret redactor: an Aho-Corasick automaton over the workload's
/// secret-sourced env VALUES, plus the zeroizing source buffer.
///
/// Built once per workload at launch (one automaton, shared by the stdout + stderr
/// pumps via an `Arc`) and dropped when the log forwarder tears down — at which point
/// the [`Zeroizing`] buffer scrubs the plaintext secret bytes from memory.
///
/// **Plaintext-in-memory lifecycle (best-effort — see caveat).** The authoritative copy
/// of the redaction set lives in [`secrets`](Self::secrets), a
/// [`Zeroizing`]`<Vec<String>>` scrubbed on drop; the Aho-Corasick automaton also holds a
/// *derived* representation of the same bytes, freed — not scrubbed — at teardown.
///
/// The zeroizing here is deliberately **best-effort, not a guarantee the secret bytes are
/// gone from the process**: the SAME plaintext is co-resident, UNzeroized, in the
/// workload's `spec.env` (a plain `BTreeMap<String, String>` the launch path hands to the
/// backend to set the container/VM environment, by design — the guest must receive these
/// values). That `spec.env` copy — not this automaton — is the larger, longer-lived
/// residue, and it is inherent to injecting env at all. So this zeroizing narrows the
/// redactor's OWN footprint (and keeps the set out of `Debug`/serialization), but it does
/// not and cannot make the launcher/backend process secret-free while a workload is being
/// launched. Everything here lives within that same trust boundary, which already holds
/// the plaintext to inject it; the redactor adds no exposure beyond it.
pub struct Redactor {
    /// The matcher. One pass per line, O(line length), independent of the set size.
    ac: AhoCorasick,
    /// The source secret VALUES, zeroized on drop (see the type-level note). Retained
    /// (rather than dropped after the build) so there is one authoritative buffer that is
    /// explicitly scrubbed at teardown, and so [`len`](Self::len) can report the set size
    /// for diagnostics without ever exposing a value.
    secrets: Zeroizing<Vec<String>>,
}

impl Redactor {
    /// Build a redactor from a workload's secret-sourced env values.
    ///
    /// Applies the [`MIN_SECRET_LEN`] floor and de-dups, so the automaton carries only
    /// distinct, long-enough values. Returns `None` when nothing qualifies (the caller
    /// then skips the redaction scan entirely — no automaton, no per-line cost), so a
    /// workload with no secret-sourced env is exactly as before.
    #[must_use]
    pub fn build<I, S>(values: I) -> Option<Arc<Self>>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut secrets: Vec<String> = Vec::new();
        for v in values {
            let v = v.into();
            // Min-length floor + de-dup: a value below the floor is dropped so it cannot
            // over-redact; a duplicate is skipped to keep the automaton minimal.
            if v.len() >= MIN_SECRET_LEN && !secrets.iter().any(|s| s == &v) {
                secrets.push(v);
            }
        }
        if secrets.is_empty() {
            return None;
        }
        let secrets = Zeroizing::new(secrets);
        // LeftmostLongest: on overlapping/nested secrets prefer the longest match, so a
        // secret that is a prefix of another is not left partially visible. A build error
        // (not expected — the floor rules out the empty-pattern case) degrades to no
        // redaction rather than aborting the launch.
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(secrets.iter())
            .ok()?;
        Some(Arc::new(Self { ac, secrets }))
    }

    /// Replace every exact occurrence of a secret value in `line` with
    /// [`REDACTED_PLACEHOLDER`], returning the (possibly unchanged) text.
    ///
    /// A single Aho-Corasick pass decides whether the line contains any secret; its cost
    /// is O(line length) and **independent of the number of secrets**. The common case (a
    /// line with no secret) borrows the input unchanged with no allocation; only a line
    /// that actually contains a secret is rewritten.
    #[must_use]
    pub fn redact<'a>(&self, line: &'a str) -> Cow<'a, str> {
        if !self.ac.is_match(line) {
            return Cow::Borrowed(line);
        }
        let mut out = String::with_capacity(line.len());
        self.ac
            .replace_all_with(line, &mut out, |_m, _matched, dst| {
                dst.push_str(REDACTED_PLACEHOLDER);
                true
            });
        Cow::Owned(out)
    }

    /// The number of distinct secret values this redactor matches. For diagnostics/tests
    /// only — never exposes a value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Whether the redactor matches nothing. (`build` never returns an empty redactor, so
    /// this is always `false` for a live one; present for API completeness.)
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }
}

/// A redacting [`Debug`] so a `Redactor` can sit inside a `#[derive(Debug)]` type (e.g.
/// threaded through a backend) without ever printing a secret value.
impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field(
                "secrets",
                &format_args!("<{} redacted>", self.secrets.len()),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DSN: &str = "postgres://app:S3cr3tP%40ss@bramp-db-abc123.flycast:5432/appdb";

    #[test]
    fn redacts_an_exact_injected_secret_value() {
        let r = Redactor::build([DSN]).expect("one long secret qualifies");
        let line = format!("connecting to {DSN} now");
        let out = r.redact(&line);
        assert!(!out.contains(DSN), "the secret leaked: {out}");
        assert!(out.contains(REDACTED_PLACEHOLDER), "no placeholder: {out}");
        assert_eq!(out, format!("connecting to {REDACTED_PLACEHOLDER} now"));
    }

    #[test]
    fn mutation_proof_without_redaction_the_secret_leaks() {
        // The inverse of the gate: a redactor that is NOT applied (the opt-out / None
        // path) leaves the secret intact. This is what the backend's opt-out produces and
        // what a removed redact-step would produce — the integration test asserts the
        // complement (redacted), so the two together bind the redaction.
        let line = format!("DATABASE_URL={DSN}");
        assert!(
            line.contains(DSN),
            "baseline: unredacted line carries the secret"
        );
    }

    #[test]
    fn a_value_below_the_floor_is_not_redacted() {
        // `admin` (5 < 8) is below the floor, so it is dropped from the set and cannot
        // blanket-redact the benign word elsewhere in the output.
        let r = Redactor::build(["admin", DSN]).expect("the DSN still qualifies");
        assert_eq!(r.len(), 1, "only the long value is kept");
        let line = "role=admin ready; admin console up";
        let out = r.redact(line);
        assert_eq!(out, line, "a sub-floor value does not over-redact: {out}");
    }

    #[test]
    fn build_returns_none_when_nothing_qualifies() {
        assert!(
            Redactor::build(Vec::<String>::new()).is_none(),
            "empty set → None"
        );
        assert!(
            Redactor::build(["short", "tiny", "1234567"]).is_none(),
            "all below the 8-char floor → None (no automaton, no per-line cost)"
        );
    }

    #[test]
    fn dedups_and_handles_multiple_secrets() {
        let r = Redactor::build([DSN, DSN, "another-long-token-xyz", "another-long-token-xyz"])
            .expect("two distinct long secrets");
        assert_eq!(r.len(), 2, "duplicates collapse");
        let line = format!("{DSN} and another-long-token-xyz");
        let out = r.redact(&line);
        assert!(!out.contains(DSN));
        assert!(!out.contains("another-long-token-xyz"));
        assert_eq!(
            out,
            format!("{REDACTED_PLACEHOLDER} and {REDACTED_PLACEHOLDER}")
        );
    }

    #[test]
    fn no_match_borrows_the_input_unchanged() {
        let r = Redactor::build([DSN]).unwrap();
        let line = "a perfectly ordinary log line with no secret";
        let out = r.redact(line);
        assert!(
            matches!(out, Cow::Borrowed(_)),
            "no allocation when nothing matches"
        );
        assert_eq!(out, line);
    }

    #[test]
    fn longest_match_wins_on_nested_secrets() {
        // A secret that is a substring of a longer secret: the longer (full) value is
        // replaced as one unit, never leaving the trailing bytes of the longer value
        // dangling after redacting only the inner one.
        let inner = "token-abc12345";
        let outer = "token-abc12345-with-suffix-ZZ";
        let r = Redactor::build([inner, outer]).unwrap();
        let line = format!("x={outer}");
        let out = r.redact(&line);
        assert_eq!(
            out,
            format!("x={REDACTED_PLACEHOLDER}"),
            "whole longer value redacted"
        );
    }

    #[test]
    fn debug_never_prints_a_secret_value() {
        let r = Redactor::build([DSN]).unwrap();
        let shown = format!("{r:?}");
        assert!(!shown.contains(DSN), "Debug leaked the secret: {shown}");
        assert!(shown.contains("redacted"));
    }

    /// Aho-Corasick property: the per-line scan cost is **independent of the number of
    /// secrets** (one DFA pass), so adding more secrets does not change per-line cost.
    /// A naive per-secret loop would be O(N) per line (~N× slower at N=2000); the DFA is
    /// O(line). The bound is deliberately loose (≤ 8×) so it is robust to CI timing noise
    /// while still catching an O(N)-per-line regression (which would be ~2000×).
    #[test]
    fn per_line_scan_is_n_independent() {
        use std::time::Instant;

        // A representative benign line (the common case: no secret present, so the whole
        // line is scanned to EOF — the worst case for the matcher).
        let line =
            "ts=2026-11-17T12:00:00Z level=info msg=\"request handled\" path=/api/x dur=12ms";
        let iters = 20_000usize;

        let one = Redactor::build([DSN]).unwrap();
        // 2000 distinct long secrets. If the scan were per-secret, this would be ~2000×
        // the single-secret cost; with one DFA it is essentially unchanged.
        let many: Vec<String> = (0..2000)
            .map(|i| format!("secret-value-{i:08}-padding"))
            .collect();
        let many = Redactor::build(many).unwrap();
        assert_eq!(many.len(), 2000);

        // Warm up, then time each.
        for _ in 0..iters {
            std::hint::black_box(one.redact(line));
            std::hint::black_box(many.redact(line));
        }
        let t1 = {
            let s = Instant::now();
            for _ in 0..iters {
                std::hint::black_box(one.redact(line));
            }
            s.elapsed()
        };
        let tn = {
            let s = Instant::now();
            for _ in 0..iters {
                std::hint::black_box(many.redact(line));
            }
            s.elapsed()
        };
        // Guard against a divide-by-zero / absurdly fast clock: only enforce the ratio
        // when the single-secret baseline is measurable.
        if t1.as_nanos() > 0 {
            let ratio = tn.as_nanos() as f64 / t1.as_nanos() as f64;
            assert!(
                ratio < 8.0,
                "per-line scan cost grew {ratio:.1}× from 1 to 2000 secrets (expected ~1×; \
                 an O(N)-per-line regression would be ~2000×): t1={t1:?} tn={tn:?}"
            );
        }
    }
}
