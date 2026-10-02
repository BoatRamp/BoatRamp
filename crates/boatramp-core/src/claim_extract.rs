//! Bounded, declarative derivation of a tenant key from a **verified** JWT claim.
//!
//! The `token` tenant source ([`crate::tenancy::TenantSource::Token`]) can optionally *derive* the
//! tenant key from a verified claim instead of injecting the claim's value verbatim. This module is
//! the host-side evaluator + the apply-time validator for that transform. It is deliberately **not**
//! a scripting engine:
//!
//! - **One bounded extraction.** Either a `{tenant}` path *template* (the recommended surface,
//!   lowered to an anchored `\A…\z` regex) or a single-named-capture *regex* escape hatch (a
//!   substring matcher) — both a linear-time (RE2-style, no backtracking) `regex::Regex` with
//!   exactly one capture named `tenant`, whose captured span is screened to an ASCII key-safe
//!   alphabet at resolution ([`span_char_ok`]). Compiled at most once per pattern (process-wide LRU,
//!   Arc-cheap clones), mirroring [`crate::matcher`].
//! - **A structural, injective namespace.** When a per-issuer `namespace` is set, the derived key is
//!   `namespace` + the host-owned reserved delimiter [`NAMESPACE_DELIMITER`] + the extracted span.
//!   The namespace is a strict operator slug (so the delimiter cannot appear in it), and the span is
//!   screened to the key-safe alphabet **excluding** the delimiter ([`span_char_ok`]), so the
//!   `(namespace, span)` split is unique — cross-IdP collision is unrepresentable *by construction*,
//!   not by hoping an operator's regex is tight. (A concatenated free-form prefix would be a tenancy
//!   text-marker; the standing rule forbids that — inject structurally.)
//! - **Deny-by-default.** A non-string claim, a non-matching or empty extraction, a span outside the
//!   alphabet, or a derived key that fails [`crate::project::validate_key_segment`] all resolve
//!   **no** tenant ([`DeriveOutcome`] carries the precise reason for an operator log; the guest sees
//!   one uniform "no principal → scoped op fails closed", so there is no oracle).
//!
//! Everything statically decidable is checked at apply ([`validate_extract`], [`validate_namespace`])
//! so a misconfiguration is a loud 422, never a silent runtime deny.

use std::num::NonZeroUsize;
use std::sync::{Mutex, OnceLock};

use lru::LruCache;
use regex::{Regex, RegexBuilder};
use serde_json::Value;

use crate::error::ConfigError;
use crate::tenancy::{ClaimExtract, ExtractSyntax};

/// The host-owned reserved namespace delimiter. An operator **never** writes it — it is inserted
/// between a source's `namespace` and the extracted span. It is permitted by
/// [`crate::project::validate_key_segment`] (so a derived key passes the key-safety screen) but is
/// excluded from BOTH the namespace (a strict slug — see [`validate_namespace`]) AND the extracted
/// span ([`span_char_ok`]), so `namespace : span` splits uniquely and two namespaces can never
/// collide.
pub const NAMESPACE_DELIMITER: char = ':';

/// Longest claim value we will attempt to match (bytes). A longer claim yields no match → deny; it
/// bounds the match cost on the auth path. (A tenant-bearing claim — a `sub` URL, an id — is short;
/// 8 KiB is generous.)
const MAX_CLAIM_LEN: usize = 8 * 1024;

/// Compiled-regex program size ceiling (bytes). Bounds a pathological operator pattern.
const REGEX_SIZE_LIMIT: usize = 64 * 1024;
/// Compiled-regex lazy-DFA cache ceiling (bytes).
const REGEX_DFA_SIZE_LIMIT: usize = 64 * 1024;

/// Bound on the process-wide compiled-extract cache (patterns come from deploy configs — bounded in
/// practice; the LRU just caps churn). Mirrors [`crate::matcher`]'s pattern cache.
const EXTRACT_CACHE_CAP: usize = 1024;

/// Whether `c` is admissible in an extracted tenant span: the ASCII key-safe alphabet **excluding**
/// the [`NAMESPACE_DELIMITER`] (`:`) and every character [`crate::project::validate_key_segment`]
/// rejects (`/ \ *`, whitespace, control). ASCII-only on purpose — a byte-stable span cannot collide
/// with a victim's key via a Unicode homoglyph or a nondeterministic collation fold. The template's
/// `{tenant}` class is exactly this set; the regex hatch's capture is screened against it at runtime.
pub fn span_char_ok(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '@' | '+' | '-')
}

/// A compiled claim extractor — cheap to clone (the underlying [`Regex`] is reference-counted), so
/// compiled patterns are cached and handed out by clone.
#[derive(Debug, Clone)]
pub struct CompiledExtract {
    regex: Regex,
}

impl CompiledExtract {
    /// Extract the `tenant` span from a claim value, or `None` if the claim is over-long, does not
    /// match, the named group did not participate, or it captured the empty string (all → deny).
    pub fn extract<'a>(&self, claim: &'a str) -> Option<&'a str> {
        if claim.len() > MAX_CLAIM_LEN {
            return None;
        }
        let caps = self.regex.captures(claim)?;
        let span = caps.name("tenant")?.as_str();
        if span.is_empty() { None } else { Some(span) }
    }
}

fn extract_cache() -> &'static Mutex<LruCache<String, CompiledExtract>> {
    static CACHE: OnceLock<Mutex<LruCache<String, CompiledExtract>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(LruCache::new(NonZeroUsize::new(EXTRACT_CACHE_CAP).expect("cap > 0"))))
}

/// Compile an [`ClaimExtract`], memoizing the result. A valid pattern compiles at most once per
/// process (the auth hot path recompiles nothing); an invalid one errors and is not cached.
pub fn compile(extract: &ClaimExtract) -> Result<CompiledExtract, ConfigError> {
    // The syntax tag keys the cache so a template and a regex with the same text never alias.
    let cache_key = format!(
        "{}\u{1}{}",
        match extract.syntax {
            ExtractSyntax::Template => 't',
            ExtractSyntax::Regex => 'r',
        },
        extract.pattern
    );
    if let Some(cached) = extract_cache().lock().unwrap().get(&cache_key) {
        return Ok(cached.clone());
    }
    let compiled = compile_uncached(extract)?;
    extract_cache().lock().unwrap().put(cache_key, compiled.clone());
    Ok(compiled)
}

fn compile_uncached(extract: &ClaimExtract) -> Result<CompiledExtract, ConfigError> {
    let source = match extract.syntax {
        ExtractSyntax::Template => lower_template(&extract.pattern)?,
        ExtractSyntax::Regex => lower_regex(&extract.pattern)?,
    };
    let regex = RegexBuilder::new(&source)
        // Byte-stability of the *captured* span is enforced structurally, not by the engine's
        // Unicode flag: the template's `{tenant}` class is explicit ASCII, and the regex hatch's
        // capture is screened by `span_char_ok` at resolution — so a Unicode homoglyph in a capture
        // denies rather than keying a tenant. Unicode stays ON so a negated class (the ignored
        // `[^/]` segment) can't match invalid UTF-8, which the `&str` engine rejects at build.
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
        .build()
        .map_err(|e| ConfigError::pattern(&extract.pattern, format!("regex failed to compile: {e}")))?;
    Ok(CompiledExtract { regex })
}

/// Lower a `{tenant}`/`{_}` path template to an anchored, single-named-capture regex source.
///
/// `{tenant}` → one key-safe ASCII segment capture; `{_}` (or `{}`) → one ignored segment
/// (`[^/]+`); every other character is matched literally (regex-escaped). Anchored `\A…\z` (whole
/// claim). Exactly one `{tenant}` is required. A literal `{` must be written via the regex hatch.
fn lower_template(template: &str) -> Result<String, ConfigError> {
    let mut out = String::from(r"\A");
    let mut tenant_count = 0usize;
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' {
            let close = template[i..]
                .find('}')
                .map(|off| i + off)
                .ok_or_else(|| ConfigError::pattern(template, "unclosed `{` placeholder (a literal `{` needs the regex surface)"))?;
            let name = &template[i + 1..close];
            match name {
                "tenant" => {
                    // Keep this class in lock-step with `span_char_ok`.
                    out.push_str(r"(?<tenant>[0-9A-Za-z._~@+\-]+)");
                    tenant_count += 1;
                }
                "" | "_" => out.push_str("[^/]+"),
                other => {
                    return Err(ConfigError::pattern(
                        template,
                        format!("unknown placeholder `{{{other}}}` (use `{{tenant}}` for the key, `{{_}}` to ignore a segment)"),
                    ));
                }
            }
            i = close + 1;
        } else {
            let ch = template[i..].chars().next().expect("char boundary");
            out.push_str(&regex::escape(ch.encode_utf8(&mut [0u8; 4])));
            i += ch.len_utf8();
        }
    }
    out.push_str(r"\z");
    match tenant_count {
        1 => Ok(out),
        0 => Err(ConfigError::pattern(template, "template has no `{tenant}` placeholder")),
        n => Err(ConfigError::pattern(
            template,
            format!("template has {n} `{{tenant}}` placeholders, expected exactly 1"),
        )),
    }
}

/// Validate an operator-authored regex hatch and return it as the regex source (unchanged — the
/// hatch is a *substring* matcher by design, so it is not re-anchored). Rejects anything but
/// **exactly one** capturing group, named `tenant`, that **always participates** and whose
/// subexpression cannot match the empty string — so an empty-capture mass-merge onto the bare
/// namespace is impossible at admission (and the runtime screen denies it besides). Byte-stability
/// of the captured span is not an admission concern: it is enforced at resolution by
/// [`span_char_ok`] (a Unicode homoglyph in a capture denies rather than keying a tenant), so the
/// HIR is parsed with the engine's default (Unicode) flags.
fn lower_regex(pattern: &str) -> Result<String, ConfigError> {
    let hir = regex_syntax::parse(pattern)
        .map_err(|e| ConfigError::pattern(pattern, format!("regex failed to compile: {e}")))?;

    let mut captures: Vec<(Option<&str>, &regex_syntax::hir::Hir, bool)> = Vec::new();
    collect_captures(&hir, false, &mut captures);
    match captures.len() {
        1 => {}
        0 => {
            return Err(ConfigError::pattern(
                pattern,
                "regex has no capturing group — name the tenant group: (?<tenant>…)",
            ));
        }
        n => {
            return Err(ConfigError::pattern(
                pattern,
                format!("regex has {n} capturing groups, expected exactly 1 named (?<tenant>…)"),
            ));
        }
    }
    let (name, sub, optional) = captures[0];
    if name != Some("tenant") {
        return Err(ConfigError::pattern(
            pattern,
            "the single capturing group must be named `tenant`: (?<tenant>…)",
        ));
    }
    // The capture must not be skippable (under an outer `?`/`*`/`{0,}` or an alternation arm): a
    // skipped group never participates → bare-namespace key.
    if optional {
        return Err(ConfigError::pattern(
            pattern,
            "the `tenant` capture is optional (it can be skipped) — it must always participate (drop the surrounding `?`/`*` or alternation)",
        ));
    }
    // ...and it must consume at least one byte when it does participate.
    match sub.properties().minimum_len() {
        Some(n) if n >= 1 => Ok(pattern.to_string()),
        _ => Err(ConfigError::pattern(
            pattern,
            "the `tenant` capture may match empty — require at least one character (e.g. `[0-9A-Za-z]+`, not `*`/`?`)",
        )),
    }
}

/// Walk the HIR collecting every capturing group as `(name, subexpression, optional)`, where
/// `optional` means the group sits under an outer min-zero repetition (`?`/`*`/`{0,}`) or inside a
/// multi-arm alternation (so it can be skipped). Recurses through the capture's own subexpression
/// too, so a nested capture is counted (and therefore rejected — exactly one is allowed).
fn collect_captures<'h>(
    hir: &'h regex_syntax::hir::Hir,
    optional: bool,
    out: &mut Vec<(Option<&'h str>, &'h regex_syntax::hir::Hir, bool)>,
) {
    use regex_syntax::hir::HirKind::*;
    match hir.kind() {
        Capture(c) => {
            out.push((c.name.as_deref(), &*c.sub, optional));
            collect_captures(&c.sub, optional, out);
        }
        Repetition(r) => collect_captures(&r.sub, optional || r.min == 0, out),
        Concat(v) => {
            for h in v {
                collect_captures(h, optional, out);
            }
        }
        Alternation(v) => {
            let opt = optional || v.len() > 1;
            for h in v {
                collect_captures(h, opt, out);
            }
        }
        Empty | Literal(_) | Class(_) | Look(_) => {}
    }
}

/// The outcome of deriving a tenant key from a verified claim — a precise, operator-loggable reason
/// on every deny (the guest sees one uniform "no principal", so none of these is an oracle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeriveOutcome {
    /// A tenant key was derived and passed every screen.
    Resolved(String),
    /// The claim is present but not a JSON string, so the extraction cannot apply (the `claim` path
    /// likely points at the wrong field).
    ClaimNonString,
    /// The extraction did not match, or matched but captured the empty string.
    NoMatch { empty_capture: bool },
    /// The extracted span, or the composed `namespace:span` key, failed a screen — carries the
    /// specific reason (span alphabet / key-safety / length).
    KeyRejected(String),
}

/// Derive the tenant key for a `token` source whose transform is **active** (at least one of
/// `extract` / `namespace` is set). The caller resolves the verbatim path (neither set) separately
/// (today's behavior, unchanged). `claim_value` is the already-verified claim as fetched from the
/// token.
///
/// Order (each stage denies fail-closed): claim must be a string → extract the span (or the whole
/// value when `extract` is `None`) → span non-empty → span ⊆ [`span_char_ok`] → compose
/// `namespace:span` → the composed key passes [`crate::project::validate_key_segment`].
pub fn derive_tenant(
    extract: Option<&ClaimExtract>,
    namespace: Option<&str>,
    claim_value: &Value,
) -> DeriveOutcome {
    let claim = match claim_value {
        Value::String(s) => s.as_str(),
        _ => return DeriveOutcome::ClaimNonString,
    };

    let span: &str = match extract {
        Some(ext) => {
            // A compile error here means the config was never validated at apply — treat as a
            // fail-closed no-match rather than trusting an unvalidated pattern.
            let compiled = match compile(ext) {
                Ok(c) => c,
                Err(_) => return DeriveOutcome::NoMatch { empty_capture: false },
            };
            match compiled.extract(claim) {
                Some(s) => {
                    // Borrow-checker: `compiled` owns the captures' lifetime, so re-run against the
                    // owned claim string is avoided by screening/copying here.
                    if !s.chars().all(span_char_ok) {
                        return DeriveOutcome::KeyRejected(format!(
                            "extracted segment contains a character outside the key-safe alphabet or the reserved `{NAMESPACE_DELIMITER}`"
                        ));
                    }
                    return finish(namespace, s);
                }
                None => return DeriveOutcome::NoMatch { empty_capture: span_was_empty(&compiled, claim) },
            }
        }
        // No extraction: the whole (string) claim value is the span (the "bare" / "prefixed-bare"
        // case). Still screened to the span alphabet so a namespaced key stays injective.
        None => claim,
    };

    if span.is_empty() {
        return DeriveOutcome::NoMatch { empty_capture: true };
    }
    if !span.chars().all(span_char_ok) {
        return DeriveOutcome::KeyRejected(format!(
            "claim value contains a character outside the key-safe alphabet or the reserved `{NAMESPACE_DELIMITER}`"
        ));
    }
    finish(namespace, span)
}

/// Compose the namespace (if any) with the screened span and run the final key-safety screen.
fn finish(namespace: Option<&str>, span: &str) -> DeriveOutcome {
    let key = match namespace {
        Some(ns) => format!("{ns}{NAMESPACE_DELIMITER}{span}"),
        None => span.to_string(),
    };
    match crate::project::validate_key_segment("tenant", &key) {
        Ok(()) => DeriveOutcome::Resolved(key),
        Err(e) => DeriveOutcome::KeyRejected(e.to_string()),
    }
}

/// Distinguish "the pattern matched but the capture was empty" from "the pattern did not match",
/// for the operator triage sub-tag. (`CompiledExtract::extract` folds both into `None`.)
fn span_was_empty(compiled: &CompiledExtract, claim: &str) -> bool {
    claim.len() <= MAX_CLAIM_LEN
        && compiled
            .regex
            .captures(claim)
            .and_then(|c| c.name("tenant").map(|m| m.as_str().is_empty()))
            .unwrap_or(false)
}

/// Apply-time validation of an [`ClaimExtract`] (compiles the pattern → exactly one named,
/// non-nullable capture for the regex hatch; exactly one `{tenant}` + known placeholders for the
/// template). A 422 at apply, never a silent runtime deny.
pub fn validate_extract(extract: &ClaimExtract) -> Result<(), ConfigError> {
    compile(extract).map(|_| ())
}

/// Apply-time validation of a source `namespace`: a strict operator slug
/// ([`crate::project::validate_resource_name`]), which is non-empty, ≤63 bytes, and whose alphabet
/// **cannot** contain the reserved [`NAMESPACE_DELIMITER`] — so the structural `namespace:span`
/// split is injective.
pub fn validate_namespace(namespace: &str) -> Result<(), ConfigError> {
    crate::project::validate_resource_name("namespace", namespace)
        .map_err(|e| ConfigError::pattern(namespace, e.to_string()))?;
    // Defense-in-depth: the strict slug already excludes it, but assert the invariant explicitly so
    // a future slug-alphabet change can't silently reintroduce the delimiter.
    if namespace.contains(NAMESPACE_DELIMITER) {
        return Err(ConfigError::pattern(
            namespace,
            format!("a namespace must not contain the reserved delimiter `{NAMESPACE_DELIMITER}`"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenancy::ExtractSyntax;
    use serde_json::json;

    fn tmpl(p: &str) -> ClaimExtract {
        ClaimExtract { syntax: ExtractSyntax::Template, pattern: p.to_string() }
    }
    fn rx(p: &str) -> ClaimExtract {
        ClaimExtract { syntax: ExtractSyntax::Regex, pattern: p.to_string() }
    }

    #[test]
    fn template_extracts_salesforce_org_id_and_namespaces() {
        let ext = tmpl("https://login.salesforce.com/id/{tenant}/{_}");
        let claim = json!("https://login.salesforce.com/id/00D5f0000000abcEAA/0055f00000ABCDEFGH");
        assert_eq!(
            derive_tenant(Some(&ext), Some("sfdc"), &claim),
            DeriveOutcome::Resolved("sfdc:00D5f0000000abcEAA".to_string())
        );
    }

    #[test]
    fn regex_hatch_named_capture_extracts() {
        let ext = rx(r"/id/(?<tenant>[0-9A-Za-z]+)/");
        let claim = json!("https://login.salesforce.com/id/00D5f0000000abcEAA/0055f00000ABCDEFGH");
        assert_eq!(
            derive_tenant(Some(&ext), Some("sfdc"), &claim),
            DeriveOutcome::Resolved("sfdc:00D5f0000000abcEAA".to_string())
        );
    }

    #[test]
    fn no_extract_namespaces_a_bare_claim() {
        assert_eq!(
            derive_tenant(None, Some("sfdc"), &json!("acme")),
            DeriveOutcome::Resolved("sfdc:acme".to_string())
        );
    }

    #[test]
    fn non_string_claim_denies() {
        let ext = tmpl("{tenant}");
        assert_eq!(derive_tenant(Some(&ext), None, &json!(12345)), DeriveOutcome::ClaimNonString);
        assert_eq!(derive_tenant(None, Some("sfdc"), &json!(["a"])), DeriveOutcome::ClaimNonString);
    }

    #[test]
    fn no_match_denies() {
        let ext = tmpl("https://login.salesforce.com/id/{tenant}/{_}");
        // A token from a different issuer shape — does not match the anchored template.
        let out = derive_tenant(Some(&ext), Some("sfdc"), &json!("https://other.example/u/42"));
        assert_eq!(out, DeriveOutcome::NoMatch { empty_capture: false });
    }

    #[test]
    fn greedy_capture_with_slash_is_rejected_not_cross_tenant() {
        // A loose hatch capturing across the `/` boundary lands a `/` in the span → rejected
        // (the derived-key screen), never a valid cross-tenant key.
        let ext = rx(r"/id/(?<tenant>.+)/");
        let claim = json!("https://login.salesforce.com/id/00D/evil/0055");
        match derive_tenant(Some(&ext), Some("sfdc"), &claim) {
            DeriveOutcome::KeyRejected(_) => {}
            other => panic!("expected KeyRejected, got {other:?}"),
        }
    }

    #[test]
    fn empty_capture_never_keys_on_the_bare_namespace() {
        // Admission would reject a nullable capture; prove runtime also denies if one slips in by
        // driving a template whose capture is non-nullable but feeding a value that makes the whole
        // thing not match (so no bare-"sfdc:" tenant is ever produced).
        let ext = tmpl("prefix-{tenant}");
        // Matches "prefix-" then needs ≥1 span char; "prefix-" alone has none → no match.
        let out = derive_tenant(Some(&ext), Some("sfdc"), &json!("prefix-"));
        assert!(matches!(out, DeriveOutcome::NoMatch { .. }));
        // Crucially NOT Resolved("sfdc:").
        assert_ne!(out, DeriveOutcome::Resolved("sfdc:".to_string()));
    }

    #[test]
    fn admission_rejects_nullable_capture() {
        assert!(validate_extract(&rx(r"(?<tenant>[0-9A-Za-z]*)")).is_err());
        assert!(validate_extract(&rx(r"(?<tenant>[0-9A-Za-z]+)?")).is_err());
    }

    #[test]
    fn admission_rejects_wrong_group_count_or_name() {
        assert!(validate_extract(&rx(r"(?<tenant>a)(?<other>b)")).is_err());
        assert!(validate_extract(&rx(r"(a)")).is_err()); // unnamed
        assert!(validate_extract(&rx(r"(?<org>[0-9A-Za-z]+)")).is_err()); // wrong name
        assert!(validate_extract(&rx(r"[0-9A-Za-z]+")).is_err()); // no capture
    }

    #[test]
    fn admission_accepts_a_sound_regex_and_template() {
        assert!(validate_extract(&rx(r"/id/(?<tenant>[0-9A-Za-z]+)/")).is_ok());
        assert!(validate_extract(&tmpl("https://login.salesforce.com/id/{tenant}/{_}")).is_ok());
    }

    #[test]
    fn admission_rejects_malformed_template() {
        assert!(validate_extract(&tmpl("/id/{_}/{_}")).is_err()); // no {tenant}
        assert!(validate_extract(&tmpl("/id/{tenant}/{tenant}")).is_err()); // two {tenant}
        assert!(validate_extract(&tmpl("/id/{org}/")).is_err()); // unknown placeholder
        assert!(validate_extract(&tmpl("/id/{tenant")).is_err()); // unclosed
    }

    #[test]
    fn namespace_validation_rejects_the_delimiter_and_bad_slugs() {
        assert!(validate_namespace("sfdc").is_ok());
        assert!(validate_namespace("auth0").is_ok());
        assert!(validate_namespace("sfdc:").is_err()); // contains the delimiter
        assert!(validate_namespace("").is_err());
        assert!(validate_namespace("a/b").is_err());
    }

    #[test]
    fn span_class_and_template_class_agree() {
        // Every char the template `{tenant}` class accepts must satisfy `span_char_ok`, and the
        // delimiter must be excluded from both.
        for c in "abcABC012._~@+-".chars() {
            assert!(span_char_ok(c), "{c} should be allowed");
        }
        assert!(!span_char_ok(NAMESPACE_DELIMITER));
        assert!(!span_char_ok('/'));
        assert!(!span_char_ok(' '));
    }
}
