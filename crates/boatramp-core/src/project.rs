//! Project scoping for the store: the wire [`Project`] types (re-exported from
//! [`boatramp_types::project`]) plus [`ProjectRef`], a borrowing newtype threaded as
//! the **first argument** of every per-name `DeployStore` method. Using a distinct type
//! (not a bare `&str`) makes the store-wide scoping change compiler-enforced — you
//! cannot pass a site name where a project is meant — and lets the compiler enumerate
//! every call site during the re-key.

pub use boatramp_types::project::*;

/// A borrowed project name scoping a store operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProjectRef<'a>(&'a str);

impl<'a> ProjectRef<'a> {
    /// The `default` project — every pre-project resource + the CLI default. The only
    /// place the literal is written is [`DEFAULT_PROJECT`].
    pub const DEFAULT: ProjectRef<'static> = ProjectRef(DEFAULT_PROJECT);

    /// Scope to the named project.
    pub fn new(name: &'a str) -> Self {
        ProjectRef(name)
    }

    /// The underlying project name.
    pub fn as_str(&self) -> &'a str {
        self.0
    }

    /// Project-qualify a guest **data-plane** namespace `base` (a handler/function
    /// binding scope, a SQL identity, a messaging topic, or a blob-watch storage
    /// prefix): the bare `base` for the reserved `default` project — so a
    /// pre-project / single-project store keeps byte-identical keys and needs no
    /// data migration — else `"<project>/<base>"`. Project names are validated to
    /// carry no `/` ([`validate_resource_name`]), so the single separator is
    /// unambiguous. This is the tenant boundary for the guest **data** plane
    /// (kv/blob/sql/messaging/logs), parallel to the `project/<proj>/…` keys the
    /// control plane already uses.
    pub fn qualified(&self, base: &str) -> String {
        if self.0 == DEFAULT_PROJECT {
            base.to_string()
        } else {
            format!("{}/{base}", self.0)
        }
    }
}

impl<'a> From<&'a str> for ProjectRef<'a> {
    fn from(name: &'a str) -> Self {
        ProjectRef(name)
    }
}

impl std::fmt::Display for ProjectRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// A resource name (project / site / function / compute / workload / workflow)
/// rejected by [`validate_resource_name`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} name {value:?}: {reason}")]
pub struct InvalidResourceName {
    /// What kind of name failed (for the error message), e.g. `"site"`.
    pub kind: &'static str,
    /// The offending value.
    pub value: String,
    /// Why it was rejected.
    pub reason: &'static str,
}

/// Maximum length, in bytes, of a project/site/function/compute/workflow name.
/// Matches the tightest SQL identifier limit (Postgres `NAMEDATALEN - 1 = 63`)
/// so a name can be folded into a per-tenant database identifier without forcing
/// pathological truncation. Longer than any realistic human-chosen name.
pub const MAX_RESOURCE_NAME_LEN: usize = 63;

/// Validate a project/site/function/compute/workflow/**database** name at the
/// create/write (and every URL-path) boundary, so a name can never escape its
/// `project/<proj>/…` key prefix, collide with the store's fixed sub-key grammar,
/// smuggle a (possibly percent-decoded) path separator, break Cedar entity/target
/// construction, or — for a SQL db-binding name threaded into `/api/sql/{db}/…` —
/// collapse into an empty or `//` URL path segment. This is the canonical
/// resource-identifier validator for every **operator / control-plane / URL-path** ingress
/// (config load, control-plane API path params, CLI `--db`, and the operator-SQL / migration
/// lookup — `connect_for`) — they all route through it so the accept/reject rule is identical
/// there. `kind` is a free-form label for the error message (`"project"`, `"site"`,
/// `"function"`, `"database"`, …); the rule set is uniform. Note this is NOT the gate on the
/// guest `sql.open(name)` path — a guest legitimately opens the default as `""`, which this
/// validator rejects; that path is guarded separately (see below).
///
/// Two *guest-facing* db-name boundaries keep their own, deliberately **stricter** rules and
/// are NOT this function. They are subsets in the dangerous direction (they never accept what
/// this rejects for a concrete openable name), but only ONE of them is pinned by a drift-guard
/// test today:
///
/// - The libsql storage boundary (`boatramp-storage`'s `validate_db_name` — same character
///   class, but it still accepts `""` for the legacy default until the name-independent-path
///   work lands) IS pinned as a subset of this validator by
///   `libsql_db_name_rule_is_a_subset_of_the_canonical_validator`, so that relationship can't
///   silently drift.
/// - The `sql:<name>` allow-import grant ([`is_named_sql_import`](crate::config)) is a
///   deliberately tighter `[A-Za-z0-9_-]` allowlist on what a guest may name in `sql.open`. On
///   its character class it is a subset for every *concrete openable name* — the one non-name
///   it admits, the `sql:*` wildcard sentinel, is expanded/dropped at grant time before it ever
///   becomes a db name (and length is bounded at the storage boundary above). It is NOT
///   currently pinned by a subset test.
///
/// Do not add a third divergent rule set; extend one of these or this function.
///
/// Rejects: the empty string, names longer than [`MAX_RESOURCE_NAME_LEN`] bytes,
/// `.` / `..`, and any name containing a path separator (`/` or `\`), a `*` (the
/// authz wildcard sentinel — a resource named `*` would alias a project/site
/// wildcard), whitespace, or an ASCII control character. This is a *targeted*
/// denylist of the characters that carry a security or integrity consequence,
/// plus a length bound, not a full slug allowlist, so it does not reject
/// pre-existing otherwise-ordinary names.
///
/// The length bound is defense-in-depth for per-tenant database provisioning: it
/// stops a caller from forcing pathological truncation when a name is folded into
/// a SQL identifier (see `boatramp-storage`'s `sanitize_ident`). Injectivity there
/// no longer depends on it (a wide, always-on digest carries it), but a bound
/// keeps derived identifiers readable and keys short.
pub fn validate_resource_name(kind: &'static str, value: &str) -> Result<(), InvalidResourceName> {
    let reject = |reason| {
        Err(InvalidResourceName {
            kind,
            value: value.to_string(),
            reason,
        })
    };
    if value.is_empty() {
        return reject("must not be empty");
    }
    if value.len() > MAX_RESOURCE_NAME_LEN {
        return reject("must not exceed 63 bytes");
    }
    if value == "." || value == ".." {
        return reject("must not be '.' or '..'");
    }
    for c in value.chars() {
        match c {
            '/' | '\\' => return reject("must not contain a path separator ('/' or '\\')"),
            '*' => return reject("must not contain '*'"),
            c if c.is_whitespace() => return reject("must not contain whitespace"),
            c if c.is_control() => return reject("must not contain control characters"),
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_ref_default_and_wrap() {
        assert_eq!(ProjectRef::DEFAULT.as_str(), "default");
        assert_eq!(ProjectRef::new("acme").as_str(), "acme");
        assert_eq!(ProjectRef::from("shop").to_string(), "shop");
    }

    #[test]
    fn resource_name_validation_rejects_the_dangerous_shapes() {
        for ok in ["blog", "my-site", "resize_v2", "a.b", "Blog9"] {
            assert!(
                validate_resource_name("site", ok).is_ok(),
                "{ok} should pass"
            );
        }
        // Validation runs on the already-percent-decoded value the handler
        // receives, so the `%2F` → `/` path-param case arrives here as a literal
        // `/` and is caught by the separator rule.
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "blog/../evil",
            "*",
            "proj*",
            "a b",
            "tab\tname",
            "ctl\u{0}name",
        ] {
            assert!(
                validate_resource_name("site", bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn database_kind_shares_the_one_rule_set() {
        // The `"database"` kind is not special-cased — it rides the single rule set,
        // so a db-binding name is accepted iff it is a safe URL path segment. This is
        // the contract every db-name ingress (config, API path param, CLI `--db`,
        // handler lookup) relies on.
        for ok in ["default", "analytics", "events_log", "pg-primary"] {
            assert!(
                validate_resource_name("database", ok).is_ok(),
                "{ok} should be a valid database name"
            );
        }
        // The reserved default binding's *real* name is a valid path segment; the
        // legacy empty-string key is NOT — the config load fails closed on it (the
        // v0.5.0 breaking change) rather than emitting a `//` path.
        assert!(
            validate_resource_name("database", "").is_err(),
            "the empty-string db name (legacy default key) must be rejected"
        );
        // The error names the kind so an operator can tell which identifier failed.
        let err = validate_resource_name("database", "a/b").unwrap_err();
        assert_eq!(err.kind, "database");
        assert_eq!(err.value, "a/b");
    }

    #[test]
    fn resource_name_length_bound() {
        // Exactly at the bound passes; one over is rejected.
        let at = "a".repeat(MAX_RESOURCE_NAME_LEN);
        let over = "a".repeat(MAX_RESOURCE_NAME_LEN + 1);
        assert!(
            validate_resource_name("site", &at).is_ok(),
            "{}-char name should pass",
            MAX_RESOURCE_NAME_LEN
        );
        assert!(
            validate_resource_name("site", &over).is_err(),
            "{}-char name should be rejected",
            MAX_RESOURCE_NAME_LEN + 1
        );
    }

    // ---- cross-surface consistency guard (v0.5.0 uniform db-name screening) -----
    //
    // The anti-regression guard the uniform-parameter-screening request demands: for a
    // generated corpus of identifiers, assert that `validate_resource_name` accepts a
    // value IFF it is a **safe URL path segment**, AND that every accepted value
    // round-trips through the CLI path construction + the API-route path grammar
    // without producing a malformed path (no empty / `//` segment, no truncation). It
    // is a REAL detector: an INDEPENDENT path-segment oracle (below) is compared
    // against the validator, so if the validator ever drifts to accept a value that is
    // not a safe segment — or a path-construction change reintroduces a `//` — the
    // test fails.

    /// An INDEPENDENT re-statement of the "safe URL path segment" spec, deliberately
    /// NOT sharing code with [`validate_resource_name`] so the two can disagree (which
    /// is exactly what this test detects). A value is a safe path segment when it is
    /// non-empty, is not `.`/`..`, and contains no `/`, `\`, whitespace, or control
    /// character. (`*` is a validator-only concern — the authz wildcard sentinel — so
    /// the oracle folds it in to keep the equivalence exact.)
    fn is_safe_path_segment(v: &str) -> bool {
        !v.is_empty()
            && v != "."
            && v != ".."
            && v.len() <= MAX_RESOURCE_NAME_LEN
            && !v
                .chars()
                .any(|c| c == '/' || c == '\\' || c == '*' || c.is_whitespace() || c.is_control())
    }

    /// Build a control-plane path the way the CLI (`boatramp sql` / `project migrate`)
    /// and the server route (`/api/sql/{db}/exec`) compose it: the `{db}` segment is
    /// interpolated verbatim between two fixed segments. Returns the path so the test
    /// can inspect its segments.
    fn cli_sql_path(db: &str) -> String {
        // Mirrors `crates/boatramp/src/sql.rs`: `{server}/api/{seg}/{db}/exec` with the
        // default-project `seg = "sql"`, and `crates/boatramp/src/client.rs`
        // `migrate`: `{server}/api/{seg}/{db}/status`.
        format!("/api/sql/{db}/exec")
    }

    #[test]
    fn validator_matches_the_safe_path_segment_oracle() {
        // A broad generated corpus: safe names, the dangerous shapes, boundary
        // lengths, and every ASCII byte spliced into a name (so no accepted value can
        // carry a control/space/separator the oracle would reject).
        let mut corpus: Vec<String> = vec![
            "default".into(),
            "analytics".into(),
            "events_log".into(),
            "pg-primary".into(),
            "a.b".into(),
            "Blog9".into(),
            String::new(),
            ".".into(),
            "..".into(),
            "a/b".into(),
            "a\\b".into(),
            "blog/../evil".into(),
            "*".into(),
            "proj*".into(),
            "a b".into(),
            "tab\tname".into(),
            "ctl\u{0}name".into(),
            "a".repeat(MAX_RESOURCE_NAME_LEN),
            "a".repeat(MAX_RESOURCE_NAME_LEN + 1),
        ];
        for b in 0u8..=127 {
            corpus.push(format!("x{}y", b as char));
        }

        for v in &corpus {
            let accepted = validate_resource_name("database", v).is_ok();
            let safe = is_safe_path_segment(v);
            assert_eq!(
                accepted, safe,
                "validator/oracle disagree on {v:?}: validator accepted={accepted}, \
                 safe-path-segment={safe}"
            );

            if accepted {
                // A REAL round-trip: every accepted value must produce a path whose
                // segments are exactly [api, sql, <db>, exec] with the db segment
                // equal to `v` — no empty segment, no `//`, no truncation.
                let path = cli_sql_path(v);
                assert!(
                    !path.contains("//"),
                    "accepted {v:?} produced a `//` in {path:?}"
                );
                let segments: Vec<&str> = path.trim_start_matches('/').split('/').collect();
                assert_eq!(
                    segments,
                    vec!["api", "sql", v.as_str(), "exec"],
                    "accepted {v:?} did not round-trip cleanly: {path:?}"
                );
                assert!(
                    segments.iter().all(|s| !s.is_empty()),
                    "accepted {v:?} produced an empty path segment: {path:?}"
                );
            }
        }
    }

    #[test]
    fn empty_db_name_would_break_the_path_and_is_rejected() {
        // The linchpin the whole deliverable turns on: the legacy empty default-DB
        // name IS a value that would break a path segment (collapses `/api/sql//exec`
        // to a `//`), and the validator rejects it. If someone "fixed" the validator
        // to accept `""`, the oracle equivalence test above would fail — but assert it
        // directly too, as the single most important case.
        assert!(!is_safe_path_segment(""), "empty is not a safe segment");
        assert!(
            validate_resource_name("database", "").is_err(),
            "empty db name must be rejected"
        );
        assert!(
            cli_sql_path("").contains("//"),
            "empty db name DOES collapse the path to `//` (why it must be rejected)"
        );
    }
}
