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
/// **ASCII strict single-label slug (v0.7.0 breaking).** Accepts a name IFF it
/// matches `^[A-Za-z0-9]([A-Za-z0-9_-]*[A-Za-z0-9])?$` and is 1–[`MAX_RESOURCE_NAME_LEN`]
/// bytes: the first AND last byte must be ASCII alphanumeric, interior bytes may
/// additionally be `_` or `-`, and a single-character name must be alphanumeric.
///
/// This is an **allowlist**, not the pre-v0.7.0 path-traversal denylist. The old
/// denylist rejected only the characters that carried an immediate consequence
/// (`.`/`..`, `/`, `\`, `*`, whitespace, control), so `${PROJECT}`, `{tenant}`,
/// `a;b`, `` `x` ``, `a|b`, `a%b`, `a#b`, `a"b`, `a'b`, `a$b`, `a(b)` all *passed* —
/// every one a latent injection waiting for the next sink that formats a name into a
/// shell / `.env` / DNS / SQL string. The allowlist removes the whole class: only
/// the slug alphabet survives, and it is enforced with a **byte loop**
/// (`value.bytes()` + [`u8::is_ascii_alphanumeric`]) so a Unicode homoglyph
/// (`аcme` Cyrillic, `acme１` fullwidth, `café`) cannot pass by satisfying
/// `char::is_alphanumeric`. Mirror of `cedar.rs::is_safe_ident`. The `.`/`..` guard
/// and the `≤63B` cap are now subsumed by the rule (a `.` byte is not in the
/// alphabet), but the length check runs first for a precise error.
///
/// The leading-`-`/`_` ban is also a flag-injection defense: a name is never emitted
/// as a bare argument that a downstream tool could parse as an option.
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
    // Precise reasons for the two most common shapes (empty / over-long) before the
    // general alphabet reason, so an operator reads the specific problem. Both are
    // subsumed by `is_valid_resource_slug` (it also rejects them), so the accept/reject
    // decision is unchanged — only the message is sharper.
    if value.is_empty() {
        return reject("must not be empty");
    }
    if value.len() > MAX_RESOURCE_NAME_LEN {
        return reject("must not exceed 63 bytes");
    }
    // The one canonical rule (byte loop, homoglyph-safe) lives in the lowest crate so
    // the authz-match backstop shares it verbatim; see [`is_valid_resource_slug`].
    if is_valid_resource_slug(value) {
        Ok(())
    } else {
        reject(INVALID_NAME_REASON)
    }
}

/// Validate a **data-plane-derived** name used as a KV/blob **key segment** — a `tenant`
/// (the host-resolved `ScopeAxis::Tenant` value from a signed `tid` claim, which is
/// routinely an email `user@acme.com` or a dotted domain `acme.corp`) or a `container`
/// (which an operator `{tenant}` template legitimately expands to a tenant value, e.g.
/// `assets-user@acme.com`).
///
/// Enforces **key safety only** — the segment cannot reshape the key or traverse
/// (`/`, `\`, `.`/`..`, `*`, whitespace, control are rejected; ≤63 bytes) — WITHOUT the
/// single-label slug alphabet, because these values are NOT operator-chosen identifiers:
/// they carry `.`/`@`/etc. from an externally-signed tenant identity. This is deliberately
/// the pre-v0.7.0 denylist rule, preserved for exactly the two kinds that are data-plane
/// values rather than resource identifiers. Do NOT route operator identifiers
/// (project/site/database/…) through this — they use [`validate_resource_name`]'s strict
/// slug. A homoglyph is not an impersonation vector here: the tenant is the token's own
/// signed claim, not an operator-registered name.
pub fn validate_key_segment(kind: &'static str, value: &str) -> Result<(), InvalidResourceName> {
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

/// Validate a **token role target** (audit A8) at every mint feeder — the segment-aware
/// counterpart to [`validate_resource_name`], because a target is a `/`-bearing scope
/// string, not a single name segment.
///
/// A role scope is `<role>:<target>` ([`GrantedRole::parse`](crate::authz::GrantedRole::parse)),
/// and the `<target>` is one of:
/// - `<project>` — a bare project target;
/// - `<project>/<site>` — a per-site target;
/// - `<project>/*` — a project wildcard.
///
/// This splits on `/` (exactly one permitted, optionally the trailing wildcard) and
/// runs [`validate_resource_name`] on each real segment (`project`, and `site` for a
/// two-segment target). The whole string is NEVER passed to `validate_resource_name`
/// (it rejects `/`). A wildcard `*` segment is the sole non-slug token accepted, and
/// only in the trailing `<project>/*` position — it is the authz project-wildcard
/// sentinel, never a resource name.
///
/// Called at all FOUR mint feeders (`create_token`, `bootstrap_token`, OIDC
/// `auth_exchange`, offline `mint_offline`) so a `publisher:${PROJECT}` role can never
/// be issued. It is complemented by the fail-closed authz-match backstop
/// (`authz::target_matches` via [`is_conforming_role_target`]) which denies any target
/// that reaches match time non-conforming (a pre-v0.7.0 or offline token).
///
/// A **global** role (no `:`/target) never reaches here — the caller only validates a
/// [`GrantedRole`] whose `target` is `Some`.
pub fn validate_role_target(target: &str) -> Result<(), InvalidResourceName> {
    let reject = |value: &str, reason| {
        Err(InvalidResourceName {
            kind: "role target",
            value: value.to_string(),
            reason,
        })
    };
    match target.split_once('/') {
        // `<project>/*` — the project wildcard: validate the project segment only.
        Some((project, "*")) => validate_resource_name("project", project),
        // `<project>/<site>` — reject a second `/` (three-segment target), then both.
        Some((project, site)) => {
            if site.contains('/') {
                return reject(
                    target,
                    "must be `<project>`, `<project>/<site>`, or `<project>/*` \
                     (at most one '/')",
                );
            }
            validate_resource_name("project", project)?;
            validate_resource_name("site", site)
        }
        // A bare `<project>` target.
        None => validate_resource_name("project", target),
    }
}

/// The maximum length (bytes) of an external object key accepted by the S3
/// ingress — matches the S3 object-key limit and bounds the derived storage path.
pub const MAX_OBJECT_KEY_LEN: usize = 1024;

/// Validate a **decoded** external object key destined for the storage path
/// `hblob/{project-qualified-site}/{container}/{key}` (the S3 blob-ingress
/// choke point).
///
/// Unlike [`validate_resource_name`] — which screens a single path *segment* and
/// rejects `/` — an object key is a `/`-separated *path* that legitimately
/// contains `/` (e.g. `avatars/<user>/<uuid>.jpg`). This is the traversal-safe
/// screen enforced where the S3 face composes the storage key, so an uploaded
/// object can never escape its scoped prefix on **any** backend (the `fs`
/// traversal backstop does not exist for the cloud `Storage` backends).
///
/// The caller MUST percent-decode the key exactly once before calling this
/// (SigV4 signs the encoded form; storage uses the decoded form).
///
/// Rejects: the empty string; keys longer than [`MAX_OBJECT_KEY_LEN`] bytes; a
/// leading `/` (absolute) or any empty segment (`//`, a trailing `/`); any `.`
/// or `..` segment (traversal); any segment in boatramp's reserved `.boatramp*`
/// namespace (the container marker + multipart staging live there, so a client
/// key must not collide with them); a backslash, a `*` (the authz wildcard
/// sentinel), or any ASCII control character (incl. NUL / newline). Other bytes
/// — spaces, mid-name dots — are allowed (S3 keys are liberal, and the key is
/// otherwise host-scoped).
pub fn validate_object_key(value: &str) -> Result<(), InvalidResourceName> {
    let reject = |reason| {
        Err(InvalidResourceName {
            kind: "object key",
            value: value.to_string(),
            reason,
        })
    };
    if value.is_empty() {
        return reject("must not be empty");
    }
    if value.len() > MAX_OBJECT_KEY_LEN {
        return reject("must not exceed 1024 bytes");
    }
    for c in value.chars() {
        match c {
            '\\' => return reject("must not contain a backslash"),
            '*' => return reject("must not contain '*'"),
            c if c.is_control() => return reject("must not contain control characters"),
            _ => {}
        }
    }
    for segment in value.split('/') {
        if segment.is_empty() {
            return reject(
                "must not contain an empty path segment (no leading/trailing/doubled '/')",
            );
        }
        if segment == "." || segment == ".." {
            return reject("must not contain a '.' or '..' path segment");
        }
        // boatramp reserves the `.boatramp*` segment namespace for the container
        // marker (`.boatramp-container`) and multipart staging (`.boatramp-uploads/`);
        // a client key must not collide with it. Case-insensitive so a
        // case-folding filesystem can't be tricked with `.BoatRamp*`.
        if segment.to_ascii_lowercase().starts_with(".boatramp") {
            return reject("must not use a reserved '.boatramp*' path segment");
        }
    }
    Ok(())
}

#[cfg(test)]
mod object_key_tests {
    use super::*;

    #[test]
    fn accepts_ordinary_and_nested_keys() {
        for ok in [
            "avatars/u1/abc.jpg",
            "abc123",
            "a/b/c",
            "file with spaces.png",
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "a.b.c",
            "deep/nested/path/ok.bin",
            "images/2026/09/photo-01.png",
        ] {
            assert!(validate_object_key(ok).is_ok(), "{ok:?} should pass");
        }
    }

    #[test]
    fn rejects_traversal_and_absolute_and_empty_segments() {
        for bad in [
            "",          // empty
            "/leading",  // absolute / leading slash → empty first segment
            "trailing/", // trailing slash → empty last segment
            "a//b",      // doubled slash → empty middle segment
            "..",        // traversal
            ".",         // current-dir segment
            "a/../b",    // embedded traversal
            "a/./b",     // embedded current-dir
            "../escape", // prefix escape
        ] {
            assert!(
                validate_object_key(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_reserved_boatramp_namespace() {
        for bad in [
            ".boatramp-container",   // the container marker
            ".boatramp-uploads/x",   // multipart staging
            "a/.boatramp-uploads/p", // reserved segment nested
            ".BoatRamp-Container",   // case-folded trick
        ] {
            assert!(
                validate_object_key(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_dangerous_bytes() {
        assert!(validate_object_key("back\\slash").is_err());
        assert!(validate_object_key("star*key").is_err());
        assert!(validate_object_key("nul\0byte").is_err());
        assert!(validate_object_key("new\nline").is_err());
        assert!(validate_object_key("tab\tkey").is_err());
    }

    #[test]
    fn rejects_over_length() {
        let over = "a".repeat(MAX_OBJECT_KEY_LEN + 1);
        assert!(validate_object_key(&over).is_err());
        let at = "a".repeat(MAX_OBJECT_KEY_LEN);
        assert!(validate_object_key(&at).is_ok());
    }
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
        // Valid slugs: alphanumeric ends, interior `_`/`-`, single alphanumerics.
        for ok in ["blog", "my-site", "resize_v2", "Blog9", "a", "9", "a1_b-2c"] {
            assert!(
                validate_resource_name("site", ok).is_ok(),
                "{ok} should pass"
            );
        }
        // Validation runs on the already-percent-decoded value the handler
        // receives, so the `%2F` → `/` path-param case arrives here as a literal
        // `/` and is caught by the allowlist.
        for bad in [
            "",
            ".",
            "..",
            "a.b", // v0.7.0: the dot is no longer in the alphabet
            "a/b",
            "a\\b",
            "blog/../evil",
            "*",
            "proj*",
            "a b",
            "tab\tname",
            "ctl\u{0}name",
            // v0.7.0 allowlist closes the whole injection class the old denylist let through:
            "${PROJECT}",
            "{tenant}",
            "a;b",
            "`x`",
            "a|b",
            "a%b",
            "a#b",
            "a\"b",
            "a'b",
            "a$b",
            "a(b)",
            // Leading/trailing/non-alphanumeric-edge shapes:
            "-x",
            "x-",
            "_x",
            "x_",
            "-",
            "_",
            // Unicode homoglyphs — the byte loop rejects them; a `char`-based
            // `is_alphanumeric` loop would ACCEPT these (the G1 mutation).
            "аcme",   // leading Cyrillic 'а' (U+0430)
            "acme１", // trailing fullwidth '１' (U+FF11)
            "café",   // trailing 'é' (U+00E9)
        ] {
            assert!(
                validate_resource_name("site", bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn key_segment_is_key_safe_but_not_slug_strict() {
        // Data-plane-derived names (tenant from a signed `tid` claim; a `{tenant}`-expanded
        // container) are KEY-SAFE, not slug-strict — `.`/`@`/dots survive so email/dotted
        // tenants keep working; only traversal/separators/control are refused.
        for ok in [
            "acme",
            "acme.corp",
            "u@acme.com",
            "assets-user@acme.com",
            "tid-123",
            "a.b.c",
            "9",
        ] {
            assert!(
                validate_key_segment("tenant", ok).is_ok(),
                "{ok:?} should pass the key-segment rule"
            );
        }
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "../evil",
            "*",
            "a b",
            "tab\tname",
            "ctl\u{0}name",
        ] {
            assert!(
                validate_key_segment("tenant", bad).is_err(),
                "{bad:?} should be rejected as key-unsafe"
            );
        }
        // The anti-regression LOCK for MEDIUM-1 + its container sibling: the two tiers
        // genuinely differ — an email/dotted value is REJECTED as an operator identifier
        // (strict slug) but ACCEPTED as a data-plane key segment. Routing a data-plane
        // tenant through the slug (the bug) would break sealed-secret + blob-upload access
        // for every email/dotted tenant.
        for v in ["u@acme.com", "acme.corp"] {
            assert!(
                validate_resource_name("project", v).is_err(),
                "{v:?} slug-rejected"
            );
            assert!(
                validate_key_segment("tenant", v).is_ok(),
                "{v:?} key-accepted"
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

    /// G1 (charset / homoglyph): the byte-loop MUST reject a Unicode homoglyph that a
    /// `char::is_alphanumeric` loop would accept. If the validator is mutated to
    /// `value.chars().all(char::is_alphanumeric)` (or first/last checked with
    /// `char::is_alphanumeric`), every name below is accepted and this test fails —
    /// the anti-hollow mutation witness for the byte-loop requirement.
    #[test]
    fn resource_name_rejects_unicode_homoglyphs() {
        for homoglyph in [
            "аcme",     // U+0430 Cyrillic 'а' followed by ASCII "cme"
            "acme１",   // ASCII "acme" followed by U+FF11 fullwidth '１'
            "café",     // trailing U+00E9 'é'
            "\u{212a}", // Kelvin sign (looks like 'K')
            "ⅰdent",    // U+2170 small roman numeral one (looks like 'i')
        ] {
            assert!(
                validate_resource_name("project", homoglyph).is_err(),
                "{homoglyph:?} (Unicode homoglyph) must be rejected by the byte loop"
            );
        }
        // And the pure-ASCII slug that the homoglyphs impersonate IS accepted, so the
        // test is not vacuously rejecting everything.
        assert!(validate_resource_name("project", "acme").is_ok());
        assert!(validate_resource_name("project", "ident").is_ok());
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

    // ---- cross-surface consistency guard (v0.7.0 strict slug allowlist) --------
    //
    // The anti-regression guard: for a generated corpus of identifiers, assert that
    // `validate_resource_name` accepts a value IFF it is a **valid slug** (the v0.7.0
    // rule), AND that every accepted value round-trips through the CLI path
    // construction + the API-route path grammar without producing a malformed path
    // (no empty / `//` segment, no truncation). A valid slug is a strict subset of a
    // safe URL path segment, so this remains a REAL detector: an INDEPENDENT slug
    // oracle (below) is compared against the validator, so if the validator ever
    // drifts to accept a value that is not a valid slug — or a path-construction
    // change reintroduces a `//` — the test fails.

    /// An INDEPENDENT re-statement of the v0.7.0 slug spec, deliberately NOT sharing
    /// code with [`validate_resource_name`] so the two can disagree (which is exactly
    /// what this test detects). A value is a valid slug when it is 1–63 bytes, its
    /// first and last `char` is an ASCII alphanumeric, and every interior `char` is an
    /// ASCII alphanumeric or `_`/`-`. Written over `char`s (not bytes) on purpose: a
    /// homoglyph like `café` has an ASCII-alphanumeric-looking `char` shape only for
    /// its ASCII prefix — its `é` `char` is NOT `is_ascii_alphanumeric`, so the oracle
    /// rejects it exactly as the byte-loop validator does, keeping the equivalence
    /// exact while still restating the rule independently.
    fn is_valid_slug(v: &str) -> bool {
        if v.is_empty() || v.len() > MAX_RESOURCE_NAME_LEN {
            return false;
        }
        let chars: Vec<char> = v.chars().collect();
        // Any non-ASCII char (a multi-byte homoglyph) fails `is_ascii_alphanumeric`.
        for (i, &c) in chars.iter().enumerate() {
            let first_or_last = i == 0 || i == chars.len() - 1;
            let ok = if first_or_last {
                c.is_ascii_alphanumeric()
            } else {
                c.is_ascii_alphanumeric() || c == '_' || c == '-'
            };
            if !ok {
                return false;
            }
        }
        true
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
    fn validator_matches_the_slug_oracle() {
        // A broad generated corpus: valid slugs, the dangerous shapes, the whole
        // injection class the old denylist let through, boundary lengths, Unicode
        // homoglyphs, and every ASCII byte spliced into a name (so no accepted value
        // can carry a byte the slug oracle would reject).
        let mut corpus: Vec<String> = vec![
            "default".into(),
            "analytics".into(),
            "events_log".into(),
            "pg-primary".into(),
            "a.b".into(), // v0.7.0: now rejected (dot not in the alphabet)
            "Blog9".into(),
            "a".into(),
            "9".into(),
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
            "${PROJECT}".into(),
            "{tenant}".into(),
            "a;b".into(),
            "`x`".into(),
            "a|b".into(),
            "-x".into(),
            "x-".into(),
            "_x".into(),
            "x_".into(),
            // Unicode homoglyphs — must be rejected (the G1 byte-loop invariant).
            "аcme".into(),
            "acme１".into(),
            "café".into(),
            "a".repeat(MAX_RESOURCE_NAME_LEN),
            "a".repeat(MAX_RESOURCE_NAME_LEN + 1),
        ];
        for b in 0u8..=127 {
            corpus.push(format!("x{}y", b as char));
        }

        for v in &corpus {
            let accepted = validate_resource_name("database", v).is_ok();
            let slug = is_valid_slug(v);
            assert_eq!(
                accepted, slug,
                "validator/oracle disagree on {v:?}: validator accepted={accepted}, \
                 valid-slug={slug}"
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
        assert!(!is_valid_slug(""), "empty is not a valid slug");
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
