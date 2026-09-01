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

/// Validate a project/site/function/compute/workflow name at the create/write
/// boundary, so a name can never escape its `project/<proj>/…` key prefix, collide
/// with the store's fixed sub-key grammar, smuggle a (possibly percent-decoded)
/// path separator, or break Cedar entity/target construction.
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
}
