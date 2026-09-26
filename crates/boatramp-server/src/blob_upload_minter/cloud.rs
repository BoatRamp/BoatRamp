//! Shared helpers for the M4 **cloud** blob-upload minters (AWS / GCS / Azure).
//!
//! The two things every cloud minter needs — derived ONLY from the host-stamped [`MintScope`], never
//! from guest-chosen input — are:
//!
//! 1. **The object-prefix the brokered credential must be resource-scoped to.** This is byte-identical
//!    to the `hblob/{project-qualified-site}/{container}/…` prefix the local face composes and the guest
//!    `compat::blob` binding reads — reusing [`keypath::container_prefix`](crate::s3_ingress::keypath)
//!    guarantees the cloud policy confines to exactly the same tree the platform reads back, so a
//!    brokered credential can never write outside the guest's own container. For a single-KEY target the
//!    scope is the exact object key; for a PREFIX target it is the prefix subtree.
//!
//! 2. **The honest `enforced` vs `advisory` constraint contract** (the M4 security crux). A cloud
//!    session policy / SAS / signed URL can bind the *prefix* and the *actions*, but generally cannot cap
//!    object *size* or *content-type*. A minter MUST NOT claim to enforce what its store cannot cap —
//!    those constraints are `advisory`. Content-addressing (`require_sha256`) IS enforceable on every
//!    backend (the key==sha256 identity + the store's checksum condition), so it is always `enforced`;
//!    where a cloud CAN structurally cap a constraint (e.g. Azure SAS pins the exact blob for a
//!    single-key credential ⇒ create-only overwrite protection is real), the specific minter promotes it.

use boatramp_handlers::{MintScope, UploadConstraints, UploadTarget};

use crate::s3_ingress::keypath::container_prefix;

/// The exact object-prefix (or object key) within the backing store's bucket/container that a brokered
/// credential must be resource-scoped to, for a host-stamped [`MintScope`]. This is the storage key
/// space the guest reads back through `hblob/…`, so scoping the cloud policy to it confines the
/// credential to the guest's own container tree — the structural scope-confinement invariant.
///
/// - [`UploadTarget::Key`] ⇒ the single fully-qualified object key `hblob/…/{container}/{key}`.
/// - [`UploadTarget::Prefix`] ⇒ the subtree `hblob/…/{container}/{prefix}` (no trailing slash added;
///   callers append the wildcard/`startsWith` semantics their cloud uses).
///
/// The `container` is a single validated segment (the binding + the S3-face choke point screen it), so
/// this cannot itself escape the `hblob/{qualified-site}/` root.
pub fn scoped_object_path(scope: &MintScope) -> String {
    let prefix = container_prefix(&scope.project, &scope.site, &scope.container);
    match &scope.target {
        UploadTarget::Key(k) => format!("{prefix}{k}"),
        UploadTarget::Prefix(p) => format!("{prefix}{p}"),
    }
}

/// The `hblob/{project-qualified-site}/{container}/` prefix (always ends in `/`) — the container root a
/// prefix credential is anchored under. Cloud minters use this to bound a whole-container fallback
/// (e.g. Azure's container-scoped SAS) honestly to the platform's own tree.
pub fn scoped_container_root(scope: &MintScope) -> String {
    container_prefix(&scope.project, &scope.site, &scope.container)
}

/// A single constraint and whether the backend can HARD-enforce it in-policy.
pub struct ConstraintLabel {
    /// The human-readable constraint string (e.g. `max_bytes=1048576`), matching the local-face
    /// vocabulary so the two credential kinds read identically.
    pub text: String,
    /// `true` ⇒ the backing store structurally enforces it (goes in `enforced`); `false` ⇒ the store
    /// cannot cap it in the brokered policy (goes in `advisory`).
    pub enforced: bool,
}

/// What a given cloud backend can structurally cap in a brokered credential. A minter fills this in per
/// its store's real capability — this is the ONE place the enforced/advisory honesty is decided, so the
/// M5 gate's "a cloud minter never labels an uncapped constraint enforced" assertion has a single
/// choke point to check.
#[derive(Debug, Clone, Copy)]
pub struct CloudEnforcement {
    /// Can the brokered policy cap object SIZE? (AWS session policy: no; SAS: no; signed URL: no.)
    /// Content-addressing makes size moot for a fixed object, but a raw byte cap is not a policy knob.
    pub can_cap_size: bool,
    /// Can the brokered policy pin the object CONTENT-TYPE? (Generally no across clouds; a presigned URL
    /// can bind a signed `Content-Type` header, which the specific minter reflects.)
    pub can_cap_content_type: bool,
    /// Can the brokered credential enforce CREATE-ONLY (no overwrite)? A single-object-scoped credential
    /// plus the store's `If-None-Match: *` precondition can; a broad prefix credential cannot pin it in
    /// the policy itself.
    pub can_enforce_create_only: bool,
}

impl CloudEnforcement {
    /// The conservative baseline for a broad (prefix/bulk) brokered credential: the policy binds the
    /// prefix + actions, but caps nothing about the object bytes. Everything except content-addressing
    /// is advisory. This is the safe default a minter starts from and only PROMOTES from (never demotes
    /// something to `enforced` it can't actually cap).
    pub const NONE: Self = Self {
        can_cap_size: false,
        can_cap_content_type: false,
        can_enforce_create_only: false,
    };
}

/// Build the honest `(enforced, advisory)` constraint contract for a cloud-brokered credential, given
/// what the backend [`CloudEnforcement`] can structurally cap. The mapping is the security-critical
/// part: a constraint the store cannot cap is `advisory`, so the client (and any auditor) is told the
/// truth. `require_sha256` is ALWAYS enforced (content-addressing is enforceable everywhere: the object
/// key must equal `sha256(bytes)`, verified by the store's checksum condition + the read-path identity).
///
/// Returns `(enforced, advisory)`, each a human-readable list matching the local-face vocabulary.
pub fn constraint_contract(
    constraints: &UploadConstraints,
    caps: CloudEnforcement,
) -> (Vec<String>, Vec<String>) {
    let mut enforced = Vec::new();
    let mut advisory = Vec::new();

    let mut place = |label: ConstraintLabel| {
        if label.enforced {
            enforced.push(label.text);
        } else {
            advisory.push(label.text);
        }
    };

    if let Some(mb) = constraints.max_bytes {
        place(ConstraintLabel {
            text: format!("max_bytes={mb}"),
            // Size is enforceable only if the object is content-addressed (a fixed key ⇒ fixed bytes ⇒
            // fixed size), OR the backend can cap size in-policy (none of AWS/GCS/Azure can today).
            enforced: caps.can_cap_size || constraints.require_sha256,
        });
    }
    if let Some(ct) = &constraints.content_type {
        place(ConstraintLabel {
            text: format!("content_type={ct}"),
            enforced: caps.can_cap_content_type,
        });
    }
    if constraints.require_sha256 {
        // Content-addressing is the mandatory cross-cloud STRONG enforcement — always enforced.
        place(ConstraintLabel {
            text: "require_sha256".to_string(),
            enforced: true,
        });
    }
    if constraints.create_only {
        place(ConstraintLabel {
            text: "create_only".to_string(),
            // Enforceable when the credential is pinned to a single object AND the client sends the
            // no-overwrite precondition; a content-addressed key makes overwrite a harmless no-op either
            // way. A broad prefix credential cannot pin it in-policy ⇒ advisory.
            enforced: caps.can_enforce_create_only || constraints.require_sha256,
        });
    }

    (enforced, advisory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_handlers::{UploadPerm, UploadTarget};

    fn scope(target: UploadTarget, c: UploadConstraints) -> MintScope {
        MintScope {
            project: "acme".into(),
            site: "blog".into(),
            container: "photos".into(),
            target,
            perms: vec![UploadPerm::Put],
            constraints: c,
            ttl_secs: 900,
        }
    }

    #[test]
    fn scoped_path_is_the_hblob_key_the_guest_reads() {
        // A named project ⇒ a `project/site` qualified segment; the prefix matches container_prefix
        // exactly (same helper the local face + guest read-path use), so the cloud policy confines to
        // the SAME tree the platform reads back.
        let s = scope(
            UploadTarget::Key("avatars/u.jpg".into()),
            Default::default(),
        );
        assert_eq!(
            scoped_object_path(&s),
            "hblob/acme/blog/photos/avatars/u.jpg"
        );
        let p = scope(UploadTarget::Prefix("ingest/".into()), Default::default());
        assert_eq!(scoped_object_path(&p), "hblob/acme/blog/photos/ingest/");
        assert_eq!(scoped_container_root(&p), "hblob/acme/blog/photos/");
    }

    #[test]
    fn size_and_content_type_are_advisory_when_the_store_cannot_cap_them() {
        let c = UploadConstraints {
            max_bytes: Some(1024),
            content_type: Some("image/png".into()),
            require_sha256: false,
            create_only: true,
        };
        let (enforced, advisory) = constraint_contract(&c, CloudEnforcement::NONE);
        // Nothing the store can't cap is claimed as enforced.
        assert!(
            enforced.is_empty(),
            "NONE caps ⇒ nothing enforced: {enforced:?}"
        );
        assert!(advisory.contains(&"max_bytes=1024".to_string()));
        assert!(advisory.contains(&"content_type=image/png".to_string()));
        assert!(advisory.contains(&"create_only".to_string()));
    }

    #[test]
    fn content_addressing_makes_size_and_create_only_enforced_everywhere() {
        let c = UploadConstraints {
            max_bytes: Some(1024),
            content_type: None,
            require_sha256: true,
            create_only: true,
        };
        let (enforced, advisory) = constraint_contract(&c, CloudEnforcement::NONE);
        // require_sha256 is the strong cross-cloud enforcement; it also makes size + overwrite moot.
        assert!(enforced.contains(&"require_sha256".to_string()));
        assert!(enforced.contains(&"max_bytes=1024".to_string()));
        assert!(enforced.contains(&"create_only".to_string()));
        assert!(
            advisory.is_empty(),
            "content-addressed ⇒ nothing merely advisory: {advisory:?}"
        );
    }

    #[test]
    fn a_store_that_can_pin_content_type_promotes_it() {
        let c = UploadConstraints {
            content_type: Some("image/jpeg".into()),
            ..Default::default()
        };
        let caps = CloudEnforcement {
            can_cap_content_type: true,
            ..CloudEnforcement::NONE
        };
        let (enforced, advisory) = constraint_contract(&c, caps);
        assert!(enforced.contains(&"content_type=image/jpeg".to_string()));
        assert!(advisory.is_empty());
    }
}
