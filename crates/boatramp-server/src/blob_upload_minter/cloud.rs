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
/// - [`UploadTarget::Prefix`] ⇒ the subtree `hblob/…/{container}/{prefix}` — a NON-EMPTY prefix is
///   normalized to end in `/` so the `startsWith`/wildcard the cloud appends is a **path-segment
///   boundary** (Security MEDIUM-1): without it, `photos/a` would match sibling prefixes `photos/ab`,
///   `photos/annual` under an AWS `{prefix}*` or a GCS `startsWith`. An EMPTY prefix ⇒ the container
///   root (`hblob/…/{container}/`), the intended whole-container scope.
///
/// The `container` is a single validated segment (the binding + the S3-face choke point screen it), so
/// this cannot itself escape the `hblob/{qualified-site}/` root.
pub fn scoped_object_path(scope: &MintScope) -> String {
    let prefix = container_prefix(&scope.project, &scope.site, &scope.container);
    match &scope.target {
        UploadTarget::Key(k) => format!("{prefix}{k}"),
        UploadTarget::Prefix(p) if p.is_empty() => prefix,
        UploadTarget::Prefix(p) => {
            // A subtree boundary: append the guest prefix, ensuring exactly one trailing `/` so the
            // wildcard/`startsWith` the caller appends can only match keys strictly UNDER the prefix
            // directory — never a sibling prefix that merely shares a leading substring.
            let body = p.strip_suffix('/').unwrap_or(p);
            format!("{prefix}{body}/")
        }
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
    /// Content-addressing makes size moot for a fixed object, but ONLY when the store also pins the
    /// hash (`content_addressed_size_moot`); a raw byte cap is not a policy knob on any cloud today.
    pub can_cap_size: bool,
    /// Can the brokered policy pin the object CONTENT-TYPE? (Generally no across clouds; a presigned URL
    /// can bind a signed `Content-Type` header, which the specific minter reflects.)
    pub can_cap_content_type: bool,
    /// Can the brokered credential enforce CREATE-ONLY (no overwrite)? A single-object-scoped credential
    /// plus the store's `If-None-Match: *` precondition can; a broad prefix credential cannot pin it in
    /// the policy itself.
    pub can_enforce_create_only: bool,
    /// Can the brokered credential actually PIN the object hash (`require_sha256` ⇒ the store rejects
    /// bytes whose sha256 ≠ the key)? This is the HONESTY crux (Security HIGH-2): the plan claimed
    /// content-addressing is "always enforced" cross-cloud, but NO cloud minter today emits a checksum
    /// condition (AWS `session_policy_json` has no `Condition`; the GCS CAB has none; the Azure SAS has
    /// none), and on cloud boatramp never sees the bytes, so it cannot verify `key == sha256`. A minter
    /// sets this `true` ONLY where its store structurally pins the hash (e.g. an AWS single-key request
    /// signed with an `s3:x-amz-checksum-sha256` condition); otherwise `require_sha256` is `advisory`.
    pub can_enforce_sha256: bool,
    /// When the credential is content-addressed AND the store pins the hash
    /// ([`can_enforce_sha256`](Self::can_enforce_sha256)), a fixed key ⇒ fixed bytes ⇒ fixed size and a
    /// harmless (idempotent) overwrite, so `max_bytes` + `create_only` are effectively enforced. This
    /// is set by the minter to mirror `can_enforce_sha256` and is the ONLY thing that promotes those two
    /// via content-addressing — an UNPINNED `require_sha256` promotes NOTHING (Security HIGH-2).
    pub content_addressed_size_moot: bool,
}

impl CloudEnforcement {
    /// The conservative baseline for a broad (prefix/bulk) brokered credential: the policy binds the
    /// prefix + actions, but caps nothing about the object bytes AND does not pin the hash. Everything
    /// is advisory. This is the safe default a minter starts from and only PROMOTES from (never demotes
    /// something to `enforced` it can't actually cap). Because no cloud minter emits a checksum
    /// condition today, `can_enforce_sha256` is `false` here — so `require_sha256` (and the size/
    /// create-only it would otherwise promote) is honestly `advisory` on every cloud shape.
    pub const NONE: Self = Self {
        can_cap_size: false,
        can_cap_content_type: false,
        can_enforce_create_only: false,
        can_enforce_sha256: false,
        content_addressed_size_moot: false,
    };
}

/// Build the honest `(enforced, advisory)` constraint contract for a cloud-brokered credential, given
/// what the backend [`CloudEnforcement`] can structurally cap. The mapping is the security-critical
/// part: a constraint the store cannot cap is `advisory`, so the client (and any auditor) is told the
/// truth.
///
/// **Honesty of `require_sha256` (Security HIGH-2):** content-addressing is enforced ONLY where the
/// store actually PINS the hash ([`CloudEnforcement::can_enforce_sha256`]) — i.e. the brokered
/// credential carries a checksum condition the store rejects a mismatch against. On cloud boatramp
/// never sees the uploaded bytes, so it cannot verify `key == sha256`; and no cloud minter today emits
/// a checksum condition, so on those shapes `require_sha256` is `advisory` (NOT enforced), and it
/// promotes neither `max_bytes` nor `create_only`. The earlier "always enforced" labeling was
/// dishonest — this is the corrected contract.
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

    // Content-addressing makes size/overwrite moot ONLY when the store actually pins the hash — an
    // unpinned `require_sha256` (the default on every cloud shape today) promotes nothing.
    let hash_pinned = constraints.require_sha256 && caps.can_enforce_sha256;
    let size_moot_by_hash = hash_pinned && caps.content_addressed_size_moot;

    if let Some(mb) = constraints.max_bytes {
        place(ConstraintLabel {
            text: format!("max_bytes={mb}"),
            // Size is enforceable only if the backend can cap size in-policy (none of AWS/GCS/Azure can
            // today), OR the object is content-addressed AND the store pins the hash (a fixed key ⇒
            // fixed bytes ⇒ fixed size). An UNPINNED sha256 does NOT make size enforceable.
            enforced: caps.can_cap_size || size_moot_by_hash,
        });
    }
    if let Some(ct) = &constraints.content_type {
        place(ConstraintLabel {
            text: format!("content_type={ct}"),
            enforced: caps.can_cap_content_type,
        });
    }
    if constraints.require_sha256 {
        // Content-addressing is the STRONG enforcement ONLY where the store pins the hash; otherwise
        // (every cloud minter today emits no checksum condition) it is advisory — boatramp never sees
        // the cloud-uploaded bytes to verify `key == sha256` itself.
        place(ConstraintLabel {
            text: "require_sha256".to_string(),
            enforced: caps.can_enforce_sha256,
        });
    }
    if constraints.create_only {
        place(ConstraintLabel {
            text: "create_only".to_string(),
            // Enforceable when the credential is pinned to a single object AND the client sends the
            // no-overwrite precondition; a hash-PINNED content-addressed key makes overwrite a harmless
            // no-op. A broad prefix credential (or an unpinned sha256) cannot pin it ⇒ advisory.
            enforced: caps.can_enforce_create_only || size_moot_by_hash,
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
    fn a_non_empty_prefix_is_normalized_to_a_trailing_slash_boundary() {
        // Security MEDIUM-1: a prefix `a` must become `.../a/` so the wildcard/`startsWith` the cloud
        // appends is a PATH-SEGMENT boundary — `photos/a` must not match sibling `photos/ab`/`photos/annual`.
        let no_slash = scope(UploadTarget::Prefix("a".into()), Default::default());
        assert_eq!(
            scoped_object_path(&no_slash),
            "hblob/acme/blog/photos/a/",
            "a bare prefix gains a trailing-slash boundary"
        );
        // Idempotent: an already-`/`-terminated prefix is not doubled.
        let with_slash = scope(UploadTarget::Prefix("a/".into()), Default::default());
        assert_eq!(scoped_object_path(&with_slash), "hblob/acme/blog/photos/a/");
        // A nested prefix keeps its internal separators and gains one trailing `/`.
        let nested = scope(
            UploadTarget::Prefix("photos/2026".into()),
            Default::default(),
        );
        assert_eq!(
            scoped_object_path(&nested),
            "hblob/acme/blog/photos/photos/2026/"
        );
        // An empty prefix ⇒ the container root exactly (whole-container scope).
        let empty = scope(UploadTarget::Prefix(String::new()), Default::default());
        assert_eq!(scoped_object_path(&empty), "hblob/acme/blog/photos/");
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
    fn unpinned_sha256_is_advisory_and_promotes_nothing() {
        // Security HIGH-2: with the baseline (no cloud minter pins the hash), `require_sha256` is
        // ADVISORY — boatramp never sees the cloud-uploaded bytes to verify `key == sha256`, and no
        // checksum condition is emitted. It must NOT promote max_bytes / create_only to enforced.
        let c = UploadConstraints {
            max_bytes: Some(1024),
            content_type: None,
            require_sha256: true,
            create_only: true,
        };
        let (enforced, advisory) = constraint_contract(&c, CloudEnforcement::NONE);
        assert!(
            enforced.is_empty(),
            "an UNPINNED sha256 enforces nothing: {enforced:?}"
        );
        assert!(advisory.contains(&"require_sha256".to_string()));
        assert!(advisory.contains(&"max_bytes=1024".to_string()));
        assert!(advisory.contains(&"create_only".to_string()));
    }

    #[test]
    fn a_store_that_pins_the_hash_enforces_content_addressing_and_makes_size_moot() {
        // Where a minter DOES pin the hash (e.g. an AWS single-key checksum condition), it sets
        // can_enforce_sha256 + content_addressed_size_moot ⇒ require_sha256 + the moot size/overwrite
        // become enforced HONESTLY.
        let c = UploadConstraints {
            max_bytes: Some(1024),
            content_type: None,
            require_sha256: true,
            create_only: true,
        };
        let caps = CloudEnforcement {
            can_enforce_sha256: true,
            content_addressed_size_moot: true,
            ..CloudEnforcement::NONE
        };
        let (enforced, advisory) = constraint_contract(&c, caps);
        assert!(enforced.contains(&"require_sha256".to_string()));
        assert!(enforced.contains(&"max_bytes=1024".to_string()));
        assert!(enforced.contains(&"create_only".to_string()));
        assert!(
            advisory.is_empty(),
            "hash-pinned content-addressed ⇒ nothing merely advisory: {advisory:?}"
        );
    }

    #[test]
    fn no_uncapped_constraint_is_ever_labeled_enforced_on_the_baseline() {
        // The M5 honesty gate: on the conservative baseline (a broad prefix/temp-cred shape) NOTHING is
        // enforced — every constraint the store cannot structurally cap is advisory.
        let c = UploadConstraints {
            max_bytes: Some(7),
            content_type: Some("image/png".into()),
            require_sha256: true,
            create_only: true,
        };
        let (enforced, _advisory) = constraint_contract(&c, CloudEnforcement::NONE);
        assert!(
            enforced.is_empty(),
            "baseline caps nothing ⇒ nothing enforced: {enforced:?}"
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
