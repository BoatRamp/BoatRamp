//! The `blob-upload` capability host binding: a guest **mints a short-lived, scoped S3 upload
//! credential** (`boatramp:handlers/blob-upload`, PLAN-blob-s3-ingress §6 + folded "Guest mint
//! discipline"). An external client (a browser, a bulk agent) uses the credential to upload binary
//! objects DIRECTLY into one of the project's blob containers over the standard S3 protocol; the wasm
//! guest then reads the object by key via the unchanged `wasi:blobstore` (`hblob/…` read-through).
//!
//! # The security model (why a guest can never mint outside its own project+site)
//!
//! 1. **Project AND site are host-supplied, never guest-supplied.** The WIT surface has NO
//!    project/site parameter. The host holds them ([`project`](BlobUploadBinding::project) /
//!    [`site`](BlobUploadBinding::site)) — the resolved invocation scope — and passes them to the
//!    minter. A guest cannot name, override, or forge them, so a minted credential is structurally
//!    confined to its origin tenant (mirrors the `capability.rs` audience host-forcing).
//! 2. **Deny-by-default.** No grant ⇒ no binding ([`BlobUploadHost::new(None)`]) ⇒ `mint` returns
//!    `access-denied`.
//! 3. **Independent rights, re-checked per call.** A single-shot `put` needs
//!    [`can_write`](BlobUploadBinding::can_write) (`blob-upload:write`); `multipart` needs
//!    [`can_multipart`](BlobUploadBinding::can_multipart) (`blob-upload:multipart`). Bare
//!    `blob-upload` is NOT a grant, and there is NO `blob-upload:*` — the two derive from the SEPARATE
//!    imports, neither implied by deploy/publish.
//! 4. **A per-component container allowlist.** [`allow_containers`](BlobUploadBinding::allow_containers)
//!    filters WHICH containers are mintable: empty ⇒ deny-all; a container not in it ⇒ `access-denied`
//!    (before any signing). Least-privilege, mirroring `tenant_secret_names`.
//! 5. **Fail-closed on no resolved site.** An `all`/anonymous/unscoped invocation has no single site to
//!    confine to; the binding returns `no-resolved-site` BEFORE any signing (distinct from
//!    `access-denied`, cf. the `tenant_secrets::NoResolvedTenant` pattern).
//! 6. **The host CLAMPS the TTL and max-bytes** to the operator ceilings (a guest can only narrow); the
//!    perms default to write-only. The clamp is applied in the binding (defense in depth) and the
//!    minter/face re-enforces authoritatively.

use std::sync::Arc;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/blob-upload-host",
        async: {
            only_imports: ["mint"],
        },
    });
}

use generated::boatramp::handlers::{blob_upload, blob_upload_types};

/// A single permitted S3 operation the minted credential may perform — the host-native mirror of the
/// WIT `upload-perm` (so the server-side minter seam does not depend on the generated type).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadPerm {
    /// Single-shot `PutObject` (needs `blob-upload:write`).
    Put,
    /// The multipart quartet (needs `blob-upload:multipart`).
    Multipart,
}

/// What the credential is bound to — the host-native mirror of the WIT `upload-target`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadTarget {
    /// Exactly one object key.
    Key(String),
    /// A key prefix.
    Prefix(String),
}

/// The upload constraints the guest requested — host-native mirror of the WIT `upload-constraints`.
/// `max_bytes` is the guest's request BEFORE the host clamp (the binding clamps it down).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UploadConstraints {
    /// Requested max object size in bytes (clamped down to the operator/container ceiling).
    pub max_bytes: Option<u64>,
    /// Required `Content-Type` (exact or a `type/*` family); `None` ⇒ any.
    pub content_type: Option<String>,
    /// Require the object key to equal `sha256(bytes)` (content-addressing).
    pub require_sha256: bool,
    /// Refuse to overwrite an existing key (create-only).
    pub create_only: bool,
}

/// The host-native, fully-validated + host-forced mint request the [`BlobUploadMinter`] seam receives.
/// Project + site are host-stamped (the guest never named them); `perms`/`target`/`constraints`/`ttl`
/// are the guest's shape, with the TTL + `max_bytes` already CLAMPED by the binding.
#[derive(Debug, Clone)]
pub struct MintScope {
    /// The owning project (host-forced from the invocation scope).
    pub project: String,
    /// The owning site (host-forced from the invocation scope).
    pub site: String,
    /// The blob container (allowlist-checked, a single segment — re-validated at the face).
    pub container: String,
    /// The single key or prefix the credential may write.
    pub target: UploadTarget,
    /// The permitted operations (non-empty; write/multipart only).
    pub perms: Vec<UploadPerm>,
    /// The (clamped) upload constraints.
    pub constraints: UploadConstraints,
    /// The (clamped) lifetime in seconds.
    pub ttl_secs: u64,
}

/// The self-describing minted credential — host-native mirror of the WIT `credentials` variant.
#[derive(Debug, Clone)]
pub enum MintedCredentials {
    /// A one-shot presigned PUT (single-key / PUT-only / browser).
    PresignedPut(PresignedPut),
    /// S3 STS-style temporary credentials (prefix / multipart / bulk).
    TempCredentials(TempCredentials),
}

/// A presigned PUT the client uploads with a single `fetch`.
#[derive(Debug, Clone)]
pub struct PresignedPut {
    pub url: String,
    pub method: String,
    pub required_headers: Vec<(String, String)>,
    pub expires_at: u64,
    pub expires_in_secs: u64,
}

/// S3 STS-style temporary credentials for a full S3 SDK.
#[derive(Debug, Clone)]
pub struct TempCredentials {
    pub access_key_id: String,
    pub secret: String,
    pub session_token: String,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub force_path_style: bool,
    pub expires_at: u64,
    pub expires_in_secs: u64,
    /// Constraints HARD-enforced for this credential (human-readable).
    pub enforced: Vec<String>,
    /// Constraints ADVISORY only for this credential's backend (human-readable).
    pub advisory: Vec<String>,
}

/// The host mint seam: sign + assemble a scoped S3 upload credential for the (host-forced) `scope`.
/// The concrete implementation lives in the server (it holds the fleet
/// [`Signer`](boatramp_core::cose::Signer) + the S3-ingress secret + the face endpoint/region config);
/// this seam keeps the binding testable with a fake. Returns the credential or an error string.
#[async_trait::async_trait]
pub trait BlobUploadMinter: Send + Sync {
    async fn mint(&self, scope: &MintScope) -> Result<MintedCredentials, String>;
}

/// A per-invocation `blob-upload` grant: the host-forced project + site, the shared minter, the
/// operator ceilings (max TTL + max bytes), the per-component container allowlist, and the two
/// independent rights. `None` in [`Bindings`](super::Bindings) = not granted.
///
/// `site == None` ⇒ an unscoped invocation (no single resolved site) → `mint` is `no-resolved-site`.
#[derive(Clone)]
pub struct BlobUploadBinding {
    /// The owning project (host-stamped at bind — the guest never names it).
    pub(crate) project: String,
    /// THIS invocation's host-resolved site. `None` ⇒ no single resolved site → `mint` fails closed
    /// with `no-resolved-site`.
    pub(crate) site: Option<String>,
    /// The shared minter (reaches the fleet signer + the S3-ingress secret host-side).
    pub(crate) minter: Arc<dyn BlobUploadMinter>,
    /// The operator ceiling on credential TTL, seconds. A `0` ceiling disables minting even with a
    /// present binding (posture-off).
    pub(crate) max_ttl_secs: u64,
    /// The operator ceiling on a credential's `max_bytes`. `None` ⇒ no host-side max-bytes clamp (the
    /// per-container ceiling at the face still applies).
    pub(crate) max_bytes_ceiling: Option<u64>,
    /// The component's `upload_containers` allowlist. EMPTY ⇒ deny-all.
    pub(crate) allow_containers: Vec<String>,
    /// Whether `blob-upload:write` was granted — gates a `put` credential.
    pub(crate) can_write: bool,
    /// Whether `blob-upload:multipart` was granted — gates a `multipart` credential.
    pub(crate) can_multipart: bool,
}

/// Why a mint was refused (host-native; mapped 1:1 to the WIT `mint-error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MintRefused {
    /// A needed right was not granted, or the container is outside the allowlist (deny-by-default).
    AccessDenied,
    /// This invocation has no single resolved site — fail closed BEFORE any signing.
    NoResolvedSite,
    /// The request was malformed (client-safe reason).
    InvalidRequest(String),
    /// The host failed to mint (no signer / no face / a signing failure) — generic detail.
    Failed(String),
}

impl MintRefused {
    fn into_wit(self) -> blob_upload_types::MintError {
        match self {
            Self::AccessDenied => blob_upload_types::MintError::AccessDenied,
            Self::NoResolvedSite => blob_upload_types::MintError::NoResolvedSite,
            Self::InvalidRequest(m) => blob_upload_types::MintError::InvalidRequest(m),
            Self::Failed(m) => blob_upload_types::MintError::Failed(m),
        }
    }
}

impl BlobUploadBinding {
    /// The resolved site to confine to, or `NoResolvedSite` fail-closed. Checked BEFORE any signing.
    fn site(&self) -> Result<&str, MintRefused> {
        self.site.as_deref().ok_or(MintRefused::NoResolvedSite)
    }

    /// Whether the guest may mint for `container`: it must be in the component's allowlist. Empty ⇒
    /// deny-all. A refused container is `access-denied` (before any signing).
    fn container_allowed(&self, container: &str) -> bool {
        self.allow_containers.iter().any(|c| c == container)
    }

    /// The host-native mint path (the whole thing the WIT `Host::mint` delegates to — public so a
    /// host-side live gate can drive the real minter without a wasm guest, mirroring
    /// `TenantSecretsBinding::read`). Validates the request shape, applies the right/allowlist/
    /// resolved-site gates, CLAMPS the TTL + max_bytes, host-forces project+site, and delegates.
    pub async fn mint(
        &self,
        container: &str,
        target: UploadTarget,
        mut perms: Vec<UploadPerm>,
        constraints: UploadConstraints,
        ttl_secs: u64,
    ) -> Result<MintedCredentials, MintRefused> {
        // Posture-off: a zero TTL ceiling disables minting even with a present binding.
        if self.max_ttl_secs == 0 {
            return Err(MintRefused::AccessDenied);
        }
        // Shape validation (fail-closed on an obviously-bad request).
        if container.trim().is_empty() {
            return Err(MintRefused::InvalidRequest("container is required".into()));
        }
        match &target {
            UploadTarget::Key(k) if k.trim().is_empty() => {
                return Err(MintRefused::InvalidRequest("target key is empty".into()));
            }
            // A prefix MAY be empty (whole-container), so only the key is non-empty-checked.
            _ => {}
        }
        if ttl_secs == 0 {
            return Err(MintRefused::InvalidRequest(
                "ttl-seconds must be greater than zero".into(),
            ));
        }
        // Perms default to write-only (single-shot) when the guest names none.
        if perms.is_empty() {
            perms.push(UploadPerm::Put);
        }
        perms.sort_by_key(|p| match p {
            UploadPerm::Put => 0u8,
            UploadPerm::Multipart => 1u8,
        });
        perms.dedup();

        // Independent-rights check: EVERY requested perm must be granted. `put` needs `:write`,
        // `multipart` needs `:multipart` (deny-by-default; a missing right is access-denied).
        for p in &perms {
            let ok = match p {
                UploadPerm::Put => self.can_write,
                UploadPerm::Multipart => self.can_multipart,
            };
            if !ok {
                return Err(MintRefused::AccessDenied);
            }
        }
        // Container allowlist (before any signing).
        if !self.container_allowed(container) {
            return Err(MintRefused::AccessDenied);
        }
        // No single resolved site ⇒ fail closed (distinct from access-denied).
        let site = self.site()?;

        // CLAMP the TTL down to the operator ceiling (a guest can only narrow).
        let ttl = ttl_secs.min(self.max_ttl_secs);
        // CLAMP max_bytes down to the operator ceiling: the tighter of the guest's request and the
        // ceiling (a guest can only narrow; the per-container ceiling at the face is a further backstop).
        let clamped_max_bytes = match (constraints.max_bytes, self.max_bytes_ceiling) {
            (Some(g), Some(c)) => Some(g.min(c)),
            (Some(g), None) => Some(g),
            (None, Some(c)) => Some(c),
            (None, None) => None,
        };
        let scope = MintScope {
            project: self.project.clone(),
            site: site.to_string(),
            container: container.trim().to_string(),
            target,
            perms,
            constraints: UploadConstraints {
                max_bytes: clamped_max_bytes,
                ..constraints
            },
            ttl_secs: ttl,
        };
        self.minter.mint(&scope).await.map_err(MintRefused::Failed)
    }
}

/// Per-invocation view over the (optional) `blob-upload` grant. `None` ⇒ not granted
/// (deny-by-default: `mint` ⇒ `access-denied`).
pub struct BlobUploadHost<'a> {
    binding: Option<&'a BlobUploadBinding>,
}

impl<'a> BlobUploadHost<'a> {
    /// Build a view; `None` means the capability was not granted.
    pub fn new(binding: Option<&'a BlobUploadBinding>) -> Self {
        Self { binding }
    }
}

/// Translate the guest's WIT request into the host-native shape, rejecting a both/neither key+prefix
/// target as `invalid-request`.
fn parse_request(
    req: blob_upload_types::MintRequest,
) -> Result<
    (
        String,
        UploadTarget,
        Vec<UploadPerm>,
        UploadConstraints,
        u64,
    ),
    MintRefused,
> {
    let target = match (req.target.key, req.target.prefix) {
        (Some(k), None) => UploadTarget::Key(k),
        (None, Some(p)) => UploadTarget::Prefix(p),
        (Some(_), Some(_)) => {
            return Err(MintRefused::InvalidRequest(
                "target must set exactly one of key/prefix, not both".into(),
            ));
        }
        (None, None) => {
            return Err(MintRefused::InvalidRequest(
                "target must set one of key/prefix".into(),
            ));
        }
    };
    let perms = req
        .perms
        .into_iter()
        .map(|p| match p {
            blob_upload_types::UploadPerm::Put => UploadPerm::Put,
            blob_upload_types::UploadPerm::Multipart => UploadPerm::Multipart,
        })
        .collect();
    let constraints = UploadConstraints {
        max_bytes: req.constraints.max_bytes,
        content_type: req.constraints.content_type,
        require_sha256: req.constraints.require_sha256,
        create_only: req.constraints.create_only,
    };
    Ok((req.container, target, perms, constraints, req.ttl_seconds))
}

/// Map a host-native minted credential to the WIT `credentials` variant.
fn credentials_to_wit(c: MintedCredentials) -> blob_upload_types::Credentials {
    match c {
        MintedCredentials::PresignedPut(p) => {
            blob_upload_types::Credentials::PresignedPut(blob_upload_types::PresignedPut {
                url: p.url,
                method: p.method,
                required_headers: p.required_headers,
                expires_at: p.expires_at,
                expires_in_secs: p.expires_in_secs,
            })
        }
        MintedCredentials::TempCredentials(t) => {
            blob_upload_types::Credentials::TempCredentials(blob_upload_types::TempCredentials {
                access_key_id: t.access_key_id,
                secret: t.secret,
                session_token: t.session_token,
                endpoint: t.endpoint,
                region: t.region,
                bucket: t.bucket,
                force_path_style: t.force_path_style,
                expires_at: t.expires_at,
                expires_in_secs: t.expires_in_secs,
                enforced: t.enforced,
                advisory: t.advisory,
            })
        }
    }
}

impl blob_upload::Host for BlobUploadHost<'_> {
    async fn mint(
        &mut self,
        request: blob_upload_types::MintRequest,
    ) -> Result<blob_upload_types::Credentials, blob_upload_types::MintError> {
        // Deny-by-default: no grant ⇒ no binding ⇒ access-denied. The binding then applies the
        // right + allowlist + resolved-site gates (all before any signing).
        let Some(binding) = self.binding else {
            return Err(blob_upload_types::MintError::AccessDenied);
        };
        let (container, target, perms, constraints, ttl) =
            parse_request(request).map_err(MintRefused::into_wit)?;
        binding
            .mint(&container, target, perms, constraints, ttl)
            .await
            .map(credentials_to_wit)
            .map_err(MintRefused::into_wit)
    }
}

/// Add the `blob-upload` interface to `linker`, resolving the per-invocation [`BlobUploadHost`] via
/// `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> BlobUploadHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    blob_upload::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::blob_upload::Host;
    use super::*;
    use std::sync::Mutex;

    /// Records every mint call verbatim, so a test can assert the host-forced project+site + the
    /// clamped TTL/max_bytes.
    #[derive(Default)]
    struct FakeMinter {
        calls: Mutex<Vec<MintScope>>,
    }
    #[async_trait::async_trait]
    impl BlobUploadMinter for FakeMinter {
        async fn mint(&self, scope: &MintScope) -> Result<MintedCredentials, String> {
            self.calls.lock().unwrap().push(scope.clone());
            // Shape mimics the real minter: a single Key/Put ⇒ presigned-put, else temp-credentials.
            if matches!(scope.target, UploadTarget::Key(_)) && scope.perms == [UploadPerm::Put] {
                Ok(MintedCredentials::PresignedPut(PresignedPut {
                    url: "https://s3.local/c/k?X-Amz-Signature=deadbeef".into(),
                    method: "PUT".into(),
                    required_headers: vec![],
                    expires_at: 1000 + scope.ttl_secs,
                    expires_in_secs: scope.ttl_secs,
                }))
            } else {
                Ok(MintedCredentials::TempCredentials(TempCredentials {
                    access_key_id: "BRUPTEST".into(),
                    secret: "sekret".into(),
                    session_token: "tok".into(),
                    endpoint: "https://s3.local".into(),
                    region: "boatramp".into(),
                    bucket: scope.container.clone(),
                    force_path_style: true,
                    expires_at: 1000 + scope.ttl_secs,
                    expires_in_secs: scope.ttl_secs,
                    enforced: vec!["require_sha256".into()],
                    advisory: vec![],
                }))
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn binding(
        minter: Arc<FakeMinter>,
        site: Option<&str>,
        allow: &[&str],
        can_write: bool,
        can_multipart: bool,
        max_ttl: u64,
        max_bytes_ceiling: Option<u64>,
    ) -> BlobUploadBinding {
        BlobUploadBinding {
            project: "shop".into(),
            site: site.map(str::to_owned),
            minter,
            max_ttl_secs: max_ttl,
            max_bytes_ceiling,
            allow_containers: allow.iter().map(ToString::to_string).collect(),
            can_write,
            can_multipart,
        }
    }

    fn put_key_request(container: &str, key: &str, ttl: u64) -> blob_upload_types::MintRequest {
        blob_upload_types::MintRequest {
            container: container.into(),
            target: blob_upload_types::UploadTarget {
                key: Some(key.into()),
                prefix: None,
            },
            perms: vec![blob_upload_types::UploadPerm::Put],
            constraints: blob_upload_types::UploadConstraints {
                max_bytes: None,
                content_type: None,
                require_sha256: false,
                create_only: false,
            },
            ttl_seconds: ttl,
        }
    }

    #[tokio::test]
    async fn ungranted_mint_is_denied() {
        let mut host = BlobUploadHost::new(None);
        assert!(matches!(
            host.mint(put_key_request("photos", "k", 300))
                .await
                .unwrap_err(),
            blob_upload_types::MintError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn mint_forces_project_and_site_never_guest_supplied() {
        // The WIT surface has no project/site — the binding stamps both. A presigned-put comes back
        // for the single-key/put case.
        let minter = Arc::new(FakeMinter::default());
        let b = binding(
            minter.clone(),
            Some("blog"),
            &["photos"],
            true,
            false,
            3600,
            None,
        );
        let mut host = BlobUploadHost::new(Some(&b));
        let creds = host
            .mint(put_key_request("photos", "avatars/u.jpg", 300))
            .await
            .unwrap();
        assert!(matches!(
            creds,
            blob_upload_types::Credentials::PresignedPut(_)
        ));
        let calls = minter.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].project, "shop",
            "project host-forced from the binding"
        );
        assert_eq!(calls[0].site, "blog", "site host-forced from the binding");
        assert_eq!(calls[0].container, "photos");
        assert_eq!(calls[0].target, UploadTarget::Key("avatars/u.jpg".into()));
    }

    #[tokio::test]
    async fn no_resolved_site_is_refused_before_signing() {
        // An all/anonymous/unscoped invocation: no resolved site ⇒ no-resolved-site (distinct from
        // access-denied), BEFORE the minter is touched.
        let minter = Arc::new(FakeMinter::default());
        let b = binding(minter.clone(), None, &["photos"], true, true, 3600, None);
        let mut host = BlobUploadHost::new(Some(&b));
        assert!(matches!(
            host.mint(put_key_request("photos", "k", 300))
                .await
                .unwrap_err(),
            blob_upload_types::MintError::NoResolvedSite
        ));
        assert!(
            minter.calls.lock().unwrap().is_empty(),
            "nothing was signed"
        );
    }

    #[tokio::test]
    async fn a_zero_ttl_ceiling_denies_even_a_present_binding() {
        let minter = Arc::new(FakeMinter::default());
        let b = binding(
            minter.clone(),
            Some("blog"),
            &["photos"],
            true,
            true,
            0,
            None,
        );
        let mut host = BlobUploadHost::new(Some(&b));
        assert!(matches!(
            host.mint(put_key_request("photos", "k", 300))
                .await
                .unwrap_err(),
            blob_upload_types::MintError::AccessDenied
        ));
        assert!(minter.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn container_outside_the_allowlist_is_access_denied() {
        let minter = Arc::new(FakeMinter::default());
        let b = binding(
            minter.clone(),
            Some("blog"),
            &["photos"],
            true,
            true,
            3600,
            None,
        );
        let mut host = BlobUploadHost::new(Some(&b));
        assert!(matches!(
            host.mint(put_key_request("secret-docs", "k", 300))
                .await
                .unwrap_err(),
            blob_upload_types::MintError::AccessDenied
        ));
        assert!(minter.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn empty_allowlist_denies_every_container() {
        let minter = Arc::new(FakeMinter::default());
        let b = binding(minter.clone(), Some("blog"), &[], true, true, 3600, None);
        let mut host = BlobUploadHost::new(Some(&b));
        assert!(matches!(
            host.mint(put_key_request("photos", "k", 300))
                .await
                .unwrap_err(),
            blob_upload_types::MintError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn write_right_alone_cannot_mint_multipart() {
        // Independent rights: a write-only binding refuses a multipart credential with access-denied.
        let minter = Arc::new(FakeMinter::default());
        let b = binding(
            minter.clone(),
            Some("blog"),
            &["bulk"],
            true,
            false,
            3600,
            None,
        );
        let mut host = BlobUploadHost::new(Some(&b));
        let mut req = put_key_request("bulk", "big/obj", 300);
        req.perms = vec![blob_upload_types::UploadPerm::Multipart];
        req.target = blob_upload_types::UploadTarget {
            key: None,
            prefix: Some("big".into()),
        };
        assert!(matches!(
            host.mint(req).await.unwrap_err(),
            blob_upload_types::MintError::AccessDenied
        ));
        assert!(minter.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn multipart_right_alone_cannot_mint_a_put() {
        let minter = Arc::new(FakeMinter::default());
        let b = binding(
            minter.clone(),
            Some("blog"),
            &["bulk"],
            false,
            true,
            3600,
            None,
        );
        let mut host = BlobUploadHost::new(Some(&b));
        assert!(matches!(
            host.mint(put_key_request("bulk", "k", 300))
                .await
                .unwrap_err(),
            blob_upload_types::MintError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn ttl_and_max_bytes_are_clamped_to_the_operator_ceiling() {
        let minter = Arc::new(FakeMinter::default());
        // Ceilings below the request: ttl 600, max_bytes 1_000_000.
        let b = binding(
            minter.clone(),
            Some("blog"),
            &["bulk"],
            true,
            true,
            600,
            Some(1_000_000),
        );
        let mut host = BlobUploadHost::new(Some(&b));
        let mut req = put_key_request("bulk", "big/obj", 100_000);
        req.target = blob_upload_types::UploadTarget {
            key: None,
            prefix: Some("big".into()),
        };
        req.perms = vec![blob_upload_types::UploadPerm::Multipart];
        req.constraints.max_bytes = Some(9_999_999_999);
        req.constraints.require_sha256 = true;
        let creds = host.mint(req).await.unwrap();
        assert!(matches!(
            creds,
            blob_upload_types::Credentials::TempCredentials(_)
        ));
        let calls = minter.calls.lock().unwrap();
        assert_eq!(calls[0].ttl_secs, 600, "ttl clamped to the ceiling");
        assert_eq!(
            calls[0].constraints.max_bytes,
            Some(1_000_000),
            "max_bytes clamped to the ceiling"
        );
    }

    #[tokio::test]
    async fn max_bytes_narrows_below_the_ceiling() {
        // A guest can only narrow: a smaller request stays as requested.
        let minter = Arc::new(FakeMinter::default());
        let b = binding(
            minter.clone(),
            Some("blog"),
            &["photos"],
            true,
            false,
            3600,
            Some(1_000_000),
        );
        let mut host = BlobUploadHost::new(Some(&b));
        let mut req = put_key_request("photos", "k", 300);
        req.constraints.max_bytes = Some(4096);
        host.mint(req).await.unwrap();
        assert_eq!(
            minter.calls.lock().unwrap()[0].constraints.max_bytes,
            Some(4096)
        );
    }

    #[tokio::test]
    async fn malformed_requests_are_refused() {
        let minter = Arc::new(FakeMinter::default());
        let b = binding(
            minter.clone(),
            Some("blog"),
            &["photos"],
            true,
            true,
            3600,
            None,
        );
        let mut host = BlobUploadHost::new(Some(&b));
        // both key + prefix
        let both = blob_upload_types::MintRequest {
            container: "photos".into(),
            target: blob_upload_types::UploadTarget {
                key: Some("k".into()),
                prefix: Some("p".into()),
            },
            perms: vec![blob_upload_types::UploadPerm::Put],
            constraints: blob_upload_types::UploadConstraints {
                max_bytes: None,
                content_type: None,
                require_sha256: false,
                create_only: false,
            },
            ttl_seconds: 300,
        };
        assert!(matches!(
            host.mint(both).await.unwrap_err(),
            blob_upload_types::MintError::InvalidRequest(_)
        ));
        // neither key nor prefix
        let neither = blob_upload_types::MintRequest {
            container: "photos".into(),
            target: blob_upload_types::UploadTarget {
                key: None,
                prefix: None,
            },
            perms: vec![blob_upload_types::UploadPerm::Put],
            constraints: blob_upload_types::UploadConstraints {
                max_bytes: None,
                content_type: None,
                require_sha256: false,
                create_only: false,
            },
            ttl_seconds: 300,
        };
        assert!(matches!(
            host.mint(neither).await.unwrap_err(),
            blob_upload_types::MintError::InvalidRequest(_)
        ));
        // zero ttl
        let mut zero = put_key_request("photos", "k", 0);
        zero.ttl_seconds = 0;
        assert!(matches!(
            host.mint(zero).await.unwrap_err(),
            blob_upload_types::MintError::InvalidRequest(_)
        ));
        // empty container
        assert!(matches!(
            host.mint(put_key_request("", "k", 300)).await.unwrap_err(),
            blob_upload_types::MintError::InvalidRequest(_)
        ));
        assert!(minter.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn empty_perms_defaults_to_put_only() {
        let minter = Arc::new(FakeMinter::default());
        let b = binding(
            minter.clone(),
            Some("blog"),
            &["photos"],
            true,
            false,
            3600,
            None,
        );
        let mut host = BlobUploadHost::new(Some(&b));
        let mut req = put_key_request("photos", "k", 300);
        req.perms = vec![]; // guest names none
        host.mint(req).await.unwrap();
        assert_eq!(
            minter.calls.lock().unwrap()[0].perms,
            vec![UploadPerm::Put],
            "an empty perm set defaults to write-only"
        );
    }
}
