//! Configuration + shared state for the local S3-ingress face (PLAN §8 policy knobs, §Endpoint
//! topology, §CORS, §DoS caps).
//!
//! [`S3IngressState`] is the immutable, `Arc`-shared handle the listener passes into every request:
//! the SigV4 region/service the face signs under, the verification trust anchor
//! ([`TokenPublicKey`]), the rotation-aware ingress secret ([`S3IngressSecret`]), the storage/KV
//! handle ([`DeployStore`]), the `UploadGuard` (concurrency + Content-Length early-reject), and the
//! resolved policy knobs (global defaults + per-container overrides).
//!
//! Per-container config ([`ContainerPolicy`]) carries the CORS allow-list and the DoS/size ceilings.
//! Everything is plain, cloneable data so the face is unit-testable without a live socket.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use boatramp_core::cose::TokenPublicKey;
use boatramp_core::deploy::DeployStore;

use super::credential::S3IngressSecret;

/// The fixed SigV4 **region** the local face signs/verifies under. The local face is not a real AWS
/// region; a fixed token keeps the credential-scope string stable and greppable. The client is handed
/// this verbatim in its temp credential (M3), so it always matches.
pub const LOCAL_REGION: &str = "boatramp";
/// The fixed SigV4 **service** term (`s3`) — matches what every S3 SDK signs for the S3 service.
pub const LOCAL_SERVICE: &str = "s3";

/// A hard ceiling on parts per multipart upload (S3's own limit is 10 000). Bounds the staged-part
/// fan-out and the assembly `list`. (Security MEDIUM-3.)
pub const MAX_PARTS_PER_UPLOAD: u32 = 10_000;

/// The default per-container caps when the operator sets no override.
pub const DEFAULT_MAX_CONCURRENT_UPLOADS_PER_CONTAINER: usize = 64;
/// Default staging-GC TTL: incomplete multipart staging older than this is swept. Aggressive on
/// purpose (Security MEDIUM-3) — a dead client's parts don't linger.
pub const DEFAULT_STAGING_GC_TTL: Duration = Duration::from_secs(24 * 3600);

/// Per-container policy (PLAN §8): CORS + the size/DoS ceilings. Absent fields fall back to the
/// [`S3IngressState`] global defaults. Cloneable plain data.
#[derive(Debug, Clone, Default)]
pub struct ContainerPolicy {
    /// The exact origins the CORS preflight/actual-request handler may echo. **Never `*`** on this
    /// credentialed write endpoint, and an arbitrary `Origin` is never reflected — only a member of
    /// this list is echoed back (UX P3). Empty ⇒ no cross-origin browser access (same-origin only).
    pub cors_allowed_origins: Vec<String>,
    /// Per-container object-size ceiling in bytes (a hard cap independent of a credential's own
    /// `max_bytes`, which can only narrow further). `None` ⇒ the global default.
    pub max_object_bytes: Option<u64>,
    /// Cap on simultaneously-open multipart uploads for this container. `None` ⇒ the global default.
    pub max_concurrent_uploads: Option<usize>,
    /// Staging-GC TTL for this container's incomplete multipart uploads. `None` ⇒ the global default.
    pub staging_gc_ttl: Option<Duration>,
}

/// Whether the deployment is clustered (used by the fail-closed multi-node secret guard at startup).
/// A plain enum so the live wiring supplies it from real cluster membership and tests supply it
/// directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deployment {
    /// A single node — the ingress secret may be auto-generated per the credential model.
    SingleNode,
    /// A multi-node cluster — an explicit, cluster-uniform ingress secret is REQUIRED (fail-closed).
    MultiNode,
}

impl Deployment {
    /// Whether this is a multi-node deployment (the input to
    /// [`multi_node_secret_ok`](super::credential::multi_node_secret_ok)).
    pub fn is_multi_node(self) -> bool {
        matches!(self, Self::MultiNode)
    }
}

/// The immutable shared state of the local S3 face, `Arc`-cloned into each request.
pub struct S3IngressState {
    /// The trust anchor that verifies the `KIND_S3_SESSION` session tokens (the fleet root public
    /// key). Verification is offline — no signer needed on the face.
    pub public_key: TokenPublicKey,
    /// The dedicated, rotation-aware ingress root secret. Derives/verifies `secret_access_key`s.
    pub secret: S3IngressSecret,
    /// Storage + KV. Objects land at `hblob/…` (guest-readable); revocation reads `authz/revoked/…`.
    pub deploy: DeployStore,
    /// Concurrency + Content-Length early-reject + per-stream size/idle abort (reused from the
    /// control-plane upload path).
    pub guard: Arc<crate::limits::UploadGuard>,
    /// Opt-in `cti` revocation on the verify path: when `true`, verified sessions additionally check
    /// `authz/revoked/<cti>`. Off by default to keep the stateless fast path (PLAN credential model).
    pub revocation_enabled: bool,
    /// The global default per-container object-size ceiling (bytes). `None` ⇒ unbounded (still bounded
    /// by the `UploadGuard`'s `max_upload_bytes` and each credential's own `max_bytes`).
    pub default_max_object_bytes: Option<u64>,
    /// The global default cap on simultaneously-open multipart uploads per container.
    pub default_max_concurrent_uploads: usize,
    /// The global default staging-GC TTL.
    pub default_staging_gc_ttl: Duration,
    /// Per-container policy overrides, keyed by `"<project>/<site>/<container>"`.
    container_policies: HashMap<String, ContainerPolicy>,
}

impl S3IngressState {
    /// Build the face state with global defaults and no per-container overrides. Callers add overrides
    /// via [`with_container_policy`](Self::with_container_policy).
    pub fn new(
        public_key: TokenPublicKey,
        secret: S3IngressSecret,
        deploy: DeployStore,
        guard: Arc<crate::limits::UploadGuard>,
    ) -> Self {
        Self {
            public_key,
            secret,
            deploy,
            guard,
            revocation_enabled: false,
            default_max_object_bytes: None,
            default_max_concurrent_uploads: DEFAULT_MAX_CONCURRENT_UPLOADS_PER_CONTAINER,
            default_staging_gc_ttl: DEFAULT_STAGING_GC_TTL,
            container_policies: HashMap::new(),
        }
    }

    /// Enable opt-in `cti` revocation on the verify path.
    pub fn with_revocation(mut self, enabled: bool) -> Self {
        self.revocation_enabled = enabled;
        self
    }

    /// Set the global default object-size ceiling.
    pub fn with_default_max_object_bytes(mut self, max: Option<u64>) -> Self {
        self.default_max_object_bytes = max;
        self
    }

    /// Register a per-container policy override, keyed by the scope triple.
    pub fn with_container_policy(
        mut self,
        project: &str,
        site: &str,
        container: &str,
        policy: ContainerPolicy,
    ) -> Self {
        self.container_policies
            .insert(policy_key(project, site, container), policy);
        self
    }

    /// Whether ANY configured container policy for `container` (across projects/sites) allows
    /// `origin` (UX P3). A CORS preflight arrives BEFORE auth (a browser preflight carries no
    /// credential), so the (project, site) is unknown; the face therefore consults the union of
    /// configured policies for that container name. An origin must be EXPLICITLY listed — the empty
    /// default (or an unconfigured container) allows nothing, and `*` is never a member (it is never
    /// written into a policy's list; the CLI/config validates against it in M3).
    pub fn cors_allows(&self, container: &str, origin: &str) -> bool {
        self.container_policies
            .iter()
            .filter(|(key, _)| key.rsplit('/').next() == Some(container))
            .any(|(_, policy)| {
                policy
                    .cors_allowed_origins
                    .iter()
                    .any(|allowed| allowed == origin)
            })
    }

    /// The effective policy for a container: the operator override merged over the global defaults.
    /// Never returns `None` — an unconfigured container gets a policy with the global ceilings and an
    /// empty CORS list (same-origin only).
    pub fn container_policy(&self, project: &str, site: &str, container: &str) -> ContainerPolicy {
        let over = self
            .container_policies
            .get(&policy_key(project, site, container))
            .cloned()
            .unwrap_or_default();
        ContainerPolicy {
            cors_allowed_origins: over.cors_allowed_origins,
            max_object_bytes: over.max_object_bytes.or(self.default_max_object_bytes),
            max_concurrent_uploads: Some(
                over.max_concurrent_uploads
                    .unwrap_or(self.default_max_concurrent_uploads),
            ),
            staging_gc_ttl: Some(over.staging_gc_ttl.unwrap_or(self.default_staging_gc_ttl)),
        }
    }
}

/// The per-container policy key `"<project>/<site>/<container>"` — the same shape the
/// `Resource::BlobUpload` authz target uses.
fn policy_key(project: &str, site: &str, container: &str) -> String {
    format!("{project}/{site}/{container}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_policy_merges_override_over_defaults() {
        use boatramp_core::cose::Signer as _;
        let secret = S3IngressSecret::generate().unwrap();
        let pk = boatramp_core::cose::LocalSigner::generate(boatramp_core::cose::TokenAlg::Es256)
            .public_key();
        let deploy = test_deploy();
        let guard = Arc::new(crate::limits::UploadGuard::new(Default::default()));
        let state = S3IngressState::new(pk, secret, deploy, guard)
            .with_default_max_object_bytes(Some(1000))
            .with_container_policy(
                "default",
                "blog",
                "photos",
                ContainerPolicy {
                    cors_allowed_origins: vec!["https://app.example".into()],
                    max_object_bytes: Some(500),
                    ..Default::default()
                },
            );

        // Overridden container: the override's size wins; the CORS list is present.
        let p = state.container_policy("default", "blog", "photos");
        assert_eq!(p.max_object_bytes, Some(500));
        assert_eq!(
            p.cors_allowed_origins,
            vec!["https://app.example".to_string()]
        );
        assert_eq!(
            p.max_concurrent_uploads,
            Some(DEFAULT_MAX_CONCURRENT_UPLOADS_PER_CONTAINER)
        );

        // Unconfigured container: global default size, empty CORS (same-origin only).
        let d = state.container_policy("default", "blog", "other");
        assert_eq!(d.max_object_bytes, Some(1000));
        assert!(d.cors_allowed_origins.is_empty());
    }

    #[test]
    fn deployment_multi_node_flag() {
        assert!(Deployment::MultiNode.is_multi_node());
        assert!(!Deployment::SingleNode.is_multi_node());
    }

    fn test_deploy() -> DeployStore {
        let storage = Arc::new(super::super::test_support::MapStorage::default());
        let kv = Arc::new(boatramp_core::kv::MemoryKv::new());
        DeployStore::new(storage, kv)
    }
}
