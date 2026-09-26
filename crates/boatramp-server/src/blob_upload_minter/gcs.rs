//! The **GCS** cloud blob-upload minter (M4, folded "Cloud STS scoping" — Security HIGH-3 / §SDK).
//!
//! For a GCS-backed blob container, boatramp brokers a native, scoped upload authorization so the client
//! uploads DIRECTLY to Cloud Storage; the guest reads the object back through the unchanged `hblob/…`
//! read-path. Two shapes, chosen by the (pre-confined) [`MintScope`], mirroring the local face + AWS:
//!
//! - **single key + PUT-only** ⇒ a per-object **V4 signed PUT URL** via the OFFICIAL
//!   `google-cloud-storage` 1.x [`SignedUrlBuilder::sign_with`], scoped to the exact `hblob/…` object.
//!   Keyless / Workload-Identity-friendly when the [`Signer`] is built from ADC (IAM `signBlob` under the
//!   hood; needs `roles/iam.serviceAccountTokenCreator`). A constrained content-type is signed into the
//!   URL, so GCS itself rejects a mismatched upload ⇒ content-type is *enforced* on this shape.
//! - **prefix or bulk** ⇒ a **downscoped STS token** via a hand-rolled **Credential Access Boundary**
//!   token-exchange against `sts.googleapis.com/v1/token` (no Rust crate exists — [`cab_options_json`] +
//!   [`sts_exchange`]). The access boundary is resource-scoped to the exact `hblob/…` object-prefix
//!   (`resource.name.startsWith(...)`) with only `roles/storage.objectCreator` — no read/list/delete.
//!   The client uses the returned OAuth access token as a Bearer credential against the JSON/XML upload
//!   API.
//!
//! **The scope is derived from the host-stamped `MintScope`, never widened** (Security invariant): the
//! signed-URL object / the CAB `startsWith` prefix are [`cloud::scoped_object_path`] under the real
//! bucket. **enforced vs advisory**: neither a signed URL nor a CAB caps object *size* (advisory unless
//! content-addressed); the CAB shape cannot pin content-type (advisory), the signed-URL shape can.

use std::time::Duration;

use async_trait::async_trait;
use boatramp_handlers::{
    BlobUploadMinter, MintScope, MintedCredentials, PresignedPut, TempCredentials, UploadPerm,
    UploadTarget,
};
use gcs_signer::builder::storage::SignedUrlBuilder;
use gcs_signer::http::Method;
use gcs_signer_auth::signer::Signer;

use super::cloud::{self, CloudEnforcement};

/// The GCS STS token endpoint for the Credential-Access-Boundary token-exchange (RFC 8693, Google
/// profile). Boatramp POSTs a downscoping request here with its base access token as the `subject_token`.
pub const GCS_STS_ENDPOINT: &str = "https://sts.googleapis.com/v1/token";

/// The IAM role a downscoped GCS credential is granted — object-create ONLY (write/multipart). NOT
/// `objectViewer`/`objectAdmin`: no read/list/delete on the brokered credential.
pub const GCS_OBJECT_CREATOR_ROLE: &str = "inRole:roles/storage.objectCreator";

/// The static config a GCS cloud minter needs: the real bucket + the endpoint the signed URL / upload
/// targets. The service-account email is needed for the signing scope when signing keylessly via IAM.
#[derive(Debug, Clone)]
pub struct GcsMinterConfig {
    /// The real GCS bucket the node's blob backend writes to.
    pub bucket: String,
    /// The public storage endpoint the client targets (defaults to `https://storage.googleapis.com`).
    pub endpoint: Option<String>,
}

/// The GCS cloud minter: holds the auth [`Signer`] (for V4 signed URLs) + an HTTP client (for the STS
/// token-exchange) + the static config. `subject_token_source` yields the base OAuth access token the
/// CAB exchange downscopes; in production this comes from ADC.
pub struct GcsBlobUploadMinter {
    signer: Signer,
    http: reqwest::Client,
    config: GcsMinterConfig,
    /// A source of the base OAuth2 access token to downscope (the ADC token). Boxed so tests can inject
    /// a fake without a live metadata server.
    subject_token: std::sync::Arc<dyn SubjectTokenSource>,
}

/// Yields the base OAuth2 access token the CAB exchange downscopes. In production this reads ADC; a test
/// injects a fixed token.
#[async_trait]
pub trait SubjectTokenSource: Send + Sync {
    /// The current base access token (a bearer the node's service account already holds).
    async fn access_token(&self) -> Result<String, String>;
}

impl GcsBlobUploadMinter {
    /// Build a minter from a pre-built [`Signer`], an HTTP client, the config, and the subject-token
    /// source. Kept SDK-injectable so the policy/URL construction is unit-testable without live GCP.
    pub fn new(
        signer: Signer,
        http: reqwest::Client,
        config: GcsMinterConfig,
        subject_token: std::sync::Arc<dyn SubjectTokenSource>,
    ) -> Self {
        Self {
            signer,
            http,
            config,
            subject_token,
        }
    }

    /// Whether this credential returns a signed PUT URL (single key + PUT-only) — the SAME rule as the
    /// local face + AWS, so the client's variant handling is backend-independent.
    fn wants_signed_url(scope: &MintScope) -> bool {
        matches!(scope.target, UploadTarget::Key(_)) && scope.perms == [UploadPerm::Put]
    }

    /// The **Credential Access Boundary `options` JSON** — the security-critical artifact the M5 gate
    /// asserts is prefix-resource-scoped + object-create-only (invariant 9). Built ENTIRELY from the
    /// host-stamped [`MintScope`]: the `availableResource` is the real bucket, the single
    /// `availablePermission` is `roles/storage.objectCreator`, and the `availabilityCondition` CEL
    /// expression confines writes to `resource.name.startsWith('projects/_/buckets/{bucket}/objects/
    /// {hblob-prefix}')`. A neutered/bucket-wide/no-condition boundary would be a finding.
    ///
    /// Pure + deterministic ⇒ unit-testable without any live STS call. Returns the JSON string that goes
    /// verbatim into the `options` form field of the token-exchange request.
    pub fn cab_options_json(bucket: &str, scope: &MintScope) -> String {
        // The object-prefix the credential may write under, anchored at `hblob/{qualified-site}/{ctr}/…`.
        let object_prefix = cloud::scoped_object_path(scope);
        // GCS resource names in a CAB CEL condition are `projects/_/buckets/{bucket}/objects/{name}`.
        let cel = format!(
            "resource.name.startsWith('projects/_/buckets/{bucket}/objects/{object_prefix}')"
        );
        let available_resource = format!("//storage.googleapis.com/projects/_/buckets/{bucket}");
        // Hand-build the JSON so the exact byte shape is stable + greppable (the gate inspects it).
        format!(
            "{{\"accessBoundary\":{{\"accessBoundaryRules\":[{{\
             \"availableResource\":\"{available_resource}\",\
             \"availablePermissions\":[\"{GCS_OBJECT_CREATOR_ROLE}\"],\
             \"availabilityCondition\":{{\"title\":\"boatramp-blob-ingress\",\
             \"expression\":\"{cel}\"}}}}]}}}}"
        )
    }

    /// The `x-www-form-urlencoded` body of the STS token-exchange (RFC 8693, Google downscoping profile).
    /// Pure ⇒ testable. `subject_token` is the base ADC access token; `options` is [`cab_options_json`].
    pub fn sts_exchange_form(subject_token: &str, options_json: &str) -> Vec<(String, String)> {
        vec![
            (
                "grant_type".into(),
                "urn:ietf:params:oauth:grant-type:token-exchange".into(),
            ),
            (
                "subject_token_type".into(),
                "urn:ietf:params:oauth:token-type:access_token".into(),
            ),
            (
                "requested_token_type".into(),
                "urn:ietf:params:oauth:token-type:access_token".into(),
            ),
            ("subject_token".into(), subject_token.to_string()),
            ("options".into(), options_json.to_string()),
        ]
    }

    /// POST the token-exchange to [`GCS_STS_ENDPOINT`] and return `(access_token, expires_at_unix)`.
    async fn sts_exchange(&self, scope: &MintScope) -> Result<(String, u64), String> {
        let subject = self.subject_token.access_token().await?;
        let options = Self::cab_options_json(&self.config.bucket, scope);
        let form = Self::sts_exchange_form(&subject, &options);
        let resp = self
            .http
            .post(GCS_STS_ENDPOINT)
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("GCS STS token-exchange request failed: {e}"))?;
        if !resp.status().is_success() {
            let code = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("GCS STS token-exchange returned {code}: {body}"));
        }
        let body: StsResponse = resp
            .json()
            .await
            .map_err(|e| format!("GCS STS token-exchange decode failed: {e}"))?;
        let now = boatramp_core::time::now_unix();
        // The downscoped token expiry is min(subject expiry, requested TTL); GCS returns `expires_in`.
        let expires_at = now.saturating_add(body.expires_in.min(scope.ttl_secs));
        Ok((body.access_token, expires_at))
    }
}

/// The subset of the STS token-exchange response boatramp reads.
#[derive(serde::Deserialize)]
struct StsResponse {
    access_token: String,
    #[serde(default)]
    expires_in: u64,
}

#[async_trait]
impl BlobUploadMinter for GcsBlobUploadMinter {
    async fn mint(&self, scope: &MintScope) -> Result<MintedCredentials, String> {
        let now = boatramp_core::time::now_unix();
        let expires_at = now.saturating_add(scope.ttl_secs);

        if Self::wants_signed_url(scope) {
            let key = match &scope.target {
                UploadTarget::Key(k) => k.clone(),
                UploadTarget::Prefix(_) => unreachable!("wants_signed_url implies a Key target"),
            };
            let object = format!("{}{key}", cloud::scoped_container_root(scope));
            let mut builder = SignedUrlBuilder::for_object(self.config.bucket.clone(), object)
                .with_method(Method::PUT)
                .with_expiration(Duration::from_secs(scope.ttl_secs));
            if let Some(endpoint) = &self.config.endpoint {
                builder = builder.with_endpoint(endpoint.clone());
            }
            let mut required_headers = Vec::new();
            if let Some(ct) = &scope.constraints.content_type {
                // Signing Content-Type into the URL binds it: GCS rejects a mismatched upload.
                builder = builder.with_header("Content-Type", ct.clone());
                required_headers.push(("content-type".to_string(), ct.clone()));
            }
            let url = builder
                .sign_with(&self.signer)
                .await
                .map_err(|e| format!("GCS V4 signed-url signing failed: {e}"))?;
            Ok(MintedCredentials::PresignedPut(PresignedPut {
                url,
                method: "PUT".to_string(),
                required_headers,
                expires_at,
                expires_in_secs: scope.ttl_secs,
            }))
        } else {
            // A prefix/bulk credential ⇒ a downscoped STS token. There is no S3-style secret/session
            // token; the client uses the returned OAuth access token as a Bearer. We surface it in the
            // `session_token` field (the self-describing shape the client feeds its GCS SDK / a raw
            // upload). `access_key_id`/`secret` are empty (GCS uses a bearer, not a HMAC key pair).
            let (access_token, sts_expires_at) = self.sts_exchange(scope).await?;
            // A CAB caps neither object size nor content-type; content-addressing is the strong
            // cross-cloud enforcement. Nothing else is claimed enforced.
            let (enforced, advisory) =
                cloud::constraint_contract(&scope.constraints, CloudEnforcement::NONE);
            Ok(MintedCredentials::TempCredentials(TempCredentials {
                access_key_id: String::new(),
                secret: String::new(),
                session_token: access_token,
                endpoint: self
                    .config
                    .endpoint
                    .clone()
                    .unwrap_or_else(|| "https://storage.googleapis.com".to_string()),
                region: "auto".to_string(),
                bucket: self.config.bucket.clone(),
                force_path_style: false,
                expires_at: sts_expires_at,
                expires_in_secs: sts_expires_at.saturating_sub(now),
                enforced,
                advisory,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_handlers::UploadConstraints;

    fn scope(target: UploadTarget, perms: Vec<UploadPerm>, c: UploadConstraints) -> MintScope {
        MintScope {
            project: "acme".into(),
            site: "blog".into(),
            container: "photos".into(),
            target,
            perms,
            constraints: c,
            ttl_secs: 1800,
        }
    }

    #[test]
    fn cab_boundary_is_prefix_resource_scoped_and_object_create_only() {
        let s = scope(
            UploadTarget::Prefix("ingest/".into()),
            vec![UploadPerm::Put],
            Default::default(),
        );
        let options = GcsBlobUploadMinter::cab_options_json("my-bucket", &s);
        // The CEL condition confines writes to the EXACT hblob prefix — NOT the whole bucket (invariant
        // 9; the gate neuters this to a bucket-wide/no-condition boundary ⇒ FAIL).
        assert!(
            options.contains(
                "resource.name.startsWith('projects/_/buckets/my-bucket/objects/hblob/acme/blog/photos/ingest/')"
            ),
            "CAB must confine to the exact hblob prefix: {options}"
        );
        // Object-create ONLY — no viewer/admin.
        assert!(options.contains("inRole:roles/storage.objectCreator"));
        assert!(
            !options.contains("objectViewer")
                && !options.contains("objectAdmin")
                && !options.contains("storage.objects.get"),
            "must not grant read/list/admin: {options}"
        );
        // Bucket-scoped availableResource (the boundary's ceiling), not `*`.
        assert!(options.contains("//storage.googleapis.com/projects/_/buckets/my-bucket"));
    }

    #[test]
    fn sts_exchange_form_is_a_token_exchange_grant() {
        let form = GcsBlobUploadMinter::sts_exchange_form("BASE_TOKEN", "{\"accessBoundary\":{}}");
        let get = |k: &str| form.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.as_str());
        assert_eq!(
            get("grant_type"),
            Some("urn:ietf:params:oauth:grant-type:token-exchange")
        );
        assert_eq!(get("subject_token"), Some("BASE_TOKEN"));
        assert_eq!(get("options"), Some("{\"accessBoundary\":{}}"));
        assert_eq!(
            get("requested_token_type"),
            Some("urn:ietf:params:oauth:token-type:access_token")
        );
    }

    #[test]
    fn a_single_key_cab_scopes_to_the_exact_object() {
        let s = scope(
            UploadTarget::Key("avatars/u.jpg".into()),
            vec![UploadPerm::Put, UploadPerm::Multipart],
            Default::default(),
        );
        let options = GcsBlobUploadMinter::cab_options_json("b", &s);
        assert!(
            options.contains("objects/hblob/acme/blog/photos/avatars/u.jpg'"),
            "a key target confines to the exact object: {options}"
        );
    }

    #[test]
    fn size_and_content_type_are_advisory_on_gcs_cab() {
        let c = UploadConstraints {
            max_bytes: Some(9_000_000),
            content_type: Some("video/mp4".into()),
            require_sha256: false,
            create_only: false,
        };
        let (enforced, advisory) = cloud::constraint_contract(&c, CloudEnforcement::NONE);
        assert!(
            enforced.is_empty(),
            "a CAB caps neither size nor content-type: {enforced:?}"
        );
        assert!(advisory.contains(&"max_bytes=9000000".to_string()));
        assert!(advisory.contains(&"content_type=video/mp4".to_string()));
    }
}
