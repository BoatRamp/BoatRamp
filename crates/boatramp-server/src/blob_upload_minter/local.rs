//! The server-side implementation of the guest `blob-upload` mint seam
//! ([`boatramp_handlers::BlobUploadMinter`], PLAN-blob-s3-ingress §6 / M3).
//!
//! The binding ([`boatramp-handlers/src/bindings/blob_upload.rs`]) has already enforced
//! deny-by-default, the write/multipart right split, the `upload_containers` allowlist, the host-forced
//! project+site, the TTL/max-bytes clamp, and the fail-closed no-resolved-site check. This minter is
//! the trusted assembly step: it mints the fleet-signed [`KIND_S3_SESSION`](boatramp_core::cose) token
//! carrying the (host-stamped) scope, generates the public `access_key_id`, derives the
//! `secret_access_key` from the dedicated S3-ingress secret, and returns the self-describing
//! credential.
//!
//! **Variant selection** (PLAN "Mint return shape / DX"): a single-key + PUT-only credential returns a
//! `presigned-put` (a ready-to-`fetch()` URL, no SigV4-in-JS for the browser); anything else (a prefix,
//! or a multipart credential) returns `temp-credentials` (an S3 SDK configures them and uses native
//! multipart). Both feed the SAME M2 local face — the face verifies whatever the credential produces.
//!
//! The minter is only ever wired for the LOCAL S3 face (M3); the cloud brokering (M4) plugs a different
//! `BlobUploadMinter` behind the same seam. So on the local face every constraint is HARD-enforced —
//! the `enforced` list carries them all and `advisory` is empty.

use std::sync::Arc;

use boatramp_core::cose::{
    S3Constraints, S3Perm, S3SessionScope, S3Target, Signer, mint_s3_session,
};
use boatramp_handlers::{
    BlobUploadMinter, MintScope, MintedCredentials, PresignedPut, TempCredentials, UploadPerm,
    UploadTarget,
};

use crate::s3_ingress::credential::{S3IngressSecret, generate_access_key_id};
use crate::s3_ingress::sigv4::{self, CredentialScope};

/// The static config the local-face minter needs to shape a credential: the publicly-reachable S3
/// endpoint base URL a client targets, and the SigV4 region/service the face signs/verifies under
/// (fixed local tokens — see [`crate::s3_ingress::config`]). Cloneable plain data.
#[derive(Debug, Clone)]
pub struct BlobUploadFaceConfig {
    /// The S3 endpoint base URL the client SDK / browser targets, e.g. `http://127.0.0.1:9000` or the
    /// operator's public S3-face URL. Path-style: the object path is `/{container}/{key}`.
    pub endpoint_base: String,
    /// The SigV4 region the face signs under ([`LOCAL_REGION`](crate::s3_ingress::config::LOCAL_REGION)).
    pub region: String,
    /// The SigV4 service term ([`LOCAL_SERVICE`](crate::s3_ingress::config::LOCAL_SERVICE)), `s3`.
    pub service: String,
}

/// Build the [`BlobUploadMintConfig`](crate::BlobUploadMintConfig) the runtime registers (the startup
/// wiring seam): the shared S3-ingress `secret`, the public `endpoint_base` a minted credential
/// targets, and the operator TTL/max-bytes ceilings. The SigV4 region/service are the fixed local
/// tokens. Keeps the region/service constants out of the CLI wiring.
pub fn mint_config(
    secret: S3IngressSecret,
    endpoint_base: String,
    max_ttl_secs: u64,
    max_bytes_ceiling: Option<u64>,
) -> crate::BlobUploadMintConfig {
    crate::BlobUploadMintConfig {
        secret: Arc::new(secret),
        face: BlobUploadFaceConfig {
            endpoint_base,
            region: crate::s3_ingress::config::LOCAL_REGION.to_string(),
            service: crate::s3_ingress::config::LOCAL_SERVICE.to_string(),
        },
        max_ttl_secs,
        max_bytes_ceiling,
    }
}

/// The local-face blob-upload minter: holds the fleet [`Signer`] (to mint the session token) and the
/// dedicated [`S3IngressSecret`] (to derive the `secret_access_key`), plus the endpoint/region config.
pub struct ServerBlobUploadMinter {
    /// The fleet signer (reused from the runtime `session_signer`), signs the `KIND_S3_SESSION` token.
    pub signer: Arc<dyn Signer>,
    /// The dedicated S3-ingress secret — the SAME material the face derives+verifies under, so a
    /// credential this minter issues is accepted by the face (shared `Arc`).
    pub secret: Arc<S3IngressSecret>,
    /// Endpoint + region/service config for shaping the returned credential.
    pub config: BlobUploadFaceConfig,
}

impl ServerBlobUploadMinter {
    /// Build the `S3SessionScope` for a host-forced [`MintScope`] (perms/target/constraints mapped from
    /// the host-native binding types). Project + site are already host-stamped by the binding.
    fn session_scope(scope: &MintScope) -> S3SessionScope {
        S3SessionScope {
            project: scope.project.clone(),
            site: scope.site.clone(),
            container: scope.container.clone(),
            target: match &scope.target {
                UploadTarget::Key(k) => S3Target::Key(k.clone()),
                UploadTarget::Prefix(p) => S3Target::Prefix(p.clone()),
            },
            perms: scope
                .perms
                .iter()
                .map(|p| match p {
                    UploadPerm::Put => S3Perm::Put,
                    UploadPerm::Multipart => S3Perm::Multipart,
                })
                .collect(),
            constraints: S3Constraints {
                max_bytes: scope.constraints.max_bytes,
                content_type: scope.constraints.content_type.clone(),
                require_sha256: scope.constraints.require_sha256,
                create_only: scope.constraints.create_only,
            },
        }
    }

    /// Whether this credential should return a `presigned-put`: a single OBJECT KEY (not a prefix) with
    /// PUT (and only PUT) permitted — the browser-UGC shape a single `fetch()` handles. Everything else
    /// (a prefix, or any multipart grant) needs a full SDK ⇒ `temp-credentials`.
    fn wants_presigned_put(scope: &MintScope) -> bool {
        matches!(scope.target, UploadTarget::Key(_)) && scope.perms == [UploadPerm::Put]
    }

    /// The human-readable `enforced` constraint contract for the LOCAL face — every stamped constraint
    /// is a hard, fail-closed check at the face (§ M2), so all present ones are enforced (advisory is
    /// empty here; a cloud minter, M4, populates advisory for what its store can't cap in-policy).
    fn enforced_list(scope: &MintScope) -> Vec<String> {
        let c = &scope.constraints;
        let mut out = Vec::new();
        if let Some(mb) = c.max_bytes {
            out.push(format!("max_bytes={mb}"));
        }
        if let Some(ct) = &c.content_type {
            out.push(format!("content_type={ct}"));
        }
        if c.require_sha256 {
            out.push("require_sha256".to_string());
        }
        if c.create_only {
            out.push("create_only".to_string());
        }
        out
    }
}

#[async_trait::async_trait]
impl BlobUploadMinter for ServerBlobUploadMinter {
    async fn mint(&self, scope: &MintScope) -> Result<MintedCredentials, String> {
        let now = boatramp_core::time::now_unix();
        let session_scope = Self::session_scope(scope);
        // Mint the fleet-signed KIND_S3_SESSION token carrying the host-stamped scope. The TTL was
        // already clamped by the binding.
        let session_token =
            mint_s3_session(&session_scope, scope.ttl_secs, now, self.signer.as_ref())
                .await
                .map_err(|e| e.to_string())?;
        // Verify our own freshly-minted token to read back its `cti` (the secret is bound to it) — the
        // cti is generated inside `mint_s3_session`, so we recover it via a self-verify.
        let session =
            boatramp_core::cose::verify_s3_session(&session_token, &self.signer.public_key(), now)
                .map_err(|e| e.to_string())?;
        let access_key_id = generate_access_key_id().map_err(|e| e.to_string())?;
        let secret = self
            .secret
            .derive_secret(&access_key_id, &session.cti)
            .map_err(|e| e.to_string())?;
        let expires_at = now.saturating_add(scope.ttl_secs);

        if Self::wants_presigned_put(scope) {
            // A single-key PUT-only credential ⇒ a ready-to-fetch presigned URL (no SigV4-in-JS).
            let key = match &scope.target {
                UploadTarget::Key(k) => k.clone(),
                UploadTarget::Prefix(_) => unreachable!("wants_presigned_put implies a Key target"),
            };
            let cred_scope = CredentialScope {
                access_key_id: access_key_id.clone(),
                // The scope date is the YYYYMMDD prefix of the presigned X-Amz-Date.
                date: sigv4::unix_to_amz_date(now as i64)[..8].to_string(),
                region: self.config.region.clone(),
                service: self.config.service.clone(),
            };
            let url = sigv4::presign_put_url(
                &self.config.endpoint_base,
                &scope.container,
                &key,
                &cred_scope,
                &secret,
                &session_token,
                now as i64,
                scope.ttl_secs as i64,
            )
            .map_err(|e| format!("{e:?}"))?;
            // The client must send the constrained Content-Type verbatim, when set (it is NOT signed
            // into the presigned URL — presigned only signs `host` — so it is an enforced check the
            // face applies from the credential scope; we surface it as a required header for the client).
            let mut required_headers = Vec::new();
            if let Some(ct) = &scope.constraints.content_type {
                required_headers.push(("content-type".to_string(), ct.clone()));
            }
            Ok(MintedCredentials::PresignedPut(PresignedPut {
                url,
                method: "PUT".to_string(),
                required_headers,
                expires_at,
                expires_in_secs: scope.ttl_secs,
            }))
        } else {
            // A prefix or multipart credential ⇒ temp-credentials for a full S3 SDK.
            Ok(MintedCredentials::TempCredentials(TempCredentials {
                access_key_id,
                secret,
                session_token,
                endpoint: self.config.endpoint_base.clone(),
                region: self.config.region.clone(),
                bucket: scope.container.clone(),
                force_path_style: true,
                expires_at,
                expires_in_secs: scope.ttl_secs,
                enforced: Self::enforced_list(scope),
                // The local face hard-enforces every constraint, so nothing is advisory (M4 cloud
                // minters populate this for what a cloud store cannot cap in a session policy).
                advisory: Vec::new(),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3_ingress::config::{LOCAL_REGION, LOCAL_SERVICE};
    use boatramp_core::cose::{LocalSigner, S3Session, TokenAlg, verify_s3_session};
    use boatramp_handlers::UploadConstraints;

    const ROOT: [u8; 32] = [0x5a; 32];

    fn minter() -> (
        ServerBlobUploadMinter,
        Arc<dyn Signer>,
        Arc<S3IngressSecret>,
    ) {
        let signer: Arc<dyn Signer> = Arc::new(LocalSigner::generate(TokenAlg::Es256));
        let secret = Arc::new(S3IngressSecret::from_bytes(&ROOT).unwrap());
        let m = ServerBlobUploadMinter {
            signer: signer.clone(),
            secret: secret.clone(),
            config: BlobUploadFaceConfig {
                endpoint_base: "http://127.0.0.1:9000".into(),
                region: LOCAL_REGION.into(),
                service: LOCAL_SERVICE.into(),
            },
        };
        (m, signer, secret)
    }

    fn scope(
        target: UploadTarget,
        perms: Vec<UploadPerm>,
        c: UploadConstraints,
        ttl: u64,
    ) -> MintScope {
        MintScope {
            project: "acme".into(),
            site: "blog".into(),
            container: "photos".into(),
            target,
            perms,
            constraints: c,
            ttl_secs: ttl,
        }
    }

    #[tokio::test]
    async fn single_key_put_only_yields_a_presigned_put() {
        let (m, _signer, _secret) = minter();
        let creds = m
            .mint(&scope(
                UploadTarget::Key("avatars/u.jpg".into()),
                vec![UploadPerm::Put],
                UploadConstraints::default(),
                900,
            ))
            .await
            .unwrap();
        match creds {
            MintedCredentials::PresignedPut(p) => {
                assert_eq!(p.method, "PUT");
                assert!(
                    p.url
                        .starts_with("http://127.0.0.1:9000/photos/avatars/u.jpg?")
                );
                assert!(p.url.contains("X-Amz-Signature="));
                assert_eq!(p.expires_in_secs, 900);
            }
            other => panic!("expected presigned-put, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn prefix_or_multipart_yields_temp_credentials_and_a_valid_session_token() {
        let (m, signer, secret) = minter();
        let creds = m
            .mint(&scope(
                UploadTarget::Prefix("ingest/".into()),
                vec![UploadPerm::Put, UploadPerm::Multipart],
                UploadConstraints {
                    require_sha256: true,
                    ..Default::default()
                },
                1800,
            ))
            .await
            .unwrap();
        match creds {
            MintedCredentials::TempCredentials(t) => {
                assert!(t.access_key_id.starts_with("BRUP"));
                assert_eq!(t.bucket, "photos");
                assert_eq!(t.region, LOCAL_REGION);
                assert!(t.force_path_style);
                assert_eq!(t.expires_in_secs, 1800);
                assert!(t.enforced.iter().any(|e| e == "require_sha256"));
                assert!(t.advisory.is_empty(), "local face enforces everything");
                // The session token verifies + carries the host-stamped scope, and the secret is the
                // one derivable for this (akid, cti) — proving the credential is internally consistent.
                let now = boatramp_core::time::now_unix();
                let session: S3Session =
                    verify_s3_session(&t.session_token, &signer.public_key(), now).unwrap();
                assert_eq!(session.scope.project, "acme");
                assert_eq!(session.scope.site, "blog");
                assert_eq!(session.scope.container, "photos");
                let expected = secret
                    .derive_secret(&t.access_key_id, &session.cti)
                    .unwrap();
                assert_eq!(expected, t.secret, "the secret is HKDF(akid, cti)");
            }
            other => panic!("expected temp-credentials, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn content_type_constraint_surfaces_as_a_required_header_on_presigned() {
        let (m, _signer, _secret) = minter();
        let creds = m
            .mint(&scope(
                UploadTarget::Key("x.jpg".into()),
                vec![UploadPerm::Put],
                UploadConstraints {
                    content_type: Some("image/jpeg".into()),
                    ..Default::default()
                },
                600,
            ))
            .await
            .unwrap();
        match creds {
            MintedCredentials::PresignedPut(p) => {
                assert!(
                    p.required_headers
                        .iter()
                        .any(|(k, v)| k == "content-type" && v == "image/jpeg"),
                    "a constrained content-type is surfaced as a required header"
                );
            }
            other => panic!("expected presigned-put, got {other:?}"),
        }
    }

    /// THE integration invariant (PLAN M3 test requirement): a MINTED credential is actually accepted
    /// by the M2 local S3 FACE end-to-end — mint (temp-credentials for a prefix) → SigV4-sign a PUT
    /// with those exact credentials → drive the real `face::handle` → the object lands at the
    /// guest-readable `hblob/{site}/{container}/{key}` key, byte-identical. This ties the mint side
    /// (M3) to the verify side (M2) over the SAME signer + ingress secret.
    #[tokio::test]
    async fn minted_temp_credentials_are_accepted_by_the_m2_face_round_trip() {
        use crate::s3_ingress::config::S3IngressState;
        use crate::s3_ingress::face::{self, S3Request};
        use crate::s3_ingress::sigv4;
        use axum::body::Body;
        use axum::http::StatusCode;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::MemoryKv;

        // One signer + one ingress secret shared between the minter and the face.
        let signer: Arc<dyn Signer> = Arc::new(LocalSigner::generate(TokenAlg::Es256));
        let secret = Arc::new(S3IngressSecret::from_bytes(&ROOT).unwrap());
        let m = ServerBlobUploadMinter {
            signer: signer.clone(),
            secret: secret.clone(),
            config: BlobUploadFaceConfig {
                endpoint_base: "http://s3.local".into(),
                region: crate::s3_ingress::config::LOCAL_REGION.into(),
                service: crate::s3_ingress::config::LOCAL_SERVICE.into(),
            },
        };
        // Mint a prefix credential (⇒ temp-credentials) for container "photos", prefix "ingest".
        let creds = m
            .mint(&scope(
                UploadTarget::Prefix("ingest".into()),
                vec![UploadPerm::Put],
                UploadConstraints::default(),
                900,
            ))
            .await
            .unwrap();
        let MintedCredentials::TempCredentials(tc) = creds else {
            panic!("expected temp-credentials for a prefix credential");
        };

        // Build the M2 face over an in-memory store, using the SAME signer public key + a clone of the
        // SAME ingress secret — so a credential this minter issued verifies here.
        let map = Arc::new(crate::s3_ingress::test_support::MapStorage::default());
        let deploy = DeployStore::new(map.clone(), Arc::new(MemoryKv::new()));
        let guard = Arc::new(crate::limits::UploadGuard::new(Default::default()));
        let state = S3IngressState::new(
            signer.public_key(),
            S3IngressSecret::from_bytes(&ROOT).unwrap(),
            deploy,
            guard,
        );

        // Now sign a PUT to /photos/ingest/file.bin with the minted temp-credentials, exactly as an S3
        // SDK would (real-hash payload, host + date + content-sha256 + security-token signed headers).
        let body = b"minted-and-uploaded";
        // The scope's date is the YYYYMMDD prefix of the request date; use a fixed now aligned to the
        // credential's minting date (the token exp still validates within TTL).
        let now = boatramp_core::time::now_unix() as i64;
        let amz_date = sigv4::unix_to_amz_date(now);
        let scope_date = amz_date[..8].to_string();
        let uri_path = "/photos/ingest/file.bin";
        let payload_hash = sigv4::sha256_hex(body);
        let headers = vec![
            ("host".to_string(), "s3.local".to_string()),
            ("x-amz-date".to_string(), amz_date.clone()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-security-token".to_string(), tc.session_token.clone()),
            ("content-length".to_string(), body.len().to_string()),
        ];
        let signed = vec![
            "host".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ];
        let cred_scope = sigv4::CredentialScope {
            access_key_id: tc.access_key_id.clone(),
            date: scope_date,
            region: tc.region.clone(),
            service: crate::s3_ingress::config::LOCAL_SERVICE.into(),
        };
        let creq_req = sigv4::CanonicalRequest {
            method: "PUT",
            uri_path,
            query: "",
            headers: &headers,
            payload_hash: &payload_hash,
        };
        let (creq, signed_str) = sigv4::canonical_request_string(&creq_req, &signed).unwrap();
        let sts = sigv4::string_to_sign(&amz_date, &cred_scope, &creq);
        let sig = sigv4::compute_signature(&tc.secret, &cred_scope, &sts);
        let mut req_headers = headers.clone();
        req_headers.push((
            "authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{}/{}/{}/aws4_request, SignedHeaders={signed_str}, Signature={sig}",
                tc.access_key_id,
                &amz_date[..8],
                tc.region,
                crate::s3_ingress::config::LOCAL_SERVICE,
            ),
        ));
        let req = S3Request {
            method: "PUT".into(),
            uri_path: uri_path.into(),
            query: String::new(),
            headers: req_headers,
            body: Body::from(body.to_vec()),
        };
        let resp = face::handle(&state, req, now).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a minted credential must be accepted by the M2 face"
        );
        // Guest read-through: the object is at the exact hblob key the guest compat::blob binding
        // reads. The scope's project is "acme" (a NAMED project ⇒ a project segment), site "blog".
        assert_eq!(
            map.get_bytes("hblob/acme/blog/photos/ingest/file.bin")
                .unwrap(),
            body,
            "the uploaded object lands guest-readable, proving mint→PUT→read"
        );
    }

    /// HIGH-1 (M3 security review) — the headline browser-UGC flow end-to-end: mint a `presigned-put`
    /// credential (single key + PUT-only ⇒ a ready `fetch()` URL), then drive that URL through the real
    /// `face::handle` with the session token in the **query only** (`X-Amz-Security-Token`, exactly as a
    /// browser `fetch(url, {method:"PUT", body})` sends it — never a header). The face MUST accept it
    /// (200) and land the object guest-readable at `hblob/…`.
    ///
    /// This proves the fix: `presign_put_url` signs `X-Amz-Security-Token` into the canonical query, so
    /// the face must source the token from that query param. Before the fix the face read the token ONLY
    /// from the `x-amz-security-token` header ⇒ `None` ⇒ uniform 403 ⇒ every presigned-put credential
    /// unredeemable. See `presigned_put_url_query_token_is_required_by_the_face` below for the anti-hollow
    /// mutation (remove the query lookup ⇒ this class of request 403s).
    #[tokio::test]
    async fn minted_presigned_put_is_accepted_by_the_face_with_token_in_query_only() {
        use crate::s3_ingress::config::S3IngressState;
        use crate::s3_ingress::face::{self, S3Request};
        use axum::body::Body;
        use axum::http::StatusCode;
        use boatramp_core::deploy::DeployStore;
        use boatramp_core::kv::MemoryKv;

        // One signer + one ingress secret shared between the minter and the face.
        let signer: Arc<dyn Signer> = Arc::new(LocalSigner::generate(TokenAlg::Es256));
        let secret = Arc::new(S3IngressSecret::from_bytes(&ROOT).unwrap());
        // The minter's endpoint host MUST match the `host` the face signs/verifies over (the presigned
        // URL signs `host`), so use a fixed host and send that same host header on the request.
        let m = ServerBlobUploadMinter {
            signer: signer.clone(),
            secret: secret.clone(),
            config: BlobUploadFaceConfig {
                endpoint_base: "http://s3.local".into(),
                region: crate::s3_ingress::config::LOCAL_REGION.into(),
                service: crate::s3_ingress::config::LOCAL_SERVICE.into(),
            },
        };
        // Mint a single-key PUT-only credential ⇒ a `presigned-put` (the browser-UGC shape).
        let creds = m
            .mint(&scope(
                UploadTarget::Key("avatars/u1.jpg".into()),
                vec![UploadPerm::Put],
                UploadConstraints::default(),
                900,
            ))
            .await
            .unwrap();
        let MintedCredentials::PresignedPut(p) = creds else {
            panic!("expected presigned-put for a single-key PUT-only credential");
        };
        assert_eq!(p.method, "PUT");
        // The token is carried in the URL query (not a header) — the whole point of a presigned URL.
        assert!(
            p.url.contains("X-Amz-Security-Token="),
            "the presigned URL must carry the session token in the query: {}",
            p.url
        );

        // Build the M2 face over an in-memory store, with the SAME signer public key + a clone of the
        // SAME ingress secret.
        let map = Arc::new(crate::s3_ingress::test_support::MapStorage::default());
        let deploy = DeployStore::new(map.clone(), Arc::new(MemoryKv::new()));
        let guard = Arc::new(crate::limits::UploadGuard::new(Default::default()));
        let state = S3IngressState::new(
            signer.public_key(),
            S3IngressSecret::from_bytes(&ROOT).unwrap(),
            deploy,
            guard,
        );

        // Split the minted URL into path + query exactly as the listener does, then drive it through
        // the face as a browser `fetch(url, {method:"PUT", body})` would: NO `x-amz-security-token`
        // header, ONLY the `host` header the presigned signature was computed over. The token lives in
        // the query.
        let (path, query) = p
            .url
            .strip_prefix("http://s3.local")
            .expect("minted URL uses the configured endpoint")
            .split_once('?')
            .expect("a presigned URL has a query");
        let body = b"the avatar bytes";
        let req = S3Request {
            method: "PUT".into(),
            uri_path: path.into(),
            query: query.into(),
            headers: vec![("host".to_string(), "s3.local".to_string())],
            body: Body::from(body.to_vec()),
        };
        // Drive at the credential's mint time (the presigned expiry window holds).
        let now = boatramp_core::time::now_unix() as i64;
        let resp = face::handle(&state, req, now).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a minted presigned-put URL (token in query only) must be accepted by the face"
        );
        // Guest read-through: the object lands at the exact hblob key. Project "acme", site "blog".
        assert_eq!(
            map.get_bytes("hblob/acme/blog/photos/avatars/u1.jpg")
                .unwrap(),
            body,
            "the presigned upload lands guest-readable, proving the browser-UGC flow works end-to-end"
        );
    }
}
