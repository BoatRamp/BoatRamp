//! The **AWS** cloud blob-upload minter (M4, folded "Cloud STS scoping" — Security HIGH-3).
//!
//! For an S3-backed blob container, boatramp brokers a **native, scoped, short-lived AWS credential** so
//! the client uploads DIRECTLY to real S3 (bytes never transit the node), then the guest reads the
//! object back through the unchanged `hblob/…` read-path.
//!
//! Two shapes, chosen by the (pre-confined) [`MintScope`], IDENTICAL to the local face's variant split:
//!
//! - **single key + PUT-only** ⇒ a per-object **presigned PUT** (`aws-sdk-s3` `PutObject.presigned()`):
//!   a ready-to-`fetch()` URL for the browser-UGC case, no SigV4-in-JS. When a content-type is
//!   constrained it is signed into the request, so S3 itself rejects a mismatched upload — that makes
//!   content-type *enforced* on the presigned shape.
//! - **prefix or multipart** ⇒ **temp credentials** via STS. Default `AssumeRole` (works from an
//!   assumed instance/task role) with an **inline session policy** [`session_policy_json`] that is
//!   **resource-scoped to the exact `hblob/…` prefix** and **action-scoped to `s3:PutObject` + the
//!   multipart quartet only** — no `Get`/`List`/`Delete`, no bucket-level. `GetFederationToken` is the
//!   fallback for IAM-user deployments (same session policy). The client feeds the returned
//!   `{access_key_id, secret, session_token}` to any S3 SDK and uses native multipart for resume.
//!
//! **The scope is derived from the host-stamped `MintScope`, never widened** (Security invariant): the
//! policy `Resource` is [`cloud::scoped_object_path`] under the real bucket, so a brokered credential
//! can only write inside the guest's own container tree.
//!
//! **enforced vs advisory** (the security crux): a session policy CANNOT cap object *size*, and cannot
//! pin *content-type* on a broad prefix credential ⇒ those are `advisory` on the temp-credential shape
//! unless content-addressing makes them enforceable (see [`cloud::constraint_contract`]). This minter
//! NEVER labels an uncapped constraint `enforced`.

use std::time::Duration;

use async_trait::async_trait;
use boatramp_handlers::{
    BlobUploadMinter, MintScope, MintedCredentials, PresignedPut, TempCredentials, UploadPerm,
    UploadTarget,
};

use super::cloud::{self, CloudEnforcement};

/// How boatramp obtains the scoped temp credential from AWS STS. `AssumeRole` is the default (works
/// from an assumed instance/task role); `GetFederationToken` is for IAM-user deployments (no role to
/// assume, but the caller must be a real IAM user, not itself a session).
#[derive(Debug, Clone)]
pub enum StsMode {
    /// `sts:AssumeRole` with an inline session policy (default). Needs a role ARN the base credential is
    /// allowed to assume, whose own permissions are a superset of the session policy (the effective
    /// permission is the intersection).
    AssumeRole {
        /// The role ARN to assume (e.g. `arn:aws:iam::123456789012:role/boatramp-blob-ingress`).
        role_arn: String,
    },
    /// `sts:GetFederationToken` with an inline policy — for an IAM-user base credential.
    GetFederationToken,
}

/// The static config an AWS cloud minter needs: the real bucket, its region, the STS mode, and the TTL
/// ceiling for the brokered credential (STS enforces its own min/max, which we clamp into).
#[derive(Debug, Clone)]
pub struct AwsMinterConfig {
    /// The real S3 bucket the node's blob backend writes to (the `hblob/…` keys live under it).
    pub bucket: String,
    /// The AWS region of the bucket (used in the ARN and handed to the client SDK).
    pub region: String,
    /// The public endpoint the client SDK targets. `None` ⇒ the AWS default for the region; `Some` for
    /// an S3-compatible/MinIO deployment (then also set `force_path_style`).
    pub endpoint: Option<String>,
    /// Path-style addressing (MinIO / most S3-compatibles). Real AWS uses virtual-host style.
    pub force_path_style: bool,
    /// How to broker the temp credential.
    pub sts_mode: StsMode,
}

/// The AWS cloud minter: holds the STS + S3 clients (built from the node's ambient AWS config, the SAME
/// base credential the storage backend uses) and the static minter config.
pub struct AwsBlobUploadMinter {
    sts: aws_sdk_sts::Client,
    s3: aws_sdk_s3::Client,
    config: AwsMinterConfig,
}

impl AwsBlobUploadMinter {
    /// Build a minter from an existing `aws_config::SdkConfig` (the ambient/base AWS config the node
    /// resolved for its S3 storage backend) + the static minter config. The STS + S3 clients share the
    /// base credential; the session policy narrows every brokered credential.
    pub fn new(sdk_config: &aws_config::SdkConfig, config: AwsMinterConfig) -> Self {
        let sts = aws_sdk_sts::Client::new(sdk_config);
        // The S3 client for presigning honours the same endpoint/path-style as the storage backend so a
        // presigned URL targets the same host the client would otherwise configure.
        let mut s3_builder = aws_sdk_s3::config::Builder::from(sdk_config);
        if let Some(endpoint) = &config.endpoint {
            s3_builder = s3_builder.endpoint_url(endpoint.clone());
        }
        if config.force_path_style {
            s3_builder = s3_builder.force_path_style(true);
        }
        let s3 = aws_sdk_s3::Client::from_conf(s3_builder.build());
        Self { sts, s3, config }
    }

    /// The `s3:PutObject` + multipart-quartet action set — and NOTHING else (no get/list/delete, no
    /// bucket-level). The exact minimal action-scope the folded condition requires.
    fn actions(perms: &[UploadPerm]) -> Vec<&'static str> {
        let mut actions = Vec::new();
        // A single-shot PUT is always allowed on a write/multipart credential (the binding pushed `Put`
        // when only multipart was granted, mirroring the local face). Multipart adds the quartet.
        actions.push("s3:PutObject");
        if perms.contains(&UploadPerm::Multipart) {
            // The multipart quartet: create, upload part, complete, abort. `ListMultipartUploads`/
            // `ListParts` are deliberately EXCLUDED (they are read/list surfaces, not needed to write).
            actions.push("s3:CreateMultipartUpload");
            actions.push("s3:UploadPart");
            actions.push("s3:CompleteMultipartUpload");
            actions.push("s3:AbortMultipartUpload");
        }
        actions
    }

    /// The **inline session policy JSON** — the security-critical artifact the M5 gate asserts is
    /// prefix-resource-scoped + put/multipart-action-scoped only (invariant 9). Built ENTIRELY from the
    /// host-stamped [`MintScope`]: the `Resource` is `arn:aws:s3:::{bucket}/{hblob-scoped-path}*` (a
    /// single key ⇒ the exact object; a prefix ⇒ the subtree wildcard, which `scoped_object_path`
    /// already boundaried with a trailing `/`), the `Action` is the minimal [`actions`](Self::actions)
    /// set. A neutered/bucket-wide/`*` policy would be a finding.
    ///
    /// **Built with `serde_json`, NOT `format!`-splicing (Security HIGH-1):** the resource ARN carries a
    /// host-forced-but-composed key/prefix; a stray `"` in it must never be able to break out of the
    /// string and inject a second, broader `Allow`. `serde_json` escapes every value, so the document
    /// structure is fixed by construction — belt-and-suspenders with the charset screen at the mint
    /// choke point ([`screen_upload_target`](boatramp_handlers::screen_upload_target)).
    ///
    /// Pure + deterministic ⇒ unit-testable without any live STS call.
    pub fn session_policy_json(bucket: &str, scope: &MintScope) -> String {
        let actions = Self::actions(&scope.perms);
        // The object-resource ARN. For a KEY target the resource is the exact object (no wildcard); for
        // a PREFIX target it is the subtree (`prefix/*`). `scoped_object_path` already anchors under
        // `hblob/{qualified-site}/{container}/`, so the credential cannot address another container.
        let object_path = cloud::scoped_object_path(scope);
        let resource = match &scope.target {
            UploadTarget::Key(_) => format!("arn:aws:s3:::{bucket}/{object_path}"),
            UploadTarget::Prefix(_) => format!("arn:aws:s3:::{bucket}/{object_path}*"),
        };
        // Build the document as structured JSON so a metacharacter in `resource`/`actions` can only ever
        // be an escaped string value — never a new key, statement, or Allow. `serde_json::to_string`
        // cannot fail on this (all-string) value.
        let policy = serde_json::json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "BoatrampBlobIngress",
                "Effect": "Allow",
                "Action": actions,
                "Resource": resource,
            }],
        });
        serde_json::to_string(&policy).expect("session policy JSON is always serializable")
    }

    /// Broker the temp credential via STS under the configured [`StsMode`], scoped by the inline session
    /// policy. Returns `(access_key_id, secret, session_token, expires_at_unix)`.
    async fn broker_temp_credentials(
        &self,
        scope: &MintScope,
    ) -> Result<(String, String, String, u64), String> {
        let policy = Self::session_policy_json(&self.config.bucket, scope);
        // STS duration is in whole seconds; clamp into STS's own valid range (min 900s, max 43_200s
        // for AssumeRole). The binding already clamped the TTL to the operator ceiling; STS floors it.
        let duration = i32::try_from(scope.ttl_secs.clamp(900, 43_200)).unwrap_or(3_600);
        let creds = match &self.config.sts_mode {
            StsMode::AssumeRole { role_arn } => {
                let out = self
                    .sts
                    .assume_role()
                    .role_arn(role_arn)
                    .role_session_name("boatramp-blob-ingress")
                    .policy(policy)
                    .duration_seconds(duration)
                    .send()
                    .await
                    .map_err(|e| format!("sts:AssumeRole failed: {e}"))?;
                out.credentials
                    .ok_or_else(|| "sts:AssumeRole returned no credentials".to_string())?
            }
            StsMode::GetFederationToken => {
                let out = self
                    .sts
                    .get_federation_token()
                    .name("boatramp-blob-ingress")
                    .policy(policy)
                    // GetFederationToken min is also 900s; max is 129_600s but we cap at the operator TTL.
                    .duration_seconds(duration)
                    .send()
                    .await
                    .map_err(|e| format!("sts:GetFederationToken failed: {e}"))?;
                out.credentials
                    .ok_or_else(|| "sts:GetFederationToken returned no credentials".to_string())?
            }
        };
        let expires_at = u64::try_from(creds.expiration().as_secs_f64() as i64)
            .unwrap_or_else(|_| boatramp_core::time::now_unix().saturating_add(scope.ttl_secs));
        Ok((
            creds.access_key_id().to_string(),
            creds.secret_access_key().to_string(),
            creds.session_token().to_string(),
            expires_at,
        ))
    }

    /// Whether this credential returns a presigned PUT (single key + PUT-only) — the SAME rule as the
    /// local face, so the client's variant handling is backend-independent.
    fn wants_presigned_put(scope: &MintScope) -> bool {
        matches!(scope.target, UploadTarget::Key(_)) && scope.perms == [UploadPerm::Put]
    }
}

#[async_trait]
impl BlobUploadMinter for AwsBlobUploadMinter {
    async fn mint(&self, scope: &MintScope) -> Result<MintedCredentials, String> {
        let now = boatramp_core::time::now_unix();
        let expires_at = now.saturating_add(scope.ttl_secs);

        if Self::wants_presigned_put(scope) {
            let key = match &scope.target {
                UploadTarget::Key(k) => k.clone(),
                UploadTarget::Prefix(_) => unreachable!("wants_presigned_put implies a Key target"),
            };
            let object_key = format!("{}{key}", cloud::scoped_container_root(scope));
            let presign = aws_sdk_s3::presigning::PresigningConfig::expires_in(
                Duration::from_secs(scope.ttl_secs),
            )
            .map_err(|e| format!("presigning config: {e}"))?;
            // Sign a PutObject to the exact hblob key. A constrained content-type is signed INTO the
            // request, so S3 itself rejects a mismatched Content-Type ⇒ it is enforced on this shape.
            let mut put = self
                .s3
                .put_object()
                .bucket(&self.config.bucket)
                .key(&object_key);
            if let Some(ct) = &scope.constraints.content_type {
                put = put.content_type(ct.clone());
            }
            let presigned = put
                .presigned(presign)
                .await
                .map_err(|e| format!("presign put_object: {e}"))?;
            let mut required_headers = Vec::new();
            if let Some(ct) = &scope.constraints.content_type {
                required_headers.push(("content-type".to_string(), ct.clone()));
            }
            Ok(MintedCredentials::PresignedPut(PresignedPut {
                url: presigned.uri().to_string(),
                method: "PUT".to_string(),
                required_headers,
                expires_at,
                expires_in_secs: scope.ttl_secs,
            }))
        } else {
            let (access_key_id, secret, session_token, sts_expires_at) =
                self.broker_temp_credentials(scope).await?;
            // A session policy caps neither object size nor content-type; content-addressing is the
            // strong cross-cloud enforcement. Nothing else is claimed enforced on the temp-cred shape.
            let (enforced, advisory) =
                cloud::constraint_contract(&scope.constraints, CloudEnforcement::NONE);
            Ok(MintedCredentials::TempCredentials(TempCredentials {
                access_key_id,
                secret,
                session_token,
                endpoint: self.config.endpoint.clone().unwrap_or_default(),
                region: self.config.region.clone(),
                bucket: self.config.bucket.clone(),
                // Real AWS is virtual-host style; an S3-compatible endpoint is path-style.
                force_path_style: self.config.force_path_style,
                // STS may return a slightly-shorter expiry than the requested TTL (its own flooring);
                // surface the authoritative STS value, not our optimistic `expires_at`.
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
    fn session_policy_is_prefix_resource_scoped_and_action_scoped() {
        let s = scope(
            UploadTarget::Prefix("ingest/".into()),
            vec![UploadPerm::Put, UploadPerm::Multipart],
            Default::default(),
        );
        let policy = AwsBlobUploadMinter::session_policy_json("my-bucket", &s);
        // Resource is scoped to the EXACT hblob prefix under the real bucket, with a subtree wildcard —
        // NOT bucket-wide, NOT `*`. This is invariant 9 (the M5 gate neuters this to `*` ⇒ FAIL).
        assert!(
            policy.contains(
                "\"Resource\":\"arn:aws:s3:::my-bucket/hblob/acme/blog/photos/ingest/*\""
            ),
            "resource must be the exact hblob prefix subtree: {policy}"
        );
        assert!(
            !policy.contains("arn:aws:s3:::my-bucket/*")
                && !policy.contains("arn:aws:s3:::my-bucket\""),
            "must never be bucket-wide: {policy}"
        );
        // Action-scoped to PutObject + the multipart quartet ONLY — no get/list/delete/bucket-level.
        for want in [
            "s3:PutObject",
            "s3:CreateMultipartUpload",
            "s3:UploadPart",
            "s3:CompleteMultipartUpload",
            "s3:AbortMultipartUpload",
        ] {
            assert!(policy.contains(want), "missing action {want}: {policy}");
        }
        for forbidden in [
            "s3:GetObject",
            "s3:ListBucket",
            "s3:DeleteObject",
            "s3:ListMultipartUploads",
        ] {
            assert!(
                !policy.contains(forbidden),
                "must not grant {forbidden}: {policy}"
            );
        }
    }

    #[test]
    fn a_put_only_credential_omits_the_multipart_quartet() {
        let s = scope(
            UploadTarget::Prefix("ingest/".into()),
            vec![UploadPerm::Put],
            Default::default(),
        );
        let policy = AwsBlobUploadMinter::session_policy_json("b", &s);
        assert!(policy.contains("s3:PutObject"));
        assert!(
            !policy.contains("s3:UploadPart"),
            "no multipart perm ⇒ no multipart actions: {policy}"
        );
    }

    #[test]
    fn a_single_key_target_scopes_to_the_exact_object_not_a_wildcard() {
        let s = scope(
            UploadTarget::Key("avatars/u.jpg".into()),
            vec![UploadPerm::Put, UploadPerm::Multipart],
            Default::default(),
        );
        let policy = AwsBlobUploadMinter::session_policy_json("b", &s);
        assert!(
            policy.contains("\"Resource\":\"arn:aws:s3:::b/hblob/acme/blog/photos/avatars/u.jpg\""),
            "a key target is the exact object, no trailing wildcard: {policy}"
        );
    }

    #[test]
    fn size_and_content_type_are_advisory_on_aws_temp_credentials() {
        // The security crux: a session policy can't cap size or content-type, so they are advisory —
        // never overclaimed as enforced (the M5 honesty assertion).
        let c = UploadConstraints {
            max_bytes: Some(5_000_000),
            content_type: Some("image/png".into()),
            require_sha256: false,
            create_only: false,
        };
        let (enforced, advisory) = cloud::constraint_contract(&c, CloudEnforcement::NONE);
        assert!(
            enforced.is_empty(),
            "AWS session policy caps neither: {enforced:?}"
        );
        assert!(advisory.contains(&"max_bytes=5000000".to_string()));
        assert!(advisory.contains(&"content_type=image/png".to_string()));
    }

    #[test]
    fn unpinned_sha256_is_advisory_on_aws_temp_credentials() {
        // Security HIGH-2: the AWS temp-credential (session-policy) shape emits NO checksum condition,
        // so require_sha256 is ADVISORY — boatramp never sees the bytes the client PUTs to real S3, so
        // it cannot verify `key == sha256`. It must NOT promote max_bytes.
        let c = UploadConstraints {
            require_sha256: true,
            max_bytes: Some(1024),
            ..Default::default()
        };
        let (enforced, advisory) = cloud::constraint_contract(&c, CloudEnforcement::NONE);
        assert!(
            enforced.is_empty(),
            "AWS session policy pins no hash ⇒ nothing enforced: {enforced:?}"
        );
        assert!(advisory.contains(&"require_sha256".to_string()));
        assert!(advisory.contains(&"max_bytes=1024".to_string()));
    }

    #[test]
    fn a_metacharacter_in_the_scoped_path_cannot_restructure_the_policy() {
        // Security HIGH-1 belt-and-suspenders: even if a `"` reached the (serde_json-built) policy — it
        // cannot, because the mint choke point screens it out first — the document must remain a single
        // Allow statement with the metacharacter confined to the (escaped) Resource string, never a
        // second injected statement. We drive a hostile container directly past the screen (the pure
        // builder is standalone) to prove the construction is injection-proof.
        let s = MintScope {
            project: "acme".into(),
            site: "blog".into(),
            container: "photos".into(),
            // A key carrying a `"` that in a naive format! would close the Resource string and let the
            // rest inject `,"Resource":"arn:aws:s3:::*"` — a bucket-wide Allow.
            target: UploadTarget::Key("x\",\"Resource\":\"arn:aws:s3:::*".into()),
            perms: vec![UploadPerm::Put],
            constraints: Default::default(),
            ttl_secs: 900,
        };
        let policy = AwsBlobUploadMinter::session_policy_json("my-bucket", &s);
        // Parse it back: it MUST be one statement, one resource, and the resource must be the SINGLE
        // scoped object ARN with the metacharacter escaped INSIDE it — not a bucket-wide `*`.
        let v: serde_json::Value = serde_json::from_str(&policy).expect("valid JSON");
        let stmts = v["Statement"].as_array().expect("Statement array");
        assert_eq!(stmts.len(), 1, "exactly one Allow statement: {policy}");
        assert_eq!(stmts[0]["Effect"], "Allow");
        let resource = stmts[0]["Resource"].as_str().expect("Resource string");
        assert!(
            resource.starts_with("arn:aws:s3:::my-bucket/hblob/acme/blog/photos/"),
            "the metacharacter stayed inside the scoped object resource: {resource}"
        );
        assert_ne!(resource, "arn:aws:s3:::*", "no bucket-wide injection");
        // The Resource is a single scalar string, not an array of two resources.
        assert!(stmts[0]["Resource"].is_string(), "Resource is one string");
    }
}
