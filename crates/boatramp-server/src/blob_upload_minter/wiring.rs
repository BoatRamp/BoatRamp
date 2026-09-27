//! Startup wiring for the M4 **cloud** blob-upload minters: build the right
//! [`BlobUploadMinter`](boatramp_handlers::BlobUploadMinter) for the node's cloud blob backend, from
//! plain operator config. The binary calls [`build_cloud_minter`] after resolving its blob backend and
//! (when it returns `Some`) hands the minter to
//! [`set_blob_upload_cloud_minter`](crate::HandlerRuntime::set_blob_upload_cloud_minter), so a cloud
//! backend brokers native scoped credentials instead of re-transiting through the local S3 face.
//!
//! Kept out of the CLI crate so the (feature-gated) cloud SDK deps live entirely in `boatramp-server`.
//! Each cloud arm is compiled only with its `blob-upload-{aws,gcs,azure}` feature; a spec for a cloud
//! whose feature is off returns `None` (the local face mints, or minting is simply not offered).

use std::sync::Arc;

use boatramp_handlers::BlobUploadMinter;

/// A node-level **sealed base S3 credential** `(access_key_id, secret_access_key)` for the AWS cloud
/// minter's STS/presign SDK config (#505). The secret half is confidential, so `Debug` is manual and
/// **redacts** it — `CloudMinterSpec` derives `Debug`, so a struct-`Debug` in a log/panic must not leak
/// the sealed key (mirrors `S3IngressSecret` / `azure_core::Secret`).
#[derive(Clone)]
pub struct BaseCredential {
    access_key_id: String,
    secret_access_key: String,
}

impl BaseCredential {
    /// Build from a resolved `(access_key_id, secret_access_key)` pair.
    pub fn new(access_key_id: String, secret_access_key: String) -> Self {
        Self {
            access_key_id,
            secret_access_key,
        }
    }

    /// The public access-key id.
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// The confidential secret access key (behind a method so a caller asks explicitly).
    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }
}

impl std::fmt::Debug for BaseCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BaseCredential")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

/// Which cloud backend the node's blobs live on, plus the per-cloud brokering knobs. The binary
/// populates this from its resolved blob-backend args + `[serve.s3_ingress_cloud]`. Only the arm for
/// the active backend is consulted.
#[derive(Debug, Clone)]
pub enum CloudMinterSpec {
    /// An S3 (or S3-compatible) backend: broker an STS session-policy credential / presigned PUT.
    Aws {
        bucket: String,
        region: String,
        endpoint: Option<String>,
        force_path_style: bool,
        /// The role ARN to assume; `None` + `use_federation_token` ⇒ `GetFederationToken`.
        role_arn: Option<String>,
        use_federation_token: bool,
        /// The node-level **sealed base S3 credential** to sign the STS/presign SDK config with (#505),
        /// or `None` for the ambient AWS env chain (the historical default). The SAME source the S3 blob
        /// object backend uses — construens' one Tigris key. Redacted from `Debug` (see [`BaseCredential`]).
        base_credential: Option<BaseCredential>,
    },
    /// A GCS backend: broker a V4 signed PUT URL / a downscoped CAB token.
    Gcs {
        bucket: String,
        endpoint: Option<String>,
    },
    /// An Azure Blob backend: broker a user-delegation SAS.
    Azure {
        account: String,
        service_url: String,
        container: String,
        /// Whether the account has a hierarchical namespace (HNS/ADLS-Gen2). A prefix mint is refused
        /// unless this is `true` (a directory SAS only confines on HNS; Security LOW-1). Default false.
        hns: bool,
    },
}

/// Build the cloud minter for `spec`, or `None` when the matching cloud feature is not compiled in (so
/// the caller falls back to the local S3 face). Async because the AWS arm resolves the ambient AWS
/// config, and the GCS arm builds the signer + HTTP client.
pub async fn build_cloud_minter(
    spec: CloudMinterSpec,
) -> Result<Option<Arc<dyn BlobUploadMinter>>, String> {
    match spec {
        #[cfg(feature = "blob-upload-aws")]
        CloudMinterSpec::Aws {
            bucket,
            region,
            endpoint,
            force_path_style,
            role_arn,
            use_federation_token,
            base_credential,
        } => {
            use super::aws::{AwsBlobUploadMinter, AwsMinterConfig, StsMode};
            let mut sdk_config =
                aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
            // #505: when the operator configured a node-level sealed base credential, override the
            // resolved chain so the STS + S3 (presign) clients the minter builds from this `SdkConfig`
            // sign with the sealed key — never the ambient `AWS_ACCESS_KEY_ID`/`_SECRET`. `None` ⇒ the
            // ambient chain (unchanged).
            if let Some(cred) = &base_credential {
                let provider = aws_sdk_sts::config::SharedCredentialsProvider::new(
                    aws_sdk_sts::config::Credentials::new(
                        cred.access_key_id().to_string(),
                        cred.secret_access_key().to_string(),
                        None,
                        None,
                        "boatramp-sealed",
                    ),
                );
                sdk_config = sdk_config
                    .into_builder()
                    .credentials_provider(provider)
                    .build();
            }
            let sts_mode = match (role_arn, use_federation_token) {
                (Some(role_arn), _) => StsMode::AssumeRole { role_arn },
                (None, true) => StsMode::GetFederationToken,
                (None, false) => {
                    return Err(
                        "AWS blob-upload cloud brokering needs either `aws_role_arn` (AssumeRole) or \
                         `aws_use_federation_token = true` (GetFederationToken)"
                            .to_string(),
                    );
                }
            };
            let minter = AwsBlobUploadMinter::new(
                &sdk_config,
                AwsMinterConfig {
                    bucket,
                    region,
                    endpoint,
                    force_path_style,
                    sts_mode,
                },
            );
            Ok(Some(Arc::new(minter)))
        }
        #[cfg(not(feature = "blob-upload-aws"))]
        CloudMinterSpec::Aws { .. } => Ok(None),

        #[cfg(feature = "blob-upload-gcs")]
        CloudMinterSpec::Gcs { bucket, endpoint } => {
            use super::gcs::{AdcSubjectToken, GcsBlobUploadMinter, GcsMinterConfig};
            let signer = gcs_signer_auth::credentials::Builder::default()
                .build_signer()
                .map_err(|e| format!("GCS signer (ADC): {e}"))?;
            let minter = GcsBlobUploadMinter::new(
                signer,
                reqwest::Client::new(),
                GcsMinterConfig { bucket, endpoint },
                Arc::new(AdcSubjectToken::new()?),
            );
            Ok(Some(Arc::new(minter)))
        }
        #[cfg(not(feature = "blob-upload-gcs"))]
        CloudMinterSpec::Gcs { .. } => Ok(None),

        #[cfg(feature = "blob-upload-azure")]
        CloudMinterSpec::Azure {
            account,
            service_url,
            container,
            hns,
        } => {
            use super::azure::{AzureBlobUploadMinter, AzureMinterConfig};
            let credential = azure_identity::DeveloperToolsCredential::new(None)
                .map_err(|e| format!("Azure AAD credential: {e}"))?;
            let minter = AzureBlobUploadMinter::new(
                credential,
                AzureMinterConfig {
                    account,
                    service_url,
                    container,
                    hns,
                },
            );
            Ok(Some(Arc::new(minter)))
        }
        #[cfg(not(feature = "blob-upload-azure"))]
        CloudMinterSpec::Azure { .. } => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_credential_redacts_the_secret_in_debug() {
        // #505 minter-injection side: the sealed base credential the AWS minter's STS/presign SDK config
        // signs with must NEVER leak in a `CloudMinterSpec`/`BaseCredential` `Debug` (log/panic). The
        // public access-key id is fine; the secret is redacted (mirrors the backend's `S3Options`).
        let cred = BaseCredential::new(
            "AKID-PUBLIC".to_string(),
            "SUPER-SECRET-DO-NOT-LOG".to_string(),
        );
        assert_eq!(cred.access_key_id(), "AKID-PUBLIC");
        assert_eq!(cred.secret_access_key(), "SUPER-SECRET-DO-NOT-LOG");
        let dbg = format!("{cred:?}");
        assert!(
            !dbg.contains("SUPER-SECRET-DO-NOT-LOG"),
            "the sealed secret must be redacted from BaseCredential Debug: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "redaction marker present: {dbg}"
        );
        assert!(
            dbg.contains("AKID-PUBLIC"),
            "the access-key id is public: {dbg}"
        );
        // And the enclosing CloudMinterSpec::Aws Debug must not leak it either (it derives Debug, which
        // delegates to BaseCredential's manual redacting Debug).
        let spec = CloudMinterSpec::Aws {
            bucket: "b".to_string(),
            region: "auto".to_string(),
            endpoint: None,
            force_path_style: false,
            role_arn: None,
            use_federation_token: true,
            base_credential: Some(cred),
        };
        let spec_dbg = format!("{spec:?}");
        assert!(
            !spec_dbg.contains("SUPER-SECRET-DO-NOT-LOG"),
            "CloudMinterSpec::Aws Debug must not leak the sealed secret: {spec_dbg}"
        );
    }
}
