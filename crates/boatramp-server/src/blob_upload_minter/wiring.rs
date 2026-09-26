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
        } => {
            use super::aws::{AwsBlobUploadMinter, AwsMinterConfig, StsMode};
            let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
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
                },
            );
            Ok(Some(Arc::new(minter)))
        }
        #[cfg(not(feature = "blob-upload-azure"))]
        CloudMinterSpec::Azure { .. } => Ok(None),
    }
}
