//! The **Azure** cloud blob-upload minter (M4, folded "Cloud STS scoping" — Security HIGH-3 / §SDK).
//!
//! For an Azure-Blob-backed container, boatramp brokers a **user-delegation SAS** (AAD-signed, no
//! account key) so the client uploads DIRECTLY to Blob Storage; the guest reads the object back through
//! the unchanged `hblob/…` read-path. Built on the NEW GA Azure SDK 1.x generation (`azure_storage_blob`
//! / `azure_storage_sas` / `azure_identity`), DISTINCT from the `azure_storage_blobs` 0.21 the storage
//! backend uses (different crate names ⇒ they coexist; the storage read/write path is untouched).
//!
//! **The scope-shape asymmetry, reflected HONESTLY** (the security crux): an Azure user-delegation SAS
//! scopes to **a single blob**, **a whole container**, or **a directory prefix** (hierarchical-namespace
//! accounts) — it CANNOT bind an arbitrary sub-prefix on a flat account. So:
//!
//! - **single key** ⇒ a **blob-scoped** SAS (`.blob(container, blob)`), pinned to the exact `hblob/…`
//!   object. `write`+`create`; a content-type can be signed in ⇒ content-type is *enforced* here, and a
//!   single-blob scope makes create-only *enforceable*.
//! - **prefix** ⇒ a **directory-scoped** SAS (`.directory(container, dir)`) confined to the `hblob/…`
//!   prefix path. This is honest only when the target maps to a directory path; the broker labels size
//!   and content-type `advisory` (a SAS caps neither), and `require_sha256` is the strong fallback.
//!
//! **The scope is derived from the host-stamped `MintScope`, never widened** (Security invariant): the
//! blob / directory path is [`cloud::scoped_object_path`], anchored under `hblob/{qualified-site}/{ctr}/`.

use std::sync::Arc;

use async_trait::async_trait;
use azure_core_v1::credentials::TokenCredential;
use azure_core_v1::http::{RequestContent, Url};
use azure_core_v1::time::OffsetDateTime;
use azure_storage_blob::BlobServiceClient;
use azure_storage_common::models::UserDelegationKey;
use azure_storage_sas::SasBuilder;
use boatramp_handlers::{
    BlobUploadMinter, MintScope, MintedCredentials, PresignedPut, TempCredentials, UploadPerm,
    UploadTarget,
};

use super::cloud::{self, CloudEnforcement};

/// The static config an Azure cloud minter needs: the storage account name + its blob service URL + the
/// real container the node's blob backend writes to. The `hblob/…` object keys live under it.
#[derive(Debug, Clone)]
pub struct AzureMinterConfig {
    /// The storage account name (used to sign the SAS + build the blob URL).
    pub account: String,
    /// The blob service URL, e.g. `https://{account}.blob.core.windows.net/`.
    pub service_url: String,
    /// The real container the node's blob backend writes to.
    pub container: String,
}

/// The Azure cloud minter: holds the AAD [`TokenCredential`] (to fetch the user-delegation key) + the
/// static config. The SAS is signed offline from the fetched delegation key.
pub struct AzureBlobUploadMinter {
    credential: Arc<dyn TokenCredential>,
    config: AzureMinterConfig,
}

impl AzureBlobUploadMinter {
    /// Build a minter from an AAD credential (e.g. `azure_identity::DeveloperToolsCredential` /
    /// `ManagedIdentityCredential`) + the static config.
    pub fn new(credential: Arc<dyn TokenCredential>, config: AzureMinterConfig) -> Self {
        Self { credential, config }
    }

    /// Whether this credential returns a single-blob SAS (single key) — a blob-scoped SAS pins the exact
    /// object, so it is the strongest Azure shape (overwrite + content-type enforceable).
    fn is_single_key(scope: &MintScope) -> bool {
        matches!(scope.target, UploadTarget::Key(_))
    }

    /// Fetch a short-lived user-delegation key from the blob service (AAD-signed; no account key), valid
    /// from now until `expiry`. This is the key the SAS is signed with. The request body is the
    /// spec-defined `<KeyInfo>` XML (start/expiry in RFC3339, seconds precision) — hand-serialized so we
    /// do not depend on an unstable model-serialization helper.
    async fn user_delegation_key(
        &self,
        start: OffsetDateTime,
        expiry: OffsetDateTime,
    ) -> Result<UserDelegationKey, String> {
        let service_url = Url::parse(&self.config.service_url)
            .map_err(|e| format!("invalid Azure service URL: {e}"))?;
        let client = BlobServiceClient::new(service_url, Some(self.credential.clone()), None)
            .map_err(|e| format!("Azure BlobServiceClient: {e}"))?;
        let body = Self::key_info_xml(start, expiry)?;
        let content: RequestContent<_, _> = RequestContent::from(body.into_bytes());
        let resp = client
            .get_user_delegation_key(content, None)
            .await
            .map_err(|e| format!("Azure get_user_delegation_key: {e}"))?;
        resp.into_model()
            .map_err(|e| format!("Azure user-delegation-key decode: {e}"))
    }

    /// The `<KeyInfo>` request body for Get User Delegation Key (start/expiry as RFC3339, seconds
    /// precision — the exact shape the Azure Blob REST API requires). Pure ⇒ unit-testable.
    fn key_info_xml(start: OffsetDateTime, expiry: OffsetDateTime) -> Result<String, String> {
        let fmt = &time::format_description::well_known::Rfc3339;
        let start_s = start
            .replace_millisecond(0)
            .map_err(|e| format!("Azure start time: {e}"))?
            .format(fmt)
            .map_err(|e| format!("Azure start format: {e}"))?;
        let expiry_s = expiry
            .replace_millisecond(0)
            .map_err(|e| format!("Azure expiry time: {e}"))?
            .format(fmt)
            .map_err(|e| format!("Azure expiry format: {e}"))?;
        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\
             <KeyInfo><Start>{start_s}</Start><Expiry>{expiry_s}</Expiry></KeyInfo>"
        ))
    }
}

#[async_trait]
impl BlobUploadMinter for AzureBlobUploadMinter {
    async fn mint(&self, scope: &MintScope) -> Result<MintedCredentials, String> {
        let now = boatramp_core::time::now_unix();
        let expires_at = now.saturating_add(scope.ttl_secs);
        let start = OffsetDateTime::from_unix_timestamp(now as i64)
            .map_err(|e| format!("Azure SAS start: {e}"))?;
        let expiry = OffsetDateTime::from_unix_timestamp(expires_at as i64)
            .map_err(|e| format!("Azure SAS expiry: {e}"))?;
        let key = self.user_delegation_key(start, expiry).await?;

        // The object/prefix path within the container, anchored at `hblob/{qualified-site}/{ctr}/…`.
        // For a KEY target this is the exact blob; for a PREFIX target it is the directory path.
        let can_multipart = scope.perms.contains(&UploadPerm::Multipart);

        let (sas_query, blob_path, single_object) = match &scope.target {
            UploadTarget::Key(_) => {
                let object = cloud::scoped_object_path(scope);
                let mut builder = SasBuilder::new(&self.config.account, &key, expiry)
                    .map_err(|e| format!("Azure SAS builder: {e}"))?
                    .blob(self.config.container.clone(), object.clone())
                    .write()
                    .create();
                if let Some(ct) = &scope.constraints.content_type {
                    builder = builder.content_type(ct.clone());
                }
                (builder.build(), object, true)
            }
            UploadTarget::Prefix(_) => {
                // A prefix ⇒ a directory-scoped SAS confined to the hblob prefix path. `create`+`write`
                // for the objects landing under it.
                let dir = cloud::scoped_object_path(scope);
                let mut builder = SasBuilder::new(&self.config.account, &key, expiry)
                    .map_err(|e| format!("Azure SAS builder: {e}"))?
                    .directory(self.config.container.clone(), dir.clone())
                    .write()
                    .create();
                if can_multipart {
                    builder = builder.add();
                }
                (builder.build(), dir, false)
            }
        };

        if Self::is_single_key(scope) && scope.perms == [UploadPerm::Put] {
            // A single blob + PUT-only ⇒ a ready presigned-style URL (blob URL + SAS query) the browser
            // PUTs directly. A blob-scoped SAS binds the exact object, and content-type is signed in ⇒
            // both are enforced on this shape.
            let url = format!(
                "{}/{}/{}?{}",
                self.config.service_url.trim_end_matches('/'),
                self.config.container,
                blob_path,
                sas_query
            );
            let mut required_headers = Vec::new();
            // Azure block-blob PUT needs the blob type header; a browser fetch must send it.
            required_headers.push(("x-ms-blob-type".to_string(), "BlockBlob".to_string()));
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
            // A directory/prefix or multipart credential ⇒ the SAS query as the "session token" the
            // client appends to its blob URLs (the self-describing shape for the Azure SDK / a raw PUT).
            // A blob-scoped SAS (single object) can enforce content-type + create-only; a directory SAS
            // cannot cap size/content-type ⇒ those are advisory (content-addressing is the strong
            // fallback). This is the honest reflection of the Azure scope-shape asymmetry.
            let caps = if single_object {
                CloudEnforcement {
                    can_cap_content_type: scope.constraints.content_type.is_some(),
                    can_enforce_create_only: true,
                    ..CloudEnforcement::NONE
                }
            } else {
                CloudEnforcement::NONE
            };
            let (enforced, advisory) = cloud::constraint_contract(&scope.constraints, caps);
            Ok(MintedCredentials::TempCredentials(TempCredentials {
                access_key_id: String::new(),
                secret: String::new(),
                session_token: sas_query,
                endpoint: self.config.service_url.clone(),
                region: String::new(),
                bucket: self.config.container.clone(),
                force_path_style: false,
                expires_at,
                expires_in_secs: scope.ttl_secs,
                enforced,
                advisory,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    // NOTE: the SAS/URL construction is exercised against a live Azure emulator/account in the M5 live
    // gate (the delegation key is AAD-signed and cannot be minted offline without a credential). The
    // pure enforced/advisory labelling — the security crux — is unit-tested here without any Azure call.
    use super::*;
    use boatramp_handlers::UploadConstraints;

    fn constraints(
        size: Option<u64>,
        ct: Option<&str>,
        sha: bool,
        create: bool,
    ) -> UploadConstraints {
        UploadConstraints {
            max_bytes: size,
            content_type: ct.map(str::to_string),
            require_sha256: sha,
            create_only: create,
        }
    }

    #[test]
    fn a_directory_prefix_sas_labels_size_and_content_type_advisory() {
        // A directory (prefix) SAS caps neither size nor content-type ⇒ advisory, never overclaimed.
        let c = constraints(Some(1024), Some("image/png"), false, true);
        let (enforced, advisory) = cloud::constraint_contract(&c, CloudEnforcement::NONE);
        assert!(
            enforced.is_empty(),
            "a directory SAS enforces none: {enforced:?}"
        );
        assert!(advisory.contains(&"max_bytes=1024".to_string()));
        assert!(advisory.contains(&"content_type=image/png".to_string()));
        assert!(advisory.contains(&"create_only".to_string()));
    }

    #[test]
    fn a_single_blob_sas_enforces_content_type_and_create_only() {
        // A blob-scoped SAS pins the exact object: content-type is signed in, overwrite is preventable.
        let c = constraints(None, Some("image/jpeg"), false, true);
        let caps = CloudEnforcement {
            can_cap_content_type: true,
            can_enforce_create_only: true,
            ..CloudEnforcement::NONE
        };
        let (enforced, advisory) = cloud::constraint_contract(&c, caps);
        assert!(enforced.contains(&"content_type=image/jpeg".to_string()));
        assert!(enforced.contains(&"create_only".to_string()));
        assert!(advisory.is_empty());
    }

    #[test]
    fn content_addressing_is_the_strong_fallback_on_azure() {
        let c = constraints(Some(2048), None, true, false);
        let (enforced, advisory) = cloud::constraint_contract(&c, CloudEnforcement::NONE);
        assert!(enforced.contains(&"require_sha256".to_string()));
        assert!(
            enforced.contains(&"max_bytes=2048".to_string()),
            "content-addressed ⇒ size moot"
        );
        assert!(advisory.is_empty());
    }
}
