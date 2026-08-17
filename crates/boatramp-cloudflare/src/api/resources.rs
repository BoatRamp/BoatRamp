//! Cloudflare resource provisioning for the deploy — the R2 bucket (blobs), D1
//! database (the `sql` binding), and KV namespace. All documented public REST
//! (each is its own Terraform resource). `ensure_*` are **idempotent**: reuse an
//! existing resource by name, else create it — so a redeploy is safe.

use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{ApiError, CfApi};

/// A D1 database (the fields boatramp needs to bind it).
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct D1Database {
    /// The database id (the value the Worker `d1` binding references).
    pub uuid: String,
    /// The database name.
    pub name: String,
}

/// A Workers KV namespace.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct KvNamespace {
    /// The namespace id (the Worker `kv_namespace` binding references it).
    pub id: String,
    /// The namespace title (its human name).
    pub title: String,
}

/// R2 S3-compatible credentials for this account, derived from the configured
/// API token via Cloudflare's documented scheme: the S3 **access key id** is the
/// token's id, and the **secret** is the hex SHA-256 of the token value. Reusing
/// the deploy token means no separate R2 token to provision (it must carry R2
/// read/write). The secret is one-way, so a container holding only these S3
/// credentials can reach R2 but cannot act as the raw Cloudflare token.
#[derive(Debug, Clone, PartialEq)]
pub struct R2S3Credentials {
    /// The S3 access key id (the API token's id).
    pub access_key_id: String,
    /// The S3 secret access key (hex SHA-256 of the token value).
    pub secret_access_key: String,
    /// The R2 S3 endpoint (`https://<account>.r2.cloudflarestorage.com`).
    pub endpoint: String,
}

/// The `GET /user/tokens/verify` result — used only for the token's id.
#[derive(Debug, Clone, Deserialize)]
struct TokenVerify {
    id: String,
}

/// A Durable Object namespace (created by a Worker's DO migration). The
/// container application binds to the node DO namespace by **id**, resolved from
/// this list after the Worker upload.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct DoNamespace {
    /// The namespace id (what the container app's `durable_objects` references).
    pub id: String,
    /// The Worker script that owns it.
    #[serde(default)]
    pub script: String,
    /// The exported DO class name.
    #[serde(default)]
    pub class: String,
}

#[derive(serde::Serialize)]
struct NameBody<'a> {
    name: &'a str,
}

#[derive(serde::Serialize)]
struct TitleBody<'a> {
    title: &'a str,
}

impl CfApi {
    /// Ensure an R2 bucket named `name` exists (idempotent — a
    /// bucket-already-exists error counts as success).
    pub async fn ensure_r2_bucket(&self, name: &str) -> Result<(), ApiError> {
        let url = format!("{}/r2/buckets", self.account_base());
        match self
            .send::<_, serde_json::Value>(reqwest::Method::POST, url, &NameBody { name })
            .await
        {
            Ok(_) => Ok(()),
            // 10004 = bucket already exists — idempotent success.
            Err(ApiError::Api(m)) if m.contains("already") || m.contains("10004") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Derive R2 S3-compatible credentials for this account from the configured
    /// API token (Cloudflare's scheme: access key id = token id, secret = hex
    /// SHA-256 of the token value). One `GET /user/tokens/verify` for the id; the
    /// secret is computed locally. Lets the container reach R2 (blobs + SlateDB)
    /// without carrying the raw Cloudflare token.
    pub async fn r2_s3_credentials(&self) -> Result<R2S3Credentials, ApiError> {
        let verify: TokenVerify = self
            .get(format!("{}/user/tokens/verify", super::API_BASE))
            .await?;
        Ok(R2S3Credentials {
            access_key_id: verify.id,
            secret_access_key: hex::encode(Sha256::digest(self.token().as_bytes())),
            endpoint: format!("https://{}.r2.cloudflarestorage.com", self.account_id()),
        })
    }

    /// Ensure a D1 database named `name` exists; return it (reuse-or-create).
    pub async fn ensure_d1_database(&self, name: &str) -> Result<D1Database, ApiError> {
        if let Some(db) = self.find_d1(name).await? {
            return Ok(db);
        }
        let url = format!("{}/d1/database", self.account_base());
        self.send(reqwest::Method::POST, url, &NameBody { name })
            .await
    }

    async fn find_d1(&self, name: &str) -> Result<Option<D1Database>, ApiError> {
        let dbs: Vec<D1Database> = self
            .get(format!("{}/d1/database", self.account_base()))
            .await?;
        Ok(dbs.into_iter().find(|d| d.name == name))
    }

    /// Ensure a KV namespace titled `title` exists; return it (reuse-or-create).
    pub async fn ensure_kv_namespace(&self, title: &str) -> Result<KvNamespace, ApiError> {
        if let Some(ns) = self.find_kv(title).await? {
            return Ok(ns);
        }
        let url = format!("{}/storage/kv/namespaces", self.account_base());
        self.send(reqwest::Method::POST, url, &TitleBody { title })
            .await
    }

    async fn find_kv(&self, title: &str) -> Result<Option<KvNamespace>, ApiError> {
        let nss: Vec<KvNamespace> = self
            .get(format!("{}/storage/kv/namespaces", self.account_base()))
            .await?;
        Ok(nss.into_iter().find(|n| n.title == title))
    }

    /// Resolve the id of the Durable Object namespace owned by `script` for DO
    /// `class` (created by the Worker upload's migration) — the container
    /// application binds to it by id.
    pub async fn find_do_namespace(
        &self,
        script: &str,
        class: &str,
    ) -> Result<Option<String>, ApiError> {
        let nss: Vec<DoNamespace> = self
            .get(format!(
                "{}/workers/durable_objects/namespaces",
                self.account_base()
            ))
            .await?;
        Ok(nss
            .into_iter()
            .find(|n| n.script == script && n.class == class)
            .map(|n| n.id))
    }
}

#[cfg(test)]
mod tests {
    use super::super::parse_envelope;
    use super::*;

    #[test]
    fn parses_a_d1_create_response() {
        let body = br#"{"success":true,"errors":[],
            "result":{"uuid":"d1-abc","name":"boatramp-sql","version":"production"}}"#;
        let db: D1Database = parse_envelope(body).unwrap();
        assert_eq!(db.uuid, "d1-abc");
        assert_eq!(db.name, "boatramp-sql");
    }

    #[test]
    fn parses_token_verify_for_the_id() {
        // Only the token id is read (the R2 S3 access key id); other fields ignored.
        let body = br#"{"success":true,"errors":[],
            "result":{"id":"tok-abc","status":"active","not_before":"2026-01-01"}}"#;
        let v: TokenVerify = parse_envelope(body).unwrap();
        assert_eq!(v.id, "tok-abc");
    }

    #[test]
    fn r2_secret_is_a_64_hex_sha256_of_the_token() {
        // CF's R2 scheme: secret = hex(SHA-256(token value)); deterministic, one-way.
        let s = hex::encode(Sha256::digest(b"my-cf-token"));
        assert_eq!(s.len(), 64);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(s, hex::encode(Sha256::digest(b"my-cf-token")));
    }

    #[test]
    fn parses_a_kv_namespace_list() {
        let body = br#"{"success":true,"errors":[],
            "result":[{"id":"kv-1","title":"boatramp-cache","supports_url_encoding":true}]}"#;
        let nss: Vec<KvNamespace> = parse_envelope(body).unwrap();
        assert_eq!(nss.len(), 1);
        assert_eq!(nss[0].id, "kv-1");
        assert_eq!(nss[0].title, "boatramp-cache");
    }
}
