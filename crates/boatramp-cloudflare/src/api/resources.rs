//! Cloudflare resource provisioning for the deploy — the R2 bucket (blobs), D1
//! database (the `sql` binding), and KV namespace. All documented public REST
//! (each is its own Terraform resource). `ensure_*` are **idempotent**: reuse an
//! existing resource by name, else create it — so a redeploy is safe.

use serde::Deserialize;

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
    fn parses_a_kv_namespace_list() {
        let body = br#"{"success":true,"errors":[],
            "result":[{"id":"kv-1","title":"boatramp-cache","supports_url_encoding":true}]}"#;
        let nss: Vec<KvNamespace> = parse_envelope(body).unwrap();
        assert_eq!(nss.len(), 1);
        assert_eq!(nss[0].id, "kv-1");
        assert_eq!(nss[0].title, "boatramp-cache");
    }
}
