//! Cloudflare KV backed [`KvStore`] (compile with `--features cloudflare-kv`).
//!
//! Talks to the Cloudflare KV REST API, so a self-hosted boatramp server can
//! keep its (small) deploy manifests and per-site pointers in Cloudflare KV —
//! useful when blobs live in R2/S3 and you want the metadata layer to be a
//! managed, globally-replicated store. Wrap it in
//! [`boatramp_core::kv::CachedKv`] to avoid a network round-trip per request.

use async_trait::async_trait;
use boatramp_core::kv::{KvError, KvStore};
use serde::Deserialize;

const API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// A [`KvStore`] backed by a Cloudflare KV namespace via the REST API.
#[derive(Debug, Clone)]
pub struct CloudflareKv {
    client: reqwest::Client,
    account_id: String,
    namespace_id: String,
    token: String,
}

impl CloudflareKv {
    /// Build a client for the given account, namespace, and API token.
    pub fn new(
        account_id: impl Into<String>,
        namespace_id: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            account_id: account_id.into(),
            namespace_id: namespace_id.into(),
            token: token.into(),
        }
    }

    /// Build a client from the `CF_ACCOUNT_ID`, `CF_KV_NAMESPACE_ID`, and
    /// `CF_API_TOKEN` environment variables.
    pub fn from_env() -> Result<Self, KvError> {
        let var = |name: &str| {
            std::env::var(name).map_err(|_| KvError::backend(format!("{name} is not set")))
        };
        Ok(Self::new(
            var("CF_ACCOUNT_ID")?,
            var("CF_KV_NAMESPACE_ID")?,
            var("CF_API_TOKEN")?,
        ))
    }

    fn values_url(&self, key: &str) -> Result<reqwest::Url, KvError> {
        let base = format!(
            "{API_BASE}/accounts/{}/storage/kv/namespaces/{}/values",
            self.account_id, self.namespace_id
        );
        let mut url = reqwest::Url::parse(&base).map_err(|e| KvError::backend(e.to_string()))?;
        url.path_segments_mut()
            .map_err(|()| KvError::backend("invalid base url"))?
            .push(key);
        Ok(url)
    }

    fn keys_url(&self) -> Result<reqwest::Url, KvError> {
        let base = format!(
            "{API_BASE}/accounts/{}/storage/kv/namespaces/{}/keys",
            self.account_id, self.namespace_id
        );
        reqwest::Url::parse(&base).map_err(|e| KvError::backend(e.to_string()))
    }
}

fn net_err(err: reqwest::Error) -> KvError {
    KvError::backend(err.to_string())
}

#[derive(Deserialize)]
struct ListResponse {
    result: Vec<KeyName>,
    result_info: ResultInfo,
}

#[derive(Deserialize)]
struct KeyName {
    name: String,
}

#[derive(Deserialize)]
struct ResultInfo {
    cursor: Option<String>,
}

#[async_trait]
impl KvStore for CloudflareKv {
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KvError> {
        let resp = self
            .client
            .get(self.values_url(key)?)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(net_err)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = resp.error_for_status().map_err(net_err)?;
        Ok(Some(resp.bytes().await.map_err(net_err)?.to_vec()))
    }

    async fn put(&self, key: &str, value: Vec<u8>) -> Result<(), KvError> {
        self.client
            .put(self.values_url(key)?)
            .bearer_auth(&self.token)
            .body(value)
            .send()
            .await
            .map_err(net_err)?
            .error_for_status()
            .map_err(net_err)?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), KvError> {
        let resp = self
            .client
            .delete(self.values_url(key)?)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(net_err)?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        resp.error_for_status().map_err(net_err)?;
        Ok(())
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<String>, KvError> {
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut url = self.keys_url()?;
            {
                let mut query = url.query_pairs_mut();
                query.append_pair("prefix", prefix);
                if let Some(cursor) = &cursor {
                    query.append_pair("cursor", cursor);
                }
            }
            let body: ListResponse = self
                .client
                .get(url)
                .bearer_auth(&self.token)
                .send()
                .await
                .map_err(net_err)?
                .error_for_status()
                .map_err(net_err)?
                .json()
                .await
                .map_err(net_err)?;

            out.extend(body.result.into_iter().map(|key| key.name));

            match body.result_info.cursor {
                Some(next) if !next.is_empty() => cursor = Some(next),
                _ => break,
            }
        }
        Ok(out)
    }
}
