//! Cloudflare DNS provider (API v4, token auth).
//!
//! Upsert is create-or-replace: list the records of that `(type, name)`, then
//! `PUT` the first match or `POST` a new one. The request **construction**
//! (URLs, JSON bodies) is factored into pure helpers and unit-tested; the
//! send/parse round-trip is exercised against a live zone (the documented
//! integration seam — no Cloudflare account in CI).

use async_trait::async_trait;
use serde::Deserialize;

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind};

const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// A Cloudflare zone editor scoped to one zone.
pub struct CloudflareDns {
    client: reqwest::Client,
    api_base: String,
    token: String,
    zone_id: String,
}

impl CloudflareDns {
    /// Build a provider for `zone_id`, authenticating with an API token that has
    /// `Zone.DNS:Edit` on that zone.
    pub fn new(zone_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            token: token.into(),
            zone_id: zone_id.into(),
        }
    }

    /// Override the API base URL (for pointing tests/proxies at a stub).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// `…/zones/{zone}/dns_records` (the collection endpoint).
    fn records_url(&self) -> String {
        format!("{}/zones/{}/dns_records", self.api_base, self.zone_id)
    }

    /// The JSON body for a create/replace of `record`.
    fn record_body(record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({
            "type": record.kind.as_str(),
            "name": record.name,
            "content": record.value,
            "ttl": record.ttl,
        })
    }

    /// Find the id of an existing `(type, name)` record (the first match), or
    /// `None`. `content` narrows the match for `delete` (TXT/A can repeat).
    async fn find_record_id(
        &self,
        record: &DnsRecord,
        match_content: bool,
    ) -> Result<Option<String>, DnsError> {
        let mut request = self
            .client
            .get(self.records_url())
            .bearer_auth(&self.token)
            .query(&[
                ("type", record.kind.as_str()),
                ("name", record.name.as_str()),
            ]);
        if match_content {
            request = request.query(&[("content", record.value.as_str())]);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let body: ListResponse = resp
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .json()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(body.result.into_iter().next().map(|r| r.id))
    }
}

#[derive(Deserialize)]
struct ListResponse {
    result: Vec<ListRecord>,
}

#[derive(Deserialize)]
struct ListRecord {
    id: String,
}

#[async_trait]
impl DnsProvider for CloudflareDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let body = Self::record_body(record);
        let existing = self.find_record_id(record, false).await?;
        let request = match &existing {
            Some(id) => self
                .client
                .put(format!("{}/{}", self.records_url(), id))
                .bearer_auth(&self.token)
                .json(&body),
            None => self
                .client
                .post(self.records_url())
                .bearer_auth(&self.token)
                .json(&body),
        };
        request
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        // For TXT/A several records can share a name, so match content too.
        let match_content = matches!(
            record.kind,
            RecordKind::Txt | RecordKind::A | RecordKind::Aaaa
        );
        let Some(id) = self.find_record_id(record, match_content).await? else {
            return Ok(()); // already gone
        };
        self.client
            .delete(format!("{}/{}", self.records_url(), id))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_url_targets_the_zone() {
        let cf = CloudflareDns::new("zone123", "tok").with_api_base("https://example.test/v4");
        assert_eq!(
            cf.records_url(),
            "https://example.test/v4/zones/zone123/dns_records"
        );
    }

    #[test]
    fn record_body_shape() {
        let body = CloudflareDns::record_body(&DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        });
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["name"], "_acme-challenge.example.com");
        assert_eq!(body["content"], "abc");
        assert_eq!(body["ttl"], 60);
    }
}
