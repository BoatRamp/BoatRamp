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
    /// Proxy address/CNAME records through Cloudflare (orange-cloud). Per
    /// provider instance, so it is set per-invocation (e.g. `dns
    /// configure-domain --proxied`) — never globally; TXT is never proxied.
    proxied: bool,
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
            proxied: false,
        }
    }

    /// Override the API base URL (for pointing tests/proxies at a stub).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// Proxy this instance's address/CNAME upserts through Cloudflare
    /// (orange-cloud: cache/WAF/edge TLS). TXT records are never proxied.
    pub fn with_proxied(mut self, proxied: bool) -> Self {
        self.proxied = proxied;
        self
    }

    /// `…/zones/{zone}/dns_records` (the collection endpoint).
    fn records_url(&self) -> String {
        format!("{}/zones/{}/dns_records", self.api_base, self.zone_id)
    }

    /// The JSON body for a create/replace of `record`. When this instance is
    /// `proxied`, address/CNAME records get `proxied: true` (and the automatic
    /// TTL Cloudflare requires for proxied records); TXT is never proxied.
    fn record_body(&self, record: &DnsRecord) -> serde_json::Value {
        let mut body = serde_json::json!({
            "type": record.kind.as_str(),
            "name": record.name,
            "content": record.value,
            "ttl": record.ttl,
        });
        if self.proxied
            && matches!(
                record.kind,
                RecordKind::A | RecordKind::Aaaa | RecordKind::Cname
            )
        {
            body["proxied"] = serde_json::json!(true);
            body["ttl"] = serde_json::json!(1); // proxied records must use automatic TTL
        }
        body
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
        let body = self.record_body(record);
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
        let body = CloudflareDns::new("z", "t").record_body(&DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        });
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["name"], "_acme-challenge.example.com");
        assert_eq!(body["content"], "abc");
        assert_eq!(body["ttl"], 60);
        // Not proxied by default, and never a `proxied` key when off.
        assert!(body.get("proxied").is_none());
    }

    #[test]
    fn proxied_applies_to_address_and_cname_only() {
        let cf = CloudflareDns::new("z", "t").with_proxied(true);

        // A CNAME gets proxied + automatic TTL.
        let cname = cf.record_body(&DnsRecord {
            kind: RecordKind::Cname,
            name: "docs.example.com".into(),
            value: "app.fly.dev".into(),
            ttl: 300,
        });
        assert_eq!(cname["proxied"], true);
        assert_eq!(cname["ttl"], 1);

        // A TXT is never proxied, even on a proxied instance.
        let txt = cf.record_body(&DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        });
        assert!(txt.get("proxied").is_none());
        assert_eq!(txt["ttl"], 60);
    }
}
