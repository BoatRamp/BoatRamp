//! DigitalOcean DNS provider (API v2, bearer-token auth).
//!
//! Like the Cloudflare provider, `upsert` is create-or-replace: list the
//! `(type, name)` records, then `PUT` the first match or `POST` a new one. Two
//! DigitalOcean-specific quirks the pure helpers encode:
//!   * the API is per-**domain** (the zone is the registered domain), and a
//!     record `name` in the body is **relative** to that domain (`@` = apex),
//!     while the list filter takes the full FQDN — `relative_name` bridges them;
//!   * `CNAME` data must be a FQDN with a trailing dot.
//!
//! Request construction is unit-tested; the send/parse round-trip is a live seam.

use async_trait::async_trait;
use serde::Deserialize;

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind};

const DEFAULT_API_BASE: &str = "https://api.digitalocean.com/v2";

/// A DigitalOcean DNS editor scoped to one domain (zone).
pub struct DigitalOceanDns {
    client: reqwest::Client,
    api_base: String,
    token: String,
    domain: String,
}

impl DigitalOceanDns {
    /// Build a provider for `domain` (the registered zone, e.g. `example.com`),
    /// authenticating with a personal access token that has write scope.
    pub fn new(domain: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            token: token.into(),
            domain: domain.into(),
        }
    }

    /// Override the API base URL (for pointing tests at a stub).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// `…/domains/{domain}/records` (the collection endpoint).
    fn records_url(&self) -> String {
        format!("{}/domains/{}/records", self.api_base, self.domain)
    }

    /// The record name **relative** to the domain, as DigitalOcean's body wants:
    /// `_acme-challenge.deploy.example.com` under `example.com` →
    /// `_acme-challenge.deploy`; the apex → `@`. A name outside the domain is
    /// passed through unchanged (a config error the API will reject).
    fn relative_name(&self, fqdn: &str) -> String {
        if fqdn == self.domain {
            return "@".to_string();
        }
        fqdn.strip_suffix(&format!(".{}", self.domain))
            .map(str::to_string)
            .unwrap_or_else(|| fqdn.to_string())
    }

    /// The record `data`: `CNAME` targets are FQDNs with a trailing dot; every
    /// other kind takes the raw value (TXT unquoted, A/AAAA the address).
    fn record_data(record: &DnsRecord) -> String {
        match record.kind {
            RecordKind::Cname if !record.value.ends_with('.') => format!("{}.", record.value),
            _ => record.value.clone(),
        }
    }

    /// The JSON body for a create/replace of `record`.
    fn record_body(&self, record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({
            "type": record.kind.as_str(),
            "name": self.relative_name(&record.name),
            "data": Self::record_data(record),
            "ttl": record.ttl,
        })
    }

    /// Find the id of an existing `(type, name)` record (the first match), or
    /// `None`. `match_content` narrows by `data` for kinds that can repeat at one
    /// name (TXT/A/AAAA), so `delete` removes the right one.
    async fn find_record_id(
        &self,
        record: &DnsRecord,
        match_content: bool,
    ) -> Result<Option<u64>, DnsError> {
        let resp = self
            .client
            .get(self.records_url())
            .bearer_auth(&self.token)
            .query(&[
                ("type", record.kind.as_str()),
                ("name", record.name.as_str()),
            ])
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let body: ListResponse = resp
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .json()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let want = Self::record_data(record);
        Ok(body
            .domain_records
            .into_iter()
            .find(|r| !match_content || r.data == want)
            .map(|r| r.id))
    }
}

#[derive(Deserialize)]
struct ListResponse {
    domain_records: Vec<ListRecord>,
}

#[derive(Deserialize)]
struct ListRecord {
    id: u64,
    #[serde(default)]
    data: String,
}

#[async_trait]
impl DnsProvider for DigitalOceanDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let body = self.record_body(record);
        let existing = self.find_record_id(record, false).await?;
        let request = match existing {
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

    fn provider() -> DigitalOceanDns {
        DigitalOceanDns::new("example.com", "tok").with_api_base("https://do.test/v2")
    }

    #[test]
    fn records_url_targets_the_domain() {
        assert_eq!(
            provider().records_url(),
            "https://do.test/v2/domains/example.com/records"
        );
    }

    #[test]
    fn relative_name_strips_the_domain_and_maps_apex() {
        let p = provider();
        assert_eq!(
            p.relative_name("_acme-challenge.deploy.example.com"),
            "_acme-challenge.deploy"
        );
        assert_eq!(p.relative_name("example.com"), "@");
        // Outside the domain → passed through (the API will reject it).
        assert_eq!(p.relative_name("other.net"), "other.net");
    }

    #[test]
    fn txt_body_is_relative_with_data() {
        let body = provider().record_body(&DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.deploy.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        });
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["name"], "_acme-challenge.deploy");
        assert_eq!(body["data"], "abc");
        assert_eq!(body["ttl"], 60);
    }

    #[test]
    fn cname_data_gets_a_trailing_dot() {
        let body = provider().record_body(&DnsRecord {
            kind: RecordKind::Cname,
            name: "*.deploy.example.com".into(),
            value: "lb.example.net".into(),
            ttl: 120,
        });
        assert_eq!(body["type"], "CNAME");
        assert_eq!(body["name"], "*.deploy");
        assert_eq!(body["data"], "lb.example.net.");
        // Idempotent: an already-dotted target isn't double-dotted.
        let already = provider().record_body(&DnsRecord {
            kind: RecordKind::Cname,
            name: "*.deploy.example.com".into(),
            value: "lb.example.net.".into(),
            ttl: 120,
        });
        assert_eq!(already["data"], "lb.example.net.");
    }
}
