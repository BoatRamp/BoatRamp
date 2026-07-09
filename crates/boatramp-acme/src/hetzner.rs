//! Hetzner DNS provider (public DNS API v1).
//!
//! Two Hetzner specifics the helpers encode:
//!   * auth is the `Auth-API-Token` header, not bearer;
//!   * the API path keys records by an opaque **zone id**, while the record
//!     `name` in the body is **relative** to the zone (`@` = apex) — so the
//!     provider carries both the zone id (for the URL) and the zone's domain
//!     (to relativize names). CNAME data is normalized to a trailing-dot FQDN.
//!
//! The list endpoint has no server-side name filter, so `upsert` lists the
//! zone's records and matches `(type, name)` in memory, then `PUT`s the match or
//! `POST`s a new one. Construction is pure + unit-tested; the round-trip is a
//! live seam.

use async_trait::async_trait;
use serde::Deserialize;

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind};

const DEFAULT_API_BASE: &str = "https://dns.hetzner.com/api/v1";
const AUTH_HEADER: &str = "Auth-API-Token";

/// A Hetzner DNS editor scoped to one zone.
pub struct HetznerDns {
    client: reqwest::Client,
    api_base: String,
    token: String,
    zone_id: String,
    zone: String,
}

impl HetznerDns {
    /// Build a provider for `zone_id` (the Hetzner zone identifier) whose domain
    /// is `zone` (e.g. `example.com`, used only to relativize record names),
    /// authenticating with a DNS API token.
    pub fn new(
        zone_id: impl Into<String>,
        zone: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            token: token.into(),
            zone_id: zone_id.into(),
            zone: zone.into(),
        }
    }

    /// Override the API base URL (for pointing tests at a stub).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// `…/records` (create/list collection; item ops append `/{id}`).
    fn records_url(&self) -> String {
        format!("{}/records", self.api_base)
    }

    /// The record name relative to the zone: `_acme-challenge.deploy.example.com`
    /// under `example.com` → `_acme-challenge.deploy`; the apex → `@`.
    fn relative_name(&self, fqdn: &str) -> String {
        if fqdn == self.zone {
            return "@".to_string();
        }
        fqdn.strip_suffix(&format!(".{}", self.zone))
            .map(str::to_string)
            .unwrap_or_else(|| fqdn.to_string())
    }

    /// `CNAME` values are FQDNs with a trailing dot; other kinds take the raw value.
    fn record_value(record: &DnsRecord) -> String {
        match record.kind {
            RecordKind::Cname if !record.value.ends_with('.') => format!("{}.", record.value),
            _ => record.value.clone(),
        }
    }

    /// The JSON body for a create/replace of `record`.
    fn record_body(&self, record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({
            "zone_id": self.zone_id,
            "type": record.kind.as_str(),
            "name": self.relative_name(&record.name),
            "value": Self::record_value(record),
            "ttl": record.ttl,
        })
    }

    /// Find the id of an existing `(type, name)` record (first match), or `None`.
    /// `match_content` narrows by value for kinds that can repeat (TXT/A/AAAA).
    async fn find_record_id(
        &self,
        record: &DnsRecord,
        match_content: bool,
    ) -> Result<Option<String>, DnsError> {
        let resp = self
            .client
            .get(self.records_url())
            .header(AUTH_HEADER, &self.token)
            .query(&[("zone_id", self.zone_id.as_str())])
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let body: ListResponse = resp
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .json()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let want_name = self.relative_name(&record.name);
        let want_type = record.kind.as_str();
        let want_value = Self::record_value(record);
        Ok(body
            .records
            .into_iter()
            .find(|r| {
                r.r#type == want_type
                    && r.name == want_name
                    && (!match_content || r.value == want_value)
            })
            .map(|r| r.id))
    }
}

#[derive(Deserialize)]
struct ListResponse {
    #[serde(default)]
    records: Vec<ListRecord>,
}

#[derive(Deserialize)]
struct ListRecord {
    id: String,
    #[serde(rename = "type")]
    r#type: String,
    name: String,
    #[serde(default)]
    value: String,
}

#[async_trait]
impl DnsProvider for HetznerDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let body = self.record_body(record);
        let existing = self.find_record_id(record, false).await?;
        let request = match existing {
            Some(id) => self
                .client
                .put(format!("{}/{}", self.records_url(), id))
                .header(AUTH_HEADER, &self.token)
                .json(&body),
            None => self
                .client
                .post(self.records_url())
                .header(AUTH_HEADER, &self.token)
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
        let match_content = matches!(
            record.kind,
            RecordKind::Txt | RecordKind::A | RecordKind::Aaaa
        );
        let Some(id) = self.find_record_id(record, match_content).await? else {
            return Ok(()); // already gone
        };
        self.client
            .delete(format!("{}/{}", self.records_url(), id))
            .header(AUTH_HEADER, &self.token)
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

    fn provider() -> HetznerDns {
        HetznerDns::new("zone123", "example.com", "tok").with_api_base("https://hz.test/v1")
    }

    #[test]
    fn records_url_is_the_collection() {
        assert_eq!(provider().records_url(), "https://hz.test/v1/records");
    }

    #[test]
    fn relative_name_strips_the_zone_and_maps_apex() {
        let p = provider();
        assert_eq!(
            p.relative_name("_acme-challenge.deploy.example.com"),
            "_acme-challenge.deploy"
        );
        assert_eq!(p.relative_name("example.com"), "@");
    }

    #[test]
    fn body_carries_zone_id_and_relative_name() {
        let body = provider().record_body(&DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.deploy.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        });
        assert_eq!(body["zone_id"], "zone123");
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["name"], "_acme-challenge.deploy");
        assert_eq!(body["value"], "abc");
        assert_eq!(body["ttl"], 60);
    }

    #[test]
    fn cname_value_gets_a_trailing_dot() {
        let body = provider().record_body(&DnsRecord {
            kind: RecordKind::Cname,
            name: "*.deploy.example.com".into(),
            value: "lb.example.net".into(),
            ttl: 120,
        });
        assert_eq!(body["value"], "lb.example.net.");
    }
}
