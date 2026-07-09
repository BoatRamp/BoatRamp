//! NS1 (IBM) DNS provider (API v1, `X-NSONE-Key` header).
//!
//! NS1 addresses a record by its full path `/v1/zones/{zone}/{fqdn}/{type}`, so
//! there is no record id and no list filter: `upsert` GETs that path to see if
//! the record exists, then `PUT`s (create) or `POST`s (update); `delete` DELETEs
//! it (404 = already gone). Record data is an `answers` array — a single answer
//! here (one value per `DnsRecord`); the DNS-01 wildcard path needs exactly one.
//! Names are full FQDNs (no relativizing). CNAME data is normalized to a
//! trailing-dot FQDN. Construction is pure + unit-tested; round-trip is a live seam.

use async_trait::async_trait;

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind};

const DEFAULT_API_BASE: &str = "https://api.nsone.net/v1";
const AUTH_HEADER: &str = "X-NSONE-Key";

/// An NS1 DNS editor scoped to one zone.
pub struct Ns1Dns {
    client: reqwest::Client,
    api_base: String,
    key: String,
    zone: String,
}

impl Ns1Dns {
    /// Build a provider for `zone` (the apex domain, e.g. `example.com`),
    /// authenticating with an NS1 API key.
    pub fn new(zone: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            key: key.into(),
            zone: zone.into(),
        }
    }

    /// Override the API base URL (for pointing tests at a stub).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// `…/zones/{zone}/{fqdn}/{type}` — NS1's per-record endpoint.
    fn record_url(&self, record: &DnsRecord) -> String {
        format!(
            "{}/zones/{}/{}/{}",
            self.api_base,
            self.zone,
            record.name,
            record.kind.as_str()
        )
    }

    /// `CNAME` answers are FQDNs with a trailing dot; other kinds take the raw value.
    fn answer_value(record: &DnsRecord) -> String {
        match record.kind {
            RecordKind::Cname if !record.value.ends_with('.') => format!("{}.", record.value),
            _ => record.value.clone(),
        }
    }

    /// The JSON body for a create/update of `record` (one answer).
    fn record_body(&self, record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({
            "zone": self.zone,
            "domain": record.name,
            "type": record.kind.as_str(),
            "ttl": record.ttl,
            "answers": [ { "answer": [ Self::answer_value(record) ] } ],
        })
    }

    /// Whether the `(fqdn, type)` record already exists (200 vs 404).
    async fn exists(&self, record: &DnsRecord) -> Result<bool, DnsError> {
        let resp = self
            .client
            .get(self.record_url(record))
            .header(AUTH_HEADER, &self.key)
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        match resp.status().as_u16() {
            200 => Ok(true),
            404 => Ok(false),
            other => Err(DnsError::Backend(format!("ns1 GET record: HTTP {other}"))),
        }
    }
}

#[async_trait]
impl DnsProvider for Ns1Dns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let body = self.record_body(record);
        let url = self.record_url(record);
        // NS1: PUT creates a new record, POST updates the existing one.
        let request = if self.exists(record).await? {
            self.client
                .post(url)
                .header(AUTH_HEADER, &self.key)
                .json(&body)
        } else {
            self.client
                .put(url)
                .header(AUTH_HEADER, &self.key)
                .json(&body)
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
        let resp = self
            .client
            .delete(self.record_url(record))
            .header(AUTH_HEADER, &self.key)
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        if resp.status().as_u16() == 404 {
            return Ok(()); // already gone
        }
        resp.error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> Ns1Dns {
        Ns1Dns::new("example.com", "key").with_api_base("https://ns1.test/v1")
    }

    #[test]
    fn record_url_is_zone_fqdn_type() {
        let url = provider().record_url(&DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.deploy.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        });
        assert_eq!(
            url,
            "https://ns1.test/v1/zones/example.com/_acme-challenge.deploy.example.com/TXT"
        );
    }

    #[test]
    fn body_wraps_the_value_in_an_answers_array() {
        let body = provider().record_body(&DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.deploy.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        });
        assert_eq!(body["zone"], "example.com");
        assert_eq!(body["domain"], "_acme-challenge.deploy.example.com");
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["ttl"], 60);
        assert_eq!(body["answers"][0]["answer"][0], "abc");
    }

    #[test]
    fn cname_answer_gets_a_trailing_dot() {
        let body = provider().record_body(&DnsRecord {
            kind: RecordKind::Cname,
            name: "*.deploy.example.com".into(),
            value: "lb.example.net".into(),
            ttl: 120,
        });
        assert_eq!(body["answers"][0]["answer"][0], "lb.example.net.");
    }
}
