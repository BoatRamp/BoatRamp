//! Azure DNS provider (Resource Manager REST, OAuth2 bearer token).
//!
//! Azure record sets are addressed by `(zone, type, relative-name)` and edited
//! with a single idempotent `PUT` (create-or-replace) — no read-modify-write, so
//! `upsert` is one request and `delete` one more (404 = already gone). The record
//! body is per-type (`TXTRecords` / `ARecords` / `AAAARecords` / `CNAMERecord`).
//! Names are relative to the zone (`@` = apex). The access token comes from the
//! environment (`AZURE_ACCESS_TOKEN`), matching the Key Vault signer. Request
//! construction is pure + unit-tested; the round-trip is a live seam.

use async_trait::async_trait;

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind};

const DEFAULT_API_BASE: &str = "https://management.azure.com";
const API_VERSION: &str = "2018-05-01";

/// An Azure DNS editor scoped to one zone in a subscription + resource group.
pub struct AzureDns {
    client: reqwest::Client,
    api_base: String,
    token: String,
    subscription: String,
    resource_group: String,
    zone: String,
}

impl AzureDns {
    /// Build a provider for `zone` under `subscription` + `resource_group`,
    /// authenticating with an Azure AD access token for the Resource Manager.
    pub fn new(
        subscription: impl Into<String>,
        resource_group: impl Into<String>,
        zone: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            token: token.into(),
            subscription: subscription.into(),
            resource_group: resource_group.into(),
            zone: zone.into(),
        }
    }

    /// Override the API base URL (for pointing tests at a stub).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
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

    /// The record-set URL: `…/dnsZones/{zone}/{TYPE}/{relative}?api-version=…`.
    fn record_url(&self, record: &DnsRecord) -> String {
        format!(
            "{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/dnsZones/{}/{}/{}?api-version={}",
            self.api_base,
            self.subscription,
            self.resource_group,
            self.zone,
            record.kind.as_str(),
            self.relative_name(&record.name),
            API_VERSION,
        )
    }

    /// The per-type `PUT` body (`properties` with the TTL + the type's record array).
    fn body(record: &DnsRecord) -> serde_json::Value {
        let mut properties = serde_json::Map::new();
        properties.insert("TTL".to_string(), serde_json::json!(record.ttl));
        let (key, value) = match record.kind {
            RecordKind::Txt => (
                "TXTRecords",
                serde_json::json!([{ "value": [record.value] }]),
            ),
            RecordKind::A => (
                "ARecords",
                serde_json::json!([{ "ipv4Address": record.value }]),
            ),
            RecordKind::Aaaa => (
                "AAAARecords",
                serde_json::json!([{ "ipv6Address": record.value }]),
            ),
            RecordKind::Cname => ("CNAMERecord", serde_json::json!({ "cname": record.value })),
        };
        properties.insert(key.to_string(), value);
        serde_json::json!({ "properties": serde_json::Value::Object(properties) })
    }
}

#[async_trait]
impl DnsProvider for AzureDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        // PUT is create-or-replace — idempotent, no read first.
        self.client
            .put(self.record_url(record))
            .bearer_auth(&self.token)
            .json(&Self::body(record))
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
            .bearer_auth(&self.token)
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

    fn provider() -> AzureDns {
        AzureDns::new("sub1", "rg1", "example.com", "tok").with_api_base("https://az.test")
    }

    #[test]
    fn record_url_is_zone_type_relative() {
        let url = provider().record_url(&DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.deploy.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        });
        assert_eq!(
            url,
            "https://az.test/subscriptions/sub1/resourceGroups/rg1/providers/Microsoft.Network/dnsZones/example.com/TXT/_acme-challenge.deploy?api-version=2018-05-01"
        );
    }

    #[test]
    fn apex_name_is_at_sign() {
        let url = provider().record_url(&DnsRecord {
            kind: RecordKind::A,
            name: "example.com".into(),
            value: "203.0.113.7".into(),
            ttl: 60,
        });
        assert!(url.contains("/A/@?api-version="));
    }

    #[test]
    fn txt_body_wraps_value_in_txtrecords() {
        let body = AzureDns::body(&DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.deploy.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        });
        assert_eq!(body["properties"]["TTL"], 60);
        assert_eq!(body["properties"]["TXTRecords"][0]["value"][0], "abc");
    }

    #[test]
    fn typed_bodies_use_the_right_shape() {
        let a = AzureDns::body(&DnsRecord {
            kind: RecordKind::A,
            name: "deploy.example.com".into(),
            value: "203.0.113.7".into(),
            ttl: 60,
        });
        assert_eq!(a["properties"]["ARecords"][0]["ipv4Address"], "203.0.113.7");

        let c = AzureDns::body(&DnsRecord {
            kind: RecordKind::Cname,
            name: "*.deploy.example.com".into(),
            value: "lb.example.net".into(),
            ttl: 120,
        });
        assert_eq!(c["properties"]["CNAMERecord"]["cname"], "lb.example.net");
    }
}
