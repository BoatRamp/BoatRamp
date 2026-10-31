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

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind, RecordKindTag};

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

    /// The per-type `PUT` body (`properties` with the TTL + the type's record
    /// array). **WS2:** the original four plus MX/SRV/CAA/NS/PTR — Azure DNS's
    /// documented supported record types (A, AAAA, CAA, CNAME, MX, NS, PTR, SOA,
    /// SRV, TXT). **WS2b re-confirmed (doc updated 2026-09-14):** Azure's own
    /// "DNS zones and records overview" still enumerates exactly that set —
    /// "Azure DNS supports all common DNS record types: A, AAAA, CAA, CNAME,
    /// MX, NS, PTR, SOA, SRV, and TXT" — with DS/TLSA gated behind a
    /// DNSSEC-signed zone (a zone-level feature this crate doesn't model) and no
    /// mention of HTTPS/SVCB anywhere on the page:
    /// <https://learn.microsoft.com/azure/dns/dns-zones-records>. TLSA and
    /// HTTPS/SVCB stay refused — a genuine provider gap, not an unpinned
    /// encoding — so they fall to the `UnsupportedRecordType` arm (the central
    /// [`crate::dns::validate_writable`] guardrail catches it first, but this
    /// keeps the adapter honest if called directly).
    fn body(record: &DnsRecord) -> Result<serde_json::Value, DnsError> {
        let mut properties = serde_json::Map::new();
        properties.insert("TTL".to_string(), serde_json::json!(record.ttl));
        let (key, value) = match &record.kind {
            RecordKind::Txt(strings) => ("TXTRecords", serde_json::json!([{ "value": strings }])),
            RecordKind::A(ip) => (
                "ARecords",
                serde_json::json!([{ "ipv4Address": ip.to_string() }]),
            ),
            RecordKind::Aaaa(ip) => (
                "AAAARecords",
                serde_json::json!([{ "ipv6Address": ip.to_string() }]),
            ),
            RecordKind::Cname(target) => ("CNAMERecord", serde_json::json!({ "cname": target })),
            RecordKind::Mx {
                preference,
                exchange,
            } => (
                "MXRecords",
                serde_json::json!([{ "preference": preference, "exchange": exchange }]),
            ),
            RecordKind::Srv {
                priority,
                weight,
                port,
                target,
            } => (
                "SRVRecords",
                serde_json::json!([{ "priority": priority, "weight": weight, "port": port, "target": target }]),
            ),
            RecordKind::Caa { flags, tag, value } => (
                "CAARecords",
                serde_json::json!([{ "flags": flags, "tag": tag.as_str(), "value": value }]),
            ),
            RecordKind::Ns(target) => ("NSRecords", serde_json::json!([{ "nsdname": target }])),
            RecordKind::Ptr(target) => ("PTRRecords", serde_json::json!([{ "ptrdname": target }])),
            other => {
                return Err(DnsError::UnsupportedRecordType {
                    provider: "azure",
                    kind: other.tag(),
                });
            }
        };
        properties.insert(key.to_string(), value);
        Ok(serde_json::json!({ "properties": serde_json::Value::Object(properties) }))
    }
}

#[async_trait]
impl DnsProvider for AzureDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        // PUT is create-or-replace — idempotent, no read first.
        self.client
            .put(self.record_url(record))
            .bearer_auth(&self.token)
            .json(&Self::body(record)?)
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

    fn supported_kinds(&self) -> &'static [RecordKindTag] {
        // Azure DNS's documented supported record types: A, AAAA, CAA, CNAME,
        // MX, NS, PTR, SOA, SRV, TXT. No TLSA, no HTTPS/SVCB — see `body`'s doc
        // comment for the WS2b re-confirmation + doc URL.
        &[
            RecordKindTag::A,
            RecordKindTag::Aaaa,
            RecordKindTag::Cname,
            RecordKindTag::Txt,
            RecordKindTag::Mx,
            RecordKindTag::Srv,
            RecordKindTag::Caa,
            RecordKindTag::Ns,
            RecordKindTag::Ptr,
        ]
    }

    fn name(&self) -> &'static str {
        "azure"
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
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.deploy.example.com".into(),
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
            kind: RecordKind::A("203.0.113.7".parse().unwrap()),
            name: "example.com".into(),
            ttl: 60,
        });
        assert!(url.contains("/A/@?api-version="));
    }

    #[test]
    fn txt_body_wraps_value_in_txtrecords() {
        let body = AzureDns::body(&DnsRecord {
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.deploy.example.com".into(),
            ttl: 60,
        })
        .unwrap();
        assert_eq!(body["properties"]["TTL"], 60);
        assert_eq!(body["properties"]["TXTRecords"][0]["value"][0], "abc");
    }

    #[test]
    fn typed_bodies_use_the_right_shape() {
        let a = AzureDns::body(&DnsRecord {
            kind: RecordKind::A("203.0.113.7".parse().unwrap()),
            name: "deploy.example.com".into(),
            ttl: 60,
        })
        .unwrap();
        assert_eq!(a["properties"]["ARecords"][0]["ipv4Address"], "203.0.113.7");

        let c = AzureDns::body(&DnsRecord {
            kind: RecordKind::Cname("lb.example.net".into()),
            name: "*.deploy.example.com".into(),
            ttl: 120,
        })
        .unwrap();
        assert_eq!(c["properties"]["CNAMERecord"]["cname"], "lb.example.net");
    }

    /// Golden: the exact per-type `properties` body for every kind (singular
    /// `CNAMERecord`, plural `*Records` arrays) plus the apex/subdomain relative-name
    /// encoding — Azure's DNS record-set wire shape, pinned against drift.
    #[test]
    fn body_and_relative_name_golden_for_every_kind() {
        let rec = |kind| DnsRecord {
            kind,
            name: "x.example.com".into(),
            ttl: 60,
        };
        assert_eq!(
            AzureDns::body(&rec(RecordKind::A("203.0.113.7".parse().unwrap()))).unwrap(),
            serde_json::json!({"properties": {"TTL": 60, "ARecords": [{"ipv4Address": "203.0.113.7"}]}})
        );
        assert_eq!(
            AzureDns::body(&rec(RecordKind::Aaaa("2001:db8::1".parse().unwrap()))).unwrap(),
            serde_json::json!({"properties": {"TTL": 60, "AAAARecords": [{"ipv6Address": "2001:db8::1"}]}})
        );
        assert_eq!(
            AzureDns::body(&rec(RecordKind::Cname("lb.example.net".into()))).unwrap(),
            serde_json::json!({"properties": {"TTL": 60, "CNAMERecord": {"cname": "lb.example.net"}}})
        );
        assert_eq!(
            AzureDns::body(&rec(RecordKind::Txt(vec!["tok".into()]))).unwrap(),
            serde_json::json!({"properties": {"TTL": 60, "TXTRecords": [{"value": ["tok"]}]}})
        );
        // The apex resolves to `@`; a subdomain drops the zone suffix.
        assert_eq!(provider().relative_name("example.com"), "@");
        assert_eq!(
            provider().relative_name("_acme-challenge.deploy.example.com"),
            "_acme-challenge.deploy"
        );
    }

    /// Golden: the WS2 record types Azure declares support for.
    #[test]
    fn body_golden_for_ws2_kinds() {
        let rec = |kind| DnsRecord {
            kind,
            name: "x.example.com".into(),
            ttl: 60,
        };
        assert_eq!(
            AzureDns::body(&rec(RecordKind::Mx {
                preference: 10,
                exchange: "mx.example.com".into(),
            }))
            .unwrap(),
            serde_json::json!({"properties": {"TTL": 60, "MXRecords": [{"preference": 10, "exchange": "mx.example.com"}]}})
        );
        assert_eq!(
            AzureDns::body(&rec(RecordKind::Srv {
                priority: 1,
                weight: 5,
                port: 443,
                target: "svc.example.com".into(),
            }))
            .unwrap(),
            serde_json::json!({"properties": {"TTL": 60, "SRVRecords": [{"priority": 1, "weight": 5, "port": 443, "target": "svc.example.com"}]}})
        );
        assert_eq!(
            AzureDns::body(&rec(RecordKind::Caa {
                flags: 0,
                tag: crate::dns::CaaTag::Issue,
                value: "letsencrypt.org".into(),
            }))
            .unwrap(),
            serde_json::json!({"properties": {"TTL": 60, "CAARecords": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}]}})
        );
        assert_eq!(
            AzureDns::body(&rec(RecordKind::Ns("ns1.example.net".into()))).unwrap(),
            serde_json::json!({"properties": {"TTL": 60, "NSRecords": [{"nsdname": "ns1.example.net"}]}})
        );
        assert_eq!(
            AzureDns::body(&rec(RecordKind::Ptr("host.example.com".into()))).unwrap(),
            serde_json::json!({"properties": {"TTL": 60, "PTRRecords": [{"ptrdname": "host.example.com"}]}})
        );
        // TLSA and HTTPS/SVCB are not declared for Azure.
        assert!(matches!(
            AzureDns::body(&rec(RecordKind::Tlsa {
                usage: 3,
                selector: 1,
                matching: 1,
                data: "abcdef".into(),
            })),
            Err(DnsError::UnsupportedRecordType {
                kind: crate::dns::RecordKindTag::Tlsa,
                ..
            })
        ));
    }

    /// WS2b: re-confirmed against Azure's current "DNS zones and records
    /// overview" (doc updated 2026-09-14) — HTTPS/SVCB are still absent from
    /// Azure's supported-type list, so `body` refuses both directly (not just
    /// via the central guardrail) and `supported_kinds` excludes them.
    #[test]
    fn https_svcb_stay_unsupported() {
        let rec = |kind| DnsRecord {
            kind,
            name: "x.example.com".into(),
            ttl: 60,
        };
        assert!(matches!(
            AzureDns::body(&rec(RecordKind::Https {
                priority: 1,
                target: ".".into(),
                params: vec![],
            })),
            Err(DnsError::UnsupportedRecordType {
                kind: crate::dns::RecordKindTag::Https,
                provider: "azure",
            })
        ));
        assert!(matches!(
            AzureDns::body(&rec(RecordKind::Svcb {
                priority: 0,
                target: "svc.example.net".into(),
                params: vec![],
            })),
            Err(DnsError::UnsupportedRecordType {
                kind: crate::dns::RecordKindTag::Svcb,
                provider: "azure",
            })
        ));
        let p = provider();
        assert!(!p.supports_kind(RecordKindTag::Https));
        assert!(!p.supports_kind(RecordKindTag::Svcb));
    }
}
