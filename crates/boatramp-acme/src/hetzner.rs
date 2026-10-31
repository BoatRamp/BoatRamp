//! Hetzner DNS provider (**classic** public DNS API v1 — `dns.hetzner.com/api/v1`
//! with the `Auth-API-Token` header).
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
//!
//! **WS2b note on HTTPS/SVCB/PTR:** Hetzner's newer Cloud-console DNS surface
//! documents HTTPS and SVCB zone records (e.g.
//! <https://docs.hetzner.com/networking/dns/record-types/svcb-record>,
//! <https://docs.hetzner.com/networking/dns/record-types/https-record/>), but
//! that is a **different** API from the one this adapter targets. Ansible's
//! `community.dns` collection — which supports both — documents the split
//! explicitly: "the old API (`hetzner_token`) does not support `HTTPS`, `PTR`,
//! and `SVCB` records[;] the new API (`hetzner_api_token`) does not support
//! `DANE` records"
//! (<https://docs.ansible.com/projects/ansible/14/collections/community/dns/hetzner_dns_record_module.html>).
//! This adapter is the classic `Auth-API-Token` ("old") API, so HTTPS/PTR/SVCB
//! stay genuinely unsupported here — not an unpinned encoding, but the wrong
//! API surface for those three types.
//!
//! **Flag for owner review (bigger than WS2b):** `DEFAULT_API_BASE` below
//! (`dns.hetzner.com/api/v1`) appears to be **decommissioned**, not merely
//! legacy: every request to it — any path, with or without an `Auth-API-Token`
//! header, `GET` or otherwise — 301-redirects to `console.hetzner.com` instead
//! of returning a 401/404 JSON error (verified live, 2026-10-31). That is host
//! retirement, not an auth failure, so this adapter may not work for ANY record
//! type right now, not just HTTPS/SVCB. Migrating to Hetzner's current API
//! (`api.hetzner.cloud` Zones/RRSets — bearer auth, a structured value/params
//! record shape) is a separate, larger workstream than WS2b's HTTPS/SVCB-only
//! remit, so it is flagged here rather than attempted as a drive-by fix.

use async_trait::async_trait;
use serde::Deserialize;

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind, RecordKindTag};

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

    /// A target name as an FQDN with the trailing dot Hetzner's convention wants
    /// for name-valued rdata (`CNAME`, and now `MX`/`SRV`/`NS`'s name fields).
    fn dotted(name: &str) -> String {
        if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        }
    }

    /// The record `value`: `CNAME`/`NS` targets and `MX`/`SRV`'s name fields are
    /// FQDNs with a trailing dot; `CAA`/`TLSA` are RFC 1035 presentation-format
    /// strings; other kinds take the raw value (unchanged from WS1).
    fn record_value(record: &DnsRecord) -> String {
        match &record.kind {
            RecordKind::Cname(target) | RecordKind::Ns(target) => Self::dotted(target),
            RecordKind::Mx {
                preference,
                exchange,
            } => format!("{preference} {}", Self::dotted(exchange)),
            RecordKind::Srv {
                priority,
                weight,
                port,
                target,
            } => format!("{priority} {weight} {port} {}", Self::dotted(target)),
            RecordKind::Caa { flags, tag, value } => format!("{flags} {tag} \"{value}\""),
            RecordKind::Tlsa {
                usage,
                selector,
                matching,
                data,
            } => format!("{usage} {selector} {matching} {data}"),
            _ => record.kind.flat_value(),
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
            RecordKind::Txt(_) | RecordKind::A(_) | RecordKind::Aaaa(_)
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

    fn supported_kinds(&self) -> &'static [RecordKindTag] {
        // Hetzner's classic-API record types: A, AAAA, NS, MX, CNAME, SOA,
        // HINFO, SRV, TXT, DANE (TLSA), DS, CAA. No PTR and no HTTPS/SVCB on
        // THIS (old/`Auth-API-Token`) API — see the module doc comment for the
        // old-vs-new API citation.
        &[
            RecordKindTag::A,
            RecordKindTag::Aaaa,
            RecordKindTag::Cname,
            RecordKindTag::Txt,
            RecordKindTag::Mx,
            RecordKindTag::Srv,
            RecordKindTag::Caa,
            RecordKindTag::Ns,
            RecordKindTag::Tlsa,
        ]
    }

    fn name(&self) -> &'static str {
        "hetzner"
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
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.deploy.example.com".into(),
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
            kind: RecordKind::Cname("lb.example.net".into()),
            name: "*.deploy.example.com".into(),
            ttl: 120,
        });
        assert_eq!(body["value"], "lb.example.net.");
    }

    /// Golden: the exact create/replace body for every kind, pinning Hetzner's
    /// `zone_id` + `value`-keyed, relative-name (apex → `@`) wire shape.
    #[test]
    fn record_body_golden_for_every_kind() {
        let p = provider();
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        assert_eq!(
            p.record_body(&rec(
                RecordKind::A("203.0.113.7".parse().unwrap()),
                "deploy.example.com",
                60
            )),
            serde_json::json!({"zone_id": "zone123", "type": "A", "name": "deploy", "value": "203.0.113.7", "ttl": 60})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Aaaa("2001:db8::1".parse().unwrap()),
                "deploy.example.com",
                60
            )),
            serde_json::json!({"zone_id": "zone123", "type": "AAAA", "name": "deploy", "value": "2001:db8::1", "ttl": 60})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Cname("lb.example.net".into()),
                "www.example.com",
                300
            )),
            serde_json::json!({"zone_id": "zone123", "type": "CNAME", "name": "www", "value": "lb.example.net.", "ttl": 300})
        );
        assert_eq!(
            p.record_body(&rec(RecordKind::Txt(vec!["tok".into()]), "example.com", 60)),
            serde_json::json!({"zone_id": "zone123", "type": "TXT", "name": "@", "value": "tok", "ttl": 60})
        );
    }

    /// Golden: the WS2 record types Hetzner declares support for.
    #[test]
    fn record_body_golden_for_ws2_kinds() {
        let p = provider();
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Mx {
                    preference: 10,
                    exchange: "mx.example.com".into(),
                },
                "example.com",
                300
            )),
            serde_json::json!({"zone_id": "zone123", "type": "MX", "name": "@", "value": "10 mx.example.com.", "ttl": 300})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Srv {
                    priority: 1,
                    weight: 5,
                    port: 443,
                    target: "svc.example.com".into(),
                },
                "_svc._tcp.example.com",
                300
            )),
            serde_json::json!({"zone_id": "zone123", "type": "SRV", "name": "_svc._tcp", "value": "1 5 443 svc.example.com.", "ttl": 300})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Caa {
                    flags: 0,
                    tag: crate::dns::CaaTag::Issue,
                    value: "letsencrypt.org".into(),
                },
                "example.com",
                300
            )),
            serde_json::json!({"zone_id": "zone123", "type": "CAA", "name": "@", "value": "0 issue \"letsencrypt.org\"", "ttl": 300})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Ns("ns1.example.net".into()),
                "sub.example.com",
                3600
            )),
            serde_json::json!({"zone_id": "zone123", "type": "NS", "name": "sub", "value": "ns1.example.net.", "ttl": 3600})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Tlsa {
                    usage: 3,
                    selector: 1,
                    matching: 1,
                    data: "abcdef".into(),
                },
                "_443._tcp.example.com",
                300
            )),
            serde_json::json!({"zone_id": "zone123", "type": "TLSA", "name": "_443._tcp", "value": "3 1 1 abcdef", "ttl": 300})
        );
    }

    /// WS2b re-confirmed: this adapter targets Hetzner's classic
    /// `Auth-API-Token` DNS API, which — per Ansible's `community.dns`
    /// collection (see the module doc comment) — does not support PTR,
    /// HTTPS, or SVCB; only Hetzner's newer API does.
    #[test]
    fn supported_kinds_excludes_ptr_and_svcb_family() {
        let p = provider();
        for tag in [
            crate::dns::RecordKindTag::Ptr,
            crate::dns::RecordKindTag::Https,
            crate::dns::RecordKindTag::Svcb,
        ] {
            assert!(!p.supports_kind(tag), "hetzner should NOT support {tag}");
        }
    }
}
