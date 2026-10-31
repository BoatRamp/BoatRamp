//! DNSimple DNS provider (API v2, bearer-token auth).
//!
//! Records live under `/v2/{account}/zones/{zone}/records`; the record `name` is
//! **relative** to the zone — an **empty string** for the apex (DNSimple's
//! convention, unlike the `@` other providers use). `upsert` filters by `(name,
//! type)`, then `PATCH`es the match's content or `POST`s a new record; `delete`
//! removes it by id. CNAME content is normalized to a trailing-dot FQDN.
//! Construction is pure + unit-tested; the round-trip is a live seam.

use async_trait::async_trait;
use serde::Deserialize;

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind, RecordKindTag};

const DEFAULT_API_BASE: &str = "https://api.dnsimple.com/v2";

/// A DNSimple DNS editor scoped to one account + zone.
pub struct DnsimpleDns {
    client: reqwest::Client,
    api_base: String,
    token: String,
    account: String,
    zone: String,
}

impl DnsimpleDns {
    /// Build a provider for `account` (the numeric account id) + `zone` (the
    /// domain, e.g. `example.com`), authenticating with an API access token.
    pub fn new(
        account: impl Into<String>,
        zone: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            token: token.into(),
            account: account.into(),
            zone: zone.into(),
        }
    }

    /// Override the API base URL (for pointing tests at a stub).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// `…/{account}/zones/{zone}/records` (create/list; item ops append `/{id}`).
    fn records_url(&self) -> String {
        format!(
            "{}/{}/zones/{}/records",
            self.api_base, self.account, self.zone
        )
    }

    /// The record name relative to the zone: `_acme-challenge.deploy.example.com`
    /// under `example.com` → `_acme-challenge.deploy`; the apex → `""` (empty).
    fn relative_name(&self, fqdn: &str) -> String {
        if fqdn == self.zone {
            return String::new();
        }
        fqdn.strip_suffix(&format!(".{}", self.zone))
            .map(str::to_string)
            .unwrap_or_else(|| fqdn.to_string())
    }

    /// A target name as an FQDN with the trailing dot DNSimple's convention wants.
    fn dotted(name: &str) -> String {
        if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        }
    }

    /// A SvcParam list rendered as RFC 9460 presentation-form tokens
    /// (`key=value`, or a bare `key` when the value is empty), space-joined —
    /// DNSimple documents the HTTPS/SVCB `content` as exactly this zone-file
    /// presentation form (see `record_content`'s doc comment).
    fn svcparams_presentation(params: &[crate::dns::SvcParam]) -> String {
        params
            .iter()
            .map(|p| {
                if p.value.is_empty() {
                    p.key.clone()
                } else {
                    format!("{}={}", p.key, p.value)
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The record `content`, in DNSimple's RFC 1035 master-file presentation
    /// format: `CNAME`/`NS`/`PTR` targets and `MX`/`SRV`'s name fields are
    /// trailing-dot FQDNs, `CAA`/`TLSA` are space-joined field strings,
    /// `HTTPS`/`SVCB` are `<priority> <dotted target> <SvcParams...>` (DNSimple's
    /// own announcement confirms `content` uses "the same presentation format as
    /// in zone files" for these two types:
    /// <https://blog.dnsimple.com/2026/02/svcb-https-record-support/>, with the
    /// target-dotting convention documented at
    /// <https://support.dnsimple.com/articles/manage-service-binding-records/>),
    /// other kinds take the raw value (unchanged from WS1).
    fn record_content(record: &DnsRecord) -> String {
        match &record.kind {
            RecordKind::Cname(target) | RecordKind::Ns(target) | RecordKind::Ptr(target) => {
                Self::dotted(target)
            }
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
            RecordKind::Https {
                priority,
                target,
                params,
            }
            | RecordKind::Svcb {
                priority,
                target,
                params,
            } => {
                let svcparams = Self::svcparams_presentation(params);
                let target = Self::dotted(target);
                if svcparams.is_empty() {
                    format!("{priority} {target}")
                } else {
                    format!("{priority} {target} {svcparams}")
                }
            }
            _ => record.kind.flat_value(),
        }
    }

    /// The JSON body for creating `record`.
    fn record_body(&self, record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({
            "name": self.relative_name(&record.name),
            "type": record.kind.as_str(),
            "content": Self::record_content(record),
            "ttl": record.ttl,
        })
    }

    /// Find the id of an existing `(type, name)` record (first match), or `None`.
    /// `match_content` narrows by content for kinds that can repeat (TXT/A/AAAA).
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
                ("name", self.relative_name(&record.name)),
                ("type", record.kind.as_str().to_string()),
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
        let want = Self::record_content(record);
        Ok(body
            .data
            .into_iter()
            .find(|r| !match_content || r.content == want)
            .map(|r| r.id))
    }
}

#[derive(Deserialize)]
struct ListResponse {
    #[serde(default)]
    data: Vec<ListRecord>,
}

#[derive(Deserialize)]
struct ListRecord {
    id: u64,
    #[serde(default)]
    content: String,
}

#[async_trait]
impl DnsProvider for DnsimpleDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let existing = self.find_record_id(record, false).await?;
        let request = match existing {
            // PATCH only mutates content + ttl (name/type are fixed by the URL).
            Some(id) => self
                .client
                .patch(format!("{}/{}", self.records_url(), id))
                .bearer_auth(&self.token)
                .json(&serde_json::json!({
                    "content": Self::record_content(record),
                    "ttl": record.ttl,
                })),
            None => self
                .client
                .post(self.records_url())
                .bearer_auth(&self.token)
                .json(&self.record_body(record)),
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
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }

    fn supported_kinds(&self) -> &'static [RecordKindTag] {
        // WS2b: DNSimple added HTTPS/SVCB support
        // (https://blog.dnsimple.com/2026/02/svcb-https-record-support/) with
        // `content` in the same zone-file presentation form as every other
        // DNSimple record type — see `record_content`'s doc comment for the
        // pinned encoding.
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
            RecordKindTag::Tlsa,
            RecordKindTag::Https,
            RecordKindTag::Svcb,
        ]
    }

    fn name(&self) -> &'static str {
        "dnsimple"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> DnsimpleDns {
        DnsimpleDns::new("1234", "example.com", "tok").with_api_base("https://ds.test/v2")
    }

    #[test]
    fn records_url_is_account_zone_scoped() {
        assert_eq!(
            provider().records_url(),
            "https://ds.test/v2/1234/zones/example.com/records"
        );
    }

    #[test]
    fn relative_name_strips_the_zone_and_maps_apex_to_empty() {
        let p = provider();
        assert_eq!(
            p.relative_name("_acme-challenge.deploy.example.com"),
            "_acme-challenge.deploy"
        );
        assert_eq!(p.relative_name("example.com"), "");
    }

    #[test]
    fn body_is_relative_with_content() {
        let body = provider().record_body(&DnsRecord {
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.deploy.example.com".into(),
            ttl: 60,
        });
        assert_eq!(body["name"], "_acme-challenge.deploy");
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["content"], "abc");
        assert_eq!(body["ttl"], 60);
    }

    #[test]
    fn cname_content_gets_a_trailing_dot() {
        let body = provider().record_body(&DnsRecord {
            kind: RecordKind::Cname("lb.example.net".into()),
            name: "*.deploy.example.com".into(),
            ttl: 120,
        });
        assert_eq!(body["content"], "lb.example.net.");
    }

    /// Golden: the exact create body for every kind, pinning DNSimple's
    /// `content`-keyed, relative-name (apex → empty string) wire shape.
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
            serde_json::json!({"name": "deploy", "type": "A", "content": "203.0.113.7", "ttl": 60})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Aaaa("2001:db8::1".parse().unwrap()),
                "deploy.example.com",
                60
            )),
            serde_json::json!({"name": "deploy", "type": "AAAA", "content": "2001:db8::1", "ttl": 60})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Cname("lb.example.net".into()),
                "www.example.com",
                300
            )),
            serde_json::json!({"name": "www", "type": "CNAME", "content": "lb.example.net.", "ttl": 300})
        );
        // The apex resolves to an empty relative name.
        assert_eq!(
            p.record_body(&rec(RecordKind::Txt(vec!["tok".into()]), "example.com", 60)),
            serde_json::json!({"name": "", "type": "TXT", "content": "tok", "ttl": 60})
        );
    }

    /// Golden: the WS2 record types DNSimple declares support for.
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
            serde_json::json!({"name": "", "type": "MX", "content": "10 mx.example.com.", "ttl": 300})
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
            serde_json::json!({"name": "_svc._tcp", "type": "SRV", "content": "1 5 443 svc.example.com.", "ttl": 300})
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
            serde_json::json!({"name": "", "type": "CAA", "content": "0 issue \"letsencrypt.org\"", "ttl": 300})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Ns("ns1.example.net".into()),
                "sub.example.com",
                3600
            )),
            serde_json::json!({"name": "sub", "type": "NS", "content": "ns1.example.net.", "ttl": 3600})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Ptr("host.example.com".into()),
                "7.113.0.203.in-addr.arpa",
                3600
            )),
            serde_json::json!({"name": "7.113.0.203.in-addr.arpa", "type": "PTR", "content": "host.example.com.", "ttl": 3600})
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
            serde_json::json!({"name": "_443._tcp", "type": "TLSA", "content": "3 1 1 abcdef", "ttl": 300})
        );
    }

    /// Golden (WS2b): DNSimple's HTTPS/SVCB `content` — RFC 9460 presentation
    /// form, target dotted like every other name-bearing field. Values mirror
    /// DNSimple's own worked examples
    /// (<https://blog.dnsimple.com/2026/02/svcb-https-record-support/>,
    /// <https://support.dnsimple.com/articles/manage-service-binding-records/>).
    #[test]
    fn record_body_golden_for_https_svcb() {
        let p = provider();
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        // ServiceMode, self-target (AliasMode-style "."), one SvcParam.
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Https {
                    priority: 1,
                    target: ".".into(),
                    params: vec![crate::dns::SvcParam {
                        key: "alpn".into(),
                        value: "h2,h3".into(),
                    }],
                },
                "example.com",
                300
            )),
            serde_json::json!({"name": "", "type": "HTTPS", "content": "1 . alpn=h2,h3", "ttl": 300})
        );
        // AliasMode (priority 0), real target, no params.
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Svcb {
                    priority: 0,
                    target: "svc.example.net".into(),
                    params: vec![],
                },
                "_8443._tcp.example.com",
                300
            )),
            serde_json::json!({"name": "_8443._tcp", "type": "SVCB", "content": "0 svc.example.net.", "ttl": 300})
        );
    }

    /// DNSimple now declares HTTPS/SVCB support (WS2b).
    #[test]
    fn supported_kinds_includes_https_svcb() {
        let p = provider();
        for tag in [RecordKindTag::Https, RecordKindTag::Svcb] {
            assert!(p.supports_kind(tag), "dnsimple should support {tag}");
        }
    }
}
