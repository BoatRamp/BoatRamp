//! NS1 (IBM) DNS provider (API v1, `X-NSONE-Key` header).
//!
//! NS1 addresses a record by its full path `/v1/zones/{zone}/{fqdn}/{type}`, so
//! there is no record id and no list filter: `upsert` GETs that path to see if
//! the record exists, then `PUT`s (create) or `POST`s (update); `delete` removes
//! it with a `DELETE` (404 = already gone). Record data is an `answers` array — a
//! single answer here (one value per `DnsRecord`); the DNS-01 wildcard needs one.
//! Names are full FQDNs (no relativizing). CNAME data is normalized to a
//! trailing-dot FQDN. Construction is pure + unit-tested; round-trip is a live seam.

use async_trait::async_trait;

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind, RecordKindTag};

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
        let value = record.kind.flat_value();
        if matches!(record.kind, RecordKind::Cname(_)) && !value.ends_with('.') {
            format!("{value}.")
        } else {
            value
        }
    }

    /// A target name as an FQDN with the trailing dot NS1's convention wants.
    fn dotted(name: &str) -> String {
        if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        }
    }

    /// A SvcParam list rendered as RFC 9460 presentation-form tokens
    /// (`key=value`, or a bare `key` when the value is empty), space-joined —
    /// the same convention this crate uses everywhere else (route53, GCP,
    /// Akamai, DNSimple); see `answer_fields`'s doc comment for why NS1 gets
    /// the same unquoted convention rather than a guessed quoting rule.
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

    /// The `answer` array's elements: NS1 represents a multi-field RDATA (MX,
    /// SRV, CAA, TLSA) as the fields **positionally**, each its own array
    /// element (not one presentation-format string) — distinct from the
    /// single-value shape the original four kinds use.
    ///
    /// **WS2b:** NS1 (IBM NS1 Connect) added SVCB/HTTPS support in 2023:
    /// <https://community.ibm.com/community/user/aiops/blogs/shane-kerr/2023/09/27/ibmns1-announces-support-for-svcb-and-https-record>.
    /// IBM's own "Types of DNS records" reference page
    /// (`ibm.com/docs/en/ns1-connect?topic=answers-types-dns-records`) 403s
    /// every automated fetch attempted for this change (a WAF block, not a
    /// missing page), so the exact `answer` shape is pinned instead from a
    /// second, independent, currently-maintained integration against NS1's
    /// real production REST API: DNSControl's NS1 provider
    /// (`providers/ns1/records.go`), whose `dnsv2.TypeSVCB`/`TypeHTTPS` cases
    /// build `Rdata: []string{strconv.Itoa(int(f.Priority)), f.Target,
    /// models.Svcbv2ValueToString(f.Value)}` — i.e. a **3-element**
    /// `[priority, target, joined-SvcParams]` array — using that file's own
    /// `dns.Answer` type, imported from NS1's **own official Go SDK**
    /// (`gopkg.in/ns1/ns1-go.v2/rest/model/dns`, confirmed from that file's
    /// import block), not a third-party model. This adapter always emits the
    /// 3-element form (empty SvcParams become an empty third-element string)
    /// for uniformity with every other multi-field type here, and keeps the
    /// unquoted SvcParams convention (no evidence NS1 requires quoting, unlike
    /// Cloudflare):
    /// <https://github.com/DNSControl/dnscontrol/blob/main/providers/ns1/records.go>.
    fn answer_fields(record: &DnsRecord) -> Vec<serde_json::Value> {
        match &record.kind {
            RecordKind::Cname(target) | RecordKind::Ns(target) | RecordKind::Ptr(target) => {
                vec![serde_json::json!(Self::dotted(target))]
            }
            RecordKind::Mx {
                preference,
                exchange,
            } => vec![
                serde_json::json!(preference),
                serde_json::json!(Self::dotted(exchange)),
            ],
            RecordKind::Srv {
                priority,
                weight,
                port,
                target,
            } => vec![
                serde_json::json!(priority),
                serde_json::json!(weight),
                serde_json::json!(port),
                serde_json::json!(Self::dotted(target)),
            ],
            RecordKind::Caa { flags, tag, value } => vec![
                serde_json::json!(flags),
                serde_json::json!(tag.as_str()),
                serde_json::json!(value),
            ],
            RecordKind::Tlsa {
                usage,
                selector,
                matching,
                data,
            } => vec![
                serde_json::json!(usage),
                serde_json::json!(selector),
                serde_json::json!(matching),
                serde_json::json!(data),
            ],
            RecordKind::Https {
                priority,
                target,
                params,
            }
            | RecordKind::Svcb {
                priority,
                target,
                params,
            } => vec![
                serde_json::json!(priority),
                serde_json::json!(Self::dotted(target)),
                serde_json::json!(Self::svcparams_presentation(params)),
            ],
            _ => vec![serde_json::json!(Self::answer_value(record))],
        }
    }

    /// The JSON body for a create/update of `record` (one answer).
    fn record_body(&self, record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({
            "zone": self.zone,
            "domain": record.name,
            "type": record.kind.as_str(),
            "ttl": record.ttl,
            "answers": [ { "answer": Self::answer_fields(record) } ],
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

    fn supported_kinds(&self) -> &'static [RecordKindTag] {
        // WS2b: NS1 (IBM NS1 Connect) added HTTPS/SVCB support in 2023 — see
        // `answer_fields`'s doc comment for the pinned 3-element answer
        // shape + sources.
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
        "ns1"
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
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.deploy.example.com".into(),
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
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.deploy.example.com".into(),
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
            kind: RecordKind::Cname("lb.example.net".into()),
            name: "*.deploy.example.com".into(),
            ttl: 120,
        });
        assert_eq!(body["answers"][0]["answer"][0], "lb.example.net.");
    }

    /// Golden: the exact create/update body for every kind, pinning NS1's
    /// `answers: [{answer: [value]}]` wire shape with the full-FQDN `domain`.
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
            serde_json::json!({"zone": "example.com", "domain": "deploy.example.com", "type": "A", "ttl": 60, "answers": [{"answer": ["203.0.113.7"]}]})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Aaaa("2001:db8::1".parse().unwrap()),
                "deploy.example.com",
                60
            )),
            serde_json::json!({"zone": "example.com", "domain": "deploy.example.com", "type": "AAAA", "ttl": 60, "answers": [{"answer": ["2001:db8::1"]}]})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Cname("lb.example.net".into()),
                "www.example.com",
                300
            )),
            serde_json::json!({"zone": "example.com", "domain": "www.example.com", "type": "CNAME", "ttl": 300, "answers": [{"answer": ["lb.example.net."]}]})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Txt(vec!["tok".into()]),
                "_acme-challenge.example.com",
                60
            )),
            serde_json::json!({"zone": "example.com", "domain": "_acme-challenge.example.com", "type": "TXT", "ttl": 60, "answers": [{"answer": ["tok"]}]})
        );
    }

    /// Golden: the WS2 record types NS1 declares support for — multi-field
    /// RDATA (MX/SRV/CAA/TLSA) is each field as its own `answer` array element.
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
            serde_json::json!({"zone": "example.com", "domain": "example.com", "type": "MX", "ttl": 300, "answers": [{"answer": [10, "mx.example.com."]}]})
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
            serde_json::json!({"zone": "example.com", "domain": "_svc._tcp.example.com", "type": "SRV", "ttl": 300, "answers": [{"answer": [1, 5, 443, "svc.example.com."]}]})
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
            serde_json::json!({"zone": "example.com", "domain": "example.com", "type": "CAA", "ttl": 300, "answers": [{"answer": [0, "issue", "letsencrypt.org"]}]})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Ns("ns1.example.net".into()),
                "sub.example.com",
                3600
            )),
            serde_json::json!({"zone": "example.com", "domain": "sub.example.com", "type": "NS", "ttl": 3600, "answers": [{"answer": ["ns1.example.net."]}]})
        );
        assert_eq!(
            p.record_body(&rec(
                RecordKind::Ptr("host.example.com".into()),
                "7.113.0.203.in-addr.arpa",
                3600
            )),
            serde_json::json!({"zone": "example.com", "domain": "7.113.0.203.in-addr.arpa", "type": "PTR", "ttl": 3600, "answers": [{"answer": ["host.example.com."]}]})
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
            serde_json::json!({"zone": "example.com", "domain": "_443._tcp.example.com", "type": "TLSA", "ttl": 300, "answers": [{"answer": [3, 1, 1, "abcdef"]}]})
        );
    }

    /// Golden (WS2b): NS1's HTTPS/SVCB `answer` — a 3-element positional array
    /// `[priority, dotted target, SvcParams-string]` (empty SvcParams become
    /// an empty third element), unquoted like every other adapter's SvcParams
    /// rendering except Cloudflare's. Pinned against the sources cited in
    /// `answer_fields`'s doc comment.
    #[test]
    fn record_body_golden_for_https_svcb() {
        let p = provider();
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
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
                3600
            )),
            serde_json::json!({"zone": "example.com", "domain": "example.com", "type": "HTTPS", "ttl": 3600, "answers": [{"answer": [1, ".", "alpn=h2,h3"]}]})
        );
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
            serde_json::json!({"zone": "example.com", "domain": "_8443._tcp.example.com", "type": "SVCB", "ttl": 300, "answers": [{"answer": [0, "svc.example.net.", ""]}]})
        );
    }

    /// NS1 now declares HTTPS/SVCB support (WS2b).
    #[test]
    fn supported_kinds_includes_https_svcb() {
        let p = provider();
        for tag in [RecordKindTag::Https, RecordKindTag::Svcb] {
            assert!(p.supports_kind(tag), "ns1 should support {tag}");
        }
    }
}
