//! Google Cloud DNS provider (v1 REST, OAuth2 bearer token).
//!
//! Cloud DNS edits are atomic **changes** (a batch of `additions` + `deletions`
//! posted to `…/changes`) with no in-place update: to replace a record set you
//! delete the current one — by its *exact* current object — and add the new one
//! in the same change, so `upsert` first reads the current rrset. Two format
//! rules the helpers encode: names are FQDNs with a trailing dot, and TXT rrdata
//! is double-quoted. The access token comes from the environment
//! (`GCP_ACCESS_TOKEN`), matching the KMS signer — no embedded SDK credential
//! flow. Request construction is pure + unit-tested; the round-trip is a live seam.

use async_trait::async_trait;
use serde::Deserialize;

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind, RecordKindTag};

const DEFAULT_API_BASE: &str = "https://dns.googleapis.com/dns/v1";

/// A Google Cloud DNS editor scoped to one managed zone.
pub struct GcpDns {
    client: reqwest::Client,
    api_base: String,
    token: String,
    project: String,
    zone: String,
}

impl GcpDns {
    /// Build a provider for `project` + managed `zone`, authenticating with an
    /// OAuth2 access token scoped for Cloud DNS.
    pub fn new(
        project: impl Into<String>,
        zone: impl Into<String>,
        token: impl Into<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            token: token.into(),
            project: project.into(),
            zone: zone.into(),
        }
    }

    /// Override the API base URL (for pointing tests at a stub).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// A name as an FQDN with the trailing dot Cloud DNS requires.
    fn fqdn(name: &str) -> String {
        if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        }
    }

    /// A SvcParam list rendered as RFC 9460 presentation-form tokens
    /// (`key=value`, or a bare `key` when the value is empty), space-joined —
    /// Cloud DNS's HTTPS/SVCB rrdata takes the whole SvcParams set this way (see
    /// `rrdatas`'s doc comment for the reference).
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

    /// The single-element rrdata list for `record`, in the RFC 1035 master-file
    /// presentation format Cloud DNS expects: TXT is double-quoted, CNAME/NS/PTR
    /// targets and MX/SRV's name fields are trailing-dot FQDNs, CAA/TLSA are
    /// space-joined field strings, A/AAAA are the raw address. **WS2b:**
    /// HTTPS/SVCB are `"<priority> <dotted target> SvcParams..."` — Cloud DNS's
    /// "Supported DNS record types" reference confirms HTTPS "is based on the
    /// more general SVCB record type and uses the same value format," both
    /// rendered as `SvcPriority TargetName SvcParams`:
    /// <https://cloud.google.com/dns/docs/records-overview>.
    fn rrdatas(record: &DnsRecord) -> Vec<String> {
        let value = match &record.kind {
            RecordKind::Txt(_) => format!("\"{}\"", record.kind.flat_value()),
            RecordKind::Cname(target) | RecordKind::Ns(target) | RecordKind::Ptr(target) => {
                Self::fqdn(target)
            }
            RecordKind::Mx {
                preference,
                exchange,
            } => format!("{preference} {}", Self::fqdn(exchange)),
            RecordKind::Srv {
                priority,
                weight,
                port,
                target,
            } => format!("{priority} {weight} {port} {}", Self::fqdn(target)),
            RecordKind::Caa { flags, tag, value } => {
                // LOW-5: escape embedded `\` and `"` in the quoted value, consistent with
                // Route53/Hetzner (correctness — serde escapes it in transport regardless).
                let value = value.replace('\\', "\\\\").replace('"', "\\\"");
                format!("{flags} {tag} \"{value}\"")
            }
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
                let target = Self::fqdn(target);
                if svcparams.is_empty() {
                    format!("{priority} {target}")
                } else {
                    format!("{priority} {target} {svcparams}")
                }
            }
            _ => record.kind.flat_value(),
        };
        vec![value]
    }

    /// The rrset object for `record` (an `additions` entry).
    fn rrset(&self, record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({
            "name": Self::fqdn(&record.name),
            "type": record.kind.as_str(),
            "ttl": record.ttl,
            "rrdatas": Self::rrdatas(record),
        })
    }

    fn changes_url(&self) -> String {
        format!(
            "{}/projects/{}/managedZones/{}/changes",
            self.api_base, self.project, self.zone
        )
    }

    fn rrsets_url(&self) -> String {
        format!(
            "{}/projects/{}/managedZones/{}/rrsets",
            self.api_base, self.project, self.zone
        )
    }

    /// The current rrset object for `(name, type)`, if any — needed verbatim as
    /// the `deletions` entry when replacing.
    async fn current_rrset(
        &self,
        record: &DnsRecord,
    ) -> Result<Option<serde_json::Value>, DnsError> {
        let resp = self
            .client
            .get(self.rrsets_url())
            .bearer_auth(&self.token)
            .query(&[
                ("name", Self::fqdn(&record.name)),
                ("type", record.kind.as_str().to_string()),
            ])
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let body: RrsetsResponse = resp
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .json()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(body.rrsets.into_iter().next())
    }

    async fn post_change(&self, change: serde_json::Value) -> Result<(), DnsError> {
        self.client
            .post(self.changes_url())
            .bearer_auth(&self.token)
            .json(&change)
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }
}

#[derive(Deserialize)]
struct RrsetsResponse {
    #[serde(default)]
    rrsets: Vec<serde_json::Value>,
}

#[async_trait]
impl DnsProvider for GcpDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let desired = self.rrset(record);
        let current = self.current_rrset(record).await?;
        // Already correct (same ttl + rrdatas) → a no-op change would be rejected.
        if let Some(cur) = &current
            && cur.get("ttl") == desired.get("ttl")
            && cur.get("rrdatas") == desired.get("rrdatas")
        {
            return Ok(());
        }
        let change = serde_json::json!({
            "additions": [desired],
            "deletions": current.into_iter().collect::<Vec<_>>(),
        });
        self.post_change(change).await
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let Some(current) = self.current_rrset(record).await? else {
            return Ok(()); // already gone
        };
        self.post_change(serde_json::json!({ "deletions": [current] }))
            .await
    }

    fn supported_kinds(&self) -> &'static [RecordKindTag] {
        // WS2b: Cloud DNS's "Supported DNS record types" reference
        // (https://cloud.google.com/dns/docs/records-overview) lists HTTPS and
        // SVCB alongside MX/SRV/CAA/NS/PTR/TLSA — see `rrdatas`'s doc comment
        // for the pinned rrdata encoding.
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
        "gcp"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> GcpDns {
        GcpDns::new("proj", "zone1", "tok").with_api_base("https://gcp.test/dns/v1")
    }

    #[test]
    fn changes_url_is_zone_scoped() {
        assert_eq!(
            provider().changes_url(),
            "https://gcp.test/dns/v1/projects/proj/managedZones/zone1/changes"
        );
    }

    #[test]
    fn txt_rrset_is_dotted_and_quoted() {
        let rr = provider().rrset(&DnsRecord {
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.deploy.example.com".into(),
            ttl: 60,
        });
        assert_eq!(rr["name"], "_acme-challenge.deploy.example.com.");
        assert_eq!(rr["type"], "TXT");
        assert_eq!(rr["ttl"], 60);
        assert_eq!(rr["rrdatas"][0], "\"abc\"");
    }

    #[test]
    fn cname_rrdata_is_a_dotted_fqdn() {
        let rr = provider().rrset(&DnsRecord {
            kind: RecordKind::Cname("lb.example.net".into()),
            name: "*.deploy.example.com".into(),
            ttl: 120,
        });
        assert_eq!(rr["name"], "*.deploy.example.com.");
        assert_eq!(rr["rrdatas"][0], "lb.example.net.");
    }

    #[test]
    fn address_rrdata_is_raw() {
        let rr = provider().rrset(&DnsRecord {
            kind: RecordKind::A("203.0.113.7".parse().unwrap()),
            name: "deploy.example.com".into(),
            ttl: 60,
        });
        assert_eq!(rr["rrdatas"][0], "203.0.113.7");
    }

    /// Golden: the exact `rrset` object for every kind, pinning GCP's FQDN-with-dot
    /// name, quoted-TXT, dotted-CNAME `rrdatas` wire shape.
    #[test]
    fn rrset_golden_for_every_kind() {
        let p = provider();
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        assert_eq!(
            p.rrset(&rec(
                RecordKind::A("203.0.113.7".parse().unwrap()),
                "deploy.example.com",
                60
            )),
            serde_json::json!({"name": "deploy.example.com.", "type": "A", "ttl": 60, "rrdatas": ["203.0.113.7"]})
        );
        assert_eq!(
            p.rrset(&rec(
                RecordKind::Aaaa("2001:db8::1".parse().unwrap()),
                "deploy.example.com",
                60
            )),
            serde_json::json!({"name": "deploy.example.com.", "type": "AAAA", "ttl": 60, "rrdatas": ["2001:db8::1"]})
        );
        assert_eq!(
            p.rrset(&rec(
                RecordKind::Cname("lb.example.net".into()),
                "www.example.com",
                300
            )),
            serde_json::json!({"name": "www.example.com.", "type": "CNAME", "ttl": 300, "rrdatas": ["lb.example.net."]})
        );
        assert_eq!(
            p.rrset(&rec(
                RecordKind::Txt(vec!["tok".into()]),
                "_acme-challenge.example.com",
                60
            )),
            serde_json::json!({"name": "_acme-challenge.example.com.", "type": "TXT", "ttl": 60, "rrdatas": ["\"tok\""]})
        );
    }

    /// Golden: the WS2 record types GCP declares support for.
    #[test]
    fn rrset_golden_for_ws2_kinds() {
        let p = provider();
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        assert_eq!(
            p.rrset(&rec(
                RecordKind::Mx {
                    preference: 10,
                    exchange: "mx.example.com".into(),
                },
                "example.com",
                300
            )),
            serde_json::json!({"name": "example.com.", "type": "MX", "ttl": 300, "rrdatas": ["10 mx.example.com."]})
        );
        assert_eq!(
            p.rrset(&rec(
                RecordKind::Srv {
                    priority: 1,
                    weight: 5,
                    port: 443,
                    target: "svc.example.com".into(),
                },
                "_svc._tcp.example.com",
                300
            )),
            serde_json::json!({"name": "_svc._tcp.example.com.", "type": "SRV", "ttl": 300, "rrdatas": ["1 5 443 svc.example.com."]})
        );
        assert_eq!(
            p.rrset(&rec(
                RecordKind::Caa {
                    flags: 0,
                    tag: crate::dns::CaaTag::Issue,
                    value: "letsencrypt.org".into(),
                },
                "example.com",
                300
            )),
            serde_json::json!({"name": "example.com.", "type": "CAA", "ttl": 300, "rrdatas": ["0 issue \"letsencrypt.org\""]})
        );
        assert_eq!(
            p.rrset(&rec(
                RecordKind::Ns("ns1.example.net".into()),
                "sub.example.com",
                3600
            )),
            serde_json::json!({"name": "sub.example.com.", "type": "NS", "ttl": 3600, "rrdatas": ["ns1.example.net."]})
        );
        assert_eq!(
            p.rrset(&rec(
                RecordKind::Ptr("host.example.com".into()),
                "7.113.0.203.in-addr.arpa",
                3600
            )),
            serde_json::json!({"name": "7.113.0.203.in-addr.arpa.", "type": "PTR", "ttl": 3600, "rrdatas": ["host.example.com."]})
        );
        assert_eq!(
            p.rrset(&rec(
                RecordKind::Tlsa {
                    usage: 3,
                    selector: 1,
                    matching: 1,
                    data: "abcdef".into(),
                },
                "_443._tcp.example.com",
                300
            )),
            serde_json::json!({"name": "_443._tcp.example.com.", "type": "TLSA", "ttl": 300, "rrdatas": ["3 1 1 abcdef"]})
        );
    }

    /// Golden (WS2b): Cloud DNS's HTTPS/SVCB rrdata — `"<priority> <dotted
    /// target> SvcParams..."`, the same presentation form as every other
    /// name-bearing rrdata in this adapter. Pinned against the API reference
    /// cited in `rrdatas`'s doc comment.
    #[test]
    fn rrset_golden_for_https_svcb() {
        let p = provider();
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        assert_eq!(
            p.rrset(&rec(
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
            serde_json::json!({"name": "example.com.", "type": "HTTPS", "ttl": 3600, "rrdatas": ["1 . alpn=h2,h3"]})
        );
        assert_eq!(
            p.rrset(&rec(
                RecordKind::Svcb {
                    priority: 0,
                    target: "svc.example.net".into(),
                    params: vec![],
                },
                "_8443._tcp.example.com",
                300
            )),
            serde_json::json!({"name": "_8443._tcp.example.com.", "type": "SVCB", "ttl": 300, "rrdatas": ["0 svc.example.net."]})
        );
    }

    /// LOW-5: a CAA value with an embedded `"`/`\` is escaped in the quoted
    /// rrdata string (consistent with Route53/Hetzner).
    #[test]
    fn caa_rrdata_escapes_embedded_quote_and_backslash() {
        assert_eq!(
            GcpDns::rrdatas(&DnsRecord {
                kind: RecordKind::Caa {
                    flags: 0,
                    tag: crate::dns::CaaTag::Iodef,
                    value: "mailto:a\"b\\c".into(),
                },
                name: "example.com".into(),
                ttl: 300,
            }),
            vec!["0 iodef \"mailto:a\\\"b\\\\c\"".to_string()]
        );
    }

    /// Cloud DNS now declares HTTPS/SVCB support (WS2b).
    #[test]
    fn supported_kinds_includes_https_svcb() {
        let p = provider();
        for tag in [RecordKindTag::Https, RecordKindTag::Svcb] {
            assert!(p.supports_kind(tag), "gcp should support {tag}");
        }
    }
}
