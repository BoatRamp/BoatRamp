//! AWS Route 53 DNS provider.
//!
//! Uses `ChangeResourceRecordSets` with `UPSERT` (create-or-replace, natively
//! idempotent) and `DELETE`. Credentials + region come from the standard AWS
//! provider chain (`aws-config`). The value/type mapping (notably Route 53's
//! requirement that `TXT` values be quoted) is pure + unit-tested; the SDK call
//! is the live integration seam.

use async_trait::async_trait;
use aws_sdk_route53::Client;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
};

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind, RecordKindTag};

/// A Route 53 editor scoped to one hosted zone.
pub struct Route53Dns {
    client: Client,
    hosted_zone_id: String,
}

impl Route53Dns {
    /// Build from the ambient AWS config (env / profile / IMDS) for the given
    /// hosted zone id (e.g. `Z123EXAMPLE`).
    pub async fn from_env(hosted_zone_id: impl Into<String>) -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Self {
            client: Client::new(&config),
            hosted_zone_id: hosted_zone_id.into(),
        }
    }

    /// Build over an existing client (tests / custom config).
    pub fn with_client(client: Client, hosted_zone_id: impl Into<String>) -> Self {
        Self {
            client,
            hosted_zone_id: hosted_zone_id.into(),
        }
    }

    async fn change(&self, action: ChangeAction, record: &DnsRecord) -> Result<(), DnsError> {
        let rr = ResourceRecord::builder()
            .value(rr_value(record))
            .build()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let rrset = ResourceRecordSet::builder()
            .name(&record.name)
            .r#type(rr_type(&record.kind))
            .ttl(record.ttl as i64)
            .resource_records(rr)
            .build()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let change = Change::builder()
            .action(action)
            .resource_record_set(rrset)
            .build()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        self.client
            .change_resource_record_sets()
            .hosted_zone_id(&self.hosted_zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(|e| {
                // Route 53 signals "delete of an absent record" via an
                // `InvalidChangeBatch` message; recognize it at this boundary so
                // callers get a typed `DnsError::NotFound` instead of having to
                // string-match a `Backend` message.
                let msg = e.to_string();
                if msg.contains("not found") || msg.contains("NoSuch") {
                    DnsError::NotFound
                } else {
                    DnsError::Backend(msg)
                }
            })?;
        Ok(())
    }
}

/// Map a [`RecordKind`] to the Route 53 record type. **WS2: total** — the
/// `aws-sdk-route53` `RrType` enum has a variant for every Tier-1/Tier-2 kind
/// (confirmed directly from the SDK's generated model, not just docs: `A`,
/// `Aaaa`, `Caa`, `Cname`, `Https`, `Mx`, `Ns`, `Ptr`, `Srv`, `Svcb`, `Tlsa`,
/// `Txt`), so Route 53 is the one adapter with zero per-type guesswork — AWS's
/// own SDK model is the evidence, not inference from public docs.
fn rr_type(kind: &RecordKind) -> RrType {
    match kind {
        RecordKind::A(_) => RrType::A,
        RecordKind::Aaaa(_) => RrType::Aaaa,
        RecordKind::Cname(_) => RrType::Cname,
        RecordKind::Txt(_) => RrType::Txt,
        RecordKind::Mx { .. } => RrType::Mx,
        RecordKind::Srv { .. } => RrType::Srv,
        RecordKind::Caa { .. } => RrType::Caa,
        RecordKind::Https { .. } => RrType::Https,
        RecordKind::Svcb { .. } => RrType::Svcb,
        RecordKind::Ns(_) => RrType::Ns,
        RecordKind::Ptr(_) => RrType::Ptr,
        RecordKind::Tlsa { .. } => RrType::Tlsa,
    }
}

/// A SvcParam list rendered as RFC 9460 presentation-form tokens
/// (`key=value`, or a bare `key` when the value is empty), space-joined —
/// shared by the `Https`/`Svcb` resource-record value below.
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

/// The resource-record value, in the RFC 1035 master-file presentation format
/// Route 53 expects for every type. `TXT` and `CAA`'s string field are quoted
/// (Route 53 requires it); address/CNAME/NS/PTR values are passed verbatim.
fn rr_value(record: &DnsRecord) -> String {
    match &record.kind {
        RecordKind::A(_) | RecordKind::Aaaa(_) | RecordKind::Cname(_) => record.kind.flat_value(),
        RecordKind::Txt(_) => {
            let value = record.kind.flat_value();
            format!("\"{}\"", value.replace('"', "\\\""))
        }
        RecordKind::Mx {
            preference,
            exchange,
        } => format!("{preference} {exchange}"),
        RecordKind::Srv {
            priority,
            weight,
            port,
            target,
        } => format!("{priority} {weight} {port} {target}"),
        RecordKind::Caa { flags, tag, value } => {
            format!("{flags} {tag} \"{}\"", value.replace('"', "\\\""))
        }
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
            let svcparams = svcparams_presentation(params);
            if svcparams.is_empty() {
                format!("{priority} {target}")
            } else {
                format!("{priority} {target} {svcparams}")
            }
        }
        RecordKind::Ns(target) | RecordKind::Ptr(target) => target.clone(),
        RecordKind::Tlsa {
            usage,
            selector,
            matching,
            data,
        } => format!("{usage} {selector} {matching} {data}"),
    }
}

#[async_trait]
impl DnsProvider for Route53Dns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        self.change(ChangeAction::Upsert, record).await
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        // DELETE must match the exact record set; absent → treat as success.
        match self.change(ChangeAction::Delete, record).await {
            Ok(()) | Err(DnsError::NotFound) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn supported_kinds(&self) -> &'static [RecordKindTag] {
        // AWS's own SDK model supports every Tier-1/Tier-2 kind (see `rr_type`).
        &[
            RecordKindTag::A,
            RecordKindTag::Aaaa,
            RecordKindTag::Cname,
            RecordKindTag::Txt,
            RecordKindTag::Mx,
            RecordKindTag::Srv,
            RecordKindTag::Caa,
            RecordKindTag::Https,
            RecordKindTag::Svcb,
            RecordKindTag::Ns,
            RecordKindTag::Ptr,
            RecordKindTag::Tlsa,
        ]
    }

    fn name(&self) -> &'static str {
        "route53"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_values_are_quoted_others_verbatim() {
        let txt = DnsRecord {
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.example.com".into(),
            ttl: 60,
        };
        assert_eq!(rr_value(&txt), "\"abc\"");

        let a = DnsRecord {
            kind: RecordKind::A("203.0.113.7".parse().unwrap()),
            name: "*.deploy.example.com".into(),
            ttl: 120,
        };
        assert_eq!(rr_value(&a), "203.0.113.7");
    }

    #[test]
    fn record_kind_maps_to_rr_type() {
        assert_eq!(
            rr_type(&RecordKind::A("203.0.113.7".parse().unwrap())),
            RrType::A
        );
        assert_eq!(
            rr_type(&RecordKind::Aaaa("2001:db8::1".parse().unwrap())),
            RrType::Aaaa
        );
        assert_eq!(
            rr_type(&RecordKind::Cname("app.fly.dev".into())),
            RrType::Cname
        );
        assert_eq!(rr_type(&RecordKind::Txt(vec!["tok".into()])), RrType::Txt);
        // WS2: every Tier-1/Tier-2 kind now maps — the AWS SDK's RrType enum has
        // a variant for each (see `rr_type`'s doc comment).
        assert_eq!(
            rr_type(&RecordKind::Mx {
                preference: 10,
                exchange: "mx.example.com".into()
            }),
            RrType::Mx
        );
        assert_eq!(
            rr_type(&RecordKind::Srv {
                priority: 1,
                weight: 5,
                port: 443,
                target: "svc.example.com".into(),
            }),
            RrType::Srv
        );
        assert_eq!(
            rr_type(&RecordKind::Caa {
                flags: 0,
                tag: crate::dns::CaaTag::Issue,
                value: "letsencrypt.org".into(),
            }),
            RrType::Caa
        );
        assert_eq!(
            rr_type(&RecordKind::Https {
                priority: 1,
                target: ".".into(),
                params: vec![],
            }),
            RrType::Https
        );
        assert_eq!(
            rr_type(&RecordKind::Svcb {
                priority: 1,
                target: "svc.example.net".into(),
                params: vec![],
            }),
            RrType::Svcb
        );
        assert_eq!(
            rr_type(&RecordKind::Ns("ns1.example.net".into())),
            RrType::Ns
        );
        assert_eq!(
            rr_type(&RecordKind::Ptr("host.example.com".into())),
            RrType::Ptr
        );
        assert_eq!(
            rr_type(&RecordKind::Tlsa {
                usage: 3,
                selector: 1,
                matching: 1,
                data: "abcdef".into(),
            }),
            RrType::Tlsa
        );
    }

    /// Golden: the exact resource-record value for every kind. Route 53 passes
    /// address/CNAME values verbatim and wraps TXT in double quotes (escaping any
    /// embedded quote) — the one Route 53-specific transform, pinned here.
    #[test]
    fn rr_value_golden_for_every_kind() {
        let rec = |kind| DnsRecord {
            kind,
            name: "x.example.com".into(),
            ttl: 60,
        };
        assert_eq!(
            rr_value(&rec(RecordKind::A("203.0.113.7".parse().unwrap()))),
            "203.0.113.7"
        );
        assert_eq!(
            rr_value(&rec(RecordKind::Aaaa("2001:db8::1".parse().unwrap()))),
            "2001:db8::1"
        );
        assert_eq!(
            rr_value(&rec(RecordKind::Cname("app.fly.dev".into()))),
            "app.fly.dev"
        );
        assert_eq!(
            rr_value(&rec(RecordKind::Txt(vec!["tok".into()]))),
            "\"tok\""
        );
        // An embedded quote is backslash-escaped inside the Route 53 quoting.
        assert_eq!(
            rr_value(&rec(RecordKind::Txt(vec!["a\"b".into()]))),
            "\"a\\\"b\""
        );
    }

    /// Golden: the exact resource-record value for every WS2 kind, in the RFC
    /// 1035 master-file presentation format Route 53 expects.
    #[test]
    fn rr_value_golden_for_ws2_kinds() {
        let rec = |kind| DnsRecord {
            kind,
            name: "x.example.com".into(),
            ttl: 60,
        };
        assert_eq!(
            rr_value(&rec(RecordKind::Mx {
                preference: 10,
                exchange: "mx.example.com".into(),
            })),
            "10 mx.example.com"
        );
        assert_eq!(
            rr_value(&rec(RecordKind::Srv {
                priority: 1,
                weight: 5,
                port: 443,
                target: "svc.example.com".into(),
            })),
            "1 5 443 svc.example.com"
        );
        assert_eq!(
            rr_value(&rec(RecordKind::Caa {
                flags: 0,
                tag: crate::dns::CaaTag::Issue,
                value: "letsencrypt.org".into(),
            })),
            "0 issue \"letsencrypt.org\""
        );
        assert_eq!(
            rr_value(&rec(RecordKind::Https {
                priority: 1,
                target: ".".into(),
                params: vec![crate::dns::SvcParam {
                    key: "alpn".into(),
                    value: "h2,h3".into(),
                }],
            })),
            "1 . alpn=h2,h3"
        );
        assert_eq!(
            rr_value(&rec(RecordKind::Svcb {
                priority: 0,
                target: "svc.example.net".into(),
                params: vec![],
            })),
            "0 svc.example.net"
        );
        assert_eq!(
            rr_value(&rec(RecordKind::Ns("ns1.example.net".into()))),
            "ns1.example.net"
        );
        assert_eq!(
            rr_value(&rec(RecordKind::Ptr("host.example.com".into()))),
            "host.example.com"
        );
        assert_eq!(
            rr_value(&rec(RecordKind::Tlsa {
                usage: 3,
                selector: 1,
                matching: 1,
                data: "abcdef".into(),
            })),
            "3 1 1 abcdef"
        );
    }

    /// Route 53 declares every Tier-1/Tier-2 kind supported.
    #[test]
    fn supported_kinds_is_everything() {
        let config = aws_sdk_route53::Config::builder()
            .behavior_version(aws_sdk_route53::config::BehaviorVersion::latest())
            .region(aws_sdk_route53::config::Region::new("us-east-1"))
            .build();
        let p = Route53Dns::with_client(aws_sdk_route53::Client::from_conf(config), "Z1");
        for tag in [
            RecordKindTag::A,
            RecordKindTag::Aaaa,
            RecordKindTag::Cname,
            RecordKindTag::Txt,
            RecordKindTag::Mx,
            RecordKindTag::Srv,
            RecordKindTag::Caa,
            RecordKindTag::Https,
            RecordKindTag::Svcb,
            RecordKindTag::Ns,
            RecordKindTag::Ptr,
            RecordKindTag::Tlsa,
        ] {
            assert!(p.supports_kind(tag), "route53 should support {tag}");
        }
    }
}
