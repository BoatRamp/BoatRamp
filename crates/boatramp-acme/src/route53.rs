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

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind};

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
            .r#type(rr_type(&record.kind)?)
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

/// Map a [`RecordKind`] to the Route 53 record type. WS1: only the original
/// writable set maps; a newly-modeled type is refused (the central
/// [`crate::dns::validate_writable`] guardrail catches it first, but this keeps
/// the adapter honest if called directly).
fn rr_type(kind: &RecordKind) -> Result<RrType, DnsError> {
    Ok(match kind {
        RecordKind::A(_) => RrType::A,
        RecordKind::Aaaa(_) => RrType::Aaaa,
        RecordKind::Cname(_) => RrType::Cname,
        RecordKind::Txt(_) => RrType::Txt,
        other => {
            return Err(DnsError::UnsupportedRecordType {
                provider: "route53",
                kind: other.tag(),
            });
        }
    })
}

/// The resource-record value. Route 53 requires `TXT` values be enclosed in
/// double quotes; address/CNAME values are passed verbatim.
fn rr_value(record: &DnsRecord) -> String {
    let value = record.kind.flat_value();
    if matches!(record.kind, RecordKind::Txt(_)) {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value
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
            rr_type(&RecordKind::A("203.0.113.7".parse().unwrap())).unwrap(),
            RrType::A
        );
        assert_eq!(
            rr_type(&RecordKind::Aaaa("2001:db8::1".parse().unwrap())).unwrap(),
            RrType::Aaaa
        );
        assert_eq!(
            rr_type(&RecordKind::Cname("app.fly.dev".into())).unwrap(),
            RrType::Cname
        );
        assert_eq!(
            rr_type(&RecordKind::Txt(vec!["tok".into()])).unwrap(),
            RrType::Txt
        );
        // A newly-modeled type is refused by the adapter's type mapping.
        assert!(matches!(
            rr_type(&RecordKind::Mx {
                preference: 10,
                exchange: "mx.example.com".into()
            }),
            Err(DnsError::UnsupportedRecordType {
                kind: crate::dns::RecordKindTag::Mx,
                ..
            })
        ));
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
}
