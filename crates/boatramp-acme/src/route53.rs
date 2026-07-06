//! AWS Route 53 DNS provider.
//!
//! Uses `ChangeResourceRecordSets` with `UPSERT` (create-or-replace, natively
//! idempotent) and `DELETE`. Credentials + region come from the standard AWS
//! provider chain (`aws-config`). The value/type mapping (notably Route 53's
//! requirement that `TXT` values be quoted) is pure + unit-tested; the SDK call
//! is the live integration seam.

use async_trait::async_trait;
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
};
use aws_sdk_route53::Client;

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
            .r#type(rr_type(record.kind))
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
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }
}

/// Map a [`RecordKind`] to the Route 53 record type.
fn rr_type(kind: RecordKind) -> RrType {
    match kind {
        RecordKind::A => RrType::A,
        RecordKind::Aaaa => RrType::Aaaa,
        RecordKind::Cname => RrType::Cname,
        RecordKind::Txt => RrType::Txt,
    }
}

/// The resource-record value. Route 53 requires `TXT` values be enclosed in
/// double quotes; address/CNAME values are passed verbatim.
fn rr_value(record: &DnsRecord) -> String {
    match record.kind {
        RecordKind::Txt => format!("\"{}\"", record.value.replace('"', "\\\"")),
        _ => record.value.clone(),
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
            Ok(()) => Ok(()),
            Err(DnsError::Backend(msg)) if msg.contains("not found") || msg.contains("NoSuch") => {
                Ok(())
            }
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_values_are_quoted_others_verbatim() {
        let txt = DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        };
        assert_eq!(rr_value(&txt), "\"abc\"");

        let a = DnsRecord {
            kind: RecordKind::A,
            name: "*.deploy.example.com".into(),
            value: "203.0.113.7".into(),
            ttl: 120,
        };
        assert_eq!(rr_value(&a), "203.0.113.7");
    }

    #[test]
    fn record_kind_maps_to_rr_type() {
        assert_eq!(rr_type(RecordKind::A), RrType::A);
        assert_eq!(rr_type(RecordKind::Aaaa), RrType::Aaaa);
        assert_eq!(rr_type(RecordKind::Cname), RrType::Cname);
        assert_eq!(rr_type(RecordKind::Txt), RrType::Txt);
    }
}
