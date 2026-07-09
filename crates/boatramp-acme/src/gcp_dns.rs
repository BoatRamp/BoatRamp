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

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind};

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

    /// The single-element rrdata list for `record`: TXT is double-quoted, CNAME is
    /// a trailing-dot FQDN, A/AAAA are the raw address.
    fn rrdatas(record: &DnsRecord) -> Vec<String> {
        let value = match record.kind {
            RecordKind::Txt => format!("\"{}\"", record.value),
            RecordKind::Cname => Self::fqdn(&record.value),
            _ => record.value.clone(),
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
        if let Some(cur) = &current {
            if cur.get("ttl") == desired.get("ttl") && cur.get("rrdatas") == desired.get("rrdatas")
            {
                return Ok(());
            }
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
            kind: RecordKind::Txt,
            name: "_acme-challenge.deploy.example.com".into(),
            value: "abc".into(),
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
            kind: RecordKind::Cname,
            name: "*.deploy.example.com".into(),
            value: "lb.example.net".into(),
            ttl: 120,
        });
        assert_eq!(rr["name"], "*.deploy.example.com.");
        assert_eq!(rr["rrdatas"][0], "lb.example.net.");
    }

    #[test]
    fn address_rrdata_is_raw() {
        let rr = provider().rrset(&DnsRecord {
            kind: RecordKind::A,
            name: "deploy.example.com".into(),
            value: "203.0.113.7".into(),
            ttl: 60,
        });
        assert_eq!(rr["rrdatas"][0], "203.0.113.7");
    }
}
