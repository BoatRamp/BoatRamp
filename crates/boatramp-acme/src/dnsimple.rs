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

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind};

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

    /// `CNAME` content is a FQDN with a trailing dot; other kinds take the raw value.
    fn record_content(record: &DnsRecord) -> String {
        match record.kind {
            RecordKind::Cname if !record.value.ends_with('.') => format!("{}.", record.value),
            _ => record.value.clone(),
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
            RecordKind::Txt | RecordKind::A | RecordKind::Aaaa
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
            kind: RecordKind::Txt,
            name: "_acme-challenge.deploy.example.com".into(),
            value: "abc".into(),
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
            kind: RecordKind::Cname,
            name: "*.deploy.example.com".into(),
            value: "lb.example.net".into(),
            ttl: 120,
        });
        assert_eq!(body["content"], "lb.example.net.");
    }
}
