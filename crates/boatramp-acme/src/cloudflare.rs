//! Cloudflare DNS provider (API v4, token auth).
//!
//! Upsert is create-or-replace: list the records of that `(type, name)`, then
//! `PUT` the first match or `POST` a new one. The request **construction**
//! (URLs, JSON bodies) is factored into pure helpers and unit-tested; the
//! send/parse round-trip is exercised against a live zone (the documented
//! integration seam — no Cloudflare account in CI).

use std::collections::HashSet;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::Deserialize;

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind, RecordKindTag};

const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// A SvcParam list rendered as Cloudflare's `data.value` wants it: space-joined
/// `key="value"` tokens (value **double-quoted**), or a bare `key` when the
/// value is empty. Unlike route53's unquoted convention, Cloudflare's own
/// OpenAPI schema example quotes every param value —
/// `alpn="h3,h2" ipv4hint="127.0.0.1" ipv6hint="::1"` (`dns-records_HTTPSRecord`
/// / `dns-records_SVCBRecord` in
/// <https://github.com/cloudflare/api-schemas/blob/main/openapi.json>) — see
/// `record_body`'s doc comment for the full reference.
fn svcparams_presentation(params: &[crate::dns::SvcParam]) -> String {
    params
        .iter()
        .map(|p| {
            if p.value.is_empty() {
                p.key.clone()
            } else {
                format!("{}=\"{}\"", p.key, p.value)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// A Cloudflare zone editor scoped to one zone.
pub struct CloudflareDns {
    client: reqwest::Client,
    api_base: String,
    token: String,
    zone_id: String,
    /// Proxy address/CNAME records through Cloudflare (orange-cloud). Per
    /// provider instance, so it is set per-invocation (e.g. `dns
    /// configure-domain --proxied`) — never globally; TXT is never proxied.
    proxied: bool,
    /// The Cloudflare record ids THIS instance created via
    /// [`create_txt_record`](Self::create_txt_record) while converging a TXT
    /// challenge set (U20). The converge's delete step is scoped to exactly these
    /// ids (F1): it may remove only a record this solver instance itself wrote, so
    /// a concurrent ACME order's challenge value — or any unrelated TXT — at the
    /// same `_acme-challenge.<name>` is never clobbered (that was a
    /// denial-of-issuance). In-memory per instance: after a process restart a new
    /// instance simply never deletes a record it has no record of creating (it
    /// lingers harmlessly), which is the safe failure — never deleting foreign.
    own_created: Mutex<HashSet<String>>,
}

impl CloudflareDns {
    /// Build a provider for `zone_id`, authenticating with an API token that has
    /// `Zone.DNS:Edit` on that zone.
    pub fn new(zone_id: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            token: token.into(),
            zone_id: zone_id.into(),
            proxied: false,
            own_created: Mutex::new(HashSet::new()),
        }
    }

    /// Override the API base URL (for pointing tests/proxies at a stub).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// Proxy this instance's address/CNAME upserts through Cloudflare
    /// (orange-cloud: cache/WAF/edge TLS). TXT records are never proxied.
    pub fn with_proxied(mut self, proxied: bool) -> Self {
        self.proxied = proxied;
        self
    }

    /// `…/zones/{zone}/dns_records` (the collection endpoint).
    fn records_url(&self) -> String {
        format!("{}/zones/{}/dns_records", self.api_base, self.zone_id)
    }

    /// `…/zones/{zone}/ssl/universal/settings` — the zone-wide **Universal SSL**
    /// toggle (Cloudflare's own edge certificate plus the ACME domain-control-validation
    /// TXT records it manages at `_acme-challenge.<zone>`).
    fn universal_ssl_url(&self) -> String {
        format!(
            "{}/zones/{}/ssl/universal/settings",
            self.api_base, self.zone_id
        )
    }

    /// Whether **Universal SSL** is enabled on this zone.
    ///
    /// Why this matters for a wildcard: even on a **DNS-only** (grey-cloud) zone whose
    /// edge certificate is never served, an enabled Universal SSL keeps running its own
    /// domain-control validation, whose managed TXT records at `_acme-challenge.<zone>`
    /// **clobber a wildcard's DNS-01 delegation** (e.g. a fly wildcard cert's
    /// `_acme-challenge.<zone>` CNAME to the ACME provider's nameservers). Let's Encrypt
    /// then reads Cloudflare's tokens instead of the delegated challenge, so the wildcard
    /// never validates and sits "Not verified". Exact-host certs over HTTP-01 are
    /// unaffected — hence a confusing asymmetric failure.
    ///
    /// `GET` → `result.enabled`. Needs a token with **Zone.SSL and Certificates:Read**
    /// (the `Zone.DNS:Edit` token used for record upserts may not carry it — the caller
    /// treats an error as "couldn't check" rather than fatal).
    pub async fn universal_ssl_enabled(&self) -> Result<bool, DnsError> {
        let resp = self
            .client
            .get(self.universal_ssl_url())
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let body: UniversalSslResponse = resp
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .json()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(body.result.enabled)
    }

    /// Enable or disable **Universal SSL** on this zone. `PATCH {"enabled": <b>}`.
    ///
    /// For a DNS-only zone that terminates TLS elsewhere (e.g. fly), the edge
    /// certificate is unused, so disabling Universal SSL is safe and stops its DCV TXT
    /// from conflicting with a wildcard's DNS-01 delegation. (A **proxied** / orange-cloud
    /// zone *does* serve the edge cert — there the answer is a Cloudflare Origin CA cert,
    /// not disabling Universal SSL.) Needs a token with **Zone.SSL and
    /// Certificates:Edit**.
    pub async fn set_universal_ssl(&self, enabled: bool) -> Result<(), DnsError> {
        self.client
            .patch(self.universal_ssl_url())
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "enabled": enabled }))
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }

    /// The JSON body for a create/replace of `record`. When this instance is
    /// `proxied`, address/CNAME records get `proxied: true` (and the automatic
    /// TTL Cloudflare requires for proxied records); TXT is never proxied.
    ///
    /// Cloudflare's API v4 body shape varies by type: A/AAAA/CNAME/TXT/NS/PTR/MX
    /// take a flat `content` string (MX adds a top-level `priority`); SRV/CAA/TLSA
    /// take a structured `data` object. **WS2b:** HTTPS/SVCB also take a
    /// structured `data` object — `{priority, target, value}`, where `value` is
    /// the whole SvcParams set, presentation-form with **each param's value
    /// double-quoted** (e.g. `"alpn=\"h2,h3\""`) — confirmed directly from
    /// Cloudflare's own OpenAPI schema (`dns-records_HTTPSRecord` /
    /// `dns-records_SVCBRecord` in
    /// <https://github.com/cloudflare/api-schemas/blob/main/openapi.json>, whose
    /// documented example is `alpn="h3,h2" ipv4hint="127.0.0.1"
    /// ipv6hint="::1"`), mirrored at
    /// <https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/create/>
    /// and the conceptual overview at
    /// <https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/>.
    fn record_body(&self, record: &DnsRecord) -> serde_json::Value {
        let mut body = match &record.kind {
            RecordKind::A(_) | RecordKind::Aaaa(_) | RecordKind::Cname(_) | RecordKind::Txt(_) => {
                serde_json::json!({
                    "type": record.kind.as_str(),
                    "name": record.name,
                    "content": record.kind.flat_value(),
                    "ttl": record.ttl,
                })
            }
            RecordKind::Ns(target) | RecordKind::Ptr(target) => serde_json::json!({
                "type": record.kind.as_str(),
                "name": record.name,
                "content": target,
                "ttl": record.ttl,
            }),
            RecordKind::Mx {
                preference,
                exchange,
            } => serde_json::json!({
                "type": "MX",
                "name": record.name,
                "content": exchange,
                "priority": preference,
                "ttl": record.ttl,
            }),
            RecordKind::Srv {
                priority,
                weight,
                port,
                target,
            } => serde_json::json!({
                "type": "SRV",
                "name": record.name,
                "data": {
                    "priority": priority,
                    "weight": weight,
                    "port": port,
                    "target": target,
                },
                "ttl": record.ttl,
            }),
            RecordKind::Caa { flags, tag, value } => serde_json::json!({
                "type": "CAA",
                "name": record.name,
                "data": {
                    "flags": flags,
                    "tag": tag.as_str(),
                    "value": value,
                },
                "ttl": record.ttl,
            }),
            RecordKind::Tlsa {
                usage,
                selector,
                matching,
                data,
            } => serde_json::json!({
                "type": "TLSA",
                "name": record.name,
                "data": {
                    "usage": usage,
                    "selector": selector,
                    "matching_type": matching,
                    "certificate": data,
                },
                "ttl": record.ttl,
            }),
            RecordKind::Https {
                priority,
                target,
                params,
            }
            | RecordKind::Svcb {
                priority,
                target,
                params,
            } => serde_json::json!({
                "type": record.kind.as_str(),
                "name": record.name,
                "data": {
                    "priority": priority,
                    "target": target,
                    "value": svcparams_presentation(params),
                },
                "ttl": record.ttl,
            }),
        };
        if self.proxied
            && matches!(
                record.kind,
                RecordKind::A(_) | RecordKind::Aaaa(_) | RecordKind::Cname(_)
            )
        {
            body["proxied"] = serde_json::json!(true);
            body["ttl"] = serde_json::json!(1); // proxied records must use automatic TTL
        }
        body
    }

    /// Find the id of an existing `(type, name)` record (the first match), or
    /// `None`. `content` narrows the match for `delete` (TXT/A can repeat).
    async fn find_record_id(
        &self,
        record: &DnsRecord,
        match_content: bool,
    ) -> Result<Option<String>, DnsError> {
        let mut request = self
            .client
            .get(self.records_url())
            .bearer_auth(&self.token)
            .query(&[
                ("type", record.kind.as_str()),
                ("name", record.name.as_str()),
            ]);
        let content = record.kind.flat_value();
        if match_content {
            request = request.query(&[("content", content.as_str())]);
        }
        let resp = request
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let body: ListResponse = resp
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .json()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(body.result.into_iter().next().map(|r| r.id))
    }

    /// Every `(id, content)` TXT record at `name` — the current RRset, for
    /// converging a TXT challenge set (U20).
    async fn list_txt_records(&self, name: &str) -> Result<Vec<(String, String)>, DnsError> {
        let resp = self
            .client
            .get(self.records_url())
            .bearer_auth(&self.token)
            .query(&[("type", "TXT"), ("name", name)])
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let body: ListResponse = resp
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .json()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(body.result.into_iter().map(|r| (r.id, r.content)).collect())
    }

    /// Delete one record by its Cloudflare id.
    async fn delete_record_by_id(&self, id: &str) -> Result<(), DnsError> {
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

    /// Create one TXT record `value` at `name` (POST, never replacing a sibling) —
    /// used to add a value to a TXT challenge set (U20). Records the new
    /// Cloudflare id in [`own_created`](Self::own_created) so the converge's delete
    /// step can be scoped to only records this instance itself wrote (F1).
    async fn create_txt_record(&self, name: &str, value: &str, ttl: u32) -> Result<(), DnsError> {
        let body = self.record_body(&crate::dns::txt_record(name, value, ttl));
        let created: CreateResponse = self
            .client
            .post(self.records_url())
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .json()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        if let Ok(mut own) = self.own_created.lock() {
            own.insert(created.result.id);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct ListResponse {
    result: Vec<ListRecord>,
}

/// Cloudflare's single-object `result` from a `POST /dns_records` — we read only
/// the new record's `id`, to remember which records this instance created (F1).
#[derive(Deserialize)]
struct CreateResponse {
    result: CreatedRecord,
}

#[derive(Deserialize)]
struct CreatedRecord {
    id: String,
}

#[derive(Deserialize)]
struct ListRecord {
    id: String,
    /// The record's rdata (for TXT, the value) — used to converge a TXT challenge
    /// set (U20). `default` so a list of record types without a `content` field
    /// still deserializes.
    #[serde(default)]
    content: String,
}

/// Pure converge plan for a Cloudflare TXT RRset at one name toward the exact set
/// `desired` (U20): the ids to DELETE and the values to CREATE. Idempotent — a
/// set already equal to `desired` yields no deletes and no creates.
///
/// **F1 — never delete a foreign record.** The delete step is scoped to
/// `own_created`: the Cloudflare ids THIS solver instance itself wrote. A record
/// is deleted only when it is own-created AND its content is no longer in
/// `desired` (a value this issuance withdrew). Records this instance did not
/// create — a concurrent ACME order's challenge value at the same
/// `_acme-challenge.<name>` (overlapping renew, blue/green, boatramp alongside an
/// external certbot), Cloudflare's Universal-SSL managed token, or any unrelated
/// TXT — are never touched; clobbering them was a denial-of-issuance. The
/// create side is unchanged (every `desired` value absent by content is created),
/// so our full set, including wildcard+apex, is always made present and
/// re-converge stays idempotent.
///
/// Pure (no network), so the converge logic is unit-tested; the list/delete/create
/// round-trip is the documented live seam.
fn txt_set_plan(
    existing: &[(String, String)],
    desired: &[String],
    own_created: &HashSet<String>,
) -> (Vec<String>, Vec<String>) {
    let want: HashSet<&str> = desired.iter().map(String::as_str).collect();
    let to_delete: Vec<String> = existing
        .iter()
        .filter(|(id, content)| own_created.contains(id) && !want.contains(content.as_str()))
        .map(|(id, _)| id.clone())
        .collect();
    let to_create: Vec<String> = desired
        .iter()
        .filter(|v| !existing.iter().any(|(_, c)| c == *v))
        .cloned()
        .collect();
    (to_delete, to_create)
}

#[derive(Deserialize)]
struct UniversalSslResponse {
    result: UniversalSslResult,
}

#[derive(Deserialize)]
struct UniversalSslResult {
    enabled: bool,
}

#[async_trait]
impl DnsProvider for CloudflareDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let body = self.record_body(record);
        let existing = self.find_record_id(record, false).await?;
        let request = match &existing {
            Some(id) => self
                .client
                .put(format!("{}/{}", self.records_url(), id))
                .bearer_auth(&self.token)
                .json(&body),
            None => self
                .client
                .post(self.records_url())
                .bearer_auth(&self.token)
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

    /// Converge the TXT RRset at `name` to EXACTLY `values` (U20): a wildcard+apex
    /// order's two authorizations publish different values at the SAME
    /// `_acme-challenge.<base>`, and both must coexist — the plain `upsert`
    /// (replace-first-match) would drop one. Lists the current TXT records,
    /// computes the pure [`txt_set_plan`], then deletes the ids this instance
    /// created that are no longer desired (F1 — never a foreign record) and
    /// creates the missing values. Idempotent across retries.
    async fn upsert_txt_set(
        &self,
        name: &str,
        values: &[String],
        ttl: u32,
    ) -> Result<(), DnsError> {
        // F2: honor the `[] = no-op` trait contract. An empty desired set is a
        // teardown (that is `delete`'s job), never "wipe the whole RRset" — so a
        // future caller passing `&[]` can't delete anything here. (The default
        // trait impl already special-cases empty; this override must too.)
        if values.is_empty() {
            return Ok(());
        }
        let existing = self.list_txt_records(name).await?;
        // Snapshot the own-created ids (no lock held across an await), plan, then
        // delete only this instance's now-unwanted records.
        let own_snapshot: HashSet<String> = self
            .own_created
            .lock()
            .map(|own| own.clone())
            .unwrap_or_default();
        let (to_delete, to_create) = txt_set_plan(&existing, values, &own_snapshot);
        for id in to_delete {
            self.delete_record_by_id(&id).await?;
            if let Ok(mut own) = self.own_created.lock() {
                own.remove(&id);
            }
        }
        for value in to_create {
            self.create_txt_record(name, &value, ttl).await?;
        }
        Ok(())
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        // For TXT/A several records can share a name, so match content too.
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
        // WS2b: Cloudflare's DNS Records API supports HTTPS/SVCB (see
        // `record_body`'s doc comment for the pinned `data` shape + API ref).
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
        "cloudflare"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_url_targets_the_zone() {
        let cf = CloudflareDns::new("zone123", "tok").with_api_base("https://example.test/v4");
        assert_eq!(
            cf.records_url(),
            "https://example.test/v4/zones/zone123/dns_records"
        );
    }

    #[test]
    fn universal_ssl_url_targets_the_zone_setting() {
        let cf = CloudflareDns::new("zone123", "tok").with_api_base("https://example.test/v4");
        assert_eq!(
            cf.universal_ssl_url(),
            "https://example.test/v4/zones/zone123/ssl/universal/settings"
        );
    }

    #[test]
    fn universal_ssl_response_parses_enabled_flag() {
        // Cloudflare's `GET /zones/{id}/ssl/universal/settings` wire shape.
        let on: UniversalSslResponse = serde_json::from_value(serde_json::json!({
            "success": true,
            "result": { "enabled": true }
        }))
        .unwrap();
        assert!(on.result.enabled);
        let off: UniversalSslResponse =
            serde_json::from_value(serde_json::json!({ "result": { "enabled": false } })).unwrap();
        assert!(!off.result.enabled);
    }

    #[test]
    fn record_body_shape() {
        let body = CloudflareDns::new("z", "t").record_body(&DnsRecord {
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.example.com".into(),
            ttl: 60,
        });
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["name"], "_acme-challenge.example.com");
        assert_eq!(body["content"], "abc");
        assert_eq!(body["ttl"], 60);
        // Not proxied by default, and never a `proxied` key when off.
        assert!(body.get("proxied").is_none());
    }

    #[test]
    fn proxied_applies_to_address_and_cname_only() {
        let cf = CloudflareDns::new("z", "t").with_proxied(true);

        // A CNAME gets proxied + automatic TTL.
        let cname = cf.record_body(&DnsRecord {
            kind: RecordKind::Cname("app.fly.dev".into()),
            name: "docs.example.com".into(),
            ttl: 300,
        });
        assert_eq!(cname["proxied"], true);
        assert_eq!(cname["ttl"], 1);

        // A TXT is never proxied, even on a proxied instance.
        let txt = cf.record_body(&DnsRecord {
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.example.com".into(),
            ttl: 60,
        });
        assert!(txt.get("proxied").is_none());
        assert_eq!(txt["ttl"], 60);
    }

    /// Golden: the exact create/replace body for every record kind (unproxied),
    /// pinning Cloudflare's `content`-keyed wire shape against accidental drift.
    #[test]
    fn record_body_golden_for_every_kind() {
        let cf = CloudflareDns::new("z", "t");
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::A("203.0.113.7".parse().unwrap()),
                "deploy.example.com",
                300
            )),
            serde_json::json!({"type": "A", "name": "deploy.example.com", "content": "203.0.113.7", "ttl": 300})
        );
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::Aaaa("2001:db8::1".parse().unwrap()),
                "deploy.example.com",
                300
            )),
            serde_json::json!({"type": "AAAA", "name": "deploy.example.com", "content": "2001:db8::1", "ttl": 300})
        );
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::Cname("app.fly.dev".into()),
                "www.example.com",
                300
            )),
            serde_json::json!({"type": "CNAME", "name": "www.example.com", "content": "app.fly.dev", "ttl": 300})
        );
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::Txt(vec!["tok".into()]),
                "_acme-challenge.example.com",
                60
            )),
            serde_json::json!({"type": "TXT", "name": "_acme-challenge.example.com", "content": "tok", "ttl": 60})
        );
    }

    /// Golden: the WS2 record types Cloudflare declares support for — `content` +
    /// top-level `priority` for MX, structured `data` objects for SRV/CAA/TLSA.
    #[test]
    fn record_body_golden_for_ws2_kinds() {
        let cf = CloudflareDns::new("z", "t");
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::Mx {
                    preference: 10,
                    exchange: "mx.example.com".into(),
                },
                "example.com",
                300
            )),
            serde_json::json!({"type": "MX", "name": "example.com", "content": "mx.example.com", "priority": 10, "ttl": 300})
        );
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::Srv {
                    priority: 1,
                    weight: 5,
                    port: 443,
                    target: "svc.example.com".into(),
                },
                "_svc._tcp.example.com",
                300
            )),
            serde_json::json!({"type": "SRV", "name": "_svc._tcp.example.com", "data": {"priority": 1, "weight": 5, "port": 443, "target": "svc.example.com"}, "ttl": 300})
        );
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::Caa {
                    flags: 0,
                    tag: crate::dns::CaaTag::Issue,
                    value: "letsencrypt.org".into(),
                },
                "example.com",
                300
            )),
            serde_json::json!({"type": "CAA", "name": "example.com", "data": {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}, "ttl": 300})
        );
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::Ns("ns1.example.net".into()),
                "sub.example.com",
                3600
            )),
            serde_json::json!({"type": "NS", "name": "sub.example.com", "content": "ns1.example.net", "ttl": 3600})
        );
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::Ptr("host.example.com".into()),
                "7.113.0.203.in-addr.arpa",
                3600
            )),
            serde_json::json!({"type": "PTR", "name": "7.113.0.203.in-addr.arpa", "content": "host.example.com", "ttl": 3600})
        );
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::Tlsa {
                    usage: 3,
                    selector: 1,
                    matching: 1,
                    data: "abcdef".into(),
                },
                "_443._tcp.example.com",
                300
            )),
            serde_json::json!({"type": "TLSA", "name": "_443._tcp.example.com", "data": {"usage": 3, "selector": 1, "matching_type": 1, "certificate": "abcdef"}, "ttl": 300})
        );
    }

    /// Cloudflare declares the WS2-widened set plus (WS2b) HTTPS/SVCB.
    #[test]
    fn supported_kinds_is_the_ws2b_widened_set() {
        let cf = CloudflareDns::new("z", "t");
        for tag in [
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
        ] {
            assert!(cf.supports_kind(tag), "cloudflare should support {tag}");
        }
    }

    /// Golden (WS2b): Cloudflare's HTTPS/SVCB `data` object — `{priority,
    /// target, value}`, `value` holding the whole SvcParams set with each
    /// param's value double-quoted. The multi-param case reproduces
    /// Cloudflare's own OpenAPI schema example verbatim
    /// (`alpn="h3,h2" ipv4hint="127.0.0.1" ipv6hint="::1"`) — see
    /// `record_body`'s doc comment for the reference.
    #[test]
    fn record_body_golden_for_https_svcb() {
        let cf = CloudflareDns::new("z", "t");
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        assert_eq!(
            cf.record_body(&rec(
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
            serde_json::json!({"type": "HTTPS", "name": "example.com", "data": {"priority": 1, "target": ".", "value": "alpn=\"h2,h3\""}, "ttl": 3600})
        );
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::Svcb {
                    priority: 0,
                    target: "svc.example.net".into(),
                    params: vec![],
                },
                "_8443._tcp.example.com",
                300
            )),
            serde_json::json!({"type": "SVCB", "name": "_8443._tcp.example.com", "data": {"priority": 0, "target": "svc.example.net", "value": ""}, "ttl": 300})
        );
        // Cloudflare's own documented example, verbatim.
        assert_eq!(
            cf.record_body(&rec(
                RecordKind::Https {
                    priority: 1,
                    target: ".".into(),
                    params: vec![
                        crate::dns::SvcParam {
                            key: "alpn".into(),
                            value: "h3,h2".into(),
                        },
                        crate::dns::SvcParam {
                            key: "ipv4hint".into(),
                            value: "127.0.0.1".into(),
                        },
                        crate::dns::SvcParam {
                            key: "ipv6hint".into(),
                            value: "::1".into(),
                        },
                    ],
                },
                "example.com",
                3600
            )),
            serde_json::json!({"type": "HTTPS", "name": "example.com", "data": {"priority": 1, "target": ".", "value": "alpn=\"h3,h2\" ipv4hint=\"127.0.0.1\" ipv6hint=\"::1\""}, "ttl": 3600})
        );
    }

    // ---- U20: TXT challenge-set converge plan (pure) ---------------------------

    fn ids(v: Vec<String>) -> Vec<String> {
        let mut v = v;
        v.sort();
        v
    }

    /// The set of Cloudflare ids this instance "created" (F1 ownership scope).
    fn owned(ids: &[&str]) -> HashSet<String> {
        ids.iter().copied().map(String::from).collect()
    }

    /// The converge plan from the empty set: create every desired value, delete
    /// nothing. This is the wildcard+apex first publish.
    #[test]
    fn txt_set_plan_creates_all_from_empty() {
        let (del, create) = txt_set_plan(&[], &["a".to_string(), "b".to_string()], &owned(&[]));
        assert!(del.is_empty());
        assert_eq!(ids(create), vec!["a".to_string(), "b".to_string()]);
    }

    /// Adding a second value keeps the first (no churn on the already-present one):
    /// exactly the apex value staying live while the wildcard value is added (U20).
    #[test]
    fn txt_set_plan_adds_second_value_without_touching_first() {
        let existing = vec![("id-a".to_string(), "a".to_string())];
        let (del, create) = txt_set_plan(
            &existing,
            &["a".to_string(), "b".to_string()],
            &owned(&["id-a"]),
        );
        assert!(
            del.is_empty(),
            "the already-present value must not be deleted"
        );
        assert_eq!(
            create,
            vec!["b".to_string()],
            "only the missing value is created"
        );
    }

    /// An already-converged set is a no-op (idempotent across issuance retries).
    #[test]
    fn txt_set_plan_is_idempotent_when_converged() {
        let existing = vec![
            ("id-a".to_string(), "a".to_string()),
            ("id-b".to_string(), "b".to_string()),
        ];
        let (del, create) = txt_set_plan(
            &existing,
            &["a".to_string(), "b".to_string()],
            &owned(&["id-a", "id-b"]),
        );
        assert!(del.is_empty() && create.is_empty());
    }

    /// An own-created value this issuance no longer wants is deleted, and a
    /// genuinely missing value is created — a reconcile scoped to our own records.
    #[test]
    fn txt_set_plan_deletes_own_unwanted_and_creates_missing() {
        let existing = vec![
            ("id-a".to_string(), "a".to_string()),
            ("id-stale".to_string(), "stale".to_string()), // own-created, no longer wanted
        ];
        let (del, create) = txt_set_plan(
            &existing,
            &["a".to_string(), "b".to_string()],
            &owned(&["id-a", "id-stale"]),
        );
        assert_eq!(del, vec!["id-stale".to_string()]);
        assert_eq!(create, vec!["b".to_string()]);
    }

    /// F1 — THE denial-of-issuance gate: the converge must NEVER delete a TXT
    /// record this solver instance did not itself create. A foreign/unrelated TXT
    /// at the same `_acme-challenge` name (an unrelated record, Cloudflare's
    /// Universal-SSL token) AND a concurrent ACME order's live challenge value both
    /// survive the converge — only our own missing value is created. If a reviewer
    /// drops the own-created scoping (deleting every non-desired content), both
    /// foreign records land in `del` and this goes RED.
    #[test]
    fn txt_set_plan_never_deletes_a_foreign_record() {
        let existing = vec![
            (
                "id-foreign".to_string(),
                "unrelated-verification".to_string(),
            ),
            // A concurrent order's DNS-01 challenge value (43-char base64url), live
            // at the SAME name — must not be swept.
            (
                "id-concurrent".to_string(),
                "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk".to_string(),
            ),
            ("id-ours".to_string(), "ours-apex".to_string()), // this issuance's record
        ];
        let (del, create) = txt_set_plan(
            &existing,
            &["ours-apex".to_string(), "ours-wild".to_string()],
            &owned(&["id-ours"]),
        );
        assert!(
            del.is_empty(),
            "neither the foreign record nor the concurrent order's value may be deleted, got {del:?}"
        );
        assert_eq!(
            create,
            vec!["ours-wild".to_string()],
            "only our own missing value is created; foreign content is left untouched"
        );
    }

    /// Reducing to a single value (one authorization's teardown) deletes exactly
    /// the withdrawn value's OWN record and leaves the survivor — and a foreign
    /// record present at the name is still never touched.
    #[test]
    fn txt_set_plan_reduces_to_the_surviving_value() {
        let existing = vec![
            ("id-a".to_string(), "a".to_string()),
            ("id-b".to_string(), "b".to_string()),
            ("id-foreign".to_string(), "foreign".to_string()),
        ];
        let (del, create) = txt_set_plan(&existing, &["b".to_string()], &owned(&["id-a", "id-b"]));
        assert_eq!(del, vec!["id-a".to_string()]);
        assert!(create.is_empty());
    }

    /// F2 — the override must honor the `[] = no-op` trait contract: an empty
    /// desired set does NOTHING (teardown is `delete`'s job), so a future caller
    /// passing `&[]` can't wipe the whole RRset. The provider points at an
    /// unreachable base, yet the empty converge returns `Ok(())` WITHOUT any
    /// network call — if the early return were dropped, `list_txt_records` would
    /// hit that base and this would be an `Err`.
    #[tokio::test]
    async fn upsert_txt_set_empty_is_a_no_op_without_network() {
        // Port 1 ⇒ connection refused fast, so a leaked request fails loudly
        // rather than hanging.
        let cf = CloudflareDns::new("zone123", "tok").with_api_base("http://127.0.0.1:1/v4");
        assert!(
            cf.upsert_txt_set("_acme-challenge.example.com", &[], 60)
                .await
                .is_ok(),
            "an empty desired set must be a no-op (delete nothing, no network)"
        );
    }
}
