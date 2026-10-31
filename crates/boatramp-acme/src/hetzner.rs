//! Hetzner DNS provider (**Hetzner Cloud API** — `api.hetzner.cloud/v1`, Bearer
//! auth, a Zones/RRSets record model).
//!
//! Hetzner's DNS is now part of the Hetzner Cloud API (DNS became generally
//! available there on 2025-11-10). This adapter targets that API; the previous
//! **classic** surface (`dns.hetzner.com/api/v1` with the `Auth-API-Token`
//! header) is decommissioned — every request to it 301-redirects to
//! `console.hetzner.com` — so this is a migration, not a tweak. Primary source
//! for the shapes below: Hetzner's own official Go SDK, `hcloud-go`
//! (`hcloud/zone_rrset.go`, `hcloud/schema/zone_rrset.go`,
//! `hcloud/exp/zoneutil/txt.go`), which points at
//! <https://docs.hetzner.cloud/reference/cloud#zone-rrsets>.
//!
//! Specifics the helpers encode:
//!   * **Auth** is `Authorization: Bearer <Hetzner Cloud API token>` (standard
//!     Cloud-API bearer), not the classic `Auth-API-Token` header. This is a
//!     **breaking credential change** for existing Hetzner users: `HETZNER_DNS_TOKEN`
//!     must now be a Hetzner **Cloud** API token, not a classic DNS API token.
//!   * **Zone addressing.** The RRSet endpoints accept `{zoneIDOrName}`
//!     (`/zones/{id_or_name}/rrsets/...`), so the adapter uses the zone's domain
//!     **name** directly as the path identifier — operators need only the token
//!     and the zone name; no separate numeric `HETZNER_ZONE_ID` lookup is
//!     required (the classic adapter needed one). The zone name doubles as the
//!     base for relativizing record names.
//!   * **Record names are relative** to the zone (`www`, `_acme-challenge.deploy`,
//!     `@` for the apex) — same convention as the classic API and the Hetzner
//!     console.
//!   * **RRSet model.** A record set for a `(name, type)` carries a `records`
//!     array of `{ "value": <presentation-form rdata> }`. `upsert` is
//!     create-or-replace of the whole set: it GETs the RRSet, `POST`s a new one
//!     (`/zones/{zone}/rrsets`) if absent, else replaces its values via
//!     `.../actions/set_records` (and `.../actions/change_ttl` if the TTL drifts).
//!     `delete` removes the whole `(name, type)` set (`DELETE`; 404 = already
//!     gone). This mirrors the Google Cloud DNS adapter's whole-rrset semantics.
//!
//! **Supported types.** Per `hcloud-go`'s `ZoneRRSetType` enum, the Cloud API
//! supports A, AAAA, CAA, CNAME, DS, HINFO, HTTPS, MX, NS, PTR, RP, SOA, SRV,
//! SVCB, **TLSA**, TXT. Of the writer's [`RecordKind`] set, that covers **every**
//! writable kind — including HTTPS/SVCB/PTR (which the classic API lacked) **and**
//! TLSA. (A stale Ansible `community.dns` note claims "the new API does not
//! support DANE records"; that refers to a different/earlier surface — Hetzner's
//! own Cloud SDK enum lists `TLSA`, so this adapter supports it. DS/SOA are
//! provider-managed Tier-3 types with no writable [`RecordKind`] variant, and
//! HINFO/RP are not in the writer's model, so none of those are offered.)
//!
//! Request construction is pure + unit-tested (golden bodies per type); the
//! send/parse round-trip is a live seam (no Hetzner Cloud credentials in CI).

use async_trait::async_trait;
use serde::Deserialize;

use crate::dns::{
    DnsError, DnsProvider, DnsRecord, RecordKind, RecordKindTag, SvcParam, encode_name_segment,
};

const DEFAULT_API_BASE: &str = "https://api.hetzner.cloud/v1";

/// A Hetzner Cloud DNS editor scoped to one zone.
pub struct HetznerDns {
    client: reqwest::Client,
    api_base: String,
    token: String,
    /// The zone's domain (e.g. `example.com`). Used **both** as the
    /// `{zoneIDOrName}` path segment and to relativize record names.
    zone: String,
}

impl HetznerDns {
    /// Build a provider for the zone whose domain is `zone` (e.g. `example.com`),
    /// authenticating with a Hetzner **Cloud** API token (Bearer). The zone name
    /// is used directly as the API's zone identifier, so no numeric zone id is
    /// needed.
    pub fn new(zone: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            token: token.into(),
            zone: zone.into(),
        }
    }

    /// Override the API base URL (for pointing tests at a stub).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// `…/zones/{zone}/rrsets` — the RRSet create/list collection.
    fn rrsets_url(&self) -> String {
        format!("{}/zones/{}/rrsets", self.api_base, self.zone)
    }

    /// `…/zones/{zone}/rrsets/{name}/{type}` — a single RRSet (GET/DELETE, and
    /// the base for its `/actions/*` sub-resources). `name` is the zone-relative
    /// owner (`@` for the apex). The owner segment is percent-encoded as
    /// defense-in-depth so it can never escape its segment (the central
    /// `canonicalize_owner_name` already refuses every byte this would encode; the
    /// apex `@`, the `_acme-challenge.*` underscore labels, and a `*` wildcard
    /// label are all preserved as valid URL path chars).
    fn rrset_url(&self, name: &str, record_type: &str) -> String {
        format!(
            "{}/zones/{}/rrsets/{}/{}",
            self.api_base,
            self.zone,
            encode_name_segment(name),
            record_type
        )
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

    /// A target name as an FQDN with a trailing dot. Hetzner treats a name-valued
    /// rdata **without** a trailing dot as relative (the zone is auto-appended)
    /// and **with** one as absolute (used as-is) — see the SVCB record docs,
    /// <https://docs.hetzner.com/networking/dns/record-types/svcb-record> — so an
    /// already-fully-qualified target (`CNAME`/`NS`/`PTR` target, `MX`/`SRV`
    /// exchange/target, HTTPS/SVCB target) gets a trailing dot to prevent
    /// double-qualification.
    fn dotted(name: &str) -> String {
        if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        }
    }

    /// A TXT character-string, escaped and double-quoted as Hetzner's Cloud API
    /// expects. Mirrors `hcloud-go`'s `zoneutil.FormatTXTRecord`: each string is
    /// wrapped in `"…"`, with embedded `\` and `"` backslash-escaped (and a value
    /// over 255 bytes would be split into several quoted chunks — handled by the
    /// caller, since [`RecordKind::Txt`] already carries the ≤255-byte chunks).
    fn txt_chunk(s: &str) -> String {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    }

    /// RFC 9460 SvcParams for HTTPS/SVCB, rendered as Hetzner's docs show them:
    /// space-joined `key=value` tokens, a value **double-quoted when it contains
    /// a comma** (matching the HTTPS record doc's `alpn="h3,h2"` example,
    /// <https://docs.hetzner.com/networking/dns/record-types/https-record/>) and
    /// left bare otherwise (`ipv4hint=203.0.113.1`); a valueless key is emitted
    /// bare (`no-default-alpn`). (Hetzner's SVCB page shows a comma value unquoted;
    /// RFC 9460 presentation accepts both forms, so the quoted form — the HTTPS
    /// page's own example — is used uniformly.)
    fn svcparams_presentation(params: &[SvcParam]) -> String {
        params
            .iter()
            .map(|p| {
                if p.value.is_empty() {
                    p.key.clone()
                } else if p.value.contains(',') {
                    format!("{}=\"{}\"", p.key, p.value)
                } else {
                    format!("{}={}", p.key, p.value)
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The single presentation-format `value` string for `record`'s rdata, as the
    /// Cloud API's `records[].value` field expects it.
    ///
    /// Per-type encoding (presentation form, RFC 1035 / RFC 9460):
    ///   * `A`/`AAAA` — the raw address (`198.51.100.1`), per `hcloud-go`'s RRSet
    ///     fixtures.
    ///   * `CNAME`/`NS`/`PTR` — the target as a trailing-dot FQDN.
    ///   * `TXT` — each character-string quoted + escaped, space-joined
    ///     (`FormatTXTRecord`).
    ///   * `MX` — `<preference> <exchange.>`.
    ///   * `SRV` — `<priority> <weight> <port> <target.>`.
    ///   * `CAA` — `<flags> <tag> "<value>"`.
    ///   * `HTTPS`/`SVCB` — `<priority> <target.> [SvcParams]` (SvcParams omitted
    ///     in AliasMode).
    ///   * `TLSA` — `<usage> <selector> <matching> <data>`.
    fn record_value(record: &DnsRecord) -> String {
        match &record.kind {
            RecordKind::A(ip) => ip.to_string(),
            RecordKind::Aaaa(ip) => ip.to_string(),
            RecordKind::Cname(target) | RecordKind::Ns(target) | RecordKind::Ptr(target) => {
                Self::dotted(target)
            }
            RecordKind::Txt(strings) => strings
                .iter()
                .map(|s| Self::txt_chunk(s))
                .collect::<Vec<_>>()
                .join(" "),
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
                if svcparams.is_empty() {
                    format!("{priority} {}", Self::dotted(target))
                } else {
                    format!("{priority} {} {svcparams}", Self::dotted(target))
                }
            }
            RecordKind::Tlsa {
                usage,
                selector,
                matching,
                data,
            } => format!("{usage} {selector} {matching} {data}"),
        }
    }

    /// The `records` array for `record` — a single `{ "value": … }` element (the
    /// writer models one value per [`DnsRecord`]; `upsert` owns the whole set).
    fn records_json(record: &DnsRecord) -> serde_json::Value {
        serde_json::json!([{ "value": Self::record_value(record) }])
    }

    /// The `POST /zones/{zone}/rrsets` body that creates the RRSet for `record`.
    fn create_body(&self, record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({
            "name": self.relative_name(&record.name),
            "type": record.kind.as_str(),
            "ttl": record.ttl,
            "records": Self::records_json(record),
        })
    }

    /// The `/actions/set_records` body that replaces the RRSet's values.
    fn set_records_body(record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({ "records": Self::records_json(record) })
    }

    /// The current RRSet for `(name, type)`, or `None` on a 404. Used by `upsert`
    /// to pick create vs replace and to short-circuit a no-op.
    async fn get_rrset(&self, name: &str, record_type: &str) -> Result<Option<Rrset>, DnsError> {
        let resp = self
            .client
            .get(self.rrset_url(name, record_type))
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        let body: GetResponse = resp
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .json()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(Some(body.rrset))
    }

    async fn post(&self, url: String, body: &serde_json::Value) -> Result<(), DnsError> {
        self.client
            .post(url)
            .bearer_auth(&self.token)
            .json(body)
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }
}

#[derive(Deserialize)]
struct GetResponse {
    rrset: Rrset,
}

#[derive(Deserialize)]
struct Rrset {
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    records: Vec<RrsetRecord>,
}

#[derive(Deserialize)]
struct RrsetRecord {
    #[serde(default)]
    value: String,
}

#[async_trait]
impl DnsProvider for HetznerDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let name = self.relative_name(&record.name);
        let record_type = record.kind.as_str();
        let desired = Self::record_value(record);

        match self.get_rrset(&name, record_type).await? {
            None => {
                // No such RRSet yet — create it with our single value.
                self.post(self.rrsets_url(), &self.create_body(record))
                    .await
            }
            Some(current) => {
                // Already exactly our value + TTL → nothing to do (a retried ACME
                // challenge or re-run auto-config converges without a write).
                let already = current.ttl == Some(record.ttl)
                    && current.records.len() == 1
                    && current.records[0].value == desired;
                if already {
                    return Ok(());
                }
                // Replace the whole set's values, and fix the TTL if it drifted
                // (`set_records` does not carry TTL — that is a separate action).
                let base = self.rrset_url(&name, record_type);
                self.post(
                    format!("{base}/actions/set_records"),
                    &Self::set_records_body(record),
                )
                .await?;
                if current.ttl != Some(record.ttl) {
                    self.post(
                        format!("{base}/actions/change_ttl"),
                        &serde_json::json!({ "ttl": record.ttl }),
                    )
                    .await?;
                }
                Ok(())
            }
        }
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let name = self.relative_name(&record.name);
        let resp = self
            .client
            .delete(self.rrset_url(&name, record.kind.as_str()))
            .bearer_auth(&self.token)
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
        // Hetzner Cloud's `ZoneRRSetType` enum (hcloud-go) covers every writable
        // kind the writer models — including HTTPS/SVCB/PTR (new vs the classic
        // API) and TLSA. See the module doc comment for the source + the TLSA
        // note. DS/SOA (Tier-3) and HINFO/RP (unmodeled) are not offered.
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
        "hetzner"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::CaaTag;

    fn provider() -> HetznerDns {
        HetznerDns::new("example.com", "tok").with_api_base("https://hz.test/v1")
    }

    #[test]
    fn rrsets_url_is_the_zone_collection() {
        assert_eq!(
            provider().rrsets_url(),
            "https://hz.test/v1/zones/example.com/rrsets"
        );
    }

    #[test]
    fn rrset_url_addresses_name_and_type() {
        assert_eq!(
            provider().rrset_url("_acme-challenge.deploy", "TXT"),
            "https://hz.test/v1/zones/example.com/rrsets/_acme-challenge.deploy/TXT"
        );
        // The apex owner is `@`.
        assert_eq!(
            provider().rrset_url("@", "A"),
            "https://hz.test/v1/zones/example.com/rrsets/@/A"
        );
    }

    #[test]
    fn relative_name_strips_the_zone_and_maps_apex() {
        let p = provider();
        assert_eq!(
            p.relative_name("_acme-challenge.deploy.example.com"),
            "_acme-challenge.deploy"
        );
        assert_eq!(p.relative_name("example.com"), "@");
        // A wildcard preview owner relativizes to a `*`-prefixed label.
        assert_eq!(p.relative_name("*.deploy.example.com"), "*.deploy");
    }

    #[test]
    fn create_body_carries_relative_name_and_records_array() {
        let body = provider().create_body(&DnsRecord {
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.deploy.example.com".into(),
            ttl: 60,
        });
        assert_eq!(body["name"], "_acme-challenge.deploy");
        assert_eq!(body["type"], "TXT");
        assert_eq!(body["ttl"], 60);
        // TXT values are quoted (FormatTXTRecord).
        assert_eq!(body["records"][0]["value"], "\"abc\"");
    }

    #[test]
    fn cname_value_gets_a_trailing_dot() {
        let body = provider().create_body(&DnsRecord {
            kind: RecordKind::Cname("lb.example.net".into()),
            name: "*.deploy.example.com".into(),
            ttl: 120,
        });
        assert_eq!(body["name"], "*.deploy");
        assert_eq!(body["records"][0]["value"], "lb.example.net.");
    }

    #[test]
    fn txt_value_escapes_and_quotes_each_chunk() {
        // Embedded quote + backslash are escaped; multiple chunks join with a space.
        assert_eq!(
            HetznerDns::record_value(&DnsRecord {
                kind: RecordKind::Txt(vec!["he said \"hi\"".into(), "second\\part".into()]),
                name: "example.com".into(),
                ttl: 60,
            }),
            "\"he said \\\"hi\\\"\" \"second\\\\part\""
        );
    }

    #[test]
    fn set_records_body_is_the_records_array_only() {
        let body = HetznerDns::set_records_body(&DnsRecord {
            kind: RecordKind::A("203.0.113.7".parse().unwrap()),
            name: "deploy.example.com".into(),
            ttl: 60,
        });
        assert_eq!(
            body,
            serde_json::json!({ "records": [{ "value": "203.0.113.7" }] })
        );
    }

    /// Golden: the exact create body for the four originally-writable kinds,
    /// pinning Hetzner Cloud's relative-name (apex → `@`) `records: [{value}]`
    /// wire shape.
    #[test]
    fn create_body_golden_for_core_kinds() {
        let p = provider();
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        assert_eq!(
            p.create_body(&rec(
                RecordKind::A("203.0.113.7".parse().unwrap()),
                "deploy.example.com",
                60
            )),
            serde_json::json!({"name": "deploy", "type": "A", "ttl": 60, "records": [{"value": "203.0.113.7"}]})
        );
        assert_eq!(
            p.create_body(&rec(
                RecordKind::Aaaa("2001:db8::1".parse().unwrap()),
                "deploy.example.com",
                60
            )),
            serde_json::json!({"name": "deploy", "type": "AAAA", "ttl": 60, "records": [{"value": "2001:db8::1"}]})
        );
        assert_eq!(
            p.create_body(&rec(
                RecordKind::Cname("lb.example.net".into()),
                "www.example.com",
                300
            )),
            serde_json::json!({"name": "www", "type": "CNAME", "ttl": 300, "records": [{"value": "lb.example.net."}]})
        );
        assert_eq!(
            p.create_body(&rec(RecordKind::Txt(vec!["tok".into()]), "example.com", 60)),
            serde_json::json!({"name": "@", "type": "TXT", "ttl": 60, "records": [{"value": "\"tok\""}]})
        );
    }

    /// Golden: the structured multi-field kinds (MX/SRV/CAA/NS/PTR/TLSA), each
    /// rendered to its presentation-format `value`.
    #[test]
    fn create_body_golden_for_structured_kinds() {
        let p = provider();
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        assert_eq!(
            p.create_body(&rec(
                RecordKind::Mx {
                    preference: 10,
                    exchange: "mx.example.com".into(),
                },
                "example.com",
                300
            )),
            serde_json::json!({"name": "@", "type": "MX", "ttl": 300, "records": [{"value": "10 mx.example.com."}]})
        );
        assert_eq!(
            p.create_body(&rec(
                RecordKind::Srv {
                    priority: 1,
                    weight: 5,
                    port: 443,
                    target: "svc.example.com".into(),
                },
                "_svc._tcp.example.com",
                300
            )),
            serde_json::json!({"name": "_svc._tcp", "type": "SRV", "ttl": 300, "records": [{"value": "1 5 443 svc.example.com."}]})
        );
        assert_eq!(
            p.create_body(&rec(
                RecordKind::Caa {
                    flags: 0,
                    tag: CaaTag::Issue,
                    value: "letsencrypt.org".into(),
                },
                "example.com",
                300
            )),
            serde_json::json!({"name": "@", "type": "CAA", "ttl": 300, "records": [{"value": "0 issue \"letsencrypt.org\""}]})
        );
        assert_eq!(
            p.create_body(&rec(
                RecordKind::Ns("ns1.example.net".into()),
                "sub.example.com",
                3600
            )),
            serde_json::json!({"name": "sub", "type": "NS", "ttl": 3600, "records": [{"value": "ns1.example.net."}]})
        );
        assert_eq!(
            p.create_body(&rec(
                RecordKind::Ptr("host.example.com".into()),
                "7.113.0.203.example.com",
                3600
            )),
            serde_json::json!({"name": "7.113.0.203", "type": "PTR", "ttl": 3600, "records": [{"value": "host.example.com."}]})
        );
        assert_eq!(
            p.create_body(&rec(
                RecordKind::Tlsa {
                    usage: 3,
                    selector: 1,
                    matching: 1,
                    data: "abcdef".into(),
                },
                "_443._tcp.example.com",
                300
            )),
            serde_json::json!({"name": "_443._tcp", "type": "TLSA", "ttl": 300, "records": [{"value": "3 1 1 abcdef"}]})
        );
    }

    /// Golden: HTTPS/SVCB presentation `value` — AliasMode (no SvcParams) is
    /// `<priority> <target.>`; ServiceMode appends space-joined SvcParams with a
    /// comma-bearing value quoted (Hetzner's HTTPS-record doc `alpn="h3,h2"`) and
    /// a comma-free one bare.
    #[test]
    fn create_body_golden_for_https_svcb() {
        let p = provider();
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        // ServiceMode: comma value quoted; a valueless key stays bare.
        assert_eq!(
            p.create_body(&rec(
                RecordKind::Https {
                    priority: 1,
                    target: ".".into(),
                    params: vec![
                        SvcParam {
                            key: "alpn".into(),
                            value: "h2,h3".into(),
                        },
                        SvcParam {
                            key: "no-default-alpn".into(),
                            value: String::new(),
                        },
                    ],
                },
                "example.com",
                3600
            )),
            serde_json::json!({"name": "@", "type": "HTTPS", "ttl": 3600, "records": [{"value": "1 . alpn=\"h2,h3\" no-default-alpn"}]})
        );
        // ServiceMode: a comma-free value stays bare (ipv4hint).
        assert_eq!(
            p.create_body(&rec(
                RecordKind::Svcb {
                    priority: 1,
                    target: "svc.example.net".into(),
                    params: vec![SvcParam {
                        key: "ipv4hint".into(),
                        value: "203.0.113.1".into(),
                    }],
                },
                "_8443._tcp.example.com",
                300
            )),
            serde_json::json!({"name": "_8443._tcp", "type": "SVCB", "ttl": 300, "records": [{"value": "1 svc.example.net. ipv4hint=203.0.113.1"}]})
        );
        // AliasMode: no SvcParams → `<priority> <target.>`.
        assert_eq!(
            p.create_body(&rec(
                RecordKind::Svcb {
                    priority: 0,
                    target: "svc.example.net".into(),
                    params: vec![],
                },
                "_8443._tcp.example.com",
                300
            )),
            serde_json::json!({"name": "_8443._tcp", "type": "SVCB", "ttl": 300, "records": [{"value": "0 svc.example.net."}]})
        );
    }

    /// The Cloud API supports every writable kind — including the three the
    /// classic API lacked (HTTPS/SVCB/PTR) and TLSA.
    #[test]
    fn supported_kinds_covers_every_writable_kind() {
        let p = provider();
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
            assert!(p.supports_kind(tag), "hetzner cloud should support {tag}");
        }
        assert_eq!(p.supported_kinds().len(), 12);
    }

    /// The GET-single response envelope (`{ "rrset": { ttl, records: [{value}] } }`)
    /// parses into the fields `upsert`'s no-op check reads.
    #[test]
    fn get_response_parses_ttl_and_record_values() {
        let body: GetResponse = serde_json::from_value(serde_json::json!({
            "rrset": {
                "id": "www/A",
                "name": "www",
                "type": "A",
                "ttl": 3600,
                "records": [{ "value": "198.51.100.1", "comment": "web" }],
                "zone": 42
            }
        }))
        .unwrap();
        assert_eq!(body.rrset.ttl, Some(3600));
        assert_eq!(body.rrset.records.len(), 1);
        assert_eq!(body.rrset.records[0].value, "198.51.100.1");
    }
}
