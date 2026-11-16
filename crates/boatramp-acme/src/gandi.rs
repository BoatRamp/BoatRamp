//! Gandi LiveDNS provider (**LiveDNS API v5** — `api.gandi.net/v5/livedns`,
//! Bearer Personal-Access-Token auth, an RRSet record model).
//!
//! Implemented cleanly from Gandi's PUBLIC LiveDNS REST documentation
//! (<https://api.gandi.net/docs/livedns/>), no proprietary client code.
//!
//! Specifics the helpers encode:
//!   * **Auth** is `Authorization: Bearer <PAT>` — a Gandi **Personal Access
//!     Token** (the recommended scheme; the legacy `Authorization: Apikey …`
//!     production-key header is deprecated and not used here). The token is the
//!     only secret and is carried only in the auth header.
//!   * **Host is pinned** to `api.gandi.net` (the `DEFAULT_API_BASE` constant) —
//!     it is never derived from any credential or guest input, so there is no
//!     blind-SSRF surface (unlike a provider whose request authority is a
//!     credential field). `with_api_base` exists ONLY to retarget a test stub.
//!   * **Zone addressing.** Records live under `/domains/{fqdn}/records`, where
//!     `{fqdn}` is the zone's domain **name** directly — operators need only the
//!     token and the zone name, no numeric id. The zone name doubles as the base
//!     for relativizing record names.
//!   * **Record names are relative** to the zone (`www`, `_acme-challenge.deploy`,
//!     `@` for the apex) — Gandi's documented convention.
//!   * **RRSet model.** A single `(name, type)` record set is addressed at
//!     `/domains/{fqdn}/records/{rrset_name}/{rrset_type}` and carries
//!     `{ "rrset_ttl": <ttl>, "rrset_values": [<presentation-form rdata>, …] }`.
//!     `upsert` is a single **`PUT`** of that set — Gandi's PUT is
//!     create-or-replace, so it is idempotent by construction (a retried ACME
//!     challenge or a re-run auto-config converges without a read-then-write
//!     dance). `delete` removes the whole `(name, type)` set (`DELETE`; a 404 =
//!     already gone, which the trait treats as success).
//!
//! **Supported types.** Gandi LiveDNS supports A, AAAA, CNAME, TXT, MX, SRV, CAA,
//! HTTPS, SVCB, NS, PTR and TLSA (among others) — i.e. **every** writable
//! [`RecordKind`] the writer models. `rrset_values` take standard RFC 1035 /
//! RFC 9460 **zone-file presentation** form, so TXT strings are quoted + escaped,
//! name-valued rdata is a trailing-dot FQDN, and HTTPS/SVCB is
//! `<priority> <target.> [SvcParams]`. (DS/SOA and the DNSSEC family are
//! provider-managed Tier-3 types with no writable [`RecordKind`] variant, so none
//! are offered.)
//!
//! Request construction is pure + unit-tested (golden bodies per type); the
//! send/parse round-trip is a live seam (no Gandi credentials in CI).

use async_trait::async_trait;

use crate::dns::{
    DnsError, DnsProvider, DnsRecord, RecordKind, RecordKindTag, SvcParam, encode_name_segment,
};

const DEFAULT_API_BASE: &str = "https://api.gandi.net/v5/livedns";

/// A Gandi LiveDNS editor scoped to one zone.
pub struct GandiDns {
    client: reqwest::Client,
    api_base: String,
    token: String,
    /// The zone's domain (e.g. `example.com`). Used **both** as the `{fqdn}`
    /// path segment and to relativize record names.
    zone: String,
}

impl GandiDns {
    /// Build a provider for the zone whose domain is `zone` (e.g. `example.com`),
    /// authenticating with a Gandi **Personal Access Token** (Bearer). The zone
    /// name is used directly as the API's domain identifier, so no numeric id is
    /// needed.
    pub fn new(zone: impl Into<String>, token: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            token: token.into(),
            zone: zone.into(),
        }
    }

    /// Override the API base URL (for pointing tests at a stub). The production
    /// host is fixed to `api.gandi.net` — this is test-only.
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// `…/domains/{zone}/records/{name}/{type}` — a single RRSet (GET/PUT/DELETE).
    /// `name` is the zone-relative owner (`@` for the apex). The owner segment is
    /// percent-encoded as defense-in-depth so it can never escape its path segment
    /// (the central `canonicalize_owner_name` already refuses every byte this
    /// would encode; the apex `@`, the `_acme-challenge.*` underscore labels, and
    /// a `*` wildcard label are all preserved as valid URL path chars). The type
    /// segment is one of our own fixed `as_str()` tokens, never caller input.
    fn rrset_url(&self, name: &str, record_type: &str) -> String {
        format!(
            "{}/domains/{}/records/{}/{}",
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

    /// A target name as an FQDN with a trailing dot. Gandi treats a name-valued
    /// rdata **with** a trailing dot as absolute and **without** one as relative
    /// (the zone is auto-appended), so an already-fully-qualified target
    /// (`CNAME`/`NS`/`PTR` target, `MX`/`SRV` exchange/target, HTTPS/SVCB target)
    /// gets a trailing dot to prevent double-qualification.
    fn dotted(name: &str) -> String {
        if name.ends_with('.') {
            name.to_string()
        } else {
            format!("{name}.")
        }
    }

    /// A TXT character-string, escaped and double-quoted as Gandi's zone-file
    /// presentation form expects: each string is wrapped in `"…"`, with embedded
    /// `\` and `"` backslash-escaped. (A value over 255 bytes would be split into
    /// several quoted chunks — handled by the caller, since [`RecordKind::Txt`]
    /// already carries the ≤255-byte chunks.)
    fn txt_chunk(s: &str) -> String {
        let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    }

    /// RFC 9460 SvcParams for HTTPS/SVCB, rendered as space-joined `key=value`
    /// tokens: a value containing a comma is double-quoted (RFC 9460 presentation
    /// accepts the quoted form uniformly), a comma-free value is bare, and a
    /// valueless key is emitted bare (`no-default-alpn`).
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

    /// The single presentation-format `value` string for `record`'s rdata, as one
    /// element of the RRSet's `rrset_values` array.
    ///
    /// Per-type encoding (presentation form, RFC 1035 / RFC 9460):
    ///   * `A`/`AAAA` — the raw address (`198.51.100.1`).
    ///   * `CNAME`/`NS`/`PTR` — the target as a trailing-dot FQDN.
    ///   * `TXT` — each character-string quoted + escaped, space-joined.
    ///   * `MX` — `<preference> <exchange.>`.
    ///   * `SRV` — `<priority> <weight> <port> <target.>`.
    ///   * `CAA` — `<flags> <tag> "<value>"` (embedded `"`/`\` escaped).
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
            RecordKind::Caa { flags, tag, value } => {
                // Escape embedded `\` and `"` in the quoted value (consistent with
                // the DNSimple adapter — correctness regardless of transport escaping).
                let value = value.replace('\\', "\\\\").replace('"', "\\\"");
                format!("{flags} {tag} \"{value}\"")
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

    /// The `PUT` body for `record` — the RRSet's TTL + its single value. Gandi's
    /// PUT is create-or-replace, so this one body both creates and overwrites the
    /// `(name, type)` set (the writer models one value per [`DnsRecord`]; `upsert`
    /// owns the whole set).
    fn rrset_body(record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({
            "rrset_ttl": record.ttl,
            "rrset_values": [Self::record_value(record)],
        })
    }
}

#[async_trait]
impl DnsProvider for GandiDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        // A single PUT is a create-or-replace of the whole `(name, type)` RRSet —
        // idempotent by construction, so a retried challenge converges with no GET.
        let url = self.rrset_url(&self.relative_name(&record.name), record.kind.as_str());
        self.client
            .put(url)
            .bearer_auth(&self.token)
            .json(&Self::rrset_body(record))
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let url = self.rrset_url(&self.relative_name(&record.name), record.kind.as_str());
        let resp = self
            .client
            .delete(url)
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
        // Gandi LiveDNS covers every writable kind the writer models (its
        // `rrset_values` take standard zone-file presentation for each type). DS/SOA
        // (Tier-3) and types the writer does not model are not offered.
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
        "gandi"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::CaaTag;

    fn provider() -> GandiDns {
        GandiDns::new("example.com", "tok").with_api_base("https://gandi.test/v5/livedns")
    }

    #[test]
    fn rrset_url_addresses_domain_name_and_type() {
        assert_eq!(
            provider().rrset_url("_acme-challenge.deploy", "TXT"),
            "https://gandi.test/v5/livedns/domains/example.com/records/_acme-challenge.deploy/TXT"
        );
        // The apex owner is `@`.
        assert_eq!(
            provider().rrset_url("@", "A"),
            "https://gandi.test/v5/livedns/domains/example.com/records/@/A"
        );
        // A `*` wildcard label is preserved as a valid path char.
        assert_eq!(
            provider().rrset_url("*.deploy", "A"),
            "https://gandi.test/v5/livedns/domains/example.com/records/*.deploy/A"
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
    fn rrset_body_carries_ttl_and_values_array() {
        let body = GandiDns::rrset_body(&DnsRecord {
            kind: RecordKind::Txt(vec!["abc".into()]),
            name: "_acme-challenge.deploy.example.com".into(),
            ttl: 60,
        });
        assert_eq!(body["rrset_ttl"], 60);
        // TXT values are quoted (zone-file presentation).
        assert_eq!(body["rrset_values"][0], "\"abc\"");
    }

    #[test]
    fn cname_value_gets_a_trailing_dot() {
        let body = GandiDns::rrset_body(&DnsRecord {
            kind: RecordKind::Cname("lb.example.net".into()),
            name: "www.example.com".into(),
            ttl: 120,
        });
        assert_eq!(body["rrset_values"][0], "lb.example.net.");
    }

    #[test]
    fn txt_value_escapes_and_quotes_each_chunk() {
        // Embedded quote + backslash are escaped; multiple chunks join with a space.
        assert_eq!(
            GandiDns::record_value(&DnsRecord {
                kind: RecordKind::Txt(vec!["he said \"hi\"".into(), "second\\part".into()]),
                name: "example.com".into(),
                ttl: 60,
            }),
            "\"he said \\\"hi\\\"\" \"second\\\\part\""
        );
    }

    /// Golden: the exact `PUT` body for the four core kinds, pinning Gandi's
    /// `{rrset_ttl, rrset_values:[presentation]}` wire shape.
    #[test]
    fn rrset_body_golden_for_core_kinds() {
        let rec = |kind, name: &str, ttl| DnsRecord {
            kind,
            name: name.into(),
            ttl,
        };
        assert_eq!(
            GandiDns::rrset_body(&rec(
                RecordKind::A("203.0.113.7".parse().unwrap()),
                "deploy.example.com",
                60
            )),
            serde_json::json!({"rrset_ttl": 60, "rrset_values": ["203.0.113.7"]})
        );
        assert_eq!(
            GandiDns::rrset_body(&rec(
                RecordKind::Aaaa("2001:db8::1".parse().unwrap()),
                "deploy.example.com",
                60
            )),
            serde_json::json!({"rrset_ttl": 60, "rrset_values": ["2001:db8::1"]})
        );
        assert_eq!(
            GandiDns::rrset_body(&rec(RecordKind::Txt(vec!["tok".into()]), "example.com", 60)),
            serde_json::json!({"rrset_ttl": 60, "rrset_values": ["\"tok\""]})
        );
    }

    /// Golden: the structured multi-field kinds (MX/SRV/CAA/NS/PTR/TLSA), each
    /// rendered to its presentation-format `value`.
    #[test]
    fn rrset_body_golden_for_structured_kinds() {
        let value = |kind, name: &str| {
            GandiDns::record_value(&DnsRecord {
                kind,
                name: name.into(),
                ttl: 300,
            })
        };
        assert_eq!(
            value(
                RecordKind::Mx {
                    preference: 10,
                    exchange: "mx.example.com".into(),
                },
                "example.com"
            ),
            "10 mx.example.com."
        );
        assert_eq!(
            value(
                RecordKind::Srv {
                    priority: 1,
                    weight: 5,
                    port: 443,
                    target: "svc.example.com".into(),
                },
                "_svc._tcp.example.com"
            ),
            "1 5 443 svc.example.com."
        );
        assert_eq!(
            value(
                RecordKind::Caa {
                    flags: 0,
                    tag: CaaTag::Issue,
                    value: "letsencrypt.org".into(),
                },
                "example.com"
            ),
            "0 issue \"letsencrypt.org\""
        );
        assert_eq!(
            value(RecordKind::Ns("ns1.example.net".into()), "sub.example.com"),
            "ns1.example.net."
        );
        assert_eq!(
            value(
                RecordKind::Ptr("host.example.com".into()),
                "7.113.0.203.example.com"
            ),
            "host.example.com."
        );
        assert_eq!(
            value(
                RecordKind::Tlsa {
                    usage: 3,
                    selector: 1,
                    matching: 1,
                    data: "abcdef".into(),
                },
                "_443._tcp.example.com"
            ),
            "3 1 1 abcdef"
        );
    }

    /// Golden: HTTPS/SVCB presentation `value` — AliasMode (no SvcParams) is
    /// `<priority> <target.>`; ServiceMode appends space-joined SvcParams with a
    /// comma-bearing value quoted and a comma-free one bare.
    #[test]
    fn record_value_golden_for_https_svcb() {
        // ServiceMode: comma value quoted; a valueless key stays bare.
        assert_eq!(
            GandiDns::record_value(&DnsRecord {
                kind: RecordKind::Https {
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
                name: "example.com".into(),
                ttl: 300,
            }),
            "1 . alpn=\"h2,h3\" no-default-alpn"
        );
        // ServiceMode: a comma-free value stays bare (ipv4hint).
        assert_eq!(
            GandiDns::record_value(&DnsRecord {
                kind: RecordKind::Svcb {
                    priority: 1,
                    target: "svc.example.net".into(),
                    params: vec![SvcParam {
                        key: "ipv4hint".into(),
                        value: "203.0.113.1".into(),
                    }],
                },
                name: "_8443._tcp.example.com".into(),
                ttl: 300,
            }),
            "1 svc.example.net. ipv4hint=203.0.113.1"
        );
        // AliasMode: no SvcParams → `<priority> <target.>`.
        assert_eq!(
            GandiDns::record_value(&DnsRecord {
                kind: RecordKind::Svcb {
                    priority: 0,
                    target: "svc.example.net".into(),
                    params: vec![],
                },
                name: "_8443._tcp.example.com".into(),
                ttl: 300,
            }),
            "0 svc.example.net."
        );
    }

    #[test]
    fn caa_value_escapes_embedded_quote_and_backslash() {
        assert_eq!(
            GandiDns::record_value(&DnsRecord {
                kind: RecordKind::Caa {
                    flags: 0,
                    tag: CaaTag::Iodef,
                    value: "mailto:a\"b\\c".into(),
                },
                name: "example.com".into(),
                ttl: 300,
            }),
            "0 iodef \"mailto:a\\\"b\\\\c\""
        );
    }

    /// Gandi LiveDNS supports every writable kind the writer models.
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
            assert!(p.supports_kind(tag), "gandi should support {tag}");
        }
        assert_eq!(p.supported_kinds().len(), 12);
        assert_eq!(p.name(), "gandi");
    }
}
