//! Google Cloud DNS provider (v1 REST, OAuth2 bearer token).
//!
//! Cloud DNS edits are atomic **changes** (a batch of `additions` + `deletions`
//! posted to `…/changes`) with no in-place update: to replace a record set you
//! delete the current one — by its *exact* current object — and add the new one
//! in the same change, so `upsert` first reads the current rrset. Two format
//! rules the helpers encode: names are FQDNs with a trailing dot, and TXT rrdata
//! is double-quoted. Request construction is pure + unit-tested; the round-trip is a live seam.
//!
//! **Credential (cap-req #31): a LONG-LIVED service-account key, exchanged host-side.** The adapter
//! takes the whole service-account JSON (`client_email` + `private_key` + `project_id`), builds and
//! RS256-signs a JWT host-side, and exchanges it (`urn:ietf:params:oauth:grant-type:jwt-bearer`) at the
//! FIXED Google token endpoint for a short-lived access token, which it CACHES (per adapter instance)
//! until near expiry. No short-lived token is ever accepted as the stored credential, and the minted
//! token is never sealed, returned, or logged. The token endpoint is pinned (not read from the JSON's
//! `token_uri`), so a crafted SA JSON cannot redirect the exchange.

use async_trait::async_trait;
use serde::Deserialize;

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind, RecordKindTag};

const DEFAULT_API_BASE: &str = "https://dns.googleapis.com/dns/v1";
/// The FIXED Google OAuth2 token endpoint (pinned — never taken from the service-account JSON).
const GCP_TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
/// The Cloud DNS read-write scope the minted token is requested for.
const GCP_SCOPE: &str = "https://www.googleapis.com/auth/ndev.clouddns.readwrite";

/// The service-account JSON fields the adapter needs (the rest of the key file is ignored). The
/// `token_uri` in the file is deliberately NOT used for the exchange (pinned) — only the signing
/// identity + key + project matter.
#[derive(Deserialize)]
struct ServiceAccountKey {
    client_email: String,
    private_key: String,
    project_id: String,
}

/// A Google Cloud DNS editor scoped to one managed zone, authenticating via a sealed service-account
/// key exchanged host-side for a cached short-lived token.
pub struct GcpDns {
    client: reqwest::Client,
    api_base: String,
    /// The token-exchange endpoint (pinned to [`GCP_TOKEN_ENDPOINT`]; overridable in tests only).
    token_endpoint: String,
    project: String,
    zone: String,
    client_email: String,
    signing_key: rsa::pkcs1v15::SigningKey<rsa::sha2::Sha256>,
    token_cell: crate::oauth::TokenCell,
}

impl GcpDns {
    /// Build a provider for managed `zone` from a service-account JSON key (cap-req #31). The project is
    /// read from the key's `project_id`. A malformed JSON / missing field / bad private key is a
    /// [`DnsError::Config`].
    pub fn from_service_account(
        zone: impl Into<String>,
        service_account_json: &str,
    ) -> Result<Self, DnsError> {
        use rsa::pkcs8::DecodePrivateKey;
        let sa: ServiceAccountKey = serde_json::from_str(service_account_json)
            .map_err(|e| DnsError::Config(format!("GCP service-account JSON: {e}")))?;
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(&sa.private_key)
            .map_err(|e| DnsError::Config(format!("GCP service-account private key: {e}")))?;
        Ok(Self {
            client: reqwest::Client::new(),
            api_base: DEFAULT_API_BASE.to_string(),
            token_endpoint: GCP_TOKEN_ENDPOINT.to_string(),
            project: sa.project_id,
            zone: zone.into(),
            client_email: sa.client_email,
            signing_key: rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(key),
            token_cell: crate::oauth::TokenCell::new(),
        })
    }

    /// Override the API base URL (for pointing tests at a stub).
    pub fn with_api_base(mut self, base: impl Into<String>) -> Self {
        self.api_base = base.into();
        self
    }

    /// Override the token-exchange endpoint — TESTS ONLY (point it at a local mock). Production pins
    /// [`GCP_TOKEN_ENDPOINT`].
    #[doc(hidden)]
    pub fn with_token_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.token_endpoint = endpoint.into();
        self
    }

    /// A valid access token — cached, or minted by a fresh JWT-bearer exchange (cap-req #31).
    async fn token(&self) -> Result<String, DnsError> {
        self.token_cell.get_or_exchange(|| self.exchange()).await
    }

    /// Mint a token: sign a JWT with the service-account key and POST the jwt-bearer assertion to the
    /// FIXED token endpoint.
    async fn exchange(&self) -> Result<(String, u64), DnsError> {
        let assertion = self.signed_jwt()?;
        crate::oauth::post_token(
            &self.client,
            &self.token_endpoint,
            &[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", &assertion),
            ],
        )
        .await
    }

    /// Build + RS256-sign the JWT-bearer assertion (`iss`=client_email, `scope`=Cloud DNS,
    /// `aud`=the pinned token endpoint, short `iat`/`exp`).
    fn signed_jwt(&self) -> Result<String, DnsError> {
        use base64::Engine;
        use rsa::signature::{SignatureEncoding, Signer};
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let now = crate::now_secs();
        let header = b64.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = serde_json::json!({
            "iss": self.client_email,
            "scope": GCP_SCOPE,
            "aud": self.token_endpoint,
            "iat": now,
            "exp": now + 3600,
        });
        let claims_json =
            serde_json::to_vec(&claims).map_err(|e| DnsError::Backend(e.to_string()))?;
        let signing_input = format!("{header}.{}", b64.encode(claims_json));
        let signature = self.signing_key.sign(signing_input.as_bytes());
        Ok(format!(
            "{signing_input}.{}",
            b64.encode(signature.to_bytes())
        ))
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
            .bearer_auth(&self.token().await?)
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
            .bearer_auth(&self.token().await?)
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

    /// A throwaway RSA key (PKCS#8 PEM) + a service-account JSON wrapping it, for construction tests.
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA5SrFVYD26w2NArwi\n\
6uNqb0rEKalyCAaSLeURe7sWG6FSMY1SoZ0klwDoVzTw83Sg6UWOlP7ZULzP43F1\n\
dfBy5QIDAQABAkEA4t+KBxEq4h9DN67r3qCP8WgSdbBjzOA8faUmvtjDlUsrcPrr\n\
97v9jcBeflXcw/uG8pQ1p+tWJDOKA+UN3oECzQIhAPe0thijPyMLOQEX2K3LFLtK\n\
Z0oHkKqFyXt7kZmDUlMvAiEA7Ncl7GYtqI5ZjalxU/SB5a7sL+6KqJcK1lXgvnKU\n\
pisCIAF7SzuKfm4vOwAOrHUdqdoU79k5glwCwNnEO3K3nl5xAiBSLNgwrMc8y59Q\n\
4rC6k4Saf9XdT6P2mOmeso9XJQRknwIgG689c5E5fvq9T4eam9dBCNJup4IgI6VT\n\
sAmaXlKwnv8=\n\
-----END PRIVATE KEY-----\n";

    /// A minimal service-account JSON with `project_id = proj`, for the construction tests.
    fn test_sa_json() -> String {
        serde_json::json!({
            "client_email": "dns@proj.iam.gserviceaccount.com",
            "private_key": TEST_KEY_PEM,
            "project_id": "proj",
            "token_uri": "https://oauth2.googleapis.com/token",
        })
        .to_string()
    }

    fn provider() -> GcpDns {
        GcpDns::from_service_account("zone1", &test_sa_json())
            .expect("valid SA JSON")
            .with_api_base("https://gcp.test/dns/v1")
    }

    #[test]
    fn service_account_json_reads_project_and_builds_signer() {
        let p = provider();
        assert_eq!(p.project, "proj");
        assert_eq!(p.client_email, "dns@proj.iam.gserviceaccount.com");
        // A valid JWT-bearer assertion is three base64url segments.
        let jwt = p.signed_jwt().expect("sign");
        assert_eq!(jwt.split('.').count(), 3);
    }

    #[tokio::test]
    async fn oauth_gate_gcp_jwt_bearer_mint_and_cache() {
        let (url, count) =
            crate::oauth::test_mock::spawn(r#"{"access_token":"gcp-minted","expires_in":3600}"#)
                .await;
        let p = GcpDns::from_service_account("zone1", &test_sa_json())
            .unwrap()
            .with_token_endpoint(url);
        assert_eq!(p.token().await.unwrap(), "gcp-minted");
        assert_eq!(p.token().await.unwrap(), "gcp-minted");
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the JWT-bearer exchange ran once; the second call was cached"
        );
    }

    #[test]
    fn malformed_service_account_json_is_config_error() {
        assert!(GcpDns::from_service_account("z", "{not json").is_err());
        assert!(
            GcpDns::from_service_account("z", r#"{"client_email":"x","project_id":"p"}"#).is_err(),
            "missing private_key"
        );
        assert!(
            GcpDns::from_service_account(
                "z",
                r#"{"client_email":"x","project_id":"p","private_key":"not a pem"}"#
            )
            .is_err(),
            "bad private key"
        );
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
