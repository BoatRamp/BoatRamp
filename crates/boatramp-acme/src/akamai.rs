//! Akamai Edge DNS provider (Zone Management API v2).
//!
//! Requests are signed with Akamai's [EdgeGrid scheme](https://techdocs.akamai.com/developer/docs/authenticate-with-edgegrid)
//! (`EG1-HMAC-SHA256`): a per-request signing key is `HMAC-SHA256(client_secret,
//! timestamp)`, and the signature is `HMAC-SHA256(signing_key, data_to_sign)`
//! over a tab-joined `method \t https \t host \t path \t headers \t content_hash
//! \t auth_header`. Per the scheme, the content hash is only included for `POST`.
//! Records are addressed by full FQDN; `upsert` GETs to pick create (`POST`) vs
//! replace (`PUT`); TXT rdata is quoted, CNAME rdata a trailing-dot FQDN.
//!
//! The signing composition + timestamp are pure + unit-tested (injected clock);
//! the HMAC round-trip against a real Akamai contract is the live seam.

use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::dns::{DnsError, DnsProvider, DnsRecord, RecordKind};

type HmacSha256 = Hmac<Sha256>;

const API_PREFIX: &str = "/config-dns/v2";

/// An Akamai Edge DNS editor scoped to one zone, holding the EdgeGrid credentials.
pub struct AkamaiDns {
    client: reqwest::Client,
    /// API host, e.g. `akab-xxxx.luna.akamaiapis.net` (no scheme).
    host: String,
    client_token: String,
    client_secret: String,
    access_token: String,
    zone: String,
}

impl AkamaiDns {
    /// Build from the EdgeGrid credentials (`host`, `client_token`,
    /// `client_secret`, `access_token`) and the managed `zone`.
    pub fn new(
        host: impl Into<String>,
        client_token: impl Into<String>,
        client_secret: impl Into<String>,
        access_token: impl Into<String>,
        zone: impl Into<String>,
    ) -> Self {
        Self {
            client: reqwest::Client::new(),
            host: host.into(),
            client_token: client_token.into(),
            client_secret: client_secret.into(),
            access_token: access_token.into(),
            zone: zone.into(),
        }
    }

    /// `/config-dns/v2/zones/{zone}/names/{fqdn}/types/{type}` — the record path.
    fn record_path(&self, record: &DnsRecord) -> String {
        format!(
            "{API_PREFIX}/zones/{}/names/{}/types/{}",
            self.zone,
            record.name,
            record.kind.as_str()
        )
    }

    /// The rdata value: TXT is double-quoted, CNAME is a trailing-dot FQDN, others raw.
    fn rdata_value(record: &DnsRecord) -> String {
        match record.kind {
            RecordKind::Txt => format!("\"{}\"", record.value),
            RecordKind::Cname if !record.value.ends_with('.') => format!("{}.", record.value),
            _ => record.value.clone(),
        }
    }

    /// The create/replace body for `record`.
    fn record_body(record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({
            "name": record.name,
            "type": record.kind.as_str(),
            "ttl": record.ttl,
            "rdata": [Self::rdata_value(record)],
        })
    }

    /// The full `Authorization` header for one request, with the timestamp + nonce
    /// injected so the signature is reproducible in tests.
    fn authorization(
        &self,
        method: &str,
        path: &str,
        content_hash: &str,
        timestamp: &str,
        nonce: &str,
    ) -> String {
        let prefix = auth_prefix(&self.client_token, &self.access_token, timestamp, nonce);
        let signing_key = hmac_b64(self.client_secret.as_bytes(), timestamp.as_bytes());
        let data = data_to_sign(method, &self.host, path, content_hash, &prefix);
        let signature = hmac_b64(signing_key.as_bytes(), data.as_bytes());
        format!("{prefix}signature={signature}")
    }

    /// Sign + send one request. The content hash is included only for `POST`
    /// bodies, per the EdgeGrid scheme.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&[u8]>,
    ) -> Result<reqwest::StatusCode, DnsError> {
        let timestamp = eg_timestamp(crate::now_secs());
        let nonce = make_nonce();
        let content_hash = match (method.as_str(), body) {
            ("POST", Some(b)) => {
                base64::engine::general_purpose::STANDARD.encode(Sha256::digest(b))
            }
            _ => String::new(),
        };
        let auth = self.authorization(method.as_str(), path, &content_hash, &timestamp, &nonce);
        let url = format!("https://{}{path}", self.host);
        let mut req = self
            .client
            .request(method, &url)
            .header(reqwest::header::AUTHORIZATION, auth);
        if let Some(body) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(resp.status())
    }

    /// Whether the `(fqdn, type)` record already exists (200 vs 404).
    async fn exists(&self, record: &DnsRecord) -> Result<bool, DnsError> {
        let status = self
            .send(reqwest::Method::GET, &self.record_path(record), None)
            .await?;
        match status.as_u16() {
            200 => Ok(true),
            404 => Ok(false),
            other => Err(DnsError::Backend(format!(
                "akamai GET record: HTTP {other}"
            ))),
        }
    }
}

/// `HMAC-SHA256(key, msg)`, base64-standard-encoded.
fn hmac_b64(key: &[u8], msg: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// The authorization value up to (and including) the trailing `;` before the
/// signature — this exact string is both signed and prefixed onto the final header.
fn auth_prefix(client_token: &str, access_token: &str, timestamp: &str, nonce: &str) -> String {
    format!(
        "EG1-HMAC-SHA256 client_token={client_token};access_token={access_token};timestamp={timestamp};nonce={nonce};"
    )
}

/// The tab-joined data-to-sign: method, scheme, host, path, canonicalized headers
/// (none), content hash, and the auth prefix (RFC-less, per Akamai's scheme).
fn data_to_sign(
    method: &str,
    host: &str,
    path: &str,
    content_hash: &str,
    auth_prefix: &str,
) -> String {
    [
        method,
        "https",
        host,
        path,
        "", // canonicalized headers — none are signed
        content_hash,
        auth_prefix,
    ]
    .join("\t")
}

/// EdgeGrid timestamp: `yyyyMMddTHH:mm:ss+0000` (UTC). Pure given Unix seconds.
fn eg_timestamp(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let secs = unix_secs % 86_400;
    let (hour, min, sec) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}{month:02}{day:02}T{hour:02}:{min:02}:{sec:02}+0000")
}

/// Howard Hinnant's days→(y,m,d) civil-date algorithm (proleptic Gregorian).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A per-request nonce (high-resolution clock, hex) — EdgeGrid only needs it
/// unique within the timestamp window.
fn make_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:032x}")
}

#[async_trait]
impl DnsProvider for AkamaiDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let body = serde_json::to_vec(&Self::record_body(record))
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        // POST creates, PUT replaces — pick by whether it already exists.
        let method = if self.exists(record).await? {
            reqwest::Method::PUT
        } else {
            reqwest::Method::POST
        };
        let status = self
            .send(method, &self.record_path(record), Some(&body))
            .await?;
        if !status.is_success() {
            return Err(DnsError::Backend(format!(
                "akamai upsert record: HTTP {}",
                status.as_u16()
            )));
        }
        Ok(())
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let status = self
            .send(reqwest::Method::DELETE, &self.record_path(record), None)
            .await?;
        match status.as_u16() {
            404 => Ok(()), // already gone
            s if (200..300).contains(&s) => Ok(()),
            s => Err(DnsError::Backend(format!("akamai delete record: HTTP {s}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider() -> AkamaiDns {
        AkamaiDns::new(
            "akab-h.luna.akamaiapis.net",
            "ct",
            "sekret",
            "at",
            "example.com",
        )
    }

    #[test]
    fn record_path_is_fqdn_typed() {
        let p = provider().record_path(&DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.deploy.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        });
        assert_eq!(
            p,
            "/config-dns/v2/zones/example.com/names/_acme-challenge.deploy.example.com/types/TXT"
        );
    }

    #[test]
    fn txt_rdata_is_quoted_cname_is_dotted() {
        let txt = AkamaiDns::record_body(&DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.deploy.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        });
        assert_eq!(txt["rdata"][0], "\"abc\"");
        assert_eq!(txt["type"], "TXT");
        assert_eq!(txt["name"], "_acme-challenge.deploy.example.com");

        let cname = AkamaiDns::record_body(&DnsRecord {
            kind: RecordKind::Cname,
            name: "*.deploy.example.com".into(),
            value: "lb.example.net".into(),
            ttl: 120,
        });
        assert_eq!(cname["rdata"][0], "lb.example.net.");
    }

    #[test]
    fn eg_timestamp_matches_known_values() {
        assert_eq!(eg_timestamp(0), "19700101T00:00:00+0000");
        // RFC 7231's worked example instant, in EdgeGrid format.
        assert_eq!(eg_timestamp(784_887_151), "19941115T08:12:31+0000");
    }

    #[test]
    fn auth_prefix_shape() {
        assert_eq!(
            auth_prefix("ct", "at", "19700101T00:00:00+0000", "nonce1"),
            "EG1-HMAC-SHA256 client_token=ct;access_token=at;timestamp=19700101T00:00:00+0000;nonce=nonce1;"
        );
    }

    #[test]
    fn data_to_sign_is_tab_joined_with_empty_headers() {
        let d = data_to_sign("GET", "h", "/p", "", "EG1-HMAC-SHA256 ...;");
        assert_eq!(d, "GET\thttps\th\t/p\t\t\tEG1-HMAC-SHA256 ...;");
    }

    #[test]
    fn signature_is_deterministic_for_fixed_inputs() {
        // The whole point of injecting timestamp+nonce: a fixed request signs the
        // same way every time (regression-guards the EdgeGrid composition).
        let a = provider().authorization(
            "GET",
            "/config-dns/v2/zones/example.com",
            "",
            "19700101T00:00:00+0000",
            "n1",
        );
        let b = provider().authorization(
            "GET",
            "/config-dns/v2/zones/example.com",
            "",
            "19700101T00:00:00+0000",
            "n1",
        );
        assert_eq!(a, b);
        assert!(a.starts_with("EG1-HMAC-SHA256 client_token=ct;access_token=at;"));
        assert!(a.contains(";signature="));
        // A different nonce changes the signature.
        let c = provider().authorization(
            "GET",
            "/config-dns/v2/zones/example.com",
            "",
            "19700101T00:00:00+0000",
            "n2",
        );
        assert_ne!(a, c);
    }
}
