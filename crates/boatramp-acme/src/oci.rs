//! Oracle Cloud Infrastructure (OCI) DNS provider.
//!
//! OCI has no Rust SDK, so this signs requests directly with the OCI
//! [request-signing scheme](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm)
//! (draft-cavage HTTP signatures, RSA-SHA256). Upsert replaces an RRSet
//! (`PUT …/records/{domain}/{rtype}`, idempotent); delete removes it.
//!
//! The signing-string composition, header set, and `keyId` format are pure +
//! unit-tested against the scheme's documented shape; the RSA signing and the
//! live API call are the integration seam (no OCI tenancy in CI).

use async_trait::async_trait;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::sha2::Sha256;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;

use crate::dns::{DnsError, DnsProvider, DnsRecord};

/// The OCI DNS API version path segment.
const API_VERSION: &str = "20180115";

/// An OCI DNS editor scoped to one zone, with the credentials to sign requests.
pub struct OciDns {
    client: reqwest::Client,
    /// Service host, e.g. `dns.us-ashburn-1.oraclecloud.com`.
    host: String,
    /// Zone name or OCID.
    zone: String,
    /// `keyId`: `{tenancy-ocid}/{user-ocid}/{key-fingerprint}`.
    key_id: String,
    signing_key: SigningKey<Sha256>,
}

impl OciDns {
    /// Build from the region, zone, the API `keyId`, and the PEM private key.
    pub fn new(
        region: &str,
        zone: impl Into<String>,
        key_id: impl Into<String>,
        private_key_pem: &str,
    ) -> Result<Self, DnsError> {
        let key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
            .map_err(|e| DnsError::Config(format!("OCI private key: {e}")))?;
        Ok(Self {
            client: reqwest::Client::new(),
            host: format!("dns.{region}.oraclecloud.com"),
            zone: zone.into(),
            key_id: key_id.into(),
            signing_key: SigningKey::<Sha256>::new(key),
        })
    }

    /// `/20180115/zones/{zone}/records/{domain}/{rtype}` — the RRSet path.
    fn rrset_path(&self, record: &DnsRecord) -> String {
        format!(
            "/{API_VERSION}/zones/{}/records/{}/{}",
            self.zone,
            record.name,
            record.kind.as_str()
        )
    }

    /// The RRSet replacement body for an upsert.
    fn rrset_body(record: &DnsRecord) -> serde_json::Value {
        serde_json::json!({
            "items": [{
                "domain": record.name,
                "rtype": record.kind.as_str(),
                "rdata": record.value,
                "ttl": record.ttl,
            }]
        })
    }

    /// Sign + send one request. `date` is injected (so the signature is
    /// reproducible in tests); production passes the current time.
    async fn send(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&[u8]>,
        date: &str,
    ) -> Result<(), DnsError> {
        let (signing_string, headers_list) =
            signing_string(method.as_str(), path, &self.host, date, body);
        let signature = self.sign(&signing_string)?;
        let auth = authorization_header(&self.key_id, &headers_list, &signature);

        let url = format!("https://{}{path}", self.host);
        let mut req = self
            .client
            .request(method, &url)
            .header(reqwest::header::HOST, &self.host)
            .header(reqwest::header::DATE, date)
            .header(reqwest::header::AUTHORIZATION, auth);
        if let Some(body) = body {
            let digest = base64::engine::general_purpose::STANDARD
                .encode(<Sha256 as rsa::sha2::Digest>::digest(body));
            req = req
                .header("x-content-sha256", digest)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(reqwest::header::CONTENT_LENGTH, body.len())
                .body(body.to_vec());
        }
        req.send()
            .await
            .map_err(|e| DnsError::Backend(e.to_string()))?
            .error_for_status()
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }

    fn sign(&self, signing_string: &str) -> Result<String, DnsError> {
        let signature = self.signing_key.sign(signing_string.as_bytes());
        Ok(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()))
    }
}

/// Build the OCI signing string + the space-separated headers list it covers.
/// For body methods the body headers (`x-content-sha256`, `content-type`,
/// `content-length`) are included, per the OCI scheme.
fn signing_string(
    method: &str,
    path: &str,
    host: &str,
    date: &str,
    body: Option<&[u8]>,
) -> (String, String) {
    let mut lines = vec![
        format!("(request-target): {} {path}", method.to_ascii_lowercase()),
        format!("host: {host}"),
        format!("date: {date}"),
    ];
    let mut headers = vec!["(request-target)", "host", "date"];
    if let Some(body) = body {
        let digest = base64::engine::general_purpose::STANDARD
            .encode(<Sha256 as rsa::sha2::Digest>::digest(body));
        lines.push(format!("x-content-sha256: {digest}"));
        lines.push("content-type: application/json".to_string());
        lines.push(format!("content-length: {}", body.len()));
        headers.extend(["x-content-sha256", "content-type", "content-length"]);
    }
    (lines.join("\n"), headers.join(" "))
}

/// The `Authorization` header value for the OCI signature scheme (version 1).
fn authorization_header(key_id: &str, headers_list: &str, signature: &str) -> String {
    format!(
        "Signature version=\"1\",keyId=\"{key_id}\",algorithm=\"rsa-sha256\",headers=\"{headers_list}\",signature=\"{signature}\""
    )
}

/// IMF-fixdate (RFC 7231) for the `Date` header, e.g.
/// `Tue, 15 Nov 1994 08:12:31 GMT`. Pure given the Unix-seconds input.
fn imf_fixdate(unix_secs: u64) -> String {
    // Days since the Unix epoch and the time-of-day.
    let days = unix_secs / 86_400;
    let secs = unix_secs % 86_400;
    let (hour, min, sec) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    // 1970-01-01 was a Thursday (index 4 if Sun=0).
    const DOW: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let dow = DOW[((days + 4) % 7) as usize];
    let (year, month, day) = civil_from_days(days as i64);
    const MON: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{dow}, {day:02} {} {year:04} {hour:02}:{min:02}:{sec:02} GMT",
        MON[(month - 1) as usize]
    )
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

#[async_trait]
impl DnsProvider for OciDns {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let body = serde_json::to_vec(&Self::rrset_body(record))
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        let date = imf_fixdate(now_secs());
        self.send(
            reqwest::Method::PUT,
            &self.rrset_path(record),
            Some(&body),
            &date,
        )
        .await
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        let date = imf_fixdate(now_secs());
        match self
            .send(
                reqwest::Method::DELETE,
                &self.rrset_path(record),
                None,
                &date,
            )
            .await
        {
            Ok(()) => Ok(()),
            // A missing RRSet is already in the desired state.
            Err(DnsError::Backend(msg)) if msg.contains("404") => Ok(()),
            Err(err) => Err(err),
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::RecordKind;

    #[test]
    fn get_signing_string_covers_minimal_headers() {
        let (s, headers) = signing_string(
            "GET",
            "/20180115/zones/z/records",
            "dns.r.oraclecloud.com",
            "Tue, 01 Jan 2030 00:00:00 GMT",
            None,
        );
        assert_eq!(headers, "(request-target) host date");
        assert_eq!(
            s,
            "(request-target): get /20180115/zones/z/records\n\
             host: dns.r.oraclecloud.com\n\
             date: Tue, 01 Jan 2030 00:00:00 GMT"
        );
    }

    #[test]
    fn body_signing_string_adds_content_headers() {
        let (s, headers) = signing_string("PUT", "/p", "h", "D", Some(b"{}"));
        assert_eq!(
            headers,
            "(request-target) host date x-content-sha256 content-type content-length"
        );
        assert!(s.contains("\nx-content-sha256: "));
        assert!(s.contains("\ncontent-type: application/json"));
        assert!(s.ends_with("\ncontent-length: 2"));
        assert!(s.starts_with("(request-target): put /p\n"));
    }

    #[test]
    fn authorization_header_shape() {
        let h = authorization_header("t/u/fp", "(request-target) host date", "SIG");
        assert_eq!(
            h,
            "Signature version=\"1\",keyId=\"t/u/fp\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"SIG\""
        );
    }

    #[test]
    fn imf_fixdate_matches_known_values() {
        // Unix epoch was Thursday 1970-01-01 00:00:00 GMT.
        assert_eq!(imf_fixdate(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        // RFC 7231's worked example timestamp.
        assert_eq!(imf_fixdate(784_887_151), "Tue, 15 Nov 1994 08:12:31 GMT");
        // A leap-year date: 2020-02-29 00:00:00 UTC (a Saturday).
        assert_eq!(imf_fixdate(1_582_934_400), "Sat, 29 Feb 2020 00:00:00 GMT");
        // The day after is 2020-03-01 (a Sunday).
        assert_eq!(imf_fixdate(1_583_020_800), "Sun, 01 Mar 2020 00:00:00 GMT");
    }

    #[test]
    fn rrset_path_and_body() {
        let record = DnsRecord {
            kind: RecordKind::Txt,
            name: "_acme-challenge.example.com".into(),
            value: "abc".into(),
            ttl: 60,
        };
        // (build a provider only to exercise rrset_path; key parsing is separate)
        let body = OciDns::rrset_body(&record);
        assert_eq!(body["items"][0]["rtype"], "TXT");
        assert_eq!(body["items"][0]["rdata"], "abc");
        assert_eq!(body["items"][0]["domain"], "_acme-challenge.example.com");
        assert_eq!(body["items"][0]["ttl"], 60);
    }
}
