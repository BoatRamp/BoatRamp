//! AWS **Signature Version 4** engine (PLAN-blob-s3-ingress, folded "SigV4 verifier" — Security
//! CRITICAL-2), full day one.
//!
//! This is the SDK-independent core: given a parsed request and a `secret_access_key`, it computes
//! the SigV4 **canonical request → string-to-sign → signature**, and verifies a client signature in
//! **constant time**. It covers the payload-signing modes real S3 SDKs send:
//!
//! - `x-amz-content-sha256` = a real hex SHA-256 of the body,
//! - `UNSIGNED-PAYLOAD`,
//! - and `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` (aws-chunked) — the per-chunk signature *chain* is
//!   verified while streaming (via [`ChunkVerifier`]), so the body is NEVER fully buffered.
//!
//! Both **header** authorization (`Authorization: AWS4-HMAC-SHA256 …`) and **presigned query**
//! authorization (`X-Amz-Signature=…`) are supported.
//!
//! Security posture (all enforced, not optional):
//! - **Constant-time** signature comparison (`aws_lc_rs::constant_time`), so a mismatch leaks no
//!   timing oracle.
//! - **Bounded clock skew** ([`MAX_CLOCK_SKEW_SECS`], tight, cf. `cose::POP_SKEW_SECS`).
//! - A single, uniform failure type ([`SigV4Error`]) — the *caller* (the M2 face) maps EVERY variant
//!   to one indistinguishable `403`, so there is no which-check-failed oracle (mirroring
//!   `tenant_secrets::refuse`). The variants exist only for host-side logging/tests.
//!
//! Canonicalization is built against the AWS `aws-sig-v4-test-suite` vectors (see the fixtures under
//! `tests/fixtures/sigv4/` and the `vector_*` tests below), and property-tested for sign→verify
//! round-trips.

use std::collections::BTreeMap;

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::digest::{self, SHA256};
use aws_lc_rs::hmac;

/// The SigV4 algorithm token.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";
/// The streaming (aws-chunked) payload marker in `x-amz-content-sha256`.
pub const STREAMING_PAYLOAD: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
/// The streaming-with-trailer payload marker (checksum trailer after the last chunk).
pub const STREAMING_PAYLOAD_TRAILER: &str = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER";
/// The unsigned-payload marker in `x-amz-content-sha256`.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
/// The per-chunk string-to-sign algorithm token for aws-chunked.
const CHUNK_ALGORITHM: &str = "AWS4-HMAC-SHA256-PAYLOAD";
/// SHA-256 of the empty string (the canonical "no body" payload hash).
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Maximum tolerated clock skew between the request's `x-amz-date` and the server's clock, in
/// seconds. Tight on purpose: it bounds signature replay reuse across the request timestamp without
/// a stateful nonce cache. Mirrors the spirit of `cose::POP_SKEW_SECS`/`POP_WINDOW_SECS`.
pub const MAX_CLOCK_SKEW_SECS: i64 = 300;

/// Hard upper bound on the byte size a single aws-chunked chunk may declare in its header
/// (`<hex-size>;chunk-signature=…`). 16 MiB — real S3 SDKs chunk at ≤8 MiB, so this is comfortably
/// above any honest client while refusing a hostile header. This is a **security invariant, not a
/// policy knob** (M2-review MEDIUM-1): `parse_chunk_header` parses the declared size with
/// `usize::from_str_radix(.., 16)`, so an unbounded value near `usize::MAX` would let the downstream
/// `data_start + size` / `data_end + 2` framing math in `chunked::take_one_chunk` wrap (release
/// builds have no overflow checks) and panic on a bad slice range. A declared size over this bound is
/// rejected up front as a [`SigV4Error::MalformedChunk`].
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// A SigV4 verification/signing failure. **Uniform to the client**: the M2 face maps every variant
/// to one indistinguishable 403 (`BoatrampSignatureMismatch`-class), so an attacker cannot learn
/// *which* check failed. The variants are for host-side logs + these unit tests only.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SigV4Error {
    /// The `Authorization` header / presigned query was absent or unparsable.
    #[error("malformed authorization")]
    MalformedAuthorization,
    /// The algorithm was not `AWS4-HMAC-SHA256`.
    #[error("unsupported signature algorithm")]
    UnsupportedAlgorithm,
    /// A required header named in `SignedHeaders` was not present on the request.
    #[error("a signed header is missing from the request")]
    MissingSignedHeader,
    /// `x-amz-date` was absent or not a valid ISO8601 basic timestamp.
    #[error("missing or invalid request date")]
    BadDate,
    /// The request date is outside the tolerated clock-skew window.
    #[error("request date outside the allowed skew window")]
    SkewExceeded,
    /// A presigned request is past its `X-Amz-Expires` window.
    #[error("presigned request expired")]
    Expired,
    /// The computed signature did not match the client's (constant-time compared).
    #[error("signature mismatch")]
    SignatureMismatch,
    /// An aws-chunked chunk was malformed (bad size line / missing chunk signature).
    #[error("malformed streaming chunk")]
    MalformedChunk,
}

/// The parsed SigV4 credential scope: `<access_key_id>/<date>/<region>/<service>/aws4_request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialScope {
    /// The public access key id.
    pub access_key_id: String,
    /// The scope date, `YYYYMMDD`.
    pub date: String,
    /// The AWS region (e.g. `us-east-1`; boatramp's local face uses a fixed region).
    pub region: String,
    /// The service (`s3` for the ingress face).
    pub service: String,
}

impl CredentialScope {
    /// The `<date>/<region>/<service>/aws4_request` scope string used in the string-to-sign.
    pub fn scope_string(&self) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            self.date, self.region, self.service
        )
    }

    /// Parse a `Credential=` value: `<akid>/<date>/<region>/<service>/aws4_request`.
    fn parse(raw: &str) -> Result<Self, SigV4Error> {
        let parts: Vec<&str> = raw.split('/').collect();
        if parts.len() != 5 || parts[4] != "aws4_request" {
            return Err(SigV4Error::MalformedAuthorization);
        }
        Ok(Self {
            access_key_id: parts[0].to_string(),
            date: parts[1].to_string(),
            region: parts[2].to_string(),
            service: parts[3].to_string(),
        })
    }
}

/// A fully parsed SigV4 authorization (from the header OR presigned query), ready to verify.
#[derive(Debug, Clone)]
pub struct ParsedSignature {
    /// The credential scope (`akid/date/region/service/aws4_request`).
    pub scope: CredentialScope,
    /// The lowercased, `;`-joined signed-header names, in the order the client declared (which the
    /// spec requires be sorted — we re-sort defensively when canonicalizing).
    pub signed_headers: Vec<String>,
    /// The client's hex signature.
    pub signature: String,
    /// The request timestamp (`x-amz-date`, ISO8601 basic `YYYYMMDDTHHMMSSZ`).
    pub amz_date: String,
    /// Whether this came from the presigned-query form (vs the `Authorization` header).
    pub presigned: bool,
    /// The presigned expiry window in seconds (`X-Amz-Expires`), if presigned.
    pub expires: Option<i64>,
}

/// A canonical request: the four descriptors the SigV4 canonical-request is built from. The caller
/// (M2) fills these from the live HTTP request; here they are plain data so the engine is pure.
#[derive(Debug, Clone)]
pub struct CanonicalRequest<'a> {
    /// The HTTP method, upper-case (`PUT`, `POST`, …).
    pub method: &'a str,
    /// The URI path, already split from the query. Canonicalized (percent-encoded per segment) here.
    pub uri_path: &'a str,
    /// The raw query string (without the leading `?`); may be empty. For presigned verification the
    /// `X-Amz-Signature` parameter MUST be excluded by the caller before building this.
    pub query: &'a str,
    /// The request headers as `(lowercase-name, value)`. Multiple values for a name are pre-joined by
    /// the caller with `,` in received order (per the spec's multi-value handling), or passed as
    /// separate entries (we group + join here defensively).
    pub headers: &'a [(String, String)],
    /// The payload hash string that goes into the canonical request's final line: a hex SHA-256, or
    /// `UNSIGNED-PAYLOAD`, or `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`.
    pub payload_hash: &'a str,
}

/// Hex SHA-256 of `data`.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(digest::digest(&SHA256, data).as_ref())
}

/// AWS URI-encode `s` per SigV4: unreserved chars (`A-Za-z0-9-._~`) verbatim, everything else
/// percent-encoded uppercase-hex. When `encode_slash` is false, `/` is passed through (used for the
/// path, where each segment is encoded but the separators are kept); when true, `/` is encoded (used
/// for query keys/values). This is the exact ruleset the AWS test suite pins.
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            b'/' if !encode_slash => out.push('/'),
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// Canonicalize the URI path: encode each segment (the segments are already the raw path split on
/// `/`, keeping the separators). S3 uses single-encoding (the path is NOT re-normalized for `.`/`..`
/// — that is the object-key normalizer's job, `validate_object_key`, upstream). An empty path
/// canonicalizes to `/`.
fn canonical_uri(path: &str) -> String {
    if path.is_empty() {
        return "/".to_string();
    }
    // Encode each `/`-separated segment, preserving the separators.
    path.split('/')
        .map(|seg| uri_encode(seg, true))
        .collect::<Vec<_>>()
        .join("/")
}

/// Percent-decode a raw query key/value once (`%XX` → byte, `+` is NOT treated as space in the SigV4
/// path — S3 canonicalization decodes `%XX` only). Invalid `%XX` sequences are left verbatim.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    // SigV4 keys/values are text; a non-UTF8 decode is left as lossy (never a panic on hostile input).
    String::from_utf8_lossy(&out).into_owned()
}

/// Hex digit value, or `None`.
fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Encode + sort already-DECODED `(key, value)` query pairs into the canonical query string: each key
/// and value is URI-encoded (with `/` encoded), pairs are sorted by encoded key then value, and
/// joined with `&`. Shared by [`canonical_query`] (which decodes a raw wire query first) and
/// [`presigned_canonical_query`] (which drops `X-Amz-Signature` from already-decoded params).
fn encode_and_sort_query(mut pairs: Vec<(String, String)>) -> String {
    for (k, v) in &mut pairs {
        *k = uri_encode(k, true);
        *v = uri_encode(v, true);
    }
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Canonicalize a RAW (on-the-wire, still percent-encoded) query string per SigV4: split into
/// key=value pairs, **percent-decode each once**, then URI-encode + sort ([`encode_and_sort_query`]).
/// A key with no `=` gets an empty value (canonicalized as `key=`). Decoding-then-encoding is the AWS
/// rule (so a wire `%2F` and a literal `/` canonicalize identically).
fn canonical_query(query: &str) -> String {
    if query.is_empty() {
        return String::new();
    }
    let pairs: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect();
    encode_and_sort_query(pairs)
}

/// Build the canonical headers block + the `SignedHeaders` list. Headers are grouped by lowercase
/// name; multiple values are joined with `,` in received order; each value is trimmed of leading/
/// trailing whitespace and internal runs of whitespace collapsed to a single space (per the spec).
/// Only the headers named in `signed_headers` are included; a named-but-absent header is an error.
fn canonical_headers(
    headers: &[(String, String)],
    signed_headers: &[String],
) -> Result<(String, String), SigV4Error> {
    // Group values by lowercase header name, preserving received order.
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (name, value) in headers {
        grouped
            .entry(name.to_ascii_lowercase())
            .or_default()
            .push(trim_ws(value));
    }
    let mut sorted_names: Vec<String> = signed_headers
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    sorted_names.sort();
    sorted_names.dedup();

    let mut block = String::new();
    for name in &sorted_names {
        let values = grouped.get(name).ok_or(SigV4Error::MissingSignedHeader)?;
        block.push_str(name);
        block.push(':');
        block.push_str(&values.join(","));
        block.push('\n');
    }
    let signed = sorted_names.join(";");
    Ok((block, signed))
}

/// Trim + collapse internal whitespace runs to one space (SigV4 header-value normalization). Values
/// inside double-quotes are NOT specially handled — S3 signed headers here are simple ASCII.
fn trim_ws(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut prev_space = false;
    for c in v.trim().chars() {
        if c == ' ' || c == '\t' {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(c);
            prev_space = false;
        }
    }
    out
}

/// Assemble the canonical request string + return the `SignedHeaders` list actually used.
pub fn canonical_request_string(
    req: &CanonicalRequest<'_>,
    signed_headers: &[String],
) -> Result<(String, String), SigV4Error> {
    let (header_block, signed) = canonical_headers(req.headers, signed_headers)?;
    let creq = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        req.method.to_ascii_uppercase(),
        canonical_uri(req.uri_path),
        canonical_query(req.query),
        header_block,
        signed,
        req.payload_hash,
    );
    Ok((creq, signed))
}

/// The string-to-sign: `AWS4-HMAC-SHA256\n<amz_date>\n<scope>\n<hex sha256(canonical_request)>`.
pub fn string_to_sign(amz_date: &str, scope: &CredentialScope, canonical_request: &str) -> String {
    format!(
        "{ALGORITHM}\n{amz_date}\n{}\n{}",
        scope.scope_string(),
        sha256_hex(canonical_request.as_bytes()),
    )
}

/// Derive the SigV4 signing key: `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service),
/// "aws4_request")`. `secret_access_key` is the credential's secret (for boatramp's face, the
/// hex-encoded HKDF output from [`super::credential`]).
pub fn signing_key(secret_access_key: &str, date: &str, region: &str, service: &str) -> hmac::Tag {
    let k_secret = format!("AWS4{secret_access_key}");
    let k_date = hmac_sign(k_secret.as_bytes(), date.as_bytes());
    let k_region = hmac_sign(k_date.as_ref(), region.as_bytes());
    let k_service = hmac_sign(k_region.as_ref(), service.as_bytes());
    hmac_sign(k_service.as_ref(), b"aws4_request")
}

/// One HMAC-SHA256 step.
fn hmac_sign(key: &[u8], data: &[u8]) -> hmac::Tag {
    let k = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&k, data)
}

/// Compute the final hex signature for a string-to-sign under a credential scope + secret.
pub fn compute_signature(
    secret_access_key: &str,
    scope: &CredentialScope,
    string_to_sign: &str,
) -> String {
    let key = signing_key(
        secret_access_key,
        &scope.date,
        &scope.region,
        &scope.service,
    );
    hex::encode(hmac_sign(key.as_ref(), string_to_sign.as_bytes()).as_ref())
}

/// **Verify** a client's SigV4 signature over a canonical request, in constant time. Recomputes the
/// canonical request → string-to-sign → signature under `secret_access_key` and compares against
/// `parsed.signature`. Returns `Ok(())` on a match, [`SigV4Error::SignatureMismatch`] otherwise.
///
/// The caller must pass the `payload_hash` matching how the client signed (a real hash,
/// `UNSIGNED-PAYLOAD`, or the streaming marker) inside `req`. The `secret_candidates` slice lets the
/// caller supply the current AND previous rotation-derived secrets — the first that verifies wins;
/// none ⇒ mismatch. Every candidate is compared in constant time.
pub fn verify(
    req: &CanonicalRequest<'_>,
    parsed: &ParsedSignature,
    secret_candidates: &[String],
) -> Result<(), SigV4Error> {
    let (creq, _signed) = canonical_request_string(req, &parsed.signed_headers)?;
    let sts = string_to_sign(&parsed.amz_date, &parsed.scope, &creq);
    let client_sig = parsed.signature.as_bytes();
    let mut matched = false;
    for secret in secret_candidates {
        let expected = compute_signature(secret, &parsed.scope, &sts);
        // Constant-time compare: no early return on the first mismatched byte, and we try every
        // candidate rather than short-circuiting, so timing does not reveal which (if any) matched.
        if verify_slices_are_equal(expected.as_bytes(), client_sig).is_ok() {
            matched = true;
        }
    }
    if matched {
        Ok(())
    } else {
        Err(SigV4Error::SignatureMismatch)
    }
}

/// Parse the `Authorization` header form:
/// `AWS4-HMAC-SHA256 Credential=<akid>/<scope>, SignedHeaders=h1;h2, Signature=<hex>`. The request's
/// `x-amz-date` is supplied separately (it is a signed header, not part of the auth line).
pub fn parse_authorization_header(
    authorization: &str,
    amz_date: &str,
) -> Result<ParsedSignature, SigV4Error> {
    let rest = authorization
        .strip_prefix(ALGORITHM)
        .ok_or(SigV4Error::UnsupportedAlgorithm)?
        .trim_start();
    let mut credential = None;
    let mut signed_headers = None;
    let mut signature = None;
    for part in rest.split(',') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("Credential=") {
            credential = Some(v.trim());
        } else if let Some(v) = part.strip_prefix("SignedHeaders=") {
            signed_headers = Some(v.trim());
        } else if let Some(v) = part.strip_prefix("Signature=") {
            signature = Some(v.trim());
        }
    }
    let scope = CredentialScope::parse(credential.ok_or(SigV4Error::MalformedAuthorization)?)?;
    let signed_headers: Vec<String> = signed_headers
        .ok_or(SigV4Error::MalformedAuthorization)?
        .split(';')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    let signature = signature
        .ok_or(SigV4Error::MalformedAuthorization)?
        .to_string();
    if signed_headers.is_empty() || signature.is_empty() {
        return Err(SigV4Error::MalformedAuthorization);
    }
    Ok(ParsedSignature {
        scope,
        signed_headers,
        signature,
        amz_date: amz_date.to_string(),
        presigned: false,
        expires: None,
    })
}

/// Parse the presigned-query form from the request's query parameters. Reads `X-Amz-Algorithm`,
/// `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-SignedHeaders`, `X-Amz-Signature`, and (optionally)
/// `X-Amz-Expires`. The parameters are provided already percent-DECODED as `(name, value)`.
pub fn parse_presigned_query(params: &[(String, String)]) -> Result<ParsedSignature, SigV4Error> {
    let get = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    if get("X-Amz-Algorithm") != Some(ALGORITHM) {
        return Err(SigV4Error::UnsupportedAlgorithm);
    }
    let scope =
        CredentialScope::parse(get("X-Amz-Credential").ok_or(SigV4Error::MalformedAuthorization)?)?;
    let amz_date = get("X-Amz-Date").ok_or(SigV4Error::BadDate)?.to_string();
    let signed_headers: Vec<String> = get("X-Amz-SignedHeaders")
        .ok_or(SigV4Error::MalformedAuthorization)?
        .split(';')
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    let signature = get("X-Amz-Signature")
        .ok_or(SigV4Error::MalformedAuthorization)?
        .to_string();
    if signed_headers.is_empty() || signature.is_empty() {
        return Err(SigV4Error::MalformedAuthorization);
    }
    let expires = get("X-Amz-Expires").and_then(|e| e.parse::<i64>().ok());
    Ok(ParsedSignature {
        scope,
        signed_headers,
        signature,
        amz_date,
        presigned: true,
        expires,
    })
}

/// For presigned verification, rebuild the canonical query string EXCLUDING `X-Amz-Signature` (the
/// signature is computed over every query param except itself). The params are the DECODED
/// `(name, value)` pairs; this re-encodes + sorts them exactly as [`canonical_query`] does.
pub fn presigned_canonical_query(params: &[(String, String)]) -> String {
    let pairs: Vec<(String, String)> = params
        .iter()
        .filter(|(k, _)| k != "X-Amz-Signature")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    encode_and_sort_query(pairs)
}

// ---- Presigning (mint side, M3) -------------------------------------------------------------

/// Format Unix seconds as the SigV4 ISO8601 *basic* timestamp `YYYYMMDDTHHMMSSZ` (the inverse of
/// [`parse_amz_date`]). Self-contained (no chrono) — a fixed, unambiguous UTC format. Used by the
/// mint side to stamp `X-Amz-Date` on a presigned URL.
pub fn unix_to_amz_date(now_unix: i64) -> String {
    let (y, mo, d, h, mi, s) = unix_to_civil(now_unix);
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z")
}

/// Unix seconds → civil `(year, month, day, hour, min, sec)` UTC (inverse of `civil_to_unix`;
/// Howard Hinnant's `civil_from_days`). Proleptic Gregorian.
fn unix_to_civil(t: i64) -> (i64, i64, i64, i64, i64, i64) {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, secs / 3600, (secs % 3600) / 60, secs % 60)
}

/// Build a full **presigned PUT URL** for `endpoint_base`/`bucket`/`key` under `scope` + `secret` +
/// `session_token`, valid for `expires_secs` from `now_unix`. This is the mint-side companion to the
/// presigned-verify path ([`parse_presigned_query`] + [`presigned_canonical_query`] + [`verify`]) — it
/// produces exactly the URL a browser can `fetch(url, {method:"PUT", body})` with no SigV4-in-JS.
///
/// The payload is signed `UNSIGNED-PAYLOAD` (a browser PUT does not pre-hash its body), and `host` is
/// the only signed header (the minimal presigned set S3 SDKs use). `endpoint_base` is the scheme+host
/// (+ optional port), e.g. `http://127.0.0.1:9000`; the object path is `/{bucket}/{key}` (path-style).
/// The returned URL carries `X-Amz-Algorithm/Credential/Date/Expires/SignedHeaders/Security-Token` and
/// the final `X-Amz-Signature`.
pub fn presign_put_url(
    endpoint_base: &str,
    bucket: &str,
    key: &str,
    scope: &CredentialScope,
    secret_access_key: &str,
    session_token: &str,
    now_unix: i64,
    expires_secs: i64,
) -> Result<String, SigV4Error> {
    let host = endpoint_host(endpoint_base);
    let amz_date = unix_to_amz_date(now_unix);
    let uri_path = format!("/{bucket}/{key}");
    let credential = format!("{}/{}", scope.access_key_id, scope.scope_string());
    // The presigned query params (decoded form), everything the client will send EXCEPT the signature.
    let params = vec![
        ("X-Amz-Algorithm".to_string(), ALGORITHM.to_string()),
        ("X-Amz-Credential".to_string(), credential),
        ("X-Amz-Date".to_string(), amz_date.clone()),
        ("X-Amz-Expires".to_string(), expires_secs.to_string()),
        ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
        (
            "X-Amz-Security-Token".to_string(),
            session_token.to_string(),
        ),
    ];
    let canonical_q = presigned_canonical_query(&params);
    let headers = vec![("host".to_string(), host.clone())];
    let req = CanonicalRequest {
        method: "PUT",
        uri_path: &uri_path,
        query: &canonical_q,
        headers: &headers,
        payload_hash: UNSIGNED_PAYLOAD,
    };
    let (creq, _) = canonical_request_string(&req, &["host".to_string()])?;
    let sts = string_to_sign(&amz_date, scope, &creq);
    let signature = compute_signature(secret_access_key, scope, &sts);
    // The final URL: endpoint + path + the canonical query (already encoded+sorted) + the signature.
    Ok(format!(
        "{}{uri_path}?{canonical_q}&X-Amz-Signature={signature}",
        endpoint_base.trim_end_matches('/')
    ))
}

/// The `host` header value for `endpoint_base` (scheme stripped, path stripped) — what the presigned
/// signature is computed over. Includes a non-default port. Falls back to the whole string if it does
/// not look like a URL.
fn endpoint_host(endpoint_base: &str) -> String {
    let after_scheme = endpoint_base
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(endpoint_base);
    after_scheme
        .split(['/', '?'])
        .next()
        .unwrap_or(after_scheme)
        .to_string()
}

// ---- Clock-skew / expiry checks -------------------------------------------------------------

/// Parse an ISO8601 *basic* timestamp `YYYYMMDDTHHMMSSZ` to Unix seconds. Returns
/// [`SigV4Error::BadDate`] on any malformation. Self-contained (no chrono dependency) — SigV4 dates
/// are a fixed, unambiguous format.
pub fn parse_amz_date(amz_date: &str) -> Result<i64, SigV4Error> {
    let b = amz_date.as_bytes();
    if b.len() != 16 || b[8] != b'T' || b[15] != b'Z' {
        return Err(SigV4Error::BadDate);
    }
    let num = |s: &str| s.parse::<i64>().map_err(|_| SigV4Error::BadDate);
    let year = num(&amz_date[0..4])?;
    let month = num(&amz_date[4..6])?;
    let day = num(&amz_date[6..8])?;
    let hour = num(&amz_date[9..11])?;
    let min = num(&amz_date[11..13])?;
    let sec = num(&amz_date[13..15])?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return Err(SigV4Error::BadDate);
    }
    Ok(civil_to_unix(year, month, day, hour, min, sec))
}

/// Days-from-civil (Howard Hinnant's algorithm) → Unix seconds. Proleptic Gregorian, UTC.
fn civil_to_unix(y: i64, m: i64, d: i64, hh: i64, mm: i64, ss: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + hh * 3600 + mm * 60 + ss
}

/// Enforce the clock-skew window on a header-auth request: the request date must be within
/// [`MAX_CLOCK_SKEW_SECS`] of `now_unix` in either direction.
pub fn check_skew(amz_date: &str, now_unix: i64) -> Result<(), SigV4Error> {
    let ts = parse_amz_date(amz_date)?;
    if (ts - now_unix).abs() > MAX_CLOCK_SKEW_SECS {
        return Err(SigV4Error::SkewExceeded);
    }
    Ok(())
}

/// Enforce a presigned request's `X-Amz-Expires` window: `now` must be within
/// `[date - skew, date + expires + skew]`. A missing/absurd expiry fails closed.
pub fn check_presigned_expiry(parsed: &ParsedSignature, now_unix: i64) -> Result<(), SigV4Error> {
    let start = parse_amz_date(&parsed.amz_date)?;
    let expires = parsed.expires.ok_or(SigV4Error::Expired)?;
    if expires <= 0 {
        return Err(SigV4Error::Expired);
    }
    // Allow a small skew before the start (a slightly-fast client) but never past date+expires+skew.
    if now_unix < start - MAX_CLOCK_SKEW_SECS || now_unix > start + expires + MAX_CLOCK_SKEW_SECS {
        return Err(SigV4Error::Expired);
    }
    Ok(())
}

// ---- aws-chunked streaming verification (STREAMING-AWS4-HMAC-SHA256-PAYLOAD) -----------------
//
// The body is a sequence of chunks, each:
//   <hex size>;chunk-signature=<hex sig>\r\n<chunk data>\r\n
// terminated by a zero-size chunk. The per-chunk signature CHAINS: each is HMAC over
//   "AWS4-HMAC-SHA256-PAYLOAD\n<amz_date>\n<scope>\n<prev signature>\n<sha256("")>\n<sha256(chunk)>"
// where the FIRST `prev signature` is the request (seed) signature. We verify the chain incrementally
// so the whole body is never buffered — the M2 face feeds each chunk as it streams in.

/// Verifies the aws-chunked per-chunk signature chain incrementally. Constructed with the request's
/// (seed) signature + the signing key; each `verify_chunk` call checks one chunk's signature against
/// the running chain and advances it. The trailing zero-length chunk is verified like any other.
pub struct ChunkVerifier {
    signing_key: hmac::Tag,
    amz_date: String,
    scope_string: String,
    prev_signature: String,
}

impl ChunkVerifier {
    /// Build from the credential scope, the request's seed signature (the `Signature=` from the
    /// header/query auth), and the `secret_access_key`. The seed signature is the chain's first
    /// `prev signature`.
    pub fn new(
        secret_access_key: &str,
        scope: &CredentialScope,
        amz_date: &str,
        seed_signature: &str,
    ) -> Self {
        Self {
            signing_key: signing_key(
                secret_access_key,
                &scope.date,
                &scope.region,
                &scope.service,
            ),
            amz_date: amz_date.to_string(),
            scope_string: scope.scope_string(),
            prev_signature: seed_signature.to_string(),
        }
    }

    /// The string-to-sign for a chunk carrying `chunk_data` (may be empty for the terminating chunk),
    /// given the current chain state.
    fn chunk_sts(&self, chunk_data: &[u8]) -> String {
        format!(
            "{CHUNK_ALGORITHM}\n{}\n{}\n{}\n{EMPTY_SHA256}\n{}",
            self.amz_date,
            self.scope_string,
            self.prev_signature,
            sha256_hex(chunk_data),
        )
    }

    /// Verify ONE chunk's `chunk_signature` (hex) over `chunk_data`, in constant time, and advance the
    /// chain. Returns [`SigV4Error::SignatureMismatch`] on a bad chunk signature (fail-closed, no
    /// partial accept).
    pub fn verify_chunk(
        &mut self,
        chunk_data: &[u8],
        chunk_signature: &str,
    ) -> Result<(), SigV4Error> {
        let sts = self.chunk_sts(chunk_data);
        let expected = hex::encode(hmac_sign(self.signing_key.as_ref(), sts.as_bytes()).as_ref());
        verify_slices_are_equal(expected.as_bytes(), chunk_signature.as_bytes())
            .map_err(|_| SigV4Error::SignatureMismatch)?;
        // Advance the chain to this chunk's (now-verified) signature.
        self.prev_signature = expected;
        Ok(())
    }

    /// The current chain signature (after the chunks verified so far) — used to seed trailer
    /// verification if the request uses `-TRAILER`.
    pub fn current_signature(&self) -> &str {
        &self.prev_signature
    }
}

/// Parse one aws-chunked chunk header line `<hex-size>;chunk-signature=<hex>` into `(size, signature)`.
/// Returns [`SigV4Error::MalformedChunk`] on any malformation. The M2 streaming reader uses this to
/// frame the body without buffering it.
pub fn parse_chunk_header(line: &str) -> Result<(usize, String), SigV4Error> {
    let (size_hex, rest) = line.split_once(';').ok_or(SigV4Error::MalformedChunk)?;
    let size =
        usize::from_str_radix(size_hex.trim(), 16).map_err(|_| SigV4Error::MalformedChunk)?;
    // Bound the declared size (M2-review MEDIUM-1): an unbounded `size` near `usize::MAX` would make
    // the framing math (`data_start + size`, `data_end + 2`) wrap and panic downstream. A honest SDK
    // never declares more than a few MiB per chunk, so anything over `MAX_CHUNK_SIZE` is malformed.
    if size > MAX_CHUNK_SIZE {
        return Err(SigV4Error::MalformedChunk);
    }
    let sig = rest
        .trim()
        .strip_prefix("chunk-signature=")
        .ok_or(SigV4Error::MalformedChunk)?
        .to_string();
    if sig.is_empty() {
        return Err(SigV4Error::MalformedChunk);
    }
    Ok((size, sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- AWS test-suite vectors (vendored as inline fixtures; see the module doc) --------------
    //
    // From the canonical `aws-sig-v4-test-suite` (the same corpus aws-sdk-rust vendors). Credentials
    // and clock are the suite's fixed context:
    //   access_key_id = AKIDEXAMPLE, secret = wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY,
    //   region = us-east-1, service = service, date = 20150830T123600Z.

    const SUITE_SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const SUITE_AMZ_DATE: &str = "20150830T123600Z";

    fn suite_scope() -> CredentialScope {
        CredentialScope {
            access_key_id: "AKIDEXAMPLE".into(),
            date: "20150830".into(),
            region: "us-east-1".into(),
            service: "service".into(),
        }
    }

    #[test]
    fn vector_get_vanilla_canonical_request_and_signature() {
        // get-vanilla: GET / with Host + x-amz-date signed.
        let headers = vec![
            ("host".to_string(), "example.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), SUITE_AMZ_DATE.to_string()),
        ];
        let signed = vec!["host".to_string(), "x-amz-date".to_string()];
        let req = CanonicalRequest {
            method: "GET",
            uri_path: "/",
            query: "",
            headers: &headers,
            payload_hash: EMPTY_SHA256,
        };
        let (creq, signed_str) = canonical_request_string(&req, &signed).unwrap();
        let expected_creq = "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            creq, expected_creq,
            "canonical request must match the AWS vector"
        );
        assert_eq!(signed_str, "host;x-amz-date");

        let sts = string_to_sign(SUITE_AMZ_DATE, &suite_scope(), &creq);
        let expected_sts = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63";
        assert_eq!(
            sts, expected_sts,
            "string-to-sign must match the AWS vector"
        );

        let sig = compute_signature(SUITE_SECRET, &suite_scope(), &sts);
        assert_eq!(
            sig, "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
            "signature must match the AWS vector"
        );
    }

    #[test]
    fn vector_get_vanilla_query_presigned() {
        // get-vanilla-query: presigned GET / with only Host signed. The M2 face passes the query
        // params already percent-DECODED; `presigned_canonical_query` re-encodes + sorts them (and
        // drops X-Amz-Signature) to build the canonical query. The credential value's `/`s decode to
        // literal slashes, which re-encode to `%2F` — matching the AWS vector.
        let headers = vec![("host".to_string(), "example.amazonaws.com".to_string())];
        let signed = vec!["host".to_string()];
        let decoded_params = vec![
            (
                "X-Amz-Algorithm".to_string(),
                "AWS4-HMAC-SHA256".to_string(),
            ),
            (
                "X-Amz-Credential".to_string(),
                "AKIDEXAMPLE/20150830/us-east-1/service/aws4_request".to_string(),
            ),
            ("X-Amz-Date".to_string(), "20150830T123600Z".to_string()),
            ("X-Amz-Expires".to_string(), "3600".to_string()),
            ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
        ];
        let canonical_q = presigned_canonical_query(&decoded_params);
        let expected_q = "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fservice%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host";
        assert_eq!(
            canonical_q, expected_q,
            "presigned canonical query must match the AWS vector"
        );

        let req = CanonicalRequest {
            method: "GET",
            uri_path: "/",
            query: &canonical_q,
            headers: &headers,
            payload_hash: EMPTY_SHA256,
        };
        let (creq, _) = canonical_request_string(&req, &signed).unwrap();
        let expected_creq = "GET\n/\nX-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIDEXAMPLE%2F20150830%2Fus-east-1%2Fservice%2Faws4_request&X-Amz-Date=20150830T123600Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host\nhost:example.amazonaws.com\n\nhost\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(
            creq, expected_creq,
            "presigned canonical request must match the AWS vector"
        );

        let sts = string_to_sign(SUITE_AMZ_DATE, &suite_scope(), &creq);
        let sig = compute_signature(SUITE_SECRET, &suite_scope(), &sts);
        assert_eq!(
            sig, "e93c787ed7f371d5c6b165c1b38ede9550f4dce4144713e844b25b7192d3865d",
            "presigned signature must match the AWS vector"
        );
    }

    #[test]
    fn parse_authorization_header_round_trip() {
        let auth = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
        let parsed = parse_authorization_header(auth, SUITE_AMZ_DATE).unwrap();
        assert_eq!(parsed.scope, suite_scope());
        assert_eq!(parsed.signed_headers, vec!["host", "x-amz-date"]);
        assert_eq!(
            parsed.signature,
            "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
        );
        assert!(!parsed.presigned);
    }

    #[test]
    fn parse_presigned_query_round_trip() {
        let params = vec![
            (
                "X-Amz-Algorithm".to_string(),
                "AWS4-HMAC-SHA256".to_string(),
            ),
            (
                "X-Amz-Credential".to_string(),
                "AKIDEXAMPLE/20150830/us-east-1/service/aws4_request".to_string(),
            ),
            ("X-Amz-Date".to_string(), SUITE_AMZ_DATE.to_string()),
            ("X-Amz-Expires".to_string(), "3600".to_string()),
            ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
            (
                "X-Amz-Signature".to_string(),
                "e93c787ed7f371d5c6b165c1b38ede9550f4dce4144713e844b25b7192d3865d".to_string(),
            ),
        ];
        let parsed = parse_presigned_query(&params).unwrap();
        assert!(parsed.presigned);
        assert_eq!(parsed.expires, Some(3600));
        assert_eq!(parsed.scope, suite_scope());
        // The canonical query excludes X-Amz-Signature.
        let cq = presigned_canonical_query(&params);
        assert!(!cq.contains("X-Amz-Signature"));
        assert!(cq.contains("X-Amz-Algorithm=AWS4-HMAC-SHA256"));
    }

    #[test]
    fn verify_accepts_the_correct_signature_and_rejects_tamper() {
        // Round-trip through the public verify() path against the get-vanilla vector.
        let headers = vec![
            ("host".to_string(), "example.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), SUITE_AMZ_DATE.to_string()),
        ];
        let auth = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
        let parsed = parse_authorization_header(auth, SUITE_AMZ_DATE).unwrap();
        let req = CanonicalRequest {
            method: "GET",
            uri_path: "/",
            query: "",
            headers: &headers,
            payload_hash: EMPTY_SHA256,
        };
        // Correct secret ⇒ Ok.
        assert!(verify(&req, &parsed, &[SUITE_SECRET.to_string()]).is_ok());

        // Flipped-bit signature ⇒ mismatch.
        let mut bad = parsed.clone();
        bad.signature.replace_range(0..1, "6");
        assert_eq!(
            verify(&req, &bad, &[SUITE_SECRET.to_string()]),
            Err(SigV4Error::SignatureMismatch)
        );

        // Swapped SignedHeaders (drop x-amz-date from the signed set) ⇒ different creq ⇒ mismatch.
        let mut swapped = parsed.clone();
        swapped.signed_headers = vec!["host".to_string()];
        assert_eq!(
            verify(&req, &swapped, &[SUITE_SECRET.to_string()]),
            Err(SigV4Error::SignatureMismatch)
        );

        // Wrong secret ⇒ mismatch.
        assert_eq!(
            verify(&req, &parsed, &["not-the-secret".to_string()]),
            Err(SigV4Error::SignatureMismatch)
        );
    }

    #[test]
    fn verify_rejects_a_modified_host_header() {
        // Modifying a signed header value (the Host) changes the canonical request ⇒ the client
        // signature no longer matches ⇒ rejected.
        let headers = vec![
            ("host".to_string(), "evil.example.com".to_string()), // tampered
            ("x-amz-date".to_string(), SUITE_AMZ_DATE.to_string()),
        ];
        let auth = "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
        let parsed = parse_authorization_header(auth, SUITE_AMZ_DATE).unwrap();
        let req = CanonicalRequest {
            method: "GET",
            uri_path: "/",
            query: "",
            headers: &headers,
            payload_hash: EMPTY_SHA256,
        };
        assert_eq!(
            verify(&req, &parsed, &[SUITE_SECRET.to_string()]),
            Err(SigV4Error::SignatureMismatch)
        );
    }

    #[test]
    fn missing_signed_header_is_an_error_not_a_silent_pass() {
        let headers = vec![("host".to_string(), "example.amazonaws.com".to_string())];
        let signed = vec!["host".to_string(), "x-amz-date".to_string()]; // x-amz-date absent
        let req = CanonicalRequest {
            method: "GET",
            uri_path: "/",
            query: "",
            headers: &headers,
            payload_hash: EMPTY_SHA256,
        };
        assert_eq!(
            canonical_request_string(&req, &signed).unwrap_err(),
            SigV4Error::MissingSignedHeader
        );
    }

    #[test]
    fn uri_and_query_encoding_matches_aws_rules() {
        // Path: `/` separators preserved, spaces + reserved encoded.
        assert_eq!(canonical_uri("/foo bar/baz"), "/foo%20bar/baz");
        assert_eq!(
            canonical_uri("/documents and settings/"),
            "/documents%20and%20settings/"
        );
        // unreserved pass through verbatim.
        assert_eq!(canonical_uri("/-._~"), "/-._~");
        // Query: keys+values encoded (incl. `/`), sorted by encoded key.
        assert_eq!(canonical_query("b=2&a=1"), "a=1&b=2");
        assert_eq!(canonical_query("x=a/b"), "x=a%2Fb");
        // key with no value ⇒ `key=`.
        assert_eq!(canonical_query("flag"), "flag=");
        // Decode-then-encode is the AWS rule: a wire-encoded `%2F` and a literal `/` canonicalize
        // identically (so a client that pre-encoded a value and one that didn't sign the same thing).
        assert_eq!(canonical_query("x=a%2Fb"), canonical_query("x=a/b"));
        assert_eq!(canonical_query("k=%20"), "k=%20"); // wire space stays encoded
        // A canonical query is idempotent under re-canonicalization (no double-encoding).
        let once = canonical_query("X-Amz-Credential=a/b/c&Z=1");
        assert_eq!(canonical_query(&once), once);
    }

    #[test]
    fn presigned_verify_end_to_end_round_trip() {
        // Sign a presigned PUT with our own signer, then verify through the full presigned path:
        // parse the query → build the canonical query (sans X-Amz-Signature) → verify(). Proves the
        // presigned wire form round-trips, not just the canonicalization sub-steps.
        let scope = CredentialScope {
            access_key_id: "BRUPTEST".into(),
            date: "20150830".into(),
            region: "boatramp".into(),
            service: "s3".into(),
        };
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let headers = vec![("host".to_string(), "s3.local".to_string())];
        let signed = vec!["host".to_string()];
        // The presigned params the client would put on the wire (decoded form).
        let mut params = vec![
            (
                "X-Amz-Algorithm".to_string(),
                "AWS4-HMAC-SHA256".to_string(),
            ),
            (
                "X-Amz-Credential".to_string(),
                "BRUPTEST/20150830/boatramp/s3/aws4_request".to_string(),
            ),
            ("X-Amz-Date".to_string(), SUITE_AMZ_DATE.to_string()),
            ("X-Amz-Expires".to_string(), "900".to_string()),
            ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
        ];
        // Client computes the signature over the canonical request (payload UNSIGNED for presigned).
        let canonical_q = presigned_canonical_query(&params);
        let req = CanonicalRequest {
            method: "PUT",
            uri_path: "/uploads/pic.jpg",
            query: &canonical_q,
            headers: &headers,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        let (creq, _) = canonical_request_string(&req, &signed).unwrap();
        let sts = string_to_sign(SUITE_AMZ_DATE, &scope, &creq);
        let sig = compute_signature(secret, &scope, &sts);
        params.push(("X-Amz-Signature".to_string(), sig));

        // Server side: parse + verify.
        let parsed = parse_presigned_query(&params).unwrap();
        let server_q = presigned_canonical_query(&params);
        let server_req = CanonicalRequest {
            method: "PUT",
            uri_path: "/uploads/pic.jpg",
            query: &server_q,
            headers: &headers,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        assert!(verify(&server_req, &parsed, &[secret.to_string()]).is_ok());
        // Tamper: a different key path ⇒ different creq ⇒ reject.
        let tampered_req = CanonicalRequest {
            uri_path: "/uploads/other.jpg",
            ..server_req
        };
        assert!(verify(&tampered_req, &parsed, &[secret.to_string()]).is_err());
    }

    #[test]
    fn unsigned_payload_mode_verifies() {
        // A client sending `x-amz-content-sha256: UNSIGNED-PAYLOAD` signs the literal marker as the
        // payload hash — verify must reproduce that exactly.
        let scope = CredentialScope {
            access_key_id: "BRUPTEST".into(),
            date: "20150830".into(),
            region: "boatramp".into(),
            service: "s3".into(),
        };
        let secret = "abcdef00abcdef00abcdef00abcdef00abcdef00abcdef00abcdef00abcdef00";
        let headers = vec![
            ("host".to_string(), "s3.local".to_string()),
            ("x-amz-date".to_string(), SUITE_AMZ_DATE.to_string()),
            (
                "x-amz-content-sha256".to_string(),
                UNSIGNED_PAYLOAD.to_string(),
            ),
        ];
        let signed = vec![
            "host".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ];
        let req = CanonicalRequest {
            method: "PUT",
            uri_path: "/c/k",
            query: "",
            headers: &headers,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        let (creq, _) = canonical_request_string(&req, &signed).unwrap();
        let sts = string_to_sign(SUITE_AMZ_DATE, &scope, &creq);
        let sig = compute_signature(secret, &scope, &sts);
        let parsed = ParsedSignature {
            scope,
            signed_headers: signed,
            signature: sig,
            amz_date: SUITE_AMZ_DATE.to_string(),
            presigned: false,
            expires: None,
        };
        assert!(verify(&req, &parsed, &[secret.to_string()]).is_ok());
    }

    #[test]
    fn header_value_whitespace_is_normalized() {
        // Internal whitespace runs collapse to one space; leading/trailing trimmed.
        assert_eq!(trim_ws("  a   b  c "), "a b c");
        assert_eq!(trim_ws("nochange"), "nochange");
    }

    #[test]
    fn amz_date_parsing_and_skew_window() {
        // 20150830T123600Z → a fixed epoch; verify the parse + the skew window boundaries.
        let ts = parse_amz_date("20150830T123600Z").unwrap();
        // Within +/- 300s ⇒ Ok; beyond ⇒ SkewExceeded.
        assert!(check_skew("20150830T123600Z", ts).is_ok());
        assert!(check_skew("20150830T123600Z", ts + MAX_CLOCK_SKEW_SECS).is_ok());
        assert_eq!(
            check_skew("20150830T123600Z", ts + MAX_CLOCK_SKEW_SECS + 1),
            Err(SigV4Error::SkewExceeded)
        );
        assert_eq!(
            check_skew("20150830T123600Z", ts - MAX_CLOCK_SKEW_SECS - 1),
            Err(SigV4Error::SkewExceeded)
        );
        // Malformed date ⇒ BadDate (fail-closed, not a panic).
        assert_eq!(
            parse_amz_date("not-a-date").unwrap_err(),
            SigV4Error::BadDate
        );
        assert_eq!(
            parse_amz_date("20150830 123600Z").unwrap_err(),
            SigV4Error::BadDate
        );
    }

    #[test]
    fn amz_date_matches_a_known_epoch() {
        // 1970-01-01T00:00:00Z is epoch 0; a day later is 86400.
        assert_eq!(parse_amz_date("19700101T000000Z").unwrap(), 0);
        assert_eq!(parse_amz_date("19700102T000000Z").unwrap(), 86400);
        // 2015-08-30T12:36:00Z (the suite date) is a known epoch.
        assert_eq!(parse_amz_date("20150830T123600Z").unwrap(), 1_440_938_160);
    }

    #[test]
    fn presigned_expiry_window() {
        let start = parse_amz_date(SUITE_AMZ_DATE).unwrap();
        let params = vec![
            (
                "X-Amz-Algorithm".to_string(),
                "AWS4-HMAC-SHA256".to_string(),
            ),
            (
                "X-Amz-Credential".to_string(),
                "AKIDEXAMPLE/20150830/us-east-1/service/aws4_request".to_string(),
            ),
            ("X-Amz-Date".to_string(), SUITE_AMZ_DATE.to_string()),
            ("X-Amz-Expires".to_string(), "3600".to_string()),
            ("X-Amz-SignedHeaders".to_string(), "host".to_string()),
            ("X-Amz-Signature".to_string(), "deadbeef".to_string()),
        ];
        let parsed = parse_presigned_query(&params).unwrap();
        assert!(check_presigned_expiry(&parsed, start + 100).is_ok());
        assert!(check_presigned_expiry(&parsed, start + 3600).is_ok());
        // Past date + expires + skew ⇒ Expired.
        assert_eq!(
            check_presigned_expiry(&parsed, start + 3600 + MAX_CLOCK_SKEW_SECS + 1),
            Err(SigV4Error::Expired)
        );
        // No expires ⇒ Expired (fail closed).
        let mut noexp = parsed.clone();
        noexp.expires = None;
        assert_eq!(
            check_presigned_expiry(&noexp, start),
            Err(SigV4Error::Expired)
        );
    }

    #[test]
    fn sign_then_verify_round_trip_over_a_put() {
        // A PUT with a real payload hash: sign it with our own signer, then verify — the primary
        // property (differential vs a reference is added below where available).
        let body = b"the object bytes";
        let payload_hash = sha256_hex(body);
        let headers = vec![
            ("host".to_string(), "s3.local".to_string()),
            ("x-amz-date".to_string(), SUITE_AMZ_DATE.to_string()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ];
        let signed = vec![
            "host".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ];
        let scope = CredentialScope {
            access_key_id: "BRUPTEST".into(),
            date: "20150830".into(),
            region: "boatramp".into(),
            service: "s3".into(),
        };
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let req = CanonicalRequest {
            method: "PUT",
            uri_path: "/uploads/avatars/u1/pic.jpg",
            query: "",
            headers: &headers,
            payload_hash: &payload_hash,
        };
        let (creq, _) = canonical_request_string(&req, &signed).unwrap();
        let sts = string_to_sign(SUITE_AMZ_DATE, &scope, &creq);
        let sig = compute_signature(secret, &scope, &sts);
        let parsed = ParsedSignature {
            scope,
            signed_headers: signed,
            signature: sig,
            amz_date: SUITE_AMZ_DATE.to_string(),
            presigned: false,
            expires: None,
        };
        assert!(verify(&req, &parsed, &[secret.to_string()]).is_ok());
        // Same request, wrong candidate ⇒ reject; a rotation-overlap [wrong, right] ⇒ accept.
        assert!(verify(&req, &parsed, &["wrong".to_string()]).is_err());
        assert!(verify(&req, &parsed, &["wrong".to_string(), secret.to_string()]).is_ok());
    }

    #[test]
    fn aws_chunked_chain_is_self_consistent_and_order_bound() {
        // Uses the AWS chunked-upload example shape — secret wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY,
        // region us-east-1, service s3, date 20130524T000000Z, seed
        // 4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9, chunk1 = 65536 * 'a',
        // chunk2 = 1024 * 'a', chunk3 = empty (final). The expected per-chunk signatures are computed
        // via the SAME chain the verifier uses (the chunk-STS format is confirmed against AWS's docs
        // in `aws_chunked_chunk_data_hash_matches_the_documented_constant`); this test proves the
        // chain is built + advanced correctly and that it is bound to chunk content AND order. See the
        // M1 report note: the exact AWS-published chunk-*signature* triple could not be re-fetched
        // (docs are JS-rendered) to pin as a full external differential — flagged for M5 follow-up.
        let scope = CredentialScope {
            access_key_id: "AKIDEXAMPLE".into(),
            date: "20130524".into(),
            region: "us-east-1".into(),
            service: "s3".into(),
        };
        let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let amz_date = "20130524T000000Z";

        let chunk1 = vec![b'a'; 65536];
        let chunk2 = vec![b'a'; 1024];
        let chunk3: Vec<u8> = vec![];

        // Independently compute each expected chunk signature via the same chain the verifier uses,
        // then feed those to the verifier — this proves the chain construction + advancement, and the
        // tamper checks prove fail-closed behavior. (The AWS-documented chunk-data hash constant is
        // asserted in `aws_chunked_chunk_data_hash_matches_the_documented_constant` below; a full
        // external seed→per-chunk-signature vector is scheduled for the M5 differential-fuzz gate.)
        let mut expected_prev = seed.to_string();
        let mut expected_sigs = Vec::new();
        for data in [&chunk1, &chunk2, &chunk3] {
            let sts = format!(
                "{CHUNK_ALGORITHM}\n{amz_date}\n{}\n{}\n{EMPTY_SHA256}\n{}",
                scope.scope_string(),
                expected_prev,
                sha256_hex(data),
            );
            let key = signing_key(secret, &scope.date, &scope.region, &scope.service);
            let sig = hex::encode(hmac_sign(key.as_ref(), sts.as_bytes()).as_ref());
            expected_sigs.push(sig.clone());
            expected_prev = sig;
        }

        let mut v = ChunkVerifier::new(secret, &scope, amz_date, seed);
        assert!(v.verify_chunk(&chunk1, &expected_sigs[0]).is_ok());
        assert!(v.verify_chunk(&chunk2, &expected_sigs[1]).is_ok());
        assert!(v.verify_chunk(&chunk3, &expected_sigs[2]).is_ok());

        // Tamper: a fresh verifier, wrong chunk signature ⇒ reject (fail-closed, chain not advanced).
        let mut v2 = ChunkVerifier::new(secret, &scope, amz_date, seed);
        assert_eq!(
            v2.verify_chunk(
                &chunk1,
                "00000000000000000000000000000000000000000000000000000000000000ff"
            ),
            Err(SigV4Error::SignatureMismatch)
        );
        // Tamper: right signatures but WRONG order (chunk2's sig on chunk1) ⇒ reject (chain binds
        // order + content).
        let mut v3 = ChunkVerifier::new(secret, &scope, amz_date, seed);
        assert_eq!(
            v3.verify_chunk(&chunk1, &expected_sigs[1]),
            Err(SigV4Error::SignatureMismatch)
        );
    }

    #[test]
    fn aws_chunked_chunk_data_hash_matches_the_documented_constant() {
        // AWS's canonical chunked-upload example transfers a 65536-byte first chunk of `'a'`; its
        // documented chunk-data SHA-256 (the 5th line of the chunk string-to-sign) is this constant.
        // Pinning it proves our per-chunk hashing matches AWS's published example even though the
        // full seed→chunk-signature triple below is self-consistent rather than externally pinned
        // (see `aws_chunked_chain_is_self_consistent_and_order_bound` and the M1 report note).
        assert_eq!(
            sha256_hex(&vec![b'a'; 65536]),
            "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a",
            "our chunk-data SHA-256 must match AWS's documented chunked-upload example"
        );
        // The empty-chunk hash line is the SHA-256 of the empty string — the well-known constant.
        assert_eq!(sha256_hex(&[]), EMPTY_SHA256);
    }

    // ---- Property tests over the canonicalization + sign/verify ---------------------------------
    //
    // The AWS test-suite vectors above pin canonicalization against AWS's OWN reference output (the
    // vectors ARE `aws-sig-v4-test-suite`), so they serve as the external differential. These
    // property tests then fuzz the engine's invariants across randomized inputs. (A full live
    // differential against the transitive `aws-sigv4` crate is noted as possible M5 hardening — see
    // the M1 report.)

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// A signature computed by our signer always verifies under the SAME secret, and never under
        /// a different one — over randomized method/path/headers/secret.
        #[test]
        fn prop_sign_then_verify_round_trips(
            method in prop::sample::select(vec!["PUT", "POST", "GET", "DELETE", "HEAD"]),
            seg1 in "[a-zA-Z0-9._-]{1,12}",
            seg2 in "[a-zA-Z0-9._-]{1,12}",
            host in "[a-z][a-z0-9.-]{2,20}",
            secret in "[0-9a-f]{64}",
            other in "[0-9a-f]{64}",
        ) {
            prop_assume!(secret != other);
            let path = format!("/{seg1}/{seg2}");
            let scope = CredentialScope {
                access_key_id: "BRUPPROP".into(),
                date: "20150830".into(),
                region: "boatramp".into(),
                service: "s3".into(),
            };
            let headers = vec![
                ("host".to_string(), host),
                ("x-amz-date".to_string(), SUITE_AMZ_DATE.to_string()),
                ("x-amz-content-sha256".to_string(), UNSIGNED_PAYLOAD.to_string()),
            ];
            let signed = vec![
                "host".to_string(),
                "x-amz-content-sha256".to_string(),
                "x-amz-date".to_string(),
            ];
            let req = CanonicalRequest {
                method,
                uri_path: &path,
                query: "",
                headers: &headers,
                payload_hash: UNSIGNED_PAYLOAD,
            };
            let (creq, _) = canonical_request_string(&req, &signed).unwrap();
            let sts = string_to_sign(SUITE_AMZ_DATE, &scope, &creq);
            let sig = compute_signature(&secret, &scope, &sts);
            let parsed = ParsedSignature {
                scope,
                signed_headers: signed,
                signature: sig,
                amz_date: SUITE_AMZ_DATE.to_string(),
                presigned: false,
                expires: None,
            };
            // Correct secret verifies; a different (random) secret never does.
            prop_assert!(verify(&req, &parsed, std::slice::from_ref(&secret)).is_ok());
            prop_assert_eq!(verify(&req, &parsed, &[other]), Err(SigV4Error::SignatureMismatch));
        }

        /// Canonical-query decode-then-encode is idempotent: canonicalizing an already-canonical query
        /// yields the same string (no double-encoding), over randomized key/value pairs.
        #[test]
        fn prop_canonical_query_is_idempotent(
            pairs in prop::collection::vec(
                ("[A-Za-z][A-Za-z0-9-]{0,8}", "[A-Za-z0-9/ ._~=]{0,10}"),
                0..6,
            ),
        ) {
            let raw = pairs
                .iter()
                .map(|(k, v)| format!("{}={}", k, uri_encode(v, true)))
                .collect::<Vec<_>>()
                .join("&");
            let once = canonical_query(&raw);
            prop_assert_eq!(canonical_query(&once), once);
        }

        /// A one-byte flip of a signed header value ALWAYS breaks verification (no silent accept).
        #[test]
        fn prop_tampering_a_signed_header_breaks_verify(
            host in "[a-z][a-z0-9]{3,12}",
            secret in "[0-9a-f]{64}",
        ) {
            let scope = CredentialScope {
                access_key_id: "BRUPPROP".into(),
                date: "20150830".into(),
                region: "boatramp".into(),
                service: "s3".into(),
            };
            let headers = vec![
                ("host".to_string(), host.clone()),
                ("x-amz-date".to_string(), SUITE_AMZ_DATE.to_string()),
            ];
            let signed = vec!["host".to_string(), "x-amz-date".to_string()];
            let req = CanonicalRequest {
                method: "PUT",
                uri_path: "/c/k",
                query: "",
                headers: &headers,
                payload_hash: EMPTY_SHA256,
            };
            let (creq, _) = canonical_request_string(&req, &signed).unwrap();
            let sts = string_to_sign(SUITE_AMZ_DATE, &scope, &creq);
            let sig = compute_signature(&secret, &scope, &sts);
            let parsed = ParsedSignature {
                scope,
                signed_headers: signed.clone(),
                signature: sig,
                amz_date: SUITE_AMZ_DATE.to_string(),
                presigned: false,
                expires: None,
            };
            // Tamper the host that was signed.
            let tampered_headers = vec![
                ("host".to_string(), format!("{host}x")),
                ("x-amz-date".to_string(), SUITE_AMZ_DATE.to_string()),
            ];
            let tampered = CanonicalRequest {
                method: "PUT",
                uri_path: "/c/k",
                query: "",
                headers: &tampered_headers,
                payload_hash: EMPTY_SHA256,
            };
            prop_assert_eq!(
                verify(&tampered, &parsed, &[secret]),
                Err(SigV4Error::SignatureMismatch)
            );
        }
    }

    #[test]
    fn parse_chunk_header_frames_and_rejects_malformed() {
        assert_eq!(
            parse_chunk_header("10000;chunk-signature=abcdef").unwrap(),
            (0x10000, "abcdef".to_string())
        );
        assert_eq!(
            parse_chunk_header("0;chunk-signature=deadbeef").unwrap(),
            (0, "deadbeef".to_string())
        );
        // No `;` ⇒ malformed.
        assert_eq!(
            parse_chunk_header("10000").unwrap_err(),
            SigV4Error::MalformedChunk
        );
        // No chunk-signature ⇒ malformed.
        assert_eq!(
            parse_chunk_header("10000;something=x").unwrap_err(),
            SigV4Error::MalformedChunk
        );
        // Non-hex size ⇒ malformed.
        assert_eq!(
            parse_chunk_header("zz;chunk-signature=abc").unwrap_err(),
            SigV4Error::MalformedChunk
        );
        // Empty signature ⇒ malformed.
        assert_eq!(
            parse_chunk_header("1;chunk-signature=").unwrap_err(),
            SigV4Error::MalformedChunk
        );
    }

    #[test]
    fn unix_to_amz_date_round_trips_parse() {
        // The formatter is the exact inverse of the parser over known epochs + a round-trip.
        assert_eq!(unix_to_amz_date(0), "19700101T000000Z");
        assert_eq!(unix_to_amz_date(86400), "19700102T000000Z");
        assert_eq!(unix_to_amz_date(1_440_938_160), "20150830T123600Z");
        for t in [0i64, 1, 86400, 1_440_938_160, 1_700_000_000] {
            assert_eq!(parse_amz_date(&unix_to_amz_date(t)).unwrap(), t);
        }
    }

    #[test]
    fn presigned_put_url_verifies_through_the_face_path() {
        // MINT→VERIFY round trip: presign a PUT URL, then drive it through the SAME parse+verify path
        // the M2 face uses (parse the query → rebuild the canonical query sans signature → verify).
        // A correct URL verifies; a tampered key does not — proving a minted presigned-put credential
        // is actually accepted by the face's SigV4 verifier.
        let now = 1_440_938_160; // 20150830T123600Z
        let scope = CredentialScope {
            access_key_id: "BRUPPRESIGN".into(),
            date: "20150830".into(),
            region: "boatramp".into(),
            service: "s3".into(),
        };
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let url = presign_put_url(
            "http://127.0.0.1:9000",
            "photos",
            "avatars/u1.jpg",
            &scope,
            secret,
            "SESSIONTOKEN",
            now,
            900,
        )
        .unwrap();
        assert!(url.starts_with("http://127.0.0.1:9000/photos/avatars/u1.jpg?"));
        assert!(url.contains("X-Amz-Signature="));
        assert!(url.contains("X-Amz-Security-Token=SESSIONTOKEN"));

        // Server side: split the query, decode the params, parse + verify (path-style bucket/key).
        let (path, query) = url
            .strip_prefix("http://127.0.0.1:9000")
            .unwrap()
            .split_once('?')
            .unwrap();
        let decoded: Vec<(String, String)> = query
            .split('&')
            .map(|p| {
                let (k, v) = p.split_once('=').unwrap();
                (percent_decode(k), percent_decode(v))
            })
            .collect();
        let parsed = parse_presigned_query(&decoded).unwrap();
        assert!(parsed.presigned);
        assert_eq!(parsed.scope, scope);
        let server_q = presigned_canonical_query(&decoded);
        let headers = vec![("host".to_string(), "127.0.0.1:9000".to_string())];
        let req = CanonicalRequest {
            method: "PUT",
            uri_path: path,
            query: &server_q,
            headers: &headers,
            payload_hash: UNSIGNED_PAYLOAD,
        };
        assert!(
            verify(&req, &parsed, &[secret.to_string()]).is_ok(),
            "a minted presigned PUT URL must verify through the face path"
        );
        // Presigned expiry window holds at mint time.
        assert!(check_presigned_expiry(&parsed, now + 100).is_ok());
        // Tamper the key ⇒ different canonical request ⇒ reject.
        let tampered = CanonicalRequest {
            uri_path: "/photos/other.jpg",
            ..req
        };
        assert!(verify(&tampered, &parsed, &[secret.to_string()]).is_err());
    }

    #[test]
    fn endpoint_host_strips_scheme_and_path() {
        assert_eq!(endpoint_host("http://127.0.0.1:9000"), "127.0.0.1:9000");
        assert_eq!(endpoint_host("https://s3.example.com"), "s3.example.com");
        assert_eq!(
            endpoint_host("https://s3.example.com/x/y"),
            "s3.example.com"
        );
        assert_eq!(endpoint_host("bare-host:1234"), "bare-host:1234");
    }

    #[test]
    fn parse_chunk_header_bounds_the_declared_size_no_overflow_panic() {
        // M2-review MEDIUM-1: a hostile chunk header declaring an enormous size must yield a clean
        // `Err(MalformedChunk)`, NOT a parse-then-overflow panic downstream.
        // `ffffffffffffffff` = usize::MAX on a 64-bit target — the exact wrap-inducing value.
        assert_eq!(
            parse_chunk_header("ffffffffffffffff;chunk-signature=abc").unwrap_err(),
            SigV4Error::MalformedChunk,
            "a size ≈ usize::MAX must be rejected, not parsed"
        );
        // Exactly at the bound is accepted; one byte over is rejected.
        let at = format!("{MAX_CHUNK_SIZE:x};chunk-signature=abc");
        assert_eq!(
            parse_chunk_header(&at).unwrap(),
            (MAX_CHUNK_SIZE, "abc".to_string())
        );
        let over = format!("{:x};chunk-signature=abc", MAX_CHUNK_SIZE + 1);
        assert_eq!(
            parse_chunk_header(&over).unwrap_err(),
            SigV4Error::MalformedChunk,
            "one byte over MAX_CHUNK_SIZE must be rejected"
        );
    }
}
