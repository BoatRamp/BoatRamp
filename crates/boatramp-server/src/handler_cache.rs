//! Edge response cache: policy, keying, and entry codec (HS-4 / PLAN-persisted-queries).
//!
//! Pure and deterministic — **no I/O**. This module decides *whether* a handler
//! response may be cached, *under what key*, and *for how long*, and (de)serializes a
//! cached entry to/from bytes. The store read/write and the dispatch wiring live in
//! `handler_dispatch`; keeping the policy here, infrastructure-free, lets the
//! correctness-critical rules be exhaustively unit-tested:
//!
//! * **Tenant isolation.** The key is prefixed with the request's *scope* (the
//!   project-qualified site / preview identity that already isolates kv/blob/messaging),
//!   so two tenants' identical requests can never collide on one entry.
//! * **Never cache a private response.** `no-store` / `private` / `no-cache`, a
//!   `Set-Cookie`, `Vary: *`, or an `Authorization`-bearing request (absent an explicit
//!   `public` / `s-maxage`) all bypass the cache.
//! * **Explicit opt-in.** A response is stored only when it carries a positive
//!   `max-age` / `s-maxage`; nothing is cached heuristically.

use axum::body::Body;
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use boatramp_core::kv::KvStore;
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Per-site edge-cache configuration (`[handlers.cache]`). Disabled by default — the
/// cache is strictly opt-in.
#[derive(Debug, Clone)]
pub(crate) struct CacheConfig {
    pub enabled: bool,
    /// Largest cacheable entry (encoded status+headers+body); a larger response streams
    /// through uncached rather than buffering unbounded host memory.
    pub max_entry_bytes: usize,
    /// Upper bound on a stored entry's TTL, clamping an over-long `max-age`.
    pub max_ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_entry_bytes: 256 * 1024,
            max_ttl_secs: 3600,
        }
    }
}

/// Methods eligible for the edge cache. Only methods whose cache key needs *no request
/// body* qualify here — a POST GraphQL query is keyed by its persisted-query hash in a
/// later stage, never by buffering the body.
pub(crate) fn method_cacheable(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD)
}

/// Response statuses the edge cache will store (a conservative subset; each still
/// requires an explicit positive `max-age` / `s-maxage` to actually be cached).
fn status_cacheable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 200 | 203 | 204 | 301 | 404 | 410)
}

/// The store key for a request: `hcache/{scope}/{sha256(method \0 path&query)}`. The
/// `scope` prefix is the tenant-isolation boundary (same scope that namespaces
/// `hkv/`/`hblob/`); the hash bounds the key length and tolerates any path/query bytes.
pub(crate) fn cache_key(scope: &str, method: &Method, path_and_query: &str) -> String {
    let mut h = Sha256::new();
    h.update(method.as_str().as_bytes());
    h.update([0]);
    h.update(path_and_query.as_bytes());
    format!("hcache/{scope}/{}", hex::encode(h.finalize()))
}

/// The relevant `Cache-Control` directives, parsed from a response.
#[derive(Default, Debug, PartialEq, Eq)]
struct CacheControl {
    no_store: bool,
    no_cache: bool,
    private: bool,
    public: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
}

fn parse_cache_control(headers: &HeaderMap) -> CacheControl {
    let mut cc = CacheControl::default();
    for value in headers.get_all(header::CACHE_CONTROL) {
        let Ok(s) = value.to_str() else { continue };
        for directive in s.split(',') {
            let (name, arg) = match directive.trim().split_once('=') {
                Some((n, a)) => (n.trim(), Some(a.trim().trim_matches('"'))),
                None => (directive.trim(), None),
            };
            match name.to_ascii_lowercase().as_str() {
                "no-store" => cc.no_store = true,
                "no-cache" => cc.no_cache = true,
                "private" => cc.private = true,
                "public" => cc.public = true,
                "max-age" => cc.max_age = arg.and_then(|a| a.parse().ok()),
                "s-maxage" => cc.s_maxage = arg.and_then(|a| a.parse().ok()),
                _ => {}
            }
        }
    }
    cc
}

/// The `Vary` header, interpreted: `*` disqualifies caching entirely; otherwise a
/// (lowercased) list of request-header names the response varies on.
enum Vary {
    Any,
    Headers(Vec<String>),
}

fn parse_vary(headers: &HeaderMap) -> Vary {
    let mut names = Vec::new();
    for value in headers.get_all(header::VARY) {
        let Ok(s) = value.to_str() else { continue };
        for name in s.split(',') {
            let name = name.trim();
            if name == "*" {
                return Vary::Any;
            }
            if !name.is_empty() {
                names.push(name.to_ascii_lowercase());
            }
        }
    }
    Vary::Headers(names)
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Whether the request may be answered from the cache at all (before a lookup). Cheap
/// gate so a non-cacheable method never touches the store.
pub(crate) fn request_lookupable(cfg: &CacheConfig, method: &Method) -> bool {
    cfg.enabled && method_cacheable(method)
}

/// The decision for whether (and how) to store a completed response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum WriteDecision {
    /// Store with this TTL (seconds) and the captured `Vary` request-header values.
    Cache {
        ttl_secs: u64,
        vary: Vec<(String, Option<String>)>,
    },
    /// Do not store.
    Bypass,
}

/// Decide whether a completed response may be cached, applying every privacy rule.
/// Conservative: a response is cached only when it explicitly opts in via a positive
/// `max-age` / `s-maxage` and carries no privacy signal.
pub(crate) fn write_decision(
    req_method: &Method,
    req_headers: &HeaderMap,
    status: StatusCode,
    resp_headers: &HeaderMap,
    cfg: &CacheConfig,
) -> WriteDecision {
    if !cfg.enabled || !method_cacheable(req_method) || !status_cacheable(status) {
        return WriteDecision::Bypass;
    }
    // A per-user response is never shared.
    if resp_headers.contains_key(header::SET_COOKIE) {
        return WriteDecision::Bypass;
    }
    let cc = parse_cache_control(resp_headers);
    if cc.no_store || cc.no_cache || cc.private {
        return WriteDecision::Bypass;
    }
    let vary = match parse_vary(resp_headers) {
        Vary::Any => return WriteDecision::Bypass,
        Vary::Headers(names) => names
            .iter()
            .map(|n| (n.clone(), header_value(req_headers, n)))
            .collect(),
    };
    // A shared cache must not store a response to an `Authorization`-bearing request
    // unless the response explicitly permits it (RFC 9111 §3.5).
    if req_headers.contains_key(header::AUTHORIZATION) && !(cc.public || cc.s_maxage.is_some()) {
        return WriteDecision::Bypass;
    }
    match cc.s_maxage.or(cc.max_age).filter(|&t| t > 0) {
        Some(ttl) => WriteDecision::Cache {
            ttl_secs: ttl.min(cfg.max_ttl_secs),
            vary,
        },
        None => WriteDecision::Bypass,
    }
}

/// A stored response: status + headers + body, plus its absolute expiry and the request
/// header values it was keyed against (`Vary`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CacheEntry {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Vec<u8>,
    pub expiry_unix: u64,
    pub vary: Vec<(String, Option<String>)>,
}

impl CacheEntry {
    /// Not yet expired at `now_unix`.
    pub fn is_fresh(&self, now_unix: u64) -> bool {
        self.expiry_unix > now_unix
    }

    /// Whether this entry may answer `req_headers`: every varied request header must
    /// still equal the value captured when the entry was stored (a differing or newly
    /// absent header is a miss).
    pub fn matches_vary(&self, req_headers: &HeaderMap) -> bool {
        self.vary
            .iter()
            .all(|(name, stored)| header_value(req_headers, name).as_deref() == stored.as_deref())
    }

    /// Encode to a compact, self-describing byte string for the store. A leading version
    /// byte lets the layout evolve; `decode` rejects anything else.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(1u8); // version
        out.extend_from_slice(&self.status.to_be_bytes());
        out.extend_from_slice(&self.expiry_unix.to_be_bytes());
        put_u32(&mut out, self.headers.len() as u32);
        for (name, value) in &self.headers {
            put_bytes(&mut out, name.as_bytes());
            put_bytes(&mut out, value);
        }
        put_u32(&mut out, self.vary.len() as u32);
        for (name, value) in &self.vary {
            put_bytes(&mut out, name.as_bytes());
            match value {
                Some(v) => {
                    out.push(1);
                    put_bytes(&mut out, v.as_bytes());
                }
                None => out.push(0),
            }
        }
        put_bytes(&mut out, &self.body);
        out
    }

    /// Decode an entry written by [`CacheEntry::encode`]. Returns `None` on any
    /// truncation, bad version, or non-UTF-8 name — a corrupt store entry is a miss,
    /// never a panic. Allocations are driven by the actual bytes read (no
    /// count-prefixed pre-allocation), so a malformed length can't force an OOM.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut r = Reader::new(bytes);
        if r.take(1)? != [1] {
            return None;
        }
        let status = u16::from_be_bytes(r.take(2)?.try_into().ok()?);
        let expiry_unix = u64::from_be_bytes(r.take(8)?.try_into().ok()?);
        let hcount = r.u32()?;
        let mut headers = Vec::new();
        for _ in 0..hcount {
            let name = r.string()?;
            let value = r.bytes()?;
            headers.push((name, value));
        }
        let vcount = r.u32()?;
        let mut vary = Vec::new();
        for _ in 0..vcount {
            let name = r.string()?;
            let value = match r.take(1)?[0] {
                1 => Some(r.string()?),
                _ => None,
            };
            vary.push((name, value));
        }
        let body = r.bytes()?;
        Some(Self {
            status,
            headers,
            body,
            expiry_unix,
            vary,
        })
    }
}

impl CacheEntry {
    /// Reconstruct the HTTP response this entry stored. Header names/values were
    /// captured from a valid response, so rebuilding cannot normally fail; a
    /// defensive fallback keeps a corrupt entry from panicking the request path.
    fn into_response(self) -> Response {
        let mut builder = axum::http::Response::builder().status(self.status);
        for (name, value) in &self.headers {
            builder = builder.header(name.as_str(), value.as_slice());
        }
        builder
            .body(Body::from(self.body))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
    }
}

/// Build the runtime cache config for a site, or `None` when the site hasn't enabled the
/// cache (the common case). Missing tunables fall back to the server defaults.
pub(crate) fn config_for(site: &boatramp_core::config::HandlersSiteConfig) -> Option<CacheConfig> {
    let c = site.cache.as_ref()?;
    if !c.enabled {
        return None;
    }
    let defaults = CacheConfig::default();
    Some(CacheConfig {
        enabled: true,
        max_entry_bytes: c
            .max_entry_bytes
            .map_or(defaults.max_entry_bytes, |n| n as usize),
        max_ttl_secs: c.max_ttl_secs.unwrap_or(defaults.max_ttl_secs),
    })
}

/// Seconds since the Unix epoch, for TTL math. Clock skew only affects freshness
/// windows, never the integrity of the stored bytes.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Look up a fresh, `Vary`-matching cached response for `key`. A stale entry is deleted
/// (lazy eviction) and treated as a miss; a decode failure is a miss. A store read error
/// is a miss — the cache is best-effort and never fails the request.
pub(crate) async fn lookup_response(
    kv: &dyn KvStore,
    key: &str,
    req_headers: &HeaderMap,
    now: u64,
) -> Option<Response> {
    let bytes = kv.get(key).await.ok().flatten()?;
    let entry = CacheEntry::decode(&bytes)?;
    if !entry.is_fresh(now) {
        let _ = kv.delete(key).await; // lazy eviction of an expired entry
        return None;
    }
    if !entry.matches_vary(req_headers) {
        return None;
    }
    Some(entry.into_response())
}

/// Consider caching a completed response, returning the response to send onward.
///
/// The response is cached only when [`write_decision`] permits **and** its size is known
/// up front (`Content-Length`) and within the cap — so buffering can never consume an
/// unbounded or oversized streaming body. In that case the body is buffered, stored, and
/// a byte-identical response returned; otherwise the response streams through untouched.
/// Storing is best-effort: a store error never fails the request.
pub(crate) async fn maybe_store(
    kv: Arc<dyn KvStore>,
    cfg: &CacheConfig,
    key: &str,
    method: &Method,
    req_headers: &HeaderMap,
    response: Response,
    now: u64,
) -> Response {
    let (ttl_secs, vary) = match write_decision(
        method,
        req_headers,
        response.status(),
        response.headers(),
        cfg,
    ) {
        WriteDecision::Cache { ttl_secs, vary } => (ttl_secs, vary),
        WriteDecision::Bypass => return response,
    };
    // Cache only when the body size is known and within the cap.
    let declared = response
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());
    if declared.is_none_or(|n| n > cfg.max_entry_bytes) {
        return response; // unknown or oversized length ⇒ stream through, don't cache
    }
    let status = response.status().as_u16();
    let headers: Vec<(String, Vec<u8>)> = response
        .headers()
        .iter()
        .map(|(n, v)| (n.as_str().to_string(), v.as_bytes().to_vec()))
        .collect();
    let (parts, body) = response.into_parts();
    let body_bytes = match axum::body::to_bytes(body, cfg.max_entry_bytes).await {
        Ok(b) => b,
        Err(_) => {
            // The guest sent more than its declared Content-Length and blew the cap; the
            // body is consumed and can't be streamed. Fail closed rather than truncate.
            return (
                StatusCode::BAD_GATEWAY,
                "handler response exceeded its declared length\n",
            )
                .into_response();
        }
    };
    let entry = CacheEntry {
        status,
        headers,
        body: body_bytes.to_vec(),
        expiry_unix: now.saturating_add(ttl_secs),
        vary,
    };
    // Encode once; store only if the whole entry (headers + framing) fits the cap. A
    // store failure is swallowed — the response is served either way.
    let encoded = entry.encode();
    if encoded.len() <= cfg.max_entry_bytes {
        let _ = kv.put(key, encoded).await;
    }
    // Rebuild the response from the buffered bytes (the original body was consumed).
    axum::http::Response::from_parts(parts, Body::from(body_bytes))
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_u32(out, b.len() as u32);
    out.extend_from_slice(b);
}

/// A bounds-checked cursor over the encoded entry. Every read returns `None` past the
/// end, so a truncated buffer decodes to `None` rather than panicking.
struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.b.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<Vec<u8>> {
        let n = self.u32()? as usize;
        Some(self.take(n)?.to_vec())
    }
    fn string(&mut self) -> Option<String> {
        String::from_utf8(self.bytes()?).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hm(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        h
    }

    fn cfg() -> CacheConfig {
        CacheConfig {
            enabled: true,
            ..CacheConfig::default()
        }
    }

    #[test]
    fn only_get_and_head_are_cacheable_methods() {
        assert!(method_cacheable(&Method::GET));
        assert!(method_cacheable(&Method::HEAD));
        assert!(!method_cacheable(&Method::POST));
        assert!(!method_cacheable(&Method::PUT));
        assert!(!method_cacheable(&Method::DELETE));
    }

    #[test]
    fn key_isolates_by_scope_method_and_path() {
        let a = cache_key("acme/shop", &Method::GET, "/x?y=1");
        // Same inputs are stable.
        assert_eq!(a, cache_key("acme/shop", &Method::GET, "/x?y=1"));
        // A different tenant scope never collides (the isolation guarantee).
        assert_ne!(a, cache_key("other/shop", &Method::GET, "/x?y=1"));
        // Method and path/query each change the key.
        assert_ne!(a, cache_key("acme/shop", &Method::HEAD, "/x?y=1"));
        assert_ne!(a, cache_key("acme/shop", &Method::GET, "/x?y=2"));
        // The scope prefix is visible in the key for namespaced operability.
        assert!(a.starts_with("hcache/acme/shop/"));
    }

    #[test]
    fn cache_control_parsing_handles_directives_quotes_and_case() {
        let cc = parse_cache_control(&hm(&[(
            "cache-control",
            "Public, S-MaxAge=\"120\", max-age=60",
        )]));
        assert_eq!(
            cc,
            CacheControl {
                public: true,
                s_maxage: Some(120),
                max_age: Some(60),
                ..Default::default()
            }
        );
        let cc = parse_cache_control(&hm(&[("cache-control", "no-store")]));
        assert!(cc.no_store);
    }

    #[test]
    fn disabled_config_never_caches() {
        let d = write_decision(
            &Method::GET,
            &HeaderMap::new(),
            StatusCode::OK,
            &hm(&[("cache-control", "max-age=60")]),
            &CacheConfig::default(), // enabled = false
        );
        assert_eq!(d, WriteDecision::Bypass);
    }

    #[test]
    fn get_with_positive_max_age_is_cached_with_ttl() {
        let d = write_decision(
            &Method::GET,
            &HeaderMap::new(),
            StatusCode::OK,
            &hm(&[("cache-control", "max-age=60")]),
            &cfg(),
        );
        assert_eq!(
            d,
            WriteDecision::Cache {
                ttl_secs: 60,
                vary: vec![]
            }
        );
    }

    #[test]
    fn non_cacheable_method_status_and_privacy_signals_bypass() {
        let cc = hm(&[("cache-control", "max-age=60")]);
        // POST is never cached.
        assert_eq!(
            write_decision(
                &Method::POST,
                &HeaderMap::new(),
                StatusCode::OK,
                &cc,
                &cfg()
            ),
            WriteDecision::Bypass
        );
        // A non-cacheable status is never cached.
        assert_eq!(
            write_decision(
                &Method::GET,
                &HeaderMap::new(),
                StatusCode::INTERNAL_SERVER_ERROR,
                &cc,
                &cfg()
            ),
            WriteDecision::Bypass
        );
        // Privacy directives bypass.
        for signal in ["no-store", "no-cache", "private"] {
            assert_eq!(
                write_decision(
                    &Method::GET,
                    &HeaderMap::new(),
                    StatusCode::OK,
                    &hm(&[("cache-control", &format!("max-age=60, {signal}"))]),
                    &cfg()
                ),
                WriteDecision::Bypass,
                "{signal} must bypass"
            );
        }
        // A Set-Cookie response is per-user.
        assert_eq!(
            write_decision(
                &Method::GET,
                &HeaderMap::new(),
                StatusCode::OK,
                &hm(&[("cache-control", "max-age=60"), ("set-cookie", "s=1")]),
                &cfg()
            ),
            WriteDecision::Bypass
        );
        // Vary: * cannot be keyed.
        assert_eq!(
            write_decision(
                &Method::GET,
                &HeaderMap::new(),
                StatusCode::OK,
                &hm(&[("cache-control", "max-age=60"), ("vary", "*")]),
                &cfg()
            ),
            WriteDecision::Bypass
        );
        // No explicit max-age ⇒ nothing cached heuristically.
        assert_eq!(
            write_decision(
                &Method::GET,
                &HeaderMap::new(),
                StatusCode::OK,
                &hm(&[("cache-control", "public")]),
                &cfg()
            ),
            WriteDecision::Bypass
        );
    }

    #[test]
    fn authorization_request_requires_explicit_permission() {
        let auth = hm(&[("authorization", "Bearer t")]);
        // max-age alone is not enough for an Authorization-bearing request.
        assert_eq!(
            write_decision(
                &Method::GET,
                &auth,
                StatusCode::OK,
                &hm(&[("cache-control", "max-age=60")]),
                &cfg()
            ),
            WriteDecision::Bypass
        );
        // public grants it.
        assert_eq!(
            write_decision(
                &Method::GET,
                &auth,
                StatusCode::OK,
                &hm(&[("cache-control", "public, max-age=60")]),
                &cfg()
            ),
            WriteDecision::Cache {
                ttl_secs: 60,
                vary: vec![]
            }
        );
        // s-maxage also grants it (shared-cache directive).
        assert_eq!(
            write_decision(
                &Method::GET,
                &auth,
                StatusCode::OK,
                &hm(&[("cache-control", "s-maxage=30")]),
                &cfg()
            ),
            WriteDecision::Cache {
                ttl_secs: 30,
                vary: vec![]
            }
        );
    }

    #[test]
    fn s_maxage_wins_and_ttl_is_clamped() {
        // s-maxage takes precedence over max-age.
        let d = write_decision(
            &Method::GET,
            &HeaderMap::new(),
            StatusCode::OK,
            &hm(&[("cache-control", "max-age=10, s-maxage=45")]),
            &cfg(),
        );
        assert_eq!(
            d,
            WriteDecision::Cache {
                ttl_secs: 45,
                vary: vec![]
            }
        );
        // An over-long max-age is clamped to the config ceiling.
        let clamped = write_decision(
            &Method::GET,
            &HeaderMap::new(),
            StatusCode::OK,
            &hm(&[("cache-control", "max-age=999999")]),
            &CacheConfig {
                enabled: true,
                max_ttl_secs: 100,
                ..CacheConfig::default()
            },
        );
        assert_eq!(
            clamped,
            WriteDecision::Cache {
                ttl_secs: 100,
                vary: vec![]
            }
        );
    }

    #[test]
    fn vary_captures_request_header_values() {
        let req = hm(&[("accept-encoding", "gzip"), ("accept", "text/html")]);
        let d = write_decision(
            &Method::GET,
            &req,
            StatusCode::OK,
            &hm(&[
                ("cache-control", "max-age=60"),
                ("vary", "Accept-Encoding, Accept"),
            ]),
            &cfg(),
        );
        assert_eq!(
            d,
            WriteDecision::Cache {
                ttl_secs: 60,
                vary: vec![
                    ("accept-encoding".into(), Some("gzip".into())),
                    ("accept".into(), Some("text/html".into())),
                ],
            }
        );
    }

    #[test]
    fn entry_freshness_and_vary_matching() {
        let entry = CacheEntry {
            status: 200,
            headers: vec![],
            body: b"x".to_vec(),
            expiry_unix: 100,
            vary: vec![("accept-encoding".into(), Some("gzip".into()))],
        };
        assert!(entry.is_fresh(99));
        assert!(!entry.is_fresh(100));
        assert!(!entry.is_fresh(101));
        // Same varied header value ⇒ match.
        assert!(entry.matches_vary(&hm(&[("accept-encoding", "gzip")])));
        // Different value ⇒ miss.
        assert!(!entry.matches_vary(&hm(&[("accept-encoding", "br")])));
        // Newly absent header ⇒ miss.
        assert!(!entry.matches_vary(&HeaderMap::new()));
    }

    #[test]
    fn entry_encode_decode_round_trips() {
        let entry = CacheEntry {
            status: 404,
            headers: vec![
                ("content-type".into(), b"application/json".to_vec()),
                ("x-empty".into(), vec![]),
            ],
            body: b"{\"error\":\"nope\"}".to_vec(),
            expiry_unix: 1_723_000_000,
            vary: vec![
                ("accept".into(), Some("application/json".into())),
                ("cookie".into(), None),
            ],
        };
        let bytes = entry.encode();
        assert_eq!(CacheEntry::decode(&bytes), Some(entry));
    }

    use boatramp_core::config::{HandlerCacheConfig, HandlersSiteConfig};
    use boatramp_core::kv::{KvStore, MemoryKv};

    fn resp(status: u16, headers: &[(&str, &str)], body: &str) -> Response {
        let mut b = axum::http::Response::builder().status(status);
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        b.body(Body::from(body.to_string())).unwrap()
    }

    async fn body_string(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[test]
    fn config_for_is_off_unless_enabled() {
        assert!(config_for(&HandlersSiteConfig::default()).is_none());
        let disabled = HandlersSiteConfig {
            cache: Some(HandlerCacheConfig::default()), // enabled = false
            ..Default::default()
        };
        assert!(config_for(&disabled).is_none());
        let on = HandlersSiteConfig {
            cache: Some(HandlerCacheConfig {
                enabled: true,
                max_entry_bytes: Some(1024),
                max_ttl_secs: Some(90),
            }),
            ..Default::default()
        };
        let cfg = config_for(&on).expect("enabled");
        assert!(cfg.enabled);
        assert_eq!(cfg.max_entry_bytes, 1024);
        assert_eq!(cfg.max_ttl_secs, 90);
    }

    #[tokio::test]
    async fn store_then_lookup_round_trips_and_skips_instantiation() {
        let kv = MemoryKv::new();
        let cfg = cfg();
        let key = cache_key("acme/shop", &Method::GET, "/data");
        let response = resp(
            200,
            &[("cache-control", "max-age=60"), ("content-length", "3")],
            "abc",
        );
        // Store returns a byte-identical response to send onward.
        let served = maybe_store(
            Arc::new(kv.clone()),
            &cfg,
            &key,
            &Method::GET,
            &HeaderMap::new(),
            response,
            1_000,
        )
        .await;
        assert_eq!(body_string(served).await, "abc");
        // A later identical request is served from the cache (no handler run).
        let hit = lookup_response(&kv, &key, &HeaderMap::new(), 1_030)
            .await
            .expect("cache hit");
        assert_eq!(hit.status(), StatusCode::OK);
        assert_eq!(body_string(hit).await, "abc");
    }

    #[tokio::test]
    async fn expired_entry_is_a_miss_and_evicted() {
        let kv = MemoryKv::new();
        let key = cache_key("acme/shop", &Method::GET, "/data");
        maybe_store(
            Arc::new(kv.clone()),
            &cfg(),
            &key,
            &Method::GET,
            &HeaderMap::new(),
            resp(
                200,
                &[("cache-control", "max-age=60"), ("content-length", "1")],
                "x",
            ),
            1_000,
        )
        .await;
        // Past expiry (1000 + 60): a miss, and the stale key is deleted.
        assert!(lookup_response(&kv, &key, &HeaderMap::new(), 2_000)
            .await
            .is_none());
        assert!(kv.get(&key).await.unwrap().is_none(), "stale entry evicted");
    }

    #[tokio::test]
    async fn vary_mismatch_is_a_miss() {
        let kv = MemoryKv::new();
        let key = cache_key("acme/shop", &Method::GET, "/data");
        let req_gzip = hm(&[("accept-encoding", "gzip")]);
        maybe_store(
            Arc::new(kv.clone()),
            &cfg(),
            &key,
            &Method::GET,
            &req_gzip,
            resp(
                200,
                &[
                    ("cache-control", "max-age=60"),
                    ("vary", "accept-encoding"),
                    ("content-length", "2"),
                ],
                "ok",
            ),
            1_000,
        )
        .await;
        // Same varied value ⇒ hit; different value ⇒ miss (not a stale serve).
        assert!(lookup_response(&kv, &key, &req_gzip, 1_010).await.is_some());
        assert!(
            lookup_response(&kv, &key, &hm(&[("accept-encoding", "br")]), 1_010)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn private_and_unknown_length_responses_are_not_stored() {
        let kv = MemoryKv::new();
        let cfg = cfg();
        // A no-store response streams through and caches nothing.
        let key1 = cache_key("acme/shop", &Method::GET, "/a");
        let served = maybe_store(
            Arc::new(kv.clone()),
            &cfg,
            &key1,
            &Method::GET,
            &HeaderMap::new(),
            resp(
                200,
                &[("cache-control", "no-store"), ("content-length", "1")],
                "a",
            ),
            1_000,
        )
        .await;
        assert_eq!(body_string(served).await, "a");
        assert!(kv.get(&key1).await.unwrap().is_none());
        // A cacheable directive without Content-Length is not cached (can't bound the buffer).
        let key2 = cache_key("acme/shop", &Method::GET, "/b");
        let served = maybe_store(
            Arc::new(kv.clone()),
            &cfg,
            &key2,
            &Method::GET,
            &HeaderMap::new(),
            resp(200, &[("cache-control", "max-age=60")], "b"),
            1_000,
        )
        .await;
        assert_eq!(body_string(served).await, "b");
        assert!(kv.get(&key2).await.unwrap().is_none());
    }

    #[test]
    fn decode_rejects_truncation_bad_version_and_garbage() {
        let entry = CacheEntry {
            status: 200,
            headers: vec![("a".into(), b"b".to_vec())],
            body: b"body".to_vec(),
            expiry_unix: 1,
            vary: vec![],
        };
        let bytes = entry.encode();
        // Every truncation decodes to None, never a panic.
        for n in 0..bytes.len() {
            assert_eq!(CacheEntry::decode(&bytes[..n]), None, "truncation at {n}");
        }
        // Wrong version byte.
        let mut bad = bytes.clone();
        bad[0] = 2;
        assert_eq!(CacheEntry::decode(&bad), None);
        // Pure garbage.
        assert_eq!(CacheEntry::decode(&[9, 9, 9, 9]), None);
    }
}
