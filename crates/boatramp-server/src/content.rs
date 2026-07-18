//! Content-serving helpers for the static/file path: precompressed-variant and
//! on-the-fly encoding negotiation, response-header rules, MIME overrides, and
//! HTTP byte-range (`Range`) serving (including `multipart/byteranges`). Tightly
//! coupled to the serve pipeline in the crate root, so it pulls that scope in via
//! `use super::*`.

use super::*;

/// Pick the best precompressed variant the client accepts (brotli preferred,
/// then gzip), or `None` to serve the identity representation.
pub(super) fn negotiate_encoding<'a>(
    entry: &'a FileEntry,
    req_headers: &HeaderMap,
) -> Option<(&'a str, &'a boatramp_core::deploy::Variant)> {
    if entry.variants.is_empty() {
        return None;
    }
    let accept = req_headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())?;
    for enc in ["br", "gzip"] {
        if accepts_encoding(accept, enc) {
            if let Some(variant) = entry.variants.get(enc) {
                // Only serve a variant that is actually smaller than identity.
                // A variant ≥ identity gains nothing and is a decompression-bomb
                // smell; fall back to identity. boatramp itself
                // never decompresses (it streams the precompressed bytes and the
                // client decodes), so this is the whole server-side surface.
                if variant.size < entry.size {
                    return Some((enc, variant));
                }
            }
        }
    }
    None
}

/// Whether a content type is worth compressing on the fly (text + structured
/// formats; never already-compressed media). Parameters (`; charset=…`) ignored.
#[cfg(feature = "compression")]
fn is_compressible(content_type: &str) -> bool {
    let ct = content_type.split(';').next().unwrap_or("").trim();
    matches!(
        ct,
        "application/javascript"
            | "application/json"
            | "application/manifest+json"
            | "application/xml"
            | "application/rss+xml"
            | "application/atom+xml"
            | "image/svg+xml"
            | "application/wasm"
    ) || ct.starts_with("text/")
}

/// On-the-fly compression, applied late so it covers
/// dynamic (handler/proxy) responses and static files with no precompressed
/// variant. Compresses only when the response is `200`, has no existing
/// `Content-Encoding` (a chosen variant / already-encoded upstream is left
/// alone), carries no `Set-Cookie` (BREACH safety), has a compressible type, and
/// (when its length is known) is at least `min_size`. Streams the encoder.
#[cfg(feature = "compression")]
pub(super) fn maybe_compress(
    response: Response,
    accept_encoding: Option<&str>,
    min_size: u64,
) -> Response {
    use tokio_util::io::{ReaderStream, StreamReader};

    if response.status() != StatusCode::OK {
        return response;
    }
    let headers = response.headers();
    if headers.contains_key(header::CONTENT_ENCODING) || headers.contains_key(header::SET_COOKIE) {
        return response;
    }
    let compressible = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(is_compressible);
    if !compressible {
        return response;
    }
    if let Some(len) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
    {
        if len < min_size {
            return response;
        }
    }
    let accept = accept_encoding.unwrap_or("");
    // Prefer gzip for on-the-fly (fast); fall back to brotli.
    let encoding = if accepts_encoding(accept, "gzip") {
        "gzip"
    } else if accepts_encoding(accept, "br") {
        "br"
    } else {
        return response;
    };

    let (mut parts, body) = response.into_parts();
    let reader = StreamReader::new(
        body.into_data_stream()
            .map(|chunk| chunk.map_err(std::io::Error::other)),
    );
    let compressed = if encoding == "gzip" {
        Body::from_stream(ReaderStream::new(
            async_compression::tokio::bufread::GzipEncoder::new(reader),
        ))
    } else {
        Body::from_stream(ReaderStream::new(
            async_compression::tokio::bufread::BrotliEncoder::new(reader),
        ))
    };
    // The framing changes, so drop the old length and let it be re-chunked.
    parts.headers.remove(header::CONTENT_LENGTH);
    parts
        .headers
        .insert(header::CONTENT_ENCODING, HeaderValue::from_static(encoding));
    append_vary_accept_encoding(&mut parts.headers);
    Response::from_parts(parts, compressed)
}

/// Add `accept-encoding` to the `Vary` header (creating or extending it).
#[cfg(feature = "compression")]
fn append_vary_accept_encoding(headers: &mut HeaderMap) {
    let existing = headers
        .get(header::VARY)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if existing
        .split(',')
        .any(|t| t.trim().eq_ignore_ascii_case("accept-encoding"))
    {
        return;
    }
    let merged = if existing.is_empty() {
        "accept-encoding".to_string()
    } else {
        format!("{existing}, accept-encoding")
    };
    if let Ok(value) = HeaderValue::from_str(&merged) {
        headers.insert(header::VARY, value);
    }
}

/// Whether an `Accept-Encoding` value accepts `enc` (honoring an explicit
/// `;q=0` refusal and the `*` wildcard).
fn accepts_encoding(accept: &str, enc: &str) -> bool {
    accept.split(',').any(|part| {
        let mut bits = part.trim().split(';');
        let token = bits.next().unwrap_or("").trim();
        let refused = bits.any(|p| matches!(p.trim(), "q=0" | "q=0.0" | "q=0.00" | "q=0.000"));
        !refused && (token.eq_ignore_ascii_case(enc) || token == "*")
    })
}

/// Set `Content-Encoding` for a served variant (no-op for identity).
pub(super) fn set_content_encoding(headers: &mut HeaderMap, encoding: Option<&str>) {
    if let Some(enc) = encoding {
        set_header(headers, header::CONTENT_ENCODING, enc);
    }
}

/// Build the common response headers: Content-Type (MIME override → entry),
/// ETag, Accept-Ranges, Cache-Control default, then deploy-config header rules.
pub(super) fn response_headers(
    config: &DeployConfig,
    request_path: &str,
    served_path: &str,
    entry: &FileEntry,
    etag: &str,
) -> HeaderMap {
    let mut headers = HeaderMap::new();

    let content_type = mime_override(config, served_path).or_else(|| entry.content_type.clone());
    if let Some(value) = content_type
        .as_deref()
        .and_then(|ct| HeaderValue::from_str(ct).ok())
    {
        headers.insert(header::CONTENT_TYPE, value);
    }
    set_header(&mut headers, header::ETAG, etag);
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    // Safe defaults for a static host; operators can override either via a
    // header rule (or `Referrer-Policy` site-wide via SecurityConfig later).
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    // When precompressed variants exist, caches must key on Accept-Encoding.
    if !entry.variants.is_empty() {
        headers.insert(header::VARY, HeaderValue::from_static("accept-encoding"));
    }
    // Cache-Control: the operator's blanket `cache.default` wins; otherwise fall
    // back to smart per-file defaults (fingerprinted assets → immutable, HTML →
    // revalidate). Explicit header rules below override either.
    let cache = config
        .cache
        .default
        .as_deref()
        .or_else(|| route::cache_control_default(served_path, content_type.as_deref()));
    if let Some(cache) = cache {
        set_header(&mut headers, header::CACHE_CONTROL, cache);
    }
    apply_header_rules(config, request_path, &mut headers);
    headers
}

/// Apply matching deploy-config header rules (set/unset) to the response.
fn apply_header_rules(config: &DeployConfig, request_path: &str, headers: &mut HeaderMap) {
    for rule in &config.headers {
        let matches = Pattern::compile(&rule.matches)
            .ok()
            .is_some_and(|pattern| pattern.is_match(request_path));
        if !matches {
            continue;
        }
        for name in &rule.unset {
            if let Ok(name) = HeaderName::from_bytes(name.as_bytes()) {
                headers.remove(name);
            }
        }
        for (key, value) in &rule.set {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(key.as_bytes()),
                HeaderValue::from_str(value),
            ) {
                headers.insert(name, value);
            }
        }
    }
}

/// MIME override for `served_path`'s extension, from the deploy config.
fn mime_override(config: &DeployConfig, served_path: &str) -> Option<String> {
    let ext = std::path::Path::new(served_path).extension()?.to_str()?;
    config.mime_overrides.get(&format!(".{ext}")).cloned()
}

/// Most ranges honored in one `Range` request; beyond this the caller ignores
/// `Range` and serves the full `200` body (a cheap multi-range-amplification
/// guard — RFC 7233 permits ignoring the header).
pub(super) const MAX_RANGES: usize = 64;

/// Parse a `Range: bytes=…` header against `total` into the satisfiable
/// `(offset, len)` ranges, in request order. `None` when the header is
/// malformed or **every** range is unsatisfiable (caller responds `416`); a
/// returned `Vec` has at least one range. Unsatisfiable ranges in an otherwise
/// satisfiable set are dropped (RFC 7233 §4.1).
pub(super) fn parse_ranges(spec: &str, total: u64) -> Option<Vec<(u64, u64)>> {
    let spec = spec.strip_prefix("bytes=")?;
    let mut out = Vec::new();
    let mut saw_range = false;
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        saw_range = true;
        if let Some(range) = parse_one_range(part, total) {
            out.push(range);
        }
    }
    if !saw_range || out.is_empty() {
        return None;
    }
    Some(out)
}

/// Parse one `start-end` / `start-` / `-suffix` spec against `total`.
fn parse_one_range(part: &str, total: u64) -> Option<(u64, u64)> {
    let (start, end) = part.split_once('-')?;
    if start.is_empty() {
        let suffix: u64 = end.parse().ok()?;
        if suffix == 0 || total == 0 {
            return None;
        }
        let len = suffix.min(total);
        return Some((total - len, len));
    }
    let start: u64 = start.parse().ok()?;
    if start >= total {
        return None;
    }
    let end = if end.is_empty() {
        total - 1
    } else {
        end.parse::<u64>().ok()?.min(total - 1)
    };
    if end < start {
        return None;
    }
    Some((start, end - start + 1))
}

/// A `206 multipart/byteranges` response over `ranges` (each a satisfiable
/// `(offset, len)` of the identity blob), streamed part-by-part — the bytes are
/// never buffered. `Content-Length` is computed up front (every part header is
/// deterministic), so the response is not chunked.
pub(super) async fn multipart_byteranges(
    deploy: &DeployStore,
    config: &DeployConfig,
    request_path: &str,
    served_path: &str,
    entry: &FileEntry,
    etag: &str,
    ranges: &[(u64, u64)],
) -> Response {
    let total = entry.size;
    // A boundary unlikely to occur in the body (the blob is content-addressed).
    let boundary = format!("boatramp{}", &entry.hash[..entry.hash.len().min(24)]);
    // The per-part `Content-Type` is the resource's own media type.
    let part_ct = mime_override(config, served_path).or_else(|| entry.content_type.clone());
    let part_ct_line = match &part_ct {
        Some(ct) => format!("Content-Type: {ct}\r\n"),
        None => String::new(),
    };

    // Open each range reader up front (bounded by MAX_RANGES) and assemble the
    // interleaved [header, body, header, body, …, closing] stream.
    let mut segments: Vec<boatramp_core::ByteStream> = Vec::with_capacity(ranges.len() * 2 + 1);
    let mut content_length: u64 = 0;
    for &(offset, len) in ranges {
        let header = format!(
            "\r\n--{boundary}\r\n{part_ct_line}Content-Range: bytes {}-{}/{}\r\n\r\n",
            offset,
            offset + len - 1,
            total
        );
        content_length += header.len() as u64 + len;
        let object = match deploy.open_blob_range(&entry.hash, offset, Some(len)).await {
            Ok(object) => object,
            Err(err) => return deploy_error_response(err),
        };
        segments.push(futures::stream::once(async move { Ok(bytes::Bytes::from(header)) }).boxed());
        segments.push(object.body);
    }
    let closing = format!("\r\n--{boundary}--\r\n");
    content_length += closing.len() as u64;
    segments.push(futures::stream::once(async move { Ok(bytes::Bytes::from(closing)) }).boxed());

    // Start from the resource headers but replace Content-Type with the
    // multipart type (each part carries the resource's own type instead).
    let mut headers = response_headers(config, request_path, served_path, entry, etag);
    set_header(
        &mut headers,
        header::CONTENT_TYPE,
        &format!("multipart/byteranges; boundary={boundary}"),
    );
    set_header(
        &mut headers,
        header::CONTENT_LENGTH,
        &content_length.to_string(),
    );
    let body = futures::stream::iter(segments).flatten();
    (
        StatusCode::PARTIAL_CONTENT,
        headers,
        Body::from_stream(body),
    )
        .into_response()
}
