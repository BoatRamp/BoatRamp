//! The HTTP/1.1 request parser + response framing (the codec's byte layer; the
//! connection loop that drives it lives in [`super::serve`]).
//!
//! The request-head parser here is the security-critical surface of a reverse proxy:
//! HTTP/1.1's Content-Length vs Transfer-Encoding ambiguity is *the* classic
//! request-smuggling / desync vector, and unlike HTTP/2 (which has h2spec) there is no
//! ready-made conformance oracle. So this codec is built **test-first**: the `tests/`
//! harness — a differential oracle against `hyper`, a curated smuggling corpus, RFC 9112
//! conformance cases, and a randomized fuzz smoke — is written and wired *before* the
//! parser, and [`parse_request_head`] is only promoted from the stub below once that
//! harness is green. See `DESIGN-serving.md`.
//!
//! The design invariant the harness enforces: **fail closed.** Any framing ambiguity is
//! a [`Reject`], never a guess — so nothing a downstream could interpret differently is
//! ever forwarded.

use http::{HeaderMap, Method, Uri, Version};

/// How a request message body is delimited (RFC 9112 §6). A request (unlike a response)
/// has no close-delimited body; absence of both framing headers means *no* body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BodyFraming {
    /// No message body — no `Transfer-Encoding`, no `Content-Length`.
    Empty,
    /// A fixed-length body of exactly this many octets.
    Length(u64),
    /// A chunked-transfer-coded body, terminated by a zero-size chunk (+ trailers).
    Chunked,
}

/// A parsed request head: the request line + header fields, with the body framing
/// already resolved (so the caller knows exactly where the body — and thus the next
/// pipelined request — begins).
#[derive(Debug, Clone)]
pub struct RequestHead {
    pub method: Method,
    pub uri: Uri,
    pub version: Version,
    pub headers: HeaderMap,
    pub framing: BodyFraming,
}

/// Why a request was rejected. Every ambiguous or malformed framing maps to one of
/// these (→ a `400`/`close`), never to a silent normalization — that is the anti-
/// smuggling contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
    /// Malformed request line (method/target/version token shape).
    BadRequestLine,
    /// HTTP version not `1.0`/`1.1`, or otherwise unacceptable.
    BadVersion,
    /// Malformed header field (name token / value bytes / missing colon).
    BadHeader,
    /// Obsolete line folding (a header line starting with SP/HTAB) — RFC 9112 §5.2.
    ObsFold,
    /// Bare CR or bare LF used as a line terminator where CRLF is required.
    BareCrlf,
    /// `Content-Length` unparsable, or multiple `Content-Length` with differing values.
    BadContentLength,
    /// Both `Content-Length` and `Transfer-Encoding` present (CL/TE desync risk), or a
    /// duplicated framing that can't be reconciled.
    ConflictingFraming,
    /// `Transfer-Encoding` present but its final coding is not `chunked` (a request with
    /// no determinable length) — RFC 9112 §6.3.
    BadTransferEncoding,
    /// A bound was exceeded (request line, header block, header count, chunk-size line).
    TooLarge,
    /// Malformed chunked framing (chunk-size not hex / overflow / bad terminator).
    BadChunk,
}

/// The outcome of parsing one request head from the front of a buffer.
// `Complete` carries the parsed head inline; it is returned once per parsed request, so
// boxing it (to shrink the enum) would trade a large stack value for a per-request heap
// allocation on the hot serving path — not worth it.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ParseResult {
    /// A complete head was parsed; `consumed` bytes were the head (the body, per
    /// [`RequestHead::framing`], begins at `consumed`).
    Complete { head: RequestHead, consumed: usize },
    /// The buffer does not yet contain a full head (no CRLFCRLF); read more.
    Incomplete,
    /// The head is malformed or ambiguous — reject the connection (fail closed).
    Reject(Reject),
}

/// Parse a single HTTP/1.x request head (request line + header fields, up to and
/// including the terminating CRLFCRLF) from the front of `buf`, resolving the body
/// framing per RFC 9112 §6.
///
/// **Contract (enforced by the `tests/` harness before this is implemented):**
/// - Byte-for-byte agreement with `hyper`'s HTTP/1 parser on well-formed input, or a
///   `Reject` where `hyper` also refuses — never *more* permissive on message boundaries.
/// - Every smuggling vector in `tests/smuggling.rs` returns `Reject` (fail closed).
/// - Panic-free and desync-free on arbitrary bytes (`tests/fuzz_smoke.rs`).
pub fn parse_request_head(buf: &[u8]) -> ParseResult {
    match parse_head_inner(buf) {
        Ok(Some((head, consumed))) => ParseResult::Complete { head, consumed },
        Ok(None) => ParseResult::Incomplete,
        Err(r) => ParseResult::Reject(r),
    }
}

/// The largest request head (request line + all headers, through the terminating
/// CRLFCRLF) we will buffer before rejecting — a slowloris / oversized-header bound.
const MAX_HEAD: usize = 64 * 1024;

/// One CRLF-terminated line pulled from a buffer, or a signal to stop.
enum Line<'a> {
    /// The line content (CRLF stripped) and the offset just past its CRLF.
    Got(&'a [u8], usize),
    /// No complete CRLF-terminated line yet — read more.
    Incomplete,
}

/// Read one strictly-CRLF-terminated line starting at `pos`. Enforces CRLF framing: a
/// bare LF (not preceded by CR) or a bare CR (inside the line) is a hard reject — those
/// are the h1 line-terminator smuggling vectors.
fn next_line(buf: &[u8], pos: usize) -> Result<Line<'_>, Reject> {
    let Some(rel_nl) = buf[pos..].iter().position(|&b| b == b'\n') else {
        return Ok(Line::Incomplete);
    };
    let nl = pos + rel_nl;
    // The byte before LF must be CR (no bare LF terminator).
    if nl == pos || buf[nl - 1] != b'\r' {
        return Err(Reject::BareCrlf);
    }
    let content = &buf[pos..nl - 1];
    // No stray CR may appear inside the line (only the terminating one, at nl-1).
    if content.contains(&b'\r') {
        return Err(Reject::BareCrlf);
    }
    Ok(Line::Got(content, nl + 1))
}

fn parse_head_inner(buf: &[u8]) -> Result<Option<(RequestHead, usize)>, Reject> {
    // Tolerate at most one empty line before the request line (RFC 9112 §2.2).
    let mut pos = match next_line(buf, 0)? {
        Line::Got(&[], next) => next,
        _ => 0,
    };

    let (method, uri, version) = match next_line(buf, pos)? {
        Line::Incomplete => {
            return if buf.len() > MAX_HEAD {
                Err(Reject::TooLarge)
            } else {
                Ok(None)
            };
        }
        Line::Got(line, next) => {
            pos = next;
            parse_request_line(line)?
        }
    };

    let is_11 = version == Version::HTTP_11;
    let mut headers = HeaderMap::new();
    // Framing-relevant fields are gathered as raw tokens for the CL×TE resolution.
    let mut cl_tokens: Vec<Vec<u8>> = Vec::new();
    let mut te_values: Vec<Vec<u8>> = Vec::new();
    let mut host_count = 0usize;
    let mut host_empty = false;

    loop {
        if buf.len() > MAX_HEAD && pos >= MAX_HEAD {
            return Err(Reject::TooLarge);
        }
        match next_line(buf, pos)? {
            Line::Incomplete => {
                return if buf.len() > MAX_HEAD {
                    Err(Reject::TooLarge)
                } else {
                    Ok(None)
                };
            }
            Line::Got(line, next) => {
                pos = next;
                if line.is_empty() {
                    break; // end of the header block
                }
                // Obs-fold (a line starting with SP/HTAB) is rejected outright (§5.2).
                if line[0] == b' ' || line[0] == b'\t' {
                    return Err(Reject::ObsFold);
                }
                let (name, value) = split_header(line)?;
                let lname = name.to_ascii_lowercase();
                if lname == b"content-length" {
                    // Split on commas so a comma-list counts as multiple tokens.
                    for tok in value.split(|&b| b == b',') {
                        cl_tokens.push(trim_ows(tok).to_vec());
                    }
                } else if lname == b"transfer-encoding" {
                    te_values.push(value.to_vec());
                } else if lname == b"host" {
                    host_count += 1;
                    host_empty = trim_ows(value).is_empty();
                }
                let hn =
                    http::header::HeaderName::from_bytes(name).map_err(|_| Reject::BadHeader)?;
                let hv =
                    http::header::HeaderValue::from_bytes(value).map_err(|_| Reject::BadHeader)?;
                headers.append(hn, hv);
            }
        }
    }

    // Host coherence (RFC 9112 §3.2): exactly one non-empty Host in 1.1; ≤1 in 1.0.
    if is_11 {
        if host_count != 1 || host_empty {
            return Err(Reject::BadHeader);
        }
    } else if host_count > 1 {
        return Err(Reject::BadHeader);
    }

    let framing = resolve_framing(&cl_tokens, &te_values, is_11)?;
    Ok(Some((
        RequestHead {
            method,
            uri,
            version,
            headers,
            framing,
        },
        pos,
    )))
}

/// Parse the request line into `(method, uri, version)`, enforcing exactly one SP
/// between the three tokens and per-method target validity.
fn parse_request_line(line: &[u8]) -> Result<(Method, Uri, Version), Reject> {
    // Exactly three SP-separated fields — split on b' ' and require precisely 3 parts,
    // so any extra/other whitespace (double SP, TAB, VT, FF) is malformed.
    let mut parts = line.split(|&b| b == b' ');
    let (Some(m), Some(t), Some(v), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Reject::BadRequestLine);
    };
    if m.is_empty() || !m.iter().all(|&b| is_tchar(b)) {
        return Err(Reject::BadRequestLine);
    }
    let method = Method::from_bytes(m).map_err(|_| Reject::BadRequestLine)?;
    let version = match v {
        b"HTTP/1.1" => Version::HTTP_11,
        b"HTTP/1.0" => Version::HTTP_10,
        _ => return Err(Reject::BadVersion),
    };
    let uri = parse_target(&method, t)?;
    Ok((method, uri, version))
}

/// Validate + parse a request target for `method`. Rejects any space/control/DEL byte
/// and a fragment; `*` is only valid for OPTIONS; otherwise origin-form (`/...`),
/// absolute-form (`scheme://...`), or CONNECT authority-form.
fn parse_target(method: &Method, target: &[u8]) -> Result<Uri, Reject> {
    if target.is_empty() || target.iter().any(|&b| b <= 0x20 || b == 0x7f || b == b'#') {
        return Err(Reject::BadRequestLine);
    }
    let is_asterisk = target == b"*";
    let is_origin = target[0] == b'/';
    let is_absolute = target.windows(3).any(|w| w == b"://");
    let ok = if *method == Method::OPTIONS {
        is_asterisk || is_origin || is_absolute
    } else if *method == Method::CONNECT {
        // authority-form: host:port, no scheme, no path.
        !is_asterisk && !is_origin && !is_absolute && target.contains(&b':')
    } else {
        is_origin || is_absolute
    };
    if !ok {
        return Err(Reject::BadRequestLine);
    }
    Uri::try_from(target).map_err(|_| Reject::BadRequestLine)
}

/// Split a header line into `(name, value)`: the name is up to the first colon (and must
/// be all-`tchar`, so whitespace before the colon is a reject); the value is OWS-trimmed
/// and must contain no CTL other than HTAB.
fn split_header(line: &[u8]) -> Result<(&[u8], &[u8]), Reject> {
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(Reject::BadHeader)?;
    let name = &line[..colon];
    if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
        return Err(Reject::BadHeader);
    }
    let value = trim_ows(&line[colon + 1..]);
    // field-content: VCHAR / obs-text / SP / HTAB — reject CTL (except HTAB) and DEL.
    if value.iter().any(|&b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(Reject::BadHeader);
    }
    Ok((name, value))
}

/// Resolve request body framing from the gathered Content-Length tokens + Transfer-
/// Encoding field values (RFC 9112 §6.3). Fail-closed on every ambiguity.
fn resolve_framing(
    cl_tokens: &[Vec<u8>],
    te_values: &[Vec<u8>],
    is_11: bool,
) -> Result<BodyFraming, Reject> {
    let cl_present = !cl_tokens.is_empty();
    let te_present = !te_values.is_empty();
    // Both framing headers present is the CL/TE desync surface — never reconcile it.
    if cl_present && te_present {
        return Err(Reject::ConflictingFraming);
    }
    if te_present {
        // Transfer-Encoding is an HTTP/1.1 feature; a 1.0 request can't carry chunked (a
        // 1.0 intermediary wouldn't understand it), so TE on a 1.0 request is a desync
        // setup — reject it (RFC 9112 §6.1).
        if !is_11 {
            return Err(Reject::BadTransferEncoding);
        }
        // Multiple Transfer-Encoding *header fields* (as opposed to one comma-list) is a
        // TE.TE desync vector — servers disagree on first-vs-last — so reject it outright
        // rather than combine. A single field carrying a comma-list is still fine.
        if te_values.len() != 1 {
            return Err(Reject::BadTransferEncoding);
        }
        // Split the single value into its coding list; chunked must appear exactly once
        // and be the final coding, with no empty elements.
        let mut codings: Vec<Vec<u8>> = Vec::new();
        for value in te_values {
            for tok in value.split(|&b| b == b',') {
                codings.push(trim_ows(tok).to_ascii_lowercase());
            }
        }
        if codings.iter().any(|c| c.is_empty()) {
            return Err(Reject::BadTransferEncoding);
        }
        let chunked_count = codings
            .iter()
            .filter(|c| c.as_slice() == b"chunked")
            .count();
        let last_is_chunked = codings
            .last()
            .map(|c| c.as_slice() == b"chunked")
            .unwrap_or(false);
        if chunked_count != 1 || !last_is_chunked {
            return Err(Reject::BadTransferEncoding);
        }
        return Ok(BodyFraming::Chunked);
    }
    if cl_present {
        // Exactly one Content-Length token across all CL headers + comma-lists; any
        // duplication (even identical values) is ambiguous → reject.
        if cl_tokens.len() != 1 {
            return Err(Reject::BadContentLength);
        }
        let tok = &cl_tokens[0];
        if tok.is_empty() || !tok.iter().all(|&b| b.is_ascii_digit()) {
            return Err(Reject::BadContentLength);
        }
        let n = std::str::from_utf8(tok)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(Reject::BadContentLength)?;
        return Ok(BodyFraming::Length(n));
    }
    Ok(BodyFraming::Empty)
}

/// Trim leading + trailing optional whitespace (SP / HTAB) — RFC 9110 OWS.
fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = v {
        if *first == b' ' || *first == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = v {
        if *last == b' ' || *last == b'\t' {
            v = rest;
        } else {
            break;
        }
    }
    v
}

/// RFC 9110 `tchar`: the token characters allowed in a method / header-field name.
fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

// ---- response framing (the sender side — boatramp's own output) --------------

/// How a *response* body is delimited on the wire (RFC 9112 §6, sender side). Unlike a
/// request, a response body may be **close-delimited** (framed by connection close).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseFraming {
    /// No body is sent regardless of headers — a `HEAD` response, a `1xx`/`204`/`304`
    /// status, or a `CONNECT` 2xx (RFC 9110 §6.4.1 / RFC 9112 §6.3).
    None,
    /// A fixed-length body (`Content-Length`).
    Length(u64),
    /// A chunked-transfer-coded body.
    Chunked,
    /// Framed by connection close (HTTP/1.0-style; forces `Connection: close`).
    CloseDelimited,
}

/// Decide how a response body is framed, encoding the no-body rules: a `HEAD` request,
/// or a `1xx`/`204`/`304` status, has no body no matter what `Content-Length`/
/// `Transfer-Encoding` say. Otherwise `Transfer-Encoding: chunked` → chunked, else a
/// `Content-Length` → that length, else close-delimited.
pub fn response_framing(
    status: u16,
    request_method: &Method,
    headers: &HeaderMap,
) -> ResponseFraming {
    // No-body rules (RFC 9110 §6.4.1) override the framing headers.
    let no_body = *request_method == Method::HEAD
        || (100..200).contains(&status)
        || status == 204
        || status == 304
        || (*request_method == Method::CONNECT && (200..300).contains(&status));
    if no_body {
        return ResponseFraming::None;
    }
    if headers.contains_key(http::header::TRANSFER_ENCODING) {
        return ResponseFraming::Chunked;
    }
    if let Some(cl) = headers.get(http::header::CONTENT_LENGTH) {
        if let Some(n) = cl.to_str().ok().and_then(|s| s.trim().parse::<u64>().ok()) {
            return ResponseFraming::Length(n);
        }
    }
    ResponseFraming::CloseDelimited
}

/// Encode a response head — status line (`HTTP/1.1 <code> <reason>`) + header fields +
/// the terminating CRLFCRLF. The reason phrase is the registered one for the status.
pub fn encode_response_head(status: u16, headers: &HeaderMap) -> Vec<u8> {
    let reason = http::StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("");
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n").into_bytes();
    for (name, value) in headers.iter() {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out
}

/// Chunked-transfer coding — decode (the request-side smuggling surface: chunk-size
/// lines, extensions, trailers) and encode (response-side body framing).
pub mod chunked {
    use http::HeaderMap;

    /// The outcome of scanning a chunked body for its end.
    #[derive(Debug)]
    pub enum ChunkScan {
        /// The chunked body (all data chunks + the terminating 0-chunk + trailers +
        /// final CRLF) ends at this byte offset into the buffer.
        Complete { end: usize },
        /// More bytes are needed to reach the terminating chunk.
        Incomplete,
        /// Malformed chunk framing — reject (fail closed).
        Reject(super::Reject),
    }

    use super::{next_line, split_header, trim_ows, Line, Reject};

    /// Largest chunk-size line (`<hex>;<ext>`) accepted — bounds a size-line DoS.
    const MAX_CHUNK_SIZE_LINE: usize = 1024;
    /// Trailer field names that must never appear in a trailer section — they affect
    /// message framing/routing and would enable trailer-based desync (RFC 9110 §6.5.2).
    fn forbidden_trailer(name: &[u8]) -> bool {
        let l = name.to_ascii_lowercase();
        matches!(
            l.as_slice(),
            b"content-length"
                | b"transfer-encoding"
                | b"host"
                | b"trailer"
                | b"te"
                | b"connection"
                | b"expect"
                | b"upgrade"
                | b"content-type"
        )
    }

    /// The outcome of decoding a chunked body: the collected payload + where it ended.
    #[derive(Debug)]
    pub enum ChunkDecode {
        /// The full chunked body decoded to `data`, ending at byte offset `end`.
        Complete { data: Vec<u8>, end: usize },
        /// More bytes are needed to reach the terminating chunk.
        Incomplete,
        /// Malformed chunk framing — reject (fail closed).
        Reject(super::Reject),
    }

    /// Scan a chunked message body starting at the front of `buf`, returning where it
    /// ends. Rejects a non-hex/overflowing chunk size, bad chunk terminators, an
    /// oversized chunk-size line, or a forbidden trailer field.
    pub fn scan(buf: &[u8]) -> ChunkScan {
        match walk(buf, None) {
            Ok(Some((_, end))) => ChunkScan::Complete { end },
            Ok(None) => ChunkScan::Incomplete,
            Err(r) => ChunkScan::Reject(r),
        }
    }

    /// Decode a chunked message body starting at the front of `buf`: same framing checks
    /// as [`scan`], but also collects the decoded payload (the serve loop needs the body,
    /// not just its end).
    pub fn decode(buf: &[u8]) -> ChunkDecode {
        match walk(buf, Some(Vec::new())) {
            Ok(Some((data, end))) => ChunkDecode::Complete {
                data: data.unwrap_or_default(),
                end,
            },
            Ok(None) => ChunkDecode::Incomplete,
            Err(r) => ChunkDecode::Reject(r),
        }
    }

    /// Walk a chunked body once, enforcing framing. When `collect` is `Some`, the chunk
    /// data is appended to it; returns `(collected, end_offset)`. `scan` passes `None`.
    fn walk(
        buf: &[u8],
        mut collect: Option<Vec<u8>>,
    ) -> Result<Option<(Option<Vec<u8>>, usize)>, Reject> {
        let mut pos = 0usize;
        loop {
            // chunk-size line: `<hex>[;chunk-ext]CRLF`.
            let (line, next) = match next_line(buf, pos)? {
                Line::Got(l, n) => (l, n),
                Line::Incomplete => return Ok(None),
            };
            if line.len() > MAX_CHUNK_SIZE_LINE {
                return Err(Reject::TooLarge);
            }
            // Strip an optional chunk-extension (`;...`); the size is the hex prefix.
            let size_bytes = match line.iter().position(|&b| b == b';') {
                Some(i) => &line[..i],
                None => line,
            };
            let size = parse_chunk_size(size_bytes)?;
            pos = next;
            if size == 0 {
                // last-chunk: consume the trailer section up to the terminating empty line.
                loop {
                    let (tline, tnext) = match next_line(buf, pos)? {
                        Line::Got(l, n) => (l, n),
                        Line::Incomplete => return Ok(None),
                    };
                    pos = tnext;
                    if tline.is_empty() {
                        return Ok(Some((collect, pos))); // end of the chunked body
                    }
                    // A trailer is a header field; reject framing-sensitive ones.
                    if tline[0] == b' ' || tline[0] == b'\t' {
                        return Err(Reject::ObsFold);
                    }
                    let (name, _value) = split_header(tline)?;
                    if forbidden_trailer(name) {
                        return Err(Reject::BadChunk);
                    }
                }
            }
            // chunk-data: exactly `size` octets, then a CRLF.
            let data_end = pos.checked_add(size as usize).ok_or(Reject::BadChunk)?;
            let crlf_end = data_end.checked_add(2).ok_or(Reject::BadChunk)?;
            if crlf_end > buf.len() {
                return Ok(None);
            }
            if &buf[data_end..crlf_end] != b"\r\n" {
                return Err(Reject::BadChunk);
            }
            if let Some(acc) = collect.as_mut() {
                acc.extend_from_slice(&buf[pos..data_end]);
            }
            pos = crlf_end;
        }
    }

    /// One step of an **incremental** chunked decode from the front of a buffer — for the
    /// serve loop, which streams each chunk to the handler as it completes rather than
    /// buffering the whole body.
    #[derive(Debug)]
    pub enum ChunkStep {
        /// A data chunk: `buf[data_start..data_end]` is the payload; the next chunk starts
        /// at `next`.
        Data {
            data_start: usize,
            data_end: usize,
            next: usize,
        },
        /// The terminating 0-chunk (+ trailers) ends the body at offset `end`.
        Last { end: usize },
        /// More bytes are needed to complete the current chunk.
        Incomplete,
        /// Malformed chunk framing — reject (fail closed).
        Reject(super::Reject),
    }

    /// Parse a single chunk from the front of `buf` (see [`ChunkStep`]).
    pub fn next_chunk(buf: &[u8]) -> ChunkStep {
        match next_chunk_inner(buf) {
            Ok(step) => step,
            Err(r) => ChunkStep::Reject(r),
        }
    }

    fn next_chunk_inner(buf: &[u8]) -> Result<ChunkStep, Reject> {
        let (line, next) = match next_line(buf, 0)? {
            Line::Got(l, n) => (l, n),
            Line::Incomplete => return Ok(ChunkStep::Incomplete),
        };
        if line.len() > MAX_CHUNK_SIZE_LINE {
            return Err(Reject::TooLarge);
        }
        let size_bytes = match line.iter().position(|&b| b == b';') {
            Some(i) => &line[..i],
            None => line,
        };
        let size = parse_chunk_size(size_bytes)?;
        if size == 0 {
            // last-chunk: consume the trailer section up to the terminating empty line.
            let mut pos = next;
            loop {
                let (tline, tnext) = match next_line(buf, pos)? {
                    Line::Got(l, n) => (l, n),
                    Line::Incomplete => return Ok(ChunkStep::Incomplete),
                };
                pos = tnext;
                if tline.is_empty() {
                    return Ok(ChunkStep::Last { end: pos });
                }
                if tline[0] == b' ' || tline[0] == b'\t' {
                    return Err(Reject::ObsFold);
                }
                let (name, _value) = split_header(tline)?;
                if forbidden_trailer(name) {
                    return Err(Reject::BadChunk);
                }
            }
        }
        let data_end = next.checked_add(size as usize).ok_or(Reject::BadChunk)?;
        let crlf_end = data_end.checked_add(2).ok_or(Reject::BadChunk)?;
        if crlf_end > buf.len() {
            return Ok(ChunkStep::Incomplete);
        }
        if &buf[data_end..crlf_end] != b"\r\n" {
            return Err(Reject::BadChunk);
        }
        Ok(ChunkStep::Data {
            data_start: next,
            data_end,
            next: crlf_end,
        })
    }

    /// Parse a chunk size: 1..=16 hex digits, no sign / `0x` prefix / other bytes.
    fn parse_chunk_size(bytes: &[u8]) -> Result<u64, Reject> {
        let bytes = trim_ows(bytes); // tolerate trailing OWS before the CRLF
        if bytes.is_empty() || bytes.len() > 16 || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
            return Err(Reject::BadChunk);
        }
        let s = std::str::from_utf8(bytes).map_err(|_| Reject::BadChunk)?;
        u64::from_str_radix(s, 16).map_err(|_| Reject::BadChunk)
    }

    /// Encode one non-terminal chunk: `<hex-size>CRLF<data>CRLF`. `data` must be
    /// non-empty (an empty chunk is the terminator — use [`encode_last`]).
    pub fn encode(data: &[u8]) -> Vec<u8> {
        let mut out = format!("{:x}\r\n", data.len()).into_bytes();
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Encode the terminating chunk: `0CRLF` + the trailer section + the final CRLF.
    pub fn encode_last(trailers: &HeaderMap) -> Vec<u8> {
        let mut out = b"0\r\n".to_vec();
        for (name, value) in trailers.iter() {
            out.extend_from_slice(name.as_str().as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"\r\n");
        out
    }
}
