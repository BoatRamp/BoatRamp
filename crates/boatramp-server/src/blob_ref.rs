//! Cold-start cap-req 10 — zero-copy blob-ref handler responses.
//!
//! A wasm HTTP handler serving a large STORED object (JMAP blob download, CalDAV GET, a mail
//! attachment) would otherwise read the object into the guest and write it back out in 4 KiB
//! `blocking-write-and-flush` chunks (the WASI 0.2 ceiling) — a throughput wall. Instead a
//! handler opts in by returning an EMPTY body plus the header
//! `x-boatramp-blob-ref: <container>/<key>` (its status + content-type set normally); the host
//! then streams that object STRAIGHT from the guest's own blob backend — `sendfile` on a local
//! backend over a plaintext connection, an mmap'd slice on TLS, or a host-side stream on a
//! remote backend — so the bytes never traverse the guest.
//!
//! Security: the referenced object is resolved through the guest's EXACT `wasi:blobstore`
//! confinement ([`BlobBinding::resolve_blob_ref`]) — the host-stamped `hblob/{project-qualified
//! -site}/` prefix, the `blobstore_containers` allowlist / `{tenant}` / multi-tenant deny, and
//! the object-key traversal screen — so a traversal / cross-site / cross-tenant ref is
//! structurally impossible. The blob-ref grants NO new authority: it is only a faster transport
//! to bytes the guest's own `wasi:blobstore` get could already read.

use axum::body::Body;
use axum::http::response::Parts;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use boatramp_core::{Storage, StorageError};
use boatramp_handlers::{BlobBinding, BlobRefDenied};
use std::sync::Arc;

/// The response header a handler sets to request a zero-copy blob-ref body. Value:
/// `<container>/<key>` (the key may contain `/`). Removed before the response leaves the host.
pub(crate) const BLOB_REF_HEADER: &str = "x-boatramp-blob-ref";

/// A single parsed HTTP byte range (single-range only, like the blob-shim).
enum RangeSpec {
    From(u64),
    FromTo(u64, u64),
    Suffix(u64),
}

fn parse_range(value: &str) -> Option<RangeSpec> {
    let spec = value.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None; // single range only
    }
    let (start, end) = spec.split_once('-')?;
    match (start.trim(), end.trim()) {
        ("", "") => None,
        ("", suffix) => Some(RangeSpec::Suffix(suffix.parse().ok()?)),
        (start, "") => Some(RangeSpec::From(start.parse().ok()?)),
        (start, end) => {
            let (s, e): (u64, u64) = (start.parse().ok()?, end.parse().ok()?);
            (s <= e).then_some(RangeSpec::FromTo(s, e))
        }
    }
}

/// Resolve a range against a known total size → `(offset, len)`, or `None` when unsatisfiable.
fn resolve_range(spec: &RangeSpec, total: u64) -> Option<(u64, u64)> {
    match *spec {
        RangeSpec::From(s) if s < total => Some((s, total - s)),
        RangeSpec::FromTo(s, e) if s < total => Some((s, e.min(total - 1) - s + 1)),
        RangeSpec::Suffix(n) if n > 0 => {
            let n = n.min(total);
            Some((total - n, n))
        }
        _ => None,
    }
}

/// A coarse, backend-detail-free refusal (mirrors the blob-shim's discipline — never leak the
/// key or backend metadata to the guest's client).
fn deny(status: StatusCode, msg: &'static str) -> Response {
    (status, format!("{msg}\n")).into_response()
}

/// Swap an (empty-bodied) guest response carrying the blob-ref header for a host-streamed /
/// sendfile body read from the guest's OWN confined blob scope. `parts` is the guest's response
/// head (status + headers, the magic header already removed). Returns the final response, or a
/// fail-closed refusal (403 no-grant / not-permitted, 400 bad ref/key, 404 missing, 416 bad
/// range, 502 backend fault). `scope == None` ⇒ the handler emitted a ref without a
/// `wasi:blobstore` grant → 403.
pub(crate) async fn apply_blob_ref(
    reference: &HeaderValue,
    scope: Option<&BlobBinding>,
    plaintext: bool,
    req_range: Option<&str>,
    is_head: bool,
    parts: Parts,
) -> Response {
    let Some(scope) = scope else {
        tracing::warn!(target: "boatramp::handler", "blob-ref response but the handler holds no wasi:blobstore grant");
        return deny(StatusCode::FORBIDDEN, "blob-ref: no blobstore grant");
    };
    let Ok(reference) = reference.to_str() else {
        return deny(StatusCode::BAD_REQUEST, "blob-ref: non-ascii reference");
    };
    // `<container>/<key>` — the key keeps embedded slashes (matches the shim's `/{container}/{*key}`).
    let Some((container, object)) = reference.split_once('/') else {
        return deny(
            StatusCode::BAD_REQUEST,
            "blob-ref: expected <container>/<key>",
        );
    };
    if object.is_empty() {
        return deny(StatusCode::BAD_REQUEST, "blob-ref: empty key");
    }
    // THE CONFINEMENT GATE: resolve through the guest's exact wasi:blobstore composition.
    let (storage, skey) = match scope.resolve_blob_ref(container, object) {
        Ok(resolved) => resolved,
        Err(BlobRefDenied::NotPermitted(reason)) => {
            tracing::warn!(target: "boatramp::handler", %reason, "blob-ref: container not permitted");
            return deny(StatusCode::FORBIDDEN, "blob-ref: container not permitted");
        }
        Err(BlobRefDenied::BadKey(reason)) => {
            tracing::warn!(target: "boatramp::handler", %reason, "blob-ref: invalid object key");
            return deny(StatusCode::BAD_REQUEST, "blob-ref: invalid key");
        }
        // A null-principal pass bind's own-space is empty ⇒ nothing to serve.
        Err(BlobRefDenied::NullScoped) => {
            return deny(StatusCode::NOT_FOUND, "blob-ref: not found");
        }
    };
    build_blob_response(
        storage.as_ref(),
        &skey,
        parts,
        plaintext,
        req_range,
        is_head,
    )
    .await
}

/// How a (possibly absent) HTTP range resolved against a (possibly unknown) object size.
enum RangeOutcome {
    /// `(offset, len, partial)` — `partial` ⇒ a 206 with a `Content-Range`. `len == None` ⇒ to-end /
    /// unknown size (chunked, no `Content-Length`).
    Resolved(u64, Option<u64>, bool),
    /// The range could not be satisfied against a known total → 416 with `Content-Range: bytes */total`.
    Unsatisfiable(u64),
}

/// Resolve a (single, well-formed) range against a known total. With no range, or an unknown size, the
/// whole object is served (the range is ignored when the size is unknown — matching the prior behavior).
fn resolve_opt_range(spec: Option<&RangeSpec>, total: Option<u64>) -> RangeOutcome {
    match (spec, total) {
        (Some(spec), Some(total)) => match resolve_range(spec, total) {
            Some((o, l)) => RangeOutcome::Resolved(o, Some(l), true),
            None => RangeOutcome::Unsatisfiable(total),
        },
        // No range (or unknown size): the whole object.
        _ => RangeOutcome::Resolved(0, total, false),
    }
}

/// Stamp `Accept-Ranges`/`Content-Length`/`Content-Range` (+ 206 status) onto the guest's response head,
/// overriding any stale `Content-Length` the guest set on its empty body.
fn stamp_range_headers(
    parts: &mut Parts,
    offset: u64,
    len: Option<u64>,
    partial: bool,
    total: Option<u64>,
) {
    if partial {
        parts.status = StatusCode::PARTIAL_CONTENT;
        if let (Some(l), Some(total)) = (len, total) {
            set_header(
                parts,
                header::CONTENT_RANGE,
                &format!("bytes {offset}-{}/{total}", offset + l - 1),
            );
        }
    }
    set_header(parts, header::ACCEPT_RANGES, "bytes");
    if let Some(l) = len {
        set_header(parts, header::CONTENT_LENGTH, &l.to_string());
    } else {
        parts.headers.remove(header::CONTENT_LENGTH);
    }
}

/// 416, keeping the guest's head but stamping the unsatisfiable `Content-Range`.
fn range_not_satisfiable(mut parts: Parts, total: u64) -> Response {
    parts.status = StatusCode::RANGE_NOT_SATISFIABLE;
    set_header(
        &mut parts,
        header::CONTENT_RANGE,
        &format!("bytes */{total}"),
    );
    Response::from_parts(parts, Body::empty())
}

/// Build the response body for the resolved `(storage, key)` — a single-range-aware sendfile / mmap /
/// stream body.
///
/// Ask 3b (kill the redundant per-serve HEAD): a whole-object `GET` derives its size from the `get`
/// itself (the backend returns `Content-Length`), so the common `/img` serve is ONE backend round-trip,
/// not a `HEAD` **then** a `GET`. A `HEAD` is still issued only where it is genuinely needed and cheap:
/// an HTTP `HEAD` request (size without a body), and a **ranged** read on a remote backend (the total is
/// needed up front to resolve a `From`/`Suffix` range and stamp `Content-Range`). Local backends take
/// the size from the file/mapping, never a `HEAD`.
async fn build_blob_response(
    storage: &dyn Storage,
    skey: &str,
    mut parts: Parts,
    plaintext: bool,
    req_range: Option<&str>,
    is_head: bool,
) -> Response {
    let range = req_range.and_then(parse_range);

    // --- Local backend over a plaintext connection → zero-copy sendfile (kernel-to-kernel). Size comes
    // from the open file's metadata — NO `head`. Attach the file as a `SendfileSource` extension on an
    // empty-body response; the `http_serve` bridge turns it into a `Body::File`. ---
    if plaintext && let Some(file) = storage.local_file(skey) {
        let total = file.metadata().ok().map(|m| m.len());
        let (offset, len, partial) = match resolve_opt_range(range.as_ref(), total) {
            RangeOutcome::Resolved(o, l, p) => (o, l, p),
            RangeOutcome::Unsatisfiable(t) => return range_not_satisfiable(parts, t),
        };
        stamp_range_headers(&mut parts, offset, len, partial, total);
        if is_head {
            return Response::from_parts(parts, Body::empty());
        }
        let flen = len.or(total).unwrap_or(0);
        parts
            .extensions
            .insert(crate::serve_pipeline::SendfileSource {
                file: Arc::new(file),
                offset,
                len: flen,
            });
        return Response::from_parts(parts, Body::empty());
    }

    // --- Local backend (TLS, or plaintext without a sendfile handle) → mmap the file and serve the
    // (optionally sliced) borrowed frame. Size from the mapping — NO `head`. `None` ⇒ fall through. ---
    if let Some(bytes) = storage.mapped(skey) {
        let total = Some(bytes.len() as u64);
        let (offset, len, partial) = match resolve_opt_range(range.as_ref(), total) {
            RangeOutcome::Resolved(o, l, p) => (o, l, p),
            RangeOutcome::Unsatisfiable(t) => return range_not_satisfiable(parts, t),
        };
        stamp_range_headers(&mut parts, offset, len, partial, total);
        if is_head {
            return Response::from_parts(parts, Body::empty());
        }
        let body = if partial {
            let start = offset as usize;
            let end = len.map_or(bytes.len(), |l| (start + l as usize).min(bytes.len()));
            bytes.slice(start.min(bytes.len())..end)
        } else {
            bytes
        };
        return Response::from_parts(parts, Body::from(body));
    }

    // --- Remote / opaque backend. ---
    // A `HEAD` request, or a RANGED read, needs the size up front — the one place a `head` is still
    // issued (and the right primitive: a `HEAD` request wants no body; a range needs the total to
    // resolve `From`/`Suffix` and stamp `Content-Range`). A whole-object `GET` skips it: the `get`
    // itself carries `Content-Length`.
    if is_head || range.is_some() {
        let total: Option<u64> = match storage.head(skey).await {
            Ok(meta) => meta.size,
            Err(StorageError::NotFound(_)) => {
                return deny(StatusCode::NOT_FOUND, "blob-ref: not found");
            }
            Err(err) => {
                tracing::warn!(target: "boatramp::handler", error = %err, "blob-ref: backend head fault");
                return deny(StatusCode::BAD_GATEWAY, "blob-ref: backend unavailable");
            }
        };
        let (offset, len, partial) = match resolve_opt_range(range.as_ref(), total) {
            RangeOutcome::Resolved(o, l, p) => (o, l, p),
            RangeOutcome::Unsatisfiable(t) => return range_not_satisfiable(parts, t),
        };
        stamp_range_headers(&mut parts, offset, len, partial, total);
        if is_head {
            return Response::from_parts(parts, Body::empty());
        }
        // A ranged GET (whole-object GET falls through to the no-head path below).
        return match storage.get_range(skey, offset, len).await {
            Ok(obj) => Response::from_parts(parts, Body::from_stream(obj.body)),
            Err(StorageError::NotFound(_)) => deny(StatusCode::NOT_FOUND, "blob-ref: not found"),
            Err(err) => {
                tracing::warn!(target: "boatramp::handler", error = %err, "blob-ref: backend read fault");
                deny(StatusCode::BAD_GATEWAY, "blob-ref: backend unavailable")
            }
        };
    }

    // --- Whole-object GET on a remote backend → ONE host-side stream straight from the backend, its
    // `Content-Length` taken from the `get` response (NO preceding `head`). ---
    match storage.get(skey).await {
        Ok(obj) => {
            let size = obj.meta.size;
            stamp_range_headers(&mut parts, 0, size, false, size);
            Response::from_parts(parts, Body::from_stream(obj.body))
        }
        Err(StorageError::NotFound(_)) => deny(StatusCode::NOT_FOUND, "blob-ref: not found"),
        Err(err) => {
            tracing::warn!(target: "boatramp::handler", error = %err, "blob-ref: backend read fault");
            deny(StatusCode::BAD_GATEWAY, "blob-ref: backend unavailable")
        }
    }
}

fn set_header(parts: &mut Parts, name: header::HeaderName, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        parts.headers.insert(name, v);
    }
}

#[cfg(all(test, feature = "handlers"))]
mod tests {
    //! Cap-req 10 body/range/missing/head legs. Confinement (`resolve_blob_ref`) is proven in
    //! `boatramp-handlers::bindings::blobstore` tests; here we drive `build_blob_response` directly
    //! against a precise in-memory backend (accurate `head`/`get_range`, optional local file).
    use super::*;
    use boatramp_core::{ByteStream, GetObject, ObjectMeta};
    use bytes::Bytes;
    use futures::StreamExt as _;

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A one-object backend with ACCURATE size + range slicing, and an optional backing temp
    /// file so the sendfile (local+plaintext) leg is exercisable. Counts `head`/`get`/`get_range`
    /// so a test can prove a whole-object GET issues NO redundant `head` (Ask 3b).
    struct MemBlob {
        key: String,
        bytes: Vec<u8>,
        local: Option<Arc<std::path::PathBuf>>, // present ⇒ `local_file` returns an open handle
        heads: AtomicUsize,
        gets: AtomicUsize,
        ranges: AtomicUsize,
    }

    impl MemBlob {
        fn remote(key: &str, bytes: &[u8]) -> Self {
            Self {
                key: key.into(),
                bytes: bytes.to_vec(),
                local: None,
                heads: AtomicUsize::new(0),
                gets: AtomicUsize::new(0),
                ranges: AtomicUsize::new(0),
            }
        }
        fn local(key: &str, bytes: &[u8]) -> Self {
            let dir = std::env::temp_dir().join(format!("br-blobref-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("obj.bin");
            std::fs::write(&path, bytes).unwrap();
            Self {
                key: key.into(),
                bytes: bytes.to_vec(),
                local: Some(Arc::new(path)),
                heads: AtomicUsize::new(0),
                gets: AtomicUsize::new(0),
                ranges: AtomicUsize::new(0),
            }
        }
        fn hit(&self, key: &str) -> bool {
            key == self.key
        }
    }

    #[async_trait::async_trait]
    impl Storage for MemBlob {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            if !self.hit(key) {
                return Err(StorageError::NotFound(key.into()));
            }
            let b = Bytes::from(self.bytes.clone());
            Ok(GetObject {
                meta: ObjectMeta {
                    key: key.into(),
                    size: Some(self.bytes.len() as u64),
                    ..Default::default()
                },
                body: (futures::stream::once(async move { Ok::<_, StorageError>(b) }).boxed())
                    as ByteStream,
            })
        }
        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            self.ranges.fetch_add(1, Ordering::SeqCst);
            if !self.hit(key) {
                return Err(StorageError::NotFound(key.into()));
            }
            let start = offset as usize;
            let end = len.map_or(self.bytes.len(), |l| {
                (start + l as usize).min(self.bytes.len())
            });
            let slice = Bytes::from(self.bytes[start.min(self.bytes.len())..end].to_vec());
            let n = slice.len() as u64;
            Ok(GetObject {
                meta: ObjectMeta {
                    key: key.into(),
                    size: Some(n),
                    ..Default::default()
                },
                body: (futures::stream::once(async move { Ok::<_, StorageError>(slice) }).boxed())
                    as ByteStream,
            })
        }
        async fn put(
            &self,
            _: &str,
            _: ByteStream,
            _: boatramp_core::PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            unimplemented!()
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            self.heads.fetch_add(1, Ordering::SeqCst);
            if !self.hit(key) {
                return Err(StorageError::NotFound(key.into()));
            }
            Ok(ObjectMeta {
                key: key.into(),
                size: Some(self.bytes.len() as u64),
                ..Default::default()
            })
        }
        async fn delete(&self, _: &str) -> Result<(), StorageError> {
            Ok(())
        }
        async fn list(&self, _: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(vec![])
        }
        fn local_file(&self, key: &str) -> Option<std::fs::File> {
            if self.hit(key) {
                self.local
                    .as_ref()
                    .and_then(|p| std::fs::File::open(p.as_path()).ok())
            } else {
                None
            }
        }
    }

    fn parts() -> Parts {
        axum::http::Response::new(()).into_parts().0 // default 200 + empty headers
    }

    async fn body_bytes(resp: Response) -> Vec<u8> {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec()
    }

    #[tokio::test]
    async fn remote_whole_object_streams_with_content_length() {
        let s = MemBlob::remote("hblob/default/api/assets/big.bin", b"hello world payload");
        let resp = build_blob_response(
            &s,
            "hblob/default/api/assets/big.bin",
            parts(),
            false,
            None,
            false,
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "19");
        assert_eq!(body_bytes(resp).await, b"hello world payload");
    }

    /// Ask 3b: a whole-object GET serve issues the GET and NO redundant `head` — the content-length
    /// comes from the GET itself. Before the fix this path was a serial `head` **then** `get`.
    #[tokio::test]
    async fn whole_object_get_issues_no_redundant_head() {
        let s = MemBlob::remote("k", b"0123456789");
        let resp = build_blob_response(&s, "k", parts(), false, None, false).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "10");
        assert_eq!(body_bytes(resp).await, b"0123456789");
        assert_eq!(
            s.heads.load(Ordering::SeqCst),
            0,
            "no redundant HEAD on a whole-object GET"
        );
        assert_eq!(s.gets.load(Ordering::SeqCst), 1, "exactly one GET");
        assert_eq!(s.ranges.load(Ordering::SeqCst), 0);
    }

    /// A ranged remote read still issues ONE `head` (the total is needed to resolve the range and stamp
    /// `Content-Range`) then ONE `get_range` — and an HTTP HEAD request issues ONE `head` and no body.
    #[tokio::test]
    async fn ranged_and_head_still_use_head() {
        let s = MemBlob::remote("k", b"0123456789");
        let resp = build_blob_response(&s, "k", parts(), false, Some("bytes=2-4"), false).await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(body_bytes(resp).await, b"234");
        assert_eq!(
            s.heads.load(Ordering::SeqCst),
            1,
            "ranged read needs the total"
        );
        assert_eq!(s.ranges.load(Ordering::SeqCst), 1);
        assert_eq!(s.gets.load(Ordering::SeqCst), 0);

        let h = MemBlob::remote("k", b"0123456789");
        let resp = build_blob_response(&h, "k", parts(), false, None, true).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "10");
        assert!(body_bytes(resp).await.is_empty(), "HEAD carries no body");
        assert_eq!(
            h.heads.load(Ordering::SeqCst),
            1,
            "HEAD request uses head, not get"
        );
        assert_eq!(
            h.gets.load(Ordering::SeqCst),
            0,
            "HEAD must not download the body"
        );
    }

    #[tokio::test]
    async fn remote_range_is_206_with_content_range_and_slice() {
        let s = MemBlob::remote("k", b"0123456789");
        let resp = build_blob_response(&s, "k", parts(), false, Some("bytes=2-4"), false).await;
        assert_eq!(resp.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            resp.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes 2-4/10"
        );
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "3");
        assert_eq!(body_bytes(resp).await, b"234");
    }

    #[tokio::test]
    async fn unsatisfiable_range_is_416() {
        let s = MemBlob::remote("k", b"0123456789");
        let resp = build_blob_response(&s, "k", parts(), false, Some("bytes=50-60"), false).await;
        assert_eq!(resp.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(
            resp.headers().get(header::CONTENT_RANGE).unwrap(),
            "bytes */10"
        );
    }

    #[tokio::test]
    async fn missing_object_is_404() {
        let s = MemBlob::remote("present", b"x");
        let resp = build_blob_response(&s, "absent", parts(), false, None, false).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn head_has_length_and_empty_body() {
        let s = MemBlob::remote("k", b"0123456789");
        let resp = build_blob_response(&s, "k", parts(), false, None, true).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "10");
        assert!(body_bytes(resp).await.is_empty(), "HEAD carries no body");
    }

    #[tokio::test]
    async fn local_plaintext_attaches_sendfile_source() {
        let s = MemBlob::local("k", b"0123456789");
        let resp = build_blob_response(&s, "k", parts(), true, None, false).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get(header::CONTENT_LENGTH).unwrap(), "10");
        let src = resp
            .extensions()
            .get::<crate::serve_pipeline::SendfileSource>()
            .expect("sendfile source attached on local+plaintext");
        assert_eq!(src.len, 10);
        assert_eq!(src.offset, 0);
        assert!(
            body_bytes(resp).await.is_empty(),
            "sendfile uses an empty body + the extension"
        );
    }
}
