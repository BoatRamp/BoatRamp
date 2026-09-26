//! The local S3 **request engine** (PLAN §4 operations, §5 storage mapping, §6 create-only, §CORS).
//!
//! [`handle`] is the single entry: it takes a parsed [`S3Request`] + the face [`S3IngressState`],
//! authenticates (via [`super::auth`]), authorizes the concrete operation, and dispatches to one of:
//! `PutObject` (single-shot), the multipart quartet (Create/UploadPart/Complete/Abort), `HeadObject`,
//! or an `OPTIONS` CORS preflight. Every object write goes through the [`super::keypath`] choke point,
//! so a key can never escape the scoped prefix. Bodies stream (never buffered whole).
//!
//! Auth failures ALL map to one uniform 403 via [`super::error::refuse`] (INFO-3 no-oracle);
//! constraint results (too-big, sha256 mismatch, overwrite, quota) surface their specific greppable
//! S3 `<Code>` — those are honest results of an authenticated request, not an auth oracle.

use axum::body::Body;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use boatramp_core::cose::S3Session;
use boatramp_core::{ByteStream, PutMeta, StorageError};
use futures::StreamExt as _;
use sha2::{Digest, Sha256};

use super::auth::{self, S3AuthInput, S3Op};
use super::config::S3IngressState;
use super::error::{S3Error, S3ErrorCode, refuse};
use super::keypath;
use super::multipart::{self, MultipartError};

/// A fully-parsed S3 request the face acts on. The axum listener builds this from the live request
/// (raw path/query/headers + streaming body); tests build it directly, so the engine is exercised
/// without a socket.
pub struct S3Request {
    /// HTTP method, upper-case.
    pub method: String,
    /// The RAW (percent-encoded) URI path — `/{bucket}/{key…}`.
    pub uri_path: String,
    /// The RAW query string (no `?`); empty if none.
    pub query: String,
    /// Headers as `(lowercase-name, value)`.
    pub headers: Vec<(String, String)>,
    /// The streaming request body (present for PUT/POST; empty otherwise).
    pub body: Body,
}

/// The bucket + object-key split from the path, plus the parsed query intent.
struct Route {
    bucket: String,
    /// The raw (wire) object key — everything after `/{bucket}/`. May be empty (bucket-level).
    raw_key: String,
    intent: Intent,
}

/// What the method + query say the request wants.
enum Intent {
    /// `PUT /{b}/{k}` with no multipart query — single-shot PutObject.
    PutObject,
    /// `POST /{b}/{k}?uploads` — CreateMultipartUpload.
    CreateMultipart,
    /// `PUT /{b}/{k}?partNumber=N&uploadId=U` — UploadPart.
    UploadPart { part_number: u32, upload_id: String },
    /// `POST /{b}/{k}?uploadId=U` — CompleteMultipartUpload.
    CompleteMultipart { upload_id: String },
    /// `DELETE /{b}/{k}?uploadId=U` — AbortMultipartUpload.
    AbortMultipart { upload_id: String },
    /// `HEAD /{b}/{k}` — HeadObject.
    Head,
    /// `OPTIONS /{b}/{k}` — CORS preflight.
    Options,
    /// Anything else — not implemented (405).
    Unsupported,
}

/// Handle one S3 request end-to-end. Returns the HTTP [`Response`] (S3-shaped body).
pub async fn handle(state: &S3IngressState, req: S3Request, now_unix: i64) -> Response {
    let Some(route) = parse_route(&req) else {
        return S3Error::new(S3ErrorCode::MethodNotAllowed, "unsupported S3 request")
            .into_response();
    };

    // OPTIONS preflight is answered BEFORE auth (a browser preflight carries no credentials) — but it
    // only ever echoes an ALLOWED origin, never `*`, never an arbitrary reflected origin.
    if matches!(route.intent, Intent::Options) {
        return cors_preflight(state, &req.headers, &route.bucket);
    }

    // Authenticate (SigV4 + session token + SignedHeaders policy + trailer rejection + skew/expiry).
    let content_sha256 = header_val(&req.headers, "x-amz-content-sha256");
    let authorization = header_val(&req.headers, "authorization");
    let amz_date = header_val(&req.headers, "x-amz-date");
    let session_token = header_val(&req.headers, "x-amz-security-token");
    let presigned_params = super::listener::decoded_query_params(&req.query);
    let input = S3AuthInput {
        method: &req.method,
        uri_path: &req.uri_path,
        query: &req.query,
        headers: &req.headers,
        authorization,
        amz_date,
        content_sha256,
        session_token,
        presigned_params: &presigned_params,
    };
    let authed = match auth::authenticate(&input, &state.public_key, &state.secret, now_unix) {
        Ok(a) => a,
        Err(reason) => return refuse(&reason),
    };

    // Opt-in revocation (async KV lookup) — fail-closed.
    if state.revocation_enabled
        && let Err(reason) =
            auth::check_revocation(state.deploy.kv().as_ref(), &authed.session.cti).await
    {
        return refuse(&reason);
    }

    let session = authed.session;
    // Destructure the route so the intent's owned fields don't conflict with borrowing bucket/raw_key.
    let Route {
        bucket,
        raw_key,
        intent,
    } = route;

    // Map the intent to the permission it requires + dispatch.
    match intent {
        Intent::PutObject => {
            put_object(state, &session, &bucket, &raw_key, req.headers, req.body).await
        }
        Intent::CreateMultipart => create_multipart(state, &session, &bucket, &raw_key),
        Intent::UploadPart {
            part_number,
            upload_id,
        } => {
            upload_part(
                state,
                &session,
                &bucket,
                &raw_key,
                &upload_id,
                part_number,
                req.body,
            )
            .await
        }
        Intent::CompleteMultipart { upload_id } => {
            complete_multipart(state, &session, &bucket, &raw_key, &upload_id, req.body).await
        }
        Intent::AbortMultipart { upload_id } => {
            abort_multipart(state, &session, &bucket, &raw_key, &upload_id).await
        }
        Intent::Head => head_object(state, &session, &bucket, &raw_key).await,
        Intent::Options => unreachable!("OPTIONS handled before auth"),
        Intent::Unsupported => {
            S3Error::new(S3ErrorCode::MethodNotAllowed, "unsupported S3 operation").into_response()
        }
    }
}

// ---- operations -----------------------------------------------------------------------------

/// `PUT /{bucket}/{key}` — single-shot PutObject. Streams the body into the final key with, in order:
/// scope authorization, key composition (choke point), content-type constraint, create-only
/// precondition, size cap, and content-addressing verification.
async fn put_object(
    state: &S3IngressState,
    session: &S3Session,
    bucket: &str,
    raw_key: &str,
    headers: Vec<(String, String)>,
    body: Body,
) -> Response {
    // Scope: bucket = container, op = Put. Compose the key at the choke point.
    let (decoded_key, storage_key) =
        match authorize_and_compose(session, bucket, raw_key, S3Op::PutObject) {
            Ok(v) => v,
            Err(resp) => return resp,
        };

    // Content-Type constraint (fail-closed at the local face).
    if let Some(resp) = check_content_type(session, &headers) {
        return resp;
    }

    // Concurrency + Content-Length early reject (DoS caps, reused from the control-plane guard).
    let content_length = header_val(&headers, "content-length").and_then(|v| v.parse::<u64>().ok());
    if let Some(resp) = check_size_precondition(state, session, bucket, content_length) {
        return resp;
    }
    let Some(_permit) = state.guard.try_acquire() else {
        return S3Error::new(
            S3ErrorCode::BoatrampQuotaExceeded,
            "too many concurrent uploads",
        )
        .into_response();
    };

    // Create-only precondition: a create-only credential (UGC default) refuses to overwrite an
    // existing key. Overwrite is only safe for content-addressed keys (same bytes ⇒ same key), so a
    // require_sha256 credential skips this (idempotent replay is a no-op).
    if session.scope.constraints.create_only
        && !session.scope.constraints.require_sha256
        && object_exists(state, &storage_key).await
    {
        return S3Error::new(
            S3ErrorCode::BoatrampOverwriteDenied,
            "object already exists (create-only credential)",
        )
        .into_response();
    }

    // Stream the body into the final key, verifying content-addressing as-streamed if required.
    let require_hash = session.scope.constraints.require_sha256.then(|| {
        decoded_key
            .rsplit('/')
            .next()
            .unwrap_or(&decoded_key)
            .to_string()
    });
    match stream_put(state, &storage_key, body, session, require_hash.as_deref()).await {
        Ok(()) => ok_empty(),
        Err(resp) => resp,
    }
}

/// `POST /{bucket}/{key}?uploads` — CreateMultipartUpload → an `<UploadId>`.
fn create_multipart(
    state: &S3IngressState,
    session: &S3Session,
    bucket: &str,
    raw_key: &str,
) -> Response {
    // Authorize (multipart perm) + compose (screens the key) — we don't write yet, but screening the
    // key here fails a scope-escape early.
    if let Err(resp) = authorize_and_compose(session, bucket, raw_key, S3Op::Multipart) {
        return resp;
    }
    let upload_id = match multipart::new_upload_id(&session.scope) {
        Ok(id) => id,
        Err(_) => {
            return S3Error::new(
                S3ErrorCode::InternalError,
                "could not begin multipart upload",
            )
            .into_response();
        }
    };
    let _ = state; // reserved for future per-upload staging bookkeeping
    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <InitiateMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId>\
         </InitiateMultipartUploadResult>",
        xml_text(bucket),
        xml_text(raw_key),
        xml_text(&upload_id),
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        xml,
    )
        .into_response()
}

/// `PUT /{bucket}/{key}?partNumber=N&uploadId=U` — UploadPart → an `ETag`. Re-verifies the uploadId's
/// scope binding, then streams the part into staging.
async fn upload_part(
    state: &S3IngressState,
    session: &S3Session,
    bucket: &str,
    raw_key: &str,
    upload_id: &str,
    part_number: u32,
    body: Body,
) -> Response {
    if let Err(resp) = authorize_and_compose(session, bucket, raw_key, S3Op::Multipart) {
        return resp;
    }
    // Re-verify: the uploadId must have been issued for THIS request's scope (never trust the id).
    if let Err(e) = multipart::verify_upload_id(upload_id, &session.scope) {
        return multipart_err(e);
    }
    if let Err(e) = multipart::validate_part_number(part_number) {
        return multipart_err(e);
    }
    // Concurrency cap applies to each part too (the per-stream size cap is applied by `guarded_stream`).
    let Some(_permit) = state.guard.try_acquire() else {
        return S3Error::new(
            S3ErrorCode::BoatrampQuotaExceeded,
            "too many concurrent uploads",
        )
        .into_response();
    };
    let stream = guarded_stream(state, body);
    match multipart::stage_part(
        state.deploy.storage(),
        &session.scope,
        upload_id,
        part_number,
        stream,
    )
    .await
    {
        Ok(etag) => (StatusCode::OK, [(header::ETAG, format!("\"{etag}\""))], ()).into_response(),
        Err(_) => S3Error::new(S3ErrorCode::InternalError, "staging a part failed").into_response(),
    }
}

/// `POST /{bucket}/{key}?uploadId=U` — CompleteMultipartUpload. Parses the XML part list, assembles
/// all-or-nothing into the final key, then GCs the staging.
async fn complete_multipart(
    state: &S3IngressState,
    session: &S3Session,
    bucket: &str,
    raw_key: &str,
    upload_id: &str,
    body: Body,
) -> Response {
    let (decoded_key, storage_key) =
        match authorize_and_compose(session, bucket, raw_key, S3Op::Multipart) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
    if let Err(e) = multipart::verify_upload_id(upload_id, &session.scope) {
        return multipart_err(e);
    }
    // Parse the completion part list (bounded read of the small XML body).
    let bytes = match read_bounded(body, MAX_COMPLETE_XML_BYTES).await {
        Ok(b) => b,
        Err(resp) => return resp,
    };
    let parts = match parse_complete_part_numbers(&bytes) {
        Some(p) if !p.is_empty() => p,
        _ => {
            return S3Error::new(S3ErrorCode::BoatrampMultipartInvalid, "invalid part list")
                .into_response();
        }
    };

    // Create-only precondition on the final key (a content-addressed credential is exempt — idempotent).
    if session.scope.constraints.create_only
        && !session.scope.constraints.require_sha256
        && object_exists(state, &storage_key).await
    {
        return S3Error::new(
            S3ErrorCode::BoatrampOverwriteDenied,
            "object already exists (create-only credential)",
        )
        .into_response();
    }

    let require_hash = session.scope.constraints.require_sha256.then(|| {
        decoded_key
            .rsplit('/')
            .next()
            .unwrap_or(&decoded_key)
            .to_string()
    });
    match multipart::assemble(
        state.deploy.storage(),
        &session.scope,
        upload_id,
        &parts,
        &storage_key,
        require_hash.as_deref(),
    )
    .await
    {
        Ok(()) => {
            // GC the staging on success (idempotent).
            let _ = multipart::abort(state.deploy.storage(), &session.scope, upload_id).await;
            let etag = "\"boatramp-multipart\"";
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
                 <CompleteMultipartUploadResult><Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag>\
                 </CompleteMultipartUploadResult>",
                xml_text(bucket),
                xml_text(raw_key),
                etag,
            );
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/xml")],
                xml,
            )
                .into_response()
        }
        Err(MultipartError::BadPartList) => S3Error::new(
            S3ErrorCode::BoatrampMultipartInvalid,
            "part assembly failed",
        )
        .into_response(),
        Err(e) => multipart_err(e),
    }
}

/// `DELETE /{bucket}/{key}?uploadId=U` — AbortMultipartUpload. Drops the staging (idempotent). The
/// ONLY DELETE the external face implements — never deletes a committed object.
async fn abort_multipart(
    state: &S3IngressState,
    session: &S3Session,
    bucket: &str,
    raw_key: &str,
    upload_id: &str,
) -> Response {
    if let Err(resp) = authorize_and_compose(session, bucket, raw_key, S3Op::Multipart) {
        return resp;
    }
    if let Err(e) = multipart::verify_upload_id(upload_id, &session.scope) {
        return multipart_err(e);
    }
    match multipart::abort(state.deploy.storage(), &session.scope, upload_id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => S3Error::new(S3ErrorCode::InternalError, "abort failed").into_response(),
    }
}

/// `HEAD /{bucket}/{key}` — HeadObject (the create-only precondition probe). Scope-confined like every
/// op; returns 200 with a size header if present, 404 otherwise. Returns NO body (HEAD).
async fn head_object(
    state: &S3IngressState,
    session: &S3Session,
    bucket: &str,
    raw_key: &str,
) -> Response {
    let (_decoded, storage_key) = match authorize_and_compose(session, bucket, raw_key, S3Op::Head)
    {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    match state.deploy.storage().head(&storage_key).await {
        Ok(meta) => {
            let mut headers = HeaderMap::new();
            if let Some(size) = meta.size
                && let Ok(v) = header::HeaderValue::from_str(&size.to_string())
            {
                headers.insert(header::CONTENT_LENGTH, v);
            }
            (StatusCode::OK, headers).into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// ---- CORS -----------------------------------------------------------------------------------

/// Answer a CORS preflight (`OPTIONS`): echo the request `Origin` ONLY if it is in the container's
/// allow-list — never `*`, never an arbitrary reflected origin (UX P3). An origin not in the list gets
/// a bare 403 (no CORS headers), so the browser blocks the cross-origin call.
fn cors_preflight(state: &S3IngressState, headers: &[(String, String)], bucket: &str) -> Response {
    let origin = header_val(headers, "origin").unwrap_or("");
    // We can't know the credential's project/site here (preflight is unauthenticated), so CORS is
    // keyed to the container name across configured (project, site): we echo `origin` only if SOME
    // configured policy for this container name allows it — never `*`, never an arbitrary reflected
    // origin.
    if origin.is_empty() || !state.cors_allows(bucket, origin) {
        // No CORS headers ⇒ the browser will not expose the response (correct fail-closed for a
        // disallowed origin). Return 403 without echoing anything.
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut headers = HeaderMap::new();
    insert(&mut headers, header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
    insert(
        &mut headers,
        header::ACCESS_CONTROL_ALLOW_METHODS,
        "PUT, POST, DELETE, HEAD",
    );
    insert(
        &mut headers,
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        "authorization,x-amz-date,x-amz-content-sha256,x-amz-security-token,content-type,content-length",
    );
    insert(&mut headers, header::VARY, "Origin");
    (StatusCode::NO_CONTENT, headers).into_response()
}

// ---- shared helpers -------------------------------------------------------------------------

/// The largest CompleteMultipartUpload XML body the face reads (bounded so a hostile client can't force
/// unbounded buffering — the part list is small).
const MAX_COMPLETE_XML_BYTES: usize = 1024 * 1024;

/// Authorize the operation against the scope AND compose the final storage key at the choke point. A
/// scope refusal maps to the uniform 403; a key-escape maps to `BoatrampScopeEscape`; an operation
/// outside the perms maps to `BoatrampOperationNotPermitted`.
fn authorize_and_compose(
    session: &S3Session,
    bucket: &str,
    raw_key: &str,
    op: S3Op,
) -> Result<(String, String), Response> {
    // Compose FIRST so a malformed/escaping key is rejected as a scope escape (not leaked as an auth
    // oracle — a key escape is a client error, distinct from an authentication failure).
    let (decoded_key, storage_key) =
        keypath::compose_object_key(&session.scope.project, &session.scope.site, bucket, raw_key)
            .map_err(|e| {
            S3Error::new(S3ErrorCode::BoatrampScopeEscape, e.to_string()).into_response()
        })?;
    // Then authorize the concrete op against the signed scope. A container/key/perm mismatch is a
    // uniform refusal (no oracle) EXCEPT the perm case, which is an authenticated-but-not-permitted
    // result (the credential is valid; it just wasn't granted this op).
    match auth::authorize_operation(session, bucket, &decoded_key, op) {
        Ok(()) => Ok((decoded_key, storage_key)),
        Err(reason) if reason.contains("not in scope perms") => Err(S3Error::new(
            S3ErrorCode::BoatrampOperationNotPermitted,
            "operation not permitted for this credential",
        )
        .into_response()),
        Err(reason) => Err(refuse(&reason)),
    }
}

/// Enforce the credential's `content_type` constraint (fail-closed): the request `Content-Type` must
/// match exactly, or match a `type/*` family. Absent constraint ⇒ any type.
fn check_content_type(session: &S3Session, headers: &[(String, String)]) -> Option<Response> {
    let required = session.scope.constraints.content_type.as_deref()?;
    let actual = header_val(headers, "content-type").unwrap_or("");
    let ok = if let Some(family) = required.strip_suffix("/*") {
        actual
            .split_once('/')
            .map(|(t, _)| t == family)
            .unwrap_or(false)
    } else {
        actual == required
    };
    (!ok).then(|| {
        S3Error::new(
            S3ErrorCode::BoatrampContentTypeRejected,
            "Content-Type not permitted by the credential",
        )
        .into_response()
    })
}

/// Early size precondition: reject on a declared Content-Length that already exceeds the credential's
/// `max_bytes` OR the per-container ceiling (whichever is tighter). The streaming cap
/// ([`guarded_stream`]) is the backstop for an undeclared/lying length.
fn check_size_precondition(
    state: &S3IngressState,
    session: &S3Session,
    container: &str,
    content_length: Option<u64>,
) -> Option<Response> {
    let policy = state.container_policy(&session.scope.project, &session.scope.site, container);
    let ceiling = tightest(session.scope.constraints.max_bytes, policy.max_object_bytes);
    if let (Some(max), Some(len)) = (ceiling, content_length)
        && len > max
    {
        return Some(
            S3Error::new(
                S3ErrorCode::BoatrampSizeExceeded,
                "object exceeds the size limit",
            )
            .into_response(),
        );
    }
    None
}

/// The tighter of two optional caps.
fn tightest(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

/// Stream a PUT body into `storage_key`, applying the `UploadGuard` size/idle cap and, when
/// `require_hash` is `Some`, verifying the streamed bytes hash to that content-address (else delete +
/// reject; no committed partial). On any stream error the object is deleted.
async fn stream_put(
    state: &S3IngressState,
    storage_key: &str,
    body: Body,
    session: &S3Session,
    require_hash: Option<&str>,
) -> Result<(), Response> {
    let guarded = guarded_stream(state, body);
    // Cap the stream to the tightest of the credential's max_bytes and the container ceiling (the
    // guard's own max_upload_bytes is a coarser server-wide backstop).
    let hasher = require_hash.map(|_| std::sync::Arc::new(std::sync::Mutex::new(Sha256::new())));
    let hasher_tap = hasher.clone();
    let tapped: ByteStream = guarded
        .map(move |chunk| {
            if let (Ok(bytes), Some(h)) = (&chunk, &hasher_tap) {
                h.lock().unwrap().update(bytes);
            }
            chunk
        })
        .boxed();

    match state
        .deploy
        .storage()
        .put(storage_key, tapped, PutMeta::default())
        .await
    {
        Ok(_) => {}
        Err(StorageError::Backend(msg)) if msg.contains("limit") => {
            let _ = state.deploy.storage().delete(storage_key).await;
            return Err(S3Error::new(
                S3ErrorCode::BoatrampSizeExceeded,
                "object exceeds the size limit",
            )
            .into_response());
        }
        Err(_) => {
            let _ = state.deploy.storage().delete(storage_key).await;
            return Err(S3Error::new(S3ErrorCode::InternalError, "storage error").into_response());
        }
    }

    if let (Some(expected), Some(h)) = (require_hash, hasher) {
        let actual = hex::encode(h.lock().unwrap().clone().finalize());
        if actual != expected {
            let _ = state.deploy.storage().delete(storage_key).await;
            return Err(S3Error::new(
                S3ErrorCode::BoatrampSha256Mismatch,
                "object bytes do not match the content-addressed key",
            )
            .into_response());
        }
    }
    let _ = session; // (per-container blob-change notification is a wiring concern; see listener)
    Ok(())
}

/// Wrap a body as a size/idle-capped [`ByteStream`] via the shared `UploadGuard`.
fn guarded_stream(state: &S3IngressState, body: Body) -> ByteStream {
    let stream = body
        .into_data_stream()
        .map(|chunk| chunk.map_err(|e| StorageError::backend(e.to_string())))
        .boxed();
    state.guard.limit_body(stream)
}

/// Whether an object exists at `storage_key` (the create-only precondition probe).
async fn object_exists(state: &S3IngressState, storage_key: &str) -> bool {
    state.deploy.storage().head(storage_key).await.is_ok()
}

/// Read a bounded body fully into memory (for the small multipart-complete XML). Rejects an oversize
/// body rather than buffering unbounded.
async fn read_bounded(body: Body, max: usize) -> Result<Vec<u8>, Response> {
    match axum::body::to_bytes(body, max).await {
        Ok(b) => Ok(b.to_vec()),
        Err(_) => Err(S3Error::new(
            S3ErrorCode::MalformedRequest,
            "request body too large or unreadable",
        )
        .into_response()),
    }
}

/// A 200 with an empty body (S3 PutObject success). S3 clients accept a 200 with an ETag; the ETag is
/// optional here (we do not need to return it for the ingress use case).
fn ok_empty() -> Response {
    StatusCode::OK.into_response()
}

/// Map a [`MultipartError`] to its greppable S3 code (scope-mismatch collapses to the uniform refusal —
/// it is an authorization failure, not a client-shape error).
fn multipart_err(e: MultipartError) -> Response {
    match e {
        MultipartError::ScopeMismatch => refuse("uploadId scope mismatch"),
        MultipartError::MalformedUploadId
        | MultipartError::BadPartNumber
        | MultipartError::BadPartList => {
            S3Error::new(S3ErrorCode::BoatrampMultipartInvalid, e.to_string()).into_response()
        }
        MultipartError::Rng => {
            S3Error::new(S3ErrorCode::InternalError, "internal error").into_response()
        }
    }
}

/// Look up a header value by lowercase name.
fn header_val<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// Insert a static header value, ignoring an invalid-value error (the inputs are our own constants /
/// an allow-listed origin, so this never fails in practice).
fn insert(headers: &mut HeaderMap, name: header::HeaderName, value: &str) {
    if let Ok(v) = header::HeaderValue::from_str(value) {
        headers.insert(name, v);
    }
}

/// Minimal XML text escaping for values embedded in a result document.
fn xml_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

/// Extract the `<PartNumber>` values from a CompleteMultipartUpload XML body, in document order — a
/// tiny, dependency-free, fail-closed scan (there is no XML crate in-tree, and the body shape is
/// fixed). Bounded by the caller's [`read_bounded`]. Returns `None` on a body with no part numbers.
/// It only reads part NUMBERS (the ETags are advisory for the ingress use case — the staged parts are
/// the authority, keyed by number).
fn parse_complete_part_numbers(body: &[u8]) -> Option<Vec<u32>> {
    let text = std::str::from_utf8(body).ok()?;
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("<PartNumber>") {
        let after = &rest[open + "<PartNumber>".len()..];
        let close = after.find("</PartNumber>")?;
        let num_str = after[..close].trim();
        let n: u32 = num_str.parse().ok()?;
        out.push(n);
        rest = &after[close + "</PartNumber>".len()..];
        // Bound the count defensively (a body claiming more parts than the max is malformed).
        if out.len() > super::config::MAX_PARTS_PER_UPLOAD as usize {
            return None;
        }
    }
    (!out.is_empty()).then_some(out)
}

// ---- routing --------------------------------------------------------------------------------

/// Parse the request path + method + query into a [`Route`]. Path-style: `/{bucket}/{key…}`. The
/// bucket is the first segment; the raw key is everything after (may contain `/`). The query decides
/// the multipart intent.
fn parse_route(req: &S3Request) -> Option<Route> {
    let path = req.uri_path.trim_start_matches('/');
    let (bucket, raw_key) = match path.split_once('/') {
        Some((b, k)) => (b.to_string(), k.to_string()),
        None => (path.to_string(), String::new()),
    };
    if bucket.is_empty() {
        return None;
    }
    let params = super::listener::decoded_query_params(&req.query);
    let has = |name: &str| params.iter().any(|(k, _)| k == name);
    let get = |name: &str| {
        params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };

    let intent = match req.method.as_str() {
        "OPTIONS" => Intent::Options,
        "HEAD" => Intent::Head,
        "POST" if has("uploads") => Intent::CreateMultipart,
        "POST" if get("uploadId").is_some() => Intent::CompleteMultipart {
            upload_id: get("uploadId").unwrap(),
        },
        "PUT" if get("uploadId").is_some() && get("partNumber").is_some() => {
            let part_number = get("partNumber").and_then(|v| v.parse::<u32>().ok())?;
            Intent::UploadPart {
                part_number,
                upload_id: get("uploadId").unwrap(),
            }
        }
        "PUT" => Intent::PutObject,
        "DELETE" if get("uploadId").is_some() => Intent::AbortMultipart {
            upload_id: get("uploadId").unwrap(),
        },
        _ => Intent::Unsupported,
    };
    Some(Route {
        bucket,
        raw_key,
        intent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_part_numbers_from_complete_xml() {
        let xml = br#"<?xml version="1.0"?>
            <CompleteMultipartUpload>
              <Part><PartNumber>1</PartNumber><ETag>"a"</ETag></Part>
              <Part><PartNumber>2</PartNumber><ETag>"b"</ETag></Part>
            </CompleteMultipartUpload>"#;
        assert_eq!(parse_complete_part_numbers(xml), Some(vec![1, 2]));
        // No part numbers ⇒ None.
        assert_eq!(parse_complete_part_numbers(b"<x/>"), None);
        // A non-numeric part number ⇒ None (fail-closed).
        assert_eq!(
            parse_complete_part_numbers(b"<PartNumber>x</PartNumber>"),
            None
        );
    }

    #[test]
    fn routes_path_style_bucket_and_key() {
        let req = |method: &str, path: &str, query: &str| S3Request {
            method: method.into(),
            uri_path: path.into(),
            query: query.into(),
            headers: vec![],
            body: Body::empty(),
        };
        let r = parse_route(&req("PUT", "/photos/avatars/u1.jpg", "")).unwrap();
        assert_eq!(r.bucket, "photos");
        assert_eq!(r.raw_key, "avatars/u1.jpg");
        assert!(matches!(r.intent, Intent::PutObject));

        assert!(matches!(
            parse_route(&req("POST", "/c/k", "uploads")).unwrap().intent,
            Intent::CreateMultipart
        ));
        assert!(matches!(
            parse_route(&req("PUT", "/c/k", "partNumber=3&uploadId=abc"))
                .unwrap()
                .intent,
            Intent::UploadPart { part_number: 3, .. }
        ));
        assert!(matches!(
            parse_route(&req("POST", "/c/k", "uploadId=abc"))
                .unwrap()
                .intent,
            Intent::CompleteMultipart { .. }
        ));
        assert!(matches!(
            parse_route(&req("DELETE", "/c/k", "uploadId=abc"))
                .unwrap()
                .intent,
            Intent::AbortMultipart { .. }
        ));
        assert!(matches!(
            parse_route(&req("HEAD", "/c/k", "")).unwrap().intent,
            Intent::Head
        ));
        // GET is unsupported (write/multipart-only face — no external read).
        assert!(matches!(
            parse_route(&req("GET", "/c/k", "")).unwrap().intent,
            Intent::Unsupported
        ));
    }
}
