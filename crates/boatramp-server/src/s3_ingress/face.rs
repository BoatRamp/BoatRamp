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

use super::auth::{self, AuthedScope, S3AuthInput, S3Op};
use super::chunked::{self, ChunkContext};
use super::config::S3IngressState;
use super::error::{S3Error, S3ErrorCode, refuse};
use super::keypath;
use super::multipart::{self, MultipartError};
use super::sigv4::STREAMING_PAYLOAD;

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
    let presigned_params = super::listener::decoded_query_params(&req.query);
    // The session token: a presigned URL (the browser-UGC `fetch(url, {method:"PUT", body})` flow)
    // carries it in the SIGNED canonical query as `X-Amz-Security-Token` (see `presign_put_url`), NOT
    // as a header — a browser fetch sends only the URL. A header-auth SDK sends it as the
    // `x-amz-security-token` header. Prefer the query param when present (a presigned request), and
    // fall back to the header (a header-auth request). HIGH-1: without the query lookup, every
    // presigned-put credential is unredeemable (the token is `None` ⇒ uniform 403). No
    // signature-verification change is needed — the token is already inside the signed canonical query
    // (`presigned_canonical_query` retains it), so we neither add nor exclude it from the signature.
    let session_token = query_val(&presigned_params, "X-Amz-Security-Token")
        .or_else(|| header_val(&req.headers, "x-amz-security-token"));
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

    // If the client signed an aws-chunked (`STREAMING-...-PAYLOAD`) body, build the verification
    // context now (the payload is de-framed + per-chunk-verified as it streams — never buffered). The
    // trailing-checksum form was already rejected in `authenticate` (MEDIUM-2), so only the plain
    // streaming form reaches here.
    let chunk_ctx = build_chunk_context(&authed);
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
            put_object(
                state,
                &session,
                &bucket,
                &raw_key,
                req.headers,
                req.body,
                chunk_ctx,
            )
            .await
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
                chunk_ctx,
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
    chunk_ctx: Option<ChunkContext>,
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
    match stream_put(
        state,
        &storage_key,
        body,
        chunk_ctx,
        require_hash.as_deref(),
    )
    .await
    {
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
// The arguments are the cohesive request context (state + scope + route + upload id + part + body +
// chunk ctx); grouping them into a struct would add ceremony without clarifying the single call site.
#[allow(clippy::too_many_arguments)]
async fn upload_part(
    state: &S3IngressState,
    session: &S3Session,
    bucket: &str,
    raw_key: &str,
    upload_id: &str,
    part_number: u32,
    body: Body,
    chunk_ctx: Option<ChunkContext>,
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
    // De-frame + per-chunk-verify an aws-chunked part body (if any) BEFORE the size guard, so the guard
    // caps the actual payload bytes, not the framing.
    let stream = guarded_stream(state, payload_body(body, chunk_ctx));
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
/// reject; no committed partial). An aws-chunked body (`chunk_ctx = Some`) is de-framed + per-chunk
/// verified first. On any stream error (a bad chunk signature, a size overflow) the object is deleted.
async fn stream_put(
    state: &S3IngressState,
    storage_key: &str,
    body: Body,
    chunk_ctx: Option<ChunkContext>,
    require_hash: Option<&str>,
) -> Result<(), Response> {
    let guarded = guarded_stream(state, payload_body(body, chunk_ctx));
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
        // An aws-chunked de-framing/verification failure surfaces as a backend stream error — it is an
        // authentication failure, so it collapses to the uniform 403 (no-oracle), and the partial is
        // deleted (no committed object).
        Err(StorageError::Backend(msg)) if msg.contains("aws-chunked") => {
            let _ = state.deploy.storage().delete(storage_key).await;
            return Err(refuse(&format!("aws-chunked body: {msg}")));
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
    Ok(())
}

/// Wrap a payload [`ByteStream`] with the shared `UploadGuard` size/idle cap.
fn guarded_stream(state: &S3IngressState, stream: ByteStream) -> ByteStream {
    state.guard.limit_body(stream)
}

/// Convert the raw HTTP body into the payload [`ByteStream`] the storage backend receives: for an
/// aws-chunked request (`chunk_ctx = Some`) the body is de-framed + per-chunk verified against the
/// signature chain (never buffered whole); otherwise the raw data stream passes through unchanged.
fn payload_body(body: Body, chunk_ctx: Option<ChunkContext>) -> ByteStream {
    let raw = body
        .into_data_stream()
        .map(|chunk| chunk.map_err(|e| StorageError::backend(e.to_string())))
        .boxed();
    match chunk_ctx {
        Some(ctx) => chunked::dechunk_verified(raw, ctx),
        None => raw,
    }
}

/// Build the aws-chunked verification context from the authenticated request, when the client signed a
/// streaming (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) body. `None` for a real-hash / `UNSIGNED-PAYLOAD`
/// request (those bodies are not chunk-framed). The trailer form was already rejected at auth.
fn build_chunk_context(authed: &AuthedScope) -> Option<ChunkContext> {
    (authed.payload_hash == STREAMING_PAYLOAD).then(|| ChunkContext {
        secret: authed.secret.clone(),
        scope: authed.parsed.scope.clone(),
        amz_date: authed.parsed.amz_date.clone(),
        seed_signature: authed.parsed.signature.clone(),
    })
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

/// Look up a (decoded) query-parameter value by exact name. Used to source the session token from a
/// presigned URL's `X-Amz-Security-Token` param (the browser-UGC flow sends it in the query, never a
/// header). An empty value (a bare `?X-Amz-Security-Token`) is treated as absent so it correctly falls
/// back to the header.
fn query_val<'a>(params: &'a [(String, String)], name: &str) -> Option<&'a str> {
    params
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
        .filter(|v| !v.is_empty())
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
    let upload_id = get("uploadId");
    let part_number = get("partNumber").and_then(|v| v.parse::<u32>().ok());

    let intent = match (req.method.as_str(), upload_id, part_number) {
        ("OPTIONS", _, _) => Intent::Options,
        ("HEAD", _, _) => Intent::Head,
        ("POST", _, _) if has("uploads") => Intent::CreateMultipart,
        ("POST", Some(upload_id), _) => Intent::CompleteMultipart { upload_id },
        ("PUT", Some(upload_id), Some(part_number)) => Intent::UploadPart {
            part_number,
            upload_id,
        },
        ("PUT", None, _) => Intent::PutObject,
        ("DELETE", Some(upload_id), _) => Intent::AbortMultipart { upload_id },
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

/// End-to-end tests over the full `handle` HTTP request→response path: a real minted+signed request
/// drives the engine, and we assert on the response AND the resulting storage state (guest
/// read-through). These prove the operations wire together and enforce the security invariants at the
/// HTTP layer (not just in the pure sub-modules).
#[cfg(test)]
mod e2e {
    use super::*;
    use crate::s3_ingress::config::{LOCAL_REGION, LOCAL_SERVICE, S3IngressState};
    use crate::s3_ingress::credential::S3IngressSecret;
    use crate::s3_ingress::keypath;
    use crate::s3_ingress::sigv4;
    use axum::body::to_bytes;
    use boatramp_core::cose::{
        LocalSigner, S3Constraints, S3Perm, S3SessionScope, S3Target, Signer as _, TokenAlg,
        mint_s3_session, verify_s3_session,
    };
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::kv::MemoryKv;
    use std::sync::Arc;

    const NOW: i64 = 1_440_938_160; // 20150830T123600Z
    const AMZ_DATE: &str = "20150830T123600Z";

    /// A test harness: a fleet signer, an ingress secret, and a face state over an in-memory store we
    /// can assert on.
    struct Harness {
        signer: LocalSigner,
        secret: S3IngressSecret,
        map: Arc<crate::s3_ingress::test_support::MapStorage>,
        state: S3IngressState,
    }

    fn harness() -> Harness {
        harness_with(|s| s)
    }

    fn harness_with(f: impl FnOnce(S3IngressState) -> S3IngressState) -> Harness {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let map = Arc::new(crate::s3_ingress::test_support::MapStorage::default());
        let deploy = DeployStore::new(map.clone(), Arc::new(MemoryKv::new()));
        let guard = Arc::new(crate::limits::UploadGuard::new(Default::default()));
        // The face state and the signing helper MUST derive `secret_access_key` under the SAME ingress
        // root, so build both from one fixed 32-byte value (a random `generate()` would differ).
        const ROOT: [u8; 32] = [0x5a; 32];
        let state = f(S3IngressState::new(
            signer.public_key(),
            S3IngressSecret::from_bytes(&ROOT).unwrap(),
            deploy,
            guard,
        ));
        Harness {
            signer,
            secret: S3IngressSecret::from_bytes(&ROOT).unwrap(),
            map,
            state,
        }
    }

    /// Mint + sign a request, returning a ready [`S3Request`]. `perms`/`constraints`/`target` shape the
    /// credential scope; `body` is the request payload (its real sha256 is signed as the payload hash).
    #[allow(clippy::too_many_arguments)]
    async fn signed_request(
        h: &Harness,
        method: &str,
        container: &str,
        target: S3Target,
        perms: Vec<S3Perm>,
        constraints: S3Constraints,
        uri_path: &str,
        query: &str,
        body: &[u8],
        content_type: Option<&str>,
    ) -> S3Request {
        let scope = S3SessionScope {
            project: "default".into(),
            site: "blog".into(),
            container: container.into(),
            target,
            perms,
            constraints,
        };
        let token = mint_s3_session(&scope, 900, NOW as u64, &h.signer)
            .await
            .unwrap();
        let session = verify_s3_session(&token, &h.signer.public_key(), NOW as u64).unwrap();
        let akid = "BRUPE2ETEST";
        let sak = h.secret.derive_secret(akid, &session.cti).unwrap();
        let payload_hash = sigv4::sha256_hex(body);
        let mut headers = vec![
            ("host".to_string(), "s3.local".to_string()),
            ("x-amz-date".to_string(), AMZ_DATE.to_string()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-security-token".to_string(), token.clone()),
            ("content-length".to_string(), body.len().to_string()),
        ];
        if let Some(ct) = content_type {
            headers.push(("content-type".to_string(), ct.to_string()));
        }
        // Sign the required header set (+ content-type when present).
        let mut signed = vec![
            "host".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ];
        if content_type.is_some() {
            signed.push("content-type".to_string());
            signed.sort();
        }
        let scope_s = sigv4::CredentialScope {
            access_key_id: akid.into(),
            date: "20150830".into(),
            region: LOCAL_REGION.into(),
            service: LOCAL_SERVICE.into(),
        };
        let req = sigv4::CanonicalRequest {
            method,
            uri_path,
            query,
            headers: &headers,
            payload_hash: &payload_hash,
        };
        let (creq, signed_str) = sigv4::canonical_request_string(&req, &signed).unwrap();
        let sts = sigv4::string_to_sign(AMZ_DATE, &scope_s, &creq);
        let sig = sigv4::compute_signature(&sak, &scope_s, &sts);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={akid}/20150830/{LOCAL_REGION}/{LOCAL_SERVICE}/aws4_request, SignedHeaders={signed_str}, Signature={sig}"
        );
        headers.push(("authorization".to_string(), authorization));
        S3Request {
            method: method.to_string(),
            uri_path: uri_path.to_string(),
            query: query.to_string(),
            headers,
            body: Body::from(body.to_vec()),
        }
    }

    #[tokio::test]
    async fn put_object_lands_at_guest_readable_key() {
        // A signed single-shot PUT to container "photos", key "avatars/u1.jpg" succeeds and lands at
        // EXACTLY the hblob key the guest compat::blob binding reads.
        let h = harness();
        let body = b"the avatar bytes";
        let req = signed_request(
            &h,
            "PUT",
            "photos",
            S3Target::Key("avatars/u1.jpg".into()),
            vec![S3Perm::Put],
            S3Constraints::default(),
            "/photos/avatars/u1.jpg",
            "",
            body,
            None,
        )
        .await;
        let resp = handle(&h.state, req, NOW).await;
        assert_eq!(resp.status(), StatusCode::OK);
        // Guest read-through: the object is at hblob/blog/photos/avatars/u1.jpg (default project ⇒ no
        // project segment), byte-identical.
        let (_d, key) =
            keypath::compose_object_key("default", "blog", "photos", "avatars/u1.jpg").unwrap();
        assert_eq!(key, "hblob/blog/photos/avatars/u1.jpg");
        assert_eq!(h.map.get_bytes(&key).unwrap(), body);
    }

    #[tokio::test]
    async fn cross_container_and_key_escape_are_refused() {
        // A credential scoped to "photos"/"avatars/u1.jpg". Driving it at a DIFFERENT container, or a
        // traversal key, yields a refusal — never a committed object.
        let h = harness();
        // Cross-container: mint a credential for container "photos" but sign+send it to bucket "docs"
        // in the URL. The scope authorization (bucket must == the SIGNED scope's container) refuses it.
        let scope = S3SessionScope {
            project: "default".into(),
            site: "blog".into(),
            container: "photos".into(),
            target: S3Target::Key("avatars/u1.jpg".into()),
            perms: vec![S3Perm::Put],
            constraints: S3Constraints::default(),
        };
        let token = mint_s3_session(&scope, 900, NOW as u64, &h.signer)
            .await
            .unwrap();
        let session = verify_s3_session(&token, &h.signer.public_key(), NOW as u64).unwrap();
        let akid = "BRUPXCONT";
        let sak = h.secret.derive_secret(akid, &session.cti).unwrap();
        let body = b"x";
        let payload_hash = sigv4::sha256_hex(body);
        // Sign a request whose URL bucket is "docs" (mismatching the scope's "photos").
        let headers = vec![
            ("host".to_string(), "s3.local".to_string()),
            ("x-amz-date".to_string(), AMZ_DATE.to_string()),
            ("x-amz-content-sha256".to_string(), payload_hash.clone()),
            ("x-amz-security-token".to_string(), token.clone()),
            ("content-length".to_string(), "1".to_string()),
        ];
        let signed = vec![
            "host".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ];
        let scope_s = sigv4::CredentialScope {
            access_key_id: akid.into(),
            date: "20150830".into(),
            region: LOCAL_REGION.into(),
            service: LOCAL_SERVICE.into(),
        };
        let creq_req = sigv4::CanonicalRequest {
            method: "PUT",
            uri_path: "/docs/avatars/u1.jpg",
            query: "",
            headers: &headers,
            payload_hash: &payload_hash,
        };
        let (creq, signed_str) = sigv4::canonical_request_string(&creq_req, &signed).unwrap();
        let sts = sigv4::string_to_sign(AMZ_DATE, &scope_s, &creq);
        let sig = sigv4::compute_signature(&sak, &scope_s, &sts);
        let mut xcont_headers = headers.clone();
        xcont_headers.push((
            "authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential={akid}/20150830/{LOCAL_REGION}/{LOCAL_SERVICE}/aws4_request, SignedHeaders={signed_str}, Signature={sig}"
            ),
        ));
        let xcont = S3Request {
            method: "PUT".into(),
            uri_path: "/docs/avatars/u1.jpg".into(),
            query: String::new(),
            headers: xcont_headers,
            body: Body::from(body.to_vec()),
        };
        let resp = handle(&h.state, xcont, NOW).await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "cross-container must be refused"
        );
        assert!(
            h.map.get_bytes("hblob/blog/docs/avatars/u1.jpg").is_none(),
            "no object committed to the wrong container"
        );

        // Key escape: a percent-encoded traversal in the key ⇒ BoatrampScopeEscape (403), no object.
        let esc = signed_request(
            &h,
            "PUT",
            "photos",
            S3Target::Prefix(String::new()), // whole-container so authorization passes if the key is ok
            vec![S3Perm::Put],
            S3Constraints::default(),
            "/photos/%2e%2e%2fescape",
            "",
            b"x",
            None,
        )
        .await;
        let resp = handle(&h.state, esc, NOW).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body_bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body_bytes).contains("BoatrampScopeEscape"));
    }

    #[tokio::test]
    async fn create_only_credential_refuses_overwrite() {
        // A create-only (UGC default) credential: the first PUT succeeds; a second PUT to the same key
        // is refused with BoatrampOverwriteDenied (412), and the original bytes are untouched.
        let h = harness();
        async fn mk(h: &Harness, body: &'static [u8]) -> S3Request {
            signed_request(
                h,
                "PUT",
                "photos",
                S3Target::Key("once.bin".into()),
                vec![S3Perm::Put],
                S3Constraints {
                    create_only: true,
                    ..Default::default()
                },
                "/photos/once.bin",
                "",
                body,
                None,
            )
            .await
        }
        let first = handle(&h.state, mk(&h, b"first").await, NOW).await;
        assert_eq!(first.status(), StatusCode::OK);
        let key = "hblob/blog/photos/once.bin";
        assert_eq!(h.map.get_bytes(key).unwrap(), b"first");
        // Second PUT (overwrite) ⇒ refused, original preserved.
        let second = handle(&h.state, mk(&h, b"second").await, NOW).await;
        assert_eq!(second.status(), StatusCode::PRECONDITION_FAILED);
        let body = to_bytes(second.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("BoatrampOverwriteDenied"));
        assert_eq!(
            h.map.get_bytes(key).unwrap(),
            b"first",
            "overwrite must not have happened"
        );
    }

    #[tokio::test]
    async fn content_addressed_put_rejects_mismatched_bytes() {
        // A require_sha256 credential: the key must equal sha256(bytes). Send bytes that DON'T hash to
        // the declared key ⇒ BoatrampSha256Mismatch, no committed object.
        let h = harness();
        let real_bytes = b"hello world";
        let real_hash = sigv4::sha256_hex(real_bytes);
        // Declare a key that is NOT the hash of the bytes we send.
        let wrong_key = "0000000000000000000000000000000000000000000000000000000000000000";
        let req = signed_request(
            &h,
            "PUT",
            "cas",
            S3Target::Prefix(String::new()),
            vec![S3Perm::Put],
            S3Constraints {
                require_sha256: true,
                ..Default::default()
            },
            &format!("/cas/{wrong_key}"),
            "",
            real_bytes,
            None,
        )
        .await;
        let resp = handle(&h.state, req, NOW).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("BoatrampSha256Mismatch"));
        assert!(
            h.map
                .get_bytes(&format!("hblob/blog/cas/{wrong_key}"))
                .is_none(),
            "no committed object on mismatch"
        );
        // The matching key ⇒ committed.
        let ok = signed_request(
            &h,
            "PUT",
            "cas",
            S3Target::Prefix(String::new()),
            vec![S3Perm::Put],
            S3Constraints {
                require_sha256: true,
                ..Default::default()
            },
            &format!("/cas/{real_hash}"),
            "",
            real_bytes,
            None,
        )
        .await;
        assert_eq!(handle(&h.state, ok, NOW).await.status(), StatusCode::OK);
        assert_eq!(
            h.map
                .get_bytes(&format!("hblob/blog/cas/{real_hash}"))
                .unwrap(),
            real_bytes
        );
    }

    #[tokio::test]
    async fn aws_chunked_put_deframes_verifies_and_lands_guest_readable() {
        // A real STREAMING-AWS4-HMAC-SHA256-PAYLOAD (aws-chunked) PUT: the request is signed with the
        // streaming marker, the body is chunk-framed with a per-chunk signature chain, and the face
        // de-frames + verifies each chunk while streaming, landing the concatenated payload at the
        // guest-readable hblob key.
        let h = harness();
        let scope = S3SessionScope {
            project: "default".into(),
            site: "blog".into(),
            container: "photos".into(),
            target: S3Target::Key("chunked.bin".into()),
            perms: vec![S3Perm::Put],
            constraints: S3Constraints::default(),
        };
        let token = mint_s3_session(&scope, 900, NOW as u64, &h.signer)
            .await
            .unwrap();
        let session = verify_s3_session(&token, &h.signer.public_key(), NOW as u64).unwrap();
        let akid = "BRUPCHUNKED";
        let sak = h.secret.derive_secret(akid, &session.cti).unwrap();
        let uri_path = "/photos/chunked.bin";
        let scope_s = sigv4::CredentialScope {
            access_key_id: akid.into(),
            date: "20150830".into(),
            region: LOCAL_REGION.into(),
            service: LOCAL_SERVICE.into(),
        };
        // Sign the request with the streaming payload marker (that is what the client signs as the
        // canonical payload hash for aws-chunked).
        let headers = vec![
            ("host".to_string(), "s3.local".to_string()),
            ("x-amz-date".to_string(), AMZ_DATE.to_string()),
            (
                "x-amz-content-sha256".to_string(),
                sigv4::STREAMING_PAYLOAD.to_string(),
            ),
            ("x-amz-security-token".to_string(), token.clone()),
        ];
        let signed = vec![
            "host".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ];
        let creq_req = sigv4::CanonicalRequest {
            method: "PUT",
            uri_path,
            query: "",
            headers: &headers,
            payload_hash: sigv4::STREAMING_PAYLOAD,
        };
        let (creq, signed_str) = sigv4::canonical_request_string(&creq_req, &signed).unwrap();
        let sts = sigv4::string_to_sign(AMZ_DATE, &scope_s, &creq);
        let seed = sigv4::compute_signature(&sak, &scope_s, &sts);
        // Build the chunked wire body (two data chunks + the zero terminator), each signed off the seed
        // chain — mirroring what an S3 SDK sends.
        let mut verifier = sigv4::ChunkVerifier::new(&sak, &scope_s, AMZ_DATE, &seed);
        let mut wire = Vec::new();
        for data in [
            b"Hello, ".as_slice(),
            b"chunked!".as_slice(),
            b"".as_slice(),
        ] {
            let chunk_sts = format!(
                "AWS4-HMAC-SHA256-PAYLOAD\n{AMZ_DATE}\n{}\n{}\n{}\n{}",
                scope_s.scope_string(),
                verifier.current_signature(),
                sigv4::EMPTY_SHA256,
                sigv4::sha256_hex(data),
            );
            let key = sigv4::signing_key(&sak, &scope_s.date, &scope_s.region, &scope_s.service);
            let sig = {
                use aws_lc_rs::hmac;
                let k = hmac::Key::new(hmac::HMAC_SHA256, key.as_ref());
                hex::encode(hmac::sign(&k, chunk_sts.as_bytes()).as_ref())
            };
            wire.extend_from_slice(
                format!("{:x};chunk-signature={}\r\n", data.len(), sig).as_bytes(),
            );
            wire.extend_from_slice(data);
            wire.extend_from_slice(b"\r\n");
            verifier.verify_chunk(data, &sig).unwrap();
        }
        let mut req_headers = headers.clone();
        req_headers.push((
            "authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential={akid}/20150830/{LOCAL_REGION}/{LOCAL_SERVICE}/aws4_request, SignedHeaders={signed_str}, Signature={seed}"
            ),
        ));
        let req = S3Request {
            method: "PUT".into(),
            uri_path: uri_path.into(),
            query: String::new(),
            headers: req_headers,
            body: Body::from(wire),
        };
        let resp = handle(&h.state, req, NOW).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a valid aws-chunked PUT succeeds"
        );
        assert_eq!(
            h.map.get_bytes("hblob/blog/photos/chunked.bin").unwrap(),
            b"Hello, chunked!",
            "the de-framed payload lands guest-readable"
        );
    }

    #[tokio::test]
    async fn multipart_create_upload_complete_assembles_guest_readable_object() {
        // The full multipart flow: Create → UploadPart×2 → Complete assembles a guest-readable object;
        // the staging is gone afterward (no leak, no partial).
        let h = harness();
        let container = "bulk";
        let key = "big/object.bin";
        let target = S3Target::Prefix("big".into());
        let perms = vec![S3Perm::Multipart];

        // Create.
        let create = signed_request(
            &h,
            "POST",
            container,
            target.clone(),
            perms.clone(),
            S3Constraints::default(),
            &format!("/{container}/{key}"),
            "uploads",
            b"",
            None,
        )
        .await;
        let resp = handle(&h.state, create, NOW).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let xml = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let xml = String::from_utf8_lossy(&xml);
        let upload_id = xml
            .split("<UploadId>")
            .nth(1)
            .unwrap()
            .split("</UploadId>")
            .next()
            .unwrap()
            .to_string();

        // UploadPart 1 + 2.
        for (n, data) in [(1u32, b"AAAA".as_slice()), (2u32, b"BBBB".as_slice())] {
            let up = signed_request(
                &h,
                "PUT",
                container,
                target.clone(),
                perms.clone(),
                S3Constraints::default(),
                &format!("/{container}/{key}"),
                &format!("partNumber={n}&uploadId={upload_id}"),
                data,
                None,
            )
            .await;
            let r = handle(&h.state, up, NOW).await;
            assert_eq!(r.status(), StatusCode::OK, "UploadPart {n}");
        }

        // Complete with the part list.
        let complete_xml = "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part>\
             <Part><PartNumber>2</PartNumber></Part></CompleteMultipartUpload>"
            .to_string();
        let complete = signed_request(
            &h,
            "POST",
            container,
            target.clone(),
            perms.clone(),
            S3Constraints::default(),
            &format!("/{container}/{key}"),
            &format!("uploadId={upload_id}"),
            complete_xml.as_bytes(),
            None,
        )
        .await;
        let r = handle(&h.state, complete, NOW).await;
        assert_eq!(r.status(), StatusCode::OK);

        // Guest read-through: the assembled object is at the hblob key, parts concatenated in order.
        let final_key = format!("hblob/blog/{container}/{key}");
        assert_eq!(h.map.get_bytes(&final_key).unwrap(), b"AAAABBBB");
        // Staging is gone (GC'd on complete).
        let staging = keypath::staging_prefix("default", "blog", container, &upload_id);
        assert_eq!(h.map.count_with_prefix(&staging), 0, "staging must be GC'd");
    }

    #[tokio::test]
    async fn abort_removes_staging_via_the_face() {
        let h = harness();
        let container = "bulk";
        let key = "x/y";
        let target = S3Target::Prefix("x".into());
        let perms = vec![S3Perm::Multipart];
        let create = signed_request(
            &h,
            "POST",
            container,
            target.clone(),
            perms.clone(),
            S3Constraints::default(),
            &format!("/{container}/{key}"),
            "uploads",
            b"",
            None,
        )
        .await;
        let resp = handle(&h.state, create, NOW).await;
        let xml = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let xml = String::from_utf8_lossy(&xml);
        let upload_id = xml
            .split("<UploadId>")
            .nth(1)
            .unwrap()
            .split("</UploadId>")
            .next()
            .unwrap()
            .to_string();
        // Stage a part.
        let up = signed_request(
            &h,
            "PUT",
            container,
            target.clone(),
            perms.clone(),
            S3Constraints::default(),
            &format!("/{container}/{key}"),
            &format!("partNumber=1&uploadId={upload_id}"),
            b"data",
            None,
        )
        .await;
        assert_eq!(handle(&h.state, up, NOW).await.status(), StatusCode::OK);
        let staging = keypath::staging_prefix("default", "blog", container, &upload_id);
        assert_eq!(h.map.count_with_prefix(&staging), 1);
        // Abort.
        let abort = signed_request(
            &h,
            "DELETE",
            container,
            target,
            perms,
            S3Constraints::default(),
            &format!("/{container}/{key}"),
            &format!("uploadId={upload_id}"),
            b"",
            None,
        )
        .await;
        assert_eq!(
            handle(&h.state, abort, NOW).await.status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            h.map.count_with_prefix(&staging),
            0,
            "abort GC'd the staging"
        );
    }

    #[tokio::test]
    async fn cors_preflight_never_wildcards_and_only_echoes_allowed_origin() {
        // A container with one allowed origin. An OPTIONS preflight from that origin echoes it (never
        // `*`); from a different origin gets a bare 403 with no CORS headers.
        let h = harness_with(|s| {
            s.with_container_policy(
                "default",
                "blog",
                "photos",
                crate::s3_ingress::config::ContainerPolicy {
                    cors_allowed_origins: vec!["https://app.example".into()],
                    ..Default::default()
                },
            )
        });
        // Allowed origin ⇒ echoed exactly, never `*`.
        let req = S3Request {
            method: "OPTIONS".into(),
            uri_path: "/photos/x".into(),
            query: String::new(),
            headers: vec![("origin".to_string(), "https://app.example".to_string())],
            body: Body::empty(),
        };
        let resp = handle(&h.state, req, NOW).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let echoed = resp
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(echoed, "https://app.example");
        assert_ne!(
            echoed, "*",
            "must never wildcard a credentialed write endpoint"
        );
        // Disallowed origin ⇒ 403, no CORS header (browser blocks it).
        let req2 = S3Request {
            method: "OPTIONS".into(),
            uri_path: "/photos/x".into(),
            query: String::new(),
            headers: vec![("origin".to_string(), "https://evil.example".to_string())],
            body: Body::empty(),
        };
        let resp2 = handle(&h.state, req2, NOW).await;
        assert_eq!(resp2.status(), StatusCode::FORBIDDEN);
        assert!(
            resp2
                .headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .is_none()
        );
    }

    #[tokio::test]
    async fn multipart_upload_id_from_one_scope_is_rejected_by_another() {
        // Invariant 8: A's uploadId can't be driven by B's credential. Create an upload under a
        // credential for prefix "a", then present a valid credential for prefix "b" with A's uploadId —
        // the scope re-verification refuses it (uniform 403).
        let h = harness();
        let create = signed_request(
            &h,
            "POST",
            "bulk",
            S3Target::Prefix("a".into()),
            vec![S3Perm::Multipart],
            S3Constraints::default(),
            "/bulk/a/obj",
            "uploads",
            b"",
            None,
        )
        .await;
        let resp = handle(&h.state, create, NOW).await;
        let xml = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let xml = String::from_utf8_lossy(&xml);
        let upload_id = xml
            .split("<UploadId>")
            .nth(1)
            .unwrap()
            .split("</UploadId>")
            .next()
            .unwrap()
            .to_string();
        // A DIFFERENT credential (prefix "b") tries to UploadPart against A's uploadId.
        let hijack = signed_request(
            &h,
            "PUT",
            "bulk",
            S3Target::Prefix("b".into()),
            vec![S3Perm::Multipart],
            S3Constraints::default(),
            "/bulk/b/obj",
            &format!("partNumber=1&uploadId={upload_id}"),
            b"evil",
            None,
        )
        .await;
        let r = handle(&h.state, hijack, NOW).await;
        assert_eq!(
            r.status(),
            StatusCode::FORBIDDEN,
            "an uploadId bound to scope A must not be drivable by scope B's credential"
        );
    }
}
