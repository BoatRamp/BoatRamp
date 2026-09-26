//! Standards-shaped S3 error XML with a **stable, greppable boatramp `<Code>` vocabulary** (PLAN
//! §CLI/errors — UX P5), and the **uniform-403 no-oracle** auth-refusal mapping (M1-review INFO-3).
//!
//! Two concerns live here, deliberately separated:
//!
//! - [`S3Error`] — the response type. It serializes as the S3 `<Error>` document every S3 SDK/CLI
//!   already parses, but with boatramp-specific `<Code>`s (`BoatrampScopeEscape`, `BoatrampCredExpired`,
//!   …) so an operator can grep both server logs and client output for the exact failure. Non-auth
//!   errors (a too-big object, a sha256 mismatch, an object that already exists) carry a specific code
//!   + a helpful message — those are not an authentication oracle, they are the honest result of a
//!   well-authenticated request that violated a constraint.
//!
//! - [`refuse`] — the **authentication** refusal. EVERY `SigV4Error` / `TokenError` /
//!   `verify_s3_session` / scope-mismatch / revoked outcome maps to ONE byte-indistinguishable `403`
//!   with the single `AccessDenied`-class body, so an attacker probing the face cannot learn WHICH
//!   check failed (mirrors `tenant_secrets::refuse`). The real reason is logged host-side only.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};

/// The stable boatramp `<Code>` vocabulary (greppable). Auth failures deliberately all collapse to
/// [`Self::AccessDenied`] via [`refuse`] (no oracle); the others name a specific, non-oracle condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3ErrorCode {
    /// The uniform authentication/authorization refusal — the ONLY code any credential/signature/
    /// scope/expiry/revocation failure ever produces (byte-indistinguishable, no which-check oracle).
    AccessDenied,
    /// The composed object key escaped its scoped prefix (traversal / absolute / reserved namespace).
    BoatrampScopeEscape,
    /// The credential (session token) is expired. NOTE: never produced on the auth path (that path
    /// uniformly returns `AccessDenied`); reserved for surfaces that legitimately surface expiry.
    BoatrampCredExpired,
    /// A content-addressed upload's bytes did not hash to the declared key.
    BoatrampSha256Mismatch,
    /// The object exceeded the credential's `max_bytes` or the per-container size ceiling.
    BoatrampSizeExceeded,
    /// The `Content-Type` did not satisfy the credential's required content-type constraint.
    BoatrampContentTypeRejected,
    /// A create-only credential attempted to overwrite an existing key.
    BoatrampOverwriteDenied,
    /// A DoS cap was hit (too many parts, too many concurrent uploads, staged bytes exceeded).
    BoatrampQuotaExceeded,
    /// The multipart request was malformed (bad part list, unknown/absent uploadId, bad part number).
    BoatrampMultipartInvalid,
    /// The request named an operation the credential's `perms` do not grant (e.g. multipart on a
    /// put-only credential). Distinct from `AccessDenied` because the credential IS authentic — this
    /// is an authenticated-but-not-permitted result, not an authentication oracle.
    BoatrampOperationNotPermitted,
    /// The request body / framing was malformed (bad XML, bad chunk framing surfaced non-auth).
    MalformedRequest,
    /// A standards S3 code for an internal fault (a storage backend error). Native S3 code so SDKs
    /// retry it correctly.
    InternalError,
    /// Standards S3 code: the requested method/route is not one the face implements.
    MethodNotAllowed,
}

impl S3ErrorCode {
    /// The exact `<Code>` string (stable wire contract — greppable in logs + client output).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AccessDenied => "AccessDenied",
            Self::BoatrampScopeEscape => "BoatrampScopeEscape",
            Self::BoatrampCredExpired => "BoatrampCredExpired",
            Self::BoatrampSha256Mismatch => "BoatrampSha256Mismatch",
            Self::BoatrampSizeExceeded => "BoatrampSizeExceeded",
            Self::BoatrampContentTypeRejected => "BoatrampContentTypeRejected",
            Self::BoatrampOverwriteDenied => "BoatrampOverwriteDenied",
            Self::BoatrampQuotaExceeded => "BoatrampQuotaExceeded",
            Self::BoatrampMultipartInvalid => "BoatrampMultipartInvalid",
            Self::BoatrampOperationNotPermitted => "BoatrampOperationNotPermitted",
            Self::MalformedRequest => "MalformedRequest",
            Self::InternalError => "InternalError",
            Self::MethodNotAllowed => "MethodNotAllowed",
        }
    }

    /// The HTTP status the code maps to.
    pub fn status(self) -> StatusCode {
        match self {
            Self::AccessDenied
            | Self::BoatrampScopeEscape
            | Self::BoatrampCredExpired
            | Self::BoatrampOperationNotPermitted => StatusCode::FORBIDDEN,
            Self::BoatrampSha256Mismatch
            | Self::BoatrampContentTypeRejected
            | Self::BoatrampMultipartInvalid
            | Self::MalformedRequest => StatusCode::BAD_REQUEST,
            Self::BoatrampSizeExceeded => StatusCode::PAYLOAD_TOO_LARGE,
            // 412 Precondition Failed is the S3 code for an `If-None-Match: *` overwrite rejection.
            Self::BoatrampOverwriteDenied => StatusCode::PRECONDITION_FAILED,
            Self::BoatrampQuotaExceeded => StatusCode::TOO_MANY_REQUESTS,
            Self::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::MethodNotAllowed => StatusCode::METHOD_NOT_ALLOWED,
        }
    }
}

/// An S3-shaped error response: a `<Code>` + a human `<Message>`, rendered as the standard S3
/// `<Error>` XML document with the mapped HTTP status.
#[derive(Debug, Clone)]
pub struct S3Error {
    /// The greppable boatramp/standard code.
    pub code: S3ErrorCode,
    /// A human-readable message (safe to surface: it describes a *constraint* result, never an auth
    /// oracle — auth refusals all go through [`refuse`] with a fixed message).
    pub message: String,
}

impl S3Error {
    /// Build an error with `code` and a message.
    pub fn new(code: S3ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The single uniform authentication refusal — [`refuse`] routes every auth failure here so the
    /// body is byte-identical regardless of the underlying cause.
    pub fn access_denied() -> Self {
        Self::new(S3ErrorCode::AccessDenied, "Access Denied")
    }

    /// Render the standard S3 `<Error>` XML document. `<Resource>`/`<RequestId>` are intentionally
    /// omitted (they would leak host-side context and are optional in the S3 schema).
    pub fn to_xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <Error><Code>{}</Code><Message>{}</Message></Error>",
            self.code.as_str(),
            xml_escape(&self.message),
        )
    }
}

impl IntoResponse for S3Error {
    fn into_response(self) -> Response {
        let status = self.code.status();
        let body = self.to_xml();
        (status, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
    }
}

/// Minimal XML text escaping for the `<Message>` body (the `<Code>` is from a fixed vocabulary, never
/// user-controlled). Escapes the five XML metacharacters so a message can't break the document.
fn xml_escape(s: &str) -> String {
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

/// The **uniform authentication refusal** (M1-review INFO-3, mirrors `tenant_secrets::refuse`). Maps
/// EVERY authentication/authorization failure — a malformed/absent `Authorization`, an unsupported
/// algorithm, a missing signed header, a bad/absent date, an out-of-skew request, an expired presigned
/// window, a signature mismatch, a malformed streaming chunk, an expired/forged/wrong-kind/malformed
/// session token, a scope mismatch, a revoked `cti` — to ONE byte-indistinguishable `403 AccessDenied`
/// response, so a prober cannot learn which check failed. The concrete `reason` is logged host-side
/// only (never on the wire).
///
/// Take a `&str` reason (already formatted by the caller from its `SigV4Error`/`TokenError`/scope
/// outcome) so this single function is the ONLY place the auth path builds a response — there is no
/// second, subtly-different refusal path to drift.
pub fn refuse(reason: &str) -> Response {
    // Host-side log at debug: enough for an operator to diagnose, invisible to the client.
    tracing::debug!(target: "s3_ingress::auth", %reason, "s3-ingress request refused (uniform 403)");
    S3Error::access_denied().into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[test]
    fn code_strings_are_stable_and_greppable() {
        // Pin the wire strings — a rename is a breaking, reviewed event, not a silent drift.
        assert_eq!(S3ErrorCode::AccessDenied.as_str(), "AccessDenied");
        assert_eq!(
            S3ErrorCode::BoatrampScopeEscape.as_str(),
            "BoatrampScopeEscape"
        );
        assert_eq!(
            S3ErrorCode::BoatrampSha256Mismatch.as_str(),
            "BoatrampSha256Mismatch"
        );
        assert_eq!(
            S3ErrorCode::BoatrampSizeExceeded.as_str(),
            "BoatrampSizeExceeded"
        );
        assert_eq!(
            S3ErrorCode::BoatrampOverwriteDenied.as_str(),
            "BoatrampOverwriteDenied"
        );
    }

    #[test]
    fn error_xml_is_well_formed_and_escaped() {
        let e = S3Error::new(S3ErrorCode::BoatrampScopeEscape, "bad <key> & \"stuff\"");
        let xml = e.to_xml();
        assert!(xml.contains("<Code>BoatrampScopeEscape</Code>"));
        // The message is escaped so it can't break the document.
        assert!(xml.contains("bad &lt;key&gt; &amp; &quot;stuff&quot;"));
        assert!(!xml.contains("<key>"));
    }

    #[tokio::test]
    async fn refuse_is_byte_indistinguishable_across_reasons() {
        // INFO-3: two DIFFERENT underlying auth reasons must produce a BYTE-IDENTICAL 403 response
        // (status + headers-content-type + body) — no which-check-failed oracle.
        let a = refuse("signature mismatch");
        let b = refuse("s3-session token expired");
        assert_eq!(a.status(), StatusCode::FORBIDDEN);
        assert_eq!(b.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            a.headers().get(header::CONTENT_TYPE),
            b.headers().get(header::CONTENT_TYPE)
        );
        let (_pa, ba) = a.into_parts();
        let (_pb, bb) = b.into_parts();
        let ba = to_bytes(ba, usize::MAX).await.unwrap();
        let bb = to_bytes(bb, usize::MAX).await.unwrap();
        assert_eq!(
            ba, bb,
            "refusal bodies must be byte-identical regardless of cause"
        );
        assert!(String::from_utf8_lossy(&ba).contains("<Code>AccessDenied</Code>"));
    }

    #[test]
    fn status_mapping() {
        assert_eq!(S3ErrorCode::AccessDenied.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            S3ErrorCode::BoatrampSizeExceeded.status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            S3ErrorCode::BoatrampOverwriteDenied.status(),
            StatusCode::PRECONDITION_FAILED
        );
        assert_eq!(
            S3ErrorCode::BoatrampQuotaExceeded.status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
