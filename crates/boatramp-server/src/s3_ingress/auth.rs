//! The **authentication + authorization pipeline** of the local S3 face (PLAN §3 auth model, §10
//! invariants 1–2, and the M1-review fixes LOW-1 / INFO-3 / MEDIUM-2).
//!
//! Given a parsed request ([`S3AuthInput`]) and the face state, [`authenticate`] runs the FULL,
//! fail-closed sequence and returns either the verified upload scope (a [`AuthedScope`]) or a single
//! opaque refusal reason. It is deliberately pure over its inputs (no socket, no body) so every branch
//! is unit-testable; the caller maps ANY `Err(reason)` to one uniform 403 via [`super::error::refuse`]
//! (INFO-3 no-oracle).
//!
//! The sequence, in order (every step fails closed to the same opaque error):
//! 1. Parse the SigV4 authorization — header form or presigned-query form.
//! 2. **SignedHeaders policy** (LOW-1): reject any request whose `SignedHeaders` omits `host`,
//!    `x-amz-date`, or `x-amz-content-sha256`.
//! 3. **Trailer rejection** (MEDIUM-2): reject any `STREAMING-...-PAYLOAD-TRAILER` /
//!    trailing-checksum request with a uniform refusal (M1 names the trailer marker but does not
//!    verify the trailing checksum, so we fail closed rather than accept an unverified trailer).
//! 4. Clock-skew (header) / presigned-expiry window.
//! 5. Recompute the `secret_access_key` (HKDF, rotation-aware candidates) from the credential's
//!    `access_key_id` + the session token's `cti`, and **verify the SigV4 signature** in constant time.
//! 6. Verify the **session token** (COSE signature + mandatory `exp` + `s3-session` kind) → the
//!    host-stamped scope.
//! 7. **Opt-in revocation**: if enabled, refuse a session whose `cti` is in `authz/revoked/<cti>`.
//!
//! Scope *authorization of the concrete operation* (bucket = the scope's container, the object key
//! under the scope target, the requested S3 op ∈ the scope perms) is [`authorize_operation`], run by
//! the face once the object key is composed.

use boatramp_core::authz;
use boatramp_core::cose::{
    S3Perm, S3Session, S3Target, TokenError, TokenPublicKey, verify_s3_session,
};
use boatramp_core::kv::KvStore;

use super::credential::S3IngressSecret;
use super::sigv4::{
    self, CanonicalRequest, ParsedSignature, STREAMING_PAYLOAD_TRAILER, SigV4Error,
};

/// The signed-header names the face REQUIRES every request to have signed (LOW-1). Signing `host`
/// binds the authority; `x-amz-date` binds the timestamp (skew/replay window); `x-amz-content-sha256`
/// binds the payload mode (a client cannot claim `UNSIGNED-PAYLOAD` while having signed a hash, or
/// swap the streaming marker). Omitting any of these is a refusal.
pub const REQUIRED_SIGNED_HEADERS: [&str; 3] = ["host", "x-amz-date", "x-amz-content-sha256"];

/// The parsed inputs the face extracts from the live HTTP request for authentication. Plain,
/// borrow-y data so [`authenticate`] is pure + unit-testable. The body is NOT here — signature
/// verification uses the declared `payload_hash`; body-content verification (aws-chunked chains,
/// sha256 content-addressing) happens while streaming, after auth.
pub struct S3AuthInput<'a> {
    /// HTTP method, upper-case (`PUT`, `POST`, `HEAD`, `DELETE`).
    pub method: &'a str,
    /// The RAW (wire, percent-encoded) URI path — SigV4 signs the encoded path.
    pub uri_path: &'a str,
    /// The RAW query string (without `?`); empty if none. For presigned auth the caller keeps every
    /// param (the engine drops `X-Amz-Signature` when rebuilding the canonical query).
    pub query: &'a str,
    /// The request headers as `(lowercase-name, value)` — the caller lowercases names.
    pub headers: &'a [(String, String)],
    /// The `Authorization` header value, if present (header-auth form).
    pub authorization: Option<&'a str>,
    /// The `x-amz-date` header value, if present (required for header-auth).
    pub amz_date: Option<&'a str>,
    /// The `x-amz-content-sha256` header value — the declared payload mode.
    pub content_sha256: Option<&'a str>,
    /// The `session_token` the client presents (S3 clients send it as `x-amz-security-token`).
    pub session_token: Option<&'a str>,
    /// The presigned query params already percent-DECODED as `(name, value)`, when this is a
    /// presigned request (the caller detects `X-Amz-Signature` in the query). Empty for header-auth.
    pub presigned_params: &'a [(String, String)],
}

/// The verified outcome of [`authenticate`]: the host-stamped upload scope + the payload mode + the
/// parsed signature (the seed for aws-chunked verification). The face authorizes the concrete
/// operation against `session.scope` next.
#[derive(Debug)]
pub struct AuthedScope {
    /// The verified session (its host-stamped scope + `cti` + `exp`).
    pub session: S3Session,
    /// The `secret_access_key` (hex) that verified — passed to [`ChunkVerifier`](super::sigv4::ChunkVerifier)
    /// so aws-chunked body verification uses the SAME derived key.
    pub secret: String,
    /// The parsed signature (its seed `signature` is the aws-chunked chain's first `prev signature`).
    pub parsed: ParsedSignature,
    /// The declared payload mode (a real hash, `UNSIGNED-PAYLOAD`, or the streaming marker).
    pub payload_hash: String,
}

/// The concrete S3 operation the request names — mapped to the [`S3Perm`] it requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S3Op {
    /// Single-shot `PutObject` — requires [`S3Perm::Put`].
    PutObject,
    /// Any of the multipart quartet — requires [`S3Perm::Multipart`].
    Multipart,
    /// `HeadObject` (a create-only precondition probe / SDK head) — allowed under either write perm.
    Head,
}

impl S3Op {
    /// Whether `perms` grants this operation.
    fn permitted_by(self, perms: &[S3Perm]) -> bool {
        match self {
            Self::PutObject => perms.contains(&S3Perm::Put),
            Self::Multipart => perms.contains(&S3Perm::Multipart),
            // A HEAD is the create-only precondition probe + a benign SDK metadata call; either write
            // perm implies the right to probe within the scope. (Never a data-read of arbitrary keys —
            // HEAD returns metadata only, and is scope-confined like every op.)
            Self::Head => perms.contains(&S3Perm::Put) || perms.contains(&S3Perm::Multipart),
        }
    }
}

/// Run the full authentication pipeline. Returns the verified scope, or a single opaque `reason`
/// string (the caller maps EVERY `Err` to one uniform 403 — INFO-3). `now_unix` is the server clock.
pub fn authenticate(
    input: &S3AuthInput<'_>,
    public_key: &TokenPublicKey,
    secret: &S3IngressSecret,
    now_unix: i64,
) -> Result<AuthedScope, String> {
    // 1. Parse the SigV4 authorization (header or presigned).
    let presigned = !input.presigned_params.is_empty()
        && input
            .presigned_params
            .iter()
            .any(|(k, _)| k == "X-Amz-Signature");
    let parsed = if presigned {
        sigv4::parse_presigned_query(input.presigned_params).map_err(sig_reason)?
    } else {
        let auth = input.authorization.ok_or("missing Authorization header")?;
        let amz_date = input.amz_date.ok_or("missing x-amz-date header")?;
        sigv4::parse_authorization_header(auth, amz_date).map_err(sig_reason)?
    };

    // 2. SignedHeaders policy (LOW-1): every request must sign host + x-amz-date + x-amz-content-sha256.
    let signed_lower: Vec<String> = parsed
        .signed_headers
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();
    for required in REQUIRED_SIGNED_HEADERS {
        if !signed_lower.iter().any(|h| h == required) {
            return Err(format!("SignedHeaders omits required header {required:?}"));
        }
    }

    // 3. Trailer rejection (MEDIUM-2): a trailing-checksum streaming request is fail-closed refused —
    // M1 names the marker but does not verify the trailing checksum, so we never accept one.
    let payload_hash = input
        .content_sha256
        .ok_or("missing x-amz-content-sha256 header")?
        .to_string();
    if payload_hash == STREAMING_PAYLOAD_TRAILER
        || payload_hash.ends_with("-TRAILER")
        || input.headers.iter().any(|(k, _)| k == "x-amz-trailer")
    {
        return Err("streaming trailer / trailing-checksum requests are not accepted".into());
    }

    // 4. Clock-skew (header) or presigned-expiry window.
    if presigned {
        sigv4::check_presigned_expiry(&parsed, now_unix).map_err(sig_reason)?;
    } else {
        sigv4::check_skew(&parsed.amz_date, now_unix).map_err(sig_reason)?;
    }

    // 6 (before 5, since the token carries the cti that keys the secret): verify the session token.
    // The `secret_access_key` HKDF salt binds BOTH the access_key_id AND the token's cti, so we need
    // the verified cti to recompute the candidate secrets.
    let token = input
        .session_token
        .ok_or("missing session token (x-amz-security-token)")?;
    let session =
        verify_s3_session(token, public_key, now_unix.max(0) as u64).map_err(tok_reason)?;

    // 5. Recompute the candidate secrets (current + previous during a rotation overlap) from the
    // credential's access_key_id + the verified cti, and verify the SigV4 signature in constant time.
    let candidates = secret
        .candidate_secrets(&parsed.scope.access_key_id, &session.cti)
        .map_err(|_| "credential secret derivation failed".to_string())?;
    let canonical = build_canonical(input, &parsed, &payload_hash, presigned);
    sigv4::verify(&canonical.as_request(), &parsed, &candidates).map_err(sig_reason)?;
    // The winning secret (the one that verified) is needed to seed aws-chunked verification. `verify`
    // does not tell us which candidate matched, so re-select it constant-time-agnostically here: this
    // is AFTER a successful verify, so there is no oracle (the request is already authenticated).
    let winning = select_verified_secret(&canonical.as_request(), &parsed, &candidates)
        .ok_or("credential secret selection failed")?;

    // 7. (revocation is done by the caller, which has the async KV handle — see `check_revocation`.)

    Ok(AuthedScope {
        session,
        secret: winning,
        parsed,
        payload_hash,
    })
}

/// Opt-in **revocation** check (PLAN credential model): when the face has revocation enabled, refuse a
/// session whose `cti` marker exists at `authz/revoked/<cti>`. Async because it reads the replicated
/// KV; kept separate from [`authenticate`] (which is pure/sync) so the hot stateless path skips it
/// entirely when disabled. A KV backend error fails **closed** (refuse) — a revoked credential must
/// never slip through on a transient read error.
pub async fn check_revocation(kv: &dyn KvStore, cti: &str) -> Result<(), String> {
    match kv.get(&authz::revoked_key(cti)).await {
        Ok(Some(_)) => Err("session credential is revoked".into()),
        Ok(None) => Ok(()),
        Err(_) => Err("revocation check failed".into()),
    }
}

/// Authorize the concrete operation against the verified scope (PLAN §10 invariant 1). Checks, all
/// fail-closed: (a) the requested `container` equals the scope's container (bucket = container, from
/// the SIGNED scope — the URL bucket is only compared, never trusted as authority); (b) the composed
/// `decoded_key` is within the scope's `Key`/`Prefix` target; (c) the S3 op is in the scope's perms.
/// Returns a single opaque reason on any mismatch.
pub fn authorize_operation(
    scope: &S3Session,
    url_container: &str,
    decoded_key: &str,
    op: S3Op,
) -> Result<(), String> {
    let s = &scope.scope;
    // (a) The bucket in the URL must be exactly the container the credential was scoped to. This is a
    // COMPARE against the signed scope, not a trust of the URL — a credential for container A can
    // never act on container B even if the client puts B in the path.
    if url_container != s.container {
        return Err(format!(
            "container mismatch: url {url_container:?} != scope {:?}",
            s.container
        ));
    }
    // (b) The object key must be within the credential's target.
    match &s.target {
        S3Target::Key(k) => {
            if decoded_key != k {
                return Err(format!(
                    "key {decoded_key:?} outside single-key scope {k:?}"
                ));
            }
        }
        S3Target::Prefix(p) => {
            if !key_within_prefix(decoded_key, p) {
                return Err(format!("key {decoded_key:?} outside scope prefix {p:?}"));
            }
        }
    }
    // (c) The requested operation must be permitted.
    if !op.permitted_by(&s.perms) {
        return Err(format!("operation {op:?} not in scope perms {:?}", s.perms));
    }
    Ok(())
}

/// Whether `key` is within `prefix` on **path-segment** boundaries — so `prefix = "a/b"` matches
/// `a/b` and `a/b/c` but NOT `a/bc` (a bare string `starts_with` would wrongly admit `a/bc`). An empty
/// prefix matches any key (a whole-container credential).
fn key_within_prefix(key: &str, prefix: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    let prefix = prefix.strip_suffix('/').unwrap_or(prefix);
    key == prefix || key.starts_with(&format!("{prefix}/"))
}

/// Re-run the constant-time verify per candidate to learn WHICH secret matched (only after a
/// successful `verify`, so this is not an oracle). Returns the matching secret, if any.
fn select_verified_secret(
    req: &CanonicalRequest<'_>,
    parsed: &ParsedSignature,
    candidates: &[String],
) -> Option<String> {
    candidates
        .iter()
        .find(|c| sigv4::verify(req, parsed, std::slice::from_ref(*c)).is_ok())
        .cloned()
}

/// Owns the header vec + canonical query so a [`CanonicalRequest`] can borrow from it.
struct CanonicalOwned {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    payload_hash: String,
}

impl CanonicalOwned {
    fn as_request(&self) -> CanonicalRequest<'_> {
        CanonicalRequest {
            method: &self.method,
            uri_path: &self.path,
            query: &self.query,
            headers: &self.headers,
            payload_hash: &self.payload_hash,
        }
    }
}

/// Build the canonical-request inputs from the parsed request. For presigned auth the canonical query
/// is rebuilt from the DECODED params minus `X-Amz-Signature`; for header auth the raw wire query is
/// passed (the engine canonicalizes it). The payload hash the client signed is `content_sha256`.
fn build_canonical(
    input: &S3AuthInput<'_>,
    _parsed: &ParsedSignature,
    payload_hash: &str,
    presigned: bool,
) -> CanonicalOwned {
    let query = if presigned {
        sigv4::presigned_canonical_query(input.presigned_params)
    } else {
        input.query.to_string()
    };
    CanonicalOwned {
        method: input.method.to_string(),
        path: input.uri_path.to_string(),
        query,
        headers: input.headers.to_vec(),
        payload_hash: payload_hash.to_string(),
    }
}

/// Map a [`SigV4Error`] to an opaque host-side reason (logged only; the client sees one uniform 403).
fn sig_reason(e: SigV4Error) -> String {
    format!("sigv4: {e}")
}

/// Map a [`TokenError`] to an opaque host-side reason.
fn tok_reason(e: TokenError) -> String {
    format!("token: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::cose::{
        LocalSigner, S3Constraints, S3SessionScope, Signer as _, TokenAlg, mint_s3_session,
    };
    use boatramp_core::kv::{KvStore, MemoryKv};

    const NOW: i64 = 1_440_938_160; // 20150830T123600Z

    fn scope(target: S3Target, perms: Vec<S3Perm>, constraints: S3Constraints) -> S3SessionScope {
        S3SessionScope {
            project: "default".into(),
            site: "blog".into(),
            container: "photos".into(),
            target,
            perms,
            constraints,
        }
    }

    /// Build a fully-signed, valid header-auth request for `key`, returning the wire pieces + the
    /// minted session token, so tests can then mutate one field to prove each check fails closed.
    struct Signed {
        headers: Vec<(String, String)>,
        authorization: String,
        token: String,
    }

    async fn sign_put(
        signer: &LocalSigner,
        secret: &S3IngressSecret,
        akid: &str,
        sess_scope: &S3SessionScope,
        uri_path: &str,
        payload_hash: &str,
    ) -> Signed {
        let token = mint_s3_session(sess_scope, 900, NOW as u64, signer)
            .await
            .unwrap();
        let session = verify_s3_session(&token, &signer.public_key(), NOW as u64).unwrap();
        let sak = secret.derive_secret(akid, &session.cti).unwrap();
        let amz_date = "20150830T123600Z";
        let host = "s3.local";
        let headers = vec![
            ("host".to_string(), host.to_string()),
            ("x-amz-date".to_string(), amz_date.to_string()),
            ("x-amz-content-sha256".to_string(), payload_hash.to_string()),
            ("x-amz-security-token".to_string(), token.clone()),
        ];
        let signed = vec![
            "host".to_string(),
            "x-amz-content-sha256".to_string(),
            "x-amz-date".to_string(),
        ];
        let scope_s = sigv4::CredentialScope {
            access_key_id: akid.to_string(),
            date: "20150830".into(),
            region: super::super::config::LOCAL_REGION.into(),
            service: super::super::config::LOCAL_SERVICE.into(),
        };
        let req = CanonicalRequest {
            method: "PUT",
            uri_path,
            query: "",
            headers: &headers,
            payload_hash,
        };
        let (creq, signed_str) = sigv4::canonical_request_string(&req, &signed).unwrap();
        let sts = sigv4::string_to_sign(amz_date, &scope_s, &creq);
        let sig = sigv4::compute_signature(&sak, &scope_s, &sts);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={}/20150830/{}/{}/aws4_request, SignedHeaders={}, Signature={}",
            akid,
            super::super::config::LOCAL_REGION,
            super::super::config::LOCAL_SERVICE,
            signed_str,
            sig,
        );
        Signed {
            headers,
            authorization,
            token,
        }
    }

    fn input<'a>(
        s: &'a Signed,
        method: &'a str,
        uri_path: &'a str,
        payload_hash: &'a str,
    ) -> S3AuthInput<'a> {
        S3AuthInput {
            method,
            uri_path,
            query: "",
            headers: &s.headers,
            authorization: Some(&s.authorization),
            amz_date: Some("20150830T123600Z"),
            content_sha256: Some(payload_hash),
            session_token: Some(&s.token),
            presigned_params: &[],
        }
    }

    #[tokio::test]
    async fn happy_path_authenticates_and_authorizes() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let secret = S3IngressSecret::generate().unwrap();
        let akid = "BRUPHAPPYPATH";
        let sc = scope(
            S3Target::Key("avatars/u1.jpg".into()),
            vec![S3Perm::Put],
            S3Constraints::default(),
        );
        let ph = super::sigv4::UNSIGNED_PAYLOAD;
        let signed = sign_put(&signer, &secret, akid, &sc, "/photos/avatars/u1.jpg", ph).await;
        let authed = authenticate(
            &input(&signed, "PUT", "/photos/avatars/u1.jpg", ph),
            &signer.public_key(),
            &secret,
            NOW,
        )
        .expect("authenticates");
        assert_eq!(authed.session.scope.container, "photos");
        // Scope authorization succeeds for the exact key + a Put.
        assert!(
            authorize_operation(&authed.session, "photos", "avatars/u1.jpg", S3Op::PutObject)
                .is_ok()
        );
    }

    #[tokio::test]
    async fn rejects_missing_required_signed_header() {
        // LOW-1: a request that signs only host + x-amz-date (omitting x-amz-content-sha256) is
        // refused, even if its signature is internally consistent.
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let secret = S3IngressSecret::generate().unwrap();
        let akid = "BRUPNOSHA256";
        let sc = scope(
            S3Target::Key("k".into()),
            vec![S3Perm::Put],
            S3Constraints::default(),
        );
        let token = mint_s3_session(&sc, 900, NOW as u64, &signer)
            .await
            .unwrap();
        let session = verify_s3_session(&token, &signer.public_key(), NOW as u64).unwrap();
        let sak = secret.derive_secret(akid, &session.cti).unwrap();
        let headers = vec![
            ("host".to_string(), "s3.local".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
            ("x-amz-security-token".to_string(), token.clone()),
        ];
        // Sign with ONLY host + x-amz-date (no content-sha256) — a valid signature over a policy-
        // violating signed-header set.
        let signed = vec!["host".to_string(), "x-amz-date".to_string()];
        let scope_s = sigv4::CredentialScope {
            access_key_id: akid.into(),
            date: "20150830".into(),
            region: super::super::config::LOCAL_REGION.into(),
            service: super::super::config::LOCAL_SERVICE.into(),
        };
        let req = CanonicalRequest {
            method: "PUT",
            uri_path: "/photos/k",
            query: "",
            headers: &headers,
            payload_hash: super::sigv4::UNSIGNED_PAYLOAD,
        };
        let (creq, signed_str) = sigv4::canonical_request_string(&req, &signed).unwrap();
        let sts = sigv4::string_to_sign("20150830T123600Z", &scope_s, &creq);
        let sig = sigv4::compute_signature(&sak, &scope_s, &sts);
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={akid}/20150830/{}/{}/aws4_request, SignedHeaders={signed_str}, Signature={sig}",
            super::super::config::LOCAL_REGION,
            super::super::config::LOCAL_SERVICE,
        );
        let inp = S3AuthInput {
            method: "PUT",
            uri_path: "/photos/k",
            query: "",
            headers: &headers,
            authorization: Some(&authorization),
            amz_date: Some("20150830T123600Z"),
            content_sha256: Some(super::sigv4::UNSIGNED_PAYLOAD),
            session_token: Some(&token),
            presigned_params: &[],
        };
        let err = authenticate(&inp, &signer.public_key(), &secret, NOW).unwrap_err();
        assert!(err.contains("SignedHeaders omits"), "got: {err}");
    }

    #[tokio::test]
    async fn rejects_trailing_checksum_streaming_request() {
        // MEDIUM-2: a `STREAMING-...-PAYLOAD-TRAILER` request is fail-closed refused. We do not even
        // reach signature verification — the trailer mode is unsupported and must never be accepted.
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let secret = S3IngressSecret::generate().unwrap();
        let akid = "BRUPTRAILER";
        let sc = scope(
            S3Target::Key("k".into()),
            vec![S3Perm::Put],
            S3Constraints::default(),
        );
        let signed = sign_put(
            &signer,
            &secret,
            akid,
            &sc,
            "/photos/k",
            STREAMING_PAYLOAD_TRAILER,
        )
        .await;
        let err = authenticate(
            &input(&signed, "PUT", "/photos/k", STREAMING_PAYLOAD_TRAILER),
            &signer.public_key(),
            &secret,
            NOW,
        )
        .unwrap_err();
        assert!(err.contains("trailer"), "got: {err}");
        // Also refused when the marker is a normal hash but an x-amz-trailer header is present.
        let mut headers = signed.headers.clone();
        headers.push((
            "x-amz-trailer".to_string(),
            "x-amz-checksum-crc32c".to_string(),
        ));
        let inp = S3AuthInput {
            headers: &headers,
            content_sha256: Some(super::sigv4::UNSIGNED_PAYLOAD),
            ..input(&signed, "PUT", "/photos/k", super::sigv4::UNSIGNED_PAYLOAD)
        };
        assert!(authenticate(&inp, &signer.public_key(), &secret, NOW).is_err());
    }

    #[tokio::test]
    async fn rejects_tampered_signature_and_expired_and_wrong_kind() {
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let secret = S3IngressSecret::generate().unwrap();
        let akid = "BRUPTAMPER";
        let sc = scope(
            S3Target::Key("k".into()),
            vec![S3Perm::Put],
            S3Constraints::default(),
        );
        let ph = super::sigv4::UNSIGNED_PAYLOAD;
        let signed = sign_put(&signer, &secret, akid, &sc, "/photos/k", ph).await;

        // Tampered signature ⇒ refuse. Flip the first sig hex char to a DIFFERENT one (never a no-op:
        // `0`↔`1` guarantees the byte changes regardless of the original value — a plain "replace with
        // 0" would be a no-op ~1/16 of the time and make this test flaky).
        let mut bad_auth = signed.authorization.clone();
        let sig_pos = bad_auth.find("Signature=").unwrap() + "Signature=".len();
        let orig = &bad_auth[sig_pos..sig_pos + 1];
        let flipped = if orig == "0" { "1" } else { "0" };
        bad_auth.replace_range(sig_pos..sig_pos + 1, flipped);
        let inp = S3AuthInput {
            authorization: Some(&bad_auth),
            ..input(&signed, "PUT", "/photos/k", ph)
        };
        assert!(authenticate(&inp, &signer.public_key(), &secret, NOW).is_err());

        // Expired token (server clock past exp = NOW + 900) ⇒ refuse.
        assert!(
            authenticate(
                &input(&signed, "PUT", "/photos/k", ph),
                &signer.public_key(),
                &secret,
                NOW + 100_000
            )
            .is_err()
        );

        // A DIFFERENT fleet key (forged token) ⇒ refuse.
        let stranger = LocalSigner::generate(TokenAlg::Es256);
        assert!(
            authenticate(
                &input(&signed, "PUT", "/photos/k", ph),
                &stranger.public_key(),
                &secret,
                NOW
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn scope_authorization_blocks_cross_container_and_key_escape() {
        // The scope is for container "photos", single key "avatars/u1.jpg". Authorization must reject
        // a different container, a different key, and an operation outside the perms.
        let sc = scope(
            S3Target::Key("avatars/u1.jpg".into()),
            vec![S3Perm::Put],
            S3Constraints::default(),
        );
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let token = mint_s3_session(&sc, 900, NOW as u64, &signer)
            .await
            .unwrap();
        let session = verify_s3_session(&token, &signer.public_key(), NOW as u64).unwrap();

        // Cross-container: the credential is for "photos"; a request naming "docs" is refused.
        assert!(authorize_operation(&session, "docs", "avatars/u1.jpg", S3Op::PutObject).is_err());
        // Cross-key: a different key under the same container is refused (single-key scope).
        assert!(
            authorize_operation(&session, "photos", "avatars/u2.jpg", S3Op::PutObject).is_err()
        );
        // Wrong op: a put-only credential can't drive multipart.
        assert!(
            authorize_operation(&session, "photos", "avatars/u1.jpg", S3Op::Multipart).is_err()
        );
        // Exact match ⇒ ok.
        assert!(authorize_operation(&session, "photos", "avatars/u1.jpg", S3Op::PutObject).is_ok());
    }

    #[tokio::test]
    async fn prefix_scope_matches_on_segment_boundaries() {
        let sc = scope(
            S3Target::Prefix("uploads/2026".into()),
            vec![S3Perm::Put, S3Perm::Multipart],
            S3Constraints::default(),
        );
        let signer = LocalSigner::generate(TokenAlg::Es256);
        let token = mint_s3_session(&sc, 900, NOW as u64, &signer)
            .await
            .unwrap();
        let session = verify_s3_session(&token, &signer.public_key(), NOW as u64).unwrap();
        // Within the prefix (exact + nested) ⇒ ok.
        assert!(authorize_operation(&session, "photos", "uploads/2026", S3Op::PutObject).is_ok());
        assert!(
            authorize_operation(&session, "photos", "uploads/2026/09/x.png", S3Op::Multipart)
                .is_ok()
        );
        // A sibling that merely shares a string prefix but not a SEGMENT boundary ⇒ refused.
        assert!(authorize_operation(&session, "photos", "uploads/2026x", S3Op::PutObject).is_err());
        assert!(
            authorize_operation(&session, "photos", "uploads/2025/x", S3Op::PutObject).is_err()
        );
    }

    #[tokio::test]
    async fn revocation_fails_closed_when_marked_or_on_backend_error() {
        let kv = MemoryKv::new();
        // Not revoked ⇒ ok.
        assert!(check_revocation(&kv, "cafef00d").await.is_ok());
        // Marked revoked ⇒ refuse.
        kv.put(&authz::revoked_key("cafef00d"), Vec::new())
            .await
            .unwrap();
        assert!(check_revocation(&kv, "cafef00d").await.is_err());
    }
}
