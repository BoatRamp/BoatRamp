//! Hand-rolled **Shared Key** (account-key / Azurite-emulator) request signing for the GA Azure
//! SDK 1.x.
//!
//! The 1.x Azure SDK generation is AAD/[`TokenCredential`]-first and **dropped** native shared-key /
//! account-key + connection-string auth (the `azure_storage` crate that held
//! `StorageCredentials::access_key` has no 1.x release). boatramp authenticates its Azure storage
//! backend with an **operator-supplied account key** (`AzureOptions.access_key`) or the **Azurite**
//! emulator (well-known key), so this module preserves that non-breaking capability by implementing
//! an [`azure_core`][azure_core_v1] pipeline [`Policy`] that signs each request per-try with Azure's
//! canonical Shared Key **string-to-sign** (HMAC-SHA256, base64-decoded key).
//!
//! This is **signing code**: a canonicalization error 403s every request (breaking read / write /
//! watch at once), and a wrong one could authorize the wrong request. The construction below reproduces the
//! algorithm from the (now-dropped) `azure_storage` 0.21 `AuthorizationPolicy` — itself the vetted
//! reference — and is pinned by unit-test vectors from the Microsoft "Call REST API operations with
//! Shared Key authorization" docs (a blob List Blobs example) plus a queue-shaped vector and a
//! SAS-present skip test. See the `tests` module.
//!
//! Blob and Queue Storage share the **identical** string-to-sign (both use the non-Table shape); the
//! [`SharedKeyResource`] marker exists only to document the intent at each call site (and to leave a
//! seam should a future divergence appear). Table storage — which canonicalizes differently — is not
//! a boatramp backend and is deliberately not implemented.
//!
//! The account key is held host-side as a base64 string and is **never** logged: the policy's
//! [`Debug`] impl redacts it, and the type is not `Serialize`.

use std::sync::Arc;

use azure_core_v1::Result;
use azure_core_v1::credentials::Secret;
use azure_core_v1::http::headers::{HeaderName, Headers};
use azure_core_v1::http::policies::{Policy, PolicyResult};
use azure_core_v1::http::{Context, Method, Request, Url};
use azure_core_v1::time::{OffsetDateTime, to_rfc7231};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// The `x-ms-date` header (the request timestamp the signature covers). Restamped per-try so a
/// retried request is re-signed with a fresh, non-stale date.
const X_MS_DATE: HeaderName = HeaderName::from_static("x-ms-date");
/// The `Authorization` header the signature is written into.
const AUTHORIZATION: HeaderName = HeaderName::from_static("authorization");
/// The `Content-Length` header — stamped from the body before signing so the signed value matches
/// the wire value the transport computes (see the note in [`Policy::send`]).
const CONTENT_LENGTH: HeaderName = HeaderName::from_static("content-length");

/// Which Storage service the request targets. Blob and Queue produce the identical Shared Key
/// string-to-sign; this marker documents the call-site intent and reserves a seam for any future
/// per-service divergence. (Table storage canonicalizes differently and is not implemented.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedKeyResource {
    /// Blob service (`*.blob.core.windows.net`).
    Blob,
    /// Queue service (`*.queue.core.windows.net`).
    Queue,
}

/// An [`azure_core`][azure_core_v1] pipeline policy that authenticates each request with Azure
/// **Shared Key** (account key) auth. Inject it via `ClientOptions::per_try_policies` on the
/// blob/queue service-client options so it runs on every (re)try, after the retry policy — the point
/// where a fresh `x-ms-date` must be stamped.
///
/// If the request URL already carries a SAS `sig` query parameter, signing is **skipped** (the SAS
/// is the authorization) — mirroring the reference behavior and preventing a double-auth.
#[derive(Clone)]
pub struct SharedKeyAuthorizationPolicy {
    account: String,
    /// The base64-encoded account key, wrapped in [`Secret`] so it is not accidentally logged.
    key: Secret,
    resource: SharedKeyResource,
}

impl std::fmt::Debug for SharedKeyAuthorizationPolicy {
    /// Redacts the key material — this type carries a storage account secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedKeyAuthorizationPolicy")
            .field("account", &self.account)
            .field("key", &"<redacted>")
            .field("resource", &self.resource)
            .finish()
    }
}

impl SharedKeyAuthorizationPolicy {
    /// Build a policy from the storage account name and its **base64-encoded** account key.
    pub fn new(
        account: impl Into<String>,
        key: impl Into<String>,
        resource: SharedKeyResource,
    ) -> Self {
        Self {
            account: account.into(),
            key: Secret::new(key.into()),
            resource,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
impl Policy for SharedKeyAuthorizationPolicy {
    async fn send(
        &self,
        ctx: &Context,
        request: &mut Request,
        next: &[Arc<dyn Policy>],
    ) -> PolicyResult {
        // A SAS-authorized request carries its own signature — never overwrite it with Shared Key.
        let has_sas = request.url().query_pairs().any(|(k, _)| k == "sig");
        if !has_sas {
            // Stamp a fresh timestamp for THIS try, then sign over it (the signature must cover the
            // exact `x-ms-date` sent, so date and signature are set together, per-try).
            let date = to_rfc7231(&OffsetDateTime::now_utc());
            request.insert_header(X_MS_DATE, date);

            // Stamp `content-length` from the request body BEFORE building the string-to-sign, so
            // the signed value matches what the transport puts on the wire. The 1.x generated SDK
            // sets `content-length` on some body requests (e.g. `stage_block`) but NOT all: notably
            // `commit_block_list` omits it, and the transport (`reqwest`) then computes it from the
            // body at send time — AFTER this policy has signed. Signing a blank Content-Length slot
            // while the server sees the real length in its string-to-sign yields a signature
            // mismatch → 403 on every write. The 0.21 `azure_storage::finalize_request` always
            // stamped Content-Length before its `AuthorizationPolicy` ran; mirror that here.
            //
            // Only stamp when absent and non-zero: a zero-length body is filtered to blank by the
            // string-to-sign (the 2015-02-21+ rule, see `string_to_sign`), so 0.21's `"0"` stamp
            // and our skip produce the identical signed value — and skipping avoids putting a
            // spurious `content-length: 0` on a bodyless request. boatramp write bodies are always
            // `Body::Bytes`, so `.len()` is `Some`.
            if request
                .headers()
                .get_optional_str(&CONTENT_LENGTH)
                .is_none()
                && let Some(len) = request.body().len()
                && len != 0
            {
                request.insert_header(CONTENT_LENGTH, len.to_string());
            }

            let string_to_sign = string_to_sign(
                request.headers(),
                request.url(),
                request.method(),
                &self.account,
            );
            let signature = sign(&string_to_sign, &self.key)?;
            request.insert_header(
                AUTHORIZATION,
                format!("SharedKey {}:{}", self.account, signature),
            );
        }
        next[0].send(ctx, request, &next[1..]).await
    }
}

/// HMAC-SHA256 the `string_to_sign` with the **base64-decoded** account key and base64-encode the
/// signature — exactly Azure's Shared Key MAC.
fn sign(string_to_sign: &str, key: &Secret) -> Result<String> {
    // Reject an empty account key fail-closed. An empty string is valid base64 (decodes to zero
    // bytes) and HMAC-SHA256 accepts a zero-length key, so without this guard an empty key would
    // silently produce a well-formed but WRONG signature (a 403 with no hint of the real cause)
    // instead of an honest credential error.
    if key.secret().is_empty() {
        return Err(azure_core_v1::Error::with_message(
            azure_core_v1::error::ErrorKind::Credential,
            "Azure account key is empty",
        ));
    }
    let key_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, key.secret()).map_err(
            // NB: do NOT interpolate the `DecodeError` — its `Display` echoes a byte of the
            // rejected key, which is secret material. Keep the message generic.
            |_| {
                azure_core_v1::Error::with_message(
                    azure_core_v1::error::ErrorKind::Credential,
                    "Azure account key is not valid base64",
                )
            },
        )?;
    let mut mac = <Hmac<Sha256>>::new_from_slice(&key_bytes).map_err(|e| {
        azure_core_v1::Error::with_message(
            azure_core_v1::error::ErrorKind::Credential,
            format!("failed to init HMAC from Azure account key: {e}"),
        )
    })?;
    mac.update(string_to_sign.as_bytes());
    let out = mac.finalize().into_bytes();
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        out,
    ))
}

/// Read a header's value, or the empty string when absent.
fn header_or_empty<'a>(headers: &'a Headers, name: &HeaderName) -> &'a str {
    headers.get_optional_str(name).unwrap_or_default()
}

/// Build the canonical Shared Key **string-to-sign** for a Blob/Queue request:
///
/// ```text
/// VERB \n Content-Encoding \n Content-Language \n Content-Length \n Content-MD5 \n Content-Type \n
/// Date \n If-Modified-Since \n If-Match \n If-None-Match \n If-Unmodified-Since \n Range \n
/// CanonicalizedHeaders CanonicalizedResource
/// ```
///
/// `Content-Length` is the empty string when absent **or "0"** (the 2015-02-21+ rule). The `Date`
/// slot is empty because boatramp always sends `x-ms-date` (which lands in `CanonicalizedHeaders`).
fn string_to_sign(headers: &Headers, url: &Url, method: Method, account: &str) -> String {
    let content_length = headers
        .get_optional_str(&HeaderName::from_static("content-length"))
        .filter(|&v| v != "0")
        .unwrap_or_default();
    format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}{}",
        method.as_ref(),
        header_or_empty(headers, &HeaderName::from_static("content-encoding")),
        header_or_empty(headers, &HeaderName::from_static("content-language")),
        content_length,
        header_or_empty(headers, &HeaderName::from_static("content-md5")),
        header_or_empty(headers, &HeaderName::from_static("content-type")),
        header_or_empty(headers, &HeaderName::from_static("date")),
        header_or_empty(headers, &HeaderName::from_static("if-modified-since")),
        header_or_empty(headers, &HeaderName::from_static("if-match")),
        header_or_empty(headers, &HeaderName::from_static("if-none-match")),
        header_or_empty(headers, &HeaderName::from_static("if-unmodified-since")),
        header_or_empty(headers, &HeaderName::from_static("range")),
        canonicalized_headers(headers),
        canonicalized_resource(account, url),
    )
}

/// `CanonicalizedHeaders`: every `x-ms-*` header, lowercased name, sorted ascending, each rendered
/// `name:value\n`. (The SDK header store already lowercases names; sorting is done here regardless so
/// the output is deterministic despite the underlying `HashMap` iteration order.)
fn canonicalized_headers(headers: &Headers) -> String {
    let mut names: Vec<&HeaderName> = headers
        .iter()
        .filter_map(|(name, _)| name.as_str().starts_with("x-ms-").then_some(name))
        .collect();
    names.sort_unstable_by(|a, b| a.as_str().cmp(b.as_str()));

    let mut out = String::new();
    for name in names {
        let value = headers.get_optional_str(name).unwrap_or_default();
        out.push_str(name.as_str());
        out.push(':');
        out.push_str(value);
        out.push('\n');
    }
    out
}

/// `CanonicalizedResource`: `/{account}{path}` followed by each query parameter (lowercased key)
/// sorted ascending, rendered `\nkey:v1,v2` (values within a key sorted, comma-joined). This matches
/// Azure's documented canonicalized-resource form for Blob/Queue.
fn canonicalized_resource(account: &str, url: &Url) -> String {
    let mut res = String::new();
    res.push('/');
    res.push_str(account);
    // Preserve the exact (already percent-encoded) path segments the SDK put on the URL.
    for seg in url.path_segments().into_iter().flatten() {
        res.push('/');
        res.push_str(seg);
    }

    // Collect distinct query-parameter keys, sorted; for each, its values sorted + comma-joined.
    let mut keys: Vec<String> = Vec::new();
    for (k, _) in url.query_pairs() {
        let k = k.into_owned();
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    keys.sort();
    for key in keys {
        let mut values: Vec<String> = url
            .query_pairs()
            .filter(|(k, _)| *k == key)
            .map(|(_, v)| v.into_owned())
            .collect();
        values.sort();
        res.push('\n');
        res.push_str(&key.to_lowercase());
        res.push(':');
        res.push_str(&values.join(","));
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Azurite emulator well-known account + key (public dev credentials).
    const AZURITE_ACCOUNT: &str = "devstoreaccount1";
    const AZURITE_KEY: &str =
        "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";

    fn req(url: &str, method: Method) -> Request {
        Request::new(Url::parse(url).unwrap(), method)
    }

    // ── Blob string-to-sign vector (Microsoft docs: "Call REST API operations with Shared Key
    // authorization", the *List blobs* example) ────────────────────────────────────────────────
    //
    // Account `contosorest`, GET https://contosorest.blob.core.windows.net/container-1?restype=container&comp=list
    // with headers x-ms-date: Fri, 17 Nov 2017 05:16:48 GMT and x-ms-version: 2017-07-29 yields the
    // documented MessageSignature:
    //   GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Fri, 17 Nov 2017 05:16:48 GMT\nx-ms-version:2017-07-29\n
    //   /contosorest/container-1\ncomp:list\nrestype:container
    #[test]
    fn blob_string_to_sign_matches_microsoft_docs_list_blobs_example() {
        let mut request = req(
            "https://contosorest.blob.core.windows.net/container-1?restype=container&comp=list",
            Method::Get,
        );
        request.insert_header(X_MS_DATE, "Fri, 17 Nov 2017 05:16:48 GMT");
        request.insert_header(HeaderName::from_static("x-ms-version"), "2017-07-29");

        let sts = string_to_sign(
            request.headers(),
            request.url(),
            request.method(),
            "contosorest",
        );

        let expected = "GET\n\n\n\n\n\n\n\n\n\n\n\n\
             x-ms-date:Fri, 17 Nov 2017 05:16:48 GMT\nx-ms-version:2017-07-29\n\
             /contosorest/container-1\ncomp:list\nrestype:container";
        assert_eq!(sts, expected);
    }

    /// The docs also publish the two sub-strings independently; pin them too.
    #[test]
    fn blob_canonicalized_headers_and_resource_match_docs() {
        let mut request = req(
            "https://contosorest.blob.core.windows.net/container-1?restype=container&comp=list",
            Method::Get,
        );
        request.insert_header(X_MS_DATE, "Fri, 17 Nov 2017 05:16:48 GMT");
        request.insert_header(HeaderName::from_static("x-ms-version"), "2017-07-29");

        assert_eq!(
            canonicalized_headers(request.headers()),
            "x-ms-date:Fri, 17 Nov 2017 05:16:48 GMT\nx-ms-version:2017-07-29\n"
        );
        assert_eq!(
            canonicalized_resource("contosorest", request.url()),
            "/contosorest/container-1\ncomp:list\nrestype:container"
        );
    }

    /// A full end-to-end signature over the docs' blob string-to-sign, computed with the Azurite
    /// well-known key. This locks the whole path (canonicalization → HMAC-SHA256 → base64) to a
    /// fixed value: any drift in the string-to-sign OR the MAC changes this signature. (The docs'
    /// own signature uses `contosorest`'s private key, which is not public, so we sign the *docs'
    /// string-to-sign* with the *public Azurite key* — a self-consistent, reproducible vector.)
    #[test]
    fn blob_signature_is_stable_over_the_docs_string_to_sign() {
        let sts = "GET\n\n\n\n\n\n\n\n\n\n\n\n\
             x-ms-date:Fri, 17 Nov 2017 05:16:48 GMT\nx-ms-version:2017-07-29\n\
             /contosorest/container-1\ncomp:list\nrestype:container";
        let sig = sign(sts, &Secret::new(AZURITE_KEY.to_string())).unwrap();
        // Cross-checked against `openssl dgst -sha256 -mac HMAC` over the same
        // string-to-sign + key, so this locks the standard HMAC-SHA256/base64 path.
        assert_eq!(sig, "7Ce5bkhWrTDCEvnIn5jO2yDOiLFgW30xNQKq725ST5M=");
    }

    // ── Queue string-to-sign vector ─────────────────────────────────────────────────────────────
    //
    // A `receive_messages` on the Azurite emulator: GET
    // http://127.0.0.1:10001/devstoreaccount1/boatramp-hblob/messages?numofmessages=10 with
    // x-ms-date + x-ms-version. Queue canonicalization is identical to blob, so the resource is
    // /devstoreaccount1/... + the sorted query, and the string-to-sign has the same 12-newline
    // prefix. (Emulator queue port is 10001; the account name is a path segment.)
    #[test]
    fn queue_string_to_sign_has_the_same_shape_as_blob() {
        let mut request = req(
            "http://127.0.0.1:10001/devstoreaccount1/boatramp-hblob/messages?numofmessages=10",
            Method::Get,
        );
        request.insert_header(X_MS_DATE, "Fri, 17 Nov 2017 05:16:48 GMT");
        request.insert_header(HeaderName::from_static("x-ms-version"), "2018-03-28");

        let sts = string_to_sign(
            request.headers(),
            request.url(),
            request.method(),
            AZURITE_ACCOUNT,
        );
        let expected = "GET\n\n\n\n\n\n\n\n\n\n\n\n\
             x-ms-date:Fri, 17 Nov 2017 05:16:48 GMT\nx-ms-version:2018-03-28\n\
             /devstoreaccount1/devstoreaccount1/boatramp-hblob/messages\nnumofmessages:10";
        assert_eq!(sts, expected);
    }

    /// A queue signature is stable end-to-end with the Azurite key.
    #[test]
    fn queue_signature_is_stable() {
        let sts = "GET\n\n\n\n\n\n\n\n\n\n\n\n\
             x-ms-date:Fri, 17 Nov 2017 05:16:48 GMT\nx-ms-version:2018-03-28\n\
             /devstoreaccount1/devstoreaccount1/boatramp-hblob/messages\nnumofmessages:10";
        let sig = sign(sts, &Secret::new(AZURITE_KEY.to_string())).unwrap();
        // Cross-checked with `openssl dgst -sha256 -mac HMAC`; regression-lock — recompute
        // deliberately if the queue path shape ever changes.
        assert_eq!(sig, "NC9RQ71oyTgoBF4xtUTMCTVH8E2FBVt3M5PtYjOAG2k=");
    }

    // ── PUT with a body: Content-Length participates; Content-Type lands in its slot ────────────
    #[test]
    fn put_with_body_includes_content_length_and_type() {
        let mut request = req(
            "https://acct.blob.core.windows.net/c/blob.txt?comp=block&blockid=YnItYmxvY2s%3D",
            Method::Put,
        );
        request.insert_header(X_MS_DATE, "Fri, 17 Nov 2017 05:16:48 GMT");
        request.insert_header(HeaderName::from_static("x-ms-version"), "2021-12-02");
        request.insert_header(HeaderName::from_static("content-length"), "1024");
        request.insert_header(HeaderName::from_static("content-type"), "text/plain");

        let sts = string_to_sign(request.headers(), request.url(), request.method(), "acct");
        // VERB \n CE \n CL \n Content-Length \n MD5 \n Content-Type \n Date \n ... \n Range \n
        // canon-headers canon-resource
        let expected = "PUT\n\n\n1024\n\ntext/plain\n\n\n\n\n\n\n\
             x-ms-date:Fri, 17 Nov 2017 05:16:48 GMT\nx-ms-version:2021-12-02\n\
             /acct/c/blob.txt\nblockid:YnItYmxvY2s=\ncomp:block";
        assert_eq!(sts, expected);
    }

    // ── `commit_block_list` shape: body present, but the 1.x SDK does NOT pre-set content-length ──
    //
    // Regression lock for the CRITICAL that broke every Azure blob write: the generated 1.x
    // `commit_block_list` sends a body without stamping `content-length`, leaving the transport to
    // compute it AFTER this policy signs. Unless the policy stamps `content-length` from the body
    // before building the string-to-sign, the signed Content-Length slot is BLANK while the server
    // sees the real length → signature mismatch → 403. The GET-only docs vectors above never
    // exercised a body, so they missed this. This test drives the real `Policy::send` (the code
    // that does the stamping) and asserts the string-to-sign the policy would have signed carries
    // the body length in the Content-Length slot — reverting the stamp makes this assertion fail.
    #[tokio::test]
    async fn commit_block_list_shape_signs_body_length_not_blank() {
        use std::sync::Mutex;

        // A terminal policy that captures the request AFTER the Shared Key policy ran, so we can
        // rebuild the exact string-to-sign the policy signed over (post-stamp) and inspect it.
        #[derive(Debug)]
        struct Capture {
            content_length: Mutex<Option<String>>,
            signed_sts: Mutex<Option<String>>,
        }
        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        impl Policy for Capture {
            async fn send(
                &self,
                _ctx: &Context,
                request: &mut Request,
                _next: &[Arc<dyn Policy>],
            ) -> PolicyResult {
                *self.content_length.lock().unwrap() = request
                    .headers()
                    .get_optional_str(&CONTENT_LENGTH)
                    .map(str::to_string);
                *self.signed_sts.lock().unwrap() = Some(string_to_sign(
                    request.headers(),
                    request.url(),
                    request.method(),
                    "acct",
                ));
                Err(azure_core_v1::Error::with_message(
                    azure_core_v1::error::ErrorKind::Other,
                    "terminal test policy",
                ))
            }
        }

        // Mirror the SDK's `commit_block_list`: a PUT with a real body and NO pre-set
        // `content-length` header (the exact shape that regressed).
        let body = b"<BlockList><Latest>YnItYmxvY2s=</Latest></BlockList>";
        let mut request = Request::new(
            Url::parse("https://acct.blob.core.windows.net/c/blob.txt?comp=blocklist").unwrap(),
            Method::Put,
        );
        request.set_body(body.to_vec());
        assert!(
            request
                .headers()
                .get_optional_str(&CONTENT_LENGTH)
                .is_none(),
            "precondition: the SDK left content-length unset on commit_block_list"
        );

        let policy =
            SharedKeyAuthorizationPolicy::new("acct", AZURITE_KEY, SharedKeyResource::Blob);
        let capture = Arc::new(Capture {
            content_length: Mutex::new(None),
            signed_sts: Mutex::new(None),
        });
        let next: Vec<Arc<dyn Policy>> = vec![capture.clone()];
        let _ = policy.send(&Context::new(), &mut request, &next).await;

        // 1. The policy stamped the header from the body length (52 bytes) before signing.
        assert_eq!(
            capture.content_length.lock().unwrap().as_deref(),
            Some(body.len().to_string().as_str()),
            "the policy must stamp content-length from the body before signing"
        );

        // 2. The signed string-to-sign carries that length in its Content-Length slot (4th line) —
        //    NOT a blank. This is the assertion that fails if the stamp is reverted.
        let sts = capture.signed_sts.lock().unwrap().clone().unwrap();
        let content_length_slot = sts.split('\n').nth(3).unwrap();
        assert_eq!(
            content_length_slot,
            body.len().to_string(),
            "the signed Content-Length slot must equal the body length, not be blank; \
             string-to-sign was:\n{sts}"
        );
        // Full-shape lock for good measure: PUT, Content-Length in slot 4, comp:blocklist resource.
        assert_eq!(
            sts,
            format!(
                "PUT\n\n\n{}\n\n\n\n\n\n\n\n\n\
                 x-ms-date:{}\n\
                 /acct/c/blob.txt\ncomp:blocklist",
                body.len(),
                request.headers().get_optional_str(&X_MS_DATE).unwrap(),
            )
        );
    }

    /// A zero Content-Length is treated as absent (the 2015-02-21+ rule).
    #[test]
    fn zero_content_length_is_blank() {
        let mut request = req("https://acct.blob.core.windows.net/c/b", Method::Put);
        request.insert_header(HeaderName::from_static("content-length"), "0");
        request.insert_header(X_MS_DATE, "Mon, 01 Jan 2024 00:00:00 GMT");
        let sts = string_to_sign(request.headers(), request.url(), request.method(), "acct");
        // The Content-Length slot (4th line) is empty.
        assert_eq!(
            sts,
            "PUT\n\n\n\n\n\n\n\n\n\n\n\n\
             x-ms-date:Mon, 01 Jan 2024 00:00:00 GMT\n/acct/c/b"
        );
    }

    // ── SAS-present skip: when the URL already carries `sig`, the policy must NOT Shared-Key sign ─
    #[tokio::test]
    async fn sas_present_skips_shared_key_signing() {
        use std::sync::Mutex;

        // A terminal policy that records whether an `Authorization` header was set + how many `sig`
        // query params it saw.
        #[derive(Debug)]
        struct Capture {
            authz_present: Mutex<Option<bool>>,
        }
        #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
        impl Policy for Capture {
            async fn send(
                &self,
                _ctx: &Context,
                request: &mut Request,
                _next: &[Arc<dyn Policy>],
            ) -> PolicyResult {
                let has_authz = request.headers().get_optional_str(&AUTHORIZATION).is_some();
                *self.authz_present.lock().unwrap() = Some(has_authz);
                Err(azure_core_v1::Error::with_message(
                    azure_core_v1::error::ErrorKind::Other,
                    "terminal test policy",
                ))
            }
        }

        let policy =
            SharedKeyAuthorizationPolicy::new("acct", AZURITE_KEY, SharedKeyResource::Blob);
        let capture = Arc::new(Capture {
            authz_present: Mutex::new(None),
        });
        let next: Vec<Arc<dyn Policy>> = vec![capture.clone()];

        // 1. A SAS-signed URL → NO Shared Key `Authorization` added.
        let mut sas_req = req(
            "https://acct.blob.core.windows.net/c/b?sv=2021-12-02&sig=abc123",
            Method::Get,
        );
        let _ = policy.send(&Context::new(), &mut sas_req, &next).await;
        assert_eq!(
            *capture.authz_present.lock().unwrap(),
            Some(false),
            "a SAS `sig` present ⇒ the Shared Key policy must not add an Authorization header"
        );
        assert!(
            sas_req.headers().get_optional_str(&AUTHORIZATION).is_none(),
            "no Authorization header on the SAS request"
        );

        // 2. A plain URL → a Shared Key `Authorization` IS added (proving the skip is conditional).
        let mut plain_req = req("https://acct.blob.core.windows.net/c/b", Method::Get);
        let _ = policy.send(&Context::new(), &mut plain_req, &next).await;
        assert_eq!(*capture.authz_present.lock().unwrap(), Some(true));
        let authz = plain_req
            .headers()
            .get_optional_str(&AUTHORIZATION)
            .unwrap()
            .to_string();
        assert!(
            authz.starts_with("SharedKey acct:"),
            "the Authorization header is a Shared Key credential: {authz}"
        );
    }

    /// An empty account key is rejected fail-closed (a `Credential` error), not silently signed
    /// with a zero-length HMAC key — an empty string is valid base64 and HMAC accepts a zero-length
    /// key, so without the guard it would produce a well-formed but WRONG signature.
    #[test]
    fn empty_key_is_rejected_as_a_credential_error() {
        let err = sign(
            "PUT\n\n\n\n\n\n\n\n\n\n\n\n/acct/c/b",
            &Secret::new(String::new()),
        )
        .expect_err("an empty account key must be rejected");
        assert!(matches!(
            err.kind(),
            azure_core_v1::error::ErrorKind::Credential
        ));
        // A non-empty key still signs.
        assert!(
            sign(
                "PUT\n\n\n\n\n\n\n\n\n\n\n\n/acct/c/b",
                &Secret::new(AZURITE_KEY.to_string())
            )
            .is_ok()
        );
    }

    /// The base64-decode error path must NOT echo the rejected key material (LOW-1): the message is
    /// generic and contains no bytes of the invalid key.
    #[test]
    fn invalid_base64_key_error_does_not_leak_key_bytes() {
        // `@` is not a base64 alphabet character, so decode fails.
        let bad_key = "not-valid-base64-@@@";
        let err = sign(
            "PUT\n\n\n\n\n\n\n\n\n\n\n\n/acct/c/b",
            &Secret::new(bad_key.to_string()),
        )
        .expect_err("an invalid-base64 key must be rejected");
        assert!(matches!(
            err.kind(),
            azure_core_v1::error::ErrorKind::Credential
        ));
        let msg = err.to_string();
        assert!(
            !msg.contains('@'),
            "the error must not echo any byte of the rejected key: {msg}"
        );
    }

    /// The `Debug` impl must never leak the account key.
    #[test]
    fn debug_redacts_the_key() {
        let policy =
            SharedKeyAuthorizationPolicy::new("acct", AZURITE_KEY, SharedKeyResource::Blob);
        let dbg = format!("{policy:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains(AZURITE_KEY));
    }
}
