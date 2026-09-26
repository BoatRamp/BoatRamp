//! Multipart staging + **all-or-nothing** assembly + GC for the local S3 face (PLAN §4/§9 + Architect
//! HIGH-3 + Security HIGH-2 invariant 8 + DoS MEDIUM-3).
//!
//! A multipart upload stages its parts under the reserved
//! `hblob/{project-qualified-site}/{container}/.boatramp-uploads/{uploadId}/part-{n}` namespace
//! (M1-review MEDIUM-3: the reserved `.boatramp*` prefix, which `validate_object_key` rejects for a
//! client key — so staging can never collide with, and the guest can never reach, an in-flight part).
//!
//! **`uploadId` is fleet-issued and scope-bound.** It embeds a hash of the origin scope
//! `(project, site, container, target)`; every `UploadPart`/`Complete`/`Abort` RE-VERIFIES that the
//! request's credential scope hashes to the same value — so a credential for one scope can never drive
//! an `uploadId` minted for another (never trust the `uploadId` alone). It is NOT reversible into the
//! scope; it only *proves* origin.
//!
//! **Complete is all-or-nothing.** It streams the staged parts, in numeric order, into a SINGLE
//! `Storage::put` at the final key — so there is never a partial object at the final key (a failed
//! assembly leaves the final key absent and the staging intact for retry/GC). Assembly is restricted
//! to `fs`/in-memory backends (an object-store "local" would broker the store's native multipart in
//! M4 rather than re-transit bytes).

use std::sync::Arc;

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use boatramp_core::cose::{S3SessionScope, S3Target};
use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
use futures::StreamExt as _;
use sha2::{Digest, Sha256};

use super::config::MAX_PARTS_PER_UPLOAD;
use super::keypath;

/// A multipart failure (mapped by the face to a greppable S3 error code).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MultipartError {
    /// The `uploadId` was malformed (bad shape / not fleet-issued).
    #[error("malformed uploadId")]
    MalformedUploadId,
    /// The request's credential scope does not match the scope the `uploadId` was issued for — never
    /// trust the `uploadId` alone (Security HIGH-2 invariant 8: A's uploadId can't be driven by B's
    /// cred).
    #[error("uploadId scope mismatch")]
    ScopeMismatch,
    /// A part number outside `[1, MAX_PARTS_PER_UPLOAD]`.
    #[error("part number out of range")]
    BadPartNumber,
    /// The completion part list was empty, out of order, or referenced an absent staged part.
    #[error("invalid completion part list")]
    BadPartList,
    /// The RNG failed generating the `uploadId` nonce.
    #[error("rng failure")]
    Rng,
}

/// The scope-hash length (hex chars) embedded in an `uploadId`. 16 bytes → 32 hex chars: ample to bind
/// the scope, short enough for a compact id.
const SCOPE_HASH_HEX_LEN: usize = 32;
/// The random nonce length (hex chars) that makes each `uploadId` unique.
const NONCE_HEX_LEN: usize = 32;

/// Compute the scope-binding hash for `(project, site, container, target)` — a domain-separated
/// SHA-256 over length-prefixed fields (so distinct scopes never collide). Returned as the first
/// [`SCOPE_HASH_HEX_LEN`] hex chars. The target is included so a single-key credential and a prefix
/// credential over the same container get DIFFERENT upload ids (a prefix upload can't be redriven by a
/// narrower single-key credential and vice-versa).
pub fn scope_hash(scope: &S3SessionScope) -> String {
    let (tag, val) = match &scope.target {
        S3Target::Key(k) => ("key", k.as_str()),
        S3Target::Prefix(p) => ("prefix", p.as_str()),
    };
    let mut h = Sha256::new();
    h.update(b"boatramp-s3-ingress/uploadid-scope/v1");
    for field in [
        scope.project.as_str(),
        scope.site.as_str(),
        scope.container.as_str(),
        tag,
        val,
    ] {
        h.update((field.len() as u32).to_be_bytes());
        h.update(field.as_bytes());
    }
    hex::encode(h.finalize())[..SCOPE_HASH_HEX_LEN].to_string()
}

/// Mint a fresh, scope-bound `uploadId`: `<scope-hash><random-nonce>` (both hex). The scope hash binds
/// origin; the nonce makes it unique + unguessable. Not reversible into the scope.
pub fn new_upload_id(scope: &S3SessionScope) -> Result<String, MultipartError> {
    let mut nonce = [0u8; NONCE_HEX_LEN / 2];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| MultipartError::Rng)?;
    Ok(format!("{}{}", scope_hash(scope), hex::encode(nonce)))
}

/// **Re-verify** that `upload_id` was issued for `scope` (Architect HIGH-3 / invariant 8). Checks the
/// embedded scope hash matches the request's scope — so an `UploadPart`/`Complete`/`Abort` presenting
/// a credential for a DIFFERENT scope is refused, never trusting the id alone. Also validates the id
/// shape (fleet-issued length + hex).
pub fn verify_upload_id(upload_id: &str, scope: &S3SessionScope) -> Result<(), MultipartError> {
    if upload_id.len() != SCOPE_HASH_HEX_LEN + NONCE_HEX_LEN
        || !upload_id.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(MultipartError::MalformedUploadId);
    }
    let embedded = &upload_id[..SCOPE_HASH_HEX_LEN];
    // Constant-time-agnostic string compare is fine here: the scope hash is not a secret (it is
    // derived from the host-stamped, already-authenticated scope) — it is an integrity binding, not a
    // credential. A mismatch is an authorization refusal, mapped to the uniform error by the face.
    if embedded != scope_hash(scope) {
        return Err(MultipartError::ScopeMismatch);
    }
    Ok(())
}

/// Validate a part number is within `[1, MAX_PARTS_PER_UPLOAD]` (DoS MEDIUM-3: bounds the staged-part
/// fan-out).
pub fn validate_part_number(part_number: u32) -> Result<(), MultipartError> {
    if part_number == 0 || part_number > MAX_PARTS_PER_UPLOAD {
        return Err(MultipartError::BadPartNumber);
    }
    Ok(())
}

/// Stage one part's `body` at `…/.boatramp-uploads/{upload_id}/part-{n:08}` and return its ETag (the
/// hex SHA-256 of the part bytes — S3 clients treat the ETag opaquely, and a content hash lets Complete
/// bind the part list to content). Streams the body through a hashing tap into a single `Storage::put`
/// (never buffering the whole part in the face). `part_size` (if the caller knows the Content-Length)
/// is advisory; the actual streamed size is what's stored.
pub async fn stage_part(
    storage: &Arc<dyn Storage>,
    scope: &S3SessionScope,
    upload_id: &str,
    part_number: u32,
    body: ByteStream,
) -> Result<String, StorageError> {
    let key = keypath::staging_part_key(
        &scope.project,
        &scope.site,
        &scope.container,
        upload_id,
        part_number,
    );
    let hasher = Arc::new(std::sync::Mutex::new(Sha256::new()));
    let tap = hasher.clone();
    let hashed: ByteStream = body
        .map(move |chunk| {
            if let Ok(bytes) = &chunk {
                tap.lock().unwrap().update(bytes);
            }
            chunk
        })
        .boxed();
    storage.put(&key, hashed, PutMeta::default()).await?;
    let etag = hex::encode(hasher.lock().unwrap().clone().finalize());
    Ok(etag)
}

/// **Assemble** the staged parts into the final object, all-or-nothing. Given the ORDERED part numbers
/// the client listed in CompleteMultipartUpload, this:
/// 1. verifies every listed part is staged (an absent part ⇒ `BadPartList`, no final object written);
/// 2. streams the parts, IN THE LISTED ORDER, concatenated into a SINGLE `Storage::put` at
///    `final_storage_key` — so a partial assembly never leaves a truncated object at the final key;
/// 3. (the caller deletes the staging afterwards via [`abort`]).
///
/// `verify_sha256`, when `Some`, is a hashing tap: the assembled bytes' SHA-256 must equal it (the
/// content-addressed final key) or the final object is deleted and an error returned — no committed
/// partial (invariant 9). The parts are streamed lazily (each `get` opens a fresh stream), so the whole
/// object is never buffered.
pub async fn assemble(
    storage: &Arc<dyn Storage>,
    scope: &S3SessionScope,
    upload_id: &str,
    ordered_parts: &[u32],
    final_storage_key: &str,
    verify_sha256: Option<&str>,
) -> Result<(), MultipartError> {
    if ordered_parts.is_empty() {
        return Err(MultipartError::BadPartList);
    }
    // Confirm every listed part is staged BEFORE writing anything (fail before touching the final key).
    let mut part_keys = Vec::with_capacity(ordered_parts.len());
    let mut prev = 0u32;
    for &n in ordered_parts {
        validate_part_number(n)?;
        // S3 requires ascending, non-repeating part numbers in the completion list.
        if n <= prev {
            return Err(MultipartError::BadPartList);
        }
        prev = n;
        let key =
            keypath::staging_part_key(&scope.project, &scope.site, &scope.container, upload_id, n);
        match storage.head(&key).await {
            Ok(_) => part_keys.push(key),
            Err(_) => return Err(MultipartError::BadPartList),
        }
    }

    // Stream the parts, in order, into ONE put at the final key. The stream lazily opens each staged
    // part's body in turn (never buffering the whole object), taps a running hasher for content
    // verification, and yields chunks to the backend.
    let storage_for_stream = storage.clone();
    let hasher = Arc::new(std::sync::Mutex::new(Sha256::new()));
    let tap = hasher.clone();
    let assembled: ByteStream = futures::stream::iter(part_keys)
        .flat_map(move |key| {
            let storage = storage_for_stream.clone();
            // Open the part's stream when we reach it (lazy).
            futures::stream::once(async move { storage.get(&key).await }).flat_map(|opened| {
                match opened {
                    Ok(obj) => obj.body.boxed(),
                    Err(e) => futures::stream::once(async move { Err(e) }).boxed(),
                }
            })
        })
        .map(move |chunk| {
            if let Ok(bytes) = &chunk {
                tap.lock().unwrap().update(bytes);
            }
            chunk
        })
        .boxed();

    storage
        .put(final_storage_key, assembled, PutMeta::default())
        .await
        .map_err(|_| MultipartError::BadPartList)?;

    // Content-addressing: the assembled bytes must hash to the declared key, else no committed object.
    if let Some(expected) = verify_sha256 {
        let actual = hex::encode(hasher.lock().unwrap().clone().finalize());
        if actual != expected {
            let _ = storage.delete(final_storage_key).await;
            return Err(MultipartError::BadPartList);
        }
    }
    Ok(())
}

/// **Abort / GC** a multipart upload: delete every staged part + any staging marker under the upload's
/// prefix. Idempotent (deleting a missing object is not an error). Used by AbortMultipartUpload, by the
/// background staging-GC sweep, and after a successful Complete to clean the staging.
pub async fn abort(
    storage: &Arc<dyn Storage>,
    scope: &S3SessionScope,
    upload_id: &str,
) -> Result<(), StorageError> {
    let prefix = keypath::staging_prefix(&scope.project, &scope.site, &scope.container, upload_id);
    for obj in storage.list(&prefix).await? {
        storage.delete(&obj.key).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3_ingress::test_support::MapStorage;
    use boatramp_core::cose::{S3Constraints, S3Perm};

    fn scope(target: S3Target) -> S3SessionScope {
        S3SessionScope {
            project: "default".into(),
            site: "blog".into(),
            container: "photos".into(),
            target,
            perms: vec![S3Perm::Multipart],
            constraints: S3Constraints::default(),
        }
    }

    #[test]
    fn upload_id_is_scope_bound_and_verifies() {
        let s = scope(S3Target::Prefix("uploads".into()));
        let id = new_upload_id(&s).unwrap();
        assert_eq!(id.len(), SCOPE_HASH_HEX_LEN + NONCE_HEX_LEN);
        // The same scope verifies.
        assert!(verify_upload_id(&id, &s).is_ok());
        // A DIFFERENT scope (different container) is refused — never trust the id alone.
        let other = S3SessionScope {
            container: "docs".into(),
            ..scope(S3Target::Prefix("uploads".into()))
        };
        assert_eq!(
            verify_upload_id(&id, &other),
            Err(MultipartError::ScopeMismatch)
        );
        // A different target shape (single key vs prefix) is a different scope ⇒ refused.
        let key_scope = scope(S3Target::Key("uploads".into()));
        assert_eq!(
            verify_upload_id(&id, &key_scope),
            Err(MultipartError::ScopeMismatch)
        );
    }

    #[test]
    fn malformed_upload_id_rejected() {
        let s = scope(S3Target::Prefix("uploads".into()));
        assert_eq!(
            verify_upload_id("short", &s),
            Err(MultipartError::MalformedUploadId)
        );
        assert_eq!(
            verify_upload_id(&"z".repeat(SCOPE_HASH_HEX_LEN + NONCE_HEX_LEN), &s),
            Err(MultipartError::MalformedUploadId)
        );
    }

    #[test]
    fn part_number_bounds() {
        assert_eq!(validate_part_number(0), Err(MultipartError::BadPartNumber));
        assert!(validate_part_number(1).is_ok());
        assert!(validate_part_number(MAX_PARTS_PER_UPLOAD).is_ok());
        assert_eq!(
            validate_part_number(MAX_PARTS_PER_UPLOAD + 1),
            Err(MultipartError::BadPartNumber)
        );
    }

    #[tokio::test]
    async fn stage_two_parts_and_assemble_in_order() {
        let map = Arc::new(MapStorage::default());
        let storage: Arc<dyn Storage> = map.clone();
        let s = scope(S3Target::Prefix("uploads".into()));
        let id = new_upload_id(&s).unwrap();
        let p1: ByteStream =
            futures::stream::once(async { Ok(bytes::Bytes::from_static(b"Hello, ")) }).boxed();
        let p2: ByteStream =
            futures::stream::once(async { Ok(bytes::Bytes::from_static(b"world!")) }).boxed();
        stage_part(&storage, &s, &id, 1, p1).await.unwrap();
        stage_part(&storage, &s, &id, 2, p2).await.unwrap();

        // Assemble into the final key.
        let final_key = "hblob/blog/photos/uploads/greeting.txt";
        assemble(&storage, &s, &id, &[1, 2], final_key, None)
            .await
            .unwrap();
        assert_eq!(map.get_bytes(final_key).unwrap(), b"Hello, world!");
    }

    #[tokio::test]
    async fn assemble_is_all_or_nothing_on_missing_part() {
        let map = Arc::new(MapStorage::default());
        let storage: Arc<dyn Storage> = map.clone();
        let s = scope(S3Target::Prefix("uploads".into()));
        let id = new_upload_id(&s).unwrap();
        let p1: ByteStream =
            futures::stream::once(async { Ok(bytes::Bytes::from_static(b"only-part-1")) }).boxed();
        stage_part(&storage, &s, &id, 1, p1).await.unwrap();
        // Completion lists a part (2) that was never staged ⇒ BadPartList, and NO final object.
        let final_key = "hblob/blog/photos/uploads/x";
        assert_eq!(
            assemble(&storage, &s, &id, &[1, 2], final_key, None).await,
            Err(MultipartError::BadPartList)
        );
        assert!(
            map.get_bytes(final_key).is_none(),
            "no partial at final key"
        );
    }

    #[tokio::test]
    async fn abort_removes_all_staging() {
        let map = Arc::new(MapStorage::default());
        let storage: Arc<dyn Storage> = map.clone();
        let s = scope(S3Target::Prefix("uploads".into()));
        let id = new_upload_id(&s).unwrap();
        for n in 1..=3 {
            let body: ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(vec![b'x'; 4])) }).boxed();
            stage_part(&storage, &s, &id, n, body).await.unwrap();
        }
        let staging = keypath::staging_prefix(&s.project, &s.site, &s.container, &id);
        assert_eq!(map.count_with_prefix(&staging), 3);
        abort(&storage, &s, &id).await.unwrap();
        assert_eq!(
            map.count_with_prefix(&staging),
            0,
            "abort must delete every staged part"
        );
    }

    #[tokio::test]
    async fn assemble_content_addressed_rejects_mismatch() {
        let map = Arc::new(MapStorage::default());
        let storage: Arc<dyn Storage> = map.clone();
        let s = scope(S3Target::Prefix("cas".into()));
        let id = new_upload_id(&s).unwrap();
        let body: ByteStream =
            futures::stream::once(async { Ok(bytes::Bytes::from_static(b"abc")) }).boxed();
        stage_part(&storage, &s, &id, 1, body).await.unwrap();
        let final_key = "hblob/blog/photos/cas/deadbeef";
        // The declared content hash is wrong ⇒ reject, no committed object.
        assert_eq!(
            assemble(&storage, &s, &id, &[1], final_key, Some("deadbeef")).await,
            Err(MultipartError::BadPartList)
        );
        assert!(map.get_bytes(final_key).is_none());
        // The correct hash ⇒ committed.
        let sha = hex::encode(Sha256::digest(b"abc"));
        assemble(
            &storage,
            &s,
            &id,
            &[1],
            "hblob/blog/photos/cas/ok",
            Some(&sha),
        )
        .await
        .unwrap();
        assert_eq!(map.get_bytes("hblob/blog/photos/cas/ok").unwrap(), b"abc");
    }
}
