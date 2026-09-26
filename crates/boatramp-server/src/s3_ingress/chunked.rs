//! aws-chunked (`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`) body **de-framing + per-chunk verification** for
//! the local S3 face (PLAN §4/§SigV4, owner-directed day-one support).
//!
//! A chunked PUT/UploadPart body is framed as a sequence of:
//! `<hex-size>;chunk-signature=<hex>\r\n<chunk-bytes>\r\n` … terminated by a zero-size chunk. The
//! per-chunk signatures CHAIN off the request's seed signature (verified by M1's [`ChunkVerifier`]),
//! so the payload is authenticated as it streams — never buffered whole.
//!
//! [`dechunk_verified`] wraps the raw framed body [`ByteStream`] and returns a `ByteStream` that yields
//! ONLY the de-framed payload bytes, having verified each chunk's signature against the chain as it
//! goes. A bad chunk signature, malformed framing, or an early end aborts the stream with a
//! [`StorageError`] — so the downstream `Storage::put` sees an error and commits no object (fail-closed;
//! this pairs with the face deleting a partial on a stream error).
//!
//! **Trailing-checksum (`-TRAILER`) is NOT handled here** — the face rejects that mode up front
//! (M1-review MEDIUM-2), so only the plain streaming form reaches this adapter.

use boatramp_core::{ByteStream, StorageError};
use futures::StreamExt as _;

use super::sigv4::{self, ChunkVerifier, CredentialScope};

/// The context needed to verify an aws-chunked body: the seed (request) signature + the derived
/// `secret_access_key` + the credential scope + the request date. Built by the face from the
/// authenticated request.
pub struct ChunkContext {
    /// The `secret_access_key` (hex) that verified the request signature (M1 rotation-aware pick).
    pub secret: String,
    /// The credential scope (date/region/service) the signing key is derived under.
    pub scope: CredentialScope,
    /// The request timestamp (`x-amz-date`).
    pub amz_date: String,
    /// The request's seed signature (the chain's first `prev signature`).
    pub seed_signature: String,
}

/// The maximum bytes we buffer while waiting to complete a single chunk header line or chunk body
/// boundary — a hostile client can't force unbounded buffering (a chunk header is tiny; a chunk body
/// is bounded by the per-chunk size it declares, which the outer `UploadGuard` size cap also bounds).
const MAX_PENDING_HEADER: usize = 8 * 1024;

/// Wrap a raw aws-chunked framed `body` into a de-framed, per-chunk-verified payload stream. Yields
/// only the actual object bytes; verifies each chunk's signature against the seed chain via
/// [`ChunkVerifier`]. Any framing/signature error aborts with a [`StorageError`] (fail-closed).
pub fn dechunk_verified(body: ByteStream, ctx: ChunkContext) -> ByteStream {
    let verifier = ChunkVerifier::new(&ctx.secret, &ctx.scope, &ctx.amz_date, &ctx.seed_signature);
    // A small hand-rolled state machine fed by `unfold`: accumulate wire bytes, frame one chunk at a
    // time (header line → data → trailing CRLF), verify it, and emit the data. `pending` holds
    // unconsumed wire bytes across polls; `done` latches after the terminating zero chunk.
    struct State {
        inner: ByteStream,
        verifier: ChunkVerifier,
        pending: Vec<u8>,
        finished: bool,
        upstream_done: bool,
    }
    let state = State {
        inner: body,
        verifier,
        pending: Vec::new(),
        finished: false,
        upstream_done: false,
    };

    futures::stream::unfold(state, |mut st| async move {
        if st.finished {
            return None;
        }
        loop {
            // Try to frame + verify one complete chunk out of `pending`.
            match take_one_chunk(&mut st.pending) {
                ChunkFrame::Complete { data, signature } => {
                    // Verify this chunk against the chain (constant-time inside `verify_chunk`).
                    if let Err(e) = st.verifier.verify_chunk(&data, &signature) {
                        st.finished = true;
                        return Some((Err(chunk_err(e)), st));
                    }
                    if data.is_empty() {
                        // The terminating zero-length chunk (verified) — the stream is complete.
                        st.finished = true;
                        // Nothing more to emit; end the stream on the next poll.
                        return Some((Ok(bytes::Bytes::new()), st));
                    }
                    return Some((Ok(bytes::Bytes::from(data)), st));
                }
                ChunkFrame::NeedMore => {
                    if st.pending.len() > MAX_PENDING_HEADER
                        && !st.pending.windows(2).any(|w| w == b"\r\n")
                    {
                        // A chunk header line that never terminates ⇒ malformed (bounded buffering).
                        st.finished = true;
                        return Some((
                            Err(StorageError::backend("malformed aws-chunked header")),
                            st,
                        ));
                    }
                    if st.upstream_done {
                        // The wire ended mid-chunk without a terminating zero chunk ⇒ fail-closed.
                        st.finished = true;
                        return Some((
                            Err(StorageError::backend("truncated aws-chunked body")),
                            st,
                        ));
                    }
                    // Pull more wire bytes.
                    match st.inner.next().await {
                        Some(Ok(bytes)) => st.pending.extend_from_slice(&bytes),
                        Some(Err(e)) => {
                            st.finished = true;
                            return Some((Err(e), st));
                        }
                        None => st.upstream_done = true,
                    }
                }
                ChunkFrame::Malformed => {
                    st.finished = true;
                    return Some((
                        Err(StorageError::backend("malformed aws-chunked frame")),
                        st,
                    ));
                }
            }
        }
    })
    // Drop the empty terminator frame the state machine emits for the zero chunk (keeps downstream
    // hashing/size accounting exact).
    .filter(|item| {
        let keep = !matches!(item, Ok(b) if b.is_empty());
        std::future::ready(keep)
    })
    .boxed()
}

/// One framing attempt over the pending wire buffer.
enum ChunkFrame {
    /// A full chunk (`data` + its `signature`) was framed and consumed from `pending`.
    Complete { data: Vec<u8>, signature: String },
    /// Not enough bytes yet — pull more from upstream.
    NeedMore,
    /// The framing is structurally invalid (fail-closed).
    Malformed,
}

/// Try to consume one `<hex-size>;chunk-signature=<hex>\r\n<data>\r\n` chunk from the FRONT of
/// `pending`. On success, drains those bytes from `pending` and returns the data + signature. Returns
/// [`ChunkFrame::NeedMore`] when the buffer doesn't yet hold the whole chunk.
fn take_one_chunk(pending: &mut Vec<u8>) -> ChunkFrame {
    // Find the header line terminator.
    let Some(hdr_end) = find_crlf(pending, 0) else {
        return ChunkFrame::NeedMore;
    };
    let header_line = match std::str::from_utf8(&pending[..hdr_end]) {
        Ok(s) => s,
        Err(_) => return ChunkFrame::Malformed,
    };
    let (size, signature) = match sigv4::parse_chunk_header(header_line) {
        Ok(v) => v,
        Err(_) => return ChunkFrame::Malformed,
    };
    // The chunk data starts after the header's CRLF and is `size` bytes, followed by a trailing CRLF.
    let data_start = hdr_end + 2;
    let data_end = data_start + size;
    let trailer_end = data_end + 2;
    if pending.len() < trailer_end {
        return ChunkFrame::NeedMore;
    }
    // Validate the trailing CRLF.
    if &pending[data_end..data_end + 2] != b"\r\n" {
        return ChunkFrame::Malformed;
    }
    let data = pending[data_start..data_end].to_vec();
    // Drain the consumed bytes.
    pending.drain(..trailer_end);
    ChunkFrame::Complete { data, signature }
}

/// Find the index of the next `\r\n` in `buf` at or after `from`, if present.
fn find_crlf(buf: &[u8], from: usize) -> Option<usize> {
    buf.get(from..)
        .and_then(|s| s.windows(2).position(|w| w == b"\r\n"))
        .map(|p| from + p)
}

/// Map a SigV4 chunk error to a storage-backend error (the face turns a stream error into a deleted
/// partial + a refusal; the specific cause is not surfaced to the client).
fn chunk_err(_e: sigv4::SigV4Error) -> StorageError {
    StorageError::backend("aws-chunked signature verification failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s3_ingress::config::{LOCAL_REGION, LOCAL_SERVICE};

    /// Build a valid aws-chunked wire body for `chunks` + the seed context, signing each chunk with the
    /// SAME chain the verifier uses (so a correct body round-trips, and a tamper is caught).
    fn make_chunked(
        secret: &str,
        seed: &str,
        amz_date: &str,
        chunks: &[&[u8]],
    ) -> (Vec<u8>, ChunkContext) {
        let scope = CredentialScope {
            access_key_id: "BRUPCHUNK".into(),
            date: "20150830".into(),
            region: LOCAL_REGION.into(),
            service: LOCAL_SERVICE.into(),
        };
        let mut verifier = ChunkVerifier::new(secret, &scope, amz_date, seed);
        let mut wire = Vec::new();
        // Data chunks then the terminating zero chunk.
        let mut all: Vec<&[u8]> = chunks.to_vec();
        all.push(b"");
        for data in all {
            // Compute the expected chunk signature by advancing a parallel verifier state: we reuse the
            // real verifier's chunk_sts via verify by trial — simplest is to recompute using the public
            // signing primitives.
            let sts = format!(
                "AWS4-HMAC-SHA256-PAYLOAD\n{amz_date}\n{}\n{}\n{}\n{}",
                scope.scope_string(),
                verifier.current_signature(),
                sigv4::EMPTY_SHA256,
                sigv4::sha256_hex(data),
            );
            let key = sigv4::signing_key(secret, &scope.date, &scope.region, &scope.service);
            let sig = hex::encode(aws_lc_rs_hmac(key.as_ref(), sts.as_bytes()));
            wire.extend_from_slice(
                format!("{:x};chunk-signature={}\r\n", data.len(), sig).as_bytes(),
            );
            wire.extend_from_slice(data);
            wire.extend_from_slice(b"\r\n");
            // Advance our local verifier to mirror the chain (verify our own chunk).
            verifier.verify_chunk(data, &sig).unwrap();
        }
        let ctx = ChunkContext {
            secret: secret.to_string(),
            scope,
            amz_date: amz_date.to_string(),
            seed_signature: seed.to_string(),
        };
        (wire, ctx)
    }

    /// One HMAC-SHA256 (mirrors sigv4's private helper for the test signer).
    fn aws_lc_rs_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
        use aws_lc_rs::hmac;
        let k = hmac::Key::new(hmac::HMAC_SHA256, key);
        hmac::sign(&k, data).as_ref().to_vec()
    }

    async fn collect(mut s: ByteStream) -> Result<Vec<u8>, StorageError> {
        let mut out = Vec::new();
        while let Some(chunk) = s.next().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(out)
    }

    #[tokio::test]
    async fn dechunks_and_verifies_a_valid_body() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let amz_date = "20150830T123600Z";
        let (wire, ctx) = make_chunked(secret, seed, amz_date, &[b"Hello, ", b"world!"]);
        let body: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from(wire)) }).boxed();
        let out = collect(dechunk_verified(body, ctx)).await.unwrap();
        assert_eq!(
            out, b"Hello, world!",
            "de-framed payload is the concatenated chunk data"
        );
    }

    #[tokio::test]
    async fn split_across_stream_chunks_still_frames() {
        // Feed the wire body one byte at a time — the state machine must reassemble frames correctly.
        let secret = "abcdef00abcdef00abcdef00abcdef00abcdef00abcdef00abcdef00abcdef00";
        let seed = "1111111111111111111111111111111111111111111111111111111111111111";
        let amz_date = "20150830T123600Z";
        let (wire, ctx) = make_chunked(secret, seed, amz_date, &[b"abcdefghij"]);
        let byte_stream = futures::stream::iter(
            wire.into_iter()
                .map(|b| Ok::<_, StorageError>(bytes::Bytes::from(vec![b]))),
        )
        .boxed();
        let out = collect(dechunk_verified(byte_stream, ctx)).await.unwrap();
        assert_eq!(out, b"abcdefghij");
    }

    #[tokio::test]
    async fn tampered_chunk_signature_aborts_fail_closed() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let amz_date = "20150830T123600Z";
        let (mut wire, ctx) = make_chunked(secret, seed, amz_date, &[b"payload"]);
        // Corrupt one signature hex char in the wire.
        let pos = wire
            .windows("chunk-signature=".len())
            .position(|w| w == b"chunk-signature=")
            .unwrap()
            + "chunk-signature=".len();
        wire[pos] = if wire[pos] == b'0' { b'1' } else { b'0' };
        let body: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from(wire)) }).boxed();
        let res = collect(dechunk_verified(body, ctx)).await;
        assert!(
            res.is_err(),
            "a tampered chunk signature must abort the stream"
        );
    }

    #[tokio::test]
    async fn truncated_body_without_terminator_fails_closed() {
        let secret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let seed = "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9";
        let amz_date = "20150830T123600Z";
        let (wire, ctx) = make_chunked(secret, seed, amz_date, &[b"data"]);
        // Drop the terminating zero chunk (everything after the first chunk's trailing CRLF).
        let first_crlf = wire.windows(2).position(|w| w == b"\r\n").unwrap();
        let data_end = first_crlf + 2 + 4 + 2; // header CRLF + 4 data bytes + trailing CRLF
        let truncated = wire[..data_end].to_vec();
        let body: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from(truncated)) }).boxed();
        let res = collect(dechunk_verified(body, ctx)).await;
        assert!(
            res.is_err(),
            "a body without the zero terminator must fail closed"
        );
    }
}
