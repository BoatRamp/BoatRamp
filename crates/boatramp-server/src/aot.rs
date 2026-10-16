//! Cold-start cap-req 09 — the cluster-authenticated wire frame for a portable AOT
//! (ahead-of-time compiled) component artifact.
//!
//! A fresh node can skip a cranelift compile by loading a precompiled `Component` artifact
//! another cluster node produced. But `wasmtime::component::Component::deserialize` loads
//! EXECUTABLE NATIVE CODE and is only *lightly* validated: its embedded version check fails
//! closed on a cross-wasmtime-version blob, but is explicitly NOT integrity protection — a
//! crafted same-version blob is "trivially … arbitrary code execution". The artifact is
//! fetched from the SHARED blob store (`aot/<fingerprint>/<wasm-hash>`), which other
//! principals can write. So every artifact MUST be integrity-verified BEFORE deserialize.
//!
//! This module is the gate: it frames a serialized artifact with an HMAC keyed by a
//! cluster-shared secret, and verifies that MAC (constant-time) before the serve layer ever
//! calls `deserialize`. A blob-store attacker without the key cannot forge a frame that
//! verifies; a node without the key simply never hydrates (it compiles from source). The
//! MAC additionally binds the engine `fingerprint` + the component `wasm_hash` (both taken
//! from the lookup key, NOT the frame), so an artifact cannot be replayed under a different
//! partition. Pure + fully unit-tested; no I/O, no secrets management (the caller supplies
//! the derived key).

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Frame magic — identifies a boatramp AOT artifact wire frame.
const MAGIC: &[u8; 8] = b"BRAOTa\0\0";
/// Wire format version (bump if the framing or MAC input ever changes).
const FMT_VER: u8 = 1;
/// HMAC-SHA256 output length.
const MAC_LEN: usize = 32;
/// Header length: magic(8) + fmt_ver(1) + mac(32).
const HEADER_LEN: usize = MAGIC.len() + 1 + MAC_LEN;

/// Domain-separation label for deriving the per-cluster AOT MAC key from the cluster AOT
/// root secret. Bump the suffix to rotate every derived key.
const KEY_DERIVE_LABEL: &[u8] = b"boatramp-aot-artifact-mac-v1";

/// Derive the AOT MAC key from the 32-byte cluster AOT root secret, domain-separated. A
/// single HMAC block is exactly HKDF-Expand for a 32-byte output, which is sound for
/// deriving a MAC subkey from a uniformly-random root.
pub fn derive_key(cluster_aot_root: &[u8; 32]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(cluster_aot_root).expect("hmac accepts any key length");
    mac.update(KEY_DERIVE_LABEL);
    let out = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// The bytes the MAC is computed over: `fmt_ver ‖ fingerprint ‖ wasm_hash ‖ serialized`.
/// Binding the fingerprint + wasm_hash (from the lookup key) stops a frame minted for one
/// `(fingerprint, wasm_hash)` partition from being replayed under another.
fn mac_message(fingerprint: &[u8; 32], wasm_hash: &str, serialized: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(1 + 32 + wasm_hash.len() + serialized.len());
    msg.push(FMT_VER);
    msg.extend_from_slice(fingerprint);
    msg.extend_from_slice(wasm_hash.as_bytes());
    msg.extend_from_slice(serialized);
    msg
}

fn compute_mac(
    key: &[u8; 32],
    fingerprint: &[u8; 32],
    wasm_hash: &str,
    serialized: &[u8],
) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(&mac_message(fingerprint, wasm_hash, serialized));
    let out = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&out);
    tag
}

/// Frame a serialized AOT artifact for storage: `magic ‖ fmt_ver ‖ HMAC(32) ‖ serialized`.
/// `key` is [`derive_key`]'s output; `fingerprint`/`wasm_hash` are the artifact's partition
/// (the blob key), bound into the MAC but NOT stored in the frame (the fetcher re-supplies
/// them from the key it looked up).
pub fn frame(
    key: &[u8; 32],
    fingerprint: &[u8; 32],
    wasm_hash: &str,
    serialized: &[u8],
) -> Vec<u8> {
    let tag = compute_mac(key, fingerprint, wasm_hash, serialized);
    let mut out = Vec::with_capacity(HEADER_LEN + serialized.len());
    out.extend_from_slice(MAGIC);
    out.push(FMT_VER);
    out.extend_from_slice(&tag);
    out.extend_from_slice(serialized);
    out
}

/// Verify a framed artifact and return the serialized `Component` bytes ONLY when the frame
/// is well-formed AND the MAC (recomputed over the looked-up `fingerprint` + `wasm_hash`)
/// matches in CONSTANT TIME. Any failure — bad magic, wrong version, short frame, or a MAC
/// mismatch (tampered payload, wrong key, or wrong partition) — returns `None`, and the
/// caller MUST then compile from source. This is the gate that precedes `Component::deserialize`.
#[must_use]
pub fn verify<'a>(
    key: &[u8; 32],
    fingerprint: &[u8; 32],
    wasm_hash: &str,
    framed: &'a [u8],
) -> Option<&'a [u8]> {
    if framed.len() < HEADER_LEN {
        return None;
    }
    let (magic, rest) = framed.split_at(MAGIC.len());
    if magic != MAGIC {
        return None;
    }
    let (ver, rest) = rest.split_at(1);
    if ver[0] != FMT_VER {
        return None;
    }
    let (tag, serialized) = rest.split_at(MAC_LEN);
    // Recompute over the partition the FETCHER looked up, then constant-time verify. Using
    // the hmac crate's `verify_slice` (a constant-time compare) over a freshly-built MAC.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(&mac_message(fingerprint, wasm_hash, serialized));
    mac.verify_slice(tag).ok()?;
    Some(serialized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        derive_key(&[7u8; 32])
    }

    #[test]
    fn frame_round_trips_and_verifies() {
        let k = key();
        let fp = [9u8; 32];
        let hash = "a".repeat(64);
        let payload = b"serialized-component-bytes".to_vec();
        let framed = frame(&k, &fp, &hash, &payload);
        let got = verify(&k, &fp, &hash, &framed).expect("valid frame verifies");
        assert_eq!(got, &payload[..], "the payload round-trips byte-for-byte");
    }

    #[test]
    fn tampered_payload_is_rejected() {
        let k = key();
        let fp = [9u8; 32];
        let hash = "a".repeat(64);
        let mut framed = frame(&k, &fp, &hash, b"payload");
        // Flip one byte of the serialized payload (last byte), leaving the MAC as-is.
        let last = framed.len() - 1;
        framed[last] ^= 0xff;
        assert!(
            verify(&k, &fp, &hash, &framed).is_none(),
            "a tampered payload must fail the MAC"
        );
    }

    #[test]
    fn wrong_key_is_rejected() {
        let fp = [9u8; 32];
        let hash = "a".repeat(64);
        let framed = frame(&key(), &fp, &hash, b"payload");
        let other = derive_key(&[8u8; 32]);
        assert!(
            verify(&other, &fp, &hash, &framed).is_none(),
            "a frame MACed with another cluster's key must not verify"
        );
    }

    #[test]
    fn wrong_partition_is_rejected() {
        let k = key();
        let hash = "a".repeat(64);
        let framed = frame(&k, &[1u8; 32], &hash, b"payload");
        // Same bytes, but verified under a DIFFERENT fingerprint or hash ⇒ reject (no replay).
        assert!(
            verify(&k, &[2u8; 32], &hash, &framed).is_none(),
            "fingerprint is bound"
        );
        assert!(
            verify(&k, &[1u8; 32], &"b".repeat(64), &framed).is_none(),
            "wasm hash is bound"
        );
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let k = key();
        let fp = [9u8; 32];
        let hash = "a".repeat(64);
        // Too short.
        assert!(verify(&k, &fp, &hash, b"short").is_none());
        // Good length but wrong magic.
        let mut bad = frame(&k, &fp, &hash, b"payload");
        bad[0] ^= 0xff;
        assert!(verify(&k, &fp, &hash, &bad).is_none(), "bad magic rejected");
        // Wrong version byte.
        let mut badv = frame(&k, &fp, &hash, b"payload");
        badv[MAGIC.len()] = 0xff;
        assert!(
            verify(&k, &fp, &hash, &badv).is_none(),
            "bad version rejected"
        );
    }

    #[test]
    fn derive_key_is_deterministic_and_domain_separated() {
        assert_eq!(derive_key(&[3u8; 32]), derive_key(&[3u8; 32]));
        assert_ne!(derive_key(&[3u8; 32]), derive_key(&[4u8; 32]));
        // Not the raw root (domain separation applied).
        assert_ne!(derive_key(&[3u8; 32]), [3u8; 32]);
    }
}
