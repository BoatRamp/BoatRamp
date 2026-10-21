//! Commit-then-reveal pairing commitment (overlay follow-up #2, pairing).
//!
//! The pairing handshake (`boatramp overlay pair`) runs the relay-blind E2EE KEM
//! handshake ([`crate::e2ee`]) and then, over the sealed session, each peer
//! **commits** to a fresh random nonce before either peer **reveals** it. The
//! pairing SAS ([`crate::sas::sas_from_pair_transcript`]) folds both revealed
//! nonces in, so an active relay-in-the-middle — which, to win, must choose its
//! nonce *before* it can learn the peer's — cannot grind its KEM contribution to
//! force the two human-compared codes to collide (see the `CRITICAL` note on
//! [`crate::sas::SAS_BITS`]). That restores the `2^-SAS_BITS`-per-online-attempt
//! MITM-detection strength the un-committed transcript SAS lacks.
//!
//! This module is the pure commitment primitive: a `SHA-256` over a **canonical,
//! fixed-width** preimage, plus a constant-time verify. It is sync, allocation-
//! light, and carries no transport or async — the async state machine that drives
//! the exchange lives in the runtime crate (`boatramp_overlay::pair`).

use aws_lc_rs::constant_time::verify_slices_are_equal;
use sha2::{Digest, Sha256};

use crate::e2ee::{OFFER_LEN, REPLY_LEN};
use crate::identity::OverlayId;
use crate::wire;

/// Commitment role byte: the pairing **initiator** (the dialer). Its KEM
/// contribution is the signed KEM `offer`, exactly [`OFFER_LEN`] bytes.
pub const PAIR_ROLE_INITIATOR: u8 = 0x01;

/// Commitment role byte: the pairing **responder** (the listener). Its KEM
/// contribution is the KEM `reply`, exactly [`REPLY_LEN`] bytes.
pub const PAIR_ROLE_RESPONDER: u8 = 0x02;

/// A pairing nonce is exactly 32 bytes (platform RNG). Enforced on reveal so a
/// short/long nonce can never reshape the fixed-width commitment preimage.
pub const PAIR_NONCE_LEN: usize = 32;

/// The fixed KEM-contribution width a given commitment `role` binds, or `None`
/// for an unknown role byte (which a caller MUST treat as a protocol error). The
/// two widths differ ([`OFFER_LEN`] ≠ [`REPLY_LEN`]), and the role byte is itself
/// hashed, so there is no cross-role preimage overlap.
#[must_use]
pub fn contribution_len(role: u8) -> Option<usize> {
    match role {
        PAIR_ROLE_INITIATOR => Some(OFFER_LEN),
        PAIR_ROLE_RESPONDER => Some(REPLY_LEN),
        _ => None,
    }
}

/// Compute the pairing commitment
/// `SHA-256(TAG_PAIR_COMMIT ‖ role ‖ id_i ‖ id_r ‖ kem_contribution ‖ nonce)`.
///
/// The preimage is a **canonical fixed-width** concatenation, in this exact order:
/// the 18-byte domain tag [`wire::TAG_PAIR_COMMIT`], the 1-byte `role`, the two
/// 32-byte identities in fixed **initiator-then-responder** order, the
/// `kem_contribution` (whose width is fixed *by* the role — [`OFFER_LEN`] for
/// [`PAIR_ROLE_INITIATOR`], [`REPLY_LEN`] for [`PAIR_ROLE_RESPONDER`]), and the
/// 32-byte `nonce`. Every field is fixed-width, so the concatenation parses one
/// way only — there is no separator ambiguity and no cross-role confusion (the
/// role byte is bound and pins the contribution length).
///
/// `id_i`/`id_r` are ALWAYS the initiator/responder identities in that fixed
/// order, regardless of which side computes the commitment, so both peers hash an
/// identical preimage for a given role.
///
/// The caller must pass the role's fixed-width contribution; in the live handshake
/// it is the `offer`/`reply` already length-validated by the KEM layer
/// (`open_signed_share` / `hybrid_respond`). The `debug_assert` catches a dev-time
/// misuse without widening the release-mode signature to a fallible one.
#[must_use]
pub fn pair_commit(
    role: u8,
    id_i: &OverlayId,
    id_r: &OverlayId,
    kem_contribution: &[u8],
    nonce: &[u8; PAIR_NONCE_LEN],
) -> [u8; 32] {
    debug_assert_eq!(
        contribution_len(role),
        Some(kem_contribution.len()),
        "pair_commit: the KEM contribution must be the role's fixed width"
    );
    let mut h = Sha256::new();
    h.update(wire::TAG_PAIR_COMMIT);
    h.update([role]);
    h.update(id_i.as_bytes());
    h.update(id_r.as_bytes());
    h.update(kem_contribution);
    h.update(nonce);
    h.finalize().into()
}

/// Verify a peer's revealed `(role, kem_contribution, nonce)` against the
/// `commitment` it sent earlier. Returns `true` iff the recomputed commitment
/// equals the committed one — i.e. the peer did **not** equivocate (reveal a
/// nonce other than the one it committed to). The 32-byte digest comparison is
/// constant-time (hygiene; the digests are not secret, but a non-CT compare is a
/// needless footgun in security-critical crypto).
#[must_use]
pub fn pair_commit_verify(
    commitment: &[u8; 32],
    role: u8,
    id_i: &OverlayId,
    id_r: &OverlayId,
    kem_contribution: &[u8],
    nonce: &[u8; PAIR_NONCE_LEN],
) -> bool {
    let recomputed = pair_commit(role, id_i, id_r, kem_contribution, nonce);
    verify_slices_are_equal(&recomputed, commitment).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::OverlaySecret;

    fn ids() -> (OverlayId, OverlayId) {
        (
            OverlaySecret::generate().unwrap().id(),
            OverlaySecret::generate().unwrap().id(),
        )
    }

    #[test]
    fn commit_binds_the_nonce_and_verifies() {
        let (i, r) = ids();
        let offer = vec![7u8; OFFER_LEN];
        let n = [3u8; PAIR_NONCE_LEN];
        let c = pair_commit(PAIR_ROLE_INITIATOR, &i, &r, &offer, &n);
        // The honest reveal of the committed nonce verifies.
        assert!(pair_commit_verify(
            &c,
            PAIR_ROLE_INITIATOR,
            &i,
            &r,
            &offer,
            &n
        ));
    }

    #[test]
    fn equivocation_is_caught() {
        // A peer that reveals a DIFFERENT nonce than it committed to fails verify —
        // this is the check that denies the nonce-after-the-fact grind. Removing the
        // `pair_commit_verify` guard in the state machine makes this attack succeed.
        let (i, r) = ids();
        let offer = vec![1u8; OFFER_LEN];
        let committed = [9u8; PAIR_NONCE_LEN];
        let c = pair_commit(PAIR_ROLE_INITIATOR, &i, &r, &offer, &committed);
        let revealed = [10u8; PAIR_NONCE_LEN];
        assert!(!pair_commit_verify(
            &c,
            PAIR_ROLE_INITIATOR,
            &i,
            &r,
            &offer,
            &revealed
        ));
    }

    #[test]
    fn commit_is_domain_role_and_field_separated() {
        let (i, r) = ids();
        let offer = vec![2u8; OFFER_LEN];
        let reply = vec![2u8; REPLY_LEN];
        let n = [4u8; PAIR_NONCE_LEN];
        // Role changes the commitment (and the contribution width) — no cross-role confusion.
        let ci = pair_commit(PAIR_ROLE_INITIATOR, &i, &r, &offer, &n);
        let cr = pair_commit(PAIR_ROLE_RESPONDER, &i, &r, &reply, &n);
        assert_ne!(ci, cr);
        // The fixed initiator-then-responder identity order is bound: swapping diverges.
        let swapped = pair_commit(PAIR_ROLE_INITIATOR, &r, &i, &offer, &n);
        assert_ne!(ci, swapped);
        // A one-byte change anywhere in the contribution changes the commitment.
        let mut offer2 = offer.clone();
        offer2[0] ^= 0xff;
        assert_ne!(ci, pair_commit(PAIR_ROLE_INITIATOR, &i, &r, &offer2, &n));
        // A one-byte change in the nonce changes the commitment (the hiding property).
        let mut n2 = n;
        n2[31] ^= 0x01;
        assert_ne!(ci, pair_commit(PAIR_ROLE_INITIATOR, &i, &r, &offer, &n2));
    }

    #[test]
    fn contribution_len_pins_role_widths() {
        assert_eq!(contribution_len(PAIR_ROLE_INITIATOR), Some(OFFER_LEN));
        assert_eq!(contribution_len(PAIR_ROLE_RESPONDER), Some(REPLY_LEN));
        assert_eq!(contribution_len(0x00), None);
        assert_eq!(contribution_len(0xff), None);
        assert_ne!(
            OFFER_LEN, REPLY_LEN,
            "distinct role widths → no cross-role preimage overlap"
        );
    }
}
