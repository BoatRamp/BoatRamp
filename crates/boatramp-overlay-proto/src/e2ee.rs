//! Relay-blind end-to-end encryption — the pure crypto core (IU-4).
//!
//! A one-round, identity-signed hybrid-KEM handshake yields an ordered AEAD
//! record session that a **relay cannot read or forge**: the relay forwards
//! sealed records it has no key for. The handshake:
//!
//! 1. the initiator sends a signed KEM offer (`share ‖ pubkey ‖ sig`);
//! 2. the responder **learns** the initiator's identity from the signed share
//!    (it does not pin it — the multi-hop case, `expect = None`), replies with
//!    its own signed share, and derives the shared secret;
//! 3. the initiator **pins** the egress (`expect = Some(egress)`) and derives
//!    the same secret.
//!
//! The channel binding is a transcript hash over **both shares and both
//! identities**, so a substituted identity yields diverging session keys and
//! the AEAD open fails — closing the unknown-key-share attack. aws-lc-rs has no
//! single X25519MLKEM768 primitive, so the hybrid is assembled from ML-KEM-768
//! and X25519 and combined through HKDF.
//!
//! This module is pure: the KEM/AEAD/transcript steps are sync, and the single
//! share signature is produced by a local [`Signer`] (an `async fn`, but no
//! runtime is linked here — the caller in the runtime crate drives it). The
//! async record-mux splice over a live stream lives in the runtime crate.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use aws_lc_rs::rand::SystemRandom;
use boatramp_core::cose::Signer;

use crate::identity::{OverlayId, OverlaySecret};
use crate::wire;

const MLKEM_PUB_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const X25519_PUB_LEN: usize = 32;
const SHARED_LEN: usize = 32;
/// The initiator's KEM offer: ML-KEM-768 public key ‖ X25519 public key.
const OFFER_LEN: usize = MLKEM_PUB_LEN + X25519_PUB_LEN;
/// The responder's KEM reply: ML-KEM-768 ciphertext ‖ X25519 public key.
const REPLY_LEN: usize = MLKEM_CT_LEN + X25519_PUB_LEN;
const SIG_LEN: usize = 64;

/// HKDF `info` separating the two directional keys. Internal (never on the
/// wire), but `bro`-tagged and versioned for hygiene.
const INFO_C2S: &[u8] = b"bro-overlay-c2s-v1";
const INFO_S2C: &[u8] = b"bro-overlay-s2c-v1";

/// Which end of the handshake an endpoint is (decides the directional keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Dialed out; writes the first share. Seals on the client→server key.
    Initiator,
    /// Accepted; learns the initiator's identity. Seals on the server→client key.
    Responder,
}

/// Errors in the E2EE handshake or record session.
#[derive(Debug, thiserror::Error)]
pub enum E2eeError {
    #[error("hybrid KEM operation failed")]
    Kem,
    #[error("X25519 agreement failed")]
    Agreement,
    #[error("AEAD seal/open failed")]
    Aead,
    #[error("HKDF key derivation failed")]
    Hkdf,
    #[error("malformed KEM offer")]
    MalformedOffer,
    #[error("malformed KEM reply")]
    MalformedReply,
    #[error("malformed signed share")]
    MalformedShare,
    #[error("peer identity does not match the pinned identity")]
    IdentityMismatch,
    #[error("share signature: {0}")]
    Signature(String),
    #[error(transparent)]
    Token(#[from] boatramp_core::cose::TokenError),
}

fn combine(ss_pq: &[u8], ss_ec: &[u8]) -> Result<[u8; 64], E2eeError> {
    if ss_pq.len() != SHARED_LEN || ss_ec.len() != SHARED_LEN {
        return Err(E2eeError::Kem);
    }
    let mut out = [0u8; 64];
    out[..SHARED_LEN].copy_from_slice(ss_pq);
    out[SHARED_LEN..].copy_from_slice(ss_ec);
    Ok(out)
}

/// The initiator's ephemeral KEM state, held between sending the offer and
/// receiving the reply.
pub struct HybridInitiator {
    decaps: DecapsulationKey,
    mlkem_pub: Vec<u8>,
    x_priv: EphemeralPrivateKey,
    x_pub: Vec<u8>,
}

impl HybridInitiator {
    /// Generate the initiator's ephemeral ML-KEM-768 + X25519 key material.
    pub fn generate() -> Result<Self, E2eeError> {
        let decaps = DecapsulationKey::generate(&ML_KEM_768).map_err(|_| E2eeError::Kem)?;
        let mlkem_pub = decaps
            .encapsulation_key()
            .and_then(|k| k.key_bytes())
            .map_err(|_| E2eeError::Kem)?
            .as_ref()
            .to_vec();
        let rng = SystemRandom::new();
        let x_priv =
            EphemeralPrivateKey::generate(&X25519, &rng).map_err(|_| E2eeError::Agreement)?;
        let x_pub = x_priv
            .compute_public_key()
            .map_err(|_| E2eeError::Agreement)?
            .as_ref()
            .to_vec();
        Ok(Self {
            decaps,
            mlkem_pub,
            x_priv,
            x_pub,
        })
    }

    /// The KEM offer bytes to sign and send (`ML-KEM pub ‖ X25519 pub`).
    #[must_use]
    pub fn offer(&self) -> Vec<u8> {
        let mut o = Vec::with_capacity(OFFER_LEN);
        o.extend_from_slice(&self.mlkem_pub);
        o.extend_from_slice(&self.x_pub);
        o
    }

    /// Consume the reply and derive the 64-byte combined shared secret
    /// (`ss_mlkem ‖ ss_x25519`).
    pub fn finish(self, reply: &[u8]) -> Result<[u8; 64], E2eeError> {
        if reply.len() != REPLY_LEN {
            return Err(E2eeError::MalformedReply);
        }
        let (ct_bytes, x_pub_r) = reply.split_at(MLKEM_CT_LEN);
        let ss_pq = self
            .decaps
            .decapsulate(Ciphertext::from(ct_bytes))
            .map_err(|_| E2eeError::Kem)?;
        let ss_ec = agree_ephemeral(
            self.x_priv,
            UnparsedPublicKey::new(&X25519, x_pub_r),
            E2eeError::Agreement,
            |secret| Ok(secret.to_vec()),
        )?;
        combine(ss_pq.as_ref(), &ss_ec)
    }
}

/// The responder half: encapsulate against the initiator's offer and derive the
/// shared secret. Returns `(reply bytes to sign+send, combined secret)`.
pub fn hybrid_respond(offer: &[u8]) -> Result<(Vec<u8>, [u8; 64]), E2eeError> {
    if offer.len() != OFFER_LEN {
        return Err(E2eeError::MalformedOffer);
    }
    let (mlkem_pub, x_pub_i) = offer.split_at(MLKEM_PUB_LEN);
    let peer = EncapsulationKey::new(&ML_KEM_768, mlkem_pub).map_err(|_| E2eeError::Kem)?;
    let (ct, ss_pq) = peer.encapsulate().map_err(|_| E2eeError::Kem)?;
    let rng = SystemRandom::new();
    let x_priv = EphemeralPrivateKey::generate(&X25519, &rng).map_err(|_| E2eeError::Agreement)?;
    let x_pub_r = x_priv
        .compute_public_key()
        .map_err(|_| E2eeError::Agreement)?;
    let ss_ec = agree_ephemeral(
        x_priv,
        UnparsedPublicKey::new(&X25519, x_pub_i),
        E2eeError::Agreement,
        |secret| Ok(secret.to_vec()),
    )?;
    let mut reply = Vec::with_capacity(REPLY_LEN);
    reply.extend_from_slice(ct.as_ref());
    reply.extend_from_slice(x_pub_r.as_ref());
    Ok((reply, combine(ss_pq.as_ref(), &ss_ec)?))
}

/// Wrap a KEM share with the sender's identity and a signature over the
/// domain-tagged share: `[share_len u32][share][pubkey 32][sig 64]`. The
/// signature is a local Ed25519 op (overlay guardrail 2).
pub async fn seal_signed_share(share: &[u8], secret: &OverlaySecret) -> Result<Vec<u8>, E2eeError> {
    let mut tbs = Vec::with_capacity(wire::TAG_E2EE_SHARE.len() + share.len());
    tbs.extend_from_slice(wire::TAG_E2EE_SHARE);
    tbs.extend_from_slice(share);
    let sig = secret.signer().sign(&tbs).await?;
    if sig.len() != SIG_LEN {
        return Err(E2eeError::Signature("unexpected signature length".into()));
    }
    let id = secret.id();
    let mut out = Vec::with_capacity(4 + share.len() + X25519_PUB_LEN + SIG_LEN);
    out.extend_from_slice(&(share.len() as u32).to_be_bytes());
    out.extend_from_slice(share);
    out.extend_from_slice(id.as_bytes());
    out.extend_from_slice(&sig);
    Ok(out)
}

/// Verify a signed share and return `(share, sender identity)`. With
/// `expect = Some(id)` the sender must be exactly that identity (the initiator
/// pinning the egress); with `None` the identity is learned from the signed
/// share (the responder's multi-hop case).
pub fn open_signed_share(
    bytes: &[u8],
    expect: Option<&OverlayId>,
) -> Result<(Vec<u8>, OverlayId), E2eeError> {
    if bytes.len() < 4 {
        return Err(E2eeError::MalformedShare);
    }
    let (len_be, rest) = bytes.split_at(4);
    let share_len = u32::from_be_bytes(len_be.try_into().expect("4 bytes")) as usize;
    if rest.len() != share_len + X25519_PUB_LEN + SIG_LEN {
        return Err(E2eeError::MalformedShare);
    }
    let (share, tail) = rest.split_at(share_len);
    let (pubkey, sig) = tail.split_at(X25519_PUB_LEN);
    let id = OverlayId::try_from_bytes(pubkey.try_into().expect("32 bytes"))
        .map_err(|e| E2eeError::Signature(e.to_string()))?;
    if let Some(expected) = expect {
        if id != *expected {
            return Err(E2eeError::IdentityMismatch);
        }
    }
    let mut tbs = Vec::with_capacity(wire::TAG_E2EE_SHARE.len() + share.len());
    tbs.extend_from_slice(wire::TAG_E2EE_SHARE);
    tbs.extend_from_slice(share);
    id.to_public().verify(&tbs, sig)?;
    Ok((share.to_vec(), id))
}

/// The channel-binding transcript: `SHA-256(offer ‖ reply ‖ initiator ‖
/// responder)`. Folding both identities in is what closes unknown-key-share.
#[must_use]
pub fn transcript(
    offer: &[u8],
    reply: &[u8],
    initiator: &OverlayId,
    responder: &OverlayId,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(offer);
    h.update(reply);
    h.update(initiator.as_bytes());
    h.update(responder.as_bytes());
    h.finalize().into()
}

fn nonce_from_ctr(ctr: u64) -> Nonce {
    let mut n = [0u8; 12];
    n[4..].copy_from_slice(&ctr.to_be_bytes());
    Nonce::assume_unique_for_key(n)
}

/// An established AEAD record session. Splits into a [`Sealer`] and [`Opener`]
/// so the two record-mux pumps can run concurrently.
pub struct Session {
    seal: LessSafeKey,
    open: LessSafeKey,
}

impl Session {
    /// Derive the directional keys from the combined KEM secret bound to the
    /// handshake transcript (so the keys depend on both identities).
    pub fn new(combined: &[u8], transcript: &[u8; 32], role: Role) -> Result<Self, E2eeError> {
        let prk = Salt::new(HKDF_SHA256, transcript).extract(combined);
        let derive = |info: &[u8]| -> Result<LessSafeKey, E2eeError> {
            // `info_slices` must outlive the `Okm` it is borrowed by.
            let info_slices = [info];
            let okm = prk
                .expand(&info_slices, &AES_256_GCM)
                .map_err(|_| E2eeError::Hkdf)?;
            Ok(LessSafeKey::new(UnboundKey::from(okm)))
        };
        let c2s = derive(INFO_C2S)?;
        let s2c = derive(INFO_S2C)?;
        let (seal, open) = match role {
            Role::Initiator => (c2s, s2c),
            Role::Responder => (s2c, c2s),
        };
        Ok(Self { seal, open })
    }

    /// Split into the send and receive halves.
    #[must_use]
    pub fn split(self) -> (Sealer, Opener) {
        (
            Sealer {
                key: self.seal,
                ctr: 0,
            },
            Opener {
                key: self.open,
                ctr: 0,
            },
        )
    }
}

/// The send half: seals successive records under a monotonic counter nonce.
pub struct Sealer {
    key: LessSafeKey,
    ctr: u64,
}

impl Sealer {
    /// Seal one record. Records must be opened by the peer in send order.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, E2eeError> {
        let nonce = nonce_from_ctr(self.ctr);
        self.ctr += 1;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
            .map_err(|_| E2eeError::Aead)?;
        Ok(buf)
    }
}

/// The receive half: opens successive records under a monotonic counter nonce.
pub struct Opener {
    key: LessSafeKey,
    ctr: u64,
}

impl Opener {
    /// Open one record (ciphertext‖tag). Must be called in the peer's send order.
    pub fn open(&mut self, record: &[u8]) -> Result<Vec<u8>, E2eeError> {
        let nonce = nonce_from_ctr(self.ctr);
        self.ctr += 1;
        let mut buf = record.to_vec();
        let plaintext = self
            .key
            .open_in_place(nonce, Aad::empty(), &mut buf)
            .map_err(|_| E2eeError::Aead)?;
        Ok(plaintext.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::OverlaySecret;

    /// Run the full signed-share handshake in memory and return both split
    /// sessions plus the learned identities.
    async fn handshake(
        init: &OverlaySecret,
        resp: &OverlaySecret,
        pinned_egress: &OverlayId,
    ) -> ((Sealer, Opener), (Sealer, Opener), OverlayId, OverlayId) {
        let hi = HybridInitiator::generate().unwrap();
        let offer = hi.offer();
        let signed_offer = seal_signed_share(&offer, init).await.unwrap();

        // Responder LEARNS the initiator (expect=None), replies, derives secret.
        let (offer_back, init_id) = open_signed_share(&signed_offer, None).unwrap();
        assert_eq!(offer_back, offer);
        let (reply, combined_r) = hybrid_respond(&offer_back).unwrap();
        let signed_reply = seal_signed_share(&reply, resp).await.unwrap();

        // Initiator PINS the egress, derives the same secret.
        let (reply_back, resp_id) = open_signed_share(&signed_reply, Some(pinned_egress)).unwrap();
        let combined_i = hi.finish(&reply_back).unwrap();
        assert_eq!(
            combined_i, combined_r,
            "both ends derive the same KEM secret"
        );

        let t = transcript(&offer, &reply, &init_id, &resp_id);
        let si = Session::new(&combined_i, &t, Role::Initiator).unwrap();
        let sr = Session::new(&combined_r, &t, Role::Responder).unwrap();
        (si.split(), sr.split(), init_id, resp_id)
    }

    #[tokio::test]
    async fn handshake_yields_matching_bidirectional_session() {
        let init = OverlaySecret::generate().unwrap();
        let resp = OverlaySecret::generate().unwrap();
        let ((mut si_seal, mut si_open), (mut sr_seal, mut sr_open), init_id, resp_id) =
            handshake(&init, &resp, &resp.id()).await;

        assert_eq!(init_id, init.id());
        assert_eq!(resp_id, resp.id());

        let ct = si_seal.seal(b"ping").unwrap();
        assert_ne!(ct, b"ping", "a relay sees only ciphertext");
        assert_eq!(sr_open.open(&ct).unwrap(), b"ping");

        let ct2 = sr_seal.seal(b"pong").unwrap();
        assert_eq!(si_open.open(&ct2).unwrap(), b"pong");
    }

    #[tokio::test]
    async fn records_stay_in_lockstep() {
        let init = OverlaySecret::generate().unwrap();
        let resp = OverlaySecret::generate().unwrap();
        let ((mut si_seal, _), (_, mut sr_open), ..) = handshake(&init, &resp, &resp.id()).await;
        for i in 0..5u8 {
            let msg = [i; 10];
            let ct = si_seal.seal(&msg).unwrap();
            assert_eq!(sr_open.open(&ct).unwrap(), msg);
        }
    }

    #[tokio::test]
    async fn initiator_rejects_a_wrong_pinned_egress() {
        let init = OverlaySecret::generate().unwrap();
        let resp = OverlaySecret::generate().unwrap();
        let stranger = OverlaySecret::generate().unwrap();

        let hi = HybridInitiator::generate().unwrap();
        let signed_offer = seal_signed_share(&hi.offer(), &init).await.unwrap();
        let (offer_back, _) = open_signed_share(&signed_offer, None).unwrap();
        let (reply, _) = hybrid_respond(&offer_back).unwrap();
        let signed_reply = seal_signed_share(&reply, &resp).await.unwrap();

        // The initiator pinned `stranger`, but `resp` signed the reply.
        assert!(matches!(
            open_signed_share(&signed_reply, Some(&stranger.id())),
            Err(E2eeError::IdentityMismatch)
        ));
    }

    #[test]
    fn a_substituted_identity_breaks_the_session() {
        // Same KEM secret, but the responder's transcript folds a DIFFERENT
        // initiator id (an unknown-key-share attempt) → diverging keys → the
        // AEAD open fails. This is the channel binding doing its job.
        let resp = OverlaySecret::generate().unwrap();
        let real_init = OverlaySecret::generate().unwrap().id();
        let forged_init = OverlaySecret::generate().unwrap().id();

        let hi = HybridInitiator::generate().unwrap();
        let offer = hi.offer();
        let (reply, combined_r) = hybrid_respond(&offer).unwrap();
        let combined_i = hi.finish(&reply).unwrap();

        let t_honest = transcript(&offer, &reply, &real_init, &resp.id());
        let t_forged = transcript(&offer, &reply, &forged_init, &resp.id());

        let (mut seal, _) = Session::new(&combined_i, &t_honest, Role::Initiator)
            .unwrap()
            .split();
        let (_, mut open) = Session::new(&combined_r, &t_forged, Role::Responder)
            .unwrap()
            .split();

        let ct = seal.seal(b"secret").unwrap();
        assert!(
            open.open(&ct).is_err(),
            "a diverging-identity transcript must fail AEAD open"
        );
    }

    #[tokio::test]
    async fn a_tampered_signed_share_is_rejected() {
        let init = OverlaySecret::generate().unwrap();
        let hi = HybridInitiator::generate().unwrap();
        let mut signed = seal_signed_share(&hi.offer(), &init).await.unwrap();
        signed[8] ^= 0xff; // flip a byte inside the share
        assert!(open_signed_share(&signed, None).is_err());
    }
}
