//! Commit-then-reveal SAS pairing — the async runtime (overlay follow-up #2).
//!
//! [`pair_handshake`] drives the relay-blind E2EE KEM handshake
//! ([`boatramp_overlay_proto::e2ee`]) and then a sealed commit-then-reveal nonce
//! exchange over the resulting [`Session`], yielding the short authentication
//! string (SAS) two operators compare out-of-band to detect an active
//! man-in-the-middle. It is **transport-agnostic**: it runs over any ordered
//! duplex (`AsyncWrite`/`AsyncRead`), so the direct-dial QUIC transport this
//! increment ships ([`crate::quic::pair_dial_endpoint`] + a
//! [`crate::quic::server_endpoint`] under `AcceptAny`) and the relay-blind
//! `bropair1` rendezvous of the next increment both bolt on without changing a
//! line here.
//!
//! ## The handshake (I = initiator/dialer, R = responder/listener)
//!
//! Phase A runs the KEM handshake exactly as [`crate::e2ee::establish`] does, but
//! via the **public pure primitives** and with `expect = None` on **both** sides
//! — pairing peers *learn* each other's E2EE-proven [`OverlayId`]; they do not
//! pin an egress. (`establish` itself is untouched; forward/expose depend on it.)
//! That yields the sealed [`Session`], the channel-binding `transcript`, both
//! KEM contributions (`offer`/`reply`), and both proven identities.
//!
//! Phase B, over the sealed session, is the classic commit-then-reveal:
//! ```text
//! 1. I→R: commit_I            (n_I HIDDEN; binds offer_I)
//! 2. R→I: commit_R            (n_R HIDDEN; binds reply_R)  — I has it before revealing
//! 3. I→R: reveal n_I          (only after commit_R received)
//! 4. R: verify commit_I; abort on mismatch; then R→I: reveal n_R  (only after verifying I)
//! 5. I: verify commit_R; abort on mismatch
//! BOTH: SAS = sas_from_pair_transcript(transcript, n_I, n_R)
//! ```
//! The KEM `offer`/`reply` each commitment binds are already on the wire and
//! AEAD-bound into the transcript from phase A, so phase B carries only the
//! 32-byte commitments and 32-byte reveals.
//!
//! ## Fail-closed
//!
//! Every error path aborts with no SAS derived and no peer pinned, and logs a
//! security event: an AEAD open failure, a commitment mismatch (equivocation),
//! an unexpected/duplicate/out-of-order record, a malformed/short record, a
//! revealed nonce that is not exactly 32 bytes, a reflected identity
//! (`id_I == id_R`), a timeout bounding the pairing window, or a disconnect. The
//! sealed session's counter-nonce AEAD already enforces strict record ordering
//! (an out-of-order record fails to open); the explicit record-kind tag makes the
//! state machine's expectations explicit and rejects a malformed record early.

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use boatramp_overlay_proto::e2ee::{
    E2eeError, HybridInitiator, Opener, Role, Sealer, Session, hybrid_respond, open_signed_share,
    seal_signed_share, transcript,
};
use boatramp_overlay_proto::identity::{OverlayId, OverlaySecret};
use boatramp_overlay_proto::pairing::{
    PAIR_NONCE_LEN, PAIR_ROLE_INITIATOR, PAIR_ROLE_RESPONDER, pair_commit, pair_commit_verify,
};
use boatramp_overlay_proto::sas::{Fingerprint, SasCode, identity_fp, sas_from_pair_transcript};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::e2ee::{SpliceError, read_lp, write_lp};

/// Upper bound on a signed KEM share on the wire (shares are ~1.2 KiB; generous).
/// Kept local so pairing does not reach into `e2ee`'s private consts; it mirrors
/// the bound `establish` applies.
const PAIR_SHARE_MAX: usize = 8 * 1024;

/// Sealed pairing-record kind (the sealed plaintext's first byte): a 32-byte
/// commitment follows.
const PAIR_REC_COMMIT: u8 = 0x01;
/// Sealed pairing-record kind: a 32-byte revealed nonce follows.
const PAIR_REC_REVEAL: u8 = 0x02;

/// A sealed pairing record's plaintext: a 1-byte kind + a 32-byte payload.
const PAIR_REC_LEN: usize = 1 + PAIR_NONCE_LEN;

/// Upper bound on a sealed pairing record on the wire (plaintext + AEAD tag;
/// small and fixed — anything larger is a protocol error, not a buffer to grow).
const PAIR_REC_MAX: usize = PAIR_REC_LEN + 64;

/// A pairing-handshake failure. Every variant is a **fail-closed abort**: the
/// caller gets no SAS and must pin nothing.
#[derive(Debug, thiserror::Error)]
pub enum PairError {
    /// A KEM/AEAD/identity error from the relay-blind handshake layer.
    #[error(transparent)]
    E2ee(#[from] E2eeError),
    /// A framing error reading/writing a length-delimited record.
    #[error(transparent)]
    Splice(#[from] SpliceError),
    /// Transport IO failed.
    #[error("transport io: {0}")]
    Io(#[from] std::io::Error),
    /// The peer closed the stream before the handshake completed.
    #[error("peer closed the stream before the pairing handshake completed")]
    Closed,
    /// Both ends resolved to the SAME overlay identity — a reflected/degenerate
    /// pairing (e.g. a loopback reflection), never valid.
    #[error("the two peers resolved to the same overlay identity (reflected/degenerate pairing)")]
    ReflectedIdentity,
    /// A peer revealed a nonce it did not commit to (equivocation).
    #[error("pairing commitment mismatch: a peer revealed a nonce it did not commit to")]
    CommitmentMismatch,
    /// A record of an unexpected kind arrived (out-of-order / duplicate / wrong step).
    #[error("unexpected or out-of-order pairing record (kind {got:#04x}, expected {want:#04x})")]
    UnexpectedRecord {
        /// The record kind the state machine expected at this step.
        want: u8,
        /// The record kind that actually arrived.
        got: u8,
    },
    /// A record was the wrong length (a reveal nonce not exactly 32 bytes, or a
    /// malformed/short plaintext).
    #[error("malformed pairing record (plaintext len {0}, expected {PAIR_REC_LEN})")]
    MalformedRecord(usize),
    /// The pairing window elapsed before the handshake completed.
    #[error("pairing handshake timed out")]
    Timeout,
    /// Generating a pairing nonce from the platform RNG failed.
    #[error("generating a pairing nonce failed")]
    Rng,
}

/// Run the commit-then-reveal SAS pairing handshake over `(send, recv)` as `role`
/// and return the derived [`SasCode`] (for the operators to compare out-of-band)
/// and the peer's E2EE-proven [`OverlayId`] (the identity to pin on confirm — it
/// is NEVER operator-typed). The whole exchange is bounded by `deadline`; on any
/// error it aborts fail-closed (no SAS, no pin) and logs a security event.
///
/// `expect = None` on both sides: pairing LEARNS the peer's identity; it does not
/// use the pinned-egress mode. `establish` is not modified or called.
pub async fn pair_handshake<S, R>(
    send: &mut S,
    recv: &mut R,
    secret: &OverlaySecret,
    role: Role,
    deadline: Duration,
) -> Result<(SasCode, OverlayId), PairError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let outcome = tokio::time::timeout(deadline, pair_inner(send, recv, secret, role))
        .await
        .unwrap_or(Err(PairError::Timeout));
    if let Err(ref e) = outcome {
        // ONE consolidated security event covering every fail-closed abort path (AEAD open failure,
        // commitment mismatch, reflected id, malformed/out-of-order record, timeout, disconnect).
        tracing::warn!(
            target: "overlay.pair",
            error = %e,
            "overlay pairing aborted (fail-closed): no SAS derived, no peer pinned"
        );
    }
    outcome
}

async fn pair_inner<S, R>(
    send: &mut S,
    recv: &mut R,
    secret: &OverlaySecret,
    role: Role,
) -> Result<(SasCode, OverlayId), PairError>
where
    S: AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
{
    let rng = SystemRandom::new();

    // --- Phase A: the relay-blind KEM handshake, expect=None on BOTH sides. Driven via the PUBLIC
    //     pure primitives exactly as `establish` does (which is left untouched). Yields the sealed
    //     session, the channel-binding transcript, both KEM contributions, and both proven ids. ---
    let scaffold = match role {
        Role::Initiator => {
            let hi = HybridInitiator::generate()?;
            let offer = hi.offer();
            write_lp(send, &seal_signed_share(&offer, secret).await?).await?;
            let signed_reply = read_lp(recv, PAIR_SHARE_MAX)
                .await?
                .ok_or(PairError::Closed)?;
            let (reply, peer) = open_signed_share(&signed_reply, None)?;
            let combined = hi.finish(&reply)?;
            let (id_i, id_r) = (secret.id(), peer);
            let t = transcript(&offer, &reply, &id_i, &id_r);
            let session = Session::new(&combined, &t, Role::Initiator)?;
            Scaffold {
                session,
                t,
                offer,
                reply,
                id_i,
                id_r,
                peer,
            }
        }
        Role::Responder => {
            let signed_offer = read_lp(recv, PAIR_SHARE_MAX)
                .await?
                .ok_or(PairError::Closed)?;
            let (offer, peer) = open_signed_share(&signed_offer, None)?;
            let (reply, combined) = hybrid_respond(&offer)?;
            write_lp(send, &seal_signed_share(&reply, secret).await?).await?;
            let (id_i, id_r) = (peer, secret.id());
            let t = transcript(&offer, &reply, &id_i, &id_r);
            let session = Session::new(&combined, &t, Role::Responder)?;
            Scaffold {
                session,
                t,
                offer,
                reply,
                id_i,
                id_r,
                peer,
            }
        }
    };

    // Fail-closed: a reflected/degenerate pairing (both sides the same identity) is never valid.
    if scaffold.id_i == scaffold.id_r {
        return Err(PairError::ReflectedIdentity);
    }

    let Scaffold {
        session,
        t,
        offer,
        reply,
        id_i,
        id_r,
        peer,
    } = scaffold;
    let (mut sealer, mut opener) = session.split();

    // My fresh, exactly-32-byte nonce (platform RNG).
    let my_nonce = random_nonce(&rng)?;

    // --- Phase B: commit-then-reveal over the sealed session. The AEAD counter-nonce already
    //     enforces strict ordering (an out-of-order record fails to open); the kind tag makes the
    //     expected step explicit and rejects a malformed record early. ---
    let (n_i, n_r) = match role {
        Role::Initiator => {
            let commit_i = pair_commit(PAIR_ROLE_INITIATOR, &id_i, &id_r, &offer, &my_nonce);
            // 1. I→R: commit_I (n_I stays hidden).
            send_rec(send, &mut sealer, PAIR_REC_COMMIT, &commit_i).await?;
            // 2. R→I: commit_R — MUST be in hand before we reveal n_I.
            let commit_r = recv_rec(recv, &mut opener, PAIR_REC_COMMIT).await?;
            // 3. I→R: reveal n_I (only now).
            send_rec(send, &mut sealer, PAIR_REC_REVEAL, &my_nonce).await?;
            // 4. R→I: reveal n_R.
            let n_r = recv_rec(recv, &mut opener, PAIR_REC_REVEAL).await?;
            // 5. verify R's commitment against its contribution (reply) + revealed n_R.
            if !pair_commit_verify(&commit_r, PAIR_ROLE_RESPONDER, &id_i, &id_r, &reply, &n_r) {
                return Err(PairError::CommitmentMismatch);
            }
            (my_nonce, n_r)
        }
        Role::Responder => {
            let commit_r = pair_commit(PAIR_ROLE_RESPONDER, &id_i, &id_r, &reply, &my_nonce);
            // 1. recv commit_I.
            let commit_i = recv_rec(recv, &mut opener, PAIR_REC_COMMIT).await?;
            // 2. R→I: commit_R (n_R stays hidden).
            send_rec(send, &mut sealer, PAIR_REC_COMMIT, &commit_r).await?;
            // 3. recv reveal n_I.
            let n_i = recv_rec(recv, &mut opener, PAIR_REC_REVEAL).await?;
            // 4. verify I's commitment against its contribution (offer) + revealed n_I, BEFORE
            //    revealing n_R.
            if !pair_commit_verify(&commit_i, PAIR_ROLE_INITIATOR, &id_i, &id_r, &offer, &n_i) {
                return Err(PairError::CommitmentMismatch);
            }
            // 5. R→I: reveal n_R (only after verifying I's reveal).
            send_rec(send, &mut sealer, PAIR_REC_REVEAL, &my_nonce).await?;
            (n_i, my_nonce)
        }
    };

    // Both ends derive the same code from the shared transcript + both revealed nonces (n_I is the
    // initiator's, n_R the responder's, in that fixed order).
    let sas = sas_from_pair_transcript(&t, &n_i, &n_r);
    Ok((sas, peer))
}

/// Everything phase A produces that phase B needs.
struct Scaffold {
    session: Session,
    t: [u8; 32],
    offer: Vec<u8>,
    reply: Vec<u8>,
    /// The initiator identity (fixed order), whoever computed it.
    id_i: OverlayId,
    /// The responder identity (fixed order), whoever computed it.
    id_r: OverlayId,
    /// The OTHER side's identity — what this side learned and would pin.
    peer: OverlayId,
}

/// A fresh, exactly-[`PAIR_NONCE_LEN`]-byte nonce from the platform RNG.
fn random_nonce(rng: &SystemRandom) -> Result<[u8; PAIR_NONCE_LEN], PairError> {
    let mut n = [0u8; PAIR_NONCE_LEN];
    rng.fill(&mut n).map_err(|_| PairError::Rng)?;
    Ok(n)
}

/// Seal and send one pairing record (`kind` byte + 32-byte payload) as a length-delimited blob.
async fn send_rec<S: AsyncWrite + Unpin>(
    send: &mut S,
    sealer: &mut Sealer,
    kind: u8,
    payload: &[u8; PAIR_NONCE_LEN],
) -> Result<(), PairError> {
    let mut pt = Vec::with_capacity(PAIR_REC_LEN);
    pt.push(kind);
    pt.extend_from_slice(payload);
    let sealed = sealer.seal(&pt)?;
    write_lp(send, &sealed).await?;
    Ok(())
}

/// Read, open, and validate one pairing record, requiring kind `want`. Aborts on a closed stream,
/// an AEAD open failure (which includes an out-of-order record under the counter nonce), an
/// unexpected kind, or a wrong-length plaintext (e.g. a reveal nonce not exactly 32 bytes).
async fn recv_rec<R: AsyncRead + Unpin>(
    recv: &mut R,
    opener: &mut Opener,
    want: u8,
) -> Result<[u8; PAIR_NONCE_LEN], PairError> {
    let sealed = read_lp(recv, PAIR_REC_MAX)
        .await?
        .ok_or(PairError::Closed)?;
    let pt = opener.open(&sealed)?;
    if pt.len() != PAIR_REC_LEN {
        return Err(PairError::MalformedRecord(pt.len()));
    }
    let kind = pt[0];
    if kind != want {
        return Err(PairError::UnexpectedRecord { want, got: kind });
    }
    let mut payload = [0u8; PAIR_NONCE_LEN];
    payload.copy_from_slice(&pt[1..]);
    Ok(payload)
}

/// A peer verified out-of-band via the pairing SAS and pinned locally.
#[derive(Clone, Copy, Debug)]
pub struct VerifiedPeer {
    /// The display fingerprint of the pinned identity ([`identity_fp`]).
    pub fingerprint: Fingerprint,
    /// When the SAS was confirmed and the peer pinned.
    pub verified_at: SystemTime,
}

/// The in-memory set of overlay identities verified by an out-of-band SAS
/// comparison and pinned **locally**.
///
/// A peer is pinned ONLY after a positive, operator-confirmed SAS match — never
/// from a wire signal. (A "peer confirmed" wire record would be UX only and must
/// not gate the pin: the pairing wire is MITM-controlled.) The pinned value is
/// always the E2EE-proven [`OverlayId`] returned by [`pair_handshake`], never an
/// operator-typed identity. This increment keeps the set in memory for the
/// pairing session; a KV-persistent verified pin is deferred to the next
/// increment.
#[derive(Default)]
pub struct VerifiedPeers {
    peers: HashMap<OverlayId, VerifiedPeer>,
}

impl VerifiedPeers {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pin `id` after a CONFIRMED out-of-band SAS match. Idempotent — re-confirming refreshes
    /// `verified_at`. Returns the stored record (its fingerprint is [`identity_fp`] of `id`).
    pub fn confirm(&mut self, id: OverlayId) -> VerifiedPeer {
        let vp = VerifiedPeer {
            fingerprint: identity_fp(&id),
            verified_at: SystemTime::now(),
        };
        self.peers.insert(id, vp);
        vp
    }

    /// Record a REJECTED pairing: logs a security event and pins NOTHING (fail-closed). Kept
    /// distinct from [`confirm`](Self::confirm) so the two outcomes are explicit at the call site.
    pub fn reject(&self, id: &OverlayId) {
        tracing::warn!(
            target: "overlay.pair",
            peer = ?id,
            "overlay pairing REJECTED: identity NOT pinned"
        );
    }

    /// The pin record for `id`, if verified.
    #[must_use]
    pub fn get(&self, id: &OverlayId) -> Option<&VerifiedPeer> {
        self.peers.get(id)
    }

    /// Whether `id` has been verified and pinned.
    #[must_use]
    pub fn is_verified(&self, id: &OverlayId) -> bool {
        self.peers.contains_key(id)
    }

    /// How many peers are pinned.
    #[must_use]
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Whether no peers are pinned.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncRead, AsyncWrite};

    const DL: Duration = Duration::from_secs(10);

    /// Run a pairing between two identities over an in-memory duplex (transport-agnostic — the real
    /// direct-dial QUIC transport is exercised in `pair_over_loopback_quic_direct_dial`). Returns
    /// each side's `(SAS, learned peer)` result.
    async fn pair_over_duplex(
        init: OverlaySecret,
        resp: OverlaySecret,
    ) -> (
        Result<(SasCode, OverlayId), PairError>,
        Result<(SasCode, OverlayId), PairError>,
    ) {
        let (ia, ib) = tokio::io::duplex(64 * 1024);
        let (mut ia_r, mut ia_w) = tokio::io::split(ia);
        let (mut ib_r, mut ib_w) = tokio::io::split(ib);
        let it = tokio::spawn(async move {
            pair_handshake(&mut ia_w, &mut ia_r, &init, Role::Initiator, DL).await
        });
        let r = pair_handshake(&mut ib_w, &mut ib_r, &resp, Role::Responder, DL).await;
        (it.await.unwrap(), r)
    }

    #[tokio::test]
    async fn two_honest_peers_derive_the_same_sas_and_pin_each_other() {
        let a = OverlaySecret::generate().unwrap();
        let b = OverlaySecret::generate().unwrap();
        let (a_id, b_id) = (a.id(), b.id());

        let (i, r) = pair_over_duplex(a, b).await;
        let (sas_i, peer_i) = i.unwrap();
        let (sas_r, peer_r) = r.unwrap();

        // The humans compare: two honest peers see the SAME code (both renderings + raw bits).
        assert_eq!(sas_i.words(), sas_r.words());
        assert_eq!(sas_i.digits(), sas_r.digits());
        assert_eq!(sas_i.bits(), sas_r.bits());

        // Each learned the OTHER's E2EE-proven identity.
        assert_eq!(peer_i, b_id);
        assert_eq!(peer_r, a_id);

        // On confirm, each side pins the other (local, in-memory) — fingerprint = identity_fp.
        let mut pins_a = VerifiedPeers::new();
        let mut pins_b = VerifiedPeers::new();
        pins_a.confirm(peer_i);
        pins_b.confirm(peer_r);
        assert!(pins_a.is_verified(&b_id));
        assert!(pins_b.is_verified(&a_id));
        assert_eq!(pins_a.get(&b_id).unwrap().fingerprint, identity_fp(&b_id));
        assert_eq!(pins_a.len(), 1);
    }

    #[test]
    fn reject_pins_nothing_fail_closed() {
        // A rejected pairing records a security event and inserts NOTHING (fail-closed).
        let pins = VerifiedPeers::new();
        let stranger = OverlaySecret::generate().unwrap().id();
        pins.reject(&stranger);
        assert!(!pins.is_verified(&stranger));
        assert!(pins.is_empty());
    }

    #[tokio::test]
    async fn two_leg_mitm_makes_the_human_visible_sas_diverge() {
        // A dials, B listens, but M (a man-in-the-middle) terminates BOTH legs — responder to A,
        // initiator to B. M cannot relay sealed records (it has no session keys), so it must run
        // two DISTINCT handshakes. The operators at A and B then compare codes derived from two
        // different transcripts + different nonce pairs → the codes DIVERGE, revealing the MITM.
        //
        // The further claim — that the commitment denies M an online attempt to force the codes
        // equal (and that removing the nonce from the SAS ikm makes the attack succeed, RED) — is
        // proven at the function level in `sas::pair_sas_denies_the_offline_transcript_grind`, and
        // the commitment's binding is proven by the equivocation + ordering tests below.
        let a = OverlaySecret::generate().unwrap();
        let b = OverlaySecret::generate().unwrap();
        let m = OverlaySecret::generate().unwrap();
        let (a_id, b_id, m_id) = (a.id(), b.id(), m.id());
        let m_other_leg = OverlaySecret::from_seed_hex(&m.seed_hex()).unwrap(); // same identity

        // Leg 1: A (initiator) <-> M (responder).
        let (i1, r1) = pair_over_duplex(a, m).await;
        let (sas_a, learned_by_a) = i1.unwrap();
        r1.unwrap();
        // Leg 2: M (initiator) <-> B (responder).
        let (i2, r2) = pair_over_duplex(m_other_leg, b).await;
        i2.unwrap();
        let (sas_b, learned_by_b) = r2.unwrap();

        // A and B each believe they paired with M (the proven id is M's, not each other's) — so the
        // SAS is the ONLY cross-check, and it diverges.
        assert_eq!(learned_by_a, m_id);
        assert_eq!(learned_by_b, m_id);
        assert_ne!(m_id, a_id);
        assert_ne!(m_id, b_id);
        assert_ne!(
            sas_a.bits(),
            sas_b.bits(),
            "a two-leg MITM yields diverging SAS codes — the out-of-band comparison catches it"
        );
    }

    #[tokio::test]
    async fn responder_aborts_on_initiator_equivocation() {
        // A dishonest initiator commits to one nonce but REVEALS a different one. The honest
        // responder recomputes the commitment over the revealed nonce and aborts
        // (CommitmentMismatch). Removing the `pair_commit_verify` guard would let this through.
        let a = OverlaySecret::generate().unwrap();
        let b = OverlaySecret::generate().unwrap();
        let (ia, ib) = tokio::io::duplex(64 * 1024);
        let (mut ia_r, mut ia_w) = tokio::io::split(ia);
        let (mut ib_r, mut ib_w) = tokio::io::split(ib);

        let it = tokio::spawn(async move {
            let mut sc = init_phase_a(&mut ia_w, &mut ia_r, &a).await.unwrap();
            let committed = [1u8; PAIR_NONCE_LEN];
            let revealed = [2u8; PAIR_NONCE_LEN]; // != committed → equivocation
            let commit_i = pair_commit(
                PAIR_ROLE_INITIATOR,
                &sc.id_i,
                &sc.id_r,
                &sc.offer,
                &committed,
            );
            send_rec(&mut ia_w, &mut sc.sealer, PAIR_REC_COMMIT, &commit_i)
                .await
                .unwrap();
            let _commit_r = recv_rec(&mut ia_r, &mut sc.opener, PAIR_REC_COMMIT)
                .await
                .unwrap();
            let _ = send_rec(&mut ia_w, &mut sc.sealer, PAIR_REC_REVEAL, &revealed).await;
        });

        let r = pair_handshake(&mut ib_w, &mut ib_r, &b, Role::Responder, DL).await;
        assert!(
            matches!(r, Err(PairError::CommitmentMismatch)),
            "expected CommitmentMismatch, got {r:?}"
        );
        let _ = it.await;
    }

    #[tokio::test]
    async fn responder_aborts_on_an_out_of_order_first_record() {
        // Early reveal / out-of-order: the initiator sends a REVEAL where the responder expects a
        // COMMIT as the first sealed record → UnexpectedRecord.
        let a = OverlaySecret::generate().unwrap();
        let b = OverlaySecret::generate().unwrap();
        let (ia, ib) = tokio::io::duplex(64 * 1024);
        let (mut ia_r, mut ia_w) = tokio::io::split(ia);
        let (mut ib_r, mut ib_w) = tokio::io::split(ib);

        let it = tokio::spawn(async move {
            let mut sc = init_phase_a(&mut ia_w, &mut ia_r, &a).await.unwrap();
            // Wrong first record: a REVEAL instead of a COMMIT.
            let _ = send_rec(
                &mut ia_w,
                &mut sc.sealer,
                PAIR_REC_REVEAL,
                &[7u8; PAIR_NONCE_LEN],
            )
            .await;
        });

        let r = pair_handshake(&mut ib_w, &mut ib_r, &b, Role::Responder, DL).await;
        assert!(
            matches!(
                r,
                Err(PairError::UnexpectedRecord {
                    want: PAIR_REC_COMMIT,
                    got: PAIR_REC_REVEAL
                })
            ),
            "expected UnexpectedRecord, got {r:?}"
        );
        let _ = it.await;
    }

    #[tokio::test]
    async fn responder_aborts_on_a_wrong_length_reveal() {
        // A revealed nonce must be exactly 32 bytes: a short reveal payload → MalformedRecord.
        let a = OverlaySecret::generate().unwrap();
        let b = OverlaySecret::generate().unwrap();
        let (ia, ib) = tokio::io::duplex(64 * 1024);
        let (mut ia_r, mut ia_w) = tokio::io::split(ia);
        let (mut ib_r, mut ib_w) = tokio::io::split(ib);

        let it = tokio::spawn(async move {
            let mut sc = init_phase_a(&mut ia_w, &mut ia_r, &a).await.unwrap();
            let n = [3u8; PAIR_NONCE_LEN];
            let commit_i = pair_commit(PAIR_ROLE_INITIATOR, &sc.id_i, &sc.id_r, &sc.offer, &n);
            send_rec(&mut ia_w, &mut sc.sealer, PAIR_REC_COMMIT, &commit_i)
                .await
                .unwrap();
            let _commit_r = recv_rec(&mut ia_r, &mut sc.opener, PAIR_REC_COMMIT)
                .await
                .unwrap();
            // A malformed reveal: a short plaintext (kind byte + only 3 payload bytes).
            let sealed = sc.sealer.seal(&[PAIR_REC_REVEAL, 1, 2, 3]).unwrap();
            let _ = write_lp(&mut ia_w, &sealed).await;
        });

        let r = pair_handshake(&mut ib_w, &mut ib_r, &b, Role::Responder, DL).await;
        assert!(
            matches!(r, Err(PairError::MalformedRecord(_))),
            "expected MalformedRecord, got {r:?}"
        );
        let _ = it.await;
    }

    #[tokio::test]
    async fn reflected_identity_is_rejected_on_both_ends() {
        // Both ends use the SAME identity (a reflection): id_i == id_r → ReflectedIdentity on both.
        let s = OverlaySecret::generate().unwrap();
        let s2 = OverlaySecret::from_seed_hex(&s.seed_hex()).unwrap();
        let (i, r) = pair_over_duplex(s, s2).await;
        assert!(
            matches!(i, Err(PairError::ReflectedIdentity)),
            "initiator: expected ReflectedIdentity, got {i:?}"
        );
        assert!(
            matches!(r, Err(PairError::ReflectedIdentity)),
            "responder: expected ReflectedIdentity, got {r:?}"
        );
    }

    // Uses the accept-side `server_endpoint` + `accept` (server-gated), so this transport test builds
    // only with the `server` feature; the pure pairing-handshake tests above are client-buildable.
    #[cfg(feature = "server")]
    #[tokio::test]
    async fn pair_over_loopback_quic_direct_dial() {
        // The direct-dial transport: one peer listens (server_endpoint under AcceptAny), the other
        // dials (pair_dial_endpoint, TOFU at TLS). Neither pins the other at the TLS layer; the
        // E2EE handshake + SAS authenticate. Both derive the same SAS and learn each other's id.
        use crate::quic::{accept, dial, pair_dial_endpoint, server_endpoint};
        use boatramp_overlay_proto::peer_policy::OverlayPeerPolicy::AcceptAny;

        let a = OverlaySecret::generate().unwrap(); // initiator / dialer
        let b = OverlaySecret::generate().unwrap(); // responder / listener
        let (a_id, b_id) = (a.id(), b.id());

        let server = server_endpoint(&b, &AcceptAny, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();

        let bt = tokio::spawn(async move {
            let conn = accept(&server).await.unwrap().unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let out = pair_handshake(&mut send, &mut recv, &b, Role::Responder, DL).await;
            conn.closed().await; // hold the connection until the dialer finishes
            out
        });

        let client = pair_dial_endpoint().unwrap();
        let conn = dial(&client, addr).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        let (sas_a, peer_a) = pair_handshake(&mut send, &mut recv, &a, Role::Initiator, DL)
            .await
            .unwrap();
        conn.close(0u32.into(), b"paired");

        let (sas_b, peer_b) = bt.await.unwrap().unwrap();
        assert_eq!(sas_a.bits(), sas_b.bits(), "both ends derive the same SAS");
        assert_eq!(peer_a, b_id);
        assert_eq!(peer_b, a_id);
    }

    /// Everything a test needs to drive the initiator's phase B by hand (after an honest phase A).
    struct InitScaffold {
        sealer: Sealer,
        opener: Opener,
        offer: Vec<u8>,
        id_i: OverlayId,
        id_r: OverlayId,
    }

    /// Drive the initiator's phase A honestly and return the sealed session split + the inputs a
    /// hand-rolled dishonest/malformed phase B needs.
    async fn init_phase_a<S, R>(
        send: &mut S,
        recv: &mut R,
        secret: &OverlaySecret,
    ) -> Result<InitScaffold, PairError>
    where
        S: AsyncWrite + Unpin,
        R: AsyncRead + Unpin,
    {
        let hi = HybridInitiator::generate()?;
        let offer = hi.offer();
        write_lp(send, &seal_signed_share(&offer, secret).await?).await?;
        let signed_reply = read_lp(recv, PAIR_SHARE_MAX)
            .await?
            .ok_or(PairError::Closed)?;
        let (reply, peer) = open_signed_share(&signed_reply, None)?;
        let combined = hi.finish(&reply)?;
        let (id_i, id_r) = (secret.id(), peer);
        let t = transcript(&offer, &reply, &id_i, &id_r);
        let (sealer, opener) = Session::new(&combined, &t, Role::Initiator)?.split();
        Ok(InitScaffold {
            sealer,
            opener,
            offer,
            id_i,
            id_r,
        })
    }
}
