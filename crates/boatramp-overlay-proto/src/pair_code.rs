//! The relay-blind pairing **rendezvous code** (`bropair1…`, overlay follow-up #2, inc2).
//!
//! A pairing rendezvous lets two peers that cannot direct-dial each other (both
//! NAT'd) meet THROUGH the cluster relay: the relay matches a parked **accepter**
//! with a redeeming **dialer** by a shared rendezvous id and bridges their two
//! bi-streams **blind** (it holds no session keys — exactly like `expose`). The
//! commit-then-reveal SAS pairing handshake ([`crate::pairing`] /
//! `boatramp_overlay::pair_handshake`) then runs end-to-end over the bridge,
//! unchanged, so the SAS still detects a tampering/misrouting relay.
//!
//! [`PairCode`] is the self-contained rendezvous credential an operator mints
//! (`POST /api/overlay/pair-code`, gated `Overlay·Admin`) and shares with the new
//! peer. It carries everything BOTH sides need to meet — the rendezvous id (the
//! relay's registry key), the relay socket to dial, the relay identity to pin, and
//! the code's own expiry — rendered as a checksummed, copy-paste-safe bech32m
//! string under the reserved [`crate::wire::HRP_PAIR`] (`bropair1…`). The relay
//! itself never parses the code; it is handed only the rendezvous id over the
//! park/redeem wire, so the code is purely a client-side convenience bundle (the
//! overlay analog of a `brfwd1…`/`brexp1…` ticket, in the reserved HRP).
//!
//! The code is NOT a signed capability: its security is the short TTL + single-use
//! redemption the relay enforces, the relay-blind bridge, and the out-of-band SAS
//! comparison that backs the whole handshake. The `Overlay·Admin` gate is on the
//! MINT (who may obtain a rendezvous at this relay), not on redemption — the
//! unpaired peer that redeems a code is by design NOT membership-gated.

use crate::identity::{OverlayId, OverlayIdError};

/// Length of a pairing rendezvous id (the relay's registry key): 16 bytes of
/// platform entropy — infeasible to guess, compact in the rendered code.
pub const PAIR_RENDEZVOUS_ID_LEN: usize = 16;

/// The byte-layout version baked into a rendered [`PairCode`] (byte 0 of the
/// bech32m payload). Bumped only on a wire-incompatible change to the layout.
const PAIR_CODE_VERSION: u8 = 1;

/// A failure encoding or decoding a [`PairCode`].
#[derive(Debug, thiserror::Error)]
pub enum PairCodeError {
    /// The bech32 string could not be decoded or carried the wrong HRP.
    #[error("bech32 pairing code: {0}")]
    Bech32(String),
    /// The decoded payload was truncated, over-long, or an unknown version.
    #[error("malformed pairing code: {0}")]
    Malformed(String),
    /// The embedded relay identity was not a valid overlay id.
    #[error("pairing code relay id: {0}")]
    RelayId(#[from] OverlayIdError),
}

/// A self-contained pairing rendezvous credential, rendered as `bropair1…`.
///
/// Minted by the control plane (`Overlay·Admin`), parked by the accepter
/// (`boatramp overlay pair --accept <code>`) and redeemed by the dialer
/// (`boatramp overlay pair <code>`); both sides decode it to learn the relay to
/// dial and the rendezvous id to present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairCode {
    /// The rendezvous id — the relay's `PairRendezvous` registry key both the park
    /// and the redeem present over the wire. High-entropy; never reused.
    pub rendezvous: Vec<u8>,
    /// The relay/ingress `host:port` both peers dial to meet.
    pub relay_addr: String,
    /// The relay's overlay identity both peers pin at the TLS layer.
    pub relay_id: OverlayId,
    /// The code's expiry (Unix seconds) — advisory for the client; the relay
    /// enforces its own short rendezvous TTL regardless.
    pub expires_at: u64,
}

impl PairCode {
    /// Build a code, validating the rendezvous-id length and a non-empty relay addr.
    pub fn new(
        rendezvous: Vec<u8>,
        relay_addr: String,
        relay_id: OverlayId,
        expires_at: u64,
    ) -> Result<Self, PairCodeError> {
        if rendezvous.len() != PAIR_RENDEZVOUS_ID_LEN {
            return Err(PairCodeError::Malformed(format!(
                "rendezvous id must be {PAIR_RENDEZVOUS_ID_LEN} bytes (got {})",
                rendezvous.len()
            )));
        }
        if relay_addr.trim().is_empty() {
            return Err(PairCodeError::Malformed("empty relay address".into()));
        }
        Ok(Self {
            rendezvous,
            relay_addr,
            relay_id,
            expires_at,
        })
    }

    /// The compact byte payload (before bech32m): `version ‖ expires_at(8 BE) ‖
    /// rendezvous_len(1) ‖ rendezvous ‖ relay_id(32) ‖ relay_addr(UTF-8 tail)`.
    fn to_payload(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(1 + 8 + 1 + self.rendezvous.len() + 32 + self.relay_addr.len());
        out.push(PAIR_CODE_VERSION);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.push(self.rendezvous.len() as u8);
        out.extend_from_slice(&self.rendezvous);
        out.extend_from_slice(self.relay_id.as_bytes());
        out.extend_from_slice(self.relay_addr.as_bytes());
        out
    }

    /// Render the friendly bech32m `bropair1…` form (checksummed, copy-paste-safe).
    pub fn encode(&self) -> Result<String, PairCodeError> {
        let hrp = bech32::Hrp::parse(crate::wire::HRP_PAIR)
            .map_err(|e| PairCodeError::Bech32(e.to_string()))?;
        bech32::encode::<bech32::Bech32m>(hrp, &self.to_payload())
            .map_err(|e| PairCodeError::Bech32(e.to_string()))
    }

    /// Parse the friendly bech32m `bropair1…` form, rejecting a foreign HRP, a
    /// truncated/over-long payload, an unknown version, or a malformed relay id.
    pub fn decode(s: &str) -> Result<Self, PairCodeError> {
        let (hrp, data) =
            bech32::decode(s.trim()).map_err(|e| PairCodeError::Bech32(e.to_string()))?;
        if hrp.as_str() != crate::wire::HRP_PAIR {
            return Err(PairCodeError::Bech32(format!(
                "wrong prefix `{}` (expected `{}`)",
                hrp.as_str(),
                crate::wire::HRP_PAIR
            )));
        }
        // version(1) + expires_at(8) + rendezvous_len(1) + relay_id(32) minimum, plus a non-empty addr.
        if data.len() < 1 + 8 + 1 + 32 + 1 {
            return Err(PairCodeError::Malformed("payload too short".into()));
        }
        let version = data[0];
        if version != PAIR_CODE_VERSION {
            return Err(PairCodeError::Malformed(format!(
                "unknown version {version} (expected {PAIR_CODE_VERSION})"
            )));
        }
        let expires_at = u64::from_be_bytes(
            data[1..9]
                .try_into()
                .map_err(|_| PairCodeError::Malformed("bad expiry".into()))?,
        );
        let rlen = data[9] as usize;
        let rest = &data[10..];
        if rlen != PAIR_RENDEZVOUS_ID_LEN {
            return Err(PairCodeError::Malformed(format!(
                "rendezvous id must be {PAIR_RENDEZVOUS_ID_LEN} bytes (got {rlen})"
            )));
        }
        if rest.len() < rlen + 32 + 1 {
            return Err(PairCodeError::Malformed("payload truncated".into()));
        }
        let rendezvous = rest[..rlen].to_vec();
        let id_bytes: [u8; 32] = rest[rlen..rlen + 32]
            .try_into()
            .map_err(|_| PairCodeError::Malformed("bad relay id length".into()))?;
        let relay_id = OverlayId::try_from_bytes(id_bytes)?;
        let relay_addr = std::str::from_utf8(&rest[rlen + 32..])
            .map_err(|_| PairCodeError::Malformed("relay address is not UTF-8".into()))?
            .to_string();
        if relay_addr.is_empty() {
            return Err(PairCodeError::Malformed("empty relay address".into()));
        }
        Ok(Self {
            rendezvous,
            relay_addr,
            relay_id,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::OverlaySecret;

    fn sample() -> PairCode {
        let relay_id = OverlaySecret::generate().unwrap().id();
        PairCode::new(
            vec![7u8; PAIR_RENDEZVOUS_ID_LEN],
            "203.0.113.7:9100".into(),
            relay_id,
            1_900_000_000,
        )
        .unwrap()
    }

    #[test]
    fn round_trips_through_bropair1() {
        let code = sample();
        let s = code.encode().unwrap();
        assert!(s.starts_with("bropair1"), "rendered code: {s}");
        let back = PairCode::decode(&s).unwrap();
        assert_eq!(back, code);
    }

    #[test]
    fn rejects_a_foreign_hrp_and_garbage() {
        assert!(PairCode::decode("not-a-code").is_err());
        // Same bytes under the identity HRP (`bro1…`) must not decode as a pairing code.
        let id = OverlaySecret::generate().unwrap().id();
        assert!(PairCode::decode(&id.to_bech32()).is_err());
    }

    #[test]
    fn rejects_a_wrong_length_rendezvous_id() {
        let relay_id = OverlaySecret::generate().unwrap().id();
        assert!(matches!(
            PairCode::new(vec![1u8; 8], "a:1".into(), relay_id, 0),
            Err(PairCodeError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_a_truncated_payload() {
        // A valid-HRP bech32 whose payload is too short for the fixed header.
        let hrp = bech32::Hrp::parse(crate::wire::HRP_PAIR).unwrap();
        let short = bech32::encode::<bech32::Bech32m>(hrp, &[PAIR_CODE_VERSION, 0, 0]).unwrap();
        assert!(matches!(
            PairCode::decode(&short),
            Err(PairCodeError::Malformed(_))
        ));
    }
}
