//! Overlay peer-trust policy (IU-1).
//!
//! Trust is expressed directly over identity keys — there is no PKI and no CA.
//! A policy compiles down to a [`boatramp_rpktls::TrustSet`] plus the
//! [`boatramp_rpktls::PeerId`] a dialer pins; the runtime `quic` layer turns
//! that into the right rpktls config (a pinned `client_for`, a mutual-auth
//! `server`, or a server-auth-only accept for the hole-punch responder whose
//! peer identity is learned later at the E2EE layer, IU-4).

use std::collections::{BTreeMap, BTreeSet};

use boatramp_rpktls::{PeerId, TrustSet};

use crate::identity::OverlayId;

/// The `PeerId` a single pinned identity is registered under in the derived
/// `TrustSet`. A dialer passes this to `rpktls`'s `client_for`.
pub const PINNED_PEER_ID: PeerId = 0;

/// How an overlay endpoint decides which peer keys to trust.
#[derive(Clone, Debug)]
pub enum OverlayPeerPolicy {
    /// Pin exactly one identity — a client dialing a known egress.
    Pin(OverlayId),
    /// Trust any identity in this set — a relay/egress accepting known peers.
    Allowlist(BTreeSet<OverlayId>),
    /// Accept any presented key at the TLS layer. Real authentication is
    /// deferred to the E2EE learned-identity bind (IU-4); used by the
    /// hole-punch responder, which cannot pin its peer in advance. This is
    /// never, on its own, proof of who the peer is.
    AcceptAny,
}

impl OverlayPeerPolicy {
    /// The `rpktls` trust set this policy authorizes. `AcceptAny` yields an
    /// empty set — the runtime pairs it with a server-auth-only config rather
    /// than a client-cert verifier.
    #[must_use]
    pub fn trust_set(&self) -> TrustSet {
        match self {
            Self::AcceptAny => TrustSet::default(),
            Self::Pin(id) => TrustSet::from_map(BTreeMap::from([(PINNED_PEER_ID, id.to_spki())])),
            Self::Allowlist(ids) => {
                let map: BTreeMap<PeerId, Vec<u8>> = ids
                    .iter()
                    .enumerate()
                    .map(|(i, id)| (i as PeerId, id.to_spki()))
                    .collect();
                TrustSet::from_map(map)
            }
        }
    }

    /// For the `Pin` case, the pinned identity and the `PeerId` it is registered
    /// under (so a dialer can call `client_for`). `None` for the other variants.
    #[must_use]
    pub fn pinned(&self) -> Option<(OverlayId, PeerId)> {
        match self {
            Self::Pin(id) => Some((*id, PINNED_PEER_ID)),
            _ => None,
        }
    }

    /// Whether this policy admits `id`. `AcceptAny` admits everyone (the TLS
    /// layer is permissive; the E2EE layer authenticates).
    #[must_use]
    pub fn admits(&self, id: &OverlayId) -> bool {
        match self {
            Self::AcceptAny => true,
            Self::Pin(p) => p == id,
            Self::Allowlist(set) => set.contains(id),
        }
    }

    /// Whether this is the permissive `AcceptAny` policy (so the runtime knows
    /// to bind identity at the E2EE layer rather than the TLS layer).
    #[must_use]
    pub const fn is_accept_any(&self) -> bool {
        matches!(self, Self::AcceptAny)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::OverlaySecret;

    fn an_id() -> OverlayId {
        OverlaySecret::generate().unwrap().id()
    }

    #[test]
    fn pin_registers_one_key_under_the_pinned_peer() {
        let id = an_id();
        let policy = OverlayPeerPolicy::Pin(id);

        let snap = policy.trust_set().snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[&PINNED_PEER_ID], vec![id.to_spki()]);

        assert_eq!(policy.pinned(), Some((id, PINNED_PEER_ID)));
        assert!(policy.admits(&id));
        assert!(!policy.admits(&an_id()));
    }

    #[test]
    fn allowlist_registers_each_key_under_a_distinct_peer() {
        let a = an_id();
        let b = an_id();
        let policy = OverlayPeerPolicy::Allowlist(BTreeSet::from([a, b]));

        let snap = policy.trust_set().snapshot();
        assert_eq!(snap.len(), 2);
        // Every trusted id must appear exactly once across the peers.
        let keys: Vec<Vec<u8>> = snap.values().flatten().cloned().collect();
        assert!(keys.contains(&a.to_spki()));
        assert!(keys.contains(&b.to_spki()));

        assert_eq!(policy.pinned(), None);
        assert!(policy.admits(&a) && policy.admits(&b));
    }

    #[test]
    fn accept_any_trusts_an_empty_set_but_admits_everyone() {
        let policy = OverlayPeerPolicy::AcceptAny;
        assert!(policy.trust_set().snapshot().is_empty());
        assert!(policy.is_accept_any());
        assert!(policy.admits(&an_id()));
        assert_eq!(policy.pinned(), None);
    }
}
