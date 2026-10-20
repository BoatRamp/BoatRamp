//! ICE candidate model — the pure core (IU-6).
//!
//! Candidates (host / server-reflexive / relay) are exchanged over the E2EE **signaling channel**
//! (`CH_SIGNAL`, IU-4), never a server, and priority-ordered host-first. The relay candidate is the
//! guaranteed floor — a direct path is an optimization over the always-available relay. The
//! network-facing gathering (the connect-trick for the local source IP, STUN-lite reflexive
//! discovery) lives in the runtime crate; this module is the pure model + the signaling wire type.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// The kind of transport address a candidate names, most-preferred first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CandidateKind {
    /// A local interface address — the most direct, tried first.
    Host,
    /// A reflexive address observed by the peer/relay (the NAT's public mapping).
    ServerReflexive,
    /// The relay itself — the guaranteed floor, always reachable.
    Relay,
}

impl CandidateKind {
    /// Preference weight (higher = tried first): host > reflexive > relay.
    #[must_use]
    pub fn priority(self) -> u32 {
        match self {
            Self::Host => 126,
            Self::ServerReflexive => 100,
            Self::Relay => 0,
        }
    }
}

/// A single transport-address candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub addr: SocketAddr,
}

impl Candidate {
    #[must_use]
    pub fn new(kind: CandidateKind, addr: SocketAddr) -> Self {
        Self { kind, addr }
    }
}

/// A set of candidates, kept in priority order (most-preferred first).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateSet(Vec<Candidate>);

impl CandidateSet {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a candidate (deduped); the set stays priority-ordered.
    pub fn add(&mut self, candidate: Candidate) {
        if !self.0.contains(&candidate) {
            self.0.push(candidate);
            self.sort();
        }
    }

    fn sort(&mut self) {
        // Highest priority first; ties keep insertion order (stable sort).
        self.0
            .sort_by(|a, b| b.kind.priority().cmp(&a.kind.priority()));
    }

    /// The candidates, most-preferred first.
    #[must_use]
    pub fn as_slice(&self) -> &[Candidate] {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl FromIterator<Candidate> for CandidateSet {
    fn from_iter<I: IntoIterator<Item = Candidate>>(iter: I) -> Self {
        let mut set = Self::new();
        for c in iter {
            set.add(c);
        }
        set
    }
}

/// A signaling message carried inside the sealed E2EE stream (`CH_SIGNAL`) — never a side channel,
/// so a relay cannot read or forge the candidate exchange.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signal {
    /// This peer's gathered candidates.
    Candidates(CandidateSet),
    /// The source address this peer OBSERVED the other at (STUN-lite reflexive feedback), so the
    /// other peer learns its own public mapping.
    Observed(SocketAddr),
}

impl Signal {
    /// Encode for a `CH_SIGNAL` record (JSON — small, bounded by `wire::MAX_SIGNAL_LEN`).
    pub fn encode(&self) -> Result<Vec<u8>, SignalError> {
        serde_json::to_vec(self).map_err(|e| SignalError(e.to_string()))
    }

    /// Decode a `CH_SIGNAL` record.
    pub fn decode(bytes: &[u8]) -> Result<Self, SignalError> {
        serde_json::from_slice(bytes).map_err(|e| SignalError(e.to_string()))
    }
}

/// A malformed signaling message.
#[derive(Debug, thiserror::Error)]
#[error("ice signal: {0}")]
pub struct SignalError(String);

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn candidates_order_host_then_reflexive_then_relay() {
        let mut set = CandidateSet::new();
        set.add(Candidate::new(CandidateKind::Relay, addr("10.0.0.1:9000")));
        set.add(Candidate::new(
            CandidateKind::Host,
            addr("192.168.1.2:5000"),
        ));
        set.add(Candidate::new(
            CandidateKind::ServerReflexive,
            addr("203.0.113.5:40000"),
        ));
        let kinds: Vec<_> = set.as_slice().iter().map(|c| c.kind).collect();
        assert_eq!(
            kinds,
            [
                CandidateKind::Host,
                CandidateKind::ServerReflexive,
                CandidateKind::Relay
            ]
        );
    }

    #[test]
    fn add_is_deduped() {
        let mut set = CandidateSet::new();
        let c = Candidate::new(CandidateKind::Host, addr("127.0.0.1:1"));
        set.add(c);
        set.add(c);
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn signal_round_trips_over_the_wire() {
        let set = CandidateSet::from_iter([
            Candidate::new(CandidateKind::Host, addr("192.168.0.9:7000")),
            Candidate::new(CandidateKind::Relay, addr("10.0.0.1:9000")),
        ]);
        let sig = Signal::Candidates(set);
        assert_eq!(Signal::decode(&sig.encode().unwrap()).unwrap(), sig);

        let obs = Signal::Observed(addr("203.0.113.7:51000"));
        assert_eq!(Signal::decode(&obs.encode().unwrap()).unwrap(), obs);
    }
}
