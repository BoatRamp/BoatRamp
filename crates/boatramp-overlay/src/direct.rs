//! Direct-path negotiation (IU-7).
//!
//! After the relay-blind E2EE handshake learns the peer's identity, the two ends try to establish a
//! **direct** QUIC link that bypasses the relay, then promote the live circuit onto it. The direct
//! link is made over a [`crate::quic::peer_endpoint`] **mutually pinned to the E2EE-learned
//! identity**, so an otherwise-permissive hole-punch endpoint is not a hijack vector — only the
//! expected peer can complete the handshake.
//!
//! Candidate roles are tie-broken so both ends land on ONE connection (two independent dials would
//! make two QUIC connections): the Initiator dials the peer's candidates, the Responder accepts.
//! That covers loopback and the common case where one side is directly reachable; where neither is
//! (symmetric NAT), the direct attempt simply fails and the flow stays on the relay — the
//! guaranteed floor. (Full simultaneous-open punching is a later refinement over this.)

use std::time::Duration;

use boatramp_overlay_proto::e2ee::Role;
use boatramp_overlay_proto::ice::CandidateSet;
use quinn::{Connection, Endpoint};

use crate::quic;

/// How hard to try for a direct link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathMode {
    /// Never leave the relay.
    Relay,
    /// Try direct; fall back to the relay if it fails.
    PreferDirect,
    /// Require direct; fail the flow if it can't be established.
    DirectOnly,
}

impl PathMode {
    /// Whether a direct attempt should be made at all.
    #[must_use]
    pub fn attempts_direct(self) -> bool {
        matches!(self, Self::PreferDirect | Self::DirectOnly)
    }
}

/// Try to establish an authenticated direct connection to the peer over `endpoint` (a
/// `peer_endpoint` mutually pinned to the peer's identity). The Initiator dials the peer's
/// `peer_candidates` in priority order; the Responder accepts. Returns the established, authenticated
/// `Connection`, or `None` within `deadline`.
pub async fn negotiate_direct(
    endpoint: &Endpoint,
    peer_candidates: &CandidateSet,
    role: Role,
    deadline: Duration,
) -> Option<Connection> {
    let attempt = async {
        match role {
            Role::Initiator => {
                for candidate in peer_candidates.as_slice() {
                    if let Ok(conn) = quic::dial(endpoint, candidate.addr).await {
                        return Some(conn);
                    }
                }
                None
            }
            Role::Responder => match quic::accept(endpoint).await {
                Ok(Some(conn)) => Some(conn),
                _ => None,
            },
        }
    };
    tokio::time::timeout(deadline, attempt).await.ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_overlay_proto::ice::{Candidate, CandidateKind, CandidateSet};
    use boatramp_overlay_proto::identity::OverlaySecret;
    use boatramp_overlay_proto::peer_policy::OverlayPeerPolicy::Pin;

    /// Two peers hole-punch over mutual-pinned peer_endpoints and get a working, authenticated
    /// direct link (loopback): Initiator dials the Responder's candidate, Responder accepts, a
    /// bi-stream round-trips.
    #[tokio::test]
    async fn hole_punch_yields_a_working_authenticated_direct_link() {
        let a = OverlaySecret::generate().unwrap(); // initiator
        let b = OverlaySecret::generate().unwrap(); // responder
        let (a_id, b_id) = (a.id(), b.id());

        let a_ep = quic::peer_endpoint(&a, &Pin(b_id), &Pin(b_id), "127.0.0.1:0".parse().unwrap())
            .unwrap();
        let b_ep = quic::peer_endpoint(&b, &Pin(a_id), &Pin(a_id), "127.0.0.1:0".parse().unwrap())
            .unwrap();
        let b_addr = b_ep.local_addr().unwrap();
        let b_candidates = CandidateSet::from_iter([Candidate::new(CandidateKind::Host, b_addr)]);

        // Responder side: accept + echo one bi-stream.
        let b_task = tokio::spawn(async move {
            let conn = negotiate_direct(
                &b_ep,
                &CandidateSet::new(),
                Role::Responder,
                Duration::from_secs(5),
            )
            .await
            .expect("responder accepts a direct link");
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let got = recv.read_to_end(64).await.unwrap();
            send.write_all(&got).await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
        });

        let conn = negotiate_direct(
            &a_ep,
            &b_candidates,
            Role::Initiator,
            Duration::from_secs(5),
        )
        .await
        .expect("initiator dials a direct link");
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(b"direct!").await.unwrap();
        send.finish().unwrap();
        let echo = recv.read_to_end(64).await.unwrap();
        assert_eq!(&echo, b"direct!");

        conn.close(0u32.into(), b"done");
        let _ = b_task.await;
    }
}
