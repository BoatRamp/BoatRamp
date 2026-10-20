//! Capability dial + the dial gate (IU-2).
//!
//! A relay/egress authorizes a dial **offline** — no control-plane round-trip — from a
//! holder-key-bound COSE capability the client presents in the dial handshake. This module defines
//! the dial-handshake request and verdict, and the pure [`authorize_dial`] gate that turns a
//! verified capability plus the dialing peer's *proven* identity into an accept/reject decision.
//! The capability's mint/verify is substrate ([`boatramp_core::cose`]'s `overlay-dial` kind); the
//! async handshake that reads the request and writes the verdict over a live stream lives in the
//! runtime crate's client-edge/egress.

use boatramp_core::cose::{TokenPublicKey, verify_overlay_dial};

use crate::identity::OverlayId;

/// What the client presents in the dial handshake. (`resume` — reconnecting an in-flight circuit —
/// arrives with direct-path promotion, IU-7; the first slice dials fresh.)
#[derive(Clone, Debug)]
pub struct DialRequest {
    /// The in-cluster target the client wants to reach (e.g. `svc/db`, `node/<id>`).
    pub service: String,
    /// The overlay-dial capability (a `boatramp_core::cose` `overlay-dial` token), holder-bound to
    /// the client's identity.
    pub token: String,
    /// Whether the client will wrap the flow in the relay-blind E2EE splice.
    pub e2ee: bool,
}

/// Why a dial was refused. Returned to the client as a reason (a verdict, not an error).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialReject {
    /// The capability's holder key is not the dialing peer's proven identity (a stolen token used
    /// by a different identity).
    HolderMismatch,
    /// The requested service is outside the capability's authorized scope.
    ServiceNotAuthorized,
    /// The target requires E2EE but the dial is not E2EE (fail-closed).
    EncryptionRequired,
    /// The capability token did not verify (bad signature, expired, or wrong kind).
    InvalidCapability(String),
}

/// The gate's decision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialVerdict {
    /// Admitted; the authorized scope the capability carried.
    Accept { scope: String },
    /// Refused, with the reason to return to the client.
    Reject(DialReject),
}

/// Authorize a dial **offline**: verify the holder-bound capability under `trust_root`, confirm its
/// holder is the dialing peer's proven identity (`presented`, from the TLS/E2EE layer), and that the
/// requested service is within the capability's scope. A target that `encryption_required` refuses a
/// non-E2EE dial (fail-closed). Returns a verdict, never an error — the egress relays the reason.
///
/// Scope is matched exactly, or by a `"*"` wildcard. The richer per-flow/per-circuit ACL (Cedar
/// actions/resources or a dedicated gate) is a deliberately deferred design decision; this is the
/// holder-bound capability floor every model builds on.
#[must_use]
pub fn authorize_dial(
    request: &DialRequest,
    presented: &OverlayId,
    trust_root: &TokenPublicKey,
    now_unix: u64,
    encryption_required: bool,
) -> DialVerdict {
    let verified = match verify_overlay_dial(&request.token, trust_root, now_unix) {
        Ok(v) => v,
        Err(e) => return DialVerdict::Reject(DialReject::InvalidCapability(e.to_string())),
    };
    // Holder binding: the capability is bound to one identity; the dialing peer must BE it.
    if verified.holder != presented.to_hex() {
        return DialVerdict::Reject(DialReject::HolderMismatch);
    }
    if verified.scope != "*" && verified.scope != request.service {
        return DialVerdict::Reject(DialReject::ServiceNotAuthorized);
    }
    if encryption_required && !request.e2ee {
        return DialVerdict::Reject(DialReject::EncryptionRequired);
    }
    DialVerdict::Accept {
        scope: verified.scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::OverlaySecret;
    use boatramp_core::cose::mint_overlay_dial;

    const NOW: u64 = 1_000_000;

    /// Mint a real overlay-dial capability for `holder`, signed by `root`.
    async fn mint(root: &OverlaySecret, holder: &OverlayId, scope: &str) -> String {
        mint_overlay_dial(&holder.to_public(), scope, 3600, NOW, &root.signer())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn accepts_a_valid_holder_bound_dial() {
        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let token = mint(&root, &client.id(), "svc/db").await;
        let req = DialRequest {
            service: "svc/db".into(),
            token,
            e2ee: true,
        };
        assert_eq!(
            authorize_dial(&req, &client.id(), &root.id().to_public(), NOW, true),
            DialVerdict::Accept {
                scope: "svc/db".into()
            }
        );
    }

    #[tokio::test]
    async fn rejects_a_token_used_by_a_different_identity() {
        // Capability minted for `client`, but a DIFFERENT identity presents it.
        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let thief = OverlaySecret::generate().unwrap();
        let token = mint(&root, &client.id(), "svc/db").await;
        let req = DialRequest {
            service: "svc/db".into(),
            token,
            e2ee: true,
        };
        assert_eq!(
            authorize_dial(&req, &thief.id(), &root.id().to_public(), NOW, false),
            DialVerdict::Reject(DialReject::HolderMismatch)
        );
    }

    #[tokio::test]
    async fn rejects_a_service_outside_scope() {
        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let token = mint(&root, &client.id(), "svc/db").await;
        let req = DialRequest {
            service: "svc/secrets".into(),
            token,
            e2ee: true,
        };
        assert_eq!(
            authorize_dial(&req, &client.id(), &root.id().to_public(), NOW, false),
            DialVerdict::Reject(DialReject::ServiceNotAuthorized)
        );
    }

    #[tokio::test]
    async fn wildcard_scope_admits_any_service() {
        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let token = mint(&root, &client.id(), "*").await;
        let req = DialRequest {
            service: "node/abc".into(),
            token,
            e2ee: true,
        };
        assert!(matches!(
            authorize_dial(&req, &client.id(), &root.id().to_public(), NOW, false),
            DialVerdict::Accept { .. }
        ));
    }

    #[tokio::test]
    async fn fails_closed_when_encryption_is_required_but_absent() {
        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let token = mint(&root, &client.id(), "svc/db").await;
        let req = DialRequest {
            service: "svc/db".into(),
            token,
            e2ee: false,
        };
        assert_eq!(
            authorize_dial(&req, &client.id(), &root.id().to_public(), NOW, true),
            DialVerdict::Reject(DialReject::EncryptionRequired)
        );
    }

    #[tokio::test]
    async fn rejects_a_capability_from_a_different_trust_root() {
        let root = OverlaySecret::generate().unwrap();
        let impostor = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let token = mint(&root, &client.id(), "svc/db").await;
        let req = DialRequest {
            service: "svc/db".into(),
            token,
            e2ee: true,
        };
        // Verify against the WRONG root → the signature check fails.
        assert!(matches!(
            authorize_dial(&req, &client.id(), &impostor.id().to_public(), NOW, false),
            DialVerdict::Reject(DialReject::InvalidCapability(_))
        ));
    }

    #[tokio::test]
    async fn rejects_an_expired_capability() {
        let root = OverlaySecret::generate().unwrap();
        let client = OverlaySecret::generate().unwrap();
        let token = mint(&root, &client.id(), "svc/db").await; // exp = NOW + 3600
        let req = DialRequest {
            service: "svc/db".into(),
            token,
            e2ee: true,
        };
        // Evaluate well past expiry.
        assert!(matches!(
            authorize_dial(
                &req,
                &client.id(),
                &root.id().to_public(),
                NOW + 7200,
                false
            ),
            DialVerdict::Reject(DialReject::InvalidCapability(_))
        ));
    }
}
