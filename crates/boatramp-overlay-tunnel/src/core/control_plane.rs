//! The injected `ControlPlane` boundary (plan §1.1) — the key crate-layout consequence of the SDK
//! doing NO control-plane HTTP (`boatramp-overlay-client` has no `reqwest`). Catalog resolution and
//! dial-capability minting are abstract operations the core calls through this trait; the `boatramp`
//! CLI is the only implementor, over `client::connect` (which owns `reqwest` + the project token).
//!
//! Because one [`ControlPlane`] is built from one project-scoped token, per-project isolation is free
//! by construction: there is no representable way for one tunnel instance to resolve a name against
//! a different project's directory.

use boatramp_overlay_client::OverlayId;
use std::net::SocketAddr;

/// A catalog entry: a service name's overlay topology (no capability — minting is separate and
/// lazy). Mirrors the control plane's `GET /api/overlay/services` entry shape, parsed into the
/// strongly-typed fields the core/pool need (so a malformed entry fails at the `ControlPlane` edge,
/// not deep inside the dial path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInfo {
    /// The canonical service name (`svc/<name>`).
    pub service: String,
    /// The relay/ingress socket address to dial.
    pub relay: SocketAddr,
    /// The relay's pinned overlay identity.
    pub relay_id: OverlayId,
    /// The egress/terminator's overlay identity, pinned for the end-to-end E2EE session.
    pub egress_id: OverlayId,
    /// The relay's client-auth posture: `true` ⇒ capability-only (dial server-auth-only, present NO
    /// client certificate — the egress is the authority); `false` ⇒ mutual-pin (present the client's
    /// RPK certificate so the relay can pin it).
    pub capability_only: bool,
}

/// A resolved + minted dial grant: the topology [`ServiceInfo`] carries, plus a holder-bound
/// capability token and its absolute expiry (Unix seconds). Never cached or reused past
/// `expires_at` (plan §5 — an overlay-dial capability is offline-verified with no revocation).
///
/// Security INFO: `Debug` is hand-written (not derived) so `token` — a live, holder-bound
/// capability — never appears in a log line, a panic message, or a test assertion's failure
/// output; use [`DialGrant::token`] directly when the actual value is needed.
#[derive(Clone, PartialEq, Eq)]
pub struct DialGrant {
    pub relay: SocketAddr,
    pub relay_id: OverlayId,
    pub egress_id: OverlayId,
    pub capability_only: bool,
    /// The minted overlay-dial capability (COSE), holder-bound to the identity passed to
    /// [`ControlPlane::resolve_and_mint`].
    pub token: String,
    /// Absolute Unix-seconds expiry of `token`.
    pub expires_at: u64,
}

impl std::fmt::Debug for DialGrant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialGrant")
            .field("relay", &self.relay)
            .field("relay_id", &self.relay_id)
            .field("egress_id", &self.egress_id)
            .field("capability_only", &self.capability_only)
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// A failure resolving the catalog or minting a dial capability through the control plane.
///
/// Transport-agnostic by design (the core never assumes HTTP): the CLI's HTTP implementation maps
/// status codes onto these variants, preserving the actionable distinctions `boatramp forward`
/// already makes (finding D/overlay follow-up #3) — an unauthenticated token, an authenticated-but-
/// unauthorized one, and a flow-policy denial are different problems with different fixes.
#[derive(Debug, thiserror::Error)]
pub enum ControlPlaneError {
    /// The requested service is not in the directory.
    #[error("no overlay service `{0}` in the directory")]
    NotFound(String),
    /// The caller's credentials are missing, invalid, or expired (control-plane 401 analog).
    #[error("not authenticated to the control plane (missing, invalid, or expired credentials)")]
    Unauthenticated,
    /// The caller is authenticated but lacks the right to resolve/mint (control-plane 403 analog,
    /// RBAC-denied).
    #[error("not authorized to resolve/mint this overlay dial (missing right)")]
    Unauthorized,
    /// RBAC passed, but an operator-authored flow policy denied this specific mint (overlay
    /// follow-up #3's flow-policy 403, distinct from [`Unauthorized`](Self::Unauthorized) so a
    /// caller is never told to obtain a right it already holds).
    #[error("overlay dial denied by this cluster's flow policy")]
    FlowDenied,
    /// Any other control-plane failure (transport, malformed response, server error).
    #[error("control plane: {0}")]
    Other(String),
}

/// The injected catalog + capability-minting boundary (plan §1.1). Implemented by the `boatramp` CLI
/// over `client::connect`; the core calls it to refresh its catalog and to lazily mint dial
/// capabilities, and never performs HTTP (or holds a project token) itself.
#[async_trait::async_trait]
pub trait ControlPlane: Send + Sync {
    /// List every service in the directory this control plane's project token can see
    /// (`GET /api/overlay/services`). Names + topology only — no capabilities.
    async fn list_services(&self) -> Result<Vec<ServiceInfo>, ControlPlaneError>;

    /// Resolve `service`'s topology and mint a dial capability bound to `holder`
    /// (`POST /api/overlay/dial`). `service` is already the canonical `svc/<name>` form.
    async fn resolve_and_mint(
        &self,
        service: &str,
        holder: OverlayId,
    ) -> Result<DialGrant, ControlPlaneError>;
}
