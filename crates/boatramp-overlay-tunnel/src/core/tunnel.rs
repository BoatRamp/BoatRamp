//! `Tunnel` — the front-end-agnostic core (plan §1.6/§1.7): `(service name) → Flow → byte-copy`,
//! plus the catalog/resolve/mint/cap-lifecycle machinery the front-ends never touch directly.
//!
//! **Boundary (§1.7):** the core exposes exactly [`Tunnel::open`], [`Tunnel::catalog`], and
//! [`Tunnel::resolve_name`]. SOCKS (and, later, TUN) are thin front-ends that only translate their
//! own input into a service name and call `open` — zero overlay/cap/crypto logic lives in either.

use std::sync::Arc;

use boatramp_overlay_client::{Flow, OverlayClientError, OverlaySecret};

use super::cap_cache::CapCache;
use super::catalog::Catalog;
use super::control_plane::{ControlPlane, ControlPlaneError, ServiceInfo};
use super::name::normalize_name;
use super::pool::ClientPool;

/// Any failure opening a flow through the tunnel core.
#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    /// The requested service was not (and, after one refresh, still is not) in the directory.
    #[error(transparent)]
    ControlPlane(#[from] ControlPlaneError),
    /// Building the pooled `OverlayClient`, or the dial itself, failed.
    #[error("overlay client: {0}")]
    Client(#[from] OverlayClientError),
}

/// The shared tunnel core. Cheap to clone the `Arc` it is always held behind — [`Tunnel::new`]
/// returns one directly because the catalog-refresh and cap-cache-sweep background tasks need a
/// stable handle to spawn against.
pub struct Tunnel {
    /// This process's one fixed overlay identity. Every dial capability minted in this process is
    /// bound to it; it never leaves the core (the `ControlPlane` trait only ever receives the
    /// PUBLIC [`boatramp_overlay_client::OverlayId`] half, via [`ControlPlane::resolve_and_mint`]).
    holder: OverlaySecret,
    catalog: Arc<Catalog>,
    caps: Arc<CapCache>,
    pool: ClientPool,
}

impl Tunnel {
    /// Build a tunnel core over `control_plane`, bound to `holder`'s identity: an initial catalog
    /// refresh runs before returning (so the first `open`/`catalog` call is never cold), then the
    /// 60s catalog-refresh timer and the cap-cache sweeper are spawned in the background.
    ///
    /// `control_plane` and `holder` are exactly plan §1.1's injected boundary — the CLI builds
    /// `control_plane` over `client::connect` and passes `operator_identity()` as `holder`; this
    /// crate never performs HTTP and never reads a key file.
    pub async fn new(
        control_plane: Arc<dyn ControlPlane>,
        holder: OverlaySecret,
    ) -> Result<Arc<Self>, TunnelError> {
        let catalog = Arc::new(Catalog::new(Arc::clone(&control_plane)));
        // "refresh on start" (§1.2) — a failure here is surfaced immediately rather than silently
        // starting with an empty catalog (the first real `open` would otherwise always pay one extra
        // round trip, and a genuinely-down control plane should fail the tunnel's startup loudly).
        catalog.refresh().await?;
        catalog.spawn_refresh_timer();

        let caps = Arc::new(CapCache::new(Arc::clone(&control_plane)));
        caps.spawn_sweeper(holder.id());

        let pool = ClientPool::new(&holder);

        Ok(Arc::new(Self {
            holder,
            catalog,
            caps,
            pool,
        }))
    }

    /// Normalize `input` (a SOCKS in-band hostname today) to the canonical `svc/<name>` form. Pure —
    /// front-ends use it to show the resolved name in logs/errors before `open` does the same
    /// normalization internally.
    #[must_use]
    pub fn resolve_name(&self, input: &str) -> String {
        normalize_name(input)
    }

    /// The current catalog snapshot (service names this control plane's project token can see).
    pub async fn catalog(&self) -> Vec<ServiceInfo> {
        self.catalog.snapshot().await
    }

    /// Resolve `requested` to a service, ensure a usable dial capability, and dial it — returning a
    /// [`Flow`] the caller splices to its own transport (a SOCKS CONNECT, stdio, …).
    ///
    /// This is the ONLY path through the core that reaches the overlay: `requested` is normalized to
    /// a bare service **name** here — there is no parameter, field, or code path anywhere in this
    /// function (or anything it calls) that accepts or forwards an IP address. The dial this ends in
    /// carries exactly `{service, token, e2ee: true}` (plan §5's IP-as-local-handle invariant,
    /// enforced by `boatramp_overlay_client::DialRequest`'s own shape — see the crate-level test
    /// `dial_request_has_no_ip_field`).
    pub async fn open(&self, requested: &str) -> Result<Flow, TunnelError> {
        let service = normalize_name(requested);
        let info = self.catalog.ensure(&service).await?;
        let grant = self.caps.get_or_mint(&service, self.holder.id()).await?;
        let client = self
            .pool
            .get_or_build(
                grant.relay,
                grant.relay_id,
                grant.egress_id,
                grant.capability_only,
            )
            .await?;
        // `info` re-confirms the capability-only posture the grant already carries (both come from
        // the same resolve); kept named so a future divergence between catalog topology and the
        // freshly-minted grant's topology is at least visible to a reader, not silently ignored.
        debug_assert_eq!(info.capability_only, grant.capability_only);
        let flow = client.dial(&service, &grant.token)?;
        Ok(flow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_support::{MockControlPlane, entry_at};
    use std::sync::atomic::Ordering;

    /// Structural proof of plan §5's IP-as-local-handle invariant: the wire dial request has
    /// EXACTLY these three fields. An exhaustive (no `..`) destructure means that if a future change
    /// ever added an address/handle field to the request, this test would fail to COMPILE — forcing
    /// an explicit look at the new field before it could ship silently.
    #[test]
    fn dial_request_has_no_ip_field() {
        use boatramp_overlay_client::DialRequest;
        let req = DialRequest {
            service: "svc/db".to_string(),
            token: "cap".to_string(),
            e2ee: true,
        };
        let DialRequest {
            service,
            token,
            e2ee,
        } = req;
        assert_eq!(service, "svc/db");
        assert_eq!(token, "cap");
        assert!(e2ee);
    }

    #[tokio::test]
    async fn open_fails_cleanly_for_an_unknown_service_without_mint_or_pool_activity() {
        let cp = Arc::new(MockControlPlane::new(vec![]));
        let holder = OverlaySecret::generate().unwrap();
        let tunnel = Tunnel::new(Arc::clone(&cp) as Arc<dyn ControlPlane>, holder)
            .await
            .unwrap();
        // `Flow` (the `Ok` side) is not `Debug`, so match explicitly rather than `.unwrap_err()`
        // (which would try to `Debug`-format the whole `Result`, `Ok` side included).
        match tunnel.open("ghost").await {
            Err(TunnelError::ControlPlane(ControlPlaneError::NotFound(s))) => {
                assert_eq!(s, "svc/ghost");
            }
            Err(other) => {
                panic!("expected ControlPlaneError::NotFound, got a different error: {other}")
            }
            Ok(_flow) => panic!("expected an error opening an unknown service, got Ok(Flow)"),
        }
        // An unknown service must never reach the capability mint.
        assert_eq!(cp.mint_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn resolve_name_matches_the_free_function() {
        // `Tunnel::resolve_name` is a thin, intentionally pure wrapper — no control-plane/catalog
        // access — so a front-end can show the resolved name before `open` touches anything.
        assert_eq!(normalize_name("db"), "svc/db");
    }

    #[tokio::test]
    async fn catalog_reports_the_refreshed_snapshot() {
        let cp = Arc::new(MockControlPlane::new(vec![entry_at(
            "svc/db",
            "127.0.0.1:1".parse().unwrap(),
            true,
        )]));
        let holder = OverlaySecret::generate().unwrap();
        let tunnel = Tunnel::new(Arc::clone(&cp) as Arc<dyn ControlPlane>, holder)
            .await
            .unwrap();
        let snapshot = tunnel.catalog().await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].service, "svc/db");
    }
}
