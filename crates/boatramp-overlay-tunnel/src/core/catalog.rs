//! The service catalog (plan §1.2): a `RwLock<HashMap<name, entry>>` refreshed on start, on a 60s
//! timer, and on a cache-miss. Names + topology only — no capabilities (those are [`super::cap_cache`]'s
//! job, minted lazily and separately).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;

use super::control_plane::{ControlPlane, ControlPlaneError, ServiceInfo};

/// How often the catalog refreshes itself in the background, independent of use.
pub(super) const REFRESH_INTERVAL: Duration = Duration::from_secs(60);

/// The service directory: refreshed on start, on [`REFRESH_INTERVAL`], and on a cache-miss (an
/// entry absent from a currently-cached snapshot gets one eager re-fetch before being reported
/// unknown — covers a service published after this tunnel started).
pub(crate) struct Catalog {
    control_plane: Arc<dyn ControlPlane>,
    entries: RwLock<HashMap<String, ServiceInfo>>,
}

impl Catalog {
    pub(super) fn new(control_plane: Arc<dyn ControlPlane>) -> Self {
        Self {
            control_plane,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Re-fetch the whole directory from the control plane and replace the cached snapshot.
    pub(super) async fn refresh(&self) -> Result<(), ControlPlaneError> {
        let list = self.control_plane.list_services().await?;
        let map = list.into_iter().map(|e| (e.service.clone(), e)).collect();
        *self.entries.write().await = map;
        Ok(())
    }

    /// Current snapshot, keyed by canonical service name. Does not refresh.
    async fn get(&self, service: &str) -> Option<ServiceInfo> {
        self.entries.read().await.get(service).cloned()
    }

    /// Resolve `service` (already canonicalized), refreshing once on a cache-miss before giving up.
    pub(super) async fn ensure(&self, service: &str) -> Result<ServiceInfo, ControlPlaneError> {
        if let Some(entry) = self.get(service).await {
            return Ok(entry);
        }
        self.refresh().await?;
        self.get(service)
            .await
            .ok_or_else(|| ControlPlaneError::NotFound(service.to_string()))
    }

    /// The full current snapshot, for `Tunnel::catalog()`.
    pub(super) async fn snapshot(&self) -> Vec<ServiceInfo> {
        self.entries.read().await.values().cloned().collect()
    }

    /// Spawn the background 60s refresh timer. Logged at `warn` on failure (a transient control-
    /// plane outage should not crash the tunnel — the next cache-miss, or the next tick, retries).
    pub(super) fn spawn_refresh_timer(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(REFRESH_INTERVAL).await;
                if let Err(err) = this.refresh().await {
                    tracing::warn!(error = %err, "overlay tunnel: background catalog refresh failed");
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_support::{MockControlPlane, dummy_id};
    use std::net::SocketAddr;
    use std::sync::atomic::Ordering;

    fn entry(service: &str) -> ServiceInfo {
        ServiceInfo {
            service: service.to_string(),
            relay: "127.0.0.1:1".parse::<SocketAddr>().unwrap(),
            relay_id: dummy_id(),
            egress_id: dummy_id(),
            capability_only: true,
        }
    }

    #[tokio::test]
    async fn ensure_serves_from_cache_without_a_refresh() {
        let cp = Arc::new(MockControlPlane::new(vec![entry("svc/db")]));
        let catalog = Catalog::new(Arc::clone(&cp) as Arc<dyn ControlPlane>);
        catalog.refresh().await.unwrap();
        assert_eq!(cp.list_calls.load(Ordering::SeqCst), 1);
        let got = catalog.ensure("svc/db").await.unwrap();
        assert_eq!(got.service, "svc/db");
        // Served from cache — no extra list call.
        assert_eq!(cp.list_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_cache_miss_triggers_exactly_one_refresh() {
        let cp = Arc::new(MockControlPlane::new(vec![entry("svc/db")]));
        let catalog = Catalog::new(Arc::clone(&cp) as Arc<dyn ControlPlane>);
        // No initial refresh — the first `ensure` must refresh once on the miss.
        let got = catalog.ensure("svc/db").await.unwrap();
        assert_eq!(got.service, "svc/db");
        assert_eq!(cp.list_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn an_unknown_service_is_reported_not_found_after_the_refresh() {
        let cp = Arc::new(MockControlPlane::new(vec![entry("svc/db")]));
        let catalog = Catalog::new(Arc::clone(&cp) as Arc<dyn ControlPlane>);
        let err = catalog.ensure("svc/ghost").await.unwrap_err();
        assert!(matches!(err, ControlPlaneError::NotFound(s) if s == "svc/ghost"));
        assert_eq!(cp.list_calls.load(Ordering::SeqCst), 1);
    }
}
