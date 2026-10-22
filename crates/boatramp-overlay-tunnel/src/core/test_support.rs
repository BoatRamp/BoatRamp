//! Shared test doubles for the core's own unit tests (catalog / cap-cache / pool / `Tunnel`). Not
//! compiled outside `cfg(test)` — never shipped, never a production seam.

#![cfg(test)]

use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use boatramp_overlay_client::{OverlayId, OverlaySecret};

use super::control_plane::{ControlPlane, ControlPlaneError, DialGrant, ServiceInfo};

/// A fresh, throwaway overlay identity's public id — handy filler for topology fields a given test
/// doesn't care about.
pub(crate) fn dummy_id() -> OverlayId {
    OverlaySecret::generate().unwrap().id()
}

pub(crate) fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A catalog entry pointing at `relay` (so a pool/dial test can target a real local listener),
/// otherwise filled with throwaway ids.
pub(crate) fn entry_at(service: &str, relay: SocketAddr, capability_only: bool) -> ServiceInfo {
    ServiceInfo {
        service: service.to_string(),
        relay,
        relay_id: dummy_id(),
        egress_id: dummy_id(),
        capability_only,
    }
}

/// A mock [`ControlPlane`] whose directory and call counts are inspectable: `list_calls` /
/// `mint_calls` let a test assert exactly how many times the (fake) network was hit, and
/// `mint_ttl_secs` controls how long a minted [`DialGrant`] lives, so cap-cache lifecycle tests can
/// use short real TTLs instead of needing to fake the clock.
pub(crate) struct MockControlPlane {
    pub(crate) directory: Mutex<Vec<ServiceInfo>>,
    pub(crate) list_calls: AtomicUsize,
    pub(crate) mint_calls: AtomicUsize,
    pub(crate) mint_ttl_secs: u64,
}

impl MockControlPlane {
    pub(crate) fn new(directory: Vec<ServiceInfo>) -> Self {
        Self {
            directory: Mutex::new(directory),
            list_calls: AtomicUsize::new(0),
            mint_calls: AtomicUsize::new(0),
            mint_ttl_secs: 3600,
        }
    }

    pub(crate) fn with_ttl(directory: Vec<ServiceInfo>, ttl_secs: u64) -> Self {
        let mut this = Self::new(directory);
        this.mint_ttl_secs = ttl_secs;
        this
    }
}

#[async_trait::async_trait]
impl ControlPlane for MockControlPlane {
    async fn list_services(&self) -> Result<Vec<ServiceInfo>, ControlPlaneError> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.directory.lock().unwrap().clone())
    }

    async fn resolve_and_mint(
        &self,
        service: &str,
        _holder: OverlayId,
    ) -> Result<DialGrant, ControlPlaneError> {
        // Post-increment so each mint's token is distinguishable — several tests assert a fresh
        // mint replaced a cached one, which a constant per-service token would mask.
        let call = self.mint_calls.fetch_add(1, Ordering::SeqCst) + 1;
        let found = self
            .directory
            .lock()
            .unwrap()
            .iter()
            .find(|e| e.service == service)
            .cloned()
            .ok_or_else(|| ControlPlaneError::NotFound(service.to_string()))?;
        Ok(DialGrant {
            relay: found.relay,
            relay_id: found.relay_id,
            egress_id: found.egress_id,
            capability_only: found.capability_only,
            token: format!("mock-cap-for-{service}-mint{call}"),
            expires_at: now_unix() + self.mint_ttl_secs,
        })
    }
}
