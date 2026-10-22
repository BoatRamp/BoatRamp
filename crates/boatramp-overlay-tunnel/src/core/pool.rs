//! `OverlayClient` pool (plan §1.5): one client per `(relay, relay_id, egress_id, capability_only)`,
//! built with the same recipe `boatramp forward` uses (`PathMode::PreferDirect`, `--capability-only`
//! mirrored from the relay's own posture) and reused for every flow to that pair — avoids rebuilding
//! a QUIC endpoint per dial.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use boatramp_overlay_client::{
    OverlayClient, OverlayClientError, OverlayId, OverlaySecret, PathMode,
};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

/// `(relay, relay_id, egress_id, capability_only)` — everything that determines the shape of the
/// `OverlayClient` built to dial it. All four fields are `Copy`/cheap so the key itself is cheap.
type PoolKey = (SocketAddr, OverlayId, OverlayId, bool);

/// The pool described above. Holds the tunnel's one fixed holder identity (as its seed-hex, the same
/// representation the key file itself stores) so it can rebuild a fresh [`OverlaySecret`] per client
/// — `OverlaySecret` deliberately does not implement `Clone` (its seed is zeroized), so every pooled
/// client needs its own reconstructed copy, exactly as `OverlayClient::dial`'s internal
/// `clone_secret` does for the SDK's own per-flow endpoint.
///
/// Security MEDIUM-1: `holder_seed_hex` keeps `seed_hex()`'s own `Zeroizing<String>` wrapper rather
/// than unwrapping it into a plain `String` — a plain `String` would leave the operator's long-term
/// ed25519 seed sitting in cleartext heap for the whole life of the daemon (recoverable from a core
/// dump or swapped-out memory); `Zeroizing` overwrites it on drop instead.
pub(crate) struct ClientPool {
    holder_seed_hex: Zeroizing<String>,
    clients: RwLock<HashMap<PoolKey, Arc<OverlayClient>>>,
}

impl ClientPool {
    pub(super) fn new(holder: &OverlaySecret) -> Self {
        Self {
            holder_seed_hex: holder.seed_hex(),
            clients: RwLock::new(HashMap::new()),
        }
    }

    fn clone_holder(&self) -> Result<OverlaySecret, OverlayClientError> {
        // `&self.holder_seed_hex` auto-derefs `Zeroizing<String>` -> `&str` (clippy flags an
        // explicit `&*` here as redundant); the point of keeping `Zeroizing` is the TYPE held in
        // the struct field, not how it's borrowed at this one call site.
        Ok(OverlaySecret::from_seed_hex(&self.holder_seed_hex)?)
    }

    /// Return the pooled client for `(relay, relay_id, egress_id, capability_only)`, building (and
    /// caching) one if this is the first dial to that pair.
    pub(super) async fn get_or_build(
        &self,
        relay: SocketAddr,
        relay_id: OverlayId,
        egress_id: OverlayId,
        capability_only: bool,
    ) -> Result<Arc<OverlayClient>, OverlayClientError> {
        let key: PoolKey = (relay, relay_id, egress_id, capability_only);
        if let Some(client) = self.clients.read().await.get(&key) {
            return Ok(Arc::clone(client));
        }
        let mut clients = self.clients.write().await;
        // Re-check under the write lock — another task may have built it while we waited.
        if let Some(client) = clients.get(&key) {
            return Ok(Arc::clone(client));
        }
        let secret = self.clone_holder()?;
        let client = Arc::new(
            OverlayClient::builder(secret)
                .relay(relay, relay_id)
                .egress(egress_id)
                .capability_only(capability_only)
                .path_mode(PathMode::PreferDirect)
                .build()?,
        );
        clients.insert(key, Arc::clone(&client));
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_overlay_client::OverlaySecret;

    #[tokio::test]
    async fn the_same_relay_egress_pair_reuses_one_client() {
        let holder = OverlaySecret::generate().unwrap();
        let pool = ClientPool::new(&holder);
        let relay: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let relay_id = OverlaySecret::generate().unwrap().id();
        let egress_id = OverlaySecret::generate().unwrap().id();
        let a = pool
            .get_or_build(relay, relay_id, egress_id, true)
            .await
            .unwrap();
        let b = pool
            .get_or_build(relay, relay_id, egress_id, true)
            .await
            .unwrap();
        assert!(
            Arc::ptr_eq(&a, &b),
            "the same key must reuse the pooled client"
        );
    }

    #[tokio::test]
    async fn a_different_capability_only_posture_builds_a_distinct_client() {
        let holder = OverlaySecret::generate().unwrap();
        let pool = ClientPool::new(&holder);
        let relay: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let relay_id = OverlaySecret::generate().unwrap().id();
        let egress_id = OverlaySecret::generate().unwrap().id();
        let a = pool
            .get_or_build(relay, relay_id, egress_id, true)
            .await
            .unwrap();
        let b = pool
            .get_or_build(relay, relay_id, egress_id, false)
            .await
            .unwrap();
        assert!(
            !Arc::ptr_eq(&a, &b),
            "a different pool key must build a distinct client"
        );
    }
}
