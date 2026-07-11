//! Cluster mesh identity & RFC 7250 raw-public-key mutual TLS.
//!
//! The Raft peer mesh must authenticate every peer: a `WriteOp` is an arbitrary
//! control-plane KV write, so an unauthenticated mesh port is total compromise
//! (the audit's top finding). Mesh nodes run on private networks with no public
//! DNS, so ACME/WebPKI can't authenticate them — the mesh needs its own trust
//! domain. See `docs/SECURITY-mesh-identity.md`.
//!
//! The **RPK crypto core** — identity, the live pinning [`TrustSet`], the rustls
//! server/client configs, and the [`MeshTls`] bundle — lives in the shared,
//! raft-free [`boatramp_rpktls`] crate (also used by the control-plane bootstrap
//! TLS mode) and is re-exported here under the mesh names. This module keeps only
//! the **mesh-specific glue**: the durable trust-key format written to the
//! replicated KV, and the per-peer pinned `reqwest` client cache.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::raft::NodeId;

// The RPK crypto core, re-exported under the historical mesh names so the rest of
// the cluster crate (and any external user) is unchanged.
pub use boatramp_rpktls::{
    client_config, parse_public_key, server_config, PresentedKey, RpkError as MeshError,
    RpkIdentity as MeshIdentity, RpkTls as MeshTls, TrustSet,
};

/// The replicated-KV prefix under which the durable trust set lives: each
/// accepted key is one entry — `mesh/trust/{node_id}/{pubkey_hex}` with an empty
/// value — so a join / rotation / revocation is an atomic single-key `Put`/
/// `Delete` that the apply observer mirrors into every node's live [`TrustSet`],
/// and a restart rehydrates the set by listing this prefix. Re-exported here; the
/// canonical definition lives with the apply layer that writes it ([`crate::raft`]).
pub use crate::raft::TRUST_PREFIX;

/// The durable KV key that trusts `spki` for `node` (delegates to the canonical
/// key format in [`crate::raft`], shared with [`crate::raft::WriteOp::MeshAdmit`]).
pub fn trust_key(node: NodeId, spki: &[u8]) -> String {
    crate::raft::trust_key_hex(node, &to_hex(spki))
}

/// Parse a `mesh/trust/{node}/{hex}` key back into `(node_id, spki)`; `None` if
/// `key` is not a well-formed trust entry.
pub fn parse_trust_key(key: &str) -> Option<(NodeId, Vec<u8>)> {
    let rest = key.strip_prefix(TRUST_PREFIX)?;
    let (node, hex) = rest.split_once('/')?;
    Some((node.parse().ok()?, from_hex(hex)?))
}

/// Rebuild a `node_id → {SPKI}` map from the durable trust keys under
/// [`TRUST_PREFIX`] (the restart-hydration and snapshot-catch-up path).
pub fn trust_from_keys<'a>(
    keys: impl IntoIterator<Item = &'a str>,
) -> BTreeMap<NodeId, Vec<Vec<u8>>> {
    let mut sets: BTreeMap<NodeId, Vec<Vec<u8>>> = BTreeMap::new();
    for key in keys {
        if let Some((node, spki)) = parse_trust_key(key) {
            sets.entry(node).or_default().push(spki);
        }
    }
    sets
}

/// Per-peer pinned `reqwest` clients, cached: dialing a peer uses a client that
/// will only complete a handshake with **that peer's** trusted key (each client
/// carries its own connection pool + pinned TLS config).
#[derive(Debug)]
pub struct MeshClients {
    mesh: Arc<MeshTls>,
    cache: std::sync::Mutex<BTreeMap<NodeId, reqwest::Client>>,
}

impl MeshClients {
    /// A client factory over `mesh`.
    pub fn new(mesh: Arc<MeshTls>) -> Self {
        Self {
            mesh,
            cache: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// A `reqwest` client pinned to `peer`'s trusted key (cached across calls).
    pub fn client(&self, peer: NodeId) -> Result<reqwest::Client, MeshError> {
        if let Some(client) = self.cache.lock().expect("mesh client cache").get(&peer) {
            return Ok(client.clone());
        }
        let config = self.mesh.client_for(peer)?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .build()
            .map_err(|e| MeshError::Client(e.to_string()))?;
        self.cache
            .lock()
            .expect("mesh client cache")
            .insert(peer, client.clone());
        Ok(client)
    }
}

/// Lower-case hex of `bytes` (for the durable trust-key format).
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode an even-length hex string; `None` on any non-hex or odd length.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_key_round_trips_through_parse() {
        let id = MeshIdentity::generate().unwrap();
        let key = trust_key(7, id.public_key());
        let (node, spki) = parse_trust_key(&key).expect("well-formed trust key parses");
        assert_eq!(node, 7);
        assert_eq!(spki, id.public_key());
        // A malformed key does not parse.
        assert!(parse_trust_key("not/a/trust/key").is_none());
    }

    #[test]
    fn trust_from_keys_groups_multiple_keys_per_node() {
        let a = MeshIdentity::generate().unwrap();
        let b = MeshIdentity::generate().unwrap();
        let keys = [
            trust_key(1, a.public_key()),
            trust_key(1, b.public_key()),
            trust_key(2, a.public_key()),
        ];
        let sets = trust_from_keys(keys.iter().map(String::as_str));
        assert_eq!(sets.get(&1).map(Vec::len), Some(2));
        assert_eq!(sets.get(&2).map(Vec::len), Some(1));
    }
}
