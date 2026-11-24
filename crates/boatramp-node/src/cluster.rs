//! The cluster peer-mesh assembly (PLAN-node-library N4, "cluster + TLS assembly" — the cluster
//! slice).
//!
//! The `boatramp serve --mode cluster` startup (`run_cluster` in the binary) used to inline the
//! peer-mesh mutual-TLS listener config and the non-loopback empty-trust fail-closed guard, where
//! no in-process test could exercise the exact mesh TLS posture or the fail-closed invariant. This
//! module lifts those two pure, trust-relevant pieces behind a library seam.
//!
//! The binary keeps every IO / runtime concern of `run_cluster`: opening the node-local SlateDB
//! Raft store, the startup decision + join (dialing seeds), `build_node` (the openraft bootstrap +
//! `RaftKv` facade), the `MeshTransport` construction, the post-KV sealed-credential blob pass, and
//! the `serve_tls` loop. It calls these helpers for the pure config / decision assembly.
//!
//! **Behaviour-preserving (a pure move).** The mesh mutual-TLS config (RFC 7250 raw-public-key, the
//! live pinning trust set, the serving ALPN) and the fail-closed trust guard are assembled
//! byte-for-byte as before — no trust decision changed. `MeshTls` is
//! [`boatramp_rpktls::RpkTls`] (the shared RPK crypto core `boatramp_cluster::mesh` re-exports as
//! `MeshTls`), so this rides the RPK stack the `tls` feature already pulls and needs no
//! `boatramp-cluster` dependency. Runtime-agnostic: pure synchronous assembly, no `tokio::spawn`.

use std::net::SocketAddr;

use crate::error::Result;

/// Build the peer-mesh **mutual-TLS** listener config (`run_cluster`'s HTTP-transport mesh server):
/// RFC 7250 raw-public-key mutual TLS over the node's mesh identity + its live pinning trust set
/// ([`RpkTls::server`](boatramp_rpktls::RpkTls::server) — every `/raft/*` + `/stream/*` peer must
/// present a trusted key), advertising the serving ALPN (`h2` / `http/1.1`). A pure config build —
/// the caller layers the write-authz extension on the mesh router and runs `serve_tls`.
///
/// `mesh_tls` is a [`boatramp_rpktls::RpkTls`] — the exact type `boatramp_cluster::mesh::MeshTls`
/// aliases — so the mutual-TLS trust posture (client auth required, pinned to the live trust set,
/// no resumable tickets) is the identical build the binary ran; only the ALPN tag is appended here.
pub fn mesh_server_config(mesh_tls: &boatramp_rpktls::RpkTls) -> Result<rustls::ServerConfig> {
    let mut config = mesh_tls.server()?;
    config.alpn_protocols = boatramp_server::alpn_h1_h2();
    Ok(config)
}

/// The fail-closed guard shared by `run_cluster`'s two `MeshUnconfigured` checks: a peer mesh on a
/// **non-loopback** bind with an **empty trust set** must refuse to serve — bringing it up would
/// expose an unauthenticated control plane. The caller composes the phase condition around this
/// pure core (`!is_resume` before `build_node` seeds genesis trust; `is_resume` after `build_node`
/// rehydrates the durable trust set), so the security invariant lives in one tested place.
///
/// A loopback bind (`127.0.0.1` / `::1`) is never gated — a single-host / dev node has no peers to
/// trust — which is exactly the prior inlined behaviour.
pub fn mesh_trust_fails_closed(listen: SocketAddr, trust_empty: bool) -> bool {
    !listen.ip().is_loopback() && trust_empty
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_rpktls::{RpkIdentity, RpkTls, TrustSet};
    use std::sync::Arc;

    #[test]
    fn mesh_server_config_advertises_the_serving_alpn() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let identity = Arc::new(RpkIdentity::generate().unwrap());
        // An empty trust set builds fine — `RpkTls::server` uses a custom live-trust verifier
        // (not a webpki root store), so the config assembles and rejects untrusted peers at
        // handshake. We assert the serving ALPN the mesh listener advertises.
        let mesh = RpkTls::new(identity, TrustSet::default());
        let config = mesh_server_config(&mesh).unwrap();
        assert_eq!(config.alpn_protocols, boatramp_server::alpn_h1_h2());
    }

    #[test]
    fn mesh_fails_closed_only_on_a_non_loopback_bind_with_empty_trust() {
        let loopback: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let loopback6: SocketAddr = "[::1]:7000".parse().unwrap();
        let public: SocketAddr = "203.0.113.5:7000".parse().unwrap();
        // A loopback bind never fails closed — even with no trust (single-host / dev).
        assert!(!mesh_trust_fails_closed(loopback, true));
        assert!(!mesh_trust_fails_closed(loopback6, true));
        // A non-loopback bind with an empty trust set refuses — the security invariant.
        assert!(mesh_trust_fails_closed(public, true));
        // A non-loopback bind with a trust anchor serves.
        assert!(!mesh_trust_fails_closed(public, false));
    }
}
