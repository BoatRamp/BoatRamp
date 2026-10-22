//! # boatramp overlay service tunneler
//!
//! Reach overlay services **by name**, OpenZiti-style: the fabric already assigns dynamic internal
//! topology and authorizes by identity + capability + policy, never by address, so this crate adds
//! no new authority — it is a client-side consumption layer over the existing
//! [`boatramp_overlay_client`] SDK.
//!
//! `plans/overlay-service-tunneler.md` (in the main boatramp checkout) is the authoritative design
//! doc this crate implements; module docs below point back at its sections.
//!
//! ## Shape (R1 — this release)
//!
//! - [`core`] — the front-end-agnostic core: catalog, lazy capability mint + lifecycle, an
//!   `OverlayClient` pool, and [`core::Tunnel::open`] (`(service name) → Flow`). The
//!   [`core::ControlPlane`] trait is the injected catalog/mint boundary — this crate itself never
//!   performs control-plane HTTP or holds a project token; the `boatramp` CLI implements it.
//! - [`socks`] — the SOCKS5 front-end (plan §2): a hand-rolled, loopback-bound SOCKS5 (+ optional
//!   HTTP `CONNECT`) server that maps an in-band hostname to a service name and calls `open`.
//!
//! ## Shape (later releases)
//!
//! - `tun` (behind the `tun` cargo feature, default OFF) — the full TUN virtual-interface front-end
//!   (plan §3): synthetic IPs, an embedded DNS zone, a userspace TCP/IP stack. Not implemented in
//!   this release; see [`tun`] for the scaffold and why it is feature-isolated from day one.
//!
//! ## Dependency posture
//!
//! The only boatramp dependency is [`boatramp_overlay_client`] (the embeddable overlay client SDK).
//! This crate never links `boatramp-overlay`'s server roles, `boatramp-server`, or `boatramp-core` —
//! the lean (no-`tun`) build graph stays ring-free / rustls-platform-verifier-free, matching the
//! SDK's own posture (see `.github/workflows/mobile.yml`).
#![forbid(unsafe_code)]

pub mod core;
pub mod socks;

// Ergonomic re-exports of each module's main types, so a consumer (the `boatramp` CLI) can write
// `boatramp_overlay_tunnel::Tunnel` instead of `boatramp_overlay_tunnel::core::Tunnel`. The
// `core`/`socks`/`tun` module names themselves still match the plan's module layout (§4).
pub use core::{ControlPlane, ControlPlaneError, DialGrant, ServiceInfo, Tunnel, TunnelError};
pub use socks::{LocalAuth, LocalAuthError, SocksError, SocksServer};

/// The TUN virtual-interface front-end (plan §3) — a **feature-gated scaffold only** in this
/// release.
///
/// R1 ships the shared core + SOCKS5 front-end only (plan §8). This module exists so release R2 can
/// land the TUN device/embedded-DNS/synthetic-IP-allocator/userspace-TCP-IP-stack implementation
/// (and its much heavier dependency set — `tun`, `smoltcp`, `hickory-*`, `net-route`) behind the
/// SAME `tun` cargo feature from day one, without ever having touched the lean, ring-free SOCKS
/// build: the feature is `default = []` (off) on this crate, so the dependency isolation this module
/// reserves is real today, not aspirational.
#[cfg(feature = "tun")]
pub mod tun {
    /// Always returned in this release — see the module doc. R2 replaces this with the real
    /// device/DNS/synthetic-IP/netstack wiring (plan §3).
    #[derive(Debug, thiserror::Error)]
    pub enum TunError {
        #[error(
            "the TUN front-end is not implemented in this release (R1 ships the shared core + \
             SOCKS5 front-end only); it is a later increment — see \
             plans/overlay-service-tunneler.md §3/§8 (R2)"
        )]
        NotImplemented,
    }

    /// Always fails in this release. Present (rather than omitted) so `--features tun` already
    /// exercises the real call path a later release fills in, instead of a dangling cargo feature
    /// with nothing behind it.
    pub fn start() -> Result<(), TunError> {
        Err(TunError::NotImplemented)
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn the_tun_stub_always_reports_not_implemented() {
            assert!(matches!(
                super::start(),
                Err(super::TunError::NotImplemented)
            ));
        }
    }
}
