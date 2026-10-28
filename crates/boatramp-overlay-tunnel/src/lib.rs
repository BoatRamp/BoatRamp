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
//! ## Shape (R2 Linux + R3 macOS; behind the `tun` cargo feature, default OFF)
//!
//! - [`tun`] — the full TUN virtual-interface front-end (plan §3): a synthetic-IP allocator, an
//!   embedded non-recursive DNS zone, a `smoltcp`-based userspace TCP/IP stack bridging accepted
//!   connections to [`core::Tunnel::open`], Linux route + split-DNS host integration, and
//!   RAII+marker-file teardown (plan §3.9). Feature-isolated from day one (R1) so the lean SOCKS
//!   build never links any of this crate's (much heavier) `tun`-only dependency set. macOS (R3) and
//!   Windows (R4) are later increments — see [`tun`]'s module doc for the per-OS seam.
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
#[cfg(feature = "tun")]
pub mod tun;

// Ergonomic re-exports of each module's main types, so a consumer (the `boatramp` CLI) can write
// `boatramp_overlay_tunnel::Tunnel` instead of `boatramp_overlay_tunnel::core::Tunnel`. The
// `core`/`socks`/`tun` module names themselves still match the plan's module layout (§4).
pub use core::{ControlPlane, ControlPlaneError, DialGrant, ServiceInfo, Tunnel, TunnelError};
pub use socks::{DEFAULT_MAX_CONNECTIONS, LocalAuth, LocalAuthError, SocksError, SocksServer};
#[cfg(feature = "tun")]
pub use tun::{TunError, TunFrontend, TunOptions};
