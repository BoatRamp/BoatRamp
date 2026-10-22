//! The full TUN virtual-interface front-end (plan §3), release R2 — Linux only; see the crate-level
//! module doc for why this whole module is feature-gated and what R1 shipped instead. The
//! submodules below mirror the plan's own breakdown:
//!
//! - [`cidr`] — a tiny hand-rolled IPv4 CIDR type (plan §3.2).
//! - [`alloc`] — the per-project synthetic-IP allocator (plan §3.4).
//! - [`packet`] — panic-free IPv4+TCP header peeking, shared by the netstack's pre-scan and the
//!   `cargo-fuzz` target (plan §3.5/§5/§6).
//! - [`dns`] — the embedded, zone-scoped, non-recursive DNS responder (plan §3.3).
//! - [`netstack`] — the `smoltcp`-based userspace TCP/IP stack (plan §3.5) — the main new
//!   security-sensitive surface (plan §5).
//! - [`device`] — the real Linux TUN device + route install (plan §3.1/§3.2); the ONLY place a real
//!   file descriptor or the network stack's routing table is touched. Per-OS seam: everything above
//!   this line is already OS-agnostic; `device`/`resolver`/`privilege` are where R3 (macOS) and R4
//!   (Windows) slot in their own implementations alongside this one.
//! - [`resolver`] — host DNS split-horizon integration (plan §3.6), Linux `resolvectl`/systemd-
//!   resolved with a managed `/etc/resolv.conf` fallback.
//! - [`privilege`] — best-effort `CAP_NET_ADMIN`/root privilege drop after setup (plan §3.7).
//! - [`teardown`] — RAII host-mutation guards + the on-disk dirty-state marker (plan §3.9 — "the
//!   single most important robustness requirement").

pub mod alloc;
pub mod cidr;
pub mod device;
pub mod dns;
pub mod netstack;
pub mod packet;
pub mod privilege;
pub mod resolver;
pub mod teardown;

mod frontend;

pub use frontend::{TunError, TunFrontend, TunOptions};
