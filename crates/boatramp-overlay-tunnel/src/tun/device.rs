//! The real Linux TUN device (plan §3.1) + CIDR route install (plan §3.2) — the ONLY module in
//! this front-end that touches an actual file descriptor or the kernel's routing table. Per-OS
//! seam (see [`super`]'s module doc): everything else in this front-end (`alloc`, `dns`, `netstack`,
//! `packet`) is OS-agnostic; R3 (macOS)/R4 (Windows) would each bring their own version of this
//! module (and `resolver`/`privilege`), reusing everything else unchanged.
//!
//! Built on `tun-rs`, not the plan's originally-named `tun` crate — see this crate's `Cargo.toml`
//! for why (a license mismatch the plan didn't catch: `tun`'s own manifest declares `WTFPL`, not
//! MIT, and isn't in this workspace's license allow-list; `tun-rs` is Apache-2.0, already
//! allow-listed, and offers the same async/tokio Linux `/dev/net/tun` surface).

use std::net::Ipv4Addr;
use std::sync::Arc;

use tun_rs::AsyncDevice;

use super::cidr::Ipv4Cidr;

/// A failure opening or configuring the TUN device, or installing its route.
#[derive(Debug, thiserror::Error)]
pub enum DeviceError {
    #[error(
        "opening the TUN device: {0} — this needs CAP_NET_ADMIN (`setcap cap_net_admin+ep` on the \
         `boatramp` binary) or root; see plan §3.7"
    )]
    Open(#[source] std::io::Error),
    #[error("reading the TUN device's name/index back: {0}")]
    Query(#[source] std::io::Error),
    #[error("installing the {cidr} route via the TUN device: {source}")]
    Route {
        cidr: Ipv4Cidr,
        #[source]
        source: std::io::Error,
    },
}

/// A bound TUN device + its queried identity. [`AsyncDevice`]'s own [`Drop`] closes the underlying
/// file descriptor, which the kernel treats as "remove this interface" — so the device itself needs
/// no separate RAII wrapper here: keep this (or a clone of its `Arc`) alive for as long as the
/// interface should exist, and dropping the last reference tears the interface (and, per plan
/// §3.9, anything routed through it) down.
pub struct TunDevice {
    pub device: Arc<AsyncDevice>,
    pub name: String,
    pub if_index: u32,
}

/// Open + configure the TUN device: assign `interface_addr` (plan §3.1/§3.2 — reserved by
/// [`super::alloc::SyntheticIpAllocator::reserve_interface_address`], never handed out to a
/// service) with `cidr`'s own prefix length, set `mtu`, and bring it up (`tun-rs`'s default). This
/// function does not itself check or elevate privilege (plan §3.7) — it just surfaces the OS error
/// if the caller lacks `CAP_NET_ADMIN`/root.
pub async fn open(
    name_hint: Option<&str>,
    interface_addr: Ipv4Addr,
    cidr: Ipv4Cidr,
    mtu: u16,
) -> Result<TunDevice, DeviceError> {
    let mut builder = tun_rs::DeviceBuilder::new()
        .ipv4(interface_addr, cidr.prefix_len(), None)
        .mtu(mtu);
    if let Some(name) = name_hint {
        builder = builder.name(name);
    }
    let device = builder.build_async().map_err(DeviceError::Open)?;
    let name = device.name().map_err(DeviceError::Query)?;
    let if_index = device.if_index().map_err(DeviceError::Query)?;
    Ok(TunDevice {
        device: Arc::new(device),
        name,
        if_index,
    })
}

/// Install the route for the WHOLE configured CIDR via the TUN device (plan §3.2) using `net-route`
/// (a non-decision per plan §9). Tolerant of "already exists": assigning `interface_addr` with
/// `cidr`'s own prefix (in [`open`]) already makes the kernel create the identical connected route
/// for free on most systems, so an explicit duplicate add is expected, not a failure.
///
/// **No RAII revert here, by design** — plan §3.9's own text: "routes bound to the TUN vanish when
/// the device dies." Unlike the resolver override ([`super::resolver`]), this mutation's lifetime is
/// already tied to the device's fd (dropping [`TunDevice::device`] removes the interface and every
/// route bound to it), so there is nothing to track in the dirty-state marker beyond "a route was
/// installed" — informational, not actionable on a later cleanup.
pub async fn install_route(cidr: Ipv4Cidr, if_index: u32) -> Result<(), DeviceError> {
    let handle = net_route::Handle::new().map_err(|e| DeviceError::Route { cidr, source: e })?;
    let route = net_route::Route::new(std::net::IpAddr::V4(cidr.network()), cidr.prefix_len())
        .with_ifindex(if_index);
    match handle.add(&route).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(DeviceError::Route { cidr, source: e }),
    }
}
