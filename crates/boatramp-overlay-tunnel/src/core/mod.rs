//! The front-end-agnostic core (plan §1): catalog, cap-cache, `OverlayClient` pool, and `open`. See
//! [`Tunnel`] for the boundary front-ends (SOCKS today, TUN later) are built against.

mod cap_cache;
mod catalog;
mod control_plane;
mod name;
mod pool;
#[cfg(test)]
pub(crate) mod test_support;
mod tunnel;

pub use control_plane::{ControlPlane, ControlPlaneError, DialGrant, ServiceInfo};
pub use name::normalize_name;
pub use tunnel::{Tunnel, TunnelError};
