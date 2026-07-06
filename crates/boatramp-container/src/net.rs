//! veth networking for a container's network namespace.
//!
//! A container gets a **veth pair**: the host end is enslaved to the shared
//! bridge (`br-boatramp`, the same one the VMM taps use), and the peer end is
//! moved into the container's netns (then renamed `eth0` and given the guest IP
//! — the in-netns step, which runs once the worker has unshared its netns). The
//! interface names + IPAM are pure + unit-tested; the netlink calls are the
//! Linux seam.
//!
//! Wiring is done over **netlink** (`rtnetlink`), not `ip(8)` shell-outs.

/// A container's veth pair: `host_veth` (enslaved to `bridge`) ↔ `peer_veth`
/// (moved into the container netns and renamed `eth0`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VethNetwork {
    /// Host-side interface name (on the bridge).
    pub host_veth: String,
    /// Peer interface name (moved into the netns).
    pub peer_veth: String,
    /// The bridge the host end attaches to.
    pub bridge: String,
}

impl VethNetwork {
    /// veth pair names for VM id `vm_id` on `bridge`. Names are capped to the
    /// 15-char interface-name limit (`vth-<id>` / `cth-<id>`).
    pub fn for_vm(vm_id: &str, bridge: &str) -> Self {
        let mut host_veth = format!("vth-{vm_id}");
        host_veth.truncate(15);
        let mut peer_veth = format!("cth-{vm_id}");
        peer_veth.truncate(15);
        Self {
            host_veth,
            peer_veth,
            bridge: bridge.to_string(),
        }
    }
}

/// A netlink networking error.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub enum NetError {
    /// Opening the netlink connection failed.
    Connect(std::io::Error),
    /// A netlink request failed.
    Rtnetlink(rtnetlink::Error),
    /// A link could not be found by name.
    NoSuchLink(String),
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Connect(e) => write!(f, "netlink connect failed: {e}"),
            NetError::Rtnetlink(e) => write!(f, "netlink request failed: {e}"),
            NetError::NoSuchLink(n) => write!(f, "no such link: {n}"),
        }
    }
}

#[cfg(target_os = "linux")]
impl std::error::Error for NetError {}

#[cfg(target_os = "linux")]
impl VethNetwork {
    /// Open a netlink handle, spawning its connection driver on the current
    /// Tokio runtime (callers run inside the backend's async runtime).
    fn handle() -> Result<rtnetlink::Handle, NetError> {
        let (connection, handle, _) = rtnetlink::new_connection().map_err(NetError::Connect)?;
        tokio::spawn(connection);
        Ok(handle)
    }

    /// Resolve a link index by name.
    async fn link_index(handle: &rtnetlink::Handle, name: &str) -> Result<u32, NetError> {
        use futures::TryStreamExt;
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        match links.try_next().await.map_err(NetError::Rtnetlink)? {
            Some(msg) => Ok(msg.header.index),
            None => Err(NetError::NoSuchLink(name.to_string())),
        }
    }

    /// Host-side setup: create the veth pair, enslave the host end to the
    /// bridge, and bring it up. (The peer is moved into the worker's netns by
    /// [`move_peer_into_netns`](Self::move_peer_into_netns) once its pid is known.)
    pub async fn host_setup(&self) -> Result<(), NetError> {
        let handle = Self::handle()?;
        handle
            .link()
            .add()
            .veth(self.host_veth.clone(), self.peer_veth.clone())
            .execute()
            .await
            .map_err(NetError::Rtnetlink)?;
        let host_idx = Self::link_index(&handle, &self.host_veth).await?;
        let bridge_idx = Self::link_index(&handle, &self.bridge).await?;
        handle
            .link()
            .set(host_idx)
            .controller(bridge_idx)
            .execute()
            .await
            .map_err(NetError::Rtnetlink)?;
        handle
            .link()
            .set(host_idx)
            .up()
            .execute()
            .await
            .map_err(NetError::Rtnetlink)?;
        Ok(())
    }

    /// Move the peer end into the worker's network namespace (by pid). Run after
    /// the worker has `unshare`d its netns and before the in-netns `eth0` config.
    pub async fn move_peer_into_netns(&self, worker_pid: u32) -> Result<(), NetError> {
        let handle = Self::handle()?;
        let peer_idx = Self::link_index(&handle, &self.peer_veth).await?;
        handle
            .link()
            .set(peer_idx)
            .setns_by_pid(worker_pid)
            .execute()
            .await
            .map_err(NetError::Rtnetlink)?;
        Ok(())
    }

    /// Teardown: delete the host end, which removes the whole pair. Best-effort —
    /// a missing link is not an error (the pair may already be gone).
    pub async fn teardown(&self) -> Result<(), NetError> {
        let handle = Self::handle()?;
        match Self::link_index(&handle, &self.host_veth).await {
            Ok(idx) => handle
                .link()
                .del(idx)
                .execute()
                .await
                .map_err(NetError::Rtnetlink),
            Err(NetError::NoSuchLink(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_derived_and_length_capped() {
        let v = VethNetwork::for_vm("web-0", "br-boatramp");
        assert_eq!(v.host_veth, "vth-web-0");
        assert_eq!(v.peer_veth, "cth-web-0");
        let long = VethNetwork::for_vm("a-very-long-workload-7", "br-boatramp");
        assert_eq!(long.host_veth.len(), 15);
        assert!(long.host_veth.starts_with("vth-"));
        assert!(long.peer_veth.starts_with("cth-"));
    }
}
