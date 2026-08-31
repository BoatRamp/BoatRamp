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
    /// A bridge ioctl (`SIOCBRADDBR`) failed.
    Ioctl(std::io::Error),
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Connect(e) => write!(f, "netlink connect failed: {e}"),
            NetError::Rtnetlink(e) => write!(f, "netlink request failed: {e}"),
            NetError::NoSuchLink(n) => write!(f, "no such link: {n}"),
            NetError::Ioctl(e) => write!(f, "bridge ioctl failed: {e}"),
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
        match links.try_next().await {
            Ok(Some(msg)) => Ok(msg.header.index),
            Ok(None) => Err(NetError::NoSuchLink(name.to_string())),
            // The kernel answers a name-filtered `GETLINK` for a missing link with
            // `ENODEV` rather than an empty dump — treat that as "not found" so callers
            // (teardown, `ensure_bridge`) can proceed instead of erroring out.
            Err(rtnetlink::Error::NetlinkError(e))
                if e.to_io().raw_os_error() == Some(nix::libc::ENODEV) =>
            {
                Err(NetError::NoSuchLink(name.to_string()))
            }
            Err(e) => Err(NetError::Rtnetlink(e)),
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

/// Create a bridge by name via the classic `SIOCBRADDBR` ioctl (the `brctl addbr`
/// path). Needs no `ip` binary in the image and sidesteps `RTM_NEWLINK`, whose link-info
/// encoding the kernel rejects with the rtnetlink/netlink-packet-route versions in the
/// tree. `EEXIST` (a pre-existing bridge, or a race) is success.
#[cfg(target_os = "linux")]
fn create_bridge(name: &str) -> Result<(), NetError> {
    use nix::libc;
    const SIOCBRADDBR: libc::c_ulong = 0x89a0;
    const IFNAMSIZ: usize = 16;
    if name.len() >= IFNAMSIZ {
        return Err(NetError::Ioctl(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "bridge name too long",
        )));
    }
    // A control socket for the ioctl — its family is irrelevant.
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    if sock < 0 {
        return Err(NetError::Ioctl(std::io::Error::last_os_error()));
    }
    let mut ifname = [0u8; IFNAMSIZ];
    ifname[..name.len()].copy_from_slice(name.as_bytes());
    let rc = unsafe {
        libc::ioctl(
            sock,
            SIOCBRADDBR as _,
            ifname.as_ptr() as *const libc::c_char,
        )
    };
    // Capture errno before `close` can clobber it.
    let err = (rc < 0).then(std::io::Error::last_os_error);
    unsafe { libc::close(sock) };
    match err {
        None => Ok(()),
        Some(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(()),
        Some(e) => Err(NetError::Ioctl(e)),
    }
}

/// Ensure the shared compute bridge exists, is up, and carries the gateway address —
/// creating it (`SIOCBRADDBR` ioctl, then netlink for up + address) when it isn't there.
/// The container and embedded-VMM backends
/// enslave each veth/tap to this bridge; on a fresh host (a stock container image on fly,
/// a bare VM) nothing else creates it, so boatramp creates it itself at compute-node init
/// rather than requiring the operator to pre-create it. The capability that creates the
/// bridge is the same `CAP_NET_ADMIN` that creates the per-container veths, so a node that
/// can run these backends at all can create the bridge; a node that can't should treat the
/// error as "container/VMM backends unavailable" instead of advertising a backend that
/// then fails at launch. Idempotent: a bridge someone else already set up keeps its
/// configuration (only its `up` state is asserted).
#[cfg(target_os = "linux")]
pub async fn ensure_bridge(
    bridge: &str,
    gateway: std::net::Ipv4Addr,
    prefix_len: u8,
) -> Result<(), NetError> {
    let handle = VethNetwork::handle()?;
    // Create the bridge only when it's missing, so a pre-existing bridge (a second node,
    // or a host that set one up on purpose) keeps its addressing.
    let (idx, created) = match VethNetwork::link_index(&handle, bridge).await {
        Ok(idx) => (idx, false),
        Err(NetError::NoSuchLink(_)) => {
            // Create the bridge with the canonical `SIOCBRADDBR` ioctl (what `brctl`
            // uses) rather than an `RTM_NEWLINK` — rtnetlink 0.14's `.bridge()` builder
            // emits a message the kernel rejects (`ENODEV`), and this needs no `ip` binary
            // in the image. Bringing it up + addressing it below is done over netlink.
            create_bridge(bridge)?;
            (VethNetwork::link_index(&handle, bridge).await?, true)
        }
        Err(e) => return Err(e),
    };
    handle
        .link()
        .set(idx)
        .up()
        .execute()
        .await
        .map_err(NetError::Rtnetlink)?;
    // Give a bridge we just created the gateway address so containers can route out. On a
    // pre-existing bridge the address is likely already present (`EEXIST`) or set on
    // purpose, so an error there is tolerated; on a fresh one it is a real failure.
    match handle
        .address()
        .add(idx, std::net::IpAddr::V4(gateway), prefix_len)
        .execute()
        .await
    {
        Ok(()) => Ok(()),
        Err(e) if created => Err(NetError::Rtnetlink(e)),
        Err(_) => Ok(()),
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

    /// Live: `ensure_bridge` creates the bridge over netlink (the exact thing that makes
    /// a stock image on a fresh host turnkey) and is idempotent. `Ok` on a freshly-created
    /// bridge implies the gateway address was assigned (the function fails otherwise).
    /// Needs root / `CAP_NET_ADMIN`; ignored by default.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "needs root + CAP_NET_ADMIN (creates a real bridge over netlink)"]
    async fn ensure_bridge_creates_and_is_idempotent() {
        let name = format!("brt{}", std::process::id() % 100_000); // ≤ 15-char ifname
        let gw: std::net::Ipv4Addr = "10.201.0.1".parse().unwrap();
        let handle = VethNetwork::handle().unwrap();
        // Start clean (a previous crashed run may have left it).
        if let Ok(idx) = VethNetwork::link_index(&handle, &name).await {
            let _ = handle.link().del(idx).execute().await;
        }

        // Fresh create: assigns the gateway (returns Err if that fails), leaves the bridge.
        ensure_bridge(&name, gw, 24)
            .await
            .expect("create bridge + assign gateway");
        let idx = VethNetwork::link_index(&handle, &name)
            .await
            .expect("bridge exists after ensure_bridge");
        // Idempotent: a second call over the now-existing bridge is a no-op success.
        ensure_bridge(&name, gw, 24)
            .await
            .expect("idempotent re-ensure");

        let _ = handle.link().del(idx).execute().await; // cleanup
        eprintln!("ensure_bridge: created {name} + gateway {gw}/24, idempotent, cleaned up");
    }
}
