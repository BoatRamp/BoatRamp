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
    /// veth pair names for VM id `vm_id` on `bridge`.
    ///
    /// The Linux interface-name limit is 15 chars (`IFNAMSIZ - 1`), so the name must
    /// fit `vth-`/`cth-` (4) + an 11-char body. A plain `truncate(15)` was a **latent
    /// collision**: two distinct long workload names that share a 15-char prefix — e.g.
    /// two `Single` per-tenant containers `pg-construens_AAAA…` vs `pg-construens_BBBB…`
    /// whose sanitized idents diverge only after char 11 — collapse to the *same*
    /// `vth-…` / `cth-…` name, so the second container's `host_setup` fails (or worse,
    /// silently attaches to the first's veth). Instead, derive the 11-char body from a
    /// **stable hash of the FULL `vm_id`** (base-36, so it's dense + ifname-safe), which
    /// is deterministic (same `vm_id` ⇒ same names, for idempotent teardown/relaunch)
    /// and collision-resistant across distinct long names.
    pub fn for_vm(vm_id: &str, bridge: &str) -> Self {
        let body = veth_body(vm_id);
        Self {
            host_veth: format!("vth-{body}"),
            peer_veth: format!("cth-{body}"),
            bridge: bridge.to_string(),
        }
    }
}

/// The ≤11-char interface-name body for `vm_id`. A short-enough `vm_id` keeps its
/// literal name (readable, and byte-identical to the historical `vth-<id>` for the
/// common `web-0` case); a longer one is replaced by an 11-char base-36 digest of the
/// **whole** id so distinct long names never collapse to the same interface name.
fn veth_body(vm_id: &str) -> String {
    /// `15 - "vth-".len()` — the body must leave room for the 4-char prefix.
    const MAX_BODY: usize = 11;
    if vm_id.len() <= MAX_BODY {
        return vm_id.to_string();
    }
    hash_b36(vm_id, MAX_BODY)
}

/// A stable, deterministic base-36 (`[0-9a-z]`) digest of `s`, `width` chars wide.
///
/// Uses FNV-1a over a 64-bit accumulator (with a second, differently-seeded pass so
/// 11 base-36 chars — ~56.9 bits — carry more than one 64-bit hash's worth of entropy
/// mixed in). Deterministic across builds/platforms (unlike `std`'s `DefaultHasher`,
/// whose output is explicitly not stable), so the same `vm_id` always yields the same
/// interface names — required for idempotent teardown/relaunch. Mirrors the base-36
/// encoding style used for SQL-identifier disambiguation in `boatramp-storage`'s
/// `tenant_provision`; a full 128-bit SHA-256 digest is overkill for a 15-char ifname.
///
/// `pub(crate)` so the container backend can reuse it to clamp an over-long container
/// id to the UTS hostname limit with the same collision-resistant digest.
pub(crate) fn hash_b36(s: &str, width: usize) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    const DIGITS: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    // Two independently-seeded FNV-1a passes → a 128-bit accumulator, so the base-36
    // body draws from far more entropy than its ~57 bits can represent (no truncation
    // artifact narrows the effective space).
    let mut lo = FNV_OFFSET;
    let mut hi = FNV_OFFSET ^ 0x9e37_79b9_7f4a_7c15;
    for &b in s.as_bytes() {
        lo = (lo ^ b as u64).wrapping_mul(FNV_PRIME);
        hi = (hi.wrapping_add(b as u64)).wrapping_mul(FNV_PRIME);
    }
    let mut acc = ((hi as u128) << 64) | lo as u128;
    let mut buf = vec![b'0'; width];
    let mut i = width;
    while acc > 0 && i > 0 {
        i -= 1;
        buf[i] = DIGITS[(acc % 36) as usize];
        acc /= 36;
    }
    String::from_utf8(buf).expect("base-36 digits are ASCII")
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
    // Give the bridge the gateway address so containers can route out. This runs on
    // BOTH a freshly-created bridge AND a pre-existing one: a stale bridge left by a
    // prior boot (or another node) that never got — or somehow lost — its `.1` address
    // would otherwise leave every container with an unreachable gateway, which looks
    // exactly like the "broken first launch" auth chaos (packets never reach the DB).
    // So we always assert the address and tolerate ONLY a genuine "already present"
    // (`EEXIST`) — any other failure is real. (On a bridge someone else deliberately
    // addressed differently, the add is a harmless `EEXIST` for the same address, or a
    // real error we must surface rather than silently swallow.)
    match handle
        .address()
        .add(idx, std::net::IpAddr::V4(gateway), prefix_len)
        .execute()
        .await
    {
        Ok(()) => Ok(()),
        // The address is already on the bridge — the steady-state re-ensure path.
        Err(e) if is_already_exists(&e) => Ok(()),
        Err(e) => Err(NetError::Rtnetlink(e)),
    }
    .inspect(|()| {
        if !created {
            tracing::debug!(bridge, %gateway, "ensure_bridge: asserted gateway on pre-existing bridge");
        }
    })
}

/// Whether an rtnetlink error is a benign `EEXIST` — the address (or object) is
/// already present, so asserting it again is a no-op success.
#[cfg(target_os = "linux")]
fn is_already_exists(e: &rtnetlink::Error) -> bool {
    matches!(
        e,
        rtnetlink::Error::NetlinkError(n) if n.to_io().raw_os_error() == Some(nix::libc::EEXIST)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_derived_and_length_capped() {
        // A short id keeps its literal, readable name (byte-identical to the historical
        // `vth-<id>` — no churn for the common case).
        let v = VethNetwork::for_vm("web-0", "br-boatramp");
        assert_eq!(v.host_veth, "vth-web-0");
        assert_eq!(v.peer_veth, "cth-web-0");
        let long = VethNetwork::for_vm("a-very-long-workload-7", "br-boatramp");
        assert_eq!(long.host_veth.len(), 15);
        assert!(long.host_veth.starts_with("vth-"));
        assert!(long.peer_veth.starts_with("cth-"));
    }

    /// Two long `Single` per-tenant workload names that share a 15-char prefix (so a
    /// plain `truncate(15)` collapsed them to the same interface name) must yield
    /// DIFFERENT host AND peer veth names, each ≤15 chars, and the same name must be
    /// stable across calls (idempotent teardown/relaunch).
    #[test]
    fn long_names_sharing_a_prefix_do_not_collide() {
        // `pg-construens_xxx…<ident>`: identical through the first 15+ chars (the whole
        // `truncate(15)` window), diverging only in the tail — the exact shape that
        // collapsed under a plain truncation.
        let a_id = "pg-construens_shared_prefix_AAAAAAAAAAAA";
        let b_id = "pg-construens_shared_prefix_BBBBBBBBBBBB";
        assert_eq!(
            &a_id[..15],
            &b_id[..15],
            "the two ids share a 15-char prefix"
        );

        let a = VethNetwork::for_vm(a_id, "br-boatramp");
        let b = VethNetwork::for_vm(b_id, "br-boatramp");

        // Each name fits the 15-char ifname limit and keeps its prefix.
        for n in [&a.host_veth, &a.peer_veth, &b.host_veth, &b.peer_veth] {
            assert!(n.len() <= 15, "over the 15-char ifname limit: {n:?}");
        }
        assert!(a.host_veth.starts_with("vth-") && a.peer_veth.starts_with("cth-"));

        // Distinct ids ⇒ distinct host AND peer names (the collision the fix closes).
        assert_ne!(a.host_veth, b.host_veth, "host veth collision!");
        assert_ne!(a.peer_veth, b.peer_veth, "peer veth collision!");

        // Deterministic: the same id yields the same names every call.
        let a_again = VethNetwork::for_vm(a_id, "br-boatramp");
        assert_eq!(a.host_veth, a_again.host_veth);
        assert_eq!(a.peer_veth, a_again.peer_veth);
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
