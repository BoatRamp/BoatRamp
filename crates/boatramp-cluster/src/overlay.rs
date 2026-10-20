//! Overlay-QUIC transport for the Raft peer mesh (IU-9).
//!
//! The symmetric alternative to the HTTP mesh ([`crate::http`]): boatramp's own cluster mesh RPC
//! rides the overlay fabric's QUIC-on-raw-public-key-TLS transport ([`boatramp_overlay`]) instead
//! of reqwest/axum over HTTP. It reuses the node's **existing** mesh identity + **live** trust set
//! ([`MeshTls`], an `RpkTls`) verbatim — the same RFC-7250 raw-public-key mutual authentication, so
//! a replicated join / rotation / revocation is honored live and an untrusted peer is rejected at
//! the handshake, exactly as on the HTTP mesh. There is no second identity domain.
//!
//! The three transport seams mirror [`crate::http`] one-for-one (so raft/messaging are unchanged):
//! - [`OverlayStreamBus`] — the data-plane SSE fan-out (migrated first);
//! - [`OverlayForwarder`] — follower→leader client-write forwarding;
//! - [`OverlayNetworkFactory`] / [`OverlayNetwork`] — the openraft consensus RPCs.
//!
//! The server side is [`serve_mesh`]: a QUIC accept loop that dispatches framed requests to the
//! node's Raft handle + stream hubs — the overlay equivalent of mounting `raft_router` +
//! `stream_router` on an axum mTLS listener. Mesh peers are co-located and dial each other
//! **directly** (no relay), so QUIC's own TLS 1.3 provides the encryption and the mutual RPK auth;
//! the relay-blind E2EE and NAT traversal of the wider fabric are latent here, not needed between
//! cluster peers.
//!
//! Framing: each RPC opens its own bi-stream carrying `[kind: u8][len: u32-BE][json body]` and reads
//! back `[len: u32-BE][json body]`. A larger body than [`MAX_MESH_FRAME`] is a protocol error.

use std::collections::BTreeMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use openraft::BasicNode;
use openraft::error::{NetworkError, RPCError, RaftError, RemoteError};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};

use boatramp_core::messaging::StreamHubs;
use boatramp_overlay::quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use boatramp_overlay::{self as overlay};

use crate::http::{ClientWriteAuthz, Peers, WriteAuthz};
use crate::mesh::MeshTls;
use crate::messaging::StreamBus;
use crate::raft::{
    ClientWriteRaftError, ForwardError, Forwarder, NodeId, TypeConfig, WriteOp, WriteResponse,
};

/// RPC kind, the request's first byte.
const K_APPEND: u8 = 1;
const K_VOTE: u8 = 2;
const K_SNAPSHOT: u8 = 3;
const K_CLIENT_WRITE: u8 = 4;
const K_STREAM: u8 = 5;

/// Upper bound on a single framed mesh RPC body (64 MiB). Generous because one `InstallSnapshot`
/// chunk rides one frame; a larger frame is a protocol error, not a buffer to grow.
const MAX_MESH_FRAME: usize = 64 * 1024 * 1024;

/// Application error code used to reset the client-write stream on an authorization refusal, so the
/// forwarder sees a transport failure (mirroring the HTTP path's `403` → retry/degrade) and never
/// observes a committed write.
const UNAUTHORIZED_RESET: u32 = 0x29A;

/// How long to wait between forward retries while leadership settles (mirrors the HTTP forwarder).
const FORWARD_BACKOFF: Duration = Duration::from_millis(100);

/// The client-write request carried over the overlay. The cluster-write capability rides the frame
/// (the overlay has no HTTP headers); the leader's [`ClientWriteAuthz`] gates it exactly as on the
/// HTTP path, so being a trusted mesh peer is still not, by itself, a control-plane write capability.
#[derive(serde::Serialize, serde::Deserialize)]
struct MeshClientWrite {
    op: WriteOp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capability: Option<String>,
}

/// A live stream event relayed between nodes over the overlay mesh.
#[derive(serde::Serialize, serde::Deserialize)]
struct StreamBroadcast {
    topic: String,
    id: String,
    payload: Vec<u8>,
}

/// A mesh transport failure (dial / stream / framing). Mapped to the right error at each seam.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    /// No dialable address for the peer in the shared directory.
    #[error("no address for peer {0} in the directory")]
    NoAddress(NodeId),
    /// Building an endpoint or dialing a peer failed (incl. an untrusted-peer handshake rejection).
    #[error("overlay transport: {0}")]
    Quic(#[from] overlay::QuicError),
    /// A stream-level failure (open/read/write/finish).
    #[error("mesh stream: {0}")]
    Stream(String),
    /// A framed body exceeded [`MAX_MESH_FRAME`].
    #[error("mesh frame too large: {0} bytes")]
    TooLarge(usize),
    /// A request/response body failed to (de)serialize.
    #[error("mesh rpc wire: {0}")]
    Json(#[from] serde_json::Error),
}

/// Write a length-delimited body (4-byte big-endian length prefix) to a QUIC send stream.
async fn write_lp(send: &mut SendStream, body: &[u8]) -> Result<(), MeshError> {
    send.write_all(&(body.len() as u32).to_be_bytes())
        .await
        .map_err(|e| MeshError::Stream(e.to_string()))?;
    send.write_all(body)
        .await
        .map_err(|e| MeshError::Stream(e.to_string()))?;
    Ok(())
}

/// Read a length-delimited body (bounded by `max`) from a QUIC recv stream.
async fn read_lp(recv: &mut RecvStream, max: usize) -> Result<Vec<u8>, MeshError> {
    let mut len = [0u8; 4];
    recv.read_exact(&mut len)
        .await
        .map_err(|e| MeshError::Stream(e.to_string()))?;
    let n = u32::from_be_bytes(len) as usize;
    if n > max {
        return Err(MeshError::TooLarge(n));
    }
    let mut buf = vec![0u8; n];
    recv.read_exact(&mut buf)
        .await
        .map_err(|e| MeshError::Stream(e.to_string()))?;
    Ok(buf)
}

/// Resolve `peer`'s overlay UDP address from the shared directory. The directory stores an
/// `https://host:port` URL (shared with the HTTP transport); the overlay mesh dials the **same**
/// host:port over UDP/QUIC, so one directory and the replicated `mesh/addr/*` keys serve both
/// transports with no second address space.
fn peer_addr(peers: &Peers, peer: NodeId) -> Result<SocketAddr, MeshError> {
    let url = peers.get(peer).ok_or(MeshError::NoAddress(peer))?;
    let authority = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(&url)
        .trim_end_matches('/');
    authority
        .to_socket_addrs()
        .ok()
        .and_then(|mut a| a.next())
        .ok_or(MeshError::NoAddress(peer))
}

/// The overlay mesh dialer: one QUIC endpoint (its socket both accepts and dials), the node's
/// `MeshTls` for per-peer key-pinned client configs over the live trust set, the shared peer
/// directory, and a per-peer connection cache.
pub struct OverlayMesh {
    endpoint: Endpoint,
    tls: Arc<MeshTls>,
    peers: Peers,
    conns: tokio::sync::Mutex<BTreeMap<NodeId, Connection>>,
}

impl OverlayMesh {
    /// Build the dialer over `endpoint` (a [`boatramp_overlay::mesh_endpoint`]), the node's `tls`,
    /// and the shared peer directory.
    pub fn new(endpoint: Endpoint, tls: Arc<MeshTls>, peers: Peers) -> Self {
        Self {
            endpoint,
            tls,
            peers,
            conns: tokio::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// A live connection to `peer` (cached; a closed/faulted one is re-dialed, pinned to the peer's
    /// trusted key from the live trust set).
    async fn conn(&self, peer: NodeId) -> Result<Connection, MeshError> {
        {
            let cache = self.conns.lock().await;
            if let Some(c) = cache.get(&peer)
                && c.close_reason().is_none() {
                    return Ok(c.clone());
                }
        }
        let addr = peer_addr(&self.peers, peer)?;
        let conn = overlay::dial_mesh_peer(&self.endpoint, &self.tls, peer, addr).await?;
        self.conns.lock().await.insert(peer, conn.clone());
        Ok(conn)
    }

    /// One request/response RPC: open a bi-stream, send `[kind][lp body]`, read the `lp` response.
    /// A single re-dial is attempted if the cached connection had gone away.
    async fn rpc(&self, peer: NodeId, kind: u8, body: &[u8]) -> Result<Vec<u8>, MeshError> {
        match self.rpc_once(peer, kind, body).await {
            Ok(resp) => Ok(resp),
            Err(MeshError::Stream(_)) | Err(MeshError::Quic(_)) => {
                // The cached connection is likely stale — drop it and try once more fresh.
                self.conns.lock().await.remove(&peer);
                self.rpc_once(peer, kind, body).await
            }
            Err(e) => Err(e),
        }
    }

    async fn rpc_once(&self, peer: NodeId, kind: u8, body: &[u8]) -> Result<Vec<u8>, MeshError> {
        let conn = self.conn(peer).await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| MeshError::Stream(e.to_string()))?;
        send.write_all(&[kind])
            .await
            .map_err(|e| MeshError::Stream(e.to_string()))?;
        write_lp(&mut send, body).await?;
        send.finish()
            .map_err(|e| MeshError::Stream(e.to_string()))?;
        read_lp(&mut recv, MAX_MESH_FRAME).await
    }
}

/// A [`RaftNetworkFactory`] over the overlay mesh.
#[derive(Clone)]
pub struct OverlayNetworkFactory {
    mesh: Arc<OverlayMesh>,
}

impl OverlayNetworkFactory {
    pub fn new(mesh: Arc<OverlayMesh>) -> Self {
        Self { mesh }
    }
}

impl RaftNetworkFactory<TypeConfig> for OverlayNetworkFactory {
    type Network = OverlayNetwork;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        OverlayNetwork {
            mesh: self.mesh.clone(),
            target,
        }
    }
}

/// A network client to one peer over the overlay mesh.
pub struct OverlayNetwork {
    mesh: Arc<OverlayMesh>,
    target: NodeId,
}

impl OverlayNetwork {
    /// Send `body` to the target's `kind` RPC and decode `Result<Resp, RaftError<..E>>`, mapping a
    /// transport failure to a network error and the peer's Raft error to a remote error (mirrors
    /// [`crate::http::HttpNetwork`]).
    async fn rpc<Req, Resp, E>(
        &self,
        kind: u8,
        body: &Req,
    ) -> Result<Resp, RPCError<NodeId, BasicNode, RaftError<NodeId, E>>>
    where
        Req: serde::Serialize,
        Resp: serde::de::DeserializeOwned,
        E: std::error::Error + serde::de::DeserializeOwned,
    {
        let json =
            serde_json::to_vec(body).map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let resp = self
            .mesh
            .rpc(self.target, kind, &json)
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let result: Result<Resp, RaftError<NodeId, E>> =
            serde_json::from_slice(&resp).map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        result.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}

impl RaftNetwork<TypeConfig> for OverlayNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.rpc(K_APPEND, &rpc).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.rpc(K_VOTE, &rpc).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, openraft::error::InstallSnapshotError>>,
    > {
        self.rpc(K_SNAPSHOT, &rpc).await
    }
}

/// A [`Forwarder`] over the overlay mesh: commits a client write on the leader. Tries this node's
/// local Raft first; if it is a follower, openraft returns the leader hint and the write is sent to
/// that peer's client-write RPC. Leadership churn is handled by re-resolving and retrying for a
/// bounded number of rounds (mirrors [`crate::http::HttpForwarder`]).
#[derive(Clone)]
pub struct OverlayForwarder {
    raft: openraft::Raft<TypeConfig>,
    mesh: Arc<OverlayMesh>,
    peers: Peers,
    capability: Option<String>,
}

impl OverlayForwarder {
    pub fn new(raft: openraft::Raft<TypeConfig>, mesh: Arc<OverlayMesh>, peers: Peers) -> Self {
        Self {
            raft,
            mesh,
            peers,
            capability: None,
        }
    }

    /// Attach a cluster-write capability to forwarded writes so the leader's [`ClientWriteAuthz`]
    /// admits them.
    pub fn with_capability(mut self, capability: Option<String>) -> Self {
        self.capability = capability;
        self
    }
}

#[async_trait::async_trait]
impl Forwarder for OverlayForwarder {
    async fn commit(&self, op: WriteOp) -> Result<WriteResponse, ForwardError> {
        for _ in 0..10 {
            let leader = match self.raft.client_write(op.clone()).await {
                Ok(resp) => return Ok(resp.data),
                Err(err) => match err.forward_to_leader().and_then(|f| f.leader_id) {
                    Some(id) => id,
                    None => {
                        tokio::time::sleep(FORWARD_BACKOFF).await;
                        continue;
                    }
                },
            };
            if self.peers.get(leader).is_none() {
                return Err(ForwardError::LeaderNotInDirectory(leader));
            }
            let req = MeshClientWrite {
                op: op.clone(),
                capability: self.capability.clone(),
            };
            let body = match serde_json::to_vec(&req) {
                Ok(b) => b,
                Err(_) => {
                    tokio::time::sleep(FORWARD_BACKOFF).await;
                    continue;
                }
            };
            match self.mesh.rpc(leader, K_CLIENT_WRITE, &body).await {
                // The leader committed it.
                Ok(resp) => match serde_json::from_slice::<
                    Result<WriteResponse, ClientWriteRaftError>,
                >(&resp)
                {
                    Ok(Ok(r)) => return Ok(r),
                    // The peer was no longer leader (or election in flux) — retry.
                    Ok(Err(_)) => tokio::time::sleep(FORWARD_BACKOFF).await,
                    Err(_) => tokio::time::sleep(FORWARD_BACKOFF).await,
                },
                // Transport failure (incl. an authz-refused stream reset) — retry; the leader may
                // have moved.
                Err(_) => tokio::time::sleep(FORWARD_BACKOFF).await,
            }
        }
        Err(ForwardError::NoLeader)
    }
}

/// The [`StreamBus`] over the overlay mesh: delivers a published SSE event to this node's local
/// hubs and relays it to every peer over the mesh (fire-and-forget — at-most-once tolerates a
/// dropped inter-node hop), each over that peer's key-pinned QUIC connection.
#[derive(Clone)]
pub struct OverlayStreamBus {
    self_id: NodeId,
    local: Arc<StreamHubs>,
    peers: Peers,
    mesh: Arc<OverlayMesh>,
}

impl OverlayStreamBus {
    pub fn new(
        self_id: NodeId,
        hubs: Arc<StreamHubs>,
        peers: Peers,
        mesh: Arc<OverlayMesh>,
    ) -> Self {
        Self {
            self_id,
            local: hubs,
            peers,
            mesh,
        }
    }
}

impl StreamBus for OverlayStreamBus {
    fn broadcast(&self, topic: &str, id: &str, payload: &[u8]) {
        // Deliver to this node's own subscribers immediately.
        self.local.broadcast(topic, id, payload);
        // Relay to peers, fire-and-forget. Snapshot the live directory.
        for (peer, _url) in self.peers.snapshot() {
            if peer == self.self_id {
                continue;
            }
            let mesh = self.mesh.clone();
            let body = StreamBroadcast {
                topic: topic.to_string(),
                id: id.to_string(),
                payload: payload.to_vec(),
            };
            tokio::spawn(async move {
                if let Ok(json) = serde_json::to_vec(&body) {
                    let _ = mesh.rpc(peer, K_STREAM, &json).await;
                }
            });
        }
    }
}

/// The node-side mesh server context (the Raft handle + stream hubs + the optional client-write
/// authorizer the dispatch gates `client-write` against).
#[derive(Clone)]
struct MeshServer {
    raft: openraft::Raft<TypeConfig>,
    hubs: Arc<StreamHubs>,
    authz: WriteAuthz,
}

/// Serve the overlay mesh on `endpoint`: accept mutual-RPK-authenticated peer connections and
/// dispatch each framed RPC to `raft` / `hubs`. The overlay equivalent of mounting `raft_router` +
/// `stream_router` on an axum mTLS listener. Spawns a background accept loop and returns at once.
pub fn serve_mesh(
    endpoint: Endpoint,
    raft: openraft::Raft<TypeConfig>,
    hubs: Arc<StreamHubs>,
    authz: WriteAuthz,
) {
    let ctx = MeshServer { raft, hubs, authz };
    tokio::spawn(async move {
        while let Ok(Some(conn)) = overlay::accept(&endpoint).await {
            let ctx = ctx.clone();
            tokio::spawn(serve_conn(conn, ctx));
        }
    });
}

/// Dispatch every bi-stream on one accepted peer connection until the peer closes it.
async fn serve_conn(conn: Connection, ctx: MeshServer) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(_) => return, // connection closed / faulted
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = dispatch(send, recv, ctx).await;
        });
    }
}

/// Read one framed RPC off `recv`, run it against the Raft handle / hubs, and write the framed
/// response on `send`.
async fn dispatch(
    mut send: SendStream,
    mut recv: RecvStream,
    ctx: MeshServer,
) -> Result<(), MeshError> {
    let mut kind = [0u8; 1];
    recv.read_exact(&mut kind)
        .await
        .map_err(|e| MeshError::Stream(e.to_string()))?;
    let body = read_lp(&mut recv, MAX_MESH_FRAME).await?;
    match kind[0] {
        K_APPEND => {
            let req: AppendEntriesRequest<TypeConfig> = serde_json::from_slice(&body)?;
            let resp = ctx.raft.append_entries(req).await;
            write_lp(&mut send, &serde_json::to_vec(&resp)?).await?;
        }
        K_VOTE => {
            let req: VoteRequest<NodeId> = serde_json::from_slice(&body)?;
            let resp = ctx.raft.vote(req).await;
            write_lp(&mut send, &serde_json::to_vec(&resp)?).await?;
        }
        K_SNAPSHOT => {
            let req: InstallSnapshotRequest<TypeConfig> = serde_json::from_slice(&body)?;
            let resp = ctx.raft.install_snapshot(req).await;
            write_lp(&mut send, &serde_json::to_vec(&resp)?).await?;
        }
        K_CLIENT_WRITE => {
            let req: MeshClientWrite = serde_json::from_slice(&body)?;
            if !write_capability_ok(ctx.authz.as_deref(), req.capability.as_deref()) {
                // Refuse: reset the response stream so the forwarder sees a transport failure
                // (mirrors the HTTP `403` → error_for_status path) and retries/degrades — it never
                // observes a committed write from an unauthorized forward.
                let _ = send.reset(VarInt::from_u32(UNAUTHORIZED_RESET));
                return Ok(());
            }
            let result: Result<WriteResponse, ClientWriteRaftError> =
                ctx.raft.client_write(req.op).await.map(|r| r.data);
            write_lp(&mut send, &serde_json::to_vec(&result)?).await?;
        }
        K_STREAM => {
            let ev: StreamBroadcast = serde_json::from_slice(&body)?;
            ctx.hubs.broadcast(&ev.topic, &ev.id, &ev.payload);
            write_lp(&mut send, &serde_json::to_vec(&())?).await?;
        }
        other => return Err(MeshError::Stream(format!("unknown mesh rpc kind {other}"))),
    }
    let _ = send.finish();
    Ok(())
}

/// Whether a client-write is authorized (shared policy with the HTTP path): with no authorizer,
/// mesh trust alone suffices; otherwise the presented capability must satisfy it.
fn write_capability_ok(authz: Option<&dyn ClientWriteAuthz>, capability: Option<&str>) -> bool {
    match authz {
        None => true,
        Some(a) => a.authorize(capability),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    use openraft::{BasicNode, Config, Raft};

    use crate::mesh::{MeshIdentity, MeshTls, TrustSet};
    use crate::persist::{PersistentLogStore, PersistentStateMachine};
    use crate::raft::{LogStore, RaftKv, StateMachineStore};
    use boatramp_core::kv::{KvStore, MemoryKv};

    /// Generate `n` mesh identities that all trust each other; return each node's `MeshTls`, keyed
    /// by id — exactly the shape `boatramp-cluster` holds.
    fn mesh_cluster(n: u64) -> BTreeMap<NodeId, Arc<MeshTls>> {
        let ids: BTreeMap<NodeId, Arc<MeshIdentity>> = (1..=n)
            .map(|i| (i, Arc::new(MeshIdentity::generate().unwrap())))
            .collect();
        let trust = TrustSet::from_map(
            ids.iter()
                .map(|(k, v)| (*k, v.public_key().to_vec()))
                .collect(),
        );
        ids.into_iter()
            .map(|(id, identity)| (id, Arc::new(MeshTls::new(identity, trust.clone()))))
            .collect()
    }

    fn raft_config() -> Arc<Config> {
        Arc::new(
            Config {
                heartbeat_interval: 150,
                election_timeout_min: 300,
                election_timeout_max: 600,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        )
    }

    /// A real 3-node cluster over the **overlay** mesh (each node a QUIC `mesh_endpoint` over
    /// RFC-7250 raw-public-key mutual TLS): form the cluster, elect a leader, and replicate a
    /// write — the consensus mesh genuinely running on the overlay fabric.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn overlay_cluster_elects_and_replicates() {
        let tls = mesh_cluster(3);

        // Build each node's QUIC endpoint first, so we learn its bound UDP port for the directory.
        let mut endpoints = BTreeMap::new();
        let mut peers_map = BTreeMap::new();
        for id in 1..=3u64 {
            let ep = overlay::mesh_endpoint(&tls[&id], "127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = ep.local_addr().unwrap();
            peers_map.insert(id, format!("https://{addr}"));
            endpoints.insert(id, ep);
        }
        let peers = Peers::new(peers_map);
        let config = raft_config();

        let mut rafts = BTreeMap::new();
        let mut sms = BTreeMap::new();
        for id in 1..=3u64 {
            let endpoint = endpoints.remove(&id).unwrap();
            let mesh = Arc::new(OverlayMesh::new(
                endpoint.clone(),
                tls[&id].clone(),
                peers.clone(),
            ));
            let sm = StateMachineStore::default();
            let raft = Raft::new(
                id,
                config.clone(),
                OverlayNetworkFactory::new(mesh),
                LogStore::default(),
                sm.clone(),
            )
            .await
            .unwrap();
            // Serve this node's mesh RPC over its QUIC endpoint (no client-write authorizer).
            serve_mesh(endpoint, raft.clone(), Arc::new(StreamHubs::new()), None);
            rafts.insert(id, raft);
            sms.insert(id, sm);
        }

        let members: BTreeMap<NodeId, BasicNode> =
            (1..=3u64).map(|id| (id, BasicNode::default())).collect();
        rafts[&1].initialize(members).await.unwrap();
        rafts[&1]
            .wait(Some(Duration::from_secs(15)))
            .metrics(
                |m| m.current_leader.is_some(),
                "leader elected over overlay",
            )
            .await
            .unwrap();
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();

        rafts[&leader]
            .client_write(WriteOp::Put {
                key: "current/blog".into(),
                value: b"overlay-deploy".to_vec(),
            })
            .await
            .unwrap();

        for id in 1..=3u64 {
            rafts[&id]
                .wait(Some(Duration::from_secs(15)))
                .applied_index_at_least(Some(2), "write applied over overlay")
                .await
                .unwrap();
            assert_eq!(
                sms[&id].get("current/blog").await.as_deref(),
                Some(b"overlay-deploy".as_slice()),
                "node {id}"
            );
        }

        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }

    /// The real serving path over the overlay: a write submitted to a **follower's** `RaftKv` is
    /// forwarded to the leader over the overlay mesh ([`OverlayForwarder`]), commits, and is
    /// readable from every node's durable applied state.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn overlay_cluster_forwards_client_writes_over_mesh() {
        let tls = mesh_cluster(3);
        let mut endpoints = BTreeMap::new();
        let mut peers_map = BTreeMap::new();
        for id in 1..=3u64 {
            let ep = overlay::mesh_endpoint(&tls[&id], "127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = ep.local_addr().unwrap();
            peers_map.insert(id, format!("https://{addr}"));
            endpoints.insert(id, ep);
        }
        let peers = Peers::new(peers_map);
        let config = raft_config();

        let mut rafts = BTreeMap::new();
        let mut kvs = BTreeMap::new();
        for id in 1..=3u64 {
            let endpoint = endpoints.remove(&id).unwrap();
            let mesh = Arc::new(OverlayMesh::new(
                endpoint.clone(),
                tls[&id].clone(),
                peers.clone(),
            ));
            let store: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
            let log = PersistentLogStore::new(store.clone());
            let sm = PersistentStateMachine::new(store).await.unwrap();
            let raft = Raft::new(
                id,
                config.clone(),
                OverlayNetworkFactory::new(mesh.clone()),
                log,
                sm.clone(),
            )
            .await
            .unwrap();
            serve_mesh(endpoint, raft.clone(), Arc::new(StreamHubs::new()), None);
            let forward = Arc::new(OverlayForwarder::new(raft.clone(), mesh, peers.clone()));
            kvs.insert(id, RaftKv::new(forward, Arc::new(sm)));
            rafts.insert(id, raft);
        }

        let members: BTreeMap<NodeId, BasicNode> =
            (1..=3u64).map(|id| (id, BasicNode::default())).collect();
        rafts[&1].initialize(members).await.unwrap();
        rafts[&1]
            .wait(Some(Duration::from_secs(15)))
            .metrics(
                |m| m.current_leader.is_some(),
                "leader elected over overlay",
            )
            .await
            .unwrap();
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();
        let follower = (1..=3u64).find(|id| *id != leader).unwrap();

        // Write via a FOLLOWER's KvStore — forwarded to the leader over the overlay.
        kvs[&follower]
            .put("current/blog", b"overlay-forwarded".to_vec())
            .await
            .unwrap();

        for id in 1..=3u64 {
            rafts[&id]
                .wait(Some(Duration::from_secs(15)))
                .applied_index_at_least(Some(2), "forwarded write applied")
                .await
                .unwrap();
            assert_eq!(
                kvs[&id].get("current/blog").await.unwrap().as_deref(),
                Some(b"overlay-forwarded".as_slice()),
                "node {id}"
            );
        }

        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }

    /// Mesh acceptance over the overlay: a peer whose key is **not** in a node's trust set is
    /// rejected at the QUIC raw-public-key mutual-TLS handshake — it cannot submit an
    /// unauthenticated mesh RPC.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn untrusted_peer_is_rejected_by_the_overlay_mesh() {
        // Node 1 trusts only itself and serves its mesh over QUIC mTLS.
        let node1 = Arc::new(MeshIdentity::generate().unwrap());
        let trust1 = TrustSet::from_map(BTreeMap::from([(1u64, node1.public_key().to_vec())]));
        let tls1 = Arc::new(MeshTls::new(node1.clone(), trust1));
        let server_ep = overlay::mesh_endpoint(&tls1, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server_ep.local_addr().unwrap();

        // Minimal accept loop: echo nothing — the point is the handshake must fail first.
        tokio::spawn(async move {
            while let Ok(Some(conn)) = overlay::accept(&server_ep).await {
                tokio::spawn(async move {
                    let _ = conn.accept_bi().await;
                });
            }
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A stranger that knows node 1's key (so it can dial) but is NOT in node 1's trust set.
        let stranger = Arc::new(MeshIdentity::generate().unwrap());
        let stranger_trust =
            TrustSet::from_map(BTreeMap::from([(1u64, node1.public_key().to_vec())]));
        let stranger_tls = Arc::new(MeshTls::new(stranger, stranger_trust));
        let stranger_ep =
            overlay::mesh_endpoint(&stranger_tls, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mesh = OverlayMesh::new(
            stranger_ep,
            stranger_tls,
            Peers::new(BTreeMap::from([(1u64, format!("https://{addr}"))])),
        );

        // The stranger's key is not trusted by node 1 → the mutual-auth handshake rejects it → no
        // RPC round-trip completes.
        let outcome =
            tokio::time::timeout(Duration::from_secs(5), mesh.rpc(1, K_VOTE, b"{}")).await;
        assert!(
            !matches!(outcome, Ok(Ok(_))),
            "an untrusted peer must be rejected by the overlay mesh, got {outcome:?}"
        );
    }

    /// The client-write gate is shared with the HTTP path: no authorizer ⇒ mesh trust suffices;
    /// with one, only a request bearing the accepted capability passes.
    #[test]
    fn client_write_gate_is_shared_policy() {
        struct RequireSecret;
        impl ClientWriteAuthz for RequireSecret {
            fn authorize(&self, capability: Option<&str>) -> bool {
                capability == Some("s3cr3t")
            }
        }
        assert!(write_capability_ok(None, None));
        assert!(write_capability_ok(None, Some("whatever")));
        let authz = RequireSecret;
        assert!(write_capability_ok(Some(&authz), Some("s3cr3t")));
        assert!(!write_capability_ok(Some(&authz), Some("nope")));
        assert!(
            !write_capability_ok(Some(&authz), None),
            "a trusted peer without the capability must be refused"
        );
    }
}
