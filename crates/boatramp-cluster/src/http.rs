//! HTTP transport for the Raft peer mesh.
//!
//! Cluster nodes coordinate over their own HTTP mesh — no external transport.
//! Each node mounts [`raft_router`] (three internal `/raft/*` endpoints) and
//! talks to peers through an [`HttpNetworkFactory`], which serializes the
//! openraft RPCs (JSON). Peer addressing is a static `NodeId -> base URL` map
//! (dynamic membership is a follow-up).

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use openraft::error::{ClientWriteError, NetworkError, RPCError, RaftError, RemoteError};
use openraft::network::{RPCOption, RaftNetwork, RaftNetworkFactory};
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::BasicNode;

use boatramp_core::messaging::StreamHubs;

use crate::mesh::MeshClients;
use crate::messaging::StreamBus;
use crate::raft::{ForwardError, Forwarder, NodeId, TypeConfig, WriteOp, WriteResponse};

/// A **live** peer directory: `NodeId -> mesh base URL` (e.g.
/// `https://10.0.0.2:7000`). Mutable at runtime so dynamic-join members are added
/// (and revoked members removed) without a static genesis map — the joiner
/// populates it from the root-signed join response, and `admit` adds the joiner's
/// advertised address so the leader can replicate back to it. Cheap to clone
/// (shared) and read on every RPC dispatch. Addressing is advisory: the mesh TLS
/// re-authenticates every dial by key regardless of the URL used to reach it.
#[derive(Clone, Default)]
pub struct Peers(Arc<std::sync::RwLock<BTreeMap<NodeId, String>>>);

impl Peers {
    /// A directory seeded with `initial` entries (empty for a pure dynamic-join
    /// node that learns every peer at join time).
    pub fn new(initial: BTreeMap<NodeId, String>) -> Self {
        Peers(Arc::new(std::sync::RwLock::new(initial)))
    }

    /// The base URL for `node`, if known.
    pub fn get(&self, node: NodeId) -> Option<String> {
        self.0.read().expect("peers lock").get(&node).cloned()
    }

    /// Add or update `node`'s base URL (idempotent). Returns whether this changed
    /// the directory (a new node or a changed address).
    pub fn insert(&self, node: NodeId, url: String) -> bool {
        let mut guard = self.0.write().expect("peers lock");
        match guard.get(&node) {
            Some(existing) if *existing == url => false,
            _ => {
                guard.insert(node, url);
                true
            }
        }
    }

    /// Remove `node` from the directory (a revoked/removed member).
    pub fn remove(&self, node: NodeId) {
        self.0.write().expect("peers lock").remove(&node);
    }

    /// Whether `node` is known.
    pub fn contains(&self, node: NodeId) -> bool {
        self.0.read().expect("peers lock").contains_key(&node)
    }

    /// A point-in-time copy of the whole directory (for iteration/broadcast).
    pub fn snapshot(&self) -> BTreeMap<NodeId, String> {
        self.0.read().expect("peers lock").clone()
    }
}

/// The peer's `ClientWriteError` (what `/raft/client-write` returns on a
/// non-leader, carrying the leader hint).
type ClientWriteRaftError = RaftError<NodeId, ClientWriteError<NodeId, BasicNode>>;

/// Additional authorization for an application `client-write` submitted over the
/// mesh. The mesh mTLS authenticates the *peer*; this gates who
/// may inject control-plane writes, so being a trusted peer is not, by itself, a
/// write capability. Injected by the serve layer (token-backed, from the
/// control-plane root of trust — separate from the mesh transport key); absent
/// ⇒ mesh trust alone suffices (single-binary / tests).
pub trait ClientWriteAuthz: Send + Sync {
    /// Whether a request bearing `capability` (the `Authorization: Bearer` value,
    /// if present) may submit a client-write.
    fn authorize(&self, capability: Option<&str>) -> bool;
}

/// The optional client-write authorizer, layered as an extension by the serve
/// path. `None` ⇒ no extra gate beyond mesh trust.
pub type WriteAuthz = Option<Arc<dyn ClientWriteAuthz>>;

/// Mount the internal Raft RPC endpoints for a node onto a router. The node's
/// own [`openraft::Raft`] handle is the router state. The three **consensus**
/// RPCs (`append-entries` / `vote` / `install-snapshot`) are peer-to-peer and
/// accepted on mesh trust; the **application** `client-write` (a follower
/// forwarding to the leader — see [`HttpForwarder`]) is additionally gated by a
/// serve-layered [`ClientWriteAuthz`], so the two trust surfaces
/// are separate.
pub fn raft_router(raft: openraft::Raft<TypeConfig>) -> Router {
    Router::new()
        .route("/raft/append-entries", post(append_entries))
        .route("/raft/vote", post(vote))
        .route("/raft/install-snapshot", post(install_snapshot))
        .route("/raft/client-write", post(client_write))
        .with_state(raft)
}

/// Apply a client write on this node. If this node is the leader it commits and
/// returns the applied [`WriteResponse`]; otherwise it returns the
/// `ForwardToLeader` error so the caller can retry against the real leader.
/// Gated by the optional [`ClientWriteAuthz`] extension: a request without a
/// valid write capability is refused (`403`) even from a trusted peer.
async fn client_write(
    State(raft): State<openraft::Raft<TypeConfig>>,
    authz: Option<Extension<WriteAuthz>>,
    headers: HeaderMap,
    Json(op): Json<WriteOp>,
) -> Response {
    let authz = authz.map(|e| e.0).unwrap_or(None);
    if !write_capability_ok(authz.as_deref(), &headers) {
        return (
            StatusCode::FORBIDDEN,
            "mesh client-write requires a cluster-write capability\n",
        )
            .into_response();
    }
    let result: Result<WriteResponse, ClientWriteRaftError> =
        raft.client_write(op).await.map(|r| r.data);
    Json(result).into_response()
}

/// Whether a client-write is authorized: allowed when no authorizer is
/// configured, else the `Authorization: Bearer` capability must satisfy it.
fn write_capability_ok(authz: Option<&dyn ClientWriteAuthz>, headers: &HeaderMap) -> bool {
    let Some(authz) = authz else {
        return true;
    };
    let capability = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    authz.authorize(capability)
}

async fn append_entries(
    State(raft): State<openraft::Raft<TypeConfig>>,
    Json(req): Json<AppendEntriesRequest<TypeConfig>>,
) -> Json<Result<AppendEntriesResponse<NodeId>, RaftError<NodeId>>> {
    Json(raft.append_entries(req).await)
}

async fn vote(
    State(raft): State<openraft::Raft<TypeConfig>>,
    Json(req): Json<VoteRequest<NodeId>>,
) -> Json<Result<VoteResponse<NodeId>, RaftError<NodeId>>> {
    Json(raft.vote(req).await)
}

async fn install_snapshot(
    State(raft): State<openraft::Raft<TypeConfig>>,
    Json(req): Json<InstallSnapshotRequest<TypeConfig>>,
) -> Json<
    Result<
        InstallSnapshotResponse<NodeId>,
        RaftError<NodeId, openraft::error::InstallSnapshotError>,
    >,
> {
    Json(raft.install_snapshot(req).await)
}

/// A [`RaftNetworkFactory`] over the HTTP mesh.
#[derive(Clone)]
pub struct HttpNetworkFactory {
    mesh: Arc<MeshClients>,
    peers: Peers,
}

impl HttpNetworkFactory {
    pub fn new(peers: Peers, mesh: Arc<MeshClients>) -> Self {
        Self { mesh, peers }
    }
}

impl RaftNetworkFactory<TypeConfig> for HttpNetworkFactory {
    type Network = HttpNetwork;

    async fn new_client(&mut self, target: NodeId, _node: &BasicNode) -> Self::Network {
        HttpNetwork {
            mesh: self.mesh.clone(),
            base_url: self.peers.get(target).unwrap_or_default(),
            target,
        }
    }
}

/// A network client to one peer, POSTing JSON-encoded RPCs to its `/raft/*` over
/// the peer's pinned mutual-TLS connection.
pub struct HttpNetwork {
    mesh: Arc<MeshClients>,
    base_url: String,
    target: NodeId,
}

impl HttpNetwork {
    /// POST `body` to `{base}/{path}` and decode the peer's
    /// `Result<Resp, RaftError<..E>>`, mapping transport failures to a network
    /// error and the peer's Raft error to a remote error.
    async fn rpc<Req, Resp, E>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp, RPCError<NodeId, BasicNode, RaftError<NodeId, E>>>
    where
        Req: serde::Serialize,
        Resp: serde::de::DeserializeOwned,
        E: std::error::Error + serde::de::DeserializeOwned,
    {
        let url = format!("{}{path}", self.base_url);
        // A client pinned to this peer's trusted key (cached); an untrusted /
        // unknown peer yields a network error, never an unauthenticated call.
        let client = self
            .mesh
            .client(self.target)
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let resp = client
            .post(url)
            .json(body)
            .send()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?
            .error_for_status()
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        let result: Result<Resp, RaftError<NodeId, E>> = resp
            .json()
            .await
            .map_err(|e| RPCError::Network(NetworkError::new(&e)))?;
        result.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}

impl RaftNetwork<TypeConfig> for HttpNetwork {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.rpc("/raft/append-entries", &rpc).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        _option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.rpc("/raft/vote", &rpc).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        _option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, openraft::error::InstallSnapshotError>>,
    > {
        self.rpc("/raft/install-snapshot", &rpc).await
    }
}

/// A [`Forwarder`] for **real multi-host clusters**: commits a client write on
/// the leader over the HTTP mesh. It tries this node's local Raft first; if this
/// node is a follower, openraft returns the leader hint and the write is POSTed
/// to that peer's `/raft/client-write`. Leadership churn (a stale hint, an
/// in-flight election) is handled by re-resolving and retrying for a bounded
/// number of rounds.
#[derive(Clone)]
pub struct HttpForwarder {
    raft: openraft::Raft<TypeConfig>,
    peers: Peers,
    mesh: Arc<MeshClients>,
    /// The cluster-write capability attached to a forwarded write so the leader's
    /// [`ClientWriteAuthz`] admits it. `None` ⇒ none attached.
    capability: Option<String>,
}

impl HttpForwarder {
    pub fn new(raft: openraft::Raft<TypeConfig>, peers: Peers, mesh: Arc<MeshClients>) -> Self {
        Self {
            raft,
            peers,
            mesh,
            capability: None,
        }
    }

    /// Attach a cluster-write capability to forwarded writes. A follower
    /// presents it on `/raft/client-write` so the leader admits the forward.
    pub fn with_capability(mut self, capability: Option<String>) -> Self {
        self.capability = capability;
        self
    }

    /// POST `op` to the leader's `/raft/client-write` over `client` (pinned to the
    /// leader's trusted key), returning the peer's decoded result (the applied
    /// response, or its own forward-to-leader error).
    async fn post(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        op: &WriteOp,
    ) -> Result<Result<WriteResponse, ClientWriteRaftError>, reqwest::Error> {
        let mut req = client
            .post(format!("{base_url}/raft/client-write"))
            .json(op);
        if let Some(cap) = &self.capability {
            req = req.header(AUTHORIZATION, format!("Bearer {cap}"));
        }
        let resp = req.send().await?.error_for_status()?;
        resp.json().await
    }
}

/// A live stream event relayed between nodes over the mesh.
#[derive(serde::Serialize, serde::Deserialize)]
struct StreamBroadcast {
    topic: String,
    id: String,
    payload: Vec<u8>,
}

/// Mount the cross-node stream fan-out receive endpoint (`/stream/broadcast`),
/// delivering relayed events into this node's local [`StreamHubs`] (the
/// `subscribe` source). Merge it with [`raft_router`] on the node's listener.
pub fn stream_router(hubs: Arc<StreamHubs>) -> Router {
    Router::new()
        .route("/stream/broadcast", post(stream_broadcast))
        .with_state(hubs)
}

async fn stream_broadcast(
    State(hubs): State<Arc<StreamHubs>>,
    Json(ev): Json<StreamBroadcast>,
) -> Json<()> {
    hubs.broadcast(&ev.topic, &ev.id, &ev.payload);
    Json(())
}

/// The [`StreamBus`] for **real multi-host clusters**: delivers a published SSE
/// event to this node's local hubs and relays it to every peer's
/// `/stream/broadcast` over the mesh (fire-and-forget — at-most-once tolerates a
/// dropped inter-node hop).
#[derive(Clone)]
pub struct HttpStreamBus {
    self_id: NodeId,
    local: Arc<StreamHubs>,
    peers: Peers,
    mesh: Arc<MeshClients>,
}

impl HttpStreamBus {
    /// Build a bus for node `self_id` over its local `hubs` and the peer mesh.
    pub fn new(
        self_id: NodeId,
        hubs: Arc<StreamHubs>,
        peers: Peers,
        mesh: Arc<MeshClients>,
    ) -> Self {
        Self {
            self_id,
            local: hubs,
            peers,
            mesh,
        }
    }
}

impl StreamBus for HttpStreamBus {
    fn broadcast(&self, topic: &str, id: &str, payload: &[u8]) {
        // Deliver to this node's own subscribers immediately.
        self.local.broadcast(topic, id, payload);
        // Relay to peers, fire-and-forget (a dropped hop is tolerated), each over
        // that peer's pinned mutual-TLS connection. Snapshot the live directory.
        for (peer, url) in self.peers.snapshot() {
            if peer == self.self_id {
                continue;
            }
            // Skip an untrusted/unknown peer rather than dial it unauthenticated.
            let Ok(client) = self.mesh.client(peer) else {
                continue;
            };
            let url = format!("{url}/stream/broadcast");
            let body = StreamBroadcast {
                topic: topic.to_string(),
                id: id.to_string(),
                payload: payload.to_vec(),
            };
            tokio::spawn(async move {
                let _ = client.post(url).json(&body).send().await;
            });
        }
    }
}

#[async_trait::async_trait]
impl Forwarder for HttpForwarder {
    async fn commit(&self, op: WriteOp) -> Result<WriteResponse, ForwardError> {
        // Resolve the leader from the local Raft, then either commit locally
        // (we are the leader) or POST to the leader's endpoint.
        for _ in 0..10 {
            let leader = match self.raft.client_write(op.clone()).await {
                Ok(resp) => return Ok(resp.data),
                Err(err) => match err.forward_to_leader().and_then(|f| f.leader_id) {
                    Some(leader_id) => leader_id,
                    // No known leader yet — wait for an election and retry.
                    None => {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        continue;
                    }
                },
            };
            let Some(url) = self.peers.get(leader) else {
                return Err(ForwardError::LeaderNotInDirectory(leader));
            };
            // A client pinned to the leader's trusted key; if the leader isn't
            // trusted (shouldn't happen), treat as a transport failure and retry.
            let client = match self.mesh.client(leader) {
                Ok(client) => client,
                Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            };
            match self.post(&client, &url, &op).await {
                // The leader committed it.
                Ok(Ok(resp)) => return Ok(resp),
                // The peer was no longer leader (or election in flux) — retry.
                Ok(Err(_)) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
                // Transport failure — retry (the leader may have moved).
                Err(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
            }
        }
        Err(ForwardError::NoLeader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use openraft::{Config, Raft};

    /// Client-write gate: with no authorizer any request passes (mesh trust);
    /// with one, only a request bearing an accepted capability passes — so a
    /// trusted peer without the cluster-write capability is refused.
    #[test]
    fn client_write_gate_requires_the_capability_when_configured() {
        struct RequireSecret;
        impl ClientWriteAuthz for RequireSecret {
            fn authorize(&self, capability: Option<&str>) -> bool {
                capability == Some("s3cr3t")
            }
        }

        let mut with_cap = HeaderMap::new();
        with_cap.insert(AUTHORIZATION, "Bearer s3cr3t".parse().unwrap());
        let mut wrong_cap = HeaderMap::new();
        wrong_cap.insert(AUTHORIZATION, "Bearer nope".parse().unwrap());
        let none = HeaderMap::new();

        // No authorizer ⇒ mesh trust suffices, every request passes.
        assert!(write_capability_ok(None, &none));
        assert!(write_capability_ok(None, &wrong_cap));

        // With an authorizer, only the accepted capability passes.
        let authz = RequireSecret;
        assert!(write_capability_ok(Some(&authz), &with_cap));
        assert!(!write_capability_ok(Some(&authz), &wrong_cap));
        assert!(
            !write_capability_ok(Some(&authz), &none),
            "a trusted peer without the capability must be refused"
        );
    }

    /// The live peer directory adds, updates, removes, and snapshots members —
    /// the dynamic-join replacement for the static genesis map.
    #[test]
    fn dynamic_peers_add_update_remove_and_snapshot() {
        let peers = Peers::new(BTreeMap::from([(1u64, "https://a:7000".to_string())]));
        assert_eq!(peers.get(1).as_deref(), Some("https://a:7000"));
        assert!(peers.contains(1));
        assert!(peers.get(2).is_none());

        // A new node is a change; a redundant re-insert is not; a changed URL is.
        assert!(peers.insert(2, "https://b:7000".into()));
        assert!(!peers.insert(2, "https://b:7000".into()));
        assert!(peers.insert(2, "https://b2:7000".into()));
        assert_eq!(peers.get(2).as_deref(), Some("https://b2:7000"));

        // Snapshot is a point-in-time copy; remove drops the entry.
        assert_eq!(peers.snapshot().len(), 2);
        peers.remove(1);
        assert!(!peers.contains(1));
        assert_eq!(peers.snapshot().len(), 1);
    }

    use crate::mesh::{MeshClients, MeshIdentity, MeshTls, TrustSet};
    use crate::persist::{PersistentLogStore, PersistentStateMachine};
    use crate::raft::{LogStore, RaftKv, StateMachineStore, WriteOp};
    use boatramp_core::kv::{KvStore, MemoryKv};

    /// Generate `n` mesh identities that all trust each other; return each node's
    /// listener TLS context (`MeshTls`) and its dialer (`MeshClients`), keyed by id.
    fn mesh_cluster(
        n: u64,
    ) -> (
        BTreeMap<NodeId, Arc<MeshTls>>,
        BTreeMap<NodeId, Arc<MeshClients>>,
    ) {
        let ids: BTreeMap<NodeId, Arc<MeshIdentity>> = (1..=n)
            .map(|i| (i, Arc::new(MeshIdentity::generate().unwrap())))
            .collect();
        let trust = TrustSet::from_map(
            ids.iter()
                .map(|(k, v)| (*k, v.public_key().to_vec()))
                .collect(),
        );
        let mut tls = BTreeMap::new();
        let mut clients = BTreeMap::new();
        for (id, identity) in ids {
            let mt = Arc::new(MeshTls::new(identity, trust.clone()));
            clients.insert(id, Arc::new(MeshClients::new(mt.clone())));
            tls.insert(id, mt);
        }
        (tls, clients)
    }

    /// Bind an ephemeral localhost listener; return it + its `https://` peer URL.
    fn mesh_listener() -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        (listener, url)
    }

    /// Serve `router` on a pre-bound listener over the node's mutual-TLS config.
    fn serve_over_tls(listener: std::net::TcpListener, router: Router, mesh: &Arc<MeshTls>) {
        let config =
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(mesh.server().unwrap()));
        tokio::spawn(async move {
            let server = axum_server::from_tcp_rustls(listener, config).expect("mesh listener");
            let _ = server.serve(router.into_make_service()).await;
        });
    }

    /// A real **mutual-TLS** 3-node cluster (each node a localhost axum-server over
    /// RFC 7250 raw-public-key mTLS): form the cluster over the authenticated mesh,
    /// elect a leader, and replicate a write — the transport the cluster actually
    /// deploys with.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn http_cluster_elects_and_replicates() {
        // Three mutually-trusting mesh identities; three ephemeral TLS listeners.
        let (tls, clients) = mesh_cluster(3);
        let mut listeners = Vec::new();
        let mut peers = BTreeMap::new();
        for id in 1..=3u64 {
            let (listener, url) = mesh_listener();
            peers.insert(id, url);
            listeners.push((id, listener));
        }
        let peers: Peers = Peers::new(peers);

        let config = Arc::new(
            Config {
                heartbeat_interval: 150,
                election_timeout_min: 300,
                election_timeout_max: 600,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        );

        // Build a Raft per node and serve its /raft/* over mutual TLS.
        let mut rafts = BTreeMap::new();
        let mut sms = BTreeMap::new();
        for (id, listener) in listeners {
            let sm = StateMachineStore::default();
            let raft = Raft::new(
                id,
                config.clone(),
                HttpNetworkFactory::new(peers.clone(), clients[&id].clone()),
                LogStore::default(),
                sm.clone(),
            )
            .await
            .unwrap();
            serve_over_tls(listener, raft_router(raft.clone()), &tls[&id]);
            rafts.insert(id, raft);
            sms.insert(id, sm);
        }

        let members: BTreeMap<NodeId, BasicNode> =
            (1..=3u64).map(|id| (id, BasicNode::default())).collect();
        rafts[&1].initialize(members).await.unwrap();
        rafts[&1]
            .wait(Some(Duration::from_secs(15)))
            .metrics(|m| m.current_leader.is_some(), "leader elected over HTTP")
            .await
            .unwrap();
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();

        rafts[&leader]
            .client_write(WriteOp::Put {
                key: "current/blog".into(),
                value: b"http-deploy".to_vec(),
            })
            .await
            .unwrap();

        for id in 1..=3u64 {
            rafts[&id]
                .wait(Some(Duration::from_secs(15)))
                .applied_index_at_least(Some(2), "write applied over HTTP")
                .await
                .unwrap();
            assert_eq!(
                sms[&id].get("current/blog").await.as_deref(),
                Some(b"http-deploy".as_slice()),
                "node {id}"
            );
        }

        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }

    /// The real multi-host serving path: a control-plane write submitted to a
    /// **follower's** `RaftKv` is **forwarded to the leader over the HTTP mesh**
    /// (via [`HttpForwarder`] → `/raft/client-write`), commits, and is then
    /// readable from every node's locally-applied state — over **durable**
    /// (persistent) stores. This is what `boatramp serve --mode cluster` runs.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn http_cluster_forwards_client_writes_over_mesh() {
        let (tls, clients) = mesh_cluster(3);
        let mut listeners = Vec::new();
        let mut peers = BTreeMap::new();
        for id in 1..=3u64 {
            let (listener, url) = mesh_listener();
            peers.insert(id, url);
            listeners.push((id, listener));
        }
        let peers: Peers = Peers::new(peers);
        let config = Arc::new(
            Config {
                heartbeat_interval: 150,
                election_timeout_min: 300,
                election_timeout_max: 600,
                ..Default::default()
            }
            .validate()
            .unwrap(),
        );

        // Each node: durable (persistent) log + state machine over its own
        // KvStore, Raft over the HTTP mesh, serving /raft/*.
        let mut rafts = BTreeMap::new();
        let mut kvs = BTreeMap::new();
        for (id, listener) in listeners {
            let store: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
            let log = PersistentLogStore::new(store.clone());
            let sm = PersistentStateMachine::new(store).await.unwrap();
            let raft = Raft::new(
                id,
                config.clone(),
                HttpNetworkFactory::new(peers.clone(), clients[&id].clone()),
                log,
                sm.clone(),
            )
            .await
            .unwrap();
            serve_over_tls(listener, raft_router(raft.clone()), &tls[&id]);
            // The serving-path KvStore facade: writes forward to the leader over
            // the mesh, reads come from this node's durable applied state.
            let forward = Arc::new(HttpForwarder::new(
                raft.clone(),
                peers.clone(),
                clients[&id].clone(),
            ));
            kvs.insert(id, RaftKv::new(forward, Arc::new(sm)));
            rafts.insert(id, raft);
        }

        let members: BTreeMap<NodeId, BasicNode> =
            (1..=3u64).map(|id| (id, BasicNode::default())).collect();
        rafts[&1].initialize(members).await.unwrap();
        rafts[&1]
            .wait(Some(Duration::from_secs(15)))
            .metrics(|m| m.current_leader.is_some(), "leader elected over HTTP")
            .await
            .unwrap();
        let leader = rafts[&1].metrics().borrow().current_leader.unwrap();
        let follower = (1..=3u64).find(|id| *id != leader).unwrap();

        // Write via a FOLLOWER's KvStore — forwarded to the leader over HTTP.
        kvs[&follower]
            .put("current/blog", b"http-forwarded".to_vec())
            .await
            .unwrap();

        // Every node converges; reads come from each node's durable applied state.
        for id in 1..=3u64 {
            rafts[&id]
                .wait(Some(Duration::from_secs(15)))
                .applied_index_at_least(Some(2), "forwarded write applied")
                .await
                .unwrap();
            assert_eq!(
                kvs[&id].get("current/blog").await.unwrap().as_deref(),
                Some(b"http-forwarded".as_slice()),
                "node {id}"
            );
        }

        for raft in rafts.into_values() {
            raft.shutdown().await.unwrap();
        }
    }

    /// Mesh acceptance: a peer whose key is **not** in a node's trust set is
    /// rejected at the mesh's mutual-TLS layer — it can't submit an unauthenticated
    /// `/raft/*` request (regression-tests this rejection).
    #[tokio::test]
    async fn untrusted_peer_is_rejected_by_the_mesh() {
        // Node 1 trusts only itself and serves its mesh endpoints over mTLS.
        let node1 = Arc::new(MeshIdentity::generate().unwrap());
        let trust1 = TrustSet::from_map(BTreeMap::from([(1, node1.public_key().to_vec())]));
        let mesh1 = Arc::new(MeshTls::new(node1.clone(), trust1));
        let (listener, url) = mesh_listener();
        let router = Router::new().route("/raft/vote", post(|| async { "ok" }));
        serve_over_tls(listener, router, &mesh1);
        tokio::time::sleep(Duration::from_millis(50)).await;

        // A stranger that knows node 1's key (so it can dial) but is itself NOT in
        // node 1's trust set. Its client presents the stranger's key → node 1's
        // client-cert verifier rejects it → the request fails at the TLS layer.
        let stranger = Arc::new(MeshIdentity::generate().unwrap());
        let stranger_trust = TrustSet::from_map(BTreeMap::from([(1, node1.public_key().to_vec())]));
        let clients = MeshClients::new(Arc::new(MeshTls::new(stranger, stranger_trust)));
        let client = clients.client(1).unwrap();

        let result = client.post(format!("{url}/raft/vote")).send().await;
        assert!(
            result.is_err(),
            "an untrusted peer must be rejected by the mesh, got {result:?}"
        );
    }
}
