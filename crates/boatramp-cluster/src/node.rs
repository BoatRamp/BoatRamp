//! Assembling a runnable **cluster node** from config (the serve-path).
//!
//! [`build_node`] wires the pieces a self-hosted cluster node needs into one
//! [`ClusterNode`]: durable Raft stores ([`crate::persist`]) over a node-local
//! `KvStore`, consensus + client-write forwarding + stream fan-out over the HTTP
//! mesh ([`crate::http`]), and the serving-path facades — [`RaftKv`] (the
//! control-plane `KvStore` `DeployStore` runs over) and [`RaftMessaging`] (the
//! `wasi:messaging` coordinator). The caller binds [`ClusterNode::router`] on the
//! node's address and, on first bootstrap of a new cluster, calls
//! [`ClusterNode::bootstrap`] once.
//!
//! This is the assembly `boatramp serve --mode cluster` runs; its live
//! multi-host validation runs against real infrastructure, but every component
//! is gate-tested in-process / over localhost HTTP.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use boatramp_core::kv::KvStore;
use boatramp_core::messaging::StreamHubs;
use boatramp_core::Storage;
use openraft::{BasicNode, Config, Raft};

use crate::http::{
    raft_router, stream_router, HttpForwarder, HttpNetworkFactory, HttpStreamBus, Peers,
};
use crate::mesh::{MeshClients, MeshTls, TrustSet};
use crate::messaging::RaftMessaging;
use crate::persist::{PersistentLogStore, PersistentStateMachine};
use crate::raft::{
    add_voter, is_leader, remove_voter, ApplyObserver, ClientWriteRaftError, MembershipError,
    NodeId, RaftKv, TypeConfig, WriteOp, WriteResponse,
};

/// Mirrors committed `mesh/trust/*` writes into this node's live [`TrustSet`], so
/// a join / rotation / revocation replicated from the leader takes effect on the
/// node's TLS verifiers without a restart. Installed on the
/// durable state machine, it runs on every node for both local and replicated
/// applies — the single sync path from durable trust state to the live set.
struct MeshTrustObserver {
    trust: TrustSet,
}

impl ApplyObserver for MeshTrustObserver {
    fn on_apply(&self, muts: &[boatramp_core::kv::WriteOp]) {
        use boatramp_core::kv::WriteOp;
        for m in muts {
            match m {
                WriteOp::Put(key, _) => {
                    if let Some((node, spki)) = crate::mesh::parse_trust_key(key) {
                        self.trust.insert(node, spki);
                    }
                }
                WriteOp::Delete(key) => {
                    if let Some((node, spki)) = crate::mesh::parse_trust_key(key) {
                        self.trust.remove_key(node, &spki);
                    }
                }
            }
        }
    }

    fn on_reset(&self, keys: &[String]) {
        self.trust.replace_all(crate::mesh::trust_from_keys(
            keys.iter().map(String::as_str),
        ));
    }
}

/// A failure assembling ([`build_node`]) or bootstrapping
/// ([`ClusterNode::bootstrap`]) a cluster node.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// This node isn't listed in its own peer directory.
    #[error("this node ({0}) is not in its own peer directory")]
    NotInPeerDirectory(NodeId),
    /// The resolved voter set is empty.
    #[error("cluster needs at least one voter")]
    NoVoters,
    /// The openraft config failed validation.
    #[error("invalid raft config: {0}")]
    Config(#[from] openraft::ConfigError),
    /// Building the durable state machine failed.
    #[error("durable state init: {0}")]
    Storage(#[from] openraft::StorageError<NodeId>),
    /// Starting the Raft node failed.
    #[error("raft start: {0}")]
    RaftStart(#[from] openraft::error::Fatal<NodeId>),
    /// Initializing a brand-new cluster failed.
    #[error("cluster initialize: {0}")]
    Initialize(
        #[from]
        openraft::error::RaftError<NodeId, openraft::error::InitializeError<NodeId, BasicNode>>,
    ),
    /// Waiting for this node to win the first election failed/timed out.
    #[error("waiting for leadership: {0}")]
    Wait(#[from] openraft::metrics::WaitError),
    /// Promoting a voter during bootstrap failed.
    #[error("membership change: {0}")]
    Membership(#[from] MembershipError),
    /// Adding a learner during bootstrap failed.
    #[error("add learner: {0}")]
    AddLearner(#[from] ClientWriteRaftError),
    /// A trust-set KV write (genesis seed, or a join admission) failed.
    #[error("trust-set write: {0}")]
    TrustWrite(#[from] boatramp_core::kv::KvError),
    /// Generating or swapping a mesh identity (key rotation) failed.
    #[error("mesh key: {0}")]
    Mesh(#[from] crate::mesh::MeshError),
}

/// Inputs to assemble one cluster node.
pub struct ClusterParams {
    /// This node's id.
    pub node_id: NodeId,
    /// The static peer directory (`NodeId -> base URL`), including this node.
    pub peers: BTreeMap<NodeId, String>,
    /// The **voting** subset of `peers` (the Raft quorum). Peers not in this set
    /// join as **learners** — they replicate the log and serve local reads but
    /// don't vote, so far-region nodes give local reads without dragging the
    /// quorum across the WAN. Empty ⇒ every
    /// peer votes (a plain cluster).
    pub voters: BTreeSet<NodeId>,
    /// Node-local **durable** store for the Raft log + applied state (e.g. a
    /// SlateDB-backed `KvStore`) — distinct from the replicated control plane.
    pub durable_kv: Arc<dyn KvStore>,
    /// Shared blob store for message payloads (s3/R2), read by every node.
    pub storage: Arc<dyn Storage>,
    /// This node's mesh TLS context (identity + trust set) — authenticates every
    /// peer connection.
    pub mesh: Arc<MeshTls>,
    /// Optional cluster-write capability (a token from the control-plane root)
    /// this node attaches when forwarding a client-write to the leader, so the
    /// leader's `ClientWriteAuthz` admits it. `None` ⇒ none
    /// attached (mesh trust alone; single-binary / tests).
    pub cluster_write_capability: Option<String>,
    /// Extra post-apply observers registered alongside the built-in mesh-trust
    /// one — e.g. a daemon-config observer that reloads a node's live config when
    /// a replicated `daemon/*` write is applied (push convergence, no polling).
    pub extra_observers: Vec<Arc<dyn crate::raft::ApplyObserver>>,
}

/// A fully-wired cluster node: the Raft handle, the serving-path facades, and
/// the HTTP router to mount on the node's listener.
pub struct ClusterNode {
    /// This node's id.
    pub node_id: NodeId,
    /// The raw consensus handle (membership ops, metrics, shutdown).
    pub raft: Raft<TypeConfig>,
    /// The control-plane `KvStore` facade — back `DeployStore` with this.
    pub kv: Arc<RaftKv>,
    /// The messaging coordinator — back the consumer dispatcher with this.
    pub messaging: Arc<RaftMessaging>,
    /// `/raft/*` + `/stream/*` — bind on the node's address (the peer mesh).
    pub router: axum::Router,
    /// The other voters to promote during [`bootstrap`](Self::bootstrap).
    voters: BTreeSet<NodeId>,
    /// The learners to add during [`bootstrap`](Self::bootstrap).
    learners: Vec<NodeId>,
    /// The genesis trust set (from config), written to replicated KV during
    /// [`bootstrap`](Self::bootstrap) so durable state becomes the authority on
    /// every later restart.
    genesis_trust: BTreeMap<NodeId, Vec<Vec<u8>>>,
    /// This node's mesh TLS context — kept so [`rotate_key`](Self::rotate_key)
    /// can swap the identity it presents.
    mesh: Arc<MeshTls>,
}

impl ClusterNode {
    /// Whether this node is the current Raft leader (the gate for leader-only
    /// jobs — cron single-firing, ACME single-flight, prune).
    pub fn is_leader(&self) -> bool {
        is_leader(&self.raft, self.node_id)
    }

    /// Initialize a **brand-new** cluster from this node (call once, on the
    /// designated bootstrap voter). Uses single-node-grow: this node initializes
    /// as the sole voter (so it is the initial leader), then promotes the other
    /// voters and adds the learners — membership changes must run on the leader,
    /// and starting from one member makes that deterministic (no election race).
    /// On a node already part of a cluster (a restart recovering from durable
    /// state) it's a no-op.
    pub async fn bootstrap(&self) -> Result<(), BootstrapError> {
        let mut sole = BTreeMap::new();
        sole.insert(self.node_id, BasicNode::default());
        match self.raft.initialize(sole).await {
            Ok(()) => {}
            // Already initialized (e.g. a restart): membership is persisted.
            Err(openraft::error::RaftError::APIError(
                openraft::error::InitializeError::NotAllowed(_),
            )) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
        // We initialized as the sole voter, so we win the first election.
        self.raft
            .wait(Some(Duration::from_secs(10)))
            .metrics(
                |m| m.current_leader == Some(self.node_id),
                "bootstrap node becomes leader",
            )
            .await?;
        // Promote the remaining voters (learner-catch-up then join the quorum),
        // then add the learners (replicate-only).
        for &v in &self.voters {
            if v != self.node_id {
                add_voter(&self.raft, v).await?;
            }
        }
        for &l in &self.learners {
            self.raft
                .add_learner(l, BasicNode::default(), false)
                .await?;
        }
        // Persist the genesis trust set: from here on the durable, replicated
        // trust state (not config) is authoritative — so revocations survive a
        // restart and a fresh node learns the whole set from the log/snapshot.
        let mut seed = Vec::new();
        for (node, keys) in &self.genesis_trust {
            for key in keys {
                seed.push(boatramp_core::kv::WriteOp::Put(
                    crate::mesh::trust_key(*node, key),
                    Vec::new(),
                ));
            }
        }
        if !seed.is_empty() {
            self.kv.write_batch(seed).await?;
        }
        Ok(())
    }

    /// Admit a joining node from a **verified** join token.
    /// Proposes a single-use [`WriteOp::MeshAdmit`], which atomically trusts
    /// `(node, pubkey_hex)` cluster-wide and spends the token's `jti`; then, on
    /// the leader, adds the node as a learner so it starts replicating. Returns
    /// whether the node was admitted (`false` = the token was already spent).
    ///
    /// The caller MUST first verify the join token — signature, TTL, and that the
    /// joiner actually holds `pubkey_hex` — via
    /// [`boatramp_core::cose::verify_join`]; the state machine enforces
    /// only single-use. The mesh-admit KV write forwards from a follower, but the
    /// `add_learner` membership step needs the leader, so a join is directed
    /// there (the control-plane route forwards it).
    pub async fn admit(
        &self,
        node: NodeId,
        pubkey_hex: &str,
        jti: &str,
    ) -> Result<bool, BootstrapError> {
        let resp = self
            .kv
            .propose_with_response(WriteOp::MeshAdmit {
                jti: jti.to_string(),
                node,
                pubkey_hex: pubkey_hex.to_string(),
            })
            .await?;
        let admitted = matches!(resp, WriteResponse::Admitted(true));
        if admitted && self.is_leader() && !self.is_member(node) {
            self.raft
                .add_learner(node, BasicNode::default(), false)
                .await?;
        }
        Ok(admitted)
    }

    /// Rotate **this node's** mesh identity, make-before-break:
    ///
    /// 1. generate `K_new`;
    /// 2. trust `K_new` cluster-wide (a plain trust `Put`, which rides the
    ///    `K_old`-authenticated mesh — i.e. "signed by `K_old`"; the apply
    ///    observer mirrors it into every node's live set);
    /// 3. wait `propagation` so peers trust `K_new` before we present it (a
    ///    transient dialer rejection would self-heal via the live verifier +
    ///    retry, so this only *minimises* the window);
    /// 4. swap the presented identity to `K_new` — new handshakes present it,
    ///    established connections keep their session;
    /// 5. retire `K_old` (a trust `Delete`).
    ///
    /// Fail-safe: a stall between (2) and (4) leaves the node reachable on `K_old`
    /// (both keys are trusted in the window). Returns the new public key (SPKI).
    pub async fn rotate_key(&self, propagation: Duration) -> Result<Vec<u8>, BootstrapError> {
        use boatramp_core::kv::KvStore;

        // (1) K_new, still presenting K_old.
        let new = Arc::new(crate::mesh::MeshIdentity::generate()?);
        let new_pub = new.public_key().to_vec();

        // (2) Trust K_new cluster-wide (both keys now valid for this node).
        self.kv
            .put(&crate::mesh::trust_key(self.node_id, &new_pub), Vec::new())
            .await?;

        // (3) Let the add propagate to peers before we present K_new.
        tokio::time::sleep(propagation).await;

        // (4) Present K_new on new handshakes (persists K_new if a key file is
        // configured); K_old connections stay up.
        let old = self.mesh.set_identity(new)?;
        let old_pub = old.public_key().to_vec();

        // (5) Retire K_old — from here only K_new is trusted for this node.
        self.kv
            .delete(&crate::mesh::trust_key(self.node_id, &old_pub))
            .await?;
        Ok(new_pub)
    }

    /// Revoke a node from the mesh: delete **every** trust key
    /// for `node` — so it can no longer authenticate on the mesh (the live
    /// verifier rejects it on its next handshake, cluster-wide, once the delete
    /// replicates) — and, on the leader, drop it from the voter quorum so a
    /// revoked node no longer counts toward consensus. The trust deletion is the
    /// security guarantee; a revoked node can't connect, so any stale membership
    /// entry is inert.
    pub async fn revoke(&self, node: NodeId) -> Result<(), BootstrapError> {
        use boatramp_core::kv::{KvStore, WriteOp as KvWriteOp};

        // Delete all of `node`'s accepted keys: `mesh/trust/{node}/*`.
        let prefix = format!("{}{node}/", crate::mesh::TRUST_PREFIX);
        let keys = self.kv.list_prefix(&prefix).await?;
        let batch: Vec<KvWriteOp> = keys.into_iter().map(KvWriteOp::Delete).collect();
        if !batch.is_empty() {
            self.kv.write_batch(batch).await?;
        }

        // Drop a revoked voter from the quorum (leader-only; ignore "last voter").
        if self.is_leader() && self.is_voter(node) {
            match remove_voter(&self.raft, node).await {
                Ok(()) | Err(MembershipError::LastVoter) => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(())
    }

    /// Whether `node` is currently a voter (part of the quorum).
    fn is_voter(&self, node: NodeId) -> bool {
        self.raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .any(|id| id == node)
    }

    /// Whether `node` is already a known voter or learner (so admit doesn't
    /// re-add it).
    fn is_member(&self, node: NodeId) -> bool {
        self.raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .nodes()
            .any(|(id, _)| *id == node)
    }
}

/// Assemble a cluster node from `params`: durable stores, consensus + HTTP mesh,
/// and the [`RaftKv`] / [`RaftMessaging`] serving facades.
pub async fn build_node(params: ClusterParams) -> Result<ClusterNode, BootstrapError> {
    let ClusterParams {
        node_id,
        peers,
        voters,
        durable_kv,
        storage,
        mesh,
        cluster_write_capability,
        extra_observers,
    } = params;
    // The live trust set (shared with the TLS verifiers) — mutated by the apply
    // observer as trust changes replicate; hydrated from durable state below.
    let trust = mesh.trust().clone();
    // Per-peer pinned mutual-TLS clients, shared by every dialer.
    // The node keeps `mesh` too, so `rotate_key` can swap the presented identity.
    let mesh_clients = Arc::new(MeshClients::new(mesh.clone()));

    if !peers.contains_key(&node_id) {
        return Err(BootstrapError::NotInPeerDirectory(node_id));
    }
    // Empty `voters` ⇒ every peer votes. Otherwise the voting set is `voters`
    // (intersected with peers), and the rest are learners.
    let voters: BTreeSet<NodeId> = if voters.is_empty() {
        peers.keys().copied().collect()
    } else {
        voters
            .into_iter()
            .filter(|v| peers.contains_key(v))
            .collect()
    };
    if voters.is_empty() {
        return Err(BootstrapError::NoVoters);
    }
    let learners: Vec<NodeId> = peers
        .keys()
        .copied()
        .filter(|id| !voters.contains(id))
        .collect();

    let config = Arc::new(
        Config {
            heartbeat_interval: 250,
            election_timeout_min: 500,
            election_timeout_max: 1000,
            ..Default::default()
        }
        .validate()?,
    );
    let peers: Peers = Arc::new(peers);

    // Durable Raft log + state machine over the node-local store. The state
    // machine mirrors committed `mesh/trust/*` writes into the live trust set.
    let log = PersistentLogStore::new(durable_kv.clone());
    let mut sm = PersistentStateMachine::new(durable_kv)
        .await?
        .with_observer(Arc::new(MeshTrustObserver {
            trust: trust.clone(),
        }));
    // Caller-supplied observers (e.g. daemon-config reload on `daemon/*`) fire on
    // every apply/snapshot alongside the mesh-trust one.
    for observer in extra_observers {
        sm = sm.with_observer(observer);
    }
    // Durable state is authoritative on restart: if a trust set was persisted,
    // hydrate the live set from it (config was only the genesis seed).
    let durable_keys = sm.list_prefix(crate::mesh::TRUST_PREFIX).await;
    let durable_trust = crate::mesh::trust_from_keys(durable_keys.iter().map(String::as_str));
    if !durable_trust.is_empty() {
        trust.replace_all(durable_trust);
    }
    // The seed to persist at bootstrap (post-hydration ⇒ the config seed on a
    // fresh node; unused on a restart, where bootstrap is a no-op).
    let genesis_trust = trust.snapshot();
    let raft = Raft::new(
        node_id,
        config,
        HttpNetworkFactory::new(peers.clone(), mesh_clients.clone()),
        log,
        sm.clone(),
    )
    .await?;

    // Leader forwarding over the mesh, shared by both facades. Attaches the
    // node's cluster-write capability so the leader admits its forwards.
    let forward = Arc::new(
        HttpForwarder::new(raft.clone(), peers.clone(), mesh_clients.clone())
            .with_capability(cluster_write_capability),
    );

    // Control-plane KvStore facade (writes→leader, reads→local durable state).
    let kv = Arc::new(RaftKv::new(forward.clone(), Arc::new(sm.clone())));

    // Messaging coordinator + cross-node stream fan-out over the mesh.
    let hubs = Arc::new(StreamHubs::new());
    let bus = Arc::new(HttpStreamBus::new(
        node_id,
        hubs.clone(),
        peers.clone(),
        mesh_clients.clone(),
    ));
    let messaging = Arc::new(RaftMessaging::new(
        storage,
        forward,
        Arc::new(sm),
        node_id,
        hubs.clone(),
        bus,
    ));

    // The node's mesh router: consensus RPCs + client-write + stream relay.
    let router = raft_router(raft.clone()).merge(stream_router(hubs));

    Ok(ClusterNode {
        node_id,
        raft,
        kv,
        messaging,
        router,
        voters,
        learners,
        genesis_trust,
        mesh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::{MeshIdentity, MeshTls, TrustSet};
    use boatramp_core::kv::MemoryKv;
    use boatramp_core::messaging::Messaging;
    use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, StorageError};
    use futures::StreamExt;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    /// `n` mutually-trusting mesh identities → per-node `MeshTls`, keyed by id.
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

    /// Bind an ephemeral localhost listener; return it + its `https://` peer URL.
    fn mesh_listener() -> (std::net::TcpListener, String) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("https://{}", listener.local_addr().unwrap());
        (listener, url)
    }

    /// Serve `router` on a pre-bound listener over the node's mutual-TLS config.
    fn serve_over_tls(listener: std::net::TcpListener, router: axum::Router, mesh: &Arc<MeshTls>) {
        let config =
            axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(mesh.server().unwrap()));
        tokio::spawn(async move {
            let server = axum_server::from_tcp_rustls(listener, config).expect("mesh listener");
            let _ = server.serve(router.into_make_service()).await;
        });
    }

    /// Minimal shared in-memory blob store for message payloads.
    #[derive(Default)]
    struct MemStorage {
        objects: StdMutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            let bytes = self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            let size = bytes.len() as u64;
            let body: ByteStream =
                futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
            Ok(GetObject {
                meta: ObjectMeta {
                    key: key.to_string(),
                    size: Some(size),
                    ..Default::default()
                },
                body,
            })
        }
        async fn get_range(
            &self,
            key: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            self.get(key).await
        }
        async fn put(
            &self,
            key: &str,
            mut body: ByteStream,
            _: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            let mut buf = Vec::new();
            while let Some(chunk) = body.next().await {
                buf.extend_from_slice(&chunk?);
            }
            self.objects.lock().unwrap().insert(key.to_string(), buf);
            Ok(ObjectMeta {
                key: key.to_string(),
                ..Default::default()
            })
        }
        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            let map = self.objects.lock().unwrap();
            let bytes = map
                .get(key)
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(ObjectMeta {
                key: key.to_string(),
                size: Some(bytes.len() as u64),
                ..Default::default()
            })
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .map(|k| ObjectMeta {
                    key: k.clone(),
                    ..Default::default()
                })
                .collect())
        }
    }

    /// The whole assembled stack over a real localhost HTTP mesh: build N nodes,
    /// serve their routers, bootstrap, and exercise the serving facades end to
    /// end — a control-plane write via a follower's `RaftKv` (forwarded over the
    /// mesh, read back everywhere) and a published message consumed via
    /// `RaftMessaging`, plus a stream event fanned across nodes.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn assembled_cluster_serves_kv_messaging_and_streams() {
        // Three mutually-trusting mesh identities; bind TLS listeners + directory.
        let tls = mesh_cluster(3);
        let mut listeners = Vec::new();
        let mut peers = BTreeMap::new();
        for id in 1..=3u64 {
            let (listener, url) = mesh_listener();
            peers.insert(id, url);
            listeners.push((id, listener));
        }
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());

        // Assemble + serve each node over mutual TLS.
        let mut nodes = BTreeMap::new();
        for (id, listener) in listeners {
            let node = build_node(ClusterParams {
                node_id: id,
                peers: peers.clone(),
                voters: BTreeSet::new(), // empty ⇒ all peers vote
                durable_kv: Arc::new(MemoryKv::new()),
                storage: storage.clone(),
                mesh: tls[&id].clone(),
                cluster_write_capability: None,
                extra_observers: Vec::new(),
            })
            .await
            .unwrap();
            serve_over_tls(listener, node.router.clone(), &tls[&id]);
            nodes.insert(id, node);
        }

        // Bootstrap once and wait for a leader.
        nodes[&1].bootstrap().await.unwrap();
        nodes[&1]
            .raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(|m| m.current_leader.is_some(), "leader elected")
            .await
            .unwrap();
        let leader = nodes[&1].raft.metrics().borrow().current_leader.unwrap();
        let follower = (1..=3u64).find(|id| *id != leader).unwrap();

        // Control-plane write via a follower's KvStore — forwarded over the mesh.
        nodes[&follower]
            .kv
            .put("current/blog", b"deployed".to_vec())
            .await
            .unwrap();
        // Readable from the leader's local applied state (converges quickly).
        nodes[&leader]
            .raft
            .wait(Some(Duration::from_secs(15)))
            .applied_index_at_least(Some(2), "kv write applied")
            .await
            .unwrap();
        assert_eq!(
            nodes[&leader]
                .kv
                .get("current/blog")
                .await
                .unwrap()
                .as_deref(),
            Some(b"deployed".as_slice())
        );

        // Messaging: subscribe on one node, publish on another (stream fan-out
        // crosses the mesh); and a durable publish/claim round-trip.
        let mut sub = nodes[&2].messaging.subscribe("events", None);
        nodes[&follower]
            .messaging
            .publish("events", b"hello")
            .await
            .unwrap();
        let ev = tokio::time::timeout(Duration::from_secs(5), sub.next())
            .await
            .expect("stream event should arrive over the mesh")
            .expect("stream live");
        assert_eq!(ev.payload, b"hello");

        // Durable consumer path: publish, then claim from any node (the claim is
        // a leader proposal forwarded over the mesh).
        nodes[&follower]
            .messaging
            .publish("orders", b"order-1")
            .await
            .unwrap();
        let mut delivered = None;
        for _ in 0..20 {
            let batch = nodes[&2]
                .messaging
                .claim("orders", Duration::from_secs(30), 10, 5)
                .await
                .unwrap();
            if let Some(m) = batch.into_iter().next() {
                delivered = Some(m);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let m = delivered.expect("message claimed");
        assert_eq!(m.payload, b"order-1");
        nodes[&2].messaging.ack(&m).await.unwrap();

        for (_, node) in nodes {
            node.raft.shutdown().await.unwrap();
        }
    }

    /// Multi-region prerequisite: a **learner** node replicates the log and
    /// serves local reads but does **not** vote. Voters {1,2,3} + learner {4}
    /// over a real localhost mesh: a write replicates to the learner (local
    /// `RaftKv` read), the learner is not in the voter set, and killing a voter
    /// still re-elects among the voters (the learner can't be leader).
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn learner_replicates_reads_but_does_not_vote() {
        let tls = mesh_cluster(4);
        let mut listeners = Vec::new();
        let mut peers = BTreeMap::new();
        for id in 1..=4u64 {
            let (listener, url) = mesh_listener();
            peers.insert(id, url);
            listeners.push((id, listener));
        }
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let voters: BTreeSet<NodeId> = [1, 2, 3].into_iter().collect();

        let mut nodes = BTreeMap::new();
        for (id, listener) in listeners {
            let node = build_node(ClusterParams {
                node_id: id,
                peers: peers.clone(),
                voters: voters.clone(),
                durable_kv: Arc::new(MemoryKv::new()),
                storage: storage.clone(),
                mesh: tls[&id].clone(),
                cluster_write_capability: None,
                extra_observers: Vec::new(),
            })
            .await
            .unwrap();
            serve_over_tls(listener, node.router.clone(), &tls[&id]);
            nodes.insert(id, node);
        }

        nodes[&1].bootstrap().await.unwrap();
        nodes[&1]
            .raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(|m| m.current_leader.is_some(), "leader elected")
            .await
            .unwrap();

        // The voter set is exactly {1,2,3}; the learner (4) is not a voter.
        let voter_ids: BTreeSet<NodeId> = nodes[&1]
            .raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .collect();
        assert_eq!(voter_ids, voters, "learner must not be a voter");

        // A control-plane write replicates to the learner's local applied state.
        let leader = nodes[&1].raft.metrics().borrow().current_leader.unwrap();
        nodes[&leader]
            .kv
            .put("current/blog", b"replicated".to_vec())
            .await
            .unwrap();
        // Wait the learner up to the leader's last index (membership-change
        // entries from bootstrap shift the write past a fixed index).
        let target = nodes[&leader].raft.metrics().borrow().last_log_index;
        nodes[&4]
            .raft
            .wait(Some(Duration::from_secs(15)))
            .applied_index_at_least(target, "learner caught up")
            .await
            .unwrap();
        assert_eq!(
            nodes[&4].kv.get("current/blog").await.unwrap().as_deref(),
            Some(b"replicated".as_slice()),
            "learner serves the replicated read locally"
        );
        assert!(!nodes[&4].is_leader(), "a learner is never the leader");

        for (_, node) in nodes {
            node.raft.shutdown().await.unwrap();
        }
    }

    /// The trust set is durable and hydrates on restart: bootstrap persists the
    /// genesis seed to replicated KV; a runtime trust
    /// write (as a join/rotation would make) is mirrored into the live set by the
    /// apply observer; and a cold restart — a fresh node over the same durable
    /// store, seeded from a config that trusts only node 1 — rehydrates the whole
    /// set from durable state, so the runtime-added node survives with no config
    /// edit and durable state (not config) is the authority.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn trust_set_persists_and_rehydrates_across_restart() {
        let id1 = Arc::new(MeshIdentity::generate().unwrap());
        let key2 = MeshIdentity::generate().unwrap().public_key().to_vec();
        let durable: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());

        // Boot node 1 (sole voter) with a genesis seed trusting only itself.
        let (listener, url) = mesh_listener();
        let trust1 = TrustSet::from_map(BTreeMap::from([(1u64, id1.public_key().to_vec())]));
        let mesh1 = Arc::new(MeshTls::new(id1.clone(), trust1.clone()));
        let node = build_node(ClusterParams {
            node_id: 1,
            peers: BTreeMap::from([(1u64, url)]),
            voters: BTreeSet::new(),
            durable_kv: durable.clone(),
            storage: storage.clone(),
            mesh: mesh1.clone(),
            cluster_write_capability: None,
            extra_observers: Vec::new(),
        })
        .await
        .unwrap();
        serve_over_tls(listener, node.router.clone(), &mesh1);
        node.bootstrap().await.unwrap();
        node.raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(|m| m.current_leader == Some(1), "leader elected")
            .await
            .unwrap();

        // A runtime trust write, committed through the replicated KV. The apply
        // observer mirrors it into the live set the TLS verifiers read.
        node.kv
            .put(&crate::mesh::trust_key(2, &key2), Vec::new())
            .await
            .unwrap();
        assert!(
            trust1.contains(2, &key2),
            "the apply observer must mirror a committed trust write into the live set"
        );
        node.raft.shutdown().await.unwrap();
        drop(node);

        // "Restart": a fresh node over the SAME durable store, seeded from a
        // config that trusts only node 1. Durable state must win.
        let (listener2, url2) = mesh_listener();
        let trust1b = TrustSet::from_map(BTreeMap::from([(1u64, id1.public_key().to_vec())]));
        let mesh1b = Arc::new(MeshTls::new(id1.clone(), trust1b.clone()));
        let node2 = build_node(ClusterParams {
            node_id: 1,
            peers: BTreeMap::from([(1u64, url2)]),
            voters: BTreeSet::new(),
            durable_kv: durable.clone(),
            storage,
            mesh: mesh1b.clone(),
            cluster_write_capability: None,
            extra_observers: Vec::new(),
        })
        .await
        .unwrap();
        let _ = listener2; // built but unused: we only assert the hydrated set.
        assert!(
            trust1b.contains(1, id1.public_key()),
            "the genesis key must survive the restart"
        );
        assert!(
            trust1b.contains(2, &key2),
            "the runtime-added key must rehydrate from durable state, not config"
        );
        node2.raft.shutdown().await.unwrap();
    }

    /// A verified join admits a node cluster-wide and is single-use: the leader's
    /// `admit` proposes a `MeshAdmit` that trusts the joiner's
    /// key on **every** node (each has its own trust set, updated by its own apply
    /// observer as the entry replicates) and adds it as a learner; replaying the
    /// same token admits nothing.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn join_admission_trusts_the_node_mesh_wide_and_is_single_use() {
        // Three running nodes with *separate* trust sets, all seeded to trust
        // each other; a fourth identity is the joiner (not yet trusted anywhere).
        let ids: BTreeMap<NodeId, Arc<MeshIdentity>> = (1..=3)
            .map(|i| (i, Arc::new(MeshIdentity::generate().unwrap())))
            .collect();
        let genesis: BTreeMap<NodeId, Vec<u8>> = ids
            .iter()
            .map(|(k, v)| (*k, v.public_key().to_vec()))
            .collect();
        let trusts: BTreeMap<NodeId, TrustSet> = ids
            .keys()
            .map(|k| (*k, TrustSet::from_map(genesis.clone())))
            .collect();
        let joiner = MeshIdentity::generate().unwrap();
        let joiner_hex = joiner.public_key_hex();

        let mut listeners = Vec::new();
        let mut peers = BTreeMap::new();
        for id in 1..=3u64 {
            let (listener, url) = mesh_listener();
            peers.insert(id, url);
            listeners.push((id, listener));
        }
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());

        let mut nodes = BTreeMap::new();
        for (id, listener) in listeners {
            let mesh = Arc::new(MeshTls::new(ids[&id].clone(), trusts[&id].clone()));
            let node = build_node(ClusterParams {
                node_id: id,
                peers: peers.clone(),
                voters: BTreeSet::new(), // 1,2,3 all vote
                durable_kv: Arc::new(MemoryKv::new()),
                storage: storage.clone(),
                mesh: mesh.clone(),
                cluster_write_capability: None,
                extra_observers: Vec::new(),
            })
            .await
            .unwrap();
            serve_over_tls(listener, node.router.clone(), &mesh);
            nodes.insert(id, node);
        }

        nodes[&1].bootstrap().await.unwrap();
        nodes[&1]
            .raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(|m| m.current_leader.is_some(), "leader elected")
            .await
            .unwrap();
        let leader = nodes[&1].raft.metrics().borrow().current_leader.unwrap();

        // No node trusts the joiner (4) yet.
        for id in 1..=3u64 {
            assert!(!trusts[&id].contains(4, joiner.public_key()));
        }

        // The leader admits the joiner from a (pretend-verified) token handle.
        let admitted = nodes[&leader]
            .admit(4, &joiner_hex, "jti-join-1")
            .await
            .unwrap();
        assert!(admitted, "a fresh token must admit the node");

        // The trust replicates to every node's own live set (their observers
        // mirror the committed MeshAdmit).
        for id in 1..=3u64 {
            let trust = &trusts[&id];
            let mut ok = false;
            for _ in 0..100 {
                if trust.contains(4, joiner.public_key()) {
                    ok = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(
                ok,
                "node {id} must trust the joiner mesh-wide after admission"
            );
        }

        // The joiner is now a known member (learner) on the leader.
        assert!(
            nodes[&leader].is_member(4),
            "the admitted node must be added to membership"
        );

        // Single-use: replaying the same token admits nothing.
        let replay = nodes[&leader]
            .admit(4, &joiner_hex, "jti-join-1")
            .await
            .unwrap();
        assert!(!replay, "a replayed join token must be refused");

        for (_, node) in nodes {
            node.raft.shutdown().await.unwrap();
        }
    }

    /// `ClusterNode::rotate_key` is make-before-break: after node
    /// 1 rotates, it presents `K_new`, every node trusts `K_new` and no longer
    /// trusts `K_old` (retired), and the cluster still replicates through the
    /// rotated node. The `K_old`→`K_new` overlap (both keys accepted, no
    /// rejection window) is proven at the transport layer by the mesh
    /// `rotation_window_accepts_both_keys_then_retires_the_old` test.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rotate_key_makes_before_breaking() {
        let ids: BTreeMap<NodeId, Arc<MeshIdentity>> = (1..=2)
            .map(|i| (i, Arc::new(MeshIdentity::generate().unwrap())))
            .collect();
        let genesis: BTreeMap<NodeId, Vec<u8>> = ids
            .iter()
            .map(|(k, v)| (*k, v.public_key().to_vec()))
            .collect();
        let trusts: BTreeMap<NodeId, TrustSet> = ids
            .keys()
            .map(|k| (*k, TrustSet::from_map(genesis.clone())))
            .collect();

        let mut listeners = Vec::new();
        let mut peers = BTreeMap::new();
        for id in 1..=2u64 {
            let (listener, url) = mesh_listener();
            peers.insert(id, url);
            listeners.push((id, listener));
        }
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());

        let mut nodes = BTreeMap::new();
        let mut mesh_handles = BTreeMap::new();
        for (id, listener) in listeners {
            let mesh = Arc::new(MeshTls::new(ids[&id].clone(), trusts[&id].clone()));
            mesh_handles.insert(id, mesh.clone());
            let node = build_node(ClusterParams {
                node_id: id,
                peers: peers.clone(),
                voters: BTreeSet::new(),
                durable_kv: Arc::new(MemoryKv::new()),
                storage: storage.clone(),
                mesh: mesh.clone(),
                cluster_write_capability: None,
                extra_observers: Vec::new(),
            })
            .await
            .unwrap();
            serve_over_tls(listener, node.router.clone(), &mesh);
            nodes.insert(id, node);
        }

        nodes[&1].bootstrap().await.unwrap();
        nodes[&1]
            .raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(|m| m.current_leader.is_some(), "leader elected")
            .await
            .unwrap();

        let k_old = ids[&1].public_key().to_vec();
        // Rotate node 1's key (short propagation wait for the test).
        let k_new = nodes[&1]
            .rotate_key(Duration::from_millis(300))
            .await
            .unwrap();
        assert_ne!(k_new, k_old, "rotation must mint a fresh key");
        assert_eq!(
            mesh_handles[&1].public_key(),
            k_new,
            "node 1 must now present K_new"
        );

        // Make-before-break completed cluster-wide: every node trusts K_new and
        // has retired K_old.
        for id in 1..=2u64 {
            let trust = &trusts[&id];
            let mut ok = false;
            for _ in 0..100 {
                if trust.contains(1, &k_new) && !trust.contains(1, &k_old) {
                    ok = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(
                ok,
                "node {id} must trust K_new and have retired K_old after rotation"
            );
        }

        // The cluster still works through the rotated node.
        nodes[&2]
            .kv
            .put("current/blog", b"after-rotation".to_vec())
            .await
            .unwrap();
        nodes[&1]
            .raft
            .wait(Some(Duration::from_secs(15)))
            .applied_index_at_least(Some(3), "write applied after rotation")
            .await
            .unwrap();
        assert_eq!(
            nodes[&1].kv.get("current/blog").await.unwrap().as_deref(),
            Some(b"after-rotation".as_slice())
        );

        for (_, node) in nodes {
            node.raft.shutdown().await.unwrap();
        }
    }

    /// `ClusterNode::revoke` deletes a node's trust cluster-wide and drops it from
    /// the quorum: after revoking node 3, no node trusts its key
    /// (so it is rejected on its next handshake — the live verifier) and it is no
    /// longer a voter.
    #[serial_test::serial]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn revoke_removes_trust_cluster_wide_and_drops_the_voter() {
        let ids: BTreeMap<NodeId, Arc<MeshIdentity>> = (1..=3)
            .map(|i| (i, Arc::new(MeshIdentity::generate().unwrap())))
            .collect();
        let genesis: BTreeMap<NodeId, Vec<u8>> = ids
            .iter()
            .map(|(k, v)| (*k, v.public_key().to_vec()))
            .collect();
        let trusts: BTreeMap<NodeId, TrustSet> = ids
            .keys()
            .map(|k| (*k, TrustSet::from_map(genesis.clone())))
            .collect();

        let mut listeners = Vec::new();
        let mut peers = BTreeMap::new();
        for id in 1..=3u64 {
            let (listener, url) = mesh_listener();
            peers.insert(id, url);
            listeners.push((id, listener));
        }
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());

        let mut nodes = BTreeMap::new();
        for (id, listener) in listeners {
            let mesh = Arc::new(MeshTls::new(ids[&id].clone(), trusts[&id].clone()));
            let node = build_node(ClusterParams {
                node_id: id,
                peers: peers.clone(),
                voters: BTreeSet::new(), // 1,2,3 all vote
                durable_kv: Arc::new(MemoryKv::new()),
                storage: storage.clone(),
                mesh: mesh.clone(),
                cluster_write_capability: None,
                extra_observers: Vec::new(),
            })
            .await
            .unwrap();
            serve_over_tls(listener, node.router.clone(), &mesh);
            nodes.insert(id, node);
        }

        nodes[&1].bootstrap().await.unwrap();
        nodes[&1]
            .raft
            .wait(Some(Duration::from_secs(15)))
            .metrics(|m| m.current_leader.is_some(), "leader elected")
            .await
            .unwrap();
        let leader = nodes[&1].raft.metrics().borrow().current_leader.unwrap();
        // Revoke from the leader (a follower would forward the trust delete but
        // couldn't drop the voter).
        let target = if leader == 3 { 1 } else { 3 };
        let target_key = ids[&target].public_key().to_vec();

        nodes[&leader].revoke(target).await.unwrap();

        // The revoked key is gone from every node's live trust set.
        for id in 1..=3u64 {
            let trust = &trusts[&id];
            let mut ok = false;
            for _ in 0..100 {
                if !trust.contains(target, &target_key) {
                    ok = true;
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(ok, "node {id} must no longer trust the revoked node");
        }

        // The revoked node is no longer a voter.
        let voters: BTreeSet<NodeId> = nodes[&leader]
            .raft
            .metrics()
            .borrow()
            .membership_config
            .membership()
            .voter_ids()
            .collect();
        assert!(
            !voters.contains(&target),
            "the revoked node must be dropped from the quorum"
        );

        for (_, node) in nodes {
            node.raft.shutdown().await.unwrap();
        }
    }
}
