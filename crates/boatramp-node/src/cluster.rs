//! The cluster peer-mesh assembly (PLAN-node-library N4, "cluster + TLS assembly" — the cluster
//! slice).
//!
//! The `boatramp serve --mode cluster` startup (`run_cluster` in the binary) used to inline the
//! peer-mesh mutual-TLS listener config and the non-loopback empty-trust fail-closed guard, where
//! no in-process test could exercise the exact mesh TLS posture or the fail-closed invariant. This
//! module lifts those two pure, trust-relevant pieces behind a library seam.
//!
//! The binary keeps every IO / runtime concern of `run_cluster`: opening the node-local SlateDB
//! Raft store, the startup decision + join (dialing seeds), `build_node` (the openraft bootstrap +
//! `RaftKv` facade), the `MeshTransport` construction, the post-KV sealed-credential blob pass, and
//! the `serve_tls` loop. It calls these helpers for the pure config / decision assembly.
//!
//! **Behaviour-preserving (a pure move).** The mesh mutual-TLS config (RFC 7250 raw-public-key, the
//! live pinning trust set, the serving ALPN) and the fail-closed trust guard are assembled
//! byte-for-byte as before — no trust decision changed. `MeshTls` is
//! [`boatramp_rpktls::RpkTls`] (the shared RPK crypto core `boatramp_cluster::mesh` re-exports as
//! `MeshTls`), so this rides the RPK stack the `tls` feature already pulls and needs no
//! `boatramp-cluster` dependency. Runtime-agnostic: pure synchronous assembly, no `tokio::spawn`.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use boatramp_core::kv::KvStore;

use crate::config::{ClusterConfig, MeshConfig, ServerConfig};
use crate::error::{Error, Result};

/// Build the peer-mesh **mutual-TLS** listener config (`run_cluster`'s HTTP-transport mesh server):
/// RFC 7250 raw-public-key mutual TLS over the node's mesh identity + its live pinning trust set
/// ([`RpkTls::server`](boatramp_rpktls::RpkTls::server) — every `/raft/*` + `/stream/*` peer must
/// present a trusted key), advertising the serving ALPN (`h2` / `http/1.1`). A pure config build —
/// the caller layers the write-authz extension on the mesh router and runs `serve_tls`.
///
/// `mesh_tls` is a [`boatramp_rpktls::RpkTls`] — the exact type `boatramp_cluster::mesh::MeshTls`
/// aliases — so the mutual-TLS trust posture (client auth required, pinned to the live trust set,
/// no resumable tickets) is the identical build the binary ran; only the ALPN tag is appended here.
pub fn mesh_server_config(mesh_tls: &boatramp_rpktls::RpkTls) -> Result<rustls::ServerConfig> {
    let mut config = mesh_tls.server()?;
    config.alpn_protocols = boatramp_server::alpn_h1_h2();
    Ok(config)
}

/// The fail-closed guard shared by `run_cluster`'s two `MeshUnconfigured` checks: a peer mesh on a
/// **non-loopback** bind with an **empty trust set** must refuse to serve — bringing it up would
/// expose an unauthenticated control plane. The caller composes the phase condition around this
/// pure core (`!is_resume` before `build_node` seeds genesis trust; `is_resume` after `build_node`
/// rehydrates the durable trust set), so the security invariant lives in one tested place.
///
/// A loopback bind (`127.0.0.1` / `::1`) is never gated — a single-host / dev node has no peers to
/// trust — which is exactly the prior inlined behaviour.
pub fn mesh_trust_fails_closed(listen: SocketAddr, trust_empty: bool) -> bool {
    !listen.ip().is_loopback() && trust_empty
}

// ── The cluster substrate RUN-ENTRY (PLAN-node-library N4-B) ─────────────────────────────────────
//
// Part 2 of N4 lifts the RUNTIME PLUMBING out of the binary's `run_cluster`: the cluster-join
// decision/redemption (via [`crate::join`]), the mesh write-gate + control bridge, and the
// [`bootstrap`] run-entry that turns an OPENED durable store + parsed `[cluster]` config into a
// built, serving [`ClusterNode`](boatramp_cluster::node::ClusterNode). It owns the orchestration;
// the genuinely runtime-variable seams stay the CALLER's:
//
//   * the **cluster-store open** — the caller opens the node-local durable Raft store (its backend,
//     its repair policy, its checkpoint/GC cadence + graceful-close budget) and injects the opened
//     [`KvStore`] handle + the pre-open `store_dir_existed` signal;
//   * the **async runtime** — the caller owns the tokio runtime and `.await`s this entry (the
//     intrinsic peer-mesh serve + key-rotation `tokio::spawn`s run inside it);
//   * the **serve tail** — the post-KV sealed-credential blob pass, the ACME cert plumbing, the
//     `is_leader`/`raft_shutdown` wiring and `serve_assembled` stay with the caller, fed the
//     returned [`ClusterSubstrate`].
//
// **Behaviour-preserving (a pure move).** The cluster-join authentication, the RaftKv / peer-mesh
// mutual-TLS posture (mutual RFC 7250 raw-public-key auth, the live trust set, the non-loopback
// empty-trust fail-closed invariant on BOTH phases) and the mesh key-rotation cadence are
// byte-for-byte unchanged — this is a relocation + a reuse surface, not a trust-decision change.

/// How long a mesh key rotation waits for `K_new` to propagate before presenting it. Only minimises
/// the transient-rejection window — the live verifier + dialer retry make a shorter/absent wait
/// safe, not incorrect.
const MESH_ROTATION_PROPAGATION: std::time::Duration = std::time::Duration::from_secs(2);

/// Clock skew tolerated on a join possession proof: `proof_iat` must be within this window of the
/// admitting node's clock, so a captured proof cannot be replayed indefinitely (the single-use
/// `jti` is the primary anti-replay; this bounds the pre-spend window). Symmetric to cover both
/// directions of skew.
const JOIN_PROOF_MAX_SKEW_SECS: u64 = 300;

/// TTL on the root-signed member assertions handed back in a join response: long enough for the
/// joiner to verify + adopt each key within the round-trip, short enough that a captured response
/// can't seed a node much later. The joiner verifies each against the root anchor before trusting
/// it (PLAN-cluster-join F3).
const MEMBER_ASSERTION_TTL_SECS: u64 = 300;

/// Parse a mesh key-rotation cadence like `"30d"`, `"12h"`, `"90m"`, `"3600s"` into a `Duration`.
/// `None` for an empty/invalid value (⇒ no scheduled rotation). Only the `s`/`m`/`h`/`d` suffixes
/// are accepted.
fn parse_rotation_interval(spec: &str) -> Option<std::time::Duration> {
    let spec = spec.trim();
    let split = spec.find(|c: char| !c.is_ascii_digit())?;
    let (num, unit) = spec.split_at(split);
    let n: u64 = num.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n.checked_mul(60)?,
        "h" => n.checked_mul(3600)?,
        "d" => n.checked_mul(86_400)?,
        _ => return None,
    };
    (secs > 0).then(|| std::time::Duration::from_secs(secs))
}

/// Bridges the server's `/api/cluster/*` control routes to the cluster runtime (join admission +
/// key rotation) over [`ClusterNode`](boatramp_cluster::node::ClusterNode). `issuer` is the
/// control-plane **root signer**: a join admits only if this node can mint root-signed member
/// assertions for the joiner to adopt. The caller builds this once the post-`configure_auth` root
/// signer exists (fields are `pub` so the binary's `MeshControlBuilder` closure constructs it).
pub struct ClusterMeshControl {
    /// The cluster runtime this bridge drives.
    pub node: Arc<boatramp_cluster::node::ClusterNode>,
    /// The control-plane root signer used to vouch for members at join time.
    pub issuer: Option<Arc<dyn boatramp_core::cose::Signer>>,
}

#[async_trait::async_trait]
impl boatramp_server::MeshControl for ClusterMeshControl {
    async fn admit(
        &self,
        mesh_pubkey_hex: &str,
        jti: &str,
        possession_proof: &[u8],
        proof_iat: u64,
        now: u64,
        advertise_addr: Option<&str>,
    ) -> std::result::Result<boatramp_server::JoinOutcome, String> {
        use boatramp_server::JoinOutcome;

        // (1) Freshness: the proof must be stamped within the skew window. This
        // bounds how long a captured (pre-spend) proof stays presentable.
        let fresh = proof_iat <= now.saturating_add(JOIN_PROOF_MAX_SKEW_SECS)
            && now <= proof_iat.saturating_add(JOIN_PROOF_MAX_SKEW_SECS);
        if !fresh {
            return Ok(JoinOutcome::ProofInvalid);
        }

        // (2) The joiner is identified by the key it claims; parse it to SPKI.
        let Ok(spki) = boatramp_cluster::mesh::parse_public_key(mesh_pubkey_hex) else {
            return Ok(JoinOutcome::ProofInvalid);
        };

        // (3) Possession: the proof must be a signature by that very key over the
        // domain-separated join challenge — so a bearer token alone (without the
        // private key) cannot join in another key's name.
        let challenge = boatramp_core::cose::join_challenge(jti, mesh_pubkey_hex, proof_iat);
        if !boatramp_rpktls::verify_signature(&spki, &challenge, possession_proof) {
            return Ok(JoinOutcome::ProofInvalid);
        }

        // (4) Single-use + re-admit-proof: the state machine spends the `jti`
        // (idempotent replay ⇒ already-spent) and refuses a revoked key (F6). A
        // stale/spent token or a revoked key that survived (3) stops here.
        use boatramp_cluster::raft::AdmitOutcome;
        match self
            .node
            .admit(mesh_pubkey_hex, jti, advertise_addr)
            .await
            .map_err(|e| e.to_string())?
        {
            AdmitOutcome::Admitted => {}
            AdmitOutcome::Spent => return Ok(JoinOutcome::TokenSpent),
            AdmitOutcome::Revoked => return Ok(JoinOutcome::Revoked),
        }

        // (5) Vouch for the current members with root-signed assertions so the
        // joiner adopts each only after verifying it against the root anchor.
        let Some(issuer) = self.issuer.as_ref() else {
            return Err("cluster node has no root signing key to vouch for members".to_string());
        };
        let mut members = Vec::new();
        for (node_id, pubkey) in self.node.trusted_member_keys().await {
            let assertion = boatramp_core::cose::mint_member_assertion(
                node_id,
                &pubkey,
                MEMBER_ASSERTION_TTL_SECS,
                now,
                issuer.as_ref(),
            )
            .await
            .map_err(|e| e.to_string())?;
            members.push(assertion);
        }
        // Advisory routing so the joiner can dial every member (each dial is still
        // key-authenticated). Only entries for members it also verified above are
        // usable to it.
        let addrs = self.node.peer_addrs();
        Ok(JoinOutcome::Admitted { members, addrs })
    }

    async fn rotate_key(&self) -> std::result::Result<String, String> {
        let new_pub = self
            .node
            .rotate_key(MESH_ROTATION_PROPAGATION)
            .await
            .map_err(|e| e.to_string())?;
        Ok(new_pub.iter().map(|b| format!("{b:02x}")).collect())
    }

    async fn revoke(&self, node: u64) -> std::result::Result<(), String> {
        self.node.revoke(node).await.map_err(|e| e.to_string())
    }

    async fn members(&self) -> std::result::Result<Vec<boatramp_server::MeshMember>, String> {
        let addrs = self.node.peer_addrs();
        Ok(self
            .node
            .members()
            .into_iter()
            .map(|m| boatramp_server::MeshMember {
                node: m.node,
                voter: m.voter,
                caught_up: m.caught_up,
                leader: m.leader,
                addr: addrs.get(&m.node).cloned(),
            })
            .collect())
    }

    async fn promote(&self, node: u64) -> std::result::Result<(), String> {
        self.node.promote(node).await.map_err(|e| e.to_string())
    }
}

/// Verifies a mesh client-write **cluster-write capability**: the presented bearer must be a token
/// signed by the control-plane root that grants the `cluster-write` role. This trust root is
/// separate from the mesh transport key, so a mesh-key holder without a control-plane capability
/// can't inject writes.
struct MeshWriteAuthz {
    public: boatramp_core::cose::TokenPublicKey,
}

impl boatramp_cluster::http::ClientWriteAuthz for MeshWriteAuthz {
    fn authorize(&self, capability: Option<&str>) -> bool {
        let Some(token) = capability else {
            return false;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Verify the capability with its OWN kind check (`br_kind == cluster-write`):
        // since 8(b) the generic `cose::verify` is the ROLE path and refuses a
        // non-role kind, so the mesh write gate uses the kind-checked sibling —
        // which also strengthens domain separation (a role token that happened to
        // carry a `cluster-write` grant is now rejected here, not just role-checked).
        let Ok(verified) = boatramp_core::cose::verify_cluster_write(token, &self.public, now)
        else {
            return false;
        };
        verified.roles.iter().any(|r| r.name == "cluster-write")
    }
}

/// Build the mesh write gate from config: when `mesh.gate_client_writes` is set and the token
/// signer (root **private** key) is available, mint this node's cluster-write capability and an
/// authorizer for incoming forwards. Returns `(None, None)` when disabled or the root key is absent
/// (gating then off — defense-in-depth is opt-in and must not break a keyless cluster).
#[allow(clippy::type_complexity)]
async fn build_mesh_write_gate(
    config: &ServerConfig,
    mesh_cfg: &MeshConfig,
) -> Result<(
    Option<String>,
    Option<Arc<dyn boatramp_cluster::http::ClientWriteAuthz>>,
)> {
    use boatramp_core::authz::GrantedRole;
    use boatramp_core::cose::{self, Claims, LocalSigner, Signer};

    if !mesh_cfg.gate_client_writes.unwrap_or(false) {
        return Ok((None, None));
    }
    let priv_hex = config
        .serve
        .as_ref()
        .and_then(|s| s.auth_root_private_key.clone());
    let Some(priv_hex) = priv_hex else {
        tracing::warn!(
            "cluster.mesh.gate_client_writes is set but no token root private key is \
             configured — mesh client-write gating is disabled"
        );
        return Ok((None, None));
    };
    let signer =
        LocalSigner::from_private_hex(&priv_hex).map_err(|e| Error::AuthPrivKey(e.to_string()))?;
    // No TTL: the capability lives for this node's process (now_unix unused).
    let claims = Claims {
        roles: vec![GrantedRole::global("cluster-write")],
        kind: cose::KIND_CLUSTER_WRITE.to_string(),
        ttl_secs: None,
        now_unix: 0,
    };
    let capability = cose::mint(&claims, &signer)
        .await
        .map_err(|e| Error::AuthPrivKey(format!("minting cluster-write capability: {e}")))?;
    let authz: Arc<dyn boatramp_cluster::http::ClientWriteAuthz> = Arc::new(MeshWriteAuthz {
        public: signer.public_key(),
    });
    Ok((Some(capability), Some(authz)))
}

/// Reloads this node's dynamic daemon-config runtime whenever a replicated `daemon/*` write is
/// applied to the Raft state machine — push convergence for cluster followers and the leader
/// through ordinary log replication, no polling.
struct DaemonConfigObserver(Arc<boatramp_server::DaemonRuntime>);

impl boatramp_cluster::raft::ApplyObserver for DaemonConfigObserver {
    fn on_apply(&self, muts: &[boatramp_core::kv::WriteOp]) {
        use boatramp_core::kv::WriteOp;
        let touched = muts.iter().any(|m| match m {
            WriteOp::Put(k, _) | WriteOp::Delete(k) => k.starts_with("daemon/"),
        });
        if touched {
            self.0.notify_reload();
        }
    }

    fn on_reset(&self, data: &std::collections::BTreeMap<String, Vec<u8>>) {
        if data.keys().any(|k| k.starts_with("daemon/")) {
            self.0.notify_reload();
        }
    }
}

/// Inputs to the cluster substrate [`bootstrap`] run-entry. The caller resolves the `[cluster]`
/// config and opens the node-local durable Raft store (the injected seam), then hands the opened
/// handle in; `bootstrap` owns everything from the startup decision through the serving peer mesh.
pub struct ClusterBootstrap<'a> {
    /// The parsed server config (read for `[serve]` root-anchor fallback + the mesh write gate).
    pub config: &'a ServerConfig,
    /// The parsed `[cluster]` config. Owned + mutated internally when a one-paste `--cluster-join`
    /// ticket folds its seeds/roots/token over the file config.
    pub cluster_cfg: ClusterConfig,
    /// The node data dir — the mesh identity key defaults under `<data_dir>/mesh/identity.key`.
    pub data_dir: &'a Path,
    /// INJECTED: the OPENED node-local durable Raft log/state store. The caller owns its backend,
    /// repair policy, and checkpoint/GC/close lifecycle; `bootstrap` reads its committed-trust
    /// signal (the resume gate) and moves it into the openraft stores.
    pub durable_kv: Arc<dyn KvStore>,
    /// INJECTED: whether the durable store dir existed BEFORE the caller opened it — the weak
    /// "ever booted" signal (NOT the resume gate, which is committed trust).
    pub store_dir_existed: bool,
    /// The one-paste join ticket (`serve --cluster-join <blob>`), folded over the file config.
    pub cluster_join: Option<String>,
    /// Whether founding was explicitly requested (`--cluster-init`, or the operator ordinal-0
    /// founder designation — the caller composes that env semantics).
    pub init_requested: bool,
    /// This node's advertised reachable mesh URL (`--cluster-advertise-addr`); defaults to
    /// `https://<cluster.listen>`.
    pub cluster_advertise_addr: Option<String>,
}

/// The built cluster substrate handed back to the caller's serve tail. The intrinsic peer-mesh
/// server + key-rotation loop are already spawned; the node is bootstrapped/joined/resumed and its
/// mesh is serving. The caller resolves the post-KV sealed-credential blob pass, the ACME cert
/// plumbing, `is_leader`/`raft_shutdown`, and `serve_assembled` from [`node`](Self::node).
pub struct ClusterSubstrate {
    /// The running cluster node (RaftKv + RaftMessaging facades, the mesh identity + live trust).
    pub node: Arc<boatramp_cluster::node::ClusterNode>,
    /// The cross-node messaging payload-spill handle, UNBOUND here; the caller BINDS it to the
    /// sealed serving backend in the post-KV pass, strictly before any messaging traffic flows.
    pub messaging_spill: Arc<boatramp_cluster::messaging::LateStorage>,
}

/// Bootstrap the cluster substrate: load the mesh identity, decide found/join/resume, build the
/// openraft node + its RaftKv facade, serve the peer mesh (mutual TLS / overlay), and schedule key
/// rotation. Returns the built [`ClusterSubstrate`] for the caller's serve tail.
///
/// `options` gains the dynamic [`DaemonRuntime`](boatramp_server::DaemonRuntime) (its cluster
/// `ApplyObserver` wakes a reload on every replicated `daemon/*` apply) exactly as before.
pub async fn bootstrap(
    input: ClusterBootstrap<'_>,
    options: &mut boatramp_server::ServerOptions,
) -> Result<ClusterSubstrate> {
    use boatramp_cluster::node::{ClusterParams, build_node};

    let ClusterBootstrap {
        config,
        mut cluster_cfg,
        data_dir,
        durable_kv,
        store_dir_existed,
        cluster_join,
        init_requested,
        cluster_advertise_addr,
    } = input;

    // Cross-node messaging payload-spill store (PLAN-serve-single-cluster-parity, seal-messaging
    // residual). `build_node` wires this into `RaftMessaging` BEFORE the replicated control-plane KV
    // (`node.kv`) exists — and the node-level sealed `boatramp:` base S3 credential can only resolve
    // AFTER that KV is up (the boot chicken-and-egg). So we hand `build_node` a LATE-BOUND handle,
    // UNBOUND here (no credential wired early — NEVER the uncredentialed/ambient early backend), and
    // the caller BINDs it to the SAME sealed serving backend in the post-KV pass, strictly before
    // `serve_assembled` serves and before any messaging traffic can flow. Fail-closed until then: a
    // spill against the unbound handle errors rather than touching an ambient backend (defensive —
    // in practice no spill runs before the post-KV bind, since messaging does not serve until then).
    let messaging_spill = Arc::new(boatramp_cluster::messaging::LateStorage::unbound());

    // The real resume-vs-found/join signal (F5): whether the store holds COMMITTED
    // cluster state (persisted mesh trust). A store dir that exists but has no
    // committed trust means an earlier boot opened the KV but never finished its
    // join — such a node must re-derive its action (rejoin), not resume into an
    // empty-trust, fail-closed mesh. Checked once, over the raw (injected) store.
    let has_committed_state = boatramp_cluster::persist::has_committed_trust(&durable_kv)
        .await
        .map_err(|e| Error::ClusterStartup(e.to_string()))?;

    use boatramp_cluster::mesh::{self, MeshIdentity, MeshTls, TrustSet};

    // No static peer map: the peer directory + mesh trust set start empty and are
    // populated by founding (self), joining (adopted members), or replication.
    let mut peers = std::collections::BTreeMap::new();
    let mut genesis_trust = std::collections::BTreeMap::new();

    // Load (or generate + persist `0600`) this node's Ed25519 mesh identity.
    let mesh_cfg = cluster_cfg.mesh.clone().unwrap_or_default();
    let key_file = mesh_cfg
        .key_file
        .clone()
        .unwrap_or_else(|| data_dir.join("mesh/identity.key"));
    let identity = MeshIdentity::load_or_generate(&key_file)?;

    // This node's Raft id is DERIVED from its mesh key (dynamic-join self-identity
    // — no config id).
    let node_id = boatramp_cluster::raft::derive_node_id(identity.public_key());
    tracing::info!(
        node_id,
        pubkey = %identity.public_key_hex(),
        "cluster: mesh identity"
    );

    // A one-paste `--cluster-join <ticket>` overrides the `[cluster]` seeds/root/
    // token: decode it and fold it into the config so the rest of the flow is
    // ticket-vs-config agnostic.
    if let Some(blob) = cluster_join.as_deref() {
        let ticket = crate::join::JoinTicket::decode(blob)
            .map_err(|e| Error::ClusterStartup(e.to_string()))?;
        cluster_cfg.seeds = ticket.seeds;
        cluster_cfg.root_pubkeys = ticket.root_pubkeys;
        cluster_cfg.join_token = Some(ticket.token);
    }

    // Decide founding vs joining vs resuming (F5): the single source of truth.
    let seeds_present = !cluster_cfg.seeds.is_empty();
    let action = crate::join::decide_startup(&crate::join::StartupInputs {
        // Resume ONLY on committed state (persisted trust) — not on a store dir that
        // merely exists, which would wedge a joiner whose first join never finished.
        has_committed_state,
        // The dir already existing means this node booted before, but possibly never
        // committed any state; kept as the weaker "ever booted" signal for messaging.
        ever_member: store_dir_existed,
        seeds_present,
        init_requested,
    });
    // A resuming node seeds no genesis trust here — it rehydrates its trust set
    // from durable state inside `build_node`, so its empty-trust fail-closed check
    // is deferred until after that (below). Captured now: the `match action` moves.
    let is_resume = matches!(action, crate::join::StartupAction::Resume);

    // This node's own reachable mesh URL (advertised at join so the leader can
    // dial it), defaulting to the bind address.
    let self_advertise =
        cluster_advertise_addr.unwrap_or_else(|| format!("https://{}", cluster_cfg.listen));

    // A dynamic joiner starts with NO static membership; the seed admits it and
    // membership + trust arrive via replication. Bootstrap only when founding.
    let mut do_bootstrap = false;
    match action {
        crate::join::StartupAction::FailClosed(reason) => {
            return Err(Error::ClusterStartup(reason));
        }
        crate::join::StartupAction::Found => {
            // Genesis: this node is the sole founding member. List itself so
            // `build_node` takes the genesis path and `bootstrap` initializes it.
            peers.insert(node_id, self_advertise.clone());
            genesis_trust.insert(node_id, identity.public_key().to_vec());
            do_bootstrap = true;
            tracing::info!(node_id, "cluster: founding a new cluster (init)");
        }
        crate::join::StartupAction::Join => {
            // Redeem the join ticket against the seeds and adopt the returned,
            // root-verified members — seeding the trust set + peer directory with
            // NO static peer map. This node is a joiner: it does NOT list itself,
            // so `build_node` starts it with empty membership (the seed admits it).
            let roots = if cluster_cfg.root_pubkeys.is_empty() {
                config
                    .serve
                    .as_ref()
                    .and_then(|s| s.auth_root_public_key.clone())
                    .into_iter()
                    .collect()
            } else {
                cluster_cfg.root_pubkeys.clone()
            };
            let token = cluster_cfg
                .join_token
                .as_deref()
                .and_then(|s| {
                    crate::join::resolve_join_token(s, &boatramp_core::env::SystemEnv).transpose()
                })
                .transpose()
                .map_err(|e| Error::ClusterStartup(e.to_string()))?
                .ok_or_else(|| {
                    Error::ClusterStartup(
                        "joining requires [cluster].join_token (env:/path:/inline)".into(),
                    )
                })?;
            let ticket = crate::join::JoinTicket {
                seeds: cluster_cfg.seeds.clone(),
                root_pubkeys: roots,
                token,
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let adopted = crate::join::join_cluster(&ticket, &identity, Some(&self_advertise), now)
                .await
                .map_err(|e| Error::ClusterStartup(e.to_string()))?;
            tracing::info!(
                node_id,
                members = adopted.len(),
                "cluster: joined via seeds"
            );
            for m in adopted {
                if let Ok(spki) = mesh::parse_public_key(&m.mesh_pubkey_hex) {
                    genesis_trust.insert(m.node_id, spki);
                }
                if let Some(addr) = m.mesh_addr {
                    peers.insert(m.node_id, addr);
                }
            }
        }
        crate::join::StartupAction::Resume => {
            // Durable state is authoritative; `build_node` hydrates trust + the
            // peer directory from it. Never re-bootstraps.
            tracing::info!(node_id, "cluster: resuming from durable state");
        }
    }

    // Fail closed: never bring up a non-loopback mesh with no trusted peers.
    // Found/Join seed `genesis_trust` right here, so they are checked now; a Resume
    // leaves it empty on purpose and is checked after `build_node` rehydrates its
    // trust from durable state. The non-loopback-empty-trust core is the shared
    // guard (byte-identical); the phase condition (`!is_resume`) composes around it.
    if !is_resume && mesh_trust_fails_closed(cluster_cfg.listen, genesis_trust.is_empty()) {
        return Err(Error::MeshUnconfigured(cluster_cfg.listen));
    }

    let mesh_tls = Arc::new(MeshTls::new(
        Arc::new(identity),
        TrustSet::from_map(genesis_trust),
    ));

    // Optionally gate mesh client-writes behind a control-plane cluster-write
    // capability (this node's capability + the authorizer for incoming forwards).
    let (write_capability, write_authz) = build_mesh_write_gate(config, &mesh_cfg).await?;
    if write_authz.is_some() {
        tracing::info!("cluster: mesh client-write gating enabled");
    }

    // Dynamic daemon-config runtime: a cluster ApplyObserver wakes an immediate
    // reload on every replicated `daemon/*` apply, so leader and followers converge
    // by push (through ordinary log replication) with no polling.
    let daemon_runtime = Arc::new(boatramp_server::DaemonRuntime::new(
        boatramp_server::config_baseline(options),
    ));
    options.daemon_runtime = Some(daemon_runtime.clone());
    let daemon_observer: Arc<dyn boatramp_cluster::raft::ApplyObserver> =
        Arc::new(DaemonConfigObserver(daemon_runtime));

    // Peer-mesh transport (IU-9): `transport = "overlay"` rides boatramp's own overlay-QUIC fabric
    // (reusing the mesh identity + live trust set verbatim); anything else (incl. unset) uses the
    // HTTP mesh. Both bind the same `cluster.listen` (HTTP over TCP, overlay over UDP/QUIC). The
    // overlay server gates client-writes with the same authorizer, passed in (the overlay has no
    // HTTP header layer); the HTTP server layers it on the router below.
    let use_overlay_mesh = match mesh_cfg
        .transport
        .as_deref()
        .unwrap_or("http")
        .to_ascii_lowercase()
        .as_str()
    {
        "overlay" => true,
        "http" => false,
        other => {
            return Err(Error::ClusterStartup(format!(
                "unknown [cluster.mesh] transport {other:?} (want \"http\" or \"overlay\")"
            )));
        }
    };
    let transport = if use_overlay_mesh {
        tracing::info!(
            listen = %cluster_cfg.listen,
            "cluster: peer mesh on the overlay-QUIC transport (IU-9)"
        );
        boatramp_cluster::node::MeshTransport::Overlay {
            bind: cluster_cfg.listen,
            write_authz: write_authz.clone(),
        }
    } else {
        boatramp_cluster::node::MeshTransport::Http
    };

    let node = Arc::new(
        build_node(ClusterParams {
            node_id,
            peers,
            // Empty ⇒ every peer votes; otherwise the listed ids are the voting
            // quorum and the rest join as read-only learners (multi-region).
            // Founding uses the self-only peer map ⇒ this node is the sole voter;
            // a joiner's membership arrives from the seed. No static voter list.
            voters: std::collections::BTreeSet::new(),
            durable_kv,
            // The late-bound messaging payload-spill handle, UNBOUND here; bound to the sealed
            // serving backend in the post-KV pass (seal-messaging residual).
            storage: messaging_spill.clone(),
            mesh: mesh_tls.clone(),
            cluster_write_capability: write_capability,
            extra_observers: vec![daemon_observer],
            transport,
        })
        .await?,
    );

    // A resuming node rehydrated its trust set from durable state inside
    // `build_node`. Only now can it fail closed on a genuinely empty trust (a wiped
    // or corrupt volume) — otherwise the mesh would come up trusting no peer.
    if is_resume
        && mesh_trust_fails_closed(cluster_cfg.listen, mesh_tls.trust().snapshot().is_empty())
    {
        return Err(Error::MeshUnconfigured(cluster_cfg.listen));
    }

    // Serve this node's peer mesh. The overlay transport already stood up its own QUIC listener
    // inside `build_node` (so `node.router` is empty); only the HTTP transport mounts a router on
    // an axum mutual-TLS listener here, where every `/raft/*` + `/stream/*` request must present a
    // trusted peer key and the application `client-write` is additionally gated by the authorizer.
    if use_overlay_mesh {
        tracing::info!(
            node_id, listen = %cluster_cfg.listen,
            "cluster: serving peer mesh (overlay QUIC, mutual RPK auth)"
        );
    } else {
        let mesh_router = match write_authz {
            Some(authz) => node.router.clone().layer(axum::Extension::<
                boatramp_cluster::http::WriteAuthz,
            >(Some(authz))),
            None => node.router.clone(),
        };
        let mesh_config = mesh_server_config(&mesh_tls)?;
        let listen = cluster_cfg.listen;
        tracing::info!(
            node_id, %listen,
            "cluster: serving peer mesh (HTTP, mutual TLS)"
        );
        tokio::spawn(async move {
            if let Err(err) = boatramp_server::serve_tls(
                listen,
                mesh_config.into(),
                mesh_router,
                boatramp_server::shutdown_signal(),
            )
            .await
            {
                tracing::error!(%err, "cluster: peer mesh server exited");
            }
        });
    }

    // Initialize a brand-new cluster from this node (once) when founding.
    if do_bootstrap {
        node.bootstrap().await?;
        // A founder is never admitted, so nothing else records its address —
        // publish it into the replicated directory so joiners (and restarts) can
        // dial it with no peer map.
        node.advertise_addr(&self_advertise).await?;
        tracing::info!("cluster: bootstrapped membership");
    }

    // Scheduled mesh key rotation. Node-local, NOT leader-gated:
    // each node rotates its OWN key (only it holds/mints its private key), and
    // make-before-break is per-node + fail-safe, so nodes rotating independently
    // (even concurrently) is harmless. Absent cadence ⇒ manual rotation only.
    if let Some(interval) = mesh_cfg
        .key_rotation
        .as_deref()
        .and_then(parse_rotation_interval)
    {
        let rotate_node = node.clone();
        // Stagger the first rotation by node id (seconds) so a fleet booted
        // together doesn't rotate in lockstep; then every `interval`.
        let stagger = std::time::Duration::from_secs(node_id % 60);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval + stagger).await;
                match rotate_node.rotate_key(MESH_ROTATION_PROPAGATION).await {
                    Ok(pubkey) => tracing::info!(
                        pubkey = %pubkey.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                        "cluster: rotated mesh key on schedule"
                    ),
                    Err(err) => {
                        tracing::error!(%err, "cluster: scheduled mesh key rotation failed");
                    }
                }
            }
        });
    }

    Ok(ClusterSubstrate {
        node,
        messaging_spill,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_rpktls::{RpkIdentity, RpkTls, TrustSet};
    use std::sync::Arc;

    #[test]
    fn mesh_server_config_advertises_the_serving_alpn() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let identity = Arc::new(RpkIdentity::generate().unwrap());
        // An empty trust set builds fine — `RpkTls::server` uses a custom live-trust verifier
        // (not a webpki root store), so the config assembles and rejects untrusted peers at
        // handshake. We assert the serving ALPN the mesh listener advertises.
        let mesh = RpkTls::new(identity, TrustSet::default());
        let config = mesh_server_config(&mesh).unwrap();
        assert_eq!(config.alpn_protocols, boatramp_server::alpn_h1_h2());
    }

    #[test]
    fn mesh_fails_closed_only_on_a_non_loopback_bind_with_empty_trust() {
        let loopback: SocketAddr = "127.0.0.1:7000".parse().unwrap();
        let loopback6: SocketAddr = "[::1]:7000".parse().unwrap();
        let public: SocketAddr = "203.0.113.5:7000".parse().unwrap();
        // A loopback bind never fails closed — even with no trust (single-host / dev).
        assert!(!mesh_trust_fails_closed(loopback, true));
        assert!(!mesh_trust_fails_closed(loopback6, true));
        // A non-loopback bind with an empty trust set refuses — the security invariant.
        assert!(mesh_trust_fails_closed(public, true));
        // A non-loopback bind with a trust anchor serves.
        assert!(!mesh_trust_fails_closed(public, false));
    }

    /// The mesh client-write gate (lifted from the binary's `run_cluster` tests): only a token the
    /// control-plane root signed that carries the `cluster-write` role is honored. No capability, a
    /// wrong role, a garbage token, and a foreign-root capability are all refused.
    #[tokio::test]
    async fn mesh_write_authz_accepts_only_a_cluster_write_capability() {
        use boatramp_cluster::http::ClientWriteAuthz;
        use boatramp_core::authz::GrantedRole;
        use boatramp_core::cose::{self, Claims, LocalSigner, Signer, TokenAlg};

        async fn cap(signer: &dyn Signer, role: &str) -> String {
            let claims = Claims {
                roles: vec![GrantedRole::global(role)],
                kind: cose::KIND_CLUSTER_WRITE.to_string(),
                ttl_secs: None,
                now_unix: 0,
            };
            cose::mint(&claims, signer).await.unwrap()
        }

        let signer = LocalSigner::generate(TokenAlg::Es256);
        let authz = MeshWriteAuthz {
            public: signer.public_key(),
        };

        assert!(
            authz.authorize(Some(&cap(&signer, "cluster-write").await)),
            "a real cluster-write capability"
        );

        assert!(!authz.authorize(None), "no capability");
        assert!(
            !authz.authorize(Some(&cap(&signer, "admin").await)),
            "wrong role"
        );
        assert!(!authz.authorize(Some("not-a-token")), "garbage");

        let other = LocalSigner::generate(TokenAlg::Es256);
        assert!(
            !authz.authorize(Some(&cap(&other, "cluster-write").await)),
            "foreign root key"
        );
    }

    /// The mesh key-rotation cadence parser (lifted from the binary's `run_cluster` tests).
    #[test]
    fn rotation_interval_parses_units_and_rejects_junk() {
        use std::time::Duration;
        assert_eq!(
            parse_rotation_interval("30d"),
            Some(Duration::from_secs(30 * 86_400))
        );
        assert_eq!(
            parse_rotation_interval("12h"),
            Some(Duration::from_secs(12 * 3600))
        );
        assert_eq!(
            parse_rotation_interval("90m"),
            Some(Duration::from_secs(90 * 60))
        );
        assert_eq!(
            parse_rotation_interval(" 45s "),
            Some(Duration::from_secs(45))
        );
        // No unit, unknown unit, zero, and empty are all rejected (⇒ no schedule).
        assert_eq!(parse_rotation_interval("30"), None);
        assert_eq!(parse_rotation_interval("5w"), None);
        assert_eq!(parse_rotation_interval("0d"), None);
        assert_eq!(parse_rotation_interval(""), None);
    }

    /// In-process smoke of the lifted [`bootstrap`] run-entry (mock/throwaway, NO live cluster): a
    /// FOUND single-node founder over a throwaway in-memory durable store on a loopback mesh bind.
    /// It drives the real orchestration (mesh identity → startup decision → `build_node` openraft
    /// bring-up → `bootstrap()` → serving mesh), then asserts the node becomes leader and exposes
    /// its control-plane KV facade — i.e. the run-entry boots a node identically to `run_cluster`,
    /// with the store-open seam injected. No network join, no peers.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bootstrap_founds_a_single_node_over_an_injected_store() {
        use crate::config::{ClusterConfig, MeshConfig};

        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // A loopback, port-0 mesh bind: the HTTP transport serves on an ephemeral port (no peer
        // dials it); loopback also exempts the non-loopback empty-trust fail-closed guard.
        let listen: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "boatramp-node-cluster-bootstrap-{}",
            std::process::id()
        ));
        let cluster_cfg = ClusterConfig {
            listen,
            root_pubkeys: Vec::new(),
            seeds: Vec::new(),
            join_token: None,
            store_dir: None,
            mesh: Some(MeshConfig {
                // Keep the identity key under the throwaway dir so the test leaves nothing behind.
                key_file: Some(tmp.join("mesh/identity.key")),
                ..Default::default()
            }),
        };
        // INJECTED store seam: a throwaway in-memory KV stands in for the node-local durable Raft
        // store (a fresh store ⇒ no committed trust ⇒ the FOUND path under `init_requested`).
        let durable_kv: Arc<dyn KvStore> = Arc::new(boatramp_core::kv::MemoryKv::new());
        let config = ServerConfig::default();
        let mut options = boatramp_server::ServerOptions::default();

        let substrate = bootstrap(
            ClusterBootstrap {
                config: &config,
                cluster_cfg,
                data_dir: &tmp,
                durable_kv,
                store_dir_existed: false,
                cluster_join: None,
                init_requested: true,
                cluster_advertise_addr: None,
            },
            &mut options,
        )
        .await
        .expect("single-node founder bootstraps");

        // The founder becomes leader (sole voter) and exposes the replicated control-plane KV.
        for _ in 0..100 {
            if substrate.node.is_leader() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(
            substrate.node.is_leader(),
            "a founding single node becomes the Raft leader"
        );
        // The daemon runtime (dynamic config) was wired onto the caller's options, as before.
        assert!(
            options.daemon_runtime.is_some(),
            "bootstrap wires the dynamic daemon runtime onto options"
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
