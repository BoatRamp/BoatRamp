//! K3b — the operator's **membership executor**: drives the quorum-safe planner
//! ([`super::membership::plan_next`]) against the cluster's control-plane API.
//!
//! Each reconcile the operator fetches the live Raft membership
//! (`GET /api/cluster/members`), maps it onto StatefulSet ordinals (keeping the
//! ordinal↔node_id map — #2), plans the single next transition, and executes it:
//!
//! - **PromoteToVoter** → `POST /api/cluster/promote {node_id}` (by node id).
//! - **Remove** → `POST /api/cluster/revoke {node_id}` (by node id).
//! - **AddLearner** → handled *proactively*, not here: while the cluster has fewer
//!   members than desired, the executor keeps a fresh single-use join ticket in the
//!   `<name>-join` Secret the joining pods read as `BOATRAMP_CLUSTER_JOIN`. A joiner
//!   **self-joins at startup** (before it serves — so it is never "ready but not a
//!   member", and the planner's `AddLearner` branch never fires in this flow); its
//!   redemption's `admit` adds it as a Raft learner server-side, which the planner
//!   then promotes. One-at-a-time; a lost race self-heals on the next reconcile.
//!
//! Every control-plane call runs over an **RPK-TLS channel pinned to the target
//! pod's root-attested key** (the same attestation-pin the joiner uses), reaching
//! pods by their stable per-pod headless DNS. Membership changes + join admission
//! run on the **leader** (resolved from the reported `leader` flag), reads + mints
//! on pod-0. Reaching the cluster needs an admin token (`spec.adminTokenSecret`)
//! **and** the root anchor (`spec.rootPubkey`, to pin); without them the operator
//! only plans + reports (the caller falls back).

use boatramp_core::cose::TokenPublicKey;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use serde_json::json;

use super::crd::BoatRampCluster;
use super::membership::{self, ApiMember, MembershipAction};
use super::{resources, Error, Result};

/// The control-plane port the pods serve on (`--tls rpk`; matches `resources::PORT`).
const CONTROL_PLANE_PORT: u16 = 8080;

/// The key holding the admin token in `spec.adminTokenSecret`.
const TOKEN_KEY: &str = "token";

/// The join Secret + key a joining pod reads as `BOATRAMP_CLUSTER_JOIN`.
fn join_secret_name(brc: &BoatRampCluster) -> String {
    format!("{}-join", resources::instance(brc))
}
const JOIN_KEY: &str = "ticket";

/// Current Unix time (attestation freshness); a straight clock read is fine here.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A specific pod's control-plane base URL, over the stable per-pod headless DNS
/// (`https://<instance>-<ordinal>.<headless>.<ns>.svc:8080`). Per-pod (not the
/// load-balanced client Service) so the RPK-TLS pin is against exactly one key.
fn pod_base(brc: &BoatRampCluster, ns: &str, ordinal: u32) -> String {
    let inst = resources::instance(brc);
    format!("https://{inst}-{ordinal}.{inst}-headless.{ns}.svc:{CONTROL_PLANE_PORT}")
}

/// A pinned cluster-API client to **one** pod: an RPK-TLS reqwest client that only
/// talks to that pod's root-attested key, plus the admin bearer token.
struct ClusterApi {
    http: reqwest::Client,
    base: String,
    token: String,
}

/// The `RollingUpdate` partition for the cluster StatefulSet (K4): `0` lets the
/// rollout proceed one pod at a time, `replicas` **pauses** it. Pauses unless the
/// cluster has a quorum margin (a spare ready voter), so a rolling upgrade never
/// drops below quorum. Needs admin creds to read membership; without them (or on
/// any error) it returns `0` and defers safety to the PDB.
pub(super) async fn roll_partition(
    client: &Client,
    ns: &str,
    brc: &BoatRampCluster,
    pods: &[membership::PodState],
) -> i32 {
    let replicas = brc.spec.replicas as i32;
    let Ok(Some((token, roots))) = admin_creds(client, ns, brc).await else {
        return 0;
    };
    let Ok(api) = ClusterApi::pin_pod(brc, ns, 0, &token, &roots).await else {
        return 0;
    };
    let Ok(raw) = api.members().await else { return 0 };
    let (members, _) = membership::members_from_api(&raw);
    if membership::has_roll_margin(&members, pods) {
        0
    } else {
        replicas
    }
}

/// Resolve a cluster's admin credentials: the bearer token from `adminTokenSecret`
/// and the root anchor(s) from `rootPubkey` (needed to pin the pods' RPK-TLS
/// against the root). `Ok(None)` if either is unset (⇒ the caller reports but does
/// not act). Shared by the membership executor and the Site reconciler.
pub(super) async fn admin_creds(
    client: &Client,
    ns: &str,
    brc: &BoatRampCluster,
) -> Result<Option<(String, Vec<TokenPublicKey>)>> {
    let (Some(secret_name), Some(root)) = (
        brc.spec.admin_token_secret.as_deref(),
        brc.spec.root_pubkey.as_deref(),
    ) else {
        return Ok(None);
    };
    let root = TokenPublicKey::from_hex(root.trim())
        .map_err(|e| Error::Other(format!("invalid spec.rootPubkey: {e}")))?;
    let secrets: Api<Secret> = Api::namespaced(client.clone(), ns);
    let secret = secrets.get(secret_name).await?;
    let token = secret
        .data
        .as_ref()
        .and_then(|d| d.get(TOKEN_KEY))
        .map(|b| String::from_utf8_lossy(&b.0).trim().to_string())
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            Error::Other(format!(
                "admin token Secret {secret_name:?} has no non-empty `{TOKEN_KEY}` key"
            ))
        })?;
    Ok(Some((token, vec![root])))
}

/// A pinned control-plane channel to the cluster's **pod-0** (the stable founder):
/// an RPK-TLS reqwest client authenticated to pod-0's root-attested key, its base
/// URL, and the admin bearer token. `Ok(None)` if the cluster has no admin creds
/// (`adminTokenSecret`/`rootPubkey`) — the caller then reports but does not act.
/// Shared with the `Site` reconciler, which drives the tenant API over the same
/// pinned, root-anchored channel the membership executor uses.
pub(super) async fn pinned_admin_pod0(
    client: &Client,
    ns: &str,
    brc: &BoatRampCluster,
) -> Result<Option<(reqwest::Client, String, String)>> {
    let Some((token, roots)) = admin_creds(client, ns, brc).await? else {
        return Ok(None);
    };
    let api = ClusterApi::pin_pod(brc, ns, 0, &token, &roots).await?;
    Ok(Some((api.http, api.base, api.token)))
}

impl ClusterApi {
    /// Pin pod `ordinal`'s control plane against the root anchor(s) — the same
    /// attestation-pin the joiner uses — so every membership call goes over an
    /// RPK-TLS channel authenticated to that pod's root-signed key.
    async fn pin_pod(
        brc: &BoatRampCluster,
        ns: &str,
        ordinal: u32,
        token: &str,
        roots: &[TokenPublicKey],
    ) -> Result<Self> {
        let base = pod_base(brc, ns, ordinal);
        let http = crate::join::pinned_client(&base, roots, now_unix())
            .await
            .map_err(|e| Error::Other(format!("pin {base}: {e}")))?;
        Ok(ClusterApi {
            http,
            base,
            token: token.to_string(),
        })
    }

    /// The current Raft membership as the cluster reports it.
    async fn members(&self) -> Result<Vec<ApiMember>> {
        #[derive(serde::Deserialize)]
        struct Row {
            node: u64,
            #[serde(default)]
            voter: bool,
            #[serde(default)]
            caught_up: bool,
            #[serde(default)]
            leader: bool,
            #[serde(default)]
            addr: Option<String>,
        }
        let rows: Vec<Row> = self
            .http
            .get(format!("{}/api/cluster/members", self.base))
            .bearer_auth(&self.token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| ApiMember {
                node_id: r.node,
                voter: r.voter,
                caught_up: r.caught_up,
                leader: r.leader,
                addr: r.addr,
            })
            .collect())
    }

    /// Promote a caught-up learner to a voter (leader-only server-side).
    async fn promote(&self, node: u64) -> Result<()> {
        self.http
            .post(format!("{}/api/cluster/promote", self.base))
            .bearer_auth(&self.token)
            .json(&json!({ "node_id": node }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Remove a node from the cluster (revoke trust + drop from quorum).
    async fn remove(&self, node: u64) -> Result<()> {
        self.http
            .post(format!("{}/api/cluster/revoke", self.base))
            .bearer_auth(&self.token)
            .json(&json!({ "node_id": node }))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Mint a fresh single-use bearer join token.
    async fn mint_join_token(&self) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct Resp {
            token: String,
        }
        let resp: Resp = self
            .http
            .post(format!("{}/api/cluster/join-token", self.base))
            .bearer_auth(&self.token)
            .json(&json!({}))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(resp.token)
    }
}

/// Run one executor step: observe the live membership, plan the next quorum-safe
/// transition against `desired`+`pods`, and execute it. Returns the action taken
/// (for status/logging), or `None` if converged / no admin token / awaiting
/// quorum. `root_pubkey` anchors the join ticket the joining pods verify.
pub async fn step(
    client: &Client,
    ns: &str,
    brc: &BoatRampCluster,
    pods: &[membership::PodState],
    root_pubkey: &str,
) -> Result<Option<MembershipAction>> {
    let Some((token, roots)) = admin_creds(client, ns, brc).await? else {
        return Ok(None);
    };
    // Pin pod-0 (the stable founder) to read the live membership + mint tickets.
    let api0 = ClusterApi::pin_pod(brc, ns, 0, &token, &roots).await?;
    let raw = api0.members().await?;
    let (members, ordinal_to_node) = membership::members_from_api(&raw);
    // The current leader's ordinal (membership changes + join admission both run on
    // the leader), defaulting to pod-0 (the founder, and the initial leader).
    let leader_ordinal = raw
        .iter()
        .find(|m| m.leader)
        .and_then(|m| m.addr.as_deref())
        .and_then(membership::ordinal_from_addr)
        .unwrap_or(0);

    // Keep a fresh single-use join ticket in the `<name>-join` Secret whenever the
    // cluster has fewer members than desired, so a booting joiner pod can self-join
    // (it reads the ticket from `BOATRAMP_CLUSTER_JOIN` at startup and redeems it —
    // the seed's `admit` adds it as a Raft learner server-side). This is proactive,
    // not gated on the planner's `AddLearner`: a joiner is never "ready but not a
    // member" (it joins at startup, before serving), so the ticket must be present
    // *before* it can boot. The token is single-use, so we refresh each reconcile;
    // a crash-looping joiner picks up the current ticket on its next restart
    // (one-at-a-time convergence — a lost race self-heals on the next reconcile).
    if (members.len() as u32) < brc.spec.replicas {
        let ticket_token = api0.mint_join_token().await?;
        // Redeem against the leader (join admission runs there); every pod serves
        // its own root-signed attestation, so the joiner can pin whichever we name.
        let seed = pod_base(brc, ns, leader_ordinal);
        let ticket = crate::join::JoinTicket {
            seeds: vec![seed],
            root_pubkeys: vec![root_pubkey.to_string()],
            token: ticket_token,
        }
        .encode()
        .map_err(|e| Error::Other(e.to_string()))?;
        store_join_ticket(client, ns, brc, &ticket).await?;
    }

    let Some(action) = membership::plan_next(brc.spec.replicas, pods, &members) else {
        return Ok(None);
    };
    match action {
        MembershipAction::PromoteToVoter { .. } | MembershipAction::Remove { .. } => {
            let Some(node) = membership::action_node_id(&action, &ordinal_to_node) else {
                return Ok(Some(action));
            };
            // Promote/remove are leader-only server-side: pin the leader's pod,
            // falling back to pod-0 (which forwards / the next reconcile retries).
            let leader = if leader_ordinal == 0 {
                api0
            } else {
                ClusterApi::pin_pod(brc, ns, leader_ordinal, &token, &roots).await?
            };
            match action {
                MembershipAction::PromoteToVoter { .. } => leader.promote(node).await?,
                MembershipAction::Remove { .. } => leader.remove(node).await?,
                MembershipAction::AddLearner { .. } => unreachable!(),
            }
        }
        // A new pod self-joins with the ticket refreshed above; nothing to do here.
        MembershipAction::AddLearner { .. } => {}
    }
    Ok(Some(action))
}

/// Upsert the rolling join Secret with a fresh ticket (server-side apply).
async fn store_join_ticket(
    client: &Client,
    ns: &str,
    brc: &BoatRampCluster,
    ticket: &str,
) -> Result<()> {
    let name = join_secret_name(brc);
    let secret = json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": { "name": name, "namespace": ns },
        "type": "Opaque",
        "stringData": { JOIN_KEY: ticket },
    });
    let api: Api<Secret> = Api::namespaced(client.clone(), ns);
    api.patch(
        &name,
        &PatchParams::apply("boatramp-operator").force(),
        &Patch::Apply(&secret),
    )
    .await?;
    Ok(())
}

/// The `(secret, key)` a joining pod's `BOATRAMP_CLUSTER_JOIN` env reads.
pub fn join_env_source(brc: &BoatRampCluster) -> (String, &'static str) {
    (join_secret_name(brc), JOIN_KEY)
}
