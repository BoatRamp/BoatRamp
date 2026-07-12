//! K3b — the operator's **membership executor**: drives the quorum-safe planner
//! ([`super::membership::plan_next`]) against the cluster's control-plane API.
//!
//! Each reconcile the operator fetches the live Raft membership
//! (`GET /api/cluster/members`), maps it onto StatefulSet ordinals (keeping the
//! ordinal↔node_id map — #2), plans the single next transition, and executes it:
//!
//! - **PromoteToVoter** → `POST /api/cluster/promote {node}` (by node id).
//! - **Remove** → `POST /api/cluster/revoke {node_id}` (by node id).
//! - **AddLearner** → a new pod **self-joins** with a ticket; the operator mints a
//!   fresh single-use ticket and stores it in the join Secret the joining pods
//!   read as `BOATRAMP_CLUSTER_JOIN`. One-at-a-time (the planner's invariant), so
//!   one rolling ticket suffices; a lost race self-heals on the next reconcile.
//!
//! Reaching the cluster needs an admin token (`spec.adminTokenSecret`); without
//! one the operator only plans + reports (the caller falls back).

use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use serde_json::json;

use super::crd::BoatRampCluster;
use super::membership::{self, ApiMember, MembershipAction};
use super::{resources, Error, Result};

/// The control-plane port the client Service exposes (matches `resources::PORT`).
const CONTROL_PLANE_PORT: u16 = 8080;

/// The key holding the admin token in `spec.adminTokenSecret`.
const TOKEN_KEY: &str = "token";

/// The join Secret + key a joining pod reads as `BOATRAMP_CLUSTER_JOIN`.
fn join_secret_name(brc: &BoatRampCluster) -> String {
    format!("{}-join", resources::instance(brc))
}
const JOIN_KEY: &str = "ticket";

/// A live cluster-API client: the in-cluster base URL + the admin bearer token.
struct ClusterApi {
    http: reqwest::Client,
    base: String,
    token: String,
}

impl ClusterApi {
    /// Build the API client from the CR's admin-token Secret. `Ok(None)` if no
    /// `adminTokenSecret` is set (⇒ the operator plans but does not execute).
    async fn connect(
        client: &Client,
        ns: &str,
        brc: &BoatRampCluster,
    ) -> Result<Option<Self>> {
        let Some(secret_name) = brc.spec.admin_token_secret.as_deref() else {
            return Ok(None);
        };
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
        // In-cluster HTTP to the client Service (stable DNS). Membership APIs are
        // admin-token-gated; the mesh's own transport TLS is separate.
        let base = format!(
            "http://{}.{ns}.svc:{CONTROL_PLANE_PORT}",
            resources::instance(brc)
        );
        Ok(Some(ClusterApi {
            http: reqwest::Client::new(),
            base,
            token,
        }))
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
                addr: r.addr,
            })
            .collect())
    }

    /// Promote a caught-up learner to a voter (leader-only server-side).
    async fn promote(&self, node: u64) -> Result<()> {
        self.http
            .post(format!("{}/api/cluster/promote", self.base))
            .bearer_auth(&self.token)
            .json(&json!({ "node": node }))
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
    let Some(api) = ClusterApi::connect(client, ns, brc).await? else {
        return Ok(None);
    };
    let (members, ordinal_to_node) = membership::members_from_api(&api.members().await?);
    let Some(action) = membership::plan_next(brc.spec.replicas, pods, &members) else {
        return Ok(None);
    };
    match action {
        MembershipAction::PromoteToVoter { .. } => {
            if let Some(node) = membership::action_node_id(&action, &ordinal_to_node) {
                api.promote(node).await?;
            }
        }
        MembershipAction::Remove { .. } => {
            if let Some(node) = membership::action_node_id(&action, &ordinal_to_node) {
                api.remove(node).await?;
            }
        }
        MembershipAction::AddLearner { .. } => {
            // The pod self-joins: mint a fresh ticket + refresh the join Secret it
            // reads. One-at-a-time, so one rolling ticket is enough.
            let token = api.mint_join_token().await?;
            let seed = format!(
                "https://{}.{ns}.svc:{CONTROL_PLANE_PORT}",
                resources::instance(brc)
            );
            let ticket = crate::join::JoinTicket {
                seeds: vec![seed],
                root_pubkeys: vec![root_pubkey.to_string()],
                token,
            }
            .encode()
            .map_err(|e| Error::Other(e.to_string()))?;
            store_join_ticket(client, ns, brc, &ticket).await?;
        }
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
