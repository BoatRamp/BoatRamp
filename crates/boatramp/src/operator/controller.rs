//! The controller entrypoint (`boatramp operator run`) + the `BoatRampCluster`
//! reconciler.
//!
//! K2: reconcile a `BoatRampCluster` into its owned workloads via **server-side
//! apply** (idempotent, ownership-tracked). K3 adds the Raft **membership** state
//! machine (join → learner → voter; demote + remove before delete) on top of this
//! same loop.

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::core::v1::{ConfigMap, Service};
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::{watcher, Controller};
use kube::{Client, Resource};
use serde::de::DeserializeOwned;
use serde::Serialize;

use super::crd::{BoatRampCluster, BoatRampClusterStatus, ClusterMode};
use super::{resources, Error, Result};

/// The server-side-apply field manager: the operator owns the fields it sets.
const FIELD_MANAGER: &str = "boatramp-operator";

/// `operator run` flags.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Namespace to watch. Omit to watch all namespaces (cluster-scoped operator).
    #[arg(long, env = "BOATRAMP_OPERATOR_NAMESPACE")]
    namespace: Option<String>,
}

/// Shared reconcile context.
struct Ctx {
    client: Client,
}

/// Run the controller until the process is signalled.
pub async fn run(args: RunArgs) -> Result<()> {
    // In-cluster config (a mounted ServiceAccount) or a local kubeconfig — kube
    // picks whichever is present, so the same binary runs in-cluster and locally.
    let client = Client::try_default().await?;
    let clusters: Api<BoatRampCluster> = match &args.namespace {
        Some(ns) => Api::namespaced(client.clone(), ns),
        None => Api::all(client.clone()),
    };

    // Fail fast with a clear message if the CRDs aren't installed yet.
    if let Err(err) = clusters.list(&Default::default()).await {
        return Err(Error::Other(format!(
            "cannot list BoatRampCluster — are the CRDs installed? \
             (`boatramp operator crds | kubectl apply -f -`): {err}"
        )));
    }

    tracing::info!(
        namespace = args.namespace.as_deref().unwrap_or("<all>"),
        "boatramp operator started — watching BoatRampCluster"
    );
    // TODO(K3): operator leader election (a coordination.k8s.io Lease) so an HA
    // multi-replica operator has a single active reconciler. Single-replica is the
    // default and correct until then.
    Controller::new(clusters, watcher::Config::default())
        .run(reconcile, error_policy, Arc::new(Ctx { client }))
        .for_each(|res| async move {
            match res {
                Ok(o) => tracing::debug!(?o, "reconciled"),
                Err(err) => tracing::warn!(%err, "reconcile loop error"),
            }
        })
        .await;
    Ok(())
}

/// Reconcile one `BoatRampCluster` into its owned workloads.
async fn reconcile(brc: Arc<BoatRampCluster>, ctx: Arc<Ctx>) -> Result<Action> {
    let ns = brc
        .metadata
        .namespace
        .clone()
        .ok_or_else(|| Error::Other("BoatRampCluster has no namespace".into()))?;
    let name = brc
        .metadata
        .name
        .clone()
        .ok_or_else(|| Error::Other("BoatRampCluster has no name".into()))?;
    let client = &ctx.client;
    tracing::info!(%ns, %name, mode = ?brc.spec.mode, "reconciling BoatRampCluster");

    // Config + the client Service are applied in both modes.
    apply(
        &Api::<ConfigMap>::namespaced(client.clone(), &ns),
        &resources::config_map(&brc),
    )
    .await?;
    apply(
        &Api::<Service>::namespaced(client.clone(), &ns),
        &resources::client_service(&brc),
    )
    .await?;

    match brc.spec.mode {
        ClusterMode::Cluster => {
            apply(
                &Api::<Service>::namespaced(client.clone(), &ns),
                &resources::headless_service(&brc),
            )
            .await?;
            apply(
                &Api::<StatefulSet>::namespaced(client.clone(), &ns),
                &resources::stateful_set(&brc),
            )
            .await?;
            apply(
                &Api::<PodDisruptionBudget>::namespaced(client.clone(), &ns),
                &resources::pod_disruption_budget(&brc),
            )
            .await?;
        }
        ClusterMode::Stateless => {
            apply(
                &Api::<Deployment>::namespaced(client.clone(), &ns),
                &resources::deployment(&brc),
            )
            .await?;
            apply(
                &Api::<HorizontalPodAutoscaler>::namespaced(client.clone(), &ns),
                &resources::hpa(&brc),
            )
            .await?;
        }
    }

    // K2 records that the workloads are applied; K3 computes real membership +
    // quorum + readiness from the live pods.
    update_status(&Api::<BoatRampCluster>::namespaced(client.clone(), &ns), &name, &brc).await?;

    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Server-side-apply a child object (idempotent; the operator owns its fields).
async fn apply<K>(api: &Api<K>, obj: &K) -> Result<()>
where
    K: Resource + Serialize + DeserializeOwned + Clone + Debug,
    K::DynamicType: Default,
{
    let name = obj
        .meta()
        .name
        .clone()
        .ok_or_else(|| Error::Other("child object has no name".into()))?;
    api.patch(
        &name,
        &PatchParams::apply(FIELD_MANAGER).force(),
        &Patch::Apply(obj),
    )
    .await?;
    Ok(())
}

/// Record the reconcile in the CR's `.status` subresource.
async fn update_status(api: &Api<BoatRampCluster>, name: &str, brc: &BoatRampCluster) -> Result<()> {
    let status = BoatRampClusterStatus {
        phase: Some("Reconciling".to_string()),
        observed_generation: brc.metadata.generation,
        ..Default::default()
    };
    api.patch_status(
        name,
        &PatchParams::default(),
        &Patch::Merge(serde_json::json!({ "status": status })),
    )
    .await?;
    Ok(())
}

/// Requeue after a back-off when a reconcile fails.
fn error_policy(_obj: Arc<BoatRampCluster>, err: &Error, _ctx: Arc<Ctx>) -> Action {
    tracing::warn!(%err, "reconcile failed; backing off");
    Action::requeue(Duration::from_secs(30))
}
