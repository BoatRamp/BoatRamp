//! The controller entrypoint (`boatramp operator run`).
//!
//! K1 is a **skeleton**: it connects to the API server, watches
//! [`BoatRampCluster`], and runs a no-op reconcile loop that requeues. The actual
//! reconcilers — workloads (K2) and the Raft **membership** state machine (K3, the
//! mandatory core) — slot into [`reconcile`] without changing this wiring.

use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use kube::runtime::controller::Action;
use kube::runtime::{watcher, Controller};
use kube::{Api, Client};

use super::crd::BoatRampCluster;
use super::{Error, Result};

/// `operator run` flags.
#[derive(Debug, clap::Args)]
pub struct RunArgs {
    /// Namespace to watch. Omit to watch all namespaces (cluster-scoped operator).
    #[arg(long, env = "BOATRAMP_OPERATOR_NAMESPACE")]
    namespace: Option<String>,
}

/// Shared reconcile context (the API client; reconcilers add their handles here).
struct Ctx {
    #[allow(dead_code)] // used by the K2/K3 reconcilers.
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

    // Fail fast with a clear message if the CRDs aren't installed yet, rather than
    // looping on watch errors.
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

/// Reconcile one `BoatRampCluster`. K1: a no-op that requeues — the workload (K2)
/// and membership (K3) logic lands here.
async fn reconcile(obj: Arc<BoatRampCluster>, _ctx: Arc<Ctx>) -> Result<Action> {
    tracing::debug!(
        name = obj.metadata.name.as_deref().unwrap_or("<unnamed>"),
        "reconcile (K1 no-op)"
    );
    Ok(Action::requeue(Duration::from_secs(300)))
}

/// Requeue after a back-off when a reconcile fails.
fn error_policy(_obj: Arc<BoatRampCluster>, err: &Error, _ctx: Arc<Ctx>) -> Action {
    tracing::warn!(%err, "reconcile failed; backing off");
    Action::requeue(Duration::from_secs(30))
}
