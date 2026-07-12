//! K5 — the **`Function` reconciler**. `Function` is the Kubernetes surface of the
//! FaaS plan (`PLAN-faas` FA-1..FA-3): a wasm component published as a route. That
//! functions control-plane API is **not yet built**, so this reconciler is honest
//! about it — it watches `Function` resources and reports a clear `Pending` status
//! rather than silently doing nothing (or pretending to deploy). Once the FaaS
//! backend lands, `reconcile` gains its apply path (PUT the component + route to
//! the cluster, a finalizer to remove it) mirroring the `Site` reconciler.

use std::sync::Arc;
use std::time::Duration;

use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, ResourceExt};
use serde_json::json;

use super::crd::{Function, FunctionStatus};
use super::{Error, Result};

/// The status message surfaced until the FaaS backend exists.
const PENDING: &str = "Pending: the FaaS backend (functions API) is not yet available";

/// Shared reconcile context.
pub struct Ctx {
    pub client: Client,
}

/// Reconcile one `Function`: report the honest pending status. Requeues slowly.
pub async fn reconcile(func: Arc<Function>, ctx: Arc<Ctx>) -> Result<Action> {
    let ns = func.namespace().unwrap_or_else(|| "default".to_string());
    let name = func.name_any();
    let api: Api<Function> = Api::namespaced(ctx.client.clone(), &ns);
    let status = json!({ "status": FunctionStatus { phase: Some(PENDING.to_string()) } });
    api.patch_status(&name, &PatchParams::default(), &Patch::Merge(&status))
        .await
        .map_err(|e| Error::Other(format!("function status: {e}")))?;
    tracing::debug!(function = %name, "function reconcile: awaiting FaaS backend");
    Ok(Action::requeue(Duration::from_secs(3600)))
}
