//! In-binary **Kubernetes operator** (`boatramp operator …`).
//!
//! The operator lives in the `boatramp` binary — like every other backend — behind
//! the `operator` feature, built on `kube-rs`. The same image that serves also
//! operates: `operator run` is the controller, `operator crds` / `operator
//! manifests` emit the install YAML from the single-sourced CRD types. See
//! `../../boatramp-roadmap/plans/PLAN-kubernetes.md`.
//!
//! K1 (this): the skeleton — the subcommand, the CRD types, the manifest emitters,
//! and a no-op reconcile loop. Workload reconciliation (K2) and the Raft
//! **membership** state machine (K3, the mandatory core) build on this seam.

mod controller;
mod crd;
mod executor;
mod manifests;
mod membership;
mod resources;

use clap::Subcommand;

/// A failure in the `operator` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A Kubernetes API error.
    #[error("kubernetes: {0}")]
    Kube(#[from] kube::Error),
    /// Serializing a manifest to YAML failed.
    #[error("manifest: {0}")]
    Yaml(#[from] serde_yaml::Error),
    /// An HTTP call to the cluster control-plane API (membership executor) failed.
    #[error("cluster api: {0}")]
    Http(#[from] reqwest::Error),
    /// Any other operator failure (a legible message).
    #[error("operator: {0}")]
    Other(String),
}

/// `operator` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp operator`.
#[derive(Debug, clap::Args)]
pub struct OperatorArgs {
    #[command(subcommand)]
    command: OperatorCommand,
}

#[derive(Debug, Subcommand)]
enum OperatorCommand {
    /// Run the controller: watch the boatramp CRDs and reconcile them.
    Run(controller::RunArgs),
    /// Print the CustomResourceDefinition YAML (single-sourced from the Rust types).
    Crds,
    /// Print the full install bundle: CRDs + least-privilege RBAC + the operator
    /// Deployment (`operator manifests | kubectl apply -f -`).
    Manifests(manifests::ManifestArgs),
}

/// Entry point for `boatramp operator`.
pub async fn run(args: OperatorArgs) -> Result<()> {
    match args.command {
        OperatorCommand::Run(a) => controller::run(a).await,
        OperatorCommand::Crds => manifests::print_crds(),
        OperatorCommand::Manifests(a) => manifests::print_manifests(&a),
    }
}
