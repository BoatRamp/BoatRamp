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
mod function;
mod manifests;
mod membership;
mod resources;
mod site;

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
    /// Serializing a manifest through JSON (the CRD emit round-trip) failed.
    #[error("manifest json: {0}")]
    Json(#[from] serde_json::Error),
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

/// The result of an `operator` subcommand, rendered by [`crate::output`].
///
/// The manifest emitters (`crds` / `manifests`) are **DATA**: the human view
/// writes their YAML byte-for-byte (so `operator crds | kubectl apply -f -` keeps
/// working), while `--output-format json` emits the parsed documents as a JSON
/// array. `operator run` is the long-running controller; it reports via `tracing`
/// and has no stdout result.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum OperatorOutput {
    /// `operator run` — the controller ran until the process was signalled.
    Ran,
    /// `operator crds` — the CustomResourceDefinition YAML document stream.
    Crds {
        /// Parsed documents, for `--output-format json`.
        documents: Vec<serde_json::Value>,
        /// The exact YAML the human view prints.
        #[serde(skip)]
        yaml: String,
    },
    /// `operator manifests` — the full install bundle YAML document stream.
    Manifests {
        documents: Vec<serde_json::Value>,
        #[serde(skip)]
        yaml: String,
    },
}

impl crate::output::Rendered for OperatorOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            // The controller logs via `tracing`; it has no stdout result.
            Self::Ran => Ok(()),
            // Byte-for-byte YAML (the emitters used `print!`, no trailing newline added).
            Self::Crds { yaml, .. } | Self::Manifests { yaml, .. } => {
                write!(w, "{yaml}")
            }
        }
    }
}

/// Parse a multi-document YAML stream (`---`-separated) into a JSON array — one
/// element per document — for the `--output-format json` rendering of the manifest
/// emitters. The manifests are serde-clean (string keys only), so the round-trip
/// is lossless.
fn yaml_documents(yaml: &str) -> Vec<serde_json::Value> {
    use serde::Deserialize as _;
    serde_yaml::Deserializer::from_str(yaml)
        .filter_map(|doc| serde_yaml::Value::deserialize(doc).ok())
        .filter_map(|value| serde_json::to_value(value).ok())
        .collect()
}

/// Entry point for `boatramp operator`.
pub async fn run(args: OperatorArgs) -> Result<OperatorOutput> {
    match args.command {
        OperatorCommand::Run(a) => {
            // The controller is a long-running reconcile loop; it returns only when
            // the process is signalled, reporting progress via `tracing`.
            controller::run(a).await?;
            Ok(OperatorOutput::Ran)
        }
        OperatorCommand::Crds => {
            let yaml = manifests::crds_yaml()?;
            let documents = yaml_documents(&yaml);
            Ok(OperatorOutput::Crds { documents, yaml })
        }
        OperatorCommand::Manifests(a) => {
            let yaml = manifests::manifests_yaml(&a)?;
            let documents = yaml_documents(&yaml);
            Ok(OperatorOutput::Manifests { documents, yaml })
        }
    }
}
