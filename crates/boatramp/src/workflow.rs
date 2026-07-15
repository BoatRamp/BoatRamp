//! The `workflow` subcommand — the FaaS **orchestration** surface (PLAN-faas FA-6).
//!
//! A workflow is a small DAG of function-invocation steps. `workflow define`
//! uploads the step DAG (validated server-side), `run` starts a durable run the
//! executor advances, and `run-status` polls it.

use serde::Deserialize;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `workflow` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum WorkflowError {
    /// Resolving the target or a control-plane call failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A control-plane HTTP request failed.
    #[error("control-plane request: {0}")]
    Http(#[from] reqwest::Error),
    /// Reading or parsing the steps file failed.
    #[error("reading steps file: {0}")]
    Io(#[from] std::io::Error),
    /// The steps file was not valid JSON.
    #[error("steps file is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, WorkflowError>;

/// `workflow` — define + run declarative function workflows.
#[derive(Debug, clap::Args)]
pub struct WorkflowArgs {
    #[command(subcommand)]
    command: WorkflowCommand,
}

#[derive(Debug, clap::Subcommand)]
enum WorkflowCommand {
    /// Define/replace a workflow from a JSON file of steps (an array, or an
    /// object with a `steps` array).
    Define {
        /// Workflow name.
        name: String,
        /// Path to the steps JSON (`-` = stdin).
        #[arg(long)]
        file: std::path::PathBuf,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// List defined workflows.
    Ls {
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// Show a workflow definition.
    Get {
        /// Workflow name.
        name: String,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// Start a run (optionally with an input body) and print its id.
    Run {
        /// Workflow name.
        name: String,
        /// Inline run input (delivered to the root steps).
        #[arg(long)]
        data: Option<String>,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// Show a run's status + per-step state.
    RunStatus {
        /// Workflow name.
        name: String,
        /// The run id from `workflow run`.
        id: String,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// Remove a workflow definition.
    Rm {
        /// Workflow name.
        name: String,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
}

/// A workflow definition as the server reports it (name + step ids for display).
#[derive(Debug, Deserialize)]
struct WorkflowView {
    name: String,
    #[serde(default)]
    steps: Vec<StepView>,
}

#[derive(Debug, Deserialize)]
struct StepView {
    id: String,
    function: String,
    #[serde(default)]
    depends_on: Vec<String>,
}

/// A run record as the server reports it (id + status + per-step state).
#[derive(Debug, Deserialize)]
struct RunView {
    id: String,
    status: String,
    #[serde(default)]
    steps: std::collections::BTreeMap<String, StepRunView>,
}

#[derive(Debug, Deserialize)]
struct StepRunView {
    status: String,
    #[serde(default)]
    attempts: u32,
}

/// Run the `workflow` subcommand.
pub async fn run(args: WorkflowArgs, config: &ProjectConfig) -> Result<()> {
    match args.command {
        WorkflowCommand::Define { name, file, server } => {
            let (server, http) = conn(server, config)?;
            let raw = read_file(&file).await?;
            // Accept a bare steps array or a `{ "steps": [...] }` object.
            let value: serde_json::Value = serde_json::from_slice(&raw)?;
            let body = match value {
                serde_json::Value::Array(_) => serde_json::json!({ "steps": value }),
                other => other,
            };
            http.put(format!("{server}/api/workflows/{name}"))
                .json(&body)
                .send()
                .await?
                .error_for_status()?;
            println!("defined workflow {name}");
        }
        WorkflowCommand::Ls { server } => {
            let (server, http) = conn(server, config)?;
            let list: Vec<WorkflowView> = http
                .get(format!("{server}/api/workflows"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if list.is_empty() {
                println!("no workflows");
                return Ok(());
            }
            for w in list {
                println!("{}  ({} steps)", w.name, w.steps.len());
            }
        }
        WorkflowCommand::Get { name, server } => {
            let (server, http) = conn(server, config)?;
            let w: WorkflowView = http
                .get(format!("{server}/api/workflows/{name}"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", w.name);
            for s in &w.steps {
                if s.depends_on.is_empty() {
                    println!("  {} -> {}", s.id, s.function);
                } else {
                    println!(
                        "  {} -> {}  (after {})",
                        s.id,
                        s.function,
                        s.depends_on.join(", ")
                    );
                }
            }
        }
        WorkflowCommand::Run { name, data, server } => {
            let (server, http) = conn(server, config)?;
            let mut req = http.post(format!("{server}/api/workflows/{name}/runs"));
            if let Some(input) = data {
                req = req.body(input.into_bytes());
            }
            let run: RunView = req.send().await?.error_for_status()?.json().await?;
            println!("started run {} [{}]", run.id, run.status);
        }
        WorkflowCommand::RunStatus { name, id, server } => {
            let (server, http) = conn(server, config)?;
            let run: RunView = http
                .get(format!("{server}/api/workflows/{name}/runs/{id}"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}  [{}]", run.id, run.status);
            for (step_id, sr) in &run.steps {
                println!("  {step_id}: {} (attempts={})", sr.status, sr.attempts);
            }
        }
        WorkflowCommand::Rm { name, server } => {
            let (server, http) = conn(server, config)?;
            http.delete(format!("{server}/api/workflows/{name}"))
                .send()
                .await?
                .error_for_status()?;
            println!("removed workflow {name}");
        }
    }
    Ok(())
}

/// Resolve the server + an authenticated client (the shared preamble).
fn conn(server: Option<String>, config: &ProjectConfig) -> Result<(String, client::ApiClient)> {
    let server = client::resolve_server(server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    Ok((server, http))
}

/// Read a steps file (`-` = stdin).
async fn read_file(path: &std::path::Path) -> Result<Vec<u8>> {
    if path.as_os_str() == "-" {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        tokio::io::stdin().read_to_end(&mut buf).await?;
        Ok(buf)
    } else {
        Ok(tokio::fs::read(path).await?)
    }
}
