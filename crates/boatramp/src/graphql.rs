//! The `graphql` subcommand: manage a project's GraphQL admin surface — the
//! persisted-operation **safelist** (register/list/remove trusted operations) and the
//! federation **subgraphs** (publish an SDL / SQL / function subgraph, remove one, and
//! read the composed supergraph). Project-scoped over the control-plane API — the same
//! endpoints `graphql.md` previously documented with `curl`.

use std::path::PathBuf;

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `graphql` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A request to the GraphQL admin API failed.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// Reading a `--sdl`/`--file`/`--query-file` input failed.
    #[error("reading {0}: {1}")]
    Io(String, #[source] std::io::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp graphql`.
#[derive(Debug, clap::Args)]
pub struct GraphqlArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: GraphqlCommand,
}

#[derive(Debug, Subcommand)]
enum GraphqlCommand {
    /// Manage the persisted-operation safelist (trusted-operation allowlist).
    Safelist {
        #[command(subcommand)]
        command: SafelistCommand,
    },
    /// Manage federation subgraphs.
    Subgraph {
        #[command(subcommand)]
        command: SubgraphCommand,
    },
    /// Print the composed supergraph SDL.
    Supergraph,
}

#[derive(Debug, Subcommand)]
enum SafelistCommand {
    /// Register a trusted operation. Give the query inline or with `--file`.
    Add {
        /// The GraphQL operation text (omit to read from `--file`).
        query: Option<String>,
        /// Read the operation from a file instead of an argument.
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// List the registered trusted operations.
    List,
    /// Remove a trusted operation by its hash.
    Rm {
        /// The operation hash (as returned by `add`/`list`).
        hash: String,
    },
}

#[derive(Debug, Subcommand)]
enum SubgraphCommand {
    /// Publish (or replace) a Wasm subgraph from its SDL file.
    Put {
        /// Subgraph name.
        name: String,
        /// Path to the subgraph's SDL.
        #[arg(long)]
        sdl: PathBuf,
    },
    /// Publish (or replace) a SQL subgraph from a request JSON file (`{site, config}`).
    Sql {
        /// Subgraph name.
        name: String,
        /// Path to the JSON request body.
        #[arg(long)]
        file: PathBuf,
    },
    /// Register (or refresh) a function subgraph by introspecting the deployed
    /// function of the same name — no SDL, no body.
    Function {
        /// Subgraph / function name.
        name: String,
    },
    /// Remove a subgraph.
    Rm {
        /// Subgraph name.
        name: String,
    },
}

/// Entry point for `boatramp graphql`.
pub async fn run(args: GraphqlArgs, config: &ProjectConfig) -> Result<()> {
    let server = client::resolve_server(args.server, config)?;
    let project = client::resolve_project(config);
    let seg = client::project_seg(&project, "graphql");
    let http = client::http_client(client::token(config).as_deref());
    let base = format!("{server}/api/{seg}");

    match args.command {
        GraphqlCommand::Safelist { command } => match command {
            SafelistCommand::Add { query, file } => {
                let query = read_input(query, file)?;
                let resp = http
                    .post(format!("{base}/safelist"))
                    .json(&serde_json::json!({ "query": query }))
                    .send()
                    .await?
                    .error_for_status()?;
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                let hash = body
                    .get("hash")
                    .and_then(|h| h.as_str())
                    .unwrap_or("(registered)");
                println!("safelisted operation: {hash}");
            }
            SafelistCommand::List => {
                let body: serde_json::Value = http
                    .get(format!("{base}/safelist"))
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
                    .await
                    .unwrap_or_default();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
            }
            SafelistCommand::Rm { hash } => {
                http.delete(format!("{base}/safelist/{hash}"))
                    .send()
                    .await?
                    .error_for_status()?;
                println!("removed safelisted operation {hash}");
            }
        },
        GraphqlCommand::Subgraph { command } => match command {
            SubgraphCommand::Put { name, sdl } => {
                let body = read_file(&sdl)?;
                http.put(format!("{base}/subgraphs/{name}"))
                    .header("content-type", "text/plain")
                    .body(body)
                    .send()
                    .await?
                    .error_for_status()?;
                println!("published subgraph {name}");
            }
            SubgraphCommand::Sql { name, file } => {
                put_json_subgraph(&http, &base, &name, "sql", &file).await?;
            }
            SubgraphCommand::Function { name } => {
                http.put(format!("{base}/subgraphs/{name}/function"))
                    .send()
                    .await?
                    .error_for_status()?;
                println!("registered function subgraph {name}");
            }
            SubgraphCommand::Rm { name } => {
                http.delete(format!("{base}/subgraphs/{name}"))
                    .send()
                    .await?
                    .error_for_status()?;
                println!("removed subgraph {name}");
            }
        },
        GraphqlCommand::Supergraph => {
            let text = http
                .get(format!("{base}/supergraph"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            println!("{text}");
        }
    }
    Ok(())
}

/// PUT a JSON-bodied subgraph (`sql` / `function`) from a request file.
async fn put_json_subgraph(
    http: &client::ApiClient,
    base: &str,
    name: &str,
    kind: &str,
    file: &std::path::Path,
) -> Result<()> {
    let raw = read_file(file)?;
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
        Error::Io(
            file.display().to_string(),
            std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        )
    })?;
    http.put(format!("{base}/subgraphs/{name}/{kind}"))
        .json(&value)
        .send()
        .await?
        .error_for_status()?;
    println!("published {kind} subgraph {name}");
    Ok(())
}

/// Resolve a query given inline text or a `--file`.
fn read_input(inline: Option<String>, file: Option<PathBuf>) -> Result<String> {
    match (inline, file) {
        (Some(q), _) => Ok(q),
        (None, Some(path)) => read_file(&path),
        (None, None) => Ok(String::new()),
    }
}

/// Read a file, tagging the path into the error.
fn read_file(path: &std::path::Path) -> Result<String> {
    std::fs::read_to_string(path).map_err(|e| Error::Io(path.display().to_string(), e))
}
