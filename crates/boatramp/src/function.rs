//! The `function` subcommand — the FaaS **function** surface (PLAN-faas).
//!
//! FA-1 shipped the read view: list/show the derived site-scoped functions a site's
//! handlers/consumers/crons desugar to. FA-2 adds the write view for **top-level**
//! functions — `deploy` a component version, `rollback`, `alias`, and `rm` — each
//! carrying its own independent version line. `function invoke` lands in FA-3.

use serde::Deserialize;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `function` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum FunctionError {
    /// Resolving the target or a control-plane call failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A control-plane HTTP request failed.
    #[error("control-plane request: {0}")]
    Http(#[from] reqwest::Error),
    /// Reading the invoke request body (a file or stdin) failed.
    #[error("reading request body: {0}")]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, FunctionError>;

/// `function` — inspect the functions a site runs.
#[derive(Debug, clap::Args)]
pub struct FunctionArgs {
    #[command(subcommand)]
    command: FunctionCommand,
}

#[derive(Debug, clap::Subcommand)]
enum FunctionCommand {
    /// List functions (optionally for one site).
    Ls {
        /// Only this site.
        #[arg(long)]
        site: Option<String>,
        /// Server base URL (overrides config/env).
        #[arg(long)]
        server: Option<String>,
    },
    /// Show one function by its `<site>/<name>`.
    Get {
        /// The `<site>/<name>` shown by `function ls`.
        name: String,
        /// Server base URL (overrides config/env).
        #[arg(long)]
        server: Option<String>,
    },
    /// Deploy a version of a top-level function from a component `.wasm`.
    Deploy {
        /// Function name.
        name: String,
        /// Path to the component `.wasm` (uploaded as a content-addressed blob).
        #[arg(long)]
        component: std::path::PathBuf,
        /// Execution substrate: `wasm` (default), `microvm`, or `container`.
        #[arg(long)]
        runtime: Option<String>,
        /// Enable a signed webhook: the host env var holding the HMAC-SHA256
        /// verifying secret (never the secret itself).
        #[arg(long)]
        webhook_secret_env: Option<String>,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// Roll a function's active version back to `--to <version>`.
    Rollback {
        /// Function name.
        name: String,
        /// The version id to activate.
        #[arg(long)]
        to: String,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// Point an alias label at a version.
    Alias {
        /// Function name.
        name: String,
        /// The alias label (e.g. `prod`, `staging`).
        label: String,
        /// The version id the alias points at.
        version: String,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// Remove a top-level function.
    Rm {
        /// Function name.
        name: String,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// Invoke a function. Reads the request body from `--data`, `--data-file`, or
    /// stdin; prints the function's response body.
    Invoke {
        /// Function name.
        name: String,
        /// Inline request body (mutually exclusive with `--data-file`).
        #[arg(long, conflicts_with = "data_file")]
        data: Option<String>,
        /// Read the request body from this file (`-` = stdin).
        #[arg(long)]
        data_file: Option<std::path::PathBuf>,
        /// Content type of the request body.
        #[arg(long)]
        content_type: Option<String>,
        /// Deliver asynchronously: enqueue + print the invocation id to poll.
        #[arg(long)]
        r#async: bool,
        /// Idempotency key — a repeat with the same key replays the first outcome.
        #[arg(long)]
        idempotency_key: Option<String>,
        /// Invoke a specific version/alias instead of the active version.
        #[arg(long)]
        version: Option<String>,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// Show a durable (async) invocation's status/result by id.
    Invocation {
        /// Function name.
        name: String,
        /// The invocation id from `function invoke --async`.
        id: String,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// Show a function's usage aggregate (invocations, duration, bytes).
    Usage {
        /// Function name.
        name: String,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
}

/// A function as the server's `/api/functions` view reports it.
#[derive(Debug, Deserialize)]
struct FunctionSummary {
    name: String,
    runtime: String,
    version: String,
    triggers: Vec<String>,
}

/// The stored `Function` a mutating call (`deploy`/`rollback`) echoes back — the
/// full record, of which we only surface the name, active version, and runtime.
#[derive(Debug, Deserialize)]
struct StoredFunction {
    name: String,
    active: String,
    #[serde(default)]
    config: StoredConfig,
}

#[derive(Debug, Default, Deserialize)]
struct StoredConfig {
    #[serde(default)]
    runtime: String,
}

/// A durable invocation record as `/invoke` (async) and `/invocations/:id`
/// report it — the fields the CLI surfaces.
#[derive(Debug, Deserialize)]
struct InvocationRecord {
    id: String,
    status: String,
    #[serde(default)]
    attempts: u32,
    #[serde(default)]
    result: Option<InvocationResultView>,
}

#[derive(Debug, Deserialize)]
struct InvocationResultView {
    status: u16,
}

/// A function's usage aggregate as `/usage` reports it (FA-4).
#[derive(Debug, Default, Deserialize)]
struct UsageView {
    function: String,
    #[serde(default)]
    invocations: u64,
    #[serde(default)]
    successes: u64,
    #[serde(default)]
    failures: u64,
    #[serde(default)]
    duration_ms_total: u64,
    #[serde(default)]
    bytes_in_total: u64,
    #[serde(default)]
    bytes_out_total: u64,
}

/// Run the `function` subcommand.
pub async fn run(args: FunctionArgs, config: &ProjectConfig) -> Result<()> {
    match args.command {
        FunctionCommand::Ls { site, server } => {
            let funcs = fetch(server, site, config).await?;
            if funcs.is_empty() {
                println!("no functions");
                return Ok(());
            }
            for f in funcs {
                println!(
                    "{}  [{}]  {}  {}",
                    f.name,
                    f.runtime,
                    short(&f.version),
                    f.triggers.join(", ")
                );
            }
        }
        FunctionCommand::Get { name, server } => {
            let funcs = fetch(server, None, config).await?;
            match funcs.into_iter().find(|f| f.name == name) {
                Some(f) => {
                    println!("{}", f.name);
                    println!("  runtime: {}", f.runtime);
                    println!("  version: {}", f.version);
                    for t in &f.triggers {
                        println!("  trigger: {t}");
                    }
                }
                None => println!("no function {name:?}"),
            }
        }
        FunctionCommand::Deploy {
            name,
            component,
            runtime,
            webhook_secret_env,
            server,
        } => {
            let (server, http) = conn(server, config)?;
            // Upload the component first; the server rejects a deploy whose blob is
            // absent, so this is content-addressed staging, not a second round-trip.
            let hash = client::put_file_blob(&http, &server, &component).await?;
            let mut cfg = serde_json::Map::new();
            if let Some(r) = &runtime {
                cfg.insert("runtime".to_string(), serde_json::json!(r));
            }
            if let Some(secret_env) = &webhook_secret_env {
                cfg.insert(
                    "webhook".to_string(),
                    serde_json::json!({ "secret_env": secret_env }),
                );
            }
            // Top-level functions carry their own version line (decision 3).
            let body = serde_json::json!({
                "component": hash,
                "config": serde_json::Value::Object(cfg),
                "lifecycle": "independent",
            });
            let f: StoredFunction = http
                .put(format!("{server}/api/functions/{name}"))
                .json(&body)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!(
                "deployed {}  [{}]  {}",
                f.name,
                f.config.runtime,
                short(&f.active)
            );
        }
        FunctionCommand::Rollback { name, to, server } => {
            let (server, http) = conn(server, config)?;
            let f: StoredFunction = http
                .post(format!("{server}/api/functions/{name}/rollback"))
                .json(&serde_json::json!({ "to": to }))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("rolled {} back to {}", f.name, short(&f.active));
        }
        FunctionCommand::Alias {
            name,
            label,
            version,
            server,
        } => {
            let (server, http) = conn(server, config)?;
            http.put(format!("{server}/api/functions/{name}/aliases/{label}"))
                .json(&serde_json::json!({ "version": version }))
                .send()
                .await?
                .error_for_status()?;
            println!("aliased {name}:{label} -> {}", short(&version));
        }
        FunctionCommand::Rm { name, server } => {
            let (server, http) = conn(server, config)?;
            http.delete(format!("{server}/api/functions/{name}"))
                .send()
                .await?
                .error_for_status()?;
            println!("removed {name}");
        }
        FunctionCommand::Invoke {
            name,
            data,
            data_file,
            content_type,
            r#async,
            idempotency_key,
            version,
            server,
        } => {
            let (server, http) = conn(server, config)?;
            let body = read_invoke_body(data, data_file).await?;
            let mut qs: Vec<String> = Vec::new();
            if r#async {
                qs.push("mode=async".to_string());
            }
            if let Some(v) = &version {
                qs.push(format!("version={v}"));
            }
            let url = if qs.is_empty() {
                format!("{server}/api/functions/{name}/invoke")
            } else {
                format!("{server}/api/functions/{name}/invoke?{}", qs.join("&"))
            };
            let mut req = http.post(url).body(body);
            if let Some(ct) = &content_type {
                req = req.header("content-type", ct.as_str());
            }
            if let Some(key) = &idempotency_key {
                req = req.header("idempotency-key", key.as_str());
            }
            let resp = req.send().await?;
            let status = resp.status();
            let bytes = resp.bytes().await?;
            if r#async {
                // 202 + a JSON invocation record: surface the id to poll.
                match serde_json::from_slice::<InvocationRecord>(&bytes) {
                    Ok(inv) => println!("queued {} [{}]", inv.id, inv.status),
                    Err(_) => eprint!("{}", String::from_utf8_lossy(&bytes)),
                }
            } else {
                // Print the function's response body verbatim; note a non-success
                // status on stderr (a control-plane 404/401, or the guest's own).
                use std::io::Write;
                let _ = std::io::stdout().write_all(&bytes);
                if !status.is_success() {
                    eprintln!("invoke returned HTTP {}", status.as_u16());
                }
            }
        }
        FunctionCommand::Invocation { name, id, server } => {
            let (server, http) = conn(server, config)?;
            let inv: InvocationRecord = http
                .get(format!("{server}/api/functions/{name}/invocations/{id}"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}  [{}]  attempts={}", inv.id, inv.status, inv.attempts);
            if let Some(result) = &inv.result {
                println!("  result: HTTP {}", result.status);
            }
        }
        FunctionCommand::Usage { name, server } => {
            let (server, http) = conn(server, config)?;
            let usage: UsageView = http
                .get(format!("{server}/api/functions/{name}/usage"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", usage.function);
            println!(
                "  invocations: {} ({} ok, {} failed)",
                usage.invocations, usage.successes, usage.failures
            );
            println!("  duration:    {} ms total", usage.duration_ms_total);
            println!(
                "  bytes:       {} in / {} out",
                usage.bytes_in_total, usage.bytes_out_total
            );
        }
    }
    Ok(())
}

/// Read the invoke request body: `--data` inline, `--data-file <path>` (`-` =
/// stdin), or empty when neither is given.
async fn read_invoke_body(
    data: Option<String>,
    data_file: Option<std::path::PathBuf>,
) -> Result<Vec<u8>> {
    if let Some(inline) = data {
        return Ok(inline.into_bytes());
    }
    let Some(path) = data_file else {
        return Ok(Vec::new());
    };
    if path.as_os_str() == "-" {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        tokio::io::stdin().read_to_end(&mut buf).await?;
        Ok(buf)
    } else {
        Ok(tokio::fs::read(&path).await?)
    }
}

/// Resolve the target server and build an authenticated client — the shared
/// preamble of every mutating `function` subcommand.
fn conn(server: Option<String>, config: &ProjectConfig) -> Result<(String, client::ApiClient)> {
    let server = client::resolve_server(server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    Ok((server, http))
}

/// Fetch the functions view (all sites, or one with `?site=`).
async fn fetch(
    server: Option<String>,
    site: Option<String>,
    config: &ProjectConfig,
) -> Result<Vec<FunctionSummary>> {
    let server = client::resolve_server(server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    let url = match &site {
        Some(s) => format!("{server}/api/functions?site={s}"),
        None => format!("{server}/api/functions"),
    };
    Ok(http
        .get(url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Shorten a version id for display (drop the `sha256:` tag, keep 12 chars).
fn short(id: &str) -> &str {
    let id = id.strip_prefix("sha256:").unwrap_or(id);
    &id[..id.len().min(12)]
}
