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
    /// `function trigger add` needs exactly one of `--cron` / `--queue` / `--blob`.
    #[error("specify exactly one of --cron, --queue, or --blob")]
    BadTrigger,
    /// `function init --lang` named an unknown template.
    #[error("unknown template language {0:?} (supported: rust)")]
    UnknownLang(String),
    /// `function init` target directory already exists.
    #[error("{0} already exists")]
    AlreadyExists(std::path::PathBuf),
    /// `function build` (the `cargo build` invocation) failed.
    #[error("cargo build failed (is the wasm32-wasip2 target installed?)")]
    BuildFailed,
    /// `function build` produced no component `.wasm`.
    #[error("no component produced under target/wasm32-wasip2/release")]
    NoComponent,
    /// The local harness (`function test`/`dev`) failed to run the component.
    #[cfg(feature = "handlers")]
    #[error("running the component: {0}")]
    Harness(String),
    /// A `function test` assertion (status / body) failed.
    #[cfg(feature = "handlers")]
    #[error("function test assertion failed")]
    HarnessFailed,
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
    /// Manage a function's scheduled / event triggers (cron, queue).
    Trigger(TriggerArgs),
    /// Scaffold a new function project from a language template.
    Init {
        /// Function/project name (also the Rust crate name).
        name: String,
        /// Language template (only `rust` for now).
        #[arg(long, default_value = "rust")]
        lang: String,
        /// Parent directory to create the project under (default: cwd).
        #[arg(long)]
        dir: Option<std::path::PathBuf>,
    },
    /// Build a function project to a `wasi:http` component (`cargo build
    /// --release --target wasm32-wasip2`). Prints the produced `.wasm` path.
    Build {
        /// The project directory (default: cwd).
        #[arg(long)]
        dir: Option<std::path::PathBuf>,
    },
    /// Run a component locally against one request and assert on the response
    /// (the local single-function harness).
    #[cfg(feature = "handlers")]
    Test {
        /// Path to the component `.wasm`.
        #[arg(long)]
        component: std::path::PathBuf,
        /// Request path (default `/`).
        #[arg(long, default_value = "/")]
        path: String,
        /// Request method (default `GET`).
        #[arg(long, default_value = "GET")]
        method: String,
        /// Inline request body.
        #[arg(long)]
        data: Option<String>,
        /// Request content type.
        #[arg(long)]
        content_type: Option<String>,
        /// Assert the response status equals this.
        #[arg(long)]
        expect_status: Option<u16>,
        /// Assert the response body contains this substring.
        #[arg(long)]
        expect_body: Option<String>,
    },
    /// Serve a component locally on an HTTP port (the local dev harness).
    #[cfg(feature = "handlers")]
    Dev {
        /// Path to the component `.wasm`.
        #[arg(long)]
        component: std::path::PathBuf,
        /// Port to listen on (127.0.0.1).
        #[arg(long, default_value = "8787")]
        port: u16,
    },
}

/// `function trigger` — cron + queue triggers the server dispatches.
#[derive(Debug, clap::Args)]
struct TriggerArgs {
    #[command(subcommand)]
    command: TriggerCommand,
}

#[derive(Debug, clap::Subcommand)]
enum TriggerCommand {
    /// Add/replace a trigger. Exactly one of `--cron` / `--queue` / `--blob`.
    Add {
        /// Function name.
        name: String,
        /// Trigger id (unique within the function).
        id: String,
        /// A cron schedule (`min hour dom month dow`) — a scheduled invoke.
        #[arg(long, conflicts_with_all = ["queue", "blob"])]
        cron: Option<String>,
        /// A queue topic — invoke the function per message on `fn/<name>/<topic>`.
        #[arg(long, conflicts_with = "blob")]
        queue: Option<String>,
        /// A blobstore prefix — invoke the function when an object under
        /// `fn/<name>/<prefix>` changes (needs a watch-capable storage backend).
        #[arg(long)]
        blob: Option<String>,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// List a function's triggers.
    Ls {
        /// Function name.
        name: String,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
    /// Remove a trigger by id.
    Rm {
        /// Function name.
        name: String,
        /// Trigger id.
        id: String,
        /// Server base URL.
        #[arg(long)]
        server: Option<String>,
    },
}

/// A stored trigger as `/triggers` reports it (id + kind).
#[derive(Debug, Deserialize)]
struct TriggerView {
    id: String,
    kind: serde_json::Value,
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
        FunctionCommand::Trigger(args) => run_trigger(args, config).await?,
        FunctionCommand::Init { name, lang, dir } => init_project(&name, &lang, dir)?,
        FunctionCommand::Build { dir } => build_project(dir).await?,
        #[cfg(feature = "handlers")]
        FunctionCommand::Test {
            component,
            path,
            method,
            data,
            content_type,
            expect_status,
            expect_body,
        } => {
            harness::test_component(
                component,
                &path,
                &method,
                data,
                content_type,
                expect_status,
                expect_body,
            )
            .await?
        }
        #[cfg(feature = "handlers")]
        FunctionCommand::Dev { component, port } => harness::dev_serve(component, port).await?,
    }
    Ok(())
}

/// Run the `function trigger` subcommand.
async fn run_trigger(args: TriggerArgs, config: &ProjectConfig) -> Result<()> {
    match args.command {
        TriggerCommand::Add {
            name,
            id,
            cron,
            queue,
            blob,
            server,
        } => {
            let (server, http) = conn(server, config)?;
            let kind = match (cron, queue, blob) {
                (Some(schedule), None, None) => {
                    serde_json::json!({ "type": "cron", "schedule": schedule })
                }
                (None, Some(topic), None) => {
                    serde_json::json!({ "type": "queue", "topic": topic })
                }
                (None, None, Some(prefix)) => {
                    serde_json::json!({ "type": "blob", "prefix": prefix })
                }
                _ => return Err(FunctionError::BadTrigger),
            };
            http.put(format!("{server}/api/functions/{name}/triggers/{id}"))
                .json(&kind)
                .send()
                .await?
                .error_for_status()?;
            println!("added trigger {name}/{id}");
        }
        TriggerCommand::Ls { name, server } => {
            let (server, http) = conn(server, config)?;
            let list: Vec<TriggerView> = http
                .get(format!("{server}/api/functions/{name}/triggers"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if list.is_empty() {
                println!("no triggers");
                return Ok(());
            }
            for t in list {
                let kind = t.kind.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                println!("{}  [{}]", t.id, kind);
            }
        }
        TriggerCommand::Rm { name, id, server } => {
            let (server, http) = conn(server, config)?;
            http.delete(format!("{server}/api/functions/{name}/triggers/{id}"))
                .send()
                .await?
                .error_for_status()?;
            println!("removed trigger {name}/{id}");
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

/// The embedded Rust function template (`function init --lang rust`).
static RUST_TEMPLATE: include_dir::Dir<'_> =
    include_dir::include_dir!("$CARGO_MANIFEST_DIR/templates/rust");

/// Scaffold a new function project from a language template.
fn init_project(name: &str, lang: &str, dir: Option<std::path::PathBuf>) -> Result<()> {
    if lang != "rust" {
        return Err(FunctionError::UnknownLang(lang.to_string()));
    }
    let crate_name = sanitize_crate_name(name);
    let target = dir
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(&crate_name);
    if target.exists() {
        return Err(FunctionError::AlreadyExists(target));
    }
    write_template(&RUST_TEMPLATE, &target, &crate_name)?;
    println!("scaffolded {crate_name} in {}", target.display());
    println!("  next: cd {crate_name} && boatramp function build");
    Ok(())
}

/// Write every embedded template file to `dest_root`, renaming `Cargo.toml.tmpl`
/// → `Cargo.toml` with the crate name substituted.
fn write_template(
    dir: &include_dir::Dir,
    dest_root: &std::path::Path,
    crate_name: &str,
) -> Result<()> {
    let mut files: Vec<&include_dir::File> = Vec::new();
    collect_files(dir, &mut files);
    for file in files {
        let rel = file.path();
        let (rel, contents) = if rel.file_name().and_then(|n| n.to_str()) == Some("Cargo.toml.tmpl")
        {
            let text = std::str::from_utf8(file.contents())
                .unwrap_or_default()
                .replace("BOATRAMP_FUNCTION_NAME", crate_name);
            (rel.with_file_name("Cargo.toml"), text.into_bytes())
        } else {
            (rel.to_path_buf(), file.contents().to_vec())
        };
        let dest = dest_root.join(&rel);
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, contents)?;
    }
    Ok(())
}

/// Recursively gather every file in the embedded directory (paths are relative to
/// the template root).
fn collect_files<'a>(dir: &'a include_dir::Dir, out: &mut Vec<&'a include_dir::File<'a>>) {
    out.extend(dir.files());
    for sub in dir.dirs() {
        collect_files(sub, out);
    }
}

/// A valid Rust crate name from a function name: lowercase, non-alphanumerics → `-`,
/// collapsed, trimmed. Empty input becomes `function`.
fn sanitize_crate_name(name: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in name.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "function".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Build a function project to a component and print the produced `.wasm` path.
async fn build_project(dir: Option<std::path::PathBuf>) -> Result<()> {
    let dir = dir.unwrap_or_else(|| std::path::PathBuf::from("."));
    let status = tokio::process::Command::new("cargo")
        .args(["build", "--release", "--target", "wasm32-wasip2"])
        .current_dir(&dir)
        .status()
        .await?;
    if !status.success() {
        return Err(FunctionError::BuildFailed);
    }
    // The cdylib output is a single `<crate>.wasm` under the release dir.
    let release = dir.join("target/wasm32-wasip2/release");
    let component = std::fs::read_dir(&release)
        .ok()
        .and_then(|entries| {
            entries
                .flatten()
                .map(|e| e.path())
                .find(|p| p.extension().and_then(|e| e.to_str()) == Some("wasm"))
        })
        .ok_or(FunctionError::NoComponent)?;
    println!("built {}", component.display());
    println!(
        "  deploy: boatramp function deploy <name> --component {}",
        component.display()
    );
    Ok(())
}

/// The local single-function harness (FA-7): run a scaffolded component through
/// the engine in-process — `function test` (one request + asserts) and
/// `function dev` (a local HTTP server). Only the no-capability request path is
/// wired (the template's shape); capability-backed local testing is future.
#[cfg(feature = "handlers")]
mod harness {
    use super::{FunctionError, Result};
    use boatramp_handlers::{Bindings, HandlerEngine, Limits};
    use http_body_util::{BodyExt, Full};

    /// The engine's compile-cache key for a locally-run component (one per run).
    const LOCAL_HASH: &str = "function-local";

    /// Run `component` against one request; print the response and assert.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn test_component(
        component: std::path::PathBuf,
        path: &str,
        method: &str,
        data: Option<String>,
        content_type: Option<String>,
        expect_status: Option<u16>,
        expect_body: Option<String>,
    ) -> Result<()> {
        let wasm = tokio::fs::read(&component).await?;
        let engine = HandlerEngine::new(Limits::default(), 4).map_err(harness_err)?;
        let (status, body) = run_once(
            &engine,
            &wasm,
            method,
            path,
            content_type.as_deref(),
            data.unwrap_or_default().into_bytes(),
        )
        .await?;
        let text = String::from_utf8_lossy(&body);
        println!("HTTP {status}");
        print!("{text}");
        if !text.ends_with('\n') {
            println!();
        }

        let mut ok = true;
        if let Some(exp) = expect_status {
            if status != exp {
                eprintln!("FAIL: expected status {exp}, got {status}");
                ok = false;
            }
        }
        if let Some(sub) = &expect_body {
            if !text.contains(sub.as_str()) {
                eprintln!("FAIL: body does not contain {sub:?}");
                ok = false;
            }
        }
        if ok {
            println!("ok");
            Ok(())
        } else {
            Err(FunctionError::HarnessFailed)
        }
    }

    /// Serve `component` locally on `127.0.0.1:<port>` until interrupted. Each
    /// request runs the component; the response is buffered (fine for local dev).
    pub(super) async fn dev_serve(component: std::path::PathBuf, port: u16) -> Result<()> {
        use hyper::server::conn::http1;
        use hyper::service::service_fn;
        use hyper_util::rt::TokioIo;
        use std::sync::Arc;

        let wasm = Arc::new(tokio::fs::read(&component).await?);
        let engine = Arc::new(HandlerEngine::new(Limits::default(), 16).map_err(harness_err)?);
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
        println!(
            "serving {} on http://127.0.0.1:{port}  (Ctrl-C to stop)",
            component.display()
        );

        loop {
            let (stream, _) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let engine = engine.clone();
            let wasm = wasm.clone();
            tokio::spawn(async move {
                let service = service_fn(move |req: http::Request<hyper::body::Incoming>| {
                    let engine = engine.clone();
                    let wasm = wasm.clone();
                    async move {
                        let response = match engine
                            .serve(LOCAL_HASH, &wasm, req, Bindings::new("fn/local"))
                            .await
                        {
                            Ok(resp) => {
                                let (parts, body) = resp.into_parts();
                                let bytes = body
                                    .collect()
                                    .await
                                    .map(|c| c.to_bytes())
                                    .unwrap_or_default();
                                http::Response::from_parts(parts, Full::new(bytes))
                            }
                            Err(err) => http::Response::builder()
                                .status(500)
                                .body(Full::new(bytes::Bytes::from(format!(
                                    "function error: {err:?}\n"
                                ))))
                                .unwrap(),
                        };
                        Ok::<_, std::convert::Infallible>(response)
                    }
                });
                let _ = http1::Builder::new().serve_connection(io, service).await;
            });
        }
    }

    /// Run one request through the engine → (status, body bytes).
    async fn run_once(
        engine: &HandlerEngine,
        wasm: &[u8],
        method: &str,
        path: &str,
        content_type: Option<&str>,
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>)> {
        let mut builder = http::Request::builder()
            .method(method)
            .uri(format!("http://localhost{path}"));
        if let Some(ct) = content_type {
            builder = builder.header("content-type", ct);
        }
        let request = builder
            .body(Full::new(bytes::Bytes::from(body)))
            .map_err(harness_err)?;
        let response = engine
            .serve(LOCAL_HASH, wasm, request, Bindings::new("fn/local"))
            .await
            .map_err(|e| FunctionError::Harness(format!("{e:?}")))?;
        let status = response.status().as_u16();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| FunctionError::Harness(format!("{e:?}")))?
            .to_bytes();
        Ok((status, bytes.to_vec()))
    }

    fn harness_err<E: std::fmt::Display>(err: E) -> FunctionError {
        FunctionError::Harness(err.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_crate_names() {
        assert_eq!(sanitize_crate_name("My Cool Fn"), "my-cool-fn");
        assert_eq!(sanitize_crate_name("resize_images"), "resize-images");
        assert_eq!(sanitize_crate_name("  --Foo.Bar--  "), "foo-bar");
        assert_eq!(sanitize_crate_name("!!!"), "function");
    }

    #[test]
    fn init_scaffolds_a_buildable_tree() {
        let root = std::env::temp_dir().join(format!("boatramp-init-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        init_project("My Cool Fn", "rust", Some(root.clone())).unwrap();
        let proj = root.join("my-cool-fn");

        // The manifest is written (not the `.tmpl`), with the name substituted.
        let cargo = std::fs::read_to_string(proj.join("Cargo.toml")).unwrap();
        assert!(cargo.contains("name = \"my-cool-fn\""));
        assert!(!cargo.contains("BOATRAMP_FUNCTION_NAME"));
        assert!(!proj.join("Cargo.toml.tmpl").exists());
        // Source + the WIT closure came along, so `cargo build` would have them.
        assert!(proj.join("src/lib.rs").exists());
        assert!(proj.join("wit/handler.wit").exists());

        // Refuses an unknown language and an existing directory.
        assert!(matches!(
            init_project("x", "python", Some(root.clone())),
            Err(FunctionError::UnknownLang(_))
        ));
        assert!(matches!(
            init_project("My Cool Fn", "rust", Some(root.clone())),
            Err(FunctionError::AlreadyExists(_))
        ));

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The local harness runs a component through the engine: a matching assertion
    /// passes, a wrong one fails. Uses a prebuilt fixture (no `cargo build`), so
    /// it is fast; needs `--features handlers` (the engine).
    #[cfg(feature = "handlers")]
    #[tokio::test]
    async fn harness_runs_a_component_and_asserts() {
        const HTTP_200: &[u8] =
            include_bytes!("../../boatramp-handlers/tests/fixtures/http-200.wasm");
        let tmp =
            std::env::temp_dir().join(format!("boatramp-harness-{}.wasm", std::process::id()));
        std::fs::write(&tmp, HTTP_200).unwrap();

        // A matching status + body assertion passes.
        harness::test_component(
            tmp.clone(),
            "/",
            "GET",
            None,
            None,
            Some(200),
            Some("hello from boatramp".into()),
        )
        .await
        .unwrap();

        // A wrong status assertion fails.
        assert!(matches!(
            harness::test_component(tmp.clone(), "/", "GET", None, None, Some(404), None).await,
            Err(FunctionError::HarnessFailed)
        ));

        let _ = std::fs::remove_file(&tmp);
    }

    /// The scaffolded Rust template compiles to a real `wasi:http` component.
    /// `#[ignore]`d because it invokes `cargo build --target wasm32-wasip2` (slow +
    /// needs the wasm toolchain); run with `--ignored`, and wired into the flake
    /// check. Validates FA-7's init → build round-trip end to end.
    #[tokio::test]
    #[ignore = "compiles a wasm component; run with --ignored / in the flake check"]
    async fn init_then_build_produces_a_component() {
        let root = std::env::temp_dir().join(format!("boatramp-roundtrip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        init_project("roundtrip demo", "rust", Some(root.clone())).unwrap();
        let proj = root.join("roundtrip-demo");
        build_project(Some(proj.clone())).await.unwrap();
        let wasm = proj.join("target/wasm32-wasip2/release/roundtrip_demo.wasm");
        assert!(wasm.exists(), "expected a built component at {wasm:?}");
        // A component starts with the wasm preamble + the component-model layer.
        let bytes = std::fs::read(&wasm).unwrap();
        assert_eq!(&bytes[..4], b"\0asm");
        let _ = std::fs::remove_dir_all(&root);
    }
}
