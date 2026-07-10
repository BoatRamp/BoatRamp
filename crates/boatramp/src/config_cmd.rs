//! The `config` subcommand: read and change the **dynamic daemon config** over the
//! control-plane API (`/api/daemon/config`). Operational knobs set here converge
//! fleet-wide without a restart; trust anchors and posture stay in `boatramp.cfg`
//! (restart to change) — this command refuses those with a clear pointer, so the
//! old "edit the file + SIGHUP is a silent no-op" trap can't happen.

use std::path::PathBuf;

use boatramp_core::daemon_config::{DaemonConfig, KernelRef};
use clap::Subcommand;
use serde::Deserialize;

use crate::client;
use crate::config::ProjectConfig;

/// A failure running a `boatramp config` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server target failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A control-plane HTTP request failed.
    #[error("control-plane request: {0}")]
    Http(#[from] reqwest::Error),
    /// (De)serializing the config failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// Reading the `apply` file failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An unknown / non-dynamic key.
    #[error("unknown dynamic config key {0:?}; run `boatramp config list`")]
    UnknownKey(String),
    /// A restart-class (file-only) key was addressed.
    #[error(
        "{0} is a restart-class setting: edit `[{1}]` in boatramp.cfg on each node and restart \
         (it is not runtime-changeable — that is deliberate)"
    )]
    RestartClass(String, &'static str),
    /// A bad value for a key.
    #[error("invalid value for {key}: {msg}")]
    BadValue { key: String, msg: String },
    /// The server rejected the config (validate-before-commit).
    #[error("server rejected the config: {0}")]
    Rejected(String),
}

/// `config` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp config`.
#[derive(Debug, clap::Args)]
pub struct ConfigArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Print the active dynamic config and its generation, or one key's value.
    Get {
        /// Optional dotted key (e.g. `default_site`, `compute.vcpus`).
        key: Option<String>,
    },
    /// Set one dynamic key and converge it fleet-wide (read-modify-write).
    Set {
        /// Dotted key (see `config list`).
        key: String,
        /// New value (`null`/`unset` clears it).
        value: String,
    },
    /// Roll the dynamic config back to the previous generation.
    Rollback,
    /// Replace the whole dynamic config from a JSON file (validated server-side).
    Apply {
        /// JSON file holding a full `DaemonConfig`.
        #[arg(short, long)]
        file: PathBuf,
    },
    /// List the dynamic (runtime-settable) keys.
    List,
    /// Describe a key: what it is and its change class (dynamic vs restart).
    Describe {
        /// Dotted key.
        key: String,
    },
}

/// The `GET /api/daemon/config` response.
#[derive(Deserialize)]
struct ConfigResponse {
    generation: Option<String>,
    config: DaemonConfig,
}

/// Entry point for `boatramp config`.
pub async fn run(args: ConfigArgs, config: &ProjectConfig) -> Result<()> {
    // `list` / `describe` are static — no server needed.
    match &args.command {
        ConfigCommand::List => {
            print_list();
            return Ok(());
        }
        ConfigCommand::Describe { key } => {
            describe(key);
            return Ok(());
        }
        _ => {}
    }
    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    match args.command {
        ConfigCommand::Get { key } => get(&http, &server, key).await,
        ConfigCommand::Set { key, value } => set(&http, &server, &key, &value).await,
        ConfigCommand::Rollback => rollback(&http, &server).await,
        ConfigCommand::Apply { file } => apply(&http, &server, &file).await,
        ConfigCommand::List | ConfigCommand::Describe { .. } => unreachable!("handled above"),
    }
}

async fn fetch(http: &reqwest::Client, server: &str) -> Result<ConfigResponse> {
    Ok(http
        .get(format!("{server}/api/daemon/config"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn put(http: &reqwest::Client, server: &str, cfg: &DaemonConfig) -> Result<String> {
    let resp = http
        .put(format!("{server}/api/daemon/config"))
        .json(cfg)
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::BAD_REQUEST {
        return Err(Error::Rejected(resp.text().await?.trim().to_string()));
    }
    let v: serde_json::Value = resp.error_for_status()?.json().await?;
    Ok(v["generation"].as_str().unwrap_or("").to_string())
}

async fn get(http: &reqwest::Client, server: &str, key: Option<String>) -> Result<()> {
    let r = fetch(http, server).await?;
    match key {
        None => {
            println!(
                "generation: {}",
                r.generation.as_deref().unwrap_or("(file baseline)")
            );
            println!("{}", serde_json::to_string_pretty(&r.config)?);
        }
        Some(k) => println!("{}", read_key(&r.config, &k)?),
    }
    Ok(())
}

async fn set(http: &reqwest::Client, server: &str, key: &str, value: &str) -> Result<()> {
    let mut r = fetch(http, server).await?;
    write_key(&mut r.config, key, value)?;
    let generation = put(http, server, &r.config).await?;
    println!("set {key} = {value}  (generation {generation})");
    Ok(())
}

async fn rollback(http: &reqwest::Client, server: &str) -> Result<()> {
    let resp = http
        .post(format!("{server}/api/daemon/config/rollback"))
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::CONFLICT {
        println!("no prior generation to roll back to");
        return Ok(());
    }
    let v: serde_json::Value = resp.error_for_status()?.json().await?;
    println!(
        "rolled back to generation {}",
        v["generation"].as_str().unwrap_or("?")
    );
    Ok(())
}

async fn apply(http: &reqwest::Client, server: &str, file: &std::path::Path) -> Result<()> {
    let bytes = std::fs::read(file)?;
    let cfg: DaemonConfig = serde_json::from_slice(&bytes)?;
    let generation = put(http, server, &cfg).await?;
    println!("applied {} (generation {generation})", file.display());
    Ok(())
}

/// A cleared value (`null`/`unset`/empty) resets the key to the file baseline.
fn is_clear(value: &str) -> bool {
    matches!(value, "null" | "unset" | "")
}

fn parse_bool(key: &str, value: &str) -> Result<bool> {
    value.parse().map_err(|_| Error::BadValue {
        key: key.to_string(),
        msg: format!("expected true/false, got {value:?}"),
    })
}

fn parse_u64(key: &str, value: &str) -> Result<u64> {
    value.parse().map_err(|_| Error::BadValue {
        key: key.to_string(),
        msg: format!("expected an integer, got {value:?}"),
    })
}

/// Restart-class keys the operator might reach for — reject with a clear pointer
/// instead of a cryptic "unknown key" (or the old SIGHUP silent no-op).
fn restart_class_section(key: &str) -> Option<&'static str> {
    match key {
        "addr" | "data_dir" | "http_redirect_addr" => Some("serve"),
        k if k.starts_with("auth_root") || k == "signer" || k == "bootstrap_secret" => {
            Some("serve")
        }
        k if k.starts_with("tls") || k.starts_with("acme") => Some("serve"),
        k if k.starts_with("security.") || k == "security" => Some("security"),
        k if k.starts_with("cluster.") || k == "cluster" => Some("cluster"),
        _ => None,
    }
}

fn write_key(cfg: &mut DaemonConfig, key: &str, value: &str) -> Result<()> {
    if let Some(section) = restart_class_section(key) {
        return Err(Error::RestartClass(key.to_string(), section));
    }
    let clear = is_clear(value);
    match key {
        "default_site" => cfg.default_site = (!clear).then(|| value.to_string()),
        "protect_previews" => cfg.protect_previews = clear_or(clear, parse_bool(key, value)?),
        "cluster_rate_limit" => cfg.cluster_rate_limit = clear_or(clear, parse_bool(key, value)?),
        "max_upload_bytes" => cfg.max_upload_bytes = clear_or(clear, parse_u64(key, value)?),
        "upload_idle_timeout_secs" => {
            cfg.upload_idle_timeout_secs = clear_or(clear, parse_u64(key, value)?)
        }
        "max_concurrent_uploads" => {
            cfg.max_concurrent_uploads = clear_or(clear, parse_u64(key, value)?)
        }
        "compute.vcpus" => cfg.compute.vcpus = clear_or(clear, parse_u64(key, value)? as u32),
        "compute.mem_mib" => cfg.compute.mem_mib = clear_or(clear, parse_u64(key, value)? as u32),
        "compute.default_kernel" => {
            cfg.compute.default_kernel = if clear {
                None
            } else {
                Some(
                    serde_json::from_str::<KernelRef>(value).map_err(|e| Error::BadValue {
                        key: key.to_string(),
                        msg: format!("expected a KernelRef JSON object: {e}"),
                    })?,
                )
            }
        }
        "posture.oidc_require_audience" => {
            cfg.posture.oidc_require_audience = clear_or(clear, parse_bool(key, value)?)
        }
        "posture.ratelimit_fail_open" => {
            cfg.posture.ratelimit_fail_open = clear_or(clear, parse_bool(key, value)?)
        }
        "posture.allow_shared_kernel_compute" => {
            cfg.posture.allow_shared_kernel_compute = clear_or(clear, parse_bool(key, value)?)
        }
        _ => return Err(Error::UnknownKey(key.to_string())),
    }
    Ok(())
}

fn clear_or<T>(clear: bool, v: T) -> Option<T> {
    (!clear).then_some(v)
}

fn read_key(cfg: &DaemonConfig, key: &str) -> Result<String> {
    let json = serde_json::to_value(cfg)?;
    let mut node = &json;
    for part in key.split('.') {
        node = node.get(part).unwrap_or(&serde_json::Value::Null);
    }
    Ok(if node.is_null() {
        "(unset — file baseline)".to_string()
    } else {
        node.to_string()
    })
}

fn print_list() {
    println!("Dynamic keys (change fleet-wide with `config set`, no restart):");
    for (k, class) in DYNAMIC_KEYS {
        println!("  {k:<32} {class}");
    }
    println!("\nTrust anchors + posture + listener settings are restart-class");
    println!("(edit boatramp.cfg + restart). See `config describe <key>`.");
}

fn describe(key: &str) {
    if let Some(section) = restart_class_section(key) {
        println!("{key}: restart-class — edit `[{section}]` in boatramp.cfg + restart.");
        return;
    }
    match DYNAMIC_KEYS.iter().find(|(k, _)| *k == key) {
        Some((_, class)) => {
            println!("{key}: dynamic — `config set` converges it fleet-wide without a restart.");
            println!("  {class}");
        }
        None => println!("{key}: unknown; run `config list`."),
    }
}

/// The dynamic keys + a one-line note.
const DYNAMIC_KEYS: &[(&str, &str)] = &[
    ("default_site", "catch-all site for an unmatched Host"),
    ("protect_previews", "require a token to view previews"),
    ("max_upload_bytes", "upload cap (≤ the posture ceiling)"),
    ("upload_idle_timeout_secs", "abort a stalled upload"),
    ("max_concurrent_uploads", "cap simultaneous uploads"),
    ("cluster_rate_limit", "rate-limit via the shared KV"),
    ("compute.vcpus", "advertised schedulable vCPUs"),
    ("compute.mem_mib", "advertised schedulable memory (MiB)"),
    (
        "compute.default_kernel",
        "fleet default microVM kernel (KernelRef JSON)",
    ),
    (
        "posture.oidc_require_audience",
        "tighten-only: require an OIDC audience",
    ),
    (
        "posture.ratelimit_fail_open",
        "tighten-only: fail closed (set false)",
    ),
    (
        "posture.allow_shared_kernel_compute",
        "tighten-only: forbid shared-kernel (set false)",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_scalars_and_clear() {
        let mut cfg = DaemonConfig::default();
        write_key(&mut cfg, "default_site", "blog").unwrap();
        assert_eq!(cfg.default_site.as_deref(), Some("blog"));
        write_key(&mut cfg, "max_upload_bytes", "1048576").unwrap();
        assert_eq!(cfg.max_upload_bytes, Some(1048576));
        write_key(&mut cfg, "compute.vcpus", "8").unwrap();
        assert_eq!(cfg.compute.vcpus, Some(8));
        // Clearing resets to the file baseline.
        write_key(&mut cfg, "default_site", "unset").unwrap();
        assert!(cfg.default_site.is_none());
    }

    #[test]
    fn restart_class_and_unknown_are_rejected() {
        let mut cfg = DaemonConfig::default();
        // A trust anchor / posture / listener setting → clear restart-class error.
        assert!(matches!(
            write_key(&mut cfg, "auth_root_private_key", "x"),
            Err(Error::RestartClass(_, "serve"))
        ));
        assert!(matches!(
            write_key(
                &mut cfg,
                "security.allow_unauthenticated_public_bind",
                "true"
            ),
            Err(Error::RestartClass(_, "security"))
        ));
        // A genuinely unknown key.
        assert!(matches!(
            write_key(&mut cfg, "nope", "1"),
            Err(Error::UnknownKey(_))
        ));
        // A bad value.
        assert!(matches!(
            write_key(&mut cfg, "protect_previews", "maybe"),
            Err(Error::BadValue { .. })
        ));
    }

    #[test]
    fn read_key_reports_unset() {
        let cfg = DaemonConfig::default();
        assert!(read_key(&cfg, "default_site").unwrap().contains("unset"));
    }
}
