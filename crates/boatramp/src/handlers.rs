//! The `handlers` subcommand: manage a site's **handler policy** — the
//! `SiteConfig.handlers` gate (`enabled` + the `allow_imports` allowlist + resource
//! caps) that activation prechecks a handler-shipping deployment against. Edits the
//! site's `SiteConfig.handlers` via the control-plane API (the same `PUT
//! /api/sites/:site/config` the console form and `apply` use).
//!
//! A deployment that ships handlers is refused at activation unless the site is
//! `enabled` and its `allow_imports` is a superset of every handler's declared imports.

use boatramp_core::config::{CookieAuthConfig, HandlerCacheConfig, HandlersSiteConfig};
use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `handlers` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the target or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
}

/// `handlers` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp handlers`.
#[derive(Debug, clap::Args)]
pub struct HandlersArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    /// Site to edit (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE", global = true)]
    site: Option<String>,

    #[command(subcommand)]
    command: HandlersCommand,
}

#[derive(Debug, Subcommand)]
enum HandlersCommand {
    /// Show the site's current handler policy.
    Show,
    /// Enable handlers on the site. Optionally set the import allowlist (`--allow`,
    /// repeatable — **replaces** the current list when given) and resource caps.
    Enable {
        /// An interface handlers may import (e.g. `sql`, `wasi:keyvalue`, `invoke`);
        /// repeatable. Given at least once, it replaces the whole allowlist.
        #[arg(long = "allow", value_name = "IMPORT")]
        allow: Vec<String>,
        /// Cap on per-handler memory (MiB).
        #[arg(long)]
        max_memory_mb: Option<u32>,
        /// Cap on per-handler timeout (ms).
        #[arg(long)]
        max_timeout_ms: Option<u32>,
        /// Cap on concurrent invocations for the site.
        #[arg(long)]
        max_concurrency: Option<u32>,
        /// Cap on per-handler CPU fuel (instruction-count proxy).
        #[arg(long)]
        max_fuel: Option<u64>,
    },
    /// Disable handlers on the site (keeps the allowlist + caps for a later re-enable).
    Disable,
    /// Add interface(s) to the site's import allowlist.
    Allow {
        /// Interface name(s), e.g. `sql wasi:keyvalue invoke`.
        #[arg(required = true, value_name = "IMPORT")]
        imports: Vec<String>,
    },
    /// Remove interface(s) from the site's import allowlist.
    Deny {
        /// Interface name(s) to remove.
        #[arg(required = true, value_name = "IMPORT")]
        imports: Vec<String>,
    },
    /// Configure the edge response cache for handler routes.
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
    /// Configure browser cookie → application-bearer session auth.
    CookieAuth {
        #[command(subcommand)]
        command: CookieAuthCommand,
    },
}

#[derive(Debug, Subcommand)]
enum CacheCommand {
    /// Enable the edge response cache, optionally with per-entry / TTL caps.
    Enable {
        /// Max cached response body size (bytes).
        #[arg(long)]
        max_entry_bytes: Option<u64>,
        /// Max cache entry lifetime (seconds).
        #[arg(long)]
        max_ttl_secs: Option<u64>,
    },
    /// Disable the edge response cache.
    Disable,
}

#[derive(Debug, Subcommand)]
enum CookieAuthCommand {
    /// Treat the named cookie as the application bearer for this site.
    Set {
        /// Cookie name (e.g. `__Host-session`).
        #[arg(long)]
        cookie_name: String,
        /// An extra allowed browser origin (for a cross-origin app); repeatable.
        #[arg(long = "allowed-origin", value_name = "ORIGIN")]
        allowed_origins: Vec<String>,
    },
    /// Turn off cookie session auth.
    Clear,
}

/// Entry point for `boatramp handlers`.
pub async fn run(args: HandlersArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let mut site_config = cp.fetch_site_config(&site).await?;

    if matches!(args.command, HandlersCommand::Show) {
        print_policy(&site, site_config.handlers.as_ref());
        return Ok(());
    }

    let handlers = site_config
        .handlers
        .get_or_insert_with(HandlersSiteConfig::default);
    match args.command {
        HandlersCommand::Show => unreachable!("handled above"),
        HandlersCommand::Enable {
            allow,
            max_memory_mb,
            max_timeout_ms,
            max_concurrency,
            max_fuel,
        } => {
            handlers.enabled = true;
            if !allow.is_empty() {
                handlers.allow_imports = dedup(allow);
            }
            if max_memory_mb.is_some() {
                handlers.max_memory_mb = max_memory_mb;
            }
            if max_timeout_ms.is_some() {
                handlers.max_timeout_ms = max_timeout_ms;
            }
            if max_concurrency.is_some() {
                handlers.max_concurrency = max_concurrency;
            }
            if max_fuel.is_some() {
                handlers.max_fuel = max_fuel;
            }
            println!(
                "handlers enabled for {site} (allow_imports: {})",
                fmt_list(&handlers.allow_imports)
            );
        }
        HandlersCommand::Disable => {
            handlers.enabled = false;
            println!("handlers disabled for {site}");
        }
        HandlersCommand::Allow { imports } => {
            for import in imports {
                if !handlers.allow_imports.iter().any(|e| e == &import) {
                    handlers.allow_imports.push(import);
                }
            }
            println!(
                "allow_imports for {site}: {}",
                fmt_list(&handlers.allow_imports)
            );
        }
        HandlersCommand::Deny { imports } => {
            handlers.allow_imports.retain(|e| !imports.contains(e));
            println!(
                "allow_imports for {site}: {}",
                fmt_list(&handlers.allow_imports)
            );
        }
        HandlersCommand::Cache { command } => match command {
            CacheCommand::Enable {
                max_entry_bytes,
                max_ttl_secs,
            } => {
                let cache = handlers
                    .cache
                    .get_or_insert_with(HandlerCacheConfig::default);
                cache.enabled = true;
                if max_entry_bytes.is_some() {
                    cache.max_entry_bytes = max_entry_bytes;
                }
                if max_ttl_secs.is_some() {
                    cache.max_ttl_secs = max_ttl_secs;
                }
                println!("handlers cache enabled for {site}");
            }
            CacheCommand::Disable => {
                if let Some(cache) = handlers.cache.as_mut() {
                    cache.enabled = false;
                }
                println!("handlers cache disabled for {site}");
            }
        },
        HandlersCommand::CookieAuth { command } => match command {
            CookieAuthCommand::Set {
                cookie_name,
                allowed_origins,
            } => {
                let ca = handlers
                    .cookie_auth
                    .get_or_insert_with(CookieAuthConfig::default);
                ca.cookie_name = cookie_name.clone();
                ca.allowed_origins = allowed_origins;
                println!("cookie auth on {site}: cookie {cookie_name}");
            }
            CookieAuthCommand::Clear => {
                handlers.cookie_auth = None;
                println!("cookie auth disabled for {site}");
            }
        },
    }

    cp.put_site_config(&site, &site_config).await?;
    Ok(())
}

/// De-duplicate while preserving order.
fn dedup(imports: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(imports.len());
    for import in imports {
        if !out.contains(&import) {
            out.push(import);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_preserves_first_occurrence_order() {
        let got = dedup(vec![
            "sql".into(),
            "wasi:keyvalue".into(),
            "sql".into(),
            "invoke".into(),
        ]);
        assert_eq!(got, vec!["sql", "wasi:keyvalue", "invoke"]);
    }

    #[test]
    fn enable_and_allow_deny_mutate_the_policy() {
        // The pure mutation the subcommands apply, exercised on a fresh policy.
        let mut h = HandlersSiteConfig::default();
        assert!(!h.enabled);
        // enable --allow sql --allow wasi:keyvalue
        h.enabled = true;
        h.allow_imports = dedup(vec!["sql".into(), "wasi:keyvalue".into()]);
        // allow invoke (idempotent)
        for import in ["invoke", "sql"] {
            if !h.allow_imports.iter().any(|e| e == import) {
                h.allow_imports.push(import.to_string());
            }
        }
        assert_eq!(h.allow_imports, vec!["sql", "wasi:keyvalue", "invoke"]);
        // deny wasi:keyvalue
        let remove = ["wasi:keyvalue".to_string()];
        h.allow_imports.retain(|e| !remove.contains(e));
        assert_eq!(h.allow_imports, vec!["sql", "invoke"]);
        // disable keeps the allowlist
        h.enabled = false;
        assert_eq!(h.allow_imports, vec!["sql", "invoke"]);
    }
}

/// Render a string list as `[a, b]` or `[]`.
fn fmt_list(list: &[String]) -> String {
    format!("[{}]", list.join(", "))
}

/// Print the site's handler policy for `handlers show`.
fn print_policy(site: &str, handlers: Option<&HandlersSiteConfig>) {
    match handlers.filter(|h| h.enabled) {
        None => {
            println!("handlers: disabled for {site}");
            println!("  enable with: boatramp handlers enable --site {site} [--allow <import>]…");
        }
        Some(h) => {
            println!("handlers: enabled for {site}");
            println!("  allow_imports: {}", fmt_list(&h.allow_imports));
            if let Some(v) = h.max_memory_mb {
                println!("  max_memory_mb: {v}");
            }
            if let Some(v) = h.max_timeout_ms {
                println!("  max_timeout_ms: {v}");
            }
            if let Some(v) = h.max_concurrency {
                println!("  max_concurrency: {v}");
            }
            if let Some(v) = h.max_fuel {
                println!("  max_fuel: {v}");
            }
        }
    }
}
