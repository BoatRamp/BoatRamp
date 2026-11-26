//! The `handlers` subcommand: manage a site's **handler policy** — the
//! `SiteConfig.handlers` gate (`enabled` + the `allow_imports` allowlist + resource
//! caps + the `secrets` ENV-name → secret-ref pool) that activation prechecks a
//! handler-shipping deployment against. Edits the site's `SiteConfig.handlers` via
//! the control-plane API (the same `PUT /api/sites/:site/config` the console form
//! and `apply` use).
//!
//! A deployment that ships handlers is refused at activation unless the site is
//! `enabled` and its `allow_imports` is a superset of every handler's declared imports.
//!
//! `handlers secrets` is the config-only counterpart to a `sites:` block's
//! `handlers.secrets` map: it read-modify-writes just that map (via the same
//! `get`/`put` site-config round trip every other `handlers` subcommand uses), so a
//! handler↔secret binding can be changed without redeploying the site's content.

use std::collections::BTreeMap;

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
    /// A `secrets set` argument was not `ENV=secret-ref` (or had an empty ENV name).
    #[error("invalid secrets binding {0:?}: expected ENV=secret-ref")]
    InvalidSecretBinding(String),
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
    /// Manage the site's handler↔secret bindings (`[handlers].secrets`: ENV name →
    /// secret-ref) — config-only, no content redeploy.
    Secrets {
        #[command(subcommand)]
        command: SecretsCommand,
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

#[derive(Debug, Subcommand)]
enum SecretsCommand {
    /// Show the site's current ENV name → secret-ref bindings.
    List,
    /// Set (insert or update) one or more `ENV_NAME=secret-ref` bindings.
    Set {
        /// `ENV_NAME=secret-ref` pair, e.g. `API_KEY=boatramp:api-key`; repeatable.
        #[arg(required = true, value_name = "ENV=REF")]
        bindings: Vec<String>,
    },
    /// Remove one or more ENV name(s) from the bindings.
    Unset {
        /// ENV name(s) to remove.
        #[arg(required = true, value_name = "ENV")]
        names: Vec<String>,
    },
}

/// The result of a `handlers` subcommand, rendered by [`crate::output`].
// `Show` carries the full `HandlersSiteConfig`; a larger data variant is fine
// and clearer than boxing the policy payload.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum HandlersOutput {
    /// `handlers show` — the site's current handler policy (`None` ⇒ unset).
    Show {
        site: String,
        handlers: Option<HandlersSiteConfig>,
    },
    /// Handlers were enabled on the site.
    Enabled {
        site: String,
        allow_imports: Vec<String>,
    },
    /// Handlers were disabled on the site.
    Disabled { site: String },
    /// The import allowlist was updated (`allow` / `deny`).
    AllowImports {
        site: String,
        allow_imports: Vec<String>,
    },
    /// The edge response cache was enabled.
    CacheEnabled { site: String },
    /// The edge response cache was disabled.
    CacheDisabled { site: String },
    /// Cookie → bearer session auth was configured.
    CookieAuthSet { site: String, cookie_name: String },
    /// Cookie session auth was turned off.
    CookieAuthCleared { site: String },
    /// `handlers secrets list` — the site's current ENV name → secret-ref bindings.
    SecretsList {
        site: String,
        secrets: BTreeMap<String, String>,
    },
    /// The handler secret bindings were updated (`secrets set` / `secrets unset`) —
    /// carries the resulting bindings.
    Secrets {
        site: String,
        secrets: BTreeMap<String, String>,
    },
}

impl crate::output::Rendered for HandlersOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Show { site, handlers } => write_policy(w, site, handlers.as_ref()),
            Self::Enabled {
                site,
                allow_imports,
            } => writeln!(
                w,
                "handlers enabled for {site} (allow_imports: {})",
                fmt_list(allow_imports)
            ),
            Self::Disabled { site } => writeln!(w, "handlers disabled for {site}"),
            Self::AllowImports {
                site,
                allow_imports,
            } => writeln!(w, "allow_imports for {site}: {}", fmt_list(allow_imports)),
            Self::CacheEnabled { site } => {
                writeln!(w, "handlers cache enabled for {site}")
            }
            Self::CacheDisabled { site } => {
                writeln!(w, "handlers cache disabled for {site}")
            }
            Self::CookieAuthSet { site, cookie_name } => {
                writeln!(w, "cookie auth on {site}: cookie {cookie_name}")
            }
            Self::CookieAuthCleared { site } => {
                writeln!(w, "cookie auth disabled for {site}")
            }
            Self::SecretsList { site, secrets } => write_secrets(w, site, secrets),
            Self::Secrets { site, secrets } => write_secrets(w, site, secrets),
        }
    }
}

/// Entry point for `boatramp handlers`.
pub async fn run(args: HandlersArgs, config: &ProjectConfig) -> Result<HandlersOutput> {
    let (server, site) = client::resolve_target(args.server, args.site, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );
    let mut site_config = cp.fetch_site_config(&site).await?;

    if matches!(args.command, HandlersCommand::Show) {
        return Ok(HandlersOutput::Show {
            site,
            handlers: site_config.handlers.clone(),
        });
    }
    if matches!(
        args.command,
        HandlersCommand::Secrets {
            command: SecretsCommand::List
        }
    ) {
        let secrets = site_config
            .handlers
            .as_ref()
            .map(|h| h.secrets.clone())
            .unwrap_or_default();
        return Ok(HandlersOutput::SecretsList { site, secrets });
    }

    let handlers = site_config
        .handlers
        .get_or_insert_with(HandlersSiteConfig::default);
    let out = match args.command {
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
            HandlersOutput::Enabled {
                site: site.clone(),
                allow_imports: handlers.allow_imports.clone(),
            }
        }
        HandlersCommand::Disable => {
            handlers.enabled = false;
            HandlersOutput::Disabled { site: site.clone() }
        }
        HandlersCommand::Allow { imports } => {
            for import in imports {
                if !handlers.allow_imports.iter().any(|e| e == &import) {
                    handlers.allow_imports.push(import);
                }
            }
            HandlersOutput::AllowImports {
                site: site.clone(),
                allow_imports: handlers.allow_imports.clone(),
            }
        }
        HandlersCommand::Deny { imports } => {
            handlers.allow_imports.retain(|e| !imports.contains(e));
            HandlersOutput::AllowImports {
                site: site.clone(),
                allow_imports: handlers.allow_imports.clone(),
            }
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
                HandlersOutput::CacheEnabled { site: site.clone() }
            }
            CacheCommand::Disable => {
                if let Some(cache) = handlers.cache.as_mut() {
                    cache.enabled = false;
                }
                HandlersOutput::CacheDisabled { site: site.clone() }
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
                HandlersOutput::CookieAuthSet {
                    site: site.clone(),
                    cookie_name,
                }
            }
            CookieAuthCommand::Clear => {
                handlers.cookie_auth = None;
                HandlersOutput::CookieAuthCleared { site: site.clone() }
            }
        },
        HandlersCommand::Secrets { command } => match command {
            SecretsCommand::List => unreachable!("handled above"),
            SecretsCommand::Set { bindings } => {
                for binding in &bindings {
                    let (env, secret_ref) = parse_secret_binding(binding)?;
                    handlers.secrets.insert(env, secret_ref);
                }
                HandlersOutput::Secrets {
                    site: site.clone(),
                    secrets: handlers.secrets.clone(),
                }
            }
            SecretsCommand::Unset { names } => {
                for name in &names {
                    handlers.secrets.remove(name);
                }
                HandlersOutput::Secrets {
                    site: site.clone(),
                    secrets: handlers.secrets.clone(),
                }
            }
        },
    };

    cp.put_site_config(&site, &site_config).await?;
    Ok(out)
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

/// Render a string list as `[a, b]` or `[]`.
fn fmt_list(list: &[String]) -> String {
    format!("[{}]", list.join(", "))
}

/// Render a secrets map as `{a=1, b=2}` or `{}` (iteration order is the
/// `BTreeMap`'s sorted key order, so this is deterministic).
fn fmt_secrets(secrets: &BTreeMap<String, String>) -> String {
    let entries: Vec<String> = secrets.iter().map(|(k, v)| format!("{k}={v}")).collect();
    format!("{{{}}}", entries.join(", "))
}

/// Parse a `secrets set ENV=secret-ref` argument, erroring on a missing `=` or an
/// empty ENV name. Mirrors `sync`'s `--tag key=value` parsing.
fn parse_secret_binding(pair: &str) -> Result<(String, String)> {
    let (env, secret_ref) = pair
        .split_once('=')
        .ok_or_else(|| Error::InvalidSecretBinding(pair.to_string()))?;
    let env = env.trim();
    if env.is_empty() {
        return Err(Error::InvalidSecretBinding(pair.to_string()));
    }
    Ok((env.to_string(), secret_ref.to_string()))
}

/// Write a site's handler secret bindings for `secrets list` / `secrets set` /
/// `secrets unset`.
fn write_secrets(
    w: &mut dyn std::io::Write,
    site: &str,
    secrets: &BTreeMap<String, String>,
) -> std::io::Result<()> {
    if secrets.is_empty() {
        return writeln!(w, "secrets: none set for {site}");
    }
    writeln!(w, "secrets for {site}:")?;
    for (env, secret_ref) in secrets {
        writeln!(w, "  {env} = {secret_ref}")?;
    }
    Ok(())
}

/// Write the site's handler policy for `handlers show`.
fn write_policy(
    w: &mut dyn std::io::Write,
    site: &str,
    handlers: Option<&HandlersSiteConfig>,
) -> std::io::Result<()> {
    match handlers.filter(|h| h.enabled) {
        None => {
            writeln!(w, "handlers: disabled for {site}")?;
            writeln!(
                w,
                "  enable with: boatramp handlers enable --site {site} [--allow <import>]…"
            )?;
        }
        Some(h) => {
            writeln!(w, "handlers: enabled for {site}")?;
            writeln!(w, "  allow_imports: {}", fmt_list(&h.allow_imports))?;
            if let Some(v) = h.max_memory_mb {
                writeln!(w, "  max_memory_mb: {v}")?;
            }
            if let Some(v) = h.max_timeout_ms {
                writeln!(w, "  max_timeout_ms: {v}")?;
            }
            if let Some(v) = h.max_concurrency {
                writeln!(w, "  max_concurrency: {v}")?;
            }
            if let Some(v) = h.max_fuel {
                writeln!(w, "  max_fuel: {v}")?;
            }
            if !h.secrets.is_empty() {
                writeln!(w, "  secrets: {}", fmt_secrets(&h.secrets))?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::Rendered;

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

    #[test]
    fn parse_secret_binding_splits_on_first_equals() {
        let (env, secret_ref) = parse_secret_binding("API_KEY=boatramp:api-key").unwrap();
        assert_eq!(env, "API_KEY");
        assert_eq!(secret_ref, "boatramp:api-key");
        // Only the first `=` splits, so a ref may itself contain `=`.
        let (env, secret_ref) = parse_secret_binding("TOKEN=env:SOME=THING").unwrap();
        assert_eq!(env, "TOKEN");
        assert_eq!(secret_ref, "env:SOME=THING");
    }

    #[test]
    fn parse_secret_binding_trims_the_env_name() {
        let (env, secret_ref) = parse_secret_binding(" API_KEY =boatramp:api-key").unwrap();
        assert_eq!(env, "API_KEY");
        assert_eq!(secret_ref, "boatramp:api-key");
    }

    #[test]
    fn parse_secret_binding_rejects_missing_equals_and_empty_env() {
        assert!(matches!(
            parse_secret_binding("no-equals-sign"),
            Err(Error::InvalidSecretBinding(_))
        ));
        assert!(matches!(
            parse_secret_binding("=boatramp:api-key"),
            Err(Error::InvalidSecretBinding(_))
        ));
        assert!(matches!(
            parse_secret_binding("   =boatramp:api-key"),
            Err(Error::InvalidSecretBinding(_))
        ));
    }

    #[test]
    fn secrets_set_and_unset_mutate_the_pool_read_modify_write() {
        // The pure mutation `secrets set` / `secrets unset` apply, exercised on a
        // fresh policy — no content redeploy, just the `[handlers].secrets` map.
        let mut h = HandlersSiteConfig::default();
        assert!(h.secrets.is_empty());
        // secrets set API_KEY=boatramp:api-key DB_URL=env:DATABASE_URL
        for pair in ["API_KEY=boatramp:api-key", "DB_URL=env:DATABASE_URL"] {
            let (env, secret_ref) = parse_secret_binding(pair).unwrap();
            h.secrets.insert(env, secret_ref);
        }
        assert_eq!(
            h.secrets.get("API_KEY").map(String::as_str),
            Some("boatramp:api-key")
        );
        assert_eq!(
            h.secrets.get("DB_URL").map(String::as_str),
            Some("env:DATABASE_URL")
        );
        // secrets set API_KEY=boatramp:api-key-v2 (update, not duplicate)
        let (env, secret_ref) = parse_secret_binding("API_KEY=boatramp:api-key-v2").unwrap();
        h.secrets.insert(env, secret_ref);
        assert_eq!(h.secrets.len(), 2);
        assert_eq!(
            h.secrets.get("API_KEY").map(String::as_str),
            Some("boatramp:api-key-v2")
        );
        // secrets unset DB_URL
        h.secrets.remove("DB_URL");
        assert_eq!(h.secrets.len(), 1);
        assert!(!h.secrets.contains_key("DB_URL"));
        // unsetting an absent name is a no-op, not an error
        h.secrets.remove("NEVER_SET");
        assert_eq!(h.secrets.len(), 1);
    }

    #[test]
    fn secrets_output_renders_human_and_json() {
        let secrets = BTreeMap::from([("API_KEY".to_string(), "boatramp:api-key".to_string())]);
        let out = HandlersOutput::Secrets {
            site: "demo".to_string(),
            secrets: secrets.clone(),
        };
        let mut buf = Vec::new();
        out.render_human(&mut buf).unwrap();
        let text = String::from_utf8(buf).unwrap();
        assert!(text.contains("demo"));
        assert!(text.contains("API_KEY = boatramp:api-key"));

        let json = serde_json::to_value(&out).unwrap();
        assert_eq!(json["result"], "secrets");
        assert_eq!(json["site"], "demo");
        assert_eq!(json["secrets"]["API_KEY"], "boatramp:api-key");

        // An empty pool renders a clear "none set" line, not a blank body.
        let empty = HandlersOutput::SecretsList {
            site: "demo".to_string(),
            secrets: BTreeMap::new(),
        };
        let mut buf = Vec::new();
        empty.render_human(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "secrets: none set for demo\n"
        );
    }
}
