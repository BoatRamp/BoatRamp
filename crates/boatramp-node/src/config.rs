//! Local configuration files (RON).
//!
//! Two distinct files, split by audience:
//!
//! - **`project.cfg`** — one per project folder, read by the client commands
//!   (`sync`, `build`, `bundle`, `validate`): where/how to publish, the optional
//!   build/bundle steps, and the deploy-scoped `routing` config that is folded
//!   into the immutable deployment manifest. See [`ProjectConfig`].
//! - **`boatramp.cfg`** — the server daemon config, read by `serve`:
//!   `serve` / `handlers` / `cluster`. See [`ServerConfig`].
//!
//! Both are RON; a missing file yields the default config.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use boatramp_core::config::DeployConfig;
use serde::{Deserialize, Serialize};

/// RON parse options shared by both loaders: `implicit_some` lets optional fields
/// be written as bare values (`server: "..."`, not `Some("...")`). `pub` so the
/// binary (which re-exports this module) can parse a manifest with the same
/// options after the module moved into this crate.
pub fn ron_options() -> ron::Options {
    ron::Options::default().with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME)
}

/// The wire format an operator-authored config file is decoded as (v0.6.5).
///
/// Config files are historically RON. JSON was added as a second **input** format
/// purely for interop — so a config can be generated from Nickel (`nickel export` →
/// JSON) and fed to boatramp unchanged. It is an alternative *decoder* into the
/// **same** typed structs (they all derive serde `Deserialize` with externally-tagged
/// enums + `deny_unknown_fields`), so JSON preserves every variant name and the same
/// strictness — no type changes, and the same downstream validation runs either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ConfigFormat {
    /// RON (the historical, default format). Selected for every non-`.json`
    /// extension (`.cfg` / `.ron` / none).
    #[default]
    Ron,
    /// JSON — for configs generated from Nickel (`nickel export`) or any JSON
    /// pipeline. Selected for a `.json` (case-insensitive) extension.
    Json,
}

/// Resolve the [`ConfigFormat`] for a config path.
///
/// The rule is explicit and predictable (config is the operator trust boundary, so
/// there is **no content-sniffing** — a sniff could silently RON-parse a JSON file
/// into a wrong-but-valid config, and vice versa):
///
/// 1. an explicit `override_` (the CLI `--format ron|json`) always wins; else
/// 2. auto by extension — a `.json` (case-insensitive) extension ⇒ [`ConfigFormat::Json`];
///    everything else (`.cfg` / `.ron` / no extension) ⇒ [`ConfigFormat::Ron`].
pub fn resolve_format(path: &Path, override_: Option<ConfigFormat>) -> ConfigFormat {
    if let Some(fmt) = override_ {
        return fmt;
    }
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) if ext.eq_ignore_ascii_case("json") => ConfigFormat::Json,
        _ => ConfigFormat::Ron,
    }
}

/// A failure loading or parsing a local config file (`project.cfg` / `boatramp.cfg`).
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Wraps an underlying error with the file path it came from.
    #[error("{path}: {source}")]
    File {
        path: String,
        #[source]
        source: Box<Self>,
    },
    /// The RON document failed to parse.
    #[error("invalid config syntax: {0}")]
    Ron(#[from] ron::error::SpannedError),
    /// The JSON document failed to parse (JSON config input — e.g. from
    /// `nickel export`). Same strictness as RON: `deny_unknown_fields` on the
    /// structs makes a typo'd/unknown key a hard error here, not a silent drop.
    #[error("invalid JSON config: {0}")]
    Json(#[from] serde_json::Error),
    /// The `routing` section failed its compile-check.
    #[error("routing: {0}")]
    Routing(#[from] boatramp_core::ConfigError),
    /// Reading the file failed (other than not-found, which yields defaults).
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// An environment-variable override could not be parsed (bad number/bool).
    #[error("environment variable {var}: {reason}")]
    Env {
        /// The offending `BOATRAMP_*` variable. Owned because some names are built
        /// dynamically (the keyed `databases` map, whose members aren't known at
        /// compile time).
        var: String,
        /// Why the value was rejected.
        reason: String,
    },
    /// A `handlers.bindings.sql.databases` binding name is not a safe URL path
    /// segment — it is threaded verbatim into `/api/sql/{db}/…` and `--db`, so an
    /// empty/`//`-collapsing or path-separator-bearing name is refused at load
    /// (fail-closed) rather than emitting a malformed control-plane path.
    #[error("SQL database binding {name:?}: {reason}{cure}")]
    InvalidDbName {
        /// The offending binding name (the `databases` map key).
        name: String,
        /// Why it was rejected (from the canonical validator).
        reason: &'static str,
        /// A trailing remediation hint (empty unless this is the legacy empty-name
        /// default case, where it points at the `default` cure).
        cure: &'static str,
    },
    /// A `[serve.blob_backends.<project>]` key is not a valid project name, or is the reserved
    /// `default` project (which always resolves the global `[serve]` backend). Refused at config load
    /// (fail-closed) rather than silently binding a project's blobs to the wrong backend.
    #[error("per-project blob backend {name:?}: {reason}{cure}")]
    InvalidBlobBackendProject {
        /// The offending project key (the `blob_backends` map key).
        name: String,
        /// Why it was rejected.
        reason: &'static str,
        /// A trailing remediation hint.
        cure: &'static str,
    },
    /// A `[serve.listeners.<name>]` (host-owned inbound-TCP listener, PLAN-handler-tcp-inbound) is
    /// invalid: a blank `component`, a non-positive `max_conns`/timeout, or a declared `tls` block
    /// missing its `cert_file`/`key_file` (or a malformed STARTTLS grammar). Refused at config load
    /// (fail-closed, boot-LOUD) rather than binding a listener that would silently mislead the
    /// operator. (Host-side TLS/STARTTLS and a host-mediated `tcp-egress` `egress_allowlist` are
    /// supported — cap-req 06 / 19.)
    #[error("inbound TCP listener {name:?}: {reason}{cure}")]
    InvalidListener {
        /// The offending listener key (the `listeners` map key).
        name: String,
        /// Why it was rejected.
        reason: &'static str,
        /// A trailing remediation hint (empty unless there is a concrete cure to point at).
        cure: &'static str,
    },
    /// The layered config pipeline failed to resolve/extract the merged config (a bad
    /// numeric/addr env value that figment's lossy coercion rejects, a `[cluster]` missing
    /// its required `listen`, etc.). The figment error is rendered to a string so
    /// `ConfigError` stays small.
    #[error("config resolution: {0}")]
    Resolve(String),
}

/// Project configuration, loaded from `project.cfg` (RON) in the project folder.
///
/// Read by the client commands (`sync`, `build`, `bundle`, `validate`).
/// Everything is optional; a missing file is the default.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ProjectConfig {
    /// Where and how to publish this project.
    pub publish: PublishConfig,
    /// Optional build step run before `sync`.
    pub build: Option<BuildConfig>,
    /// Optional embedded-bundler step (`bundler` feature).
    pub bundle: Option<BundleConfig>,
    /// Deploy-scoped routing/handlers config. Folded into the deployment
    /// manifest at `sync` (so it is atomic with the content and rolls back with
    /// it). The bulk of a project's config — redirects, rewrites, headers,
    /// handlers, consumers, crons, streams.
    pub routing: DeployConfig,
}

impl ProjectConfig {
    /// Parse a `project.cfg` document as **RON** (the default). Kept for the existing
    /// callers/tests; [`Self::parse_with_format`] is the format-aware entry point.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        Self::parse_with_format(text, ConfigFormat::Ron)
    }

    /// Parse a `project.cfg` document in `fmt` (RON or JSON). The deserializer is
    /// selected by format (RON ⇒ [`ron_options`], JSON ⇒ `serde_json`) into the SAME
    /// typed struct; the `routing` section is then compile-checked (route patterns,
    /// cron schedules, imports) regardless of format so a bad config fails fast.
    pub fn parse_with_format(text: &str, fmt: ConfigFormat) -> Result<Self, ConfigError> {
        let config: Self = match fmt {
            ConfigFormat::Ron => ron_options().from_str(text)?,
            ConfigFormat::Json => serde_json::from_str(text)?,
        };
        config.routing.compile_check()?;
        Ok(config)
    }

    /// Load from `path`, decoding as RON or JSON per [`resolve_format`] (`override_`
    /// wins; else `.json` ⇒ JSON, everything else ⇒ RON). A missing file yields the
    /// default config (unlike an apply manifest).
    pub fn load(path: &Path, override_: Option<ConfigFormat>) -> Result<Self, ConfigError> {
        let fmt = resolve_format(path, override_);
        match std::fs::read_to_string(path) {
            Ok(contents) => {
                Self::parse_with_format(&contents, fmt).map_err(|err| ConfigError::File {
                    path: path.display().to_string(),
                    source: Box::new(err),
                })
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err.into()),
        }
    }
}

/// Server daemon configuration, loaded from `boatramp.cfg` (RON). Read by
/// `boatramp serve`; flags/env override the `serve` values.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    /// Server defaults for `serve` (flag/env override these).
    pub serve: Option<ServeConfig>,
    /// Server-side handler runtime config (which backend serves each binding),
    /// consumed only with the `handlers` feature.
    pub handlers: Option<HandlersConfig>,
    /// Self-hosted cluster mode (consumed only with the `cluster` feature).
    pub cluster: Option<ClusterConfig>,
    /// Opt-in **compute** backends. Present ⇒ this node
    /// runs compute workloads via the backends it can offer; absent ⇒ no compute
    /// (the reconcile loop stays a no-op).
    pub compute: Option<ComputeConfig>,
    /// Operator security posture (the hardening knobs): a profile
    /// preset + overrides, resolved at startup. Absent ⇒ the strict
    /// `multi-tenant` default. Operator-only — never part of site config.
    pub security: Option<boatramp_core::security::SecurityConfig>,
    /// Secrets-at-rest envelope. Absent ⇒ private
    /// keys stored cleartext in the (replicated) control plane.
    pub secrets: Option<SecretsConfig>,
    /// Overlay forward-flow serve roles (consumed only with the `overlay` feature): stand up a
    /// relay/ingress and/or egress/terminator so a remote `boatramp forward` can reach in-cluster
    /// services over the relay-blind overlay. Absent ⇒ this node serves no overlay roles.
    pub overlay: Option<OverlayServeConfig>,
}

/// `[overlay]` — the forward-flow **serve roles** this node runs (the server side of
/// `boatramp forward`). A node may be a **relay/ingress** (accepts external client dials and
/// forwards them, blind, into the cluster), an **egress/terminator** (fronts local backend
/// services), or both. A relay's `routes` double as the self-serve **discovery directory**: the
/// control plane resolves `boatramp forward svc/<name>` against them and mints the dial capability,
/// so the CLI needs no hand-typed topology (the explicit flags / `overlay grant --ticket` remain for
/// control-plane-less forwards).
#[cfg_attr(not(feature = "overlay"), allow(dead_code))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OverlayServeConfig {
    /// This node's overlay identity — an `ed25519:<hex>` seed inline, or a path to a file holding
    /// one. Auto-generated at `<data-dir>/overlay/identity.key` when unset. This is the identity a
    /// relay's clients and an egress's relay pin.
    pub identity: Option<String>,
    /// The dial-capability **trust root** (`ed25519:`/`es256:` tagged hex) every dial is verified
    /// against. Defaults to `serve.auth_root_public_key` (the cluster's control-plane root).
    pub trust_root: Option<String>,
    /// Whether dials must be end-to-end encrypted (fail-closed). Default `true`.
    pub encryption_required: Option<bool>,
    /// Server cap on a minted dial capability's lifetime (seconds). A `POST /api/overlay/dial`
    /// request's `ttl_secs` is clamped to this (overlay-dial caps are offline-verified — no
    /// revocation — so an unbounded TTL is a standing risk). Unset ⇒ 24h.
    pub max_dial_ttl_secs: Option<u64>,
    /// Bind a **relay/ingress** here (UDP/QUIC). Unset ⇒ this node runs no relay.
    pub relay_listen: Option<SocketAddr>,
    /// The relay's transport-layer client-auth posture (Security Blocker #1):
    /// `"capability-only"` accepts any client key at TLS and rests authorization on the capability
    /// gate + the egress's E2EE-proven re-authz (self-serve, no pre-enrollment); `"mutual-pin"` keeps
    /// the `allowed_clients` RPK pin as a strictly-more-restrictive pre-filter. REQUIRED for a relay
    /// unless `allowed_clients` is non-empty (which defaults to mutual-pin); a relay with neither is a
    /// hard error — an empty allowlist is never silently treated as accept-any.
    pub client_auth: Option<String>,
    /// The client overlay identities (`ed25519:`/`es256:` tagged hex) the relay mutual-authenticates
    /// — the enrolled operators/clients allowed to dial under `client_auth = "mutual-pin"`. (A
    /// capability is still required and is the authority; this is the relay's transport-layer
    /// pre-filter. Ignored under `"capability-only"`.)
    pub allowed_clients: Vec<String>,
    /// Relay routing: a requested service → its egress. Used when `relay_listen` is set.
    pub routes: Vec<OverlayRoute>,
    /// Reverse ingress (`boatramp expose`): accept exposer REGISTRATIONS on this relay, so a LOCAL
    /// service published into the cluster (the exposer dials OUT and parks a connection) is reachable
    /// by a cluster-side `boatramp forward svc/<name>`. Opt-in — a relay accepts exposers only when
    /// this is `true`; `None`/`false` keeps the forward-only relay. Requires `relay_listen`. The
    /// registration is holder-bound to an `overlay-publish` capability the relay verifies against
    /// `trust_root`; first-live-claim-wins on the name.
    pub accept_exposed: Option<bool>,
    /// Digit count for the human-typeable pairing SHORT CODE a relay can mint alongside a `bropair1…`
    /// code (overlay follow-up #2 inc3, `boatramp overlay pair-code --short`): default 8
    /// (`K = 10^8 ≈ 2^26.6`), floor 7, ceiling 10 (clamped). Independent of `accept_exposed` — read
    /// only when a relay actually mints/redeems a short code.
    pub pair_short_code_digits: Option<usize>,
    /// Per-relay operator choice for the pairing PARK service (owner decision: "the relay manager
    /// should choose, per relay, whether PARK is offered as an OPEN or AUTHENTICATED service"):
    /// `"open"` (the DEFAULT) keeps today's behavior — an unauthenticated park, bounded only by the
    /// existing park budget + per-IP cap, with the human-compared SAS as the trust anchor;
    /// `"authenticated"` additionally requires the parking accepter to present a holder-bound
    /// `overlay-pairing-park` capability and prove possession, exactly like `accept_exposed`'s
    /// exposer-registration path (`register_exposer`). REDEEM stays unauthenticated in BOTH modes —
    /// the unpaired dialer is, by design, not membership-gated; the SAS backstops it. Read only when a
    /// relay actually runs the pairing rendezvous (the same `accept_exposed` ingress-router branch
    /// `pair_short_code_digits` shares).
    pub pairing_park: Option<String>,
    /// Bind an **egress/terminator** here (UDP/QUIC). Unset ⇒ this node runs no egress.
    pub egress_listen: Option<SocketAddr>,
    /// Egress service map: a service name → the local backend it fronts. Used when `egress_listen`
    /// is set; a service not listed here is refused (the egress authorizes only what it fronts).
    pub services: Vec<OverlayService>,
}

/// One relay route: the egress a requested `service` is forwarded to.
#[cfg_attr(not(feature = "overlay"), allow(dead_code))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OverlayRoute {
    /// The in-cluster service name (e.g. `svc/db`).
    pub service: String,
    /// The egress's overlay UDP address to forward to.
    pub egress: Option<SocketAddr>,
    /// The egress's overlay identity (`ed25519:`/`es256:` tagged hex) to pin.
    pub egress_id: Option<String>,
}

/// One egress service: the local backend a `service` name fronts.
#[cfg_attr(not(feature = "overlay"), allow(dead_code))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OverlayService {
    /// The in-cluster service name this egress fronts (e.g. `svc/db`).
    pub name: String,
    /// The local backend address the service maps to (e.g. `127.0.0.1:5432`).
    pub backend: Option<SocketAddr>,
}

/// `secrets` section — envelope encryption for private keys at rest.
#[cfg_attr(not(feature = "cluster"), allow(dead_code))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecretsConfig {
    /// Backend: `"local"` (machine-local AES-256-GCM KEK) or `"vault"` (Vault
    /// Transit). Empty/other ⇒ no wrapping. In a cluster a local KEK must be the
    /// **same file on every node** (wrapped certs replicate); Vault avoids that.
    pub envelope: String,
    /// Local-KEK key file (`envelope = "local"`). Default
    /// `<data-dir>/secrets/kek`. Auto-generated `0600` if absent.
    pub kek_file: Option<PathBuf>,
    /// Vault Transit config (`envelope = "vault"`).
    pub vault: Option<VaultSecretsConfig>,
}

/// Vault Transit settings for `envelope = "vault"`. The token is read from the
/// environment (`token_env`), never stored in the config file.
#[cfg_attr(not(all(feature = "cluster", feature = "acme-dns")), allow(dead_code))]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultSecretsConfig {
    /// Vault address, e.g. `https://vault:8200`.
    pub addr: String,
    /// Transit key name to wrap under.
    pub key: String,
    /// Environment variable holding the Vault token (default `VAULT_TOKEN`).
    #[serde(default = "default_vault_token_env")]
    pub token_env: String,
}

fn default_vault_token_env() -> String {
    "VAULT_TOKEN".to_string()
}

impl Default for VaultSecretsConfig {
    fn default() -> Self {
        Self {
            addr: String::new(),
            key: String::new(),
            token_env: default_vault_token_env(),
        }
    }
}

/// The RESERVED compute-workload name prefix (#501 Stage B LOW-2). boatramp DERIVES the
/// per-project managed-database server workloads with this prefix
/// (`boatramp_storage::tenant_provision::DERIVED_MANAGED_DB_PREFIX`), so an operator must
/// NOT name a static `[handlers].bindings.sql.databases.*.compute` workload with it — a
/// collision could shadow / alias a derived managed server. Screened fail-closed at
/// config load ([`ServerConfig::validate_sql_db_names`]). Kept as a literal here (not the
/// `boatramp-storage` const) so the screen holds on a build without the sql engine
/// features; the two must stay in sync (a single source of truth would couple config
/// loading to the optional storage dep).
const RESERVED_MANAGED_DB_COMPUTE_PREFIX: &str = "bramp-db-";

impl ServerConfig {
    /// Parse a `boatramp.cfg` document as **RON** (the default). Kept for the existing
    /// callers/tests; [`Self::parse_with_format`] is the format-aware entry point.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        Self::parse_with_format(text, ConfigFormat::Ron)
    }

    /// Parse a `boatramp.cfg` document in `fmt` (RON or JSON). The deserializer is
    /// selected by format (RON ⇒ [`ron_options`], JSON ⇒ `serde_json`) into the SAME
    /// typed struct. Db-binding names declared in the file are validated here (the same
    /// fail-closed check `load` re-runs after the env merge) **regardless of format**, so
    /// a file-only config path — e.g. `boatramp cloudflare` rendering, or the
    /// operator-resources loader — is guarded even without going through `load`.
    pub fn parse_with_format(text: &str, fmt: ConfigFormat) -> Result<Self, ConfigError> {
        let config: Self = match fmt {
            ConfigFormat::Ron => ron_options().from_str(text)?,
            ConfigFormat::Json => serde_json::from_str(text)?,
        };
        config.validate_sql_db_names()?;
        config.validate_blob_backend_projects()?;
        config.validate_listeners()?;
        Ok(config)
    }

    /// Load from `path`, decoding as RON or JSON per [`resolve_format`] (`override_`
    /// wins; else `.json` ⇒ JSON, everything else ⇒ RON), then layer `BOATRAMP_*`
    /// environment overrides on top. A missing file yields the default config, so
    /// `serve` can be configured entirely from the environment (12-factor deployments
    /// where dropping a `boatramp.cfg` is awkward — fly.io / Cloudflare / containers).
    ///
    /// The env-override merge runs AFTER the parse for either format — JSON is only an
    /// alternative decoder into the same typed struct; it does not change the
    /// file < env precedence.
    pub fn load(path: &Path, override_: Option<ConfigFormat>) -> Result<Self, ConfigError> {
        // The ONE layered pipeline (defaults → file → env), used by serve AND every offline
        // op. With no explicit CLI flags here, this is file + env; the serve binary passes its
        // `ValueSource::CommandLine` flags as the top layer via `load_with_flags`.
        figment_resolve::load_with_figment(
            path,
            override_,
            &EnvSource::Process,
            figment::value::Dict::new(),
        )
    }

    /// Load through the pipeline with an explicit **CLI-flag** top layer. `cli_flags` is a map
    /// `{BOATRAMP_<NAME>: raw-value}` of the args the operator set on the COMMAND LINE (the
    /// serve binary builds it from `clap::ArgMatches`, keeping only `ValueSource::CommandLine`
    /// — so a defaulted `--blobs fs` is absent and never clobbers file/env, subsuming the old
    /// `--blobs` `var_os` probe). Resolution is `base-seed → file → env → these flags`. Keys
    /// the overlay doesn't recognise (runtime/selector flags like `--tls`, the cluster-action
    /// flags) are ignored, so they never enter the config. The binary passes a plain map —
    /// figment types stay internal to this crate.
    pub fn load_with_flags(
        path: &Path,
        override_: Option<ConfigFormat>,
        cli_flags: &BTreeMap<String, String>,
    ) -> Result<Self, ConfigError> {
        let flags = figment_resolve::flag_overlay_dict(cli_flags);
        figment_resolve::load_with_figment(path, override_, &EnvSource::Process, flags)
    }

    /// Serialize the (already-resolved) config for `boatramp config dump`, with the
    /// secret-bearing fields REDACTED. The config is `Serialize` (for the file layer), which
    /// would otherwise expose the control-plane root key / bootstrap secret / azure access
    /// key / signer key / join-token in a dump. Returns pretty JSON (also a valid config
    /// input format).
    pub fn dump_redacted(&self) -> Result<String, ConfigError> {
        figment_resolve::dump_redacted(self)
    }

    /// Test-only adapter: layer the `BOATRAMP_*` env overlay over `self` (the base/file) THROUGH
    /// the real figment pipeline. The production Loader-B `apply_env_overrides` is gone; this thin
    /// delegator keeps the pre-figment env tests — which assert specific resolved fields after
    /// `cfg.apply_env_overrides(&env(…))` — running against the ONE pipeline (so they are genuine
    /// figment tests, not a second implementation).
    #[cfg(test)]
    fn apply_env_overrides(&mut self, source: &EnvSource) -> Result<(), ConfigError> {
        *self = figment_resolve::resolve_env_over(self, source)?;
        Ok(())
    }

    /// Validate every configured `handlers.bindings.sql.databases` binding name
    /// through the one canonical [`validate_resource_name`](boatramp_core::project::validate_resource_name)
    /// (`kind = "database"`). A db-binding name is threaded verbatim into the
    /// control-plane URL (`/api/sql/{db}/…`, `/api/migrate/{db}/…`) and the CLI
    /// `--db`, so it must be a non-empty, path-segment-safe identifier — the same rule
    /// project/site/function names already pass. The empty-string legacy default key
    /// gets a targeted cure pointing at the reserved `default` name.
    ///
    /// Also screens each binding's `compute` field against the
    /// [`RESERVED_MANAGED_DB_COMPUTE_PREFIX`] (#501 Stage B LOW-2): the `bramp-db-`
    /// prefix is reserved for the derived per-project managed-DB server workloads, so an
    /// operator may not point a static BYO binding at a `bramp-db-…` workload.
    fn validate_sql_db_names(&self) -> Result<(), ConfigError> {
        let Some(databases) = self
            .handlers
            .as_ref()
            .and_then(|h| h.bindings.sql.as_ref())
            .map(|s| &s.databases)
        else {
            return Ok(());
        };
        for (name, db) in databases {
            if let Err(err) = boatramp_core::project::validate_resource_name("database", name) {
                // The empty-string case is the pre-v0.5.0 default binding key: point
                // at the cure (name it `default`, or set nothing and let the reserved
                // `DEFAULT` token map to `default` automatically). Any other
                // non-conforming name gets the v0.7.0 slug cure pointing at
                // `project doctor`. This is a boot-LOUD refusal — an operator learns of
                // a bad name at `serve` boot, not at the first request.
                let cure = if name.is_empty() {
                    " — name your default binding `default` (or set \
                     BOATRAMP_HANDLERS_SQL_DB_DEFAULT_*, which now maps to `default` \
                     automatically); see the v0.5.0 CHANGELOG"
                } else {
                    boatramp_core::project::INVALID_NAME_CURE
                };
                return Err(ConfigError::InvalidDbName {
                    name: err.value,
                    reason: err.reason,
                    cure,
                });
            }
            // #501 Stage B LOW-2: the `bramp-db-` compute-workload prefix is RESERVED for
            // the derived per-project managed-DB server workloads
            // (`boatramp_storage::tenant_provision::DERIVED_MANAGED_DB_PREFIX`). An operator
            // must not point a static BYO binding at a `compute` workload with that prefix —
            // it could shadow / alias a derived managed server. Screen it fail-closed at
            // config load (cheap: a `starts_with` on an already-parsed field).
            if let Some(compute) = db.compute.as_deref()
                && compute.starts_with(RESERVED_MANAGED_DB_COMPUTE_PREFIX)
            {
                return Err(ConfigError::InvalidDbName {
                    name: compute.to_string(),
                    reason: "the `bramp-db-` compute-workload prefix is reserved for \
                             boatramp-derived managed-database servers",
                    cure: " — rename the `compute` workload to not start with `bramp-db-`",
                });
            }
            // The `compute` value becomes the workload name, which keys the container
            // id/cgroup/veth AND the per-(project, workload) volume-scope directory. Slug-validate
            // it through the one canonical checker so it can never carry a `/`, `..`, or other
            // path-unsafe byte into a derived filesystem path (defense in depth — fail-closed at
            // boot).
            if let Some(compute) = db.compute.as_deref().filter(|c| !c.is_empty())
                && let Err(err) = boatramp_core::project::validate_resource_name("compute", compute)
            {
                return Err(ConfigError::InvalidDbName {
                    name: err.value,
                    reason: err.reason,
                    cure: boatramp_core::project::INVALID_NAME_CURE,
                });
            }
        }
        Ok(())
    }

    /// Validate every configured `[serve.blob_backends.<project>]` key
    /// (PLAN-per-project-blob-backend). A key must be a valid project name (the canonical
    /// [`validate_resource_name`](boatramp_core::project::validate_resource_name), `kind = "project"`),
    /// and must NOT be the reserved `default` project: the `default` project ALWAYS resolves the global
    /// `[serve]` backend (invariant 5), so a `[serve.blob_backends.default]` entry would be ambiguous
    /// (the node-wide backend is configured under `[serve]`, not here). Both are boot-LOUD refusals
    /// (fail-closed — an operator learns of a bad name at `serve` boot, not at the first request). The
    /// project the entry binds to is host-routed at serve time, never guest input (invariant 1).
    fn validate_blob_backend_projects(&self) -> Result<(), ConfigError> {
        let Some(serve) = self.serve.as_ref() else {
            return Ok(());
        };
        for name in serve.blob_backends.keys() {
            if name == boatramp_core::project::DEFAULT_PROJECT {
                return Err(ConfigError::InvalidBlobBackendProject {
                    name: name.clone(),
                    reason: "the reserved `default` project always resolves the global [serve] blob \
                             backend",
                    cure: " — configure the node-wide backend under [serve] (blobs/s3_*), not \
                           [serve.blob_backends.default]",
                });
            }
            if let Err(err) = boatramp_core::project::validate_resource_name("project", name) {
                return Err(ConfigError::InvalidBlobBackendProject {
                    name: err.value,
                    reason: err.reason,
                    cure: boatramp_core::project::INVALID_NAME_CURE,
                });
            }
        }
        Ok(())
    }

    /// Validate every configured `[serve.listeners.<name>]` (PLAN-handler-tcp-inbound), fail-closed +
    /// boot-LOUD on the fully merged (file + env) map. A host-owned inbound-TCP listener is a
    /// security-sensitive surface, so a half-declared one REFUSES the node rather than binding
    /// something that would silently mislead the operator:
    /// - a blank `bind` / `component` / `project` / `site` (all required),
    /// - a `max_conns` / `idle_timeout_ms` / `max_conn_duration_ms` explicitly set to `0`,
    /// - a declared `tls` block missing its `cert_file`/`key_file`, or a malformed STARTTLS grammar.
    ///
    /// Host-side per-listener TLS/STARTTLS (cap-req 06) and a host-mediated `tcp-egress`
    /// `egress_allowlist` (cap-req 19) are now SUPPORTED — no longer refused here.
    fn validate_listeners(&self) -> Result<(), ConfigError> {
        let Some(serve) = self.serve.as_ref() else {
            return Ok(());
        };
        for (name, l) in &serve.listeners {
            let err = |reason: &'static str, cure: &'static str| {
                Err(ConfigError::InvalidListener {
                    name: name.clone(),
                    reason,
                    cure,
                })
            };
            if l.bind.is_none() {
                return err(
                    "missing `bind` address",
                    " — set `bind = \"0.0.0.0:<port>\"`",
                );
            }
            if l.component.trim().is_empty() {
                return err("missing `component` (the guest .wasm path)", "");
            }
            if l.project.trim().is_empty() {
                return err("missing `project`", "");
            }
            if l.site.trim().is_empty() {
                return err("missing `site`", "");
            }
            if l.max_conns == Some(0) {
                return err("`max_conns` must be > 0", " — omit it for the default");
            }
            if l.idle_timeout_ms == Some(0) {
                return err(
                    "`idle_timeout_ms` must be > 0",
                    " — omit it for the default",
                );
            }
            if l.max_conn_duration_ms == Some(0) {
                return err(
                    "`max_conn_duration_ms` must be > 0",
                    " — omit it for the default",
                );
            }
            // IPv6 rate-limit bucket prefix must be a real prefix length (senior-architect review).
            if let Some(p) = l.conn_rate_ipv6_prefix
                && !(1..=128).contains(&p)
            {
                return err(
                    "`conn_rate_ipv6_prefix` must be in 1..=128",
                    " — e.g. 64 (per-/64), or omit it for the default (/64)",
                );
            }
            // PROXY-protocol requires a trusted source (senior-architect review — OWNER DECISION:
            // require). Enabling `proxy_protocol` with no `proxy_protocol_trusted_cidrs` would trust a
            // spoofable header from ANY source; refuse that (fail-closed, boot-loud) unless the operator
            // explicitly opts into the firewall-only mode via `proxy_protocol_trust_any = true`.
            if l.proxy_protocol
                && l.proxy_protocol_trusted_cidrs.is_empty()
                && !l.proxy_protocol_trust_any
            {
                return err(
                    "`proxy_protocol` requires a non-empty `proxy_protocol_trusted_cidrs` (a header \
                     from any source would otherwise be trusted and spoofable)",
                    " — set `proxy_protocol_trusted_cidrs = [\"<proxy CIDR>\"]`, or (only if the port \
                     is firewalled to the proxy) set `proxy_protocol_trust_any = true`",
                );
            }
            // Host-side per-listener TLS termination (cap-req 06): a declared `tls` block is honored,
            // but it MUST name both a cert and a key (the host loads them + terminates TLS, handing the
            // guest a decrypted plaintext stream). This holds for BOTH implicit TLS (465/993) and
            // STARTTLS (25/587/143) — STARTTLS still terminates TLS after the in-band upgrade.
            if let Some(tls) = &l.tls {
                if tls.cert_file.is_none() || tls.key_file.is_none() {
                    return err(
                        "listener `tls` requires both `cert_file` and `key_file`",
                        " — set cert_file/key_file (PEM), or remove the `tls` block for a plaintext listener",
                    );
                }
                // Declarative STARTTLS grammar (cap-req 06, Stage B): the one piece of protocol data.
                if let Some(st) = &tls.starttls {
                    if st.trigger.trim().is_empty() {
                        return err(
                            "listener `tls.starttls.trigger` must be non-empty",
                            " — e.g. trigger = \"STARTTLS\" (SMTP/IMAP) or \"STLS\" (POP3)",
                        );
                    }
                    if st.response.trim().is_empty() {
                        return err(
                            "listener `tls.starttls.response` must be non-empty",
                            " — the line the host sends before upgrading, e.g. \"220 Ready to start TLS\"",
                        );
                    }
                    // `{tag}` in the response is only meaningful when a tag is captured — otherwise the
                    // literal `{tag}` would leak to the wire.
                    if st.response.contains("{tag}") && !st.tag_capture {
                        return err(
                            "listener `tls.starttls.response` uses `{tag}` but `tag_capture` is false",
                            " — set tag_capture = true (IMAP-style), or remove the {tag} placeholder",
                        );
                    }
                    // trigger/response are matched against / written as a single line — refuse embedded
                    // CR/LF (which would split the line and could inject a second response line).
                    if st.trigger.contains(['\r', '\n']) || st.response.contains(['\r', '\n']) {
                        return err(
                            "listener `tls.starttls` trigger/response must not contain CR or LF",
                            " — they are a single line; the host appends CRLF to the response",
                        );
                    }
                }
                // On-demand per-SNI issuance for this listener (cap-req 03 #4) shares the node's one
                // on-demand engine — it is meaningless (and silently a no-op) unless that engine runs.
                if tls.on_demand && !serve.on_demand_tls.as_ref().is_some_and(|o| o.enabled) {
                    return err(
                        "listener `tls.on_demand` requires `[serve.on_demand_tls] enabled = true`",
                        " — enable node on-demand TLS, or set on_demand = false to serve only the static cert",
                    );
                }
            }
            // cap-req 19: a non-empty `egress_allowlist` is now SUPPORTED — it drives the listener
            // guest's HOST-MEDIATED `tcp-egress` dials (the host dials + terminates TLS; the guest
            // never holds raw `wasi:sockets`). It takes effect only when the node posture
            // `allow_guest_tcp_egress` is on AND the component imports `tcp-egress`; the runtime dial
            // is connect-only + SSRF-floored (the SAME gate as a request handler's egress). Entries
            // are validated (and rejected) at that runtime gate, mirroring the handler/function
            // allowlist, so no config-load format check here.
        }
        Ok(())
    }
}

/// The `BOATRAMP_*` variables that populate the `[compute]` section. Kept as one
/// list so [`ServerConfig::apply_env_overrides`] can decide whether to materialise
/// an absent section without repeating the names.
const COMPUTE_ENV_VARS: &[&str] = &[
    "BOATRAMP_COMPUTE_BRIDGE",
    "BOATRAMP_COMPUTE_SUBNET",
    "BOATRAMP_COMPUTE_VCPUS",
    "BOATRAMP_COMPUTE_MEM_MIB",
    "BOATRAMP_COMPUTE_REGION",
    "BOATRAMP_COMPUTE_SQL_SHIM_URL",
    "BOATRAMP_COMPUTE_BLOB_SHIM_URL",
    "BOATRAMP_COMPUTE_MESSAGING_SHIM_URL",
    "BOATRAMP_COMPUTE_BLOB_SHIM_MAX_OBJECT_BYTES",
    "BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE",
    "BOATRAMP_COMPUTE_DOCKER_ENDPOINT",
    "BOATRAMP_COMPUTE_DOCKER_VOLUME_MODE",
    "BOATRAMP_COMPUTE_KERNEL_SIGNING_PUBKEYS",
    "BOATRAMP_COMPUTE_KERNEL_ALLOWED_HASHES",
    "BOATRAMP_COMPUTE_INTERNAL_DNS",
    "BOATRAMP_COMPUTE_DNS_UPSTREAM",
    "BOATRAMP_COMPUTE_DNS_DOMAIN",
    "BOATRAMP_COMPUTE_PG_CLIENT_IMAGE",
    "BOATRAMP_COMPUTE_MYSQL_CLIENT_IMAGE",
];

/// The `BOATRAMP_*` variables that populate the `[security]` section.
const SECURITY_ENV_VARS: &[&str] = &[
    "BOATRAMP_SECURITY_PROFILE",
    "BOATRAMP_SECURITY_ALLOW_UNAUTHENTICATED_PUBLIC_BIND",
    "BOATRAMP_SECURITY_MAX_UPLOAD_BYTES",
    "BOATRAMP_SECURITY_ALLOW_SITE_UNIX_UPSTREAMS",
    "BOATRAMP_SECURITY_ALLOW_SITE_PRIVATE_UPSTREAMS",
    "BOATRAMP_SECURITY_ALLOW_GUEST_PRIVATE_EGRESS",
    "BOATRAMP_SECURITY_ALLOW_GUEST_SELF_EGRESS",
    "BOATRAMP_SECURITY_ALLOW_GUEST_EGRESS_EXTRA_CA",
    "BOATRAMP_SECURITY_ALLOW_GUEST_TCP_EGRESS",
    "BOATRAMP_SECURITY_ALLOW_GUEST_TCP_LISTENER",
    "BOATRAMP_SECURITY_MAX_HANDLER_BLOB_BYTES",
    "BOATRAMP_SECURITY_MAX_COMPONENT_BYTES",
    "BOATRAMP_SECURITY_OIDC_REQUIRE_AUDIENCE",
    "BOATRAMP_SECURITY_DOMAIN_VERIFY_ALLOW_PRIVATE",
    "BOATRAMP_SECURITY_DOMAIN_VERIFY_SELF_SERVE",
    "BOATRAMP_SECURITY_ALLOW_SHARED_KERNEL_COMPUTE",
    "BOATRAMP_SECURITY_ALLOW_COMPUTE_EXEC",
    "BOATRAMP_SECURITY_ALLOW_DEV_BLOB_BIND",
    "BOATRAMP_SECURITY_ALLOW_DEV_MESSAGING_BIND",
    "BOATRAMP_SECURITY_RATELIMIT_FAIL_OPEN",
    "BOATRAMP_SECURITY_ALLOW_IMPLICIT_ROUTING",
    "BOATRAMP_SECURITY_REQUIRE_POP",
    "BOATRAMP_SECURITY_REQUIRE_DOMAIN_VERIFICATION",
    "BOATRAMP_SECURITY_ALLOW_ENV_SECRET_REFS",
    "BOATRAMP_SECURITY_REQUIRE_TENANCY_DECLARATION",
    "BOATRAMP_SECURITY_ALLOW_CROSS_TENANT_DB",
    "BOATRAMP_SECURITY_ALLOW_GUEST_MINT_CAPABILITY",
    "BOATRAMP_SECURITY_MAX_GUEST_CAPABILITY_TTL_SECS",
    "BOATRAMP_SECURITY_ALLOW_GUEST_EMAIL",
    "BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_DOMAINS",
    "BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_EMAIL",
    "BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_SITE",
    "BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_SECRETS",
];

/// The `BOATRAMP_*` variables that populate `handlers.bindings.sql`.
const SQL_ENV_VARS: &[&str] = &[
    "BOATRAMP_HANDLERS_SQL_DIR",
    "BOATRAMP_HANDLERS_SQL_URL",
    "BOATRAMP_HANDLERS_SQL_ADMIN_URL",
    "BOATRAMP_HANDLERS_SQL_REPLICA_URL",
    "BOATRAMP_HANDLERS_SQL_TOKEN_ENV",
    "BOATRAMP_HANDLERS_SQL_ADMIN_TOKEN_ENV",
    "BOATRAMP_HANDLERS_SQL_PREVIEW_MODE",
    "BOATRAMP_HANDLERS_SQL_PREVIEW_INIT",
    "BOATRAMP_HANDLERS_SQL_DEPROVISION_GRACE_SECS",
    "BOATRAMP_HANDLERS_SQL_MIGRATE_TRUSTED_EXTENSIONS",
    "BOATRAMP_HANDLERS_SQL_MAX_DECLARED_DATABASES",
    "BOATRAMP_HANDLERS_SQL_MAX_DECLARED_VOLUME_MIB",
];

/// The `[handlers]` JWKS-freshness env levers (two-tier own/foreign refresh + hard-ttl + prewarm),
/// mirroring the `jwks_*` fields on [`HandlersConfig`]. Kept in sync by the forgot-a-knob guard test.
const JWKS_ENV_VARS: &[&str] = &[
    "BOATRAMP_HANDLERS_JWKS_REFRESH_SECS",
    "BOATRAMP_HANDLERS_JWKS_HARD_TTL_SECS",
    "BOATRAMP_HANDLERS_JWKS_FOREIGN_REFRESH_SECS",
    "BOATRAMP_HANDLERS_JWKS_FOREIGN_HARD_TTL_SECS",
    "BOATRAMP_HANDLERS_JWKS_PREWARM",
];

/// The `[handlers]` concurrency-lane env levers (per-component serve-admission gate + the global
/// sync/async lane ceilings), mirroring the `serve_concurrency` / `sync_max_concurrency` /
/// `async_max_concurrency` fields on [`HandlersConfig`]. Kept in sync by the forgot-a-knob guard test.
const HANDLER_CONCURRENCY_ENV_VARS: &[&str] = &[
    "BOATRAMP_HANDLERS_SERVE_CONCURRENCY",
    "BOATRAMP_HANDLERS_SYNC_MAX_CONCURRENCY",
    "BOATRAMP_HANDLERS_ASYNC_MAX_CONCURRENCY",
];

/// The `[handlers]` serve-path blob-read env levers (fetch-tail cut + read-through cache), mirroring the
/// `blob_hedge_delay_ms` / `blob_hedge_max_inflight` / `blob_read_cache_bytes` fields on
/// [`HandlersConfig`]. Kept in sync by the forgot-a-knob guard test.
const HANDLER_BLOB_HEDGE_ENV_VARS: &[&str] = &[
    "BOATRAMP_HANDLERS_BLOB_HEDGE_DELAY_MS",
    "BOATRAMP_HANDLERS_BLOB_HEDGE_MAX_INFLIGHT",
    "BOATRAMP_HANDLERS_BLOB_READ_CACHE_BYTES",
];

/// The `[handlers]` cold-start env levers (cap-req 09): the warm floor + the portable AOT
/// artifact cache, mirroring the `keep_warm_max` / `aot_artifact_cache` /
/// `aot_artifact_max_bytes` fields on [`HandlersConfig`]. Kept in sync by the forgot-a-knob
/// guard test.
const HANDLER_COLDSTART_ENV_VARS: &[&str] = &[
    "BOATRAMP_HANDLERS_KEEP_WARM_MAX",
    "BOATRAMP_HANDLERS_AOT_ARTIFACT_CACHE",
    "BOATRAMP_HANDLERS_AOT_ARTIFACT_MAX_BYTES",
];

/// The `[serve.s3_ingress_cloud]` env levers (the blob-upload minter's cloud-brokering policy),
/// mirroring the fields on [`S3IngressCloud`]. Kept in sync by the forgot-a-knob guard test. These are
/// policy toggles only; the signing credential stays the sealed `[secrets]` one.
const S3_INGRESS_CLOUD_ENV_VARS: &[&str] = &[
    "BOATRAMP_S3_INGRESS_CLOUD_AWS_ROLE_ARN",
    "BOATRAMP_S3_INGRESS_CLOUD_AWS_USE_FEDERATION_TOKEN",
    "BOATRAMP_S3_INGRESS_CLOUD_AWS_PRESIGNED_ONLY",
    "BOATRAMP_S3_INGRESS_CLOUD_GCS_CLIENT_EMAIL",
    "BOATRAMP_S3_INGRESS_CLOUD_AZURE_ACCOUNT",
    "BOATRAMP_S3_INGRESS_CLOUD_AZURE_SERVICE_URL",
    "BOATRAMP_S3_INGRESS_CLOUD_AZURE_HNS",
];

/// The fixed prefix of a keyed `handlers.bindings.sql.databases` variable —
/// `BOATRAMP_HANDLERS_SQL_DB_<NAME>_<FIELD>`. Member names aren't known ahead of
/// time (there is no config file to enumerate them), so they are discovered by
/// scanning the environment for this prefix.
const SQL_DB_ENV_PREFIX: &str = "BOATRAMP_HANDLERS_SQL_DB_";

/// The recognised `_<FIELD>` suffixes of a `databases` variable, ordered so a
/// name-isolating strip matches the **longest** suffix first (`_READ_URL_ENV`
/// before `_URL_ENV`). Each mirrors a field of [`ExternalDatabaseConfig`].
const SQL_DB_FIELD_SUFFIXES: &[&str] = &[
    "_STARTUP_GRACE_SECS",
    "_CONNECT_TIMEOUT_SECS",
    // `_SESSION_GUC` / `_TENANT_GUC` / `_TENANT_ALL_MARKER` before `_TENANT`/`_TENANT_SCOPE`
    // (longest-first name isolation).
    "_SESSION_GUC",
    "_TENANT_ALL_MARKER",
    "_TENANT_GUC",
    "_VOLUME_SIZE_MIB",
    "_READ_URL_ENV",
    "_PASSWORD_ENV",
    "_ALLOW_PREVIEW",
    "_URL_ENV",
    "_DATABASE",
    "_READ_ONLY",
    "_POOL_MAX",
    "_RLS_SESSION",
    "_TENANT_SCOPE",
    "_COMPUTE",
    "_TENANT",
    "_IMAGE",
    "_KIND",
    "_USER",
];

/// The fixed prefix of a keyed `[serve.blob_backends.<project>]` variable —
/// `BOATRAMP_SERVE_BLOB_BACKEND_<PROJECT>_<FIELD>` (PLAN-per-project-blob-backend). Member project
/// names aren't known ahead of time (there is no config file to enumerate them), so they are discovered
/// by scanning the environment for this prefix — mirroring [`SQL_DB_ENV_PREFIX`].
const BLOB_BACKEND_ENV_PREFIX: &str = "BOATRAMP_SERVE_BLOB_BACKEND_";

/// The recognised `_<FIELD>` suffixes of a `[serve.blob_backends]` variable, ordered so a
/// name-isolating strip matches the **longest** suffix first (so `_S3_SECRET_ACCESS_KEY` wins over any
/// shorter overlap). Each mirrors a field of [`BlobBackendConfig`] (the sealed credential's two public
/// refs are flattened as `_S3_ACCESS_KEY_ID` / `_S3_SECRET_ACCESS_KEY`). Kept in sync by the
/// `blob_backend_env_covers_every_field` forgot-a-knob guard test.
const BLOB_BACKEND_FIELD_SUFFIXES: &[&str] = &[
    "_S3_SECRET_ACCESS_KEY",
    "_S3_ACCESS_KEY_ID",
    "_S3_PATH_STYLE",
    "_S3_ENDPOINT",
    "_S3_BUCKET",
    "_S3_REGION",
    "_KIND",
];

/// The fixed prefix of a keyed `[serve.listeners.<name>]` variable —
/// `BOATRAMP_SERVE_LISTENER_<NAME>_<FIELD>` (PLAN-handler-tcp-inbound). Listener names aren't known
/// ahead of time (there is no config file to enumerate them under env-only config), so they are
/// discovered by scanning the environment for this prefix — mirroring [`BLOB_BACKEND_ENV_PREFIX`].
const LISTENER_ENV_PREFIX: &str = "BOATRAMP_SERVE_LISTENER_";

/// The recognised `_<FIELD>` suffixes of a `[serve.listeners]` variable, ordered so a name-isolating
/// strip matches the **longest** suffix first (so `_MAX_CONN_DURATION_MS` wins over `_MAX_CONNS`). Each
/// mirrors a SCALAR field of [`ListenerConfig`]; the structured fields (`imports`/`env`/`tenancy`) and
/// the Phase-1-refused `tls`/`egress_allowlist` are set only from the config file. `_IMPORTS` is a
/// comma-separated list. Kept in sync by the `listener_env_covers_every_field` forgot-a-knob guard.
const LISTENER_FIELD_SUFFIXES: &[&str] = &[
    "_MAX_CONN_DURATION_MS",
    "_IDLE_TIMEOUT_MS",
    "_MAX_CONNS",
    "_COMPONENT",
    "_IMPORTS",
    "_PROJECT",
    "_BIND",
    "_SITE",
];

/// The `BOATRAMP_*` variables that populate the `[secrets]` section (excluding the
/// nested `vault` sub-config, gated separately by [`SECRETS_VAULT_ENV_VARS`]).
const SECRETS_ENV_VARS: &[&str] = &[
    "BOATRAMP_SECRETS_ENVELOPE",
    "BOATRAMP_SECRETS_KEK_FILE",
    "BOATRAMP_SECRETS_VAULT_ADDR",
    "BOATRAMP_SECRETS_VAULT_KEY",
    "BOATRAMP_SECRETS_VAULT_TOKEN_ENV",
];

/// The `BOATRAMP_*` variables that populate the nested `[secrets.vault]` sub-config.
const SECRETS_VAULT_ENV_VARS: &[&str] = &[
    "BOATRAMP_SECRETS_VAULT_ADDR",
    "BOATRAMP_SECRETS_VAULT_KEY",
    "BOATRAMP_SECRETS_VAULT_TOKEN_ENV",
];

/// The `BOATRAMP_*` variables that populate the `[cluster]` section fields (the
/// section's own config, distinct from the founding/joining *action* flags
/// `BOATRAMP_CLUSTER_INIT` / `_JOIN` / `_ADVERTISE_ADDR`, which are `serve` clap
/// args and are deliberately not listed here).
const CLUSTER_ENV_VARS: &[&str] = &[
    "BOATRAMP_CLUSTER_LISTEN",
    "BOATRAMP_CLUSTER_ROOT_PUBKEYS",
    "BOATRAMP_CLUSTER_SEEDS",
    "BOATRAMP_CLUSTER_JOIN_TOKEN",
    "BOATRAMP_CLUSTER_STORE_DIR",
    "BOATRAMP_CLUSTER_MESH_KEY_FILE",
    "BOATRAMP_CLUSTER_MESH_KEY_ROTATION",
    "BOATRAMP_CLUSTER_MESH_JOIN_TOKEN_TTL",
    "BOATRAMP_CLUSTER_MESH_GATE_CLIENT_WRITES",
];

/// Where env-override values come from: the real process environment, or an explicit map
/// (the CLI-flag layer, which reuses the env overlay to turn `{BOATRAMP_<NAME>: value}`
/// command-line flags into a figment dict; and deterministic unit tests — no racy,
/// process-global `std::env`).
pub(crate) enum EnvSource {
    /// The live process environment (`std::env::var`).
    Process,
    /// A fixed name→value map (the CLI-flag layer + tests).
    Map(BTreeMap<String, String>),
}

impl EnvSource {
    /// The value of `var`, if set to a non-empty string. An empty value is treated
    /// as unset so an accidental `VAR=` doesn't clobber a file value with `""`.
    fn get(&self, var: &str) -> Option<String> {
        let raw = match self {
            Self::Process => std::env::var(var).ok(),
            Self::Map(m) => m.get(var).cloned(),
        };
        raw.filter(|v| !v.is_empty())
    }

    /// Whether any of `vars` is set (to a non-empty value).
    fn any(&self, vars: &[&str]) -> bool {
        vars.iter().any(|v| self.get(v).is_some())
    }

    /// The full set of variable names visible to this source. Used to discover the
    /// keyed-map member names from the environment (there is no config file to
    /// enumerate them). Returned owned so it doesn't borrow the process env.
    fn names(&self) -> Box<dyn Iterator<Item = String> + '_> {
        match self {
            Self::Process => Box::new(std::env::vars().map(|(k, _)| k)),
            Self::Map(m) => Box::new(m.keys().cloned()),
        }
    }

    /// The distinct `<NAME>` tokens of every `BOATRAMP_HANDLERS_SQL_DB_<NAME>_<FIELD>`
    /// variable that is set. The name is everything between the fixed prefix and the
    /// *last* `_<FIELD>` segment, so a database name may itself contain underscores
    /// (the field suffix is one of a known set). Returned sorted + de-duplicated so
    /// the map is built deterministically.
    fn sql_database_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .names()
            .filter(|n| n.starts_with(SQL_DB_ENV_PREFIX) && self.get(n).is_some())
            .filter_map(|n| {
                let rest = n.strip_prefix(SQL_DB_ENV_PREFIX)?;
                // Strip the recognised field suffix to isolate `<NAME>`. The suffixes
                // are matched longest-first so `READ_URL_ENV` wins over `URL_ENV`.
                SQL_DB_FIELD_SUFFIXES
                    .iter()
                    .find_map(|suffix| rest.strip_suffix(suffix))
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
            })
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// The distinct `<PROJECT>` tokens of every `BOATRAMP_SERVE_BLOB_BACKEND_<PROJECT>_<FIELD>`
    /// variable that is set (PLAN-per-project-blob-backend). The name is everything between the fixed
    /// prefix and the *last* `_<FIELD>` segment, so a project name may itself contain underscores (the
    /// field suffix is one of a known set, matched longest-first). Returned sorted + de-duplicated so
    /// the map is built deterministically. Mirrors [`Self::sql_database_names`].
    fn blob_backend_projects(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .names()
            .filter(|n| n.starts_with(BLOB_BACKEND_ENV_PREFIX) && self.get(n).is_some())
            .filter_map(|n| {
                let rest = n.strip_prefix(BLOB_BACKEND_ENV_PREFIX)?;
                BLOB_BACKEND_FIELD_SUFFIXES
                    .iter()
                    .find_map(|suffix| rest.strip_suffix(suffix))
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
            })
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// The distinct `<NAME>` tokens of every `BOATRAMP_SERVE_LISTENER_<NAME>_<FIELD>` variable that is
    /// set (PLAN-handler-tcp-inbound). The name is everything between the fixed prefix and the *last*
    /// `_<FIELD>` segment (suffixes matched longest-first), so a listener name may itself contain
    /// underscores. Returned sorted + de-duplicated so the map is built deterministically. Mirrors
    /// [`Self::blob_backend_projects`].
    fn listener_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .names()
            .filter(|n| n.starts_with(LISTENER_ENV_PREFIX) && self.get(n).is_some())
            .filter_map(|n| {
                let rest = n.strip_prefix(LISTENER_ENV_PREFIX)?;
                LISTENER_FIELD_SUFFIXES
                    .iter()
                    .find_map(|suffix| rest.strip_suffix(suffix))
                    .filter(|name| !name.is_empty())
                    .map(str::to_string)
            })
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// Parse `var` as a **comma-separated** list of non-empty trimmed items, e.g.
    /// the kernel trust anchors. A single value (no comma) yields a one-element
    /// list. Empty items are dropped so a trailing comma or doubled separator is
    /// tolerated. `Ok(None)` when unset; `Some(Vec::new())` never happens (an
    /// all-empty value is treated as unset by [`Self::get`]).
    fn parse_list(&self, var: &str) -> Option<Vec<String>> {
        self.get(var).map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
    }
}

/// How a **managed database** (PLAN-managed-compute-sql) runs its stock image on a
/// shared-kernel backend, whose entrypoint would otherwise fail under the dropped-`ALL`
/// hardening. `rootless` (the default) needs no capabilities and works under any
/// posture; `caps` is the fallback for an image that won't run rootless.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ManagedDbPrivilege {
    /// Run the DB as its image's user (`999:999` for the official postgres/mysql
    /// images) against a pre-owned volume — no added capabilities, any posture.
    #[default]
    Rootless,
    /// Add the minimal capability set the entrypoint needs (`CHOWN`, `DAC_OVERRIDE`,
    /// `FOWNER`, `SETUID`, `SETGID`). Honored only under the single-tenant posture.
    Caps,
}

/// `compute` section — opt-in compute backends. Present
/// ⇒ `serve` registers the backends this node can offer and advertises them to
/// the scheduler; backends are capability-detected (container on Linux, remote
/// docker when a daemon is reachable, VMM when `/dev/kvm` exists).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ComputeConfig {
    /// Bridge the container veths / VM taps attach to (default `br-boatramp`).
    pub bridge: String,
    /// Guest IP subnet (default `10.0.0.0/24`).
    pub subnet: String,
    /// vCPUs this node advertises as schedulable (`0` ⇒ detect from the host).
    pub vcpus: u32,
    /// Memory (MiB) this node advertises as schedulable (`0` ⇒ a 1 GiB default).
    pub mem_mib: u32,
    /// **Static** kernel-signing public keys (`"<alg>:<hex>"`) — the trust anchor
    /// for the posture-scaled kernel bar. Under `multi-tenant`, a dynamically-
    /// selected default kernel must carry a signature verifying against one of
    /// these. Host-access-gated (never in the KV tier); changing it needs a
    /// restart. Empty ⇒ no kernel may be signed-verified (strict posture then
    /// accepts none).
    pub kernel_signing_pubkeys: Vec<String>,
    /// **Static** allow-list of kernel content hashes (sha256 hex) a dynamic
    /// default may select under `multi-tenant`. Host-access-gated. Empty ⇒ no
    /// kernel is allow-listed.
    pub kernel_allowed_hashes: Vec<String>,
    /// This node's **region** tag (FA-8). Advertised on the compute `Node` so a
    /// gateway routing to a `compute:`-backed workload with `--lb nearest` sends
    /// each request to the nearest replica by its node's region — no manual
    /// `--region` map. `None` ⇒ region-agnostic.
    pub region: Option<String>,
    /// How the remote-Docker backend reports a workload's reachable endpoint.
    /// `published` (default) publishes the container port on `127.0.0.1:<ephemeral>`
    /// so a host-native `serve` reaches it on any daemon (incl. Docker Desktop /
    /// macOS, where the bridge IP is not host-routable); `bridge` routes to the
    /// container bridge IP directly (only when `serve` shares the daemon's network).
    pub docker_endpoint: boatramp_docker::DockerEndpoint,
    /// How the remote-Docker backend backs a workload's persistent volumes.
    /// `named` (default) attaches a daemon-managed `docker volume` by name (portable
    /// across daemons + Docker Desktop / macOS); `bind` bind-mounts a host directory
    /// under `<data_dir>/compute/volumes/<name>` (local daemon only).
    pub docker_volume_mode: boatramp_docker::DockerVolumeMode,
    /// Wall-clock backstop (seconds) for one project export/import client run
    /// (`run_ephemeral`: a `pg_dump`/`pg_restore` container). `0` (default) keeps the
    /// backend's generous built-in default (6h). Raise it for a very large migration so
    /// the backstop never kills legitimate work; the real unreachable-DSN hang is bounded
    /// far tighter by the client's own connect timeout.
    #[serde(default)]
    pub docker_ephemeral_timeout_secs: u64,
    /// Guest-reachable base URL of the compute **sql-shim** (PLAN-compute-bindings) —
    /// e.g. `http://10.0.0.1:8081` (the compute bridge gateway) or the docker bridge
    /// gateway. Set ⇒ a workload's `--bind sql` reaches the managed database through a
    /// listener bound on the **host:port this URL names** (the bridge-gateway IP /
    /// loopback — NOT all interfaces; a token-gated tenant-SQL data plane must not be
    /// off-node reachable). `None` (default) ⇒ compute sql bindings off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub sql_shim_url: Option<String>,
    /// Guest-reachable base URL of the compute **blob-shim** (PLAN-compute-bindings) —
    /// e.g. `http://10.0.0.1:8082` (the compute bridge gateway) or the docker bridge
    /// gateway. Set ⇒ a workload's `--bind blob` reaches the SAME per-site
    /// `hblob/{qualified-site}/…` blob namespace a `wasi:blobstore` handler sees, through a
    /// listener bound on the **host:port this URL names** (the bridge-gateway IP /
    /// loopback — NOT all interfaces; the token-gated `hblob/{site}/` data plane must not
    /// be off-node reachable). `None` (default) ⇒ compute blob bindings off. The direct
    /// analogue of [`Self::sql_shim_url`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub blob_shim_url: Option<String>,
    /// Guest-reachable base URL of the compute **messaging-shim** (PLAN-compute-bindings) —
    /// e.g. `http://10.0.0.1:8083` (the compute bridge gateway) or the docker bridge gateway.
    /// Set ⇒ a workload's `--bind messaging` reaches BOTH halves of the SAME `{project}/bus/
    /// <topic>` project bus a `wasi:messaging` handler sees — `POST /publish/{topic}` AND the
    /// consume ops `POST /claim/{topic}`, `POST /ack`, `POST /nack` — through a listener bound
    /// on the **host:port this URL names** (the bridge-gateway IP / loopback — NOT all
    /// interfaces; the token-gated `{project}/bus/` data plane must not be off-node reachable).
    /// `None` (default) ⇒ compute messaging bindings off. The direct analogue of
    /// [`Self::sql_shim_url`] / [`Self::blob_shim_url`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub messaging_shim_url: Option<String>,
    /// Per-object PUT ceiling (bytes) for the compute blob-shim — bounds a single write so a
    /// compromised/buggy workload cannot exhaust node/bucket storage with one unbounded PUT (`413`
    /// on an oversize PUT). `None` (default) ⇒ the shim's built-in default (5 GiB, S3's single-PUT
    /// limit); `Some(0)` ⇒ unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub blob_shim_max_object_bytes: Option<u64>,
    /// Privilege strategy for a managed database's stock image on a shared-kernel
    /// backend (see [`ManagedDbPrivilege`]). `rootless` by default.
    #[serde(default)]
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub managed_db_privilege: ManagedDbPrivilege,
    /// Per-project **internal DNS** (service discovery): run a lightweight resolver
    /// on the bridge gateway so a guest can reach peers by name (`<workload>` /
    /// `<workload>.<project>.<dns_domain>`) instead of a numeric IP, scoped to its
    /// own project. Default **on** — it activates only when the container backend +
    /// bridge come up, so a node without them is unaffected. `false` disables it and
    /// leaves each image's own `/etc/resolv.conf`.
    #[serde(default = "default_internal_dns")]
    pub internal_dns: bool,
    /// The upstream resolver the internal DNS forwards non-internal queries to
    /// (external names + non-`A`/`AAAA` types), so the resolver is the guest's single
    /// nameserver. `"host:port"`; default `1.1.1.1:53`.
    #[serde(default = "default_dns_upstream")]
    pub dns_upstream: String,
    /// The internal DNS suffix names live under (`<workload>.<project>.<dns_domain>`);
    /// also the `search` domain written into each container's resolv.conf. Default
    /// `boatramp.internal`.
    #[serde(default = "default_dns_domain")]
    pub dns_domain: String,
    /// **Air-gap override** for the project export/import **client images** the native
    /// container backend runs via `run_ephemeral` (a `pg_dump`/`pg_restore`/`mysqldump`/
    /// `mysql`/`psql` one-shot). Maps a client image reference → a **preloaded rootfs**, so
    /// an export/import can run with NO registry pull on an isolated node. The value is
    /// either an **absolute host path** to an already-unpacked rootfs directory (used
    /// verbatim), or a **Storage blob hash** of a rootfs tar the backend stages like any
    /// `RootSource::Tar`. Empty (the default) ⇒ every client image is pulled + built
    /// on demand over the registry HTTP API (daemonless), the same path `materialize`
    /// uses. Only the native `container` backend consults this; the remote `docker`
    /// backend pulls through its daemon. Example:
    ///
    /// ```toml
    /// [compute.client_image_rootfs]
    /// "pgvector/pgvector:pg16" = "/var/lib/boatramp/client-rootfs/pg16"
    /// "mysql:8.0"              = "9f86d0818...<rootfs-tar-blob-sha256>"
    /// ```
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub client_image_rootfs: BTreeMap<String, String>,
    /// **Digest-pin / override** for the Postgres client image the project export/import + `sql exec`
    /// seams run via `run_ephemeral` (`pg_dump`/`pg_restore`/`psql`). When set, this image reference is
    /// used VERBATIM instead of the version-computed `pgvector/pgvector:pg{major}` tag — so an operator
    /// can pin it by digest (`pgvector/pgvector:pg16@sha256:<hex>`) and have it accepted under the
    /// multi-tenant posture (which refuses an un-pinned mutable-tag pull), with NO rootfs staging:
    /// boatramp pulls + runs it through the normal on-demand path. The lighter-weight alternative to
    /// [`Self::client_image_rootfs`] for a node with registry egress. `None` (default) ⇒ the computed
    /// tag. Env: `BOATRAMP_COMPUTE_PG_CLIENT_IMAGE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub pg_client_image: Option<String>,
    /// MySQL counterpart of [`Self::pg_client_image`] — pins/overrides the `mysql:<maj.min>` client
    /// image for the export/import/`sql exec` `run_ephemeral` (`mysqldump`/`mysql`). Env:
    /// `BOATRAMP_COMPUTE_MYSQL_CLIENT_IMAGE`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub mysql_client_image: Option<String>,
    /// **Operator node-wide registry pull credentials** (PLAN-compute-registry-auth):
    /// `registry-host → `[`OperatorRegistryAuth`](boatramp_core::registry_auth::OperatorRegistryAuth)
    /// for operator-provisioned fleet images. When a workload's `image(...)` registry host matches a
    /// key here (and the workload itself names NO project `pull_secret`), the referenced sealed
    /// secret authenticates the pull. The ref names a sealed `{username,password}` secret the
    /// operator sets with System·Admin authority via `boatramp compute registry-auth set --operator`,
    /// stored in the reserved, tenant-unreachable
    /// [`OPERATOR_REGISTRY_PROJECT`](boatramp_core::registry_auth::OPERATOR_REGISTRY_PROJECT)
    /// keyspace — this map holds only the NON-secret ref, NEVER a credential. The host key matches
    /// [`registry_host_of`](boatramp_core::registry_auth::registry_host_of): e.g. `"ghcr.io"`,
    /// `"registry.example.com:5000"`, or `"docker.io"` for Hub.
    ///
    /// Each value is EITHER a bare string (host-wide, back-compat) OR a struct carrying an optional
    /// repository-path-prefix allowlist (`repos`): a scoped entry attaches ONLY to images whose repo
    /// path ([`registry_repo_of`](boatramp_core::registry_auth::registry_repo_of)) starts with one of
    /// the prefixes, so a tenant can't borrow a node-wide credential for UNRELATED private repos at
    /// the same host (Security MEDIUM-2). A configured+matching host whose secret is unset fails the
    /// pull CLOSED (never anonymous); a host-match-but-repo-no-match falls through to anonymous.
    /// Empty (default) ⇒ operator scope off. Dynamic daemon setting (hot-swappable like the rest of
    /// `[compute]`). Example (RON):
    ///
    /// ```ron
    /// registry_auth: {
    ///     "ghcr.io": "fleet-ghcr",                                      // host-wide
    ///     "registry.internal:5000": ( secret: "internal-reg", repos: ["myorg/base-"] ),
    /// }
    /// ```
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub registry_auth: BTreeMap<String, boatramp_core::registry_auth::OperatorRegistryAuth>,
}

/// Default for [`ComputeConfig::internal_dns`] — on (activates only with the
/// container backend + bridge).
fn default_internal_dns() -> bool {
    true
}

/// Default upstream resolver for [`ComputeConfig::dns_upstream`].
fn default_dns_upstream() -> String {
    "1.1.1.1:53".to_string()
}

/// Default internal DNS suffix for [`ComputeConfig::dns_domain`].
fn default_dns_domain() -> String {
    boatramp_container::dns::DEFAULT_INTERNAL_DOMAIN.to_string()
}

/// The built-in **boatramp kernel-signing public key** (`es256:…`), whose private
/// half lives as the `KERNEL_SIGNING_KEY` Actions secret in
/// [`BoatRamp/boatramp-vmlinux`](https://github.com/BoatRamp/boatramp-vmlinux).
/// Shipped as a default trust anchor so the first-party signed `boatramp-vmlinux`
/// verifies out of the box under the strict posture. An operator can replace
/// `kernel_signing_pubkeys` to trust only their own keys.
pub const BOATRAMP_KERNEL_SIGNING_PUBKEY: &str =
    "es256:02c4e4af2e9cba6ba6745c513f193622e6674a8b2d0187ebea5612f5b46a7eade4";

/// The first-party signed-kernel content hashes trusted under the **strict**
/// posture, for this build's **guest arch**. The guest arch mirrors the host: an
/// x86_64 host boots x86_64 KVM guests (the embedded VMM); an Apple-silicon host
/// boots aarch64 guests (the Virtualization.framework `vmm-vz` backend). An x86_64
/// kernel can't boot an aarch64 VM (and vice versa), so each arch trusts only its
/// own signed `boatramp-vmlinux-<arch>` releases. Bump on each new signed release.
///
/// The **relaxed** (single-tenant) posture ignores this list — it verifies only the
/// content-hash pin — so an operator-supplied kernel boots there regardless of arch.
fn default_allowed_kernel_hashes() -> Vec<String> {
    #[cfg(target_arch = "x86_64")]
    {
        vec![
            // v0.2.0 minimal Firecracker 6.1-config kernel: boots under the
            // firecracker-*binary* backend (ACPI device discovery) but NOT the
            // in-process embedded VMM. Kept trusted so operators on the currently
            // published release don't fail strict verification.
            "cf1e590a9e642be3667131ca35fbf390378a457d8908169d2a169608e299d974".to_string(),
            // Same kernel + CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y (flake `#vmlinux`),
            // so the embedded VMM binds its virtio-block root over the cmdline
            // transport. Reproducible build output (deterministic nix build,
            // verified on KVM); the next signed boatramp-vmlinux release — which
            // reuses this flake — publishes + signs it, gated by
            // `vmlinux-release-boot.yml`.
            "d0dc2098ab2a2a3c1bc72ab61dc85d9e464d798d7e55b6b80525db5ca2f00c5a".to_string(),
        ]
    }
    #[cfg(target_arch = "aarch64")]
    {
        vec![
            // `boatramp-vmlinux-aarch64` v0.2.3 (the Virtualization.framework guest
            // kernel, flake `#vmlinux` on aarch64-linux — a raw arm64 `Image`). This
            // release enables the generic PCIe host + virtio-pci so the guest actually
            // discovers VZ's virtio disk/net/console (the earlier v0.2.2 `be95fb0d…`
            // built with `CONFIG_PCI` off never booted under VZ and is dropped). This
            // is the hash of the **published, ES256-signed** release asset (signed by
            // BOATRAMP_KERNEL_SIGNING_PUBKEY), so a selected `compute.default_kernel`
            // clears the strict bar out of the box; the boot + scale-to-zero round-trip
            // was validated against this exact published kernel. NOTE: unlike x86_64,
            // the aarch64 build is not currently bit-reproducible across build hosts
            // (same config + size, different build metadata), so pin/verify against the
            // published `.sha256`/`.sig`, not a local rebuild. Bump on each new release.
            "d785a48d754e65a4630443301f1fb84cb69cf882336d3cf37055e437b3d8e21f".to_string(),
        ]
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Vec::new()
    }
}

impl Default for ComputeConfig {
    fn default() -> Self {
        Self {
            bridge: "br-boatramp".to_string(),
            subnet: "10.0.0.0/24".to_string(),
            vcpus: 0,
            mem_mib: 0,
            kernel_signing_pubkeys: vec![BOATRAMP_KERNEL_SIGNING_PUBKEY.to_string()],
            kernel_allowed_hashes: default_allowed_kernel_hashes(),
            region: None,
            docker_endpoint: boatramp_docker::DockerEndpoint::default(),
            docker_volume_mode: boatramp_docker::DockerVolumeMode::default(),
            docker_ephemeral_timeout_secs: 0,
            sql_shim_url: None,
            blob_shim_url: None,
            messaging_shim_url: None,
            blob_shim_max_object_bytes: None,
            managed_db_privilege: ManagedDbPrivilege::default(),
            internal_dns: default_internal_dns(),
            dns_upstream: default_dns_upstream(),
            dns_domain: default_dns_domain(),
            client_image_rootfs: BTreeMap::new(),
            pg_client_image: None,
            mysql_client_image: None,
            registry_auth: BTreeMap::new(),
        }
    }
}

/// `cluster` section — self-hosted **cluster mode**. Parsed in
/// every build so config files stay portable; only *consumed* when the `cluster`
/// feature is compiled in (`boatramp serve --mode cluster`).
#[cfg_attr(not(feature = "cluster"), allow(dead_code))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    /// Address to bind this node's Raft **peer mesh** on (the `/raft/*` +
    /// `/stream/*` endpoints) — distinct from the public `serve.addr`.
    pub listen: SocketAddr,
    /// The cluster **root anchor set** — the `es256:`/`ed25519:`-tagged public
    /// keys that define this cluster's identity (a cluster *is* its root key).
    /// Every join/trust decision verifies against this set. Empty ⇒ falls back to
    /// `serve.auth_root_public_key` (the single-anchor default). A *set* enables
    /// make-before-break root rotation.
    #[serde(default)]
    pub root_pubkeys: Vec<String>,
    /// **Seeds** — control-plane addresses of existing cluster members
    /// (`host:port`), any of which can admit this node. Present ⇒ this node
    /// **joins** (redeems its `join_token`); absent + no durable state + explicit
    /// `--cluster-init` ⇒ it **founds**. There is no peer map: members are learned
    /// from the root-signed join response.
    #[serde(default)]
    pub seeds: Vec<String>,
    /// The single-use bearer **join token** used when `seeds` are set. Keeps the
    /// secret out of the file via a prefix: `env:VAR`, `path:/file`, or an inline
    /// literal. Usually supplied via `serve --cluster-join <ticket>` instead.
    #[serde(default)]
    pub join_token: Option<String>,
    /// Directory for this node's **durable** Raft log/state store (node-local;
    /// distinct from the replicated control plane). Default
    /// `<data-dir>/raft`.
    #[serde(default)]
    pub store_dir: Option<PathBuf>,
    /// Mesh identity + TLS settings. Absent ⇒ defaults (identity key
    /// auto-generated under `<data-dir>/mesh/identity.key`).
    #[serde(default)]
    pub mesh: Option<MeshConfig>,
}

/// `[cluster.mesh]` — mesh identity + TLS knobs.
#[cfg_attr(not(feature = "cluster"), allow(dead_code))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MeshConfig {
    /// Path to this node's Ed25519 identity key (PKCS#8 DER, `0600`,
    /// auto-generated). Default `<data-dir>/mesh/identity.key`.
    pub key_file: Option<PathBuf>,
    /// Automatic key-rotation cadence (e.g. `"30d"`); `None` = manual only.
    /// Consumed by the rotation loop.
    pub key_rotation: Option<String>,
    /// TTL for a single-use join token (e.g. `"1h"`).
    pub join_token_ttl: Option<String>,
    /// Gate mesh `client-write`s behind a control-plane **cluster-write
    /// capability**, so a trusted peer can't inject arbitrary
    /// control-plane writes on mesh trust alone. Requires the token root
    /// **private** key on every node (each mints + presents its own capability);
    /// default `false`.
    pub gate_client_writes: Option<bool>,
    /// Which transport carries the Raft peer-mesh RPC (IU-9): `"http"` (default — reqwest/axum
    /// over the mutual-TLS mesh) or `"overlay"` (boatramp's own overlay-QUIC fabric, reusing the
    /// mesh identity + live trust set verbatim). `None` ⇒ `"http"`. Both bind the same
    /// `cluster.listen` address — HTTP over TCP, overlay over UDP/QUIC.
    pub transport: Option<String>,
}

/// `handlers` section — server-side handler runtime config (read by `serve`).
/// Parsed in every build (so config files stay portable), but only *consumed*
/// when the `handlers` feature is compiled in.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HandlersConfig {
    /// `handlers.bindings` — which backend serves each handler binding.
    pub bindings: BindingsConfig,
    /// Use the wasmtime **pooling** instance allocator: faster
    /// instantiation at the cost of a large up-front virtual-memory reservation.
    /// Off by default — opt in and benchmark for your workload.
    pub pooling: bool,
    /// Capacity of the per-lane **warm compile cache** — how many distinct compiled+linked components
    /// (keyed by content hash) stay resident per lane (request / consumer / session). A component
    /// evicted here (LRU, once the node serves more than this many distinct components on a lane) pays
    /// a cold cranelift recompile on its next request. Absent ⇒ 64 (the historical default). Raise it
    /// on a node that serves more than ~64 components so none is evicted; the `/api/instance-stats`
    /// surface reports `warm_capacity` + `evictions` so the right value is measured, not guessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_cache_size: Option<usize>,
    /// **Warm floor** (cold-start cap-req 09): the maximum number of request components PINNED
    /// in a never-evicted set, so a latency-critical face never cold-starts under LRU capacity
    /// pressure. Absent/`0` ⇒ off (the plain LRU). Each activated request component is pinned
    /// up to this cap (first-come); size it ≥ your latency-critical handler count. Pinned
    /// components cost one resident instance each on top of the LRU, so keep it modest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keep_warm_max: Option<usize>,
    /// **Portable cross-node AOT artifact cache** (cold-start cap-req 09). When `true` AND a
    /// `[secrets]` envelope is configured, a node publishes each request component's precompiled
    /// artifact (cluster-MAC-authenticated) to the shared blob store, and a FRESH replica
    /// hydrates it instead of recompiling from source. Default **off** (opt-in): it loads
    /// native code off the shared store, so it is gated on the cluster secret + a MAC check.
    /// A node without the envelope silently never participates (it still compiles + warm-caches).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aot_artifact_cache: Option<bool>,
    /// Per-artifact size ceiling for the AOT cache (bytes; `0` ⇒ unlimited). Native code is
    /// large; an artifact over this is neither published nor (beyond a hard safety ceiling)
    /// read. Absent ⇒ a generous default. Only consulted when `aot_artifact_cache` is on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aot_artifact_max_bytes: Option<u64>,
    /// **Blob container-marker cache size** (entries). Every blob container open re-`HEAD`s the
    /// `.boatramp-container` ownership marker — a second serial object-store round-trip per serve. A
    /// process-wide, positive-only cache of VERIFIED markers (keyed by the fully-resolved, tenant-confined
    /// container prefix; invalidated on container delete) skips that HEAD for an already-verified
    /// container WITHOUT touching confinement (`container_access` still runs on every op). Absent ⇒ 4096;
    /// `0` disables the cache (every open re-HEADs). A node rarely has more than a handful of live
    /// containers, so the default is generous headroom.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_marker_cache_entries: Option<usize>,
    /// **Hedged blob-read delay** (milliseconds). When a serve's object GET has not returned within this
    /// many ms, the host races a SECOND GET and takes whichever lands first — cutting the serve-path
    /// fetch tail on an external store (measured: `blob_range` p50 ≈ 16ms but p99 ≈ 727ms, with CPU
    /// idle). Blob reads are idempotent, so the hedge is always safe; the loser is cancelled. Absent/`0`
    /// ⇒ disabled (one GET per read). Set it a little above the warm p90 (e.g. 60–100ms) so only the
    /// genuinely-slow tail hedges. Pairs with [`blob_hedge_max_inflight`](Self::blob_hedge_max_inflight).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_hedge_delay_ms: Option<u64>,
    /// **Concurrent-hedge cap** — the max number of in-flight hedge (second) reads at once. Guards against
    /// a hedge storm when the whole store is slow (every read would otherwise double): over the cap a slow
    /// read simply waits on its single request. Absent ⇒ a small internal default (16). Only meaningful
    /// when [`blob_hedge_delay_ms`](Self::blob_hedge_delay_ms) is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_hedge_max_inflight: Option<usize>,
    /// **Blob read-through cache size** (bytes). The serve path fronts each blob backend with a bounded,
    /// byte-LRU read-through cache of whole-object bodies (`get` / whole-object `get_range`) plus a small
    /// positive-only cache of `head` metas, so a WARM blob/image serve — a content-addressed, immutable
    /// `/img` derivative read on a node that already served it — is answered from memory and skips the
    /// backend GET and its cold-connect tail entirely. A genuinely-partial range on a miss streams
    /// through uncached (never stored as if whole); writes/deletes evict the key. Absent ⇒ 128 MiB;
    /// `0` disables the cache (every read goes to the backend). ONE cache per backend (global + each
    /// per-project), keyed by the fully-resolved tenant-confined key — confinement (`container_access`)
    /// is decided before any read reaches it, so it never crosses tenants. Sized per node; image
    /// derivatives are ~10–25 KB, so the default holds thousands of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_read_cache_bytes: Option<u64>,
    /// **Per-component serve-admission concurrency** (image-serve-latency Ask B). Caps how many
    /// requests to the SAME component (keyed by content hash) are concurrently inside the expensive
    /// `build_bindings` + instantiate + serve-to-head region; a burst beyond it (e.g. a gallery firing
    /// dozens of `/img` thumbnails) queues cheaply on a semaphore instead of oversubscribing the tokio
    /// workers, which on a small-core node makes each request's await-resumptions pile up into a
    /// multi-second scheduling stall (the measured `bindgap`). Absent ⇒ a host-parallelism default
    /// (`available_parallelism * 4`, floored at 8) so a small node is bounded out of the box; `0`
    /// disables the gate (legacy unbounded serve). Raise it on a big node, or lower it if one hot
    /// component should be tighter; `/api/instance-stats` + the `bindgap` Server-Timing phase make the
    /// right value measurable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serve_concurrency: Option<usize>,
    /// Engine-wide **safety max** on a *connection-bearing* invocation (a site
    /// handler or a synchronous function/webhook invoke), milliseconds. A route
    /// or function may declare a *lower* timeout, never a higher one. Kept tight
    /// on purpose: a client, proxy, and the shared request pool are all blocked
    /// while a sync handler runs. Absent ⇒ 10s (the historical default). This is
    /// a node safety ceiling, not a per-invocation budget, and is distinct from
    /// a per-site `max_timeout_ms`.
    pub sync_max_timeout_ms: Option<u64>,
    /// Max concurrent in-flight *sync-lane* invocations node-wide — the GLOBAL ceiling every
    /// connection-bearing serve (site handler, synchronous invoke, and the `/graphql` gateway's
    /// subgraph fan-out) passes through, distinct from the PER-COMPONENT `serve_concurrency` gate.
    /// Absent ⇒ a host-parallelism default (`available_parallelism * 4`, floored at **64** — so it is
    /// unchanged on nodes up to ~16 vCPU and only scales ABOVE that). Without this, the lane was pinned
    /// at 64 regardless of host size, so adding vCPUs past ~16 bought no extra concurrent live
    /// throughput and there was no knob to lift it. Raise it on a big node to let the sync lane use more
    /// cores; lower it to cap aggregate live concurrency. Read once at startup. NOTE: with `[handlers]
    /// pooling` on, the shared instance pool is sized off the summed lane concurrencies, so a larger
    /// value enlarges the up-front virtual reservation (the non-pooling default sizes memory
    /// per-invocation and is unaffected). Unlike `serve_concurrency`, `0` is NOT "disable" — the
    /// global sync lane is a required safety ceiling, so a configured `0` is rejected (falls back to
    /// the host default, with a loud WARN at startup).
    pub sync_max_concurrency: Option<usize>,
    /// Emit the per-phase `Server-Timing` RESPONSE HEADER to clients. Default **off** (absent ⇒
    /// `false`): the per-phase breakdown always goes to the structured phase-timing LOG (operator
    /// observability), but putting it on the wire exposes internal phase structure + a timing
    /// side-channel to every caller. Turn it on for a debugging window (e.g. correlating a client's
    /// slow request to a host phase), off in production. Read once at startup.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_timing: Option<bool>,
    /// Engine-wide safety max on a *durable async* invocation — the drain that
    /// runs `?mode=async` calls, workflow steps, cron/queue/blob triggers, and
    /// `wasi:messaging` consumers, milliseconds. No client is connected and the
    /// work is retried + dead-lettered, so this can be far larger than the sync
    /// ceiling: it is what lets a legitimately long background job (e.g. an LLM
    /// generation) declare and actually get minutes of runtime. Absent ⇒ 15
    /// minutes. Runs on its own concurrency budget (`async_max_concurrency`), so
    /// a long job never starves live traffic.
    pub async_max_timeout_ms: Option<u64>,
    /// Max concurrent in-flight *async-lane* invocations, kept separate from the
    /// (larger) request pool so a burst of long background jobs can't exhaust the
    /// slots live site traffic needs. Absent ⇒ 8.
    pub async_max_concurrency: Option<usize>,
    /// Optional CPU **fuel** ceiling for an async-lane invocation. A large async
    /// timeout bounds only wall-clock; without a fuel bound a CPU-bound guest can
    /// spin for the whole window. Absent ⇒ unmetered (same as the sync default).
    pub async_max_fuel: Option<u64>,
    /// Per-component WASM linear-memory **ceiling** for the *async* lane, in MiB —
    /// the durable `wasi:messaging` / workflow-step lane where heavy, retryable jobs
    /// (image decode+resize, PDF, document processing) belong. This RAISES the lane
    /// ceiling above the 64 MiB default; a component's own `limits.memory_mb` (or the
    /// site `max_memory_mb`) then clamps it back **down** from here — so an operator
    /// sets the lane high enough for the heaviest consumer and each component
    /// right-sizes itself. Absent ⇒ 64 MiB (unchanged for every existing component;
    /// no component can raise its own memory above this operator-set ceiling). With
    /// `[handlers] pooling` on, the shared pool is sized off the largest lane ceiling;
    /// see the virtual-reservation note on `pooling`.
    pub async_max_memory_mb: Option<usize>,
    /// Per-component WASM linear-memory ceiling for the *sync* (request) lane, MiB.
    /// Absent ⇒ 64 MiB. Same semantics as [`async_max_memory_mb`](Self::async_max_memory_mb)
    /// (raises the lane ceiling; a component clamps down). Raising the sync lane means
    /// many concurrent request instances can each reach this ceiling, so weigh it
    /// against the request pool's size.
    pub sync_max_memory_mb: Option<usize>,
    /// Per-component WASM linear-memory ceiling for the *streaming* lane, MiB.
    /// Absent ⇒ 64 MiB. Same semantics as [`async_max_memory_mb`](Self::async_max_memory_mb).
    pub streaming_max_memory_mb: Option<usize>,
    /// **Relaxed messaging-publish durability** — the max number of published
    /// messages that may be acknowledged from the in-memory buffer BEFORE a durable
    /// checkpoint is forced. **Absent / `0` ⇒ strong durability (the default):**
    /// every `publish()` returns only after the message is crash-durable — a
    /// *stronger* guarantee than NATS JetStream's default sync publish. Set `N > 0`
    /// to opt a node into fast-ack (publish returns on the buffer insert, ~10µs
    /// instead of ~one flush interval), at the cost of a **bounded loss window: up
    /// to `N` acknowledged-but-unflushed messages are lost on a process crash / OOM
    /// / SIGKILL / power loss** before the next flush. Affects ONLY the messaging
    /// bus publish path — control-plane, auth, and consumer ack/redelivery
    /// durability are unaffected. Single-node only (cluster durability is
    /// replication). A node with `N > 0` logs a warning at startup.
    pub messaging_max_unflushed_msgs: Option<usize>,
    /// **Event-driven delivery — safety-net reconcile cadence** (ms). The coarse timer the delivery
    /// drainer falls back to when no fast-path wake fires: it drains the durable ready-set and fires
    /// lease-expiry redelivery via the per-message due-heap, so a dropped wake or a time-based
    /// visibility never stalls delivery beyond this interval. It never scans idle topics (an idle
    /// fleet costs ~0). Absent ⇒ ~2 s. Lower for tighter redelivery latency at more wakeups; raise to
    /// quiet a large idle fleet further.
    pub messaging_safetynet_interval_ms: Option<u64>,
    /// **Event-driven delivery — ready-set rebuild cadence** (ms). The long-cadence self-heal that
    /// re-derives the ready-set from the authoritative message index — recovering a marker lost to a
    /// crash between the index write and the ready write, pruning a stale marker, and self-populating
    /// a fresh/upgraded node's ready-set. This is the one full-ish scan, so it runs rarely. Absent ⇒
    /// ~30 s. The correctness backstop for the ready-set (a lost marker costs at most one rebuild
    /// interval of latency, never a lost message).
    pub messaging_readyset_rebuild_interval_ms: Option<u64>,
    /// Max wall-clock for a *streaming-lane* response (a `#[handler(stream)]`
    /// route — SSE, chunked, agent token streaming), milliseconds. A client is
    /// connected but the body is written incrementally over seconds-to-minutes,
    /// so this is far larger than the sync ceiling. Runs on its own concurrency
    /// budget (`streaming_max_concurrency`), isolated from both the fast request
    /// pool and the async drain. Absent ⇒ 15 minutes.
    pub streaming_max_timeout_ms: Option<u64>,
    /// Max concurrent in-flight *streaming-lane* responses, kept separate from the
    /// request pool and the async drain so a burst of long-lived streams starves
    /// neither. Absent ⇒ 64.
    pub streaming_max_concurrency: Option<usize>,
    /// Optional CPU **fuel** ceiling for a streaming-lane response. Absent ⇒
    /// unmetered (a stream is I/O-bound on the client, not CPU-bound).
    pub streaming_max_fuel: Option<u64>,
    /// **Idle cap** for a streaming-lane response (ms): if the handler emits no body frame to the
    /// client for this long, the host tears the stream down and reclaims its lane slot — the
    /// slowloris bound for the streaming lane, so a `streaming_max_concurrency`-sized burst of
    /// silent streams can't hold every slot. A well-behaved SSE stream sends heartbeats well inside
    /// it. The absolute lifetime stays bounded by `streaming_max_timeout_ms`. Floored at 1 s. Absent
    /// ⇒ 600 s (matches the `[stream]` fan-out idle window).
    pub streaming_idle_timeout_ms: Option<u64>,
    /// Optional ceiling on a guest's **outbound** `wasi:http` call — the connect
    /// and time-to-first-byte wait — milliseconds, independent of the invocation
    /// timeout, so a hung upstream is bounded on its own terms. The streaming
    /// (between-bytes) timeout is left at wasmtime's default so a slow token
    /// stream is not cut mid-flight. Absent ⇒ wasmtime's default.
    pub outbound_timeout_ms: Option<u64>,
    /// Per-INVOCATION `dns-resolve` budget — how many `boatramp:handlers/dns-resolve` lookups one
    /// guest invocation (one store) may issue before `rate-limited` (mailroom cap-req #20). For a
    /// SESSION-mode listener the budget is seeded ONCE per connection and shared across every re-entry
    /// (so a session guest can't reset it by sending another inbound frame). Absent ⇒
    /// [`boatramp_handlers::DEFAULT_DNS_RESOLVE_BUDGET`] (256). Takes effect only when the node posture
    /// `allow_guest_tcp_egress` is on and the component imports `dns-resolve`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_resolve_budget: Option<u32>,
    /// **DEV/TEST resolver override** for the consumer-lane `dns-resolve` / `resolve-mx` host
    /// capability (mailroom cap-req #21 residual). Injects a STATIC host→records map (consulted first,
    /// answered WITHOUT touching the network — the hook for a hermetic / fully-offline direct-MX relay
    /// proof) and/or points the resolver at a custom `upstream` nameserver instead of the host's
    /// `/etc/resolv.conf`. OFF by default (absent ⇒ the system resolver, byte-for-byte unchanged). This
    /// is OPERATOR/serve config only (node-global) — a guest/project can never set it — and its answers
    /// still pass through the unchanged grant + egress posture + SSRF floor, so it is neither a tenancy
    /// bypass nor a private-IP oracle. Takes effect only with the `tcp-egress` resolver compiled in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_resolve_override:
        Option<boatramp_server::dns_resolve_override::DnsResolveOverrideConfig>,
    /// **JWKS freshness — `own` (first-party) tier: background-refresh age** (seconds). The soft age at
    /// which a node-fixed `token_claims.jwks_url`/`jwks_env` verifier is refreshed in the BACKGROUND
    /// (the current keys keep serving — no request blocks on the fetch). Absent ⇒ 120 s. Floored at 60 s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_refresh_secs: Option<u64>,
    /// **JWKS freshness — `own` tier: hard TTL / revocation bound** (seconds). The age past which the
    /// first-party keys are no longer served and a request BLOCKS on a fresh fetch (fail-closed on
    /// failure) — caps how long a key revoked at the IdP can keep verifying. Absent ⇒ 600 s. Must be
    /// `> jwks_refresh_secs` (else clamped up, with a warning). Floored at 60 s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_hard_ttl_secs: Option<u64>,
    /// **JWKS freshness — `foreign` (user-declared multi-issuer) tier: background-refresh age**
    /// (seconds). As [`jwks_refresh_secs`](Self::jwks_refresh_secs) but for the multi-issuer
    /// (`issuer_trust`+`jwks` discovery) path, which is less trusted. Absent ⇒ 60 s. Floored at 60 s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_foreign_refresh_secs: Option<u64>,
    /// **JWKS freshness — `foreign` tier: hard TTL / revocation bound** (seconds). As
    /// [`jwks_hard_ttl_secs`](Self::jwks_hard_ttl_secs) but for user-declared issuers — typically set
    /// TIGHTER (faster revocation of a potentially-compromised foreign key). Absent ⇒ 300 s. Must be
    /// `> jwks_foreign_refresh_secs`. Floored at 60 s.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_foreign_hard_ttl_secs: Option<u64>,
    /// **JWKS pre-warm at startup.** When on (the default), the node fetches each configured
    /// first-party (`own`-tier) `jwks_url` at startup so even the FIRST request is instant; foreign
    /// (user-declared) issuers can't be pre-warmed (they aren't known until a token arrives). Set
    /// `false` to skip startup JWKS fetches (the first request per issuer then pays the fetch). Absent ⇒ on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_prewarm: Option<bool>,
}

/// `handlers.bindings` — per-binding backend configuration. kv/blob reuse the
/// server's own KV/Storage backends (per-site prefixed); `sql` is the single
/// libsql backend, whose single-node-vs-cluster split is the only choice.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct BindingsConfig {
    /// `handlers.bindings.sql` — libsql settings. Absent ⇒ single-node,
    /// per-site embedded files under `<data-dir>/handlers-sql`.
    pub sql: Option<SqlBindingConfig>,
}

/// libsql settings for the handler `sql` binding — the single SQL backend. Each
/// site gets a real database boundary (an embedded file per site, or a sqld
/// namespace per site), never schema separation (which arbitrary guest SQL
/// escapes). Setting `url` switches from single-node to a shared sqld cluster;
/// everything else stays identical.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SqlBindingConfig {
    /// Single-node: root directory for the per-site embedded database files
    /// (default `<data-dir>/handlers-sql`). Ignored when `url` is set.
    pub dir: Option<PathBuf>,
    /// Cluster: base sqld data URL (e.g. `http://sqld:8080`). When set, each
    /// site is a sqld namespace addressed as a subdomain of this URL; `admin_url`
    /// is then required.
    pub url: Option<String>,
    /// Cluster: sqld admin API base URL (e.g. `http://sqld:9090`) for creating
    /// per-site namespaces. Required when `url` is set.
    pub admin_url: Option<String>,
    /// Cluster: optional sqld **read-replica** data URL. When set, handlers'
    /// read-only `sql` transactions (`open-read-only`) route to this endpoint
    /// while writes stay on `url` (reads → replicas, writes → primary).
    /// Reads may lag (eventually consistent). Ignored in
    /// single-node mode (no `url`).
    pub replica_url: Option<String>,
    /// Name of the env var holding the sqld data auth token (optional; never
    /// the token itself in-file).
    pub token_env: Option<String>,
    /// Name of the env var holding the sqld admin API auth key (optional).
    pub admin_token_env: Option<String>,
    /// How preview deployments get their SQL database: `empty` (default — a
    /// fresh isolated db), `branch` (a consistent copy of the site's live db;
    /// single-node only), or `shared` (the site's live db). See
    /// `boatramp_core::sql::PreviewSqlMode`.
    pub preview_mode: Option<String>,
    /// Path to an idempotent SQL script run when an `empty` preview database is
    /// first opened (e.g. schema/seed). Ignored in `branch`/`shared` modes.
    pub preview_init: Option<PathBuf>,
    /// `handlers.bindings.sql.databases` — external **bring-your-own** databases,
    /// each opened by name via `sql.open("<name>")`. An operator-configured
    /// Postgres/MySQL whose *isolation is the operator's* (it's their database),
    /// so these bypass the per-site libsql boundary and are reachable by any
    /// handler/function granted the `sql` binding. Needs the `sql-postgres` /
    /// `sql-mysql` build feature for the engine. A name here shadows the same
    /// name on the managed libsql default.
    pub databases: BTreeMap<String, ExternalDatabaseConfig>,
    /// **Soft-delete grace window** for a per-tenant managed database, in seconds
    /// (env `BOATRAMP_HANDLERS_SQL_DEPROVISION_GRACE_SECS`). When a project/site is
    /// deleted, a **Shared + Postgres** tenant is *soft*-deleted (its database is
    /// renamed aside and its role disabled) and stays recoverable for this long
    /// before a reaper hard-drops it — see
    /// [`tenant_sql`](crate::tenant_sql). `None` ⇒ the 7-day default
    /// (`DEFAULT_DEPROVISION_GRACE_SECS`); `0` ⇒ disable the soft path (immediate,
    /// irreversible hard drop everywhere). MySQL and all `Single` tenants always
    /// hard-drop immediately (the engine/cell can't be renamed aside safely), so this
    /// knob only affects the Shared-Postgres cell.
    pub deprovision_grace_secs: Option<u64>,
    /// **Trusted-extension allowlist** for the owner-gated schema-migration surface — the ONLY
    /// Postgres extensions a migration `Extension` step may enable (a name not here is refused
    /// fail-closed). A raw `sql` migration step may not `CREATE EXTENSION` at all, so this list is
    /// the single, operator-controlled gate on which extensions a project can install via
    /// migrations. Empty / `None` ⇒ no extension may be enabled through a migration (the safest
    /// default). Keep it tight (e.g. `["pgcrypto", "uuid-ossp", "citext"]`); an entry like
    /// `dblink`/`postgres_fdw` deliberately widens cross-database reach, so add those only knowingly.
    ///
    /// Env-settable (12-factor parity) via **`BOATRAMP_HANDLERS_SQL_MIGRATE_TRUSTED_EXTENSIONS`** —
    /// a comma-separated list (`pg_trgm,pgcrypto`), env-over-file, unset ⇒ the file value. Only an
    /// input path; the allowlist semantics (the `Extension`-step gate, the fail-closed refusal of an
    /// unlisted name, the `sql`-step `CREATE EXTENSION` ban) are unchanged.
    pub migrate_trusted_extensions: Option<Vec<String>>,
    /// **Per-project declared-database COUNT ceiling** (#501 Stage B MEDIUM-1 — the
    /// disk-exhaustion / errno-28 guard). The maximum number of `databases:` entries a
    /// single project may declare; a declare that would exceed it is refused fail-closed
    /// (a 422-class error). Each declared DB eagerly provisions a 10–200 GiB volume, so
    /// without this a `Project·Admin` could declare an unbounded number and exhaust the
    /// node's disk. `None` ⇒ the built-in default
    /// (`apply_db_caps::DEFAULT_MAX_DECLARED_DATABASES_PER_PROJECT`, 16); `0` ⇒ declaring
    /// any managed database is disabled on this node. Env-settable via
    /// **`BOATRAMP_HANDLERS_SQL_MAX_DECLARED_DATABASES`** (env-over-file).
    pub max_declared_databases: Option<usize>,
    /// **Per-project aggregate declared-VOLUME ceiling**, in MiB (#501 Stage B
    /// MEDIUM-1). The maximum SUM of `volume_size_mib` across all of a project's declared
    /// databases; a declare whose incoming volume would push the project's total past
    /// this is refused fail-closed. `None` ⇒ the built-in default
    /// (`apply_db_caps::DEFAULT_MAX_DECLARED_VOLUME_MIB`, 512 GiB); `0` ⇒ disable managed
    /// declarations on this node (the aggregate can never fit a non-zero volume). Env-settable via
    /// **`BOATRAMP_HANDLERS_SQL_MAX_DECLARED_VOLUME_MIB`** (env-over-file).
    pub max_declared_volume_mib: Option<u64>,
}

/// One external SQL database for the handler `sql` binding. Its **source** is one
/// of two mutually-exclusive forms:
///  - `url_env` — a **bring-your-own** database: the connection URL is a secret,
///    named indirectly by an env var (never written in the config file).
///  - `compute` — a database **boatramp runs** as a compute workload: boatramp
///    derives the connection from the workload's live endpoint (host\:port) plus
///    the `database`/`user`/`password_env` here, so there is no URL to hand-map and
///    it follows the workload across restarts (PLAN-managed-compute-sql).
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExternalDatabaseConfig {
    /// Engine: `postgres` (aliases `postgresql`/`pg`), `mysql` (alias
    /// `mariadb`), or `libsql` (aliases `sqlite`/`sqlite3`) — the embedded
    /// SQLite-compatible engine (single-node file, or a remote sqld primary via
    /// `url_env`). A `libsql` entry needs neither `compute` nor an external URL for
    /// the single-node case: it names an on-disk file via [`path`](Self::path).
    pub kind: String,
    /// Name of the env var holding the connection URL (e.g.
    /// `postgres://user:pw@host/db`). Required unless `compute` is set — or, for a
    /// single-node `libsql` database, unless `path` is set (an embedded file needs
    /// no URL/secret).
    pub url_env: String,
    /// Optional env var holding a **read-replica** connection URL. When set,
    /// `open-read-only` transactions route there; writes stay on `url_env`.
    pub read_url_env: Option<String>,
    /// Optional env var holding a **DDL/migration** connection URL for the
    /// **owner-role analog** of the schema-migration surface — a login that is
    /// DDL-capable *and distinct from the runtime binding user* (`user` /
    /// `url_env`). Its whole purpose is to keep migration DDL off the runtime
    /// tenant identity, mirroring the Postgres owner-role split (Postgres mints a
    /// per-tenant non-superuser owner role automatically; MySQL has no such role
    /// model, so the DDL identity must be supplied explicitly).
    ///
    /// **MySQL:** required to run schema migrations. Point it at an admin/DDL
    /// login (e.g. `mysql://root:…@host/db` or a purpose-made `_migrate` grant
    /// with `CREATE, ALTER, DROP, INDEX, REFERENCES` on the schema) that is **not**
    /// the runtime `user`. If it is unset (or resolves to the same identity as the
    /// runtime binding), migrate **refuses** fail-closed rather than run owner-DDL
    /// as the runtime tenant user — there is no owner/runtime split to fall back
    /// on. Ignored by the normal handler `sql` path; read only by the migration
    /// runner.
    ///
    /// **Postgres:** ignored — the per-project non-superuser owner role +
    /// its sealed credential are minted automatically at provision, so no
    /// operator-supplied DDL URL is needed (a set value is harmless and unused).
    pub migration_url_env: Option<String>,
    /// The name of a **compute workload** (a Postgres/MySQL server boatramp runs)
    /// to source this database from, instead of `url_env`. boatramp resolves the
    /// workload's live endpoint and builds the connection. Mutually exclusive with
    /// `url_env`.
    ///
    /// **Reserved prefix (#501 Stage B LOW-2):** do NOT name a static workload with the
    /// `bramp-db-` prefix — it is reserved for the per-project managed-database servers
    /// boatramp derives for declarative `databases:` entries
    /// (`boatramp_storage::tenant_provision::DERIVED_MANAGED_DB_PREFIX`). A `bramp-db-…`
    /// value here is refused fail-closed at config load
    /// ([`ConfigError::InvalidDbName`](crate::config::ConfigError::InvalidDbName)).
    pub compute: Option<String>,
    /// The database name inside the compute-backed server (non-secret).
    pub database: Option<String>,
    /// The connecting user for the compute-backed server (non-secret).
    pub user: Option<String>,
    /// Env var holding the password for `user` on the compute-backed server.
    /// **Omit to let boatramp fully manage the credential** (PLAN-managed-compute-sql
    /// Phase 2): it generates a strong password once, seals it with the `[secrets]`
    /// envelope, injects it into the DB workload's server-init env at launch, and
    /// connects the handler with it — the operator sets no DB secret at all. Set it
    /// only to bring your own password for the compute-backed server.
    pub password_env: Option<String>,
    /// Maximum pooled connections (default 8).
    pub pool_max: Option<u32>,
    /// Warm **floor** of pooled connections kept established while idle (default none).
    /// `0`/unset lets an idle pool drain fully, so the next burst re-establishes every
    /// connection from cold — serially paying a TCP+TLS+auth handshake per connection
    /// (the proven public-storefront saturation). Set a small floor for a hot **shared**
    /// storefront pool so a burst acquires warm connections. NOTE: on a per-tenant managed
    /// binding this floor is held *per tenant*, so each tenant's pool keeps that many idle
    /// DB sessions — set it only where that fan-out is acceptable. Clamped to `pool_max`.
    pub pool_min: Option<u32>,
    /// Open every transaction `READ ONLY` (the engine rejects writes) — for a
    /// database functions should only read.
    pub read_only: bool,
    /// Permit **preview** deployments to reach this database. Default `false`: a
    /// preview is refused, so it can never touch the operator's live external DB.
    pub allow_preview: bool,
    /// Connection/acquire timeout in seconds (default 10).
    pub connect_timeout_secs: Option<u64>,
    /// The stock OCI image for a **managed co-located** database (`compute` set, no
    /// `password_env`). When omitted, boatramp auto-registers the workload from the
    /// engine's default image (`pgvector/pgvector:pg16` for postgres, `mysql:8.0`
    /// for mysql). Ignored for a bring-your-own (`url_env`) database.
    pub image: Option<String>,
    /// The persistent data-volume size in MiB for a **managed co-located** database
    /// (default 10240 = 10 GiB). Ignored for a bring-your-own database.
    pub volume_size_mib: Option<u32>,
    /// Startup grace (seconds) for a **managed co-located** database: how long a
    /// freshly launched server has to finish its first `initdb` before the reconcile
    /// loop treats a still-unhealthy replica as a broken launch to stop + relaunch.
    /// When set it overrides the engine default the synthesizer picks (Postgres 60,
    /// MySQL 120). Omit to use that default. Ignored for a bring-your-own database.
    pub startup_grace_secs: Option<u32>,
    /// **One-time migration designation** (default `false`): mark THIS binding as the owner
    /// of the pre-v0.46 shared legacy data volume. Before co-located managed databases keyed
    /// their on-disk data directory per `(project, workload)`, EVERY default-project / shared
    /// managed DB shared one bare `<data_dir>/compute/volumes/data` directory. On upgrade the
    /// container backend adopts that legacy directory into the owning workload's per-workload
    /// scoped directory by an atomic, data-preserving rename. When **exactly one** managed DB
    /// is configured, it is the unambiguous owner and no flag is needed. When **two or more**
    /// co-located managed DBs exist, boatramp cannot prove from disk which one initialized the
    /// shared cluster, so it **fails closed** (refuses to launch them, leaving the data
    /// untouched) until an operator sets this flag on the ONE binding whose data lives there.
    /// Set it on at most one binding; setting it on two is itself ambiguous (fail closed).
    /// Ignored for a bring-your-own (`url_env`) database and once the volume is migrated.
    ///
    /// **Upgrade constraint (v0.46):** the legacy-data owner is inferred from the managed
    /// `databases` bindings present at boot, so do NOT remove or rename a managed `databases`
    /// binding across the upgrade that first scopes volumes — if the removed/renamed binding
    /// owned the shared `data` cluster, the surviving binding could auto-adopt a cluster that
    /// is not its own (fail-closed in practice: a per-(project, workload) sealed credential
    /// will not authenticate against a foreign cluster's roles, so the DB comes up unusable
    /// rather than leaking). If you must change bindings during that upgrade, set this flag on
    /// the ONE binding that owns the on-disk cluster so adoption is explicit.
    #[serde(default)]
    pub adopt_legacy_data_volume: bool,
    /// **Opt-in** (default `false`): enable row-level change capture on this **managed
    /// co-located** database so it can source a delta export's SQL true-delta (Postgres
    /// logical WAL / MySQL binlog). Flips `wal_level=logical` / `--log-bin` in the launch
    /// argv — a start-only server setting — so toggling it remints the content-addressed spec
    /// and requires a restart (governed by `restart_policy`). Off ⇒ no WAL/binlog overhead and
    /// a delta export of this DB falls back to a full dump. Ignored for a bring-your-own
    /// (`url_env`) database.
    #[serde(default)]
    pub delta_capture: bool,
    /// How a restart-requiring config change on this **managed co-located** database (today:
    /// toggling `delta_capture`) is applied: `manual` (default — stage it and mark the DB
    /// restart-pending for an explicit `boatramp db restart`) or `auto` (apply + restart the
    /// DB immediately). Ignored for a bring-your-own database.
    #[serde(default)]
    pub restart_policy: DbRestartPolicy,
    /// **Isolation mechanism** for a compute-backed managed database (2×2 axis 1).
    /// `single` (default) — a *dedicated* database server (its own container) per
    /// tenant; `shared` — *one* server hosting a permission-separated database + role
    /// per tenant. Ignored for a bring-your-own (`url_env`) database.
    pub tenant: TenantIsolation,
    /// **Tenant grain** for a compute-backed managed database (2×2 axis 2). `project`
    /// (default) — a tenant is a project; `site` — a tenant is a site. A tenant may
    /// hold several databases (one per binding that names it); it gets one login role
    /// and sealed credential per (tenant, server), granted on all its own databases
    /// and none of another tenant's. The reserved `default` project uses the plain
    /// configured name, so a single-tenant install is just one ordinary database.
    pub tenant_scope: TenantScope,
    /// The per-surface **readiness gate** (v0.45.0): the readiness level each surface
    /// requires before it treats a managed-DB replica as usable. Default: every surface
    /// `provisioned` (strict — route/answer/migrate only once post-launch provisioning has
    /// completed). Relax a surface to `service_ready` to use a replica as soon as it
    /// answers `SELECT 1`, before provisioning finishes. Ignored for a bring-your-own
    /// (`url_env`) database.
    #[serde(default)]
    pub readiness_gate: ReadinessGate,
    /// **Opt-in** (default `false`): inject the request's `boatramp.project` /
    /// `boatramp.site` into the SQL session at each transaction start (Postgres
    /// `set_config` GUC, MySQL session var), so hand-written **native RLS** policies
    /// can key on them per-request. The GraphQL data connector's row-level policy is
    /// claim-sourced and needs nothing here; this is for hand-rolled RLS on the plain
    /// `sql.open` path (Postgres — the engine with native row-level security).
    ///
    /// # Trust model — read before relying on this for isolation
    ///
    /// `rls_session` **provides** the request's tenant to the SQL session for an app's
    /// RLS to key on. It is **not** a general hostile-guest boundary:
    ///
    /// - The reserved keys (`boatramp.*` / `@boatramp_*`) are **protected** from guest
    ///   override — a handler statement that tries to `set_config('boatramp.…', …)` /
    ///   `SET boatramp.… ` / `SET @boatramp_… ` (or `RESET`/`DISCARD` them) is refused,
    ///   so a guest cannot spoof its injected tenant.
    /// - But the **real tenant-isolation boundary** is the **per-tenant database +
    ///   role** (`tenant = single` / `shared`), which a compromised handler cannot
    ///   cross regardless of what it does in-session. `rls_session` is a convenience
    ///   for app-authored RLS *within* a tenant's own database, layered on top of that
    ///   boundary — not a substitute for it.
    /// - For untrusted data, prefer **claim-sourced** enforcement (the GraphQL data
    ///   connector's row-level policy), which derives the tenant from the verified
    ///   request, not from anything the handler's SQL can influence.
    pub rls_session: bool,
    /// The Postgres session GUC name an app's RLS policies read for the host-resolved **tenant**
    /// (e.g. `app.tenant_id`), set per request/write on the `rls_session` path so RLS mirrors
    /// boatramp's injected predicate as a defense-in-depth backstop (v0.4.20). Only honored when
    /// `rls_session` is on and the backend is Postgres. `None` ⇒ not exposed (today's behavior).
    /// The guest can never set this GUC itself (its namespace becomes reserved).
    #[serde(default)]
    pub tenant_guc: Option<String>,
    /// The session GUC name for the anonymous **session** axis (e.g. `app.session_id`), the
    /// disjoint-column sibling of `tenant_guc` for `TenantOrSession` tables. `None` ⇒ not exposed.
    #[serde(default)]
    pub session_guc: Option<String>,
    /// A reserved sentinel value written to `tenant_guc` on an **`all`-scoped READ** (v0.4.21), so a
    /// table that opts in with `USING (… OR current_setting(tenant_guc, true) = '<marker>')` opens
    /// cross-tenant for the audited `all` twins. Pick a value that can **never** be a real tenant id
    /// (e.g. `*` or `__all__`). Only honored with `tenant_guc` set + `rls_session` on + Postgres.
    /// `None`/empty ⇒ `all` reads leave the GUC untouched (v0.4.20 fail-closed behavior). The guest
    /// can never set it — the `tenant_guc` namespace is already reserved against guest writes.
    #[serde(default)]
    pub tenant_all_marker: Option<String>,
    /// The on-disk file path for a single-node **`libsql`** database (`kind: "libsql"`), e.g.
    /// `/data/app.db`. The parent directory is created if absent. Used only by the embedded engine;
    /// ignored for `postgres`/`mysql` and for a remote-sqld `libsql` binding (which uses `url_env`).
    /// A `libsql` entry sets exactly one of `path` (single-node file) or `url_env` (remote sqld).
    #[serde(default)]
    pub path: Option<PathBuf>,
}

/// How a managed compute-backed database is physically isolated per tenant (2×2 axis
/// 1). `Single` = a dedicated server (container) per tenant (isolation by separate
/// process); `Shared` = one server with a per-tenant database + login role (isolation
/// by grants — Postgres `REVOKE CONNECT FROM PUBLIC` + owner grant; MySQL per-schema
/// grant), so a tenant's role cannot connect to another tenant's database.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantIsolation {
    /// A dedicated database server (its own container) per tenant. The default.
    #[default]
    Single,
    /// One shared server hosting a per-tenant database + role (grant-isolated).
    Shared,
}

/// The grain of a tenant for a managed compute-backed database (2×2 axis 2) —
/// `Project` (default) or `Site`. The two grains are parallel; the isolation
/// mechanism is [`TenantIsolation`].
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantScope {
    /// A tenant is a **project** (the default).
    #[default]
    Project,
    /// A tenant is a **site** (finer than project).
    Site,
}

/// Re-export: the readiness-gate value types live in `boatramp-types` (shared between the
/// manifest `ApplyDatabase` and this serving config), surfaced here for the
/// `ExternalDatabaseConfig::readiness_gate` field.
#[cfg_attr(not(feature = "handlers"), allow(unused_imports))]
pub use boatramp_core::compute::{DbRestartPolicy, ReadinessGate, ReadinessLevel};

impl ExternalDatabaseConfig {
    /// Validate the source is well-formed: **exactly one** of `url_env` /
    /// `compute`, and a `compute`-backed database has the connection details
    /// boatramp can't infer (`database` + `user`). `password_env` is **optional** —
    /// omit it to let boatramp manage the credential (Phase 2). `name` is the
    /// binding name, for the error message.
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub fn validate(&self, name: &str) -> Result<(), String> {
        let has_url = !self.url_env.is_empty();
        let has_compute = self.compute.as_deref().is_some_and(|c| !c.is_empty());
        let has_path = self
            .path
            .as_deref()
            .is_some_and(|p| !p.as_os_str().is_empty());

        // A `libsql`/`sqlite` entry is the embedded engine: single-node via `path`, or remote sqld
        // via `url_env` — never `compute` (boatramp doesn't run a libsql server workload). Validate
        // it on its own axis (exactly one of `path` / `url_env`), and reject `path` on the external
        // engines (a Postgres/MySQL binding has no on-disk file).
        let is_libsql = matches!(
            self.kind.trim().to_ascii_lowercase().as_str(),
            "libsql" | "sqlite" | "sqlite3"
        );
        if is_libsql {
            if has_compute {
                return Err(format!(
                    "sql database {name:?}: a `libsql` database is the embedded engine — set `path` \
                     (single-node file) or `url_env` (remote sqld), not `compute`"
                ));
            }
            return match (has_path, has_url) {
                (true, true) => Err(format!(
                    "sql database {name:?}: a `libsql` database sets exactly one of `path` \
                     (single-node file) or `url_env` (remote sqld), not both"
                )),
                (false, false) => Err(format!(
                    "sql database {name:?}: a `libsql` database needs a source — set `path` \
                     (single-node file) or `url_env` (remote sqld)"
                )),
                _ => Ok(()),
            };
        }
        if has_path {
            return Err(format!(
                "sql database {name:?}: `path` is only valid for a `libsql` database (the embedded \
                 engine); a {} binding uses `url_env` or `compute`",
                self.kind
            ));
        }

        match (has_url, has_compute) {
            (true, true) => Err(format!(
                "sql database {name:?}: set exactly one of `url_env` or `compute`, not both"
            )),
            (false, false) => Err(format!(
                "sql database {name:?}: needs a source — set `url_env` (bring-your-own) or \
                 `compute` (a database boatramp runs)"
            )),
            (false, true) => {
                // `database` + `user` are non-secret and can't be inferred; a missing
                // `password_env` is *not* an error — it selects the managed credential.
                for (field, val) in [("database", &self.database), ("user", &self.user)] {
                    if val.as_deref().is_none_or(str::is_empty) {
                        return Err(format!(
                            "sql database {name:?}: a `compute`-backed database requires `{field}`"
                        ));
                    }
                }
                Ok(())
            }
            (true, false) => Ok(()),
        }
    }

    /// Whether this compute-backed database uses a **boatramp-managed** credential
    /// (Phase 2): `compute` is set and no `password_env` was supplied.
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub fn is_managed_credential(&self) -> bool {
        self.compute.as_deref().is_some_and(|c| !c.is_empty())
            && self.password_env.as_deref().is_none_or(str::is_empty)
    }
}

/// The signing algorithm for a signer that can choose one (`Local`, `Vault`,
/// `Pkcs11`). ES256 is the portable default; the cloud KMS backends are ES256-only
/// and ignore this. Written as a RON enum: `alg: Es256` / `alg: Ed25519`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub enum SignerAlg {
    /// ECDSA P-256 (COSE ES256) — the default.
    #[default]
    Es256,
    /// Ed25519 (COSE EdDSA).
    Ed25519,
}

impl SignerAlg {
    fn to_token_alg(self) -> boatramp_core::cose::TokenAlg {
        match self {
            Self::Es256 => boatramp_core::cose::TokenAlg::Es256,
            Self::Ed25519 => boatramp_core::cose::TokenAlg::Ed25519,
        }
    }
}

/// External token signer selector (`serve.signer`). Maps to
/// [`boatramp_server::signer::SignerConfig`]; secrets (tokens/PINs) are resolved
/// from the named env vars at startup, never stored in config. Written as a RON
/// enum — `signer: Vault(...)`, `signer: AwsKms(...)`, `signer: Pkcs11(...)`, ….
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AuthSignerConfig {
    /// In-process key (`"<alg>:<hex>"`).
    Local {
        /// The private key spec, `"<alg>:<hex>"`.
        private_key: String,
    },
    /// HashiCorp Vault Transit key.
    Vault {
        /// Vault base address.
        address: String,
        /// The Transit key name.
        key: String,
        /// Env var holding the Vault token.
        token_env: String,
        /// The key algorithm.
        #[serde(default)]
        alg: SignerAlg,
    },
    /// AWS KMS asymmetric key (ES256).
    AwsKms {
        /// The KMS key id or ARN.
        key_id: String,
        /// Optional region override.
        #[serde(default)]
        region: Option<String>,
    },
    /// GCP Cloud KMS key version (ES256).
    GcpKms {
        /// The key-version resource name.
        key_version: String,
        /// Env var holding a GCP OAuth2 access token.
        access_token_env: String,
    },
    /// Azure Key Vault key (ES256).
    AzureKv {
        /// The vault base URL.
        vault_url: String,
        /// The key name.
        key: String,
        /// The key version.
        key_version: String,
        /// Env var holding an Azure AD access token.
        access_token_env: String,
    },
    /// PKCS#11 HSM key.
    Pkcs11 {
        /// Path to the PKCS#11 module.
        module: String,
        /// The token label.
        token_label: String,
        /// The key's `CKA_LABEL`.
        key_label: String,
        /// Env var holding the user PIN.
        pin_env: String,
        /// The key algorithm.
        #[serde(default)]
        alg: SignerAlg,
    },
}

impl AuthSignerConfig {
    /// Map the config-file form to the server's runtime [`SignerConfig`].
    pub fn to_signer_config(&self) -> boatramp_server::signer::SignerConfig {
        use boatramp_server::signer::SignerConfig;
        match self {
            Self::Local { private_key } => SignerConfig::Local {
                private_key: private_key.clone(),
            },
            Self::Vault {
                address,
                key,
                token_env,
                alg,
            } => SignerConfig::Vault {
                address: address.clone(),
                key: key.clone(),
                token_env: token_env.clone(),
                alg: alg.to_token_alg(),
            },
            Self::AwsKms { key_id, region } => SignerConfig::AwsKms {
                key_id: key_id.clone(),
                region: region.clone(),
            },
            Self::GcpKms {
                key_version,
                access_token_env,
            } => SignerConfig::GcpKms {
                key_version: key_version.clone(),
                access_token_env: access_token_env.clone(),
            },
            Self::AzureKv {
                vault_url,
                key,
                key_version,
                access_token_env,
            } => SignerConfig::AzureKv {
                vault_url: vault_url.clone(),
                key: key.clone(),
                key_version: key_version.clone(),
                access_token_env: access_token_env.clone(),
            },
            Self::Pkcs11 {
                module,
                token_label,
                key_label,
                pin_env,
                alg,
            } => SignerConfig::Pkcs11 {
                module: module.clone(),
                token_label: token_label.clone(),
                key_label: key_label.clone(),
                pin_env: pin_env.clone(),
                alg: alg.to_token_alg(),
            },
        }
    }
}

/// `serve` section — server defaults, overridden by flags/env.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServeConfig {
    /// Bind address (e.g. `0.0.0.0:8080`).
    pub addr: Option<SocketAddr>,
    /// Data directory for filesystem backends.
    pub data_dir: Option<PathBuf>,
    /// Base directory for **resumable** project export/import (T3). When set, `boatramp
    /// project export --resumable <name>` / `import --resumable <name>` write/read a
    /// member-object directory `<resumable_export_dir>/<name>` on the NODE (the node-local
    /// dir is what lets an interrupted export resume instead of restart). The operator
    /// passes only the relative `<name>`; the host confines it under this base and refuses
    /// any escape. `None` (the default) ⇒ the resumable surface is DISABLED, fail-closed.
    pub resumable_export_dir: Option<PathBuf>,
    /// Blob object-store backend (`fs`/`s3`/`gcs`/`azure`) — the config-level analog of the
    /// `--blobs` flag. Absent ⇒ the flag/env decides (`--blobs`/`BOATRAMP_BLOBS`, default `fs`).
    /// The flag/env still wins over this (uniform `serve` precedence). Read primarily by `boatramp
    /// blob migrate`, which builds a source/destination backend from a config file alone; `serve`
    /// also honours it as the config-level fallback under the flag.
    pub blobs: Option<crate::backends::BlobBackend>,
    /// S3 bucket (`--blobs s3`). Config-level fallback for `--s3-bucket`/`BOATRAMP_S3_BUCKET`.
    pub s3_bucket: Option<String>,
    /// S3 endpoint URL (e.g. a MinIO/R2/Tigris endpoint). Fallback for `--s3-endpoint`.
    pub s3_endpoint: Option<String>,
    /// S3 region. Fallback for `--s3-region`.
    pub s3_region: Option<String>,
    /// Use S3 path-style addressing (required by MinIO). Fallback for `--s3-path-style`.
    pub s3_path_style: bool,
    /// GCS bucket (`--blobs gcs`). Fallback for `--gcs-bucket`.
    pub gcs_bucket: Option<String>,
    /// GCS storage endpoint URL (e.g. a `fake-gcs-server` emulator). Fallback for `--gcs-endpoint`.
    pub gcs_endpoint: Option<String>,
    /// Skip GCS credential resolution (anonymous — the emulator). Fallback for `--gcs-anonymous`.
    pub gcs_anonymous: bool,
    /// Azure storage account name (`--blobs azure`). Fallback for `--azure-account`.
    pub azure_account: Option<String>,
    /// Azure container name (`--blobs azure`). Fallback for `--azure-container`.
    pub azure_container: Option<String>,
    /// Azure storage account access key (shared-key auth). Fallback for `--azure-access-key`.
    /// Prefer the env/flag over persisting a key in the config file.
    pub azure_access_key: Option<String>,
    /// Use the Azurite emulator (well-known dev credentials + local endpoint). Fallback for
    /// `--azure-emulator`.
    pub azure_emulator: bool,
    /// `[serve.blob_fallback]` — a **read-only SECONDARY blob backend** for a zero-downtime
    /// backend switch (blob-backend migration Part 2). When set, serving reads the PRIMARY (the
    /// `blobs`/`s3_*`/`gcs_*`/`azure_*` fields above) first and, on a definitive miss for a
    /// boatramp-owned key, falls through to this secondary — so a `--blobs` switch (fs→cloud,
    /// provider→provider, region→region) has no serving gap while `boatramp blob migrate` drains
    /// the secondary into the primary. **Writes are primary-only**; the secondary is never written
    /// or deleted. This is a **bounded transition aid**: drain, verify, then remove this block and
    /// restart (the node logs a prominent startup WARNING while it is active, and GC prune is
    /// refused). Absent ⇒ no fallback (unchanged). See [`BlobFallbackConfig`].
    pub blob_fallback: Option<BlobFallbackConfig>,
    /// `[serve.blob_backends.<project>]` — **per-project** blob object-store overrides
    /// (PLAN-per-project-blob-backend). A project named here serves its `wasi:blobstore` data from its
    /// OWN bucket/endpoint/credential instead of the one node-wide `[serve]` backend; a project with NO
    /// entry — and the reserved `default` project — resolves the global default (invariant 5: an
    /// all-global deployment is byte-for-byte unchanged). Operator-configured (node config + sealed
    /// `[secrets]`), mirroring `[handlers.bindings.sql.databases]`; a project OWNER declaring its own
    /// backend is out of scope for this cut. Each entry's sealed S3 credential is a secret **reference**
    /// (`boatramp:`/`env:`), never inlined (invariant 3). Empty ⇒ no overrides (the common case). See
    /// [`BlobBackendConfig`]. Env parity: `BOATRAMP_SERVE_BLOB_BACKEND_<PROJECT>_*`.
    pub blob_backends: BTreeMap<String, BlobBackendConfig>,
    /// Token root **private** key (hex) — issuing node: verifies *and* mints
    /// tokens / OIDC exchanges.
    pub auth_root_private_key: Option<String>,
    /// Token root **public** key (hex) — verify-only node.
    pub auth_root_public_key: Option<String>,
    /// Single-use bootstrap secret enabling `POST /api/tokens/bootstrap` (mint the
    /// first token without an admin bearer). Prefer the `BOATRAMP_BOOTSTRAP_SECRET`
    /// env / `--bootstrap-secret` flag so it isn't persisted in the config file.
    pub bootstrap_secret: Option<String>,
    /// External token signer (`[serve.signer]`): mint with a
    /// KMS/HSM/Vault-held root key instead of an in-process `auth_root_private_key`.
    /// Absent ⇒ the in-process key. When set, its public half is the trust anchor.
    pub signer: Option<AuthSignerConfig>,
    /// Reject blob uploads larger than this many bytes.
    pub max_upload_bytes: Option<u64>,
    /// Abort an upload that stalls for longer than this many seconds.
    pub upload_idle_timeout_secs: Option<u64>,
    /// Cap on simultaneous blob uploads.
    pub max_concurrent_uploads: Option<usize>,
    /// In a TLS mode, bind this plain-HTTP address on a second listener that
    /// redirects to HTTPS (dual-listener). Only read in `tls` builds.
    #[cfg_attr(not(feature = "tls"), allow(dead_code))]
    pub http_redirect_addr: Option<SocketAddr>,
    /// Site to serve for a `Host` matching no domain, instead of 404.
    pub default_site: Option<String>,
    /// The fleet's canonical public origin (e.g. `https://cp.example.com`) that a
    /// per-request proof-of-possession must bind to (`aud`). Required for
    /// holder-bound (`cnf`/PoP) tokens to be usable — a proof's origin is compared
    /// against this value, never against a `Host`/`X-Forwarded-*` header.
    pub pop_origin: Option<String>,
    /// Require a valid control-plane token to view deployment previews.
    pub protect_previews: bool,
    /// Rate-limit cluster-wide via the control-plane KV instead of per node.
    pub cluster_rate_limit: bool,
    /// Keep the config cache coherent across processes sharing one KV via the
    /// changelog.
    pub shared_cache_coherence: bool,
    /// Cloud blob-change notification provisioning tier (FA-5b2): how boatramp
    /// obtains the native event pipeline (S3→SQS) that backs a `blob` trigger —
    /// `dry-run` (print the recipe), `provision` (create + retract), `verify-only`
    /// (operator pre-wired), or `refuse` (fail closed). Absent ⇒ no provisioning:
    /// `blob` triggers then work only on a self-watching backend (fs). Only wired
    /// for the S3 backend (`--features s3`).
    pub blob_notify_tier: Option<boatramp_core::blob_notify::ProvisionTier>,
    /// The AWS account id used to scope the provisioned SQS queue's `SendMessage`
    /// policy (`aws:SourceAccount`). Required when `blob_notify_tier` provisions.
    pub blob_notify_account_id: Option<String>,
    /// `[serve.console]` — the embedded web management console. Absent (or
    /// `enabled: false`) ⇒ not served. This is the **baseline** for the dynamic
    /// `console.*` daemon-config override, which can enable/move it at runtime
    /// (`boatramp config set console.enabled true`) without a restart.
    pub console: Option<ConsoleConfig>,
    /// Bind address for the **dedicated local S3-ingress listener** (PLAN-blob-s3-ingress,
    /// Architect HIGH-4). Absent ⇒ the local S3 face is NOT served (it is opt-in — a deployment that
    /// only mints cloud-brokered credentials never needs it). This is a SEPARATE listener from the
    /// control-plane `addr`: it has its own SigV4 auth surface and never reaches `serve_by_host` or
    /// the `/api` router.
    pub s3_ingress_addr: Option<SocketAddr>,
    /// Path to the **dedicated S3-ingress root secret** file (raw 32 bytes) — the independently-
    /// rotatable HKDF root for `secret_access_key` derivation (hard domain separation from the
    /// `[secrets]` KEK + the COSE signing key). Like `[secrets].kek_file`, this holds a *path*, never
    /// key material in the config text, and (in a cluster) the **same file must be present on every
    /// node** so every node derives the same `secret_access_key`. Absent on a single node ⇒ an
    /// ephemeral per-process root is auto-generated; absent on a **multi-node** deployment ⇒ the S3
    /// face is refused to enable (fail-closed — credentials would otherwise be un-verifiable across
    /// nodes). Prefer the `BOATRAMP_S3_INGRESS_SECRET_FILE` env / flag so the path stays out of the
    /// committed config where that matters operationally.
    pub s3_ingress_secret_file: Option<PathBuf>,
    /// The publicly-reachable base URL an external client targets for the local S3 face — what a
    /// **minted** upload credential (`boatramp:handlers/blob-upload` guest mint / `boatramp blob
    /// mint-upload` operator) embeds as its endpoint (a presigned-put URL prefix, or the SDK endpoint
    /// for temp-credentials). Absent ⇒ derived from `s3_ingress_addr` as `http://<addr>` (fine for a
    /// same-host dev/test loop; set it explicitly to the TLS-terminated public URL in production).
    /// Only consulted when guest/operator upload minting is wired (`blob-upload` feature + the face
    /// enabled).
    pub s3_ingress_public_url: Option<String>,
    /// Operator ceiling (seconds) on a minted upload credential's TTL — a guest/operator can only
    /// request a SHORTER lifetime (the mint clamps to this). Absent ⇒ a conservative default
    /// ([`DEFAULT_S3_INGRESS_MINT_MAX_TTL_SECS`]). A `0` disables minting entirely (the binding is
    /// never attached).
    pub s3_ingress_mint_max_ttl_secs: Option<u64>,
    /// Operator ceiling (bytes) on a minted credential's `max_bytes` constraint — a guest can only
    /// request a SMALLER cap (clamped to this). Absent ⇒ no host-side max-bytes clamp (the per-container
    /// ceiling at the face still applies).
    pub s3_ingress_mint_max_bytes: Option<u64>,
    /// **Cloud brokering** (M4): when the node's blob backend is a cloud object store (S3/GCS/Azure)
    /// and this is set, minting brokers a NATIVE scoped credential (STS session policy / signed URL +
    /// CAB / user-delegation SAS) so the client uploads DIRECTLY to the real store (bytes never transit
    /// the node) — INSTEAD of the local S3 face. Absent ⇒ the local face is used (an fs/in-memory
    /// backend, or a cloud backend that re-transits through the local face). See [`S3IngressCloud`].
    pub s3_ingress_cloud: Option<S3IngressCloud>,
    /// **Node-level base S3 credential source** (`[serve.s3_credential]`, task #505). When set, BOTH the
    /// S3 blob **object backend** (`--blobs s3`) and the AWS blob-upload **cloud minter**
    /// (`[serve.s3_ingress_cloud]`) source their base AWS credential from boatramp's `[secrets]` sealed
    /// store instead of the ambient `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` env chain. ONE shared
    /// source (both consumers read the SAME bucket key). Absent ⇒ the ambient AWS env chain (current
    /// behavior, non-breaking). Requires a `[secrets]` envelope when the `secret_access_key` is a sealed
    /// `boatramp:`/`env:` ref — a configured ref with no envelope is a **startup error** (fail-closed, no
    /// silent env fallback). See [`S3CredentialConfig`].
    pub s3_credential: Option<S3CredentialConfig>,
    /// `[serve.kv]` — control-plane SlateDB KV durability cadence + shutdown budget (v0.9.0
    /// KV-recovery). Absent ⇒ the defaults (periodic checkpoint ON at
    /// [`DEFAULT_KV_CHECKPOINT_INTERVAL_SECS`], close budget [`DEFAULT_KV_CLOSE_DEADLINE_SECS`]).
    /// See [`KvConfig`].
    pub kv: Option<KvConfig>,
    /// `[serve.listeners.<name>]` — host-owned **inbound-TCP listeners** (PLAN-handler-tcp-inbound).
    /// Each declares a bind address + a target guest `tcp-connection-handler` component (pinned to a
    /// project + site + Dimension-0 tenancy): the node binds + listens + accepts and re-enters the
    /// guest once per ALREADY-ACCEPTED connection, handing it only the connection's `wasi:io` streams
    /// (the guest NEVER receives `wasi:sockets`). GATED on the posture `allow_guest_tcp_listener` (off
    /// under multi-tenant) AND the declaration here — both must hold. Empty ⇒ no listeners (the common
    /// case; serving is byte-for-byte unchanged). Env parity: `BOATRAMP_SERVE_LISTENER_<NAME>_*`. See
    /// [`ListenerConfig`].
    #[serde(default)]
    pub listeners: BTreeMap<String, ListenerConfig>,
    /// `[serve.on_demand_tls]` — on-demand per-SNI ACME issuance at scale (cap-req 03). Absent or
    /// `enabled = false` ⇒ OFF (the static `--tls acme-dns` resolver is byte-for-byte unchanged). When
    /// on, the edge issues + caches a cert on the first TLS handshake for an unknown-but-#02-**verified**
    /// custom domain, gated so an arbitrary/unverified SNI is refused (fail-closed). File-configured.
    /// See [`OnDemandTlsConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_demand_tls: Option<OnDemandTlsConfig>,
    /// `[serve.alerts]` — the node/system-health ALERTING subsystem (node-health-alerting
    /// Stage 2). Off unless `enabled`. Declares the evaluation cadence, the disk /
    /// managed-SQL / orphan-replica signal thresholds + graces, the webhook/email delivery
    /// channels (secrets SEALED, never plaintext here), and the opt-in orphan reaper. The
    /// leader-gated evaluation loop is spawned only when `enabled`. Env parity:
    /// `BOATRAMP_ALERTS_*` (the `serve` segment dropped, like `s3_ingress_cloud`). See
    /// [`boatramp_core::health_alert::AlertsConfig`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alerts: Option<boatramp_core::health_alert::AlertsConfig>,
}

/// `[serve.on_demand_tls]` — on-demand per-SNI TLS issuance (cap-req 03). Off unless `enabled`. When
/// on, an unknown-but-#02-verified SNI triggers issuance at handshake time (the client retries once
/// the cert is warm); an unauthorized SNI is refused, so a flood of unknown names can't become an ACME
/// storm. The ACME account + issued certs persist in the control-plane cert store and replicate across
/// the cluster (the leader issues; followers serve the replicated cert).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OnDemandTlsConfig {
    /// Master toggle. `false` (default) ⇒ the whole feature is off.
    pub enabled: bool,
    /// How to prove control of a name to the CA. `tls-alpn-01` (default) validates on the 443 edge (no
    /// extra port); `dns-01` uses the node's configured ACME DNS provider (an operator-controlled zone).
    pub challenge: OnDemandChallenge,
    /// ACME directory URL. Absent ⇒ the ACME client default (Let's Encrypt production).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub directory_url: Option<String>,
    /// ACME account contact email (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_email: Option<String>,
    /// Max concurrent in-flight issuances (global). Absent ⇒ 4.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_inflight: Option<usize>,
    /// How long a refused/failed SNI is negatively cached (seconds). Absent ⇒ 300.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub negative_ttl_secs: Option<u64>,
    /// Max CA orders per rolling hour (the account rate-limit floor). Absent ⇒ 50; `0` ⇒ unlimited.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_hour: Option<u32>,
    /// DNS-01 only: **maximum** seconds to wait for the `_acme-challenge` TXT to become visible before
    /// telling the CA to validate. This is a real readiness poll, not a blind sleep — issuance proceeds
    /// as soon as the record resolves, falling back to proceeding-anyway (the CA retries) only if this
    /// elapses. Absent ⇒ 15. Ignored for the `tls-alpn-01` challenge (nothing external to wait for).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub propagation_wait_secs: Option<u64>,
    /// DNS-01 only: how often (seconds) to re-check DNS while waiting for the TXT to propagate. Absent
    /// ⇒ 2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub propagation_poll_interval_secs: Option<u64>,
}

/// How [`OnDemandTlsConfig`] proves control of a name to the CA.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OnDemandChallenge {
    /// TLS-ALPN-01 on the 443 edge (default) — no extra port.
    #[default]
    TlsAlpn01,
    /// DNS-01 via the node's configured ACME DNS provider (an operator-controlled zone / wildcard).
    Dns01,
}

/// `[serve.listeners.<name>]` — a **host-owned inbound-TCP listener** (PLAN-handler-tcp-inbound). The
/// node binds + listens + accepts on `bind` and dispatches each accepted connection to the guest
/// `component`'s `tcp-connection-handler` export, with tenancy OPERATOR-PINNED here (a raw socket
/// carries no Host/path/principal, so there is nothing per-connection to resolve). The guest is handed
/// only the connection's `wasi:io` byte streams — it holds NO raw `wasi:sockets` authority (bind stays
/// host-side). Modeled on [`boatramp_core::function::FunctionConfig`] / the session route config.
///
/// Host-side per-listener TLS/STARTTLS termination (cap-req 06) and a host-mediated `tcp-egress`
/// `egress_allowlist` (cap-req 19 — the host dials + terminates TLS, the guest still holds no raw
/// socket) are both supported. See [`validate_listeners`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ListenerConfig {
    /// The address the node binds + listens + accepts on (e.g. `0.0.0.0:9000`). **Required** (a blank
    /// `bind` is refused at config load).
    pub bind: Option<SocketAddr>,
    /// Path to the guest `.wasm` within the pinned site's deployment (exports `tcp-connection-handler`).
    /// **Required**.
    pub component: String,
    /// The project this listener's component is deployed under (host-resolved, never guest input). The
    /// active deployment of `project`/`site` is what the accept loop serves. **Required**.
    pub project: String,
    /// The site within `project` whose active deployment holds `component`. **Required**.
    pub site: String,
    /// Requested capabilities (interface names; see `KNOWN_IMPORTS`). A listener component declares
    /// whatever `sql`/`orm`/`kv`/… it uses per connection — NOT `wasi:sockets` (the host owns the
    /// socket; a `tcp-connection-host` guest imports only `wasi:io`, handed the accepted streams).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<String>,
    /// Static environment variables injected into the component (never secrets).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Per-listener outbound-TCP allowlist (cap-req 19) for the listener guest's HOST-MEDIATED
    /// `tcp-egress` dials: the `host:port` / `ip:port` / `CIDR:port` targets the host may dial on the
    /// guest's behalf (the host dials + terminates TLS — the guest NEVER holds raw `wasi:sockets`). It
    /// takes effect only when the node posture `allow_guest_tcp_egress` is on AND the component imports
    /// `tcp-egress`; the dial is connect-only + SSRF-floored (the SAME gate as a handler/function
    /// `egress_allowlist`). Empty ⇒ no egress. Enables e.g. an imap-proxy listener dialing the IMAPS
    /// upstream.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub egress_allowlist: Vec<String>,
    /// Operator-pinned Dimension-0 tenancy for this listener's `sql`/`orm` (resolved once from this
    /// config, carried on every connection — nothing per-connection to resolve from). Absent ⇒ plain
    /// (project = database).
    #[serde(
        default,
        deserialize_with = "boatramp_core::tenancy::de_opt_tenancy",
        skip_serializing_if = "Option::is_none"
    )]
    pub tenancy: Option<boatramp_core::tenancy::Tenancy>,
    /// DEFERRED (Phase 1): per-listener host-TLS. Phase 1 ships plaintext-only; a declared `tls` block
    /// is REFUSED at config load (fail-closed) so an operator is never misled into thinking a listener
    /// terminates TLS when it does not. Terminate TLS in front of boatramp, or wait for the fast-follow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<ListenerTlsConfig>,
    /// Cap on simultaneously-live connections for THIS listener (a per-listener DoS bound on top of the
    /// engine's conn-lane ceiling). `0` is refused; absent ⇒ [`DEFAULT_LISTENER_MAX_CONNS`].
    pub max_conns: Option<usize>,
    /// Tear a connection down after this many milliseconds with NO bytes in either direction (idle
    /// timeout — the conn lane replaces the per-invocation epoch deadline with this). `0` is refused;
    /// absent ⇒ [`DEFAULT_LISTENER_IDLE_TIMEOUT_MS`].
    pub idle_timeout_ms: Option<u64>,
    /// Absolute cap (milliseconds) on a single connection's lifetime regardless of activity. `0` is
    /// refused; absent ⇒ [`DEFAULT_LISTENER_MAX_CONN_DURATION_MS`].
    pub max_conn_duration_ms: Option<u64>,
    /// Per-source-IP connection-rate limit (cap-req 18): the sustained rate (connections/sec) one
    /// peer IP may open on THIS listener, atop a `conn_burst_per_ip` immediate allowance. A FaaS
    /// listener guest can't see the peer IP, so the HOST enforces this at the accept loop to keep
    /// native-daemon brute-force protection (a client otherwise resets its auth-backoff by
    /// reconnecting). Absent ⇒ ON at [`DEFAULT_LISTENER_CONN_RATE_PER_IP`] (protection is NOT
    /// opt-in); `0` ⇒ DISABLED (no per-IP limit; the `max_conns` live-cap still applies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_conns_per_ip_per_sec: Option<f64>,
    /// Immediate per-source-IP connection allowance (the token-bucket burst depth) before the
    /// sustained `max_conns_per_ip_per_sec` throttles. Absent ⇒ [`DEFAULT_LISTENER_CONN_BURST_PER_IP`].
    /// Ignored when the rate is `0` (limit disabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn_burst_per_ip: Option<u32>,
    /// IPv6 **bucket prefix** (bits) for the per-source-IP connection-rate limit (senior-architect
    /// review). An IPv6 peer is keyed for rate-limiting by this prefix, not its full `/128`: a single
    /// site is routinely handed a whole `/64`, so keying on the full address would let one owner rotate
    /// through addresses to get a fresh bucket per connection (and spray the tracked map). Masking to
    /// the prefix collapses a site to one bucket. IPv4 is always keyed in full (`/32`). Valid `1..=128`;
    /// absent ⇒ [`DEFAULT_LISTENER_CONN_RATE_IPV6_PREFIX`] (`/64`). Ignored when the rate limit is off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conn_rate_ipv6_prefix: Option<u8>,
    /// Trust a **PROXY-protocol** (v1/v2) header on each accepted connection (cap-req 18 completion):
    /// when this listener sits behind a trusted L4 proxy/load-balancer, the kernel peer is the
    /// proxy's, so the host reads the prepended header to recover the REAL client address and uses it
    /// for the per-source-IP rate limit AND the `peer` handed to the guest. **Opt-in + fail-closed**:
    /// `false` (default) never parses a header (so a direct client can't forge one to spoof its IP);
    /// `true` asserts the listener is reachable ONLY via the trusted proxy, and a connection that does
    /// not present a well-formed header is dropped. Set it ONLY when a proxy actually fronts the port.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub proxy_protocol: bool,
    /// Explicitly trust a PROXY-protocol header from ANY source (senior-architect review — OWNER
    /// DECISION: require trusted CIDRs by default). `proxy_protocol = true` now REQUIRES a non-empty
    /// `proxy_protocol_trusted_cidrs` UNLESS this is set `true` (the firewall-only mode, where the
    /// operator asserts the port is unreachable except via the proxy). Default `false` ⇒ a
    /// `proxy_protocol` listener with no trusted CIDRs is REFUSED at config load (fail-closed,
    /// boot-loud), so a header is never silently trusted from any source by omission. Set this ONLY
    /// when you genuinely cannot enumerate the proxy's source CIDRs but the port is firewalled to it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub proxy_protocol_trust_any: bool,
    /// Trusted-proxy source CIDRs for `proxy_protocol` (cap-req 18 / security-review MEDIUM-1): the
    /// defense-in-depth backstop to the network-isolation assumption. When NON-EMPTY, a PROXY-protocol
    /// header is trusted ONLY when the kernel peer (the direct TCP source) is inside one of these
    /// `ip/prefix` CIDRs (e.g. `10.0.0.0/8`, `2001:db8::/32`); a connection from anywhere else is
    /// dropped — so a firewall gap can't become source-IP spoofing. EMPTY (default) trusts a header
    /// from any source (the firewall-only mode), which is sound only if the port is truly unreachable
    /// except via the proxy; set this whenever you can. Ignored unless `proxy_protocol` is `true`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proxy_protocol_trusted_cidrs: Vec<String>,
    /// How the accepted connection is driven (cap-req 08). [`ListenerMode::Connection`] (default) is the
    /// long-lived model: the guest's `tcp-connection-handler` holds the connection — and ONE wasm
    /// instance — for the connection's whole life. [`ListenerMode::Session`] drives the connection
    /// through the re-entrant **session** model instead: the host owns the socket, re-enters the guest's
    /// `session-handler` per inbound batch carrying a host-held checkpoint, and holds NO instance between
    /// batches — so thousands of mostly-idle connections (IMAP IDLE, long-poll) cost ~a socket each, not
    /// an instance each, and a protocol-idle-but-alive connection is never torn down for inactivity
    /// (only a dead peer or `max_conn_duration` reaps it). The component must export `session-handler`,
    /// not `tcp-connection-handler`. Additive + back-compat: absent ⇒ `Connection` (unchanged).
    #[serde(default)]
    pub mode: ListenerMode,
}

/// How a `[serve.listeners.<name>]` drives each accepted connection (cap-req 08). See
/// [`ListenerConfig::mode`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ListenerMode {
    /// Long-lived `tcp-connection-handler` — one wasm instance pinned per connection for its whole life
    /// (the original inbound-TCP model). The default.
    #[default]
    Connection,
    /// Re-entrant `session-handler` — the host owns the socket and drives it through the session model,
    /// holding NO instance between inbound batches (idle ⇒ socket + checkpoint only). A quiet, PARKED
    /// connection (blocked on the socket read between batches) is NOT evicted for inactivity — only the
    /// absolute `max_conn_duration_ms` cap and dead-peer detection (EOF) end it, so a protocol-idle but
    /// alive peer (IMAP IDLE) survives. In this mode `idle_timeout_ms` is reinterpreted as the
    /// per-re-entry **processing deadline** — the max wall-clock ONE re-entry may spend (instantiate +
    /// handle + write its response) — bounding a guest stalled on a slow/zero-window peer so it cannot
    /// pin a session-pool slot + instance; a re-entry that exceeds it is cancelled and the connection
    /// closed. Re-entries run on a DEDICATED concurrency pool, never the shared async lane.
    Session,
}

/// Per-listener host-side TLS material (cap-req 06). The host terminates TLS and hands the guest a
/// decrypted plaintext stream (the guest does no crypto). With `starttls` absent this is **implicit
/// TLS** (handshake at accept — 465/993); with `starttls` present it is **STARTTLS** (plaintext
/// dialog, in-band upgrade on the declared trigger — 25/587/143). Either way requires both
/// `cert_file` and `key_file`. File-only (never set from the env overlay).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerTlsConfig {
    /// PEM certificate chain path.
    pub cert_file: Option<PathBuf>,
    /// PEM private-key path.
    pub key_file: Option<PathBuf>,
    /// Absent ⇒ implicit TLS (handshake at accept). Present ⇒ STARTTLS (plaintext until the declared
    /// trigger, then an in-band upgrade). Still requires `cert_file` + `key_file`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starttls: Option<ListenerStarttlsConfig>,
    /// Opt this listener into **on-demand per-SNI issuance** (cap-req 03 #4): a client that negotiates
    /// TLS with a verified custom-domain SNI terminating here gets a cert issued the same way the public
    /// edge does, sharing the one `[serve.on_demand_tls]` engine (one issuance budget, one cluster
    /// certreq single-flight). Requires `[serve.on_demand_tls]` enabled at the node. The listener's own
    /// `cert_file` still serves `server_names` (and an SNI-less handshake). Default `false` ⇒ the static
    /// cert alone (unchanged). This is transport-level only — it carries no notion of what protocol runs
    /// over the listener.
    ///
    /// **Project-scoped** (Security review Finding B): a listener is bound to exactly one project (its
    /// `project`), and that project may front many domains (its tenants/sites). On-demand serving here
    /// is restricted to SNIs whose owning project is *this* project — the listener never serves (nor
    /// routes to its guest) a cert for another project's domain, even though all certs share the one
    /// engine + cache. Point an `on_demand` listener only at a guest that is meant to handle that whole
    /// project's domains.
    #[serde(default)]
    pub on_demand: bool,
    /// SNI names the listener's own static `cert_file` serves directly (an SNI match here wins before
    /// on-demand). Absent/empty ⇒ the static cert serves only SNI-less handshakes (via the no-SNI
    /// fallback); every presented SNI then goes to on-demand. Only meaningful with `on_demand = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_names: Option<Vec<String>>,
}

/// Declarative STARTTLS grammar (cap-req 06, Stage B) — protocol-agnostic **data**. The host runs a
/// generic trigger→response→wrap engine driven entirely by these fields; no SMTP/IMAP/POP3 shapes are
/// hardcoded in the server. Examples:
/// SMTP — `(trigger: "STARTTLS", response: "220 2.0.0 Ready to start TLS")`;
/// POP3 — `(trigger: "STLS", response: "+OK begin TLS negotiation")`;
/// IMAP — `(trigger: "STARTTLS", response: "{tag} OK begin TLS negotiation", tag_capture: true)`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerStarttlsConfig {
    /// The command the host watches for in the client→server direction, matched at a line boundary,
    /// ASCII-case-insensitively. With `tag_capture` this is the token AFTER the leading tag.
    pub trigger: String,
    /// The single line the host writes to the client right before the handshake. `{tag}` is
    /// substituted with the captured tag (only valid when `tag_capture`); the host appends CRLF.
    pub response: String,
    /// IMAP-shaped: capture the leading whitespace-delimited token of the trigger line and echo it
    /// (verbatim) into `{tag}`.
    #[serde(default)]
    pub tag_capture: bool,
}

/// Default per-listener live-connection cap when `[serve.listeners.<name>] max_conns` is unset
/// (PLAN-handler-tcp-inbound). 256 — a generous but bounded ceiling on top of the engine conn lane.
pub const DEFAULT_LISTENER_MAX_CONNS: usize = 256;

/// Default per-listener idle timeout (ms) when `idle_timeout_ms` is unset — 60s. A connection with no
/// bytes in either direction for this long is torn down (so a connection that opens and sends nothing
/// can't hold a store + instance + conn-lane permit forever).
pub const DEFAULT_LISTENER_IDLE_TIMEOUT_MS: u64 = 60_000;

/// Default per-listener absolute max-connection-duration (ms) when `max_conn_duration_ms` is unset —
/// 1h. Bounds a single connection's lifetime regardless of activity (CPU is wall-clock-bounded here,
/// since the conn lane disables the per-invocation CPU-fuel budget).
pub const DEFAULT_LISTENER_MAX_CONN_DURATION_MS: u64 = 3_600_000;

/// Default per-source-IP sustained connection rate (connections/sec) for a listener (cap-req 18),
/// when `max_conns_per_ip_per_sec` is unset — ON by default so a FaaS listener's brute-force
/// protection is not opt-in. Generous enough never to throttle a legitimate interactive or
/// behind-NAT client, low enough to blunt a credential-stuffing reconnect flood; set
/// `max_conns_per_ip_per_sec = 0` on a listener to disable.
pub const DEFAULT_LISTENER_CONN_RATE_PER_IP: f64 = 30.0;

/// Default per-source-IP connection burst (token-bucket depth) for a listener (cap-req 18) — the
/// immediate allowance before [`DEFAULT_LISTENER_CONN_RATE_PER_IP`] throttles.
pub const DEFAULT_LISTENER_CONN_BURST_PER_IP: u32 = 60;

/// Hard cap on simultaneously-tracked peer IPs in a listener's per-IP rate limiter (cap-req 18) —
/// bounds the limiter's memory against an IP-spray DoS (the least-recently-used — coldest, idle —
/// bucket is LRU-evicted to stay within it; dropping it is lossless, a re-created bucket starts full).
pub const DEFAULT_LISTENER_CONN_RATE_MAX_TRACKED: usize = 100_000;

/// Default IPv6 bucket prefix (bits) for a listener's per-source-IP connection-rate limit
/// (senior-architect review) — `/64`, so a whole end site (routinely a `/64`) is one rate-limit
/// bucket and can't rotate addresses to dodge the limit. IPv4 is always keyed in full (`/32`).
/// Operators override per listener via `conn_rate_ipv6_prefix` (valid `1..=128`).
pub const DEFAULT_LISTENER_CONN_RATE_IPV6_PREFIX: u8 = 64;

/// `[serve.s3_credential]` — a **node-level base S3 credential source** (#505) sourcing the base AWS
/// credential from boatramp's `[secrets]` sealed store rather than the ambient env chain. Consumed by
/// BOTH the S3 blob object backend and the AWS blob-upload cloud minter (one shared source, since it is
/// the same bucket key). Additive/non-breaking: absent ⇒ the ambient AWS env chain (unchanged).
///
/// The `access_key_id` is a public identifier (plain config). The `secret_access_key` is a **secret
/// reference** in the same scheme the guest `secrets` map uses: `boatramp:<name>` (the project-scoped
/// sealed store, resolved under the reserved default project — multi-tenant-safe, never the host env),
/// `env:<VAR>` / a bare `<VAR>` (the operator's own environment — honored only when the posture's
/// `allow_env_secret_refs` is set), unsealed at serve startup via the `[secrets]` [`KeyEnvelope`]. The
/// resolved plaintext is held **in memory only** (never env/argv/git/logs); see the redacted
/// `SealedS3Credential` the resolver produces.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3CredentialConfig {
    /// The AWS **access key id** — a public identifier, not a secret, so it is plain config (mirrors
    /// how an `access_key_id` is a public value in the S3-ingress credential model). Empty is refused
    /// at resolution.
    pub access_key_id: String,
    /// The **secret access key**, expressed as a secret **reference** (never the raw secret in the
    /// config text): `boatramp:<name>` (the project-scoped sealed store), `env:<VAR>` or a bare `<VAR>`
    /// (the operator env, posture-gated by `allow_env_secret_refs`). Unsealed at startup via the
    /// `[secrets]` envelope; the resolved value is redacted from `Debug`/logs. A `boatramp:`/`env:`
    /// ref configured with NO `[secrets]` envelope is a fail-closed startup error.
    pub secret_access_key: String,
}

/// `[serve.blob_backends.<project>]` — a **per-project** blob object-store backend
/// (PLAN-per-project-blob-backend). Same backend-descriptor shape as the `[serve]` primary's S3 fields
/// plus its OWN sealed base S3 credential (`#505` path), so project ACME can point its `wasi:blobstore`
/// at its own bucket/endpoint/account. Key-prefix confinement (`container_access`) still runs on top —
/// a separate bucket adds PHYSICAL isolation, it does not replace the confinement (invariant 2).
///
/// Operator-configured; the backend is bound to the serve's **host-resolved** project at serve wiring,
/// never to guest input (invariant 1). The sealed credential is resolved under THIS project's sealed
/// `[secrets]` store at wiring; a declared backend whose credential/bucket cannot be built REFUSES the
/// serve (fail-closed — never a silent fallback to the global or another project's backend, invariant
/// 4). First cut is S3 (and `fs`, which is degenerate — it shares the node blob dir, so only a cloud
/// bucket gives physical isolation); a per-project `gcs`/`azure` needs its own descriptor fields and is
/// a follow-up (declaring one fails closed at build — the required bucket/account is absent).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobBackendConfig {
    /// The backend kind (`fs`/`s3`/`gcs`/`azure`). **Required** (mirrors the SQL binding's required
    /// `kind`): a per-project backend with no explicit kind is a startup error, so a forgotten
    /// `blobs = "s3"` can't silently build an `fs` backend at the shared node dir that would NOT
    /// isolate the project's blobs. Resolved at serve wiring (fail-closed when absent).
    pub blobs: Option<crate::backends::BlobBackend>,
    /// S3 bucket (`blobs = s3`) — the project's OWN bucket.
    pub s3_bucket: Option<String>,
    /// S3 endpoint URL (a MinIO/R2/Tigris endpoint) for this project's backend.
    pub s3_endpoint: Option<String>,
    /// S3 region for this project's backend.
    pub s3_region: Option<String>,
    /// Use S3 path-style addressing (MinIO) for this project's backend.
    #[serde(default)]
    pub s3_path_style: bool,
    /// This project's OWN sealed base S3 credential (`#505`) — resolved through the SAME
    /// `resolve_s3_credential` path as the node primary, but keyed under THIS project's sealed store
    /// (`boatramp:<name>` resolves against `project`'s secrets, not the node default). The
    /// `access_key_id` is a public identifier; `secret_access_key` is a `boatramp:`/`env:` **reference**
    /// (never the raw secret in config, invariant 3). Absent ⇒ the ambient AWS env chain.
    pub s3_credential: Option<S3CredentialConfig>,
}

/// `[serve.blob_fallback]` — a **read-only SECONDARY blob backend** for a zero-downtime backend switch
/// (blob-backend migration Part 2). Same backend-descriptor shape as the PRIMARY (`[serve]`'s
/// `blobs`/`s3_*`/`gcs_*`/`azure_*` fields) so a source/dest is fully described by config, plus its OWN
/// optional `s3_credential` (the secondary can source its base S3 credential from the sealed `[secrets]`
/// store via its own `boatramp:`/`env:` ref, #505). Constructed exactly like the primary but with NO
/// watcher provisioning (a read-only drain source never watches). Serving wraps
/// `FallbackStorage::new(primary, secondary, …)` so a primary miss on a boatramp-owned key falls through
/// to this secondary; writes/deletes are primary-only.
///
/// The secondary is **never** handed to the blob-upload/STS minter — external ingress mints against the
/// PRIMARY only (the new backend the client should upload to), so this credential never reaches the
/// minter path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobFallbackConfig {
    /// The secondary blob backend (`fs`/`s3`/`gcs`/`azure`) — the OLD backend to fall back to on a
    /// primary miss. Absent ⇒ `fs` (the default, matching the primary's `blobs` default).
    pub blobs: Option<crate::backends::BlobBackend>,
    /// S3 bucket (secondary `blobs = s3`).
    pub s3_bucket: Option<String>,
    /// S3 endpoint URL (a MinIO/R2/Tigris endpoint) for the secondary.
    pub s3_endpoint: Option<String>,
    /// S3 region for the secondary.
    pub s3_region: Option<String>,
    /// Use S3 path-style addressing (MinIO) for the secondary.
    #[serde(default)]
    pub s3_path_style: bool,
    /// The secondary's OWN node-level sealed base S3 credential source (#505) — resolved through the
    /// SAME `resolve_s3_credential` path as the primary (same fail-closed posture, no second parser).
    /// Absent ⇒ the ambient AWS env chain (unchanged).
    pub s3_credential: Option<S3CredentialConfig>,
    /// GCS bucket (secondary `blobs = gcs`).
    pub gcs_bucket: Option<String>,
    /// GCS storage endpoint URL (a `fake-gcs-server` emulator) for the secondary.
    pub gcs_endpoint: Option<String>,
    /// Skip GCS credential resolution (anonymous — the emulator) for the secondary.
    #[serde(default)]
    pub gcs_anonymous: bool,
    /// Azure storage account name (secondary `blobs = azure`).
    pub azure_account: Option<String>,
    /// Azure container name for the secondary.
    pub azure_container: Option<String>,
    /// Azure storage account access key (shared-key auth) for the secondary.
    pub azure_access_key: Option<String>,
    /// Use the Azurite emulator for the secondary.
    #[serde(default)]
    pub azure_emulator: bool,
    /// Bound (seconds) on each secondary read so a wedged secondary degrades a primary miss to
    /// `NotFound` instead of hanging the serve path. Absent ⇒ [`DEFAULT_BLOB_FALLBACK_TIMEOUT_SECS`].
    pub secondary_timeout_secs: Option<u64>,
}

/// Default bound (seconds) on a `[serve.blob_fallback]` secondary read when
/// `secondary_timeout_secs` is unset: 5s — long enough for a cloud round-trip, short enough that a
/// wedged secondary degrades a primary miss to `NotFound` promptly rather than hanging serving.
pub const DEFAULT_BLOB_FALLBACK_TIMEOUT_SECS: u64 = 5;

/// Default control-plane KV **periodic checkpoint** cadence (seconds) when `[serve.kv]
/// checkpoint_interval` is unset (v0.9.0 KV-recovery, C1). The cadence advances the durable frontier
/// (WAL→L0 MemTable freeze) so the self-heal-on-open trailing-tail loss window is bounded to at most
/// this interval for anything NOT already frontier-synced by a crown-jewel write. 10s balances a tiny
/// loss window against manifest-PUT churn; an idle store's checkpoint is a dirty-gated no-op regardless.
pub const DEFAULT_KV_CHECKPOINT_INTERVAL_SECS: u64 = 10;

/// Default **graceful-close budget** (seconds) when `[serve.kv] close_deadline` is unset (v0.9.0
/// KV-recovery, C12). The shutdown drain+close is abandoned only after this budget — GENEROUS (not the
/// old hardcoded 3s, which self-exited BEFORE fly's SIGKILL grace and left the frontier un-advanced =
/// the exact torn tail we prevent). With continuous checkpointing (C1/C2) the close is cheap, so this
/// budget rarely bites; operators should still raise fly `kill_timeout` to ≥ their measured drain+close.
pub const DEFAULT_KV_CLOSE_DEADLINE_SECS: u64 = 20;

/// Default control-plane SlateDB **online maintenance-GC** cadence (seconds) when `[serve.kv.slatedb]
/// gc_interval` is unset (kv-data-observability durable fix). The supervised writer task reclaims the
/// stale manifest/compactions/WAL/compacted objects the embedded GC would — SURVIVING the transient
/// tick error that kills the unsupervised embedded GC permanently (the 16.5 GB manifest-retention
/// leak). 900s (15 min) matches the cadence of the embedded GC's own protective-checkpoint window, so
/// freshly-superseded SSTs age out of their checkpoint before the next reclaim; a 0 DISABLES the task.
pub const DEFAULT_KV_GC_INTERVAL_SECS: u64 = 900;

/// Default **minimum object age** (seconds) before the online maintenance GC will reclaim an object,
/// when `[serve.kv.slatedb] gc_min_age` is unset. 3600s (1h) is deliberately CONSERVATIVE: the online
/// GC only deletes objects the latest manifest no longer references, but a read replica polling the
/// shared store could still be mid-scan over a manifest generation that just became stale — a min_age
/// this large guarantees such a needed-but-unreferenced object is never a deletion candidate while any
/// plausible replica scan is in flight. A 0 (or unset) falls back to this default — it is never zero
/// (a zero min_age would reintroduce exactly the mid-scan deletion hazard this bound closes).
pub const DEFAULT_KV_GC_MIN_AGE_SECS: u64 = 3600;

/// `[serve.kv]` — control-plane KV configuration. The backend itself is selected by `--kv` /
/// `BOATRAMP_KV` (`slatedb` default, `sql`, `memory`, `cloudflare`); this block holds the
/// backend-specific settings, nested so a knob can never silently mislead under the wrong backend
/// (UX-C3): the SlateDB durability knobs live under [`slatedb`](Self::slatedb), and the SQL
/// connection under [`sql`](Self::sql). Absent block ⇒ the SlateDB defaults apply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KvConfig {
    /// `[serve.kv.slatedb]` — SlateDB-specific durability knobs (checkpoint cadence + close budget).
    /// Nested under `slatedb` (UX-C3) so they don't appear to apply under `--kv sql` / `--kv memory`.
    /// Absent ⇒ both defaults (checkpoint cadence ON, generous close budget).
    pub slatedb: Option<SlatedbKvConfig>,
    /// `[serve.kv.sql]` — the SQL KV backend's connection (`--kv sql`). Absent under `--kv sql` ⇒ the
    /// backend is configured entirely by the `BOATRAMP_KV_SQL_*` env (resolved at serve wiring).
    pub sql: Option<SqlKvConfig>,
}

impl KvConfig {
    /// The resolved periodic-checkpoint interval (SlateDB): `None` ⇒ cadence DISABLED (explicit `0`);
    /// else the configured seconds, or [`DEFAULT_KV_CHECKPOINT_INTERVAL_SECS`] when unset/absent.
    pub fn checkpoint_interval(&self) -> Option<std::time::Duration> {
        match self.slatedb.as_ref().and_then(|s| s.checkpoint_interval) {
            Some(0) => None,
            Some(secs) => Some(std::time::Duration::from_secs(secs)),
            None => Some(std::time::Duration::from_secs(
                DEFAULT_KV_CHECKPOINT_INTERVAL_SECS,
            )),
        }
    }

    /// The resolved graceful-close budget (SlateDB). A configured `0` (or unset/absent) falls back to
    /// [`DEFAULT_KV_CLOSE_DEADLINE_SECS`] — the budget must be positive so a genuinely-wedged close
    /// still cannot hang shutdown forever, while never being the too-tight 3s that caused the incident.
    pub fn close_deadline(&self) -> std::time::Duration {
        match self.slatedb.as_ref().and_then(|s| s.close_deadline) {
            Some(secs) if secs > 0 => std::time::Duration::from_secs(secs),
            _ => std::time::Duration::from_secs(DEFAULT_KV_CLOSE_DEADLINE_SECS),
        }
    }

    /// The resolved online maintenance-GC cadence (SlateDB): `None` ⇒ the task is DISABLED (explicit
    /// `0`); else the configured seconds, or [`DEFAULT_KV_GC_INTERVAL_SECS`] when unset/absent.
    pub fn gc_interval(&self) -> Option<std::time::Duration> {
        match self.slatedb.as_ref().and_then(|s| s.gc_interval) {
            Some(0) => None,
            Some(secs) => Some(std::time::Duration::from_secs(secs)),
            None => Some(std::time::Duration::from_secs(DEFAULT_KV_GC_INTERVAL_SECS)),
        }
    }

    /// The resolved online maintenance-GC minimum object age (SlateDB). A configured `0` (or
    /// unset/absent) falls back to [`DEFAULT_KV_GC_MIN_AGE_SECS`] — never zero, so a reader replica
    /// mid-scan over a just-superseded manifest generation is always protected.
    pub fn gc_min_age(&self) -> std::time::Duration {
        match self.slatedb.as_ref().and_then(|s| s.gc_min_age) {
            Some(secs) if secs > 0 => std::time::Duration::from_secs(secs),
            _ => std::time::Duration::from_secs(DEFAULT_KV_GC_MIN_AGE_SECS),
        }
    }
}

/// `[serve.kv.slatedb]` — control-plane SlateDB KV durability knobs (v0.9.0 KV-recovery). Both are
/// backstops/tuning: the crown-jewel per-write frontier-sync (C2) is unconditional and independent of
/// these. Absent ⇒ both defaults apply (checkpoint cadence ON, generous close budget). (v0.12.0 UX-C3:
/// MOVED here from the `[serve.kv]` top level so they do not appear to apply under a non-SlateDB
/// backend; with `deny_unknown_fields` a pre-v0.12.0 top-level knob now fails loud rather than
/// silently misleading.)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SlatedbKvConfig {
    /// Periodic checkpoint cadence, seconds. Unset ⇒ [`DEFAULT_KV_CHECKPOINT_INTERVAL_SECS`] (ON).
    /// `0` DISABLES the cadence (the crown-jewel per-write frontier-sync still runs; only the
    /// backstop that bounds the loss window for derived/relaxed writes is off).
    pub checkpoint_interval: Option<u64>,
    /// Graceful drain+close budget, seconds. Unset ⇒ [`DEFAULT_KV_CLOSE_DEADLINE_SECS`]. `0` is
    /// rejected up to the default (a zero budget would abandon every close, guaranteeing a torn tail).
    pub close_deadline: Option<u64>,
    /// **Online maintenance-GC cadence**, seconds (kv-data-observability durable fix). Unset ⇒
    /// [`DEFAULT_KV_GC_INTERVAL_SECS`] (ON). `0` DISABLES the supervised GC task entirely (leaving only
    /// SlateDB's embedded GC — which dies permanently on its first transient tick error, the leak this
    /// task works around; disable only if you run an external offline `boatramp kv compact` cadence).
    pub gc_interval: Option<u64>,
    /// **Online maintenance-GC minimum object age**, seconds. Unset (or `0`) ⇒
    /// [`DEFAULT_KV_GC_MIN_AGE_SECS`] (1h) — never zero, so a reader replica mid-scan over a
    /// just-superseded manifest generation can never have a needed object reclaimed out from under it.
    /// A tuned positive value is honored (e.g. a single-node deploy with no read replicas may lower it).
    /// CAVEAT: lowering it is UNSAFE whenever ANY read replica polls this shared store — a value below
    /// the time a replica may spend mid-scan reintroduces the "object reclaimed out from under a
    /// reader" hazard. Only lower it on a node you are certain has no read replicas.
    pub gc_min_age: Option<u64>,
}

/// `[serve.kv.sql]` — the **SQL control-plane KV** backend connection (`--kv sql`). The connection
/// URL is NEVER written in the config (UX-C2): a bring-your-own / remote engine names the env var
/// holding it via [`url_env`](Self::url_env) (mirroring `ExternalDatabaseConfig`), while an embedded
/// single-node SQLite database names an on-disk file via [`path`](Self::path). Every field is also
/// settable by `BOATRAMP_KV_SQL_*` env (resolved at serve wiring). **This workstream (build-order
/// step 1) wires `sqlite` (libsql-local) only**; `postgres`/`mysql` are later workstreams.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SqlKvConfig {
    /// Engine: `sqlite` (aliases `sqlite3`/`libsql`) — the embedded single-node file; `postgres`
    /// (aliases `postgresql`/`pg`) or `mysql` (alias `mariadb`) — the multi-writer engines (later
    /// workstreams), the same alias set as the `databases:` block. Empty ⇒ `sqlite`.
    pub kind: String,
    /// Name of the env var holding the connection URL (e.g. `postgres://…`, or a remote sqld URL) —
    /// NEVER a raw URL in the config. Unused for an embedded single-node `sqlite` database (which
    /// uses [`path`](Self::path)).
    pub url_env: Option<String>,
    /// On-disk file path for an embedded single-node `sqlite` KV (e.g. `/data/kv.db`). The parent
    /// directory is created if absent. Ignored for `postgres`/`mysql` and for a remote-sqld URL.
    pub path: Option<String>,
    /// Maximum pooled connections for a `postgres`/`mysql` KV (later workstreams). Ignored for the
    /// embedded `sqlite` path (one `Database` handle, connections opened per op).
    pub pool_max: Option<u32>,
    /// Warm **floor** of pooled connections the `postgres`/`mysql` KV keeps established while idle
    /// (default: a small internal floor — the KV is a single shared pool on every request's hot
    /// path, so warming a handful avoids serial cold re-establishment on a burst). `0` disables the
    /// floor. Ignored for the embedded `sqlite` path. Clamped to `pool_max`.
    pub pool_min: Option<u32>,
}

/// `[serve.s3_ingress_cloud]` — the cloud-brokering knobs for the M4 blob-upload minter (which native
/// credential the mint brokers when the node's blob backend is a cloud object store). Only the fields
/// for the active blob backend are consulted; a `None` here ⇒ the local S3 face mints.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct S3IngressCloud {
    /// **AWS**: the IAM role ARN the base credential assumes to broker the scoped session-policy
    /// credential (`sts:AssumeRole`, the default). Absent AND `aws_use_federation_token = true` ⇒
    /// `sts:GetFederationToken` is used instead (for an IAM-user base credential).
    pub aws_role_arn: Option<String>,
    /// **AWS**: use `sts:GetFederationToken` instead of `AssumeRole` (IAM-user deployments). Requires
    /// the base credential to be a real IAM user, not itself a session.
    #[serde(default)]
    pub aws_use_federation_token: bool,
    /// **AWS**: the S3-compatible backend has NO STS (Tigris/R2/MinIO): mint single-object presigned PUTs
    /// only. Prefix/multipart mints are refused (they require STS). Mutually exclusive with
    /// `aws_role_arn`/`aws_use_federation_token` (a misconfiguration that set both fails loud at wiring,
    /// never silently picks one). The presigned PUT is signed from the node's base S3 credential — the
    /// SAME source the S3 blob backend uses — so no new credential is needed. Default `false`.
    #[serde(default)]
    pub aws_presigned_only: bool,
    /// **GCS**: the service-account client email whose V4 signed URLs / IAM-signed uploads the minter
    /// produces (used in the signing scope). Absent ⇒ resolved from ADC.
    pub gcs_client_email: Option<String>,
    /// **Azure**: the storage account name (for the SAS signature + the blob URL). Absent ⇒ taken from
    /// the `azure_account` blob-backend arg.
    pub azure_account: Option<String>,
    /// **Azure**: the blob service URL (`https://{account}.blob.core.windows.net/`). Absent ⇒ derived
    /// from the account name.
    pub azure_service_url: Option<String>,
    /// **Azure**: declare the storage account has a **hierarchical namespace** (HNS/ADLS-Gen2). A
    /// directory-scoped SAS only actually confines to a sub-prefix on an HNS account; on a flat account
    /// it silently degrades to container-wide (Security LOW-1). So a PREFIX mint is refused unless this
    /// is `true`. Default `false` (fail-closed). A single-key mint is unaffected.
    #[serde(default)]
    pub azure_hns: bool,
}

/// The default operator ceiling on a minted S3 upload credential's TTL when
/// `[serve].s3_ingress_mint_max_ttl_secs` is unset: 1 hour — long enough for a browser UGC upload or a
/// bulk-agent burst, short enough to bound a leaked short-lived credential.
pub const DEFAULT_S3_INGRESS_MINT_MAX_TTL_SECS: u64 = 3600;

/// `[serve.console]` — the embedded web console (a Wasm SPA baked into the
/// binary with the `console` build feature). Opt-in: the static shell holds no
/// secrets and the `/api` it drives is token-gated, so it is served
/// **unauthenticated** at a deliberately obscure path (a bearer token can't gate
/// a top-level browser navigation anyway — the path is the obscurity, the token
/// is the real gate).
#[cfg_attr(not(feature = "console"), allow(dead_code))]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConsoleConfig {
    /// Serve the embedded console (default `false`). Requires the `console` build
    /// feature; enabling it in a build without that feature is a logged no-op.
    pub enabled: bool,
    /// Host(s) the console answers on: `*` (any host, the default), an exact host
    /// (`console.example.com`), or a leading-wildcard (`*.example.com`).
    pub host: Option<String>,
    /// URL path prefix the console mounts at (default `/_console`). Kept under the
    /// reserved `/_` namespace so it never collides with a published site path.
    pub path: Option<String>,
}

/// `publish` section — where and what to deploy (the `sync` target).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct PublishConfig {
    /// Base URL of the boatramp server (e.g. `https://pad.example.com`).
    pub server: Option<String>,
    /// Site name to publish to.
    pub site: Option<String>,
    /// API token for the control plane (or set `BOATRAMP_TOKEN`).
    pub token: Option<String>,
    /// Project this site belongs to (overrides with `--project` / `BOATRAMP_PROJECT`).
    pub project: Option<String>,
}

/// `build` section.
#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct BuildConfig {
    /// Shell command to run (e.g. `npm run build`).
    pub command: String,
    /// Directory the build emits, published by `sync` (e.g. `dist`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

/// `bundle` section — the in-process Rust bundler (`bundler` feature).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct BundleConfig {
    /// Output directory for bundled assets (e.g. `dist`).
    #[serde(default = "default_bundle_outdir")]
    pub outdir: String,
    /// JS/TS entry points bundled by Rolldown (tree-shaken, code-split).
    pub js: Vec<String>,
    /// CSS entry points bundled by lightningcss (`@import` inlined).
    pub css: Vec<String>,
    /// Minify output (default true).
    #[serde(default = "default_true")]
    pub minify: bool,
}

fn default_bundle_outdir() -> String {
    "dist".to_string()
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(text: &str) -> ProjectConfig {
        ron_options().from_str(text).unwrap()
    }

    fn server(text: &str) -> ServerConfig {
        ron_options().from_str(text).unwrap()
    }

    /// Build an [`EnvSource::Map`] from `(name, value)` pairs for deterministic
    /// override tests (no process-global `std::env` mutation).
    fn env(pairs: &[(&str, &str)]) -> EnvSource {
        EnvSource::Map(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn env_overrides_configure_all_three_sections_with_no_file() {
        // The crux of the ask: with NO `boatramp.cfg` at all (the default config),
        // env vars alone materialise + populate the compute, security, and handler
        // `sql` sections. `ServerConfig::default()` has all three absent.
        let mut cfg = ServerConfig::default();
        assert!(cfg.compute.is_none() && cfg.security.is_none() && cfg.handlers.is_none());

        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_COMPUTE_VCPUS", "8"),
            ("BOATRAMP_COMPUTE_MEM_MIB", "4096"),
            ("BOATRAMP_COMPUTE_REGION", "eu-central"),
            ("BOATRAMP_SECURITY_PROFILE", "single-tenant"),
            ("BOATRAMP_SECURITY_ALLOW_SITE_PRIVATE_UPSTREAMS", "true"),
            ("BOATRAMP_SECURITY_MAX_UPLOAD_BYTES", "1048576"),
            ("BOATRAMP_HANDLERS_SQL_URL", "http://sqld:8080"),
            ("BOATRAMP_HANDLERS_SQL_ADMIN_URL", "http://sqld:9090"),
        ]))
        .expect("valid env overrides apply");

        // compute: the section now exists with the env values (and defaults elsewhere).
        let compute = cfg.compute.expect("compute materialised from env");
        assert_eq!(compute.vcpus, 8);
        assert_eq!(compute.mem_mib, 4096);
        assert_eq!(compute.region.as_deref(), Some("eu-central"));
        assert_eq!(compute.bridge, "br-boatramp"); // untouched default

        // security: profile + an override both took, and the posture resolves.
        let security = cfg.security.expect("security materialised from env");
        assert_eq!(security.profile.as_deref(), Some("single-tenant"));
        let posture = security.resolve().expect("resolves");
        assert!(posture.allow_site_private_upstreams);
        assert_eq!(posture.max_upload_bytes, 1_048_576);

        // handler sql: the nested handlers.bindings.sql chain was created.
        let sql = cfg
            .handlers
            .expect("handlers materialised from env")
            .bindings
            .sql
            .expect("sql binding materialised from env");
        assert_eq!(sql.url.as_deref(), Some("http://sqld:8080"));
        assert_eq!(sql.admin_url.as_deref(), Some("http://sqld:9090"));
    }

    #[test]
    fn internal_dns_defaults_on_with_the_standard_upstream_and_domain() {
        // The `[compute]` defaults: internal DNS on, forwarding to 1.1.1.1:53, names
        // under `boatramp.internal`.
        let compute = ComputeConfig::default();
        assert!(compute.internal_dns, "internal DNS is on by default");
        assert_eq!(compute.dns_upstream, "1.1.1.1:53");
        assert_eq!(compute.dns_domain, "boatramp.internal");
    }

    #[test]
    fn internal_dns_knobs_parse_from_a_file() {
        // A file can turn it off and override the upstream + domain.
        let cfg = server(
            r#"(
                compute: ( internal_dns: false, dns_upstream: "10.0.0.53:53", dns_domain: "svc.internal" ),
            )"#,
        );
        let compute = cfg.compute.expect("compute section");
        assert!(!compute.internal_dns);
        assert_eq!(compute.dns_upstream, "10.0.0.53:53");
        assert_eq!(compute.dns_domain, "svc.internal");
    }

    #[test]
    fn registry_auth_parses_host_wide_and_repo_scoped_forms_from_ron() {
        // The operator `[compute].registry_auth` map accepts EITHER a bare string (host-wide,
        // back-compat) OR a `( secret, repos: [...] )` struct (repo-scoped, MEDIUM-2) — the
        // untagged enum must deserialize both from RON, the real config format.
        use boatramp_core::registry_auth::OperatorRegistryAuth;
        let cfg = server(
            r#"(
                compute: ( registry_auth: {
                    "ghcr.io": "fleet-ghcr",
                    "registry.internal:5000": ( secret: "internal-reg", repos: ["myorg/base-", "myorg/runtime-"] ),
                } ),
            )"#,
        );
        let compute = cfg.compute.expect("compute section");
        assert_eq!(
            compute.registry_auth.get("ghcr.io"),
            Some(&OperatorRegistryAuth::HostWide("fleet-ghcr".into())),
            "a bare string is host-wide"
        );
        assert_eq!(
            compute.registry_auth.get("registry.internal:5000"),
            Some(&OperatorRegistryAuth::Scoped {
                secret: "internal-reg".into(),
                repos: vec!["myorg/base-".into(), "myorg/runtime-".into()],
            }),
            "the struct form carries the repos prefix allowlist"
        );
    }

    #[test]
    fn internal_dns_knobs_are_env_settable() {
        // Env alone materialises `[compute]` and sets each internal-DNS knob (and an
        // unrecognised bool spelling is a clear error, exercised by parse_bool).
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_COMPUTE_INTERNAL_DNS", "off"),
            ("BOATRAMP_COMPUTE_DNS_UPSTREAM", "9.9.9.9:53"),
            ("BOATRAMP_COMPUTE_DNS_DOMAIN", "corp.internal"),
        ]))
        .expect("valid env overrides apply");
        let compute = cfg.compute.expect("compute materialised from env");
        assert!(!compute.internal_dns, "env `off` disables internal DNS");
        assert_eq!(compute.dns_upstream, "9.9.9.9:53");
        assert_eq!(compute.dns_domain, "corp.internal");
    }

    #[test]
    fn env_override_wins_over_file_value_but_unset_defers() {
        // A file that set each section; env then overrides one field per section
        // and leaves the rest of the file value in place (precedence: env > file).
        let mut cfg = server(
            r#"(
                compute: ( vcpus: 2, mem_mib: 512, region: "us-east" ),
                security: ( profile: "multi-tenant" ),
                handlers: ( bindings: ( sql: ( url: "http://file:8080", admin_url: "http://file:9090" ) ) ),
            )"#,
        );

        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_COMPUTE_VCPUS", "16"),
            ("BOATRAMP_SECURITY_PROFILE", "dev"),
            ("BOATRAMP_HANDLERS_SQL_URL", "http://env:8080"),
        ]))
        .expect("valid env overrides apply");

        let compute = cfg.compute.unwrap();
        assert_eq!(compute.vcpus, 16, "env wins over the file vcpus");
        assert_eq!(compute.mem_mib, 512, "unset env defers to the file mem_mib");
        assert_eq!(
            compute.region.as_deref(),
            Some("us-east"),
            "unset env defers to the file region"
        );

        assert_eq!(
            cfg.security.unwrap().profile.as_deref(),
            Some("dev"),
            "env profile wins over the file profile"
        );

        let sql = cfg.handlers.unwrap().bindings.sql.unwrap();
        assert_eq!(
            sql.url.as_deref(),
            Some("http://env:8080"),
            "env wins over the file sql url"
        );
        assert_eq!(
            sql.admin_url.as_deref(),
            Some("http://file:9090"),
            "unset env defers to the file sql admin_url"
        );
    }

    #[test]
    fn env_overrides_leave_unmentioned_sections_absent() {
        // With no relevant env vars set, an empty config stays empty — the sections
        // are materialised only on demand, so an unset environment adds nothing.
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[("SOME_UNRELATED_VAR", "x")]))
            .expect("no-op env applies");
        assert!(cfg.compute.is_none());
        assert!(cfg.security.is_none());
        assert!(cfg.handlers.is_none());
        assert!(cfg.secrets.is_none());
        assert!(cfg.cluster.is_none());
    }

    #[test]
    fn env_bool_accepts_common_spellings_and_rejects_garbage() {
        // Truthy/falsey spellings all parse.
        for (raw, want) in [
            ("true", true),
            ("1", true),
            ("YES", true),
            ("On", true),
            ("false", false),
            ("0", false),
            ("no", false),
            ("OFF", false),
        ] {
            let mut cfg = ServerConfig::default();
            cfg.apply_env_overrides(&env(&[("BOATRAMP_SECURITY_REQUIRE_POP", raw)]))
                .expect("boolean parses");
            assert_eq!(
                cfg.security.unwrap().overrides.require_pop,
                Some(want),
                "{raw:?} ⇒ {want}"
            );
        }
        // A non-boolean value is a clear error, not a silent default. (The pipeline rejects it
        // LOUDLY at extract as a `Resolve` error — figment's message names the field path, not
        // the env var, but a malformed value is never silently defaulted.)
        let mut cfg = ServerConfig::default();
        let err = cfg
            .apply_env_overrides(&env(&[("BOATRAMP_SECURITY_REQUIRE_POP", "maybe")]))
            .expect_err("garbage boolean is rejected");
        assert!(
            matches!(err, ConfigError::Resolve(_)),
            "garbage bool must fail loudly, got {err:?}"
        );
    }

    #[test]
    fn env_number_parse_error_is_loud() {
        // A non-numeric numeric var is rejected LOUDLY (never silently defaulted).
        let mut cfg = ServerConfig::default();
        let err = cfg
            .apply_env_overrides(&env(&[("BOATRAMP_COMPUTE_VCPUS", "lots")]))
            .expect_err("garbage number is rejected");
        assert!(
            matches!(err, ConfigError::Resolve(_)),
            "garbage number must fail loudly, got {err:?}"
        );
    }

    #[test]
    fn empty_env_value_is_treated_as_unset() {
        // `VAR=` (empty) must not clobber a file value with an empty string.
        let mut cfg = server(r#"( compute: ( region: "us-east" ) )"#);
        cfg.apply_env_overrides(&env(&[("BOATRAMP_COMPUTE_REGION", "")]))
            .expect("empty env applies as a no-op");
        assert_eq!(
            cfg.compute.unwrap().region.as_deref(),
            Some("us-east"),
            "an empty env value leaves the file value in place"
        );
    }

    #[test]
    fn env_configures_managed_postgres_secrets_and_privilege_with_no_file() {
        // The acceptance case: with NO `boatramp.cfg` at all, the
        // environment alone stands up a managed co-located Postgres. It configures
        // the default (`"default"`-named, v0.5.0) database in
        // `handlers.bindings.sql.databases` (kind=postgres, compute=pg, database+user
        // set), the `[secrets]` envelope (local + a kek path so the managed credential
        // can be sealed), and `compute.managed_db_privilege = rootless`. All three
        // sections start absent.
        let mut cfg = ServerConfig::default();
        assert!(cfg.handlers.is_none() && cfg.secrets.is_none() && cfg.compute.is_none());

        cfg.apply_env_overrides(&env(&[
            // The default database is addressed by the reserved `DEFAULT` token,
            // which maps to the reserved real name `"default"` (v0.5.0).
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_KIND", "postgres"),
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_COMPUTE", "pg"),
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_DATABASE", "appdb"),
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_USER", "app"),
            // Secrets: the local envelope + a KEK path (never key material).
            ("BOATRAMP_SECRETS_ENVELOPE", "local"),
            ("BOATRAMP_SECRETS_KEK_FILE", "/var/lib/boatramp/secrets/kek"),
            // The shared-kernel DB privilege strategy.
            ("BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE", "rootless"),
        ]))
        .expect("valid env overrides apply");

        // The default (`"default"`-keyed) managed database exists with the right source.
        let sql = cfg
            .handlers
            .expect("handlers materialised from env")
            .bindings
            .sql
            .expect("sql binding materialised from env");
        let db = sql
            .databases
            .get(boatramp_core::project::DEFAULT_DB_NAME)
            .expect("the default `default`-named database was created from DEFAULT");
        assert!(
            !sql.databases.contains_key(""),
            "the empty-string key is never produced (v0.5.0)"
        );
        assert_eq!(db.kind, "postgres");
        assert_eq!(db.compute.as_deref(), Some("pg"));
        assert_eq!(db.database.as_deref(), Some("appdb"));
        assert_eq!(db.user.as_deref(), Some("app"));
        // No `password_env` ⇒ boatramp manages the credential (Phase 2), and the
        // compute-backed source validates.
        assert!(db.password_env.is_none());
        assert!(db.is_managed_credential());
        assert!(db.validate("").is_ok());

        // The secrets envelope + KEK path took (the path is a location, not a key).
        let secrets = cfg.secrets.expect("secrets materialised from env");
        assert_eq!(secrets.envelope, "local");
        assert_eq!(
            secrets.kek_file.as_deref(),
            Some(Path::new("/var/lib/boatramp/secrets/kek"))
        );
        assert!(
            secrets.vault.is_none(),
            "no vault vars ⇒ no vault sub-config"
        );

        // The managed-DB privilege strategy resolved from its lowercase variant.
        let compute = cfg.compute.expect("compute materialised from env");
        assert_eq!(compute.managed_db_privilege, ManagedDbPrivilege::Rootless);
    }

    #[test]
    fn env_declares_named_databases_and_merges_over_the_file() {
        // A file declares one database; the env overrides one of its fields and
        // ADDS a second, discovering both member names from the environment.
        let mut cfg = server(
            r#"(
                handlers: ( bindings: ( sql: (
                    databases: {
                        "analytics": ( kind: "postgres", url_env: "FILE_PG_URL", pool_max: 4, pool_min: 2 ),
                    },
                ) ) ),
            )"#,
        );
        cfg.apply_env_overrides(&env(&[
            // Override the file database's pool size (merge by key, per field).
            ("BOATRAMP_HANDLERS_SQL_DB_analytics_POOL_MAX", "32"),
            // ...and its warm floor (the env `POOL_MIN` maps to the `pool_min` field).
            ("BOATRAMP_HANDLERS_SQL_DB_analytics_POOL_MIN", "8"),
            // Add a brand-new database whose name has an underscore, exercising the
            // longest-suffix name isolation (`_READ_URL_ENV`, not `_URL_ENV`).
            ("BOATRAMP_HANDLERS_SQL_DB_events_log_KIND", "mysql"),
            ("BOATRAMP_HANDLERS_SQL_DB_events_log_URL_ENV", "EVENTS_URL"),
            (
                "BOATRAMP_HANDLERS_SQL_DB_events_log_READ_URL_ENV",
                "EVENTS_RO_URL",
            ),
            ("BOATRAMP_HANDLERS_SQL_DB_events_log_READ_ONLY", "true"),
        ]))
        .expect("valid env overrides apply");

        let sql = cfg.handlers.unwrap().bindings.sql.unwrap();
        assert_eq!(sql.databases.len(), 2);

        let analytics = &sql.databases["analytics"];
        assert_eq!(
            analytics.pool_max,
            Some(32),
            "env pool_max wins over the file"
        );
        assert_eq!(
            analytics.pool_min,
            Some(8),
            "env pool_min (the warm floor) maps + wins over the file's 2"
        );
        assert_eq!(
            analytics.url_env, "FILE_PG_URL",
            "the file's url_env survives (env didn't touch it)"
        );

        let events = &sql.databases["events_log"];
        assert_eq!(events.kind, "mysql");
        assert_eq!(events.url_env, "EVENTS_URL");
        assert_eq!(events.read_url_env.as_deref(), Some("EVENTS_RO_URL"));
        assert!(events.read_only);
        assert_eq!(events.pool_min, None, "an unset warm floor stays None");
    }

    #[test]
    fn default_token_maps_to_the_reserved_default_name_not_empty() {
        // v0.5.0 breaking change: the reserved `DEFAULT` env token maps to the real
        // name `"default"` (a valid URL path segment), never the empty string. This is
        // what makes the default binding addressable as `--db default` and keeps every
        // db-name ingress path-segment-safe.
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_KIND", "postgres"),
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_URL_ENV", "PG_URL"),
        ]))
        .expect("valid env overrides apply");
        let databases = cfg.handlers.unwrap().bindings.sql.unwrap().databases;
        assert!(
            databases.contains_key(boatramp_core::project::DEFAULT_DB_NAME),
            "DEFAULT → the reserved `default` key"
        );
        assert!(
            !databases.contains_key(""),
            "the empty-string key is never produced"
        );
    }

    #[test]
    fn empty_string_db_binding_name_is_rejected_with_a_cure() {
        // A `boatramp.cfg` that literally writes the legacy empty-string default key
        // fails closed on load (it would emit a `//` control-plane path), and the
        // error points at the cure (`default`).
        let err = ServerConfig::parse(
            r#"(
                handlers: ( bindings: ( sql: (
                    databases: {
                        "": ( kind: "postgres", url_env: "PG_URL" ),
                    },
                ) ) ),
            )"#,
        )
        .expect_err("an empty-string db binding name is refused");
        match err {
            ConfigError::InvalidDbName { name, reason, cure } => {
                assert_eq!(name, "");
                assert!(reason.contains("empty"), "reason names the emptiness");
                assert!(
                    cure.contains("default") && cure.contains("CHANGELOG"),
                    "the cure points at `default` + the CHANGELOG"
                );
            }
            other => panic!("expected ConfigError::InvalidDbName, got {other:?}"),
        }
    }

    #[test]
    fn path_separator_db_binding_name_is_rejected() {
        // A non-slug name (contains `/`) is refused with the v0.7.0 slug reason and the
        // slug cure (pointing at `project doctor`) — NOT the empty-default cure (the fix
        // is to rename it to a valid slug, not adopt `default`). Boot-LOUD.
        let err = ServerConfig::parse(
            r#"(
                handlers: ( bindings: ( sql: (
                    databases: {
                        "a/b": ( kind: "postgres", url_env: "PG_URL" ),
                    },
                ) ) ),
            )"#,
        )
        .expect_err("a `/`-bearing db binding name is refused");
        match err {
            ConfigError::InvalidDbName { name, reason, cure } => {
                assert_eq!(name, "a/b");
                // The v0.7.0 slug reason (a positive statement of the allowlist).
                assert!(
                    reason.contains("valid slug"),
                    "reason states the slug rule, got {reason:?}"
                );
                // The slug cure points at `project doctor`, not the empty-default cure.
                assert_eq!(cure, boatramp_core::project::INVALID_NAME_CURE);
                assert!(!cure.contains("CHANGELOG"), "not the empty-default cure");
            }
            other => panic!("expected ConfigError::InvalidDbName, got {other:?}"),
        }
    }

    #[test]
    fn reserved_bramp_db_compute_prefix_is_rejected() {
        // #501 Stage B LOW-2: a static BYO binding may not point `compute` at a
        // `bramp-db-…` workload (reserved for derived managed-DB servers) — refused
        // fail-closed at config load.
        let err = ServerConfig::parse(
            r#"(
                handlers: ( bindings: ( sql: (
                    databases: {
                        "byo": ( kind: "postgres", compute: "bramp-db-acme-app", database: "d", user: "u" ),
                    },
                ) ) ),
            )"#,
        )
        .expect_err("a `bramp-db-` compute workload is refused");
        match err {
            ConfigError::InvalidDbName { name, reason, cure } => {
                assert_eq!(name, "bramp-db-acme-app");
                assert!(reason.contains("reserved"), "reason names the reservation");
                assert!(cure.contains("bramp-db-"), "the cure names the prefix");
            }
            other => panic!("expected ConfigError::InvalidDbName, got {other:?}"),
        }
        // A NON-reserved compute workload for a BYO binding still loads fine.
        ServerConfig::parse(
            r#"(
                handlers: ( bindings: ( sql: (
                    databases: {
                        "byo": ( kind: "postgres", compute: "my-pg", database: "d", user: "u" ),
                    },
                ) ) ),
            )"#,
        )
        .expect("a non-reserved compute workload loads");
    }

    #[test]
    fn env_sets_managed_db_startup_grace() {
        // The per-binding startup-grace override is env-settable like the other
        // managed scalars, discovered by the `_STARTUP_GRACE_SECS` suffix.
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_KIND", "postgres"),
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_COMPUTE", "pg"),
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_DATABASE", "appdb"),
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_USER", "app"),
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_STARTUP_GRACE_SECS", "90"),
        ]))
        .expect("valid env overrides apply");
        let db = &cfg.handlers.unwrap().bindings.sql.unwrap().databases
            [boatramp_core::project::DEFAULT_DB_NAME];
        assert_eq!(db.startup_grace_secs, Some(90));
    }

    #[test]
    fn env_sets_rls_gucs_and_all_marker_without_suffix_collision() {
        // The RLS GUC names + the v0.4.21 all-read marker are env-settable. `_TENANT_ALL_MARKER`
        // and `_TENANT_GUC` must NOT be shadowed by the shorter `_TENANT` suffix (longest-first
        // isolation) — a `_TENANT` value would otherwise swallow the DB-name split.
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_KIND", "postgres"),
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_DATABASE", "appdb"),
            (
                "BOATRAMP_HANDLERS_SQL_DB_DEFAULT_TENANT_GUC",
                "app.tenant_id",
            ),
            (
                "BOATRAMP_HANDLERS_SQL_DB_DEFAULT_SESSION_GUC",
                "app.session_id",
            ),
            ("BOATRAMP_HANDLERS_SQL_DB_DEFAULT_TENANT_ALL_MARKER", "*"),
        ]))
        .expect("valid env overrides apply");
        let db = &cfg.handlers.unwrap().bindings.sql.unwrap().databases
            [boatramp_core::project::DEFAULT_DB_NAME];
        assert_eq!(db.tenant_guc.as_deref(), Some("app.tenant_id"));
        assert_eq!(db.session_guc.as_deref(), Some("app.session_id"));
        assert_eq!(db.tenant_all_marker.as_deref(), Some("*"));
    }

    #[test]
    fn env_enum_parse_error_is_loud() {
        // An unknown enum value is rejected LOUDLY at extract (never silently defaulted). The
        // pipeline's `Resolve` error carries figment's message (which names the field + the
        // unknown variant), not the old hand-built "one of rootless/caps" text.
        let mut cfg = ServerConfig::default();
        let err = cfg
            .apply_env_overrides(&env(&[(
                "BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE",
                "superuser",
            )]))
            .expect_err("unknown enum variant is rejected");
        assert!(
            matches!(err, ConfigError::Resolve(_)),
            "unknown enum variant must fail loudly, got {err:?}"
        );
        // The docker enums map their lowercase serde variants too.
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_COMPUTE_DOCKER_ENDPOINT", "bridge"),
            ("BOATRAMP_COMPUTE_DOCKER_VOLUME_MODE", "bind"),
        ]))
        .expect("known enum variants parse");
        let compute = cfg.compute.unwrap();
        assert_eq!(
            compute.docker_endpoint,
            boatramp_docker::DockerEndpoint::Bridge
        );
        assert_eq!(
            compute.docker_volume_mode,
            boatramp_docker::DockerVolumeMode::Bind
        );
    }

    #[test]
    fn env_trust_anchors_parse_as_a_comma_separated_list() {
        // The kernel trust anchors are comma-separated (whitespace trimmed, empty
        // items dropped so a trailing comma is tolerated). A file default is
        // fully replaced, not appended to.
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[
            (
                "BOATRAMP_COMPUTE_KERNEL_SIGNING_PUBKEYS",
                " es256:aa , es256:bb ,",
            ),
            ("BOATRAMP_COMPUTE_KERNEL_ALLOWED_HASHES", "deadbeef"),
        ]))
        .expect("valid list env applies");
        let compute = cfg.compute.unwrap();
        assert_eq!(
            compute.kernel_signing_pubkeys,
            vec!["es256:aa".to_string(), "es256:bb".to_string()],
            "trimmed, comma-split, trailing-empty dropped, defaults replaced"
        );
        assert_eq!(
            compute.kernel_allowed_hashes,
            vec!["deadbeef".to_string()],
            "a single value is a one-element list"
        );
    }

    #[test]
    fn env_configures_secrets_vault_subconfig() {
        // The vault sub-config materialises only when a vault var is set, and the
        // token stays indirected via a variable NAME (`token_env`), never inline.
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_SECRETS_ENVELOPE", "vault"),
            ("BOATRAMP_SECRETS_VAULT_ADDR", "https://vault:8200"),
            ("BOATRAMP_SECRETS_VAULT_KEY", "certs"),
        ]))
        .expect("valid env overrides apply");
        let secrets = cfg.secrets.unwrap();
        assert_eq!(secrets.envelope, "vault");
        let vault = secrets.vault.expect("vault sub-config materialised");
        assert_eq!(vault.addr, "https://vault:8200");
        assert_eq!(vault.key, "certs");
        // token_env defaults to VAULT_TOKEN when not overridden.
        assert_eq!(vault.token_env, "VAULT_TOKEN");
    }

    #[test]
    fn env_materialises_and_overrides_the_cluster_section() {
        // With no file, a `BOATRAMP_CLUSTER_LISTEN` materialises the section; the
        // remaining fields (lists, join token, mesh) layer on. The founding/joining
        // action flags (`BOATRAMP_CLUSTER_INIT`/`_JOIN`) are separate `serve` args
        // and are not part of this section.
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_CLUSTER_LISTEN", "10.0.0.2:7000"),
            ("BOATRAMP_CLUSTER_ROOT_PUBKEYS", "es256:aa,es256:bb"),
            ("BOATRAMP_CLUSTER_SEEDS", "https://10.0.0.1:8080"),
            ("BOATRAMP_CLUSTER_JOIN_TOKEN", "env:BOATRAMP_JOIN_TOKEN"),
            ("BOATRAMP_CLUSTER_STORE_DIR", "/var/lib/boatramp/raft"),
            ("BOATRAMP_CLUSTER_MESH_GATE_CLIENT_WRITES", "true"),
        ]))
        .expect("valid env overrides apply");
        let cluster = cfg.cluster.expect("cluster materialised from env");
        assert_eq!(
            cluster.listen,
            "10.0.0.2:7000".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(
            cluster.root_pubkeys,
            vec!["es256:aa".to_string(), "es256:bb".to_string()]
        );
        assert_eq!(cluster.seeds, vec!["https://10.0.0.1:8080".to_string()]);
        assert_eq!(
            cluster.join_token.as_deref(),
            Some("env:BOATRAMP_JOIN_TOKEN")
        );
        assert_eq!(
            cluster.store_dir.as_deref(),
            Some(Path::new("/var/lib/boatramp/raft"))
        );
        assert_eq!(
            cluster.mesh.expect("mesh sub-config").gate_client_writes,
            Some(true)
        );

        // Decision 4: a `[cluster]` without its required `listen` (here: a non-listen cluster
        // var alone, no file section) now FAILS LOUDLY at extract — the old loader silently
        // dropped the section, which could mask a misconfigured cluster.
        let mut cfg = ServerConfig::default();
        let err = cfg
            .apply_env_overrides(&env(&[("BOATRAMP_CLUSTER_SEEDS", "https://10.0.0.1:8080")]))
            .expect_err("a cluster section without `listen` must fail loudly");
        assert!(
            matches!(err, ConfigError::Resolve(_)),
            "cluster-without-listen must be a loud resolution error, got {err:?}"
        );
    }

    #[test]
    fn env_cluster_listen_overrides_a_file_section() {
        // A file `[cluster]` section: env overrides `listen` and adds seeds.
        let mut cfg = server(r#"( cluster: ( listen: "0.0.0.0:7000" ) )"#);
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_CLUSTER_LISTEN", "10.0.0.9:7000"),
            ("BOATRAMP_CLUSTER_SEEDS", "https://seed:8080"),
        ]))
        .expect("applies");
        let cluster = cfg.cluster.unwrap();
        assert_eq!(
            cluster.listen,
            "10.0.0.9:7000".parse::<std::net::SocketAddr>().unwrap(),
            "env listen wins over the file"
        );
        assert_eq!(cluster.seeds, vec!["https://seed:8080".to_string()]);
    }

    #[test]
    fn empty_project_config_is_default() {
        let cfg = project("()");
        assert!(cfg.publish.server.is_none());
        assert!(cfg.publish.site.is_none());
        assert!(cfg.build.is_none());
        assert!(cfg.bundle.is_none());
        // Routing defaults: schema v1, the single default index candidate.
        assert_eq!(cfg.routing.version, 1);
        assert_eq!(cfg.routing.index, vec!["index.html".to_string()]);
    }

    #[test]
    fn serve_signer_config_parses_and_maps_each_backend() {
        use boatramp_core::cose::TokenAlg;
        use boatramp_server::signer::SignerConfig;

        // RON-native enum tagging (`Vault(...)`); `IMPLICIT_SOME` lets the optional
        // fields (region) take a bare value or be omitted (→ None). This is the
        // exact RON documented in the Authentication guide.
        let vault = server(
            r#"( serve: ( signer: Vault(
                address: "https://vault.example:8200",
                key: "boatramp-root",
                token_env: "VAULT_TOKEN",
                alg: Ed25519,
            ) ) )"#,
        );
        match vault.serve.unwrap().signer.unwrap().to_signer_config() {
            SignerConfig::Vault {
                address,
                key,
                token_env,
                alg,
            } => {
                assert_eq!(address, "https://vault.example:8200");
                assert_eq!(key, "boatramp-root");
                assert_eq!(token_env, "VAULT_TOKEN");
                assert_eq!(alg, TokenAlg::Ed25519);
            }
            other => panic!("expected Vault, got {other:?}"),
        }

        // AWS KMS: region omitted → None; PKCS#11: alg omitted → the ES256 default.
        let aws =
            server(r#"( serve: ( signer: AwsKms(key_id: "arn:aws:kms:eu-west-1:1:key/abc") ) )"#);
        assert!(matches!(
            aws.serve.unwrap().signer.unwrap().to_signer_config(),
            SignerConfig::AwsKms { region: None, .. }
        ));

        let hsm = server(
            r#"( serve: ( signer: Pkcs11(
                module: "/usr/lib/softhsm/libsofthsm2.so",
                token_label: "boatramp",
                key_label: "root",
                pin_env: "HSM_PIN",
            ) ) )"#,
        );
        match hsm.serve.unwrap().signer.unwrap().to_signer_config() {
            SignerConfig::Pkcs11 { alg, .. } => assert_eq!(alg, TokenAlg::Es256),
            other => panic!("expected Pkcs11, got {other:?}"),
        }
    }

    #[test]
    fn project_config_parses_publish_build_and_routing() {
        let cfg = project(
            r#"(
                publish: ( server: "http://127.0.0.1:8080", site: "demo" ),
                build: ( command: "npm run build", output: "dist" ),
                routing: (
                    clean_urls: true,
                    redirects: [ (from: "/old/:slug", to: "/new/:slug", status: 301) ],
                ),
            )"#,
        );
        assert_eq!(cfg.publish.server.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(cfg.publish.site.as_deref(), Some("demo"));
        let build = cfg.build.unwrap();
        assert_eq!(build.command, "npm run build");
        assert_eq!(build.output.as_deref(), Some("dist"));
        assert!(cfg.routing.clean_urls);
        assert_eq!(cfg.routing.redirects.len(), 1);
        assert_eq!(cfg.routing.redirects[0].status, 301);
    }

    #[test]
    fn project_config_rejects_bad_routing_pattern() {
        // The same compile-check `load` runs: a bad route pattern is an error.
        let cfg = project(r#"( routing: ( redirects: [ (from: "/a/**/b/**", to: "/x") ] ) )"#);
        assert!(cfg.routing.compile_check().is_err());
    }

    #[test]
    fn empty_server_config_has_no_sections() {
        let cfg = server("()");
        assert!(cfg.serve.is_none());
        assert!(cfg.handlers.is_none());
        assert!(cfg.cluster.is_none());
        assert!(cfg.security.is_none());
    }

    #[test]
    fn security_section_parses_and_resolves() {
        // A profile plus an override that wins over it.
        let cfg = server(
            r#"(
                security: (
                    profile: "dev",
                    overrides: (
                        oidc_require_audience: true,
                        max_upload_bytes: 0,
                    ),
                )
            )"#,
        );
        let posture = cfg.security.unwrap().resolve().expect("resolves");
        // `dev` is loose...
        assert!(posture.allow_unauthenticated_public_bind);
        // ...but the explicit override wins over the profile.
        assert!(posture.oidc_require_audience);
        assert_eq!(posture.max_upload_bytes, 0); // unlimited
    }

    #[test]
    fn env_wires_allow_env_secret_refs_over_the_multi_tenant_default() {
        // With no file, the multi-tenant default leaves host-env secret refs off;
        // the env knob re-enables them (env > default), same as the other posture bools.
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[("BOATRAMP_SECURITY_ALLOW_ENV_SECRET_REFS", "true")]))
            .expect("valid env override applies");
        let posture = cfg
            .security
            .expect("security materialised from env")
            .resolve()
            .expect("resolves");
        assert!(posture.allow_env_secret_refs);
    }

    #[test]
    fn env_wires_the_multi_tenant_subknobs_over_the_default() {
        // Gap 4b: the four multi-tenant sub-knobs were file-only; env now sets them (env > the
        // multi-tenant preset default), so a 12-factor deploy can tune tenancy isolation + guest
        // capability minting with no `boatramp.cfg`. Verified: strict declaration stays on while
        // cross-tenant `all` twins + guest cap-mint are permitted (they compose — Gap 4.3).
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_SECURITY_PROFILE", "multi-tenant"),
            ("BOATRAMP_SECURITY_REQUIRE_TENANCY_DECLARATION", "true"),
            ("BOATRAMP_SECURITY_ALLOW_CROSS_TENANT_DB", "true"),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_MINT_CAPABILITY", "true"),
            ("BOATRAMP_SECURITY_MAX_GUEST_CAPABILITY_TTL_SECS", "1800"),
        ]))
        .expect("valid env overrides apply");
        let posture = cfg
            .security
            .expect("security materialised from env")
            .resolve()
            .expect("resolves");
        assert!(posture.require_tenancy_declaration);
        assert!(posture.allow_cross_tenant_db);
        assert!(posture.allow_guest_mint_capability);
        assert_eq!(posture.max_guest_capability_ttl_secs, 1800);
    }

    #[test]
    fn env_wires_the_remaining_guest_feature_knobs_over_the_multi_tenant_default() {
        // v0.4.18 env parity: `allow_guest_email` (which regressed prod SMTP on the P48 cutover —
        // multi-tenant defaults it OFF and there was no env lever), its egress sibling
        // `allow_guest_egress_extra_ca` (shipped config-only in v0.4.17), and the four
        // `allow_guest_admin_*` self-config knobs were all missing from the env map. Each preset
        // defaults them OFF under `multi-tenant`; the env knob must now flip each back on for a
        // 12-factor env-only fleet, exactly like `allow_guest_mint_capability`.
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_SECURITY_PROFILE", "multi-tenant"),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_EMAIL", "true"),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_EGRESS_EXTRA_CA", "true"),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_DOMAINS", "true"),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_EMAIL", "true"),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_SITE", "true"),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_SECRETS", "true"),
        ]))
        .expect("valid env overrides apply");
        let security = cfg.security.expect("security materialised from env");
        let posture = security.resolve().expect("resolves");
        // Every one flips on over the multi-tenant preset default (which is `false` for all six).
        assert!(posture.allow_guest_email, "guest email re-enabled via env");
        assert!(posture.allow_guest_egress_extra_ca);
        assert!(posture.allow_guest_admin_domains);
        assert!(posture.allow_guest_admin_email);
        assert!(posture.allow_guest_admin_site);
        assert!(posture.allow_guest_admin_secrets);
        // `security explain` attributes each to the override/env source (not the profile preset).
        let explained = security.explain().expect("explains");
        for knob in [
            "allow_guest_email",
            "allow_guest_egress_extra_ca",
            "allow_guest_admin_domains",
            "allow_guest_admin_email",
            "allow_guest_admin_site",
            "allow_guest_admin_secrets",
        ] {
            assert!(
                explained
                    .lines()
                    .any(|l| l.contains(knob) && l.contains("true") && l.contains("(override)")),
                "explain shows {knob} = true (override): \n{explained}"
            );
        }
    }

    #[test]
    fn each_guest_feature_env_var_moves_its_own_posture_field() {
        // Cross-wiring guard: set each of the guest-feature vars ALONE over the multi-tenant
        // default and assert THAT var's own resolved field flips — so a copy-paste arm mapping a var
        // to the wrong field (or an unregistered var that never materialises the section) fails here.
        // Complements `every_posture_override_field_has_an_env_mapping` below (which proves coverage
        // by field name but not that each arm targets the right field).
        for (var, check) in [
            (
                "BOATRAMP_SECURITY_ALLOW_GUEST_EMAIL",
                (|p: &boatramp_core::security::SecurityPosture| p.allow_guest_email)
                    as fn(&boatramp_core::security::SecurityPosture) -> bool,
            ),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_EGRESS_EXTRA_CA", |p| {
                p.allow_guest_egress_extra_ca
            }),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_TCP_EGRESS", |p| {
                p.allow_guest_tcp_egress
            }),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_TCP_LISTENER", |p| {
                p.allow_guest_tcp_listener
            }),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_DOMAINS", |p| {
                p.allow_guest_admin_domains
            }),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_EMAIL", |p| {
                p.allow_guest_admin_email
            }),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_SITE", |p| {
                p.allow_guest_admin_site
            }),
            ("BOATRAMP_SECURITY_ALLOW_GUEST_ADMIN_SECRETS", |p| {
                p.allow_guest_admin_secrets
            }),
        ] {
            let mut cfg = ServerConfig::default();
            cfg.apply_env_overrides(&env(&[
                ("BOATRAMP_SECURITY_PROFILE", "multi-tenant"),
                (var, "true"),
            ]))
            .unwrap_or_else(|e| panic!("{var} applies: {e}"));
            let posture = cfg
                .security
                .unwrap_or_else(|| panic!("{var} materialises the security section"))
                .resolve()
                .expect("resolves");
            assert!(check(&posture), "{var} did not flip the resolved posture");
        }
    }

    #[test]
    fn every_posture_override_field_has_an_env_mapping() {
        // Exhaustive guard against the EXACT class of gap v0.4.18 closes — a `PostureOverrides`
        // field a 12-factor fleet can set in `[security.overrides]` but NOT via env — for EVERY
        // field, now and in the future. Enumerate the struct's fields structurally (serialize a
        // default instance; every field renders as a key) and assert each maps to a registered
        // `BOATRAMP_SECURITY_<UPPER(field)>` in `SECURITY_ENV_VARS`. A new override field added
        // without an env var (or a var left out of the registry) fails here — so the omission that
        // regressed `allow_guest_email` can't silently recur. The registry entry is load-bearing:
        // `apply_env_overrides` only materialises the section when `source.any(SECURITY_ENV_VARS)`.
        let all = serde_json::to_value(boatramp_core::security::PostureOverrides::default())
            .expect("PostureOverrides serializes");
        let fields = all.as_object().expect("a struct is a JSON object");
        assert!(!fields.is_empty(), "expected some override fields");
        for field in fields.keys() {
            let var = format!("BOATRAMP_SECURITY_{}", field.to_uppercase());
            assert!(
                SECURITY_ENV_VARS.contains(&var.as_str()),
                "PostureOverrides field `{field}` has no env mapping — add `{var}` to \
                 SECURITY_ENV_VARS + an arm in apply_env_overrides (the v0.4.18 forgot-a-knob guard)"
            );
        }
    }

    #[test]
    fn cluster_section_parses_the_dynamic_join_shape() {
        let cfg = server(
            r#"(
                cluster: (
                    listen: "10.0.0.2:7000",
                    root_pubkeys: ["es256:03a1"],
                    seeds: ["https://10.0.0.1:8080"],
                    join_token: "env:BOATRAMP_JOIN_TOKEN",
                ),
            )"#,
        );
        let cluster = cfg.cluster.unwrap();
        assert_eq!(
            cluster.listen,
            "10.0.0.2:7000".parse::<std::net::SocketAddr>().unwrap()
        );
        assert_eq!(cluster.root_pubkeys, vec!["es256:03a1".to_string()]);
        assert_eq!(cluster.seeds, vec!["https://10.0.0.1:8080".to_string()]);
        assert_eq!(
            cluster.join_token.as_deref(),
            Some("env:BOATRAMP_JOIN_TOKEN")
        );
        // store_dir defaults to None (→ <data-dir>/raft at serve time).
        assert!(cluster.store_dir.is_none());
    }

    #[test]
    fn cluster_section_founds_with_just_a_listen_addr() {
        // A founder needs no seeds/token — just where to bind the mesh.
        let cfg = server(r#"( cluster: ( listen: "0.0.0.0:7000" ) )"#);
        let cluster = cfg.cluster.unwrap();
        assert!(cluster.seeds.is_empty());
        assert!(cluster.root_pubkeys.is_empty());
        assert!(cluster.join_token.is_none());
    }

    #[test]
    fn sql_binding_single_node_defaults() {
        // A bare section (or none) means single-node: no url, default dir.
        let cfg = server(r#"( handlers: ( bindings: ( sql: () ) ) )"#);
        let sql = cfg.handlers.unwrap().bindings.sql.unwrap();
        assert!(sql.url.is_none());
        assert!(sql.dir.is_none());
    }

    #[test]
    fn sql_binding_single_node_custom_dir() {
        let cfg =
            server(r#"( handlers: ( bindings: ( sql: ( dir: "/var/lib/boatramp/sql" ) ) ) )"#);
        let sql = cfg.handlers.unwrap().bindings.sql.unwrap();
        assert_eq!(sql.dir.as_deref(), Some(Path::new("/var/lib/boatramp/sql")));
        assert!(sql.url.is_none());
    }

    #[test]
    fn sql_binding_cluster() {
        let cfg = server(
            r#"(
                handlers: ( bindings: ( sql: (
                    url: "http://sqld:8080",
                    admin_url: "http://sqld:9090",
                    token_env: "BOATRAMP_SQL_TOKEN",
                ) ) ),
            )"#,
        );
        let sql = cfg.handlers.unwrap().bindings.sql.unwrap();
        assert_eq!(sql.url.as_deref(), Some("http://sqld:8080"));
        assert_eq!(sql.admin_url.as_deref(), Some("http://sqld:9090"));
        assert_eq!(sql.token_env.as_deref(), Some("BOATRAMP_SQL_TOKEN"));
        assert_eq!(sql.admin_token_env, None);
    }

    #[test]
    fn sql_binding_env_only_sets_trusted_extensions_and_declared_caps() {
        // The crux of the ask: with NO `boatramp.cfg`, env vars alone materialise + populate the
        // sql binding's migration trusted-extension allowlist (a parse_list, comma-separated +
        // trimmed) and the declared-DB ceilings — so a fly `[env]`-only fleet can allowlist
        // `pg_trgm` without a `[[files]] boatramp.cfg` edit + a server roll.
        let mut cfg = ServerConfig::default();
        assert!(cfg.handlers.is_none());
        cfg.apply_env_overrides(&env(&[
            (
                "BOATRAMP_HANDLERS_SQL_MIGRATE_TRUSTED_EXTENSIONS",
                "pg_trgm, pgcrypto",
            ),
            ("BOATRAMP_HANDLERS_SQL_MAX_DECLARED_DATABASES", "32"),
            ("BOATRAMP_HANDLERS_SQL_MAX_DECLARED_VOLUME_MIB", "1048576"),
        ]))
        .expect("valid env overrides apply");
        let sql = cfg
            .handlers
            .expect("handlers materialised from env")
            .bindings
            .sql
            .expect("sql binding materialised from the trusted-extensions var alone");
        assert_eq!(
            sql.migrate_trusted_extensions.as_deref(),
            Some(&["pg_trgm".to_string(), "pgcrypto".to_string()][..]),
            "the allowlist is the comma-split, trimmed env list (source = env)"
        );
        assert_eq!(sql.max_declared_databases, Some(32));
        assert_eq!(sql.max_declared_volume_mib, Some(1_048_576));
    }

    #[test]
    fn sql_binding_env_over_file_for_trusted_extensions() {
        // Field-level env-over-file precedence: a file allowlist is overridden ONLY for the var that
        // is set; an unset var keeps the file value (never clobbered to empty).
        let mut cfg = server(
            r#"(
                handlers: ( bindings: ( sql: (
                    migrate_trusted_extensions: ["citext"],
                    max_declared_databases: 8,
                ) ) ),
            )"#,
        );
        cfg.apply_env_overrides(&env(&[(
            "BOATRAMP_HANDLERS_SQL_MIGRATE_TRUSTED_EXTENSIONS",
            "pg_trgm",
        )]))
        .expect("env overrides apply");
        let sql = cfg.handlers.unwrap().bindings.sql.unwrap();
        assert_eq!(
            sql.migrate_trusted_extensions.as_deref(),
            Some(&["pg_trgm".to_string()][..]),
            "env wins over the file allowlist for the var that is set"
        );
        assert_eq!(
            sql.max_declared_databases,
            Some(8),
            "a var left unset keeps the file value (not clobbered)"
        );
    }

    #[test]
    fn every_sql_binding_scalar_has_an_env_mapping() {
        // Forgot-a-knob guard (the v0.4.18 shape, for `handlers.bindings.sql`): every env-mappable
        // SCALAR field on SqlBindingConfig must have a `BOATRAMP_HANDLERS_SQL_*` entry in
        // SQL_ENV_VARS, so a file-less (fly `[env]`-only) fleet can set it without a `boatramp.cfg`
        // + server roll — the EXACT gap that left `migrate_trusted_extensions` env-unsettable. The
        // destructure is the compile-time half: a NEW field added to SqlBindingConfig breaks this
        // test until it is classified below (a scalar → add a var here + a registry entry + an
        // overlay arm; or the `databases` map, which is discovered by the
        // `BOATRAMP_HANDLERS_SQL_DB_<NAME>_*` prefix scan, not a scalar var). The loop is the runtime
        // half: each classified scalar is actually registered.
        let SqlBindingConfig {
            dir: _,
            url: _,
            admin_url: _,
            replica_url: _,
            token_env: _,
            admin_token_env: _,
            preview_mode: _,
            preview_init: _,
            // NOT a scalar env var: the keyed external-database map, discovered by prefix scan.
            databases: _,
            deprovision_grace_secs: _,
            migrate_trusted_extensions: _,
            max_declared_databases: _,
            max_declared_volume_mib: _,
        } = SqlBindingConfig::default();
        for var in [
            "BOATRAMP_HANDLERS_SQL_DIR",
            "BOATRAMP_HANDLERS_SQL_URL",
            "BOATRAMP_HANDLERS_SQL_ADMIN_URL",
            "BOATRAMP_HANDLERS_SQL_REPLICA_URL",
            "BOATRAMP_HANDLERS_SQL_TOKEN_ENV",
            "BOATRAMP_HANDLERS_SQL_ADMIN_TOKEN_ENV",
            "BOATRAMP_HANDLERS_SQL_PREVIEW_MODE",
            "BOATRAMP_HANDLERS_SQL_PREVIEW_INIT",
            "BOATRAMP_HANDLERS_SQL_DEPROVISION_GRACE_SECS",
            "BOATRAMP_HANDLERS_SQL_MIGRATE_TRUSTED_EXTENSIONS",
            "BOATRAMP_HANDLERS_SQL_MAX_DECLARED_DATABASES",
            "BOATRAMP_HANDLERS_SQL_MAX_DECLARED_VOLUME_MIB",
        ] {
            assert!(
                SQL_ENV_VARS.contains(&var),
                "{var} missing from SQL_ENV_VARS — a sql-binding scalar lost its env lever \
                 (the forgot-a-knob gap); add it to the registry + an overlay arm"
            );
        }
    }

    #[test]
    fn env_wires_the_jwks_freshness_knobs_over_the_default() {
        // The two-tier JWKS freshness knobs are env-settable (12-factor parity), and every lever is
        // registered in JWKS_ENV_VARS — a forgot-a-knob guard so a new `jwks_*` field can't silently
        // lose its env override.
        let mut cfg = ServerConfig::default();
        assert!(cfg.handlers.is_none());
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_HANDLERS_JWKS_REFRESH_SECS", "90"),
            ("BOATRAMP_HANDLERS_JWKS_HARD_TTL_SECS", "450"),
            ("BOATRAMP_HANDLERS_JWKS_FOREIGN_REFRESH_SECS", "30"),
            ("BOATRAMP_HANDLERS_JWKS_FOREIGN_HARD_TTL_SECS", "150"),
            ("BOATRAMP_HANDLERS_JWKS_PREWARM", "false"),
        ]))
        .expect("valid env overrides apply");
        let h = cfg.handlers.expect("handlers materialised from env");
        assert_eq!(h.jwks_refresh_secs, Some(90));
        assert_eq!(h.jwks_hard_ttl_secs, Some(450));
        assert_eq!(h.jwks_foreign_refresh_secs, Some(30));
        assert_eq!(h.jwks_foreign_hard_ttl_secs, Some(150));
        assert_eq!(h.jwks_prewarm, Some(false));
        for var in [
            "BOATRAMP_HANDLERS_JWKS_REFRESH_SECS",
            "BOATRAMP_HANDLERS_JWKS_HARD_TTL_SECS",
            "BOATRAMP_HANDLERS_JWKS_FOREIGN_REFRESH_SECS",
            "BOATRAMP_HANDLERS_JWKS_FOREIGN_HARD_TTL_SECS",
            "BOATRAMP_HANDLERS_JWKS_PREWARM",
        ] {
            assert!(
                JWKS_ENV_VARS.contains(&var),
                "{var} missing from JWKS_ENV_VARS — a JWKS freshness knob lost its env lever"
            );
        }
    }

    #[test]
    fn env_wires_the_handler_concurrency_knobs_over_the_default() {
        // The per-component serve-admission gate + the two lane ceilings are env-settable (12-factor
        // parity), and every lever is registered in HANDLER_CONCURRENCY_ENV_VARS — a forgot-a-knob guard
        // so a new concurrency field can't silently lose its env override and get pinned back into a
        // `boatramp.cfg`. `serve_concurrency = 0` is the MEANINGFUL "disable the gate" value and must
        // round-trip as `Some(0)`, not be dropped.
        let mut cfg = ServerConfig::default();
        assert!(cfg.handlers.is_none());
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_HANDLERS_SERVE_CONCURRENCY", "0"),
            ("BOATRAMP_HANDLERS_SYNC_MAX_CONCURRENCY", "128"),
            ("BOATRAMP_HANDLERS_ASYNC_MAX_CONCURRENCY", "16"),
        ]))
        .expect("valid env overrides apply");
        let h = cfg.handlers.expect("handlers materialised from env");
        assert_eq!(h.serve_concurrency, Some(0), "0 = disable must round-trip");
        assert_eq!(h.sync_max_concurrency, Some(128));
        assert_eq!(h.async_max_concurrency, Some(16));
        for var in [
            "BOATRAMP_HANDLERS_SERVE_CONCURRENCY",
            "BOATRAMP_HANDLERS_SYNC_MAX_CONCURRENCY",
            "BOATRAMP_HANDLERS_ASYNC_MAX_CONCURRENCY",
        ] {
            assert!(
                HANDLER_CONCURRENCY_ENV_VARS.contains(&var),
                "{var} missing from HANDLER_CONCURRENCY_ENV_VARS — a concurrency knob lost its env lever"
            );
        }
    }

    #[test]
    fn env_wires_the_blob_hedge_knobs_over_the_default() {
        // The hedged-read tail knobs are env-settable so a file-less fleet can turn hedging on and tune
        // it; every lever is registered in HANDLER_BLOB_HEDGE_ENV_VARS (forgot-a-knob guard).
        let mut cfg = ServerConfig::default();
        assert!(cfg.handlers.is_none());
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_HANDLERS_BLOB_HEDGE_DELAY_MS", "80"),
            ("BOATRAMP_HANDLERS_BLOB_HEDGE_MAX_INFLIGHT", "24"),
            ("BOATRAMP_HANDLERS_BLOB_READ_CACHE_BYTES", "268435456"),
        ]))
        .expect("valid env overrides apply");
        let h = cfg.handlers.expect("handlers materialised from env");
        assert_eq!(h.blob_hedge_delay_ms, Some(80));
        assert_eq!(h.blob_hedge_max_inflight, Some(24));
        assert_eq!(h.blob_read_cache_bytes, Some(268_435_456));
        for var in [
            "BOATRAMP_HANDLERS_BLOB_HEDGE_DELAY_MS",
            "BOATRAMP_HANDLERS_BLOB_HEDGE_MAX_INFLIGHT",
            "BOATRAMP_HANDLERS_BLOB_READ_CACHE_BYTES",
        ] {
            assert!(
                HANDLER_BLOB_HEDGE_ENV_VARS.contains(&var),
                "{var} missing from HANDLER_BLOB_HEDGE_ENV_VARS — a blob-read knob lost its env lever"
            );
        }
    }

    #[test]
    fn env_wires_the_coldstart_knobs_over_the_default() {
        // The warm floor + portable AOT cache (cap-req 09) are env-settable (12-factor parity);
        // every lever is registered in HANDLER_COLDSTART_ENV_VARS — a forgot-a-knob guard.
        let mut cfg = ServerConfig::default();
        assert!(cfg.handlers.is_none());
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_HANDLERS_KEEP_WARM_MAX", "8"),
            ("BOATRAMP_HANDLERS_AOT_ARTIFACT_CACHE", "true"),
            ("BOATRAMP_HANDLERS_AOT_ARTIFACT_MAX_BYTES", "268435456"),
        ]))
        .expect("valid env overrides apply");
        let h = cfg.handlers.expect("handlers materialised from env");
        assert_eq!(h.keep_warm_max, Some(8));
        assert_eq!(h.aot_artifact_cache, Some(true));
        assert_eq!(h.aot_artifact_max_bytes, Some(268_435_456));
        for var in [
            "BOATRAMP_HANDLERS_KEEP_WARM_MAX",
            "BOATRAMP_HANDLERS_AOT_ARTIFACT_CACHE",
            "BOATRAMP_HANDLERS_AOT_ARTIFACT_MAX_BYTES",
        ] {
            assert!(
                HANDLER_COLDSTART_ENV_VARS.contains(&var),
                "{var} missing from HANDLER_COLDSTART_ENV_VARS — a cold-start knob lost its env lever"
            );
        }
    }

    #[test]
    fn env_wires_the_s3_ingress_cloud_knobs_over_the_default() {
        // The blob-upload minter's cloud-brokering policy is env-settable, so the Tigris presigned-only
        // deployment needs no `boatramp.cfg` for it. Every lever is registered in
        // S3_INGRESS_CLOUD_ENV_VARS (forgot-a-knob guard). The signing credential is NOT here — it stays
        // the sealed `[secrets]` one; these are policy toggles only.
        let mut cfg = ServerConfig::default();
        assert!(cfg.serve.is_none());
        cfg.apply_env_overrides(&env(&[(
            "BOATRAMP_S3_INGRESS_CLOUD_AWS_PRESIGNED_ONLY",
            "true",
        )]))
        .expect("valid env overrides apply");
        let ic = cfg
            .serve
            .expect("serve materialised from env")
            .s3_ingress_cloud
            .expect("s3_ingress_cloud materialised from env");
        assert!(ic.aws_presigned_only, "presigned-only toggled on via env");
        assert!(
            !ic.aws_use_federation_token,
            "untouched toggle stays default"
        );
        assert!(ic.aws_role_arn.is_none(), "untouched field stays None");
        for var in S3_INGRESS_CLOUD_ENV_VARS {
            assert!(
                var.starts_with("BOATRAMP_S3_INGRESS_CLOUD_"),
                "{var} is not an s3_ingress_cloud lever"
            );
        }
    }

    #[test]
    fn env_wires_the_per_project_blob_backend_over_the_default() {
        // PLAN-per-project-blob-backend: a keyed `[serve.blob_backends.<project>]` map discovered from
        // the env with NO config file, mirroring the SQL `databases` map. The project name may contain
        // underscores (name isolation strips the LONGEST field suffix). The sealed credential is a
        // REFERENCE (`boatramp:`/`env:`), never the raw secret (invariant 3).
        let mut cfg = ServerConfig::default();
        assert!(cfg.serve.is_none());
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_SERVE_BLOB_BACKEND_acme_eu_KIND", "s3"),
            (
                "BOATRAMP_SERVE_BLOB_BACKEND_acme_eu_S3_BUCKET",
                "acme-eu-blobs",
            ),
            (
                "BOATRAMP_SERVE_BLOB_BACKEND_acme_eu_S3_ENDPOINT",
                "https://s3.eu.example.com",
            ),
            ("BOATRAMP_SERVE_BLOB_BACKEND_acme_eu_S3_REGION", "eu-west-1"),
            ("BOATRAMP_SERVE_BLOB_BACKEND_acme_eu_S3_PATH_STYLE", "true"),
            (
                "BOATRAMP_SERVE_BLOB_BACKEND_acme_eu_S3_ACCESS_KEY_ID",
                "AKIAACME",
            ),
            (
                "BOATRAMP_SERVE_BLOB_BACKEND_acme_eu_S3_SECRET_ACCESS_KEY",
                "boatramp:acme-eu-s3",
            ),
        ]))
        .expect("valid per-project blob-backend env overrides apply");
        let serve = cfg.serve.expect("serve materialised from env");
        let be = serve.blob_backends.get("acme_eu").expect(
            "the acme_eu per-project backend was discovered from env (underscore survives name \
             isolation)",
        );
        assert_eq!(be.blobs, Some(crate::backends::BlobBackend::S3));
        assert_eq!(be.s3_bucket.as_deref(), Some("acme-eu-blobs"));
        assert_eq!(be.s3_endpoint.as_deref(), Some("https://s3.eu.example.com"));
        assert_eq!(be.s3_region.as_deref(), Some("eu-west-1"));
        assert!(be.s3_path_style);
        let cred = be
            .s3_credential
            .as_ref()
            .expect("sealed credential materialised from its two refs");
        assert_eq!(cred.access_key_id, "AKIAACME");
        // The secret is the REFERENCE as written — never an inlined secret value (invariant 3).
        assert_eq!(cred.secret_access_key, "boatramp:acme-eu-s3");
    }

    #[test]
    fn blob_backend_env_covers_every_field() {
        // Forgot-a-knob guard (mirrors the SQL-DB + hedge guards): every field of `BlobBackendConfig`
        // reachable from config MUST have an env suffix in `BLOB_BACKEND_FIELD_SUFFIXES`, so a newly
        // added field can't silently lose its env lever. Set every suffix for one project and assert
        // each field landed; assert the suffix set is exactly the expected one (no stale/missing lever).
        let expected: &[&str] = &[
            "_KIND",
            "_S3_BUCKET",
            "_S3_ENDPOINT",
            "_S3_REGION",
            "_S3_PATH_STYLE",
            "_S3_ACCESS_KEY_ID",
            "_S3_SECRET_ACCESS_KEY",
        ];
        for suffix in expected {
            assert!(
                BLOB_BACKEND_FIELD_SUFFIXES.contains(suffix),
                "{suffix} missing from BLOB_BACKEND_FIELD_SUFFIXES — a blob-backend field lost its \
                 env lever"
            );
        }
        assert_eq!(
            BLOB_BACKEND_FIELD_SUFFIXES.len(),
            expected.len(),
            "BLOB_BACKEND_FIELD_SUFFIXES has a suffix with no matching expected field (stale lever)"
        );
    }

    #[test]
    fn env_wires_an_inbound_tcp_listener_with_no_file() {
        // PLAN-handler-tcp-inbound: a keyed `[serve.listeners.<name>]` map discovered from env with NO
        // config file (mirrors the blob-backend map). The listener name may contain underscores (name
        // isolation strips the LONGEST field suffix — `edge_api` survives).
        let mut cfg = ServerConfig::default();
        assert!(cfg.serve.is_none());
        cfg.apply_env_overrides(&env(&[
            ("BOATRAMP_SERVE_LISTENER_edge_api_BIND", "0.0.0.0:9000"),
            ("BOATRAMP_SERVE_LISTENER_edge_api_COMPONENT", "echo.wasm"),
            ("BOATRAMP_SERVE_LISTENER_edge_api_PROJECT", "acme"),
            ("BOATRAMP_SERVE_LISTENER_edge_api_SITE", "prod"),
            (
                "BOATRAMP_SERVE_LISTENER_edge_api_IMPORTS",
                "sql,wasi:keyvalue",
            ),
            ("BOATRAMP_SERVE_LISTENER_edge_api_MAX_CONNS", "32"),
            ("BOATRAMP_SERVE_LISTENER_edge_api_IDLE_TIMEOUT_MS", "15000"),
            (
                "BOATRAMP_SERVE_LISTENER_edge_api_MAX_CONN_DURATION_MS",
                "120000",
            ),
        ]))
        .expect("valid inbound-TCP listener env overrides apply + validate");
        let serve = cfg.serve.expect("serve materialised from env");
        let l = serve.listeners.get("edge_api").expect(
            "the edge_api listener was discovered from env (underscore survives isolation)",
        );
        assert_eq!(l.bind, Some("0.0.0.0:9000".parse().unwrap()));
        assert_eq!(l.component, "echo.wasm");
        assert_eq!(l.project, "acme");
        assert_eq!(l.site, "prod");
        assert_eq!(
            l.imports,
            vec!["sql".to_string(), "wasi:keyvalue".to_string()]
        );
        assert_eq!(l.max_conns, Some(32));
        assert_eq!(l.idle_timeout_ms, Some(15000));
        assert_eq!(l.max_conn_duration_ms, Some(120000));
    }

    #[test]
    fn listener_validation_fails_closed() {
        // A half-declared or Phase-1-unsupported listener REFUSES the node (boot-LOUD), never binds
        // something that would silently mislead the operator (PLAN-handler-tcp-inbound).
        // (a) a missing bind.
        let err = ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( component: "c.wasm", project: "p", site: "s" ) } ) )"#,
        )
        .expect_err("a listener with no bind must be refused");
        assert!(
            matches!(err, ConfigError::InvalidListener { .. }),
            "{err:?}"
        );
        // (b) a `tls` block MISSING cert_file/key_file is refused (cap-req 06: host-TLS needs both).
        let err = ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:9000", component: "c.wasm", project: "p", site: "s", tls: ( cert_file: "x.pem" ) ) } ) )"#,
        )
        .expect_err("a tls block without a key_file must be refused");
        assert!(
            matches!(err, ConfigError::InvalidListener { .. }),
            "{err:?}"
        );
        // (c) a non-empty egress_allowlist now PARSES (cap-req 19: it drives the listener guest's
        // HOST-MEDIATED `tcp-egress` dials; the guest still never holds raw `wasi:sockets`).
        ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:9000", component: "c.wasm", project: "p", site: "s", egress_allowlist: ["x:443"] ) } ) )"#,
        )
        .expect("a per-listener egress_allowlist is valid (host-mediated tcp-egress, cap-req 19)");
        // (d) a valid plaintext listener parses.
        ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:9000", component: "c.wasm", project: "p", site: "s" ) } ) )"#,
        )
        .expect("a fully-declared plaintext listener is valid");
        // (e) a well-formed TLS listener (cert + key) now PARSES (cap-req 06).
        ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:9000", component: "c.wasm", project: "p", site: "s", tls: ( cert_file: "x.pem", key_file: "y.pem" ) ) } ) )"#,
        )
        .expect("a TLS listener with cert_file + key_file is valid");
        // (f) a well-formed STARTTLS listener (cert + key + grammar) PARSES (cap-req 06, Stage B) —
        //     SMTP-shaped and IMAP tag-capture-shaped.
        ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:587", component: "c.wasm", project: "p", site: "s", tls: ( cert_file: "x.pem", key_file: "y.pem", starttls: ( trigger: "STARTTLS", response: "220 2.0.0 Ready to start TLS" ) ) ) } ) )"#,
        )
        .expect("a well-formed SMTP STARTTLS listener is valid");
        ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:143", component: "c.wasm", project: "p", site: "s", tls: ( cert_file: "x.pem", key_file: "y.pem", starttls: ( trigger: "STARTTLS", response: "{tag} OK begin TLS", tag_capture: true ) ) ) } ) )"#,
        )
        .expect("a well-formed IMAP tag-capture STARTTLS listener is valid");
        // (g) `{tag}` in the response without tag_capture is refused (the literal would leak to the wire).
        let err = ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:587", component: "c.wasm", project: "p", site: "s", tls: ( cert_file: "x.pem", key_file: "y.pem", starttls: ( trigger: "STARTTLS", response: "{tag} OK" ) ) ) } ) )"#,
        )
        .expect_err("`{tag}` without tag_capture must be refused");
        assert!(
            matches!(err, ConfigError::InvalidListener { .. }),
            "{err:?}"
        );
        // (h) an empty trigger is refused.
        let err = ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:587", component: "c.wasm", project: "p", site: "s", tls: ( cert_file: "x.pem", key_file: "y.pem", starttls: ( trigger: "", response: "220 ok" ) ) ) } ) )"#,
        )
        .expect_err("an empty STARTTLS trigger must be refused");
        assert!(
            matches!(err, ConfigError::InvalidListener { .. }),
            "{err:?}"
        );
        // (i) a STARTTLS grammar WITHOUT cert/key is refused (STARTTLS still terminates TLS).
        let err = ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:587", component: "c.wasm", project: "p", site: "s", tls: ( starttls: ( trigger: "STARTTLS", response: "220 ok" ) ) ) } ) )"#,
        )
        .expect_err("a STARTTLS grammar without cert/key must be refused");
        assert!(
            matches!(err, ConfigError::InvalidListener { .. }),
            "{err:?}"
        );
        // (j) a listener `tls.on_demand = true` WITHOUT node on-demand TLS enabled is refused (cap-req
        //     03 #4): the per-SNI engine it would share does not exist, so it would silently no-op.
        let err = ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:465", component: "c.wasm", project: "p", site: "s", tls: ( cert_file: "x.pem", key_file: "y.pem", on_demand: true ) ) } ) )"#,
        )
        .expect_err("listener on_demand without [serve.on_demand_tls] enabled must be refused");
        assert!(
            matches!(err, ConfigError::InvalidListener { .. }),
            "{err:?}"
        );
        // (k) the same listener WITH node on-demand TLS enabled (+ its own cert/key + server_names)
        //     parses — it shares the one engine.
        ServerConfig::parse(
            r#"( serve: ( on_demand_tls: ( enabled: true ), listeners: { "l": ( bind: "0.0.0.0:465", component: "c.wasm", project: "p", site: "s", tls: ( cert_file: "x.pem", key_file: "y.pem", on_demand: true, server_names: ["mail.example.test"] ) ) } ) )"#,
        )
        .expect("a listener on_demand with node on-demand TLS enabled is valid");
        // (l) `proxy_protocol = true` with NO trusted CIDRs and NO trust-any opt-in is REFUSED
        //     (senior-architect review — OWNER DECISION: require a trusted source; a header from any
        //     source is spoofable). Fail-closed, boot-loud.
        let err = ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:9000", component: "c.wasm", project: "p", site: "s", proxy_protocol: true ) } ) )"#,
        )
        .expect_err("proxy_protocol with no trusted CIDRs and no trust-any must be refused");
        assert!(
            matches!(err, ConfigError::InvalidListener { .. }),
            "{err:?}"
        );
        // (m) `proxy_protocol = true` with a non-empty trusted-CIDR set parses (the normal case).
        ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:9000", component: "c.wasm", project: "p", site: "s", proxy_protocol: true, proxy_protocol_trusted_cidrs: ["10.0.0.0/8"] ) } ) )"#,
        )
        .expect("proxy_protocol with trusted CIDRs is valid");
        // (n) `proxy_protocol = true` with the explicit `proxy_protocol_trust_any` opt-in (and empty
        //     CIDRs) parses — the firewall-only mode the operator must now opt into deliberately.
        ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:9000", component: "c.wasm", project: "p", site: "s", proxy_protocol: true, proxy_protocol_trust_any: true ) } ) )"#,
        )
        .expect("proxy_protocol with the trust-any opt-in parses");
        // (o) an out-of-range IPv6 rate-limit bucket prefix is refused; a valid one parses.
        let err = ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:9000", component: "c.wasm", project: "p", site: "s", conn_rate_ipv6_prefix: 129 ) } ) )"#,
        )
        .expect_err("conn_rate_ipv6_prefix > 128 must be refused");
        assert!(
            matches!(err, ConfigError::InvalidListener { .. }),
            "{err:?}"
        );
        ServerConfig::parse(
            r#"( serve: ( listeners: { "l": ( bind: "0.0.0.0:9000", component: "c.wasm", project: "p", site: "s", conn_rate_ipv6_prefix: 56 ) } ) )"#,
        )
        .expect("a valid conn_rate_ipv6_prefix parses");
    }

    #[test]
    fn listener_env_covers_every_scalar_field() {
        // Forgot-a-knob guard (mirrors the blob-backend guard): every SCALAR field of `ListenerConfig`
        // with an env lever MUST have a suffix in `LISTENER_FIELD_SUFFIXES`, so a newly added scalar
        // can't silently lose its env knob. (The structured `imports`/`env`/`tenancy` + Phase-1-refused
        // `tls`/`egress_allowlist` are deliberately file-only; `_IMPORTS` is the one list lever.)
        let expected: &[&str] = &[
            "_BIND",
            "_COMPONENT",
            "_PROJECT",
            "_SITE",
            "_IMPORTS",
            "_MAX_CONNS",
            "_IDLE_TIMEOUT_MS",
            "_MAX_CONN_DURATION_MS",
        ];
        for suffix in expected {
            assert!(
                LISTENER_FIELD_SUFFIXES.contains(suffix),
                "{suffix} missing from LISTENER_FIELD_SUFFIXES — a listener field lost its env lever"
            );
        }
        assert_eq!(
            LISTENER_FIELD_SUFFIXES.len(),
            expected.len(),
            "LISTENER_FIELD_SUFFIXES has a suffix with no matching expected field (stale lever)"
        );
    }

    #[test]
    fn blob_backend_rejects_the_reserved_default_project() {
        // Invariant 5: the reserved `default` project ALWAYS resolves the global `[serve]` backend, so
        // a `[serve.blob_backends.default]` entry is refused at load (fail-closed, boot-loud) — the
        // node-wide backend is configured under `[serve]`, not here.
        let err = ServerConfig::parse(
            r#"( serve: ( blob_backends: { "default": ( blobs: s3, s3_bucket: "x" ) } ) )"#,
        )
        .expect_err("a `default`-keyed per-project blob backend must be refused");
        assert!(
            matches!(err, ConfigError::InvalidBlobBackendProject { .. }),
            "reserved-default blob backend is InvalidBlobBackendProject, got {err:?}"
        );
    }

    #[test]
    fn blob_backend_rejects_an_unsafe_project_name() {
        // A `blob_backends` key is a project name threaded into the per-project data-plane scope, so it
        // runs the canonical slug validator (fail-closed on a path-traversal / injection shape).
        let err = ServerConfig::parse(
            r#"( serve: ( blob_backends: { "../evil": ( blobs: s3, s3_bucket: "x" ) } ) )"#,
        )
        .expect_err("a path-traversal project key must be refused");
        assert!(
            matches!(err, ConfigError::InvalidBlobBackendProject { .. }),
            "unsafe blob-backend project name is InvalidBlobBackendProject, got {err:?}"
        );
    }

    #[test]
    fn blob_backend_config_rejects_unknown_fields_and_inlined_secret_stays_a_ref() {
        // `deny_unknown_fields` on `BlobBackendConfig` + its `S3CredentialConfig` catches a typo'd key
        // at load; and the sealed credential's `secret_access_key` is stored verbatim as the REFERENCE
        // the operator wrote (a `boatramp:` name), never re-interpreted into a raw secret.
        let cfg = ServerConfig::parse(
            r#"( serve: ( blob_backends: { "acme": (
                blobs: s3,
                s3_bucket: "acme-blobs",
                s3_credential: ( access_key_id: "AKIA", secret_access_key: "boatramp:acme" ),
            ) } ) )"#,
        )
        .expect("a well-formed per-project blob backend parses");
        let be = cfg
            .serve
            .unwrap()
            .blob_backends
            .remove("acme")
            .expect("acme backend parsed");
        assert_eq!(be.blobs, Some(crate::backends::BlobBackend::S3));
        assert_eq!(
            be.s3_credential.unwrap().secret_access_key,
            "boatramp:acme",
            "the secret stays the indirect reference, never an inlined secret"
        );
        let bad = ServerConfig::parse(
            r#"( serve: ( blob_backends: { "acme": ( blobs: s3, bogus: 1 ) } ) )"#,
        );
        assert!(
            bad.is_err(),
            "an unknown [serve.blob_backends.<p>] field must be rejected (deny_unknown_fields)"
        );
    }

    #[test]
    fn sql_binding_preview_policy() {
        let cfg = server(
            r#"(
                handlers: ( bindings: ( sql: (
                    preview_mode: "branch",
                    preview_init: "/etc/boatramp/seed.sql",
                ) ) ),
            )"#,
        );
        let sql = cfg.handlers.unwrap().bindings.sql.unwrap();
        assert_eq!(sql.preview_mode.as_deref(), Some("branch"));
        assert_eq!(
            sql.preview_init.as_deref(),
            Some(Path::new("/etc/boatramp/seed.sql"))
        );
    }

    #[test]
    fn sql_binding_external_databases() {
        let cfg = server(
            r#"(
                handlers: ( bindings: ( sql: (
                    databases: {
                        "analytics": (
                            kind: "postgres",
                            url_env: "ANALYTICS_PG_URL",
                            pool_max: 16,
                            read_only: true,
                        ),
                        "events": (
                            kind: "mysql",
                            url_env: "EVENTS_MYSQL_URL",
                            read_url_env: "EVENTS_MYSQL_REPLICA_URL",
                            allow_preview: true,
                        ),
                    },
                ) ) ),
            )"#,
        );
        let sql = cfg.handlers.unwrap().bindings.sql.unwrap();
        assert_eq!(sql.databases.len(), 2);

        let analytics = &sql.databases["analytics"];
        assert_eq!(analytics.kind, "postgres");
        assert_eq!(analytics.url_env, "ANALYTICS_PG_URL");
        assert_eq!(analytics.pool_max, Some(16));
        assert!(analytics.read_only);
        assert!(!analytics.allow_preview);
        assert!(analytics.read_url_env.is_none());

        let events = &sql.databases["events"];
        assert_eq!(events.kind, "mysql");
        assert_eq!(
            events.read_url_env.as_deref(),
            Some("EVENTS_MYSQL_REPLICA_URL")
        );
        assert!(events.allow_preview);
        assert!(!events.read_only);
    }

    #[test]
    fn sql_binding_compute_backed_database() {
        let cfg = server(
            r#"(
                handlers: ( bindings: ( sql: (
                    databases: {
                        "analytics": (
                            kind: "postgres",
                            compute: "pg",
                            database: "analytics",
                            user: "app",
                            password_env: "PG_APP_PW",
                        ),
                    },
                ) ) ),
            )"#,
        );
        let db = &cfg.handlers.unwrap().bindings.sql.unwrap().databases["analytics"];
        assert_eq!(db.kind, "postgres");
        assert_eq!(db.compute.as_deref(), Some("pg"));
        assert_eq!(db.database.as_deref(), Some("analytics"));
        assert_eq!(db.user.as_deref(), Some("app"));
        assert_eq!(db.password_env.as_deref(), Some("PG_APP_PW"));
        assert!(db.url_env.is_empty(), "compute-backed has no url_env");
        assert!(db.validate("analytics").is_ok());
    }

    #[test]
    fn sql_binding_source_is_exactly_one_of_url_or_compute() {
        // Neither source → error.
        assert!(ExternalDatabaseConfig::default().validate("db").is_err());
        // Both sources → error.
        let both = ExternalDatabaseConfig {
            kind: "postgres".into(),
            url_env: "PG_URL".into(),
            compute: Some("pg".into()),
            ..Default::default()
        };
        assert!(both.validate("db").is_err());
        // `url_env` only → ok.
        let url = ExternalDatabaseConfig {
            kind: "postgres".into(),
            url_env: "PG_URL".into(),
            ..Default::default()
        };
        assert!(url.validate("db").is_ok());
        // `compute` without the connection details boatramp can't infer → error.
        let bare = ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: Some("pg".into()),
            ..Default::default()
        };
        assert!(bare.validate("db").is_err());
        // `compute` with database/user + a bring-your-own `password_env` → ok, and
        // is *not* a managed credential.
        let byo = ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: Some("pg".into()),
            database: Some("analytics".into()),
            user: Some("app".into()),
            password_env: Some("PG_APP_PW".into()),
            ..Default::default()
        };
        assert!(byo.validate("db").is_ok());
        assert!(!byo.is_managed_credential());
        // `compute` with database/user but NO `password_env` → ok, and boatramp
        // manages the credential (Phase 2).
        let managed = ExternalDatabaseConfig {
            kind: "postgres".into(),
            compute: Some("pg".into()),
            database: Some("analytics".into()),
            user: Some("app".into()),
            ..Default::default()
        };
        assert!(managed.validate("db").is_ok());
        assert!(managed.is_managed_credential());
    }

    #[test]
    fn libsql_source_is_exactly_one_of_path_or_url() {
        // A single-node `libsql` file (path only) → ok.
        let file = ExternalDatabaseConfig {
            kind: "libsql".into(),
            path: Some("/data/app.db".into()),
            ..Default::default()
        };
        assert!(file.validate("app").is_ok());
        // `sqlite` alias works the same.
        let sqlite = ExternalDatabaseConfig {
            kind: "sqlite".into(),
            path: Some("/data/app.db".into()),
            ..Default::default()
        };
        assert!(sqlite.validate("app").is_ok());
        // A remote-sqld `libsql` (url_env only) → ok.
        let remote = ExternalDatabaseConfig {
            kind: "libsql".into(),
            url_env: "LIBSQL_URL".into(),
            ..Default::default()
        };
        assert!(remote.validate("app").is_ok());
        // Neither `path` nor `url_env` → error.
        let neither = ExternalDatabaseConfig {
            kind: "libsql".into(),
            ..Default::default()
        };
        assert!(neither.validate("app").is_err());
        // Both `path` and `url_env` → error (exactly one).
        let both = ExternalDatabaseConfig {
            kind: "libsql".into(),
            path: Some("/data/app.db".into()),
            url_env: "LIBSQL_URL".into(),
            ..Default::default()
        };
        assert!(both.validate("app").is_err());
        // `compute` on a `libsql` binding → error (boatramp doesn't run a libsql server workload).
        let compute = ExternalDatabaseConfig {
            kind: "libsql".into(),
            compute: Some("x".into()),
            path: Some("/data/app.db".into()),
            ..Default::default()
        };
        assert!(compute.validate("app").is_err());
        // `path` on a NON-libsql (postgres) binding → error (only libsql has an on-disk file).
        let pg_path = ExternalDatabaseConfig {
            kind: "postgres".into(),
            url_env: "PG_URL".into(),
            path: Some("/data/app.db".into()),
            ..Default::default()
        };
        assert!(pg_path.validate("db").is_err());
    }

    /// Path to a file at the repo root (two levels up from this crate).
    fn repo_root_file(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(name)
    }

    #[test]
    fn shipped_project_example_parses() {
        // The example we ship must always parse + compile-check, so it can't drift
        // from the schema.
        let text = std::fs::read_to_string(repo_root_file("examples/site/project.cfg.example"))
            .expect("example project config is present");
        let cfg = ProjectConfig::parse(&text).expect("example project config parses");
        assert_eq!(cfg.publish.server.as_deref(), Some("http://127.0.0.1:8080"));
        assert_eq!(cfg.build.as_ref().unwrap().command, "npm run build");
        assert_eq!(
            cfg.routing.error_documents.get(&404).map(String::as_str),
            Some("/404.html")
        );
    }

    #[test]
    fn shipped_server_example_parses() {
        let text = std::fs::read_to_string(repo_root_file("boatramp.cfg.example"))
            .expect("example server config is present");
        let cfg = ServerConfig::parse(&text).expect("example server config parses");
        let serve = cfg.serve.expect("example sets a serve section");
        assert_eq!(
            serve.addr,
            Some("0.0.0.0:8080".parse::<std::net::SocketAddr>().unwrap())
        );
    }

    #[test]
    fn secrets_section_parses_local_and_vault() {
        let local = server(r#"( secrets: ( envelope: "local", kek_file: "/k/kek" ) )"#)
            .secrets
            .expect("secrets section");
        assert_eq!(local.envelope, "local");
        assert_eq!(
            local.kek_file.as_deref(),
            Some(std::path::Path::new("/k/kek"))
        );

        let vault = server(
            r#"( secrets: ( envelope: "vault", vault: ( addr: "https://vault:8200", key: "certs" ) ) )"#,
        )
        .secrets
        .expect("secrets section");
        let v = vault.vault.expect("vault subsection");
        assert_eq!(v.addr, "https://vault:8200");
        assert_eq!(v.key, "certs");
        // The token env defaults to VAULT_TOKEN and is never in the file.
        assert_eq!(v.token_env, "VAULT_TOKEN");
    }

    #[test]
    fn serve_section_partial_parses() {
        // A partial `serve` section parses — unset fields take their defaults.
        let cfg = server(r#"( serve: ( addr: "0.0.0.0:8080", protect_previews: true ) )"#);
        let serve = cfg.serve.unwrap();
        assert_eq!(
            serve.addr,
            Some("0.0.0.0:8080".parse::<std::net::SocketAddr>().unwrap())
        );
        assert!(serve.protect_previews);
        assert!(!serve.cluster_rate_limit);
        assert!(serve.data_dir.is_none());
    }

    #[test]
    fn serve_console_config_parses() {
        // Absent ⇒ no console.
        let cfg = server(r#"( serve: ( addr: "0.0.0.0:8080" ) )"#);
        assert!(cfg.serve.unwrap().console.is_none());
        // Explicit console block with host + path.
        let cfg = server(
            r#"( serve: ( console: (
                enabled: true,
                host: "console.example.com",
                path: "/_console",
            ) ) )"#,
        );
        let console = cfg.serve.unwrap().console.unwrap();
        assert!(console.enabled);
        assert_eq!(console.host.as_deref(), Some("console.example.com"));
        assert_eq!(console.path.as_deref(), Some("/_console"));
        // Bare `enabled` ⇒ host/path take their (server-side) defaults.
        let cfg = server(r#"( serve: ( console: ( enabled: true ) ) )"#);
        let console = cfg.serve.unwrap().console.unwrap();
        assert!(console.enabled);
        assert!(console.host.is_none() && console.path.is_none());
    }

    #[test]
    fn serve_s3_credential_config_parses() {
        // #505: absent ⇒ no sealed source (the ambient AWS env chain).
        let cfg = server(r#"( serve: ( addr: "0.0.0.0:8080" ) )"#);
        assert!(cfg.serve.unwrap().s3_credential.is_none());
        // An explicit `[serve.s3_credential]`: a plain `access_key_id` + a `boatramp:` sealed
        // `secret_access_key` ref (the config text carries only the REFERENCE, never the secret).
        let cfg = server(
            r#"( serve: ( s3_credential: (
                access_key_id: "tid_public_akid",
                secret_access_key: "boatramp:tigris-secret",
            ) ) )"#,
        );
        let cred = cfg.serve.unwrap().s3_credential.unwrap();
        assert_eq!(cred.access_key_id, "tid_public_akid");
        assert_eq!(cred.secret_access_key, "boatramp:tigris-secret");
        // An unknown field is rejected (`deny_unknown_fields`) — a fat-fingered key fails fast.
        let err: Result<ServerConfig, _> = ron_options().from_str(
            r#"( serve: ( s3_credential: ( access_key_id: "x", secret_access_key: "boatramp:y", bogus: 1 ) ) )"#,
        );
        assert!(
            err.is_err(),
            "unknown [serve.s3_credential] field must be rejected"
        );
    }

    #[test]
    fn serve_blob_fallback_config_parses() {
        // Blob-backend migration Part 2: absent ⇒ no fallback (the read-through composite is not wired).
        let cfg = server(r#"( serve: ( addr: "0.0.0.0:8080" ) )"#);
        assert!(cfg.serve.unwrap().blob_fallback.is_none());
        // A `[serve.blob_fallback]` secondary: the OLD fs backend to drain while the primary is s3,
        // with its own sealed S3 credential ref and a custom secondary timeout.
        let cfg = server(
            r#"( serve: (
                blobs: s3,
                s3_bucket: "new-bucket",
                blob_fallback: (
                    blobs: fs,
                    secondary_timeout_secs: 3,
                    s3_credential: (
                        access_key_id: "old_akid",
                        secret_access_key: "boatramp:old-secret",
                    ),
                ),
            ) )"#,
        );
        let serve = cfg.serve.unwrap();
        let fb = serve.blob_fallback.unwrap();
        assert_eq!(fb.blobs, Some(crate::backends::BlobBackend::Fs));
        assert_eq!(fb.secondary_timeout_secs, Some(3));
        let cred = fb.s3_credential.unwrap();
        assert_eq!(cred.access_key_id, "old_akid");
        assert_eq!(cred.secret_access_key, "boatramp:old-secret");
        // An unknown field is rejected (`deny_unknown_fields`).
        let err: Result<ServerConfig, _> =
            ron_options().from_str(r#"( serve: ( blob_fallback: ( blobs: fs, bogus: 1 ) ) )"#);
        assert!(
            err.is_err(),
            "unknown [serve.blob_fallback] field must be rejected"
        );
    }

    #[test]
    fn serve_kv_config_parses_and_defaults() {
        // Absent `[serve.kv]` ⇒ the defaults: periodic checkpoint ON at the default cadence, and the
        // generous default close budget (NOT the old 3s).
        let cfg = server(r#"( serve: ( addr: "0.0.0.0:8080" ) )"#);
        assert!(cfg.serve.unwrap().kv.is_none());
        let default_kv = super::KvConfig::default();
        assert_eq!(
            default_kv.checkpoint_interval(),
            Some(std::time::Duration::from_secs(
                super::DEFAULT_KV_CHECKPOINT_INTERVAL_SECS
            )),
            "an absent/unset checkpoint_interval defaults to the ON cadence"
        );
        assert_eq!(
            default_kv.close_deadline(),
            std::time::Duration::from_secs(super::DEFAULT_KV_CLOSE_DEADLINE_SECS),
            "an absent/unset close_deadline defaults to the generous budget"
        );
        // The online maintenance-GC knobs default ON (15 min) with a conservative 1h min_age.
        assert_eq!(
            default_kv.gc_interval(),
            Some(std::time::Duration::from_secs(
                super::DEFAULT_KV_GC_INTERVAL_SECS
            )),
            "an absent/unset gc_interval defaults to the ON cadence"
        );
        assert_eq!(
            default_kv.gc_min_age(),
            std::time::Duration::from_secs(super::DEFAULT_KV_GC_MIN_AGE_SECS),
            "an absent/unset gc_min_age defaults to the conservative 1h floor"
        );

        // An explicit block: a tuned cadence + a tuned close budget + tuned GC knobs, now nested under
        // `slatedb` (UX-C3) so they never appear to apply under a non-SlateDB backend.
        let cfg = server(
            r#"( serve: ( kv: ( slatedb: ( checkpoint_interval: 5, close_deadline: 30, gc_interval: 300, gc_min_age: 600 ) ) ) )"#,
        );
        let kv = cfg.serve.unwrap().kv.unwrap();
        assert_eq!(
            kv.checkpoint_interval(),
            Some(std::time::Duration::from_secs(5))
        );
        assert_eq!(kv.close_deadline(), std::time::Duration::from_secs(30));
        assert_eq!(kv.gc_interval(), Some(std::time::Duration::from_secs(300)));
        assert_eq!(kv.gc_min_age(), std::time::Duration::from_secs(600));

        // checkpoint_interval = 0 DISABLES the cadence; a 0 close_deadline falls back to the default
        // (a zero close budget would abandon every close, guaranteeing a torn tail — never allowed).
        // gc_interval = 0 DISABLES the maintenance task; a 0 gc_min_age clamps up to the default (a
        // zero min_age would reintroduce the reader-mid-scan deletion hazard — never allowed).
        let cfg = server(
            r#"( serve: ( kv: ( slatedb: ( checkpoint_interval: 0, close_deadline: 0, gc_interval: 0, gc_min_age: 0 ) ) ) )"#,
        );
        let kv = cfg.serve.unwrap().kv.unwrap();
        assert_eq!(kv.checkpoint_interval(), None, "0 disables the cadence");
        assert_eq!(
            kv.close_deadline(),
            std::time::Duration::from_secs(super::DEFAULT_KV_CLOSE_DEADLINE_SECS),
            "a 0 close_deadline is clamped up to the default, never zero"
        );
        assert_eq!(kv.gc_interval(), None, "0 disables the maintenance GC task");
        assert_eq!(
            kv.gc_min_age(),
            std::time::Duration::from_secs(super::DEFAULT_KV_GC_MIN_AGE_SECS),
            "a 0 gc_min_age is clamped up to the conservative default, never zero"
        );

        // The SQL KV backend connection parses under `sql` (UX-C2: `url_env`, never a raw URL).
        let cfg = server(r#"( serve: ( kv: ( sql: ( kind: "sqlite", path: "/data/kv.db" ) ) ) )"#);
        let sql = cfg.serve.unwrap().kv.unwrap().sql.unwrap();
        assert_eq!(sql.kind, "sqlite");
        assert_eq!(sql.path.as_deref(), Some("/data/kv.db"));

        // UX-C3: a pre-v0.12.0 TOP-LEVEL durability knob now fails loud (it moved under `slatedb`),
        // never silently mislead — `deny_unknown_fields` rejects it at the `[serve.kv]` level.
        let err: Result<ServerConfig, _> =
            ron_options().from_str(r#"( serve: ( kv: ( checkpoint_interval: 5 ) ) )"#);
        assert!(
            err.is_err(),
            "a top-level checkpoint_interval must be rejected (moved under [serve.kv.slatedb])"
        );

        // An unknown field inside the `slatedb` sub-block is rejected (`deny_unknown_fields`).
        let err: Result<ServerConfig, _> = ron_options()
            .from_str(r#"( serve: ( kv: ( slatedb: ( checkpoint_interval: 5, bogus: 1 ) ) ) )"#);
        assert!(
            err.is_err(),
            "unknown [serve.kv.slatedb] field must be rejected"
        );
    }

    // =======================================================================
    // JSON config input gate (v0.6.5) — serve/project config + detection half.
    //
    // ROBUST-successor gate (continuing the v0.6.4 blob-purge style): a `#[test]`
    // battery whose sole CI contract is the ordinary `cargo test` exit code — NO
    // grepped uppercase marker, NO bash env-var mutation loop. Every test is prefixed
    // `config_json_gate_` so the CI lane filters with `cargo test … config_json`. The
    // apply-manifest half (version current-schema-only, bad-route compile-check) lives
    // in `boatramp::apply`'s test module under the same prefix.
    // =======================================================================

    /// Detection: `resolve_format` follows the explicit-override-wins, else
    /// `.json`⇒Json / everything-else⇒Ron rule (no content-sniffing).
    #[test]
    fn config_json_gate_resolve_format_table() {
        use std::path::Path;
        // Auto by extension.
        assert_eq!(
            resolve_format(Path::new("boatramp.json"), None),
            ConfigFormat::Json
        );
        assert_eq!(
            resolve_format(Path::new("apply.cfg"), None),
            ConfigFormat::Ron
        );
        assert_eq!(
            resolve_format(Path::new("apply.ron"), None),
            ConfigFormat::Ron
        );
        // No extension ⇒ Ron.
        assert_eq!(resolve_format(Path::new("apply"), None), ConfigFormat::Ron);
        // Case-insensitive `.json`.
        assert_eq!(
            resolve_format(Path::new("x.JSON"), None),
            ConfigFormat::Json
        );
        // Explicit override wins BOTH ways.
        assert_eq!(
            resolve_format(Path::new("x.json"), Some(ConfigFormat::Ron)),
            ConfigFormat::Ron
        );
        assert_eq!(
            resolve_format(Path::new("x.cfg"), Some(ConfigFormat::Json)),
            ConfigFormat::Json
        );
    }

    /// Equivalence: a representative serve config authored in RON and in equivalent
    /// JSON parses to the SAME field values — including the externally-tagged
    /// enum-variant field `[serve].blobs` (`BlobBackend::S3`; RON `s3` ≡ JSON `"s3"`),
    /// proving variant-name fidelity through the JSON decoder.
    #[test]
    fn config_json_gate_serve_ron_and_json_are_equivalent() {
        let ron = r#"( serve: ( addr: "0.0.0.0:8080", blobs: s3, s3_bucket: "b" ) )"#;
        let json = r#"{ "serve": { "addr": "0.0.0.0:8080", "blobs": "s3", "s3_bucket": "b" } }"#;
        let from_ron = ServerConfig::parse_with_format(ron, ConfigFormat::Ron).unwrap();
        let from_json = ServerConfig::parse_with_format(json, ConfigFormat::Json).unwrap();
        let s_ron = from_ron.serve.unwrap();
        let s_json = from_json.serve.unwrap();
        assert_eq!(s_ron.blobs, Some(crate::backends::BlobBackend::S3));
        assert_eq!(s_json.blobs, Some(crate::backends::BlobBackend::S3));
        assert_eq!(s_ron.blobs, s_json.blobs, "the enum variant survives JSON");
        assert_eq!(s_ron.addr, s_json.addr);
        assert_eq!(s_ron.s3_bucket, s_json.s3_bucket);
        assert_eq!(s_json.s3_bucket.as_deref(), Some("b"));
    }

    /// Equivalence (project): a `project.cfg` authored in RON and in equivalent JSON
    /// parses to the same publish target.
    #[test]
    fn config_json_gate_project_ron_and_json_are_equivalent() {
        let ron = r#"( publish: ( project: "team-x" ) )"#;
        let json = r#"{ "publish": { "project": "team-x" } }"#;
        let from_ron = ProjectConfig::parse_with_format(ron, ConfigFormat::Ron).unwrap();
        let from_json = ProjectConfig::parse_with_format(json, ConfigFormat::Json).unwrap();
        assert_eq!(from_ron.publish.project.as_deref(), Some("team-x"));
        assert_eq!(from_ron.publish.project, from_json.publish.project);
    }

    /// `deny_unknown_fields` parity: a JSON serve config with an extra/typo'd field is
    /// a hard parse error, not a silent drop (the `[serve.blob_fallback]`
    /// `deny_unknown_fields` struct is the RON parity partner tested above).
    #[test]
    fn config_json_gate_serve_json_denies_unknown_fields() {
        let json = r#"{ "serve": { "blob_fallback": { "blobs": "fs", "bogus": 1 } } }"#;
        assert!(
            ServerConfig::parse_with_format(json, ConfigFormat::Json).is_err(),
            "an unknown JSON field must be rejected (deny_unknown_fields), same as RON"
        );
    }

    /// No-bypass: post-parse validation runs regardless of format. A JSON serve config
    /// with an invalid `handlers.bindings.sql.databases` db-name (a `/`-bearing,
    /// non-URL-path-safe name) is rejected identically to RON — the SAME
    /// `ConfigError::InvalidDbName`, from the SAME `validate_sql_db_names` choke point.
    #[test]
    fn config_json_gate_json_bad_db_name_is_rejected_like_ron() {
        // The invalid binding name `a/b` (a path separator) fails the canonical
        // resource-name validator that `validate_sql_db_names` runs after the parse.
        let json = r#"{ "handlers": { "bindings": { "sql": {
            "databases": { "a/b": { "kind": "postgres", "url_env": "DB_URL" } }
        } } } }"#;
        let ron = r#"( handlers: ( bindings: ( sql: (
            databases: { "a/b": ( kind: "postgres", url_env: "DB_URL" ) }
        ) ) ) )"#;
        let json_err = ServerConfig::parse_with_format(json, ConfigFormat::Json)
            .expect_err("a bad db-name in a JSON config must be rejected");
        let ron_err = ServerConfig::parse_with_format(ron, ConfigFormat::Ron)
            .expect_err("a bad db-name in a RON config must be rejected");
        assert!(
            matches!(json_err, ConfigError::InvalidDbName { .. }),
            "JSON bad db-name is InvalidDbName, got {json_err:?}"
        );
        assert!(
            matches!(ron_err, ConfigError::InvalidDbName { .. }),
            "RON bad db-name is InvalidDbName, got {ron_err:?}"
        );
    }

    /// Anti-hollow (typed, in-process): a document valid as JSON but NOT as RON MUST
    /// parse under `Json` and FAIL under `Ron`. If `parse_with_format` ignored `fmt`
    /// and always decoded RON, the JSON leg would fail — so the format selection is
    /// proven load-bearing, with no env var and no marker.
    #[test]
    fn config_json_gate_serve_format_selection_is_load_bearing() {
        // A bare JSON object is valid JSON for `ServerConfig`, not valid RON for it
        // (RON structs use `( … )`, not a brace map).
        let doc = r#"{ "serve": { "s3_bucket": "only-json" } }"#;
        let as_json = ServerConfig::parse_with_format(doc, ConfigFormat::Json).unwrap();
        assert_eq!(
            as_json.serve.unwrap().s3_bucket.as_deref(),
            Some("only-json")
        );
        assert!(
            ServerConfig::parse_with_format(doc, ConfigFormat::Ron).is_err(),
            "the same document must FAIL under Ron — else the fmt selection is hollow"
        );
    }
}

// ============================================================================
// The single figment-based config resolver (serve + every offline op).
// ============================================================================
//
// This module is the config system (shipped in v0.35.0; design record in
// docs/config-figment-migration.md). `load_with_figment` merges, in order,
//   base-seed → file → `BOATRAMP_*` env → explicit CLI flags
// into ONE `ServerConfig`, used by `ServerConfig::load` (serve AND the offline ops:
// `migrate`, `blob`, `token`). It REPLACED the three hand-rolled env loaders:
//
//   A. the serve clap `#[arg(env = …)]` layer (serve-only),
//   B. `apply_env_overrides` (ran in `load`, so everywhere), and
//   C. ad-hoc `std::env::var` reads in serve (serve-only).
//
// The core bug it fixed: A & C were serve-only, so `BOATRAMP_S3_BUCKET` (and the
// serve/kv knobs) were honored by `serve` but NOT by `migrate`/`blob` — the offline
// ops that most need them. Now the env surface is uniform across all subcommands.
//
// ## Design: emit strings, extract lossy
//
// The env/flag overlay emits every scalar as a STRING value (trimmed), lists as
// arrays, and the (rare) rename_all enums as their lowercased token. Nothing is
// parsed here, so the overlay is infallible. At extraction `Figment::extract_lossy`
// coerces each string to the target field's type:
//   * bool fields  — via `Value::to_bool_lossy` (`true/yes/1/on` + `false/no/0/off`,
//     case-insensitive — the spellings the old `parse_bool` accepted);
//   * numeric fields — via `to_num_lossy` (a non-numeric value fails to deserialize
//     LOUDLY — a malformed value is rejected, never silently defaulted);
//   * string / enum / path / socket-addr fields read the string directly.
// A string destined for a string field is never coerced (lossy only fires when the
// TARGET is bool/number), so a numeric-looking bucket name or region survives.
//
// ## Faithful, drift-proof mapping
//
// The fixed-var overlay is DRIVEN BY the `*_ENV_VARS` const tables (+ the explicit
// `SERVE_SCALARS` / `SERVE_KV` alias tables for the irregular serve names), deriving
// each config path by the section's rule (drop `serve`, drop `bindings`, drop
// `overrides`, …). Those tables are now the SINGLE source of truth; the forgot-a-knob
// guard tests assert every struct field has a table entry, and the drift guards assert
// every table entry is honored by the overlay — field ↔ var ↔ overlay, no drift.
pub(crate) mod figment_resolve {
    use super::*;
    use figment::providers::Serialized;
    use figment::value::{Dict, Map as FigMap, Tag, Value};
    use figment::{Error, Figment, Metadata, Profile, Provider};

    /// Vars whose value is a comma-separated list (trimmed, empty items dropped —
    /// `EnvSource::parse_list` semantics), emitted as a figment `Array`.
    const LIST_VARS: &[&str] = &[
        "BOATRAMP_COMPUTE_KERNEL_SIGNING_PUBKEYS",
        "BOATRAMP_COMPUTE_KERNEL_ALLOWED_HASHES",
        "BOATRAMP_HANDLERS_SQL_MIGRATE_TRUSTED_EXTENSIONS",
        "BOATRAMP_CLUSTER_ROOT_PUBKEYS",
        "BOATRAMP_CLUSTER_SEEDS",
        // The alert email recipient list (comma-separated).
        "BOATRAMP_ALERTS_EMAIL_TO",
    ];

    /// Vars whose target is a `rename_all = "lowercase"` enum with no `FromStr`.
    /// `apply_env_overrides` matches these case-insensitively against a lowercase
    /// variant table; we emit the lowercased token so serde deserializes the same
    /// variant. (The per-backend `_KIND` inside the blob-backends map is handled inline.)
    const ENUM_VARS: &[&str] = &[
        "BOATRAMP_BLOBS",
        "BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE",
        "BOATRAMP_COMPUTE_DOCKER_ENDPOINT",
        "BOATRAMP_COMPUTE_DOCKER_VOLUME_MODE",
    ];

    /// The `serve.*` scalar aliases (the former Loader-A clap `#[arg(env)]` surface,
    /// unified here). Explicit (env → path) pairs because the env names are irregular —
    /// they drop the `serve` segment (`BOATRAMP_ADDR`, not `BOATRAMP_SERVE_ADDR`) and one
    /// is a field-name mismatch (`BOATRAMP_UPLOAD_IDLE_TIMEOUT` → `upload_idle_timeout_secs`)
    /// — so the mapping is aliased, never path-derived (risk P1). Bool/numeric fields are
    /// emitted as strings and coerced by `extract_lossy`; `blobs` is in `ENUM_VARS`.
    /// (The file-only serve fields — `s3_ingress_*`, `blob_notify_*`, `console`, `signer`,
    /// `blob_fallback`, `s3_credential` — have no clap/env today and stay file-only, carried
    /// by the figment file layer.) `auth_root_private_key` / `bootstrap_secret` /
    /// `azure_access_key` are secret-bearing config fields (as they are today via clap); they
    /// resolve into the config but are REDACTED by `config dump`/`explain`.
    const SERVE_SCALARS: &[(&str, &[&str])] = &[
        ("BOATRAMP_BLOBS", &["serve", "blobs"]),
        ("BOATRAMP_S3_BUCKET", &["serve", "s3_bucket"]),
        ("BOATRAMP_S3_ENDPOINT", &["serve", "s3_endpoint"]),
        ("BOATRAMP_S3_REGION", &["serve", "s3_region"]),
        ("BOATRAMP_S3_PATH_STYLE", &["serve", "s3_path_style"]),
        ("BOATRAMP_ADDR", &["serve", "addr"]),
        ("BOATRAMP_DATA_DIR", &["serve", "data_dir"]),
        ("BOATRAMP_GCS_BUCKET", &["serve", "gcs_bucket"]),
        ("BOATRAMP_GCS_ENDPOINT", &["serve", "gcs_endpoint"]),
        ("BOATRAMP_GCS_ANONYMOUS", &["serve", "gcs_anonymous"]),
        ("BOATRAMP_AZURE_ACCOUNT", &["serve", "azure_account"]),
        ("BOATRAMP_AZURE_CONTAINER", &["serve", "azure_container"]),
        ("BOATRAMP_AZURE_ACCESS_KEY", &["serve", "azure_access_key"]),
        ("BOATRAMP_AZURE_EMULATOR", &["serve", "azure_emulator"]),
        (
            "BOATRAMP_AUTH_ROOT_PRIVATE_KEY",
            &["serve", "auth_root_private_key"],
        ),
        (
            "BOATRAMP_AUTH_ROOT_PUBLIC_KEY",
            &["serve", "auth_root_public_key"],
        ),
        ("BOATRAMP_BOOTSTRAP_SECRET", &["serve", "bootstrap_secret"]),
        ("BOATRAMP_MAX_UPLOAD_BYTES", &["serve", "max_upload_bytes"]),
        (
            "BOATRAMP_UPLOAD_IDLE_TIMEOUT",
            &["serve", "upload_idle_timeout_secs"],
        ),
        (
            "BOATRAMP_MAX_CONCURRENT_UPLOADS",
            &["serve", "max_concurrent_uploads"],
        ),
        (
            "BOATRAMP_HTTP_REDIRECT_ADDR",
            &["serve", "http_redirect_addr"],
        ),
        ("BOATRAMP_DEFAULT_SITE", &["serve", "default_site"]),
        ("BOATRAMP_POP_ORIGIN", &["serve", "pop_origin"]),
        ("BOATRAMP_PROTECT_PREVIEWS", &["serve", "protect_previews"]),
        (
            "BOATRAMP_CLUSTER_RATE_LIMIT",
            &["serve", "cluster_rate_limit"],
        ),
        (
            "BOATRAMP_SHARED_CACHE_COHERENCE",
            &["serve", "shared_cache_coherence"],
        ),
    ];

    /// The `serve.kv.*` aliases (the former Loader-C ad-hoc `std::env::var` surface). The env
    /// names drop BOTH `serve` and (for slatedb) the `slatedb` segment, so they are aliased
    /// explicitly (risk P1/P10). The `0`-disables-cadence semantics are preserved by
    /// `KvConfig::{checkpoint_interval,gc_interval}` reading the resolved `Some(0)`.
    /// (The Loader-C RUNTIME knobs that are NOT config fields — `BOATRAMP_KV_AUTHZ_FENCE_SECS`,
    /// `BOATRAMP_POD_NAME`, `BOATRAMP_COMPUTE_RECONCILE_TICK_MS`/`_NET_DEBUG` — stay as direct
    /// serve reads and are intentionally NOT mapped into the config, matching today.)
    const SERVE_KV: &[(&str, &[&str])] = &[
        (
            "BOATRAMP_KV_CHECKPOINT_INTERVAL",
            &["serve", "kv", "slatedb", "checkpoint_interval"],
        ),
        (
            "BOATRAMP_KV_CLOSE_DEADLINE",
            &["serve", "kv", "slatedb", "close_deadline"],
        ),
        (
            "BOATRAMP_KV_GC_INTERVAL",
            &["serve", "kv", "slatedb", "gc_interval"],
        ),
        (
            "BOATRAMP_KV_GC_MIN_AGE",
            &["serve", "kv", "slatedb", "gc_min_age"],
        ),
        ("BOATRAMP_KV_SQL_KIND", &["serve", "kv", "sql", "kind"]),
        ("BOATRAMP_KV_SQL_PATH", &["serve", "kv", "sql", "path"]),
        (
            "BOATRAMP_KV_SQL_URL_ENV",
            &["serve", "kv", "sql", "url_env"],
        ),
        (
            "BOATRAMP_KV_SQL_POOL_MAX",
            &["serve", "kv", "sql", "pool_max"],
        ),
        (
            "BOATRAMP_KV_SQL_POOL_MIN",
            &["serve", "kv", "sql", "pool_min"],
        ),
    ];

    /// The `serve.alerts.*` aliases (node-health-alerting Stage 2). The env names drop the
    /// `serve` segment (like `s3_ingress_cloud`), so they are aliased explicitly to their
    /// nested figment paths. All leaves are `Option`/defaulted, so a partial env sub-dict
    /// deserializes without a `base_seed` entry.
    const ALERTS: &[(&str, &[&str])] = &[
        ("BOATRAMP_ALERTS_ENABLED", &["serve", "alerts", "enabled"]),
        (
            "BOATRAMP_ALERTS_INTERVAL_SECS",
            &["serve", "alerts", "interval_secs"],
        ),
        (
            "BOATRAMP_ALERTS_DISK_ENABLED",
            &["serve", "alerts", "disk", "enabled"],
        ),
        (
            "BOATRAMP_ALERTS_DISK_WARN_PCT",
            &["serve", "alerts", "disk", "warn_pct"],
        ),
        (
            "BOATRAMP_ALERTS_DISK_CRITICAL_PCT",
            &["serve", "alerts", "disk", "critical_pct"],
        ),
        (
            "BOATRAMP_ALERTS_MANAGED_SQL_ENABLED",
            &["serve", "alerts", "managed_sql", "enabled"],
        ),
        (
            "BOATRAMP_ALERTS_MANAGED_SQL_GRACE_SECS",
            &["serve", "alerts", "managed_sql", "grace_secs"],
        ),
        (
            "BOATRAMP_ALERTS_ORPHAN_ENABLED",
            &["serve", "alerts", "orphan", "enabled"],
        ),
        (
            "BOATRAMP_ALERTS_ORPHAN_GRACE_SECS",
            &["serve", "alerts", "orphan", "grace_secs"],
        ),
        (
            "BOATRAMP_ALERTS_REAPER_ENABLED",
            &["serve", "alerts", "reaper", "enabled"],
        ),
        (
            "BOATRAMP_ALERTS_REAPER_DRY_RUN",
            &["serve", "alerts", "reaper", "dry_run"],
        ),
        (
            "BOATRAMP_ALERTS_REAPER_GRACE_SECS",
            &["serve", "alerts", "reaper", "grace_secs"],
        ),
        (
            "BOATRAMP_ALERTS_REAPER_RECLAIM_VOLUMES",
            &["serve", "alerts", "reaper", "reclaim_volumes"],
        ),
        (
            "BOATRAMP_ALERTS_WEBHOOK_URL_SECRET",
            &["serve", "alerts", "webhook", "url_secret"],
        ),
        (
            "BOATRAMP_ALERTS_WEBHOOK_ALLOW_PRIVATE",
            &["serve", "alerts", "webhook", "allow_private"],
        ),
        (
            "BOATRAMP_ALERTS_EMAIL_PROJECT",
            &["serve", "alerts", "email", "project"],
        ),
        (
            "BOATRAMP_ALERTS_EMAIL_PROFILE",
            &["serve", "alerts", "email", "profile"],
        ),
        (
            "BOATRAMP_ALERTS_EMAIL_TO",
            &["serve", "alerts", "email", "to"],
        ),
    ];

    /// Insert `value` at the nested `path`, creating intermediate dicts as needed.
    fn put(dict: &mut Dict, path: &[&str], value: Value) {
        let (last, parents) = path.split_last().expect("path is non-empty");
        let mut cursor = dict;
        for seg in parents {
            let entry = cursor
                .entry((*seg).to_string())
                .or_insert_with(|| Value::Dict(Tag::Default, Dict::new()));
            if !matches!(entry, Value::Dict(..)) {
                *entry = Value::Dict(Tag::Default, Dict::new());
            }
            cursor = match entry {
                Value::Dict(_, inner) => inner,
                _ => unreachable!("entry was just forced to a Dict"),
            };
        }
        cursor.insert((*last).to_string(), value);
    }

    /// Emit the right value KIND for `var` (list / enum / plain scalar) at `path`,
    /// iff the var is set to a non-empty value.
    ///
    /// Scalar values are **trimmed**: the legacy `parse_bool`/`parse`/`parse_enum` all did
    /// `.trim()`, and figment's `to_bool_lossy` does NOT trim — so without this a templated
    /// `BOATRAMP_..._BOOL="true\n"` (fly.toml / k8s block scalar) would fail to coerce
    /// instead of parsing `true`. Trimming the string scalars too is harmless (a config
    /// value's surrounding whitespace is never meaningful, and `get` already treats a
    /// whitespace-only value as unset). A trimmed-to-empty value is dropped (unset).
    fn emit(dict: &mut Dict, source: &EnvSource, var: &str, path: &[&str]) {
        if LIST_VARS.contains(&var) {
            if let Some(items) = source.parse_list(var) {
                put(dict, path, Value::from(items));
            }
        } else if ENUM_VARS.contains(&var) {
            if let Some(v) = source.get(var) {
                put(dict, path, Value::from(v.trim().to_ascii_lowercase()));
            }
        } else if let Some(v) = source.get(var) {
            let trimmed = v.trim();
            if !trimmed.is_empty() {
                put(dict, path, Value::from(trimmed.to_string()));
            }
        }
    }

    /// `var` with `prefix` stripped, lowercased — the config field name for the
    /// section whose env vars are `<prefix><FIELD>` (the inverse of the uppercasing
    /// the forgot-a-knob guards assert).
    fn field_of(var: &str, prefix: &str) -> String {
        var.strip_prefix(prefix)
            .expect("var belongs to this section's prefix")
            .to_ascii_lowercase()
    }

    /// Build the `BOATRAMP_*` environment overlay as a figment `Dict`. Infallible
    /// (see the module docs); a malformed value is rejected at `extract_lossy`.
    pub(crate) fn env_overlay_dict(source: &EnvSource) -> Dict {
        let mut d = Dict::new();

        // --- serve.* scalars (former Loader-A) + serve.kv.* (former Loader-C) +
        // serve.alerts.* (node-health-alerting Stage 2) ----
        for (var, path) in SERVE_SCALARS.iter().chain(SERVE_KV).chain(ALERTS) {
            emit(&mut d, source, var, path);
        }

        // --- compute (`compute.<field>`) ----------------------------------------
        for var in COMPUTE_ENV_VARS {
            let field = field_of(var, "BOATRAMP_COMPUTE_");
            emit(&mut d, source, var, &["compute", field.as_str()]);
        }

        // --- security (`security.profile` + `security.overrides.<field>`) -------
        for var in SECURITY_ENV_VARS {
            if *var == "BOATRAMP_SECURITY_PROFILE" {
                emit(&mut d, source, var, &["security", "profile"]);
            } else {
                let field = field_of(var, "BOATRAMP_SECURITY_");
                emit(
                    &mut d,
                    source,
                    var,
                    &["security", "overrides", field.as_str()],
                );
            }
        }

        // --- handlers: sql binding scalars (`handlers.bindings.sql.<field>`) ----
        // (`bindings` is dropped from the env name — the P1 rename the alias rule
        // reproduces.)
        for var in SQL_ENV_VARS {
            let field = field_of(var, "BOATRAMP_HANDLERS_SQL_");
            emit(
                &mut d,
                source,
                var,
                &["handlers", "bindings", "sql", field.as_str()],
            );
        }

        // --- handlers: jwks / concurrency / blob-hedge scalars (`handlers.<f>`) --
        for var in JWKS_ENV_VARS
            .iter()
            .chain(HANDLER_CONCURRENCY_ENV_VARS)
            .chain(HANDLER_BLOB_HEDGE_ENV_VARS)
            .chain(HANDLER_COLDSTART_ENV_VARS)
        {
            let field = field_of(var, "BOATRAMP_HANDLERS_");
            emit(&mut d, source, var, &["handlers", field.as_str()]);
        }

        // --- serve.s3_ingress_cloud (`serve` dropped from the env name) ---------
        for var in S3_INGRESS_CLOUD_ENV_VARS {
            let field = field_of(var, "BOATRAMP_S3_INGRESS_CLOUD_");
            emit(
                &mut d,
                source,
                var,
                &["serve", "s3_ingress_cloud", field.as_str()],
            );
        }

        // --- secrets (+ nested vault) -------------------------------------------
        for var in SECRETS_ENV_VARS {
            if let Some(rest) = var.strip_prefix("BOATRAMP_SECRETS_VAULT_") {
                emit(
                    &mut d,
                    source,
                    var,
                    &["secrets", "vault", rest.to_ascii_lowercase().as_str()],
                );
            } else {
                let field = field_of(var, "BOATRAMP_SECRETS_");
                emit(&mut d, source, var, &["secrets", field.as_str()]);
            }
        }

        // --- cluster (+ nested mesh) --------------------------------------------
        // The overlay always emits a cluster field when set; the `listen`
        // requirement (ClusterConfig has no Default) is enforced LOUDLY at extract,
        // rather than silently dropped as `apply_env_overrides` did for an env-only
        // cluster without a listen. See the plan's parity notes.
        for var in CLUSTER_ENV_VARS {
            if let Some(rest) = var.strip_prefix("BOATRAMP_CLUSTER_MESH_") {
                emit(
                    &mut d,
                    source,
                    var,
                    &["cluster", "mesh", rest.to_ascii_lowercase().as_str()],
                );
            } else {
                let field = field_of(var, "BOATRAMP_CLUSTER_");
                emit(&mut d, source, var, &["cluster", field.as_str()]);
            }
        }

        // --- dynamic maps (P0: the generic Env provider cannot do these) --------
        blob_backends_overlay(&mut d, source);
        sql_databases_overlay(&mut d, source);
        listeners_overlay(&mut d, source);

        d
    }

    /// `[serve.blob_backends.<project>]` — keyed by project, member names scanned
    /// from the environment (there is no file to enumerate them). Mirrors the
    /// `apply_env_overrides` block, flattening the sealed credential's two public
    /// refs under `s3_credential`.
    fn blob_backends_overlay(d: &mut Dict, source: &EnvSource) {
        for name in source.blob_backend_projects() {
            let prefix = format!("{BLOB_BACKEND_ENV_PREFIX}{name}_");
            let n = name.as_str();
            if let Some(v) = source.get(&format!("{prefix}KIND")) {
                put(
                    d,
                    &["serve", "blob_backends", n, "blobs"],
                    Value::from(v.trim().to_ascii_lowercase()),
                );
            }
            for (suffix, field) in [
                ("S3_BUCKET", "s3_bucket"),
                ("S3_ENDPOINT", "s3_endpoint"),
                ("S3_REGION", "s3_region"),
                ("S3_PATH_STYLE", "s3_path_style"),
            ] {
                if let Some(v) = source.get(&format!("{prefix}{suffix}")) {
                    put(d, &["serve", "blob_backends", n, field], Value::from(v));
                }
            }
            if let Some(v) = source.get(&format!("{prefix}S3_ACCESS_KEY_ID")) {
                put(
                    d,
                    &[
                        "serve",
                        "blob_backends",
                        name.as_str(),
                        "s3_credential",
                        "access_key_id",
                    ],
                    Value::from(v),
                );
            }
            if let Some(v) = source.get(&format!("{prefix}S3_SECRET_ACCESS_KEY")) {
                put(
                    d,
                    &[
                        "serve",
                        "blob_backends",
                        name.as_str(),
                        "s3_credential",
                        "secret_access_key",
                    ],
                    Value::from(v),
                );
            }
        }
    }

    /// `handlers.bindings.sql.databases.<name>` — keyed external-DB map. The
    /// reserved `DEFAULT` env token maps to the real key `"default"`
    /// (`DEFAULT_DB_NAME`); every other name is used verbatim.
    fn sql_databases_overlay(d: &mut Dict, source: &EnvSource) {
        for name in source.sql_database_names() {
            let key = if name == "DEFAULT" {
                boatramp_core::project::DEFAULT_DB_NAME.to_string()
            } else {
                name.clone()
            };
            let prefix = format!("{SQL_DB_ENV_PREFIX}{name}_");
            let k = key.as_str();
            // scalar string fields
            for (suffix, field) in [
                ("KIND", "kind"),
                ("URL_ENV", "url_env"),
                ("READ_URL_ENV", "read_url_env"),
                ("COMPUTE", "compute"),
                ("DATABASE", "database"),
                ("USER", "user"),
                ("PASSWORD_ENV", "password_env"),
                ("POOL_MAX", "pool_max"),
                ("POOL_MIN", "pool_min"),
                ("READ_ONLY", "read_only"),
                ("ALLOW_PREVIEW", "allow_preview"),
                ("CONNECT_TIMEOUT_SECS", "connect_timeout_secs"),
                ("IMAGE", "image"),
                ("VOLUME_SIZE_MIB", "volume_size_mib"),
                ("STARTUP_GRACE_SECS", "startup_grace_secs"),
                ("RLS_SESSION", "rls_session"),
                ("TENANT_GUC", "tenant_guc"),
                ("SESSION_GUC", "session_guc"),
                ("TENANT_ALL_MARKER", "tenant_all_marker"),
            ] {
                if let Some(v) = source.get(&format!("{prefix}{suffix}")) {
                    put(
                        d,
                        &["handlers", "bindings", "sql", "databases", k, field],
                        Value::from(v),
                    );
                }
            }
            // enum fields (lowercased token)
            for (suffix, field) in [("TENANT", "tenant"), ("TENANT_SCOPE", "tenant_scope")] {
                if let Some(v) = source.get(&format!("{prefix}{suffix}")) {
                    put(
                        d,
                        &["handlers", "bindings", "sql", "databases", k, field],
                        Value::from(v.trim().to_ascii_lowercase()),
                    );
                }
            }
        }
    }

    /// `[serve.listeners.<name>]` — keyed inbound-TCP listeners. Only the SCALAR +
    /// `imports` (list) fields are env-settable; structured fields (tenancy/env/tls)
    /// are file-only.
    fn listeners_overlay(d: &mut Dict, source: &EnvSource) {
        for name in source.listener_names() {
            let prefix = format!("{LISTENER_ENV_PREFIX}{name}_");
            let n = name.as_str();
            for (suffix, field) in [
                ("BIND", "bind"),
                ("COMPONENT", "component"),
                ("PROJECT", "project"),
                ("SITE", "site"),
                ("MAX_CONNS", "max_conns"),
                ("IDLE_TIMEOUT_MS", "idle_timeout_ms"),
                ("MAX_CONN_DURATION_MS", "max_conn_duration_ms"),
            ] {
                if let Some(v) = source.get(&format!("{prefix}{suffix}")) {
                    put(d, &["serve", "listeners", n, field], Value::from(v));
                }
            }
            if let Some(items) = source.parse_list(&format!("{prefix}IMPORTS")) {
                put(d, &["serve", "listeners", n, "imports"], Value::from(items));
            }
        }
    }

    /// A figment [`Provider`] carrying the `BOATRAMP_*` environment overlay. Merged
    /// into the pipeline ABOVE the file layer (env overrides file) and BELOW the
    /// explicit-flag layer.
    pub(crate) struct BoatrampEnv(Dict);

    impl BoatrampEnv {
        pub(crate) fn new(source: &EnvSource) -> Self {
            Self(env_overlay_dict(source))
        }
    }

    impl Provider for BoatrampEnv {
        fn metadata(&self) -> Metadata {
            Metadata::named("BOATRAMP_* environment")
        }

        fn data(&self) -> Result<FigMap<Profile, Dict>, Error> {
            let mut map = FigMap::new();
            map.insert(Profile::Default, self.0.clone());
            Ok(map)
        }
    }

    /// A figment [`Provider`] wrapping a prebuilt `Dict` at the default profile — used
    /// for the base-seed, file, and flag layers.
    struct DictLayer {
        name: &'static str,
        dict: Dict,
    }

    impl Provider for DictLayer {
        fn metadata(&self) -> Metadata {
            Metadata::named(self.name)
        }
        fn data(&self) -> Result<FigMap<Profile, Dict>, Error> {
            let mut map = FigMap::new();
            map.insert(Profile::Default, self.dict.clone());
            Ok(map)
        }
    }

    /// Recursively drop `Empty` (figment's serialized `None`) entries from a dict, so the
    /// file layer never clobbers a lower layer's value with a null (figment merge replaces
    /// a dict with a non-dict). This is what lets the base-seed layer (decision 2) survive
    /// under a file that simply omits the section.
    fn prune_empty(dict: Dict) -> Dict {
        dict.into_iter()
            .filter_map(|(k, v)| match v {
                Value::Empty(..) => None,
                Value::Dict(t, inner) => Some((k, Value::Dict(t, prune_empty(inner)))),
                other => Some((k, other)),
            })
            .collect()
    }

    /// Serialize `value` to a figment `Dict` via figment's OWN serializer (decision 1 — no
    /// serde_json bridge). The error is boxed because `figment::Error` is large
    /// (`clippy::result_large_err`).
    fn to_dict(value: &impl Serialize) -> Result<Dict, Box<Error>> {
        let mut data = Serialized::defaults(value).data().map_err(Box::new)?;
        Ok(data
            .remove(&Profile::Default)
            .or_else(|| data.into_values().next())
            .unwrap_or_default())
    }

    /// The parsed config file as a pruned figment layer (decision 1). Absent `Option`
    /// sections serialize to `Empty` and are pruned so they don't clobber the base-seed.
    fn file_layer(cfg: &ServerConfig) -> Result<Dict, Box<Error>> {
        Ok(prune_empty(to_dict(cfg)?))
    }

    /// Decision 2: the two `deny_unknown_fields` sub-structs with a REQUIRED field
    /// (`VaultSecretsConfig` has `addr`/`key`; `S3CredentialConfig` has
    /// `access_key_id`/`secret_access_key`) cannot deserialize from a partial env sub-dict.
    /// Seed their COMPLETE defaults in a layer BELOW the file, so file + env field overrides
    /// layer on top without a partial ever reaching extract — and WITHOUT clobbering a
    /// file-provided field (the file layer, merged above this, wins per-key; env wins above
    /// that). Seeded only when env actually references the sub-struct (so an unset section
    /// stays absent, matching `apply_env_overrides`' lazy materialization).
    fn base_seed(source: &EnvSource) -> Result<Dict, Box<Error>> {
        let mut d = Dict::new();
        if source.any(SECRETS_VAULT_ENV_VARS) {
            put(
                &mut d,
                &["secrets", "vault"],
                Value::Dict(Tag::Default, to_dict(&VaultSecretsConfig::default())?),
            );
        }
        for name in source.blob_backend_projects() {
            let prefix = format!("{BLOB_BACKEND_ENV_PREFIX}{name}_");
            let has_cred = source.get(&format!("{prefix}S3_ACCESS_KEY_ID")).is_some()
                || source
                    .get(&format!("{prefix}S3_SECRET_ACCESS_KEY"))
                    .is_some();
            if has_cred {
                put(
                    &mut d,
                    &["serve", "blob_backends", name.as_str(), "s3_credential"],
                    Value::Dict(Tag::Default, to_dict(&S3CredentialConfig::default())?),
                );
            }
        }
        Ok(d)
    }

    /// The single layered config resolution — `base-seed → file → env → explicit flags` —
    /// used by `ServerConfig::load` (serve + every offline op). `flags` is the caller's
    /// explicit-CLI layer (empty for the offline ops; the serve binary passes its
    /// `ValueSource::CommandLine` args, which is what keeps a defaulted `--blobs fs` from
    /// clobbering file/env — risk P3#14). Replaces `apply_env_overrides` + the serve clap
    /// `#[arg(env)]` + ad-hoc `std::env::var` loaders (the parity battery asserts the SAME
    /// result as `apply_env_overrides` across the whole surface).
    pub(crate) fn load_with_figment(
        path: &Path,
        override_: Option<ConfigFormat>,
        source: &EnvSource,
        flags: Dict,
    ) -> Result<ServerConfig, ConfigError> {
        // File: parsed with the existing RON/JSON decoder + its own validation (a file-only
        // config still fails at parse exactly as today). Decision 3 re-validates the MERGED
        // result below.
        let fmt = resolve_format(path, override_);
        let file_cfg = match std::fs::read_to_string(path) {
            Ok(contents) => ServerConfig::parse_with_format(&contents, fmt).map_err(|err| {
                ConfigError::File {
                    path: path.display().to_string(),
                    source: Box::new(err),
                }
            })?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => ServerConfig::default(),
            Err(err) => return Err(err.into()),
        };

        let base = base_seed(source).map_err(|e| ConfigError::Resolve(e.to_string()))?;
        let file = file_layer(&file_cfg).map_err(|e| ConfigError::Resolve(e.to_string()))?;

        // Decision 4: a `[cluster]` missing its required `listen` has no `ClusterConfig`
        // default, so extract fails LOUDLY here (we do not preserve the old silent-drop).
        let cfg: ServerConfig = Figment::new()
            .merge(DictLayer {
                name: "base defaults",
                dict: base,
            })
            .merge(DictLayer {
                name: "config file",
                dict: file,
            })
            .merge(BoatrampEnv::new(source))
            .merge(DictLayer {
                name: "cli flags",
                dict: flags,
            })
            .extract_lossy()
            .map_err(|e| ConfigError::Resolve(e.to_string()))?;

        // Decision 3: run the fail-closed validators on the fully merged (file + env + flags)
        // result — stricter than `apply_env_overrides`, which only re-validated the db-name /
        // blob-project / listener maps (this also validates a file-introduced entry).
        cfg.validate_sql_db_names()?;
        cfg.validate_blob_backend_projects()?;
        cfg.validate_listeners()?;
        Ok(cfg)
    }

    /// Resolve the `BOATRAMP_*` env overlay OVER an already-parsed base config (the base
    /// standing in for the file layer): `base-seed → base → env`. Equivalent to
    /// [`load_with_figment`] with the file already read into `base` and no flags. Test-only —
    /// it backs the `#[cfg(test)]` `apply_env_overrides` adapter so the pre-figment env tests
    /// (which layer env over a parsed `boatramp.cfg` struct) run THROUGH the real pipeline.
    #[cfg(test)]
    pub(crate) fn resolve_env_over(
        base: &ServerConfig,
        source: &EnvSource,
    ) -> Result<ServerConfig, ConfigError> {
        let seed = base_seed(source).map_err(|e| ConfigError::Resolve(e.to_string()))?;
        let file = file_layer(base).map_err(|e| ConfigError::Resolve(e.to_string()))?;
        let cfg: ServerConfig = Figment::new()
            .merge(DictLayer {
                name: "base defaults",
                dict: seed,
            })
            .merge(DictLayer {
                name: "base config",
                dict: file,
            })
            .merge(BoatrampEnv::new(source))
            .extract_lossy()
            .map_err(|e| ConfigError::Resolve(e.to_string()))?;
        cfg.validate_sql_db_names()?;
        cfg.validate_blob_backend_projects()?;
        cfg.validate_listeners()?;
        Ok(cfg)
    }

    /// Build the explicit-CLI-**flag** figment layer from a `{BOATRAMP_<NAME>: value}` map
    /// of the args the operator set on the command line. Reuses [`env_overlay_dict`] (a
    /// flag's name→path mapping is the SAME as its env var's), so only recognised config
    /// knobs produce entries and the runtime/selector flags (`--tls`, cluster-actions, …)
    /// are ignored. This dict is merged as the TOP layer (above the Process env), so an
    /// explicit flag wins over env + file — matching clap's `flag > env` precedence today.
    pub(crate) fn flag_overlay_dict(cli_flags: &BTreeMap<String, String>) -> Dict {
        env_overlay_dict(&EnvSource::Map(cli_flags.clone()))
    }

    /// Config-tree field names whose VALUES are raw secret material — redacted by
    /// [`dump_redacted`]. Secret *references* and env-var-NAME fields (`token_env`,
    /// `url_env`, `pin_env`, `password_env`, `access_token_env`) are NOT secrets and are
    /// left intact; only the fields that can hold raw key/secret bytes are masked.
    const SECRET_FIELDS: &[&str] = &[
        "auth_root_private_key",
        "bootstrap_secret",
        "azure_access_key",
        "secret_access_key",
        // The external token signer's in-process root key (`[serve.signer] Local { private_key }`)
        // is raw key material in the config — mask it (Security MEDIUM).
        "private_key",
        // `[cluster] join_token` is a secret REFERENCE by convention (`env:`/`path:`), but the
        // schema allows a raw-inlined token, so mask it to be safe (Security MEDIUM).
        "join_token",
    ];

    fn redact(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (k, v) in map.iter_mut() {
                    if SECRET_FIELDS.contains(&k.as_str()) && !v.is_null() {
                        *v = serde_json::Value::String("<redacted>".to_string());
                    } else {
                        redact(v);
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(redact),
            _ => {}
        }
    }

    /// Serialize the resolved [`ServerConfig`] for `boatramp config dump`, REDACTING the
    /// secret-bearing fields ([`SECRET_FIELDS`]). The config is `Serialize` for the figment
    /// file layer, which would otherwise expose the control-plane root key / bootstrap
    /// secret / azure access key / sealed-cred ref in a dump. Pretty JSON (also a valid
    /// config input).
    pub(crate) fn dump_redacted(cfg: &ServerConfig) -> Result<String, ConfigError> {
        let mut v = serde_json::to_value(cfg).map_err(ConfigError::Json)?;
        redact(&mut v);
        serde_json::to_string_pretty(&v).map_err(ConfigError::Json)
    }

    /// Resolve a [`ServerConfig`] from the environment overlay ALONE (no file, no
    /// flags) — a thin test helper for the sections that deserialize from a partial env
    /// dict. Sections needing the base-seed (decision 2) are tested through
    /// [`load_with_figment`] instead.
    #[cfg(test)]
    pub(crate) fn resolve_from_env(source: &EnvSource) -> Result<ServerConfig, Box<Error>> {
        Figment::new()
            .merge(BoatrampEnv::new(source))
            .extract_lossy()
            .map_err(Box::new)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn map(pairs: &[(&str, &str)]) -> EnvSource {
            EnvSource::Map(
                pairs
                    .iter()
                    .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                    .collect(),
            )
        }

        /// The keystone drift guard: EVERY fixed `BOATRAMP_*` var the old loader
        /// (`apply_env_overrides`) honors must also be produced by the new overlay.
        /// Because the overlay iterates the same `*_ENV_VARS` const tables, this
        /// holds by construction — the test is the regression guard that a future
        /// edit can't quietly drop a section's table from the overlay loop, and
        /// that no const var escapes classification. (The forgot-a-knob guards in
        /// the parent module already prove every struct FIELD has a const-table
        /// var; together they chain field → var → overlay entry.)
        #[test]
        fn overlay_honors_every_loader_b_fixed_var() {
            let all: Vec<&str> = COMPUTE_ENV_VARS
                .iter()
                .chain(SECURITY_ENV_VARS)
                .chain(SQL_ENV_VARS)
                .chain(JWKS_ENV_VARS)
                .chain(HANDLER_CONCURRENCY_ENV_VARS)
                .chain(HANDLER_BLOB_HEDGE_ENV_VARS)
                .chain(HANDLER_COLDSTART_ENV_VARS)
                .chain(S3_INGRESS_CLOUD_ENV_VARS)
                .chain(SECRETS_ENV_VARS)
                .chain(CLUSTER_ENV_VARS)
                .copied()
                .collect();
            let mut unhandled = Vec::new();
            for var in all {
                // A socket-addr-ish sample keeps the value non-empty; the overlay
                // emits strings (no parse), so any non-empty value exercises it.
                let dict = env_overlay_dict(&map(&[(var, "x")]));
                if dict.is_empty() {
                    unhandled.push(var);
                }
            }
            assert!(
                unhandled.is_empty(),
                "overlay produced nothing for these registered Loader-B vars \
                 (a drift gap — wire them into env_overlay_dict): {unhandled:?}"
            );
        }

        /// P4: the overlay's bool spellings match `parse_bool` end-to-end, via
        /// figment's `to_bool_lossy` at `extract_lossy`.
        #[test]
        fn bool_spellings_round_trip_like_parse_bool() {
            for (raw, expect) in [
                ("on", true),
                ("1", true),
                ("yes", true),
                ("TRUE", true),
                ("off", false),
                ("0", false),
                ("no", false),
            ] {
                let cfg = resolve_from_env(&map(&[(
                    "BOATRAMP_SECURITY_ALLOW_SHARED_KERNEL_COMPUTE",
                    raw,
                )]))
                .expect("extract");
                assert_eq!(
                    cfg.security
                        .expect("security materialised")
                        .overrides
                        .allow_shared_kernel_compute,
                    Some(expect),
                    "bool spelling {raw:?} must parse like parse_bool"
                );
            }
        }

        /// Empty env value = UNSET (never clobbers to `""`), matching `EnvSource::get`.
        #[test]
        fn empty_value_is_unset() {
            let dict = env_overlay_dict(&map(&[("BOATRAMP_S3_BUCKET", "")]));
            assert!(dict.is_empty(), "an empty value must be treated as unset");
        }

        /// `[compute]` resolves from env across str / int / list / enum / bool field kinds
        /// (`ComputeConfig` is `#[serde(default)]`, so a partial env dict fills the rest).
        #[test]
        fn compute_resolves_from_env() {
            let c = resolve_from_env(&map(&[
                ("BOATRAMP_COMPUTE_VCPUS", "4"),
                ("BOATRAMP_COMPUTE_MEM_MIB", "2048"),
                ("BOATRAMP_COMPUTE_REGION", "ams"),
                (
                    "BOATRAMP_COMPUTE_KERNEL_SIGNING_PUBKEYS",
                    "es256:aa, es256:bb",
                ),
                ("BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE", "rootless"),
                ("BOATRAMP_COMPUTE_INTERNAL_DNS", "on"),
            ]))
            .expect("figment extract")
            .compute
            .expect("compute materialised from env");
            assert_eq!(c.vcpus, 4);
            assert_eq!(c.mem_mib, 2048);
            assert_eq!(c.region.as_deref(), Some("ams"));
            assert_eq!(
                c.kernel_signing_pubkeys,
                vec!["es256:aa".to_string(), "es256:bb".to_string()],
                "comma-list trimmed + split"
            );
            assert_eq!(c.managed_db_privilege, ManagedDbPrivilege::Rootless);
            assert!(c.internal_dns, "bool coerced from \"on\"");
        }

        /// The serve S3 scalars (a finalize concern) resolve from env —
        /// `ServeConfig` is `#[serde(default)]`. Asserts ALL FIVE top-level `[serve]` S3-backend
        /// levers (`blobs`/`s3_bucket`/`s3_endpoint`/`s3_region`/`s3_path_style`) resolve — the
        /// enum, three strings, and the bool. This resolves through the pipeline with NO flag layer
        /// (`resolve_from_env`), i.e. exactly the way the OFFLINE ops (`migrate`/`blob rehome`) see
        /// the object store from the environment — the parity that v0.34.0's hand-added Loader-B
        /// `SERVE_S3_BACKEND_ENV_VARS` arm provided and the figment overlay (`SERVE_SCALARS`) now
        /// subsumes. So a file-less fleet (a Tigris-only production deployment) needs no
        /// `boatramp.cfg` for its object store.
        #[test]
        fn serve_s3_scalars_extract() {
            let cfg = resolve_from_env(&map(&[
                ("BOATRAMP_BLOBS", "s3"),
                ("BOATRAMP_S3_BUCKET", "exampleorg-blobs"),
                ("BOATRAMP_S3_ENDPOINT", "https://fly.storage.tigris.dev"),
                ("BOATRAMP_S3_REGION", "auto"),
                ("BOATRAMP_S3_PATH_STYLE", "true"),
            ]))
            .expect("extract");
            let serve = cfg.serve.expect("serve materialised from env");
            assert_eq!(serve.blobs, Some(crate::backends::BlobBackend::S3));
            assert_eq!(serve.s3_bucket.as_deref(), Some("exampleorg-blobs"));
            assert_eq!(
                serve.s3_endpoint.as_deref(),
                Some("https://fly.storage.tigris.dev")
            );
            assert_eq!(serve.s3_region.as_deref(), Some("auto"));
            assert!(serve.s3_path_style, "s3_path_style coerced from \"true\"");
        }

        /// The `[serve.alerts]` subsystem (node-health-alerting Stage 2) resolves from env
        /// across every nested leaf — the top-level toggle, the disk thresholds, the
        /// managed-SQL / orphan graces, the reaper's bool/dry-run/grace/reclaim knobs, the
        /// webhook url-secret ref + allow_private, and the email project/profile + the
        /// comma-list recipients. A forgot-a-knob guard so a new `BOATRAMP_ALERTS_*` lever
        /// can't silently escape the overlay. `ServeConfig`/`AlertsConfig` are `#[serde(default)]`,
        /// so a partial env dict fills the rest.
        #[test]
        fn serve_alerts_resolve_from_env() {
            let cfg = resolve_from_env(&map(&[
                ("BOATRAMP_ALERTS_ENABLED", "true"),
                ("BOATRAMP_ALERTS_INTERVAL_SECS", "30"),
                ("BOATRAMP_ALERTS_DISK_WARN_PCT", "70"),
                ("BOATRAMP_ALERTS_DISK_CRITICAL_PCT", "88"),
                ("BOATRAMP_ALERTS_MANAGED_SQL_GRACE_SECS", "120"),
                ("BOATRAMP_ALERTS_ORPHAN_GRACE_SECS", "3600"),
                ("BOATRAMP_ALERTS_REAPER_ENABLED", "true"),
                ("BOATRAMP_ALERTS_REAPER_DRY_RUN", "false"),
                ("BOATRAMP_ALERTS_REAPER_GRACE_SECS", "86400"),
                ("BOATRAMP_ALERTS_REAPER_RECLAIM_VOLUMES", "true"),
                (
                    "BOATRAMP_ALERTS_WEBHOOK_URL_SECRET",
                    "boatramp:node-alert-webhook",
                ),
                ("BOATRAMP_ALERTS_WEBHOOK_ALLOW_PRIVATE", "false"),
                ("BOATRAMP_ALERTS_EMAIL_PROJECT", "default"),
                ("BOATRAMP_ALERTS_EMAIL_PROFILE", "alerts"),
                (
                    "BOATRAMP_ALERTS_EMAIL_TO",
                    "ops@example.com, oncall@example.com",
                ),
            ]))
            .expect("extract");
            let alerts = cfg
                .serve
                .expect("serve materialised from env")
                .alerts
                .expect("alerts materialised from env");
            assert!(alerts.enabled);
            assert_eq!(alerts.interval().as_secs(), 30);
            assert_eq!(alerts.disk.warn_pct(), 70.0);
            assert_eq!(alerts.disk.critical_pct(), 88.0);
            assert_eq!(alerts.managed_sql.grace_secs(), 120);
            assert_eq!(alerts.orphan.grace_secs(), 3600);
            assert!(alerts.reaper.enabled());
            assert!(
                !alerts.reaper.dry_run(),
                "reaper dry_run coerced from \"false\""
            );
            assert_eq!(alerts.reaper.grace_secs(), 86400);
            assert!(alerts.reaper.reclaim_volumes);
            assert_eq!(
                alerts.webhook.url_secret_ref(),
                Some("boatramp:node-alert-webhook")
            );
            assert!(!alerts.webhook.allow_private);
            assert_eq!(alerts.email.project(), "default");
            assert_eq!(alerts.email.profile_name(), Some("alerts"));
            assert_eq!(
                alerts.email.to,
                vec![
                    "ops@example.com".to_string(),
                    "oncall@example.com".to_string()
                ],
                "comma-list trimmed + split"
            );
            assert!(alerts.any_channel_configured());
        }

        /// Drift guard: every `BOATRAMP_ALERTS_*` var in the `ALERTS` table produces an
        /// overlay entry — a future field can't silently escape `env_overlay_dict`.
        #[test]
        fn overlay_honors_every_alerts_var() {
            let mut unhandled = Vec::new();
            for (var, _) in ALERTS {
                assert!(
                    var.starts_with("BOATRAMP_ALERTS_"),
                    "an alerts env var must carry the BOATRAMP_ALERTS_ prefix: {var}"
                );
                if env_overlay_dict(&map(&[(var, "1")])).is_empty() {
                    unhandled.push(*var);
                }
            }
            assert!(
                unhandled.is_empty(),
                "these ALERTS vars produced no overlay entry: {unhandled:?}"
            );
        }

        /// P0#2: the dynamic blob-backends map populates at the right nested path,
        /// including the flattened sealed-credential public ref.
        #[test]
        fn blob_backends_dynamic_map_shape() {
            let dict = env_overlay_dict(&map(&[
                ("BOATRAMP_SERVE_BLOB_BACKEND_myproj_KIND", "s3"),
                ("BOATRAMP_SERVE_BLOB_BACKEND_myproj_S3_BUCKET", "p-blobs"),
                (
                    "BOATRAMP_SERVE_BLOB_BACKEND_myproj_S3_ACCESS_KEY_ID",
                    "AKIA",
                ),
            ]));
            let serve = match dict.get("serve") {
                Some(Value::Dict(_, s)) => s,
                _ => panic!("serve dict present"),
            };
            let backends = match serve.get("blob_backends") {
                Some(Value::Dict(_, b)) => b,
                _ => panic!("blob_backends dict present"),
            };
            let myproj = match backends.get("myproj") {
                Some(Value::Dict(_, p)) => p,
                _ => panic!("myproj backend present"),
            };
            assert!(matches!(myproj.get("blobs"), Some(Value::String(_, s)) if s == "s3"));
            assert!(matches!(myproj.get("s3_bucket"), Some(Value::String(_, s)) if s == "p-blobs"));
            match myproj.get("s3_credential") {
                Some(Value::Dict(_, cred)) => assert!(
                    matches!(cred.get("access_key_id"), Some(Value::String(_, s)) if s == "AKIA")
                ),
                _ => panic!("s3_credential flattened under the backend"),
            }
        }

        /// P0#1: the SQL `databases` map resolves the reserved `DEFAULT` token to
        /// the real key `"default"`.
        #[test]
        fn sql_db_default_token_maps_to_default_key() {
            let dict = env_overlay_dict(&map(&[(
                "BOATRAMP_HANDLERS_SQL_DB_DEFAULT_KIND",
                "postgres",
            )]));
            // handlers.bindings.sql.databases.default.kind == "postgres"
            let mut cur = &dict;
            for seg in ["handlers", "bindings", "sql", "databases", "default"] {
                cur = match cur.get(seg) {
                    Some(Value::Dict(_, inner)) => inner,
                    _ => panic!("missing dict segment {seg}"),
                };
            }
            assert!(matches!(cur.get("kind"), Some(Value::String(_, s)) if s == "postgres"));
        }

        // The figment pipeline resolves an offline op's config (base-seed + env, no file, no
        // flags) — `figment_env` — used by the direct section/serve tests below. (The old
        // full-surface parity battery, which compared this to `apply_env_overrides`, retired
        // with Loader B; its equivalence was proven green at the cutover, and the direct
        // per-section tests — here + the `env_wires_*` tests in `config::tests`, which now run
        // THROUGH the pipeline via the test adapter — are the spec going forward.)

        /// The figment pipeline an offline op takes: base-seed + env, no file, no flags.
        fn figment_env(pairs: &[(&str, &str)]) -> ServerConfig {
            load_with_figment(
                std::path::Path::new("/nonexistent/boatramp.cfg"),
                None,
                &map(pairs),
                Dict::new(),
            )
            .expect("figment load_with_figment")
        }

        // --- serve.* scalars + serve.kv.* (former Loader A / C) -------------------
        // The pipeline resolves these (the serve-only clap `#[arg(env)]` + ad-hoc env reads
        // the rewrite subsumed) into their ServeConfig fields, asserted directly below.

        /// Env-only figment resolution via the full pipeline (base-seed + env), so the
        /// serve-scalar secrets' deny-unknown neighbours aren't an issue (serve is
        /// `#[serde(default)]`).
        fn serve_from_env(pairs: &[(&str, &str)]) -> ServeConfig {
            figment_env(pairs)
                .serve
                .expect("serve materialised from env")
        }

        #[test]
        fn serve_scalars_full_extract() {
            let s = serve_from_env(&[
                ("BOATRAMP_ADDR", "0.0.0.0:8080"),
                ("BOATRAMP_DATA_DIR", "/data"),
                ("BOATRAMP_BLOBS", "s3"),
                ("BOATRAMP_S3_BUCKET", "b"),
                ("BOATRAMP_S3_PATH_STYLE", "true"),
                ("BOATRAMP_GCS_BUCKET", "gb"),
                ("BOATRAMP_GCS_ENDPOINT", "http://gcs"),
                ("BOATRAMP_GCS_ANONYMOUS", "yes"),
                ("BOATRAMP_AZURE_ACCOUNT", "acct"),
                ("BOATRAMP_AZURE_CONTAINER", "cont"),
                ("BOATRAMP_AZURE_ACCESS_KEY", "secret-key"),
                ("BOATRAMP_AZURE_EMULATOR", "true"),
                ("BOATRAMP_AUTH_ROOT_PRIVATE_KEY", "deadbeef"),
                ("BOATRAMP_AUTH_ROOT_PUBLIC_KEY", "cafe"),
                ("BOATRAMP_BOOTSTRAP_SECRET", "boot"),
                ("BOATRAMP_MAX_UPLOAD_BYTES", "1048576"),
                ("BOATRAMP_UPLOAD_IDLE_TIMEOUT", "30"),
                ("BOATRAMP_MAX_CONCURRENT_UPLOADS", "16"),
                ("BOATRAMP_HTTP_REDIRECT_ADDR", "0.0.0.0:80"),
                ("BOATRAMP_DEFAULT_SITE", "exampleorg"),
                ("BOATRAMP_POP_ORIGIN", "https://cp.example.com"),
                ("BOATRAMP_PROTECT_PREVIEWS", "true"),
                ("BOATRAMP_CLUSTER_RATE_LIMIT", "true"),
                ("BOATRAMP_SHARED_CACHE_COHERENCE", "true"),
            ]);
            assert_eq!(s.addr, Some("0.0.0.0:8080".parse().unwrap()));
            assert_eq!(s.data_dir.as_deref(), Some(std::path::Path::new("/data")));
            assert!(matches!(s.blobs, Some(crate::backends::BlobBackend::S3)));
            assert_eq!(s.s3_bucket.as_deref(), Some("b"));
            assert!(s.s3_path_style);
            assert_eq!(s.gcs_bucket.as_deref(), Some("gb"));
            assert!(s.gcs_anonymous, "GCS anonymous coerced from \"yes\"");
            assert_eq!(s.azure_account.as_deref(), Some("acct"));
            assert_eq!(s.azure_access_key.as_deref(), Some("secret-key"));
            assert!(s.azure_emulator);
            assert_eq!(s.auth_root_private_key.as_deref(), Some("deadbeef"));
            assert_eq!(s.auth_root_public_key.as_deref(), Some("cafe"));
            assert_eq!(s.bootstrap_secret.as_deref(), Some("boot"));
            assert_eq!(s.max_upload_bytes, Some(1_048_576));
            // The field-name mismatch: env UPLOAD_IDLE_TIMEOUT → field upload_idle_timeout_secs.
            assert_eq!(s.upload_idle_timeout_secs, Some(30));
            assert_eq!(s.max_concurrent_uploads, Some(16));
            assert_eq!(s.http_redirect_addr, Some("0.0.0.0:80".parse().unwrap()));
            assert_eq!(s.default_site.as_deref(), Some("exampleorg"));
            assert_eq!(s.pop_origin.as_deref(), Some("https://cp.example.com"));
            assert!(s.protect_previews);
            assert!(s.cluster_rate_limit);
            assert!(s.shared_cache_coherence);
        }

        #[test]
        fn serve_kv_knobs_full_extract() {
            let s = serve_from_env(&[
                ("BOATRAMP_KV_CHECKPOINT_INTERVAL", "0"),
                ("BOATRAMP_KV_CLOSE_DEADLINE", "30"),
                ("BOATRAMP_KV_GC_INTERVAL", "600"),
                ("BOATRAMP_KV_GC_MIN_AGE", "3600"),
                ("BOATRAMP_KV_SQL_KIND", "sqlite"),
                ("BOATRAMP_KV_SQL_PATH", "/data/kv.db"),
                ("BOATRAMP_KV_SQL_URL_ENV", "KV_URL"),
                ("BOATRAMP_KV_SQL_POOL_MAX", "8"),
            ]);
            let kv = s.kv.expect("serve.kv materialised");
            // `0` round-trips as Some(0) (the meaningful "disable cadence" value — KvConfig
            // maps Some(0) → None at resolve time, preserving Loader-C semantics). Checked on
            // the resolver BEFORE moving the sub-structs out.
            assert_eq!(
                kv.checkpoint_interval(),
                None,
                "Some(0) disables the cadence"
            );
            let slate = kv.slatedb.clone().expect("serve.kv.slatedb materialised");
            assert_eq!(slate.checkpoint_interval, Some(0));
            assert_eq!(slate.close_deadline, Some(30));
            assert_eq!(slate.gc_interval, Some(600));
            assert_eq!(slate.gc_min_age, Some(3600));
            let sql = kv.sql.expect("serve.kv.sql materialised");
            assert_eq!(sql.kind, "sqlite");
            assert_eq!(sql.path.as_deref(), Some("/data/kv.db"));
            assert_eq!(sql.url_env.as_deref(), Some("KV_URL"));
            assert_eq!(sql.pool_max, Some(8));
        }

        /// Drift guard for the serve surface: every SERVE_SCALARS + SERVE_KV var produces
        /// an overlay entry (the Loader-A/C analog of `overlay_honors_every_loader_b_fixed_var`).
        #[test]
        fn overlay_honors_every_serve_var() {
            let mut unhandled = Vec::new();
            for (var, _) in SERVE_SCALARS.iter().chain(SERVE_KV) {
                if env_overlay_dict(&map(&[(var, "x")])).is_empty() {
                    unhandled.push(*var);
                }
            }
            assert!(
                unhandled.is_empty(),
                "overlay produced nothing for these serve vars: {unhandled:?}"
            );
        }

        // --- the flag layer: precedence + the config dump redaction ---------------

        /// `flag > env > file` precedence (matching clap's `flag > env` + the file fallback),
        /// resolved through the full pipeline.
        #[test]
        fn flag_env_file_precedence() {
            let path = std::env::temp_dir().join(format!(
                "brtest-figment-{}-{:?}.cfg",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::write(
                &path,
                r#"( serve: ( s3_bucket: "from-file", s3_region: "file-region", s3_endpoint: "file-endpoint" ) )"#,
            )
            .unwrap();

            let env = map(&[
                ("BOATRAMP_S3_BUCKET", "from-env"),
                ("BOATRAMP_S3_ENDPOINT", "from-env-endpoint"),
            ]);
            let flags: BTreeMap<String, String> =
                [("BOATRAMP_S3_BUCKET".to_string(), "from-flag".to_string())]
                    .into_iter()
                    .collect();
            let cfg =
                load_with_figment(&path, None, &env, flag_overlay_dict(&flags)).expect("resolve");
            let serve = cfg.serve.expect("serve");
            assert_eq!(
                serve.s3_bucket.as_deref(),
                Some("from-flag"),
                "flag beats env+file"
            );
            assert_eq!(
                serve.s3_endpoint.as_deref(),
                Some("from-env-endpoint"),
                "env beats file when no flag"
            );
            assert_eq!(
                serve.s3_region.as_deref(),
                Some("file-region"),
                "file survives when neither env nor flag set it"
            );
            std::fs::remove_file(&path).ok();
        }

        /// `config dump` must redact the raw-secret fields (the control-plane root key,
        /// bootstrap secret, azure access key, sealed-cred ref) — never emit their values.
        #[test]
        fn dump_redacts_secrets() {
            let cfg = figment_env(&[
                ("BOATRAMP_AUTH_ROOT_PRIVATE_KEY", "deadbeefsecret"),
                ("BOATRAMP_BOOTSTRAP_SECRET", "topsecretboot"),
                ("BOATRAMP_AZURE_ACCESS_KEY", "azuresecretkey"),
                ("BOATRAMP_DEFAULT_SITE", "exampleorg"),
            ]);
            let dump = dump_redacted(&cfg).expect("dump");
            for leaked in ["deadbeefsecret", "topsecretboot", "azuresecretkey"] {
                assert!(
                    !dump.contains(leaked),
                    "config dump leaked a secret value: {leaked}\n{dump}"
                );
            }
            assert!(dump.contains("<redacted>"), "secrets shown as <redacted>");
            // A non-secret field is still shown in full.
            assert!(dump.contains("exampleorg"), "non-secret values are shown");
        }

        /// Security MEDIUM: the external signer's in-process `private_key` and a raw-inlined
        /// `cluster.join_token` must be redacted in a dump (the config is `Serialize`, so a raw
        /// dump would otherwise print the signing key / join secret in cleartext).
        #[test]
        fn dump_redacts_signer_key_and_join_token() {
            let file = r#"(
                serve: ( signer: Local( private_key: "SIGNERPRIVKEYSECRET" ) ),
                cluster: ( listen: "10.0.0.2:7000", join_token: "RAWJOINTOKENSECRET" ),
            )"#;
            let cfg = ServerConfig::parse_with_format(file, ConfigFormat::Ron).expect("parse");
            let dump = cfg.dump_redacted().expect("dump");
            assert!(
                !dump.contains("SIGNERPRIVKEYSECRET"),
                "signer private_key leaked:\n{dump}"
            );
            assert!(
                !dump.contains("RAWJOINTOKENSECRET"),
                "cluster join_token leaked:\n{dump}"
            );
            assert!(dump.contains("<redacted>"));
        }

        /// Security LOW (bool trim): a templated env value with trailing whitespace
        /// (`"true\n"` from a fly.toml / k8s block scalar) must still coerce — the overlay
        /// trims scalar values so figment's non-trimming `to_bool_lossy` sees `true`. Also
        /// covers an enum with surrounding whitespace.
        #[test]
        fn trailing_whitespace_on_bool_and_enum_still_parses() {
            let cfg = resolve_from_env(&map(&[
                ("BOATRAMP_SECURITY_REQUIRE_TENANCY_DECLARATION", "true\n"),
                ("BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE", "  rootless \n"),
            ]))
            .expect("extract despite trailing whitespace");
            assert_eq!(
                cfg.security
                    .expect("security")
                    .overrides
                    .require_tenancy_declaration,
                Some(true),
                "a trailing-newline bool must parse as true"
            );
            assert_eq!(
                cfg.compute.expect("compute").managed_db_privilege,
                ManagedDbPrivilege::Rootless,
                "a whitespace-padded enum must parse"
            );
        }

        /// Security LOW (file round-trip): the file-only, isolation-bearing structured fields
        /// must survive the file → derived-`Serialize` → `extract_lossy` path intact — the
        /// riskiest being a listener `tenancy: Scoped{…}` (custom `de_opt_tenancy` + an
        /// internally-tagged enum), plus a `security.profiles` and a `security.projects` entry.
        #[test]
        fn file_only_structured_fields_round_trip() {
            let file = r#"(
                serve: ( listeners: {
                    "edge": (
                        component: "tcp-echo", project: "proj", site: "site",
                        bind: "0.0.0.0:7100",
                        tenancy: (mode: "scoped", column: "tenant_id"),
                    ),
                } ),
                security: (
                    profile: "multi-tenant",
                    profiles: { "preview": ( allow_guest_email: true ) },
                    projects: { "proj": ( allow_cross_tenant_db: true ) },
                ),
            )"#;
            // The pipeline path a file-configured serve takes (file → figment → extract), no env.
            let cfg = load_with_figment(
                write_temp_cfg(file).as_path(),
                None,
                &EnvSource::Map(BTreeMap::new()),
                Dict::new(),
            )
            .expect("resolve file through the pipeline");
            let serve = cfg.serve.expect("serve");
            let l = serve.listeners.get("edge").expect("listener edge survived");
            assert_eq!(l.component, "tcp-echo");
            match l.tenancy.as_ref().expect("tenancy survived (Some)") {
                boatramp_core::tenancy::Tenancy::Scoped { column, .. } => {
                    assert_eq!(column, "tenant_id");
                }
                other => panic!("tenancy did not round-trip as Scoped: {other:?}"),
            }
            let sec = cfg.security.expect("security");
            assert!(
                sec.profiles
                    .get("preview")
                    .expect("profile survived")
                    .allow_guest_email
                    == Some(true)
            );
            assert!(
                sec.projects
                    .get("proj")
                    .expect("project override survived")
                    .allow_cross_tenant_db
                    == Some(true)
            );
        }

        /// Write `text` to a unique temp `.cfg` and return its path (leaked into the temp dir;
        /// fine for a test process). Used by the file round-trip test.
        fn write_temp_cfg(text: &str) -> std::path::PathBuf {
            use std::sync::atomic::{AtomicU32, Ordering};
            static N: AtomicU32 = AtomicU32::new(0);
            let path = std::env::temp_dir().join(format!(
                "brtest-rt-{}-{}.cfg",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::write(&path, text).expect("write temp cfg");
            path
        }
    }
}
