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
use serde::Deserialize;

/// RON parse options shared by both loaders: `implicit_some` lets optional fields
/// be written as bare values (`server: "..."`, not `Some("...")`). `pub` so the
/// binary (which re-exports this module) can parse a manifest with the same
/// options after the module moved into this crate.
pub fn ron_options() -> ron::Options {
    ron::Options::default().with_default_extension(ron::extensions::Extensions::IMPLICIT_SOME)
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
    /// Parse a `project.cfg` document (RON). The `routing` section is
    /// compile-checked (route patterns, cron schedules, imports) so a bad config
    /// fails fast.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = ron_options().from_str(text)?;
        config.routing.compile_check()?;
        Ok(config)
    }

    /// Load from `path` (RON). A missing file yields the default config.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(contents) => Self::parse(&contents).map_err(|err| ConfigError::File {
                path: path.display().to_string(),
                source: Box::new(err),
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(err.into()),
        }
    }
}

/// Server daemon configuration, loaded from `boatramp.cfg` (RON). Read by
/// `boatramp serve`; flags/env override the `serve` values.
#[derive(Debug, Default, Deserialize)]
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
}

/// `secrets` section — envelope encryption for private keys at rest.
#[cfg_attr(not(feature = "cluster"), allow(dead_code))]
#[derive(Debug, Clone, Default, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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

impl ServerConfig {
    /// Parse a `boatramp.cfg` document (RON).
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        Ok(ron_options().from_str(text)?)
    }

    /// Load from `path` (RON), then layer `BOATRAMP_*` environment overrides on
    /// top. A missing file yields the default config, so `serve` can be configured
    /// entirely from the environment (12-factor deployments where dropping a
    /// `boatramp.cfg` is awkward — fly.io / Cloudflare / containers).
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let mut config = match std::fs::read_to_string(path) {
            Ok(contents) => Self::parse(&contents).map_err(|err| ConfigError::File {
                path: path.display().to_string(),
                source: Box::new(err),
            })?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(err) => return Err(err.into()),
        };
        config.apply_env_overrides(&EnvSource::Process)?;
        Ok(config)
    }

    /// Layer `BOATRAMP_*` environment overrides onto the loaded config for the
    /// `compute`, `security`, and handler-`sql` sections — the operational knobs
    /// that were previously reachable only through the `boatramp.cfg` file.
    ///
    /// **Precedence: env overrides file.** This matches the existing `serve`
    /// section (its `#[arg(long, env = …)]` flags already let an env var win over
    /// the file value), keeping the resolution rule uniform. A set variable
    /// updates the field even when the file also set it; an unset variable leaves
    /// the file (or built-in default) untouched. When a section is absent from the
    /// file but any of its variables are set, the section is materialised from its
    /// defaults first — so no config file is required to configure it.
    ///
    /// `source` supplies the variables (the process environment in production; an
    /// explicit map in tests), so this stays a pure function of its inputs.
    fn apply_env_overrides(&mut self, source: &EnvSource) -> Result<(), ConfigError> {
        // --- compute ---------------------------------------------------------
        // Materialise `[compute]` only if at least one of its variables is set, so
        // an unset environment leaves an absent section absent (⇒ no compute).
        if source.any(COMPUTE_ENV_VARS) {
            let compute = self.compute.get_or_insert_with(ComputeConfig::default);
            if let Some(v) = source.get("BOATRAMP_COMPUTE_BRIDGE") {
                compute.bridge = v;
            }
            if let Some(v) = source.get("BOATRAMP_COMPUTE_SUBNET") {
                compute.subnet = v;
            }
            if let Some(v) = source.parse("BOATRAMP_COMPUTE_VCPUS")? {
                compute.vcpus = v;
            }
            if let Some(v) = source.parse("BOATRAMP_COMPUTE_MEM_MIB")? {
                compute.mem_mib = v;
            }
            if let Some(v) = source.get("BOATRAMP_COMPUTE_REGION") {
                compute.region = Some(v);
            }
            if let Some(v) = source.get("BOATRAMP_COMPUTE_SQL_SHIM_URL") {
                compute.sql_shim_url = Some(v);
            }
            // The two shared-kernel enums have no `FromStr`, only a serde
            // `rename_all = "lowercase"`; map their variants by that same spelling.
            if let Some(v) = source.parse_enum(
                "BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE",
                &[
                    ("rootless", ManagedDbPrivilege::Rootless),
                    ("caps", ManagedDbPrivilege::Caps),
                ],
            )? {
                compute.managed_db_privilege = v;
            }
            if let Some(v) = source.parse_enum(
                "BOATRAMP_COMPUTE_DOCKER_ENDPOINT",
                &[
                    ("published", boatramp_docker::DockerEndpoint::Published),
                    ("bridge", boatramp_docker::DockerEndpoint::Bridge),
                ],
            )? {
                compute.docker_endpoint = v;
            }
            if let Some(v) = source.parse_enum(
                "BOATRAMP_COMPUTE_DOCKER_VOLUME_MODE",
                &[
                    ("named", boatramp_docker::DockerVolumeMode::Named),
                    ("bind", boatramp_docker::DockerVolumeMode::Bind),
                ],
            )? {
                compute.docker_volume_mode = v;
            }
            // Kernel trust anchors — comma-separated lists. These are
            // security-critical: they are the trust anchor for the posture-scaled
            // kernel bar, so a value here decides which kernels a `multi-tenant`
            // node will boot. In a 12-factor deployment the environment IS the
            // operator's trusted config source (a fly.toml `[env]` is committed the
            // same as a file), so they are exposed here — but an operator should
            // know the environment is *more* visible than a file (it leaks through
            // `/proc/<pid>/environ` and is inherited by every subprocess), so a
            // file remains the better home for them when one is available.
            if let Some(v) = source.parse_list("BOATRAMP_COMPUTE_KERNEL_SIGNING_PUBKEYS") {
                compute.kernel_signing_pubkeys = v;
            }
            if let Some(v) = source.parse_list("BOATRAMP_COMPUTE_KERNEL_ALLOWED_HASHES") {
                compute.kernel_allowed_hashes = v;
            }
        }

        // --- security --------------------------------------------------------
        // Always materialise `[security]` when any knob is set: an absent section
        // resolves to the strict `multi-tenant` default, and an env override then
        // layers over that exactly as a file `overrides` block would.
        if source.any(SECURITY_ENV_VARS) {
            let security = self
                .security
                .get_or_insert_with(boatramp_core::security::SecurityConfig::default);
            if let Some(v) = source.get("BOATRAMP_SECURITY_PROFILE") {
                security.profile = Some(v);
            }
            let o = &mut security.overrides;
            if let Some(v) =
                source.parse_bool("BOATRAMP_SECURITY_ALLOW_UNAUTHENTICATED_PUBLIC_BIND")?
            {
                o.allow_unauthenticated_public_bind = Some(v);
            }
            if let Some(v) = source.parse("BOATRAMP_SECURITY_MAX_UPLOAD_BYTES")? {
                o.max_upload_bytes = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_ALLOW_SITE_UNIX_UPSTREAMS")? {
                o.allow_site_unix_upstreams = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_ALLOW_SITE_PRIVATE_UPSTREAMS")? {
                o.allow_site_private_upstreams = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_ALLOW_GUEST_PRIVATE_EGRESS")? {
                o.allow_guest_private_egress = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_ALLOW_GUEST_SELF_EGRESS")? {
                o.allow_guest_self_egress = Some(v);
            }
            if let Some(v) = source.parse("BOATRAMP_SECURITY_MAX_HANDLER_BLOB_BYTES")? {
                o.max_handler_blob_bytes = Some(v);
            }
            if let Some(v) = source.parse("BOATRAMP_SECURITY_MAX_COMPONENT_BYTES")? {
                o.max_component_bytes = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_OIDC_REQUIRE_AUDIENCE")? {
                o.oidc_require_audience = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_DOMAIN_VERIFY_ALLOW_PRIVATE")? {
                o.domain_verify_allow_private = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_DOMAIN_VERIFY_SELF_SERVE")? {
                o.domain_verify_self_serve = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_ALLOW_SHARED_KERNEL_COMPUTE")? {
                o.allow_shared_kernel_compute = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_ALLOW_COMPUTE_EXEC")? {
                o.allow_compute_exec = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_RATELIMIT_FAIL_OPEN")? {
                o.ratelimit_fail_open = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_ALLOW_IMPLICIT_ROUTING")? {
                o.allow_implicit_routing = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_REQUIRE_POP")? {
                o.require_pop = Some(v);
            }
            if let Some(v) = source.parse_bool("BOATRAMP_SECURITY_REQUIRE_DOMAIN_VERIFICATION")? {
                o.require_domain_verification = Some(v);
            }
        }

        // --- handler sql (`handlers.bindings.sql`) ---------------------------
        // Materialise the nested `handlers.bindings.sql` chain only when a `sql`
        // variable is set, so an unset environment doesn't conjure an empty
        // handlers section. The variables mirror the config path
        // (`BOATRAMP_HANDLERS_SQL_*`) and cover the cluster-vs-single-node knobs;
        // secrets stay indirected via `*_TOKEN_ENV` names, never the token itself.
        if source.any(SQL_ENV_VARS) {
            let handlers = self.handlers.get_or_insert_with(HandlersConfig::default);
            let sql = handlers
                .bindings
                .sql
                .get_or_insert_with(SqlBindingConfig::default);
            if let Some(v) = source.get("BOATRAMP_HANDLERS_SQL_DIR") {
                sql.dir = Some(PathBuf::from(v));
            }
            if let Some(v) = source.get("BOATRAMP_HANDLERS_SQL_URL") {
                sql.url = Some(v);
            }
            if let Some(v) = source.get("BOATRAMP_HANDLERS_SQL_ADMIN_URL") {
                sql.admin_url = Some(v);
            }
            if let Some(v) = source.get("BOATRAMP_HANDLERS_SQL_REPLICA_URL") {
                sql.replica_url = Some(v);
            }
            if let Some(v) = source.get("BOATRAMP_HANDLERS_SQL_TOKEN_ENV") {
                sql.token_env = Some(v);
            }
            if let Some(v) = source.get("BOATRAMP_HANDLERS_SQL_ADMIN_TOKEN_ENV") {
                sql.admin_token_env = Some(v);
            }
            if let Some(v) = source.get("BOATRAMP_HANDLERS_SQL_PREVIEW_MODE") {
                sql.preview_mode = Some(v);
            }
            if let Some(v) = source.get("BOATRAMP_HANDLERS_SQL_PREVIEW_INIT") {
                sql.preview_init = Some(PathBuf::from(v));
            }
            if let Some(v) = source.parse("BOATRAMP_HANDLERS_SQL_DEPROVISION_GRACE_SECS")? {
                sql.deprovision_grace_secs = Some(v);
            }
        }

        // --- handler sql external databases (`handlers.bindings.sql.databases`) ---
        // The bring-your-own / managed-compute DB map, keyed by name. There is no
        // config file to enumerate the members, so the member names are discovered
        // from the environment: any `BOATRAMP_HANDLERS_SQL_DB_<NAME>_<FIELD>`
        // variable declares database `<NAME>`. Each env-declared DB is merged into
        // (overriding, per field, by key) whatever the file already declared under
        // that name — the same env-over-file precedence as the scalars.
        //
        // The map key may be the **empty string** (the default database that a
        // handler opens as `sql.open("")`); it can't appear in a variable name, so
        // the reserved name token `DEFAULT` addresses it:
        // `BOATRAMP_HANDLERS_SQL_DB_DEFAULT_KIND` populates the `""` key.
        if source.any_with_prefix(SQL_DB_ENV_PREFIX) {
            let handlers = self.handlers.get_or_insert_with(HandlersConfig::default);
            let sql = handlers
                .bindings
                .sql
                .get_or_insert_with(SqlBindingConfig::default);
            for name in source.sql_database_names() {
                // `DEFAULT` is the reserved token for the `""` (default) database.
                let key = if name == "DEFAULT" {
                    String::new()
                } else {
                    name.clone()
                };
                let db = sql.databases.entry(key).or_default();
                let prefix = format!("{SQL_DB_ENV_PREFIX}{name}_");
                if let Some(v) = source.get(&format!("{prefix}KIND")) {
                    db.kind = v;
                }
                if let Some(v) = source.get(&format!("{prefix}URL_ENV")) {
                    db.url_env = v;
                }
                if let Some(v) = source.get(&format!("{prefix}READ_URL_ENV")) {
                    db.read_url_env = Some(v);
                }
                if let Some(v) = source.get(&format!("{prefix}COMPUTE")) {
                    db.compute = Some(v);
                }
                if let Some(v) = source.get(&format!("{prefix}DATABASE")) {
                    db.database = Some(v);
                }
                if let Some(v) = source.get(&format!("{prefix}USER")) {
                    db.user = Some(v);
                }
                if let Some(v) = source.get(&format!("{prefix}PASSWORD_ENV")) {
                    db.password_env = Some(v);
                }
                if let Some(v) = source.parse(&format!("{prefix}POOL_MAX"))? {
                    db.pool_max = Some(v);
                }
                if let Some(v) = source.parse_bool(&format!("{prefix}READ_ONLY"))? {
                    db.read_only = v;
                }
                if let Some(v) = source.parse_bool(&format!("{prefix}ALLOW_PREVIEW"))? {
                    db.allow_preview = v;
                }
                if let Some(v) = source.parse(&format!("{prefix}CONNECT_TIMEOUT_SECS"))? {
                    db.connect_timeout_secs = Some(v);
                }
                if let Some(v) = source.get(&format!("{prefix}IMAGE")) {
                    db.image = Some(v);
                }
                if let Some(v) = source.parse(&format!("{prefix}VOLUME_SIZE_MIB"))? {
                    db.volume_size_mib = Some(v);
                }
                if let Some(v) = source.parse_enum(
                    &format!("{prefix}TENANT"),
                    &[
                        ("single", TenantIsolation::Single),
                        ("shared", TenantIsolation::Shared),
                    ],
                )? {
                    db.tenant = v;
                }
                if let Some(v) = source.parse_enum(
                    &format!("{prefix}TENANT_SCOPE"),
                    &[
                        ("project", TenantScope::Project),
                        ("site", TenantScope::Site),
                    ],
                )? {
                    db.tenant_scope = v;
                }
                if let Some(v) = source.parse_bool(&format!("{prefix}RLS_SESSION"))? {
                    db.rls_session = v;
                }
            }
        }

        // --- secrets (`[secrets]`) -------------------------------------------
        // Envelope encryption for private keys at rest. `kek_file` holds a *path*
        // (never key material) and the Vault token stays indirected via
        // `token_env` (a variable name, not the token). Materialise the nested
        // `vault` sub-config only when a vault variable is set.
        if source.any(SECRETS_ENV_VARS) {
            let secrets = self.secrets.get_or_insert_with(SecretsConfig::default);
            if let Some(v) = source.get("BOATRAMP_SECRETS_ENVELOPE") {
                secrets.envelope = v;
            }
            if let Some(v) = source.get("BOATRAMP_SECRETS_KEK_FILE") {
                secrets.kek_file = Some(PathBuf::from(v));
            }
            if source.any(SECRETS_VAULT_ENV_VARS) {
                let vault = secrets
                    .vault
                    .get_or_insert_with(VaultSecretsConfig::default);
                if let Some(v) = source.get("BOATRAMP_SECRETS_VAULT_ADDR") {
                    vault.addr = v;
                }
                if let Some(v) = source.get("BOATRAMP_SECRETS_VAULT_KEY") {
                    vault.key = v;
                }
                if let Some(v) = source.get("BOATRAMP_SECRETS_VAULT_TOKEN_ENV") {
                    vault.token_env = v;
                }
            }
        }

        // --- cluster (`[cluster]`) -------------------------------------------
        // The self-hosted cluster section's own fields. The founding/joining
        // *actions* already have their own `serve` flags with env
        // (`BOATRAMP_CLUSTER_INIT` / `_JOIN` / `_ADVERTISE_ADDR`); those are
        // distinct from — and not duplicated by — the `[cluster]` section fields
        // exposed here. `join_token` keeps a secret out of plain sight via the
        // usual `env:VAR` / `path:/file` prefix, so the env holds the *reference*,
        // not the token. `ClusterConfig` has no `Default` (a founder needs at least
        // a `listen`), so a `BOATRAMP_CLUSTER_LISTEN` is required to materialise an
        // absent section from the environment.
        if source.any(CLUSTER_ENV_VARS) {
            // Materialise an absent section only if a bind address is supplied;
            // otherwise there is no valid `ClusterConfig` to build (it has no
            // `Default` — a node must know where to bind its mesh). When the file
            // already declared `[cluster]`, its `listen` stands and the other env
            // fields layer over it even without `BOATRAMP_CLUSTER_LISTEN`.
            let listen = source.parse::<SocketAddr>("BOATRAMP_CLUSTER_LISTEN")?;
            if self.cluster.is_none() {
                if let Some(listen) = listen {
                    self.cluster = Some(ClusterConfig {
                        listen,
                        root_pubkeys: Vec::new(),
                        seeds: Vec::new(),
                        join_token: None,
                        store_dir: None,
                        mesh: None,
                    });
                }
            }
            if let Some(cluster) = self.cluster.as_mut() {
                // A `listen` override applies to an already-present section too (a
                // freshly materialised one already carries it).
                if let Some(v) = listen {
                    cluster.listen = v;
                }
                if let Some(v) = source.parse_list("BOATRAMP_CLUSTER_ROOT_PUBKEYS") {
                    cluster.root_pubkeys = v;
                }
                if let Some(v) = source.parse_list("BOATRAMP_CLUSTER_SEEDS") {
                    cluster.seeds = v;
                }
                if let Some(v) = source.get("BOATRAMP_CLUSTER_JOIN_TOKEN") {
                    cluster.join_token = Some(v);
                }
                if let Some(v) = source.get("BOATRAMP_CLUSTER_STORE_DIR") {
                    cluster.store_dir = Some(PathBuf::from(v));
                }
                if source.any(CLUSTER_MESH_ENV_VARS) {
                    let mesh = cluster.mesh.get_or_insert_with(MeshConfig::default);
                    if let Some(v) = source.get("BOATRAMP_CLUSTER_MESH_KEY_FILE") {
                        mesh.key_file = Some(PathBuf::from(v));
                    }
                    if let Some(v) = source.get("BOATRAMP_CLUSTER_MESH_KEY_ROTATION") {
                        mesh.key_rotation = Some(v);
                    }
                    if let Some(v) = source.get("BOATRAMP_CLUSTER_MESH_JOIN_TOKEN_TTL") {
                        mesh.join_token_ttl = Some(v);
                    }
                    if let Some(v) =
                        source.parse_bool("BOATRAMP_CLUSTER_MESH_GATE_CLIENT_WRITES")?
                    {
                        mesh.gate_client_writes = Some(v);
                    }
                }
            }
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
    "BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE",
    "BOATRAMP_COMPUTE_DOCKER_ENDPOINT",
    "BOATRAMP_COMPUTE_DOCKER_VOLUME_MODE",
    "BOATRAMP_COMPUTE_KERNEL_SIGNING_PUBKEYS",
    "BOATRAMP_COMPUTE_KERNEL_ALLOWED_HASHES",
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
    "BOATRAMP_SECURITY_MAX_HANDLER_BLOB_BYTES",
    "BOATRAMP_SECURITY_MAX_COMPONENT_BYTES",
    "BOATRAMP_SECURITY_OIDC_REQUIRE_AUDIENCE",
    "BOATRAMP_SECURITY_DOMAIN_VERIFY_ALLOW_PRIVATE",
    "BOATRAMP_SECURITY_DOMAIN_VERIFY_SELF_SERVE",
    "BOATRAMP_SECURITY_ALLOW_SHARED_KERNEL_COMPUTE",
    "BOATRAMP_SECURITY_ALLOW_COMPUTE_EXEC",
    "BOATRAMP_SECURITY_RATELIMIT_FAIL_OPEN",
    "BOATRAMP_SECURITY_ALLOW_IMPLICIT_ROUTING",
    "BOATRAMP_SECURITY_REQUIRE_POP",
    "BOATRAMP_SECURITY_REQUIRE_DOMAIN_VERIFICATION",
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
    "_CONNECT_TIMEOUT_SECS",
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

/// The `BOATRAMP_*` variables that populate the nested `[cluster.mesh]` sub-config.
const CLUSTER_MESH_ENV_VARS: &[&str] = &[
    "BOATRAMP_CLUSTER_MESH_KEY_FILE",
    "BOATRAMP_CLUSTER_MESH_KEY_ROTATION",
    "BOATRAMP_CLUSTER_MESH_JOIN_TOKEN_TTL",
    "BOATRAMP_CLUSTER_MESH_GATE_CLIENT_WRITES",
];

/// Where env-override values come from: the real process environment, or an
/// explicit map for a deterministic unit test. Keeping the lookup behind this enum
/// lets [`ServerConfig::apply_env_overrides`] be tested without touching (racy,
/// process-global) `std::env`.
enum EnvSource {
    /// The live process environment (`std::env::var`).
    Process,
    /// A fixed name→value map (tests only).
    #[cfg(test)]
    Map(BTreeMap<String, String>),
}

impl EnvSource {
    /// The value of `var`, if set to a non-empty string. An empty value is treated
    /// as unset so an accidental `VAR=` doesn't clobber a file value with `""`.
    fn get(&self, var: &str) -> Option<String> {
        let raw = match self {
            Self::Process => std::env::var(var).ok(),
            #[cfg(test)]
            Self::Map(m) => m.get(var).cloned(),
        };
        raw.filter(|v| !v.is_empty())
    }

    /// Whether any of `vars` is set (to a non-empty value).
    fn any(&self, vars: &[&str]) -> bool {
        vars.iter().any(|v| self.get(v).is_some())
    }

    /// Whether any variable whose name starts with `prefix` is set (to a
    /// non-empty value). Used to decide whether to materialise a keyed map (the
    /// `databases` env scheme) whose member names aren't known ahead of time.
    fn any_with_prefix(&self, prefix: &str) -> bool {
        self.names()
            .any(|name| name.starts_with(prefix) && self.get(&name).is_some())
    }

    /// The full set of variable names visible to this source. Used to discover the
    /// keyed-map member names from the environment (there is no config file to
    /// enumerate them). Returned owned so it doesn't borrow the process env.
    fn names(&self) -> Box<dyn Iterator<Item = String> + '_> {
        match self {
            Self::Process => Box::new(std::env::vars().map(|(k, _)| k)),
            #[cfg(test)]
            Self::Map(m) => Box::new(m.keys().cloned()),
        }
    }

    /// Parse `var` as one of a fixed set of string-mapped variants, mapping an
    /// unknown value to a clear [`ConfigError::Env`] that names the variable and
    /// the accepted values. Used for the config enums that have no `FromStr`
    /// (their only string mapping is a serde `rename_all`). `Ok(None)` when unset.
    fn parse_enum<T: Copy>(
        &self,
        var: &str,
        variants: &[(&str, T)],
    ) -> Result<Option<T>, ConfigError> {
        match self.get(var) {
            Some(raw) => {
                let lower = raw.trim().to_ascii_lowercase();
                variants
                    .iter()
                    .find(|(name, _)| *name == lower)
                    .map(|(_, v)| Some(*v))
                    .ok_or_else(|| ConfigError::Env {
                        var: var.to_string(),
                        reason: format!(
                            "expected one of {}, got {raw:?}",
                            variants
                                .iter()
                                .map(|(n, _)| *n)
                                .collect::<Vec<_>>()
                                .join("/")
                        ),
                    })
            }
            None => Ok(None),
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

    /// Parse `var` as any [`FromStr`](std::str::FromStr) type (numbers), mapping a
    /// parse failure to a clear [`ConfigError::Env`]. `Ok(None)` when the variable
    /// is unset.
    fn parse<T>(&self, var: &str) -> Result<Option<T>, ConfigError>
    where
        T: std::str::FromStr,
        T::Err: std::fmt::Display,
    {
        match self.get(var) {
            Some(raw) => raw.parse::<T>().map(Some).map_err(|e| ConfigError::Env {
                var: var.to_string(),
                reason: e.to_string(),
            }),
            None => Ok(None),
        }
    }

    /// Parse `var` as a boolean, accepting the common truthy/falsey spellings
    /// (`true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`) case-insensitively so an
    /// operator isn't surprised by a strict `true`-only parse. `Ok(None)` when
    /// unset.
    fn parse_bool(&self, var: &str) -> Result<Option<bool>, ConfigError> {
        match self.get(var) {
            Some(raw) => match raw.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" | "on" => Ok(Some(true)),
                "false" | "0" | "no" | "off" => Ok(Some(false)),
                other => Err(ConfigError::Env {
                    var: var.to_string(),
                    reason: format!("expected a boolean (true/false), got {other:?}"),
                }),
            },
            None => Ok(None),
        }
    }
}

/// How a **managed database** (PLAN-managed-compute-sql) runs its stock image on a
/// shared-kernel backend, whose entrypoint would otherwise fail under the dropped-`ALL`
/// hardening. `rootless` (the default) needs no capabilities and works under any
/// posture; `caps` is the fallback for an image that won't run rootless.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
    /// Guest-reachable base URL of the compute **sql-shim** (PLAN-compute-bindings) —
    /// e.g. `http://10.0.0.1:8081` (the compute bridge gateway) or the docker bridge
    /// gateway. Set ⇒ a workload's `--bind sql` reaches the managed database through a
    /// listener bound on `0.0.0.0:<port>`. `None` (default) ⇒ compute sql bindings off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub sql_shim_url: Option<String>,
    /// Privilege strategy for a managed database's stock image on a shared-kernel
    /// backend (see [`ManagedDbPrivilege`]). `rootless` by default.
    #[serde(default)]
    #[cfg_attr(not(feature = "handlers"), allow(dead_code))]
    pub managed_db_privilege: ManagedDbPrivilege,
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
            sql_shim_url: None,
            managed_db_privilege: ManagedDbPrivilege::default(),
        }
    }
}

/// `cluster` section — self-hosted **cluster mode**. Parsed in
/// every build so config files stay portable; only *consumed* when the `cluster`
/// feature is compiled in (`boatramp serve --mode cluster`).
#[cfg_attr(not(feature = "cluster"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Default, Deserialize)]
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
}

/// `handlers` section — server-side handler runtime config (read by `serve`).
/// Parsed in every build (so config files stay portable), but only *consumed*
/// when the `handlers` feature is compiled in.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct HandlersConfig {
    /// `handlers.bindings` — which backend serves each handler binding.
    pub bindings: BindingsConfig,
    /// Use the wasmtime **pooling** instance allocator: faster
    /// instantiation at the cost of a large up-front virtual-memory reservation.
    /// Off by default — opt in and benchmark for your workload.
    pub pooling: bool,
    /// Engine-wide **safety max** on a *connection-bearing* invocation (a site
    /// handler or a synchronous function/webhook invoke), milliseconds. A route
    /// or function may declare a *lower* timeout, never a higher one. Kept tight
    /// on purpose: a client, proxy, and the shared request pool are all blocked
    /// while a sync handler runs. Absent ⇒ 10s (the historical default). This is
    /// a node safety ceiling, not a per-invocation budget, and is distinct from
    /// a per-site `max_timeout_ms`.
    pub sync_max_timeout_ms: Option<u64>,
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
    /// Optional ceiling on a guest's **outbound** `wasi:http` call — the connect
    /// and time-to-first-byte wait — milliseconds, independent of the invocation
    /// timeout, so a hung upstream is bounded on its own terms. The streaming
    /// (between-bytes) timeout is left at wasmtime's default so a slow token
    /// stream is not cut mid-flight. Absent ⇒ wasmtime's default.
    pub outbound_timeout_ms: Option<u64>,
}

/// `handlers.bindings` — per-binding backend configuration. kv/blob reuse the
/// server's own KV/Storage backends (per-site prefixed); `sql` is the single
/// libsql backend, whose single-node-vs-cluster split is the only choice.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
#[derive(Debug, Clone, Default, Deserialize)]
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
#[derive(Debug, Clone, Default, Deserialize)]
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
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ExternalDatabaseConfig {
    /// Engine: `postgres` (aliases `postgresql`/`pg`) or `mysql` (alias
    /// `mariadb`).
    pub kind: String,
    /// Name of the env var holding the connection URL (e.g.
    /// `postgres://user:pw@host/db`). Required unless `compute` is set.
    pub url_env: String,
    /// Optional env var holding a **read-replica** connection URL. When set,
    /// `open-read-only` transactions route there; writes stay on `url_env`.
    pub read_url_env: Option<String>,
    /// The name of a **compute workload** (a Postgres/MySQL server boatramp runs)
    /// to source this database from, instead of `url_env`. boatramp resolves the
    /// workload's live endpoint and builds the connection. Mutually exclusive with
    /// `url_env`.
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
}

/// How a managed compute-backed database is physically isolated per tenant (2×2 axis
/// 1). `Single` = a dedicated server (container) per tenant (isolation by separate
/// process); `Shared` = one server with a per-tenant database + login role (isolation
/// by grants — Postgres `REVOKE CONNECT FROM PUBLIC` + owner grant; MySQL per-schema
/// grant), so a tenant's role cannot connect to another tenant's database.
#[cfg_attr(not(feature = "handlers"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantScope {
    /// A tenant is a **project** (the default).
    #[default]
    Project,
    /// A tenant is a **site** (finer than project).
    Site,
}

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
#[derive(Debug, Clone, Copy, Default, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
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
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ServeConfig {
    /// Bind address (e.g. `0.0.0.0:8080`).
    pub addr: Option<SocketAddr>,
    /// Data directory for filesystem backends.
    pub data_dir: Option<PathBuf>,
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
}

/// `[serve.console]` — the embedded web console (a Wasm SPA baked into the
/// binary with the `console` build feature). Opt-in: the static shell holds no
/// secrets and the `/api` it drives is token-gated, so it is served
/// **unauthenticated** at a deliberately obscure path (a bearer token can't gate
/// a top-level browser navigation anyway — the path is the obscurity, the token
/// is the real gate).
#[cfg_attr(not(feature = "console"), allow(dead_code))]
#[derive(Debug, Clone, Default, Deserialize)]
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
#[derive(Debug, Clone, Deserialize)]
pub struct BuildConfig {
    /// Shell command to run (e.g. `npm run build`).
    pub command: String,
    /// Directory the build emits, published by `sync` (e.g. `dist`).
    #[serde(default)]
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
        // A non-boolean value is a clear error, not a silent default.
        let mut cfg = ServerConfig::default();
        let err = cfg
            .apply_env_overrides(&env(&[("BOATRAMP_SECURITY_REQUIRE_POP", "maybe")]))
            .expect_err("garbage boolean is rejected");
        match err {
            ConfigError::Env { var, .. } => assert_eq!(var, "BOATRAMP_SECURITY_REQUIRE_POP"),
            other => panic!("expected ConfigError::Env, got {other:?}"),
        }
    }

    #[test]
    fn env_number_parse_error_names_the_variable() {
        // A non-numeric numeric var is rejected with the variable named.
        let mut cfg = ServerConfig::default();
        let err = cfg
            .apply_env_overrides(&env(&[("BOATRAMP_COMPUTE_VCPUS", "lots")]))
            .expect_err("garbage number is rejected");
        match err {
            ConfigError::Env { var, .. } => assert_eq!(var, "BOATRAMP_COMPUTE_VCPUS"),
            other => panic!("expected ConfigError::Env, got {other:?}"),
        }
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
        // The construens acceptance case: with NO `boatramp.cfg` at all, the
        // environment alone stands up a managed co-located Postgres. It configures
        // the default (`""`-named) database in `handlers.bindings.sql.databases`
        // (kind=postgres, compute=pg, database+user set), the `[secrets]` envelope
        // (local + a kek path so the managed credential can be sealed), and
        // `compute.managed_db_privilege = rootless`. All three sections start absent.
        let mut cfg = ServerConfig::default();
        assert!(cfg.handlers.is_none() && cfg.secrets.is_none() && cfg.compute.is_none());

        cfg.apply_env_overrides(&env(&[
            // The default database is addressed by the reserved `DEFAULT` token,
            // which maps to the empty-string map key.
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

        // The default (`""`-keyed) managed database exists with the right source.
        let sql = cfg
            .handlers
            .expect("handlers materialised from env")
            .bindings
            .sql
            .expect("sql binding materialised from env");
        let db = sql
            .databases
            .get("")
            .expect("the default `\"\"`-named database was created from DEFAULT");
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
                        "analytics": ( kind: "postgres", url_env: "FILE_PG_URL", pool_max: 4 ),
                    },
                ) ) ),
            )"#,
        );
        cfg.apply_env_overrides(&env(&[
            // Override the file database's pool size (merge by key, per field).
            ("BOATRAMP_HANDLERS_SQL_DB_analytics_POOL_MAX", "32"),
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
            analytics.url_env, "FILE_PG_URL",
            "the file's url_env survives (env didn't touch it)"
        );

        let events = &sql.databases["events_log"];
        assert_eq!(events.kind, "mysql");
        assert_eq!(events.url_env, "EVENTS_URL");
        assert_eq!(events.read_url_env.as_deref(), Some("EVENTS_RO_URL"));
        assert!(events.read_only);
    }

    #[test]
    fn env_enum_parse_error_names_the_variable_and_variants() {
        // An unknown enum value is a clear error that names the offending variable.
        let mut cfg = ServerConfig::default();
        let err = cfg
            .apply_env_overrides(&env(&[(
                "BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE",
                "superuser",
            )]))
            .expect_err("unknown enum variant is rejected");
        match err {
            ConfigError::Env { var, reason } => {
                assert_eq!(var, "BOATRAMP_COMPUTE_MANAGED_DB_PRIVILEGE");
                assert!(reason.contains("rootless") && reason.contains("caps"));
            }
            other => panic!("expected ConfigError::Env, got {other:?}"),
        }
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

        // Without a listen (and no file section) there is nothing to materialise:
        // a non-listen cluster var alone leaves the section absent.
        let mut cfg = ServerConfig::default();
        cfg.apply_env_overrides(&env(&[("BOATRAMP_CLUSTER_SEEDS", "https://10.0.0.1:8080")]))
            .expect("applies");
        assert!(
            cfg.cluster.is_none(),
            "no listen + no file section ⇒ no cluster"
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
}
