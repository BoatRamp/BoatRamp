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

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use boatramp_core::config::DeployConfig;
use serde::Deserialize;

/// RON parse options shared by both loaders: `implicit_some` lets optional fields
/// be written as bare values (`server: "..."`, not `Some("...")`).
fn ron_options() -> ron::Options {
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
        source: Box<ConfigError>,
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

impl ServerConfig {
    /// Parse a `boatramp.cfg` document (RON).
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        Ok(ron_options().from_str(text)?)
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
}

/// The built-in **boatramp kernel-signing public key** (`es256:…`), whose private
/// half lives as the `KERNEL_SIGNING_KEY` Actions secret in
/// [`BoatRamp/boatramp-vmlinux`](https://github.com/BoatRamp/boatramp-vmlinux).
/// Shipped as a default trust anchor so the first-party signed `boatramp-vmlinux`
/// verifies out of the box under the strict posture. An operator can replace
/// `kernel_signing_pubkeys` to trust only their own keys.
pub const BOATRAMP_KERNEL_SIGNING_PUBKEY: &str =
    "es256:02c4e4af2e9cba6ba6745c513f193622e6674a8b2d0187ebea5612f5b46a7eade4";

impl Default for ComputeConfig {
    fn default() -> Self {
        Self {
            bridge: "br-boatramp".to_string(),
            subnet: "10.0.0.0/24".to_string(),
            vcpus: 0,
            mem_mib: 0,
            kernel_signing_pubkeys: vec![BOATRAMP_KERNEL_SIGNING_PUBKEY.to_string()],
            // The first-party signed `boatramp-vmlinux` release (v0.2.0 — a minimal
            // Firecracker microVM config, ~39 MB, serial-boot-validated in CI). Its
            // content hash is allow-listed so it clears the strict-posture kernel
            // bar out of the box when an operator selects it as the fleet
            // `compute.default_kernel`. Bump this on each new signed release.
            kernel_allowed_hashes: vec![
                "cf1e590a9e642be3667131ca35fbf390378a457d8908169d2a169608e299d974".to_string(),
            ],
        }
    }
}

/// `cluster` section — self-hosted **cluster mode**. Parsed in
/// every build so config files stay portable; only *consumed* when the `cluster`
/// feature is compiled in (`boatramp serve --mode cluster`).
#[cfg_attr(not(feature = "cluster"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
pub struct ClusterConfig {
    /// This node's stable id (unique within the cluster).
    pub node_id: u64,
    /// Address to bind this node's Raft **peer mesh** on (the `/raft/*` +
    /// `/stream/*` endpoints) — distinct from the public `serve.addr`.
    pub listen: SocketAddr,
    /// Static peer directory (the **genesis seed**): every node's id → its base
    /// URL + mesh public key, e.g.
    /// `"1": (url: "https://10.0.0.1:7000", pubkey: "…hex…")`. Keys are strings
    /// (parsed to node ids at serve time). The `pubkey` (the node's Ed25519 mesh
    /// identity, printed at startup) seeds the mesh **trust set** — the sole
    /// authority on who may speak on the mesh. Consulted only at
    /// genesis; once the cluster has durable state the live trust set is
    /// authoritative.
    #[serde(default)]
    pub peers: std::collections::BTreeMap<String, PeerEntry>,
    /// The **voting quorum**: node ids that vote (e.g. `[1, 2, 3]`). Peers not
    /// listed join as **learners** — they replicate + serve local reads but
    /// don't vote, so far-region nodes give local reads without a WAN quorum.
    /// Empty (default) ⇒ every peer votes.
    #[serde(default)]
    pub voters: Vec<u64>,
    /// Directory for this node's **durable** Raft log/state store (node-local;
    /// distinct from the replicated control plane). Default
    /// `<data-dir>/raft`.
    #[serde(default)]
    pub store_dir: Option<PathBuf>,
    /// Set on exactly one node at first cluster bring-up to initialize
    /// membership. A no-op on a node already part of a cluster (restart).
    #[serde(default)]
    pub bootstrap: bool,
    /// Mesh identity + TLS settings. Absent ⇒ defaults (identity key
    /// auto-generated under `<data-dir>/mesh/identity.key`).
    #[serde(default)]
    pub mesh: Option<MeshConfig>,
}

/// One entry in the cluster peer directory: a node's mesh address + identity.
#[cfg_attr(not(feature = "cluster"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerEntry {
    /// The node's mesh base URL, e.g. `https://10.0.0.1:7000` (mesh TLS ⇒ https).
    pub url: String,
    /// The node's mesh public key (Ed25519 `SubjectPublicKeyInfo`, hex-encoded) —
    /// its authenticated identity. Print a node's key at startup / with the
    /// cluster tooling. Not a secret.
    pub pubkey: String,
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
            SignerAlg::Es256 => boatramp_core::cose::TokenAlg::Es256,
            SignerAlg::Ed25519 => boatramp_core::cose::TokenAlg::Ed25519,
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
            AuthSignerConfig::Local { private_key } => SignerConfig::Local {
                private_key: private_key.clone(),
            },
            AuthSignerConfig::Vault {
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
            AuthSignerConfig::AwsKms { key_id, region } => SignerConfig::AwsKms {
                key_id: key_id.clone(),
                region: region.clone(),
            },
            AuthSignerConfig::GcpKms {
                key_version,
                access_token_env,
            } => SignerConfig::GcpKms {
                key_version: key_version.clone(),
                access_token_env: access_token_env.clone(),
            },
            AuthSignerConfig::AzureKv {
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
            AuthSignerConfig::Pkcs11 {
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
    fn cluster_section_parses_node_peers_and_bootstrap() {
        let cfg = server(
            r#"(
                cluster: (
                    node_id: 2,
                    listen: "10.0.0.2:7000",
                    bootstrap: true,
                    voters: [1, 2, 3],
                    peers: {
                        "1": (url: "https://10.0.0.1:7000", pubkey: "aa01"),
                        "2": (url: "https://10.0.0.2:7000", pubkey: "bb02"),
                        "3": (url: "https://10.0.0.3:7000", pubkey: "cc03"),
                    },
                ),
            )"#,
        );
        let cluster = cfg.cluster.unwrap();
        assert_eq!(cluster.node_id, 2);
        assert_eq!(
            cluster.listen,
            "10.0.0.2:7000".parse::<std::net::SocketAddr>().unwrap()
        );
        assert!(cluster.bootstrap);
        assert_eq!(cluster.peers.len(), 3);
        assert_eq!(
            cluster.peers.get("1").map(|p| p.url.as_str()),
            Some("https://10.0.0.1:7000")
        );
        assert_eq!(
            cluster.peers.get("1").map(|p| p.pubkey.as_str()),
            Some("aa01")
        );
        assert_eq!(cluster.voters, vec![1, 2, 3]);
        // store_dir defaults to None (→ <data-dir>/raft at serve time).
        assert!(cluster.store_dir.is_none());
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
}
