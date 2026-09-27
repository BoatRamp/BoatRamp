//! The `apply` subcommand (0.2.0): declarative **project manifest → reconcile to
//! desired state**.
//!
//! `boatramp apply -f apply.cfg` reads one RON manifest that declares a whole
//! project — N sites + top-level functions + compute workloads — and reconciles
//! it under a single project, idempotently. Sites reuse the same
//! content-addressed deploy flow as `sync` (hash the tree, upload only the blobs
//! the server is missing, then atomically activate), so re-applying an unchanged
//! tree uploads nothing. Functions and compute are PUT (create-or-replace) to
//! their project-scoped endpoints.
//!
//! `--dry-run` prints the plan (what would be built / deployed / activated) and
//! mutates nothing — no build, no upload, no PUT.
//!
//! **Upsert, never prune.** `apply` reconciles *only* the sites/functions/compute
//! it names, create-or-replace; it never enumerates or deletes anything else. So
//! declarative and imperative management freely coexist: sites, functions,
//! compute, domains, aliases, and tokens created via the CLI/API that are absent
//! from the manifest are left untouched. Management is cooperative
//! (last-writer-wins per named resource), not authoritative — there is
//! deliberately no `--prune` that would make the manifest the sole source of
//! truth and reap unmanaged resources.

use std::path::{Path, PathBuf};

use boatramp_core::config::{DeployConfig, HandlerLimits, SiteConfig};
use serde::Deserialize;
use serde_json::json;

use crate::client;
use crate::config::{BuildConfig, ProjectConfig};

/// A failure in the `apply` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The manifest file was missing — unlike `project.cfg`, an absent `apply.cfg`
    /// is an error (there is nothing to apply).
    #[error("no manifest at {0} (apply needs a manifest to reconcile)")]
    Missing(String),
    /// The manifest failed to parse as RON.
    #[error("invalid manifest syntax: {0}")]
    Ron(#[from] ron::error::SpannedError),
    /// A version-less manifest failed to parse strictly against the current typed
    /// schema. Wrapped to name v0.6.0 + the migration path so the failure reads as
    /// the upgrade UX it is (see [`ApplyManifest::wrap_strict_parse_error`]).
    #[error(
        "this manifest does not match the current (v0.6.0) schema: {source}\n\n\
         The most likely cause is a pre-v0.6.0 `compute[].spec` written as a raw JSON \
         blob — v0.6.0 makes `compute[].spec` the typed `ComputeSpec` (breaking).\n\
         If this is a pre-v0.6.0 manifest, add `version: 1` at the top and run \
         `boatramp config migrate <file>` to upgrade it in place."
    )]
    StrictParse {
        #[source]
        source: ron::error::SpannedError,
    },
    /// A manifest declared `version: N` newer than this build understands.
    #[error(
        "manifest declares version {declared}, but this build only understands up to \
         version {current} (v0.6.0). Upgrade boatramp, or lower the declared version."
    )]
    VersionTooNew { declared: u32, current: u32 },
    /// A migration step failed to transform an older manifest into the current schema.
    #[error("migrating manifest from version {from}: {reason}")]
    Migration { from: u32, reason: String },
    /// A site's `[handlers.graphql]` set BOTH `safelisted_ops` and
    /// `safelisted_ops_path` — they are mutually exclusive (pick one source).
    #[error(
        "site {site}: `[handlers.graphql]` sets both `safelisted_ops` (inline) and \
         `safelisted_ops_path` (file) — they are mutually exclusive; use one source of \
         safelisted operations"
    )]
    SafelistConflict { site: String },
    /// Reading a site's `safelisted_ops_path` file failed (client-side).
    #[error("site {site}: reading safelisted_ops_path {path}: {source}")]
    SafelistFile {
        site: String,
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// A site's `routing` failed its compile-check (a bad route/cron pattern).
    #[error("site {site}: routing: {source}")]
    Routing {
        site: String,
        #[source]
        source: boatramp_core::ConfigError,
    },
    /// A control-plane request failed (the `connect`/resolve path).
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A control-plane request from the reconcile core failed, carrying the
    /// 404/409 classification the core acts on (see [`CpError`]).
    #[error(transparent)]
    Cp(#[from] CpError),
    /// Loading/parsing the project config (`project.cfg`) failed.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// The optional pre-deploy build step failed.
    #[error(transparent)]
    Build(#[from] crate::build::Error),
    /// Building a site's manifest / uploading blobs failed.
    #[error(transparent)]
    Sync(#[from] crate::sync::Error),
    /// A local filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Encoding a request body failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// `apply` module result; `Err` is [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// The control-plane operations the `apply` reconcile core performs — a seam over
/// the concrete HTTP [`client::ControlPlane`] so the reconcile logic (create-or-
/// update, config-before-activate, create-on-404 / ignore-on-409) is
/// unit-testable against a mock without a live server. Static-dispatched: the
/// reconcile fns are generic over `C: ControlPlane`, so no `async-trait` / boxing.
#[allow(async_fn_in_trait)] // crate-internal trait; never used as `dyn`
trait ControlPlane {
    /// Read a project; a missing one is [`CpError::NotFound`].
    async fn get_project(&self, name: &str) -> CpResult<serde_json::Value>;
    /// Create a project; a concurrent create is [`CpError::Conflict`].
    async fn create_project(&self, body: &serde_json::Value) -> CpResult<serde_json::Value>;
    /// Negotiate a deployment; the reply lists the blob hashes still missing.
    async fn create_deployment(
        &self,
        site: &str,
        manifest: &boatramp_core::deploy::Manifest,
    ) -> CpResult<crate::client::CreateDeploymentResponse>;
    /// Upload one missing blob by content-address.
    async fn upload_blob_source(
        &self,
        hash: &str,
        source: &crate::sync::BlobSource,
    ) -> CpResult<()>;
    /// PUT a site's mutable config (applied before activation).
    async fn put_site_config(&self, site: &str, config: &SiteConfig) -> CpResult<()>;
    /// Flip a site live to a deployment id.
    async fn activate(&self, site: &str, id: &str) -> CpResult<()>;
    /// Stage a local file as a content-addressed blob, returning its hash.
    async fn put_file_blob(&self, path: &Path) -> CpResult<String>;
    /// Create/replace a top-level function record. Drives the async (`?wait=false`) +
    /// deferred-compose (`?compose=defer`) deploy and polls to a terminal outcome (bug #499), so
    /// the slow server-side compile/compose never blocks the control-plane request worker.
    async fn deploy_function(&self, name: &str, body: &serde_json::Value) -> CpResult<()>;
    /// Promote the project's staged subgraphs in one composition — the `?compose=defer`
    /// counterpart. Called once after all function deploys (bug #499). A no-op when nothing staged.
    async fn compose_subgraphs(&self) -> CpResult<()>;
    /// Create/replace a compute workload spec.
    async fn put_compute(
        &self,
        name: &str,
        body: &serde_json::Value,
    ) -> CpResult<serde_json::Value>;
    /// Replace the project's tenancy schema (the per-table tenant-key map).
    async fn put_project_tenancy(
        &self,
        schema: &boatramp_core::tenancy::TenancySchema,
    ) -> CpResult<()>;
    /// Register one trusted operation in the project's GraphQL safelist
    /// (register-only; the server validates + stores it, idempotently).
    async fn register_graphql_safelist(&self, query: &str) -> CpResult<()>;
}

/// A control-plane call outcome classified for the reconcile core: `NotFound`
/// (HTTP 404) and `Conflict` (409) are surfaced explicitly so `ensure_project`'s
/// create-on-404 / ignore-conflict-on-409 works against a mock; every other
/// failure carries the original [`client::ClientError`] verbatim.
#[derive(Debug, thiserror::Error)]
pub enum CpError {
    /// The resource is absent (HTTP 404).
    #[error("control-plane resource not found (HTTP 404)")]
    NotFound,
    /// The resource already exists (HTTP 409).
    #[error("control-plane resource already exists (HTTP 409)")]
    Conflict,
    /// Any other control-plane failure, preserved verbatim.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
}

/// Reconcile-core control-plane result; `Err` is [`CpError`].
type CpResult<T> = std::result::Result<T, CpError>;

/// The real seam: the concrete HTTP client. Each method forwards to the same-named
/// inherent method (inherent methods take precedence over trait methods, so `self.`
/// resolves to the HTTP call, not this trait). Only `get_project`/`create_project`
/// classify their error (the sole errors the reconcile core inspects); every other
/// method preserves the original `ClientError` unchanged, so no error text shifts.
impl ControlPlane for client::ControlPlane {
    async fn get_project(&self, name: &str) -> CpResult<serde_json::Value> {
        self.get_project(name).await.map_err(|e| {
            if is_not_found(&e) {
                CpError::NotFound
            } else {
                CpError::Client(e)
            }
        })
    }
    async fn create_project(&self, body: &serde_json::Value) -> CpResult<serde_json::Value> {
        self.create_project(body).await.map_err(|e| {
            if is_conflict(&e) {
                CpError::Conflict
            } else {
                CpError::Client(e)
            }
        })
    }
    async fn create_deployment(
        &self,
        site: &str,
        manifest: &boatramp_core::deploy::Manifest,
    ) -> CpResult<crate::client::CreateDeploymentResponse> {
        self.create_deployment(site, manifest, &[])
            .await
            .map_err(CpError::Client)
    }
    async fn upload_blob_source(
        &self,
        hash: &str,
        source: &crate::sync::BlobSource,
    ) -> CpResult<()> {
        self.upload_blob_source(hash, source)
            .await
            .map_err(CpError::Client)
    }
    async fn put_site_config(&self, site: &str, config: &SiteConfig) -> CpResult<()> {
        self.put_site_config(site, config)
            .await
            .map_err(CpError::Client)
    }
    async fn activate(&self, site: &str, id: &str) -> CpResult<()> {
        self.activate(site, id).await.map_err(CpError::Client)
    }
    async fn put_file_blob(&self, path: &Path) -> CpResult<String> {
        self.put_file_blob(path).await.map_err(CpError::Client)
    }
    async fn deploy_function(&self, name: &str, body: &serde_json::Value) -> CpResult<()> {
        self.deploy_function(name, body)
            .await
            .map_err(CpError::Client)
    }
    async fn compose_subgraphs(&self) -> CpResult<()> {
        self.compose_subgraphs().await.map_err(CpError::Client)
    }
    async fn put_compute(
        &self,
        name: &str,
        body: &serde_json::Value,
    ) -> CpResult<serde_json::Value> {
        self.put_compute(name, body).await.map_err(CpError::Client)
    }
    async fn put_project_tenancy(
        &self,
        schema: &boatramp_core::tenancy::TenancySchema,
    ) -> CpResult<()> {
        self.put_project_tenancy(schema)
            .await
            .map_err(CpError::Client)
    }
    async fn register_graphql_safelist(&self, query: &str) -> CpResult<()> {
        self.register_graphql_safelist(query)
            .await
            .map_err(CpError::Client)
    }
}

/// The manifest schema version this build writes and parses **as current**. A
/// manifest that OMITS `version:` is parsed strictly against the current typed
/// schema (see [`ApplyManifest::parse`]); declaring `version: N` with `N` **older**
/// than this opts that document into the migration chain. Bumped whenever the
/// manifest schema changes in a way an older document would fail to parse.
///
/// - **v1** — the pre-v0.6.0 schema: `compute[].spec` was an untyped
///   `serde_json::Value` (a `PutComputeRequest`-shaped JSON blob).
/// - **v2 (current)** — v0.6.0: `compute[].spec` is the typed
///   [`boatramp_core::compute::ComputeSpec`], with sibling `replicas`/`placement`.
pub const CURRENT_MANIFEST_VERSION: u32 = 2;

/// A whole-project desired state: the sites, functions, and compute workloads to
/// reconcile under one project.
#[derive(Debug, Default, Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApplyManifest {
    /// The manifest schema version this document was written against. **Absent ⇒
    /// current** (the document is parsed strictly against the latest typed schema;
    /// an old-shaped manifest that omits `version` fails with a message telling you
    /// to add `version: <the schema you wrote>` and run `boatramp config migrate`).
    /// A present value **older** than [`CURRENT_MANIFEST_VERSION`] opts the document
    /// into the registered migration chain (vN→…→current). Declare the schema you
    /// wrote against to get migration support; omit it and your manifest is parsed
    /// as current. An upgraded/migrated manifest OMITS this field (current = absent),
    /// so it is skipped when serialized (`config migrate` output carries no `version:`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// Target project. `None` ⇒ resolved from config / `--project` /
    /// `BOATRAMP_PROJECT` / the `default` project.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<String>,
    /// Sites to publish (each an atomic content-addressed deployment).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<ApplySite>,
    /// Top-level functions to deploy (create-or-replace).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<ApplyFunction>,
    /// Compute workloads to create-or-replace.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub compute: Vec<ApplyCompute>,
    /// The project's tenancy schema — the per-table tenant-key map the scope injector
    /// consults (deny-by-default on undeclared tables). Reconciled **before** the sites
    /// and functions, so a handler deployed in the same apply already runs under the
    /// declared isolation boundary. `None` ⇒ leave the stored schema untouched (an
    /// omitted key never clears an existing schema — use `boatramp tenancy clear`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenancy: Option<boatramp_core::tenancy::TenancySchema>,
}

/// One site in the manifest: a slug plus its content dir and folded-in config.
#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplySite {
    /// Site slug within the project.
    pub name: String,
    /// Content directory to publish. Default: `build.output`, then `.`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Optional per-site build step, run before publishing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildConfig>,
    /// Deploy-scoped routing, folded into the deployment manifest (atomic with the
    /// content, rolls back with it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<DeployConfig>,
    /// Site-scoped mutable config (domains/access/…), PUT after the deploy activates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<SiteConfig>,
}

/// One top-level function in the manifest.
#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyFunction {
    /// Function name.
    pub name: String,
    /// Path to the component `.wasm` (uploaded as a content-addressed blob).
    pub component: String,
    /// Execution substrate: `wasm` (default), `microvm`, or `container`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,
    /// Enable a signed webhook: the host env var holding the HMAC-SHA256 secret
    /// (never the secret itself).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret_env: Option<String>,
    /// Make the webhook an ingress: a verified request publishes its body onto the
    /// project bus at this topic (`bus:<topic>` for consumers) and returns 202, with
    /// no component run. Requires `webhook_secret_env`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_publish: Option<String>,
    /// Requested host capabilities (`sql`, `wasi:keyvalue`, `invoke`, …), gated by
    /// the function import policy — parity with a site handler's `imports`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<String>,
    /// Static, non-secret environment variables passed to the function.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub env: std::collections::BTreeMap<String, String>,
    /// Secret env-var references (`ENV_VAR` → `HOST_ENV`), resolved server-side
    /// from the serve env at instantiation — the value is a reference, never
    /// stored in the manifest or the control-plane store (mirrors a site
    /// handler's `[handlers].secrets`), so the manifest stays committable.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub secrets: std::collections::BTreeMap<String, String>,
    /// Function-to-function invoke allowlist (deny-by-default; `*` wildcards). Only
    /// consulted when `imports` contains `invoke`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub invoke_targets: Vec<String>,
    /// Optional resource limits (memory / timeout / fuel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<HandlerLimits>,
    /// In-site tenancy decision (Dimension 0) for this function's `sql`/`orm` — maps straight to
    /// the internal `FunctionConfig.tenancy`. Absent ⇒ *undeclared* (refused under `multi-tenant`,
    /// `Disabled` under single-tenant/dev). E.g. `(mode: "scoped", column: "tenant_id", sources:
    /// [(kind: "token", claim: "tid")], read: "own", write: "own")`, `(mode: "disabled")`, or an
    /// async worker's `(mode: "scoped", sources: [(kind: "signed_context")], read: "own", write:
    /// "own")`. Parsed via the [`boatramp_core::tenancy::de_opt_tenancy`] bridge (RON can't parse
    /// the internally-tagged enum directly — see that fn).
    #[serde(
        default,
        deserialize_with = "boatramp_core::tenancy::de_opt_tenancy",
        skip_serializing_if = "Option::is_none"
    )]
    pub tenancy: Option<boatramp_core::tenancy::Tenancy>,
    /// JWKS/issuer config verifying the app bearer when this function's tenancy names a `token`
    /// source (the function analogue of a site's `[handlers.graphql.data].claims_from_token`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_claims: Option<boatramp_core::config::HandlerGraphqlTokenClaims>,
}

/// One compute workload in the manifest.
///
/// The workload body is **typed** (v0.6.0, breaking): its `spec` / `replicas` /
/// `placement` fields mirror [`boatramp_core::compute::PutComputeRequest`]
/// EXPLICITLY (not `#[serde(flatten)]`, which would defeat `deny_unknown_fields`
/// on the manifest path). Deserializing the manifest now parses the compute spec
/// against the real [`boatramp_core::compute::ComputeSpec`] schema, so a malformed
/// or pre-v0.6.0 raw-JSON spec fails fast at parse time — an additive client gate
/// on top of the server's own semantic validation.
#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyCompute {
    /// Workload name.
    pub name: String,
    /// The immutable workload spec (rootfs/kernel source + sizing) — the typed
    /// [`boatramp_core::compute::ComputeSpec`].
    pub spec: boatramp_core::compute::ComputeSpec,
    /// Desired replica count (default 1).
    #[serde(default = "boatramp_core::compute::default_replicas")]
    pub replicas: u32,
    /// Placement constraints (regions / node labels).
    #[serde(default, skip_serializing_if = "placement_is_default")]
    pub placement: boatramp_core::compute::PlacementConstraints,
}

/// Whether a workload's placement is the default (no regions, no labels), so it is
/// omitted from a serialized (migrated) manifest for clean output.
fn placement_is_default(p: &boatramp_core::compute::PlacementConstraints) -> bool {
    p.regions.is_empty() && p.labels.is_empty()
}

impl ApplyCompute {
    /// The typed [`boatramp_core::compute::PutComputeRequest`] this workload
    /// declares — the exact body the server's `put_compute` handler deserializes,
    /// so the manifest and the wire share one schema.
    fn to_request(&self) -> boatramp_core::compute::PutComputeRequest {
        boatramp_core::compute::PutComputeRequest {
            spec: self.spec.clone(),
            replicas: self.replicas,
            placement: self.placement.clone(),
        }
    }
}

impl ApplyManifest {
    /// Parse a manifest document (RON) through the **loose-parse → migrate → typed**
    /// pipeline (v0.6.0).
    ///
    /// - **No `version:` (or `version:` == [`CURRENT_MANIFEST_VERSION`])** ⇒ parse
    ///   strictly against the current typed schema. A version-less document that does
    ///   NOT match the current schema (e.g. a pre-v0.6.0 raw-JSON `compute.spec`)
    ///   fails with the wrapped [`Error::StrictParse`] upgrade error — the migration UX.
    /// - **`version: N` with `N` < current** ⇒ run the registered migration chain
    ///   (vN→vN+1→…→current) via [`crate::apply_migrate`], then the strict typed parse.
    /// - **`version: N` > current** ⇒ [`Error::VersionTooNew`].
    ///
    /// Each site's `routing` is compile-checked (route patterns, cron schedules) so a
    /// bad manifest fails fast.
    pub fn parse(text: &str) -> Result<Self> {
        let declared = crate::apply_migrate::peek_version(text)?;
        let manifest = match declared {
            None => Self::parse_strict(text)?,
            Some(v) if v == CURRENT_MANIFEST_VERSION => {
                // An explicit current-version declaration: parse strictly, same as
                // the version-less path. The upgraded output drops `version:`.
                Self::parse_strict(text)?
            }
            Some(v) if v > CURRENT_MANIFEST_VERSION => {
                return Err(Error::VersionTooNew {
                    declared: v,
                    current: CURRENT_MANIFEST_VERSION,
                });
            }
            Some(v) => crate::apply_migrate::migrate_to_current(text, v)?,
        };
        manifest.compile_check_sites()?;
        Ok(manifest)
    }

    /// Parse strictly against the current typed schema, wrapping a parse failure in
    /// the v0.6.0 upgrade error (which names the migration path). Used for the
    /// version-less / current-version path AND as the final step after a migration.
    fn parse_strict(text: &str) -> Result<Self> {
        crate::config::ron_options()
            .from_str(text)
            .map_err(|source| Error::StrictParse { source })
    }

    /// Compile-check every site's `routing` (route/cron patterns).
    fn compile_check_sites(&self) -> Result<()> {
        for site in &self.sites {
            if let Some(routing) = &site.routing {
                routing.compile_check().map_err(|source| Error::Routing {
                    site: site.name.clone(),
                    source,
                })?;
            }
        }
        Ok(())
    }

    /// Load a manifest from `path` (RON). Unlike `project.cfg`, a **missing** file
    /// is an error — there is nothing to apply.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::Missing(path.display().to_string()))
            }
            Err(err) => Err(err.into()),
        }
    }
}

/// Arguments for `boatramp apply`.
#[derive(Debug, clap::Args)]
pub struct ApplyArgs {
    /// Path to the project manifest (RON).
    #[arg(short = 'f', long, default_value = "apply.cfg")]
    file: PathBuf,

    /// boatramp server base URL (overrides `[publish].server`).
    #[arg(long, env = "BOATRAMP_SERVER")]
    server: Option<String>,

    /// Print the plan (what would be built/deployed/activated) and mutate nothing.
    #[arg(long)]
    dry_run: bool,

    /// Run each site's configured build command before publishing it.
    #[arg(long)]
    build: bool,
}

/// Entry point for `boatramp apply`.
pub async fn run(args: ApplyArgs, config: &ProjectConfig) -> Result<()> {
    let manifest = ApplyManifest::load(&args.file)?;

    // Resolve the target project: an explicit `project:` in the manifest wins over
    // the config-resolved value (`[publish].project` / `--project` / default).
    let project = manifest
        .project
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| client::resolve_project(config));

    let (server, http) = client::connect(args.server.clone(), config)?;
    let cp = client::ControlPlane::new(server, http, project.clone());

    println!(
        "applying {} to project `{project}`: {} site(s), {} function(s), {} compute workload(s){}",
        args.file.display(),
        manifest.sites.len(),
        manifest.functions.len(),
        manifest.compute.len(),
        if args.dry_run { "  (dry-run)" } else { "" },
    );

    // Ensure the project exists (best-effort; `default` always does).
    ensure_project(&cp, &project, args.dry_run).await?;

    // Reconcile the tenancy schema *before* any site/function, so a handler shipped in
    // this same apply already runs under the declared isolation boundary.
    if let Some(schema) = &manifest.tenancy {
        reconcile_tenancy(&cp, schema, args.dry_run).await?;
    }

    // `safelisted_ops_path` is resolved relative to the manifest's own directory
    // (client-side); the manifest file itself lives at `args.file`.
    let manifest_dir = args
        .file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    for site in &manifest.sites {
        apply_site(&cp, site, config, &manifest_dir, args.build, args.dry_run).await?;
    }
    for function in &manifest.functions {
        apply_function(&cp, function, args.dry_run).await?;
    }
    // Bug #499: each function deploy staged (not composed) its subgraph SDL via `?compose=defer`,
    // keeping the slow introspect/compose off the per-deploy request critical path. Promote the
    // whole staged set in ONE composition here (O(N) instead of O(N²) recomposes). A no-op when
    // no function staged a subgraph. Skipped on dry-run (no deploys happened).
    apply_deferred_compose(&cp, !manifest.functions.is_empty(), args.dry_run).await?;
    for compute in &manifest.compute {
        apply_compute(&cp, compute, args.dry_run).await?;
    }

    println!("apply complete");
    Ok(())
}

/// Ensure the target project exists: `GET` it, and on a 404 `create` it. A
/// concurrent create (409/conflict) is ignored. The reserved `default` project
/// always exists, so it is skipped.
async fn ensure_project<C: ControlPlane>(cp: &C, project: &str, dry_run: bool) -> Result<()> {
    if project == boatramp_core::project::DEFAULT_PROJECT {
        return Ok(());
    }
    if dry_run {
        println!("  project `{project}`: ensure exists");
        return Ok(());
    }
    match cp.get_project(project).await {
        Ok(_) => Ok(()),
        Err(CpError::NotFound) => match cp.create_project(&json!({ "name": project })).await {
            Ok(_) => {
                println!("  created project `{project}`");
                Ok(())
            }
            // A concurrent create is fine — the project ends up existing either way.
            Err(CpError::Conflict) => Ok(()),
            Err(err) => Err(err.into()),
        },
        Err(err) => Err(err.into()),
    }
}

/// Reconcile the project's tenancy schema: unconditionally PUT the declared schema
/// (idempotent replace). Runs before the sites/functions so the isolation boundary is
/// in place before any handler can serve a request.
async fn reconcile_tenancy<C: ControlPlane>(
    cp: &C,
    schema: &boatramp_core::tenancy::TenancySchema,
    dry_run: bool,
) -> Result<()> {
    if dry_run {
        println!(
            "  tenancy: would set schema ({} table(s))",
            schema.tables.len()
        );
        return Ok(());
    }
    cp.put_project_tenancy(schema).await?;
    println!("  tenancy: set schema ({} table(s))", schema.tables.len());
    Ok(())
}

/// Reconcile one site: (optionally build), hash the content dir, negotiate the
/// deployment, upload the missing blobs, PUT its site config, then activate (config
/// before activate — the activation precheck gates handlers on the stored config).
async fn apply_site<C: ControlPlane>(
    cp: &C,
    site: &ApplySite,
    config: &ProjectConfig,
    manifest_dir: &Path,
    build_flag: bool,
    dry_run: bool,
) -> Result<()> {
    let dir = site_content_dir(site);

    if dry_run {
        println!(
            "  site `{}`: would deploy {} (build: {}, routing: {}, config: {})",
            site.name,
            dir.display(),
            yes_no(site.build.is_some() || build_flag),
            yes_no(site.routing.is_some()),
            yes_no(site.config.is_some()),
        );
        // #470 legibility: surface any route that deliberately EXCEEDS the site tenancy ceiling, so an
        // authorized exception is visible at plan time (never hidden behind a function indirection —
        // the whole point of the inline model). When this apply also carries the site config, flag the
        // definite misconfig where a route asks for an exception the site does not permit (the server
        // precheck refuses it at activation; we warn early). Not a hard failure — the site config may
        // be managed out-of-band, so the server remains the authoritative gate.
        let site_allows = site
            .config
            .as_ref()
            .and_then(|c| c.handlers.as_ref())
            .map(|h| h.allow_ceiling_exceptions);
        if let Some(routing) = &site.routing {
            for h in &routing.handlers {
                if matches!(
                    &h.tenancy,
                    Some(boatramp_core::tenancy::Tenancy::Scoped {
                        exceed_site_ceiling: true,
                        ..
                    })
                ) {
                    let route = &h.route;
                    let methods = h.methods.join(",");
                    match site_allows {
                        Some(false) => eprintln!(
                            "    ⚠ route {route:?} [{methods}]: declares `exceed_site_ceiling` but \
                             this apply's site config does NOT set `allow_ceiling_exceptions` — it \
                             will be REFUSED at activation. Set it, or narrow the route."
                        ),
                        _ => eprintln!(
                            "    ⚠ route {route:?} [{methods}]: exceeds the site tenancy ceiling \
                             (authorized via `exceed_site_ceiling`; the site must set \
                             `allow_ceiling_exceptions`, and an `all` grant also needs the operator \
                             posture `allow_cross_tenant_db`)."
                        ),
                    }
                }
            }
        }
        // Surface (and validate) the declared safelisted ops at plan time, so a
        // misconfig (both sources set, or an unreadable file) fails the dry-run early.
        apply_safelists(cp, site, manifest_dir, true).await?;
        return Ok(());
    }

    // Build first when the site declares a build (or `--build` was passed).
    if let Some(build) = &site.build {
        crate::build::run_command(&build.command).await?;
    } else if build_flag {
        let command = crate::build::resolve_command(None, config)?;
        crate::build::run_command(&command).await?;
    }

    if !dir.is_dir() {
        return Err(Error::Sync(crate::sync::Error::NotADirectory(
            dir.display().to_string(),
        )));
    }

    // Content-addressed manifest of the tree; fold the site's routing in.
    let (mut manifest, blobs_by_hash) = crate::sync::build_manifest(&dir).await?;
    if let Some(routing) = &site.routing {
        manifest.config = routing.clone();
    }

    let created = cp.create_deployment(&site.name, &manifest).await?;
    println!(
        "  site `{}`: deployment {} — uploading {} new blob(s)",
        site.name,
        created.id,
        created.missing.len(),
    );

    for hash in &created.missing {
        let source = blobs_by_hash
            .get(hash)
            .ok_or_else(|| Error::Sync(crate::sync::Error::NoLocalSource(hash.clone())))?;
        cp.upload_blob_source(hash, source).await?;
    }

    // Apply the site config BEFORE activating: activation prechecks a deployment's
    // handlers against the site's stored config (allow_imports / handler enablement),
    // so a handler-shipping deployment is refused (422) if its config has not landed
    // yet. Configure the site, then flip it live.
    if let Some(site_config) = &site.config {
        cp.put_site_config(&site.name, site_config).await?;
        println!("  site `{}`: config applied", site.name);
    }

    cp.activate(&site.name, &created.id).await?;
    println!("  site `{}`: activated {}", site.name, created.id);

    // Register the site's declaratively-safelisted GraphQL operations (register-only).
    apply_safelists(cp, site, manifest_dir, false).await?;

    Ok(())
}

/// Register a site's declaratively-safelisted GraphQL operations (v0.6.0) — the
/// `[handlers.graphql].safelisted_ops` (inline) OR `safelisted_ops_path` (a file,
/// resolved client-side relative to `manifest_dir`). Every collected operation is
/// registered through the existing control-plane `POST .../graphql/safelist` endpoint,
/// which runs the server-side `guard_query`→`register` validation.
///
/// **REGISTER-ONLY (union).** This never deletes or prunes: re-applying only ever ADDS
/// operations to the allowlist. Pruning a deny-by-default allowlist on apply would be a
/// self-inflicted DoS (and a silent boundary narrowing), so removal stays the explicit
/// `boatramp graphql safelist rm`. The two sources are mutually exclusive (a config
/// error if both are set). On `dry_run` the ops are collected + validated (so a misconfig
/// fails early) but nothing is registered.
async fn apply_safelists<C: ControlPlane>(
    cp: &C,
    site: &ApplySite,
    manifest_dir: &Path,
    dry_run: bool,
) -> Result<()> {
    let Some(gql) = site
        .config
        .as_ref()
        .and_then(|c| c.handlers.as_ref())
        .and_then(|h| h.graphql.as_ref())
    else {
        return Ok(());
    };

    // Mutual exclusion: pick one source of safelisted operations.
    if !gql.safelisted_ops.is_empty() && gql.safelisted_ops_path.is_some() {
        return Err(Error::SafelistConflict {
            site: site.name.clone(),
        });
    }

    // Collect the operation texts from whichever source is declared.
    let ops: Vec<String> = if let Some(rel) = &gql.safelisted_ops_path {
        // Resolve the path client-side relative to the manifest dir; only op TEXT
        // (never the path) ever leaves this host.
        let path = manifest_dir.join(rel);
        let text = std::fs::read_to_string(&path).map_err(|source| Error::SafelistFile {
            site: site.name.clone(),
            path: path.display().to_string(),
            source,
        })?;
        parse_ops_file(&text)
    } else {
        gql.safelisted_ops.clone()
    };

    if ops.is_empty() {
        return Ok(());
    }

    if dry_run {
        println!(
            "  site `{}`: would register {} safelisted operation(s) (register-only)",
            site.name,
            ops.len(),
        );
        return Ok(());
    }

    for op in &ops {
        cp.register_graphql_safelist(op).await?;
    }
    println!(
        "  site `{}`: registered {} safelisted operation(s) (register-only)",
        site.name,
        ops.len(),
    );
    Ok(())
}

/// Parse a `safelisted_ops_path` file into individual operation texts. The file is
/// either a **JSON array of operation strings** (`["query A {…}", "mutation B {…}"]`)
/// — the explicit multi-operation form — or, if it is not such an array, the WHOLE
/// file content is taken as a **single** operation (matching the existing
/// `boatramp graphql safelist add --file` semantics). Empty/whitespace-only entries
/// are dropped.
fn parse_ops_file(text: &str) -> Vec<String> {
    if let Ok(arr) = serde_json::from_str::<Vec<String>>(text) {
        return arr.into_iter().filter(|op| !op.trim().is_empty()).collect();
    }
    let single = text.trim();
    if single.is_empty() {
        Vec::new()
    } else {
        vec![single.to_string()]
    }
}

/// Reconcile one top-level function: stage its component blob, then PUT the
/// function record (`{ component, config, lifecycle }`).
async fn apply_function<C: ControlPlane>(
    cp: &C,
    function: &ApplyFunction,
    dry_run: bool,
) -> Result<()> {
    if dry_run {
        println!(
            "  function `{}`: would deploy from {}",
            function.name, function.component,
        );
        return Ok(());
    }

    let hash = cp.put_file_blob(Path::new(&function.component)).await?;
    let mut cfg = serde_json::Map::new();
    if let Some(runtime) = &function.runtime {
        cfg.insert("runtime".to_string(), json!(runtime));
    }
    if let Some(secret_env) = &function.webhook_secret_env {
        let mut webhook = serde_json::Map::new();
        webhook.insert("secret_env".to_string(), json!(secret_env));
        if let Some(topic) = &function.webhook_publish {
            webhook.insert("publish".to_string(), json!(topic));
        }
        cfg.insert("webhook".to_string(), serde_json::Value::Object(webhook));
    }
    if !function.imports.is_empty() {
        cfg.insert("imports".to_string(), json!(function.imports));
    }
    if !function.env.is_empty() {
        cfg.insert("env".to_string(), json!(function.env));
    }
    // Secret *references* only (`ENV_VAR` → `HOST_ENV`); the server resolves them
    // from its own env at instantiation, so no secret value is ever transmitted or
    // stored — just the reference, keeping the manifest committable.
    if !function.secrets.is_empty() {
        cfg.insert("secrets".to_string(), json!(function.secrets));
    }
    if !function.invoke_targets.is_empty() {
        cfg.insert("invoke_targets".to_string(), json!(function.invoke_targets));
    }
    if let Some(limits) = &function.limits {
        cfg.insert("limits".to_string(), json!(limits));
    }
    // In-site tenancy + token-verification config map straight onto the internal FunctionConfig
    // (`tenancy`/`token_claims`); the server enforces them at instantiation (Dimension 0).
    if let Some(tenancy) = &function.tenancy {
        cfg.insert("tenancy".to_string(), json!(tenancy));
    }
    if let Some(token_claims) = &function.token_claims {
        cfg.insert("token_claims".to_string(), json!(token_claims));
    }
    // Top-level functions carry their own independent version line.
    let body = json!({
        "component": hash,
        "config": serde_json::Value::Object(cfg),
        "lifecycle": "independent",
    });
    cp.deploy_function(&function.name, &body).await?;
    println!("  function `{}`: deployed", function.name);
    Ok(())
}

/// Promote the staged subgraphs once, after all functions have been deployed (bug #499). Each
/// function deploy used `?compose=defer`, so its subgraph SDL was staged (not composed) — keeping
/// the O(N) introspect/compose off each individual deploy's request critical path. This calls
/// `POST .../graphql/compose` ONCE to validate + promote the whole staged set. A no-op when the
/// manifest declares no functions (nothing could have staged), and skipped entirely on a dry-run
/// (no deploys happened). Generic over the [`ControlPlane`] seam so the mock records the call.
async fn apply_deferred_compose<C: ControlPlane>(
    cp: &C,
    any_functions: bool,
    dry_run: bool,
) -> Result<()> {
    if dry_run || !any_functions {
        return Ok(());
    }
    cp.compose_subgraphs().await?;
    Ok(())
}

/// Reconcile one compute workload: PUT its spec straight to the server.
async fn apply_compute<C: ControlPlane>(
    cp: &C,
    compute: &ApplyCompute,
    dry_run: bool,
) -> Result<()> {
    if dry_run {
        println!("  compute `{}`: would apply spec", compute.name);
        return Ok(());
    }
    // The typed request round-trips to the exact `PutComputeRequest` JSON the server
    // deserializes — the manifest and the wire share one schema.
    let body = serde_json::to_value(compute.to_request())?;
    cp.put_compute(&compute.name, &body).await?;
    println!("  compute `{}`: applied", compute.name);
    Ok(())
}

/// The content dir for a site: an explicit `path`, else the site build's
/// `output`, else `.`.
fn site_content_dir(site: &ApplySite) -> PathBuf {
    site.path
        .clone()
        .or_else(|| site.build.as_ref().and_then(|b| b.output.clone()))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Whether a control-plane error is an HTTP 404 (the resource is absent).
fn is_not_found(err: &client::ClientError) -> bool {
    matches!(
        err,
        client::ClientError::Http(e) if e.status() == Some(reqwest::StatusCode::NOT_FOUND)
    )
}

/// Whether a control-plane error is an HTTP 409 (an already-exists conflict).
fn is_conflict(err: &client::ClientError) -> bool {
    matches!(
        err,
        client::ClientError::Http(e) if e.status() == Some(reqwest::StatusCode::CONFLICT)
    )
}

/// `"yes"`/`"no"` for a dry-run plan line.
fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A recording [`ControlPlane`] double: every call appends a line to `calls`,
    /// so a reconcile test asserts *which* control-plane operations ran and *in
    /// what order* — without a live server. `project_exists` toggles `get_project`
    /// between `Ok` and [`CpError::NotFound`].
    #[derive(Default)]
    struct MockCp {
        calls: Mutex<Vec<String>>,
        project_exists: bool,
    }

    impl MockCp {
        fn rec(&self, line: impl Into<String>) {
            self.calls.lock().unwrap().push(line.into());
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl ControlPlane for MockCp {
        async fn get_project(&self, name: &str) -> CpResult<serde_json::Value> {
            self.rec(format!("get_project {name}"));
            if self.project_exists {
                Ok(json!({ "name": name }))
            } else {
                Err(CpError::NotFound)
            }
        }
        async fn create_project(&self, body: &serde_json::Value) -> CpResult<serde_json::Value> {
            self.rec(format!(
                "create_project {}",
                body["name"].as_str().unwrap_or_default()
            ));
            Ok(body.clone())
        }
        async fn create_deployment(
            &self,
            site: &str,
            _manifest: &boatramp_core::deploy::Manifest,
        ) -> CpResult<crate::client::CreateDeploymentResponse> {
            self.rec(format!("create_deployment {site}"));
            // No missing blobs ⇒ the upload loop is skipped, isolating the
            // config-before-activate ordering under test.
            Ok(crate::client::CreateDeploymentResponse {
                id: "dep-1".into(),
                missing: vec![],
            })
        }
        async fn upload_blob_source(
            &self,
            hash: &str,
            _source: &crate::sync::BlobSource,
        ) -> CpResult<()> {
            self.rec(format!("upload_blob_source {hash}"));
            Ok(())
        }
        async fn put_site_config(&self, site: &str, _config: &SiteConfig) -> CpResult<()> {
            self.rec(format!("put_site_config {site}"));
            Ok(())
        }
        async fn activate(&self, site: &str, id: &str) -> CpResult<()> {
            self.rec(format!("activate {site} {id}"));
            Ok(())
        }
        async fn put_file_blob(&self, path: &Path) -> CpResult<String> {
            self.rec(format!("put_file_blob {}", path.display()));
            Ok("deadbeef".into())
        }
        async fn deploy_function(&self, name: &str, _body: &serde_json::Value) -> CpResult<()> {
            self.rec(format!("deploy_function {name}"));
            Ok(())
        }
        async fn compose_subgraphs(&self) -> CpResult<()> {
            self.rec("compose_subgraphs".to_string());
            Ok(())
        }
        async fn put_compute(
            &self,
            name: &str,
            _body: &serde_json::Value,
        ) -> CpResult<serde_json::Value> {
            self.rec(format!("put_compute {name}"));
            Ok(json!({}))
        }
        async fn put_project_tenancy(
            &self,
            schema: &boatramp_core::tenancy::TenancySchema,
        ) -> CpResult<()> {
            self.rec(format!("put_project_tenancy {}", schema.tables.len()));
            Ok(())
        }
        async fn register_graphql_safelist(&self, query: &str) -> CpResult<()> {
            // Record the op text so a test can assert POST-per-op (and that no DELETE
            // is ever issued — the mock has no delete method at all).
            self.rec(format!("register_graphql_safelist {query}"));
            Ok(())
        }
    }

    fn a_function() -> ApplyFunction {
        ApplyFunction {
            name: "resize".into(),
            component: "resize.wasm".into(),
            runtime: None,
            webhook_secret_env: None,
            webhook_publish: None,
            imports: vec![],
            env: Default::default(),
            secrets: Default::default(),
            invoke_targets: vec![],
            limits: None,
            tenancy: None,
            token_claims: None,
        }
    }

    #[tokio::test]
    async fn ensure_project_creates_on_404() {
        let mock = MockCp::default(); // project_exists: false
        ensure_project(&mock, "acme", false).await.unwrap();
        assert_eq!(mock.calls(), ["get_project acme", "create_project acme"]);
    }

    #[tokio::test]
    async fn ensure_project_existing_does_not_create() {
        let mock = MockCp {
            project_exists: true,
            ..Default::default()
        };
        ensure_project(&mock, "acme", false).await.unwrap();
        assert_eq!(mock.calls(), ["get_project acme"]);
    }

    #[tokio::test]
    async fn ensure_project_skips_the_reserved_default() {
        let mock = MockCp::default();
        ensure_project(&mock, boatramp_core::project::DEFAULT_PROJECT, false)
            .await
            .unwrap();
        assert!(mock.calls().is_empty(), "default is never created");
    }

    #[tokio::test]
    async fn ensure_project_dry_run_mutates_nothing() {
        let mock = MockCp::default();
        ensure_project(&mock, "acme", true).await.unwrap();
        assert!(mock.calls().is_empty(), "dry-run issues no requests");
    }

    #[tokio::test]
    async fn apply_function_stages_blob_then_deploys() {
        let mock = MockCp::default();
        apply_function(&mock, &a_function(), false).await.unwrap();
        assert_eq!(
            mock.calls(),
            ["put_file_blob resize.wasm", "deploy_function resize"]
        );
    }

    #[tokio::test]
    async fn apply_function_dry_run_mutates_nothing() {
        let mock = MockCp::default();
        apply_function(&mock, &a_function(), true).await.unwrap();
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn apply_deferred_compose_promotes_once_after_functions() {
        // Bug #499: with functions present (each deployed `?compose=defer`), the staged subgraphs
        // are promoted by exactly ONE `compose_subgraphs` call after the deploys.
        let mock = MockCp::default();
        apply_deferred_compose(&mock, true, false).await.unwrap();
        assert_eq!(mock.calls(), ["compose_subgraphs"]);
    }

    #[tokio::test]
    async fn apply_deferred_compose_noop_without_functions_or_on_dry_run() {
        // No functions in the manifest ⇒ nothing staged ⇒ no compose call.
        let mock = MockCp::default();
        apply_deferred_compose(&mock, false, false).await.unwrap();
        assert!(mock.calls().is_empty(), "no functions ⇒ no compose");
        // Dry-run ⇒ no deploys happened ⇒ no compose call.
        let mock = MockCp::default();
        apply_deferred_compose(&mock, true, true).await.unwrap();
        assert!(mock.calls().is_empty(), "dry-run ⇒ no compose");
    }

    /// A minimal typed image-workload spec for the compute-apply tests.
    fn an_image_spec() -> boatramp_core::compute::ComputeSpec {
        boatramp_core::compute::ComputeSpec {
            version: boatramp_core::SCHEMA_VERSION,
            root: boatramp_core::compute::RootSource::Image("nginx:latest".into()),
            kernel: String::new(),
            kernel_cmdline: None,
            vcpus: 1,
            mem_mib: 256,
            entrypoint: vec![],
            env: Default::default(),
            port: 8080,
            restart: Default::default(),
            startup_grace_secs: boatramp_core::compute::default_startup_grace_secs(),
            scale_to_zero: false,
            volumes: vec![],
            writable_root: false,
            cap_add: vec![],
            user: None,
            isolation: Default::default(),
            prefer_backend: None,
            bindings: vec![],
        }
    }

    #[tokio::test]
    async fn apply_compute_puts_the_spec() {
        let mock = MockCp::default();
        let compute = ApplyCompute {
            name: "api".into(),
            spec: an_image_spec(),
            replicas: 2,
            placement: Default::default(),
        };
        apply_compute(&mock, &compute, false).await.unwrap();
        assert_eq!(mock.calls(), ["put_compute api"]);
    }

    #[tokio::test]
    async fn apply_compute_dry_run_mutates_nothing() {
        let mock = MockCp::default();
        let compute = ApplyCompute {
            name: "api".into(),
            spec: an_image_spec(),
            replicas: boatramp_core::compute::default_replicas(),
            placement: Default::default(),
        };
        apply_compute(&mock, &compute, true).await.unwrap();
        assert!(mock.calls().is_empty());
    }

    #[tokio::test]
    async fn reconcile_tenancy_puts_the_schema() {
        use boatramp_core::tenancy::{TableScope, TenancySchema};
        let mock = MockCp::default();
        let mut schema = TenancySchema::default();
        schema.tables.insert("orders".into(), TableScope::Tenant);
        schema.tables.insert(
            "tenant".into(),
            TableScope::TenantKeyed { key: "id".into() },
        );
        reconcile_tenancy(&mock, &schema, false).await.unwrap();
        assert_eq!(mock.calls(), ["put_project_tenancy 2"]);
    }

    #[tokio::test]
    async fn reconcile_tenancy_dry_run_mutates_nothing() {
        let mock = MockCp::default();
        reconcile_tenancy(&mock, &Default::default(), true)
            .await
            .unwrap();
        assert!(mock.calls().is_empty());
    }

    /// The tenancy schema round-trips through the RON manifest surface — proving the
    /// internally-tagged `TableScope` enum (`kind: "tenant" | "tenant_keyed" | "unscoped"`)
    /// deserializes from RON, not only JSON, so `boatramp apply` can declare it inline.
    #[test]
    fn manifest_parses_a_tenancy_schema() {
        use boatramp_core::tenancy::TableScope;
        let manifest = ApplyManifest::parse(
            r#"(
                project: "acme",
                tenancy: (
                    default_tenant_key: "tenant_id",
                    tables: {
                        "orders": (kind: tenant),
                        "tenant": (kind: tenant_keyed, key: "id"),
                        "countries": (kind: unscoped),
                        "oauth_state": (kind: unscoped, writable: true),
                    },
                ),
            )"#,
        )
        .expect("manifest with tenancy parses");
        let schema = manifest.tenancy.expect("tenancy present");
        assert_eq!(schema.default_tenant_key, "tenant_id");
        assert_eq!(schema.tables.get("orders"), Some(&TableScope::Tenant));
        assert_eq!(
            schema.tables.get("tenant"),
            Some(&TableScope::TenantKeyed { key: "id".into() })
        );
        // #503: a plain `unscoped` parses as `writable: false`; the `writable: true` flag parses too.
        assert_eq!(
            schema.tables.get("countries"),
            Some(&TableScope::Unscoped { writable: false })
        );
        assert_eq!(
            schema.tables.get("oauth_state"),
            Some(&TableScope::Unscoped { writable: true })
        );
    }

    /// A per-route `unscoped_writes` allowlist round-trips through the RON manifest surface (#503).
    #[test]
    fn manifest_parses_per_route_unscoped_writes() {
        use boatramp_core::tenancy::Tenancy;
        let manifest = ApplyManifest::parse(
            r#"(
                project: "acme",
                functions: [
                    (
                        name: "oauth-start",
                        component: "oauth.wasm",
                        imports: ["sql"],
                        tenancy: (mode: "scoped", column: "tenant_id",
                                  sources: [(kind: "token", claim: "tid")],
                                  read: "own", write: "own",
                                  unscoped_writes: ["oauth_state"]),
                    ),
                ],
            )"#,
        )
        .expect("manifest with per-route unscoped_writes parses");
        let f = &manifest.functions[0];
        let Some(Tenancy::Scoped { .. }) = f.tenancy.as_ref() else {
            panic!("expected a scoped tenancy");
        };
        assert_eq!(
            f.tenancy.as_ref().map(Tenancy::unscoped_writes),
            Some(&["oauth_state".to_string()][..])
        );
    }

    /// A per-function `tenancy` + `token_claims` round-trips through the RON manifest surface
    /// (Gap 2) — proving the canonical spelling: the internally-tagged `Tenancy`/`TenantSource`
    /// enums are written **fully quoted** (`mode: "scoped"`, `kind: "token"`, `read: "all"`),
    /// byte-identical to the JSON the control plane stores, and parse via the `de_opt_tenancy`
    /// `ron::Value` bridge (a direct RON parse of the internally-tagged enum is impossible — see
    /// `de_opt_tenancy`). Maps straight onto the internal `FunctionConfig` shape.
    #[test]
    fn manifest_parses_per_function_tenancy() {
        use boatramp_core::tenancy::{AccessMode, Tenancy, TenantSource};
        let manifest = ApplyManifest::parse(
            r#"(
                project: "acme",
                functions: [
                    (
                        name: "identity",
                        component: "identity.wasm",
                        imports: ["sql"],
                        tenancy: (mode: "scoped", column: "tenant_id",
                                  sources: [(kind: "token", claim: "tid")],
                                  read: "all", write: "own"),
                        token_claims: (issuer: "https://idp.example",
                                       jwks_url: "https://idp.example/jwks.json",
                                       audience: "acme"),
                    ),
                    (
                        name: "concept-worker",
                        component: "worker.wasm",
                        imports: ["sql"],
                        tenancy: (mode: "scoped", column: "tenant_id",
                                  sources: [(kind: "signed_context")],
                                  read: "own", write: "own"),
                    ),
                    (name: "public", component: "public.wasm", tenancy: (mode: "disabled")),
                ],
            )"#,
        )
        .expect("manifest with per-function tenancy parses");
        let identity = &manifest.functions[0];
        match identity.tenancy.as_ref().expect("identity tenancy") {
            Tenancy::Scoped {
                column,
                sources,
                read,
                write,
                ..
            } => {
                assert_eq!(column, "tenant_id");
                assert_eq!(
                    sources,
                    &vec![TenantSource::Token {
                        claim: "tid".into()
                    }]
                );
                assert_eq!(*read, AccessMode::All);
                assert_eq!(*write, AccessMode::Own);
            }
            other => panic!("expected scoped, got {other:?}"),
        }
        assert_eq!(
            identity.token_claims.as_ref().map(|c| c.issuer.as_str()),
            Some("https://idp.example")
        );
        // The async worker resolves its own tenant from the producer-stamped signed context.
        match manifest.functions[1].tenancy.as_ref().unwrap() {
            Tenancy::Scoped { sources, .. } => {
                assert_eq!(sources, &vec![TenantSource::SignedContext]);
            }
            other => panic!("expected scoped, got {other:?}"),
        }
        assert!(matches!(
            manifest.functions[2].tenancy.as_ref().unwrap(),
            Tenancy::Disabled
        ));
    }

    #[tokio::test]
    async fn apply_site_applies_config_before_activate() {
        // `build_manifest` hashes a real tree, so stage a one-file content dir.
        let dir = std::env::temp_dir().join(format!(
            "boatramp-apply-site-{}-{}",
            std::process::id(),
            "www"
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), b"<h1>hi</h1>").unwrap();

        let mock = MockCp::default();
        let site = ApplySite {
            name: "www".into(),
            path: Some(dir.display().to_string()),
            build: None,
            routing: None,
            config: Some(SiteConfig::default()),
        };
        let result = apply_site(
            &mock,
            &site,
            &ProjectConfig::default(),
            Path::new("."),
            false,
            false,
        )
        .await;
        let _ = std::fs::remove_dir_all(&dir);
        result.unwrap();

        // The invariant this module exists to guarantee (see `apply_site`'s doc):
        // the site config lands BEFORE the deployment is activated.
        assert_eq!(
            mock.calls(),
            [
                "create_deployment www",
                "put_site_config www",
                "activate www dep-1"
            ]
        );
    }

    #[test]
    fn manifest_round_trips_sites_functions_and_compute() {
        let manifest = ApplyManifest::parse(
            r#"(
                project: "acme",
                sites: [
                    (
                        name: "www",
                        path: "dist",
                        routing: ( clean_urls: true ),
                    ),
                    (
                        name: "docs",
                        build: ( command: "npm run docs", output: "site" ),
                        config: ( domains: ( primary: "docs.acme.com" ) ),
                    ),
                ],
                functions: [
                    (
                        name: "resize", component: "resize.wasm", runtime: "wasm",
                        imports: ["sql", "invoke"],
                        env: { "IDP_JWKS": "https://idp/.well-known/jwks.json" },
                        invoke_targets: ["thumbnail", "img-*"],
                    ),
                ],
                compute: [
                    (
                        name: "api",
                        // v0.6.0: the compute spec is the typed `ComputeSpec`
                        // (`root` is the snake_case newtype variant `image(…)`).
                        spec: ( root: image("nginx:latest"), vcpus: 1, mem_mib: 256, port: 8080 ),
                        replicas: 2,
                    ),
                ],
            )"#,
        )
        .expect("manifest parses");

        assert_eq!(manifest.project.as_deref(), Some("acme"));

        assert_eq!(manifest.sites.len(), 2);
        assert_eq!(manifest.sites[0].name, "www");
        assert_eq!(manifest.sites[0].path.as_deref(), Some("dist"));
        assert!(manifest.sites[0].routing.as_ref().unwrap().clean_urls);
        // The second site folds its build + a site config.
        assert_eq!(manifest.sites[1].name, "docs");
        let build = manifest.sites[1].build.as_ref().unwrap();
        assert_eq!(build.command, "npm run docs");
        assert_eq!(build.output.as_deref(), Some("site"));
        assert_eq!(
            manifest.sites[1]
                .config
                .as_ref()
                .unwrap()
                .domains
                .primary
                .as_deref(),
            Some("docs.acme.com"),
        );

        assert_eq!(manifest.functions.len(), 1);
        let f = &manifest.functions[0];
        assert_eq!(f.name, "resize");
        assert_eq!(f.component, "resize.wasm");
        assert_eq!(f.runtime.as_deref(), Some("wasm"));
        // The declarative surface now carries a function's capabilities, env, and
        // invoke allowlist — parity with a site handler (the apply.cfg gap).
        assert_eq!(f.imports, ["sql", "invoke"]);
        assert_eq!(
            f.env.get("IDP_JWKS").map(String::as_str),
            Some("https://idp/.well-known/jwks.json")
        );
        assert_eq!(f.invoke_targets, ["thumbnail", "img-*"]);

        assert_eq!(manifest.compute.len(), 1);
        assert_eq!(manifest.compute[0].name, "api");
        // The typed spec parsed: an image workload with the declared sizing.
        assert_eq!(manifest.compute[0].replicas, 2);
        assert_eq!(
            manifest.compute[0].spec.root,
            boatramp_core::compute::RootSource::Image("nginx:latest".into())
        );
        assert_eq!(manifest.compute[0].spec.port, 8080);
    }

    #[test]
    fn empty_manifest_is_the_default() {
        let manifest = ApplyManifest::parse("()").expect("empty manifest parses");
        assert!(manifest.project.is_none());
        assert!(manifest.sites.is_empty());
        assert!(manifest.functions.is_empty());
        assert!(manifest.compute.is_empty());
    }

    #[test]
    fn missing_manifest_is_an_error() {
        let path =
            std::env::temp_dir().join(format!("boatramp-apply-missing-{}.cfg", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(matches!(ApplyManifest::load(&path), Err(Error::Missing(_))));
    }

    #[test]
    fn bad_routing_fails_the_compile_check() {
        // A double-globstar pattern is rejected by `DeployConfig::compile_check`,
        // so the whole manifest fails to parse — a bad manifest fails fast.
        let err = ApplyManifest::parse(
            r#"(
                sites: [
                    ( name: "www", routing: ( redirects: [ (from: "/a/**/b/**", to: "/x") ] ) ),
                ],
            )"#,
        )
        .expect_err("bad routing is rejected");
        assert!(matches!(err, Error::Routing { .. }));
    }

    #[test]
    fn manifest_project_wins_over_config() {
        // The manifest's explicit `project:` takes precedence over the
        // config-resolved project (which would otherwise resolve to `acme`).
        let mut config = ProjectConfig::default();
        config.publish.project = Some("acme".into());

        let manifest = ApplyManifest::parse(r#"( project: "team-x" )"#).unwrap();
        let resolved = manifest
            .project
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| client::resolve_project(&config));
        assert_eq!(resolved, "team-x");

        // Without a manifest project, the config's project is used.
        let manifest = ApplyManifest::parse("()").unwrap();
        let resolved = manifest
            .project
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| client::resolve_project(&config));
        assert_eq!(resolved, "acme");
    }

    #[test]
    fn function_secrets_round_trip_as_references() {
        // A manifest function can declare secret *references* — the manifest stays
        // committable because only the host-env-var name lives in it, never a value.
        let manifest = ApplyManifest::parse(
            r#"(
                functions: [
                    (
                        name: "api", component: "api.wasm",
                        secrets: { "DB_URL": "PROD_DB_URL" },
                    ),
                ],
            )"#,
        )
        .expect("manifest with function secrets parses");
        let f = &manifest.functions[0];
        assert_eq!(
            f.secrets.get("DB_URL").map(String::as_str),
            Some("PROD_DB_URL")
        );
    }

    // -----------------------------------------------------------------------
    // Part 1 — typed compute
    // -----------------------------------------------------------------------

    #[test]
    fn typed_compute_spec_round_trips_from_ron() {
        // A typed `ComputeSpec` authored directly in RON parses into the real type —
        // `root` is the snake_case newtype variant `image(…)`, which the existing
        // IMPLICIT_SOME extension set already handles (no UNWRAP_VARIANT_NEWTYPES).
        let manifest = ApplyManifest::parse(
            r#"(
                compute: [
                    (
                        name: "db",
                        spec: (
                            root: image("pgvector/pgvector:pg16"),
                            vcpus: 2, mem_mib: 1024, port: 5432,
                            env: { "POSTGRES_PASSWORD": "x" },
                        ),
                        replicas: 1,
                    ),
                ],
            )"#,
        )
        .expect("a typed compute spec parses");
        let c = &manifest.compute[0];
        assert_eq!(
            c.spec.root,
            boatramp_core::compute::RootSource::Image("pgvector/pgvector:pg16".into())
        );
        assert_eq!(c.spec.vcpus, 2);
        assert_eq!(c.replicas, 1);
        // It round-trips to the exact PutComputeRequest the server deserializes.
        let req = c.to_request();
        assert_eq!(req.spec, c.spec);
        assert_eq!(req.replicas, 1);
    }

    #[test]
    fn raw_json_compute_spec_now_fails_with_the_wrapped_error() {
        // The pre-v0.6.0 raw-JSON `spec` blob, in a VERSION-LESS manifest, no longer
        // parses (it is not a typed ComputeSpec) — and the failure is the wrapped
        // v0.6.0 upgrade error that names the migration path.
        let err = ApplyManifest::parse(
            r#"(
                compute: [
                    ( name: "api", spec: { "root": { "image": "nginx" }, "replicas": 2 } ),
                ],
            )"#,
        )
        .expect_err("a raw-JSON spec is rejected under the current schema");
        assert!(matches!(err, Error::StrictParse { .. }), "got {err:?}");
        let msg = err.to_string();
        assert!(msg.contains("v0.6.0"), "names the version: {msg}");
        assert!(
            msg.contains("boatramp config migrate"),
            "names the migration verb: {msg}"
        );
        assert!(
            msg.contains("version: 1"),
            "tells the user to add version: 1: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Part 2 — config versioning + migration
    // -----------------------------------------------------------------------

    #[test]
    fn version_too_new_is_refused() {
        let err = ApplyManifest::parse(&format!("( version: {} )", CURRENT_MANIFEST_VERSION + 1))
            .expect_err("a future version is refused");
        assert!(matches!(err, Error::VersionTooNew { .. }), "got {err:?}");
    }

    #[test]
    fn explicit_current_version_parses_strictly() {
        // Declaring the current version is allowed and parses exactly like version-less.
        let manifest = ApplyManifest::parse(&format!(
            "( version: {}, project: \"acme\" )",
            CURRENT_MANIFEST_VERSION
        ))
        .expect("current-version manifest parses");
        assert_eq!(manifest.project.as_deref(), Some("acme"));
    }

    #[test]
    fn v1_raw_json_compute_manifest_migrates_to_typed() {
        // A `version: 1` manifest with the old raw-JSON PutComputeRequest-shaped spec
        // blob migrates: the blob is split into the typed spec/replicas fields.
        let text = r#"(
            version: 1,
            project: "acme",
            compute: [
                (
                    name: "api",
                    spec: {
                        "spec": { "root": { "image": "nginx:latest" }, "vcpus": 1, "mem_mib": 256, "port": 8080 },
                        "replicas": 3,
                    },
                ),
            ],
        )"#;
        let manifest = ApplyManifest::parse(text).expect("v1 manifest migrates");
        // `version:` is dropped on migration (current = absent).
        assert!(manifest.version.is_none());
        assert_eq!(manifest.project.as_deref(), Some("acme"));
        let c = &manifest.compute[0];
        assert_eq!(
            c.spec.root,
            boatramp_core::compute::RootSource::Image("nginx:latest".into())
        );
        assert_eq!(c.spec.port, 8080);
        assert_eq!(c.replicas, 3);
    }

    #[test]
    fn v1_migration_produces_a_current_serializable_manifest() {
        // The migrated manifest re-renders as RON that OMITS `version:` (current =
        // absent) — the `config migrate` output.
        let text = r#"(
            version: 1,
            compute: [
                ( name: "api", spec: { "spec": { "root": { "image": "nginx" }, "vcpus": 1, "mem_mib": 128, "port": 80 } } ),
            ],
        )"#;
        let manifest = ApplyManifest::parse(text).unwrap();
        let rendered = crate::apply_migrate::render_manifest(&manifest).unwrap();
        // The TOP-LEVEL manifest omits `version:` (current = absent). The nested
        // `ComputeSpec.version: 1` schema discriminant is a different field and is
        // expected to remain — so assert on the manifest header, not the whole string.
        let header = rendered.lines().take(2).collect::<Vec<_>>().join("\n");
        assert!(
            !header.contains("version"),
            "upgraded manifest header omits version: {header}"
        );
        // The re-rendered manifest parses cleanly as current (no top-level `version:`).
        let reparsed =
            ApplyManifest::parse(&rendered).expect("re-rendered manifest parses as current");
        assert!(reparsed.version.is_none());
    }

    #[test]
    fn db_shaped_v1_workload_still_migrates() {
        // A DB-shaped image (pgvector) draws a warning (to stderr) but the migration
        // still succeeds — it stays a plain compute workload (Stage B adds `databases:`).
        let text = r#"(
            version: 1,
            compute: [
                ( name: "vec", spec: { "spec": { "root": { "image": "pgvector/pgvector:pg16" }, "vcpus": 2, "mem_mib": 1024, "port": 5432 } } ),
            ],
        )"#;
        let manifest = ApplyManifest::parse(text).expect("DB-shaped v1 workload migrates");
        assert_eq!(
            manifest.compute[0].spec.root,
            boatramp_core::compute::RootSource::Image("pgvector/pgvector:pg16".into())
        );
    }

    // -----------------------------------------------------------------------
    // Part 4 — graphql safelist (rename + register-only apply)
    // -----------------------------------------------------------------------

    /// Build an `ApplySite` whose site config declares a graphql handler, mutating it
    /// with `f` (to set the safelist fields under test).
    fn site_with_graphql(
        name: &str,
        f: impl FnOnce(&mut boatramp_core::config::HandlerGraphqlConfig),
    ) -> ApplySite {
        let mut gql = boatramp_core::config::HandlerGraphqlConfig {
            enabled: true,
            ..Default::default()
        };
        f(&mut gql);
        let site_config = SiteConfig {
            handlers: Some(boatramp_core::config::HandlersSiteConfig {
                enabled: true,
                graphql: Some(gql),
                ..Default::default()
            }),
            ..Default::default()
        };
        ApplySite {
            name: name.into(),
            path: None,
            build: None,
            routing: None,
            config: Some(site_config),
        }
    }

    #[test]
    fn enforce_safelist_rename_parses_from_config() {
        // The renamed field parses under its new name (the old `safelist` name is gone).
        let manifest = ApplyManifest::parse(
            r#"(
                sites: [
                    ( name: "gw", config: ( handlers: ( enabled: true, graphql: ( enabled: true, enforce_safelist: true ) ) ) ),
                ],
            )"#,
        )
        .expect("enforce_safelist parses");
        let gql = manifest.sites[0]
            .config
            .as_ref()
            .unwrap()
            .handlers
            .as_ref()
            .unwrap()
            .graphql
            .as_ref()
            .unwrap();
        assert!(gql.enforce_safelist);
    }

    #[tokio::test]
    async fn apply_safelists_registers_each_op_register_only() {
        let mock = MockCp::default();
        let site = site_with_graphql("gw", |g| {
            g.safelisted_ops = vec!["query A { a }".into(), "query B { b }".into()];
        });
        apply_safelists(&mock, &site, Path::new("."), false)
            .await
            .unwrap();
        let calls = mock.calls();
        // Exactly one register per op, in order — and NO delete/prune (register-only).
        assert_eq!(
            calls,
            [
                "register_graphql_safelist query A { a }",
                "register_graphql_safelist query B { b }",
            ]
        );
        assert!(
            !calls.iter().any(|c| c.to_lowercase().contains("delete")
                || c.to_lowercase().contains("remove")
                || c.to_lowercase().contains("prune")),
            "register-only: never deletes/prunes"
        );
    }

    #[tokio::test]
    async fn apply_safelists_dry_run_registers_nothing() {
        let mock = MockCp::default();
        let site = site_with_graphql("gw", |g| {
            g.safelisted_ops = vec!["query A { a }".into()];
        });
        apply_safelists(&mock, &site, Path::new("."), true)
            .await
            .unwrap();
        assert!(mock.calls().is_empty(), "dry-run registers nothing");
    }

    #[tokio::test]
    async fn apply_safelists_mutual_exclusion_is_an_error() {
        let mock = MockCp::default();
        let site = site_with_graphql("gw", |g| {
            g.safelisted_ops = vec!["query A { a }".into()];
            g.safelisted_ops_path = Some("ops.json".into());
        });
        let err = apply_safelists(&mock, &site, Path::new("."), false)
            .await
            .expect_err("both sources set is refused");
        assert!(matches!(err, Error::SafelistConflict { .. }), "got {err:?}");
        assert!(mock.calls().is_empty(), "no registration on a conflict");
    }

    #[tokio::test]
    async fn apply_safelists_reads_ops_from_a_file_client_side() {
        // The file is read relative to the manifest dir; each op is registered.
        let dir = std::env::temp_dir().join(format!("boatramp-safelist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("ops.json"),
            br#"["query A { a }", "query B { b }"]"#,
        )
        .unwrap();

        let mock = MockCp::default();
        let site = site_with_graphql("gw", |g| {
            g.safelisted_ops_path = Some("ops.json".into());
        });
        let res = apply_safelists(&mock, &site, &dir, false).await;
        let _ = std::fs::remove_dir_all(&dir);
        res.unwrap();
        assert_eq!(
            mock.calls(),
            [
                "register_graphql_safelist query A { a }",
                "register_graphql_safelist query B { b }",
            ]
        );
    }

    #[test]
    fn parse_ops_file_handles_array_and_single_forms() {
        // A JSON array of operation strings → each element is one op.
        assert_eq!(
            parse_ops_file(r#"["query A { a }", "query B { b }"]"#),
            ["query A { a }", "query B { b }"]
        );
        // A non-array file → the whole content is a single op.
        assert_eq!(parse_ops_file("query Single { s }"), ["query Single { s }"]);
        // Empty → no ops.
        assert!(parse_ops_file("   ").is_empty());
    }
}
