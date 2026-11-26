//! The `apply` reconcile core (node-library N3): the control-plane **reconcile
//! logic** that drives a project manifest to its desired state, lifted out of the
//! `boatramp` binary so it is unit-testable in-process — not only through
//! `boatramp apply` against a live server (see `PLAN-node-library`).
//!
//! The reconcile is written against two seams rather than concrete infrastructure:
//!
//! - [`ControlPlane`] — the remote control-plane operations (create-or-update,
//!   config-before-activate, create-on-404 / ignore-on-409). The binary wires the
//!   real HTTP client; a test a recording mock.
//! - [`SiteBuilder`] — the two *local* operations a site deploy needs (run the
//!   external build command; hash the content directory into a deploy manifest +
//!   uploadable blob sources). The binary runs the real command/walk; a test stubs
//!   them, so the reconcile core carries no process/filesystem dependency of its own.
//!
//! Both seams are static-dispatched (the reconcile fns are generic over
//! `C: ControlPlane` / `B: SiteBuilder`), so there is no `async-trait` / boxing on
//! the hot path. The **config-before-activate** ordering — a site's config is PUT
//! *before* the deployment is activated, so the server's activation precheck sees it
//! — is the invariant this module exists to guarantee, and is exercised directly by
//! the mock-driven tests below.
//!
//! The binary keeps manifest parsing (`ApplyManifest`), argument handling, output
//! rendering, and the concrete [`ControlPlane`]/[`SiteBuilder`] impls; this crate
//! holds the reconcile engine and the manifest's per-resource input types.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use boatramp_core::config::{DeployConfig, HandlerLimits, SiteConfig};
use boatramp_core::deploy::Manifest;
use serde::Deserialize;
use serde_json::json;

use crate::config::BuildConfig;

/// What a deployment negotiation told the reconcile core: the new deployment id and
/// the blob hashes the server is still missing (the ones to upload). A minimal,
/// client-agnostic projection of the HTTP `CreateDeploymentResponse` the binary
/// decodes — the reconcile only ever reads these two fields.
#[derive(Debug, Clone)]
pub struct CreatedDeployment {
    /// The created deployment's id.
    pub id: String,
    /// Blob hashes the server does not yet have and needs uploaded.
    pub missing: Vec<String>,
}

/// Where a blob's bytes come from when uploading: streamed from disk (identity
/// content) or held in memory (a precompressed variant produced at sync). Produced
/// by [`SiteBuilder::hash_site`] and consumed by [`ControlPlane::upload_blob_source`].
pub enum BlobSource {
    /// Stream the blob from this local file.
    File(PathBuf),
    /// The blob's bytes, already in memory (e.g. a precompressed variant).
    Memory(Vec<u8>),
}

/// A control-plane call outcome classified for the reconcile core: `NotFound`
/// (HTTP 404) and `Conflict` (409) are surfaced explicitly so `ensure_project`'s
/// create-on-404 / ignore-conflict-on-409 works against a mock; every other failure
/// is preserved verbatim as a boxed error (the binary boxes its concrete
/// `ClientError`, whose `Display` is carried through unchanged).
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
    Client(Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Reconcile-core control-plane result; `Err` is [`CpError`].
pub type CpResult<T> = std::result::Result<T, CpError>;

/// The control-plane operations the `apply` reconcile core performs — a seam over the
/// concrete HTTP control-plane client so the reconcile logic (create-or-update,
/// config-before-activate, create-on-404 / ignore-on-409) is unit-testable against a
/// mock without a live server. Static-dispatched: the reconcile fns are generic over
/// `C: ControlPlane`, so no `async-trait` / boxing.
#[allow(async_fn_in_trait)] // static-dispatch seam; never used as `dyn`
pub trait ControlPlane {
    /// Read a project; a missing one is [`CpError::NotFound`].
    async fn get_project(&self, name: &str) -> CpResult<serde_json::Value>;
    /// Create a project; a concurrent create is [`CpError::Conflict`].
    async fn create_project(&self, body: &serde_json::Value) -> CpResult<serde_json::Value>;
    /// Negotiate a deployment; the reply lists the blob hashes still missing.
    async fn create_deployment(
        &self,
        site: &str,
        manifest: &Manifest,
    ) -> CpResult<CreatedDeployment>;
    /// Upload one missing blob by content-address.
    async fn upload_blob_source(&self, hash: &str, source: &BlobSource) -> CpResult<()>;
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
    /// (register-only; the server validates + stores it, idempotently). `site` is the site the op
    /// is declared for, so the server can validate it against that site's per-site subgraph subset.
    async fn register_graphql_safelist(&self, query: &str, site: &str) -> CpResult<()>;
    /// Declare (persist + eagerly provision) one managed database from the manifest
    /// `databases:` block (`PUT /api/{seg}/databases/{name}`, `Project·Admin`). The
    /// server enforces daemon-config-wins, identity-change refusal, and caller's-project
    /// binding; a refusal (409/…) surfaces as [`CpError::Client`] with the reason.
    async fn declare_database(
        &self,
        name: &str,
        db: &boatramp_core::compute::ApplyDatabase,
    ) -> CpResult<()>;
}

/// The *local* (non-control-plane) operations a site reconcile needs: run the site's
/// external build command, and hash a content directory into a deploy manifest plus
/// the uploadable sources for each unique blob. A seam so the reconcile core is a pure
/// library over BOTH the network ([`ControlPlane`]) and the local filesystem/process —
/// the binary wires the real command/walk, a test a stub.
#[allow(async_fn_in_trait)] // static-dispatch seam; never used as `dyn`
pub trait SiteBuilder {
    /// Run the site's external build step when one applies — the site declared a
    /// `build`, or `--build` (`build_flag`) selected the project default. A no-op
    /// otherwise.
    async fn build_site(&self, site: &ApplySite, build_flag: bool) -> ReconcileResult<()>;
    /// Hash a content directory into a deploy [`Manifest`] plus the local source for
    /// each unique blob (identity + precompressed variants), for upload. Prechecks that
    /// the path is a directory ([`ReconcileError::NotADirectory`]).
    async fn hash_site(
        &self,
        dir: &Path,
    ) -> ReconcileResult<(Manifest, HashMap<String, BlobSource>)>;
}

/// A failure in the `apply` reconcile core. The infrastructure-boxed variants
/// ([`Build`](Self::Build) / [`Hash`](Self::Hash)) and the transparent
/// [`Cp`](Self::Cp) carry the underlying error's `Display` through unchanged, so the
/// binary's user-facing error text is identical whether the reconcile ran in-process
/// or against the real client.
#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    /// A control-plane call failed, carrying the 404/409 classification the core acts on.
    #[error(transparent)]
    Cp(#[from] CpError),
    /// The resolved publish path is not a directory.
    #[error("{0} is not a directory")]
    NotADirectory(String),
    /// The server requested a blob we have no local source for.
    #[error("no local source for blob {0}")]
    NoLocalSource(String),
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
    /// The site's external build step failed (the binary's build error, boxed).
    #[error(transparent)]
    Build(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// Hashing/building the site's content manifest failed (the binary's sync error, boxed).
    #[error(transparent)]
    Hash(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// Encoding a request body failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Reconcile-core result; `Err` is [`ReconcileError`].
pub type ReconcileResult<T> = std::result::Result<T, ReconcileError>;

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
    pub fn to_request(&self) -> boatramp_core::compute::PutComputeRequest {
        boatramp_core::compute::PutComputeRequest {
            spec: self.spec.clone(),
            replicas: self.replicas,
            placement: self.placement.clone(),
            // Manifest-declared priority is a thin follow-on. `None` ⇒ PRESERVE the stored
            // workload's priority: a re-`apply` that does not carry priority never silently demotes
            // a class/rank set out-of-band via `compute set --priority-class`; a brand-new
            // workload defaults to `standard`/rank 0 server-side.
            priority: None,
        }
    }
}

/// A planned managed-database declaration.
#[derive(Debug, serde::Serialize)]
pub struct PlanDatabase {
    pub name: String,
    pub kind: boatramp_core::compute::ApplyDatabaseKind,
    pub tenant: boatramp_core::compute::ApplyDatabaseTenant,
    pub size: boatramp_core::compute::ApplyDatabaseSize,
}

/// A planned site deployment.
#[derive(Debug, serde::Serialize)]
pub struct PlanSite {
    pub name: String,
    pub dir: String,
    pub build: bool,
    pub routing: bool,
    pub config: bool,
    /// How many safelisted GraphQL operations would be registered (register-only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safelist_ops: Option<usize>,
}

/// A planned function deployment.
#[derive(Debug, serde::Serialize)]
pub struct PlanFunction {
    pub name: String,
    pub component: String,
}

/// A planned compute workload.
#[derive(Debug, serde::Serialize)]
pub struct PlanCompute {
    pub name: String,
}

/// The structured `--dry-run` plan — each field is a resource that *would* be
/// reconciled, carrying the same facts the human plan lines show. Assembled by
/// [`reconcile_project`] as it walks the manifest (every helper contributes its
/// dry-run entry; a real apply leaves the plan empty and reconciles instead).
///
/// The binary's `ApplyOutput::Plan` carries this verbatim and renders it via
/// [`ApplyPlan::render`] (node-library N4 lifted the plan type + its rendering out of
/// the binary alongside the driver, so the `--dry-run` output is locked by a library
/// test, not only the CLI).
#[derive(Debug, Default, serde::Serialize)]
pub struct ApplyPlan {
    /// The non-`default` project that would be ensured to exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ensure_project: Option<String>,
    /// The tenancy schema's table count, when one would be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenancy_tables: Option<usize>,
    /// Managed databases that would be declared + provisioned.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub databases: Vec<PlanDatabase>,
    /// Sites that would be deployed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sites: Vec<PlanSite>,
    /// Top-level functions that would be deployed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub functions: Vec<PlanFunction>,
    /// Compute workloads that would be applied.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub compute: Vec<PlanCompute>,
}

impl ApplyPlan {
    /// Render the plan's human lines (byte-for-byte the former `--dry-run` stdout, minus
    /// the header + the ceiling-exception warnings, which ride `tracing`). Public so the
    /// binary's `ApplyOutput::render_human` delegates to it.
    pub fn render(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        if let Some(project) = &self.ensure_project {
            writeln!(w, "  project `{project}`: ensure exists")?;
        }
        if let Some(tables) = self.tenancy_tables {
            writeln!(w, "  tenancy: would set schema ({tables} table(s))")?;
        }
        for db in &self.databases {
            writeln!(
                w,
                "  database `{}`: would declare + provision ({:?}, {:?}, size {:?})",
                db.name, db.kind, db.tenant, db.size
            )?;
        }
        for site in &self.sites {
            writeln!(
                w,
                "  site `{}`: would deploy {} (build: {}, routing: {}, config: {})",
                site.name,
                site.dir,
                yes_no(site.build),
                yes_no(site.routing),
                yes_no(site.config),
            )?;
            if let Some(ops) = site.safelist_ops {
                writeln!(
                    w,
                    "  site `{}`: would register {} safelisted operation(s) (register-only)",
                    site.name, ops,
                )?;
            }
        }
        for f in &self.functions {
            writeln!(
                w,
                "  function `{}`: would deploy from {}",
                f.name, f.component
            )?;
        }
        for c in &self.compute {
            writeln!(w, "  compute `{}`: would apply spec", c.name)?;
        }
        Ok(())
    }
}

/// `"yes"`/`"no"` for a dry-run plan line.
fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

/// Ensure the target project exists: `GET` it, and on a 404 `create` it. A
/// concurrent create (409/conflict) is ignored. The reserved `default` project
/// always exists, so it is skipped.
/// Returns `Some(project)` as a dry-run plan entry when a non-`default` project would
/// be ensured; otherwise `None` (default project, or a real apply).
pub async fn ensure_project<C: ControlPlane>(
    cp: &C,
    project: &str,
    dry_run: bool,
) -> ReconcileResult<Option<String>> {
    if project == boatramp_core::project::DEFAULT_PROJECT {
        return Ok(None);
    }
    if dry_run {
        return Ok(Some(project.to_string()));
    }
    match cp.get_project(project).await {
        Ok(_) => Ok(None),
        Err(CpError::NotFound) => match cp.create_project(&json!({ "name": project })).await {
            Ok(_) => {
                tracing::info!(project, "created project");
                Ok(None)
            }
            // A concurrent create is fine — the project ends up existing either way.
            Err(CpError::Conflict) => Ok(None),
            Err(err) => Err(err.into()),
        },
        Err(err) => Err(err.into()),
    }
}

/// Reconcile the project's tenancy schema: unconditionally PUT the declared schema
/// (idempotent replace). Runs before the sites/functions so the isolation boundary is
/// in place before any handler can serve a request.
/// Returns `Some(table_count)` as a dry-run plan entry; `None` in a real apply (the
/// set is reported via `tracing`).
pub async fn reconcile_tenancy<C: ControlPlane>(
    cp: &C,
    schema: &boatramp_core::tenancy::TenancySchema,
    dry_run: bool,
) -> ReconcileResult<Option<usize>> {
    if dry_run {
        return Ok(Some(schema.tables.len()));
    }
    cp.put_project_tenancy(schema).await?;
    tracing::info!(tables = schema.tables.len(), "set tenancy schema");
    Ok(None)
}

/// Reconcile the declared managed databases (#501 Stage B): `PUT` each — a create-or-replace
/// that eagerly provisions — and NEVER prune. Runs BEFORE sites/functions/compute so a
/// handler shipped in the same apply binds an already-provisioned DB. Upsert-only (matching
/// the module's upsert-never-prune contract): an entry dropped from a later manifest is left
/// untouched server-side (its DB/volume/credential are kept). The server enforces the security
/// invariants (daemon-config-wins, identity-change refusal, caller's-project binding); a
/// refusal surfaces as a client error here.
/// Returns the dry-run plan entries (one per declared DB); an empty vec in a real
/// apply (each declare is reported via `tracing`).
pub async fn apply_databases<C: ControlPlane>(
    cp: &C,
    databases: &[boatramp_core::compute::ApplyDatabase],
    dry_run: bool,
) -> ReconcileResult<Vec<PlanDatabase>> {
    let mut plan = Vec::new();
    for db in databases {
        if dry_run {
            plan.push(PlanDatabase {
                name: db.name.clone(),
                kind: db.kind,
                tenant: db.tenant,
                size: db.size,
            });
            continue;
        }
        cp.declare_database(&db.name, db).await?;
        tracing::info!(database = %db.name, "declared + provisioned database");
    }
    Ok(plan)
}

/// Reconcile one site: (optionally build), hash the content dir, negotiate the
/// deployment, upload the missing blobs, PUT its site config, then activate (config
/// before activate — the activation precheck gates handlers on the stored config).
/// Returns `Some(PlanSite)` as a dry-run plan entry; `None` in a real apply (progress
/// is reported via `tracing`).
pub async fn apply_site<C: ControlPlane, B: SiteBuilder>(
    cp: &C,
    builder: &B,
    site: &ApplySite,
    manifest_dir: &Path,
    build_flag: bool,
    dry_run: bool,
) -> ReconcileResult<Option<PlanSite>> {
    let dir = site_content_dir(site);

    if dry_run {
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
                    let methods = h.methods.join(",");
                    match site_allows {
                        Some(false) => tracing::warn!(
                            route = ?h.route,
                            methods = %methods,
                            "route declares `exceed_site_ceiling` but this apply's site config does \
                             NOT set `allow_ceiling_exceptions` — it will be REFUSED at activation. \
                             Set it, or narrow the route."
                        ),
                        _ => tracing::warn!(
                            route = ?h.route,
                            methods = %methods,
                            "route exceeds the site tenancy ceiling (authorized via \
                             `exceed_site_ceiling`; the site must set `allow_ceiling_exceptions`, and \
                             an `all` grant also needs the operator posture `allow_cross_tenant_db`)."
                        ),
                    }
                }
            }
        }
        // Surface (and validate) the declared safelisted ops at plan time, so a
        // misconfig (both sources set, or an unreadable file) fails the dry-run early.
        let safelist_ops = apply_safelists(cp, site, manifest_dir, true).await?;
        return Ok(Some(PlanSite {
            name: site.name.clone(),
            dir: dir.display().to_string(),
            build: site.build.is_some() || build_flag,
            routing: site.routing.is_some(),
            config: site.config.is_some(),
            safelist_ops,
        }));
    }

    // Build first when the site declares a build (or `--build` was passed). Delegated to
    // the injected `SiteBuilder` (the CLI runs the real external command; a test a stub),
    // so the reconcile core holds no process dependency of its own.
    builder.build_site(site, build_flag).await?;

    // Content-addressed manifest of the tree (the builder also prechecks that `dir` is a
    // directory); fold the site's routing in.
    let (mut manifest, blobs_by_hash) = builder.hash_site(&dir).await?;
    if let Some(routing) = &site.routing {
        manifest.config = routing.clone();
    }

    let created = cp.create_deployment(&site.name, &manifest).await?;
    tracing::info!(
        site = %site.name,
        deployment = %created.id,
        missing = created.missing.len(),
        "negotiated site deployment; uploading new blobs"
    );

    for hash in &created.missing {
        let source = blobs_by_hash
            .get(hash)
            .ok_or_else(|| ReconcileError::NoLocalSource(hash.clone()))?;
        cp.upload_blob_source(hash, source).await?;
    }

    // Apply the site config BEFORE activating: activation prechecks a deployment's
    // handlers against the site's stored config (allow_imports / handler enablement),
    // so a handler-shipping deployment is refused (422) if its config has not landed
    // yet. Configure the site, then flip it live.
    if let Some(site_config) = &site.config {
        cp.put_site_config(&site.name, site_config).await?;
        tracing::info!(site = %site.name, "applied site config");
    }

    cp.activate(&site.name, &created.id).await?;
    tracing::info!(site = %site.name, deployment = %created.id, "activated site");

    // Register the site's declaratively-safelisted GraphQL operations (register-only).
    apply_safelists(cp, site, manifest_dir, false).await?;

    Ok(None)
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
/// Returns `Some(op_count)` as a dry-run plan entry when ops would be registered;
/// `None` otherwise (nothing to register, or a real apply — where the registration is
/// reported via `tracing`).
pub async fn apply_safelists<C: ControlPlane>(
    cp: &C,
    site: &ApplySite,
    manifest_dir: &Path,
    dry_run: bool,
) -> ReconcileResult<Option<usize>> {
    let Some(gql) = site
        .config
        .as_ref()
        .and_then(|c| c.handlers.as_ref())
        .and_then(|h| h.graphql.as_ref())
    else {
        return Ok(None);
    };

    // Mutual exclusion: pick one source of safelisted operations.
    if !gql.safelisted_ops.is_empty() && gql.safelisted_ops_path.is_some() {
        return Err(ReconcileError::SafelistConflict {
            site: site.name.clone(),
        });
    }

    // Collect the operation texts from whichever source is declared.
    let ops: Vec<String> = if let Some(rel) = &gql.safelisted_ops_path {
        // Resolve the path client-side relative to the manifest dir; only op TEXT
        // (never the path) ever leaves this host.
        let path = manifest_dir.join(rel);
        let text =
            std::fs::read_to_string(&path).map_err(|source| ReconcileError::SafelistFile {
                site: site.name.clone(),
                path: path.display().to_string(),
                source,
            })?;
        parse_ops_file(&text)
    } else {
        gql.safelisted_ops.clone()
    };

    if ops.is_empty() {
        return Ok(None);
    }

    if dry_run {
        return Ok(Some(ops.len()));
    }

    for op in &ops {
        cp.register_graphql_safelist(op, &site.name).await?;
    }
    tracing::info!(
        site = %site.name,
        ops = ops.len(),
        "registered safelisted operations (register-only)"
    );
    Ok(None)
}

/// Parse a `safelisted_ops_path` file into individual operation texts. The file is
/// either a **JSON array of operation strings** (`["query A {…}", "mutation B {…}"]`)
/// — the explicit multi-operation form — or, if it is not such an array, the WHOLE
/// file content is taken as a **single** operation (matching the existing
/// `boatramp graphql safelist add --file` semantics). Empty/whitespace-only entries
/// are dropped.
pub fn parse_ops_file(text: &str) -> Vec<String> {
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
/// Returns `Some(PlanFunction)` as a dry-run plan entry; `None` in a real apply (the
/// deploy is reported via `tracing`).
pub async fn apply_function<C: ControlPlane>(
    cp: &C,
    function: &ApplyFunction,
    dry_run: bool,
) -> ReconcileResult<Option<PlanFunction>> {
    if dry_run {
        return Ok(Some(PlanFunction {
            name: function.name.clone(),
            component: function.component.clone(),
        }));
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
    tracing::info!(function = %function.name, "deployed function");
    Ok(None)
}

/// Promote the staged subgraphs once, after all functions have been deployed (bug #499). Each
/// function deploy used `?compose=defer`, so its subgraph SDL was staged (not composed) — keeping
/// the O(N) introspect/compose off each individual deploy's request critical path. This calls
/// `POST .../graphql/compose` ONCE to validate + promote the whole staged set. A no-op when the
/// manifest declares no functions (nothing could have staged), and skipped entirely on a dry-run
/// (no deploys happened). Generic over the [`ControlPlane`] seam so the mock records the call.
pub async fn apply_deferred_compose<C: ControlPlane>(
    cp: &C,
    any_functions: bool,
    dry_run: bool,
) -> ReconcileResult<()> {
    if dry_run || !any_functions {
        return Ok(());
    }
    cp.compose_subgraphs().await?;
    Ok(())
}

/// Reconcile one compute workload: PUT its spec straight to the server.
/// Returns `Some(PlanCompute)` as a dry-run plan entry; `None` in a real apply (the
/// apply is reported via `tracing`).
pub async fn apply_compute<C: ControlPlane>(
    cp: &C,
    compute: &ApplyCompute,
    dry_run: bool,
) -> ReconcileResult<Option<PlanCompute>> {
    if dry_run {
        return Ok(Some(PlanCompute {
            name: compute.name.clone(),
        }));
    }
    // The typed request round-trips to the exact `PutComputeRequest` JSON the server
    // deserializes — the manifest and the wire share one schema.
    let body = serde_json::to_value(compute.to_request())?;
    cp.put_compute(&compute.name, &body).await?;
    tracing::info!(compute = %compute.name, "applied compute workload");
    Ok(None)
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

/// The desired-state inputs the reconcile driver walks: the already-resolved target
/// project plus the manifest's per-resource sections, each borrowed. A plain
/// value/borrow bundle — the binary keeps manifest *parsing* (`ApplyManifest`),
/// project resolution, and name validation; the driver takes the resolved pieces.
///
/// `manifest_dir` is the directory a site's `safelisted_ops_path` resolves against
/// (the manifest file's own directory); the binary computes it from the `-f` path.
pub struct ReconcileRequest<'a> {
    /// The resolved target project (an explicit manifest `project:` or the
    /// config-resolved value). `default` is never created.
    pub project: &'a str,
    /// The project tenancy schema to set before any site/function, if declared.
    pub tenancy: Option<&'a boatramp_core::tenancy::TenancySchema>,
    /// Declared managed databases, reconciled before sites/functions/compute.
    pub databases: &'a [boatramp_core::compute::ApplyDatabase],
    /// Sites to deploy (content-addressed, config-before-activate).
    pub sites: &'a [ApplySite],
    /// Top-level functions to deploy (each staging its subgraph via `?compose=defer`).
    pub functions: &'a [ApplyFunction],
    /// Compute workloads to create-or-replace.
    pub compute: &'a [ApplyCompute],
    /// The directory a site's `safelisted_ops_path` is resolved against.
    pub manifest_dir: &'a Path,
    /// Run each site's configured build command before publishing it (`--build`).
    pub build: bool,
    /// Print the plan and mutate nothing (`--dry-run`).
    pub dry_run: bool,
}

/// Drive a whole project manifest to its desired state (node-library N4): the
/// reconcile **driver** that sequences the per-resource helpers under the ordering
/// contract, lifted out of the binary's `apply::run` so the end-to-end sequence — not
/// only each helper in isolation — is unit-testable in-process against a mock.
///
/// The ordering is the contract (a handler shipped in the same apply must already run
/// under the isolation boundary and bind a provisioned DB), preserved byte-for-byte
/// from the former in-binary driver:
///
/// 1. **ensure the project** exists (create-on-404; `default` is skipped);
/// 2. **tenancy** schema — before any site/function;
/// 3. **databases** (#501 Stage B) — before sites/functions/compute;
/// 4. **sites** — each content-addressed, config-before-activate;
/// 5. **functions** — each staging its subgraph (`?compose=defer`);
/// 6. **deferred compose** — one promotion after the functions (bug #499), skipped
///    when no function was declared or on a dry-run;
/// 7. **compute** workloads.
///
/// Under `--dry-run` nothing is mutated: each helper contributes its plan entry and no
/// control-plane write is issued, so the returned [`ApplyPlan`] is the whole plan. In a
/// real apply the helpers reconcile (reporting progress via `tracing`) and the returned
/// plan is empty.
pub async fn reconcile_project<C: ControlPlane, B: SiteBuilder>(
    cp: &C,
    builder: &B,
    req: &ReconcileRequest<'_>,
) -> ReconcileResult<ApplyPlan> {
    // Ensure the project exists (best-effort; `default` always does).
    let mut plan = ApplyPlan {
        ensure_project: ensure_project(cp, req.project, req.dry_run).await?,
        ..Default::default()
    };

    // Reconcile the tenancy schema *before* any site/function, so a handler shipped in
    // this same apply already runs under the declared isolation boundary.
    if let Some(schema) = req.tenancy {
        plan.tenancy_tables = reconcile_tenancy(cp, schema, req.dry_run).await?;
    }

    // Reconcile declared managed databases *before* sites/functions/compute (#501 Stage B),
    // so a handler shipped in the same apply binds an already-provisioned DB. Each is
    // `PUT`-only (create-or-replace + eager provision); removing an entry never
    // deprovisions (the server keeps the DB/volume/credential).
    plan.databases = apply_databases(cp, req.databases, req.dry_run).await?;

    for site in req.sites {
        if let Some(planned) =
            apply_site(cp, builder, site, req.manifest_dir, req.build, req.dry_run).await?
        {
            plan.sites.push(planned);
        }
    }
    for function in req.functions {
        if let Some(planned) = apply_function(cp, function, req.dry_run).await? {
            plan.functions.push(planned);
        }
    }
    // Bug #499: each function deploy staged (not composed) its subgraph SDL via `?compose=defer`,
    // keeping the slow introspect/compose off the per-deploy request critical path. Promote the
    // whole staged set in ONE composition here (O(N) instead of O(N²) recomposes). A no-op when
    // no function staged a subgraph. Skipped on dry-run (no deploys happened).
    apply_deferred_compose(cp, !req.functions.is_empty(), req.dry_run).await?;
    for workload in req.compute {
        if let Some(planned) = apply_compute(cp, workload, req.dry_run).await? {
            plan.compute.push(planned);
        }
    }

    Ok(plan)
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
            _manifest: &Manifest,
        ) -> CpResult<CreatedDeployment> {
            self.rec(format!("create_deployment {site}"));
            // No missing blobs ⇒ the upload loop is skipped, isolating the
            // config-before-activate ordering under test.
            Ok(CreatedDeployment {
                id: "dep-1".into(),
                missing: vec![],
            })
        }
        async fn upload_blob_source(&self, hash: &str, _source: &BlobSource) -> CpResult<()> {
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
        async fn register_graphql_safelist(&self, query: &str, _site: &str) -> CpResult<()> {
            // Record the op text so a test can assert POST-per-op (and that no DELETE
            // is ever issued — the mock has no delete method at all).
            self.rec(format!("register_graphql_safelist {query}"));
            Ok(())
        }
        async fn declare_database(
            &self,
            name: &str,
            db: &boatramp_core::compute::ApplyDatabase,
        ) -> CpResult<()> {
            // Record the declare so a test can assert PUT-per-db (and that no deprovision
            // is ever issued — the mock has no delete/deprovision method at all).
            self.rec(format!("declare_database {name} kind={:?}", db.kind));
            Ok(())
        }
    }

    /// A no-op [`SiteBuilder`]: the build step does nothing and `hash_site` returns an
    /// empty manifest with no blob sources, so the site-reconcile tests exercise the
    /// control-plane ordering (config-before-activate) with no filesystem/process
    /// dependency — the whole point of the N3 seam.
    #[derive(Default)]
    struct MockBuilder;

    impl SiteBuilder for MockBuilder {
        async fn build_site(&self, _site: &ApplySite, _build_flag: bool) -> ReconcileResult<()> {
            Ok(())
        }
        async fn hash_site(
            &self,
            _dir: &Path,
        ) -> ReconcileResult<(Manifest, HashMap<String, BlobSource>)> {
            Ok((Manifest::default(), HashMap::new()))
        }
    }

    /// A [`ControlPlane`] that models the server's activation **precheck**: `activate`
    /// SUCCEEDS only after the site's config has been PUT (which `apply_site` must do
    /// first); otherwise it fails as a control-plane error — exactly the 422 the real
    /// server returns when a handler-shipping deployment is activated before its config
    /// lands. Lets a test prove the config-before-activate contract end to end: a site
    /// shipping config activates; one that ships none is rejected at activation.
    #[derive(Default)]
    struct PrecheckCp {
        calls: Mutex<Vec<String>>,
        config_landed: Mutex<bool>,
    }

    impl PrecheckCp {
        fn rec(&self, line: impl Into<String>) {
            self.calls.lock().unwrap().push(line.into());
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl ControlPlane for PrecheckCp {
        async fn get_project(&self, _name: &str) -> CpResult<serde_json::Value> {
            unreachable!("apply_site does not ensure the project")
        }
        async fn create_project(&self, _body: &serde_json::Value) -> CpResult<serde_json::Value> {
            unreachable!("apply_site does not create the project")
        }
        async fn create_deployment(
            &self,
            site: &str,
            _manifest: &Manifest,
        ) -> CpResult<CreatedDeployment> {
            self.rec(format!("create_deployment {site}"));
            Ok(CreatedDeployment {
                id: "dep-1".into(),
                missing: vec![],
            })
        }
        async fn upload_blob_source(&self, _hash: &str, _source: &BlobSource) -> CpResult<()> {
            Ok(())
        }
        async fn put_site_config(&self, site: &str, _config: &SiteConfig) -> CpResult<()> {
            self.rec(format!("put_site_config {site}"));
            *self.config_landed.lock().unwrap() = true;
            Ok(())
        }
        async fn activate(&self, site: &str, id: &str) -> CpResult<()> {
            self.rec(format!("activate {site} {id}"));
            if *self.config_landed.lock().unwrap() {
                Ok(())
            } else {
                // The server's activation precheck: a handler-shipping deployment whose
                // config has not landed is refused (422), surfaced here as a client error.
                Err(CpError::Client(
                    "activation precheck: site config has not landed (HTTP 422)".into(),
                ))
            }
        }
        async fn put_file_blob(&self, _path: &Path) -> CpResult<String> {
            unreachable!("apply_site does not stage a file blob")
        }
        async fn deploy_function(&self, _name: &str, _body: &serde_json::Value) -> CpResult<()> {
            unreachable!("apply_site does not deploy functions")
        }
        async fn compose_subgraphs(&self) -> CpResult<()> {
            unreachable!("apply_site does not compose subgraphs")
        }
        async fn put_compute(
            &self,
            _name: &str,
            _body: &serde_json::Value,
        ) -> CpResult<serde_json::Value> {
            unreachable!("apply_site does not put compute")
        }
        async fn put_project_tenancy(
            &self,
            _schema: &boatramp_core::tenancy::TenancySchema,
        ) -> CpResult<()> {
            unreachable!("apply_site does not set tenancy")
        }
        async fn register_graphql_safelist(&self, _query: &str, _site: &str) -> CpResult<()> {
            Ok(())
        }
        async fn declare_database(
            &self,
            _name: &str,
            _db: &boatramp_core::compute::ApplyDatabase,
        ) -> CpResult<()> {
            unreachable!("apply_site does not declare databases")
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

    /// A minimal typed image-workload spec for the compute-apply tests.
    fn an_image_spec() -> boatramp_core::compute::ComputeSpec {
        boatramp_core::compute::ComputeSpec::builder(
            boatramp_core::compute::RootSource::Image("nginx:latest".into()),
            1,
            256,
            8080,
        )
        .build()
    }

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
            handlers: Some(
                boatramp_core::config::HandlersSiteConfig::builder()
                    .enabled(true)
                    .graphql(Some(gql))
                    .build(),
            ),
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

    #[tokio::test]
    async fn apply_site_applies_config_before_activate() {
        // The invariant this module exists to guarantee (see `apply_site`'s doc): the
        // site config lands BEFORE the deployment is activated. Driven entirely through
        // the ControlPlane + SiteBuilder seams — no live server, no filesystem.
        let mock = MockCp::default();
        let builder = MockBuilder;
        let site = ApplySite {
            name: "www".into(),
            path: Some("dist".into()),
            build: None,
            routing: None,
            config: Some(SiteConfig::default()),
        };
        apply_site(&mock, &builder, &site, Path::new("."), false, false)
            .await
            .unwrap();
        assert_eq!(
            mock.calls(),
            [
                "create_deployment www",
                "put_site_config www",
                "activate www dep-1"
            ]
        );
    }

    #[tokio::test]
    async fn config_before_activate_a_shipped_config_activates() {
        // End-to-end through the seam against a control plane that enforces the real
        // activation precheck: a site shipping its config PUTs it first, so activation
        // is accepted. If the reconcile activated before applying config, the precheck
        // mock would reject it.
        let cp = PrecheckCp::default();
        let builder = MockBuilder;
        let site = ApplySite {
            name: "www".into(),
            path: Some("dist".into()),
            build: None,
            routing: None,
            config: Some(SiteConfig::default()),
        };
        apply_site(&cp, &builder, &site, Path::new("."), false, false)
            .await
            .expect("a site shipping its config activates (config landed before activate)");
        assert_eq!(
            cp.calls(),
            [
                "create_deployment www",
                "put_site_config www",
                "activate www dep-1"
            ],
            "config is PUT before activate"
        );
    }

    #[tokio::test]
    async fn config_before_activate_a_config_gated_deploy_is_rejected_at_activation() {
        // The inverse: a deployment whose config never lands (the manifest ships none)
        // is refused by the activation precheck — proving the reconcile surfaces the
        // server's config-before-activate gate rather than masking it. The precheck
        // model here always requires config, standing in for a handler-shipping deploy.
        let cp = PrecheckCp::default();
        let builder = MockBuilder;
        let site = ApplySite {
            name: "www".into(),
            path: Some("dist".into()),
            build: None,
            routing: None,
            config: None, // ships no config → nothing is PUT before activate
        };
        let err = apply_site(&cp, &builder, &site, Path::new("."), false, false)
            .await
            .expect_err("activation is rejected when the config never landed");
        // The rejection is the control-plane precheck error, surfaced verbatim.
        assert!(
            matches!(err, ReconcileError::Cp(CpError::Client(_))),
            "a config-gated deploy is rejected at activation, got {err:?}"
        );
        // The reconcile never PUT a config (there was none), and the failure happened
        // at `activate` — not before it.
        assert_eq!(cp.calls(), ["create_deployment www", "activate www dep-1"]);
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
        assert!(
            matches!(err, ReconcileError::SafelistConflict { .. }),
            "got {err:?}"
        );
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

    /// `apply_databases` PUTs each declared DB (create-or-replace + eager provision) and
    /// NEVER issues a deprovision — the mock has no delete/deprovision method at all, so an
    /// upsert-only reconcile is structural. Confirms the eager-declare wiring + the
    /// inert-on-removal contract at the reconcile seam.
    #[tokio::test]
    async fn apply_databases_puts_each_and_never_deprovisions() {
        let mock = MockCp::default();
        let dbs = vec![
            sample_db("app", boatramp_core::compute::ApplyDatabaseKind::Postgres),
            sample_db("metrics", boatramp_core::compute::ApplyDatabaseKind::Mysql),
        ];
        apply_databases(&mock, &dbs, false).await.unwrap();
        assert_eq!(
            mock.calls(),
            [
                "declare_database app kind=Postgres",
                "declare_database metrics kind=Mysql",
            ],
            "each declared DB is PUT once; no deprovision is ever issued"
        );
    }

    /// A `--dry-run` apply declares NOTHING (mutates no state).
    #[tokio::test]
    async fn apply_databases_dry_run_declares_nothing() {
        let mock = MockCp::default();
        let dbs = vec![sample_db(
            "app",
            boatramp_core::compute::ApplyDatabaseKind::Postgres,
        )];
        apply_databases(&mock, &dbs, true).await.unwrap();
        assert!(mock.calls().is_empty(), "dry-run declares nothing");
    }

    /// A minimal `ApplyDatabase` for the declare tests — only `name`/`kind` matter to the
    /// reconcile; every other field is its default.
    fn sample_db(
        name: &str,
        kind: boatramp_core::compute::ApplyDatabaseKind,
    ) -> boatramp_core::compute::ApplyDatabase {
        // Every optional knob at its default, so this is exactly `new(name, kind)`.
        boatramp_core::compute::ApplyDatabase::new(name.into(), kind)
    }

    // --- node-library N4: the reconcile DRIVER (`reconcile_project`) --------------------
    //
    // These drive the whole manifest sequence through the recording mock, locking the
    // end-to-end ORDERING CONTRACT and the dry-run plan assembly — the behaviour that
    // previously lived in the binary's `apply::run` and was only reachable through the
    // CLI. The per-resource helpers above are each tested in isolation; these test the
    // driver that sequences them.

    /// A plain site shipping an (empty) config, so the config-before-activate path runs
    /// (`put_site_config` lands before `activate`). No graphql handler ⇒ no safelist.
    fn a_plain_site(name: &str) -> ApplySite {
        ApplySite {
            name: name.into(),
            path: Some("dist".into()),
            build: None,
            routing: None,
            config: Some(SiteConfig::default()),
        }
    }

    /// A minimal image compute workload for the driver tests.
    fn an_api_compute() -> ApplyCompute {
        ApplyCompute {
            name: "api".into(),
            spec: an_image_spec(),
            replicas: 1,
            placement: Default::default(),
        }
    }

    /// The headline N4 test: a full manifest (project + tenancy + one database + one site
    /// + one function + one compute) drives through `reconcile_project` in the exact
    /// control-plane ORDER the contract requires — ensure-project, tenancy, databases,
    /// the site (config BEFORE activate), the function, exactly ONE deferred compose, then
    /// compute. The ordering is the contract (a handler shipped in the same apply must run
    /// under the declared isolation + bind a provisioned DB), so locking the whole order
    /// end-to-end — not only each helper in isolation — is the point of the driver seam.
    #[tokio::test]
    async fn reconcile_project_drives_the_full_sequence_in_contract_order() {
        use boatramp_core::tenancy::{TableScope, TenancySchema};
        let cp = MockCp::default(); // project_exists: false → get + create
        let builder = MockBuilder;

        let mut schema = TenancySchema::default();
        schema.tables.insert("orders".into(), TableScope::Tenant);

        let sites = vec![a_plain_site("www")];
        let functions = vec![a_function()];
        let databases = vec![sample_db(
            "app",
            boatramp_core::compute::ApplyDatabaseKind::Postgres,
        )];
        let compute = vec![an_api_compute()];

        let req = ReconcileRequest {
            project: "acme",
            tenancy: Some(&schema),
            databases: &databases,
            sites: &sites,
            functions: &functions,
            compute: &compute,
            manifest_dir: Path::new("."),
            build: false,
            dry_run: false,
        };
        let plan = reconcile_project(&cp, &builder, &req).await.unwrap();

        assert_eq!(
            cp.calls(),
            [
                "get_project acme",
                "create_project acme",
                "put_project_tenancy 1",
                "declare_database app kind=Postgres",
                "create_deployment www",
                "put_site_config www",
                "activate www dep-1",
                "put_file_blob resize.wasm",
                "deploy_function resize",
                "compose_subgraphs",
                "put_compute api",
            ],
            "the driver sequences the helpers under the ordering contract"
        );
        // A real apply reconciles (progress rides `tracing`); the returned plan is empty.
        assert!(plan.ensure_project.is_none());
        assert!(plan.tenancy_tables.is_none());
        assert!(
            plan.databases.is_empty()
                && plan.sites.is_empty()
                && plan.functions.is_empty()
                && plan.compute.is_empty(),
            "a real apply returns no dry-run plan entries"
        );
    }

    /// A `--dry-run` through the driver mutates NOTHING (no control-plane write at all,
    /// across every resource kind) and returns the whole assembled plan — one entry per
    /// declared resource. The inverse of the ordering test: same manifest, zero calls.
    #[tokio::test]
    async fn reconcile_project_dry_run_assembles_the_plan_and_mutates_nothing() {
        use boatramp_core::tenancy::{TableScope, TenancySchema};
        let cp = MockCp::default();
        let builder = MockBuilder;

        let mut schema = TenancySchema::default();
        schema.tables.insert("orders".into(), TableScope::Tenant);
        schema.tables.insert(
            "tenant".into(),
            TableScope::TenantKeyed { key: "id".into() },
        );

        let sites = vec![a_plain_site("www")];
        let functions = vec![a_function()];
        let databases = vec![sample_db(
            "app",
            boatramp_core::compute::ApplyDatabaseKind::Postgres,
        )];
        let compute = vec![an_api_compute()];

        let req = ReconcileRequest {
            project: "acme",
            tenancy: Some(&schema),
            databases: &databases,
            sites: &sites,
            functions: &functions,
            compute: &compute,
            manifest_dir: Path::new("."),
            build: false,
            dry_run: true,
        };
        let plan = reconcile_project(&cp, &builder, &req).await.unwrap();

        assert!(
            cp.calls().is_empty(),
            "dry-run issues no control-plane write, got {:?}",
            cp.calls()
        );
        assert_eq!(plan.ensure_project.as_deref(), Some("acme"));
        assert_eq!(plan.tenancy_tables, Some(2));
        assert_eq!(plan.databases.len(), 1);
        assert_eq!(plan.sites.len(), 1, "one planned site");
        assert_eq!(plan.functions.len(), 1, "one planned function");
        assert_eq!(plan.compute.len(), 1, "one planned compute workload");
        assert_eq!(plan.sites[0].name, "www");
        assert_eq!(plan.functions[0].name, "resize");
        assert_eq!(plan.compute[0].name, "api");
    }

    /// The deferred compose (bug #499) fires only when a function was declared: a manifest
    /// with sites + compute but NO functions issues NO `compose_subgraphs`, even though the
    /// other resources reconcile. Guards the "once, and only with functions" promotion rule
    /// at the driver level.
    #[tokio::test]
    async fn reconcile_project_skips_deferred_compose_without_functions() {
        let cp = MockCp {
            project_exists: true,
            ..Default::default()
        };
        let builder = MockBuilder;
        let sites = vec![a_plain_site("www")];
        let compute = vec![an_api_compute()];

        let req = ReconcileRequest {
            project: "acme",
            tenancy: None,
            databases: &[],
            sites: &sites,
            functions: &[],
            compute: &compute,
            manifest_dir: Path::new("."),
            build: false,
            dry_run: false,
        };
        reconcile_project(&cp, &builder, &req).await.unwrap();

        let calls = cp.calls();
        assert!(
            !calls.iter().any(|c| c == "compose_subgraphs"),
            "no functions ⇒ no deferred compose, got {calls:?}"
        );
        // The project already exists ⇒ a single GET, then the site + compute reconcile.
        assert_eq!(
            calls,
            [
                "get_project acme",
                "create_deployment www",
                "put_site_config www",
                "activate www dep-1",
                "put_compute api",
            ]
        );
    }

    /// Lock the `--dry-run` human rendering now that `ApplyPlan` + `render` live in the
    /// library (N4 lifted them out of the binary alongside the driver). Databases are
    /// omitted so only the deterministic line types (project / tenancy / site / function /
    /// compute) are asserted byte-for-byte — the former `boatramp apply --dry-run` stdout
    /// (minus the header, which the binary's `ApplyOutput` still renders).
    #[tokio::test]
    async fn reconcile_project_dry_run_plan_renders_byte_for_byte() {
        use boatramp_core::tenancy::{TableScope, TenancySchema};
        let cp = MockCp::default();
        let builder = MockBuilder;
        let mut schema = TenancySchema::default();
        schema.tables.insert("orders".into(), TableScope::Tenant);

        let sites = vec![a_plain_site("www")];
        let functions = vec![a_function()];
        let compute = vec![an_api_compute()];

        let req = ReconcileRequest {
            project: "acme",
            tenancy: Some(&schema),
            databases: &[],
            sites: &sites,
            functions: &functions,
            compute: &compute,
            manifest_dir: Path::new("."),
            build: false,
            dry_run: true,
        };
        let plan = reconcile_project(&cp, &builder, &req).await.unwrap();

        let mut buf = Vec::new();
        plan.render(&mut buf).unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "  project `acme`: ensure exists\n\
             \x20 tenancy: would set schema (1 table(s))\n\
             \x20 site `www`: would deploy dist (build: no, routing: no, config: yes)\n\
             \x20 function `resize`: would deploy from resize.wasm\n\
             \x20 compute `api`: would apply spec\n",
        );
    }
}
