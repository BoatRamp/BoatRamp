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

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use boatramp_core::config::SiteConfig;
use boatramp_core::deploy::Manifest;
use serde::Deserialize;

// The reconcile core (node-library N3) lives in `boatramp-node`; the binary keeps
// manifest parsing, arg handling, output rendering, and the concrete seam impls, and
// re-exports the per-resource manifest types so `crate::apply::{ApplySite, …}` call
// sites (e.g. `apply_migrate`) are unchanged.
use boatramp_node::reconcile::{
    self, BlobSource, ControlPlane, CpError, CpResult, CreatedDeployment, PlanCompute,
    PlanDatabase, PlanFunction, PlanSite, ReconcileError, SiteBuilder,
};
pub use boatramp_node::reconcile::{ApplyCompute, ApplyFunction, ApplySite};

use crate::client;
use crate::config::ProjectConfig;

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
    /// A **JSON** manifest (v0.6.5) failed to parse strictly against the current typed
    /// schema. The [`StrictParse`](Self::StrictParse)-class analogue for JSON input —
    /// the RON variant wraps a `ron::error::SpannedError`, so JSON carries its own
    /// `serde_json::Error`, but the upgrade UX reads the same (`deny_unknown_fields`
    /// makes a typo'd key a hard error, not a silent drop).
    #[error(
        "this JSON manifest does not match the current (v0.6.0) schema: {source}\n\n\
         JSON config input is current-schema only. If it was generated from Nickel, \
         regenerate it against the current schema (re-run `nickel export`); check for a \
         typo'd/unknown field (rejected by `deny_unknown_fields`) or a raw pre-v0.6.0 \
         `compute[].spec` shape."
    )]
    JsonStrictParse {
        #[source]
        source: serde_json::Error,
    },
    /// A manifest declared `version: N` newer than this build understands.
    #[error(
        "manifest declares version {declared}, but this build only understands up to \
         version {current} (v0.6.0). Upgrade boatramp, or lower the declared version."
    )]
    VersionTooNew { declared: u32, current: u32 },
    /// A **JSON** manifest declared `version: N` OLDER than the current schema. JSON
    /// config input was never accepted before v0.6.5, so there are no legacy JSON
    /// manifests to migrate — JSON is current-schema only. (The RON migration chain is
    /// unchanged; an old RON manifest still upgrades via `boatramp config migrate`.)
    #[error(
        "JSON config input is current-schema only (declares version {declared}); \
         regenerate current-schema JSON (e.g. re-run `nickel export`), or migrate the \
         RON source with `boatramp config migrate`"
    )]
    JsonLegacyVersion { declared: u32 },
    /// A migration step failed to transform an older manifest into the current schema.
    #[error("migrating manifest from version {from}: {reason}")]
    Migration { from: u32, reason: String },
    /// The manifest carries a resource name the v0.7.0 slug allowlist rejects (the
    /// project, a site, a function, a compute workload, or a database). Refused
    /// client-side BEFORE any reconcile — mirrors the migration-gate refusal style and
    /// points at `project doctor` so the operator discovers + fixes every bad name at
    /// once rather than hitting a per-resource 422 mid-apply.
    #[error(
        "manifest {kind} name {name:?} is not accepted (v0.7.0 tightened name \
         validation): {reason}.\n\n\
         Run `boatramp project doctor` to list every non-conforming name and its fix, \
         then rename to a valid slug (start/end with a letter or digit; interior may add \
         '_' / '-'; 1-63 bytes) and re-apply."
    )]
    InvalidName {
        kind: &'static str,
        name: String,
        reason: &'static str,
    },
    /// A site's `routing` failed its compile-check (a bad route/cron pattern).
    #[error("site {site}: routing: {source}")]
    Routing {
        site: String,
        #[source]
        source: boatramp_core::ConfigError,
    },
    /// A function's `token`-source claim transform (extract/namespace) or the cross-source
    /// namespace rule failed its apply-time check.
    #[error("function {function}: tenancy sources: {source}")]
    TenancySources {
        function: String,
        #[source]
        source: boatramp_core::ConfigError,
    },
    /// A `token_claims` (function or site GDC) failed its apply-time check — the single-issuer and
    /// multi-issuer (`issuer_trust`/`jwks`) forms are mutually exclusive, and the multi-issuer form
    /// needs a non-empty, well-formed policy + exactly one `jwks` discovery rule.
    #[error("{scope}: token_claims: {source}")]
    TokenClaims {
        scope: String,
        #[source]
        source: boatramp_core::ConfigError,
    },
    /// A control-plane request failed (the `connect`/resolve path).
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// Loading/parsing the project config (`project.cfg`) failed.
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// A local filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Decoding a JSON document failed (the version-peek on a JSON manifest).
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The reconcile core (node-library N3) failed. Wraps
    /// [`boatramp_node::reconcile::ReconcileError`] transparently, so the control-plane,
    /// build, blob-hashing, safelist, and encoding failures the reconcile surfaces keep
    /// their exact user-facing text — the apply error is identical whether the reconcile
    /// ran in-process or against the live client.
    #[error(transparent)]
    Reconcile(#[from] ReconcileError),
}

/// `apply` module result; `Err` is [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// The real [`ControlPlane`] seam: the concrete HTTP client. Each method forwards to
/// the same-named inherent method (inherent methods take precedence over trait methods,
/// so `self.` resolves to the HTTP call, not this trait). Only `get_project`/
/// `create_project` classify their error (the sole errors the reconcile core inspects);
/// every other method boxes the original `ClientError`, whose `Display` is carried
/// through [`CpError::Client`] unchanged, so no error text shifts.
impl ControlPlane for client::ControlPlane {
    async fn get_project(&self, name: &str) -> CpResult<serde_json::Value> {
        self.get_project(name).await.map_err(|e| {
            if is_not_found(&e) {
                CpError::NotFound
            } else {
                CpError::Client(Box::new(e))
            }
        })
    }
    async fn create_project(&self, body: &serde_json::Value) -> CpResult<serde_json::Value> {
        self.create_project(body).await.map_err(|e| {
            if is_conflict(&e) {
                CpError::Conflict
            } else {
                CpError::Client(Box::new(e))
            }
        })
    }
    async fn create_deployment(
        &self,
        site: &str,
        manifest: &Manifest,
    ) -> CpResult<CreatedDeployment> {
        let resp = self
            .create_deployment(site, manifest, &[])
            .await
            .map_err(|e| CpError::Client(Box::new(e)))?;
        Ok(CreatedDeployment {
            id: resp.id,
            missing: resp.missing,
        })
    }
    async fn upload_blob_source(&self, hash: &str, source: &BlobSource) -> CpResult<()> {
        self.upload_blob_source(hash, source)
            .await
            .map_err(|e| CpError::Client(Box::new(e)))
    }
    async fn put_site_config(&self, site: &str, config: &SiteConfig) -> CpResult<()> {
        self.put_site_config(site, config)
            .await
            .map_err(|e| CpError::Client(Box::new(e)))
    }
    async fn activate(&self, site: &str, id: &str) -> CpResult<()> {
        self.activate(site, id)
            .await
            .map_err(|e| CpError::Client(Box::new(e)))
    }
    async fn put_file_blob(&self, path: &Path) -> CpResult<String> {
        self.put_file_blob(path)
            .await
            .map_err(|e| CpError::Client(Box::new(e)))
    }
    async fn deploy_function(&self, name: &str, body: &serde_json::Value) -> CpResult<()> {
        self.deploy_function(name, body)
            .await
            .map_err(|e| CpError::Client(Box::new(e)))
    }
    async fn compose_subgraphs(&self) -> CpResult<()> {
        self.compose_subgraphs()
            .await
            .map_err(|e| CpError::Client(Box::new(e)))
    }
    async fn put_compute(
        &self,
        name: &str,
        body: &serde_json::Value,
    ) -> CpResult<serde_json::Value> {
        self.put_compute(name, body)
            .await
            .map_err(|e| CpError::Client(Box::new(e)))
    }
    async fn put_project_tenancy(
        &self,
        schema: &boatramp_core::tenancy::TenancySchema,
    ) -> CpResult<()> {
        self.put_project_tenancy(schema)
            .await
            .map_err(|e| CpError::Client(Box::new(e)))
    }
    async fn register_graphql_safelist(&self, query: &str, site: &str) -> CpResult<()> {
        self.register_graphql_safelist(query, Some(site))
            .await
            .map_err(|e| CpError::Client(Box::new(e)))
    }
    async fn declare_database(
        &self,
        name: &str,
        db: &boatramp_core::compute::ApplyDatabase,
    ) -> CpResult<()> {
        self.declare_database(name, db)
            .await
            .map_err(|e| CpError::Client(Box::new(e)))
    }
}

/// The real [`SiteBuilder`] seam: the CLI runs the external build command (`sh -c …`)
/// and does the content-addressed directory walk ([`crate::sync::build_manifest`]) that
/// the reconcile core delegates. Build/hash failures are boxed into the transparent
/// [`ReconcileError`] variants, so their `Display` (the original `build::Error` /
/// `sync::Error`) is unchanged. Holds the resolved project config so the `--build`
/// default command is reachable.
struct CliSiteBuilder<'a> {
    config: &'a ProjectConfig,
}

impl SiteBuilder for CliSiteBuilder<'_> {
    async fn build_site(
        &self,
        site: &ApplySite,
        build_flag: bool,
    ) -> std::result::Result<(), ReconcileError> {
        // Build first when the site declares a build (or `--build` was passed).
        if let Some(build) = &site.build {
            crate::build::run_command(&build.command)
                .await
                .map_err(|e| ReconcileError::Build(Box::new(e)))?;
        } else if build_flag {
            let command = crate::build::resolve_command(None, self.config)
                .map_err(|e| ReconcileError::Build(Box::new(e)))?;
            crate::build::run_command(&command)
                .await
                .map_err(|e| ReconcileError::Build(Box::new(e)))?;
        }
        Ok(())
    }

    async fn hash_site(
        &self,
        dir: &Path,
    ) -> std::result::Result<(Manifest, HashMap<String, BlobSource>), ReconcileError> {
        if !dir.is_dir() {
            return Err(ReconcileError::NotADirectory(dir.display().to_string()));
        }
        // Content-addressed manifest of the tree (identity + precompressed variants).
        crate::sync::build_manifest(dir)
            .await
            .map_err(|e| ReconcileError::Hash(Box::new(e)))
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
    /// Declared **managed databases** (#501 Stage B) — the sole authoring surface for a
    /// project-scoped managed DB (there is deliberately no imperative `db create`). Each
    /// [`ApplyDatabase`] is a TYPED, SAFE projection of the internal
    /// `ExternalDatabaseConfig` (no secret / URL / host-fs / image field — that exclusion
    /// IS the security contract). Reconciled **before** sites/functions/compute (like
    /// `tenancy`), so a handler shipped in the same apply binds an already-provisioned DB.
    /// **ADDITIVE within schema v2** — an absent `databases:` still parses (no version
    /// bump, no migration arm). `PUT`-only (create-or-replace + eager provision);
    /// removing an entry NEVER deprovisions (data-loss guard — teardown is an explicit
    /// imperative verb).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub databases: Vec<boatramp_core::compute::ApplyDatabase>,
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
        Self::parse_with_format(text, crate::config::ConfigFormat::Ron)
    }

    /// Parse a manifest document in `fmt` (RON or JSON) through the version-aware
    /// pipeline.
    ///
    /// **RON** follows the historical **loose-parse → migrate → typed** path unchanged:
    /// absent/current ⇒ strict parse; older `version:` ⇒ the migration chain;
    /// too-new ⇒ [`Error::VersionTooNew`].
    ///
    /// **JSON is current-schema only** (v0.6.5): JSON config input was never accepted
    /// before, so there are no legacy JSON manifests and thus no JSON migration chain.
    /// - `version:` absent or `== CURRENT_MANIFEST_VERSION` ⇒ strict JSON parse;
    /// - `version: N` (`N < current`) ⇒ [`Error::JsonLegacyVersion`] (a clear
    ///   regenerate-or-migrate-the-RON-source error — never silently mis-parsed/migrated);
    /// - `version: N` (`N > current`) ⇒ [`Error::VersionTooNew`] (same as RON).
    pub fn parse_with_format(text: &str, fmt: crate::config::ConfigFormat) -> Result<Self> {
        let declared = crate::apply_migrate::peek_version(text, fmt)?;
        let manifest = match declared {
            None => Self::parse_strict(text, fmt)?,
            Some(v) if v == CURRENT_MANIFEST_VERSION => {
                // An explicit current-version declaration: parse strictly, same as
                // the version-less path. The upgraded output drops `version:`.
                Self::parse_strict(text, fmt)?
            }
            Some(v) if v > CURRENT_MANIFEST_VERSION => {
                return Err(Error::VersionTooNew {
                    declared: v,
                    current: CURRENT_MANIFEST_VERSION,
                });
            }
            // An OLD version. For RON, run the registered migration chain. For JSON,
            // there is deliberately no chain — refuse with the clear current-schema-only
            // error so an old-version JSON is never wrongly parsed or migrated.
            Some(v) => match fmt {
                crate::config::ConfigFormat::Ron => {
                    crate::apply_migrate::migrate_to_current(text, v)?
                }
                crate::config::ConfigFormat::Json => {
                    return Err(Error::JsonLegacyVersion { declared: v });
                }
            },
        };
        manifest.compile_check_sites()?;
        manifest.check_tenancy_sources()?;
        manifest.check_token_claims()?;
        Ok(manifest)
    }

    /// Parse strictly against the current typed schema in `fmt`, wrapping a RON parse
    /// failure in the v0.6.0 upgrade error (which names the migration path), and a JSON
    /// parse failure in the same [`Error::StrictParse`]-class wrapping so the upgrade UX
    /// still reads well. Used for the version-less / current-version path AND (RON) as the
    /// final step after a migration.
    fn parse_strict(text: &str, fmt: crate::config::ConfigFormat) -> Result<Self> {
        match fmt {
            crate::config::ConfigFormat::Ron => crate::config::ron_options()
                .from_str(text)
                .map_err(|source| Error::StrictParse { source }),
            crate::config::ConfigFormat::Json => {
                serde_json::from_str(text).map_err(|source| Error::JsonStrictParse { source })
            }
        }
    }

    /// Validate every `token_claims` (a function's, and a site's GDC `claims_from_token`) at apply:
    /// the single-issuer and multi-issuer (`issuer_trust`/`jwks`) forms are mutually exclusive, and
    /// the multi-issuer form needs a non-empty, well-formed policy + exactly one `jwks` rule. A loud
    /// error here, not a silent per-request deny at serve time.
    fn check_token_claims(&self) -> Result<()> {
        for f in &self.functions {
            if let Some(tc) = &f.token_claims {
                tc.validate().map_err(|source| Error::TokenClaims {
                    scope: format!("function {}", f.name),
                    source,
                })?;
            }
        }
        for site in &self.sites {
            if let Some(tc) = site
                .config
                .as_ref()
                .and_then(|c| c.handlers.as_ref())
                .and_then(|h| h.graphql.as_ref())
                .and_then(|g| g.data.as_ref())
                .and_then(|d| d.claims_from_token.as_ref())
            {
                tc.validate().map_err(|source| Error::TokenClaims {
                    scope: format!("site {}", site.name),
                    source,
                })?;
            }
        }
        Ok(())
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

    /// Validate every function's `token`-source claim transform at apply — compile the
    /// `extract` pattern (exactly one always-participating, non-nullable named capture),
    /// screen the `namespace`, and enforce the cross-source namespace rule — so a
    /// misconfiguration is a loud error here, not a silent per-request deny at serve time.
    /// (The security invariants are enforced again at resolution; this is the fail-fast UX.)
    fn check_tenancy_sources(&self) -> Result<()> {
        for f in &self.functions {
            if let Some(boatramp_core::tenancy::Tenancy::Scoped { sources, .. }) = &f.tenancy {
                boatramp_core::claim_extract::validate_sources(sources).map_err(|source| {
                    Error::TenancySources {
                        function: f.name.clone(),
                        source,
                    }
                })?;
                // PLAN-system-principal S0 mix rule (defense-in-depth; a runtime backstop in
                // `resolve_from_sources` is primary): a `system_when` token source confers a typed
                // CLASS, not a tenant key, so it must be the SOLE source — mixing it with any other
                // tenant-producing source blurs the class boundary. Fail fast at apply.
                if f.token_claims
                    .as_ref()
                    .is_some_and(|tc| tc.system_when.is_some())
                    && !matches!(
                        sources.as_slice(),
                        [boatramp_core::tenancy::TenantSource::Token { .. }]
                    )
                {
                    return Err(Error::TokenClaims {
                        scope: format!("function {}", f.name),
                        source: boatramp_core::ConfigError::parse(
                            "system_when is set, so the function's `tenancy.sources` must be exactly \
                             a single `token` source (a system principal has no tenant, so it can't \
                             be mixed with a domain/signed_context/second source)",
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Load a manifest from `path`, decoding as RON or JSON per
    /// [`resolve_format`](crate::config::resolve_format) (`override_` wins; else `.json`
    /// ⇒ JSON, everything else ⇒ RON). Unlike `project.cfg`, a **missing** file is an
    /// error — there is nothing to apply.
    pub fn load(path: &Path, override_: Option<crate::config::ConfigFormat>) -> Result<Self> {
        let fmt = crate::config::resolve_format(path, override_);
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse_with_format(&text, fmt),
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
    /// Path to the project manifest (RON or JSON — auto-detected by extension).
    #[arg(short = 'f', long, default_value = "apply.cfg")]
    file: PathBuf,

    /// Manifest file format: RON or JSON, auto-detected by extension (`.json` ⇒
    /// JSON, everything else ⇒ RON). Set explicitly for Nickel/JSON piped to a
    /// non-`.json` path (`nickel export | boatramp apply -f - --format json` is the
    /// intended interop path).
    #[arg(long, value_enum)]
    format: Option<crate::config::ConfigFormat>,

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
/// v0.7.0 client-side preflight: every resource name a manifest declares (the target
/// project, plus each site / function / compute / database) must be a valid slug. The
/// first non-conforming name is an [`Error::InvalidName`] (which names `project doctor`
/// + the slug rule). Read-only; runs before any network call.
fn check_manifest_names(project: &str, manifest: &ApplyManifest) -> Result<()> {
    use boatramp_core::project::validate_resource_name;
    let check = |kind: &'static str, name: &str| -> Result<()> {
        validate_resource_name(kind, name).map_err(|err| Error::InvalidName {
            kind,
            name: name.to_string(),
            reason: err.reason,
        })
    };
    check("project", project)?;
    for s in &manifest.sites {
        check("site", &s.name)?;
    }
    for f in &manifest.functions {
        check("function", &f.name)?;
    }
    for c in &manifest.compute {
        check("compute", &c.name)?;
    }
    for d in &manifest.databases {
        check("database", &d.name)?;
    }
    Ok(())
}

/// The result of `boatramp apply`: a completed reconcile, or (under `--dry-run`) the
/// plan that *would* run. Per-resource progress during a real apply (project created,
/// deployed, activated, …) is not here — it rides the `tracing` sink. Rendered by
/// [`crate::output`].
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum ApplyOutput {
    /// `--dry-run`: the reconcile plan (nothing was mutated).
    Plan {
        /// The manifest file applied.
        file: String,
        /// The target project.
        project: String,
        /// Declared site / function / compute / database counts (the header summary).
        sites: usize,
        functions: usize,
        compute: usize,
        databases: usize,
        /// The structured plan: the resources that would be reconciled.
        plan: ApplyPlan,
    },
    /// A completed apply.
    Applied {
        /// The manifest file applied.
        file: String,
        /// The target project.
        project: String,
        /// Declared site / function / compute / database counts (the header summary).
        sites: usize,
        functions: usize,
        compute: usize,
        databases: usize,
    },
}

/// The structured `--dry-run` plan — each field is a resource that *would* be
/// reconciled, carrying the same facts the human plan lines show.
#[derive(Debug, Default, serde::Serialize)]
pub struct ApplyPlan {
    /// The non-`default` project that would be ensured to exist.
    #[serde(skip_serializing_if = "Option::is_none")]
    ensure_project: Option<String>,
    /// The tenancy schema's table count, when one would be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    tenancy_tables: Option<usize>,
    /// Managed databases that would be declared + provisioned.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    databases: Vec<PlanDatabase>,
    /// Sites that would be deployed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sites: Vec<PlanSite>,
    /// Top-level functions that would be deployed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    functions: Vec<PlanFunction>,
    /// Compute workloads that would be applied.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    compute: Vec<PlanCompute>,
}

impl crate::output::Rendered for ApplyOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Plan {
                file,
                project,
                sites,
                functions,
                compute,
                databases,
                plan,
            } => {
                writeln!(
                    w,
                    "applying {file} to project `{project}`: {sites} site(s), {functions} \
                     function(s), {compute} compute workload(s), {databases} database(s)  (dry-run)"
                )?;
                plan.render(w)?;
                writeln!(w, "apply complete")
            }
            Self::Applied {
                file,
                project,
                sites,
                functions,
                compute,
                databases,
            } => {
                writeln!(
                    w,
                    "applying {file} to project `{project}`: {sites} site(s), {functions} \
                     function(s), {compute} compute workload(s), {databases} database(s)"
                )?;
                writeln!(w, "apply complete")
            }
        }
    }
}

impl ApplyPlan {
    /// Render the plan's human lines (byte-for-byte the former `--dry-run` stdout, minus
    /// the header + the ceiling-exception warnings, which now ride `tracing`).
    fn render(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
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

pub async fn run(args: ApplyArgs, config: &ProjectConfig) -> Result<ApplyOutput> {
    let manifest = ApplyManifest::load(&args.file, args.format)?;

    // Resolve the target project: an explicit `project:` in the manifest wins over
    // the config-resolved value (`[publish].project` / `--project` / default).
    let project = manifest
        .project
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| client::resolve_project(config));

    // v0.7.0: refuse a config carrying a non-conforming resource name up front (before
    // any reconcile), pointing at `project doctor`. Defense-in-depth over the server's
    // per-resource 422; catches the whole manifest at once. `default` is always valid.
    check_manifest_names(&project, &manifest)?;

    let (server, http) = client::connect(args.server.clone(), config)?;
    let cp = client::ControlPlane::new(server, http, project.clone());
    // The local-infra seam (node-library N3): the CLI runs the real build command + the
    // content-addressed directory walk the reconcile core delegates via `SiteBuilder`.
    let builder = CliSiteBuilder { config };

    // The header summary (declared counts) is the first line of the typed result's
    // human rendering (for both modes); the per-resource progress below rides `tracing`.
    let file = args.file.display().to_string();
    let sites = manifest.sites.len();
    let functions = manifest.functions.len();
    let compute = manifest.compute.len();
    let databases = manifest.databases.len();

    // Assemble the dry-run plan as the helpers run; in a real apply the helpers reconcile
    // (emitting progress via `tracing`) and contribute nothing to the plan.
    // Ensure the project exists (best-effort; `default` always does).
    let mut plan = ApplyPlan {
        ensure_project: reconcile::ensure_project(&cp, &project, args.dry_run).await?,
        ..Default::default()
    };

    // Reconcile the tenancy schema *before* any site/function, so a handler shipped in
    // this same apply already runs under the declared isolation boundary.
    if let Some(schema) = &manifest.tenancy {
        plan.tenancy_tables = reconcile::reconcile_tenancy(&cp, schema, args.dry_run).await?;
    }

    // Reconcile declared managed databases *before* sites/functions/compute (#501 Stage B),
    // so a handler shipped in the same apply binds an already-provisioned DB. Each is
    // `PUT`-only (create-or-replace + eager provision); removing an entry never
    // deprovisions (the server keeps the DB/volume/credential).
    plan.databases = reconcile::apply_databases(&cp, &manifest.databases, args.dry_run).await?;

    // `safelisted_ops_path` is resolved relative to the manifest's own directory
    // (client-side); the manifest file itself lives at `args.file`.
    let manifest_dir = args
        .file
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    for site in &manifest.sites {
        if let Some(planned) =
            reconcile::apply_site(&cp, &builder, site, &manifest_dir, args.build, args.dry_run)
                .await?
        {
            plan.sites.push(planned);
        }
    }
    for function in &manifest.functions {
        if let Some(planned) = reconcile::apply_function(&cp, function, args.dry_run).await? {
            plan.functions.push(planned);
        }
    }
    // Bug #499: each function deploy staged (not composed) its subgraph SDL via `?compose=defer`,
    // keeping the slow introspect/compose off the per-deploy request critical path. Promote the
    // whole staged set in ONE composition here (O(N) instead of O(N²) recomposes). A no-op when
    // no function staged a subgraph. Skipped on dry-run (no deploys happened).
    reconcile::apply_deferred_compose(&cp, !manifest.functions.is_empty(), args.dry_run).await?;
    for workload in &manifest.compute {
        if let Some(planned) = reconcile::apply_compute(&cp, workload, args.dry_run).await? {
            plan.compute.push(planned);
        }
    }

    if args.dry_run {
        Ok(ApplyOutput::Plan {
            file,
            project,
            sites,
            functions,
            compute,
            databases,
            plan,
        })
    } else {
        Ok(ApplyOutput::Applied {
            file,
            project,
            sites,
            functions,
            compute,
            databases,
        })
    }
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
                        claim: "tid".into(),
                        extract: None,
                        namespace: None,
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

    /// PLAN-system-principal S0 mix rule (apply-time, defense-in-depth): a function whose
    /// `token_claims.system_when` is set must declare EXACTLY a single `token` source. A single token
    /// source passes; mixing in any other source is a loud apply error.
    #[test]
    fn system_when_requires_a_single_token_source_at_apply() {
        let ron = |sources: &str| {
            format!(
                r#"(
                    project: "acme",
                    functions: [(
                        name: "console",
                        component: "console.wasm",
                        imports: ["sql"],
                        tenancy: (mode: "scoped", column: "tenant_id",
                                  sources: {sources}, read: "own", write: "own"),
                        token_claims: (issuer: "https://admin.example",
                                       jwks_url: "https://admin.example/jwks.json",
                                       system_when: (issuer: "https://admin.example",
                                                     equals: "super_admin")),
                    )],
                )"#
            )
        };
        // A single token source is accepted (parse runs `check_tenancy_sources` internally).
        ApplyManifest::parse(&ron(r#"[(kind: "token", claim: "tid")]"#))
            .expect("a single token source with system_when is valid");
        // Mixing in a domain source is refused at parse (validation runs there).
        let err =
            ApplyManifest::parse(&ron(r#"[(kind: "token", claim: "tid"), (kind: "domain")]"#))
                .expect_err("system_when mixed with a domain source must be refused");
        assert!(
            matches!(err, Error::TokenClaims { .. }),
            "the mix is reported as a token_claims error, got {err:?}"
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
        assert!(matches!(
            ApplyManifest::load(&path, None),
            Err(Error::Missing(_))
        ));
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
    fn compute_spec_backend_selection_parses_from_ron_manifest() {
        // v0.67.0: an apply.cfg manifest can pin the tenant backend selection directly on the
        // typed spec (`prefer_backend` soft / `require_backend` hard) — the manifest path to
        // `compute set --prefer-backend`/`--require-backend`. It round-trips to the exact
        // PutComputeRequest the server stores.
        let manifest = ApplyManifest::parse(
            r#"(
                compute: [
                    (
                        name: "db",
                        spec: (
                            root: image("pg:16"),
                            vcpus: 1, mem_mib: 512, port: 5432,
                            require_backend: "firecracker",
                        ),
                    ),
                    (
                        name: "web",
                        spec: (
                            root: image("nginx:1"),
                            vcpus: 1, mem_mib: 256, port: 80,
                            prefer_backend: "docker",
                        ),
                    ),
                ],
            )"#,
        )
        .expect("backend selection on the typed spec parses");
        assert_eq!(
            manifest.compute[0].spec.require_backend.as_deref(),
            Some("firecracker")
        );
        assert_eq!(manifest.compute[0].spec.prefer_backend, None);
        assert_eq!(
            manifest.compute[1].spec.prefer_backend.as_deref(),
            Some("docker")
        );
        // Round-trips to the server's PutComputeRequest unchanged.
        assert_eq!(
            manifest.compute[0].to_request().spec,
            manifest.compute[0].spec
        );
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

    // -----------------------------------------------------------------------
    // Part 3 — declarative managed databases (#501 Stage B)
    // -----------------------------------------------------------------------

    /// A `databases:` block parses into the typed `ApplyDatabase` projection — the SAFE
    /// fields only. It is ADDITIVE within schema v2 (no `version:` needed).
    #[test]
    fn databases_block_parses_the_safe_typed_projection() {
        let manifest = ApplyManifest::parse(
            r#"(
                databases: [
                    ( name: "app", kind: postgres, version: 16, size: medium,
                      tenant: shared, tenant_scope: project, extensions: ["pgcrypto"],
                      rls_session: true, tenant_guc: "app.tenant_id", pool_max: 8 ),
                ],
            )"#,
        )
        .expect("a databases: block parses");
        assert_eq!(manifest.databases.len(), 1);
        let db = &manifest.databases[0];
        assert_eq!(db.name, "app");
        assert_eq!(db.kind, boatramp_core::compute::ApplyDatabaseKind::Postgres);
        assert_eq!(db.size, boatramp_core::compute::ApplyDatabaseSize::Medium);
        assert_eq!(
            db.tenant,
            boatramp_core::compute::ApplyDatabaseTenant::Shared
        );
        assert_eq!(db.extensions, ["pgcrypto"]);
        assert!(db.rls_session);
        assert_eq!(db.tenant_guc.as_deref(), Some("app.tenant_id"));
    }

    /// An absent `databases:` still parses (additive — no version bump / migration).
    #[test]
    fn absent_databases_block_still_parses() {
        let manifest = ApplyManifest::parse(r#"( sites: [] )"#).unwrap();
        assert!(manifest.databases.is_empty());
    }

    /// The SECURITY CONTRACT at the manifest surface: `ApplyDatabase` `deny_unknown_fields`
    /// REFUSES any of the excluded credential/RCE/SSRF/host-fs keys — a manifest cannot
    /// smuggle `password_env`/`url_env`/`image`/`path`/`compute` past the parser.
    #[test]
    fn databases_block_refuses_the_excluded_credential_fields() {
        for excluded in [
            r#"( name: "x", kind: postgres, password_env: "PW" )"#,
            r#"( name: "x", kind: postgres, url_env: "URL" )"#,
            r#"( name: "x", kind: postgres, read_url_env: "URL" )"#,
            r#"( name: "x", kind: postgres, migration_url_env: "URL" )"#,
            r#"( name: "x", kind: postgres, image: "evil/oci:latest" )"#,
            r#"( name: "x", kind: postgres, path: "/etc/passwd" )"#,
            r#"( name: "x", kind: postgres, compute: "other-tenants-server" )"#,
        ] {
            let text = format!("( databases: [ {excluded} ] )");
            assert!(
                ApplyManifest::parse(&text).is_err(),
                "a manifest smuggling an excluded field must fail to parse: {excluded}"
            );
        }
    }

    // =======================================================================
    // JSON config input gate (v0.6.5) — apply-manifest half.
    //
    // The ROBUST-successor gate (continuing the v0.6.4 blob-purge style): a
    // `#[test]` battery whose sole CI contract is the ordinary `cargo test` exit
    // code — NO grepped uppercase marker, NO bash env-var mutation loop. Every test
    // here is prefixed `config_json_gate_` so the CI lane can filter with
    // `cargo test … config_json`. The `boatramp-node` half (detection table,
    // serve/project equivalence, no-bypass db-name, deny_unknown_fields) lives in
    // `boatramp_node::config`'s test module under the same prefix.
    // =======================================================================

    /// Equivalence: the SAME manifest authored in RON and in equivalent JSON
    /// deserializes to the SAME typed value — including the externally-tagged
    /// enum-variant field `RootSource::Image` (RON `image("…")` ≡ JSON
    /// `{"image":"…"}`), proving variant-name fidelity survives the JSON decoder.
    #[test]
    fn config_json_gate_manifest_ron_and_json_are_equivalent() {
        let ron = r#"(
            project: "team-x",
            compute: [
                (
                    name: "db",
                    spec: (
                        root: image("pgvector/pgvector:pg16"),
                        vcpus: 2, mem_mib: 1024, port: 5432,
                        restart: always,
                    ),
                    replicas: 1,
                ),
            ],
        )"#;
        let json = r#"{
            "project": "team-x",
            "compute": [
                {
                    "name": "db",
                    "spec": {
                        "root": { "image": "pgvector/pgvector:pg16" },
                        "vcpus": 2, "mem_mib": 1024, "port": 5432,
                        "restart": "always"
                    },
                    "replicas": 1
                }
            ]
        }"#;
        let from_ron =
            ApplyManifest::parse_with_format(ron, crate::config::ConfigFormat::Ron).unwrap();
        let from_json =
            ApplyManifest::parse_with_format(json, crate::config::ConfigFormat::Json).unwrap();
        // The typed values are identical (the enum variant + every scalar).
        assert_eq!(from_json.project.as_deref(), Some("team-x"));
        assert_eq!(
            from_json.compute[0].spec.root,
            boatramp_core::compute::RootSource::Image("pgvector/pgvector:pg16".into())
        );
        assert!(matches!(
            from_json.compute[0].spec.restart,
            boatramp_core::compute::RestartPolicy::Always
        ));
        // Prove the two decoders agree field-for-field: they PUT the identical request.
        assert_eq!(
            from_ron.compute[0].to_request().spec,
            from_json.compute[0].to_request().spec
        );
        assert_eq!(from_ron.project, from_json.project);
    }

    /// `deny_unknown_fields` parity: a JSON manifest with an extra/typo'd field is a
    /// hard parse error, not a silent drop — the same strictness RON gets.
    #[test]
    fn config_json_gate_manifest_json_denies_unknown_fields() {
        let json = r#"{ "project": "x", "bogus_field": true }"#;
        let err = ApplyManifest::parse_with_format(json, crate::config::ConfigFormat::Json)
            .expect_err("an unknown JSON field must be rejected (deny_unknown_fields)");
        assert!(
            matches!(err, Error::JsonStrictParse { .. }),
            "unknown-field JSON is a strict-parse failure, got {err:?}"
        );
    }

    /// No-bypass: a JSON manifest with a bad route still fails `compile_check` — JSON
    /// is only an alternative decoder into the SAME typed struct + the SAME downstream
    /// checks. A `**`-in-the-middle globstar is rejected by `DeployConfig::compile_check`.
    #[test]
    fn config_json_gate_manifest_json_bad_route_fails_compile_check() {
        let json = r#"{
            "sites": [
                {
                    "name": "web",
                    "path": ".",
                    "routing": { "redirects": [ { "from": "/a/**/b/**", "to": "/x" } ] }
                }
            ]
        }"#;
        let err = ApplyManifest::parse_with_format(json, crate::config::ConfigFormat::Json)
            .expect_err("a bad route in a JSON manifest must fail the compile-check");
        assert!(
            matches!(err, Error::Routing { .. }),
            "bad-route JSON fails the routing compile-check, got {err:?}"
        );
    }

    /// Current-schema-only (JSON): an OLD `version: N` (`N < current`) yields the clear
    /// [`Error::JsonLegacyVersion`] — never a silent wrong-schema parse or a JSON migration.
    #[test]
    fn config_json_gate_json_old_version_is_current_schema_only() {
        let json = r#"{ "version": 1, "project": "x" }"#;
        let err = ApplyManifest::parse_with_format(json, crate::config::ConfigFormat::Json)
            .expect_err("an old-version JSON manifest is current-schema only");
        assert!(
            matches!(err, Error::JsonLegacyVersion { declared: 1 }),
            "old-version JSON is refused with the clear current-schema-only error, got {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("current-schema only") && msg.contains("boatramp config migrate"),
            "the error names the cure: {msg}"
        );
    }

    /// Current-schema-only (JSON): a `version: > current` yields the SAME
    /// [`Error::VersionTooNew`] as RON (a newer schema this build can't understand).
    #[test]
    fn config_json_gate_json_too_new_version_is_version_too_new() {
        let json = format!(
            r#"{{ "version": {}, "project": "x" }}"#,
            CURRENT_MANIFEST_VERSION + 1
        );
        let err = ApplyManifest::parse_with_format(&json, crate::config::ConfigFormat::Json)
            .expect_err("a future-version JSON manifest is refused");
        assert!(
            matches!(err, Error::VersionTooNew { .. }),
            "too-new JSON is VersionTooNew, got {err:?}"
        );
    }

    /// Current-schema-only (JSON): an absent OR current `version:` parses strictly.
    #[test]
    fn config_json_gate_json_absent_and_current_version_parse_ok() {
        // Absent version.
        ApplyManifest::parse_with_format(
            r#"{ "project": "x" }"#,
            crate::config::ConfigFormat::Json,
        )
        .expect("a version-less JSON manifest parses (current schema)");
        // Explicit current version.
        let cur = format!(r#"{{ "version": {CURRENT_MANIFEST_VERSION}, "project": "x" }}"#);
        ApplyManifest::parse_with_format(&cur, crate::config::ConfigFormat::Json)
            .expect("a current-version JSON manifest parses");
    }

    /// Anti-hollow (typed, in-process): a document that is valid JSON but NOT valid
    /// RON MUST parse under `Json` and FAIL under `Ron`. If `parse_with_format` ever
    /// ignored `fmt` and always decoded RON, the JSON leg here would fail — so this
    /// proves the format selection is load-bearing, with no env var and no marker.
    #[test]
    fn config_json_gate_format_selection_is_load_bearing() {
        // A bare JSON object `{ … }` is valid JSON for the `ApplyManifest` struct, but
        // is NOT valid RON for it (RON structs use `( … )`, not a brace map).
        let doc = r#"{ "project": "only-valid-as-json" }"#;
        let as_json =
            ApplyManifest::parse_with_format(doc, crate::config::ConfigFormat::Json).unwrap();
        assert_eq!(as_json.project.as_deref(), Some("only-valid-as-json"));
        assert!(
            ApplyManifest::parse_with_format(doc, crate::config::ConfigFormat::Ron).is_err(),
            "the same document must FAIL under Ron — else the fmt selection is hollow"
        );
    }
}
