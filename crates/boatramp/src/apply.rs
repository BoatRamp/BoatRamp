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
    /// A `--var` argument was not `KEY=VALUE`.
    #[error("--var must be KEY=VALUE, got {0:?}")]
    BadVar(String),
    /// The manifest references `${KEY}` but no `--var KEY=…` was supplied.
    #[error("manifest references ${{{0}}} but no --var {0}=… was supplied")]
    UndefinedVar(String),
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
type Result<T> = std::result::Result<T, Error>;

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
    /// Create/replace a top-level function record.
    async fn deploy_function(
        &self,
        name: &str,
        body: &serde_json::Value,
    ) -> CpResult<serde_json::Value>;
    /// Create/replace a compute workload spec.
    async fn put_compute(
        &self,
        name: &str,
        body: &serde_json::Value,
    ) -> CpResult<serde_json::Value>;
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
    async fn deploy_function(
        &self,
        name: &str,
        body: &serde_json::Value,
    ) -> CpResult<serde_json::Value> {
        self.deploy_function(name, body)
            .await
            .map_err(CpError::Client)
    }
    async fn put_compute(
        &self,
        name: &str,
        body: &serde_json::Value,
    ) -> CpResult<serde_json::Value> {
        self.put_compute(name, body).await.map_err(CpError::Client)
    }
}

/// A whole-project desired state: the sites, functions, and compute workloads to
/// reconcile under one project.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApplyManifest {
    /// Target project. `None` ⇒ resolved from config / `--project` /
    /// `BOATRAMP_PROJECT` / the `default` project.
    pub project: Option<String>,
    /// Sites to publish (each an atomic content-addressed deployment).
    pub sites: Vec<ApplySite>,
    /// Top-level functions to deploy (create-or-replace).
    pub functions: Vec<ApplyFunction>,
    /// Compute workloads to create-or-replace.
    pub compute: Vec<ApplyCompute>,
}

/// One site in the manifest: a slug plus its content dir and folded-in config.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplySite {
    /// Site slug within the project.
    pub name: String,
    /// Content directory to publish. Default: `build.output`, then `.`.
    #[serde(default)]
    pub path: Option<String>,
    /// Optional per-site build step, run before publishing.
    #[serde(default)]
    pub build: Option<BuildConfig>,
    /// Deploy-scoped routing, folded into the deployment manifest (atomic with the
    /// content, rolls back with it).
    #[serde(default)]
    pub routing: Option<DeployConfig>,
    /// Site-scoped mutable config (domains/access/…), PUT after the deploy activates.
    #[serde(default)]
    pub config: Option<SiteConfig>,
}

/// One top-level function in the manifest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyFunction {
    /// Function name.
    pub name: String,
    /// Path to the component `.wasm` (uploaded as a content-addressed blob).
    pub component: String,
    /// Execution substrate: `wasm` (default), `microvm`, or `container`.
    #[serde(default)]
    pub runtime: Option<String>,
    /// Enable a signed webhook: the host env var holding the HMAC-SHA256 secret
    /// (never the secret itself).
    #[serde(default)]
    pub webhook_secret_env: Option<String>,
    /// Make the webhook an ingress: a verified request publishes its body onto the
    /// project bus at this topic (`bus:<topic>` for consumers) and returns 202, with
    /// no component run. Requires `webhook_secret_env`.
    #[serde(default)]
    pub webhook_publish: Option<String>,
    /// Requested host capabilities (`sql`, `wasi:keyvalue`, `invoke`, …), gated by
    /// the function import policy — parity with a site handler's `imports`.
    #[serde(default)]
    pub imports: Vec<String>,
    /// Static, non-secret environment variables passed to the function.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Secret env-var references (`ENV_VAR` → `HOST_ENV`), resolved server-side
    /// from the serve env at instantiation — the value is a reference, never
    /// stored in the manifest or the control-plane store (mirrors a site
    /// handler's `[handlers].secrets`), so the manifest stays committable.
    #[serde(default)]
    pub secrets: std::collections::BTreeMap<String, String>,
    /// Function-to-function invoke allowlist (deny-by-default; `*` wildcards). Only
    /// consulted when `imports` contains `invoke`.
    #[serde(default)]
    pub invoke_targets: Vec<String>,
    /// Optional resource limits (memory / timeout / fuel).
    #[serde(default)]
    pub limits: Option<HandlerLimits>,
}

/// One compute workload in the manifest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyCompute {
    /// Workload name.
    pub name: String,
    /// The `PutComputeRequest`-shaped body, PUT straight to the server (which
    /// validates it).
    pub spec: serde_json::Value,
}

impl ApplyManifest {
    /// Parse a manifest document (RON). Each site's `routing` is compile-checked
    /// (route patterns, cron schedules) so a bad manifest fails fast.
    pub fn parse(text: &str) -> Result<Self> {
        let manifest: Self = crate::config::ron_options().from_str(text)?;
        for site in &manifest.sites {
            if let Some(routing) = &site.routing {
                routing.compile_check().map_err(|source| Error::Routing {
                    site: site.name.clone(),
                    source,
                })?;
            }
        }
        Ok(manifest)
    }

    /// Parse a manifest after interpolating `${KEY}` placeholders from `vars`
    /// (see [`interpolate`]). Scalar text substitution on the raw RON, before the
    /// parse — the manifest can commit `${…}` placeholders and bind them at apply
    /// time with `--var`.
    pub fn parse_with_vars(
        text: &str,
        vars: &std::collections::BTreeMap<String, String>,
    ) -> Result<Self> {
        Self::parse(&interpolate(text, vars)?)
    }

    /// Load a manifest from `path` (RON), interpolating `${KEY}` placeholders from
    /// `vars` first. Unlike `project.cfg`, a **missing** file is an error — there
    /// is nothing to apply.
    pub fn load(path: &Path, vars: &std::collections::BTreeMap<String, String>) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse_with_vars(&text, vars),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                Err(Error::Missing(path.display().to_string()))
            }
            Err(err) => Err(err.into()),
        }
    }
}

/// Substitute `${KEY}` placeholders in a raw manifest with their `--var` values,
/// **before** the RON parse — pure scalar text substitution (no includes, no
/// record-merge). A `${KEY}` with no matching `vars` entry is a hard error naming
/// the key (never a silent empty). `$${` is an escape for a literal `${` (so a
/// manifest that legitimately needs the two characters can emit them); a bare
/// `${` is otherwise reserved for interpolation.
pub fn interpolate(
    text: &str,
    vars: &std::collections::BTreeMap<String, String>,
) -> Result<String> {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // `$${` → a literal `${` (escape), consumed without interpolating.
        if bytes[i] == b'$' && bytes.get(i + 1) == Some(&b'$') && bytes.get(i + 2) == Some(&b'{') {
            out.push_str("${");
            i += 3;
            continue;
        }
        // `${KEY}` → the value of `KEY` from `vars` (error if unknown/unterminated).
        if bytes[i] == b'$' && bytes.get(i + 1) == Some(&b'{') {
            let start = i + 2;
            let end = text[start..]
                .find('}')
                .map(|rel| start + rel)
                .ok_or_else(|| Error::UndefinedVar(text[start..].to_string()))?;
            let key = &text[start..end];
            let value = vars
                .get(key)
                .ok_or_else(|| Error::UndefinedVar(key.to_string()))?;
            out.push_str(value);
            i = end + 1;
            continue;
        }
        // A non-placeholder byte: copy the whole UTF-8 char through verbatim.
        let ch = text[i..].chars().next().expect("valid utf-8 boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    Ok(out)
}

/// Parse repeatable `--var KEY=VALUE` flags into a map (mirrors compute `--env`).
fn parse_vars(pairs: &[String]) -> Result<std::collections::BTreeMap<String, String>> {
    let mut map = std::collections::BTreeMap::new();
    for pair in pairs {
        let (k, v) = pair
            .split_once('=')
            .ok_or_else(|| Error::BadVar(pair.clone()))?;
        map.insert(k.to_string(), v.to_string());
    }
    Ok(map)
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

    /// Bind a manifest variable: every `${KEY}` in the manifest is substituted
    /// with VALUE before parsing (`KEY=VALUE`, repeatable). A `${KEY}` with no
    /// `--var` is an error; write `$${` for a literal `${`.
    #[arg(long = "var", value_name = "KEY=VALUE")]
    var: Vec<String>,
}

/// Entry point for `boatramp apply`.
pub async fn run(args: ApplyArgs, config: &ProjectConfig) -> Result<()> {
    let vars = parse_vars(&args.var)?;
    let manifest = ApplyManifest::load(&args.file, &vars)?;

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

    for site in &manifest.sites {
        apply_site(&cp, site, config, args.build, args.dry_run).await?;
    }
    for function in &manifest.functions {
        apply_function(&cp, function, args.dry_run).await?;
    }
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

/// Reconcile one site: (optionally build), hash the content dir, negotiate the
/// deployment, upload the missing blobs, PUT its site config, then activate (config
/// before activate — the activation precheck gates handlers on the stored config).
async fn apply_site<C: ControlPlane>(
    cp: &C,
    site: &ApplySite,
    config: &ProjectConfig,
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

    Ok(())
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
    cp.put_compute(&compute.name, &compute.spec).await?;
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
    if b {
        "yes"
    } else {
        "no"
    }
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
        async fn deploy_function(
            &self,
            name: &str,
            _body: &serde_json::Value,
        ) -> CpResult<serde_json::Value> {
            self.rec(format!("deploy_function {name}"));
            Ok(json!({}))
        }
        async fn put_compute(
            &self,
            name: &str,
            _body: &serde_json::Value,
        ) -> CpResult<serde_json::Value> {
            self.rec(format!("put_compute {name}"));
            Ok(json!({}))
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
    async fn apply_compute_puts_the_spec() {
        let mock = MockCp::default();
        let compute = ApplyCompute {
            name: "api".into(),
            spec: json!({ "replicas": 2 }),
        };
        apply_compute(&mock, &compute, false).await.unwrap();
        assert_eq!(mock.calls(), ["put_compute api"]);
    }

    #[tokio::test]
    async fn apply_compute_dry_run_mutates_nothing() {
        let mock = MockCp::default();
        let compute = ApplyCompute {
            name: "api".into(),
            spec: json!({}),
        };
        apply_compute(&mock, &compute, true).await.unwrap();
        assert!(mock.calls().is_empty());
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
        let result = apply_site(&mock, &site, &ProjectConfig::default(), false, false).await;
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
                    ( name: "api", spec: { "replicas": 2 } ),
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
        assert_eq!(manifest.compute[0].spec["replicas"], json!(2));
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
            ApplyManifest::load(&path, &Default::default()),
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
    fn var_interpolation_substitutes_scalars() {
        let vars = std::collections::BTreeMap::from([
            ("project".to_string(), "construens".to_string()),
            ("site".to_string(), "www".to_string()),
        ]);
        let manifest = ApplyManifest::parse_with_vars(
            r#"( project: "${project}", sites: [ ( name: "${site}", path: "dist" ) ] )"#,
            &vars,
        )
        .expect("interpolated manifest parses");
        assert_eq!(manifest.project.as_deref(), Some("construens"));
        assert_eq!(manifest.sites[0].name, "www");
    }

    #[test]
    fn var_interpolation_missing_key_errors_and_names_it() {
        let err =
            ApplyManifest::parse_with_vars(r#"( project: "${project}" )"#, &Default::default())
                .expect_err("a manifest with an unbound ${var} is rejected");
        match err {
            Error::UndefinedVar(key) => assert_eq!(key, "project"),
            other => panic!("expected UndefinedVar, got {other:?}"),
        }
    }

    #[test]
    fn var_interpolation_escape_stays_literal() {
        // `$${literal}` is the escape for a literal `${literal}` — it is NOT looked
        // up in `vars` (so it does not error even though `literal` is unbound).
        let out = interpolate("a $${literal} b", &Default::default()).unwrap();
        assert_eq!(out, "a ${literal} b");

        // The escape and a real substitution coexist on one line.
        let vars = std::collections::BTreeMap::from([("x".to_string(), "1".to_string())]);
        assert_eq!(interpolate("$${keep} ${x}", &vars).unwrap(), "${keep} 1");
    }

    #[test]
    fn var_interpolation_unterminated_placeholder_errors() {
        // A `${` with no closing `}` is a hard error (naming what it saw).
        assert!(matches!(
            interpolate("${oops", &Default::default()),
            Err(Error::UndefinedVar(_))
        ));
    }

    #[test]
    fn parse_vars_rejects_non_kv() {
        assert!(matches!(
            parse_vars(&["nope".to_string()]),
            Err(Error::BadVar(_))
        ));
        let ok = parse_vars(&["k=v=extra".to_string()]).unwrap();
        // `split_once` keeps everything after the first `=` as the value.
        assert_eq!(ok.get("k").map(String::as_str), Some("v=extra"));
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
}
