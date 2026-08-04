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

use boatramp_core::config::{DeployConfig, SiteConfig};
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
    /// A site's `routing` failed its compile-check (a bad route/cron pattern).
    #[error("site {site}: routing: {source}")]
    Routing {
        site: String,
        #[source]
        source: boatramp_core::ConfigError,
    },
    /// A control-plane request failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
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
async fn ensure_project(cp: &client::ControlPlane, project: &str, dry_run: bool) -> Result<()> {
    if project == boatramp_core::project::DEFAULT_PROJECT {
        return Ok(());
    }
    if dry_run {
        println!("  project `{project}`: ensure exists");
        return Ok(());
    }
    match cp.get_project(project).await {
        Ok(_) => Ok(()),
        Err(err) if is_not_found(&err) => {
            match cp.create_project(&json!({ "name": project })).await {
                Ok(_) => {
                    println!("  created project `{project}`");
                    Ok(())
                }
                // A concurrent create is fine — the project ends up existing either way.
                Err(err) if is_conflict(&err) => Ok(()),
                Err(err) => Err(err.into()),
            }
        }
        Err(err) => Err(err.into()),
    }
}

/// Reconcile one site: (optionally build), hash the content dir, negotiate the
/// deployment, upload the missing blobs, activate, then PUT its site config.
async fn apply_site(
    cp: &client::ControlPlane,
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

    let created = cp.create_deployment(&site.name, &manifest, &[]).await?;
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

    cp.activate(&site.name, &created.id).await?;
    println!("  site `{}`: activated {}", site.name, created.id);

    // Site-scoped config (domains/access/…) is PUT after the deploy is live.
    if let Some(site_config) = &site.config {
        cp.put_site_config(&site.name, site_config).await?;
        println!("  site `{}`: config applied", site.name);
    }

    Ok(())
}

/// Reconcile one top-level function: stage its component blob, then PUT the
/// function record (`{ component, config, lifecycle }`).
async fn apply_function(
    cp: &client::ControlPlane,
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
        cfg.insert("webhook".to_string(), json!({ "secret_env": secret_env }));
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
async fn apply_compute(
    cp: &client::ControlPlane,
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
                    ( name: "resize", component: "resize.wasm", runtime: "wasm" ),
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
        assert_eq!(manifest.functions[0].name, "resize");
        assert_eq!(manifest.functions[0].component, "resize.wasm");
        assert_eq!(manifest.functions[0].runtime.as_deref(), Some("wasm"));

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
}
