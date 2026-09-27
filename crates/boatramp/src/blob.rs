//! The `blob` subcommand group: upload a file as a content-addressed blob and print
//! its hash (`blob put`), and — with the `blob-upload` feature — mint a scoped, short-lived
//! S3 upload credential for a project+site's blob container (`blob mint-upload`, S3 external
//! ingress). `blob put` is the control-plane ARTIFACT namespace; `blob mint-upload` is the
//! external-INGRESS credential minter — deliberately distinct verbs.

use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure running a `boatramp blob` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server target from flags/config failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A bad flag combination (e.g. neither/both `--key` and `--prefix`).
    #[error("{0}")]
    Usage(String),
    /// Loading/parsing a `--from`/`--to` node config file failed (`blob migrate`).
    #[error(transparent)]
    Config(#[from] boatramp_node::config::ConfigError),
    /// Building a source/destination blob backend from a config failed (`blob migrate`).
    #[error("building the {side} blob backend: {source}")]
    BackendBuild {
        /// Which side failed to build (`source` or `destination`).
        side: &'static str,
        /// The underlying node error.
        #[source]
        source: boatramp_node::Error,
    },
    /// Resolving the `--from`/`--to` node-level sealed S3 credential failed (`blob migrate`).
    #[error("resolving the {side} [serve.s3_credential]: {source}")]
    Credential {
        /// Which side's credential failed to resolve.
        side: &'static str,
        /// The underlying credential-resolution error.
        #[source]
        source: boatramp_node::s3_credential::S3CredentialError,
    },
    /// Building the `[secrets]` envelope for a `--from`/`--to` config failed (`blob migrate`).
    #[error("building the {side} [secrets] envelope: {reason}")]
    Envelope {
        /// Which side's envelope failed.
        side: &'static str,
        /// Why it failed.
        reason: String,
    },
    /// The offline copy engine reported an error (a storage failure or a failed verification).
    #[error(transparent)]
    Migrate(#[from] boatramp_node::blob_migrate::MigrateError),
    /// Serializing the `--json` migration report failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// `blob` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp blob`.
#[derive(Debug, clap::Args)]
pub struct BlobArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: BlobCommand,
}

#[derive(Debug, Subcommand)]
enum BlobCommand {
    /// Upload a file as a content-addressed blob; prints its hash (the key other
    /// commands reference, e.g. `compute set --kernel <hash>`).
    Put {
        /// File to upload.
        file: std::path::PathBuf,
    },
    /// Mint a scoped, short-lived S3 upload credential for a project+site's blob container, which an
    /// external client (a browser, a bulk agent) uses to upload directly over the S3 protocol. The
    /// wasm guest then reads the object by key via the unchanged `wasi:blobstore`. Project is
    /// host-forced from your token/`--project`; the TTL + max-bytes are clamped to the operator
    /// ceilings. Gated by an operator token holding the `BlobUpload` right.
    #[cfg(feature = "blob-upload")]
    MintUpload(MintUploadArgs),
    /// **Migrate the node blob backend**, offline: copy every object from a SOURCE backend to a
    /// DESTINATION backend so switching `--blobs` (fs→cloud, provider→provider, region→region) has
    /// no re-upload step and no serving gap. This is a NODE-LOCAL operation — it builds both
    /// backends in-process from two node config files (`boatramp.cfg` shape: their `[serve]` blob
    /// block + optional `[secrets]`), NOT a control-plane HTTP call, so it needs local access to the
    /// backends' credentials, not a `BOATRAMP_SERVER`.
    ///
    /// The copy is idempotent + resumable (a destination object already present at matching size is
    /// skipped), reads the SOURCE read-only (never deletes it), preserves keys byte-exact, and — by
    /// default — verifies every source object is present in the destination afterwards. The source
    /// stays authoritative until you flip `--blobs`/config; retire the old store separately.
    ///
    /// Unrelated to the top-level `boatramp migrate` (a one-time control-plane store re-key).
    Migrate(MigrateArgs),
}

/// Arguments for `boatramp blob migrate`.
#[derive(Debug, clap::Args)]
pub struct MigrateArgs {
    /// Path to the node config file (`boatramp.cfg` shape) whose `[serve]` blob block defines the
    /// SOURCE backend (+ optional `[secrets]` for a sealed `boatramp:`/`env:` S3 credential ref).
    #[arg(long)]
    from: std::path::PathBuf,
    /// Path to the node config file whose `[serve]` blob block defines the DESTINATION backend.
    #[arg(long)]
    to: std::path::PathBuf,
    /// Bounded copy concurrency (number of objects in flight at once).
    #[arg(long, default_value_t = 8)]
    concurrency: usize,
    /// Skip the post-copy verification pass. Verification (every source object present in the
    /// destination) is ON by default; pass `--no-verify` to turn it off.
    #[arg(long)]
    no_verify: bool,
    /// Enumerate + classify (would-copy / would-skip) and report, but copy nothing.
    #[arg(long)]
    dry_run: bool,
    /// Restrict the migration to source keys under this prefix (default: all objects).
    #[arg(long, default_value = "")]
    prefix: String,
    /// Emit the run's summary as JSON instead of a human line.
    #[arg(long)]
    json: bool,
}

/// Arguments for `boatramp blob mint-upload`.
#[cfg(feature = "blob-upload")]
#[derive(Debug, clap::Args)]
pub struct MintUploadArgs {
    /// The site the container belongs to (with the host-forced project, scopes the credential).
    #[arg(long)]
    site: String,
    /// The blob container to mint an upload credential for.
    #[arg(long, short = 'c')]
    container: String,
    /// Bind the credential to exactly ONE object key (the browser-UGC shape; create-only by default).
    #[arg(long, conflicts_with = "prefix")]
    key: Option<String>,
    /// Bind the credential to a key PREFIX (the bulk-agent shape; needs an S3 SDK).
    #[arg(long)]
    prefix: Option<String>,
    /// Permitted operations (repeatable): `put` (single-shot) and/or `multipart` (resumable). Empty ⇒
    /// write-only (single-shot).
    #[arg(long = "perms", value_delimiter = ',')]
    perms: Vec<String>,
    /// Credential lifetime in seconds (clamped to the operator ceiling).
    #[arg(long, default_value_t = 900)]
    ttl: u64,
    /// Constrain the uploaded object's Content-Type (exact, or a `type/*` family).
    #[arg(long)]
    content_type: Option<String>,
    /// Constrain the uploaded object's max size in bytes (clamped to the operator ceiling).
    #[arg(long)]
    max_bytes: Option<u64>,
    /// Require content-addressing: the object key must equal `sha256(bytes)` (idempotent, replay-inert).
    #[arg(long)]
    sha256: bool,
    /// Output form: `env` (a shell `export …` block for an S3 SDK), `aws` (an `~/.aws`-style profile),
    /// `rclone` (an rclone remote block), or `json` (the raw credential). Default ⇒ a human table plus
    /// an `env` block.
    #[arg(long, value_enum, default_value_t = Emit::Human)]
    emit: Emit,
}

/// The `--emit` output form.
#[cfg(feature = "blob-upload")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Emit {
    /// A human table + an `env` block (default).
    Human,
    /// A shell `export …` block (temp-credentials) or the presigned URL (presigned-put).
    Env,
    /// An `~/.aws/credentials`-style profile block.
    Aws,
    /// An rclone remote config block.
    Rclone,
    /// The raw JSON credential.
    Json,
}

/// Entry point for `boatramp blob`.
pub async fn run(args: BlobArgs, config: &ProjectConfig) -> Result<()> {
    // `migrate` is NODE-LOCAL: it builds both blob backends in-process from two node config files
    // and never touches a control-plane server. Handle it before resolving the server target (the
    // other verbs are control-plane clients that require a `BOATRAMP_SERVER`/`[deploy].server`).
    if let BlobCommand::Migrate(a) = args.command {
        return migrate(a).await;
    }

    let server = client::resolve_server(args.server, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );

    match args.command {
        BlobCommand::Put { file } => {
            let hash = cp.put_file_blob(&file).await?;
            println!("{hash}");
        }
        #[cfg(feature = "blob-upload")]
        BlobCommand::MintUpload(a) => mint_upload(&cp, a).await?,
        // Handled node-locally above (returned before the control-plane client was built).
        BlobCommand::Migrate(_) => unreachable!("handled before the control-plane client"),
    }
    Ok(())
}

/// Run the offline, node-local blob-backend migration (`boatramp blob migrate`). Builds the source
/// and destination backends from two node config files (each `[serve]` blob block plus an optional
/// `[secrets]`), then copies every object source→dest with the [`boatramp_node::blob_migrate`] engine.
async fn migrate(a: MigrateArgs) -> Result<()> {
    let source = build_side("source", &a.from).await?;
    let dest = build_side("destination", &a.to).await?;

    let opts = boatramp_node::blob_migrate::MigrateOptions {
        concurrency: a.concurrency,
        verify: !a.no_verify,
        dry_run: a.dry_run,
        prefix: a.prefix.clone(),
    };
    let report = boatramp_node::blob_migrate::migrate(source, dest, &opts).await?;

    if a.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "total_objects": report.total_objects,
                "copied_objects": report.copied_objects,
                "skipped_objects": report.skipped_objects,
                "copied_bytes": report.copied_bytes,
                "verified": report.verified,
                "dry_run": a.dry_run,
            }))?
        );
    } else {
        let verb = if a.dry_run { "would copy" } else { "copied" };
        println!(
            "blob migrate {}: {} {} object(s), skipped {} present, {} byte(s){}",
            if a.dry_run { "(dry-run)" } else { "complete" },
            verb,
            report.copied_objects,
            report.skipped_objects,
            report.copied_bytes,
            if report.verified {
                format!(
                    "; VERIFY OK: {} object(s) present in destination",
                    report.total_objects
                )
            } else {
                String::new()
            },
        );
    }
    Ok(())
}

/// Build one side (`source`/`destination`) of a migration from a node config file: parse the
/// `[serve]` blob block into a [`BlobArgs`](boatramp_node::blobs::BlobArgs), resolve an optional
/// node-level sealed S3 credential from `[serve.s3_credential]` (+ `[secrets]`), and construct the
/// backend via `build_blobs` with NO watcher provisioning (a migration never watches).
async fn build_side(
    side: &'static str,
    config_path: &std::path::Path,
) -> Result<std::sync::Arc<dyn boatramp_core::Storage>> {
    use std::sync::Arc;

    let config = boatramp_node::config::ServerConfig::load(config_path)?;
    let serve = config.serve.clone().unwrap_or_default();
    // The fs backend roots at `<data_dir>/blobs`, so honour the config's `[serve].data_dir`
    // (default `./data`) — the same resolution `serve` uses — so an fs source/dest points at the
    // real on-disk tree.
    let data_dir = serve
        .data_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("./data"));

    // The backend is the config's `[serve].blobs` (default `fs` when absent) — the config-level
    // analog of `serve`'s `--blobs` flag. All per-backend options come from the SAME `[serve]`
    // block, so the source/dest are described entirely by their own config file.
    let mut blob_args = boatramp_node::blobs::BlobArgs {
        blobs: serve
            .blobs
            .unwrap_or(boatramp_node::backends::BlobBackend::Fs),
        s3_bucket: serve.s3_bucket.clone(),
        s3_endpoint: serve.s3_endpoint.clone(),
        s3_region: serve.s3_region.clone(),
        s3_path_style: serve.s3_path_style,
        s3_credential: None,
        gcs_bucket: serve.gcs_bucket.clone(),
        gcs_endpoint: serve.gcs_endpoint.clone(),
        gcs_anonymous: serve.gcs_anonymous,
        azure_account: serve.azure_account.clone(),
        azure_container: serve.azure_container.clone(),
        azure_access_key: serve.azure_access_key.clone(),
        azure_emulator: serve.azure_emulator,
    };

    // Resolve the node-level sealed base S3 credential (#505), if configured — the same source the
    // serve path uses. A `boatramp:` sealed ref needs the control-plane KV, which this offline
    // command does not open; only `env:`/bare refs (posture-permitted) resolve here. The posture is
    // read from the same config file so `allow_env_secret_refs` matches how the node would run.
    if let Some(cred_cfg) = serve.s3_credential.clone() {
        let posture = config
            .security
            .clone()
            .unwrap_or_default()
            .resolve()
            .map_err(|e| Error::Envelope {
                side,
                reason: format!("resolving [security] posture: {e}"),
            })?;
        let envelope = build_secrets_envelope(side, config.secrets.as_ref(), &data_dir)?;
        let cred = boatramp_node::s3_credential::resolve_s3_credential(
            &cred_cfg,
            // No control-plane KV on the offline path; an `env:`/bare ref never touches it, and a
            // `boatramp:` ref correctly reports MissingBoatrampSecret against the empty stand-in.
            Arc::new(boatramp_core::kv::MemoryKv::new()),
            envelope,
            posture.allow_env_secret_refs,
            &boatramp_core::env::SystemEnv,
        )
        .await
        .map_err(|source| Error::Credential { side, source })?;
        blob_args.s3_credential = Some(cred);
    }

    let built = boatramp_node::blobs::build_blobs(&blob_args, &data_dir, None, None)
        .await
        .map_err(|source| Error::BackendBuild { side, source })?;
    Ok(built.storage)
}

/// Build the `[secrets]` key envelope from a config's `[secrets]` section (mirrors the serve path's
/// `serve_secrets_envelope`). `None` ⇒ no envelope (no sealed secret store). A `vault` backend is
/// resolved from the config's `token_env`.
fn build_secrets_envelope(
    side: &'static str,
    secrets: Option<&boatramp_node::config::SecretsConfig>,
    data_dir: &std::path::Path,
) -> Result<Option<std::sync::Arc<dyn boatramp_core::envelope::KeyEnvelope>>> {
    use boatramp_server::envelope::{EnvelopeSpec, build_envelope};
    let Some(cfg) = secrets else {
        return Ok(None);
    };
    let err = |reason: String| Error::Envelope { side, reason };
    let spec = match cfg.envelope.as_str() {
        "" => EnvelopeSpec::None,
        "local" => EnvelopeSpec::Local {
            kek_file: cfg
                .kek_file
                .clone()
                .unwrap_or_else(|| data_dir.join("secrets/kek")),
        },
        "vault" => {
            let v = cfg.vault.as_ref().ok_or_else(|| {
                err("secrets.envelope = \"vault\" needs a [secrets.vault] section".into())
            })?;
            let token = std::env::var(&v.token_env)
                .map_err(|_| err(format!("Vault token env `{}` is not set", v.token_env)))?;
            EnvelopeSpec::Vault {
                addr: v.addr.clone(),
                key: v.key.clone(),
                token,
            }
        }
        other => {
            return Err(err(format!(
                "unknown secrets.envelope {other:?} (want \"local\" or \"vault\")"
            )));
        }
    };
    build_envelope(spec).map_err(|e| err(e.to_string()))
}

/// Mint an upload credential and render it per `--emit`.
#[cfg(feature = "blob-upload")]
async fn mint_upload(cp: &client::ControlPlane, a: MintUploadArgs) -> Result<()> {
    if a.key.is_none() && a.prefix.is_none() {
        return Err(Error::Usage(
            "specify exactly one of --key or --prefix".into(),
        ));
    }
    let creds = cp
        .mint_upload(
            &a.site,
            &a.container,
            a.key.as_deref(),
            a.prefix.as_deref(),
            &a.perms,
            a.ttl,
            a.content_type.as_deref(),
            a.max_bytes,
            a.sha256,
        )
        .await?;
    render(&creds, a.emit);
    Ok(())
}

/// Render a minted credential in the requested form.
#[cfg(feature = "blob-upload")]
fn render(c: &client::MintUploadResult, emit: Emit) {
    let is_presigned = c.kind == "presigned_put";
    match emit {
        Emit::Json => {
            // Re-serialize the deserialized struct verbatim (stable field order via serde).
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "kind": c.kind,
                    "url": c.url,
                    "method": c.method,
                    "required_headers": c.required_headers,
                    "access_key_id": c.access_key_id,
                    "secret": c.secret,
                    "session_token": c.session_token,
                    "endpoint": c.endpoint,
                    "region": c.region,
                    "bucket": c.bucket,
                    "force_path_style": c.force_path_style,
                    "expires_at": c.expires_at,
                    "expires_in_secs": c.expires_in_secs,
                    "enforced": c.enforced,
                    "advisory": c.advisory,
                }))
                .unwrap_or_default()
            );
        }
        Emit::Aws => {
            if is_presigned {
                // A presigned PUT is not an SDK profile — there is nothing to put in ~/.aws.
                eprintln!(
                    "# a presigned-put credential is a single URL, not an SDK profile; use --emit env or json"
                );
                print_presigned(c);
            } else {
                println!("[boatramp-upload]");
                println!("aws_access_key_id = {}", opt(&c.access_key_id));
                println!("aws_secret_access_key = {}", opt(&c.secret));
                println!("aws_session_token = {}", opt(&c.session_token));
                println!("# region = {}", opt(&c.region));
                println!("# endpoint_url = {}", opt(&c.endpoint));
                println!("# addressing_style = path");
                println!(
                    "# bucket = {}  (expires in {}s)",
                    opt(&c.bucket),
                    c.expires_in_secs
                );
            }
        }
        Emit::Rclone => {
            if is_presigned {
                eprintln!(
                    "# a presigned-put credential is a single URL, not an rclone remote; use --emit env or json"
                );
                print_presigned(c);
            } else {
                println!("[boatramp-upload]");
                println!("type = s3");
                println!("provider = Other");
                println!("access_key_id = {}", opt(&c.access_key_id));
                println!("secret_access_key = {}", opt(&c.secret));
                println!("session_token = {}", opt(&c.session_token));
                println!("region = {}", opt(&c.region));
                println!("endpoint = {}", opt(&c.endpoint));
                println!("force_path_style = true");
            }
        }
        Emit::Env => {
            if is_presigned {
                print_presigned(c);
            } else {
                print_env(c);
            }
        }
        Emit::Human => {
            if is_presigned {
                println!("Minted a presigned PUT credential (single-key, browser-friendly):");
                print_presigned(c);
            } else {
                println!(
                    "Minted temporary S3 credentials (path-style; expires in {}s):",
                    c.expires_in_secs
                );
                println!("  bucket   {}", opt(&c.bucket));
                println!("  endpoint {}", opt(&c.endpoint));
                println!("  region   {}", opt(&c.region));
                if !c.enforced.is_empty() {
                    println!("  enforced {}", c.enforced.join(", "));
                }
                if !c.advisory.is_empty() {
                    println!("  advisory {}", c.advisory.join(", "));
                }
                println!();
                print_env(c);
            }
        }
    }
}

/// Print the shell `export` block an S3 SDK reads for temp-credentials.
#[cfg(feature = "blob-upload")]
fn print_env(c: &client::MintUploadResult) {
    println!("export AWS_ACCESS_KEY_ID={}", opt(&c.access_key_id));
    println!("export AWS_SECRET_ACCESS_KEY={}", opt(&c.secret));
    println!("export AWS_SESSION_TOKEN={}", opt(&c.session_token));
    println!("export AWS_REGION={}", opt(&c.region));
    println!("export AWS_ENDPOINT_URL={}", opt(&c.endpoint));
    // Path-style is mandatory for the local face (bucket = container in the path).
    println!("export AWS_S3_FORCE_PATH_STYLE=true");
    println!("# then: aws s3 cp <file> s3://{}/<key>", opt(&c.bucket));
}

/// Print a presigned-put credential (the URL + any required headers + a ready `curl`).
#[cfg(feature = "blob-upload")]
fn print_presigned(c: &client::MintUploadResult) {
    let url = opt(&c.url);
    println!("  method  {}", opt(&c.method));
    println!("  url     {url}");
    for (k, v) in &c.required_headers {
        println!("  header  {k}: {v}");
    }
    println!("  expires in {}s", c.expires_in_secs);
    let hdrs: String = c
        .required_headers
        .iter()
        .map(|(k, v)| format!(" -H '{k}: {v}'"))
        .collect();
    println!(
        "# curl -X {} '{url}'{hdrs} --data-binary @<file>",
        opt(&c.method)
    );
}

/// Format an optional string field for display ("" when absent).
#[cfg(feature = "blob-upload")]
fn opt(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("")
}
