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
    }
    Ok(())
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
