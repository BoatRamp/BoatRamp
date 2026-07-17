//! The `sync` subcommand: publish a folder as a new atomic deployment.
//!
//! Flow (content-addressed):
//! 1. optionally run the build command;
//! 2. walk the target dir, hashing each file (streamed, never fully buffered)
//!    into a [`Manifest`];
//! 3. POST the manifest; the server replies with the blob hashes it is missing;
//! 4. stream just those blobs up;
//! 5. activate — the server atomically flips the site's `current` pointer.
//!
//! Re-deploying an unchanged tree uploads nothing; rollback is re-activating an
//! older deployment id.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};

use boatramp_core::deploy::{FileEntry, Manifest, Variant};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use walkdir::WalkDir;

/// Files at or above this size are considered for precompression; tiny files
/// rarely benefit and may even grow.
const MIN_COMPRESS_SIZE: u64 = 1024;

use crate::build;
use crate::config::ProjectConfig;

/// A failure in the `sync` subcommand (publishing a deployment).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The resolved publish path is not a directory.
    #[error("{0} is not a directory")]
    NotADirectory(String),
    /// The server requested a blob we have no local source for.
    #[error("no local source for blob {0}")]
    NoLocalSource(String),
    /// Reading a `_redirects` / `_headers` migration-shim file failed.
    #[error("reading {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Resolving the publish target (server/site) failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// The optional pre-publish build step failed.
    #[error(transparent)]
    Build(#[from] crate::build::Error),
    /// Sync-time handler/consumer component validation failed.
    #[error(transparent)]
    Validate(#[from] crate::handler_validate::Error),
    /// A control-plane HTTP request (deployment negotiation, blob upload,
    /// activation) failed.
    #[error("control-plane request: {0}")]
    Http(#[from] reqwest::Error),
    /// A walked path was not under the scan root.
    #[error(transparent)]
    StripPrefix(#[from] std::path::StripPrefixError),
    /// A filesystem operation failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// `sync` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// boatramp's own files, never published as site content (mirrors how Netlify
/// skips `netlify.toml`). `project.cfg` is local tooling (its `routing` section
/// travels inside the manifest, not as an asset); `_redirects`/`_headers` are
/// folded into the routing config (the migration shim) rather than served.
const SKIP_FILES: [&str; 3] = ["project.cfg", "_redirects", "_headers"];

/// Arguments for `boatramp sync`.
#[derive(Debug, clap::Args)]
pub struct SyncArgs {
    /// Directory to publish (defaults to [build].output, then ".").
    path: Option<PathBuf>,

    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER")]
    server: Option<String>,

    /// Site to publish to (overrides [deploy].site).
    #[arg(long, env = "BOATRAMP_SITE")]
    site: Option<String>,

    /// Run the configured build command before publishing.
    #[arg(long)]
    build: bool,

    /// Do not run the build command even if one is configured.
    #[arg(long, conflicts_with = "build")]
    no_build: bool,

    /// Upload the deployment but do not activate it.
    #[arg(long)]
    no_activate: bool,

    /// Deploy message recorded with the deployment.
    #[arg(long, short = 'm')]
    message: Option<String>,

    /// Source revision (defaults to the current git commit SHA, if any).
    #[arg(long)]
    source: Option<String>,

    /// Source branch (defaults to the current git branch, if any).
    #[arg(long)]
    branch: Option<String>,

    /// Deploy author.
    #[arg(long)]
    author: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateDeploymentResponse {
    id: String,
    missing: Vec<String>,
}

/// Entry point for `boatramp sync`.
pub async fn run(args: SyncArgs, config: &ProjectConfig) -> Result<()> {
    let (server, site) =
        crate::client::resolve_target(args.server.clone(), args.site.clone(), config)?;

    // Build first if asked, or if a build is configured (unless suppressed).
    let should_build = !args.no_build && (args.build || config.build.is_some());
    if should_build {
        let command = build::resolve_command(None, config)?;
        build::run_command(&command).await?;
    }

    let dir = args
        .path
        .clone()
        .or_else(|| {
            config
                .build
                .as_ref()
                .and_then(|b| b.output.clone())
                .map(PathBuf::from)
        })
        .unwrap_or_else(|| PathBuf::from("."));

    if !dir.is_dir() {
        return Err(Error::NotADirectory(dir.display().to_string()));
    }

    let (mut manifest, blobs_by_hash) = build_manifest(&dir).await?;
    apply_deploy_config(config, &dir, &mut manifest)?;
    // Validate any declared handler/consumer components (no-op without the
    // `handlers` feature).
    crate::handler_validate::validate_deploy(&dir, &manifest.config)?;
    let variant_count: usize = manifest.files.values().map(|f| f.variants.len()).sum();
    println!(
        "scanned {} file(s) in {} ({} unique blob(s), {} precompressed variant(s))",
        manifest.files.len(),
        dir.display(),
        blobs_by_hash.len(),
        variant_count,
    );

    let client = crate::client::http_client(crate::client::token(config).as_deref());

    // Capture provenance: explicit flags win, else fall back to git.
    let (git_sha, git_branch) = git_info(&dir);
    let meta = [
        ("source", args.source.clone().or(git_sha)),
        ("branch", args.branch.clone().or(git_branch)),
        ("author", args.author.clone()),
        ("message", args.message.clone()),
    ];
    let query: Vec<(&str, String)> = meta
        .into_iter()
        .filter_map(|(k, v)| v.map(|v| (k, v)))
        .collect();

    // Negotiate the deployment: server stores the manifest and tells us which
    // blobs it still needs.
    let created: CreateDeploymentResponse = client
        .post(format!("{server}/api/sites/{site}/deployments"))
        .query(&query)
        .json(&manifest)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    println!(
        "deployment {} — uploading {} new blob(s)",
        created.id,
        created.missing.len()
    );

    for hash in &created.missing {
        let source = blobs_by_hash
            .get(hash)
            .ok_or_else(|| Error::NoLocalSource(hash.clone()))?;
        upload_blob(&client, &server, hash, source).await?;
    }

    if args.no_activate {
        println!(
            "uploaded but not activated; preview at {server}/_deploy/{}/\n  \
             activate with: curl -X POST {server}/api/sites/{site}/deployments/{}/activate",
            created.id, created.id
        );
        return Ok(());
    }

    client
        .post(format!(
            "{server}/api/sites/{site}/deployments/{}/activate",
            created.id
        ))
        .send()
        .await?
        .error_for_status()?;

    println!("activated {site} -> {}", created.id);
    println!("now serving {server}/_sites/{site}/");
    println!("immutable preview: {server}/_deploy/{}/", created.id);
    Ok(())
}

/// Best-effort `(commit SHA, branch)` for the git repo containing `dir`.
/// Returns `None`s when git is unavailable or `dir` is not a repo.
fn git_info(dir: &Path) -> (Option<String>, Option<String>) {
    let sha = run_git(dir, &["rev-parse", "HEAD"]);
    // A detached HEAD reports the branch as "HEAD" — treat that as unknown.
    let branch = run_git(dir, &["rev-parse", "--abbrev-ref", "HEAD"]).filter(|b| b != "HEAD");
    (sha, branch)
}

/// Run a git command in `dir`, returning trimmed stdout on success.
fn run_git(dir: &Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// Fold the project's deploy-scoped `routing` config into the manifest.
///
/// The routing config comes from `project.cfg` (loaded + compile-checked
/// already); it travels inside the manifest, so it is atomic with the content
/// and rolls back with it. Netlify/Pages-style `_redirects` / `_headers` files
/// in the deploy root are then appended as a migration shim.
fn apply_deploy_config(config: &ProjectConfig, dir: &Path, manifest: &mut Manifest) -> Result<()> {
    manifest.config = config.routing.clone();
    if !manifest.config.redirects.is_empty()
        || !manifest.config.rewrites.is_empty()
        || !manifest.config.headers.is_empty()
    {
        println!(
            "routing: {} redirect(s), {} rewrite(s), {} header rule(s)",
            manifest.config.redirects.len(),
            manifest.config.rewrites.len(),
            manifest.config.headers.len(),
        );
    }

    // Migration shim: fold Netlify/Pages-style `_redirects` / `_headers` into the
    // config (appended after any project.cfg routing rules, so explicit rules win
    // the first-match redirect ordering).
    if let Some(text) = read_optional(&dir.join("_redirects"))? {
        let parsed = boatramp_core::compat::parse_redirects(&text);
        let (r, w) = (parsed.redirects.len(), parsed.rewrites.len());
        manifest.config.redirects.extend(parsed.redirects);
        manifest.config.rewrites.extend(parsed.rewrites);
        println!("loaded _redirects: {r} redirect(s), {w} rewrite(s)");
    }
    if let Some(text) = read_optional(&dir.join("_headers"))? {
        let rules = boatramp_core::compat::parse_headers(&text);
        println!("loaded _headers: {} header rule(s)", rules.len());
        manifest.config.headers.extend(rules);
    }
    Ok(())
}

/// Read a file's text, returning `None` if it doesn't exist.
fn read_optional(path: &Path) -> Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::Read {
            path: path.display().to_string(),
            source: err,
        }),
    }
}

/// Where a blob's bytes come from when uploading: streamed from disk (identity
/// content) or held in memory (a precompressed variant produced at sync).
enum BlobSource {
    File(PathBuf),
    Memory(Vec<u8>),
}

/// Walk `dir`, hashing each file into a manifest (with precompressed `br`/`gzip`
/// variants for compressible types) and recording where each unique blob — both
/// identity and variant — can be read from locally for upload.
async fn build_manifest(dir: &Path) -> Result<(Manifest, HashMap<String, BlobSource>)> {
    let mut manifest = Manifest::default();
    let mut blobs: HashMap<String, BlobSource> = HashMap::new();

    for entry in WalkDir::new(dir)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = path.strip_prefix(dir)?.to_string_lossy().replace('\\', "/");

        if SKIP_FILES.contains(&rel.as_str()) {
            continue; // boatramp's own config files are never served content
        }

        let content_type = content_type_for(&rel);
        let mut file_entry = FileEntry {
            hash: String::new(),
            size: 0,
            content_type: content_type.clone(),
            variants: BTreeMap::new(),
        };

        if is_compressible(content_type.as_deref()) && file_size(path).await? >= MIN_COMPRESS_SIZE {
            // Read once: hash the identity bytes and derive variants from them.
            let data = tokio::fs::read(path).await?;
            file_entry.hash = sha256_hex(&data);
            file_entry.size = data.len() as u64;
            blobs
                .entry(file_entry.hash.clone())
                .or_insert_with(|| BlobSource::File(path.to_path_buf()));

            for (encoding, compressed) in compress_variants(&data) {
                // Keep a variant only when it actually shrinks the payload.
                if compressed.len() >= data.len() {
                    continue;
                }
                let hash = sha256_hex(&compressed);
                let size = compressed.len() as u64;
                file_entry.variants.insert(
                    encoding,
                    Variant {
                        hash: hash.clone(),
                        size,
                    },
                );
                blobs.entry(hash).or_insert(BlobSource::Memory(compressed));
            }
        } else {
            // Stream-hash without buffering (binary/large/incompressible files).
            let (hash, size) = hash_file(path).await?;
            file_entry.hash = hash.clone();
            file_entry.size = size;
            blobs
                .entry(hash)
                .or_insert_with(|| BlobSource::File(path.to_path_buf()));
        }

        manifest.files.insert(rel, file_entry);
    }

    Ok((manifest, blobs))
}

/// SHA-256 hex of a byte slice.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Whether a content type is worth precompressing.
fn is_compressible(content_type: Option<&str>) -> bool {
    match content_type {
        Some(ct) => {
            ct.starts_with("text/")
                || ct.contains("javascript")
                || ct.contains("json")
                || ct.contains("svg")
                || ct.contains("xml")
                || ct == "application/wasm"
        }
        None => false,
    }
}

/// Produce `(encoding, bytes)` precompressed variants of `data`.
fn compress_variants(data: &[u8]) -> Vec<(String, Vec<u8>)> {
    vec![
        ("br".to_string(), compress_brotli(data)),
        ("gzip".to_string(), compress_gzip(data)),
    ]
}

/// Brotli-compress at a build-time quality (window 22, quality 9).
fn compress_brotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut out, 4096, 9, 22);
        let _ = writer.write_all(data);
        let _ = writer.flush();
    }
    out
}

/// Gzip-compress at best ratio.
fn compress_gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    let _ = encoder.write_all(data);
    encoder.finish().unwrap_or_default()
}

/// A file's size without reading its contents.
async fn file_size(path: &Path) -> Result<u64> {
    Ok(tokio::fs::metadata(path).await?.len())
}

/// Stream a file through SHA-256, returning its hex digest and size.
async fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut size = 0u64;
    loop {
        let read = file.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buf[..read]);
        size += read as u64;
    }
    Ok((hex::encode(hasher.finalize()), size))
}

/// Upload a blob to the server, streaming from disk or sending in-memory bytes.
async fn upload_blob(
    client: &crate::client::ApiClient,
    server: &str,
    hash: &str,
    source: &BlobSource,
) -> Result<()> {
    let body = match source {
        BlobSource::File(path) => {
            let file = tokio::fs::File::open(path).await?;
            reqwest::Body::wrap_stream(ReaderStream::new(file))
        }
        BlobSource::Memory(bytes) => reqwest::Body::from(bytes.clone()),
    };
    client
        .put(format!("{server}/api/blobs/{hash}"))
        .body(body)
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

/// Best-effort MIME type from a path's extension.
fn content_type_for(path: &str) -> Option<String> {
    let ext = Path::new(path).extension()?.to_str()?;
    let mime = match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        "woff2" => "font/woff2",
        _ => return None,
    };
    Some(mime.to_string())
}
