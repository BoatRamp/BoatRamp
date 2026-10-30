//! The `blob` subcommand group: upload a file as a content-addressed blob and print
//! its hash (`blob put`), and — with the `blob-upload` feature — mint a scoped, short-lived
//! S3 upload credential for a project+site's blob container (`blob mint-upload`, S3 external
//! ingress). `blob put` is the control-plane ARTIFACT namespace; `blob mint-upload` is the
//! external-INGRESS credential minter — deliberately distinct verbs.

use std::io::Write;

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
    /// The daemon-mediated `blob drain` did not complete — the daemon reported a verify-failure
    /// (objects still absent from the primary) or a storage error. The streamed report already
    /// printed the detail; this maps to a non-zero exit.
    #[error("blob drain did not complete — see the drain report above (re-run to resume)")]
    DrainIncomplete,
    /// The blob purge reported a storage error (the streamed report already printed the detail);
    /// maps to a non-zero exit.
    #[error("blob purge did not complete — see the purge report above (re-run to resume)")]
    PurgeIncomplete,
    /// Serializing the `--json` migration report failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// `--from` was omitted and the `--node-config` has no `[serve.blob_fallback]` to drain from.
    #[error(
        "no migration SOURCE: pass --from <config>, or configure [serve.blob_fallback] in \
         {node_config} (the drain one-liner) — {node_config} has no fallback secondary to drain"
    )]
    NoSource {
        /// The node config path consulted for a fallback.
        node_config: String,
    },
    /// The resolved source and destination backends are the SAME identity — a migration would be a
    /// no-op (or corrupt in place). Refused before copying.
    #[error(
        "refusing to migrate: source and destination resolve to the SAME backend ({identity}); \
         pick distinct --from/--to backends"
    )]
    SameSourceDest {
        /// The shared backend identity.
        identity: String,
    },
    /// Opening the control-plane KV (for the `projectmeta/` set the `blob rehome` translator needs)
    /// failed — delegated to the same `serve` store builder, so the same `--kv`/`--data-dir` guidance
    /// applies.
    #[error(transparent)]
    KvOpen(#[from] Box<crate::serve::Error>),
    /// Reading the `projectmeta/` project set from the control-plane KV failed.
    #[error("reading the project set from the control-plane KV: {0}")]
    KvRead(String),
    /// The default-scope blob re-home engine (`blob rehome`) reported a storage/verification error.
    #[error("blob rehome: {0}")]
    Rehome(String),
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
    /// **Drain the daemon's configured `[serve.blob_fallback]`** secondary into the primary, over the
    /// control plane — for a MANAGED node reachable only via `BOATRAMP_SERVER` (no local disk / no
    /// `fly ssh`), where the offline `blob migrate` can't run. Unlike `blob migrate`, this REQUIRES a
    /// server: it triggers the RUNNING daemon (which already holds both backends of its `FallbackStorage`
    /// composite open) to copy its OWN configured secondary → primary internally, then relays progress.
    ///
    /// The client names NO source/destination — the daemon drains only its own configured
    /// fallback → primary, so a token-bearing client can't point a copy at arbitrary backends (tighter
    /// than the offline CLI's arbitrary `--from`/`--to`). Gated by an operator token (System·Admin).
    /// The copy is idempotent + resumable, reads the secondary read-only, and — on a verified drain —
    /// reports that it is safe to remove `[serve].blob_fallback` and restart the node.
    ///
    /// For OFFLINE / pre-boot / volume-local copies between arbitrary backends, use `boatramp blob migrate`.
    Drain(DrainArgs),
    /// **Purge a PROVABLY-SAFE blob set** over the control plane (v0.6.4). Dry-run by default (report
    /// only); pass `--apply` to actually delete. Exactly ONE mode is required:
    ///
    /// `--unreferenced` — on-demand garbage collection: reclaim content-addressed blobs that no live
    /// deploy manifest references (nothing serving can break). This is the everyday reclaim front
    /// door. It is REFUSED (409) while a read-fallback secondary is attached (`[serve.blob_fallback]`),
    /// because GC would phantom-reclaim a secondary-only orphan — drain + drop the fallback first.
    ///
    /// `--drained-source` — the migration DECOMMISSION: after `blob drain` (or `blob migrate`) has
    /// copied the OLD secondary into the primary, delete each source key ONLY once it is byte-confirmed
    /// (present at matching size) in the primary. Fail-closed: an unconfirmed key SURVIVES. Requires a
    /// configured `[serve.blob_fallback]` (else 422); runs while the fallback is still attached, then
    /// you drop it.
    Purge(PurgeArgs),
    /// Print the node's structured blob transition-mode state (v0.6.4): whether a read-fallback
    /// secondary is currently attached (the node is mid-migration). The direct, structured answer to
    /// "is this node still in TRANSITION mode?" — no log-grepping. Read-only (System·Read).
    Status(StatusArgs),
    /// **Verify content-addressed references** (System·Read): list every blob a LIVE site deployment
    /// or function references that is MISSING from the backend — a dead reference that would 404 on
    /// invoke/serve (the `identity`-component-missing shape). Read-only. To repair one, re-upload the
    /// bytes (`boatramp blob put <file>`) or re-deploy the resource; the GC fix that stops new dead
    /// references (referencing live function components) ships alongside this.
    Verify(VerifyArgs),
    /// **Default-scope blob re-home** (v0.31.0 Finding 8), offline + node-local — the blob half of the
    /// `boatramp migrate` default-scope re-key. Re-homes the node's own bare default-scoped blob
    /// objects (`hblob/{site}/…`, `mqp/…`, `mqgp/…`) to their two-segment `…/default/…` spelling IN
    /// PLACE on the node's own backend (built from `--node-config`'s `[serve]` block, like
    /// `blob migrate`). It reads the `projectmeta/` project set from the control-plane KV so a named
    /// project's keys are never touched.
    ///
    /// Two phases mirroring `boatramp migrate --stage`/`--finalize`: the default (drain) copies every
    /// re-homeable object old→new, `head`-verifies, and NEVER deletes the source; `--finalize`
    /// (retire) deletes each old key ONLY after its new key verifies present (copy-before-delete). Run
    /// the daemon-side read-fallback bridges serving during the drain; run `--finalize` only after the
    /// drain verifies, together with `boatramp migrate --finalize`. Run with the node STOPPED (it opens
    /// the control-plane KV). Local libsql + managed-DB data are migrated separately (`sql rehome-default`
    /// / `boatramp migrate`).
    Rehome(RehomeArgs),
}

/// Arguments for `boatramp blob rehome` (offline, node-local — v0.31.0 Finding 8).
#[derive(Debug, clap::Args)]
pub struct RehomeArgs {
    /// Path to the running node's config (`boatramp.cfg` shape). Its `[serve]` blob block is the
    /// backend re-homed in place, and its `[serve].data_dir` locates the control-plane KV.
    #[arg(long, default_value = "boatramp.cfg")]
    node_config: std::path::PathBuf,
    /// Metadata (KV) backend holding the `projectmeta/` project set. Must match `serve`.
    #[arg(long, value_enum, default_value_t = boatramp_node::backends::KvBackend::Slatedb)]
    kv: boatramp_node::backends::KvBackend,
    /// Data directory for the control-plane KV (flag > `[serve].data_dir` > `./data`). Must match `serve`.
    #[arg(long)]
    data_dir: Option<std::path::PathBuf>,
    /// Finalize: delete each old bare-scoped key ONLY after its new `…/default/…` key verifies present
    /// (copy-before-delete). Without this the run is the non-destructive drain (copy + verify, keep old).
    #[arg(long)]
    finalize: bool,
    /// Classify/would-copy (drain) or would-delete (finalize) only; write + delete nothing.
    #[arg(long)]
    dry_run: bool,
}

/// Arguments for `boatramp blob purge`. Exactly one of `--unreferenced` / `--drained-source` is
/// required (a clap `ArgGroup`); dry-run unless `--apply`.
#[derive(Debug, clap::Args)]
#[command(group(
    clap::ArgGroup::new("purge_mode")
        .required(true)
        .args(["unreferenced", "drained_source"]),
))]
pub struct PurgeArgs {
    /// Reclaim content-addressed blobs no live manifest references (on-demand GC). Refused (409)
    /// while a read-fallback secondary is attached.
    #[arg(long)]
    unreferenced: bool,
    /// Reclaim the drained OLD secondary: delete each source key only once byte-confirmed in the
    /// primary (fail-closed). Requires a configured `[serve.blob_fallback]`.
    #[arg(long)]
    drained_source: bool,
    /// Actually delete (default: dry-run — report what WOULD be reclaimed, delete nothing).
    #[arg(long)]
    apply: bool,
    /// Restrict a `--drained-source` purge to source keys under this prefix (default: all objects).
    /// Ignored by `--unreferenced` (which GCs the whole content-addressed keyspace).
    #[arg(long)]
    prefix: Option<String>,
}

/// Arguments for `boatramp blob status`.
#[derive(Debug, clap::Args)]
pub struct StatusArgs {}

/// Arguments for `boatramp blob verify`.
#[derive(Debug, clap::Args)]
pub struct VerifyArgs {}

/// Arguments for `boatramp blob drain`.
#[derive(Debug, clap::Args)]
pub struct DrainArgs {
    /// Enumerate + classify (would-copy / would-skip) on the daemon and report, but copy nothing.
    #[arg(long)]
    dry_run: bool,
    /// Bounded copy concurrency on the daemon (objects in flight at once).
    #[arg(long)]
    concurrency: Option<usize>,
    /// Restrict the drain to secondary keys under this prefix (default: all objects).
    #[arg(long)]
    prefix: Option<String>,
}

/// Arguments for `boatramp blob migrate`.
#[derive(Debug, clap::Args)]
pub struct MigrateArgs {
    /// Path to the node config file (`boatramp.cfg` shape) whose `[serve]` blob block defines the
    /// SOURCE backend (+ optional `[secrets]` for a sealed `boatramp:`/`env:` S3 credential ref).
    /// OPTIONAL: when omitted, the SOURCE is the `[serve.blob_fallback]` SECONDARY of the node config
    /// (`--node-config`, default `boatramp.cfg`) — the zero-downtime drain one-liner. Omitting it with
    /// no configured fallback is an error.
    #[arg(long)]
    from: Option<std::path::PathBuf>,
    /// Path to the node config file whose `[serve]` blob block defines the DESTINATION backend.
    /// OPTIONAL: when omitted, the DESTINATION defaults to the node config's OWN blob backend (the
    /// running node's primary), so `boatramp blob migrate --from <old>` migrates into the node you run.
    #[arg(long)]
    to: Option<std::path::PathBuf>,
    /// Path to the running node's config (`boatramp.cfg` shape) — the source of the `--from`/`--to`
    /// defaults: its `[serve]` blob block is the DEFAULT destination (the primary), and its
    /// `[serve.blob_fallback]` is the DEFAULT source (the secondary). Only read when `--from` or `--to`
    /// is omitted. Defaults to `boatramp.cfg`.
    #[arg(long, default_value = "boatramp.cfg")]
    node_config: std::path::PathBuf,
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
pub(crate) enum Emit {
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

/// The result of a `boatramp blob` subcommand, rendered by [`crate::output`].
///
/// Each variant carries the facts a JSON consumer reads; [`render_human`](crate::output::Rendered::render_human)
/// reproduces the exact text the command historically printed. The report subcommands
/// (`migrate`/`drain`/`purge`/`status`/`verify`/`rehome`) keep their own `--json` flag: in human
/// mode it still governs the rendering byte-for-byte (its old ad-hoc report JSON, or the human
/// summary). That `json` flag is skipped from the typed serialization; `--output-format json` renders
/// the named fields instead.
// A build-then-emit result; one data-carrying variant (Migrate/Rehome reports) is larger than the
// bare acks, but the value is short-lived and boxing would only obscure its shape/JSON.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum BlobOutput {
    /// `blob put` — the content hash of the uploaded blob.
    Put {
        /// The content-addressed hash (the key other commands reference).
        hash: String,
    },
    /// `blob mint-upload` — a minted S3 upload credential, rendered per `--emit`.
    #[cfg(feature = "blob-upload")]
    MintUpload {
        /// The minted credential (serialized as the `--emit json` object).
        #[serde(serialize_with = "serialize_mint_creds")]
        creds: client::MintUploadResult,
        /// The `--emit` form chosen for the human rendering.
        #[serde(skip)]
        emit: Emit,
    },
    /// `blob migrate` — the offline, node-local backend-migration summary.
    Migrate {
        /// Resolved source backend identity.
        source: String,
        /// Resolved destination backend identity.
        dest: String,
        /// Objects present in the source.
        total_objects: u64,
        /// Objects copied source→dest.
        copied_objects: u64,
        /// Objects already present in the destination (skipped).
        skipped_objects: u64,
        /// Bytes copied.
        copied_bytes: u64,
        /// Whether the post-copy verification passed.
        verified: bool,
        /// Whether this was a dry run.
        dry_run: bool,
        /// Whether a configured fallback→primary drain is now fully verified.
        secondary_drained: bool,
    },
    /// `blob drain` — the daemon's final drain report (opaque server JSON).
    Drain {
        /// The daemon's final report object.
        report: serde_json::Value,
    },
    /// `blob purge` — the daemon's final purge report (opaque server JSON).
    Purge {
        /// The daemon's final report object.
        report: serde_json::Value,
    },
    /// `blob status` — the node's blob transition-mode state (opaque server JSON).
    Status {
        /// The node's structured status object.
        state: serde_json::Value,
    },
    /// `blob verify` — the dead-reference report (opaque server JSON).
    Verify {
        /// The server's verification object (carries `dead_references`).
        state: serde_json::Value,
    },
    /// `blob rehome` — the offline default-scope re-home summary.
    Rehome {
        /// `"drain"` or `"retire"`.
        phase: &'static str,
        /// Whether this was a dry run.
        dry_run: bool,
        /// Re-homeable objects considered.
        total: u64,
        /// Objects copied old→new.
        copied: u64,
        /// Objects already present at the new key.
        skipped: u64,
        /// Old keys deleted (retire only).
        deleted: u64,
        /// Whether the control-plane "blob substrate retired" marker was set.
        blob_retired_marker_set: bool,
    },
}

impl crate::output::Rendered for BlobOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Put { hash } => writeln!(w, "{hash}"),
            #[cfg(feature = "blob-upload")]
            Self::MintUpload { creds, emit } => write_mint(creds, *emit, w),
            // `source`/`dest` ride the JSON shape only; the human summary never showed them.
            Self::Migrate {
                total_objects,
                copied_objects,
                skipped_objects,
                copied_bytes,
                verified,
                dry_run,
                secondary_drained,
                ..
            } => write_migrate(
                *total_objects,
                *copied_objects,
                *skipped_objects,
                *copied_bytes,
                *verified,
                *dry_run,
                *secondary_drained,
                w,
            ),
            Self::Drain { report } => write_drain(report, w),
            Self::Purge { report } => write_purge(report, w),
            Self::Status { state } => write_status(state, w),
            Self::Verify { state } => write_verify(state, w),
            Self::Rehome {
                phase,
                dry_run,
                total,
                copied,
                skipped,
                deleted,
                blob_retired_marker_set,
            } => write_rehome(
                phase,
                *dry_run,
                *total,
                *copied,
                *skipped,
                *deleted,
                *blob_retired_marker_set,
                w,
            ),
        }
    }
}

/// Serialize a minted credential as the self-describing `--emit json` object (the struct is
/// `Deserialize`-only, so this maps its fields into a value for the typed JSON output).
#[cfg(feature = "blob-upload")]
fn serialize_mint_creds<S>(
    c: &client::MintUploadResult,
    s: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serde::Serialize::serialize(&mint_creds_value(c), s)
}

/// The `--emit json` object for a minted credential (shared by the JSON serialization and the human
/// `--emit json` rendering so the two stay identical).
#[cfg(feature = "blob-upload")]
fn mint_creds_value(c: &client::MintUploadResult) -> serde_json::Value {
    serde_json::json!({
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
    })
}

/// Render the `blob migrate` summary (human line), byte-for-byte as the command historically
/// printed it.
#[allow(clippy::too_many_arguments)]
fn write_migrate(
    total_objects: u64,
    copied_objects: u64,
    skipped_objects: u64,
    copied_bytes: u64,
    verified: bool,
    dry_run: bool,
    secondary_drained: bool,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let verb = if dry_run { "would copy" } else { "copied" };
    writeln!(
        w,
        "blob migrate {}: {} {} object(s), skipped {} present, {} byte(s){}",
        if dry_run { "(dry-run)" } else { "complete" },
        verb,
        copied_objects,
        skipped_objects,
        copied_bytes,
        if verified {
            format!("; VERIFY OK: {total_objects} object(s) present in destination")
        } else {
            String::new()
        },
    )?;
    if secondary_drained {
        writeln!(
            w,
            "SECONDARY FULLY DRAINED — safe to remove [serve].blob_fallback and restart the node."
        )?;
    }
    Ok(())
}

/// Render the `blob drain` final report (human summary).
fn write_drain(report: &serde_json::Value, w: &mut dyn std::io::Write) -> std::io::Result<()> {
    let message = report
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(no message)");
    writeln!(w, "blob drain: {message}")
}

/// Render the `blob purge` final report (human summary).
fn write_purge(report: &serde_json::Value, w: &mut dyn std::io::Write) -> std::io::Result<()> {
    let message = report
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("(no message)");
    writeln!(w, "blob purge: {message}")
}

/// Render the `blob status` transition-mode state (human line).
fn write_status(state: &serde_json::Value, w: &mut dyn std::io::Write) -> std::io::Result<()> {
    let active = state
        .get("blob_fallback_active")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if active {
        writeln!(
            w,
            "blob status: a read-fallback secondary is ATTACHED ([serve.blob_fallback]) — the \
             node is mid-migration (TRANSITION mode). Drain it (blob drain / blob purge \
             --drained-source), drop [serve.blob_fallback], and restart to finish."
        )
    } else {
        writeln!(
            w,
            "blob status: no read-fallback secondary attached — the node is not mid-migration."
        )
    }
}

/// Render the `blob verify` report (human lines): dead references (missing) + size mismatches
/// (declared≠stored).
fn write_verify(state: &serde_json::Value, w: &mut dyn std::io::Write) -> std::io::Result<()> {
    let dead = state
        .get("dead_references")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let size_mismatches = state
        .get("size_mismatches")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();

    if dead.is_empty() && size_mismatches.is_empty() {
        return writeln!(
            w,
            "blob verify: OK — every referenced blob is present AND matches its declared size."
        );
    }

    if !dead.is_empty() {
        writeln!(
            w,
            "blob verify: {} DEAD reference(s) — referenced by a live deployment/function but \
             MISSING from the backend (would 404 on invoke/serve):",
            dead.len()
        )?;
        for d in &dead {
            let hash = d
                .get("hash")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let referrer = d
                .get("referrer")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            writeln!(w, "  • {hash}  ({referrer})")?;
        }
        writeln!(
            w,
            "\nTo repair a dead reference: re-upload each missing blob (`boatramp blob put <file>` \
             restores it under the same content hash) or re-deploy the resource."
        )?;
    }

    if !size_mismatches.is_empty() {
        if !dead.is_empty() {
            writeln!(w)?;
        }
        writeln!(
            w,
            "blob verify: {} SIZE mismatch(es) — the backend stores a different byte count than the \
             manifest declares (a truncated/hung Content-Length; also blocks a streaming clone):",
            size_mismatches.len()
        )?;
        for m in &size_mismatches {
            let hash = m
                .get("hash")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("?");
            let referrer = m
                .get("referrer")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let declared = m.get("declared").and_then(serde_json::Value::as_u64);
            let stored = m.get("stored").and_then(serde_json::Value::as_u64);
            let declared = declared.map_or_else(|| "?".to_string(), |v| v.to_string());
            let stored = stored.map_or_else(|| "(backend reports no size)".to_string(), |v| v.to_string());
            writeln!(
                w,
                "  • {hash}  declared {declared}, stored {stored}  ({referrer})"
            )?;
        }
        writeln!(
            w,
            "\nTo repair a size mismatch: a re-generable derivative can be blessed with `boatramp \
             blob reconcile` (recomputes the declared size from the stored bytes); on primary data \
             a mismatch signals a truncation/corruption to investigate (re-upload / re-deploy)."
        )?;
    }
    Ok(())
}

/// Render the `blob rehome` summary (human line).
#[allow(clippy::too_many_arguments)]
fn write_rehome(
    phase: &str,
    dry_run: bool,
    total: u64,
    copied: u64,
    skipped: u64,
    deleted: u64,
    blob_retired_marker_set: bool,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    if phase == "retire" {
        writeln!(
            w,
            "blob rehome (retire{}): {} old key(s) deleted after their new key verified, of {} \
             re-homeable object(s). Old bare default-scoped keys reclaimed.{}",
            if dry_run { ", dry-run" } else { "" },
            deleted,
            total,
            if blob_retired_marker_set {
                " Blob substrate verified re-homed — `boatramp migrate --finalize` may now proceed."
            } else {
                ""
            }
        )
    } else {
        writeln!(
            w,
            "blob rehome (drain{}): {} object(s) copied old→new (verified), {} already present, of \
             {} re-homeable object(s). Source kept — run `blob rehome --finalize` after a verified \
             soak (with `boatramp migrate --finalize`).",
            if dry_run { ", dry-run" } else { "" },
            copied,
            skipped,
            total
        )
    }
}

/// Entry point for `boatramp blob`.
pub async fn run(args: BlobArgs, config: &ProjectConfig) -> Result<BlobOutput> {
    // `migrate` is NODE-LOCAL: it builds both blob backends in-process from two node config files
    // and never touches a control-plane server. Handle it before resolving the server target (the
    // other verbs are control-plane clients that require a `BOATRAMP_SERVER`/`[deploy].server`).
    if let BlobCommand::Migrate(a) = args.command {
        return migrate(a).await;
    }
    // `rehome` is likewise NODE-LOCAL (offline): it re-homes the node's own blob backend in place and
    // reads the project set from the control-plane KV — no control-plane server.
    if let BlobCommand::Rehome(a) = args.command {
        return rehome(a).await;
    }

    let server = client::resolve_server(args.server, config)?;
    let cp = client::ControlPlane::new(
        server,
        client::http_client(client::token(config).as_deref()),
        client::resolve_project(config),
    );

    let out = match args.command {
        BlobCommand::Put { file } => {
            let hash = cp.put_file_blob(&file).await?;
            BlobOutput::Put { hash }
        }
        #[cfg(feature = "blob-upload")]
        BlobCommand::MintUpload(a) => mint_upload(&cp, a).await?,
        // Unlike `migrate` (offline, handled above), `drain` is a control-plane client: it triggers
        // the RUNNING daemon to drain its OWN configured fallback → primary and relays the stream.
        BlobCommand::Drain(a) => drain(&cp, a).await?,
        // General provably-safe purge + structured transition status (v0.6.4), both control-plane clients.
        BlobCommand::Purge(a) => purge(&cp, a).await?,
        BlobCommand::Status(_) => status(&cp).await?,
        BlobCommand::Verify(_) => verify(&cp).await?,
        // Handled node-locally above (returned before the control-plane client was built).
        BlobCommand::Migrate(_) => unreachable!("handled before the control-plane client"),
        BlobCommand::Rehome(_) => unreachable!("handled before the control-plane client"),
    };
    Ok(out)
}

/// Run the offline, node-local default-scope blob re-home (`boatramp blob rehome`, v0.31.0 Finding 8).
/// Builds the node's OWN primary blob backend from `--node-config`'s `[serve]` block (same path as
/// `blob migrate`'s destination), opens the control-plane KV for the `projectmeta/` set (so a named
/// project's keys are never touched), then runs the `blob_rehome` drain (default) or retire
/// (`--finalize`) over the `hblob/`,`mqp/`,`mqgp/` families.
#[cfg(feature = "fallback")]
async fn rehome(a: RehomeArgs) -> Result<BlobOutput> {
    use std::sync::Arc;

    // 1. The node's own primary blob backend (the `[serve]` block of `--node-config`).
    let side = build_primary_side("rehome", &a.node_config).await?;
    // Preamble echo of the resolved backend → tracing (diagnostic/stderr); the summary is the result.
    tracing::info!(backend = %side.identity, "blob rehome: backend");

    // 2. The control-plane KV, for the `projectmeta/` project set the project-aware translator needs.
    //    Opened STRICT (a re-home is not a crash recovery) — run with the node STOPPED.
    let config = boatramp_node::config::ServerConfig::load(&a.node_config, None)?;
    let data_dir = a
        .data_dir
        .clone()
        .or_else(|| config.serve.as_ref().and_then(|s| s.data_dir.clone()))
        .unwrap_or_else(|| std::path::PathBuf::from("./data"));
    let kv = crate::serve::build_control_plane_kv(
        a.kv,
        &data_dir,
        None,
        boatramp_core::kv::KvOpenPolicy::Strict,
        None,
    )
    .await
    .map_err(|e| Error::KvOpen(Box::new(crate::serve::Error::from(e))))?;
    let mut projects = std::collections::HashSet::new();
    for key in kv
        .list_prefix(boatramp_core::project::POINTER_PREFIX)
        .await
        .map_err(|e| Error::KvRead(e.to_string()))?
    {
        if let Some(name) = key.strip_prefix(boatramp_core::project::POINTER_PREFIX)
            && !name.is_empty()
            && !name.contains('/')
        {
            projects.insert(name.to_string());
        }
    }

    // 3. Drive the engine. The default is the non-destructive drain; `--finalize` is the retire
    //    (copy-before-delete). The `to_new` translator skips named projects + already-`default/` keys.
    let projects = Arc::new(projects);
    let storage = side.storage.clone(); // kept for the post-retire verification + marker
    let opts = boatramp_storage::blob_rehome::RehomeOptions {
        prefixes: boatramp_node::blobs::DEFAULT_SCOPE_BLOB_FAMILIES
            .iter()
            .map(|&p| p.to_string())
            .collect(),
        to_new: boatramp_node::blobs::default_scope_to_new(projects.clone()),
        dry_run: a.dry_run,
    };
    let (phase, report) = if a.finalize {
        (
            "retire",
            boatramp_storage::blob_rehome::retire(side.storage, &opts)
                .await
                .map_err(|e| Error::Rehome(e.to_string()))?,
        )
    } else {
        (
            "drain",
            boatramp_storage::blob_rehome::drain(side.storage, &opts)
                .await
                .map_err(|e| Error::Rehome(e.to_string()))?,
        )
    };

    // After a real retire, VERIFY no bare default-scoped object remains and set the control-plane KV
    // marker `boatramp migrate --finalize` requires (HIGH-2c sequence) — the explicit "blob substrate
    // retired" signal from the command that holds the backend. A node with no blob data sets it here
    // too (a 0-object retire).
    let mut blob_marker_set = false;
    if a.finalize && !a.dry_run {
        let outstanding =
            boatramp_node::default_scope::blob_default_outstanding(&storage, projects.as_ref())
                .await
                .map_err(|e| Error::Rehome(e.to_string()))?;
        if outstanding {
            return Err(Error::Rehome(
                "bare default-scoped blob object(s) still present after retire — run `blob rehome` \
                 (drain) to copy them forward first, then re-run `--finalize`. The migrate-finalize \
                 marker was NOT set."
                    .into(),
            ));
        }
        kv.put(
            boatramp_node::default_scope::BLOB_RETIRED_MARKER,
            b"1".to_vec(),
        )
        .await
        .map_err(|e| Error::KvRead(e.to_string()))?;
        kv.flush().await.map_err(|e| Error::KvRead(e.to_string()))?;
        blob_marker_set = true;
    }

    Ok(BlobOutput::Rehome {
        phase,
        dry_run: a.dry_run,
        total: report.total,
        copied: report.copied,
        skipped: report.skipped,
        deleted: report.deleted,
        blob_retired_marker_set: blob_marker_set,
    })
}

/// `boatramp blob rehome` is unavailable in a build without a blob-backend feature (no `fallback`).
#[cfg(not(feature = "fallback"))]
async fn rehome(_a: RehomeArgs) -> Result<BlobOutput> {
    Err(Error::Usage(
        "`blob rehome` needs a blob-backend feature (e.g. --features fs/s3/gcs/azure); rebuild \
         with one"
            .into(),
    ))
}

/// Trigger the daemon-mediated blob drain (`boatramp blob drain`, v0.6.3): POST `/api/blob-drain`, then
/// consume the NDJSON progress stream (one JSON object per line), printing human progress to stderr as
/// it arrives, and finally the human summary — or, with `--json`, the final report object — to stdout.
/// Exits non-zero on a verify-failure or a refused/error status (mirrors `client.rs::migrate_trigger`'s
/// 200-vs-422 branching, surfaced here through [`client::ControlPlane::blob_drain`]).
async fn drain(cp: &client::ControlPlane, a: DrainArgs) -> Result<BlobOutput> {
    let final_report = cp
        .blob_drain(a.dry_run, a.concurrency, a.prefix.as_deref())
        .await?;

    // The daemon's final report (tagged `"type":"report"`): a verify-failure carries `missing`, a
    // storage error carries `error` — either means the drain did NOT complete (non-zero exit).
    let verify_failed = final_report.get("missing").is_some();
    let errored = final_report.get("error").is_some();

    // Non-zero exit on a verify-failure or a reported storage error (the drain did NOT complete). The
    // report must still reach the user (the error message points at "the drain report above"), but
    // `emit` never runs on the `Err` path — so surface it to stdout here (honoring `--json`), flush,
    // then fail. The daemon's `message` already carries the human summary (incl. the verified-drain
    // "SECONDARY FULLY DRAINED…" signal), printed verbatim.
    if verify_failed || errored {
        let mut out = std::io::stdout().lock();
        let _ = write_drain(&final_report, &mut out);
        let _ = out.flush();
        return Err(Error::DrainIncomplete);
    }
    Ok(BlobOutput::Drain {
        report: final_report,
    })
}

/// Run a general provably-safe blob purge (`boatramp blob purge`, v0.6.4): POST `/api/blob-purge` in
/// the selected mode, consume the NDJSON stream (progress to stderr, the final report to stdout — or
/// `--json`), and exit non-zero on a refusal/storage error. Dry-run unless `--apply`.
async fn purge(cp: &client::ControlPlane, a: PurgeArgs) -> Result<BlobOutput> {
    // The clap `ArgGroup` already guarantees exactly one mode is set (required + mutually exclusive),
    // but map it explicitly so the wire value is unambiguous.
    let mode = if a.unreferenced {
        "unreferenced"
    } else {
        // The group is `required`, so `drained_source` is set when `unreferenced` is not.
        "drained_source"
    };

    let final_report = cp.blob_purge(mode, a.apply, a.prefix.as_deref()).await?;

    // A storage error in the final report means the purge did NOT complete (non-zero exit). A 409
    // (unreferenced refused while a fallback is attached) or a 422 (no fallback for drained-source)
    // surfaced earlier as `ClientError::Refused` from `blob_purge`.
    let errored = final_report.get("error").is_some();

    // As with `drain`: on the incomplete path the report must reach the user before the non-zero
    // exit, but `emit` does not run on `Err` — so render it here (honoring `--json`), then fail.
    if errored {
        let mut out = std::io::stdout().lock();
        let _ = write_purge(&final_report, &mut out);
        let _ = out.flush();
        return Err(Error::PurgeIncomplete);
    }
    Ok(BlobOutput::Purge {
        report: final_report,
    })
}

/// Print the node's structured blob transition-mode state (`boatramp blob status`, v0.6.4): GET
/// `/api/blob-status` and report whether a read-fallback secondary is attached (mid-migration).
async fn status(cp: &client::ControlPlane) -> Result<BlobOutput> {
    let state = cp.blob_status().await?;
    Ok(BlobOutput::Status { state })
}

/// `boatramp blob verify`: list dead content-addressed references (referenced-but-missing blobs).
async fn verify(cp: &client::ControlPlane) -> Result<BlobOutput> {
    let state = cp.blob_verify().await?;
    Ok(BlobOutput::Verify { state })
}

/// Run the offline, node-local blob-backend migration (`boatramp blob migrate`). Resolves the SOURCE
/// and DESTINATION from `--from`/`--to` (each a node config file's `[serve]` blob block), defaulting an
/// omitted `--to` to the node config's OWN primary and an omitted `--from` to the node config's
/// `[serve.blob_fallback]` secondary (the zero-downtime drain one-liner). It echoes the resolved
/// backend identities, REFUSES if they resolve equal, then copies every object source→dest with the
/// [`boatramp_node::blob_migrate`] engine — and, on a verified fallback→primary drain, prints the
/// "safe to remove [serve].blob_fallback" signal.
async fn migrate(a: MigrateArgs) -> Result<BlobOutput> {
    let (source, dest) = resolve_sides(&a).await?;

    // Echo the RESOLVED source + destination identity before copying (never a credential) → tracing
    // (diagnostic/stderr); the identities also ride the typed result's `source`/`dest` facts.
    tracing::info!(source = %source.identity, dest = %dest.identity, "blob migrate: resolved backends");
    // Refuse a migration whose source and destination resolve to the SAME backend — a no-op at best,
    // an in-place corruption at worst.
    if source.identity == dest.identity {
        return Err(Error::SameSourceDest {
            identity: source.identity,
        });
    }
    // Whether this is the zero-downtime drain shape (source == the configured fallback secondary,
    // dest == the configured primary) — the case that, once verified, means the secondary is drained.
    let is_configured_drain = source.is_configured_fallback && dest.is_configured_primary;

    let opts = boatramp_node::blob_migrate::MigrateOptions {
        concurrency: a.concurrency,
        verify: !a.no_verify,
        dry_run: a.dry_run,
        prefix: a.prefix.clone(),
        // The offline CLI logs via tracing only — no streaming callback (that path is the
        // daemon-mediated `blob drain`, which wires an mpsc sink over the control-plane response).
        on_progress: None,
    };
    let report = boatramp_node::blob_migrate::migrate(source.storage, dest.storage, &opts).await?;

    // A verified fallback→primary drain: the secondary now has no object the primary lacks.
    let drained = report.verified && is_configured_drain;

    Ok(BlobOutput::Migrate {
        source: source.identity,
        dest: dest.identity,
        total_objects: report.total_objects,
        copied_objects: report.copied_objects,
        skipped_objects: report.skipped_objects,
        copied_bytes: report.copied_bytes,
        verified: report.verified,
        dry_run: a.dry_run,
        secondary_drained: drained,
    })
}

/// A built migration side: the backend, its human identity (for the echo + the equal-refusal), and
/// whether it came from the node config's configured fallback (source) / primary (dest) — which
/// together mark the zero-downtime drain shape that emits the "SAFE TO DROP FALLBACK" signal.
struct ResolvedSide {
    storage: std::sync::Arc<dyn boatramp_core::Storage>,
    identity: String,
    is_configured_fallback: bool,
    is_configured_primary: bool,
}

/// Resolve + build the source and destination sides from the CLI args, applying the defaults:
/// - SOURCE: `--from <config>`'s primary, else the `--node-config`'s `[serve.blob_fallback]` secondary
///   (error if neither).
/// - DEST: `--to <config>`'s primary, else the `--node-config`'s OWN primary.
async fn resolve_sides(a: &MigrateArgs) -> Result<(ResolvedSide, ResolvedSide)> {
    // SOURCE.
    let source = match a.from.as_ref() {
        Some(from) => build_primary_side("source", from).await?,
        None => {
            // No `--from`: drain the configured fallback secondary of the node config.
            let config = boatramp_node::config::ServerConfig::load(&a.node_config, None)?;
            let serve = config.serve.clone().unwrap_or_default();
            let Some(fb) = serve.blob_fallback.clone() else {
                return Err(Error::NoSource {
                    node_config: a.node_config.display().to_string(),
                });
            };
            build_fallback_side("source", &config, &fb).await?
        }
    };

    // DEST.
    let dest_path = a.to.clone().unwrap_or_else(|| a.node_config.clone());
    // The destination is a "configured primary" (for the drain signal) when it came from the node
    // config's own `[serve]` — i.e. `--to` was omitted so it defaulted to `--node-config`.
    let dest_is_configured_primary = a.to.is_none();
    let mut dest = build_primary_side("destination", &dest_path).await?;
    dest.is_configured_primary = dest_is_configured_primary;

    Ok((source, dest))
}

/// Build a side from a node config file's PRIMARY `[serve]` blob block: parse it into a
/// [`BlobArgs`](boatramp_node::blobs::BlobArgs), resolve an optional node-level sealed S3 credential
/// from `[serve.s3_credential]` (+ `[secrets]`), and construct the backend via `build_blobs` with NO
/// watcher provisioning (a migration never watches).
async fn build_primary_side(
    side: &'static str,
    config_path: &std::path::Path,
) -> Result<ResolvedSide> {
    let config = boatramp_node::config::ServerConfig::load(config_path, None)?;
    let serve = config.serve.clone().unwrap_or_default();
    let data_dir = serve
        .data_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("./data"));

    // The backend is the config's `[serve].blobs` (default `fs` when absent) — the config-level
    // analog of `serve`'s `--blobs` flag. All per-backend options come from the SAME `[serve]` block.
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
    if let Some(cred_cfg) = serve.s3_credential.clone() {
        blob_args.s3_credential =
            Some(resolve_side_credential(side, &config, &cred_cfg, &data_dir).await?);
    }
    let identity = backend_identity(&blob_args, &data_dir);
    let built = boatramp_node::blobs::build_blobs(&blob_args, &data_dir, None, None)
        .await
        .map_err(|source| Error::BackendBuild { side, source })?;
    Ok(ResolvedSide {
        storage: built.storage,
        identity,
        is_configured_fallback: false,
        is_configured_primary: false,
    })
}

/// Build a side from a `[serve.blob_fallback]` SECONDARY descriptor (the drain source). Uses the
/// node config's `[secrets]`/`[security]` for the secondary's OWN sealed credential, exactly like the
/// serve path resolves it.
async fn build_fallback_side(
    side: &'static str,
    config: &boatramp_node::config::ServerConfig,
    fb: &boatramp_node::config::BlobFallbackConfig,
) -> Result<ResolvedSide> {
    let serve = config.serve.clone().unwrap_or_default();
    let data_dir = serve
        .data_dir
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("./data"));

    let mut blob_args = boatramp_node::blobs::BlobArgs {
        blobs: fb.blobs.unwrap_or(boatramp_node::backends::BlobBackend::Fs),
        s3_bucket: fb.s3_bucket.clone(),
        s3_endpoint: fb.s3_endpoint.clone(),
        s3_region: fb.s3_region.clone(),
        s3_path_style: fb.s3_path_style,
        s3_credential: None,
        gcs_bucket: fb.gcs_bucket.clone(),
        gcs_endpoint: fb.gcs_endpoint.clone(),
        gcs_anonymous: fb.gcs_anonymous,
        azure_account: fb.azure_account.clone(),
        azure_container: fb.azure_container.clone(),
        azure_access_key: fb.azure_access_key.clone(),
        azure_emulator: fb.azure_emulator,
    };
    if let Some(cred_cfg) = fb.s3_credential.clone() {
        blob_args.s3_credential =
            Some(resolve_side_credential(side, config, &cred_cfg, &data_dir).await?);
    }
    let identity = backend_identity(&blob_args, &data_dir);
    let built = boatramp_node::blobs::build_blobs(&blob_args, &data_dir, None, None)
        .await
        .map_err(|source| Error::BackendBuild { side, source })?;
    Ok(ResolvedSide {
        storage: built.storage,
        identity,
        is_configured_fallback: true,
        is_configured_primary: false,
    })
}

/// Resolve a node-level sealed base S3 credential (#505) for a migration side — the same source the
/// serve path uses. A `boatramp:` sealed ref needs the control-plane KV, which this offline command
/// does not open; only `env:`/bare refs (posture-permitted) resolve here. The posture is read from the
/// same config so `allow_env_secret_refs` matches how the node would run.
async fn resolve_side_credential(
    side: &'static str,
    config: &boatramp_node::config::ServerConfig,
    cred_cfg: &boatramp_node::config::S3CredentialConfig,
    data_dir: &std::path::Path,
) -> Result<boatramp_node::s3_credential::SealedS3Credential> {
    use std::sync::Arc;
    let posture = config
        .security
        .clone()
        .unwrap_or_default()
        .resolve()
        .map_err(|e| Error::Envelope {
            side,
            reason: format!("resolving [security] posture: {e}"),
        })?;
    let envelope = build_secrets_envelope(side, config.secrets.as_ref(), data_dir)?;
    boatramp_node::s3_credential::resolve_s3_credential(
        cred_cfg,
        Arc::new(boatramp_core::kv::MemoryKv::new()),
        envelope,
        posture.allow_env_secret_refs,
        &boatramp_core::env::SystemEnv,
    )
    .await
    .map_err(|source| Error::Credential { side, source })
}

/// A short human identity for a built blob backend — the backend plus its bucket/path/endpoint. Used
/// for the resolved source/dest echo and the equal-refusal (never renders a credential). fs renders
/// its resolved `<data_dir>/blobs` root so two fs sides at different data_dirs compare distinct.
fn backend_identity(args: &boatramp_node::blobs::BlobArgs, data_dir: &std::path::Path) -> String {
    use boatramp_node::backends::BlobBackend;
    match args.blobs {
        BlobBackend::Fs => format!("fs {}", data_dir.join("blobs").display()),
        BlobBackend::S3 => format!(
            "s3 bucket={} endpoint={} region={} path_style={}",
            args.s3_bucket.as_deref().unwrap_or("?"),
            args.s3_endpoint.as_deref().unwrap_or("(default)"),
            args.s3_region.as_deref().unwrap_or("(default)"),
            args.s3_path_style
        ),
        BlobBackend::Gcs => format!(
            "gcs bucket={} endpoint={}",
            args.gcs_bucket.as_deref().unwrap_or("?"),
            args.gcs_endpoint.as_deref().unwrap_or("(default)")
        ),
        BlobBackend::Azure => format!(
            "azure account={} container={}",
            args.azure_account.as_deref().unwrap_or("?"),
            args.azure_container.as_deref().unwrap_or("?")
        ),
    }
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
async fn mint_upload(cp: &client::ControlPlane, a: MintUploadArgs) -> Result<BlobOutput> {
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
    Ok(BlobOutput::MintUpload {
        creds,
        emit: a.emit,
    })
}

/// Render a minted credential in the requested `--emit` form, byte-for-byte as the command printed it.
#[cfg(feature = "blob-upload")]
fn write_mint(
    c: &client::MintUploadResult,
    emit: Emit,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let is_presigned = c.kind == "presigned_put";
    match emit {
        Emit::Json => {
            // Re-serialize the deserialized struct verbatim (stable field order via serde).
            writeln!(
                w,
                "{}",
                serde_json::to_string_pretty(&mint_creds_value(c)).unwrap_or_default()
            )
        }
        Emit::Aws => {
            if is_presigned {
                // A presigned PUT is not an SDK profile — there is nothing to put in ~/.aws.
                tracing::warn!(
                    "# a presigned-put credential is a single URL, not an SDK profile; use --emit env or json"
                );
                write_presigned(c, w)
            } else {
                writeln!(w, "[boatramp-upload]")?;
                writeln!(w, "aws_access_key_id = {}", opt(&c.access_key_id))?;
                writeln!(w, "aws_secret_access_key = {}", opt(&c.secret))?;
                writeln!(w, "aws_session_token = {}", opt(&c.session_token))?;
                writeln!(w, "# region = {}", opt(&c.region))?;
                writeln!(w, "# endpoint_url = {}", opt(&c.endpoint))?;
                writeln!(w, "# addressing_style = path")?;
                writeln!(
                    w,
                    "# bucket = {}  (expires in {}s)",
                    opt(&c.bucket),
                    c.expires_in_secs
                )
            }
        }
        Emit::Rclone => {
            if is_presigned {
                tracing::warn!(
                    "# a presigned-put credential is a single URL, not an rclone remote; use --emit env or json"
                );
                write_presigned(c, w)
            } else {
                writeln!(w, "[boatramp-upload]")?;
                writeln!(w, "type = s3")?;
                writeln!(w, "provider = Other")?;
                writeln!(w, "access_key_id = {}", opt(&c.access_key_id))?;
                writeln!(w, "secret_access_key = {}", opt(&c.secret))?;
                writeln!(w, "session_token = {}", opt(&c.session_token))?;
                writeln!(w, "region = {}", opt(&c.region))?;
                writeln!(w, "endpoint = {}", opt(&c.endpoint))?;
                writeln!(w, "force_path_style = true")
            }
        }
        Emit::Env => {
            if is_presigned {
                write_presigned(c, w)
            } else {
                write_env(c, w)
            }
        }
        Emit::Human => {
            if is_presigned {
                writeln!(
                    w,
                    "Minted a presigned PUT credential (single-key, browser-friendly):"
                )?;
                write_presigned(c, w)
            } else {
                writeln!(
                    w,
                    "Minted temporary S3 credentials (path-style; expires in {}s):",
                    c.expires_in_secs
                )?;
                writeln!(w, "  bucket   {}", opt(&c.bucket))?;
                writeln!(w, "  endpoint {}", opt(&c.endpoint))?;
                writeln!(w, "  region   {}", opt(&c.region))?;
                if !c.enforced.is_empty() {
                    writeln!(w, "  enforced {}", c.enforced.join(", "))?;
                }
                if !c.advisory.is_empty() {
                    writeln!(w, "  advisory {}", c.advisory.join(", "))?;
                }
                writeln!(w)?;
                write_env(c, w)
            }
        }
    }
}

/// Write the shell `export` block an S3 SDK reads for temp-credentials.
#[cfg(feature = "blob-upload")]
fn write_env(c: &client::MintUploadResult, w: &mut dyn std::io::Write) -> std::io::Result<()> {
    writeln!(w, "export AWS_ACCESS_KEY_ID={}", opt(&c.access_key_id))?;
    writeln!(w, "export AWS_SECRET_ACCESS_KEY={}", opt(&c.secret))?;
    writeln!(w, "export AWS_SESSION_TOKEN={}", opt(&c.session_token))?;
    writeln!(w, "export AWS_REGION={}", opt(&c.region))?;
    writeln!(w, "export AWS_ENDPOINT_URL={}", opt(&c.endpoint))?;
    // Path-style is mandatory for the local face (bucket = container in the path).
    writeln!(w, "export AWS_S3_FORCE_PATH_STYLE=true")?;
    writeln!(w, "# then: aws s3 cp <file> s3://{}/<key>", opt(&c.bucket))
}

/// Write a presigned-put credential (the URL + any required headers + a ready `curl`).
#[cfg(feature = "blob-upload")]
fn write_presigned(
    c: &client::MintUploadResult,
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    let url = opt(&c.url);
    writeln!(w, "  method  {}", opt(&c.method))?;
    writeln!(w, "  url     {url}")?;
    for (k, v) in &c.required_headers {
        writeln!(w, "  header  {k}: {v}")?;
    }
    writeln!(w, "  expires in {}s", c.expires_in_secs)?;
    let hdrs: String = c
        .required_headers
        .iter()
        .map(|(k, v)| format!(" -H '{k}: {v}'"))
        .collect();
    writeln!(
        w,
        "# curl -X {} '{url}'{hdrs} --data-binary @<file>",
        opt(&c.method)
    )
}

/// Format an optional string field for display ("" when absent).
#[cfg(feature = "blob-upload")]
fn opt(v: &Option<String>) -> &str {
    v.as_deref().unwrap_or("")
}
