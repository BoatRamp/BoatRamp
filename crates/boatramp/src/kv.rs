//! `boatramp kv` — offline maintenance of the control-plane SlateDB store (v0.9.0 KV-recovery).
//!
//! - **`repair`** — the one-shot WAL-tail quarantine: DRY-RUN by default (prints the plan), quarantines
//!   a torn TRAILING tail on `--apply`. The OFFLINE tail-only tool.
//! - **`recover`** — the SUPERSET of `repair` (C9/C10): DRY-RUN diagnoses the WHOLE store; `--apply`
//!   repairs a recoverable shape in place; for an UNSAFE shape (a torn compacted/L0 SST) beyond
//!   auto-heal, `--adopt-volume <mounted-path>` validates + adopts an operator-attached CLEAN volume
//!   snapshot (verify-open → swap, retaining the crashed copy).
//! - **`checkpoint`** — flush the store to a consistent, GUARANTEED-BOOTABLE on-disk state (drain
//!   WAL→L0) so a volume snapshot is reliably bootable. OFFLINE (open + close); the LIVE forms are the
//!   automatic `[serve.kv] checkpoint_interval` cadence + on-demand `POST /api/kv-checkpoint`.
//! - **`status`** — show the durable degraded-state breadcrumb (`{root}/DEGRADED.json`) a self-heal
//!   wrote; `--ack` clears it. Reads WITHOUT opening the store, so it works even when the store won't boot.
//!
//! The data-loss guard lives entirely in the core: it quarantines ONLY a physically-torn object
//! that is strictly trailing AND strictly beyond the durable frontier, and REFUSES (fails loud)
//! on a mid-range gap, a WAL-id hole, or an unreadable manifest. See [`boatramp_storage::wal_repair`].
//! The self-heal-on-open default (`boatramp serve`) is the automatic boot-time counterpart; a stale
//! `BOATRAMP_KV_REPAIR=1` is now a no-op (self-heal is the default).

use std::path::PathBuf;
use std::sync::Arc;

use boatramp_storage::kv_slatedb::{
    RepairMode, RepairReport, clear_degraded_marker, read_degraded_marker,
};
use boatramp_storage::object_store::ObjectStore;
use boatramp_storage::wal_repair::{
    CompactionsRecovery, CompactionsResetReport, ManifestRecovery, ManifestRecoveryReport,
    WalRepairError, recover_corrupt_compactions, recover_last_good_manifest, repair_wal_tail,
};
use clap::{Args, Subcommand};

/// `boatramp kv` command group.
#[derive(Debug, Args)]
pub struct KvArgs {
    #[command(subcommand)]
    command: KvCommand,
}

#[derive(Debug, Subcommand)]
enum KvCommand {
    /// Repair a torn TRAILING WAL tail on the control-plane SlateDB store so it opens again
    /// (crash / snapshot partial-tail recovery). DRY-RUN by default (prints the plan); pass
    /// `--apply` to quarantine the torn tail. Refuses on a mid-range gap or unreadable manifest.
    /// This is the OFFLINE tail-only quarantine; `boatramp kv recover` is the daemon-mediated
    /// superset (in-place robust repair, else adopt a clean volume).
    Repair(RepairArgs),
    /// Show the control-plane KV degraded state (v0.9.0 KV-recovery, C6): whether a self-heal-on-open
    /// quarantined a torn WAL tail (from the durable `{root}/DEGRADED.json` breadcrumb). `--ack`
    /// clears the breadcrumb once the loss window has been reviewed. Reads the breadcrumb WITHOUT
    /// opening the store, so it works even when the store will not boot.
    Status(StatusArgs),
    /// Flush the control-plane store to a consistent, GUARANTEED-BOOTABLE on-disk state (drain
    /// WAL→L0, advance the durable frontier), so an operator can snapshot the volume safely. OFFLINE
    /// by default (the daemon must be stopped — SlateDB is single-writer). Pass `--live` to checkpoint
    /// a RUNNING daemon over `POST /api/kv-checkpoint` (System·Admin) WITHOUT stopping it — the client
    /// verb for the on-demand live checkpoint (the automatic form is the `[serve.kv]
    /// checkpoint_interval` cadence). The offline form fails loud if the store is torn (run `kv
    /// recover` first). NOTE (fsync): a snapshot is bootable only after a checkpoint drained WAL→L0;
    /// v0.11.0 fsync makes even a mid-close hard stop non-corrupting, but a checkpoint before the
    /// snapshot is still the reliable point-in-time.
    Checkpoint(CheckpointArgs),
    /// Recover an unbootable control-plane store (v0.9.0 KV-recovery, C9/C10) — the SUPERSET of
    /// `kv repair`. DRY-RUN by default (diagnose the WHOLE store + print the plan). `--apply`
    /// repairs a recoverable shape IN PLACE (quarantine a safe trailing torn tail, retaining the
    /// torn bytes for forensics). For an UNSAFE shape (a torn compacted/L0 SST), attach a clean
    /// volume snapshot and pass `--adopt-volume <mounted-path>`: it validates the attached store
    /// opens clean + zero-torn BEFORE adopting, prints the discard-delta, and (with `--apply`)
    /// adopts it via verify-open-then-swap, RETAINING the crashed copy until the adopt is verified.
    Recover(RecoverArgs),
    /// Export the control-plane KV to a PORTABLE, backend-agnostic dump FILE (kv-sql WS7). A LOGICAL
    /// dump captures CONTENT (`{key, value, version}` records), NOT the physical LSM/manifest/
    /// `.compactions` — so a restore (`kv import`) rebuilds a FRESH clean store, structurally immune
    /// to the torn-manifest / corrupt-`.compactions` physical-corruption classes that make volume
    /// snapshots useless. Works over ANY backend. The dump carries SEALED ciphertext for secrets
    /// (sealing is pre-put — NO plaintext) + plaintext control-plane config/RBAC, and NEVER the
    /// envelope KEK (a restore needs the separately-held key). OFFLINE/quiesced by default (the
    /// daemon should be stopped — a live single-writer source races concurrent writes). SENSITIVE —
    /// op-gated over the API (`GET /api/kv-export`, System·Admin); protect the file at rest.
    Export(ExportArgs),
    /// Import a portable dump FILE (from `kv export`) into a control-plane KV (kv-sql WS7). DRY-RUN by
    /// default (prints the plan: source key count, destination state, what would be copied);
    /// `--apply` executes, then VERIFIES (re-reads every key, compares bytes + count). REFUSES a
    /// non-empty destination — or one with an existing control-plane identity — unless `--force`
    /// (never silently COMMINGLE two control planes). The reserved `_cp/*` / `_inval/*` feeds are
    /// never imported (they regenerate). OFFLINE/quiesced by default.
    Import(ImportArgs),
    /// Migrate a control-plane KV store→store over the portable dump (kv-sql WS7) — the SlateDB⇄SQL
    /// adoption path (and back). DRY-RUN by default (prints the plan); `--apply` copies + VERIFIES
    /// (bytes + count). REFUSES a non-empty `--to` destination unless `--force`. Reserved `_cp/*` /
    /// `_inval/*` feeds are skipped (regenerated). OFFLINE/quiesced by default.
    Migrate(MigrateArgs),
    /// Report the control-plane SlateDB store's PHYSICAL vs LOGICAL size (kv-data-observability) — the
    /// diagnostic the 17.2 GB ENOSPC incident lacked. PHYSICAL = a walk of every object under the
    /// store root (live AND superseded SSTs, every manifest version, every WAL object), broken down
    /// per subdir (`wal/`, `compacted/`, `manifest/`, `compactions/`). LOGICAL = the bytes the CURRENT
    /// manifest actually references (live SSTs). The gap is reclaimable garbage — `boatramp kv compact`
    /// reclaims it. Pure read-only; safe against a quiesced store.
    Stats(StatsArgs),
    /// Compact + garbage-collect the control-plane SlateDB store to reclaim the physical-vs-logical gap
    /// (kv-data-observability). DRY-RUN by default (prints the physical/logical stats + the reclaimable
    /// delta, and runs GC in dry-run so slatedb logs the delete candidates — mutates NOTHING). `--apply`
    /// performs a one-shot FULL MERGE of every L0 SST + sorted run into one sorted run, then GCs the
    /// now-unreferenced garbage (superseded SSTs + old manifests + replayed WAL). GC deletion is
    /// IRREVERSIBLE. OFFLINE ONLY: STOP the daemon first — SlateDB is single-writer (manifest fencing)
    /// and a running daemon runs its own embedded compactor + GC, which this would contend. Like
    /// `kv repair` / `kv recover`, it addresses `<data-dir>/kv-slate` directly.
    Compact(CompactArgs),
}

/// A source/destination KV ENDPOINT descriptor for `export`/`import`/`migrate` — `scheme:rest`:
/// - `memory` — an ephemeral in-memory store (tests / piping).
/// - `slatedb:<data-dir>` — the local SlateDB control-plane store under `<data-dir>/kv-slate`
///   (default `./data` when `rest` is empty).
/// - `sqlite:<path>` — an embedded SQLite/libsql file.
/// - `postgres:<ENV_VAR>` / `mysql:<ENV_VAR>` — an external primary; `ENV_VAR` NAMES the env var
///   holding the connection URL (UX-C2 — never a raw URL on the command line/in config).
async fn open_endpoint(
    desc: &str,
) -> Result<std::sync::Arc<dyn boatramp_core::kv::KvStore>, Error> {
    use boatramp_core::kv::KvOpenPolicy;
    use boatramp_node::backends::{KvBackend, build_kv};
    use boatramp_node::config::SqlKvConfig;
    use std::path::Path;

    let (scheme, rest) = desc.split_once(':').unwrap_or((desc, ""));
    let sql = |kind: &str, url_env: Option<String>, path: Option<String>| SqlKvConfig {
        kind: kind.to_string(),
        url_env,
        path,
        pool_max: None,
    };
    let built = match scheme {
        "memory" => {
            build_kv(
                KvBackend::Memory,
                Path::new("."),
                None,
                KvOpenPolicy::SelfHeal,
                None,
            )
            .await
        }
        "slatedb" => {
            let data_dir = if rest.is_empty() { "./data" } else { rest };
            build_kv(
                KvBackend::Slatedb,
                Path::new(data_dir),
                None,
                KvOpenPolicy::SelfHeal,
                None,
            )
            .await
        }
        "sqlite" | "sqlite3" | "libsql" => {
            if rest.is_empty() {
                return Err(Error::Endpoint(
                    "`sqlite:` needs a file path (e.g. `sqlite:/data/kv.db`)".to_string(),
                ));
            }
            let cfg = sql("sqlite", None, Some(rest.to_string()));
            build_kv(
                KvBackend::Sql,
                Path::new("."),
                None,
                KvOpenPolicy::SelfHeal,
                Some(&cfg),
            )
            .await
        }
        "postgres" | "postgresql" | "pg" => {
            if rest.is_empty() {
                return Err(Error::Endpoint(
                    "`postgres:` needs the NAME of the env var holding the URL (e.g. \
                     `postgres:BOATRAMP_KV_SQL_URL`)"
                        .to_string(),
                ));
            }
            let cfg = sql("postgres", Some(rest.to_string()), None);
            build_kv(
                KvBackend::Sql,
                Path::new("."),
                None,
                KvOpenPolicy::SelfHeal,
                Some(&cfg),
            )
            .await
        }
        "mysql" | "mariadb" => {
            if rest.is_empty() {
                return Err(Error::Endpoint(
                    "`mysql:` needs the NAME of the env var holding the URL (e.g. \
                     `mysql:BOATRAMP_KV_SQL_URL`)"
                        .to_string(),
                ));
            }
            let cfg = sql("mysql", Some(rest.to_string()), None);
            build_kv(
                KvBackend::Sql,
                Path::new("."),
                None,
                KvOpenPolicy::SelfHeal,
                Some(&cfg),
            )
            .await
        }
        other => {
            return Err(Error::Endpoint(format!(
                "unknown KV endpoint {other:?}: expected memory | slatedb:<data-dir> | \
                 sqlite:<path> | postgres:<ENV_VAR> | mysql:<ENV_VAR>"
            )));
        }
    };
    built.map_err(|e| Error::Endpoint(e.to_string()))
}

/// Current unix-seconds timestamp for a dump header (best-effort; a pre-epoch clock stamps 0).
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug, Args)]
struct ExportArgs {
    /// The KV endpoint to export (see the subcommand help for the descriptor forms). Defaults to the
    /// local SlateDB store under `./data/kv-slate`.
    #[arg(long, default_value = "slatedb:./data")]
    store: String,

    /// Write the portable dump to this file (the sensitive dump — protect it at rest).
    #[arg(long, value_name = "FILE")]
    out: std::path::PathBuf,
}

#[derive(Debug, Args)]
struct ImportArgs {
    /// The portable dump file to import (produced by `kv export` / `GET /api/kv-export`).
    #[arg(value_name = "FILE")]
    file: std::path::PathBuf,

    /// The destination KV endpoint (see the subcommand help). Defaults to the local SlateDB store.
    #[arg(long, default_value = "slatedb:./data")]
    store: String,

    /// Perform the import. Without this the command is a DRY-RUN: it prints the plan and mutates
    /// NOTHING.
    #[arg(long)]
    apply: bool,

    /// Overlay the dump onto a NON-EMPTY destination (or one with an existing control-plane
    /// identity). Without it, a non-empty destination is REFUSED to avoid commingling two control
    /// planes.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct MigrateArgs {
    /// The SOURCE KV endpoint (see the subcommand help for the descriptor forms).
    #[arg(long, value_name = "DESCRIPTOR")]
    from: String,

    /// The DESTINATION KV endpoint.
    #[arg(long, value_name = "DESCRIPTOR")]
    to: String,

    /// Perform the migration. Without this the command is a DRY-RUN: it prints the plan and mutates
    /// NOTHING.
    #[arg(long)]
    apply: bool,

    /// Overlay onto a NON-EMPTY `--to` destination (or one with an existing control-plane identity).
    /// Without it, a non-empty destination is REFUSED (commingle hazard).
    #[arg(long)]
    force: bool,
}

/// The store-addressing flags shared by every `boatramp kv` subcommand — they build EXACTLY the
/// object store + root the opener uses (R2/S3 rooted at the prefix, or the local fs rooted at `kv`),
/// so an offline command sees the same objects the serving open would.
#[derive(Debug, Args)]
struct StoreAddr {
    /// Which control-plane KV backend this node runs (matches `serve --kv` / `BOATRAMP_KV`). These
    /// `boatramp kv` verbs are SlateDB maintenance/recovery tools (manifest / WAL / `.compactions`);
    /// they do NOT apply to a `sql` backend (the SQL engine's own crash recovery handles that), nor
    /// to `memory` / `cloudflare`. A non-SlateDB backend gets a clear "not applicable" message rather
    /// than building a bogus SlateDB object store against a path that isn't one.
    #[arg(
        long = "kv",
        value_enum,
        env = "BOATRAMP_KV",
        default_value_t = boatramp_node::backends::KvBackend::Slatedb
    )]
    backend: boatramp_node::backends::KvBackend,

    /// The server data directory (as passed to `boatramp serve --data-dir`). The local SlateDB
    /// control-plane store lives under `<data-dir>/kv-slate` (root `kv`). Defaults to `./data`.
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,

    /// Target the R2/S3-backed store instead of the local disk store (matches `serve --kv-s3`).
    /// Uses the ambient AWS credentials; addressing comes from the `--s3-*` flags below.
    #[arg(long, env = "BOATRAMP_KV_S3")]
    kv_s3: bool,

    /// S3/R2 bucket for `--kv-s3`.
    #[arg(long, env = "BOATRAMP_S3_BUCKET")]
    s3_bucket: Option<String>,

    /// S3/R2 endpoint for `--kv-s3` (R2: `https://<account>.r2.cloudflarestorage.com`).
    #[arg(long, env = "BOATRAMP_S3_ENDPOINT")]
    s3_endpoint: Option<String>,

    /// S3/R2 region for `--kv-s3` (R2 uses `auto`).
    #[arg(long, env = "BOATRAMP_S3_REGION")]
    s3_region: Option<String>,

    /// Path-style addressing for `--kv-s3` (R2 accepts it).
    #[arg(long, env = "BOATRAMP_S3_PATH_STYLE")]
    s3_path_style: bool,

    /// Key prefix (root) of the `--kv-s3` store within the bucket (matches `serve --kv-s3-prefix`).
    #[arg(long, env = "BOATRAMP_KV_S3_PREFIX", default_value = "_kv")]
    kv_s3_prefix: String,
}

impl StoreAddr {
    /// Open the control-plane SlateDB store this addressing points at, with `policy` (offline —
    /// the daemon MUST be down, since SlateDB is single-writer). Used by `kv checkpoint`
    /// (open + close = drain WAL→L0) and by `kv recover --adopt-volume` (verify a volume opens).
    async fn open_store(
        &self,
        policy: boatramp_storage::kv_slatedb::KvOpenPolicy,
    ) -> Result<boatramp_storage::SlateKv, Error> {
        let flush = boatramp_node::backends::CONTROL_PLANE_FLUSH;
        if self.kv_s3 {
            let cfg = boatramp_storage::S3StoreConfig {
                bucket: self.s3_bucket.clone().unwrap_or_default(),
                endpoint: self.s3_endpoint.clone(),
                region: self.s3_region.clone(),
                path_style: self.s3_path_style,
            };
            boatramp_storage::SlateKv::open_s3_with_flush_policy(
                &cfg,
                &self.kv_s3_prefix,
                flush,
                policy,
            )
            .await
            .map_err(|e| Error::Store(e.to_string()))
        } else {
            boatramp_storage::SlateKv::open_local_with_flush_policy(
                self.data_dir.join("kv-slate"),
                flush,
                policy,
            )
            .await
            .map_err(|e| Error::Store(e.to_string()))
        }
    }

    /// `Some(message)` when the configured backend is NOT SlateDB — these verbs are SlateDB-specific
    /// (C7). The caller PRINTS the message and returns `Ok` (a clean "not applicable", not an error),
    /// rather than building a bogus object store. The message is backend-specific + actionable.
    fn not_applicable(&self, verb: &str) -> Option<String> {
        use boatramp_node::backends::KvBackend;
        match self.backend {
            KvBackend::Slatedb => None,
            KvBackend::Sql => Some(format!(
                "`boatramp kv {verb}` does NOT apply to the `sql` control-plane KV backend.\n\
                 It is a SlateDB-specific maintenance/recovery tool (manifest / WAL / `.compactions`); \
                 a SQL backend has none of those — PostgreSQL/SQLite crash recovery is the engine's \
                 own (WAL + fsync), and durability is the transaction COMMIT. Use your database's \
                 native tooling for backup/restore/repair. The running node's SQL KV health is \
                 reported at `GET /api/kv-status` (and logged in the startup banner)."
            )),
            KvBackend::Memory => Some(format!(
                "`boatramp kv {verb}` does NOT apply to the `memory` backend — it is ephemeral \
                 (lost on restart), so there is nothing durable to {verb}."
            )),
            KvBackend::Cloudflare => Some(format!(
                "`boatramp kv {verb}` does NOT apply to the `cloudflare` backend — Cloudflare KV is a \
                 managed remote store with no local manifest/WAL to {verb}."
            )),
        }
    }

    /// Build the `(object store, root)` the opener uses.
    fn build(&self) -> Result<(Arc<dyn ObjectStore>, String), Error> {
        if self.kv_s3 {
            let cfg = boatramp_storage::S3StoreConfig {
                bucket: self.s3_bucket.clone().unwrap_or_default(),
                endpoint: self.s3_endpoint.clone(),
                region: self.s3_region.clone(),
                path_style: self.s3_path_style,
            };
            let store = boatramp_storage::kv_slatedb::s3_object_store(&cfg)
                .map_err(|e| Error::Store(e.to_string()))?;
            Ok((store, self.kv_s3_prefix.clone()))
        } else {
            let dir = self.data_dir.join("kv-slate");
            let fs = boatramp_storage::kv_slatedb::local_object_store(&dir)
                .map_err(|e| Error::Store(e.to_string()))?;
            Ok((Arc::new(fs), "kv".to_string()))
        }
    }
}

#[derive(Debug, Args)]
struct RepairArgs {
    #[command(flatten)]
    addr: StoreAddr,

    /// Perform the quarantine. Without this the command is a DRY-RUN: it prints the plan and
    /// mutates NOTHING.
    #[arg(long)]
    apply: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    #[command(flatten)]
    addr: StoreAddr,

    /// Acknowledge + CLEAR the DEGRADED breadcrumb (after reviewing the loss window). Idempotent —
    /// clearing an absent breadcrumb is a no-op.
    #[arg(long)]
    ack: bool,
}

#[derive(Debug, Args)]
struct RecoverArgs {
    #[command(flatten)]
    addr: StoreAddr,

    /// Perform the recovery (in-place repair, or adopt the attached volume). Without this the
    /// command is a DRY-RUN: it diagnoses + prints the plan and mutates NOTHING.
    #[arg(long)]
    apply: bool,

    /// Adopt an operator-attached CLEAN volume snapshot mounted at this path (expects its
    /// `kv-slate` store underneath) INSTEAD of an in-place repair — for a shape beyond auto-heal
    /// (a torn compacted/L0 SST). The attached store is validated (opens clean + zero-torn) BEFORE
    /// adopting; `--apply` swaps it in, RETAINING the crashed copy until the adopt is verified.
    /// boatramp does NOT create/destroy fly volumes — attach the snapshot volume with the fly CLI
    /// first (`fly volumes create` from a snapshot, then mount it). Local-disk / fly-volume only.
    #[arg(long, value_name = "MOUNTED_PATH")]
    adopt_volume: Option<PathBuf>,
}

/// Arguments for `boatramp kv checkpoint`.
#[derive(Debug, Args)]
struct CheckpointArgs {
    #[command(flatten)]
    addr: StoreAddr,

    /// Checkpoint a RUNNING daemon over `POST /api/kv-checkpoint` (System·Admin) instead of the offline
    /// open+close. The live form advances the durable frontier WITHOUT stopping the writer, so a
    /// snapshot of the running node is guaranteed-bootable. Requires `--server`/`--remote` (or a
    /// configured `[deploy].server`).
    #[arg(long)]
    live: bool,

    /// The running daemon URL for `--live` (else the configured `[deploy].server`/`BOATRAMP_SERVER`).
    #[arg(long, value_name = "URL")]
    server: Option<String>,
}

/// Arguments for `boatramp kv stats`.
#[derive(Debug, Args)]
struct StatsArgs {
    #[command(flatten)]
    addr: StoreAddr,
}

/// Arguments for `boatramp kv compact`.
#[derive(Debug, Args)]
struct CompactArgs {
    #[command(flatten)]
    addr: StoreAddr,

    /// Perform the compaction + GC reclaim. Without this the command is a DRY-RUN: it prints the
    /// physical/logical stats and the reclaimable delta, runs GC in dry-run (slatedb logs the delete
    /// candidates), and mutates NOTHING. `--apply` runs the full-merge compaction then the
    /// IRREVERSIBLE GC. OFFLINE ONLY — stop the daemon first.
    #[arg(long)]
    apply: bool,

    /// Max seconds to wait for the full-merge compaction to land before stopping the compactor (a
    /// large store merges a lot of data). Default 3600 (1 hour). Only used with `--apply`.
    #[arg(long, value_name = "SECONDS", default_value_t = 3600)]
    timeout_secs: u64,
}

/// Errors surfaced by `boatramp kv`.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Building the object store to operate on (bad `--kv-s3` addressing / local dir).
    #[error("kv: could not build the store: {0}")]
    Store(String),
    /// The repair itself refused or failed (loud — the caller must not proceed to serve).
    #[error(transparent)]
    Repair(#[from] WalRepairError),
    /// A `--live` control-plane request failed (no server, auth, or a server-side refusal).
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// A bad / unbuildable `export`/`import`/`migrate` KV endpoint descriptor.
    #[error("kv: {0}")]
    Endpoint(String),
    /// Reading/writing the dump file (`export --out` / `import <file>`).
    #[error("kv: dump file i/o error: {0}")]
    Io(#[from] std::io::Error),
    /// A corrupt / foreign / truncated dump file on `import`.
    #[error(transparent)]
    Dump(#[from] boatramp_core::kv_dump::DumpError),
    /// An `import`/`migrate` apply failure (commingle refusal, write, or the byte/count verify).
    #[error(transparent)]
    Import(#[from] boatramp_core::kv_dump::ImportError),
}

/// The typed result of a `boatramp kv` subcommand, rendered once by [`crate::output`] as the
/// historical human text or as JSON. Each subcommand's RESULT/DATA rides a struct-variant carrying
/// the same facts the human text shows; transient progress/diagnostics go to `tracing` instead.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
// A short-lived, once-per-invocation result value (built then immediately rendered by `emit`), so the
// spread between the stats-bearing variants and the one-line acks does not matter — boxing would only
// obscure the shape and the JSON/Debug output.
#[allow(clippy::large_enum_variant)]
pub enum KvOutput {
    /// A verb was invoked against a non-SlateDB control-plane backend it does not apply to (C7).
    NotApplicable { message: String },
    /// `kv export` wrote a portable dump.
    Export {
        records: usize,
        bytes: usize,
        store: String,
        out: String,
    },
    /// `kv import` DRY-RUN plan.
    ImportPlan {
        store: String,
        format_version: u32,
        created_at: u64,
        source_entries: usize,
        source_reserved_skipped: usize,
        dest_user_keys: usize,
        dest_reserved_keys: usize,
        dest_has_control_plane_id: bool,
        dest_pristine: bool,
        would_write: usize,
        would_refuse_commingle: bool,
    },
    /// `kv import --apply` outcome.
    ImportApplied {
        store: String,
        written: usize,
        verified: usize,
    },
    /// `kv migrate` DRY-RUN plan.
    MigratePlan {
        from: String,
        to: String,
        source_entries: usize,
        dest_user_keys: usize,
        dest_reserved_keys: usize,
        dest_has_control_plane_id: bool,
        dest_pristine: bool,
        would_write: usize,
        would_refuse_commingle: bool,
    },
    /// `kv migrate --apply` outcome.
    MigrateApplied {
        from: String,
        to: String,
        written: usize,
        verified: usize,
    },
    /// `kv repair` plan/outcome.
    Repair {
        report: RepairReportView,
        /// Whether `--apply` was passed (the report label); distinct from whether a mutation landed.
        applied_mode: bool,
    },
    /// `kv status --ack` — whether a breadcrumb existed and was cleared.
    StatusAck { cleared: bool },
    /// `kv status` — the durable DEGRADED breadcrumb (or `None` when the store is clean).
    Status {
        marker: Option<boatramp_core::kv::DegradedMarker>,
    },
    /// `kv checkpoint --live` — the server's response line.
    CheckpointLive { server: String, message: String },
    /// `kv checkpoint` (offline open+close).
    CheckpointOffline,
    /// `kv recover` — corrupt-`.compactions` reset plan/outcome.
    RecoverCompactions {
        report: CompactionsResetView,
        applied_mode: bool,
    },
    /// `kv recover` — in-place WAL-tail plan/outcome (the superset of `kv repair`).
    RecoverWal {
        report: RepairReportView,
        applied_mode: bool,
    },
    /// `kv recover` — last-good manifest-generation rollback plan/outcome.
    RecoverManifest {
        report: ManifestRecoveryView,
        applied_mode: bool,
    },
    /// `kv recover --adopt-volume` DRY-RUN (validate + discard-delta).
    AdoptVolumeDryRun {
        volume_store: String,
        target_store: String,
    },
    /// `kv recover --adopt-volume --apply` outcome.
    AdoptVolumeApplied {
        volume_store: String,
        target_store: String,
        retained: String,
    },
    /// `kv stats` — physical-vs-logical footprint.
    Stats { stats: KvStatsView },
    /// `kv compact` DRY-RUN — current footprint.
    CompactDryRun { stats: KvStatsView },
    /// `kv compact --apply` — before/after footprint, compaction + GC outcome.
    CompactApply {
        before: KvStatsView,
        after: KvStatsView,
        compaction: KvCompactView,
        timeout_secs: u64,
        dropped_checkpoints: usize,
    },
}

/// One WAL candidate beyond the frontier (serializable mirror of the core `WalCandidate`).
#[derive(Debug, serde::Serialize)]
pub struct WalCandidateView {
    pub id: u64,
    pub size: u64,
    /// The footer-probe class (the `WalClass` debug spelling, e.g. `Torn` / `Readable` / `Fence`).
    pub class: String,
}

/// A torn SST object outside the safe WAL-tail scope (serializable mirror of the core `TornObject`).
#[derive(Debug, serde::Serialize)]
pub struct TornObjectView {
    pub path: String,
    pub size: u64,
    pub class: String,
    pub kind: String,
}

/// Serializable mirror of a [`RepairReport`].
#[derive(Debug, serde::Serialize)]
pub struct RepairReportView {
    pub frontier: u64,
    pub candidates: Vec<WalCandidateView>,
    pub quarantined: Vec<u64>,
    pub quarantine_dir: Option<String>,
    pub applied: bool,
    pub out_of_scope_torn: Vec<TornObjectView>,
}

impl RepairReportView {
    fn from_report(r: &RepairReport) -> Self {
        Self {
            frontier: r.frontier,
            candidates: r
                .candidates
                .iter()
                .map(|c| WalCandidateView {
                    id: c.id,
                    size: c.size,
                    class: format!("{:?}", c.class),
                })
                .collect(),
            quarantined: r.quarantined.clone(),
            quarantine_dir: r.quarantine_dir.clone(),
            applied: r.applied,
            out_of_scope_torn: r
                .out_of_scope_torn
                .iter()
                .map(|t| TornObjectView {
                    path: t.path.clone(),
                    size: t.size,
                    class: format!("{:?}", t.class),
                    kind: format!("{:?}", t.kind),
                })
                .collect(),
        }
    }

    /// Mirrors `RepairReport::is_noop`.
    fn is_noop(&self) -> bool {
        self.quarantined.is_empty() && self.out_of_scope_torn.is_empty()
    }
}

/// Serializable mirror of a [`CompactionsResetReport`].
#[derive(Debug, serde::Serialize)]
pub struct CompactionsResetView {
    pub quarantined_compactions_ids: Vec<u64>,
    pub quarantine_dir: Option<String>,
    pub boundary_removed: bool,
    pub applied: bool,
}

impl CompactionsResetView {
    fn from_report(r: &CompactionsResetReport) -> Self {
        Self {
            quarantined_compactions_ids: r.quarantined_compactions_ids.clone(),
            quarantine_dir: r.quarantine_dir.clone(),
            boundary_removed: r.boundary_removed,
            applied: r.applied,
        }
    }
}

/// One rung of the manifest generation-walk ladder (mirror of the core `ManifestCandidate`).
#[derive(Debug, serde::Serialize)]
pub struct ManifestCandidateView {
    pub generation: u64,
    pub frontier: Option<u64>,
    pub status: String,
}

/// Serializable mirror of a [`ManifestRecoveryReport`].
#[derive(Debug, serde::Serialize)]
pub struct ManifestRecoveryView {
    pub rolled_back_to_generation: u64,
    pub frontier: u64,
    pub quarantined_manifest_ids: Vec<u64>,
    pub manifest_quarantine_dir: Option<String>,
    pub wal_repair: RepairReportView,
    pub orphaned_nonacked_objects: Vec<String>,
    pub candidate_ladder: Vec<ManifestCandidateView>,
    pub applied: bool,
}

impl ManifestRecoveryView {
    fn from_report(r: &ManifestRecoveryReport) -> Self {
        Self {
            rolled_back_to_generation: r.rolled_back_to_generation,
            frontier: r.frontier,
            quarantined_manifest_ids: r.quarantined_manifest_ids.clone(),
            manifest_quarantine_dir: r.manifest_quarantine_dir.clone(),
            wal_repair: RepairReportView::from_report(&r.wal_repair),
            orphaned_nonacked_objects: r.orphaned_nonacked_objects.clone(),
            candidate_ladder: r
                .candidate_ladder
                .iter()
                .map(|c| ManifestCandidateView {
                    generation: c.generation,
                    frontier: c.frontier,
                    status: c.status.clone(),
                })
                .collect(),
            applied: r.applied,
        }
    }
}

/// Per-subdir physical footprint (mirror of the storage `KvDirStat`).
#[derive(Debug, serde::Serialize)]
pub struct KvDirStatView {
    pub name: String,
    pub objects: u64,
    pub bytes: u64,
}

/// Physical-vs-logical store footprint (mirror of `KvPhysicalStats` + `KvLogicalStats`).
#[derive(Debug, serde::Serialize)]
pub struct KvStatsView {
    pub physical_total_bytes: u64,
    pub physical_total_objects: u64,
    pub logical_live_bytes: u64,
    pub logical_live_sst_count: u64,
    pub manifest_id: u64,
    pub l0_count: u64,
    pub sorted_run_count: u64,
    pub dirs: Vec<KvDirStatView>,
}

impl KvStatsView {
    fn from_stats(
        physical: &boatramp_storage::kv_slatedb::KvPhysicalStats,
        logical: &boatramp_storage::kv_slatedb::KvLogicalStats,
    ) -> Self {
        Self {
            physical_total_bytes: physical.total_bytes,
            physical_total_objects: physical.total_objects,
            logical_live_bytes: logical.live_bytes,
            logical_live_sst_count: logical.live_sst_count,
            manifest_id: logical.manifest_id,
            l0_count: logical.l0_count,
            sorted_run_count: logical.sorted_run_count,
            dirs: physical
                .dirs
                .iter()
                .map(|d| KvDirStatView {
                    name: d.name.clone(),
                    objects: d.objects,
                    bytes: d.bytes,
                })
                .collect(),
        }
    }
}

/// Serializable mirror of a `KvCompactOutcome`.
#[derive(Debug, serde::Serialize)]
pub struct KvCompactView {
    pub runs_before: u64,
    pub runs_after: u64,
    pub merged: bool,
    pub spec: Option<String>,
    pub timed_out: bool,
}

impl KvCompactView {
    fn from_outcome(o: &boatramp_storage::kv_slatedb::KvCompactOutcome) -> Self {
        Self {
            runs_before: o.runs_before,
            runs_after: o.runs_after,
            merged: o.merged,
            spec: o.spec.clone(),
            timed_out: o.timed_out,
        }
    }
}

impl crate::output::Rendered for KvOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::NotApplicable { message } => writeln!(w, "{message}"),
            Self::Export {
                records,
                bytes,
                store,
                out,
            } => {
                writeln!(
                    w,
                    "kv export: wrote {} record(s) ({} bytes) from `{}` to `{}`.",
                    records, bytes, store, out
                )?;
                writeln!(
                    w,
                    "  A LOGICAL dump (CONTENT, not the physical LSM/manifest) — `kv import` rebuilds a FRESH \
                     clean store, immune to the torn-manifest / corrupt-`.compactions` classes. The dump carries \
                     SEALED secret ciphertext (no plaintext) + plaintext control-plane config/RBAC, and NO KEK \
                     (a restore needs the separately-held envelope key). Treat it as SENSITIVE — protect it at \
                     rest."
                )
            }
            Self::ImportPlan {
                store,
                format_version,
                created_at,
                source_entries,
                source_reserved_skipped,
                dest_user_keys,
                dest_reserved_keys,
                dest_has_control_plane_id,
                dest_pristine,
                would_write,
                would_refuse_commingle,
            } => {
                writeln!(w, "kv import (DRY-RUN — no mutation) into `{store}`")?;
                writeln!(
                    w,
                    "  dump format v{} created at (unix): {}",
                    format_version, created_at
                )?;
                writeln!(w, "  source dumpable records:    {}", source_entries)?;
                if *source_reserved_skipped > 0 {
                    writeln!(
                        w,
                        "  reserved records skipped:   {} (`_cp/*` / `_inval/*` regenerate; never imported)",
                        source_reserved_skipped
                    )?;
                }
                write_dest_state(
                    w,
                    *dest_user_keys,
                    *dest_reserved_keys,
                    *dest_has_control_plane_id,
                    *dest_pristine,
                )?;
                writeln!(w, "  would copy:                 {}", would_write)?;
                if *would_refuse_commingle {
                    writeln!(
                        w,
                        "  REFUSAL: the destination is NON-EMPTY — `--apply` would be refused to avoid \
                         commingling two control planes. Pass `--force` only to deliberately overlay it."
                    )?;
                }
                writeln!(
                    w,
                    "\nDRY-RUN: re-run with `--apply` to import{}.",
                    if *would_refuse_commingle {
                        " (and `--force` to overlay the non-empty destination)"
                    } else {
                        ""
                    }
                )
            }
            Self::ImportApplied {
                store,
                written,
                verified,
            } => writeln!(
                w,
                "kv import: APPLIED {} record(s) into `{}` and VERIFIED {} byte-for-byte (re-read + count).",
                written, store, verified
            ),
            Self::MigratePlan {
                from,
                to,
                source_entries,
                dest_user_keys,
                dest_reserved_keys,
                dest_has_control_plane_id,
                dest_pristine,
                would_write,
                would_refuse_commingle,
            } => {
                writeln!(
                    w,
                    "kv migrate (DRY-RUN — no mutation): `{}` → `{}`",
                    from, to
                )?;
                writeln!(w, "  source dumpable records:    {}", source_entries)?;
                write_dest_state(
                    w,
                    *dest_user_keys,
                    *dest_reserved_keys,
                    *dest_has_control_plane_id,
                    *dest_pristine,
                )?;
                writeln!(w, "  would copy:                 {}", would_write)?;
                if *would_refuse_commingle {
                    writeln!(
                        w,
                        "  REFUSAL: the destination is NON-EMPTY — `--apply` would be refused to avoid \
                         commingling two control planes. Re-run with `--apply --force` only to overlay it."
                    )?;
                }
                writeln!(
                    w,
                    "\nDRY-RUN: re-run with `--apply` to migrate (then it VERIFIES bytes + count)."
                )
            }
            Self::MigrateApplied {
                from,
                to,
                written,
                verified,
            } => writeln!(
                w,
                "kv migrate: APPLIED {} record(s) `{}` → `{}` and VERIFIED {} byte-for-byte.",
                written, from, to, verified
            ),
            Self::Repair {
                report,
                applied_mode,
            } => write_report(w, report, *applied_mode),
            Self::StatusAck { cleared } => {
                if *cleared {
                    writeln!(
                        w,
                        "kv status: CLEARED the DEGRADED breadcrumb (acknowledged)."
                    )
                } else {
                    writeln!(w, "kv status: no DEGRADED breadcrumb to acknowledge.")
                }
            }
            Self::Status { marker } => match marker {
                Some(m) if m.rolled_back_to_generation.is_some() => {
                    // v0.11.0 F2 manifest-rollback shape (UX C2): LEAD with the lossless verdict and
                    // SUPPRESS the version-0-SST "no recovery of acked pairs" NOTE unless a real
                    // WAL-tail drop occurred.
                    let generation = m.rolled_back_to_generation.unwrap_or_default();
                    let wal_tail_dropped = !m.quarantined_ids.is_empty();
                    if wal_tail_dropped {
                        writeln!(
                            w,
                            "kv status: RECOVERED — auto-rolled-back to manifest gen {generation}; a torn WAL \
                             tail beyond the frontier was ALSO quarantined (a bounded, forensic-only loss)."
                        )?;
                    } else {
                        writeln!(
                            w,
                            "kv status: RECOVERED (lossless) — auto-rolled-back to manifest gen {generation}; \
                             zero acked loss (N-1 + WAL replay = a normal open)."
                        )?;
                    }
                    writeln!(w, "  recovered at (unix):        {}", m.stamp)?;
                    writeln!(w, "  frontier_source:            {}", m.frontier_source)?;
                    writeln!(w, "  last_durable_seq:           {}", m.frontier)?;
                    writeln!(w, "  rolled back to generation:  {generation}")?;
                    writeln!(
                        w,
                        "  quarantined manifest ids:   {:?}",
                        m.quarantined_manifest_ids
                    )?;
                    writeln!(w, "  manifest-quarantine dir:    {}", m.quarantine_dir)?;
                    if !m.orphaned_nonacked_objects.is_empty() {
                        writeln!(
                            w,
                            "  reclaimable orphaned SST(s): {:?} (SPACE only, NOT loss — the reopened store's \
                             GC reclaims them)",
                            m.orphaned_nonacked_objects
                        )?;
                    }
                    if wal_tail_dropped {
                        writeln!(w, "  quarantined WAL ids:        {:?}", m.quarantined_ids)?;
                        writeln!(w, "  loss window:                {}", m.loss_window)?;
                        writeln!(
                            w,
                            "  NOTE: the ADDITIONALLY quarantined torn WAL tail preserves raw bytes for \
                             FORENSICS ONLY — no supported recovery of acked pairs from a torn version-0 SST."
                        )?;
                    }
                    writeln!(
                        w,
                        "  Acknowledge with `boatramp kv status --ack` once reviewed."
                    )
                }
                Some(m) => {
                    writeln!(
                        w,
                        "kv status: DEGRADED (a self-heal-on-open quarantined a torn WAL tail)"
                    )?;
                    writeln!(w, "  self-healed at (unix): {}", m.stamp)?;
                    writeln!(w, "  frontier_source:       {}", m.frontier_source)?;
                    writeln!(w, "  last_durable_seq:      {}", m.frontier)?;
                    writeln!(w, "  quarantined WAL ids:   {:?}", m.quarantined_ids)?;
                    writeln!(w, "  loss window:           {}", m.loss_window)?;
                    writeln!(w, "  quarantine dir:        {}", m.quarantine_dir)?;
                    writeln!(
                        w,
                        "  NOTE: the quarantined torn tail preserves raw bytes for FORENSICS ONLY — there \
                         is no supported recovery of acked KV pairs from a torn version-0 SST."
                    )?;
                    writeln!(
                        w,
                        "  Acknowledge with `boatramp kv status --ack` once reviewed."
                    )
                }
                None => writeln!(
                    w,
                    "kv status: OK — no DEGRADED breadcrumb (the store opened cleanly, a self-heal was \
                     zero-loss, or a prior degraded state was acked). If the store will not open, run \
                     `boatramp kv recover` (dry-run) to diagnose."
                ),
            },
            Self::CheckpointLive { server, message } => {
                write!(w, "kv checkpoint --live (server {server}): {message}")?;
                if !message.ends_with('\n') {
                    writeln!(w)?;
                }
                Ok(())
            }
            Self::CheckpointOffline => writeln!(
                w,
                "kv checkpoint: WAL drained to L0 and the durable frontier advanced — the on-disk store is \
                 now a consistent, bootable snapshot point. Snapshot the volume now (a block snapshot of a \
                 LIVE un-checkpointed store is not reliably bootable; that is the recurring root cause)."
            ),
            Self::RecoverCompactions {
                report,
                applied_mode,
            } => {
                write_compactions_recovery(w, report, *applied_mode)?;
                if !*applied_mode {
                    writeln!(
                        w,
                        "\nRe-run `boatramp kv recover --apply` to reset the corrupt `.compactions` \
                         bookkeeping in place (lossless-for-acked — `.compactions` holds no committed \
                         data; the objects are retained under `compactions-quarantine/` for forensics)."
                    )?;
                }
                Ok(())
            }
            Self::RecoverWal {
                report,
                applied_mode,
            } => {
                write_report(w, report, *applied_mode)?;
                if !*applied_mode && !report.quarantined.is_empty() {
                    writeln!(
                        w,
                        "\nRe-run `boatramp kv recover --apply` to quarantine the safe trailing \
                         tail in place (the crashed torn bytes are retained under `wal-quarantine/` \
                         for forensics)."
                    )?;
                }
                Ok(())
            }
            Self::RecoverManifest {
                report,
                applied_mode,
            } => {
                write_manifest_recovery(w, report, *applied_mode)?;
                if !*applied_mode {
                    writeln!(
                        w,
                        "\nRe-run `boatramp kv recover --apply` to adopt the newest manifest generation \
                         that opens clean in place (lossless-for-acked; the quarantined manifest \
                         generations are retained under `manifest-quarantine/` for forensics)."
                    )?;
                }
                Ok(())
            }
            Self::AdoptVolumeDryRun {
                volume_store,
                target_store,
            } => {
                write_adopt_preamble(w, volume_store, target_store)?;
                writeln!(
                    w,
                    "\nDRY-RUN: re-run with `--apply` to adopt (copy → verify-open the COPY → swap, retaining \
                     the crashed copy). The source snapshot is never mutated."
                )
            }
            Self::AdoptVolumeApplied {
                volume_store,
                target_store,
                retained,
            } => {
                write_adopt_preamble(w, volume_store, target_store)?;
                writeln!(
                    w,
                    "kv recover: ADOPTED the clean snapshot into `{}`. The crashed store is RETAINED at `{}` \
                     (delete it once the node is confirmed serving). Start the daemon.",
                    target_store, retained
                )
            }
            Self::Stats { stats } => write_kv_stats(w, stats),
            Self::CompactDryRun { stats } => {
                writeln!(
                    w,
                    "kv compact: DRY-RUN (no changes made). Current store footprint:"
                )?;
                write_kv_stats(w, stats)?;
                writeln!(
                    w,
                    "\n  A compaction + GC would merge every L0 SST + sorted run into one sorted run and \
                     reclaim the now-unreferenced garbage (superseded SSTs + old manifests + replayed WAL).\n  \
                     Running GC in DRY-RUN below (slatedb logs each delete CANDIDATE; nothing is deleted):"
                )?;
                writeln!(
                    w,
                    "\n  OFFLINE ONLY — STOP the daemon first, then re-run with `--apply` to compact + \
                     reclaim (GC deletion is IRREVERSIBLE)."
                )
            }
            Self::CompactApply {
                before,
                after,
                compaction,
                timeout_secs,
                dropped_checkpoints,
            } => {
                writeln!(
                    w,
                    "kv compact --apply: OFFLINE full-merge compaction + GC reclaim. IRREVERSIBLE.\n  \
                     WARNING: this command CANNOT detect a running daemon and does not stop one — STOP the \
                     daemon on this node FIRST. Run against a live daemon it will fence/crash it and may delete \
                     objects an in-flight reader still needs (possible data loss)."
                )?;
                writeln!(w, "\n  BEFORE:")?;
                write_kv_stats(w, before)?;
                match (&compaction.spec, compaction.merged, compaction.timed_out) {
                    (Some(spec), true, _) => writeln!(
                        w,
                        "\n  COMPACTED: merged {} run(s) → {} sorted run [spec {spec}].",
                        compaction.runs_before, compaction.runs_after
                    )?,
                    (Some(spec), false, true) => writeln!(
                        w,
                        "\n  WARNING: the full-merge compaction [spec {spec}] did NOT land within {}s (still {} \
                         run(s)). GC will still reclaim any already-unreferenced garbage, but re-run with a larger \
                         `--timeout-secs` to complete the merge.",
                        timeout_secs, compaction.runs_after
                    )?,
                    (Some(spec), false, false) => writeln!(
                        w,
                        "\n  NOTE: the submitted full-merge [spec {spec}] did not reach a single sorted run \
                         (still {} run(s)); proceeding to GC.",
                        compaction.runs_after
                    )?,
                    (None, _, _) => writeln!(
                        w,
                        "\n  Nothing to merge ({} run(s) — already compact); proceeding to GC to reclaim old \
                         manifests / WAL.",
                        compaction.runs_before
                    )?,
                }
                if *dropped_checkpoints > 0 {
                    writeln!(
                        w,
                        "  GC: dropped {} protective checkpoint(s) (safe OFFLINE), then reclaimed unreferenced \
                         SSTs + old manifests + replayed WAL.",
                        dropped_checkpoints
                    )?;
                } else {
                    writeln!(
                        w,
                        "  GC: reclaimed unreferenced SSTs + old manifests + replayed WAL."
                    )?;
                }
                writeln!(w, "\n  AFTER:")?;
                write_kv_stats(w, after)?;
                let reclaimed = before
                    .physical_total_bytes
                    .saturating_sub(after.physical_total_bytes);
                writeln!(
                    w,
                    "\n  RECLAIMED: {} ({} → {} physical).",
                    human_bytes(reclaimed),
                    human_bytes(before.physical_total_bytes),
                    human_bytes(after.physical_total_bytes),
                )
            }
        }
    }
}

/// Dispatch `boatramp kv <subcommand>`.
pub async fn run(args: KvArgs) -> Result<KvOutput, Error> {
    match args.command {
        KvCommand::Repair(repair) => run_repair(repair).await,
        KvCommand::Status(status) => run_status(status).await,
        KvCommand::Checkpoint(checkpoint) => run_checkpoint(checkpoint).await,
        KvCommand::Recover(recover) => run_recover(recover).await,
        KvCommand::Export(export) => run_export(export).await,
        KvCommand::Import(import) => run_import(import).await,
        KvCommand::Migrate(migrate) => run_migrate(migrate).await,
        KvCommand::Stats(stats) => run_stats(stats).await,
        KvCommand::Compact(compact) => run_compact(compact).await,
    }
}

/// `boatramp kv export` — scan the store into the portable dump and write it to `--out` (kv-sql WS7).
async fn run_export(args: ExportArgs) -> Result<KvOutput, Error> {
    let store = open_endpoint(&args.store).await?;
    let bytes = boatramp_core::kv_dump::export_to_bytes(store.as_ref(), now_secs())
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    let decoded = boatramp_core::kv_dump::decode_dump(&bytes)?;
    std::fs::write(&args.out, &bytes)?;
    Ok(KvOutput::Export {
        records: decoded.entries.len(),
        bytes: bytes.len(),
        out: args.out.display().to_string(),
        store: args.store,
    })
}

/// `boatramp kv import <file>` — DRY-RUN plan by default; `--apply` imports + verifies (kv-sql WS7).
async fn run_import(args: ImportArgs) -> Result<KvOutput, Error> {
    let store = open_endpoint(&args.store).await?;
    let bytes = std::fs::read(&args.file)?;
    let decoded = boatramp_core::kv_dump::decode_dump(&bytes)?;

    if !args.apply {
        let plan =
            boatramp_core::kv_dump::plan_import(store.as_ref(), &decoded.entries, args.force)
                .await
                .map_err(|e| Error::Store(e.to_string()))?;
        return Ok(KvOutput::ImportPlan {
            format_version: decoded.header.format_version,
            created_at: decoded.header.created_at,
            source_entries: plan.source_entries,
            source_reserved_skipped: plan.source_reserved_skipped,
            dest_user_keys: plan.dest.user_keys,
            dest_reserved_keys: plan.dest.reserved_keys,
            dest_has_control_plane_id: plan.dest.has_control_plane_id,
            dest_pristine: plan.dest.is_pristine(),
            would_write: plan.would_write,
            would_refuse_commingle: plan.would_refuse_commingle,
            store: args.store,
        });
    }

    let report =
        boatramp_core::kv_dump::apply_import(store.as_ref(), &decoded.entries, args.force).await?;
    Ok(KvOutput::ImportApplied {
        written: report.written,
        verified: report.verified,
        store: args.store,
    })
}

/// `boatramp kv migrate --from <desc> --to <desc>` — store→store; DRY-RUN by default (kv-sql WS7).
async fn run_migrate(args: MigrateArgs) -> Result<KvOutput, Error> {
    let src = open_endpoint(&args.from).await?;
    let dst = open_endpoint(&args.to).await?;
    let entries = boatramp_core::kv_dump::scan_dumpable(src.as_ref())
        .await
        .map_err(|e| Error::Store(e.to_string()))?;

    if !args.apply {
        let plan = boatramp_core::kv_dump::plan_import(dst.as_ref(), &entries, args.force)
            .await
            .map_err(|e| Error::Store(e.to_string()))?;
        return Ok(KvOutput::MigratePlan {
            source_entries: plan.source_entries,
            dest_user_keys: plan.dest.user_keys,
            dest_reserved_keys: plan.dest.reserved_keys,
            dest_has_control_plane_id: plan.dest.has_control_plane_id,
            dest_pristine: plan.dest.is_pristine(),
            would_write: plan.would_write,
            would_refuse_commingle: plan.would_refuse_commingle,
            from: args.from,
            to: args.to,
        });
    }

    let report = boatramp_core::kv_dump::migrate(src.as_ref(), dst.as_ref(), args.force).await?;
    Ok(KvOutput::MigrateApplied {
        written: report.written,
        verified: report.verified,
        from: args.from,
        to: args.to,
    })
}

/// Write the destination emptiness/identity portion of an import/migrate plan.
fn write_dest_state(
    w: &mut dyn std::io::Write,
    user_keys: usize,
    reserved_keys: usize,
    has_control_plane_id: bool,
    pristine: bool,
) -> std::io::Result<()> {
    writeln!(
        w,
        "  destination state:          {} user key(s), {} reserved, control-plane-id {}",
        user_keys,
        reserved_keys,
        if has_control_plane_id {
            "PRESENT (commingle hazard)"
        } else {
            "absent"
        }
    )?;
    writeln!(
        w,
        "  destination:                {}",
        if pristine {
            "PRISTINE (safe to import without --force)"
        } else {
            "NON-EMPTY (needs --force)"
        }
    )
}

async fn run_repair(args: RepairArgs) -> Result<KvOutput, Error> {
    if let Some(message) = args.addr.not_applicable("repair") {
        return Ok(KvOutput::NotApplicable { message });
    }
    let (store, root) = args.addr.build()?;
    let mode = if args.apply {
        RepairMode::Apply
    } else {
        RepairMode::DryRun
    };
    let report = repair_wal_tail(&store, &root, mode).await?;
    Ok(KvOutput::Repair {
        report: RepairReportView::from_report(&report),
        applied_mode: args.apply,
    })
}

async fn run_status(args: StatusArgs) -> Result<KvOutput, Error> {
    if let Some(message) = args.addr.not_applicable("status") {
        return Ok(KvOutput::NotApplicable { message });
    }
    let (store, root) = args.addr.build()?;
    if args.ack {
        let existed = clear_degraded_marker(&store, &root)
            .await
            .map_err(|e| Error::Store(e.to_string()))?;
        return Ok(KvOutput::StatusAck { cleared: existed });
    }
    // The three breadcrumb shapes (RECOVERED / DEGRADED / OK) are rendered from the marker by
    // `KvOutput::Status`; reading it (without opening the store) stays here.
    let marker = read_degraded_marker(&store, &root)
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    Ok(KvOutput::Status { marker })
}

async fn run_checkpoint(args: CheckpointArgs) -> Result<KvOutput, Error> {
    if let Some(message) = args.addr.not_applicable("checkpoint") {
        return Ok(KvOutput::NotApplicable { message });
    }
    if args.live {
        return run_checkpoint_live(&args).await;
    }
    run_checkpoint_offline(args.addr).await
}

/// `kv checkpoint --live` (UX C6) — the client verb over `POST /api/kv-checkpoint` (System·Admin):
/// advance the RUNNING daemon's durable frontier WITHOUT stopping it, then the operator can snapshot a
/// bootable volume of the live node. The URL comes from `--server`, else `[deploy].server` /
/// `BOATRAMP_SERVER`; the control-plane token comes from the config / `BOATRAMP_TOKEN`.
async fn run_checkpoint_live(args: &CheckpointArgs) -> Result<KvOutput, Error> {
    use crate::client;
    // `kv` runs before the project config is loaded (a store needing repair may predate a valid
    // config), so load `project.cfg` here best-effort — a missing file is the default, and an explicit
    // `--server` + `BOATRAMP_TOKEN` still work without a config file.
    let config = crate::config::ProjectConfig::load(std::path::Path::new("project.cfg"), None)
        .unwrap_or_default();
    let server = client::resolve_server(args.server.clone(), &config)?;
    let cp = client::ControlPlane::new(
        server.clone(),
        client::http_client(client::token(&config).as_deref()),
        client::resolve_project(&config),
    );
    let message = cp.kv_checkpoint().await?;
    Ok(KvOutput::CheckpointLive { server, message })
}

async fn run_checkpoint_offline(addr: StoreAddr) -> Result<KvOutput, Error> {
    // Open STRICT (a torn store must be RECOVERED first, never checkpointed) then CLOSE: the close
    // drains the memtable → L0 and advances the durable frontier (slatedb `CloseOptions` default
    // `FlushType::MemTable` — the same primitive as the periodic checkpoint), leaving a consistent,
    // bootable on-disk state. OFFLINE only (single-writer fencing — the daemon must be stopped).
    let kv = addr
        .open_store(boatramp_storage::kv_slatedb::KvOpenPolicy::Strict)
        .await?;
    boatramp_core::kv::KvStore::close(&kv)
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    Ok(KvOutput::CheckpointOffline)
}

async fn run_recover(args: RecoverArgs) -> Result<KvOutput, Error> {
    if let Some(message) = args.addr.not_applicable("recover") {
        return Ok(KvOutput::NotApplicable { message });
    }
    if let Some(volume) = args.adopt_volume.clone() {
        return run_recover_adopt_volume(&args.addr, &volume, args.apply).await;
    }
    // MF3 (v0.11.0) — the in-place recovery must REFUSE on a cluster node-local Raft store, mirroring
    // the `serve --repair-wal` cluster refusal (serve.rs). `kv recover` addresses `<data-dir>/kv-slate`,
    // never `<data-dir>/raft`; a co-located cluster deployment (a `raft/`/`mesh/` store beside the
    // target) marks this as a cluster node, and a cluster node recovers by failing loud then REJOINING
    // peers (which re-replicate the authoritative log), NOT by auto-quarantining/manifest-recovering its
    // node-local store (which could regress below the committed index → double-vote / log↔SM desync).
    if !args.addr.kv_s3 && is_cluster_node_data_dir(&args.addr.data_dir) {
        return Err(Error::Store(format!(
            "REFUSING in-place recovery: `{}` looks like a CLUSTER node data dir (a `raft/`/`mesh/` \
             store is present). A cluster node NEVER self-recovers its node-local Raft store — that \
             could regress below the committed index (double-vote / log↔state-machine desync). Recover \
             by wiping this node's store and REJOINING peers (which re-replicate the authoritative \
             log): stop the node, remove its data dir, and restart with `--cluster-join <ticket>`.",
            args.addr.data_dir.display()
        )));
    }
    let (store, root) = args.addr.build()?;
    let mode = if args.apply {
        RepairMode::Apply
    } else {
        RepairMode::DryRun
    };
    // Shape detection (UX C4/C5): the empty/torn LATEST manifest shape (v0.11.0 F2) vs the WAL-tail
    // shape. `recover_last_good_manifest` returns `LatestReadable` (a no-op) when the manifest is
    // readable, so we fall through to the ordinary WAL-tail `kv repair` superset; `RolledBack` when the
    // latest manifest is empty/torn and it (would, dry-run) roll back to the last-good generation.
    match recover_last_good_manifest(&store, &root, mode).await {
        Ok(ManifestRecovery::LatestReadable { .. }) => {
            // The latest manifest + SSTs are readable. First check the v0.11.1 corrupt-`.compactions`
            // shape (compactor-ON `Invalid error: invalid compaction` while the manifest is intact):
            // reset the `.compactions` bookkeeping (quarantine it + remove the compactions GC boundary).
            match recover_corrupt_compactions(&store, &root, mode).await {
                Ok(CompactionsRecovery::Reset(report)) => {
                    return Ok(KvOutput::RecoverCompactions {
                        report: CompactionsResetView::from_report(&report),
                        applied_mode: args.apply,
                    });
                }
                Ok(CompactionsRecovery::NotCorrupt) => {}
                Err(e) => {
                    tracing::warn!("kv recover: compactions reset cannot proceed — {e}");
                    warn_adopt_volume_guidance();
                    return Err(e.into());
                }
            }
            // The ordinary in-place WAL-tail path (unchanged): the SUPERSET of `kv repair`, with the
            // shape-split escalation to `--adopt-volume` (C10).
            match repair_wal_tail(&store, &root, mode).await {
                Ok(report) => {
                    if !report.out_of_scope_torn.is_empty() {
                        warn_adopt_volume_guidance();
                    }
                    Ok(KvOutput::RecoverWal {
                        report: RepairReportView::from_report(&report),
                        applied_mode: args.apply,
                    })
                }
                Err(e) => {
                    // C10 shape-split: name the exact refusal, then point at the snapshot-restore path.
                    tracing::warn!("kv recover: in-place repair cannot proceed — {e}");
                    warn_adopt_volume_guidance();
                    Err(e.into())
                }
            }
        }
        Ok(ManifestRecovery::RolledBack(report)) => {
            // The empty/torn LATEST manifest shape (UX C5) OR the v0.11.1 invalid-compaction shape (the
            // latest DECODES but won't open — a referenced compacted SST was removed/torn): the dry-run
            // WORKS (prints the walk ladder + the generation it will adopt) and `--apply` adopts the
            // newest generation that OPENS CLEAN in place, non-destructively (the quarantined manifest
            // generations are retained under `manifest-quarantine/` until verify).
            Ok(KvOutput::RecoverManifest {
                report: ManifestRecoveryView::from_report(&report),
                applied_mode: args.apply,
            })
        }
        Err(e) => {
            // A manifest shape recovery REFUSED (no decodable generation, NO generation opens clean
            // [v0.11.1 NoOpenableManifest], a WAL GC hole, or below the GC boundary). Name the refusal,
            // then point at the clean-snapshot escalation (UX C4).
            tracing::warn!("kv recover: manifest recovery cannot proceed — {e}");
            warn_adopt_volume_guidance();
            Err(e.into())
        }
    }
}

/// Whether `data_dir` belongs to a CLUSTER node — a `raft/` node-local durable store or a `mesh/`
/// identity dir sits beside the control-plane target (see `serve::run_cluster`). Used by
/// [`run_recover`] to refuse an in-place recovery on a cluster node (MF3): a cluster recovers by
/// rejoining peers, never by self-recovering its node-local Raft store.
fn is_cluster_node_data_dir(data_dir: &std::path::Path) -> bool {
    data_dir.join("raft").is_dir() || data_dir.join("mesh").is_dir()
}

/// Write the last-good-generation manifest-recovery plan / outcome (v0.11.0 F2 + v0.11.1 walk).
fn write_manifest_recovery(
    w: &mut dyn std::io::Write,
    report: &ManifestRecoveryView,
    applied: bool,
) -> std::io::Result<()> {
    writeln!(
        w,
        "control-plane MANIFEST recovery {}",
        if applied {
            "(APPLY)"
        } else {
            "(DRY-RUN — no mutation)"
        }
    )?;
    // v0.11.1: classify the shape. If any decodable generation above the adopted one was SKIPPED as
    // unopenable, the latest DECODES but won't OPEN (the invalid-compaction / missing-referenced-SST
    // shape) — NEVER "should open normally". Otherwise it is the classic empty/torn-latest shape.
    let skipped_unopenable = report
        .candidate_ladder
        .iter()
        .any(|c| c.status.starts_with("skipped:"));
    if skipped_unopenable {
        writeln!(
            w,
            "  the LATEST manifest DECODES but will NOT open (invalid compaction / a referenced \
             compacted SST was removed or torn — a mid-compaction unclean exit). This is a \
             RECOVERABLE shape: walking back to the newest manifest generation that OPENS CLEAN."
        )?;
    } else {
        writeln!(
            w,
            "  the LATEST manifest is empty/torn — rolling back to the last-good manifest generation."
        )?;
    }
    // The candidate ladder (highest generation first): exactly which generations were skipped as
    // unopenable and which one is adopted — so a won't-open latest is never reported "should open
    // normally".
    writeln!(w, "  generation walk ladder (newest first):")?;
    for c in &report.candidate_ladder {
        let frontier = c
            .frontier
            .map(|f| format!("frontier {f}"))
            .unwrap_or_else(|| "frontier n/a".to_string());
        writeln!(
            w,
            "    generation {:<12} {:<22} {}",
            c.generation, frontier, c.status
        )?;
    }
    writeln!(
        w,
        "  adopt manifest generation (newest that OPENS CLEAN): {}",
        report.rolled_back_to_generation
    )?;
    writeln!(
        w,
        "  durable frontier (replay_after_wal_id) at that generation: {}",
        report.frontier
    )?;
    if report.quarantined_manifest_ids.is_empty() {
        writeln!(w, "  torn manifest generation(s) to quarantine: (none)")?;
    } else {
        let ids: Vec<String> = report
            .quarantined_manifest_ids
            .iter()
            .map(|id| format!("{id:020}"))
            .collect();
        writeln!(
            w,
            "  torn manifest generation(s) to quarantine (retained under manifest-quarantine/): [{}]",
            ids.join(", ")
        )?;
    }
    // The embedded WAL-tail sub-plan at F: for the pure last-good-generation rollback this is empty
    // (discard = none, lossless-for-acked); a crash that ALSO tore a WAL tail beyond F shows it here.
    if report.wal_repair.quarantined.is_empty() {
        writeln!(
            w,
            "  WAL tail beyond the frontier to discard: none (discard = none — lossless-for-acked)."
        )?;
    } else {
        let ids: Vec<String> = report
            .wal_repair
            .quarantined
            .iter()
            .map(|id| format!("{id:020}"))
            .collect();
        writeln!(
            w,
            "  ADDITIONALLY a torn WAL tail beyond the frontier would be quarantined [{}] — those \
             bytes are FORENSIC-ONLY (no supported recovery of acked pairs from a torn version-0 SST).",
            ids.join(", ")
        )?;
    }
    if !report.orphaned_nonacked_objects.is_empty() {
        writeln!(
            w,
            "  reclaimable orphaned L0 SST(s) (SPACE only, NOT loss): {:?}",
            report.orphaned_nonacked_objects
        )?;
    }
    if applied {
        writeln!(
            w,
            "  RECOVERED (lossless-for-acked): adopted generation {} (the newest that OPENS CLEAN) and \
             replayed the WAL forward — the store now opens with zero acked loss (adopted generation + \
             WAL replay, MF2-contiguity-verified). The quarantined manifest generation(s) are retained \
             under `{}` for forensics.",
            report.rolled_back_to_generation,
            report
                .manifest_quarantine_dir
                .as_deref()
                .unwrap_or("<none>")
        )
    } else {
        writeln!(
            w,
            "  WOULD adopt generation {} (the newest that OPENS CLEAN; lossless-for-acked, \
             MF2-contiguity-verified).",
            report.rolled_back_to_generation
        )
    }
}

/// Write the v0.11.1 corrupt-`.compactions` reset plan / outcome.
fn write_compactions_recovery(
    w: &mut dyn std::io::Write,
    report: &CompactionsResetView,
    applied: bool,
) -> std::io::Result<()> {
    writeln!(
        w,
        "control-plane COMPACTIONS reset {}",
        if applied {
            "(APPLY)"
        } else {
            "(DRY-RUN — no mutation)"
        }
    )?;
    writeln!(
        w,
        "  the manifest + SSTs are intact, but the `.compactions` bookkeeping object is CORRUPT \
         (compactor-ON open fails `Invalid error: invalid compaction`). `.compactions` holds NO \
         committed data — only compactor bookkeeping — so a reset is lossless-for-acked: the compactor \
         fresh-starts from the manifest's current SST set."
    )?;
    if report.quarantined_compactions_ids.is_empty() {
        writeln!(w, "  .compactions object(s) to quarantine: (none listed)")?;
    } else {
        let ids: Vec<String> = report
            .quarantined_compactions_ids
            .iter()
            .map(|id| format!("{id:020}"))
            .collect();
        writeln!(
            w,
            "  .compactions object(s) to quarantine (retained under compactions-quarantine/): [{}]",
            ids.join(", ")
        )?;
    }
    writeln!(
        w,
        "  compactions GC boundary (`gc/compactions.boundary`) {}: required so the fresh id-1 \
         `.compactions` the compactor-ON reopen creates is not rejected (ObjectVersionExists).",
        if report.boundary_removed {
            "will be removed"
        } else {
            "absent (nothing to remove)"
        }
    )?;
    if applied {
        writeln!(
            w,
            "  RESET (lossless-for-acked): quarantined the corrupt `.compactions` + removed the \
             compactions GC boundary; a compactor-ON reopen now fresh-starts the compactor from the \
             manifest. The objects are retained under `{}` for forensics.",
            report.quarantine_dir.as_deref().unwrap_or("<none>")
        )
    } else {
        writeln!(
            w,
            "  WOULD reset the corrupt `.compactions` bookkeeping (lossless-for-acked)."
        )
    }
}

/// The `--adopt-volume` escalation guidance (C10): a shape beyond auto-heal AND beyond `kv repair`
/// (tail-only) is recovered by adopting a clean volume snapshot. This is diagnostic guidance printed
/// alongside a refusal (the command then returns `Err`), so it rides the `tracing` sink (stderr), not
/// the command's typed result. boatramp validates + adopts the volume the operator attaches; it never
/// drives the fly volume lifecycle.
fn warn_adopt_volume_guidance() {
    tracing::warn!(
        "\nUNSAFE SHAPE — beyond auto-heal and beyond `kv repair` (tail-only). Recover by adopting a \
         CLEAN volume snapshot:\n  \
         1. fly volumes create <name> --snapshot-id <snap>   (or restore/clone a known-good volume)\n  \
         2. mount it on a machine (e.g. a second mount, or a maintenance machine)\n  \
         3. boatramp kv recover --adopt-volume <mounted-path>            (dry-run: validate + delta)\n  \
         4. boatramp kv recover --adopt-volume <mounted-path> --apply    (verify → swap; crashed copy retained)\n\
         boatramp validates + adopts the volume you attach; it does NOT create/destroy fly volumes."
    );
}

/// Write the `--adopt-volume` validate-and-discard-delta preamble (the stdout result text shared by
/// the dry-run and apply outcomes).
fn write_adopt_preamble(
    w: &mut dyn std::io::Write,
    volume_store: &str,
    target_store: &str,
) -> std::io::Result<()> {
    writeln!(
        w,
        "adopt-volume: the attached store at `{}` passes the whole-store torn scan (ZERO torn) — \
         validated READ-ONLY, the snapshot is left byte-pristine.\n  \
         Adopting REPLACES the crashed store at `{}` with a COPY of the snapshot (a definitive \
         real-open bootability verify then runs on the copy, never the source).\n  \
         DISCARD-DELTA: every write in the crashed store made AFTER the snapshot's point-in-time is \
         LOST (a snapshot is a point-in-time copy; boatramp cannot merge the crashed WAL into it).\n  \
         The crashed copy is RETAINED (renamed aside) until the adopt is verified serving.",
        volume_store, target_store
    )
}

/// `kv recover --adopt-volume <mounted-path>`: validate an operator-attached CLEAN volume snapshot
/// and (with `--apply`) adopt it in place of the crashed local store, RETAINING the crashed copy
/// until the adopt is verified (C9). Local-disk / fly-volume only (a snapshot is a mounted path).
async fn run_recover_adopt_volume(
    target: &StoreAddr,
    volume: &std::path::Path,
    apply: bool,
) -> Result<KvOutput, Error> {
    if target.kv_s3 {
        return Err(Error::Store(
            "--adopt-volume is a local-disk / fly-volume flow (a mounted snapshot path); it does \
             not apply to an --kv-s3 store. Recover an S3/R2 store via its own object-store \
             versioning/restore, then `kv recover` (in-place) or redeploy."
                .to_string(),
        ));
    }
    let target_dir = target.data_dir.join("kv-slate");
    // The attached volume's control-plane store (its own `kv-slate`, mirroring the live layout).
    let volume_dir = volume.join("kv-slate");
    if !volume_dir.is_dir() {
        return Err(Error::Store(format!(
            "the attached volume at `{}` has no `kv-slate` store (expected `{}`). Mount the volume \
             whose `kv-slate` is the clean snapshot.",
            volume.display(),
            volume_dir.display()
        )));
    }

    // 1. VALIDATE the attached volume BEFORE adopting — WITHOUT mutating it (Security L3): the
    //    operator's snapshot must stay byte-pristine. So the source is only ever READ here: a
    //    read-only whole-store torn scan (`repair_wal_tail` DryRun = list + get_range only, never a
    //    write). We deliberately do NOT open the source as a writer (a `Db` open takes the writer
    //    fence + writes a manifest) NOR as a `DbReader` (which `write_checkpoint`s a reader
    //    checkpoint into the manifest on open) — both would mutate the pristine snapshot. The
    //    DEFINITIVE real-open bootability verify runs later on the COPY (never the source), so a
    //    truncated edge the footer probe misses is still caught (and rolled back) at `--apply`.
    let vol_obj: Arc<dyn ObjectStore> = Arc::new(
        boatramp_storage::kv_slatedb::local_object_store(&volume_dir)
            .map_err(|e| Error::Store(e.to_string()))?,
    );
    let vol_dry = repair_wal_tail(&vol_obj, "kv", RepairMode::DryRun).await?;
    if !vol_dry.is_noop() {
        return Err(Error::Store(format!(
            "REFUSING to adopt: the attached volume at `{}` is ITSELF torn/dirty (would need \
             recovery too) — trailing torn tail {:?}, out-of-scope torn objects: {}. Attach a \
             genuinely clean snapshot.",
            volume.display(),
            vol_dry.quarantined,
            vol_dry.out_of_scope_torn.len()
        )));
    }

    // 2. Discard-delta: adopting the snapshot DISCARDS the crashed store's post-snapshot writes. The
    //    operator-facing preamble + discard-delta notice is rendered by `KvOutput` (see
    //    `write_adopt_preamble`); here we only decide dry-run vs apply.
    if !apply {
        return Ok(KvOutput::AdoptVolumeDryRun {
            volume_store: volume_dir.display().to_string(),
            target_store: target_dir.display().to_string(),
        });
    }

    // 3. --apply: retain the crashed copy, copy the validated snapshot into place, verify it opens;
    //    roll back on any failure so a botched adopt never leaves an unbootable/empty store.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let retained = target
        .data_dir
        .join(format!("kv-slate.crashed-{stamp:020}"));
    if target_dir.exists() {
        std::fs::rename(&target_dir, &retained).map_err(|e| {
            Error::Store(format!(
                "could not retain the crashed store `{}` → `{}`: {e}",
                target_dir.display(),
                retained.display()
            ))
        })?;
    }
    // Copy (never move) the operator's mounted snapshot into the live store dir.
    if let Err(e) = copy_dir_all(&volume_dir, &target_dir) {
        // Roll back: remove the partial copy, restore the crashed copy.
        let _ = std::fs::remove_dir_all(&target_dir);
        if retained.exists() {
            let _ = std::fs::rename(&retained, &target_dir);
        }
        return Err(Error::Store(format!(
            "adopt FAILED copying the snapshot into place (rolled back — the crashed store is \
             restored): {e}"
        )));
    }
    // Verify the adopted store opens clean; roll back if not.
    match boatramp_storage::SlateKv::open_local_with_flush_policy(
        &target_dir,
        boatramp_node::backends::CONTROL_PLANE_FLUSH,
        boatramp_storage::kv_slatedb::KvOpenPolicy::Strict,
    )
    .await
    {
        Ok(vk) => {
            let _ = boatramp_core::kv::KvStore::close(&vk).await;
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&target_dir);
            if retained.exists() {
                let _ = std::fs::rename(&retained, &target_dir);
            }
            return Err(Error::Store(format!(
                "adopt FAILED: the adopted store did not open after the swap (rolled back — the \
                 crashed store is restored): {e}"
            )));
        }
    }
    Ok(KvOutput::AdoptVolumeApplied {
        volume_store: volume_dir.display().to_string(),
        target_store: target_dir.display().to_string(),
        retained: retained.display().to_string(),
    })
}

/// Recursively copy a directory tree (`src` → `dst`) — the snapshot adopt copies the mounted volume
/// into the live store dir rather than moving it (the operator's snapshot volume stays intact).
fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_all(&from, &to)?;
        } else {
            std::fs::copy(&from, &to)?;
        }
    }
    Ok(())
}

/// Write the repair plan / outcome.
fn write_report(
    w: &mut dyn std::io::Write,
    report: &RepairReportView,
    applied_mode: bool,
) -> std::io::Result<()> {
    writeln!(
        w,
        "control-plane WAL repair {}",
        if applied_mode {
            "(APPLY)"
        } else {
            "(DRY-RUN — no mutation)"
        }
    )?;
    writeln!(
        w,
        "  durable frontier (replay_after_wal_id): {}",
        report.frontier
    )?;
    writeln!(
        w,
        "  WAL candidates beyond the frontier (highest id first):"
    )?;
    if report.candidates.is_empty() {
        writeln!(w, "    (none)")?;
    } else {
        for c in &report.candidates {
            writeln!(w, "    {:020}.sst  {:>10} bytes  {}", c.id, c.size, c.class)?;
        }
    }
    // Out-of-scope torn SSTs (torn compacted/L0 SSTs + torn non-trailing WAL objects). These are
    // DETECTION-ONLY: the repair NEVER quarantines/removes them (a compacted SST is referenced by
    // the manifest — removing it without a manifest rollback would drop acked data). Print them
    // LOUDLY before the "should open normally" line so the compacted-SST case is unmistakable and
    // an apply's `UnrepairableTornObject` failure is explained.
    if !report.out_of_scope_torn.is_empty() {
        writeln!(
            w,
            "  OUT-OF-SCOPE torn SST(s) this tool will NOT auto-remove \
             (requires manifest-aware recovery; escalate):"
        )?;
        for t in &report.out_of_scope_torn {
            writeln!(
                w,
                "    {}  {:>10} bytes  {}  [{}]",
                t.path, t.size, t.class, t.kind
            )?;
        }
        writeln!(
            w,
            "  A torn compacted/L0 SST cannot be quarantined safely (it is referenced by the \
             manifest); dropping it needs a manifest rollback. `--apply` will quarantine any safe \
             trailing WAL tail, then FAIL LOUD naming the object(s) above — the store will not open \
             until they are resolved out of band."
        )?;
    }
    if report.is_noop() {
        return writeln!(
            w,
            "  no torn SST found (WAL tail or compacted) — the store should open normally."
        );
    }
    let ids: Vec<String> = report
        .quarantined
        .iter()
        .map(|id| format!("{id:020}"))
        .collect();
    if report.applied {
        writeln!(
            w,
            "  QUARANTINED the trailing torn tail [{}] to `{}`.",
            ids.join(", "),
            report.quarantine_dir.as_deref().unwrap_or("<unknown>")
        )?;
        writeln!(
            w,
            "  The store should now open. NOTE (honest loss-window): a HARD-CRASH repair may have \
             lost the most-recent acked-into-WAL-but-not-yet-L0 writes — the graceful shutdown \
             path (quiesce-then-close) is lossless; only an abrupt crash/snapshot can lose the tail."
        )
    } else {
        writeln!(
            w,
            "  WOULD quarantine the trailing torn tail [{}]. Re-run with `--apply` to perform it.",
            ids.join(", ")
        )?;
        writeln!(
            w,
            "  NOTE (honest loss-window): applying on a HARD-CRASH store may lose the most-recent \
             acked-into-WAL-but-not-yet-L0 writes; a graceful shutdown is lossless."
        )
    }
}

/// `boatramp kv stats` — report the store's physical-vs-logical footprint (kv-data-observability).
async fn run_stats(args: StatsArgs) -> Result<KvOutput, Error> {
    if let Some(message) = args.addr.not_applicable("stats") {
        return Ok(KvOutput::NotApplicable { message });
    }
    let (store, root) = args.addr.build()?;
    let physical = boatramp_storage::kv_slatedb::kv_physical_stats(&store, &root)
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    let logical = boatramp_storage::kv_slatedb::kv_logical_stats(&store, &root)
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    Ok(KvOutput::Stats {
        stats: KvStatsView::from_stats(&physical, &logical),
    })
}

/// `boatramp kv compact` — DRY-RUN (default) prints the stats + reclaimable delta and runs GC in
/// dry-run; `--apply` runs the OFFLINE full-merge compaction then the IRREVERSIBLE GC reclaim.
async fn run_compact(args: CompactArgs) -> Result<KvOutput, Error> {
    use boatramp_storage::kv_slatedb::{kv_compact, kv_gc, kv_logical_stats, kv_physical_stats};

    if let Some(message) = args.addr.not_applicable("compact") {
        return Ok(KvOutput::NotApplicable { message });
    }
    let (store, root) = args.addr.build()?;

    let physical_before = kv_physical_stats(&store, &root)
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    let logical_before = kv_logical_stats(&store, &root)
        .await
        .map_err(|e| Error::Store(e.to_string()))?;

    if !args.apply {
        // Run GC in DRY-RUN for its side effect only — slatedb logs each delete CANDIDATE to the
        // tracing sink and deletes nothing; the footprint + guidance text is rendered by
        // `KvOutput::CompactDryRun`.
        kv_gc(&store, &root, true, std::time::Duration::ZERO)
            .await
            .map_err(|e| Error::Store(e.to_string()))?;
        return Ok(KvOutput::CompactDryRun {
            stats: KvStatsView::from_stats(&physical_before, &logical_before),
        });
    }

    // APPLY. OFFLINE ONLY + IRREVERSIBLE. This path drops EVERY protective checkpoint then runs GC
    // with min_age=0 — it deletes every unreferenced object immediately, including SSTs/manifests an
    // in-flight reader may still need. The CLI CANNOT reliably detect a running daemon: SlateDB's
    // writer open is TAKE-OVER (last-writer-wins, manifest-epoch fencing), so opening the store here
    // would FENCE a live daemon (disrupting it + risking loss of its recently-acked writes) rather
    // than refuse — there is no safe in-process liveness probe, and no out-of-band daemon lock exists
    // to consult yet (tracked follow-up: an advisory flock the daemon holds + this verb checks). So we
    // do NOT probe; the operator is responsible for stopping the daemon, and the warning rides the
    // rendered result.
    let outcome = kv_compact(
        &store,
        &root,
        std::time::Duration::from_secs(args.timeout_secs),
    )
    .await
    .map_err(|e| Error::Store(e.to_string()))?;

    let gc = kv_gc(&store, &root, false, std::time::Duration::ZERO)
        .await
        .map_err(|e| Error::Store(e.to_string()))?;

    let physical_after = kv_physical_stats(&store, &root)
        .await
        .map_err(|e| Error::Store(e.to_string()))?;
    let logical_after = kv_logical_stats(&store, &root)
        .await
        .map_err(|e| Error::Store(e.to_string()))?;

    Ok(KvOutput::CompactApply {
        before: KvStatsView::from_stats(&physical_before, &logical_before),
        after: KvStatsView::from_stats(&physical_after, &logical_after),
        compaction: KvCompactView::from_outcome(&outcome),
        timeout_secs: args.timeout_secs,
        dropped_checkpoints: gc.dropped_checkpoints,
    })
}

/// Write a physical-vs-logical stats block: totals, the reclaimable delta, and the per-subdir
/// physical breakdown.
fn write_kv_stats(w: &mut dyn std::io::Write, stats: &KvStatsView) -> std::io::Result<()> {
    let reclaimable = stats
        .physical_total_bytes
        .saturating_sub(stats.logical_live_bytes);
    let pct = if stats.physical_total_bytes > 0 {
        reclaimable as f64 / stats.physical_total_bytes as f64 * 100.0
    } else {
        0.0
    };
    writeln!(
        w,
        "  physical:    {} in {} object(s)",
        human_bytes(stats.physical_total_bytes),
        stats.physical_total_objects
    )?;
    writeln!(
        w,
        "  logical:     {} in {} live SST(s) (manifest gen {}, {} L0 + {} sorted run(s))",
        human_bytes(stats.logical_live_bytes),
        stats.logical_live_sst_count,
        stats.manifest_id,
        stats.l0_count,
        stats.sorted_run_count,
    )?;
    writeln!(
        w,
        "  reclaimable: {} ({pct:.1}% of physical — superseded SSTs + old manifests + replayed WAL)",
        human_bytes(reclaimable),
    )?;
    if !stats.dirs.is_empty() {
        writeln!(w, "  by subdir:")?;
        for d in &stats.dirs {
            writeln!(
                w,
                "    {:<12} {} in {} object(s)",
                format!("{}/", d.name),
                human_bytes(d.bytes),
                d.objects
            )?;
        }
    }
    Ok(())
}

/// Human-readable bytes (binary units), e.g. `17.2 GiB`. Diagnostic-only formatting.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `copy_dir_all` (used by `kv recover --adopt-volume`) copies a nested tree faithfully.
    #[test]
    fn copy_dir_all_copies_a_nested_tree() {
        let tmp = std::env::temp_dir().join(format!("br-kv-copy-{}", std::process::id()));
        let src = tmp.join("src");
        let dst = tmp.join("dst");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"a").unwrap();
        std::fs::write(src.join("sub/b.txt"), b"b").unwrap();
        copy_dir_all(&src, &dst).unwrap();
        assert_eq!(std::fs::read(dst.join("a.txt")).unwrap(), b"a");
        assert_eq!(std::fs::read(dst.join("sub/b.txt")).unwrap(), b"b");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn local_addr(data_dir: PathBuf) -> StoreAddr {
        StoreAddr {
            backend: boatramp_node::backends::KvBackend::Slatedb,
            data_dir,
            kv_s3: false,
            s3_bucket: None,
            s3_endpoint: None,
            s3_region: None,
            s3_path_style: false,
            kv_s3_prefix: "_kv".to_string(),
        }
    }

    /// C7 — the `boatramp kv` verbs are SlateDB-specific: a `sql`/`memory`/`cloudflare` backend gets a
    /// clear "not applicable" message (so a non-SlateDB operator is never pointed at a bogus store),
    /// while SlateDB proceeds. The SQL message names the engine's own recovery + the `kv-status` seam.
    #[test]
    fn kv_verbs_not_applicable_to_non_slatedb_backends() {
        use boatramp_node::backends::KvBackend;
        let mut addr = local_addr(PathBuf::from("./data"));
        addr.backend = KvBackend::Slatedb;
        assert!(addr.not_applicable("status").is_none(), "SlateDB proceeds");
        addr.backend = KvBackend::Sql;
        let msg = addr.not_applicable("recover").expect("sql is N/A");
        assert!(msg.contains("does NOT apply to the `sql`"));
        assert!(msg.contains("/api/kv-status"));
        addr.backend = KvBackend::Memory;
        assert!(
            addr.not_applicable("checkpoint")
                .unwrap()
                .contains("ephemeral")
        );
        addr.backend = KvBackend::Cloudflare;
        assert!(
            addr.not_applicable("repair")
                .unwrap()
                .contains("Cloudflare KV")
        );
    }

    /// `kv recover --adopt-volume` REFUSES a mounted path with no `kv-slate` store (never mutates the
    /// target) — the guard before any validate/swap.
    #[tokio::test]
    async fn adopt_volume_refuses_a_volume_without_a_kv_slate_store() {
        let tmp = std::env::temp_dir().join(format!("br-kv-adopt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let addr = local_addr(tmp.join("data"));
        let err = run_recover_adopt_volume(&addr, &tmp.join("emptyvol"), false)
            .await
            .expect_err("adopt must refuse a volume with no kv-slate store");
        assert!(matches!(err, Error::Store(_)), "got {err:?}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    /// `--adopt-volume` is refused for an `--kv-s3` target (it is a local-disk / fly-volume flow).
    #[tokio::test]
    async fn adopt_volume_refuses_an_s3_target() {
        let mut addr = local_addr(std::path::PathBuf::from("./data"));
        addr.kv_s3 = true;
        let err = run_recover_adopt_volume(&addr, std::path::Path::new("/mnt/snap"), true)
            .await
            .expect_err("adopt must refuse an --kv-s3 target");
        assert!(matches!(err, Error::Store(_)), "got {err:?}");
    }
}
