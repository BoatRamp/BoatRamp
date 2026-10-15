//! The control-plane **store migration mechanism**: a versioned, ordered registry of
//! forward-only migrations the engine walks to bring a store up to the layout this
//! binary requires.
//!
//! ## The mechanism
//!
//! - A single monotonic **schema version** ([`SchemaState::version`]) is recorded in
//!   the [`SCHEMA_KEY`] marker, alongside a crash-resume cursor
//!   ([`SchemaState::in_progress`]), the set of migrations whose destructive cleanup is
//!   still deferred ([`SchemaState::unfinalized`]), and an applied-[`AppliedRecord`]
//!   history for audit.
//! - Each [`Migration`] declares its target [`version`](Migration::version), a cheap
//!   [`is_applicable`](Migration::is_applicable) check, an ordered list of
//!   non-destructive [`forward_steps`](Migration::forward_steps), and (for an *online*
//!   migration) a list of destructive [`cleanup_steps`](Migration::cleanup_steps)
//!   deferred to `--finalize`.
//! - The [`registry`] lists every migration in ascending version order. A store at
//!   version `N` applies every migration with `version > N`, in order.
//! - Each [`Step`] is an idempotent, re-verifying unit; the engine records each
//!   completed step in the resume cursor and persists after every step, so a crash
//!   re-runs only the interrupted step. The reusable steps ([`RekeyFamily`],
//!   [`RewriteValues`], [`DeleteOldFamily`], …) are the building blocks a new migration
//!   composes rather than re-implementing copy/verify/resume.
//!
//! ## Online migrations + the dual soak
//!
//! An *online* migration writes its new state and leaves the old readable, deferring
//! the destructive delete to a `finalize` pass — so an operator can `--stage` (copy +
//! verify, serve off the new state with an old-state fallback), soak, then `--finalize`
//! (delete). A migration with no cleanup steps is *simple* (its forward is the whole
//! thing). `MigrateOptions::finalize` (the default / `one_shot`) runs cleanup inline;
//! `--stage` (`finalize = false`) leaves the store in the `dual` soak.
//!
//! ## Safety
//!
//! Forward-only (no down-migrations; rollback is a backup, or a revert within the
//! pre-finalize dual window while the old keys still exist). Copy-before-delete:
//! [`RekeyFamily`] copies + read-back verifies and never deletes; [`DeleteOldFamily`]
//! re-reads and byte-compares before each delete and refuses to delete an old key whose
//! new key is absent/mismatched — so a partially-copied family never loses data. Every
//! step is idempotent, so a re-run (or a concurrent racer in a cluster) converges
//! rather than corrupts. The startup guard ([`status`]) refuses to serve a store below
//! the current version.
//!
//! ## Cluster
//!
//! The migration runs through the same [`KvStore`] a node serves from; in a Raft
//! cluster that is the replicated store, so a single leader-run migration replicates
//! for free. Prefer running `boatramp migrate` **once** (against the leader) before a
//! rolling upgrade. The startup guard does not elect a leader or block followers, so if
//! several nodes start with `--auto-migrate` against a still-out-of-date store they may
//! run concurrently — which is **safe, only redundant**: every step is idempotent and
//! re-verifying, so racers converge. The marker cursor is a last-writer-wins `put` (no
//! CAS), so a race can at worst redo a step, never skip a delete-guard.

use std::collections::HashSet;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::kv::{KvStore, WriteOp};
use crate::project::{self, DEFAULT_PROJECT, DomainOwner, owner_kind};
use crate::time::now_unix;

/// The global marker key recording the store's schema version + migration progress.
pub const SCHEMA_KEY: &str = "schema/version";

/// A pre-migration snapshot of the full key list, written once before any change so an
/// operator can diff/audit what existed before the first migration ran.
pub const PREMIGRATION_INDEX_KEY: &str = "schema/premigration-index";

/// The latest schema version this binary knows how to reach — the highest-versioned
/// entry in [`registry`]. A store below this must be migrated before it will serve.
pub const CURRENT_VERSION: u32 = 2;

/// The version produced by the **default-scope re-home** migration ([`DefaultScopeRehomeV2`],
/// v0.31.0 Finding 8). Exposed so the serve wiring can detect that the store is in this
/// migration's `dual` soak (`unfinalized.contains(&DEFAULT_SCOPE_REHOME_VERSION)`) and enable the
/// translating blob read-fallback for the transition window — the blob substrate's analogue of the
/// KV copy-before-delete this migration performs (the KV finalize and the blob retire are meant to
/// happen together at the end of the soak; see the docs).
pub const DEFAULT_SCOPE_REHOME_VERSION: u32 = 2;

/// The guest **data-plane** KV families the default-scope re-key (migration 2) moves from the bare
/// `{base}` scope to the two-segment `{DEFAULT_PROJECT}/{base}` scope (Finding 8). Each key is
/// `{family}{scope}/…` (or `{family}{scope}` for the single-segment markers `mqpause/`/`mqpolicy/`/
/// `mqready/`/`mqlogmax/`), where `{scope}` is the `ProjectRef::qualified(..)` output. The payload
/// BLOBS (`mqp/`, `mqgp/`) live in a different substrate and migrate via the translating blob
/// read-fallback + drain, NOT here. `mqgstate/` carries the durable consumer-group OFFSETS, so it is
/// re-homed in the SAME forward pass as its `mqglog/`/`mqgd/` index — the runtime addresses the new
/// spelling only after the forward completes (the version guard), and the old spelling is deleted
/// only at finalize, so no message is lost and no topic is claimable under two spellings at once.
pub const DEFAULT_SCOPE_FAMILIES: &[&str] = &[
    "hkv/",      // guest key/value
    "mq/",       // work-queue index records
    "mqdead/",   // dead-lettered records
    "mqpause/",  // per-topic pause flag (key is `mqpause/{topic}`)
    "mqpolicy/", // per-topic operator policy (`mqpolicy/{topic}`)
    "mqready/",  // per-topic ready-set marker (`mqready/{topic}`)
    "mqglog/",   // grouped retained log
    "mqgstate/", // consumer-group durable state (hwm + in-flight OFFSETS)
    "mqlogmax/", // per-topic latest-id gate (`mqlogmax/{topic}`)
    "mqgd/",     // grouped dead-letters
];

/// The mutable per-name families the project re-key (migration 1) moves under
/// `project/<default>/…`. Order is irrelevant to correctness (families are independent)
/// but fixed for a legible, resumable progress record.
pub const MUTABLE_FAMILIES: &[&str] = &[
    "current/",
    "site/",
    "history/",
    "alias/",
    "domainverify/",
    "dnsmanaged/",
    "functions/",
    "metering/",
    "blobnotify/",
    "workflows/",
    "compute/",
    "compute_state/",
];

/// The domain-routing families: the **key stays global**, the **value** is rewritten
/// from a bare site name to a `{project, site}` [`DomainOwner`].
pub const DOMAIN_FAMILIES: &[&str] = &["domain/", "wildcard/", "httpchallenge/"];

/// Families that are **never** migrated by the project re-key: content-addressed bodies
/// (dedup-shared, stable across layouts) and control-plane singletons. Listed for
/// documentation + the migration's own guard against clobbering them. (Blob bodies live
/// under a two-hex-char shard prefix in the *blob* store, a different backend entirely.)
pub const GLOBAL_FAMILIES: &[&str] = &[
    "manifests/",
    "meta/",
    "siteconfig/",
    "computever/",
    "daemonconfig/",
    "authz/",
    "daemon/",
    "cert/",
    // The 0.2.0 namespaces themselves — already the project layout, must not be moved.
    "project/",
    "projectmeta/",
    "projectver/",
    "project-history/",
    "owner/",
    "schema/",
];

// ---- the marker ------------------------------------------------------------------

/// The persisted schema-version marker + migration progress.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SchemaState {
    /// The highest **forward-applied** migration version — the layout the store serves
    /// at. `0` = never migrated (a fresh store born at the current layout, or a
    /// pre-migration legacy store).
    pub version: u32,
    /// Migrations whose forward is applied but whose destructive cleanup is deferred (a
    /// `dual` soak, ascending). Empty = nothing awaiting `--finalize`.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub unfinalized: Vec<u32>,
    /// A forward phase interrupted mid-flight — the crash-resume cursor. Present only
    /// while a migration's forward steps are running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_progress: Option<InProgress>,
    /// Applied migrations, for audit.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<AppliedRecord>,
    /// Unix time of the last marker write.
    pub updated_at: u64,
}

/// A forward phase mid-flight: the migration being applied + the ids of its completed
/// steps (the resume cursor).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InProgress {
    /// The version whose forward is running.
    pub target: u32,
    /// Ids of the forward steps already completed (skipped on resume).
    pub steps_done: Vec<String>,
}

/// One applied migration, recorded in [`SchemaState::history`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedRecord {
    /// The migration's target version.
    pub version: u32,
    /// The migration's stable id.
    pub id: String,
    /// Unix time it was fully applied.
    pub at: u64,
}

/// The pre-mechanism (0.2.0-preview) marker shape, mapped onto [`SchemaState`] by the
/// tolerant reader so a store written by the original one-shot engine is understood.
#[derive(Debug, Deserialize)]
struct LegacyMarker {
    #[serde(default)]
    layout: u32,
    #[serde(default)]
    dual: bool,
    #[serde(default)]
    families_done: Vec<String>,
}

impl LegacyMarker {
    fn into_state(self) -> SchemaState {
        if self.layout >= 2 {
            // The project re-key (v1) forward is done; `dual` means cleanup pending.
            SchemaState {
                version: 1,
                unfinalized: if self.dual { vec![1] } else { Vec::new() },
                in_progress: None,
                history: Vec::new(),
                updated_at: now_unix(),
            }
        } else {
            // Layout 1: unmigrated. A partial `families_done` resumes v1's forward — its
            // family names map onto the new per-family step ids.
            let steps_done: Vec<String> = self
                .families_done
                .iter()
                .map(|f| rekey_step_id(DEFAULT_PROJECT, f))
                .collect();
            SchemaState {
                version: 0,
                unfinalized: Vec::new(),
                in_progress: (!steps_done.is_empty()).then_some(InProgress {
                    target: 1,
                    steps_done,
                }),
                history: Vec::new(),
                updated_at: now_unix(),
            }
        }
    }
}

// ---- public API (stable: consumed by the CLI + serve startup guard) --------------

/// How a store needs to be treated on startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Status {
    /// At the current version with nothing pending (or empty) — serve as-is.
    Ready,
    /// Below the current version with applicable work (or a forward interrupted
    /// mid-flight) — refuse to serve until migrated.
    NeedsMigration,
    /// Forward done, destructive cleanup deferred (`dual` soak) — serve OK; a
    /// `finalize` pass is the only remaining work.
    Dual,
}

/// Options controlling a migration pass.
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrateOptions {
    /// Scan and report what *would* change, writing nothing.
    pub dry_run: bool,
    /// Run each online migration's destructive cleanup inline (a one-shot). With
    /// `false` the pass stops after the forward phase, leaving old state for a
    /// soak/rollback window (`dual`); a later `finalize` runs the cleanups.
    pub finalize: bool,
}

impl MigrateOptions {
    /// The default one-shot migration: forward + cleanup, to the current version.
    pub fn one_shot() -> Self {
        Self {
            dry_run: false,
            finalize: true,
        }
    }
}

/// A per-pass tally of what a migration run moved (or, on a dry run, would move).
/// Aggregated across every migration applied in the pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReport {
    /// Keys re-keyed per family (`family` → count).
    pub rekeyed: Vec<(String, usize)>,
    /// Index values rewritten per family.
    pub values_rewritten: Vec<(String, usize)>,
    /// Owner reverse-index entries written.
    pub owner_entries: usize,
    /// Whether the pass created the `default` project pointer.
    pub created_default_project: bool,
    /// The store was already at the current version — the pass was a no-op.
    pub already_migrated: bool,
    /// The store is left in the `dual` soak (forward done, cleanup deferred).
    pub dual: bool,
}

impl MigrationReport {
    /// Total keys re-keyed across all families.
    pub fn total_rekeyed(&self) -> usize {
        self.rekeyed.iter().map(|(_, n)| n).sum()
    }
}

/// A migration failure.
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// The underlying KV store failed.
    #[error(transparent)]
    Kv(#[from] crate::error::KvError),
    /// A copied datum failed read-back verification — the pass aborts rather than risk
    /// deleting the source of a datum that did not land.
    #[error("verification failed for migrated key {0}")]
    Verify(String),
    /// (De)serializing the marker / a record failed.
    #[error("migration serde error: {0}")]
    Serde(String),
    /// The default-scope re-home (migration 2) is blocked by a pre-existing scope conflict: a
    /// reserved-`default`-project resource is named `default` (its bare data-plane scope `default` is
    /// indistinguishable from an already-re-homed `default/…` key), or is named like a KNOWN project
    /// (its bare scope `{name}` commingles with that project's keyspace — the pre-existing Finding-8
    /// collision). The commingled keyspace carries no provenance, so the re-home cannot auto-split it
    /// without risking a cross-tenant mix — it refuses, fail-closed. This is an OFFLINE `boatramp
    /// migrate` refusal (the node keeps serving the existing layout meanwhile — it never bricks a
    /// boot — and `serve --auto-migrate` logs it and falls back to serving). Resolve it manually with
    /// the existing operator tools: re-create each listed default-project resource under a
    /// non-colliding name via the normal deploy flow and delete the old one, then re-run `boatramp
    /// migrate` (docs/default-scope-migration.md has the step-by-step). Detected PRE-forward
    /// only (before any `default/…` re-homed key exists).
    #[error(
        "refusing the default-scope re-home: the default project has resource(s) whose bare \
         data-plane scope conflicts with the re-home ({resources:?}). This is an offline `boatramp \
         migrate` refusal, not a serve error — the node keeps serving the existing layout (and \
         `serve --auto-migrate` falls back to serving rather than failing). To resolve: re-create \
         each listed default-project resource under a NON-colliding name via the normal deploy flow \
         and delete the old one (the conflict is a resource named like a tenant project, or \
         `default`), then re-run `boatramp migrate`. See docs/default-scope-migration.md."
    )]
    DefaultNamedResource {
        /// The offending resource identities (e.g. `["site/default", "compute/acme (commingles with project `acme`)"]`).
        resources: Vec<String>,
    },
    /// `migrate --abort` found no staged (dual-soak) migration to roll back — the store is either
    /// already at a clean version (nothing unfinalized) or below any online migration.
    #[error(
        "nothing to abort: the store has no migration in the dual soak (run `boatramp migrate status`)"
    )]
    AbortNothingStaged,
    /// `migrate --abort` refused because a forward phase is interrupted mid-flight (a crash-resume
    /// cursor is present). Re-run `boatramp migrate` to complete the forward into the dual soak first,
    /// then abort.
    #[error(
        "cannot abort: a migration forward phase is interrupted mid-flight; re-run `boatramp migrate` \
         to finish staging it into the dual soak, then `--abort`"
    )]
    AbortMidFlight,
    /// `migrate --abort` refused because a staged migration does not support a verified lossless
    /// reverse (it is not [`Migration::abortable`]). Finalizing forward is the only completion.
    #[error("cannot abort: staged migration version {version} is not reversible")]
    AbortNotSupported {
        /// The non-abortable staged migration version.
        version: u32,
    },
    /// `migrate --abort` refused because rolling back would LOSE data: a staged NEW key diverged from
    /// its retained OLD twin (a write landed during the soak). Fail-closed — nothing is deleted.
    /// Finalize forward (`boatramp migrate --finalize`) or reconcile the listed keys manually.
    #[error(
        "cannot abort without data loss: {} staged key(s) received writes during the soak and have no \
         identical pre-migration twin to roll back to (e.g. {first}). Finalize forward instead, or \
         reconcile manually.",
        keys.len(),
        first = keys.first().map(String::as_str).unwrap_or("")
    )]
    AbortWouldLoseData {
        /// The diverged staged keys that block a lossless abort.
        keys: Vec<String>,
    },
}

/// Read the schema-version marker, tolerantly mapping the pre-mechanism marker shape.
/// A fresh store (no marker) reads as version 0.
pub async fn read_state(kv: &dyn KvStore) -> Result<SchemaState, MigrateError> {
    let Some(bytes) = kv.get(SCHEMA_KEY).await? else {
        return Ok(SchemaState::default());
    };
    if let Ok(state) = serde_json::from_slice::<SchemaState>(&bytes) {
        return Ok(state);
    }
    // Not the current shape → the pre-mechanism `{layout, dual, families_done}` marker.
    let legacy: LegacyMarker =
        serde_json::from_slice(&bytes).map_err(|e| MigrateError::Serde(e.to_string()))?;
    Ok(legacy.into_state())
}

async fn persist_state(kv: &dyn KvStore, state: &SchemaState) -> Result<(), MigrateError> {
    let bytes = serde_json::to_vec(state).map_err(|e| MigrateError::Serde(e.to_string()))?;
    // Crown-jewel (v0.9.0 KV-recovery, C2): a migration step re-keys sealed secrets / authz / token
    // records in place, then advances this SCHEMA_KEY cursor. Frontier-sync the cursor write so the
    // whole just-completed step (its re-keyed crown-jewel data, already in the memtable) is past the
    // durable replay boundary before the next step — a boot-time crash mid-migration can then be
    // resumed from a durable cursor and the self-heal-on-open can never drop a re-keyed secret.
    kv.put_durable_checkpointed(SCHEMA_KEY, bytes).await?;
    Ok(())
}

/// Classify a store for the serve-startup guard.
pub async fn status(kv: &dyn KvStore) -> Result<Status, MigrateError> {
    status_of(kv, &registry()).await
}

async fn status_of(
    kv: &dyn KvStore,
    migrations: &[Box<dyn Migration>],
) -> Result<Status, MigrateError> {
    let state = read_state(kv).await?;
    // A forward interrupted mid-flight must be resumed before serving.
    if state.in_progress.is_some() {
        return Ok(Status::NeedsMigration);
    }
    // Forward done, cleanup deferred: serve OK, finalize pending.
    if !state.unfinalized.is_empty() {
        return Ok(Status::Dual);
    }
    // Any pending migration with real work refuses serving; a fresh store whose pending
    // migrations are all inapplicable is Ready (new writes already land at the current
    // layout).
    for m in migrations.iter().filter(|m| m.version() > state.version) {
        if m.is_applicable(kv).await? {
            return Ok(Status::NeedsMigration);
        }
    }
    Ok(Status::Ready)
}

/// Migrate `kv` up to the current version, resumable + idempotent. Applies every
/// registered migration whose version exceeds the store's, in order; forward phases
/// are non-destructive, and (unless `finalize`) destructive cleanups are left for a
/// `dual` soak. Safe to call on an up-to-date store (no-op) and safe to re-run after
/// an interruption (resumes from the marker).
pub async fn migrate(
    kv: &dyn KvStore,
    opts: MigrateOptions,
) -> Result<MigrationReport, MigrateError> {
    // Non-interactive: an empty skip set ⇒ the guard refuses on ANY default-scope collision.
    run(kv, opts, &HashSet::new(), &registry()).await
}

/// An operator's answers to the interactive migration's [`MigrationDecision`]s. Collisions resolved by
/// renaming are simply gone from the next scan (nothing to carry); this records the ones the operator
/// chose to SKIP (proceed, leaving the resource un-re-homed/bare) and whether any decision was answered
/// `abort`. Serde so the console admin surface can persist/replay it (`schema/pending-decision`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationAnswers {
    /// Collision decision ids (`collision:{kind}/{name}`) the operator chose to SKIP.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub skip_collisions: Vec<String>,
    /// The operator chose `abort` at a decision — the migration must not proceed.
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub aborted: bool,
}

/// The outcome of an interactive stage ([`migrate_with_answers`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteractiveOutcome {
    /// The operator aborted at a decision; nothing was changed.
    Aborted,
    /// The stage ran; carries its report.
    Staged(MigrationReport),
}

/// Stage the migration honoring the operator's interactive [`MigrationAnswers`]. Unlike the
/// non-interactive [`migrate`], a collision the operator chose to SKIP does not refuse (the resource
/// is left bare / un-re-homed); a collision that is neither renamed-away nor skipped STILL refuses
/// fail-closed (so the driver can re-prompt). `abort` short-circuits without touching the store.
/// Always STAGES into the dual soak (never inline-finalizes) — finalize stays an explicit later step.
pub async fn migrate_with_answers(
    kv: &dyn KvStore,
    answers: &MigrationAnswers,
) -> Result<InteractiveOutcome, MigrateError> {
    if answers.aborted {
        return Ok(InteractiveOutcome::Aborted);
    }
    let skip: HashSet<String> = answers.skip_collisions.iter().cloned().collect();
    let report = run(
        kv,
        MigrateOptions {
            dry_run: false,
            finalize: false,
        },
        &skip,
        &registry(),
    )
    .await?;
    Ok(InteractiveOutcome::Staged(report))
}

/// The reserved key holding **armed** interactive answers — the operator's [`MigrationAnswers`]
/// collected via the console wizard, to be consumed by the next `serve --auto-migrate` at BOOT (before
/// the handler runtime + its layout decorators are built), so the stage runs with no process ever
/// serving through a stale layout (the zero-window path). A `schema/` global key, so the
/// backward-read-compat decorator passes it through untouched on every store.
pub const ARMED_ANSWERS_KEY: &str = "schema/migrate-answers";

/// Read the armed interactive answers, if any (`None` ⇒ nothing armed).
pub async fn read_armed_answers(
    kv: &dyn KvStore,
) -> Result<Option<MigrationAnswers>, MigrateError> {
    match kv.get(ARMED_ANSWERS_KEY).await? {
        Some(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).map_err(|e| MigrateError::Serde(e.to_string()))?,
        )),
        None => Ok(None),
    }
}

/// **Arm** interactive answers for the next boot-time stage (the console wizard writes these, then the
/// operator restarts and `serve --auto-migrate` consumes them). Durable (frontier-synced) so a crash
/// can't lose them.
pub async fn arm_answers(kv: &dyn KvStore, answers: &MigrationAnswers) -> Result<(), MigrateError> {
    let bytes = serde_json::to_vec(answers).map_err(|e| MigrateError::Serde(e.to_string()))?;
    kv.put_durable_checkpointed(ARMED_ANSWERS_KEY, bytes)
        .await?;
    Ok(())
}

/// Clear any armed answers (consumed after a successful boot-time stage, or when the operator un-arms).
pub async fn clear_armed_answers(kv: &dyn KvStore) -> Result<(), MigrateError> {
    kv.delete_checkpointed(ARMED_ANSWERS_KEY).await?;
    Ok(())
}

/// Complete a store staged into the `dual` soak (and apply any pending forward): a
/// one-shot pass that runs every deferred cleanup and flips to the current version.
pub async fn finalize(kv: &dyn KvStore) -> Result<MigrationReport, MigrateError> {
    migrate(kv, MigrateOptions::one_shot()).await
}

/// **Abort** a store staged into the dual soak — roll it back to its exact pre-forward bytes, the
/// inverse of staging a `migrate`. An OFFLINE operator action (run with the node stopped; opening the
/// store fences a live writer). Aborts every unfinalized online migration, newest-first:
///
/// 1. **Verify** each is [`Migration::abortable`] and its [`abort_verify`](Migration::abort_verify)
///    passes — writing NOTHING — so an abort is wholly safe or wholly refused (fail-closed on any key
///    that received a soak-window write).
/// 2. **Durably downgrade** the schema marker below the aborted versions FIRST, so a crash during the
///    next step leaves a safe below-version store (served via backward-read-compat) whose leftover NEW
///    keys are harmless orphans a re-run reclaims.
/// 3. **Clean up** — delete the staged NEW keys (idempotent/resumable).
///
/// Refuses if nothing is staged ([`MigrateError::AbortNothingStaged`]) or a forward is interrupted
/// mid-flight ([`MigrateError::AbortMidFlight`]).
pub async fn abort(kv: &dyn KvStore) -> Result<MigrationReport, MigrateError> {
    abort_with(kv, &registry()).await
}

async fn abort_with(
    kv: &dyn KvStore,
    migrations: &[Box<dyn Migration>],
) -> Result<MigrationReport, MigrateError> {
    let mut state = read_state(kv).await?;
    if state.in_progress.is_some() {
        return Err(MigrateError::AbortMidFlight);
    }
    if state.unfinalized.is_empty() {
        return Err(MigrateError::AbortNothingStaged);
    }
    // Staged migrations, newest-first.
    let mut staged = state.unfinalized.clone();
    staged.sort_unstable();
    staged.reverse();
    // 1. VERIFY every staged migration is reversible and would lose nothing (writes nothing).
    for v in &staged {
        let m = migrations
            .iter()
            .find(|m| m.version() == *v)
            .ok_or(MigrateError::AbortNotSupported { version: *v })?;
        if !m.abortable() {
            return Err(MigrateError::AbortNotSupported { version: *v });
        }
        m.abort_verify(kv).await?;
    }
    // 2. DURABLY DOWNGRADE the marker FIRST (crash-safe). Drop the aborted versions from history +
    //    unfinalized and set `version` to the highest surviving applied version.
    let aborted: HashSet<u32> = staged.iter().copied().collect();
    state.history.retain(|r| !aborted.contains(&r.version));
    state.unfinalized.retain(|v| !aborted.contains(v));
    // Return to the version just below the EARLIEST aborted migration. The registry is sequential and
    // the unfinalized set is a contiguous top suffix, so this is exactly the pre-stage version.
    // (Recomputing from `history` alone is wrong — a store can reach its prior version with no history
    // record, e.g. a legacy store whose v1 predates history tracking; the seed/`LegacyMarker` path.)
    let floor = staged.iter().copied().min().unwrap_or(0);
    state.version = floor.saturating_sub(1);
    state.updated_at = now_unix();
    persist_state(kv, &state).await?;
    // 3. CLEANUP — delete the staged NEW keys (idempotent; a crash here resumes on re-run).
    for v in &staged {
        if let Some(m) = migrations.iter().find(|m| m.version() == *v) {
            m.abort_cleanup(kv).await?;
        }
    }
    Ok(MigrationReport::default())
}

/// The engine core, parameterized by the migration list so tests can drive it with a
/// synthetic chain.
async fn run(
    kv: &dyn KvStore,
    opts: MigrateOptions,
    skip_collisions: &HashSet<String>,
    migrations: &[Box<dyn Migration>],
) -> Result<MigrationReport, MigrateError> {
    let mut state = read_state(kv).await?;
    let mut report = MigrationReport::default();

    let has_pending_forward = migrations.iter().any(|m| m.version() > state.version);
    if !has_pending_forward && state.unfinalized.is_empty() && state.in_progress.is_none() {
        report.already_migrated = true;
        return Ok(report);
    }

    // Fail-closed PRE-MIGRATION guard (v0.31.0 Finding 8): BEFORE migration 2's forward runs (so no
    // `…/default/…` re-homed key exists yet), refuse if a default-project resource's bare data-plane
    // scope conflicts with the re-home — a site/compute named `default` (collides with the re-home
    // prefix) or named like a KNOWN project (the pre-existing commingling). Skipped on resume (the
    // pre-forward invariant no longer holds). `skip_collisions` holds the decision ids
    // (`collision:{kind}/{name}`) the operator explicitly chose to SKIP via the interactive flow — a
    // skipped resource is left bare (its data is NOT re-homed; `rehome_default_scope` already no-ops
    // it) and does NOT refuse; a collision that is neither resolved (renamed away) nor skipped STILL
    // refuses fail-closed. The non-interactive `migrate()` passes an empty set, so it refuses on ANY
    // collision (unchanged). This is the KV-level half; blob/libsql substrate-completeness is observed
    // by the node-level readiness guard.
    let v2_pending = state.version < DEFAULT_SCOPE_REHOME_VERSION;
    let resuming_v2 = state
        .in_progress
        .as_ref()
        .is_some_and(|ip| ip.target == DEFAULT_SCOPE_REHOME_VERSION);
    if v2_pending && !resuming_v2 {
        let unresolved: Vec<String> = default_scope_collisions(kv)
            .await?
            .into_iter()
            .filter(|c| !skip_collisions.contains(&format!("collision:{}/{}", c.kind, c.name)))
            .map(|c| c.describe())
            .collect();
        if !unresolved.is_empty() {
            return Err(MigrateError::DefaultNamedResource {
                resources: unresolved,
            });
        }
    }

    // A dry run reports the pending forward work without persisting anything.
    if opts.dry_run {
        for m in migrations.iter().filter(|m| m.version() > state.version) {
            if m.is_applicable(kv).await? {
                for step in m.forward_steps() {
                    step.run(kv, true, &mut report).await?;
                }
            }
        }
        report.dual = !opts.finalize;
        return Ok(report);
    }

    // Snapshot the pre-migration key list once (best-effort, never overwriting).
    if kv.get(PREMIGRATION_INDEX_KEY).await?.is_none() {
        write_premigration_index(kv).await?;
    }

    // Forward phase: apply each pending migration in order.
    for m in migrations {
        if m.version() <= state.version {
            continue;
        }
        let resuming = state
            .in_progress
            .as_ref()
            .is_some_and(|ip| ip.target == m.version());

        // A migration with no work on this store still advances the version (records it
        // as vacuously applied), so a fresh store reaches the current version.
        if !resuming && !m.is_applicable(kv).await? {
            state.version = m.version();
            state.history.push(AppliedRecord {
                version: m.version(),
                id: m.id().to_string(),
                at: now_unix(),
            });
            state.updated_at = now_unix();
            persist_state(kv, &state).await?;
            continue;
        }

        // Run the forward steps, skipping those already recorded, persisting the cursor
        // after each so a crash resumes at the next step.
        let mut done = if resuming {
            state
                .in_progress
                .take()
                .map(|ip| ip.steps_done)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        for step in m.forward_steps() {
            let sid = step.id();
            if done.contains(&sid) {
                continue;
            }
            step.run(kv, false, &mut report).await?;
            done.push(sid);
            state.in_progress = Some(InProgress {
                target: m.version(),
                steps_done: done.clone(),
            });
            state.updated_at = now_unix();
            persist_state(kv, &state).await?;
        }

        // Forward complete: the version advances; the destructive cleanup is deferred.
        state.version = m.version();
        state.in_progress = None;
        state.history.push(AppliedRecord {
            version: m.version(),
            id: m.id().to_string(),
            at: now_unix(),
        });
        if m.online() {
            state.unfinalized.push(m.version());
        }
        state.updated_at = now_unix();
        persist_state(kv, &state).await?;
    }

    // Finalize: run the deferred cleanups (this pass's + any pre-staged), oldest first.
    if opts.finalize && !state.unfinalized.is_empty() {
        let mut pending = state.unfinalized.clone();
        pending.sort_unstable();
        for v in pending {
            if let Some(m) = migrations.iter().find(|m| m.version() == v) {
                for step in m.cleanup_steps() {
                    step.run(kv, false, &mut report).await?;
                }
            }
        }
        state.unfinalized.clear();
        state.updated_at = now_unix();
        persist_state(kv, &state).await?;
    }

    report.dual = !state.unfinalized.is_empty();
    Ok(report)
}

/// Write the pre-migration key snapshot (a newline-joined list of every key that a
/// migration might touch, for audit/rollback). Best-effort.
async fn write_premigration_index(kv: &dyn KvStore) -> Result<(), MigrateError> {
    let mut keys = Vec::new();
    for family in MUTABLE_FAMILIES.iter().chain(DOMAIN_FAMILIES) {
        keys.extend(kv.list_prefix(family).await?);
    }
    keys.sort();
    kv.put(PREMIGRATION_INDEX_KEY, keys.join("\n").into_bytes())
        .await?;
    Ok(())
}

// ---- the migration registry ------------------------------------------------------

/// Every migration this binary can apply, in **ascending version order**. A store at
/// version `N` applies each entry with `version > N`. Append the next breaking store
/// change here as a new [`Migration`] with the next version; never renumber or reorder
/// an existing one.
fn registry() -> Vec<Box<dyn Migration>> {
    vec![Box::new(ProjectRekeyV1), Box::new(DefaultScopeRehomeV2)]
}

/// One ordered, versioned, forward-only migration.
#[async_trait]
trait Migration: Send + Sync {
    /// The schema version this migration produces (unique + ascending across the
    /// registry).
    fn version(&self) -> u32;
    /// A stable id for logs + the marker history.
    fn id(&self) -> &'static str;
    /// A one-line description.
    #[allow(dead_code)]
    fn description(&self) -> &'static str;
    /// Whether this store has anything for this migration to do. A cheap detector, so a
    /// fresh store (born at the current layout) is `Ready` without running the
    /// migration.
    async fn is_applicable(&self, kv: &dyn KvStore) -> Result<bool, MigrateError>;
    /// The ordered, non-destructive forward steps that make the store serve at this
    /// version.
    fn forward_steps(&self) -> Vec<Box<dyn Step>>;
    /// The destructive cleanup steps (delete old state), deferred to `finalize`. Empty
    /// ⇒ a *simple* migration.
    fn cleanup_steps(&self) -> Vec<Box<dyn Step>> {
        Vec::new()
    }
    /// Whether this migration has a deferrable destructive phase (supports the dual
    /// soak).
    fn online(&self) -> bool {
        !self.cleanup_steps().is_empty()
    }

    /// Whether this (online) migration can be **aborted** while in the dual soak — rolled back to the
    /// exact pre-forward bytes. Default `false`: a migration that does not implement a verified,
    /// lossless reverse is not abortable (the engine refuses `migrate --abort` while it is staged, so a
    /// half-reverse can never corrupt). The default-scope re-home overrides this to `true` (its forward
    /// is a non-destructive copy, so deleting the copy is a clean reverse).
    fn abortable(&self) -> bool {
        false
    }

    /// Phase 1 of abort — **verify, write nothing**: refuse (all-or-nothing) if rolling back would
    /// lose data, i.e. a staged NEW key diverged from its retained OLD twin (a write during the soak).
    /// Run across the whole migration BEFORE any delete, so an abort is either wholly safe or wholly
    /// refused. Default: nothing to verify.
    async fn abort_verify(&self, _kv: &dyn KvStore) -> Result<(), MigrateError> {
        Ok(())
    }

    /// Phase 2 of abort — **cleanup**: delete the staged NEW keys (whose OLD twin `abort_verify`
    /// confirmed is present + identical), returning the store to its pre-forward bytes. Idempotent +
    /// resumable (an already-deleted NEW key is skipped), and run by the engine ONLY after it has
    /// durably downgraded the schema marker below this version — so a crash mid-cleanup leaves a safe
    /// below-version store (served via backward-read-compat) with harmless orphan NEW keys a re-run
    /// reclaims. Default: nothing to clean up.
    async fn abort_cleanup(&self, _kv: &dyn KvStore) -> Result<(), MigrateError> {
        Ok(())
    }
}

/// Migration **1** — re-key the flat, pre-0.2.0 store to the project-scoped layout: move
/// each mutable per-name family under `project/<default>/…`, rewrite the domain-routing
/// index values to the `{project, site}` form, create the `default` project pointer, and
/// build the `owner/*` reverse index. Online (the old-key delete is deferrable).
struct ProjectRekeyV1;

#[async_trait]
impl Migration for ProjectRekeyV1 {
    fn version(&self) -> u32 {
        1
    }
    fn id(&self) -> &'static str {
        "project-rekey"
    }
    fn description(&self) -> &'static str {
        "re-key the pre-0.2.0 store under project/<default>/ and add the project-scoped index"
    }
    async fn is_applicable(&self, kv: &dyn KvStore) -> Result<bool, MigrateError> {
        // Any layout-1 datum in a mutable or domain family means there is work to do.
        for family in MUTABLE_FAMILIES.iter().chain(DOMAIN_FAMILIES) {
            if !kv.list_prefix(family).await?.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn forward_steps(&self) -> Vec<Box<dyn Step>> {
        let mut steps: Vec<Box<dyn Step>> = Vec::new();
        for family in MUTABLE_FAMILIES {
            steps.push(Box::new(RekeyFamily {
                family,
                project: DEFAULT_PROJECT,
            }));
        }
        for family in DOMAIN_FAMILIES {
            steps.push(Box::new(RewriteValues {
                family,
                transform: domain_owner_canonical,
            }));
        }
        steps.push(Box::new(EnsureDefaultProject));
        steps.push(Box::new(BuildOwnerIndex));
        steps
    }
    fn cleanup_steps(&self) -> Vec<Box<dyn Step>> {
        MUTABLE_FAMILIES
            .iter()
            .map(|family| {
                Box::new(DeleteOldFamily {
                    family,
                    project: DEFAULT_PROJECT,
                }) as Box<dyn Step>
            })
            .collect()
    }
}

/// Migration **2** — re-home the bare **default-scoped** guest data plane under the two-segment
/// `default/…` scope (v0.31.0 Finding 8). Before this, [`ProjectRef::qualified`] special-cased the
/// reserved `default` project to a BARE one-segment scope (`qualified(DEFAULT, "blog") == "blog"`),
/// which let a `default`-project workload collide with a same-named NAMED project across every
/// client-composed-key family (`hblob/`, `hkv/`, `mq*/`). Dropping that special-case makes `default`
/// a normal two-segment project; this migration re-homes the KV substrates that PERSIST the bare
/// default scope (`hkv/` + every `mq*/` KV family) from `{family}{base}/…` to
/// `{family}default/{base}/…`. Online (the old-key delete is deferred to `--finalize`).
///
/// The transform is the **default-scope re-home** ([`rehome_default_scope`]): a key is moved ONLY
/// when its scope segment is a bare default scope (not a known project name), so a named project's
/// keys are never touched and a re-run (or a dual-soak re-scan that sees both spellings) is a no-op.
/// This is a *default-scope re-home* — insert `default/` AFTER the family prefix — NOT the
/// `project/<proj>/` wrap [`RekeyFamily`] hard-codes; it mirrors [`RekeyFamily`]/[`DeleteOldFamily`]'s
/// copy→verify / re-read→byte-compare→delete invariants with that transform parameterized in.
struct DefaultScopeRehomeV2;

#[async_trait]
impl Migration for DefaultScopeRehomeV2 {
    fn version(&self) -> u32 {
        DEFAULT_SCOPE_REHOME_VERSION
    }
    fn id(&self) -> &'static str {
        "default-scope-rehome"
    }
    fn description(&self) -> &'static str {
        "re-home the bare default-scoped guest data plane (hkv/ + mq*/ KV families) under the \
         two-segment default/ scope (Finding 8)"
    }
    async fn is_applicable(&self, kv: &dyn KvStore) -> Result<bool, MigrateError> {
        // Applicable iff at least one key under a data-plane family is a bare default scope needing
        // re-home — a store with only named-project (already two-segment) data-plane keys is NOT
        // applicable, so it advances vacuously without a spurious dual soak. Short-circuits on the
        // first re-homeable key. (Only ever reached while the store is below this version — once at
        // version 2 the startup `status` guard never re-scans these families.)
        let projects = known_projects(kv).await?;
        for family in DEFAULT_SCOPE_FAMILIES {
            for key in kv.list_prefix(family).await? {
                if rehome_default_scope(family, &key, &projects).is_some() {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    fn forward_steps(&self) -> Vec<Box<dyn Step>> {
        DEFAULT_SCOPE_FAMILIES
            .iter()
            .map(|family| Box::new(RehomeDefaultScope { family }) as Box<dyn Step>)
            .collect()
    }
    fn cleanup_steps(&self) -> Vec<Box<dyn Step>> {
        DEFAULT_SCOPE_FAMILIES
            .iter()
            .map(|family| Box::new(DeleteRehomedDefaultScope { family }) as Box<dyn Step>)
            .collect()
    }
    fn abortable(&self) -> bool {
        // The forward is a non-destructive copy (the bare OLD keys are retained until finalize), so
        // deleting the re-homed NEW keys is a provably-lossless reverse (verified below).
        true
    }
    async fn abort_verify(&self, kv: &dyn KvStore) -> Result<(), MigrateError> {
        // Refuse (all-or-nothing) if any re-homed NEW key (`{family}default/{suffix}`) diverged from
        // its retained OLD twin (`{family}{suffix}`) — a write during the soak the reverse would lose.
        // Writes nothing; the engine deletes only after this passes for the whole migration.
        let mut divergent = Vec::new();
        for family in DEFAULT_SCOPE_FAMILIES {
            for new_key in kv.list_prefix(family).await? {
                let Some(old_key) = default_scope_to_bare(family, &new_key) else {
                    continue; // not a re-homed default/ key (bare old key, named project)
                };
                match (kv.get(&old_key).await?, kv.get(&new_key).await?) {
                    // Clean: the NEW key equals its retained OLD twin → safe to drop the NEW copy.
                    (Some(o), Some(n)) if o == n => {}
                    // The NEW key is already gone (a prior partial abort) → nothing to lose.
                    (_, None) => {}
                    // The NEW key is present but has no identical OLD twin — a soak-window write the
                    // reverse would discard. Refuse, naming the key.
                    (_, Some(_)) => divergent.push(new_key),
                }
            }
        }
        if divergent.is_empty() {
            Ok(())
        } else {
            divergent.sort();
            Err(MigrateError::AbortWouldLoseData { keys: divergent })
        }
    }
    async fn abort_cleanup(&self, kv: &dyn KvStore) -> Result<(), MigrateError> {
        // Delete every re-homed NEW key (verified clean by `abort_verify`), leaving only the bare OLD
        // keys — the exact pre-forward bytes. Idempotent: an already-deleted NEW key simply isn't
        // listed. Re-verifies the OLD twin per key as a belt-and-suspenders (never deletes a NEW key
        // lacking an identical OLD twin, even if state changed since `abort_verify`).
        for family in DEFAULT_SCOPE_FAMILIES {
            for new_key in kv.list_prefix(family).await? {
                let Some(old_key) = default_scope_to_bare(family, &new_key) else {
                    continue;
                };
                match (kv.get(&old_key).await?, kv.get(&new_key).await?) {
                    (Some(o), Some(n)) if o == n => kv.delete(&new_key).await?,
                    (_, None) => {}
                    (_, Some(_)) => {
                        return Err(MigrateError::AbortWouldLoseData {
                            keys: vec![new_key],
                        });
                    }
                }
            }
        }
        Ok(())
    }
}

/// The set of **known project names** (the `projectmeta/<name>` pointer keys), including the reserved
/// `default` once the v1 re-key has materialized it. Used by [`rehome_default_scope`] to tell a bare
/// default scope (a site/function/topic-base belonging to the default project) from a key that is
/// already two-segment-scoped under a named project.
pub(crate) async fn known_projects(kv: &dyn KvStore) -> Result<HashSet<String>, MigrateError> {
    let mut set = HashSet::new();
    for key in kv.list_prefix(project::POINTER_PREFIX).await? {
        if let Some(name) = key.strip_prefix(project::POINTER_PREFIX)
            && !name.is_empty()
            && !name.contains('/')
        {
            set.insert(name.to_string());
        }
    }
    Ok(set)
}

/// Pre-forward conflict scan (v0.31.0 Finding 8): default-project resources whose BARE data-plane
/// scope conflicts with the default-scope re-home — a site or compute workload literally named
/// `default` (its scope collides with the `default/…` re-home prefix) or named like a KNOWN project
/// (its bare scope `{name}` commingles with that project's keyspace, the pre-existing collision).
/// Returns a human list of offending `kind/name (reason)` identities (empty ⇒ clear).
///
/// Scans the control-plane resource pointers (`project/default/site|compute/<name>`), which are
/// stable regardless of the data-plane re-home, so it is correct whenever called — but it is only
/// *meaningful as a fail-closed gate* PRE-forward (the engine skips it on resume). Functions are not
/// scanned: their scope is always `fn/<name>` (first segment `fn`), so a function can never collide.
pub async fn default_scope_premigration_conflicts(
    kv: &dyn KvStore,
) -> Result<Vec<String>, MigrateError> {
    Ok(default_scope_collisions(kv)
        .await?
        .iter()
        .map(DefaultScopeCollision::describe)
        .collect())
}

/// Why a default-project resource's bare scope conflicts with the re-home.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CollisionReason {
    /// The resource is literally named `default` — its bare scope collides with the `default/…`
    /// re-home prefix.
    NamedDefault,
    /// The resource is named like a KNOWN tenant project — its bare scope `{name}` commingles with
    /// that project's keyspace (the pre-existing Finding-8 collision), undecidable to auto-split.
    CommingleProject,
}

/// A structured default-scope collision — a default-project `site`/`compute` whose bare data-plane
/// scope conflicts with the re-home. The structured form backs both the string refusal
/// ([`default_scope_premigration_conflicts`]) and the interactive [`plan`]'s operator-answered
/// decision (rename / skip / abort).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DefaultScopeCollision {
    /// The resource kind (`site` / `compute`).
    pub kind: String,
    /// The colliding resource name.
    pub name: String,
    /// Why it conflicts.
    pub reason: CollisionReason,
}

impl DefaultScopeCollision {
    /// The one-line human description (stable substrings `"<kind>/<name>"` + `"commingles"`, relied on
    /// by the `DefaultNamedResource` error message and its test).
    pub fn describe(&self) -> String {
        let Self { kind, name, reason } = self;
        match reason {
            CollisionReason::NamedDefault => format!(
                "{kind}/{name} (named `default` — its scope collides with the re-home prefix)"
            ),
            CollisionReason::CommingleProject => {
                format!("{kind}/{name} (commingles with the existing project `{name}`)")
            }
        }
    }
}

/// Pre-forward conflict scan, STRUCTURED (the source of [`default_scope_premigration_conflicts`]).
/// Scans the control-plane `site`/`compute` pointers of the default project (both the v1+
/// `project/default/<kind>/<name>` and the pre-v1 flat `<kind>/<name>` shapes) and classifies each
/// name that is `default` or a known tenant project. Sorted, de-duplicated.
pub async fn default_scope_collisions(
    kv: &dyn KvStore,
) -> Result<Vec<DefaultScopeCollision>, MigrateError> {
    let projects = known_projects(kv).await?; // includes the reserved `default`
    let mut out = Vec::new();
    for kind in ["site", "compute"] {
        let mut seen = HashSet::new();
        for prefix in [
            format!("project/{DEFAULT_PROJECT}/{kind}/"),
            format!("{kind}/"),
        ] {
            for key in kv.list_prefix(&prefix).await? {
                let Some(rest) = key.strip_prefix(&prefix) else {
                    continue;
                };
                let name = rest.split('/').next().unwrap_or("");
                if name.is_empty() || !seen.insert(name.to_string()) {
                    continue;
                }
                let reason = if name == DEFAULT_PROJECT {
                    Some(CollisionReason::NamedDefault)
                } else if projects.contains(name) {
                    Some(CollisionReason::CommingleProject)
                } else {
                    None
                };
                if let Some(reason) = reason {
                    out.push(DefaultScopeCollision {
                        kind: kind.to_string(),
                        name: name.to_string(),
                        reason,
                    });
                }
            }
        }
    }
    out.sort_by(|a, b| a.describe().cmp(&b.describe()));
    Ok(out)
}

// ---- interactive migration: the operator-answerable decision model ---------------

/// An operator-answerable fork in the migration — a point with more than one valid route that the
/// interactive flow (CLI prompts / console wizard) presents and the operator chooses. Serde so the
/// console admin API can render + park it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationDecision {
    /// Stable id an answer references (e.g. `collision:site/construens`).
    pub id: String,
    /// The question to put to the operator.
    pub question: String,
    /// The routes the operator may choose among.
    pub routes: Vec<DecisionRoute>,
}

/// One route of a [`MigrationDecision`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRoute {
    /// Stable key an answer carries (e.g. `rename`).
    pub key: String,
    /// Human label.
    pub label: String,
    /// A free-text input this route needs (e.g. the new name for a rename), with its prompt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<RouteInput>,
    /// A consequence/warning to show before choosing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// A free-text input a [`DecisionRoute`] requires from the operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteInput {
    /// What to prompt for.
    pub prompt: String,
    /// How to validate it.
    pub kind: RouteInputKind,
}

/// The validation class for a [`RouteInput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteInputKind {
    /// A resource slug (validated by [`crate::project::validate_resource_name`]).
    ResourceName,
}

/// The interactive migration plan — the current status, the target version, a human summary of the
/// forward work (from a dry run that writes nothing), and the operator-answerable [`MigrationDecision`]s
/// that must be resolved before the re-home can complete. Both the CLI prompt loop and the console
/// admin wizard render this; it is the read-only first step of an interactive migration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// The store's current layout status.
    pub status: Status,
    /// The store's current schema version.
    pub current_version: u32,
    /// The version the migration would reach.
    pub target_version: u32,
    /// Forks the operator must resolve to proceed (empty ⇒ a straight-through migration).
    pub decisions: Vec<MigrationDecision>,
    /// Human lines describing the forward work (or why none).
    pub summary: Vec<String>,
}

/// Compute the interactive [`MigrationPlan`] for a store — status, the forward-work summary, and the
/// operator-answerable decisions (currently: one per default-scope collision — rename / skip / abort).
/// Writes NOTHING. When collisions exist the dry-run summary is skipped (the engine refuses to stage a
/// colliding store until the operator resolves them, so there is no clean forward to preview yet).
pub async fn plan(kv: &dyn KvStore) -> Result<MigrationPlan, MigrateError> {
    let state = read_state(kv).await?;
    let status = status(kv).await?;

    let decisions: Vec<MigrationDecision> = default_scope_collisions(kv)
        .await?
        .into_iter()
        .map(collision_decision)
        .collect();

    let mut summary = Vec::new();
    if status == Status::NeedsMigration {
        if decisions.is_empty() {
            // No collisions → a dry run previews the forward work (writes nothing).
            let report = run(
                kv,
                MigrateOptions {
                    dry_run: true,
                    finalize: false,
                },
                &HashSet::new(),
                &registry(),
            )
            .await?;
            for (family, n) in &report.rekeyed {
                summary.push(format!("re-home {n} key(s) under {family}"));
            }
            if summary.is_empty() {
                summary.push("no bare default-scoped data-plane keys to re-home".to_string());
            }
        } else {
            summary.push(
                "Resolve the decision(s) above, then re-run the plan — the re-home proceeds once no \
                 collision remains."
                    .to_string(),
            );
        }
    }

    Ok(MigrationPlan {
        status,
        current_version: state.version,
        target_version: CURRENT_VERSION,
        decisions,
        summary,
    })
}

/// Build the operator-answerable decision for one collision: rename (with a new-name input) / skip
/// (leave un-re-homed) / abort.
fn collision_decision(c: DefaultScopeCollision) -> MigrationDecision {
    let commingle = matches!(c.reason, CollisionReason::CommingleProject);
    let DefaultScopeCollision { kind, name, .. } = &c;
    MigrationDecision {
        id: format!("collision:{kind}/{name}"),
        question: format!(
            "default-project {kind} `{name}` {} — how do you want to resolve it before the re-home?",
            if commingle {
                format!("commingles with the existing tenant project `{name}`")
            } else {
                "is named `default`, which collides with the re-home prefix".to_string()
            }
        ),
        routes: vec![
            DecisionRoute {
                key: "rename".to_string(),
                label: format!("Re-create the {kind} under a new, non-colliding name"),
                input: Some(RouteInput {
                    prompt: "new name".to_string(),
                    kind: RouteInputKind::ResourceName,
                }),
                note: Some(if commingle {
                    "Guest data this resource wrote under the shared scope is commingled with the \
                     tenant and is NOT auto-moved — confirm it has none, or reconcile it manually."
                        .to_string()
                } else {
                    "Re-creates via the normal deploy path, which carries its deploy history, \
                     domains, aliases and functions."
                        .to_string()
                }),
            },
            DecisionRoute {
                key: "skip".to_string(),
                label: "Leave it un-re-homed".to_string(),
                input: None,
                note: Some(
                    "Its bare default-scoped data stays as-is (stranded at finalize); the rest of \
                     the default project still re-homes."
                        .to_string(),
                ),
            },
            DecisionRoute {
                key: "abort".to_string(),
                label: "Cancel the migration".to_string(),
                input: None,
                note: None,
            },
        ],
    }
}

/// The **default-scope re-home key transform** — the single, mutation-gated predicate that decides,
/// idempotently and prefix-aware, whether a data-plane key is a bare default scope to re-home.
///
/// Given a key `{family}{rest}` (where `{rest}` begins with the `ProjectRef::qualified(..)` scope
/// segment), returns:
/// - `Some("{family}default/{rest}")` when `{rest}`'s FIRST segment is a **bare default scope** — a
///   site/function/topic-base that is NOT a known project name. This is exactly a pre-fix
///   `qualified(DEFAULT, base)` == `base` key, re-homed to the post-fix `default/base`.
/// - `None` (a **NO-OP**) when the first segment is already a known project (a named project — the
///   key belongs to it, never re-home) OR the reserved `default` (already two-segment-scoped). The
///   explicit `default` check makes a re-run — and a dual-soak re-scan that lists both the old
///   `{family}{base}/…` and the new `{family}default/{base}/…` spellings — strictly idempotent: only
///   bare default-scoped keys ever move.
///
/// `family` must end in `/`. A key not under `family`, or with an empty scope segment, is `None`.
pub(crate) fn rehome_default_scope(
    family: &str,
    key: &str,
    projects: &HashSet<String>,
) -> Option<String> {
    let rest = key.strip_prefix(family)?;
    let first = rest.split('/').next().unwrap_or("");
    if first.is_empty() {
        return None;
    }
    // Idempotent + prefix-aware: `default` (already re-homed) and every named project are left
    // alone. The explicit `DEFAULT_PROJECT` guard does not rely on `projectmeta/default` existing,
    // so idempotency holds even on an oddly-shaped store.
    if first == DEFAULT_PROJECT || projects.contains(first) {
        return None;
    }
    Some(format!("{family}{DEFAULT_PROJECT}/{rest}"))
}

/// The **new→old** (purely syntactic) inverse of [`rehome_default_scope`] for ONE family: given a
/// post-fix two-segment key `{family}default/{rest}`, name the pre-fix bare key `{family}{rest}`.
/// `None` for any key that is not a re-homed `{family}default/…` key (a named project's key, a
/// non-family key). No project set is needed — only an explicit `default/` second segment translates,
/// so a named project's `{family}{project}/…` key can never be wrongly stripped (the KV analogue of the
/// blob substrate's `default_scope_to_old`). Used by the un-migrated-store backward-read-compat
/// decorator (to address the old spelling the store physically holds) and by the migration's
/// `--abort` step (to name the new key to remove).
pub(crate) fn default_scope_to_bare(family: &str, key: &str) -> Option<String> {
    let rest = key.strip_prefix(family)?;
    let after = rest.strip_prefix(DEFAULT_PROJECT)?;
    // `default` must be a WHOLE first segment: a scoped `{family}default/{tail}`, or the degenerate
    // bare marker `{family}default` (a topic literally named `default` — impossible, `default` is a
    // reserved project name, but handled for totality). A key like `{family}defaultish/…` must NOT
    // match, so anything other than a `/` boundary or end-of-key is rejected.
    let tail = if let Some(t) = after.strip_prefix('/') {
        t
    } else if after.is_empty() {
        after
    } else {
        return None;
    };
    Some(format!("{family}{tail}"))
}

/// Whether a store needs the **un-migrated backward-read-compat** decoration: it is below the
/// default-scope re-home version AND actually carries bare default-scoped data-plane data to serve
/// (migration 2 is applicable). A fresh store born at the current layout (version 0, no bare data) is
/// `false` — it already composes and persists the new two-segment spelling, so wrapping it would wrongly
/// strip writes to the old spelling. A staged/finalized store (version ≥ 2) is `false` — its new keys
/// are present. So this is `true` exactly for a legacy store (e.g. a v1 single-project store) that has
/// not yet run `boatramp migrate`, which is the only case that must serve the old layout un-migrated.
pub async fn default_scope_compat_needed(kv: &dyn KvStore) -> Result<bool, MigrateError> {
    let state = read_state(kv).await?;
    if state.version >= DEFAULT_SCOPE_REHOME_VERSION {
        return Ok(false);
    }
    DefaultScopeRehomeV2.is_applicable(kv).await
}

// ---- reusable migration steps ----------------------------------------------------

/// One idempotent, resumable unit of a migration. `id` is stable (recorded in the
/// resume cursor). `run` must be safe to re-run and must fail closed (verify before any
/// destructive action). On `dry_run` it counts without writing.
#[async_trait]
trait Step: Send + Sync {
    fn id(&self) -> String;
    async fn run(
        &self,
        kv: &dyn KvStore,
        dry_run: bool,
        report: &mut MigrationReport,
    ) -> Result<(), MigrateError>;
}

fn rekey_step_id(project: &str, family: &str) -> String {
    format!("rekey:{project}:{family}")
}

/// Copy one mutable family to its `project/<project>/…` keys: copy → read-back verify,
/// **without** deleting the source (that is [`DeleteOldFamily`], the finalize half).
struct RekeyFamily {
    family: &'static str,
    project: &'static str,
}

#[async_trait]
impl Step for RekeyFamily {
    fn id(&self) -> String {
        rekey_step_id(self.project, self.family)
    }
    async fn run(
        &self,
        kv: &dyn KvStore,
        dry_run: bool,
        report: &mut MigrationReport,
    ) -> Result<(), MigrateError> {
        let mut moved = 0;
        for old_key in kv.list_prefix(self.family).await? {
            let new_key = format!("project/{}/{}", self.project, old_key);
            if dry_run {
                moved += 1;
                continue;
            }
            let Some(value) = kv.get(&old_key).await? else {
                continue; // vanished between listing and read
            };
            kv.put(&new_key, value.clone()).await?;
            if kv.get(&new_key).await?.as_deref() != Some(value.as_slice()) {
                return Err(MigrateError::Verify(new_key));
            }
            moved += 1;
        }
        if moved > 0 {
            report.rekeyed.push((self.family.to_string(), moved));
        }
        Ok(())
    }
}

/// Delete the old keys of one mutable family whose `project/<project>/…` counterpart is
/// present and byte-identical — the finalize half of copy-verify-delete. Idempotent (a
/// missing old key is skipped); refuses to delete an old key whose new key is absent or
/// mismatched, so a partially-copied family never loses data.
struct DeleteOldFamily {
    family: &'static str,
    project: &'static str,
}

#[async_trait]
impl Step for DeleteOldFamily {
    fn id(&self) -> String {
        format!("delete:{}:{}", self.project, self.family)
    }
    async fn run(
        &self,
        kv: &dyn KvStore,
        dry_run: bool,
        _report: &mut MigrationReport,
    ) -> Result<(), MigrateError> {
        for old_key in kv.list_prefix(self.family).await? {
            let new_key = format!("project/{}/{}", self.project, old_key);
            if dry_run {
                continue;
            }
            match (kv.get(&old_key).await?, kv.get(&new_key).await?) {
                (Some(o), Some(n)) if o == n => kv.delete(&old_key).await?,
                (Some(_), _) => return Err(MigrateError::Verify(new_key)),
                (None, _) => {}
            }
        }
        Ok(())
    }
}

/// Copy one data-plane family's bare default-scoped keys to their two-segment `default/…` keys
/// (copy → read-back verify; **never** deletes — [`DeleteRehomedDefaultScope`] is the finalize half).
/// The default-scope analogue of [`RekeyFamily`], differing only in the transform: it inserts
/// `default/` AFTER the family prefix via [`rehome_default_scope`], and SKIPS any key whose scope
/// segment is a known project (named, or the already-re-homed `default`) — so a named project's keys
/// and an already-migrated key are both no-ops, and listing a family that already contains both
/// spellings re-copies nothing.
struct RehomeDefaultScope {
    family: &'static str,
}

#[async_trait]
impl Step for RehomeDefaultScope {
    fn id(&self) -> String {
        format!("rehome:default-scope:{}", self.family)
    }
    async fn run(
        &self,
        kv: &dyn KvStore,
        dry_run: bool,
        report: &mut MigrationReport,
    ) -> Result<(), MigrateError> {
        let projects = known_projects(kv).await?;
        let mut moved = 0;
        for old_key in kv.list_prefix(self.family).await? {
            let Some(new_key) = rehome_default_scope(self.family, &old_key, &projects) else {
                continue; // named-project / already-re-homed key: leave it
            };
            if dry_run {
                moved += 1;
                continue;
            }
            let Some(value) = kv.get(&old_key).await? else {
                continue; // vanished between listing and read
            };
            kv.put(&new_key, value.clone()).await?;
            if kv.get(&new_key).await?.as_deref() != Some(value.as_slice()) {
                return Err(MigrateError::Verify(new_key));
            }
            moved += 1;
        }
        if moved > 0 {
            report.rekeyed.push((self.family.to_string(), moved));
        }
        Ok(())
    }
}

/// Delete the old bare default-scoped keys of one data-plane family whose two-segment `default/…`
/// counterpart is present and byte-identical — the finalize half of copy-verify-delete, the
/// default-scope analogue of [`DeleteOldFamily`]. Idempotent; refuses to delete an old key whose new
/// key is absent or mismatched (so a partially-copied family never loses data). A key that is NOT a
/// bare default scope (a named project's key, or an already-re-homed `default/…` key) yields `None`
/// from the transform and is left untouched — critical here because, unlike the v1 families, both
/// the old and the new spelling share the SAME family prefix, so the cleanup listing sees both.
struct DeleteRehomedDefaultScope {
    family: &'static str,
}

#[async_trait]
impl Step for DeleteRehomedDefaultScope {
    fn id(&self) -> String {
        format!("delete-rehomed:default-scope:{}", self.family)
    }
    async fn run(
        &self,
        kv: &dyn KvStore,
        dry_run: bool,
        _report: &mut MigrationReport,
    ) -> Result<(), MigrateError> {
        let projects = known_projects(kv).await?;
        for old_key in kv.list_prefix(self.family).await? {
            let Some(new_key) = rehome_default_scope(self.family, &old_key, &projects) else {
                continue; // not a bare default scope (named project, or already the new spelling)
            };
            if dry_run {
                continue;
            }
            match (kv.get(&old_key).await?, kv.get(&new_key).await?) {
                (Some(o), Some(n)) if o == n => kv.delete(&old_key).await?,
                (Some(_), _) => return Err(MigrateError::Verify(new_key)),
                (None, _) => {}
            }
        }
        Ok(())
    }
}

/// Rewrite the values of one index family through `transform` (idempotent — an
/// already-canonical value round-trips unchanged, so it is a no-op).
struct RewriteValues {
    family: &'static str,
    transform: fn(&[u8]) -> Vec<u8>,
}

#[async_trait]
impl Step for RewriteValues {
    fn id(&self) -> String {
        format!("rewrite:{}", self.family)
    }
    async fn run(
        &self,
        kv: &dyn KvStore,
        dry_run: bool,
        report: &mut MigrationReport,
    ) -> Result<(), MigrateError> {
        let mut rewritten = 0;
        for key in kv.list_prefix(self.family).await? {
            let Some(value) = kv.get(&key).await? else {
                continue;
            };
            let canonical = (self.transform)(&value);
            if canonical != value {
                if !dry_run {
                    kv.put(&key, canonical).await?;
                }
                rewritten += 1;
            }
        }
        if rewritten > 0 {
            report
                .values_rewritten
                .push((self.family.to_string(), rewritten));
        }
        Ok(())
    }
}

/// Canonicalize a domain-index value to the `{project, site}` [`DomainOwner`] form (a
/// bare legacy site string becomes `(default, <site>)`).
fn domain_owner_canonical(value: &[u8]) -> Vec<u8> {
    DomainOwner::from_bytes(value).to_bytes()
}

/// Create the `default` project pointer + content-addressed body if absent.
struct EnsureDefaultProject;

#[async_trait]
impl Step for EnsureDefaultProject {
    fn id(&self) -> String {
        "ensure-default-project".to_string()
    }
    async fn run(
        &self,
        kv: &dyn KvStore,
        dry_run: bool,
        report: &mut MigrationReport,
    ) -> Result<(), MigrateError> {
        let pointer = project::pointer_key(DEFAULT_PROJECT);
        if kv.get(&pointer).await?.is_some() {
            return Ok(());
        }
        report.created_default_project = true;
        if dry_run {
            return Ok(());
        }
        // Single-source the record shape with the boot-time ensure (fresh installs
        // materialize `default` the same way a migration does).
        let default = crate::deploy::DeployStore::default_project_record();
        let hash = default.id();
        let body = serde_json::to_vec(&default).map_err(|e| MigrateError::Serde(e.to_string()))?;
        kv.write_batch(vec![
            WriteOp::Put(project::spec_key(&hash), body),
            WriteOp::Put(pointer, hash.into_bytes()),
        ])
        .await?;
        Ok(())
    }
}

/// Build the `owner/<kind>/<name>` → project reverse index over the migrated
/// site/function/compute records. Idempotent.
struct BuildOwnerIndex;

#[async_trait]
impl Step for BuildOwnerIndex {
    fn id(&self) -> String {
        "build-owner-index".to_string()
    }
    async fn run(
        &self,
        kv: &dyn KvStore,
        dry_run: bool,
        report: &mut MigrationReport,
    ) -> Result<(), MigrateError> {
        let mut ops = Vec::new();
        // Sites: the site-config pointer `project/default/site/<site>`.
        let site_prefix = format!("project/{DEFAULT_PROJECT}/site/");
        for key in kv.list_prefix(&site_prefix).await? {
            if let Some(site) = key.strip_prefix(&site_prefix)
                && !site.is_empty()
            {
                ops.push(WriteOp::Put(
                    project::owner_key(owner_kind::SITE, site),
                    DEFAULT_PROJECT.as_bytes().to_vec(),
                ));
            }
        }
        // Functions: the meta key `project/default/functions/<name>` (no further `/`).
        let fn_prefix = format!("project/{DEFAULT_PROJECT}/functions/");
        for key in kv.list_prefix(&fn_prefix).await? {
            if let Some(rest) = key.strip_prefix(&fn_prefix)
                && !rest.is_empty()
                && !rest.contains('/')
            {
                ops.push(WriteOp::Put(
                    project::owner_key(owner_kind::FUNCTION, rest),
                    DEFAULT_PROJECT.as_bytes().to_vec(),
                ));
            }
        }
        // Compute workloads: `project/default/compute/<name>`.
        let compute_prefix = format!("project/{DEFAULT_PROJECT}/compute/");
        for key in kv.list_prefix(&compute_prefix).await? {
            if let Some(name) = key.strip_prefix(&compute_prefix)
                && !name.is_empty()
            {
                ops.push(WriteOp::Put(
                    project::owner_key(owner_kind::COMPUTE, name),
                    DEFAULT_PROJECT.as_bytes().to_vec(),
                ));
            }
        }
        report.owner_entries += ops.len();
        if !dry_run && !ops.is_empty() {
            kv.write_batch(ops).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::MemoryKv;

    /// Seed a synthetic layout-1 store: sites, functions, compute, aliases, domain
    /// index (raw bare-site values), and a content-addressed body that must NOT move.
    async fn seed_legacy(kv: &MemoryKv) {
        kv.put("current/blog", b"dep-1".to_vec()).await.unwrap();
        kv.put("site/blog", b"cfghash".to_vec()).await.unwrap();
        kv.put("history/blog", b"[]".to_vec()).await.unwrap();
        kv.put("alias/blog/staging", b"dep-1".to_vec())
            .await
            .unwrap();
        kv.put("domainverify/blog/www.example", b"{}".to_vec())
            .await
            .unwrap();
        kv.put("dnsmanaged/blog/www.example", b"{}".to_vec())
            .await
            .unwrap();
        kv.put("functions/resize", b"{}".to_vec()).await.unwrap();
        kv.put("functions/resize/versions/v1", b"{}".to_vec())
            .await
            .unwrap();
        kv.put("metering/resize", b"{}".to_vec()).await.unwrap();
        kv.put("blobnotify/resize/uploads", b"{}".to_vec())
            .await
            .unwrap();
        kv.put("workflows/etl", b"{}".to_vec()).await.unwrap();
        kv.put("compute/api", b"{}".to_vec()).await.unwrap();
        kv.put("compute_state/api/0", b"{}".to_vec()).await.unwrap();
        kv.put("domain/www.example", b"blog".to_vec())
            .await
            .unwrap();
        kv.put("wildcard/preview.example", b"blog".to_vec())
            .await
            .unwrap();
        kv.put("httpchallenge/www.example/tok", b"blog".to_vec())
            .await
            .unwrap();
        kv.put("siteconfig/cfghash", b"the-config".to_vec())
            .await
            .unwrap();
        kv.put("manifests/dep-1", b"the-manifest".to_vec())
            .await
            .unwrap();
        kv.put("authz/tokens/t1", b"tok".to_vec()).await.unwrap();
    }

    #[test]
    fn registry_versions_are_strictly_ascending_and_reach_current() {
        let reg = registry();
        assert!(!reg.is_empty());
        let mut last = 0;
        for m in &reg {
            assert!(m.version() > last, "versions must strictly ascend");
            last = m.version();
        }
        assert_eq!(
            last, CURRENT_VERSION,
            "CURRENT_VERSION == the top migration"
        );
    }

    #[tokio::test]
    async fn status_detects_legacy_fresh_and_migrated() {
        let fresh = MemoryKv::new();
        assert_eq!(status(&fresh).await.unwrap(), Status::Ready);

        let legacy = MemoryKv::new();
        seed_legacy(&legacy).await;
        assert_eq!(status(&legacy).await.unwrap(), Status::NeedsMigration);

        migrate(&legacy, MigrateOptions::one_shot()).await.unwrap();
        assert_eq!(status(&legacy).await.unwrap(), Status::Ready);
        // The version advanced + is recorded in history.
        let state = read_state(&legacy).await.unwrap();
        assert_eq!(state.version, CURRENT_VERSION);
        assert!(state.history.iter().any(|a| a.id == "project-rekey"));
    }

    #[tokio::test]
    async fn migrate_rekeys_mutable_families_and_rewrites_domain_values() {
        let kv = MemoryKv::new();
        seed_legacy(&kv).await;
        let report = migrate(&kv, MigrateOptions::one_shot()).await.unwrap();

        assert_eq!(
            kv.get("project/default/current/blog")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"dep-1"[..])
        );
        assert_eq!(
            kv.get("project/default/functions/resize/versions/v1")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"{}"[..])
        );
        assert_eq!(
            kv.get("project/default/compute_state/api/0")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"{}"[..])
        );
        assert!(kv.get("current/blog").await.unwrap().is_none());
        assert!(kv.get("compute/api").await.unwrap().is_none());

        let dv = kv.get("domain/www.example").await.unwrap().unwrap();
        assert_eq!(
            DomainOwner::from_bytes(&dv),
            DomainOwner::new("default", "blog")
        );
        assert!(String::from_utf8_lossy(&dv).contains("\"project\":\"default\""));
        assert_eq!(
            DomainOwner::from_bytes(
                &kv.get("httpchallenge/www.example/tok")
                    .await
                    .unwrap()
                    .unwrap()
            ),
            DomainOwner::new("default", "blog")
        );

        // Content-addressed body + singleton untouched.
        assert_eq!(
            kv.get("siteconfig/cfghash").await.unwrap().as_deref(),
            Some(&b"the-config"[..])
        );
        assert_eq!(
            kv.get("authz/tokens/t1").await.unwrap().as_deref(),
            Some(&b"tok"[..])
        );

        // Default project pointer + owner reverse index.
        assert!(kv.get("projectmeta/default").await.unwrap().is_some());
        assert!(report.created_default_project);
        assert_eq!(
            kv.get("owner/site/blog").await.unwrap().as_deref(),
            Some(&b"default"[..])
        );
        assert_eq!(
            kv.get("owner/function/resize").await.unwrap().as_deref(),
            Some(&b"default"[..])
        );
        assert!(
            kv.get("owner/function/resize/versions/v1")
                .await
                .unwrap()
                .is_none()
        );

        assert_eq!(status(&kv).await.unwrap(), Status::Ready);
        assert!(!report.already_migrated);
    }

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let kv = MemoryKv::new();
        seed_legacy(&kv).await;
        let first = migrate(&kv, MigrateOptions::one_shot()).await.unwrap();
        assert!(first.total_rekeyed() > 0);

        let before: Vec<String> = kv.list_prefix("project/").await.unwrap();
        let second = migrate(&kv, MigrateOptions::one_shot()).await.unwrap();
        assert!(second.already_migrated);
        assert_eq!(second.total_rekeyed(), 0);
        assert_eq!(kv.list_prefix("project/").await.unwrap(), before);
    }

    #[tokio::test]
    async fn dry_run_writes_nothing() {
        let kv = MemoryKv::new();
        seed_legacy(&kv).await;
        let report = migrate(
            &kv,
            MigrateOptions {
                dry_run: true,
                finalize: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert!(report.total_rekeyed() > 0);
        assert!(report.created_default_project);
        assert!(
            kv.get("project/default/current/blog")
                .await
                .unwrap()
                .is_none()
        );
        assert!(kv.get("current/blog").await.unwrap().is_some());
        assert!(kv.get("projectmeta/default").await.unwrap().is_none());
        assert_eq!(status(&kv).await.unwrap(), Status::NeedsMigration);
    }

    #[tokio::test]
    async fn dual_stage_then_finalize() {
        let kv = MemoryKv::new();
        seed_legacy(&kv).await;

        let staged = migrate(
            &kv,
            MigrateOptions {
                dry_run: false,
                finalize: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(staged.dual);
        assert_eq!(status(&kv).await.unwrap(), Status::Dual);
        assert!(
            kv.get("project/default/current/blog")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            kv.get("current/blog").await.unwrap().is_some(),
            "old key kept during dual soak"
        );
        // The marker records the deferred cleanup.
        assert_eq!(read_state(&kv).await.unwrap().unfinalized, vec![1]);

        let done = finalize(&kv).await.unwrap();
        assert!(!done.dual);
        assert!(kv.get("current/blog").await.unwrap().is_none());
        assert_eq!(status(&kv).await.unwrap(), Status::Ready);
    }

    #[tokio::test]
    async fn resumes_after_a_crash_mid_migration() {
        let kv = MemoryKv::new();
        seed_legacy(&kv).await;

        // Simulate a crash after only two forward steps: copy `current/` and `site/`
        // by hand and record their step ids in the resume cursor.
        for old in ["current/blog", "site/blog"] {
            let v = kv.get(old).await.unwrap().unwrap();
            kv.put(&format!("project/default/{old}"), v).await.unwrap();
            kv.delete(old).await.unwrap();
        }
        let partial = SchemaState {
            version: 0,
            unfinalized: Vec::new(),
            in_progress: Some(InProgress {
                target: 1,
                steps_done: vec![
                    rekey_step_id("default", "current/"),
                    rekey_step_id("default", "site/"),
                ],
            }),
            history: Vec::new(),
            updated_at: 1,
        };
        persist_state(&kv, &partial).await.unwrap();

        migrate(&kv, MigrateOptions::one_shot()).await.unwrap();
        assert_eq!(status(&kv).await.unwrap(), Status::Ready);
        assert_eq!(
            kv.get("project/default/compute/api")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"{}"[..])
        );
        assert_eq!(
            kv.get("project/default/current/blog")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"dep-1"[..])
        );
        assert!(kv.get("compute/api").await.unwrap().is_none());
        // No double-nesting from re-processing an already-done family.
        assert!(
            kv.get("project/default/project/default/current/blog")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn reads_the_pre_mechanism_legacy_marker() {
        // A store finalized by the original one-shot engine wrote `{layout:2, ...}`.
        let kv = MemoryKv::new();
        kv.put(
            SCHEMA_KEY,
            br#"{"layout":2,"dual":false,"migrated_at":9,"families_done":["current/"]}"#.to_vec(),
        )
        .await
        .unwrap();
        let state = read_state(&kv).await.unwrap();
        assert_eq!(state.version, 1);
        assert!(state.unfinalized.is_empty());
        assert_eq!(status(&kv).await.unwrap(), Status::Ready);

        // A `2-dual` legacy marker maps to a deferred cleanup.
        let dual = MemoryKv::new();
        dual.put(SCHEMA_KEY, br#"{"layout":2,"dual":true}"#.to_vec())
            .await
            .unwrap();
        assert_eq!(read_state(&dual).await.unwrap().unfinalized, vec![1]);
        assert_eq!(status(&dual).await.unwrap(), Status::Dual);
    }

    // ---- migration 2: default-scope re-home (Finding 8) ---------------------------

    /// A HashSet of named projects (+ `default`) for the predicate unit tests.
    fn projects(names: &[&str]) -> HashSet<String> {
        names.iter().map(|&s| s.to_string()).collect()
    }

    #[test]
    fn rehome_default_scope_predicate_moves_only_bare_default_scopes() {
        // `default` + the named project `acme` are known; `blog`/`fn` are bare default scopes.
        let known = projects(&["default", "acme"]);

        // A bare default scope re-homes: insert `default/` AFTER the family prefix.
        assert_eq!(
            rehome_default_scope("hkv/", "hkv/blog/counter", &known).as_deref(),
            Some("hkv/default/blog/counter")
        );
        // A default-project FUNCTION topic (first segment `fn`, not a project) re-homes whole.
        assert_eq!(
            rehome_default_scope("mq/", "mq/fn/resize/uploads/17-ab", &known).as_deref(),
            Some("mq/default/fn/resize/uploads/17-ab")
        );
        // A single-segment marker key (`mqpause/{topic}`) re-homes too.
        assert_eq!(
            rehome_default_scope("mqpause/", "mqpause/blog", &known).as_deref(),
            Some("mqpause/default/blog")
        );
        // A consumer-group OFFSET key (the critical one) re-homes with its group/id tail intact.
        assert_eq!(
            rehome_default_scope("mqgstate/", "mqgstate/blog/group-a", &known).as_deref(),
            Some("mqgstate/default/blog/group-a")
        );

        // A NAMED project's key is a NO-OP (it belongs to that project).
        assert_eq!(
            rehome_default_scope("hkv/", "hkv/acme/shop/counter", &known),
            None
        );
        // An ALREADY-re-homed key is a NO-OP (idempotency — survives a dual-soak re-scan that sees
        // both spellings, and holds even if `projectmeta/default` were absent).
        assert_eq!(
            rehome_default_scope("hkv/", "hkv/default/blog/counter", &projects(&["acme"])),
            None
        );
        // Non-family / empty-scope keys are left alone.
        assert_eq!(rehome_default_scope("hkv/", "mq/blog/x", &known), None);
        assert_eq!(rehome_default_scope("hkv/", "hkv/", &known), None);
    }

    /// Seed a v1-layout store (version 1 recorded) carrying BOTH a bare default-scoped data plane
    /// and a named project `acme`'s two-segment data plane, across every family migration 2 touches.
    async fn seed_default_scope(kv: &MemoryKv) {
        // The project pointers the predicate reads (as v1 would have left them).
        kv.put("projectmeta/default", b"h0".to_vec()).await.unwrap();
        kv.put("projectmeta/acme", b"h1".to_vec()).await.unwrap();

        // --- bare default-scoped keys (must re-home) ---
        kv.put("hkv/blog/counter", b"7".to_vec()).await.unwrap();
        kv.put("hkv/blog/sub/key", b"v".to_vec()).await.unwrap();
        kv.put("mq/blog/17-aa", b"rec".to_vec()).await.unwrap();
        kv.put("mqdead/blog/9-bb", b"dead".to_vec()).await.unwrap();
        kv.put("mqpause/blog", b"".to_vec()).await.unwrap();
        kv.put("mqpolicy/blog", b"{}".to_vec()).await.unwrap();
        kv.put("mqready/blog", b"".to_vec()).await.unwrap();
        kv.put("mqglog/blog/17-aa", b"".to_vec()).await.unwrap();
        kv.put("mqgstate/blog/grp", b"offs".to_vec()).await.unwrap();
        kv.put("mqlogmax/blog", b"17-aa".to_vec()).await.unwrap();
        kv.put("mqgd/blog/grp/9-bb", b"gdead".to_vec())
            .await
            .unwrap();
        // A default-project FUNCTION topic (multi-segment base).
        kv.put("mq/fn/resize/uploads/1-cc", b"r".to_vec())
            .await
            .unwrap();

        // --- named project `acme` keys (must NOT move) ---
        kv.put("hkv/acme/shop/counter", b"42".to_vec())
            .await
            .unwrap();
        kv.put("mq/acme/shop/3-dd", b"rec2".to_vec()).await.unwrap();
        kv.put("mqgstate/acme/shop/grp", b"offs2".to_vec())
            .await
            .unwrap();

        // Record the store at v1 so only migration 2 runs.
        persist_state(
            kv,
            &SchemaState {
                version: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn default_scope_rehome_moves_bare_and_leaves_named() {
        let kv = MemoryKv::new();
        seed_default_scope(&kv).await;
        assert_eq!(status(&kv).await.unwrap(), Status::NeedsMigration);

        let report = migrate(&kv, MigrateOptions::one_shot()).await.unwrap();
        assert!(report.total_rekeyed() > 0);

        // Every bare default-scoped key re-homed under `default/…`, old key gone (one-shot).
        for (old, new) in [
            ("hkv/blog/counter", "hkv/default/blog/counter"),
            ("hkv/blog/sub/key", "hkv/default/blog/sub/key"),
            ("mq/blog/17-aa", "mq/default/blog/17-aa"),
            ("mqdead/blog/9-bb", "mqdead/default/blog/9-bb"),
            ("mqpause/blog", "mqpause/default/blog"),
            ("mqpolicy/blog", "mqpolicy/default/blog"),
            ("mqready/blog", "mqready/default/blog"),
            ("mqglog/blog/17-aa", "mqglog/default/blog/17-aa"),
            ("mqgstate/blog/grp", "mqgstate/default/blog/grp"),
            ("mqlogmax/blog", "mqlogmax/default/blog"),
            ("mqgd/blog/grp/9-bb", "mqgd/default/blog/grp/9-bb"),
            (
                "mq/fn/resize/uploads/1-cc",
                "mq/default/fn/resize/uploads/1-cc",
            ),
        ] {
            assert!(
                kv.get(new).await.unwrap().is_some(),
                "{new} must exist after re-home"
            );
            assert!(
                kv.get(old).await.unwrap().is_none(),
                "{old} must be deleted by the one-shot finalize"
            );
        }

        // Named project `acme` keys are byte-untouched (never re-homed, never double-nested).
        assert_eq!(
            kv.get("hkv/acme/shop/counter").await.unwrap().as_deref(),
            Some(&b"42"[..])
        );
        assert_eq!(
            kv.get("mqgstate/acme/shop/grp").await.unwrap().as_deref(),
            Some(&b"offs2"[..])
        );
        assert!(
            kv.get("hkv/default/acme/shop/counter")
                .await
                .unwrap()
                .is_none(),
            "a named project's key must never be pulled under default/"
        );

        assert_eq!(read_state(&kv).await.unwrap().version, 2);
        assert_eq!(status(&kv).await.unwrap(), Status::Ready);
    }

    #[tokio::test]
    async fn default_scope_rehome_is_idempotent() {
        let kv = MemoryKv::new();
        seed_default_scope(&kv).await;
        migrate(&kv, MigrateOptions::one_shot()).await.unwrap();
        let before = kv.list_prefix("").await.unwrap();

        let again = migrate(&kv, MigrateOptions::one_shot()).await.unwrap();
        assert!(again.already_migrated);
        assert_eq!(again.total_rekeyed(), 0);
        // No double-nesting, no new keys, nothing moved.
        assert!(
            kv.get("hkv/default/default/blog/counter")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(kv.list_prefix("").await.unwrap(), before);
    }

    /// Snapshot every DATA key (everything except the migration's own `schema/` bookkeeping), so an
    /// abort round-trip can be asserted byte-for-byte on the actual tenant/guest data (the schema
    /// marker + the premigration-index audit artifact are expected to differ after an abort).
    async fn data_snapshot(kv: &MemoryKv) -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut out = std::collections::BTreeMap::new();
        for key in kv.list_prefix("").await.unwrap() {
            if key.starts_with("schema/") {
                continue;
            }
            if let Some(v) = kv.get(&key).await.unwrap() {
                out.insert(key, v);
            }
        }
        out
    }

    #[tokio::test]
    async fn default_scope_abort_restores_exact_bytes() {
        // GATE: `MIGRATE ABORT EXACT-BYTES OK` — staging then aborting returns the store to the exact
        // pre-stage DATA bytes (every re-homed NEW key removed, every OLD key intact), version back to 1.
        let kv = MemoryKv::new();
        seed_default_scope(&kv).await;
        let before = data_snapshot(&kv).await;

        let staged = migrate(
            &kv,
            MigrateOptions {
                dry_run: false,
                finalize: false,
            },
        )
        .await
        .unwrap();
        assert!(staged.dual);
        assert_eq!(status(&kv).await.unwrap(), Status::Dual);
        assert!(
            kv.get("hkv/default/blog/counter").await.unwrap().is_some(),
            "stage must have copied the new spelling"
        );

        abort(&kv).await.unwrap();

        assert_eq!(
            data_snapshot(&kv).await,
            before,
            "abort must restore the EXACT pre-stage data keyspace"
        );
        assert_eq!(read_state(&kv).await.unwrap().version, 1);
        assert_eq!(status(&kv).await.unwrap(), Status::NeedsMigration);
        assert!(
            kv.get("hkv/default/blog/counter").await.unwrap().is_none(),
            "no re-homed NEW key may survive an abort"
        );
        println!("MIGRATE ABORT EXACT-BYTES OK");
    }

    #[tokio::test]
    async fn default_scope_abort_fails_closed_on_a_soak_window_write() {
        // GATE (the load-bearing safety property): abort must REFUSE, deleting nothing, if a staged NEW
        // key diverged from its retained OLD twin during the soak — losing that write would be silent
        // data loss. Covers both divergence shapes: an overwrite (old twin present, mismatched) and a
        // brand-new key (no old twin).
        let kv = MemoryKv::new();
        seed_default_scope(&kv).await;
        migrate(
            &kv,
            MigrateOptions {
                dry_run: false,
                finalize: false,
            },
        )
        .await
        .unwrap();

        // (a) overwrite an existing re-homed key — diverges from its OLD twin.
        kv.put("hkv/default/blog/counter", b"SOAK-WRITE".to_vec())
            .await
            .unwrap();
        let err = abort(&kv).await;
        assert!(
            matches!(err, Err(MigrateError::AbortWouldLoseData { .. })),
            "abort must refuse a diverged soak write, got {err:?}"
        );
        // Nothing was deleted; the store is still in the dual soak with the soak write intact.
        assert_eq!(
            kv.get("hkv/default/blog/counter").await.unwrap().as_deref(),
            Some(&b"SOAK-WRITE"[..])
        );
        assert_eq!(read_state(&kv).await.unwrap().version, 2);
        assert_eq!(status(&kv).await.unwrap(), Status::Dual);

        // Restore the key to its twin's value so (a) no longer diverges, then (b) add a brand-new
        // NEW-spelling key with no OLD twin — abort must still refuse.
        kv.put("hkv/default/blog/counter", b"7".to_vec())
            .await
            .unwrap();
        kv.put("hkv/default/blog/fresh", b"new".to_vec())
            .await
            .unwrap();
        assert!(
            matches!(
                abort(&kv).await,
                Err(MigrateError::AbortWouldLoseData { .. })
            ),
            "abort must refuse a brand-new soak key with no pre-migration twin"
        );
        assert!(
            kv.get("hkv/default/blog/fresh").await.unwrap().is_some(),
            "the refused abort must delete nothing"
        );
    }

    #[tokio::test]
    async fn abort_refuses_when_nothing_staged() {
        let kv = MemoryKv::new();
        seed_default_scope(&kv).await; // version 1, nothing staged
        assert!(matches!(
            abort(&kv).await,
            Err(MigrateError::AbortNothingStaged)
        ));
    }

    #[tokio::test]
    async fn plan_surfaces_a_clean_migration_without_decisions() {
        let kv = MemoryKv::new();
        seed_default_scope(&kv).await; // bare default data + tenant acme, no colliding resource
        let p = plan(&kv).await.unwrap();
        assert_eq!(p.status, Status::NeedsMigration);
        assert_eq!(p.current_version, 1);
        assert_eq!(p.target_version, CURRENT_VERSION);
        assert!(p.decisions.is_empty(), "no collisions in the clean fixture");
        assert!(
            p.summary.iter().any(|s| s.contains("re-home")),
            "a clean plan previews the forward work: {:?}",
            p.summary
        );
    }

    #[tokio::test]
    async fn plan_surfaces_a_collision_as_a_rename_skip_abort_decision() {
        let kv = MemoryKv::new();
        seed_default_scope(&kv).await;
        // A default-project COMPUTE named like the existing tenant project `acme` → commingle collision.
        kv.put("project/default/compute/acme", b"spec".to_vec())
            .await
            .unwrap();
        let p = plan(&kv).await.unwrap();
        assert_eq!(p.decisions.len(), 1, "exactly the one collision");
        let d = &p.decisions[0];
        assert_eq!(d.id, "collision:compute/acme");
        let keys: Vec<&str> = d.routes.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, vec!["rename", "skip", "abort"]);
        let rename = d.routes.iter().find(|r| r.key == "rename").unwrap();
        assert!(
            matches!(
                rename.input,
                Some(RouteInput {
                    kind: RouteInputKind::ResourceName,
                    ..
                })
            ),
            "the rename route must take a resource-name input"
        );
        // A collision defers the dry-run preview to after resolution.
        assert!(
            p.summary.iter().any(|s| s.contains("Resolve the decision")),
            "summary should point at resolving the collision first: {:?}",
            p.summary
        );
        // The plan is serde round-trippable (the console admin API renders it as JSON).
        let json = serde_json::to_string(&p).unwrap();
        let back: MigrationPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[tokio::test]
    async fn migrate_with_answers_honors_skip_abort_and_still_refuses_unanswered() {
        // Seed a store with the clean default data + a COMPUTE collision (named like tenant `acme`).
        let seed = || async {
            let kv = MemoryKv::new();
            seed_default_scope(&kv).await;
            kv.put("project/default/compute/acme", b"spec".to_vec())
                .await
                .unwrap();
            kv
        };

        // (1) No answers → the collision is unresolved → refuses fail-closed (driver re-prompts).
        let kv = seed().await;
        assert!(matches!(
            migrate_with_answers(&kv, &MigrationAnswers::default()).await,
            Err(MigrateError::DefaultNamedResource { .. })
        ));
        assert_eq!(read_state(&kv).await.unwrap().version, 1, "nothing staged");

        // (2) Operator aborts → no-op, store untouched.
        let kv = seed().await;
        assert_eq!(
            migrate_with_answers(
                &kv,
                &MigrationAnswers {
                    aborted: true,
                    ..Default::default()
                }
            )
            .await
            .unwrap(),
            InteractiveOutcome::Aborted
        );
        assert_eq!(read_state(&kv).await.unwrap().version, 1);
        assert!(kv.get("hkv/default/blog/counter").await.unwrap().is_none());

        // (3) Operator SKIPS the collision → stages (dual soak); the non-colliding default data
        // re-homes, and the skipped resource's bare scope is left as-is.
        let kv = seed().await;
        let out = migrate_with_answers(
            &kv,
            &MigrationAnswers {
                skip_collisions: vec!["collision:compute/acme".to_string()],
                aborted: false,
            },
        )
        .await
        .unwrap();
        assert!(matches!(out, InteractiveOutcome::Staged(_)));
        assert_eq!(status(&kv).await.unwrap(), Status::Dual);
        assert!(
            kv.get("hkv/default/blog/counter").await.unwrap().is_some(),
            "the non-colliding default data re-homed"
        );
        // The tenant project `acme`'s own keyspace is untouched by the skip.
        assert_eq!(
            kv.get("hkv/acme/shop/counter").await.unwrap().as_deref(),
            Some(&b"42"[..])
        );
    }

    #[tokio::test]
    async fn default_scope_dual_stage_then_finalize_keeps_offsets() {
        let kv = MemoryKv::new();
        seed_default_scope(&kv).await;

        // Stage: copy + verify, keep the old keys (the soak window the blob drain runs in).
        let staged = migrate(
            &kv,
            MigrateOptions {
                dry_run: false,
                finalize: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(staged.dual);
        assert_eq!(status(&kv).await.unwrap(), Status::Dual);
        assert!(
            read_state(&kv)
                .await
                .unwrap()
                .unfinalized
                .contains(&DEFAULT_SCOPE_REHOME_VERSION)
        );
        // Messaging continuity: the consumer-group OFFSET is readable at BOTH spellings during the
        // soak (old kept, new copied), so a claim against either spelling finds the hwm/in-flight.
        assert_eq!(
            kv.get("mqgstate/blog/grp").await.unwrap().as_deref(),
            Some(&b"offs"[..]),
            "old offset kept during the dual soak"
        );
        assert_eq!(
            kv.get("mqgstate/default/blog/grp")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"offs"[..]),
            "new-spelling offset copied in the SAME forward pass as the log"
        );

        // Finalize: the old spelling becomes claimable-nothing (deleted) only now.
        let done = finalize(&kv).await.unwrap();
        assert!(!done.dual);
        assert!(kv.get("mqgstate/blog/grp").await.unwrap().is_none());
        assert!(kv.get("mq/blog/17-aa").await.unwrap().is_none());
        assert_eq!(
            kv.get("mqgstate/default/blog/grp")
                .await
                .unwrap()
                .as_deref(),
            Some(&b"offs"[..])
        );
        assert_eq!(status(&kv).await.unwrap(), Status::Ready);
    }

    #[tokio::test]
    async fn default_scope_finalize_never_deletes_an_unverified_old_key() {
        // The copy-before-delete guard: a tampered/absent new key must BLOCK the old delete.
        let kv = MemoryKv::new();
        seed_default_scope(&kv).await;
        migrate(
            &kv,
            MigrateOptions {
                dry_run: false,
                finalize: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        // Corrupt one new-spelling value so it no longer byte-matches its old key.
        kv.put("mqgstate/default/blog/grp", b"TAMPERED".to_vec())
            .await
            .unwrap();
        let err = finalize(&kv).await;
        assert!(
            matches!(err, Err(MigrateError::Verify(_))),
            "finalize must refuse to delete an old key whose new counterpart mismatches"
        );
        // The old key is intact — no data lost.
        assert_eq!(
            kv.get("mqgstate/blog/grp").await.unwrap().as_deref(),
            Some(&b"offs"[..])
        );
    }

    #[tokio::test]
    async fn default_scope_vacuous_on_named_only_store() {
        // A store with ONLY named-project data-plane keys has nothing to re-home → migration 2 is
        // vacuously applied (no dual soak), store advances to v2 and is Ready.
        let kv = MemoryKv::new();
        kv.put("projectmeta/default", b"h".to_vec()).await.unwrap();
        kv.put("projectmeta/acme", b"h".to_vec()).await.unwrap();
        kv.put("hkv/acme/shop/k", b"v".to_vec()).await.unwrap();
        persist_state(
            &kv,
            &SchemaState {
                version: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let report = migrate(&kv, MigrateOptions::one_shot()).await.unwrap();
        assert!(!report.dual, "no bare default keys ⇒ no dual soak");
        assert_eq!(report.total_rekeyed(), 0);
        assert_eq!(read_state(&kv).await.unwrap().version, 2);
        assert!(read_state(&kv).await.unwrap().unfinalized.is_empty());
        assert_eq!(status(&kv).await.unwrap(), Status::Ready);
        assert_eq!(
            kv.get("hkv/acme/shop/k").await.unwrap().as_deref(),
            Some(&b"v"[..])
        );
    }

    /// Fail-closed pre-migration guard (Finding 8): a default-project site literally named `default`,
    /// or named like a known project (commingling), REFUSES the re-home — unless overridden. Detected
    /// pre-forward; skipped on resume.
    #[tokio::test]
    async fn default_scope_premigration_guard_refuses_conflicts() {
        // (1) Named `default`.
        let kv = MemoryKv::new();
        kv.put("projectmeta/default", b"h".to_vec()).await.unwrap();
        kv.put("project/default/site/default", b"cfg".to_vec())
            .await
            .unwrap();
        kv.put("hkv/blog/k", b"v".to_vec()).await.unwrap();
        persist_state(
            &kv,
            &SchemaState {
                version: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let conflicts = default_scope_premigration_conflicts(&kv).await.unwrap();
        assert_eq!(conflicts.len(), 1, "a site named `default` is a conflict");
        assert!(conflicts[0].contains("site/default"));
        let err = migrate(&kv, MigrateOptions::one_shot()).await;
        assert!(
            matches!(err, Err(MigrateError::DefaultNamedResource { .. })),
            "the re-home must refuse a default-named resource, got {err:?}"
        );
        // Nothing was migrated (the guard fired before the forward) — the store is untouched, so the
        // node keeps serving the existing layout; the operator resolves via `resolve-collision`.
        assert!(kv.get("hkv/default/blog/k").await.unwrap().is_none());
        assert!(kv.get("hkv/blog/k").await.unwrap().is_some());

        // (2) Commingling: a default-project COMPUTE workload named like an existing project `acme`.
        let kv = MemoryKv::new();
        kv.put("projectmeta/default", b"h".to_vec()).await.unwrap();
        kv.put("projectmeta/acme", b"h".to_vec()).await.unwrap();
        kv.put("project/default/compute/acme", b"spec".to_vec())
            .await
            .unwrap();
        persist_state(
            &kv,
            &SchemaState {
                version: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let conflicts = default_scope_premigration_conflicts(&kv).await.unwrap();
        assert_eq!(conflicts.len(), 1);
        assert!(
            conflicts[0].contains("compute/acme") && conflicts[0].contains("commingles"),
            "a default compute named like project `acme` must surface as commingling: {conflicts:?}"
        );
        assert!(matches!(
            migrate(&kv, MigrateOptions::one_shot()).await,
            Err(MigrateError::DefaultNamedResource { .. })
        ));
    }

    // ---- framework tests: prove the engine chains an arbitrary migration list -----

    /// A synthetic **simple** migration (no cleanup) that writes one sentinel key,
    /// applicable only while the sentinel is absent.
    struct AddSentinelV2;

    #[async_trait]
    impl Migration for AddSentinelV2 {
        fn version(&self) -> u32 {
            2
        }
        fn id(&self) -> &'static str {
            "add-sentinel"
        }
        fn description(&self) -> &'static str {
            "test migration: write a sentinel key"
        }
        async fn is_applicable(&self, kv: &dyn KvStore) -> Result<bool, MigrateError> {
            Ok(kv.get("demo/v2").await?.is_none())
        }
        fn forward_steps(&self) -> Vec<Box<dyn Step>> {
            vec![Box::new(WriteSentinel)]
        }
    }

    struct WriteSentinel;
    #[async_trait]
    impl Step for WriteSentinel {
        fn id(&self) -> String {
            "write-sentinel".to_string()
        }
        async fn run(
            &self,
            kv: &dyn KvStore,
            dry_run: bool,
            _report: &mut MigrationReport,
        ) -> Result<(), MigrateError> {
            if !dry_run {
                kv.put("demo/v2", b"ok".to_vec()).await?;
            }
            Ok(())
        }
    }

    fn chain() -> Vec<Box<dyn Migration>> {
        vec![Box::new(ProjectRekeyV1), Box::new(AddSentinelV2)]
    }

    #[tokio::test]
    async fn engine_applies_a_multi_migration_chain_in_order() {
        let kv = MemoryKv::new();
        seed_legacy(&kv).await;

        run(
            &kv,
            MigrateOptions::one_shot(),
            &std::collections::HashSet::new(),
            &chain(),
        )
        .await
        .unwrap();

        // Both migrations applied: v1 re-keyed the store, v2 wrote its sentinel.
        assert!(
            kv.get("project/default/current/blog")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            kv.get("demo/v2").await.unwrap().as_deref(),
            Some(&b"ok"[..])
        );

        let state = read_state(&kv).await.unwrap();
        assert_eq!(state.version, 2);
        // History records them in order.
        let ids: Vec<&str> = state.history.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(ids, vec!["project-rekey", "add-sentinel"]);

        // Idempotent re-run.
        let again = run(
            &kv,
            MigrateOptions::one_shot(),
            &std::collections::HashSet::new(),
            &chain(),
        )
        .await
        .unwrap();
        assert!(again.already_migrated);
    }

    #[tokio::test]
    async fn engine_applies_only_pending_migrations_from_a_version() {
        // A store already at v1 (project layout) but not v2: only v2 runs.
        let kv = MemoryKv::new();
        // Write new-layout site data + a v1 marker directly (as if migrated by v1).
        kv.put("project/default/site/blog", b"cfg".to_vec())
            .await
            .unwrap();
        persist_state(
            &kv,
            &SchemaState {
                version: 1,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let report = run(
            &kv,
            MigrateOptions::one_shot(),
            &std::collections::HashSet::new(),
            &chain(),
        )
        .await
        .unwrap();
        // v1 was not re-run (no rekeyed families), v2 applied.
        assert!(report.rekeyed.is_empty());
        assert_eq!(
            kv.get("demo/v2").await.unwrap().as_deref(),
            Some(&b"ok"[..])
        );
        assert_eq!(read_state(&kv).await.unwrap().version, 2);
    }
}
