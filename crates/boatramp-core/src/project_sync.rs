//! Planning + preflight for `boatramp project sync` (increment 1 — the planning path).
//!
//! `sync` is the idempotent, selective, coherence-preserving successor to the one-shot
//! `import --clone-from` (see `PLAN-project-sync`): it reconciles a target project toward a
//! source for a SELECTED set of pieces, with config-rewriting so the result is always coherent.
//! This module is the **pure** heart of that operation — no I/O, no mutation — so it is
//! unit-testable in isolation and reusable by the CLI, the admin API, and the console:
//!
//! - [`Piece`] — the selectable replication unit (the PLAN's "Piece taxonomy ↔ control-plane KV
//!   strata" table), and [`piece_kv_strata`], which maps each piece to the actual control-plane
//!   key families it governs, BACKED BY the export allowlist
//!   ([`project_owned_prefixes`](crate::project_export::project_owned_prefixes) +
//!   [`sealed_secret_prefixes`](crate::project_export::sealed_secret_prefixes)) so the taxonomy
//!   can never drift outside the C1 cross-tenant boundary.
//! - [`Selection`] + [`SelectionInput::resolve`] — parse + validate the per-piece
//!   `--include-/--exclude-` knobs (reject a contradictory include+exclude of the same piece;
//!   require an explicit selection — the conservative default) and the per-item escape hatches.
//! - [`plan_sync`] — the DRY-RUN PREFLIGHT (construens cap-req #1 "fail fast"): classify, for the
//!   selection + source inventory + destination state, the destination precondition up front and
//!   each piece / project-owned item into a [`Disposition`] — carry / rewrite / re-derive / drop /
//!   preserve / **skip (incoherent, with reason)** — BEFORE any byte moves. Per-item coherence is
//!   per-item atomicity + skip-and-report (never refuse-all), with [`Selection::strict`] flipping
//!   skip → refuse.
//!
//! ## Increment 2 — the `--apply` EXECUTION
//!
//! [`apply_sync`] is the mutating core: it EXECUTES the preflight [`SyncPlan`] — idempotently,
//! coherently, and fail-closed on tenancy. It is deliberately a PURE orchestrator over a small
//! side-effecting seam, [`SyncExecutor`]: the engine decides WHAT happens, in WHAT order, with
//! WHICH target-scoped keys, and WHICH items atomically carry / rewrite / skip; the executor binds
//! each effect to the real machinery (the export/import clone transport, the project-create +
//! managed-DB provisioning seams, and [`crate::deploy::DeployStore::set_site_config`]) — or, in a
//! unit test, to an in-memory fake. This keeps the risky, tenancy-sensitive logic unit-testable in
//! isolation and lets the engine NEVER rebuild transport.
//!
//! The coherence CORE is [`rewrite_site_config_preserving_dest_domains`]: a `--include sites
//! --exclude domains` carry mirrors the source `SiteConfig` body EXCEPT its `domains` field, which
//! is preserved from the destination (or empty on a fresh dest) — a BODY rewrite, never a key drop,
//! carrying ZERO source domains (the A/B-safe exclude). When domains ARE carried, the write seam's
//! host-uniqueness guard refuses a second simultaneously-live claimant of a host
//! ([`SyncApplyError::DomainConflict`]) — the exclusive-domain-ownership safety constraint.

use std::collections::BTreeSet;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::config::{DomainConfig, SiteConfig};
use crate::project::ProjectRef;
use crate::project_export::sealed_secret_prefixes;

/// An empty set to borrow for the absent-destination case (no owned allocation on a dry-run).
static EMPTY_SET: BTreeSet<String> = BTreeSet::new();

/// One selectable replication **piece** — the unit the `--include-<piece>` / `--exclude-<piece>`
/// knobs toggle (the PLAN's piece taxonomy). Each maps to a concrete control-plane key family via
/// [`piece_kv_strata`] (the data-plane pieces [`Pg`](Self::Pg)/[`Blobs`](Self::Blobs) map to no KV
/// stratum — their source of truth is the managed-DB contents / the content-addressed blob store).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Piece {
    /// Managed-DB contents (runtime data; delta + shadow/swap on apply).
    Pg,
    /// The content-addressed blob store (integrity/delta).
    Blobs,
    /// Site configs — `project/<p>/site/` pointers + the `siteconfig/<hash>` bodies they
    /// reference. Carried; the `domains` field is rewritten when [`Domains`](Self::Domains) is
    /// excluded (PLAN rule 2).
    Sites,
    /// The domain layer — the `domains` field inside each `SiteConfig`, plus
    /// `project/<p>/domainverify/` proofs and `project/<p>/alias/` records.
    Domains,
    /// Imperative project settings — `project/<p>/config/` (e.g. the tenancy schema).
    Settings,
    /// Declarative managed-database bindings — `project/<p>/database/`.
    Databases,
    /// GraphQL registry (`graphql/<p>/` SDLs) + the APQ safelist (`hapq/<p>/`).
    Graphql,
    /// Runtime deploy state — `project/<p>/current/`, `current-principal/`, `history/`.
    History,
    /// KEK-sealed material — `secret/`, `tenant-secret/`, `email/`, `managed-sql-cred/<p>/`.
    /// Cannot cross the KEK boundary: `--identity fresh` DROPS it and the target re-provisions.
    Secrets,
}

impl Piece {
    /// Every piece, in the taxonomy-table order.
    pub const ALL: [Self; 9] = [
        Self::Pg,
        Self::Blobs,
        Self::Sites,
        Self::Domains,
        Self::Settings,
        Self::Databases,
        Self::Graphql,
        Self::History,
        Self::Secrets,
    ];

    /// The stable CLI/wire token (`pg`, `blobs`, `sites`, …).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pg => "pg",
            Self::Blobs => "blobs",
            Self::Sites => "sites",
            Self::Domains => "domains",
            Self::Settings => "settings",
            Self::Databases => "databases",
            Self::Graphql => "graphql",
            Self::History => "history",
            Self::Secrets => "secrets",
        }
    }

    /// Parse ONE token into a piece. `apq` is accepted as an alias for `graphql` (the PLAN lists
    /// the safelist under both spellings). An unknown token is `None` (the caller rejects it
    /// fail-closed, so a typo never silently selects nothing).
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        match token.trim() {
            "pg" => Some(Self::Pg),
            "blobs" => Some(Self::Blobs),
            "sites" => Some(Self::Sites),
            "domains" => Some(Self::Domains),
            "settings" => Some(Self::Settings),
            "databases" => Some(Self::Databases),
            "graphql" | "apq" => Some(Self::Graphql),
            "history" => Some(Self::History),
            "secrets" => Some(Self::Secrets),
            _ => None,
        }
    }
}

/// The control-plane KV key PREFIXES a `piece` governs for `project` — the concrete realisation of
/// the taxonomy table, built from the canonical [`crate::deploy::keys`] builders so it stays
/// byte-aligned with what export/import/prune already use. The data-plane pieces
/// ([`Piece::Pg`]/[`Piece::Blobs`]) govern no KV stratum (their source of truth is the managed-DB
/// contents / the blob store) and return an empty list.
///
/// INVARIANT (enforced by a unit test): every non-secret prefix returned here lies within
/// [`project_owned_prefixes`] (the C1 cross-tenant allowlist), and the [`Piece::Secrets`] set is
/// exactly [`sealed_secret_prefixes`] — so a selection can never reach outside the project's own
/// owned keyspace, and the sealed material a `--identity fresh` run drops is precisely the
/// export's sealed set.
#[must_use]
pub fn piece_kv_strata(piece: Piece, project: ProjectRef<'_>) -> Vec<String> {
    use crate::deploy::keys;
    match piece {
        Piece::Pg | Piece::Blobs => Vec::new(),
        Piece::Sites => vec![
            keys::site_prefix(project),
            format!("project/{project}/sitecontexts/"),
        ],
        Piece::Domains => vec![
            keys::domain_verification_project_prefix(project),
            keys::alias_project_prefix(project),
        ],
        Piece::Settings => vec![format!("project/{project}/config/")],
        Piece::Databases => vec![keys::project_database_prefix(project)],
        Piece::Graphql => vec![
            keys::graphql_registry_prefix(project),
            keys::graphql_safelist_prefix(project),
        ],
        Piece::History => vec![
            keys::current_prefix(project),
            format!("project/{project}/current-principal/"),
            keys::history_prefix(project),
        ],
        Piece::Secrets => sealed_secret_prefixes(project),
    }
}

/// Whether a `piece` may cross the **node-side selective-sync KV endpoint** (the per-stratum,
/// project-scoped admin KV read/write that carries [`Piece::Settings`]/[`Piece::Graphql`]/
/// [`Piece::History`] — and, under `--identity adopt`, the domain-proof stratum — between nodes).
/// TRUE iff the piece governs a NON-SECRET control-plane KV stratum: the data-plane pieces
/// ([`Piece::Pg`]/[`Piece::Blobs`]) govern no KV stratum, and [`Piece::Secrets`] is sealed under the
/// source KEK and must NEVER cross this seam (it is dropped under `--identity fresh`; an
/// `--identity adopt` installs the source KEK through the export identity container, never this KV
/// endpoint). Derived from [`piece_kv_strata`] so the rule can never drift from the taxonomy.
#[must_use]
pub fn kv_stratum_is_endpoint_carryable(piece: Piece) -> bool {
    piece != Piece::Secrets && !piece_kv_strata(piece, ProjectRef::new("_")).is_empty()
}

/// STRUCTURAL project + piece scoping for a selective-sync KV write — the fail-closed gate the
/// node-side DEST endpoint applies to every incoming entry AFTER it has been re-keyed to the
/// authenticated TARGET project ([`crate::project_export::rekey_entries_to_target`]) and BEFORE a
/// byte is written. The STRICTER, piece-restricted sibling of
/// [`enforce_target_scoped_kv`](crate::project_export::enforce_target_scoped_kv): where that admits
/// any target-owned key (sealed secrets INCLUDED — correct for a full bundle restore), this admits
/// ONLY keys under the named NON-SECRET piece's own [`piece_kv_strata`] prefixes for the target, so
/// a crafted settings/graphql/history slice can never smuggle a sealed `secret/` key, another
/// tenant's key, or a global routing/TLS key onto the destination.
///
/// Two fail-closed refusals, each naming the offending key:
///   1. the `piece` is not [`kv_stratum_is_endpoint_carryable`] (pg/blobs/secrets) — the endpoint
///      refuses the whole request; and
///   2. ANY entry whose key is outside the target's `piece` prefixes — including (asserted
///      explicitly, defence in depth) anything under [`sealed_secret_prefixes`].
///
/// The scope is built from the AUTHENTICATED `target` binding and the compile-time piece taxonomy,
/// NEVER from a client-supplied key path — the tenancy lesson: scope is enforced structurally or
/// refused, never by trusting a client string.
pub fn enforce_stratum_scoped_kv(
    entries: &[crate::kv::KvDumpEntry],
    piece: Piece,
    target: ProjectRef<'_>,
) -> Result<(), String> {
    if !kv_stratum_is_endpoint_carryable(piece) {
        return Err(format!(
            "selective-sync KV endpoint refused the `{}` piece: only non-secret control-plane KV \
             strata (settings / graphql / history / sites / domains / databases) may cross — \
             pg/blobs have no KV stratum, and secrets are sealed under the source KEK and never \
             cross this seam",
            piece.as_str()
        ));
    }
    let allowed = piece_kv_strata(piece, target);
    let sealed = sealed_secret_prefixes(target);
    for e in entries {
        // Defence in depth: a sealed-prefix key must NEVER be written here, even if some future
        // piece's stratum ever overlapped the sealed set.
        if sealed.iter().any(|s| e.key.starts_with(s.as_str())) {
            return Err(format!(
                "selective-sync KV write refused: entry {:?} lies under a sealed-secret prefix — \
                 this endpoint must never write KEK-sealed material",
                e.key
            ));
        }
        if !allowed.iter().any(|p| e.key.starts_with(p.as_str())) {
            return Err(format!(
                "selective-sync KV write refused: entry {:?} is outside target project {target}'s \
                 `{}` stratum prefixes after re-key — a crafted / foreign / cross-tenant key is \
                 never written (structural project+piece scoping)",
                e.key,
                piece.as_str()
            ));
        }
    }
    Ok(())
}

/// For a HISTORY-piece key (`project/<target>/current/<site>`, `current-principal/<site>`, or
/// `history/<site>`), the `<site>` segment it points at — the site whose content-addressed config
/// body MUST already exist on the destination for the pointer to be coherent (PLAN dependency
/// model: `current/`/`history/` → `siteconfig/<hash>`; a `current/<site>` for a site the dest has
/// no config for would dangle). `None` for any key that is not one of those per-site pointers.
/// Pure string parsing over the canonical key shapes so the DEST endpoint's skip-and-report
/// coherence check (PLAN rule 3) is unit-testable without a KV store.
#[must_use]
pub fn history_key_site<'a>(key: &'a str, target: ProjectRef<'_>) -> Option<&'a str> {
    for infix in ["current-principal/", "current/", "history/"] {
        let pref = format!("project/{target}/{infix}");
        if let Some(rest) = key.strip_prefix(&pref) {
            let site = rest.split('/').next().unwrap_or("");
            if !site.is_empty() {
                return Some(site);
            }
        }
    }
    None
}

/// What `sync` does with a piece or a single project-owned item — the CLOSED classification
/// vocabulary the preflight reports (PLAN semantics §1–3 + the taxonomy table's "On sync" column).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Disposition {
    /// Mirror toward the source (source authoritative) — the included-piece default.
    Carry,
    /// Carry the body but REWRITE a field: a `SiteConfig` body is mirrored EXCEPT its `domains`
    /// field, which is preserved from the destination (PLAN rule 2 — `--include sites --exclude
    /// domains`). Never a key drop.
    Rewrite,
    /// NOT carried — re-derived / re-issued under the target's OWN identity (global routing + TLS:
    /// `domain/`, `wildcard/`, `cert/`). Already true for import today.
    ReDerive,
    /// Dropped — sealed under the SOURCE KEK, so it cannot cross (`--identity fresh`); the target
    /// re-provisions its own. Also the per-item disposition for an explicit `--exclude-site/-db`.
    Drop,
    /// The destination's existing value is PRESERVED verbatim (an excluded piece: sync never reads,
    /// writes, or prunes it). On a fresh/absent destination this degrades to "nothing to preserve".
    Preserve,
    /// Incoherent — the item is left at the destination's prior, coherent state and REPORTED
    /// (never half-applied). The default per-item outcome for a dependency the selection leaves
    /// dangling; [`Selection::strict`] turns it into a refusal.
    Skip,
}

impl Disposition {
    /// A short stable token for the human/JSON rendering.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Carry => "carry",
            Self::Rewrite => "rewrite",
            Self::ReDerive => "re-derive",
            Self::Drop => "drop",
            Self::Preserve => "preserve",
            Self::Skip => "skip",
        }
    }
}

/// Why a [`Selection`] could not be resolved from the raw `--include-/--exclude-` knobs
/// (fail-closed — a bad selection never silently degrades to "sync everything" or "sync nothing").
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SelectionError {
    /// The same piece was both `--include-<piece>` and `--exclude-<piece>`.
    #[error("piece `{0}` was both included and excluded — pick one")]
    Contradiction(&'static str),
    /// Neither any `--include-<piece>` nor any `--exclude-<piece>` was given. A sync needs an
    /// explicit selection (the conservative default): an allowlist of `--include-<piece>`, or
    /// `--exclude-<piece>` to carve from the full set.
    #[error(
        "a sync needs an explicit selection: pass --include-<piece> … (an allowlist) or \
         --exclude-<piece> … (carve from all); pieces: pg, blobs, sites, domains, settings, \
         databases, graphql, history, secrets"
    )]
    Empty,
    /// The selection resolved to NO pieces (e.g. every piece excluded) — there is nothing to sync.
    #[error("the selection resolved to no pieces — nothing would be synced")]
    Nothing,
}

/// The raw, pre-validation selection the CLI collects from the flag surface — before
/// [`resolve`](Self::resolve) turns it into a coherent [`Selection`].
#[derive(Debug, Clone, Default)]
pub struct SelectionInput {
    /// Pieces named by a `--include-<piece>` knob.
    pub include: BTreeSet<Piece>,
    /// Pieces named by a `--exclude-<piece>` knob.
    pub exclude: BTreeSet<Piece>,
    /// `--exclude-site <name>` (per-item escape hatch).
    pub exclude_sites: BTreeSet<String>,
    /// `--exclude-db <name>` (per-item escape hatch).
    pub exclude_dbs: BTreeSet<String>,
    /// `--identity fresh` — the target mints/keeps its own KEK; source-sealed secrets are dropped.
    /// The only identity mode in increment 1 (adopt is increment 2).
    pub identity_fresh: bool,
    /// `--strict` — flip any per-item skip into a whole-run refusal (all-or-nothing for automation).
    pub strict: bool,
}

impl SelectionInput {
    /// Validate + resolve into a coherent [`Selection`]:
    /// 1. a piece in BOTH include and exclude is a contradiction (checked first);
    /// 2. the base set is the include allowlist when any `--include-<piece>` was given, else the
    ///    FULL set when only `--exclude-<piece>` was given, else [`SelectionError::Empty`] (the
    ///    conservative explicit-selection-required default);
    /// 3. the excludes are subtracted; an empty result is [`SelectionError::Nothing`].
    pub fn resolve(self) -> Result<Selection, SelectionError> {
        if let Some(dup) = self.include.intersection(&self.exclude).next() {
            return Err(SelectionError::Contradiction(dup.as_str()));
        }
        let mut pieces: BTreeSet<Piece> = if !self.include.is_empty() {
            self.include.clone()
        } else if !self.exclude.is_empty() {
            Piece::ALL.into_iter().collect()
        } else {
            return Err(SelectionError::Empty);
        };
        for p in &self.exclude {
            pieces.remove(p);
        }
        if pieces.is_empty() {
            return Err(SelectionError::Nothing);
        }
        Ok(Selection {
            pieces,
            exclude_sites: self.exclude_sites,
            exclude_dbs: self.exclude_dbs,
            identity_fresh: self.identity_fresh,
            strict: self.strict,
        })
    }
}

/// A validated, coherent sync selection — the included pieces plus the per-item escape hatches and
/// the identity / strictness mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// The INCLUDED pieces (reconciled toward the source). A piece NOT here is preserved on the dest.
    pub pieces: BTreeSet<Piece>,
    /// Sites to drop rather than carry (`--exclude-site`).
    pub exclude_sites: BTreeSet<String>,
    /// Databases to drop rather than carry (`--exclude-db`).
    pub exclude_dbs: BTreeSet<String>,
    /// Whether identity is `fresh` (source-sealed secrets dropped; target re-provisions).
    pub identity_fresh: bool,
    /// Whether a per-item skip refuses the whole run.
    pub strict: bool,
}

impl Selection {
    /// Whether `piece` is included (reconciled toward the source).
    #[must_use]
    pub fn includes(&self, piece: Piece) -> bool {
        self.pieces.contains(&piece)
    }
}

/// One site in the SOURCE project's inventory — the inputs the per-item coherence check needs
/// (what hosts the config carries, and which managed databases the site binds). Deliberately
/// abstract: HOW these are extracted from a `SiteConfig` / handler bindings is the caller's job
/// (and, for a cross-node source, the increment-2 preflight-enumeration endpoint's), keeping this
/// planner pure and seedable from a fixture.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SiteItem {
    /// The site name.
    pub name: String,
    /// Whether the source site's config carries any domains (informational for the rewrite note).
    pub has_domains: bool,
    /// The managed-database binding names this site depends on (the hard cross-reference the
    /// coherence check honours — a site binding a DB absent from the destination is incoherent).
    pub db_bindings: Vec<String>,
}

/// The engine of a database binding, for the per-DB restore-feasibility classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DbEngine {
    /// Postgres — restores via the atomic non-superuser shadow+swap (dedicated → chunked; Shared →
    /// sidecar shadow+swap).
    #[default]
    Postgres,
    /// MySQL — restores via the atomic non-superuser shadow+swap for EITHER tenancy (dedicated/Single
    /// → the chunked arm; Shared → the sidecar shadow+swap, mirroring Postgres).
    Mysql,
    /// An engine a sync restore does not know how to shadow+swap.
    Other,
}

/// One database in the SOURCE project's inventory — the inputs the per-DB restore-FEASIBILITY check
/// needs. Deliberately abstract: HOW the engine / managed-ness / tenancy are extracted from the
/// source is the caller's job, keeping the planner pure + fixture-seedable. NB: a declared managed
/// DB (`list_databases` / `ApplyDatabase`) is DEFINITIONALLY `managed = true` — the CLI inventory
/// cannot represent an external/BYO (`url_env`) binding today, so `managed = false` is reachable only
/// from a fixture (the planner is complete; the real CLI feeds only managed DBs — see the feasibility
/// classification in [`plan_sync`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbItem {
    /// The binding name (how a guest reaches it + the `project/<p>/database/<name>` key segment).
    pub name: String,
    /// The engine (Postgres / MySQL).
    pub engine: DbEngine,
    /// Whether boatramp MANAGES this binding (provisions + seals the credential). `false` = an
    /// EXTERNAL / bring-your-own-URL binding, which the non-superuser shadow+swap cannot restore (it
    /// would run on the operator's OWN server — refused by `pg_shadow_plan`).
    pub managed: bool,
    /// Whether the tenant isolation is Shared (one server, per-tenant db + role) vs dedicated/Single.
    pub shared: bool,
}

impl DbItem {
    /// A managed, dedicated/Single Postgres binding (the common case the CLI produces).
    #[must_use]
    pub fn managed_pg(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            engine: DbEngine::Postgres,
            managed: true,
            shared: false,
        }
    }

    /// Why this DB CANNOT be restored by a sync (so the preflight classifies it `Skip` with this
    /// reason, surfaced by `--strict` + the skipped count) — or `None` when it is feasible
    /// (restorable via the shadow+swap this fix routes managed members through). Managed pg AND
    /// managed MySQL are feasible for EITHER tenancy (dedicated → the chunked shadow, Shared → the
    /// sidecar shadow+swap); an external/BYO binding or an unknown engine is not.
    #[must_use]
    pub fn infeasible_reason(&self) -> Option<String> {
        if !self.managed {
            return Some(
                "external / bring-your-own-URL binding — the non-superuser shadow+swap cannot run \
                 on the operator's own server; provision + replicate it out of band"
                    .to_string(),
            );
        }
        match self.engine {
            DbEngine::Other => {
                Some("unsupported managed engine for a sync shadow+swap restore".to_string())
            }
            // Managed pg + managed MySQL both restore via the non-superuser shadow+swap for either
            // tenancy (dedicated → chunked, Shared → the sidecar shadow+swap); only a non-managed
            // (external/BYO) binding or an unknown engine is infeasible.
            _ => None,
        }
    }
}

/// The SOURCE project's inventory the preflight classifies. Only the fields a given selection
/// touches need be populated; an empty inventory yields a piece-level plan with no item rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncInventory {
    /// The source's sites (for the [`Piece::Sites`] per-item classification).
    pub sites: Vec<SiteItem>,
    /// The source's declared databases, with the per-DB metadata the restore-feasibility check needs
    /// (for [`Piece::Databases`] + the site coherence check).
    pub databases: Vec<DbItem>,
}

/// The DESTINATION's observed state — the precondition the preflight reports up front. `Absent`
/// is DETECTED, not 404'd: sync plans to create + provision it (increment 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestState {
    /// The destination project does not exist — sync will create + provision it.
    Absent,
    /// The destination exists; these are the sites + databases it already holds (so an excluded
    /// piece's "preserve" is real, and a site's bound DB that already exists on the dest is coherent
    /// even when this sync does not carry it).
    Present {
        /// Sites already on the destination.
        sites: BTreeSet<String>,
        /// Databases already on the destination.
        databases: BTreeSet<String>,
    },
}

/// The destination precondition the preflight surfaces BEFORE any byte moves (subsumes the old
/// late "non-empty destination" refusal — construens cap-req #1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DestPrecondition {
    /// The destination is absent — sync will create + provision it (increment 2). Rule 1's
    /// "excluded pieces preserved verbatim" degrades cleanly to "nothing to preserve".
    CreateAndProvision,
    /// The destination exists — excluded pieces are preserved verbatim on it.
    Exists,
}

/// How one piece is handled under the resolved selection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PiecePlan {
    /// The piece.
    pub piece: Piece,
    /// Whether it is included (reconciled toward the source) vs excluded (preserved on the dest).
    pub included: bool,
    /// The classification.
    pub disposition: Disposition,
    /// The control-plane KV strata this piece governs ([`piece_kv_strata`]); empty for the
    /// data-plane pieces.
    pub kv_strata: Vec<String>,
    /// A one-line human explanation of the disposition.
    pub note: String,
}

/// What kind of project-owned item an [`ItemPlan`] classifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ItemKind {
    /// A site.
    Site,
    /// A managed database.
    Database,
}

/// The per-item classification (PLAN semantics §3 — per-item atomicity + skip-and-report).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemPlan {
    /// Site or database.
    pub kind: ItemKind,
    /// The item name.
    pub name: String,
    /// The per-item disposition (carry / rewrite / drop / skip).
    pub disposition: Disposition,
    /// The reason — present for a skip (why it is incoherent), a rewrite, or an explicit drop.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// The DRY-RUN PREFLIGHT plan — the full, before-any-byte-moves classification of a sync.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPlan {
    /// The source label (a URL or a project name).
    pub source: String,
    /// The target (destination) project.
    pub target: String,
    /// The destination precondition (create+provision vs exists).
    pub dest: DestPrecondition,
    /// Whether identity is `fresh`.
    pub identity_fresh: bool,
    /// Whether `--strict` is set (a skip refuses the whole run).
    pub strict: bool,
    /// The per-piece plan (one row per piece, in taxonomy order).
    pub pieces: Vec<PiecePlan>,
    /// The per-item plan (sites + databases, for the included pieces). Empty when the source
    /// inventory carries no items for the selected pieces.
    pub items: Vec<ItemPlan>,
}

impl SyncPlan {
    /// The items the preflight would SKIP as incoherent (with their reasons).
    #[must_use]
    pub fn skipped_items(&self) -> Vec<&ItemPlan> {
        self.items
            .iter()
            .filter(|i| i.disposition == Disposition::Skip)
            .collect()
    }

    /// The number of incoherent, skipped items.
    #[must_use]
    pub fn skipped_count(&self) -> usize {
        self.items
            .iter()
            .filter(|i| i.disposition == Disposition::Skip)
            .count()
    }

    /// Whether `--strict` turns this plan into a refusal: strict AND at least one item is skipped.
    /// (Under the default non-strict posture, a skip is reported, not refused.)
    #[must_use]
    pub fn is_refused(&self) -> bool {
        self.strict && self.skipped_count() > 0
    }
}

/// Build the DRY-RUN PREFLIGHT plan from a resolved `selection`, the SOURCE `inventory`, and the
/// observed destination `dest`. PURE — no I/O, no mutation — so a `~46 GB` sync answers in the
/// time of the inventory fetch (construens cap-req #1 "fail fast"). `apply` (increment 2) would
/// execute exactly this plan's carried items.
#[must_use]
pub fn plan_sync(
    selection: &Selection,
    inventory: &SyncInventory,
    dest: &DestState,
    source: &str,
    target: &str,
) -> SyncPlan {
    let precondition = match dest {
        DestState::Absent => DestPrecondition::CreateAndProvision,
        DestState::Present { .. } => DestPrecondition::Exists,
    };
    let fresh_dest = matches!(dest, DestState::Absent);
    // The destination's databases anchor the per-site coherence check (a site's bound DB that
    // already lives on the dest is coherent even when this sync does not carry it). The dest's
    // sites are carried in [`DestState`] for the report/API but are not needed by the planner yet.
    let dest_dbs: &BTreeSet<String> = match dest {
        DestState::Absent => &EMPTY_SET,
        DestState::Present { databases, .. } => databases,
    };

    // --- Per-piece plan (taxonomy order) -------------------------------------------------------
    let pr = ProjectRef::new(target);
    let domains_included = selection.includes(Piece::Domains);
    let mut pieces = Vec::with_capacity(Piece::ALL.len());
    for piece in Piece::ALL {
        let included = selection.includes(piece);
        let (disposition, note) = if !included {
            let note = if fresh_dest {
                "excluded — nothing to preserve on a fresh destination".to_string()
            } else {
                "excluded — the destination's own value is preserved verbatim".to_string()
            };
            (Disposition::Preserve, note)
        } else {
            match piece {
                Piece::Pg => (
                    Disposition::Carry,
                    "carry managed-DB contents (delta)".into(),
                ),
                Piece::Blobs => (
                    Disposition::Carry,
                    "carry the content-addressed blob store (integrity/delta)".into(),
                ),
                Piece::Settings => (
                    Disposition::Carry,
                    "carry imperative project settings (project/<p>/config/)".into(),
                ),
                Piece::Databases => (
                    Disposition::Carry,
                    "carry declarative managed-database bindings".into(),
                ),
                Piece::Graphql => (
                    Disposition::Carry,
                    "carry the GraphQL registry + APQ safelist".into(),
                ),
                Piece::History => (
                    Disposition::Carry,
                    "carry runtime deploy state (current/current-principal/history)".into(),
                ),
                Piece::Sites => {
                    if domains_included {
                        (
                            Disposition::Carry,
                            "carry site configs, including their domains".into(),
                        )
                    } else {
                        (
                            Disposition::Rewrite,
                            "carry site configs; rewrite the `domains` field — the destination's \
                             own domains are preserved (no re-authorization)"
                                .into(),
                        )
                    }
                }
                Piece::Domains => (
                    Disposition::Carry,
                    "carry the domain layer (domains field + verification/alias records)".into(),
                ),
                Piece::Secrets => (
                    Disposition::Drop,
                    "sealed under the source KEK — dropped (`--identity fresh`); the target \
                     re-provisions its own"
                        .into(),
                ),
            }
        };
        pieces.push(PiecePlan {
            piece,
            included,
            disposition,
            kv_strata: piece_kv_strata(piece, pr),
            note,
        });
    }

    // --- Per-item plan (coherence; PLAN semantics §3) ------------------------------------------
    let databases_included = selection.includes(Piece::Databases);
    let sites_included = selection.includes(Piece::Sites);

    // A DB is "present on the destination after this sync" iff it is already on the dest, OR this
    // sync carries it (databases included, the source declares it as a FEASIBLE restore, and it is
    // not per-item excluded). An INFEASIBLE DB (external/BYO, Shared MySQL, …) is NOT carried, so a
    // site binding it is correctly judged incoherent (its reason surfaces on the DB row).
    let db_present_after = |name: &str| -> bool {
        if dest_dbs.contains(name) {
            return true;
        }
        databases_included
            && inventory
                .databases
                .iter()
                .any(|d| d.name == name && d.infeasible_reason().is_none())
            && !selection.exclude_dbs.contains(name)
    };

    let mut items = Vec::new();

    if sites_included {
        for site in &inventory.sites {
            if selection.exclude_sites.contains(&site.name) {
                items.push(ItemPlan {
                    kind: ItemKind::Site,
                    name: site.name.clone(),
                    disposition: Disposition::Drop,
                    reason: Some("dropped by --exclude-site".into()),
                });
                continue;
            }
            // Coherence: every bound managed DB must exist on the destination after the sync.
            let missing: Vec<String> = site
                .db_bindings
                .iter()
                .filter(|b| !db_present_after(b))
                .cloned()
                .collect();
            if !missing.is_empty() {
                items.push(ItemPlan {
                    kind: ItemKind::Site,
                    name: site.name.clone(),
                    disposition: Disposition::Skip,
                    reason: Some(format!(
                        "binds managed database(s) [{}] absent from the destination and not in \
                         this sync's selection — add the database (or --include-databases), then \
                         resync; the destination's prior state for this site is left intact",
                        missing.join(", ")
                    )),
                });
                continue;
            }
            // Coherent: carry, rewriting the domains field when domains are excluded.
            if domains_included {
                items.push(ItemPlan {
                    kind: ItemKind::Site,
                    name: site.name.clone(),
                    disposition: Disposition::Carry,
                    reason: None,
                });
            } else {
                items.push(ItemPlan {
                    kind: ItemKind::Site,
                    name: site.name.clone(),
                    disposition: Disposition::Rewrite,
                    reason: Some(
                        "domains excluded — the destination's own domains are preserved".into(),
                    ),
                });
            }
        }
    }

    if databases_included {
        for db in &inventory.databases {
            if selection.exclude_dbs.contains(&db.name) {
                items.push(ItemPlan {
                    kind: ItemKind::Database,
                    name: db.name.clone(),
                    disposition: Disposition::Drop,
                    reason: Some("dropped by --exclude-db".into()),
                });
            } else if let Some(reason) = db.infeasible_reason() {
                // FEASIBILITY preflight (fail in the PLAN, not at apply): a DB whose restore the
                // sync cannot perform (external/BYO binding, Shared MySQL, unknown engine) is SKIPPED
                // with its reason — surfaced by `--strict` + the skipped count, so the operator sees
                // it up front rather than hitting the node's late apply-time refusal.
                items.push(ItemPlan {
                    kind: ItemKind::Database,
                    name: db.name.clone(),
                    disposition: Disposition::Skip,
                    reason: Some(reason),
                });
            } else {
                // Feasible: a managed pg (any tenant) or a managed dedicated MySQL — carried and
                // restored via the provision + non-superuser shadow+swap (post-fix).
                items.push(ItemPlan {
                    kind: ItemKind::Database,
                    name: db.name.clone(),
                    disposition: Disposition::Carry,
                    reason: None,
                });
            }
        }
    }

    SyncPlan {
        source: source.to_string(),
        target: target.to_string(),
        dest: precondition,
        identity_fresh: selection.identity_fresh,
        strict: selection.strict,
        pieces,
        items,
    }
}

// =============================================================================================
// Increment 2 — the `--apply` EXECUTION
// =============================================================================================

/// Rewrite a carried SOURCE [`SiteConfig`] so the destination keeps its OWN domains (PLAN rule 2 —
/// a `--include sites --exclude domains` carry). Everything in the source body is mirrored EXCEPT
/// the `domains` field, which is REPLACED by `dest_domains` — the destination's current domains, or
/// an EMPTY [`DomainConfig`] on a fresh/absent destination (nothing to preserve).
///
/// SAFETY INVARIANT (the reliability half of the domain layer, PLAN "Exclude is complete"): the
/// result carries ZERO source domains — not `primary`, not an `alias`, not a `wildcard`, not a
/// per-host context tag (the whole [`DomainConfig`] is replaced, so `contexts` come from the dest
/// too). A resync therefore can never make the destination claim a source host, and never touches
/// the dest's own `domainverify` proofs (no re-authorization). It is a BODY rewrite, never a key
/// drop: the emitted body is re-pointed through the normal content-addressed `siteconfig/<hash>` +
/// `site/`/`current/` machinery by the executor.
#[must_use]
pub fn rewrite_site_config_preserving_dest_domains(
    source: &SiteConfig,
    dest_domains: Option<&DomainConfig>,
) -> SiteConfig {
    let mut out = source.clone();
    out.domains = dest_domains.cloned().unwrap_or_default();
    out
}

/// The content-address (`siteconfig/<hash>` hash) of a `SiteConfig` body — byte-identical to what
/// [`crate::deploy::DeployStore::set_site_config`] computes (`sha256_hex(to_json)`). So a rewrite
/// that reproduces the destination's EXISTING body yields the dest's existing hash ⇒ the pointer
/// flip is a no-op, which is what makes a second `--apply` of an unchanged source converge to
/// nothing (idempotent resync). Used by a same-node executor that writes the body + pointer
/// directly; the HTTP `put_site_config` path recomputes the same hash node-side.
pub fn site_config_hash(cfg: &SiteConfig) -> Result<String, SyncApplyError> {
    let body = cfg
        .to_json()
        .map_err(|e| SyncApplyError::Rewrite(e.to_string()))?;
    Ok(crate::deploy::sha256_hex(&body))
}

/// A failure during [`apply_sync`]. A per-ITEM failure (a site that cannot carry coherently, or an
/// exclusive-domain double-claim) is NOT one of these under the default posture — it is recorded in
/// the [`SyncApplyReport`] as a skipped item and the run continues (PLAN semantics §3,
/// skip-and-report). These variants are the RUN-level, abort-the-whole-sync failures: a data-plane
/// transfer that failed, a provisioning failure, a `--strict` refusal, or an executor seam that is
/// not available on this platform yet.
#[derive(Debug, thiserror::Error)]
pub enum SyncApplyError {
    /// The absent destination could not be created / provisioned.
    #[error("destination create/provision failed: {0}")]
    Provision(String),
    /// A data-plane transfer (managed-DB contents or blobs) failed — run-level, not per-item.
    #[error("{piece} transfer failed: {message}")]
    Transfer {
        /// `pg` or `blobs`.
        piece: &'static str,
        /// The underlying error text.
        message: String,
    },
    /// A control-plane KV stratum carry failed.
    #[error("carry of `{piece}` failed: {message}")]
    Carry {
        /// The piece whose stratum carry failed.
        piece: &'static str,
        /// The underlying error text.
        message: String,
    },
    /// EXCLUSIVE-DOMAIN double-claim (PLAN "exclusive domain ownership"): a carried site's host is
    /// already a LIVE owner in a different project/site, so writing it would create a second
    /// simultaneously-live claimant. Surfaced by the write seam's host-uniqueness guard
    /// ([`crate::deploy::DeployStore::set_site_config`] → `Conflict`). Under the default posture the
    /// engine CATCHES this and records a skipped item; it only escapes as an error under `--strict`.
    #[error("exclusive-domain conflict on site `{site}`: {message}")]
    DomainConflict {
        /// The site whose carried host is double-claimed.
        site: String,
        /// The conflict detail (which host, held by whom).
        message: String,
    },
    /// A `SiteConfig` rewrite / (de)serialize failure.
    #[error("site config rewrite failed: {0}")]
    Rewrite(String),
    /// A requested executor seam is not available on this platform/build yet (an HONEST stub — e.g.
    /// a selective control-plane KV-stratum carry that needs a node-side sync endpoint). Carries the
    /// piece so the operator sees exactly which part of the selection could not execute.
    #[error("{0}")]
    Unsupported(String),
    /// `--strict` refusal: ≥1 item is incoherent or domain-conflicting, and strict is all-or-nothing.
    #[error("strict apply refused: {count} item(s) would be skipped\n{detail}")]
    StrictRefused {
        /// How many items would be skipped.
        count: usize,
        /// Per-item reasons, one per line.
        detail: String,
    },
    /// Any other executor failure.
    #[error("{0}")]
    Other(String),
}

/// The side-effecting seam [`apply_sync`] drives. The ENGINE decides WHAT happens, in WHAT order,
/// with WHICH target-scoped keys, and WHICH items carry / rewrite / skip atomically; an executor
/// binds each effect to the real machinery — or, in a unit test, to an in-memory fake.
///
/// FAIL-CLOSED TENANCY: the engine passes ONLY target-owned, structurally-scoped prefixes to
/// [`carry_kv_stratum`](Self::carry_kv_stratum) (built from [`piece_kv_strata`], whose invariant
/// test proves every prefix lies within [`project_owned_prefixes`](crate::project_export::project_owned_prefixes)).
/// An executor can therefore never be ASKED to write outside the target project's owned keyspace;
/// a real executor additionally re-applies the import-side
/// [`enforce_target_scoped_kv`](crate::project_export::enforce_target_scoped_kv) as defence in depth.
#[async_trait]
pub trait SyncExecutor: Send {
    /// Create + provision the ABSENT destination (the project record + its managed DB), reusing the
    /// project-create + managed-DB provisioning seams. MUST be idempotent (a no-op if it already
    /// exists), so a resync after a partial create converges.
    async fn create_and_provision_dest(&mut self) -> Result<(), SyncApplyError>;

    /// Transfer the managed-DB contents (pg/mysql/libsql SQL true-delta + atomic shadow+swap) from
    /// source to target, reusing the export/import clone transport. MUST be idempotent (delta): a
    /// re-run moves only what changed and a no-change re-run moves nothing.
    async fn transfer_pg(&mut self) -> Result<(), SyncApplyError>;

    /// Transfer the content-addressed blob store (integrity/delta). MUST be idempotent (by hash):
    /// a blob already present content-matched is skipped.
    async fn transfer_blobs(&mut self) -> Result<(), SyncApplyError>;

    /// Carry a control-plane KV STRATUM: mirror the source's entries under this piece into the
    /// target, structurally re-scoped to `target_prefixes` (which the engine built from
    /// [`piece_kv_strata`] — all target-owned). The executor must reuse
    /// [`scope_entries_to_project`](crate::project_export::scope_entries_to_project) /
    /// [`enforce_target_scoped_kv`](crate::project_export::enforce_target_scoped_kv) so a crafted
    /// source can never land a foreign key. `exclude_prefixes` are target keys the carry must NOT
    /// write (a dropped/skipped site's `current/`/`alias/` dependants — coherence). A true mirror
    /// MAY prune target-only entries within the stratum (source-authoritative). Returns the number
    /// of KV records written. MUST be idempotent (same source ⇒ same bytes).
    async fn carry_kv_stratum(
        &mut self,
        piece: Piece,
        target_prefixes: &[String],
        exclude_prefixes: &BTreeSet<String>,
    ) -> Result<usize, SyncApplyError>;

    /// Carry (declare + provision) one managed-database binding `name` from the source to the target,
    /// reusing the declarative managed-DB seam. MUST be idempotent.
    async fn carry_database(&mut self, name: &str) -> Result<(), SyncApplyError>;

    /// Read the SOURCE site's `SiteConfig` (for a carry/rewrite). `None` ⇒ the source has no such
    /// site (the item is reported, not written).
    async fn read_source_site_config(
        &mut self,
        site: &str,
    ) -> Result<Option<SiteConfig>, SyncApplyError>;

    /// Read the DESTINATION site's current domains, to PRESERVE them on a domains-excluded rewrite.
    /// `None` ⇒ a fresh/absent destination or a dest without that site (⇒ empty domains — nothing to
    /// preserve).
    async fn read_dest_site_domains(
        &mut self,
        site: &str,
    ) -> Result<Option<DomainConfig>, SyncApplyError>;

    /// Write a site's `SiteConfig` to the DESTINATION — content-address the body, re-point
    /// `site/`+`current/`, rebuild the routing index, enforce the host-uniqueness hijack guard
    /// ([`crate::deploy::DeployStore::set_site_config`]). MUST return
    /// [`SyncApplyError::DomainConflict`] when a carried host is already a LIVE owner in a different
    /// project/site (the exclusive-domain guard). MUST be idempotent (same body ⇒ same hash ⇒
    /// pointer no-op). Returns `true` iff the write actually CHANGED the destination (so the report
    /// can distinguish a real carry from an idempotent no-op).
    async fn write_dest_site_config(
        &mut self,
        site: &str,
        cfg: &SiteConfig,
    ) -> Result<bool, SyncApplyError>;
}

/// One item the apply SKIPPED (did not write), with its reason — PLAN semantics §3 (skip-and-report,
/// never half-applied). The destination's prior, coherent state for the item is left intact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedItem {
    /// Site or database.
    pub kind: ItemKind,
    /// The item name.
    pub name: String,
    /// Why it was skipped (incoherent dependency, or an exclusive-domain double-claim).
    pub reason: String,
}

/// The outcome of an applied sync — what actually moved, and what was skipped/dropped. Mirrors
/// [`crate::project_export::ImportReport`]'s legible-summary role.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncApplyReport {
    /// The destination project was absent and was created + provisioned.
    pub dest_created: bool,
    /// Managed-DB contents were transferred (pg piece carried).
    pub pg_transferred: bool,
    /// The blob store was transferred (blobs piece carried).
    pub blobs_transferred: bool,
    /// Control-plane KV records written across the carried strata.
    pub kv_records: usize,
    /// Which KV-stratum pieces were carried.
    pub kv_strata_carried: Vec<Piece>,
    /// Managed databases carried (declared + provisioned).
    pub databases_carried: Vec<String>,
    /// Sites carried whole (domains included).
    pub sites_carried: Vec<String>,
    /// Sites carried with the domains field rewritten to the destination's own.
    pub sites_rewritten: Vec<String>,
    /// Sites/databases whose body the write left unchanged (idempotent no-op) — the convergence
    /// signal a second `--apply` reports.
    pub unchanged: Vec<String>,
    /// Items SKIPPED (incoherent, or exclusive-domain) with reasons — never half-applied.
    pub skipped: Vec<SkippedItem>,
    /// Items explicitly dropped by a per-item `--exclude-site`/`--exclude-db`.
    pub dropped: Vec<String>,
    /// Whether identity was `fresh` (source-sealed secrets dropped).
    pub identity_fresh: bool,
    /// Whether `--strict` was in force.
    pub strict: bool,
    /// Operator notes (seams not wired on this platform, coherence caveats).
    pub notes: Vec<String>,
}

impl SyncApplyReport {
    /// How many items were skipped (incoherent / exclusive-domain). A human/CI gates on a non-zero
    /// count (PLAN semantics §3 — "a non-zero skipped count a human/CI can gate on").
    #[must_use]
    pub fn skipped_count(&self) -> usize {
        self.skipped.len()
    }

    /// Whether the apply completed WITH skips (the distinct "completed with N skipped" outcome).
    #[must_use]
    pub fn completed_with_skips(&self) -> bool {
        !self.skipped.is_empty()
    }

    /// Whether this apply changed NOTHING at the destination — every carried item was an idempotent
    /// no-op and nothing was created/transferred. The converged resync signal.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        !self.dest_created
            && !self.pg_transferred
            && !self.blobs_transferred
            && self.kv_records == 0
            && self.databases_carried.is_empty()
            && self.sites_carried.is_empty()
            && self.sites_rewritten.is_empty()
    }
}

/// EXECUTE the preflight [`SyncPlan`] against `exec` — the mutating, tenancy-sensitive core of
/// `project sync --apply`. Idempotent (a second run of an unchanged source converges to a no-op),
/// coherent (per-item atomic carry/rewrite, incoherent items skipped-and-reported, never
/// half-applied), and fail-closed on tenancy (every carried key is structurally target-scoped).
///
/// ORDER (dependency-aware): create+provision an absent dest → transfer the data plane (pg, blobs)
/// → carry managed-DB bindings → carry the independent KV strata (settings, graphql) → carry/rewrite
/// the sites per item → carry the site-DEPENDENT strata (domains' verification/alias records, then
/// history's current pointers) → drop sealed secrets (identity fresh). A `--strict` plan with any
/// pre-known incoherent item is refused up front; an exclusive-domain conflict discovered at write
/// time is a skip under the default posture and a refusal under `--strict`.
pub async fn apply_sync(
    plan: &SyncPlan,
    exec: &mut dyn SyncExecutor,
) -> Result<SyncApplyReport, SyncApplyError> {
    let target = plan.target.clone();
    let pr = ProjectRef::new(&target);

    // --- strict pre-check: a plan that already classified ≥1 incoherent item refuses as a whole
    //     (PLAN semantics §3). The dry-run computed the full plan; here we refuse before mutating.
    if plan.is_refused() {
        let detail = plan
            .skipped_items()
            .iter()
            .map(|i| {
                format!(
                    "  - {} `{}`: {}",
                    item_kind_str(i.kind),
                    i.name,
                    reason_of(i)
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        return Err(SyncApplyError::StrictRefused {
            count: plan.skipped_count(),
            detail,
        });
    }

    let mut report = SyncApplyReport {
        identity_fresh: plan.identity_fresh,
        strict: plan.strict,
        ..Default::default()
    };

    // Helper: is a piece included (disposition is a real action, not preserve)?
    let piece_plan = |p: Piece| plan.pieces.iter().find(|pp| pp.piece == p);
    let included = |p: Piece| piece_plan(p).map(|pp| pp.included).unwrap_or(false);

    // The site names the apply did NOT carry (skipped-or-dropped) — their `current/`/`alias/`
    // dependants must be excluded from the history/domains stratum carries so a carry never leaves a
    // pointer to a site body that was not written (coherence).
    let uncarried_sites: BTreeSet<String> = plan
        .items
        .iter()
        .filter(|i| {
            i.kind == ItemKind::Site
                && matches!(i.disposition, Disposition::Skip | Disposition::Drop)
        })
        .map(|i| i.name.clone())
        .collect();

    // --- 1) absent destination: create + provision -------------------------------------------
    if plan.dest == DestPrecondition::CreateAndProvision {
        exec.create_and_provision_dest().await?;
        report.dest_created = true;
    }

    // --- 2) data plane: managed-DB contents + blobs (idempotent delta / by-hash) --------------
    if included(Piece::Pg) {
        exec.transfer_pg().await?;
        report.pg_transferred = true;
    }
    if included(Piece::Blobs) {
        exec.transfer_blobs().await?;
        report.blobs_transferred = true;
    }

    // --- 3) managed-database bindings (per-item: carry declared+provisioned, or drop) ---------
    if included(Piece::Databases) {
        for it in plan.items.iter().filter(|i| i.kind == ItemKind::Database) {
            match it.disposition {
                Disposition::Drop => report.dropped.push(format!("db:{}", it.name)),
                Disposition::Skip => report.skipped.push(SkippedItem {
                    kind: ItemKind::Database,
                    name: it.name.clone(),
                    reason: reason_of(it),
                }),
                _ => {
                    exec.carry_database(&it.name).await?;
                    report.databases_carried.push(it.name.clone());
                }
            }
        }
    }

    // --- 4) independent KV strata: settings, graphql -----------------------------------------
    for piece in [Piece::Settings, Piece::Graphql] {
        if included(piece) {
            let strata = piece_plan(piece)
                .map(|pp| pp.kv_strata.clone())
                .unwrap_or_default();
            let n = exec
                .carry_kv_stratum(piece, &strata, &BTreeSet::new())
                .await?;
            report.kv_records += n;
            report.kv_strata_carried.push(piece);
        }
    }

    // --- 5) sites: per-item carry / rewrite / skip / drop (the coherence core) -----------------
    let domains_included = included(Piece::Domains);
    if included(Piece::Sites) {
        for it in plan.items.iter().filter(|i| i.kind == ItemKind::Site) {
            match it.disposition {
                Disposition::Drop => {
                    report.dropped.push(format!("site:{}", it.name));
                    continue;
                }
                Disposition::Skip => {
                    report.skipped.push(SkippedItem {
                        kind: ItemKind::Site,
                        name: it.name.clone(),
                        reason: reason_of(it),
                    });
                    continue;
                }
                _ => {}
            }
            // Read the source body (the item is reported, not written, if the source lacks it).
            let Some(source_cfg) = exec.read_source_site_config(&it.name).await? else {
                report.skipped.push(SkippedItem {
                    kind: ItemKind::Site,
                    name: it.name.clone(),
                    reason: "source has no such site config to carry".into(),
                });
                continue;
            };
            // Carry whole (domains included) vs rewrite the domains field (domains excluded).
            let to_write = if domains_included {
                source_cfg
            } else {
                let dest_domains = exec.read_dest_site_domains(&it.name).await?;
                rewrite_site_config_preserving_dest_domains(&source_cfg, dest_domains.as_ref())
            };
            match exec.write_dest_site_config(&it.name, &to_write).await {
                Ok(changed) => {
                    if !changed {
                        report.unchanged.push(format!("site:{}", it.name));
                    } else if domains_included {
                        report.sites_carried.push(it.name.clone());
                    } else {
                        report.sites_rewritten.push(it.name.clone());
                    }
                }
                Err(SyncApplyError::DomainConflict { site, message }) => {
                    // Exclusive-domain double-claim. Per-item atomic: nothing was written for this
                    // site (the dest's prior state is intact). Default → skip-and-report; strict →
                    // refuse the whole run.
                    if plan.strict {
                        return Err(SyncApplyError::StrictRefused {
                            count: 1,
                            detail: format!("  - site `{site}`: {message}"),
                        });
                    }
                    report.skipped.push(SkippedItem {
                        kind: ItemKind::Site,
                        name: site,
                        reason: format!("exclusive-domain conflict: {message}"),
                    });
                }
                Err(other) => return Err(other),
            }
        }
    }

    // --- 6) site-dependent KV strata: domains (verification/alias), then history (current/) ----
    //     Carried AFTER the sites so a current/alias pointer never precedes its site body. A
    //     skipped/dropped site's dependants are excluded (coherence).
    //
    //     DOMAINS: the hostnames (the `domains` FIELD) ride in the carried `SiteConfig` above, so a
    //     domains-included carry already re-points the dest's routing index via the site write. The
    //     `domainverify/`/`alias/` PROOF records are runtime-EARNED (ACME/DNS control proofs) and
    //     environment-coupled; under `--identity fresh` the target RE-DERIVES them under its own
    //     identity (like routing + TLS), so they are NOT carried. Only an `--identity adopt`
    //     (same-environment recovery) carries the proofs verbatim.
    if domains_included {
        if plan.identity_fresh {
            report.notes.push(
                "domains carried: the hostnames ride in the site config (routing re-indexed on \
                 write); the `domainverify`/`alias` proofs are re-earned under the target's own \
                 identity (--identity fresh), not carried"
                    .into(),
            );
        } else {
            let strata = piece_plan(Piece::Domains)
                .map(|pp| pp.kv_strata.clone())
                .unwrap_or_default();
            let excludes: BTreeSet<String> = uncarried_sites
                .iter()
                .map(|s| crate::deploy::keys::alias_prefix(pr, s))
                .collect();
            let n = exec
                .carry_kv_stratum(Piece::Domains, &strata, &excludes)
                .await?;
            report.kv_records += n;
            report.kv_strata_carried.push(Piece::Domains);
        }
    }
    if included(Piece::History) {
        let strata = piece_plan(Piece::History)
            .map(|pp| pp.kv_strata.clone())
            .unwrap_or_default();
        let mut excludes: BTreeSet<String> = BTreeSet::new();
        for s in &uncarried_sites {
            excludes.insert(format!("project/{target}/current/{s}"));
            excludes.insert(format!("project/{target}/current-principal/{s}"));
        }
        let n = exec
            .carry_kv_stratum(Piece::History, &strata, &excludes)
            .await?;
        report.kv_records += n;
        report.kv_strata_carried.push(Piece::History);
    }

    // --- 7) secrets: sealed under the source KEK — dropped under identity fresh (never carried) --
    if included(Piece::Secrets) && !plan.identity_fresh {
        return Err(SyncApplyError::Unsupported(
            "carrying sealed secrets requires `--identity adopt` (install the source KEK); \
             adopt is not implemented yet — re-run with `--identity fresh` to drop them and let \
             the target re-provision its own"
                .into(),
        ));
    }

    Ok(report)
}

/// The stable token for an [`ItemKind`] in an operator message.
fn item_kind_str(kind: ItemKind) -> &'static str {
    match kind {
        ItemKind::Site => "site",
        ItemKind::Database => "db",
    }
}

/// The reason string of an [`ItemPlan`], defaulting when none was recorded.
fn reason_of(i: &ItemPlan) -> String {
    i.reason.clone().unwrap_or_else(|| "incoherent".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project_export::project_owned_prefixes;

    fn sel(input: SelectionInput) -> Selection {
        input.resolve().expect("selection resolves")
    }

    fn input_include(pieces: &[Piece]) -> SelectionInput {
        SelectionInput {
            include: pieces.iter().copied().collect(),
            identity_fresh: true,
            ..Default::default()
        }
    }

    #[test]
    fn piece_tokens_round_trip_and_all_is_complete() {
        assert_eq!(Piece::ALL.len(), 9);
        for p in Piece::ALL {
            assert_eq!(Piece::parse(p.as_str()), Some(p), "round-trip {p:?}");
        }
        // The `apq` alias maps onto graphql; an unknown token is rejected.
        assert_eq!(Piece::parse("apq"), Some(Piece::Graphql));
        assert_eq!(Piece::parse("nope"), None);
    }

    #[test]
    fn selection_rejects_contradiction_and_empty_and_nothing() {
        // The same piece included AND excluded.
        let contradiction = SelectionInput {
            include: [Piece::Pg].into_iter().collect(),
            exclude: [Piece::Pg].into_iter().collect(),
            ..Default::default()
        };
        assert_eq!(
            contradiction.resolve(),
            Err(SelectionError::Contradiction("pg"))
        );
        // Neither include nor exclude → explicit-selection-required.
        assert_eq!(
            SelectionInput::default().resolve(),
            Err(SelectionError::Empty)
        );
        // Every piece excluded → nothing left.
        let exclude_all = SelectionInput {
            exclude: Piece::ALL.into_iter().collect(),
            ..Default::default()
        };
        assert_eq!(exclude_all.resolve(), Err(SelectionError::Nothing));
    }

    #[test]
    fn selection_include_is_an_allowlist_and_exclude_carves_from_all() {
        // Include allowlist: exactly the named pieces.
        let allow = sel(input_include(&[Piece::Pg, Piece::Blobs]));
        assert_eq!(
            allow.pieces,
            [Piece::Pg, Piece::Blobs].into_iter().collect()
        );
        // Exclude-only: the full set minus the excluded pieces.
        let carved = sel(SelectionInput {
            exclude: [Piece::Domains, Piece::Secrets].into_iter().collect(),
            ..Default::default()
        });
        let mut expected: BTreeSet<Piece> = Piece::ALL.into_iter().collect();
        expected.remove(&Piece::Domains);
        expected.remove(&Piece::Secrets);
        assert_eq!(carved.pieces, expected);
        assert!(!carved.includes(Piece::Domains) && !carved.includes(Piece::Secrets));
    }

    /// The taxonomy is BACKED BY the export allowlist: every non-secret piece's KV strata lie
    /// within [`project_owned_prefixes`] (the C1 boundary), and the secrets piece is exactly
    /// [`sealed_secret_prefixes`] (the `--identity fresh` drop set). This is the mutation that
    /// would let a selection reach outside the project's owned keyspace.
    #[test]
    fn piece_strata_stay_within_the_export_allowlist() {
        let pr = ProjectRef::new("acme");
        let owned = project_owned_prefixes(pr);
        for piece in Piece::ALL {
            let strata = piece_kv_strata(piece, pr);
            if piece == Piece::Secrets {
                assert_eq!(
                    strata,
                    sealed_secret_prefixes(pr),
                    "secrets must equal the sealed drop set"
                );
                continue;
            }
            for prefix in &strata {
                assert!(
                    owned.iter().any(|op| prefix.starts_with(op.as_str())),
                    "piece {piece:?} prefix {prefix:?} is outside project_owned_prefixes"
                );
            }
        }
        // Data-plane pieces govern no KV stratum.
        assert!(piece_kv_strata(Piece::Pg, pr).is_empty());
        assert!(piece_kv_strata(Piece::Blobs, pr).is_empty());
    }

    /// Only non-secret KV-stratum pieces cross the node-side selective-sync endpoint: pg/blobs (no
    /// stratum) and secrets (sealed under the source KEK) are refused; settings/graphql/history
    /// (and sites/domains/databases) are carryable.
    #[test]
    fn kv_stratum_endpoint_carryability_excludes_data_plane_and_secrets() {
        for p in [Piece::Settings, Piece::Graphql, Piece::History] {
            assert!(kv_stratum_is_endpoint_carryable(p), "{p:?} must carry");
        }
        for p in [Piece::Pg, Piece::Blobs, Piece::Secrets] {
            assert!(
                !kv_stratum_is_endpoint_carryable(p),
                "{p:?} must NOT cross the KV endpoint"
            );
        }
    }

    fn kv_entry(key: &str) -> crate::kv::KvDumpEntry {
        crate::kv::KvDumpEntry {
            key: key.to_string(),
            value: b"v".to_vec(),
            version: 1,
        }
    }

    /// The DEST write gate admits ONLY keys under the named piece's own target prefixes, refusing a
    /// sealed-secret key, another tenant's key, a global routing key, and a wrong-piece key — the
    /// structural project+piece scoping, fail-closed with the offending key named.
    #[test]
    fn enforce_stratum_scoped_kv_admits_only_the_target_pieces_prefixes() {
        let target = ProjectRef::new("acme");

        // A legitimate settings slice (project/<p>/config/) passes.
        assert!(
            enforce_stratum_scoped_kv(
                &[kv_entry("project/acme/config/tenancy")],
                Piece::Settings,
                target
            )
            .is_ok()
        );
        // A legitimate graphql slice (graphql/<p>/ + hapq/<p>/) passes.
        assert!(
            enforce_stratum_scoped_kv(
                &[kv_entry("graphql/acme/web"), kv_entry("hapq/acme/abc123")],
                Piece::Graphql,
                target
            )
            .is_ok()
        );

        // A sealed secret smuggled into a settings slice is refused (defence in depth) …
        let sealed = enforce_stratum_scoped_kv(
            &[kv_entry("project/acme/secret/stripe")],
            Piece::Settings,
            target,
        )
        .expect_err("sealed refused");
        assert!(sealed.contains("sealed-secret") && sealed.contains("project/acme/secret/stripe"));

        // … another tenant's key is refused (cross-tenant) …
        let foreign = enforce_stratum_scoped_kv(
            &[kv_entry("project/globex/config/tenancy")],
            Piece::Settings,
            target,
        )
        .expect_err("cross-tenant refused");
        assert!(foreign.contains("globex") && foreign.contains("structural"));

        // … a global routing key is refused …
        assert!(
            enforce_stratum_scoped_kv(&[kv_entry("domain/acme.example")], Piece::Settings, target)
                .is_err()
        );

        // … and a WRONG-piece key (graphql SDL offered under the settings piece) is refused.
        assert!(
            enforce_stratum_scoped_kv(&[kv_entry("graphql/acme/web")], Piece::Settings, target)
                .is_err()
        );

        // pg/blobs/secrets pieces are refused outright (not carryable over this seam).
        for p in [Piece::Pg, Piece::Blobs, Piece::Secrets] {
            assert!(enforce_stratum_scoped_kv(&[], p, target).is_err(), "{p:?}");
        }
    }

    /// The history-dependency site extractor recognises `current/`, `current-principal/` and
    /// `history/` per-site pointers (and only those), returning the `<site>` leaf.
    #[test]
    fn history_key_site_extracts_the_site_for_the_dependency_check() {
        let t = ProjectRef::new("acme");
        assert_eq!(history_key_site("project/acme/current/web", t), Some("web"));
        assert_eq!(
            history_key_site("project/acme/current-principal/web", t),
            Some("web")
        );
        assert_eq!(history_key_site("project/acme/history/web", t), Some("web"));
        // Not a per-site history pointer.
        assert_eq!(history_key_site("project/acme/config/x", t), None);
        assert_eq!(history_key_site("project/acme/site/web", t), None);
        // A foreign project never matches this target's infix.
        assert_eq!(history_key_site("project/globex/current/web", t), None);
    }

    #[test]
    fn piece_dispositions_follow_the_selection() {
        // sites+domains included → carry sites whole; secrets excluded → preserve.
        let s = sel(input_include(&[Piece::Sites, Piece::Domains]));
        let plan = plan_sync(
            &s,
            &SyncInventory::default(),
            &DestState::Absent,
            "src",
            "dst",
        );
        let find = |p: Piece| plan.pieces.iter().find(|x| x.piece == p).unwrap();
        assert_eq!(find(Piece::Sites).disposition, Disposition::Carry);
        assert_eq!(find(Piece::Domains).disposition, Disposition::Carry);
        assert_eq!(find(Piece::Secrets).disposition, Disposition::Preserve);

        // sites WITHOUT domains → rewrite the domains field; secrets INCLUDED + fresh → drop.
        let s2 = sel(input_include(&[Piece::Sites, Piece::Secrets]));
        let plan2 = plan_sync(
            &s2,
            &SyncInventory::default(),
            &DestState::Absent,
            "src",
            "dst",
        );
        let find2 = |p: Piece| plan2.pieces.iter().find(|x| x.piece == p).unwrap();
        assert_eq!(find2(Piece::Sites).disposition, Disposition::Rewrite);
        assert_eq!(find2(Piece::Secrets).disposition, Disposition::Drop);
    }

    /// A seeded multi-site fixture exercises the per-item coherence engine: a plain site carries,
    /// a domain-excluded site rewrites, a site binding a DB the sync does not provide is
    /// SKIPPED-AND-REPORTED (not refuse-all), and an explicit per-item exclude drops.
    fn multi_site_inventory() -> SyncInventory {
        SyncInventory {
            sites: vec![
                SiteItem {
                    name: "web".into(),
                    has_domains: true,
                    db_bindings: vec![],
                },
                SiteItem {
                    name: "app".into(),
                    has_domains: true,
                    db_bindings: vec!["maindb".into()],
                },
                SiteItem {
                    name: "legacy".into(),
                    has_domains: true,
                    db_bindings: vec!["ghostdb".into()],
                },
            ],
            databases: vec![DbItem::managed_pg("maindb")],
        }
    }

    #[test]
    fn preflight_classifies_each_item_carry_rewrite_skip_drop() {
        // Carry data + control plane, drop domains (the A/B pattern), exclude one site.
        let selection = sel(SelectionInput {
            include: [Piece::Sites, Piece::Databases, Piece::Pg, Piece::Blobs]
                .into_iter()
                .collect(),
            exclude_sites: ["web".into()].into_iter().collect(),
            identity_fresh: true,
            ..Default::default()
        });
        let plan = plan_sync(
            &selection,
            &multi_site_inventory(),
            &DestState::Absent,
            "https://prod.example.com/acme",
            "acme-staging",
        );

        let item = |name: &str| plan.items.iter().find(|i| i.name == name).unwrap();
        // `web` was excluded per-item → dropped.
        assert_eq!(item("web").disposition, Disposition::Drop);
        // `app` binds `maindb`, which this sync carries → coherent; domains excluded → rewrite.
        assert_eq!(item("app").disposition, Disposition::Rewrite);
        assert!(item("app").reason.as_deref().unwrap().contains("domains"));
        // `legacy` binds `ghostdb`, absent from the source + dest → SKIP, with a reason naming it.
        let legacy = item("legacy");
        assert_eq!(legacy.disposition, Disposition::Skip);
        assert!(legacy.reason.as_deref().unwrap().contains("ghostdb"));
        // `maindb` carries.
        assert_eq!(item("maindb").disposition, Disposition::Carry);

        // Skip-and-report, NOT refuse-all: the coherent items are still classified, one skip.
        assert_eq!(plan.skipped_count(), 1);
        assert!(!plan.is_refused(), "non-strict reports, never refuses");
        assert_eq!(plan.dest, DestPrecondition::CreateAndProvision);
    }

    #[test]
    fn a_bound_db_already_on_the_destination_makes_the_site_coherent() {
        // Sites + domains included, but NOT databases — yet every bound DB (`maindb`, `ghostdb`)
        // already exists on the destination, so no site is incoherent even though this sync carries
        // no databases. This is the "preserve the dest's own coherent state" path.
        let selection = sel(SelectionInput {
            include: [Piece::Sites, Piece::Domains].into_iter().collect(),
            identity_fresh: true,
            ..Default::default()
        });
        let dest = DestState::Present {
            sites: BTreeSet::new(),
            databases: ["maindb".into(), "ghostdb".into()].into_iter().collect(),
        };
        let plan = plan_sync(&selection, &multi_site_inventory(), &dest, "src", "dst");
        let legacy = plan.items.iter().find(|i| i.name == "legacy").unwrap();
        // Domains included + bound DB present on dest → carry whole, coherent.
        assert_eq!(legacy.disposition, Disposition::Carry);
        assert_eq!(plan.skipped_count(), 0);
        assert_eq!(plan.dest, DestPrecondition::Exists);
    }

    /// FEASIBILITY preflight (fail in the PLAN, in seconds): classify each carried DB by whether a
    /// sync can restore it. A managed pg AND a managed MySQL are feasible for EITHER tenancy
    /// (dedicated → chunked shadow, Shared → the sidecar shadow+swap) → Carry; an EXTERNAL/BYO
    /// binding and an unknown engine are NOT → `Disposition::Skip` with a clear reason (so the
    /// skipped count and `--strict` surface it rather than the node's late apply-time refusal). Pure
    /// `plan_sync` over a seeded fixture — the real CLI inventory only ever carries managed DBs (BYO
    /// is not representable in `list_databases`), but the planner is complete, so the external case
    /// is exercised here from the fixture.
    #[test]
    fn plan_sync_classifies_db_restore_feasibility() {
        let selection = sel(SelectionInput {
            include: [Piece::Databases].into_iter().collect(),
            identity_fresh: true,
            ..Default::default()
        });
        let inventory = SyncInventory {
            sites: vec![],
            databases: vec![
                // Feasible: managed pg dedicated.
                DbItem::managed_pg("pg_dedicated"),
                // Feasible: managed pg Shared (Shared pg restores via the sidecar shadow+swap).
                DbItem {
                    name: "pg_shared".into(),
                    engine: DbEngine::Postgres,
                    managed: true,
                    shared: true,
                },
                // Feasible: managed MySQL dedicated (the chunked shadow arm).
                DbItem {
                    name: "my_dedicated".into(),
                    engine: DbEngine::Mysql,
                    managed: true,
                    shared: false,
                },
                // Feasible: managed MySQL Shared (restores via the sidecar shadow+swap, like pg).
                DbItem {
                    name: "my_shared".into(),
                    engine: DbEngine::Mysql,
                    managed: true,
                    shared: true,
                },
                // Infeasible: external / BYO binding (shadow+swap can't run on the operator's server).
                DbItem {
                    name: "byo".into(),
                    engine: DbEngine::Postgres,
                    managed: false,
                    shared: false,
                },
            ],
        };
        let plan = plan_sync(&selection, &inventory, &DestState::Absent, "src", "dst");
        let disp = |name: &str| plan.items.iter().find(|i| i.name == name).unwrap();
        assert_eq!(disp("pg_dedicated").disposition, Disposition::Carry);
        assert_eq!(disp("pg_shared").disposition, Disposition::Carry);
        assert_eq!(disp("my_dedicated").disposition, Disposition::Carry);
        // Managed Shared MySQL now carries too (the sidecar shadow+swap, like Shared pg).
        assert_eq!(disp("my_shared").disposition, Disposition::Carry);
        // The ONE infeasible DB (external/BYO) is SKIPPED with a reason.
        let byo = disp("byo");
        assert_eq!(byo.disposition, Disposition::Skip);
        assert!(byo.reason.as_deref().unwrap().contains("external"));
        // Exactly the one infeasible DB is skipped; `--strict` would refuse the whole run.
        assert_eq!(plan.skipped_count(), 1);
        assert!(
            sel(SelectionInput {
                include: [Piece::Databases].into_iter().collect(),
                identity_fresh: true,
                strict: true,
                ..Default::default()
            })
            .strict
        );
        let strict_plan = plan_sync(
            &sel(SelectionInput {
                include: [Piece::Databases].into_iter().collect(),
                identity_fresh: true,
                strict: true,
                ..Default::default()
            }),
            &inventory,
            &DestState::Absent,
            "src",
            "dst",
        );
        assert!(strict_plan.is_refused());
    }

    /// A SITE binding an INFEASIBLE database is itself incoherent — the DB won't land, so the site
    /// would serve a dangling binding. The coherence check treats an infeasible (skipped) DB as
    /// NOT-present-after, so the site skips too.
    #[test]
    fn plan_sync_site_binding_an_infeasible_db_skips() {
        let selection = sel(SelectionInput {
            include: [Piece::Sites, Piece::Databases, Piece::Domains]
                .into_iter()
                .collect(),
            identity_fresh: true,
            ..Default::default()
        });
        let inventory = SyncInventory {
            sites: vec![SiteItem {
                name: "web".into(),
                has_domains: false,
                db_bindings: vec!["byo".into()],
            }],
            databases: vec![DbItem {
                name: "byo".into(),
                engine: DbEngine::Postgres,
                managed: false,
                shared: false,
            }],
        };
        let plan = plan_sync(&selection, &inventory, &DestState::Absent, "src", "dst");
        let web = plan
            .items
            .iter()
            .find(|i| i.kind == ItemKind::Site && i.name == "web")
            .unwrap();
        assert_eq!(web.disposition, Disposition::Skip);
        let byo = plan
            .items
            .iter()
            .find(|i| i.kind == ItemKind::Database && i.name == "byo")
            .unwrap();
        assert_eq!(byo.disposition, Disposition::Skip);
    }

    #[test]
    fn strict_turns_a_skip_into_a_refusal() {
        let selection = sel(SelectionInput {
            // Sites + databases: `maindb` carries (so `app` is coherent); only `legacy`'s
            // `ghostdb` is unprovided → the one incoherent skip.
            include: [Piece::Sites, Piece::Databases].into_iter().collect(),
            identity_fresh: true,
            strict: true,
            ..Default::default()
        });
        let plan = plan_sync(
            &selection,
            &multi_site_inventory(),
            &DestState::Absent,
            "src",
            "dst",
        );
        // `legacy` still skips (ghostdb missing); strict makes the whole run a refusal.
        assert!(plan.is_refused());
        let skipped: Vec<&str> = plan
            .skipped_items()
            .iter()
            .map(|i| i.name.as_str())
            .collect();
        assert_eq!(skipped, vec!["legacy"]);
    }

    // ===== Increment 2 — the `--apply` execution engine =====================================

    use crate::config::{DomainConfig, SiteConfig};
    use std::collections::BTreeMap;

    /// A `SiteConfig` with `primary` host `host` and a distinguishing non-domain field
    /// (`security.https_redirect`), so a rewrite that preserves dest domains still visibly carries
    /// the source's NON-domain body.
    fn cfg_with(host: &str, https_redirect: bool) -> SiteConfig {
        let mut c = SiteConfig {
            domains: DomainConfig {
                primary: Some(host.to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        c.security.https_redirect = https_redirect;
        c
    }

    /// An in-memory [`SyncExecutor`] for the apply-engine tests. It records every ACTUAL state
    /// change in `writes` (cleared per apply via [`take_writes`](Self::take_writes)) so idempotency
    /// is a concrete assertion (a second apply produces no writes), models the exclusive-domain
    /// guard (`live_hosts_elsewhere` → [`SyncApplyError::DomainConflict`]), and preserves dest
    /// domains out of `dest_sites`.
    #[derive(Default)]
    struct FakeExecutor {
        dest_exists: bool,
        pg_synced: bool,
        blobs_synced: bool,
        source_sites: BTreeMap<String, SiteConfig>,
        dest_sites: BTreeMap<String, SiteConfig>,
        carried_dbs: Vec<String>,
        carried_strata: Vec<Piece>,
        /// Hosts already LIVE-owned by a DIFFERENT owner — carrying one is an exclusive-domain
        /// conflict (the write-time hijack guard).
        live_hosts_elsewhere: BTreeSet<String>,
        /// Target keyspace the engine asked a stratum carry to write — recorded for the tenancy
        /// assertion (every prefix must be target-owned).
        carried_prefixes: Vec<String>,
        /// Prefixes the engine told a carry to EXCLUDE (coherence — dropped/skipped site dependants).
        excluded_prefixes: Vec<String>,
        /// Actual state changes this apply (idempotency witness).
        writes: Vec<String>,
    }

    impl FakeExecutor {
        fn take_writes(&mut self) -> Vec<String> {
            std::mem::take(&mut self.writes)
        }
    }

    #[async_trait]
    impl SyncExecutor for FakeExecutor {
        async fn create_and_provision_dest(&mut self) -> Result<(), SyncApplyError> {
            if !self.dest_exists {
                self.dest_exists = true;
                self.writes.push("create+provision dest".into());
            }
            Ok(())
        }
        async fn transfer_pg(&mut self) -> Result<(), SyncApplyError> {
            if !self.pg_synced {
                self.pg_synced = true;
                self.writes.push("pg".into());
            }
            Ok(())
        }
        async fn transfer_blobs(&mut self) -> Result<(), SyncApplyError> {
            if !self.blobs_synced {
                self.blobs_synced = true;
                self.writes.push("blobs".into());
            }
            Ok(())
        }
        async fn carry_kv_stratum(
            &mut self,
            piece: Piece,
            target_prefixes: &[String],
            exclude_prefixes: &BTreeSet<String>,
        ) -> Result<usize, SyncApplyError> {
            self.carried_strata.push(piece);
            self.carried_prefixes
                .extend(target_prefixes.iter().cloned());
            self.excluded_prefixes
                .extend(exclude_prefixes.iter().cloned());
            // One synthetic record per target prefix (idempotency is modelled at the data level by
            // the real executor; here a stratum carry is a single logical change the first time).
            self.writes.push(format!("kv:{}", piece.as_str()));
            Ok(target_prefixes.len())
        }
        async fn carry_database(&mut self, name: &str) -> Result<(), SyncApplyError> {
            if !self.carried_dbs.iter().any(|d| d == name) {
                self.carried_dbs.push(name.to_string());
                self.writes.push(format!("db:{name}"));
            }
            Ok(())
        }
        async fn read_source_site_config(
            &mut self,
            site: &str,
        ) -> Result<Option<SiteConfig>, SyncApplyError> {
            Ok(self.source_sites.get(site).cloned())
        }
        async fn read_dest_site_domains(
            &mut self,
            site: &str,
        ) -> Result<Option<DomainConfig>, SyncApplyError> {
            Ok(self.dest_sites.get(site).map(|c| c.domains.clone()))
        }
        async fn write_dest_site_config(
            &mut self,
            site: &str,
            cfg: &SiteConfig,
        ) -> Result<bool, SyncApplyError> {
            // Exclusive-domain hijack guard: refuse a carried host live-owned by another owner.
            for host in cfg.domains.exact_hosts() {
                if self.live_hosts_elsewhere.contains(host) {
                    return Err(SyncApplyError::DomainConflict {
                        site: site.to_string(),
                        message: format!("{host} is already attached to another live project/site"),
                    });
                }
            }
            // Idempotent content-address: an unchanged body is a no-op.
            let new_hash = site_config_hash(cfg)?;
            let old_hash = self
                .dest_sites
                .get(site)
                .map(site_config_hash)
                .transpose()?;
            if old_hash.as_deref() == Some(new_hash.as_str()) {
                return Ok(false);
            }
            self.dest_sites.insert(site.to_string(), cfg.clone());
            self.writes.push(format!("site:{site}"));
            Ok(true)
        }
    }

    /// Build a resolved selection from an include set (identity fresh, non-strict unless set).
    fn selection_apply(
        include: &[Piece],
        exclude_sites: &[&str],
        exclude_dbs: &[&str],
        strict: bool,
    ) -> Selection {
        SelectionInput {
            include: include.iter().copied().collect(),
            exclude_sites: exclude_sites.iter().map(|s| (*s).to_string()).collect(),
            exclude_dbs: exclude_dbs.iter().map(|s| (*s).to_string()).collect(),
            identity_fresh: true,
            strict,
            ..Default::default()
        }
        .resolve()
        .expect("selection resolves")
    }

    /// 1) ABSENT destination → the engine creates + provisions it, then transfers the data plane.
    #[tokio::test]
    async fn apply_creates_and_provisions_an_absent_destination() {
        let selection = selection_apply(&[Piece::Pg, Piece::Blobs], &[], &[], false);
        let plan = plan_sync(
            &selection,
            &SyncInventory::default(),
            &DestState::Absent,
            "src",
            "acme-staging",
        );
        let mut exec = FakeExecutor::default();
        let report = apply_sync(&plan, &mut exec).await.expect("apply ok");
        assert!(report.dest_created, "absent dest is created");
        assert!(report.pg_transferred && report.blobs_transferred);
        assert!(exec.dest_exists);
        // A fresh dest brings its own control plane: no KV strata, no secrets carried.
        assert!(report.kv_strata_carried.is_empty());
        assert!(report.identity_fresh);
    }

    /// 2) A per-piece carry: databases are declared+provisioned per item; a coherent site carries.
    #[tokio::test]
    async fn apply_carries_databases_and_a_coherent_site() {
        let selection = selection_apply(
            &[Piece::Sites, Piece::Databases, Piece::Domains],
            &[],
            &[],
            false,
        );
        let inventory = SyncInventory {
            sites: vec![SiteItem {
                name: "web".into(),
                has_domains: true,
                db_bindings: vec!["maindb".into()],
            }],
            databases: vec![DbItem::managed_pg("maindb")],
        };
        let plan = plan_sync(&selection, &inventory, &DestState::Absent, "src", "dst");
        let mut exec = FakeExecutor {
            source_sites: BTreeMap::from([("web".into(), cfg_with("web.example.com", true))]),
            ..Default::default()
        };
        let report = apply_sync(&plan, &mut exec).await.expect("apply ok");
        assert_eq!(report.databases_carried, vec!["maindb".to_string()]);
        // domains included → the site is carried WHOLE (not rewritten).
        assert_eq!(report.sites_carried, vec!["web".to_string()]);
        assert!(report.sites_rewritten.is_empty());
        assert_eq!(
            exec.dest_sites
                .get("web")
                .unwrap()
                .domains
                .primary
                .as_deref(),
            Some("web.example.com"),
            "domains included ⇒ source domains carried verbatim"
        );
    }

    /// 3) THE COHERENCE CORE: `--include sites --exclude domains` rewrites the body to PRESERVE the
    /// destination's own domains and carries ZERO source domains.
    #[tokio::test]
    async fn apply_rewrites_site_preserving_dest_domains_zero_source_carry() {
        let selection = selection_apply(&[Piece::Sites], &[], &[], false); // domains EXCLUDED
        let inventory = SyncInventory {
            sites: vec![SiteItem {
                name: "web".into(),
                has_domains: true,
                db_bindings: vec![],
            }],
            ..Default::default()
        };
        // Dest EXISTS and already serves its own domain.
        let dest = DestState::Present {
            sites: ["web".into()].into_iter().collect(),
            databases: BTreeSet::new(),
        };
        let plan = plan_sync(&selection, &inventory, &dest, "src", "dst");
        let mut exec = FakeExecutor {
            dest_exists: true,
            // Source serves `source.live.example` and has https_redirect ON (a non-domain field).
            source_sites: BTreeMap::from([("web".into(), cfg_with("source.live.example", true))]),
            // Dest serves its OWN domain, https_redirect OFF.
            dest_sites: BTreeMap::from([("web".into(), cfg_with("dst.own.example", false))]),
            ..Default::default()
        };
        let report = apply_sync(&plan, &mut exec).await.expect("apply ok");
        assert_eq!(report.sites_rewritten, vec!["web".to_string()]);
        let written = exec.dest_sites.get("web").unwrap();
        // Destination's OWN domains preserved…
        assert_eq!(written.domains.primary.as_deref(), Some("dst.own.example"));
        // …the SOURCE's non-domain body carried (https_redirect flipped on)…
        assert!(written.security.https_redirect, "source body carried");
        // …and ZERO source-domain carry (the SAFETY INVARIANT).
        assert!(
            written.domains.primary.as_deref() != Some("source.live.example")
                && !written
                    .domains
                    .aliases
                    .iter()
                    .any(|a| a == "source.live.example")
                && !written
                    .domains
                    .wildcards
                    .iter()
                    .any(|w| w == "source.live.example"),
            "no source domain may appear in the rewritten dest config"
        );
    }

    /// 4) EXCLUDED pieces are PRESERVED verbatim — the engine never carries/touches them.
    #[tokio::test]
    async fn apply_never_touches_excluded_pieces() {
        // Carry ONLY pg; everything else (sites, settings, graphql, history, domains, secrets,
        // databases, blobs) excluded → preserved.
        let selection = selection_apply(&[Piece::Pg], &[], &[], false);
        let plan = plan_sync(
            &selection,
            &SyncInventory::default(),
            &DestState::Present {
                sites: ["keep".into()].into_iter().collect(),
                databases: BTreeSet::new(),
            },
            "src",
            "dst",
        );
        let mut exec = FakeExecutor {
            dest_exists: true,
            dest_sites: BTreeMap::from([("keep".into(), cfg_with("keep.example", false))]),
            ..Default::default()
        };
        let report = apply_sync(&plan, &mut exec).await.expect("apply ok");
        assert!(report.pg_transferred);
        assert!(
            report.kv_strata_carried.is_empty(),
            "no excluded stratum carried"
        );
        assert!(report.sites_carried.is_empty() && report.sites_rewritten.is_empty());
        assert!(exec.carried_dbs.is_empty());
        // The excluded site is untouched (its config object is byte-identical).
        assert_eq!(
            exec.dest_sites
                .get("keep")
                .unwrap()
                .domains
                .primary
                .as_deref(),
            Some("keep.example")
        );
    }

    /// 5) IDEMPOTENT: a second `--apply` of an unchanged source converges to a no-op (no writes).
    #[tokio::test]
    async fn apply_is_idempotent_second_run_is_a_noop() {
        // pg + blobs + sites (domains EXCLUDED → the rewrite path, which is content-idempotent).
        let selection = selection_apply(&[Piece::Pg, Piece::Blobs, Piece::Sites], &[], &[], false);
        let inventory = SyncInventory {
            sites: vec![SiteItem {
                name: "web".into(),
                has_domains: true,
                db_bindings: vec![],
            }],
            ..Default::default()
        };
        let plan = plan_sync(&selection, &inventory, &DestState::Absent, "src", "dst");
        let mut exec = FakeExecutor {
            source_sites: BTreeMap::from([("web".into(), cfg_with("web.example", true))]),
            ..Default::default()
        };
        // First apply mutates.
        let r1 = apply_sync(&plan, &mut exec).await.expect("apply1 ok");
        assert!(r1.dest_created && !r1.sites_rewritten.is_empty());
        let first_writes = exec.take_writes();
        assert!(!first_writes.is_empty(), "first apply writes");

        // The dest now exists; model a resync plan (dest Present) over the SAME, unchanged source.
        let plan2 = plan_sync(
            &selection,
            &inventory,
            &DestState::Present {
                sites: ["web".into()].into_iter().collect(),
                databases: BTreeSet::new(),
            },
            "src",
            "dst",
        );
        let r2 = apply_sync(&plan2, &mut exec).await.expect("apply2 ok");
        let second_writes = exec.take_writes();
        assert!(
            second_writes.is_empty(),
            "second apply must be a no-op, got writes: {second_writes:?}"
        );
        assert!(!r2.dest_created, "dest already exists on resync");
        assert_eq!(r2.unchanged, vec!["site:web".to_string()], "site converged");
    }

    /// 6) PER-ITEM SKIP-AND-REPORT on apply (NOT refuse-all): an incoherent site is skipped while
    /// the coherent items still converge.
    #[tokio::test]
    async fn apply_skips_an_incoherent_item_and_reports_it() {
        let selection = selection_apply(&[Piece::Sites, Piece::Domains], &[], &[], false);
        let inventory = SyncInventory {
            sites: vec![
                SiteItem {
                    name: "ok".into(),
                    has_domains: true,
                    db_bindings: vec![],
                },
                SiteItem {
                    name: "broken".into(),
                    has_domains: true,
                    db_bindings: vec!["ghostdb".into()], // absent from source + dest → incoherent
                },
            ],
            databases: vec![],
        };
        let plan = plan_sync(&selection, &inventory, &DestState::Absent, "src", "dst");
        let mut exec = FakeExecutor {
            source_sites: BTreeMap::from([
                ("ok".into(), cfg_with("ok.example", true)),
                ("broken".into(), cfg_with("broken.example", true)),
            ]),
            ..Default::default()
        };
        let report = apply_sync(&plan, &mut exec)
            .await
            .expect("apply ok (skip, not refuse)");
        assert_eq!(
            report.sites_carried,
            vec!["ok".to_string()],
            "coherent site carried"
        );
        assert_eq!(report.skipped_count(), 1);
        assert_eq!(report.skipped[0].name, "broken");
        assert!(report.skipped[0].reason.contains("ghostdb"));
        // The skipped site was never written (atomic — dest's prior state intact).
        assert!(!exec.dest_sites.contains_key("broken"));
        assert!(report.completed_with_skips());
    }

    /// 7a) EXCLUSIVE DOMAIN: carrying domains that are still live elsewhere is a per-item skip under
    /// the default posture (never a silent second live claimant).
    #[tokio::test]
    async fn apply_skips_an_exclusive_domain_double_claim() {
        let selection = selection_apply(&[Piece::Sites, Piece::Domains], &[], &[], false);
        let inventory = SyncInventory {
            sites: vec![SiteItem {
                name: "web".into(),
                has_domains: true,
                db_bindings: vec![],
            }],
            ..Default::default()
        };
        let plan = plan_sync(&selection, &inventory, &DestState::Absent, "src", "dst");
        let mut exec = FakeExecutor {
            source_sites: BTreeMap::from([("web".into(), cfg_with("live.example.com", true))]),
            // The host is STILL live-owned by the source environment.
            live_hosts_elsewhere: ["live.example.com".into()].into_iter().collect(),
            ..Default::default()
        };
        let report = apply_sync(&plan, &mut exec).await.expect("apply ok (skip)");
        assert!(report.sites_carried.is_empty());
        assert_eq!(report.skipped_count(), 1);
        assert!(report.skipped[0].reason.contains("exclusive-domain"));
        assert!(
            !exec.dest_sites.contains_key("web"),
            "nothing written for the conflicting site"
        );
    }

    /// 7b) `--strict` turns the same exclusive-domain conflict into a whole-run refusal.
    #[tokio::test]
    async fn apply_strict_refuses_an_exclusive_domain_double_claim() {
        let selection = selection_apply(&[Piece::Sites, Piece::Domains], &[], &[], true); // strict
        let inventory = SyncInventory {
            sites: vec![SiteItem {
                name: "web".into(),
                has_domains: true,
                db_bindings: vec![],
            }],
            ..Default::default()
        };
        let plan = plan_sync(&selection, &inventory, &DestState::Absent, "src", "dst");
        let mut exec = FakeExecutor {
            source_sites: BTreeMap::from([("web".into(), cfg_with("live.example.com", true))]),
            live_hosts_elsewhere: ["live.example.com".into()].into_iter().collect(),
            ..Default::default()
        };
        let err = apply_sync(&plan, &mut exec)
            .await
            .expect_err("strict refuses");
        assert!(matches!(err, SyncApplyError::StrictRefused { .. }));
    }

    /// Strict with a pre-known incoherent item refuses UP FRONT, before mutating anything.
    #[tokio::test]
    async fn apply_strict_refuses_a_preknown_incoherent_item_before_mutating() {
        let selection = selection_apply(&[Piece::Sites, Piece::Databases], &[], &[], true);
        let inventory = SyncInventory {
            sites: vec![SiteItem {
                name: "legacy".into(),
                has_domains: true,
                db_bindings: vec!["ghostdb".into()],
            }],
            databases: vec![],
        };
        let plan = plan_sync(&selection, &inventory, &DestState::Absent, "src", "dst");
        let mut exec = FakeExecutor::default();
        let err = apply_sync(&plan, &mut exec)
            .await
            .expect_err("strict refuses up front");
        assert!(matches!(err, SyncApplyError::StrictRefused { .. }));
        assert!(!exec.dest_exists, "nothing provisioned on a strict refusal");
    }

    /// TENANCY: every KV-stratum carry the engine requests is confined to the TARGET's OWN owned
    /// prefixes (reuses the `piece_kv_strata` ⊂ `project_owned_prefixes` invariant).
    #[tokio::test]
    async fn apply_only_carries_target_owned_prefixes() {
        let selection = selection_apply(
            &[Piece::Settings, Piece::Graphql, Piece::History],
            &[],
            &[],
            false,
        );
        let plan = plan_sync(
            &selection,
            &SyncInventory::default(),
            &DestState::Absent,
            "src",
            "acme",
        );
        let mut exec = FakeExecutor::default();
        let _ = apply_sync(&plan, &mut exec).await.expect("apply ok");
        let owned = project_owned_prefixes(ProjectRef::new("acme"));
        for prefix in &exec.carried_prefixes {
            assert!(
                owned.iter().any(|op| prefix.starts_with(op.as_str())),
                "carried prefix {prefix:?} is outside the target's owned keyspace"
            );
        }
        assert!(!exec.carried_prefixes.is_empty(), "strata were carried");
    }

    // ===== Integration: the engine against a REAL DeployStore write seam =====================
    //
    // These wire [`apply_sync`]'s site path to the real [`crate::deploy::DeployStore::set_site_config`]
    // over an in-memory KV + blob store — the ACTUAL content-addressing, pointer re-point, routing
    // index, and host-uniqueness hijack guard — rather than a fake. (pg/blob transport needs a live
    // node and is out of scope here; the config-rewrite coherence core touches only the KV store.)

    use std::sync::Arc;

    /// A no-op blob [`crate::Storage`] — the site-config write path touches only the KV store, so
    /// these never fire.
    struct NullStorage;

    #[async_trait]
    impl crate::Storage for NullStorage {
        async fn get(&self, _: &str) -> Result<crate::GetObject, crate::StorageError> {
            Err(crate::StorageError::NotFound(String::new()))
        }
        async fn get_range(
            &self,
            _: &str,
            _: u64,
            _: Option<u64>,
        ) -> Result<crate::GetObject, crate::StorageError> {
            Err(crate::StorageError::NotFound(String::new()))
        }
        async fn put(
            &self,
            _: &str,
            _: crate::ByteStream,
            _: crate::PutMeta,
        ) -> Result<crate::ObjectMeta, crate::StorageError> {
            Err(crate::StorageError::unsupported("null"))
        }
        async fn head(&self, _: &str) -> Result<crate::ObjectMeta, crate::StorageError> {
            Err(crate::StorageError::NotFound(String::new()))
        }
        async fn delete(&self, _: &str) -> Result<(), crate::StorageError> {
            Ok(())
        }
        async fn list(&self, _: &str) -> Result<Vec<crate::ObjectMeta>, crate::StorageError> {
            Ok(Vec::new())
        }
    }

    /// A [`SyncExecutor`] whose site read/write go through a REAL [`crate::deploy::DeployStore`].
    struct DeployBackedExecutor {
        deploy: crate::deploy::DeployStore,
        project: String,
        source_sites: BTreeMap<String, SiteConfig>,
    }

    #[async_trait]
    impl SyncExecutor for DeployBackedExecutor {
        async fn create_and_provision_dest(&mut self) -> Result<(), SyncApplyError> {
            Ok(())
        }
        async fn transfer_pg(&mut self) -> Result<(), SyncApplyError> {
            Ok(())
        }
        async fn transfer_blobs(&mut self) -> Result<(), SyncApplyError> {
            Ok(())
        }
        async fn carry_kv_stratum(
            &mut self,
            _p: Piece,
            _t: &[String],
            _e: &BTreeSet<String>,
        ) -> Result<usize, SyncApplyError> {
            Ok(0)
        }
        async fn carry_database(&mut self, _n: &str) -> Result<(), SyncApplyError> {
            Ok(())
        }
        async fn read_source_site_config(
            &mut self,
            site: &str,
        ) -> Result<Option<SiteConfig>, SyncApplyError> {
            Ok(self.source_sites.get(site).cloned())
        }
        async fn read_dest_site_domains(
            &mut self,
            site: &str,
        ) -> Result<Option<DomainConfig>, SyncApplyError> {
            let pr = ProjectRef::new(&self.project);
            Ok(self
                .deploy
                .get_site_config(pr, site)
                .await
                .ok()
                .flatten()
                .map(|c| c.domains))
        }
        async fn write_dest_site_config(
            &mut self,
            site: &str,
            cfg: &SiteConfig,
        ) -> Result<bool, SyncApplyError> {
            let pr = ProjectRef::new(&self.project);
            let new_hash = site_config_hash(cfg)?;
            if let Ok(Some(cur)) = self.deploy.get_site_config(pr, site).await
                && site_config_hash(&cur).ok().as_deref() == Some(new_hash.as_str())
            {
                return Ok(false);
            }
            match self.deploy.set_site_config(pr, site, cfg).await {
                Ok(()) => Ok(true),
                // The REAL host-uniqueness hijack guard.
                Err(crate::DeployError::Conflict(m)) => Err(SyncApplyError::DomainConflict {
                    site: site.to_string(),
                    message: m,
                }),
                Err(e) => Err(SyncApplyError::Other(e.to_string())),
            }
        }
    }

    fn deploy_store() -> crate::deploy::DeployStore {
        crate::deploy::DeployStore::new(Arc::new(NullStorage), Arc::new(crate::kv::MemoryKv::new()))
    }

    /// INTEGRATION: `--include sites --exclude domains` against the real `set_site_config` — the dest
    /// keeps serving its OWN domain, the source's non-domain body is carried, the content-addressed
    /// `siteconfig/<hash>` + `site/` pointer are actually written, and ZERO source domains land.
    #[tokio::test]
    async fn integration_rewrite_preserves_dest_domains_via_real_deploy_store() {
        let deploy = deploy_store();
        let pr = ProjectRef::new("dst");
        // Seed the dest's own site serving its own host.
        deploy
            .set_site_config(pr, "web", &cfg_with("dst.own.example", false))
            .await
            .expect("seed dest site");

        let selection = selection_apply(&[Piece::Sites], &[], &[], false); // domains EXCLUDED
        let inventory = SyncInventory {
            sites: vec![SiteItem {
                name: "web".into(),
                has_domains: true,
                db_bindings: vec![],
            }],
            ..Default::default()
        };
        let dest = DestState::Present {
            sites: ["web".into()].into_iter().collect(),
            databases: BTreeSet::new(),
        };
        let plan = plan_sync(&selection, &inventory, &dest, "src", "dst");
        let mut exec = DeployBackedExecutor {
            deploy: deploy.clone(),
            project: "dst".into(),
            // Source serves a DIFFERENT, live host and has https_redirect ON.
            source_sites: BTreeMap::from([("web".into(), cfg_with("source.live.example", true))]),
        };
        let report = apply_sync(&plan, &mut exec).await.expect("apply ok");
        assert_eq!(report.sites_rewritten, vec!["web".to_string()]);

        // Read the config BACK through the real store.
        let got = deploy
            .get_site_config(pr, "web")
            .await
            .expect("read")
            .expect("exists");
        assert_eq!(got.domains.primary.as_deref(), Some("dst.own.example"));
        assert!(got.security.https_redirect, "source body carried");
        assert!(
            !got.domains
                .exact_hosts()
                .any(|h| h == "source.live.example"),
            "no source domain carried"
        );
        // The dest's host routes to the dest; the source host was never claimed.
        assert!(
            deploy
                .resolve_site_by_host("dst.own.example")
                .await
                .expect("resolve")
                .is_some(),
            "dest still serves its own host"
        );
        assert!(
            deploy
                .resolve_site_by_host("source.live.example")
                .await
                .expect("resolve")
                .is_none(),
            "dest never claims the source host"
        );
    }

    /// INTEGRATION: an exclusive-domain double-claim fires the REAL hijack guard
    /// (`DeployError::Conflict`), which the engine maps to a per-item skip (default posture) — the
    /// destination is never made a second live owner of a host another site already holds.
    #[tokio::test]
    async fn integration_exclusive_domain_guard_fires_against_real_store() {
        let deploy = deploy_store();
        let pr = ProjectRef::new("dst");
        // A DIFFERENT dest site already owns the host.
        deploy
            .set_site_config(pr, "incumbent", &cfg_with("shared.example", false))
            .await
            .expect("seed incumbent");

        // Carry a source site that ALSO claims the host (domains INCLUDED).
        let selection = selection_apply(&[Piece::Sites, Piece::Domains], &[], &[], false);
        let inventory = SyncInventory {
            sites: vec![SiteItem {
                name: "web".into(),
                has_domains: true,
                db_bindings: vec![],
            }],
            ..Default::default()
        };
        let dest = DestState::Present {
            sites: ["incumbent".into()].into_iter().collect(),
            databases: BTreeSet::new(),
        };
        let plan = plan_sync(&selection, &inventory, &dest, "src", "dst");
        let mut exec = DeployBackedExecutor {
            deploy: deploy.clone(),
            project: "dst".into(),
            source_sites: BTreeMap::from([("web".into(), cfg_with("shared.example", true))]),
        };
        let report = apply_sync(&plan, &mut exec).await.expect("apply ok (skip)");
        assert_eq!(report.skipped_count(), 1, "the double-claim is skipped");
        assert!(report.skipped[0].reason.contains("exclusive-domain"));
        // The incumbent still owns the host; `web` was NOT written.
        let owner = deploy
            .resolve_site_by_host("shared.example")
            .await
            .expect("resolve")
            .expect("owned");
        assert_eq!(owner.site, "incumbent", "incumbent retains the host");
        assert!(
            deploy
                .get_site_config(pr, "web")
                .await
                .expect("read")
                .is_none(),
            "the conflicting site was never written (atomic — dest prior state intact)"
        );
    }
}
