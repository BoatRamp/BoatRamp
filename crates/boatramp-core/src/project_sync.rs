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
//! **Execution (`--apply`) is increment 2.** Nothing here mutates: the data/KV transfer, the
//! config-body rewrite, and the absent-destination create/provision are deliberately out of scope.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

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

/// The SOURCE project's inventory the preflight classifies. Only the fields a given selection
/// touches need be populated; an empty inventory yields a piece-level plan with no item rows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncInventory {
    /// The source's sites (for the [`Piece::Sites`] per-item classification).
    pub sites: Vec<SiteItem>,
    /// The source's declared managed databases (for [`Piece::Databases`] + the site coherence check).
    pub databases: Vec<String>,
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
    // sync carries it (databases included, the source declares it, and it is not per-item excluded).
    let db_present_after = |name: &str| -> bool {
        if dest_dbs.contains(name) {
            return true;
        }
        databases_included
            && inventory.databases.iter().any(|d| d == name)
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
            if selection.exclude_dbs.contains(db) {
                items.push(ItemPlan {
                    kind: ItemKind::Database,
                    name: db.clone(),
                    disposition: Disposition::Drop,
                    reason: Some("dropped by --exclude-db".into()),
                });
            } else {
                items.push(ItemPlan {
                    kind: ItemKind::Database,
                    name: db.clone(),
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
            databases: vec!["maindb".into()],
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
}
