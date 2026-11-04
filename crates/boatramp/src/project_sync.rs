//! `boatramp project sync` — idempotent, selective, coherence-preserving project replication
//! (increment 1: the **planning / preflight path**).
//!
//! `sync` supersedes the one-shot `import --clone-from` for environment replication
//! (`PLAN-project-sync`): it reconciles a target project toward a source for a SELECTED set of
//! pieces, rewriting site configs so the result is always coherent (never a dangling pointer or a
//! broken serve). This module is the CLI surface: it parses + validates the selection, resolves the
//! source (reusing the cross-node `--clone-from` URL transport model) and the destination
//! (DETECTING an absent destination — planning to create + provision it, never 404-ing), and emits
//! the DRY-RUN PREFLIGHT — the plan that classifies the destination precondition up front and each
//! piece / project-owned item into carry / rewrite / re-derive / drop / preserve / skip, BEFORE a
//! byte moves (construens cap-req #1 "fail fast").
//!
//! The classification engine is the pure [`boatramp_core::project_sync`] planner (unit-tested over
//! seeded fixtures). **Execution (`--apply`) is increment 2** — here it returns a clear
//! not-yet-implemented message; nothing in this increment transfers data/KV, rewrites a config
//! body, or provisions an absent destination.

use std::collections::BTreeSet;
use std::path::PathBuf;

use boatramp_core::project_sync::{
    self, Disposition, ItemKind, Piece, Selection, SelectionInput, SyncApplyError, SyncApplyReport,
    SyncExecutor, SyncInventory, SyncPlan, apply_sync,
};

use crate::client::{self, ControlPlane};
use crate::config::ProjectConfig;

/// A failure in `boatramp project sync` (the planning path).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] client::ClientError),
    /// The `--include-/--exclude-` selection was invalid (contradiction / empty / nothing-left).
    #[error("{0}")]
    Selection(#[from] project_sync::SelectionError),
    /// An identity mode other than `fresh` was requested (adopt is increment 2).
    #[error(
        "--identity {0:?} is not supported yet: only `fresh` is available in this release \
         (adopt / same-environment recovery is increment 2)"
    )]
    IdentityUnsupported(String),
    /// `--apply` was requested without the `-y` confirmation.
    #[error(
        "project sync --apply mutates the destination — pass -y to confirm (re-run WITHOUT --apply \
         to see the dry-run preflight plan first)"
    )]
    ApplyNeedsConfirmation,
    /// The apply execution itself failed (a run-level failure; per-item skips are reported, not errored).
    #[error(transparent)]
    Apply(#[from] SyncApplyError),
    /// A cross-node `--apply` needs the SOURCE node's Project-Admin token.
    #[error(
        "a cross-node `project sync --apply` needs the SOURCE node's Project-Admin token: pass \
         --clone-source-token-file <path> or set BOATRAMP_CLONE_SOURCE_TOKEN"
    )]
    MissingSourceToken,
    /// `--strict` and the preflight found ≥1 incoherent item that would be skipped.
    #[error(
        "strict sync refused: {count} incoherent item(s) would be skipped (--strict is \
         all-or-nothing). Fix the dependency (or drop the item with --exclude-site/--exclude-db) \
         and retry, or drop --strict to converge the coherent items and report the rest:\n{detail}"
    )]
    StrictRefused {
        /// How many items are incoherent.
        count: usize,
        /// Per-item reasons, one per line.
        detail: String,
    },
}

/// `project sync` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp project sync`.
///
/// The per-piece knobs are explicit `--include-<piece>` / `--exclude-<piece>` flags (the PLAN's
/// selectable pieces). An `--include-<piece>` makes the selection an ALLOWLIST of exactly the named
/// pieces; using only `--exclude-<piece>` carves from the full set; naming neither is an error (a
/// sync needs an explicit selection — the conservative default).
#[derive(Debug, clap::Args)]
pub struct SyncArgs {
    /// The SOURCE: a cross-node base URL (reusing the `--clone-from` transport) or a same-node
    /// project name. URL sources route through the clone transport; a bare name is a project on
    /// this control plane.
    #[arg(long, value_name = "URL_OR_PROJECT")]
    from: String,

    /// The source PROJECT when `--from` is a URL (defaults to the target project — the common
    /// same-name cross-environment move).
    #[arg(long, value_name = "PROJECT")]
    from_project: Option<String>,

    /// The TARGET (destination) project. Defaults to the active `--project` (or `default`).
    target: Option<String>,

    // --- per-piece include knobs ---
    /// Include managed-DB contents.
    #[arg(long = "include-pg")]
    include_pg: bool,
    /// Include the content-addressed blob store.
    #[arg(long = "include-blobs")]
    include_blobs: bool,
    /// Include site configs.
    #[arg(long = "include-sites")]
    include_sites: bool,
    /// Include the domain layer (domains field + verification/alias records).
    #[arg(long = "include-domains")]
    include_domains: bool,
    /// Include imperative project settings.
    #[arg(long = "include-settings")]
    include_settings: bool,
    /// Include declarative managed-database bindings.
    #[arg(long = "include-databases")]
    include_databases: bool,
    /// Include the GraphQL registry + APQ safelist.
    #[arg(long = "include-graphql")]
    include_graphql: bool,
    /// Include runtime deploy history/current pointers.
    #[arg(long = "include-history")]
    include_history: bool,
    /// Include KEK-sealed secrets (dropped under `--identity fresh`; the target re-provisions).
    #[arg(long = "include-secrets")]
    include_secrets: bool,

    // --- per-piece exclude knobs ---
    /// Exclude managed-DB contents (preserve the destination's).
    #[arg(long = "exclude-pg")]
    exclude_pg: bool,
    /// Exclude the blob store.
    #[arg(long = "exclude-blobs")]
    exclude_blobs: bool,
    /// Exclude site configs.
    #[arg(long = "exclude-sites")]
    exclude_sites_piece: bool,
    /// Exclude the domain layer — carries ZERO source domains (the A/B-safe exclude).
    #[arg(long = "exclude-domains")]
    exclude_domains: bool,
    /// Exclude imperative project settings.
    #[arg(long = "exclude-settings")]
    exclude_settings: bool,
    /// Exclude declarative managed-database bindings.
    #[arg(long = "exclude-databases")]
    exclude_databases: bool,
    /// Exclude the GraphQL registry + APQ safelist.
    #[arg(long = "exclude-graphql")]
    exclude_graphql: bool,
    /// Exclude runtime deploy history/current pointers.
    #[arg(long = "exclude-history")]
    exclude_history: bool,
    /// Exclude KEK-sealed secrets.
    #[arg(long = "exclude-secrets")]
    exclude_secrets: bool,

    // --- per-item escape hatches ---
    /// Drop a specific site by name rather than carry it (repeatable).
    #[arg(long = "exclude-site", value_name = "NAME")]
    exclude_site: Vec<String>,
    /// Drop a specific managed database by name rather than carry it (repeatable).
    #[arg(long = "exclude-db", value_name = "NAME")]
    exclude_db: Vec<String>,

    /// Identity decision. Only `fresh` is available in this release (the target mints/keeps its own
    /// KEK and source-sealed secrets are dropped); `adopt` is increment 2.
    #[arg(long, default_value = "fresh", value_name = "MODE")]
    identity: String,

    /// All-or-nothing: refuse the whole run if ANY item is incoherent, instead of converging the
    /// coherent items and reporting the skipped ones.
    #[arg(long)]
    strict: bool,

    /// Execute the sync (mutating). The default (no `--apply`) is the dry-run preflight; `--apply`
    /// requires `-y`.
    #[arg(long)]
    apply: bool,

    /// Confirm a mutating `--apply`. Required for `--apply` (there is no interactive prompt).
    #[arg(long, short = 'y')]
    yes: bool,

    /// Path to a file holding the SOURCE node's Project-Admin token — required for a cross-node
    /// (URL `--from`) `--apply` (reads + streams the source). Falls back to
    /// `BOATRAMP_CLONE_SOURCE_TOKEN`. Never passed as a bare CLI argument.
    #[arg(long, value_name = "PATH")]
    clone_source_token_file: Option<PathBuf>,
}

impl SyncArgs {
    /// Fold the flag surface into the raw [`SelectionInput`] (pre-validation).
    fn selection_input(&self) -> SelectionInput {
        let mut include = BTreeSet::new();
        let mut exclude = BTreeSet::new();
        // (include flag, exclude flag, piece) — one row per piece keeps the mapping auditable.
        let rows = [
            (self.include_pg, self.exclude_pg, Piece::Pg),
            (self.include_blobs, self.exclude_blobs, Piece::Blobs),
            (self.include_sites, self.exclude_sites_piece, Piece::Sites),
            (self.include_domains, self.exclude_domains, Piece::Domains),
            (
                self.include_settings,
                self.exclude_settings,
                Piece::Settings,
            ),
            (
                self.include_databases,
                self.exclude_databases,
                Piece::Databases,
            ),
            (self.include_graphql, self.exclude_graphql, Piece::Graphql),
            (self.include_history, self.exclude_history, Piece::History),
            (self.include_secrets, self.exclude_secrets, Piece::Secrets),
        ];
        for (inc, exc, piece) in rows {
            if inc {
                include.insert(piece);
            }
            if exc {
                exclude.insert(piece);
            }
        }
        SelectionInput {
            include,
            exclude,
            exclude_sites: self.exclude_site.iter().cloned().collect(),
            exclude_dbs: self.exclude_db.iter().cloned().collect(),
            identity_fresh: true, // validated to `fresh` in `run`
            strict: self.strict,
        }
    }
}

/// The typed result of `project sync` (increment 1): the dry-run preflight plan plus operator
/// notes. Rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
pub struct SyncReport {
    /// The preflight plan (destination precondition + per-piece + per-item classification).
    pub plan: SyncPlan,
    /// Operator notes (seams not wired on this platform; where item rows come from).
    pub notes: Vec<String>,
    /// The APPLY outcome when `--apply` executed; `None` for a dry-run preflight.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applied: Option<SyncApplyReport>,
}

impl crate::output::Rendered for SyncReport {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        if let Some(a) = &self.applied {
            return render_applied(&self.plan, a, &self.notes, w);
        }
        let p = &self.plan;
        writeln!(w, "sync preflight: `{}` ← `{}`", p.target, p.source)?;
        let dest = match p.dest {
            project_sync::DestPrecondition::CreateAndProvision => {
                "ABSENT — would be created + provisioned (increment 2)"
            }
            project_sync::DestPrecondition::Exists => {
                "exists — excluded pieces are preserved verbatim"
            }
        };
        writeln!(w, "  destination: {dest}")?;
        writeln!(
            w,
            "  identity: {} | strict: {}",
            if p.identity_fresh { "fresh" } else { "adopt" },
            if p.strict { "on" } else { "off" },
        )?;

        writeln!(w, "pieces:")?;
        for pp in &p.pieces {
            writeln!(
                w,
                "  [{:<9}] {:<10} {}",
                pp.disposition.as_str(),
                pp.piece.as_str(),
                pp.note,
            )?;
        }
        // Routing + TLS are never carried — re-issued under the target's own identity.
        writeln!(
            w,
            "  [{:<9}] {:<10} global routing + TLS (domain/wildcard/cert) re-issued under the \
             target's own identity",
            Disposition::ReDerive.as_str(),
            "routing/tls",
        )?;

        writeln!(w, "items:")?;
        if p.items.is_empty() {
            writeln!(w, "  (none enumerated — see notes)")?;
        } else {
            for it in &p.items {
                let kind = match it.kind {
                    ItemKind::Site => "site",
                    ItemKind::Database => "db",
                };
                match &it.reason {
                    Some(r) => writeln!(
                        w,
                        "  {:<4} {:<16} [{:<8}] {}",
                        kind,
                        it.name,
                        it.disposition.as_str(),
                        r
                    )?,
                    None => writeln!(
                        w,
                        "  {:<4} {:<16} [{}]",
                        kind,
                        it.name,
                        it.disposition.as_str()
                    )?,
                }
            }
        }

        let skipped = p.skipped_count();
        if skipped > 0 {
            writeln!(
                w,
                "{skipped} item(s) are INCOHERENT and would be SKIPPED (reported, not applied); \
                 fix the dependency and resync, or pass --strict to refuse the whole run"
            )?;
        }
        for note in &self.notes {
            writeln!(w, "note: {note}")?;
        }
        writeln!(
            w,
            "(dry-run preflight — nothing moved; re-run with `--apply -y` to execute this plan)"
        )
    }
}

/// Render the APPLY outcome (what actually moved + what was skipped).
fn render_applied(
    plan: &SyncPlan,
    a: &SyncApplyReport,
    notes: &[String],
    w: &mut dyn std::io::Write,
) -> std::io::Result<()> {
    writeln!(w, "sync applied: `{}` ← `{}`", plan.target, plan.source)?;
    if a.dest_created {
        writeln!(w, "  destination: CREATED + provisioned (was absent)")?;
    }
    if a.pg_transferred {
        writeln!(w, "  pg: managed-DB contents transferred (delta)")?;
    }
    if a.blobs_transferred {
        writeln!(
            w,
            "  blobs: content-addressed store transferred (integrity/delta)"
        )?;
    }
    if !a.databases_carried.is_empty() {
        writeln!(w, "  databases carried: {}", a.databases_carried.join(", "))?;
    }
    if !a.kv_strata_carried.is_empty() {
        let strata: Vec<&str> = a.kv_strata_carried.iter().map(|p| p.as_str()).collect();
        writeln!(
            w,
            "  kv strata carried: {} ({} records)",
            strata.join(", "),
            a.kv_records
        )?;
    }
    if !a.sites_carried.is_empty() {
        writeln!(w, "  sites carried (whole): {}", a.sites_carried.join(", "))?;
    }
    if !a.sites_rewritten.is_empty() {
        writeln!(
            w,
            "  sites rewritten (domains preserved): {}",
            a.sites_rewritten.join(", ")
        )?;
    }
    if !a.unchanged.is_empty() {
        writeln!(
            w,
            "  unchanged (already converged): {}",
            a.unchanged.join(", ")
        )?;
    }
    if !a.dropped.is_empty() {
        writeln!(w, "  dropped (per-item exclude): {}", a.dropped.join(", "))?;
    }
    if a.completed_with_skips() {
        writeln!(
            w,
            "{} item(s) SKIPPED (incoherent / exclusive-domain):",
            a.skipped_count()
        )?;
        for s in &a.skipped {
            let kind = match s.kind {
                ItemKind::Site => "site",
                ItemKind::Database => "db",
            };
            writeln!(w, "  {kind} {}: {}", s.name, s.reason)?;
        }
    }
    for note in a.notes.iter().chain(notes.iter()) {
        writeln!(w, "note: {note}")?;
    }
    if a.is_noop() {
        writeln!(
            w,
            "(converged — this apply changed nothing at the destination)"
        )?;
    } else if a.completed_with_skips() {
        writeln!(
            w,
            "(applied WITH {} skipped — fix the dependency and resync, or --strict to refuse)",
            a.skipped_count()
        )?;
    } else {
        writeln!(w, "(applied)")?;
    }
    Ok(())
}

/// Entry point for `boatramp project sync` — the dry-run preflight (default) or the mutating
/// `--apply` execution.
pub async fn run(args: SyncArgs, config: &ProjectConfig, server: String) -> Result<SyncReport> {
    // 1) Validate + resolve the selection FIRST (cheap, no I/O) — a contradictory/empty selection
    //    is reported before any network round-trip.
    if args.identity != "fresh" {
        return Err(Error::IdentityUnsupported(args.identity.clone()));
    }
    let selection: Selection = args.selection_input().resolve()?;

    // 2) `--apply` must be explicitly confirmed with `-y` (there is no interactive prompt).
    if args.apply && !args.yes {
        return Err(Error::ApplyNeedsConfirmation);
    }

    // 3) Resolve the target + source labels.
    let target = args
        .target
        .clone()
        .unwrap_or_else(|| client::resolve_project(config));
    let source_is_url = args.from.starts_with("http://") || args.from.starts_with("https://");
    let source_project = args.from_project.clone().unwrap_or_else(|| target.clone());
    let source_label = if source_is_url {
        format!("{} (project `{source_project}`)", args.from)
    } else {
        args.from.clone()
    };

    let mut notes: Vec<String> = Vec::new();

    // 4) Resolve the SOURCE token (cross-node reads + the data stream need the source node's
    //    Project-Admin bearer; same-node reuses the operator's own dest token).
    let dest_token = client::token(config);
    let source_token: Option<Vec<u8>> = if source_is_url {
        resolve_source_token(args.clone_source_token_file.as_deref())
    } else {
        dest_token.as_deref().map(|t| t.as_bytes().to_vec())
    };

    // 5) Build the dest + source control-plane clients. The source client is built ONLY when we
    //    can actually read it (same-node always; cross-node only with a source token).
    let dest_cp = ControlPlane::new(
        server.clone(),
        client::http_client(dest_token.as_deref()),
        target.clone(),
    );
    let source_cp: Option<ControlPlane> = if source_is_url {
        source_token.as_ref().map(|tok| {
            let tok_str = String::from_utf8_lossy(tok).into_owned();
            ControlPlane::new(
                args.from.clone(),
                client::http_client(Some(tok_str.as_str())),
                source_project.clone(),
            )
        })
    } else {
        Some(ControlPlane::new(
            server.clone(),
            client::http_client(dest_token.as_deref()),
            source_project.clone(),
        ))
    };

    // 6) Destination precondition — DETECT an absent destination (plan to create + provision;
    //    never 404). `list_projects` avoids the 404-vs-error ambiguity of a direct GET.
    let projects = dest_cp.list_projects().await?;
    let dest_present = projects
        .iter()
        .any(|p| p.get("name").and_then(|v| v.as_str()) == Some(target.as_str()));

    let dest = if dest_present {
        let databases: BTreeSet<String> = dest_cp
            .list_databases()
            .await?
            .into_iter()
            .map(|d| d.name)
            .collect();
        // Enumerate the dest's own sites so an EXCLUDED piece's "preserve" and the coherence check
        // reflect the real destination.
        let sites: BTreeSet<String> = dest_cp
            .list_sites()
            .await
            .unwrap_or_default()
            .into_iter()
            .collect();
        project_sync::DestState::Present { sites, databases }
    } else {
        notes.push(format!(
            "destination project `{target}` does not exist — sync will create + provision it; on \
             a fresh destination there is nothing to preserve"
        ));
        project_sync::DestState::Absent
    };

    // 7) Source inventory. Enumerate the source's declared databases and sites (with each site's
    //    domain presence) for the per-item classification. Cross-node without a source token can't
    //    be read, so the inventory is piece-level only there.
    let mut inventory = SyncInventory::default();
    let mut source_dbs: Vec<boatramp_core::compute::ApplyDatabase> = Vec::new();
    if let Some(scp) = &source_cp {
        source_dbs = scp.list_databases().await?;
        inventory.databases = source_dbs.iter().map(|d| d.name.clone()).collect();
        // Sites: enumerate + read each config for the domain-presence flag. `db_bindings` are left
        // empty (there is no cheap managed-DB-binding extraction from a SiteConfig today) — the
        // set_site_config write still fail-closes on a genuinely incoherent binding at apply time.
        match scp.list_sites().await {
            Ok(sites) => {
                for name in sites {
                    let has_domains = scp
                        .fetch_site_config(&name)
                        .await
                        .map(|c| {
                            c.domains.primary.is_some()
                                || !c.domains.aliases.is_empty()
                                || !c.domains.wildcards.is_empty()
                        })
                        .unwrap_or(false);
                    inventory.sites.push(project_sync::SiteItem {
                        name,
                        has_domains,
                        db_bindings: Vec::new(),
                    });
                }
            }
            Err(e) => notes.push(format!("could not enumerate source sites: {e}")),
        }
        notes.push(
            "per-site managed-DB binding extraction is best-effort (bindings not enumerated); an \
             incoherent binding still fails closed at the site write"
                .to_string(),
        );
    } else {
        notes.push(format!(
            "source `{}` is cross-node and no source token was provided — its items are not \
             enumerated for this dry-run; pass --clone-source-token-file to read it",
            args.from
        ));
    }

    // 8) Build the preflight plan via the pure core planner.
    let plan = project_sync::plan_sync(&selection, &inventory, &dest, &source_label, &target);

    // 9) `--strict`: a pre-known incoherent item refuses the whole run BEFORE anything mutates.
    if plan.is_refused() {
        let detail = plan
            .skipped_items()
            .iter()
            .map(|i| {
                format!(
                    "  - {} `{}`: {}",
                    match i.kind {
                        ItemKind::Site => "site",
                        ItemKind::Database => "db",
                    },
                    i.name,
                    i.reason.as_deref().unwrap_or("incoherent"),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        return Err(Error::StrictRefused {
            count: plan.skipped_count(),
            detail,
        });
    }

    // 10) Dry-run → return the preflight. `--apply` → execute the plan via the CLI executor.
    if !args.apply {
        return Ok(SyncReport {
            plan,
            notes,
            applied: None,
        });
    }

    // Cross-node apply requires a source token (to read + stream the source).
    let Some(source_cp) = source_cp else {
        return Err(Error::MissingSourceToken);
    };
    let source_token = source_token.ok_or(Error::MissingSourceToken)?;

    let mut exec = CliSyncExecutor {
        dest_cp,
        source_cp,
        target: target.clone(),
        source_url: if source_is_url {
            args.from.clone()
        } else {
            server.clone()
        },
        source_project,
        source_token,
        source_dbs,
        pg_included: selection.includes(Piece::Pg),
        blobs_included: selection.includes(Piece::Blobs),
        data_transferred: false,
    };
    let applied = apply_sync(&plan, &mut exec).await?;
    Ok(SyncReport {
        plan,
        notes,
        applied: Some(applied),
    })
}

/// Resolve the SOURCE node's Project-Admin token for a cross-node sync: the
/// `--clone-source-token-file` contents, else `BOATRAMP_CLONE_SOURCE_TOKEN`. Never a bare CLI arg
/// (a token on argv leaks into the process table). `None` when neither is set.
fn resolve_source_token(file: Option<&std::path::Path>) -> Option<Vec<u8>> {
    if let Some(p) = file
        && let Ok(s) = std::fs::read_to_string(p)
    {
        let tok = s.trim_end_matches(['\n', '\r']).as_bytes().to_vec();
        if !tok.is_empty() {
            return Some(tok);
        }
    }
    std::env::var("BOATRAMP_CLONE_SOURCE_TOKEN")
        .ok()
        .filter(|v| !v.is_empty())
        .map(String::into_bytes)
}

/// The CLI binding of [`SyncExecutor`] to the real control-plane + the clone/import transport. It
/// REUSES — never rebuilds — the transport: the data plane rides the `clone --from` (data-only)
/// path, managed-DB bindings ride `declare_database` (declare + provision), and site configs ride
/// `fetch_site_config`/`put_site_config` (the latter is the node's `set_site_config`, with the
/// host-uniqueness hijack guard that surfaces an exclusive-domain double-claim as a `409`).
///
/// GAP (surfaced honestly, not silently): a SELECTIVE control-plane KV-stratum carry (settings /
/// graphql / history, and `domainverify` proofs under `--identity adopt`) has NO over-the-wire seam
/// today — there is no per-key admin KV API, and the whole-slice clone is not piece-selective. Those
/// strata return [`SyncApplyError::Unsupported`]; the pure engine supports them (unit-tested) and a
/// node-side selective-sync endpoint is the follow-up.
struct CliSyncExecutor {
    dest_cp: ControlPlane,
    source_cp: ControlPlane,
    target: String,
    source_url: String,
    source_project: String,
    source_token: Vec<u8>,
    source_dbs: Vec<boatramp_core::compute::ApplyDatabase>,
    pg_included: bool,
    blobs_included: bool,
    data_transferred: bool,
}

impl CliSyncExecutor {
    /// Drive the data plane (managed-DB contents + blobs) through ONE data-only clone. The transport
    /// carries pg AND blobs together, so a pg-only / blobs-only selection is refused (it would carry
    /// the excluded half) rather than silently violating the exclude.
    async fn transfer_data(&mut self) -> std::result::Result<(), SyncApplyError> {
        if self.data_transferred {
            return Ok(());
        }
        if self.pg_included != self.blobs_included {
            return Err(SyncApplyError::Unsupported(
                "the data-only clone transport carries managed-DB contents and blobs TOGETHER; a \
                 pg-only or blobs-only sync would carry the excluded half — include or exclude \
                 BOTH `pg` and `blobs`"
                    .into(),
            ));
        }
        self.dest_cp
            .project_clone_from(
                &self.target,
                &self.source_url,
                Some(&self.source_project),
                &self.source_token,
                true,  // apply
                false, // verify
                true,  // overwrite — sync's data plane is source-authoritative (mirror)
                false, // force (data-only carries no control-plane KV)
                true,  // data_only
                client::MismatchFlags::default(),
            )
            .await
            .map_err(|e| SyncApplyError::Transfer {
                piece: "data",
                message: e.to_string(),
            })?;
        self.data_transferred = true;
        Ok(())
    }
}

#[async_trait::async_trait]
impl SyncExecutor for CliSyncExecutor {
    async fn create_and_provision_dest(&mut self) -> std::result::Result<(), SyncApplyError> {
        // The project ENTITY record is NOT created by the clone/import (it lives outside the
        // project-owned export scope), so create it first, then provision the managed DB(s) the
        // source declares — the clone's pg restore needs a provisioned target DB.
        let body = serde_json::json!({ "name": self.target });
        self.dest_cp.create_project(&body).await.map_err(|e| {
            SyncApplyError::Provision(format!("create project `{}`: {e}", self.target))
        })?;
        for db in &self.source_dbs {
            self.dest_cp
                .declare_database(&db.name, db)
                .await
                .map_err(|e| {
                    SyncApplyError::Provision(format!("declare + provision DB `{}`: {e}", db.name))
                })?;
        }
        Ok(())
    }

    async fn transfer_pg(&mut self) -> std::result::Result<(), SyncApplyError> {
        self.transfer_data().await
    }

    async fn transfer_blobs(&mut self) -> std::result::Result<(), SyncApplyError> {
        self.transfer_data().await
    }

    async fn carry_kv_stratum(
        &mut self,
        piece: Piece,
        _target_prefixes: &[String],
        _exclude_prefixes: &BTreeSet<String>,
    ) -> std::result::Result<usize, SyncApplyError> {
        Err(SyncApplyError::Unsupported(format!(
            "carrying the `{p}` control-plane KV stratum needs a node-side selective-sync endpoint \
             (there is no per-key admin KV API, and the whole-slice clone is not piece-selective). \
             For now carry it with a full `project import --clone-from`, or exclude `{p}` and let \
             the destination's own `apply` bring it.",
            p = piece.as_str()
        )))
    }

    async fn carry_database(&mut self, name: &str) -> std::result::Result<(), SyncApplyError> {
        let spec = self
            .source_cp
            .get_database(name)
            .await
            .map_err(|e| SyncApplyError::Other(format!("read source DB `{name}`: {e}")))?;
        self.dest_cp
            .declare_database(name, &spec)
            .await
            .map_err(|e| SyncApplyError::Other(format!("declare DB `{name}` on dest: {e}")))?;
        Ok(())
    }

    async fn read_source_site_config(
        &mut self,
        site: &str,
    ) -> std::result::Result<Option<boatramp_core::config::SiteConfig>, SyncApplyError> {
        self.source_cp
            .fetch_site_config(site)
            .await
            .map(Some)
            .map_err(|e| SyncApplyError::Other(format!("read source site `{site}`: {e}")))
    }

    async fn read_dest_site_domains(
        &mut self,
        site: &str,
    ) -> std::result::Result<Option<boatramp_core::config::DomainConfig>, SyncApplyError> {
        // `fetch_site_config` returns defaults for an unset site, so a fresh dest yields empty
        // domains (nothing to preserve).
        match self.dest_cp.fetch_site_config(site).await {
            Ok(cfg) => Ok(Some(cfg.domains)),
            Err(e) => Err(SyncApplyError::Other(format!(
                "read dest domains for site `{site}`: {e}"
            ))),
        }
    }

    async fn write_dest_site_config(
        &mut self,
        site: &str,
        cfg: &boatramp_core::config::SiteConfig,
    ) -> std::result::Result<bool, SyncApplyError> {
        // Idempotency (best-effort detection; the node's set_site_config is itself idempotent):
        // skip the PUT when the dest already serves a byte-identical body.
        let new_hash = project_sync::site_config_hash(cfg)?;
        if let Ok(current) = self.dest_cp.fetch_site_config(site).await
            && project_sync::site_config_hash(&current).ok().as_deref() == Some(new_hash.as_str())
        {
            return Ok(false);
        }
        match self.dest_cp.put_site_config(site, cfg).await {
            Ok(()) => Ok(true),
            // The node's host-uniqueness hijack guard refuses a double-claim with `409 Conflict`.
            Err(client::ClientError::Http(e))
                if e.status() == Some(reqwest::StatusCode::CONFLICT) =>
            {
                Err(SyncApplyError::DomainConflict {
                    site: site.to_string(),
                    message: "a carried host is already attached to another live project/site \
                              (exclusive domain ownership)"
                        .to_string(),
                })
            }
            Err(e) => Err(SyncApplyError::Other(format!("write site `{site}`: {e}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    /// A minimal parser so the `project sync …` flag surface can be arg-parsed in isolation.
    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        cmd: Cmd,
    }
    #[derive(clap::Subcommand)]
    enum Cmd {
        Sync(SyncArgs),
    }

    fn parse(argv: &[&str]) -> std::result::Result<SyncArgs, clap::Error> {
        let cli = Cli::try_parse_from(std::iter::once("boatramp").chain(argv.iter().copied()))?;
        let Cmd::Sync(args) = cli.cmd;
        Ok(args)
    }

    #[test]
    fn selection_knobs_parse_into_an_allowlist() {
        let args = parse(&[
            "sync",
            "--from",
            "https://prod.example.com",
            "--include-pg",
            "--include-blobs",
            "--exclude-site",
            "web",
            "--exclude-db",
            "scratch",
            "acme-staging",
        ])
        .expect("parses");
        assert_eq!(args.from, "https://prod.example.com");
        assert_eq!(args.target.as_deref(), Some("acme-staging"));
        assert_eq!(args.exclude_site, vec!["web"]);
        assert_eq!(args.exclude_db, vec!["scratch"]);
        // The allowlist is exactly {pg, blobs}.
        let selection = args.selection_input().resolve().expect("resolves");
        let expected: BTreeSet<Piece> = [Piece::Pg, Piece::Blobs].into_iter().collect();
        assert_eq!(selection.pieces, expected);
        assert!(selection.exclude_sites.contains("web"));
        assert!(selection.exclude_dbs.contains("scratch"));
    }

    #[test]
    fn contradictory_include_and_exclude_is_rejected() {
        let args = parse(&[
            "sync",
            "--from",
            "prod",
            "--include-domains",
            "--exclude-domains",
        ])
        .expect("parses (clap allows both; resolution rejects)");
        assert!(matches!(
            args.selection_input().resolve(),
            Err(project_sync::SelectionError::Contradiction("domains"))
        ));
    }

    #[test]
    fn no_selection_is_rejected_as_explicit_selection_required() {
        let args = parse(&["sync", "--from", "prod"]).expect("parses");
        assert!(matches!(
            args.selection_input().resolve(),
            Err(project_sync::SelectionError::Empty)
        ));
    }

    #[test]
    fn exclude_only_carves_from_the_full_set() {
        let args = parse(&[
            "sync",
            "--from",
            "prod",
            "--exclude-domains",
            "--exclude-secrets",
        ])
        .expect("parses");
        let selection = args.selection_input().resolve().expect("resolves");
        assert!(!selection.includes(Piece::Domains));
        assert!(!selection.includes(Piece::Secrets));
        assert!(selection.includes(Piece::Pg) && selection.includes(Piece::Sites));
    }

    #[test]
    fn from_is_required() {
        assert!(parse(&["sync", "acme"]).is_err(), "--from is required");
    }

    #[test]
    fn apply_parses_yes_and_token_file_flags() {
        let args = parse(&[
            "sync",
            "--from",
            "https://prod.example.com",
            "--include-pg",
            "--include-blobs",
            "--apply",
            "-y",
            "--clone-source-token-file",
            "/tmp/tok",
            "acme-staging",
        ])
        .expect("parses");
        assert!(args.apply && args.yes);
        assert_eq!(
            args.clone_source_token_file.as_deref(),
            Some(std::path::Path::new("/tmp/tok"))
        );
    }

    /// Build a `CliSyncExecutor` with offline dummy control-planes (no server contacted) to exercise
    /// the executor's node-free GUARDS.
    fn dummy_exec(pg: bool, blobs: bool) -> CliSyncExecutor {
        CliSyncExecutor {
            dest_cp: ControlPlane::new(
                "http://127.0.0.1:0".into(),
                client::http_client(None),
                "dst".into(),
            ),
            source_cp: ControlPlane::new(
                "http://127.0.0.1:0".into(),
                client::http_client(None),
                "src".into(),
            ),
            target: "dst".into(),
            source_url: "http://127.0.0.1:0".into(),
            source_project: "src".into(),
            source_token: Vec::new(),
            source_dbs: Vec::new(),
            pg_included: pg,
            blobs_included: blobs,
            data_transferred: false,
        }
    }

    /// The data-only clone transport carries pg AND blobs together, so a pg-only (or blobs-only)
    /// selection is REFUSED before any network I/O rather than silently carrying the excluded half.
    #[tokio::test]
    async fn data_transport_refuses_pg_without_blobs() {
        let mut exec = dummy_exec(true, false);
        let err = exec
            .transfer_pg()
            .await
            .expect_err("pg-without-blobs refused");
        assert!(matches!(err, SyncApplyError::Unsupported(_)));
        // Both included → the guard passes (the network call is what would then run).
        assert!(dummy_exec(true, true).pg_included && dummy_exec(true, true).blobs_included);
    }

    /// A selective control-plane KV-stratum carry has no over-the-wire seam today; the CLI reports
    /// it honestly as unsupported (the pure engine supports it — this is the wiring gap).
    #[tokio::test]
    async fn kv_stratum_carry_is_honestly_unsupported_over_cli() {
        let mut exec = dummy_exec(false, false);
        let err = exec
            .carry_kv_stratum(Piece::Settings, &[], &BTreeSet::new())
            .await
            .expect_err("no selective KV seam");
        match err {
            SyncApplyError::Unsupported(m) => {
                assert!(m.contains("settings") && m.contains("selective-sync"))
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
