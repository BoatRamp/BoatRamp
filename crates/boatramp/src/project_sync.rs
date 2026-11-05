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
    /// A cross-node `--include-domains` carry without the explicit cutover intent (LOW-5).
    #[error(
        "refusing a cross-node `--include-domains` carry: the destination's host-uniqueness guard \
         is same-node only and cannot see whether the remote source `{source_label}` still \
         LIVE-owns the host(s), so this could create a SECOND simultaneously-live owner \
         (double-live-ownership). Re-run with --allow-domain-cutover only after the source has \
         yielded the host (DR / blue-green cutover), or drop --include-domains (the dest keeps its \
         own domains)."
    )]
    DomainCutoverUnconfirmed {
        /// The cross-node source label.
        source_label: String,
    },
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

    /// Intend a cross-node DOMAIN CUTOVER. Carrying `--include-domains` from a URL (cross-node)
    /// source is refused without this flag: the dest node's host-uniqueness guard is same-node only
    /// and cannot see whether the remote source still LIVE-owns the host, so a carry could create a
    /// second simultaneously-live owner. Pass this only when the operator has taken the source down
    /// (DR) or is deliberately yielding the host (blue-green cutover).
    #[arg(long)]
    allow_domain_cutover: bool,
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

/// The typed result of `project sync`: the preflight plan + operator notes, and (on `--apply`) the
/// apply outcome. Rendered by [`crate::output`].
#[derive(Debug, serde::Serialize)]
pub struct SyncReport {
    /// The preflight plan (destination precondition + per-piece + per-item classification).
    pub plan: SyncPlan,
    /// Operator notes (seams not wired on this platform; where item rows come from; any KV-stratum
    /// records the dest skipped-and-reported).
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
                "ABSENT — would be created + provisioned"
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

    // 3a) LOW-5: a cross-node `--include-domains` carry can create a second live owner of a host the
    //     remote source still serves (the dest's hijack guard is same-node only). Refuse an apply
    //     without the explicit cutover intent, and always note the hazard loudly.
    let cross_node_domains = source_is_url && selection.includes(Piece::Domains);
    if cross_node_domains {
        if args.apply && !args.allow_domain_cutover {
            return Err(Error::DomainCutoverUnconfirmed {
                source_label: args.from.clone(),
            });
        }
        notes.push(format!(
            "DANGER: carrying domains from the cross-node source `{}` — the destination's \
             host-uniqueness guard is same-node only and cannot see whether the source still \
             LIVE-owns the host(s); a carry risks a SECOND simultaneously-live owner. Ensure the \
             source has yielded the host (DR / blue-green) before applying.",
            args.from
        ));
    }

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

    // 6a) LOW-4: an EXISTING dest + an included data plane means `--apply` OVERWRITES the dest's
    //     own pg/blobs (sync is a source-authoritative mirror). Warn loudly in the preflight.
    if dest_present && (selection.includes(Piece::Pg) || selection.includes(Piece::Blobs)) {
        notes.push(format!(
            "WARNING: destination `{target}` already holds data — `--apply` OVERWRITES its \
             managed-DB contents / blobs with the source's (source-authoritative mirror). Its \
             EXCLUDED pieces are preserved, but the carried data plane is replaced."
        ));
    }

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
        strict: selection.strict,
        data_transferred: false,
        kv_skip_notes: Vec::new(),
    };
    let applied = apply_sync(&plan, &mut exec).await?;
    // Surface any KV-stratum records the dest skipped-and-reported (PLAN rule 3) in the operator
    // notes (under `--strict` a skip already aborted the run inside `carry_kv_stratum`).
    notes.append(&mut exec.kv_skip_notes);
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
/// path, managed-DB bindings ride `declare_database` (declare + provision), site configs ride
/// `fetch_site_config`/`put_site_config` (the latter is the node's `set_site_config`, with the
/// host-uniqueness hijack guard that surfaces an exclusive-domain double-claim as a `409`), and the
/// NON-SECRET control-plane KV strata (settings / graphql / history) ride the node-side
/// selective-sync KV endpoint ([`ControlPlane::get_kv_stratum`] on the source /
/// [`ControlPlane::put_kv_stratum`] on the dest) — the gap this closes.
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
    /// `--strict`: a KV-stratum record the dest skips-and-reports aborts the whole run (PLAN rule 3).
    strict: bool,
    data_transferred: bool,
    /// KV-stratum records the dest skipped-and-reported under the default (non-strict) posture,
    /// drained into the operator report by `run()`.
    kv_skip_notes: Vec<String>,
}

/// MEDIUM-2 (cross-tenant path-traversal guard): validate a SOURCE-derived resource `name` BEFORE
/// it is interpolated into a destination URL. The source is a trust boundary — a crafted site/db
/// name like `../../victim/sites/web` would, via rust-url dot-segment resolution, reshape the
/// request path to ANOTHER tenant's route (dangerous with a broad org/system dest token). A non-slug
/// name is refused fail-closed, so only canonical `[a-z0-9-]`-style names ever reach the wire.
fn validate_source_name(kind: &'static str, name: &str) -> std::result::Result<(), SyncApplyError> {
    boatramp_core::project::validate_resource_name(kind, name).map_err(|e| {
        SyncApplyError::Other(format!(
            "refusing a source-derived {kind} name that is not a safe slug (cross-tenant guard): {e}"
        ))
    })
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
            // MEDIUM-2: the DB name is SOURCE-derived — validate before it hits the dest URL.
            validate_source_name("database", &db.name)?;
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
        exclude_prefixes: &BTreeSet<String>,
    ) -> std::result::Result<usize, SyncApplyError> {
        let tok = piece.as_str();
        // READ the source slice (the SOURCE endpoint scopes it to the piece's own project prefixes)…
        let entries =
            self.source_cp
                .get_kv_stratum(tok)
                .await
                .map_err(|e| SyncApplyError::Carry {
                    piece: tok,
                    message: e.to_string(),
                })?;
        // …and WRITE it to the dest. The DEST endpoint re-keys source→target, STRUCTURALLY enforces
        // the target's own piece prefixes (fail-closed), and applies the engine's coherence excludes
        // + the history→siteconfig dependency, returning what landed + what it skipped.
        let excludes: Vec<String> = exclude_prefixes.iter().cloned().collect();
        let outcome = self
            .dest_cp
            .put_kv_stratum(tok, &self.source_project, &excludes, &entries)
            .await
            .map_err(|e| SyncApplyError::Carry {
                piece: tok,
                message: e.to_string(),
            })?;
        if !outcome.skipped.is_empty() {
            if self.strict {
                // PLAN rule 3: `--strict` flips skip → refuse-all.
                let detail = outcome
                    .skipped
                    .iter()
                    .map(|s| format!("  - {}: {}", s.key, s.reason))
                    .collect::<Vec<_>>()
                    .join("\n");
                return Err(SyncApplyError::StrictRefused {
                    count: outcome.skipped.len(),
                    detail,
                });
            }
            // Default posture: skip-and-report — surface the skipped records in the operator notes.
            self.kv_skip_notes.push(format!(
                "{tok}: {} control-plane record(s) skipped (incoherent / excluded): {}",
                outcome.skipped.len(),
                outcome
                    .skipped
                    .iter()
                    .map(|s| format!("{} ({})", s.key, s.reason))
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
        }
        // ALWAYS surface neutralized system-principal markers (Security F1) — informational, never a
        // `--strict` refuse: a `Project·Admin` sync can't grant System authority, so the dest dropped
        // these `current-principal/<site>` markers; re-grant via a dest-side System·Admin activation.
        if !outcome.neutralized.is_empty() {
            self.kv_skip_notes.push(format!(
                "{tok}: {} system-principal marker(s) NOT carried (a Project·Admin sync never grants \
                 a site the System principal; re-grant via a dest-side System·Admin activation): {}",
                outcome.neutralized.len(),
                outcome.neutralized.join(", ")
            ));
        }
        Ok(outcome.written)
    }

    async fn carry_database(&mut self, name: &str) -> std::result::Result<(), SyncApplyError> {
        validate_source_name("database", name)?; // MEDIUM-2
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
        validate_source_name("site", site)?; // MEDIUM-2 (also guards the SOURCE read URL)
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
        validate_source_name("site", site)?; // MEDIUM-2 (guards the DEST read URL)
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
        validate_source_name("site", site)?; // MEDIUM-2 — before ANY fetch/PUT interpolation
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
            strict: false,
            data_transferred: false,
            kv_skip_notes: Vec::new(),
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

    /// The selective control-plane KV-stratum carry is now WIRED over the node-side endpoint: the
    /// executor READS the source and WRITES the dest. Against an unroutable source it fails at the
    /// SOURCE READ transport (a `Carry` error naming the piece) — no longer the old honest
    /// "unsupported" stub. (The real carry path is exercised end-to-end over two in-process nodes by
    /// `crates/boatramp-server/tests/project_kv_stratum_sync_live.rs`.)
    #[tokio::test]
    async fn kv_stratum_carry_is_wired_and_hits_the_source_read_transport() {
        let mut exec = dummy_exec(false, false);
        let err = exec
            .carry_kv_stratum(Piece::Settings, &[], &BTreeSet::new())
            .await
            .expect_err("unroutable source read fails");
        match err {
            SyncApplyError::Carry { piece, message } => {
                assert_eq!(piece, "settings");
                assert!(
                    !message.contains("selective-sync endpoint"),
                    "must be a real transport failure, not the old unsupported stub: {message}"
                );
            }
            other => panic!("expected a Carry transport error, got {other:?}"),
        }
    }

    /// End-to-end over a RECORDING mock node (the `medium3` idiom): the executor reads the source
    /// slice, relays it to the dest WITHOUT decoding the values, and passes `source_project` +
    /// `exclude_prefixes` in the write body — proving the full read→relay→write shape and that a
    /// dest-reported skip surfaces (default posture) rather than aborting.
    #[tokio::test]
    async fn kv_stratum_carry_reads_source_then_writes_dest_and_reports_skips() {
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        struct Seen {
            get_q: Vec<String>,
            post_q: Vec<String>,
            post_body: Vec<serde_json::Value>,
        }
        let seen: Arc<Mutex<Seen>> = Arc::new(Mutex::new(Seen::default()));

        async fn handler(
            axum::extract::State(seen): axum::extract::State<Arc<Mutex<Seen>>>,
            axum::extract::RawQuery(raw): axum::extract::RawQuery,
            req: axum::extract::Request,
        ) -> axum::response::Response {
            use axum::response::IntoResponse;
            let q = raw.unwrap_or_default();
            if req.method() == axum::http::Method::GET {
                seen.lock().unwrap().get_q.push(q);
                // Return one settings record (opaque base64 value).
                return axum::Json(serde_json::json!({
                    "entries": [{ "key": "project/src/config/tenancy", "value_b64": "dgo=" }],
                }))
                .into_response();
            }
            // POST: record the query + the parsed body, answer with a skip to exercise reporting.
            let body = axum::body::to_bytes(req.into_body(), 1 << 20)
                .await
                .unwrap();
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            {
                let mut g = seen.lock().unwrap();
                g.post_q.push(q);
                g.post_body.push(v);
            }
            axum::Json(serde_json::json!({
                "written": 1,
                "skipped": [{ "key": "project/dst/current/web", "reason": "history→siteconfig dependency: no config for site `web`" }],
                "neutralized": ["project/dst/current-principal/web"],
            }))
            .into_response()
        }

        let app = axum::Router::new()
            .route(
                "/api/project-kv-stratum",
                axum::routing::get(handler).post(handler),
            )
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://127.0.0.1:{}", addr.port());

        let mut exec = CliSyncExecutor {
            dest_cp: ControlPlane::new(base.clone(), client::http_client(None), "dst".into()),
            source_cp: ControlPlane::new(base.clone(), client::http_client(None), "src".into()),
            target: "dst".into(),
            source_url: base.clone(),
            source_project: "src".into(),
            source_token: Vec::new(),
            source_dbs: Vec::new(),
            pg_included: false,
            blobs_included: false,
            strict: false,
            data_transferred: false,
            kv_skip_notes: Vec::new(),
        };

        let mut excludes = BTreeSet::new();
        excludes.insert("project/dst/current/legacy".to_string());
        let written = exec
            .carry_kv_stratum(Piece::History, &[], &excludes)
            .await
            .expect("carry ok (skip reported, not aborted)");
        assert_eq!(written, 1, "the dest reported one record written");

        let g = seen.lock().unwrap();
        // The GET named the SOURCE project + the piece; the POST named the DEST project + piece.
        assert!(
            g.get_q
                .iter()
                .any(|q| q.contains("project=src") && q.contains("piece=history"))
        );
        assert!(
            g.post_q
                .iter()
                .any(|q| q.contains("project=dst") && q.contains("piece=history"))
        );
        // The write body carried source_project + the exclude prefix + the relayed (undecoded) entry.
        let body = &g.post_body[0];
        assert_eq!(body["source_project"], "src");
        assert_eq!(body["exclude_prefixes"][0], "project/dst/current/legacy");
        assert_eq!(
            body["entries"][0]["value_b64"], "dgo=",
            "value relayed opaque, not decoded"
        );
        // The dest-reported skip surfaced in the executor's notes (default posture, not aborted).
        assert!(exec_has_skip_note(&exec, "web"));
        // The dest-reported system-principal neutralization (Security F1) ALSO surfaced as a note.
        assert!(
            exec_has_skip_note(&exec, "current-principal/web")
                && exec_has_skip_note(&exec, "System principal"),
            "neutralized marker must surface as an operator note: {:?}",
            exec.kv_skip_notes
        );

        fn exec_has_skip_note(exec: &CliSyncExecutor, needle: &str) -> bool {
            exec.kv_skip_notes.iter().any(|n| n.contains(needle))
        }
    }

    /// `--strict` turns a dest-reported KV-stratum skip into a whole-run refusal (PLAN rule 3).
    #[tokio::test]
    async fn kv_stratum_carry_strict_refuses_on_a_dest_reported_skip() {
        use axum::response::IntoResponse;
        async fn handler(req: axum::extract::Request) -> axum::response::Response {
            if req.method() == axum::http::Method::GET {
                return axum::Json(serde_json::json!({
                    "entries": [{ "key": "project/src/history/web", "value_b64": "W10=" }],
                }))
                .into_response();
            }
            axum::Json(serde_json::json!({
                "written": 0,
                "skipped": [{ "key": "project/dst/history/web", "reason": "no config for site `web`" }],
            }))
            .into_response()
        }
        let app = axum::Router::new().route(
            "/api/project-kv-stratum",
            axum::routing::get(handler).post(handler),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://127.0.0.1:{}", addr.port());
        let mut exec = CliSyncExecutor {
            dest_cp: ControlPlane::new(base.clone(), client::http_client(None), "dst".into()),
            source_cp: ControlPlane::new(base.clone(), client::http_client(None), "src".into()),
            target: "dst".into(),
            source_url: base.clone(),
            source_project: "src".into(),
            source_token: Vec::new(),
            source_dbs: Vec::new(),
            pg_included: false,
            blobs_included: false,
            strict: true, // <-- strict
            data_transferred: false,
            kv_skip_notes: Vec::new(),
        };
        let err = exec
            .carry_kv_stratum(Piece::History, &[], &BTreeSet::new())
            .await
            .expect_err("strict refuses on a skip");
        assert!(matches!(
            err,
            SyncApplyError::StrictRefused { count: 1, .. }
        ));
    }

    // ===== Security review fixes =============================================================

    /// MEDIUM-2: a crafted SOURCE-derived site/db name (path traversal) is refused by the
    /// client-side validation BEFORE any URL interpolation — the error is the cross-tenant guard,
    /// not a transport error (so no wire call was even attempted). A valid slug passes the guard.
    #[tokio::test]
    async fn medium2_source_derived_traversal_names_refused_before_wire() {
        let mut exec = dummy_exec(true, true);
        let cfg = boatramp_core::config::SiteConfig::default();

        let e1 = exec
            .write_dest_site_config("../../victim/sites/web", &cfg)
            .await
            .expect_err("traversal site refused");
        match e1 {
            SyncApplyError::Other(m) => {
                assert!(
                    m.contains("cross-tenant guard") && m.contains("site"),
                    "{m}"
                );
            }
            o => panic!("expected guard refusal, got {o:?}"),
        }

        let e2 = exec
            .carry_database("../../victim/databases/x")
            .await
            .expect_err("traversal db refused");
        match e2 {
            SyncApplyError::Other(m) => {
                assert!(
                    m.contains("cross-tenant guard") && m.contains("database"),
                    "{m}"
                );
            }
            o => panic!("expected guard refusal, got {o:?}"),
        }

        // A VALID slug passes the guard, then fails on the (unroutable) transport — proving the
        // guard rejects only unsafe names, not every name.
        let e3 = exec
            .carry_database("validdb")
            .await
            .expect_err("transport fails at 127.0.0.1:0");
        match e3 {
            SyncApplyError::Other(m) => assert!(
                !m.contains("cross-tenant guard"),
                "a valid name must pass the guard (reach transport): {m}"
            ),
            o => panic!("expected a transport error, got {o:?}"),
        }
    }

    /// MEDIUM-3 (the ≥2-tenant tenancy gate): with the dest = tenant A and a crafted source name
    /// pointing at tenant B, assert the write/carry are refused and the dest node receives ZERO
    /// requests — tenant B is UNTOUCHED (zero foreign bytes), because the guard fires before the
    /// wire. A recording mock control-plane stands in for the dest; any request would have been
    /// logged.
    #[tokio::test]
    async fn medium3_two_tenant_traversal_leaves_tenant_b_untouched() {
        use std::sync::{Arc, Mutex};

        async fn record_req(
            axum::extract::State(log): axum::extract::State<Arc<Mutex<Vec<String>>>>,
            req: axum::extract::Request,
        ) -> axum::Json<boatramp_core::config::SiteConfig> {
            log.lock()
                .unwrap()
                .push(format!("{} {}", req.method(), req.uri().path()));
            axum::Json(boatramp_core::config::SiteConfig::default())
        }

        let log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let app = axum::Router::new()
            .fallback(record_req)
            .with_state(log.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base = format!("http://127.0.0.1:{}", addr.port());

        // The dest client is scoped to tenant A; tenant B is the would-be victim named in the
        // traversal. (B's incumbent config is whatever the mock holds — the point is it is NEVER
        // written, i.e. never even requested.)
        let mut exec = CliSyncExecutor {
            dest_cp: ControlPlane::new(base.clone(), client::http_client(None), "A".into()),
            source_cp: ControlPlane::new(base.clone(), client::http_client(None), "A".into()),
            target: "A".into(),
            source_url: base.clone(),
            source_project: "A".into(),
            source_token: Vec::new(),
            source_dbs: Vec::new(),
            pg_included: true,
            blobs_included: true,
            strict: false,
            data_transferred: false,
            kv_skip_notes: Vec::new(),
        };

        let cfg = boatramp_core::config::SiteConfig::default();
        assert!(
            exec.write_dest_site_config("../../B/sites/web", &cfg)
                .await
                .is_err(),
            "traversal write refused"
        );
        assert!(
            exec.carry_database("../../B/databases/secret")
                .await
                .is_err(),
            "traversal carry refused"
        );
        // Give any (erroneously-sent) request a moment to land.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let seen = log.lock().unwrap().clone();
        assert!(
            seen.is_empty(),
            "ZERO foreign bytes: no request reached the dest node for a traversal name; got {seen:?}"
        );
    }

    /// `--include-settings --apply` is NO LONGER refused up front: the stratum is now wired over the
    /// node-side endpoint, so `run()` proceeds into the network (failing here only because the test
    /// server is unroutable) rather than returning the old pre-write `StratumUnsupported` refusal —
    /// proving the gap is closed. (The successful carry is exercised by the live gate.)
    #[tokio::test]
    async fn apply_with_a_kv_stratum_is_wired_not_refused_up_front() {
        let args = parse(&[
            "sync",
            "--from",
            "prod",
            "--include-settings",
            "--apply",
            "-y",
            "dst",
        ])
        .expect("parses");
        // An unroutable server: the apply now reaches the network (list_projects) and fails there —
        // a `Client` transport error, NOT a pre-write stratum refusal.
        let err = run(args, &ProjectConfig::default(), "http://127.0.0.1:0".into())
            .await
            .expect_err("fails at the network, not a pre-write refusal");
        assert!(
            matches!(err, Error::Client(_)),
            "settings is wired now — expected a network error, got {err:?}"
        );
    }

    /// LOW-5: a cross-node `--include-domains --apply` without `--allow-domain-cutover` is refused
    /// (double-live-owner risk — the dest guard can't see the remote source's live ownership).
    #[tokio::test]
    async fn low5_cross_node_domains_apply_refused_without_cutover_flag() {
        let args = parse(&[
            "sync",
            "--from",
            "https://prod.example.com",
            "--include-sites",
            "--include-domains",
            "--apply",
            "-y",
            "dst",
        ])
        .expect("parses");
        let err = run(args, &ProjectConfig::default(), "http://127.0.0.1:0".into())
            .await
            .expect_err("refused without cutover intent");
        assert!(
            matches!(err, Error::DomainCutoverUnconfirmed { .. }),
            "got {err:?}"
        );
    }

    /// Now that the stratum is wired, a dry-run including `settings` shows it as `carry` (the engine
    /// disposition) — the old "NOT carried over the CLI" honesty-stub is gone.
    #[test]
    fn dry_run_shows_a_kv_stratum_as_carry_now_that_it_is_wired() {
        use crate::output::Rendered;
        let selection = parse(&["sync", "--from", "prod", "--include-settings", "dst"])
            .expect("parses")
            .selection_input()
            .resolve()
            .expect("resolves");
        let plan = project_sync::plan_sync(
            &selection,
            &SyncInventory::default(),
            &project_sync::DestState::Absent,
            "src",
            "dst",
        );
        let report = SyncReport {
            plan,
            notes: Vec::new(),
            applied: None,
        };
        let mut buf = Vec::new();
        report.render_human(&mut buf).expect("render");
        let out = String::from_utf8(buf).unwrap();
        assert!(
            !out.contains("NOT carried over the CLI"),
            "the unsupported-stratum stub must be gone:\n{out}"
        );
        let settings_line = out
            .lines()
            .find(|l| l.contains("settings"))
            .expect("settings row present");
        assert!(
            settings_line.contains("[carry"),
            "settings must now render as carry: {settings_line}"
        );
    }
}
