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

use boatramp_core::project_sync::{
    self, Disposition, ItemKind, Piece, Selection, SelectionInput, SyncInventory, SyncPlan,
};

use crate::client;
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
    /// `--apply` — execution is increment 2.
    #[error(
        "project sync --apply is not yet implemented (increment 2 — data/KV transfer, config \
         rewrite, and absent-destination provisioning); re-run WITHOUT --apply to see the dry-run \
         preflight plan"
    )]
    ApplyNotImplemented,
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

    /// Execute the sync (increment 2). In this release it returns a not-yet-implemented message;
    /// the default (no `--apply`) is the dry-run preflight.
    #[arg(long)]
    apply: bool,

    /// Skip the interactive confirmation on `--apply` (increment 2). Parsed now for surface
    /// stability.
    #[arg(long, short = 'y')]
    yes: bool,
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
    /// Operator notes (what this increment does NOT yet do; where item rows come from).
    pub notes: Vec<String>,
}

impl crate::output::Rendered for SyncReport {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
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
            "(dry-run preflight — nothing moved; `--apply` executes the plan in increment 2)"
        )
    }
}

/// Entry point for `boatramp project sync` (planning path).
pub async fn run(args: SyncArgs, config: &ProjectConfig, server: String) -> Result<SyncReport> {
    // 1) Validate + resolve the selection FIRST (cheap, no I/O) — a contradictory/empty selection
    //    is reported before any network round-trip or the apply stub.
    if args.identity != "fresh" {
        return Err(Error::IdentityUnsupported(args.identity.clone()));
    }
    let selection: Selection = args.selection_input().resolve()?;

    // 2) `--apply` is increment 2 — a clear stub, after the selection is known to be valid.
    if args.apply {
        return Err(Error::ApplyNotImplemented);
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

    // 4) Destination precondition — DETECT an absent destination (plan to create + provision;
    //    never 404). `list_projects` avoids the 404-vs-error ambiguity of a direct GET.
    let token = client::token(config);
    let dest_cp = client::ControlPlane::new(
        server.clone(),
        client::http_client(token.as_deref()),
        target.clone(),
    );
    let projects = dest_cp.list_projects().await?;
    let dest_present = projects
        .iter()
        .any(|p| p.get("name").and_then(|v| v.as_str()) == Some(target.as_str()));

    let dest = if dest_present {
        // Databases already on the destination anchor the per-site coherence check. Dest site
        // enumeration needs a list endpoint (increment 2), so dest sites are left empty here.
        let databases: BTreeSet<String> = dest_cp
            .list_databases()
            .await?
            .into_iter()
            .map(|d| d.name)
            .collect();
        project_sync::DestState::Present {
            sites: BTreeSet::new(),
            databases,
        }
    } else {
        notes.push(format!(
            "destination project `{target}` does not exist — sync will create + provision it \
             (increment 2); on a fresh destination there is nothing to preserve"
        ));
        project_sync::DestState::Absent
    };

    // 5) Source inventory. For a same-node project source we enumerate its declared databases now
    //    (a real inventory for the per-item classification); site enumeration and cross-node (URL)
    //    source enumeration land in increment 2.
    let mut inventory = SyncInventory::default();
    if source_is_url {
        notes.push(format!(
            "source `{}` is cross-node — its items are enumerated over the `--clone-from` \
             transport in increment 2; this preflight shows the per-piece plan + destination \
             precondition",
            args.from
        ));
    } else {
        let source_cp = client::ControlPlane::new(
            server.clone(),
            client::http_client(token.as_deref()),
            source_project.clone(),
        );
        inventory.databases = source_cp
            .list_databases()
            .await?
            .into_iter()
            .map(|d| d.name)
            .collect();
        notes.push(
            "source site enumeration (and per-site managed-DB coherence) lands in increment 2; \
             database item rows are shown from the same-node source's declared bindings"
                .to_string(),
        );
    }

    // 6) Build the preflight plan via the pure core planner.
    let plan = project_sync::plan_sync(&selection, &inventory, &dest, &source_label, &target);

    // 7) `--strict`: a skip refuses the whole run (minimal refuse path — the dry-run still
    //    computed the full plan, surfaced here as the refusal detail).
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

    Ok(SyncReport { plan, notes })
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
}
