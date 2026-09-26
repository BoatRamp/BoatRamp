//! The server-side migration **orchestrator** (Backend A1). It owns step ordering, prefix-consistency
//! + content-hash immutability, `function`-step invocation (which needs the invoke kernel and so can
//! only live here, beside [`execute_migration_function`]), dry-run planning, and baseline; it drives
//! the node-side [`MigrationSubstrate`] seam for the owner-role connection + the `schema_migrations`
//! ledger + direct `sql`/`extension` execution.
//!
//! A migration is an ordered set of [`MigrationStep`]s of three kinds — `function` (the base: a
//! project function doing arbitrary work, DDL via the host-mediated owner-role `migrate-ddl`
//! capability), `sql` (sugar: a DDL script run as the owner role), `extension` (sugar: an
//! allowlist-gated `CREATE EXTENSION`). The bundle is uploaded content-addressed and referenced by
//! hash; the HTTP layer reads it and hands the parsed steps here.
//!
//! SECURITY: a `function` step runs via [`execute_migration_function`] under a [`MigrationContext`],
//! which forces the owner-role `migrate-ddl` grant + the tenant-`sql` binding-split (S1/S2). A
//! `function` step's ref resolves strictly within the host-stamped `project` (S6). A step's ledger
//! row is written only AFTER it succeeds — at-least-once + author-idempotent (S7).

#![cfg(feature = "handlers")]

use std::collections::BTreeMap;
use std::sync::Arc;

use boatramp_core::deploy::DeployStore;
use boatramp_core::function::Function;
use boatramp_core::project::ProjectRef;
use boatramp_core::sql::{
    LedgerOrigin, MigrationAction, MigrationError, MigrationFailure, MigrationReport,
    MigrationStep, MigrationSubstrate, SubstrateStepOutcome,
};

use crate::HandlerRuntimeInner;

/// What a migrate request does.
pub enum MigrateMode {
    /// Apply the pending suffix (run each step + record it).
    Apply,
    /// Compute the plan (pending ids) without running or recording anything.
    DryRun,
    /// Record the prefix through (and including) `up_to` as already-applied WITHOUT running any
    /// step — the owner-assertion adoption op (#480). `None` ⇒ baseline the whole set.
    Baseline { up_to: Option<String> },
}

/// A migration id is restricted to `[A-Za-z0-9._-]+` (non-empty) — matches the node substrate's guard
/// so a client-side and server-side rejection agree.
fn valid_migration_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// Resolve a `function` step's project function + pinned component blob hash (Backend A3 — never
/// `active` implicitly except as the documented default when `version` is unset). S6: the name must
/// resolve strictly within `project` — a `/`-bearing name (a cross-project smuggle) is refused.
async fn resolve_function(
    deploy: &DeployStore,
    project: &str,
    name: &str,
    version: Option<&str>,
) -> Result<(Function, String), String> {
    if name.contains('/') {
        return Err("a function step name may not contain a project segment".to_string());
    }
    let f = deploy
        .get_function(ProjectRef::new(project), name)
        .await
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("no function {name:?} in this project"))?;
    let reference = version.unwrap_or(&f.active);
    let component = f
        .resolve(reference)
        .map(str::to_owned)
        .ok_or_else(|| format!("no version {reference:?} in function {name:?}"))?;
    Ok((f, component))
}

/// The **effective** hash for a step (ledgered + prefix-compared): the intrinsic content hash for
/// `sql`/`extension`; for a `function` step the content hash bound to the RESOLVED component blob
/// (so a redeploy under the same version tag is caught). Returns the resolved function + component
/// alongside for the apply phase, so a function step is fetched once.
async fn resolve_effective(
    deploy: &DeployStore,
    project: &str,
    step: &MigrationStep,
) -> Result<(String, Option<(Function, String)>), String> {
    match &step.action {
        MigrationAction::Function { name, version, .. } => {
            let (f, component) =
                resolve_function(deploy, project, name, version.as_deref()).await?;
            let eff = step.effective_hash(Some(&component));
            Ok((eff, Some((f, component))))
        }
        _ => Ok((step.content_hash(), None)),
    }
}

/// The kind map for every step (U3: the report tells a thin client each id's kind).
fn kinds_of(steps: &[MigrationStep]) -> BTreeMap<String, String> {
    steps
        .iter()
        .map(|s| (s.id.clone(), s.kind().to_string()))
        .collect()
}

/// Build a `failed`-terminated report (application halts at `id`; the prior prefix stands).
fn failed(
    newly_applied: Vec<String>,
    already_applied: Vec<String>,
    steps: &[MigrationStep],
    id: &str,
    error: String,
) -> MigrationReport {
    MigrationReport {
        newly_applied,
        already_applied,
        pending: Vec::new(),
        failed: Some(MigrationFailure {
            id: id.to_string(),
            error,
        }),
        kinds: kinds_of(steps),
    }
}

/// Public embedder / live-gate seam: drive a migration given the public [`HandlerRuntime`] plus the
/// node [`MigrationSubstrate`]. The HTTP handlers call [`orchestrate`] directly (they already hold
/// the private runtime inner); this wraps it for a caller holding only the public runtime.
pub async fn run_migration(
    runtime: &crate::HandlerRuntime,
    deploy: &DeployStore,
    substrate: &Arc<dyn MigrationSubstrate>,
    project: &str,
    db: &str,
    steps: &[MigrationStep],
    mode: MigrateMode,
) -> Result<MigrationReport, MigrationError> {
    let inner = runtime.inner.as_ref().map(std::convert::AsRef::as_ref);
    orchestrate(inner, deploy, substrate, project, db, steps, mode).await
}

/// Drive an apply / dry-run / baseline over the ordered `steps`. `inner` is the handler runtime
/// (needed to invoke `function` steps); `None`/no-`migrate`-feature ⇒ a function step fails closed
/// with a clear per-step error while `sql`/`extension` steps still work.
pub(crate) async fn orchestrate(
    inner: Option<&HandlerRuntimeInner>,
    deploy: &DeployStore,
    substrate: &Arc<dyn MigrationSubstrate>,
    project: &str,
    db: &str,
    steps: &[MigrationStep],
    mode: MigrateMode,
) -> Result<MigrationReport, MigrationError> {
    // Up-front id validation (every step): a bad id can never reach the ledger SQL builder.
    for step in steps {
        if !valid_migration_id(&step.id) {
            return Ok(failed(
                Vec::new(),
                Vec::new(),
                steps,
                &step.id,
                "invalid migration id (allowed: A-Za-z0-9._-)".to_string(),
            ));
        }
    }

    // Engine gate + ledger + the recorded rows (owner role).
    let applied = substrate.preflight(project, db).await?;

    // Prefix-consistency + content-hash immutability: the recorded ids must be an ordered prefix of
    // the supplied steps, same id@ordinal, and same effective hash (blob-bound for function steps).
    if applied.len() > steps.len() {
        return Err(MigrationError::PrefixDivergence(format!(
            "the ledger has {} applied migrations but only {} were supplied",
            applied.len(),
            steps.len()
        )));
    }
    for (i, rec) in applied.iter().enumerate() {
        if steps[i].id != rec.id {
            return Err(MigrationError::PrefixDivergence(format!(
                "position {i}: ledger has {:?} but the set has {:?}",
                rec.id, steps[i].id
            )));
        }
        // Recompute the effective hash to verify the applied step was not changed. A function step
        // that no longer resolves (its version was pruned / redeployed away) cannot be verified —
        // refuse fail-closed rather than silently trusting the recorded hash.
        let (eff, _) = resolve_effective(deploy, project, &steps[i])
            .await
            .map_err(|e| {
                MigrationError::Other(format!("cannot verify applied step {:?}: {e}", steps[i].id))
            })?;
        if eff != rec.content_hash {
            return Err(MigrationError::ContentChanged(rec.id.clone()));
        }
    }

    let already_applied: Vec<String> = applied.iter().map(|a| a.id.clone()).collect();

    match mode {
        MigrateMode::DryRun => Ok(MigrationReport {
            newly_applied: Vec::new(),
            already_applied,
            pending: steps[applied.len()..]
                .iter()
                .map(|s| s.id.clone())
                .collect(),
            failed: None,
            kinds: kinds_of(steps),
        }),

        MigrateMode::Baseline { up_to } => {
            // The boundary is the count of steps to record (through `up_to` inclusive; whole set if
            // unset). It must be a strict, prefix-consistent EXTENSION of what is recorded.
            let boundary = match &up_to {
                Some(id) => match steps.iter().position(|s| &s.id == id) {
                    Some(pos) => pos + 1,
                    None => {
                        return Err(MigrationError::Other(format!(
                            "baseline up_to {id:?} is not in the supplied step set"
                        )));
                    }
                },
                None => steps.len(),
            };
            if boundary < applied.len() {
                return Err(MigrationError::PrefixDivergence(format!(
                    "baseline boundary ({boundary}) is behind the {} already-recorded steps",
                    applied.len()
                )));
            }
            let mut newly_applied = Vec::new();
            for (ordinal, step) in steps.iter().enumerate().take(boundary).skip(applied.len()) {
                // Record the SAME effective hash apply would — so a later apply of the full set sees
                // the baselined prefix as already-applied. A function step's baseline still binds the
                // resolved blob (so the later apply's consistency check passes).
                let eff = match resolve_effective(deploy, project, step).await {
                    Ok((eff, _)) => eff,
                    Err(e) => {
                        return Ok(failed(newly_applied, already_applied, steps, &step.id, e));
                    }
                };
                substrate
                    .record(project, db, step, ordinal, &eff, LedgerOrigin::Baseline)
                    .await?;
                newly_applied.push(step.id.clone());
            }
            Ok(MigrationReport {
                newly_applied,
                already_applied,
                pending: Vec::new(),
                failed: None,
                kinds: kinds_of(steps),
            })
        }

        MigrateMode::Apply => {
            let mut newly_applied = Vec::new();
            for (ordinal, step) in steps.iter().enumerate().skip(applied.len()) {
                let (eff, resolved_fn) = match resolve_effective(deploy, project, step).await {
                    Ok(r) => r,
                    Err(e) => {
                        return Ok(failed(newly_applied, already_applied, steps, &step.id, e));
                    }
                };
                match &step.action {
                    MigrationAction::Sql { .. } | MigrationAction::Extension { .. } => {
                        match substrate
                            .apply_substrate_step(project, db, step, ordinal, &eff)
                            .await?
                        {
                            SubstrateStepOutcome::Applied => newly_applied.push(step.id.clone()),
                            SubstrateStepOutcome::Failed(error) => {
                                return Ok(failed(
                                    newly_applied,
                                    already_applied,
                                    steps,
                                    &step.id,
                                    error,
                                ));
                            }
                        }
                    }
                    MigrationAction::Function { args, .. } => {
                        match apply_function_step(
                            inner,
                            deploy,
                            substrate,
                            project,
                            db,
                            step,
                            ordinal,
                            &eff,
                            resolved_fn,
                            args.as_deref(),
                        )
                        .await?
                        {
                            SubstrateStepOutcome::Applied => newly_applied.push(step.id.clone()),
                            SubstrateStepOutcome::Failed(error) => {
                                return Ok(failed(
                                    newly_applied,
                                    already_applied,
                                    steps,
                                    &step.id,
                                    error,
                                ));
                            }
                        }
                    }
                }
            }
            Ok(MigrationReport {
                newly_applied,
                already_applied,
                pending: Vec::new(),
                failed: None,
                kinds: kinds_of(steps),
            })
        }
    }
}

/// Run one `function` step: mint the owner-DDL seam, invoke the function under a migration context
/// (quota-exempt, Async lane, owner-`migrate-ddl` + tenant-`sql` binding-split), then — only on a
/// 2xx return — record its ledger row (S7 at-least-once + author-idempotent). A non-2xx return is a
/// per-step failure whose message distinguishes a guest trap (`function invocation failed`) from an
/// author-returned error (the guest's own status + body). Returns `Err(MigrationError)` only for a
/// true infra failure (owner connect down, or the ledger write failed AFTER a successful run).
#[allow(clippy::too_many_arguments)]
async fn apply_function_step(
    inner: Option<&HandlerRuntimeInner>,
    deploy: &DeployStore,
    substrate: &Arc<dyn MigrationSubstrate>,
    project: &str,
    db: &str,
    step: &MigrationStep,
    ordinal: usize,
    effective_hash: &str,
    resolved_fn: Option<(Function, String)>,
    args: Option<&str>,
) -> Result<SubstrateStepOutcome, MigrationError> {
    #[cfg(not(feature = "migrate"))]
    {
        let _ = (
            inner,
            deploy,
            substrate,
            db,
            ordinal,
            effective_hash,
            resolved_fn,
            args,
        );
        return Ok(SubstrateStepOutcome::Failed(
            "function migration steps require a build with the `migrate` feature (handler engine)"
                .to_string(),
        ));
    }
    #[cfg(feature = "migrate")]
    {
        let Some(inner) = inner else {
            return Ok(SubstrateStepOutcome::Failed(
                "function migration steps require the handler runtime (not available on this node)"
                    .to_string(),
            ));
        };
        let (function, component) = resolved_fn.expect("function step resolved above");
        // The owner-role DDL seam backing this step's `migrate-ddl` capability (S5). A connect
        // failure here is infra (retryable 503), not a per-step author failure.
        let ddl = substrate.owner_ddl(project, db).await?;
        let request = build_migration_request(args);
        let (response, _ms) = crate::function_runtime::execute_migration_function(
            inner,
            deploy,
            ProjectRef::new(project),
            &function,
            &component,
            request,
            ddl,
        )
        .await;
        if response.status().is_success() {
            // Record only after a delivered success (S7). A ledger write failure here is infra: the
            // step DID run, so surface it as an error rather than silently dropping the record.
            substrate
                .record(
                    project,
                    db,
                    step,
                    ordinal,
                    effective_hash,
                    LedgerOrigin::Apply,
                )
                .await?;
            Ok(SubstrateStepOutcome::Applied)
        } else {
            let status = response.status();
            let body = read_response_body_lossy(response).await;
            Ok(SubstrateStepOutcome::Failed(format!(
                "function step returned {status}: {}",
                body.trim()
            )))
        }
    }
}

/// Build the invoke request handed to a migration function: a `POST` at the invoke authority whose
/// body is the step's `args` (opaque to the host — the function parses it). Empty body when unset.
#[cfg(feature = "migrate")]
fn build_migration_request(args: Option<&str>) -> axum::extract::Request {
    let body = args.unwrap_or("").to_string();
    axum::http::Request::builder()
        .method(axum::http::Method::POST)
        .uri("http://function.invoke/")
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body))
        .expect("static migration invoke request builds")
}

/// Read a function response body to a bounded, lossy UTF-8 string for the failure report (so an
/// author-returned error message reaches the client without a wall of bytes).
#[cfg(feature = "migrate")]
async fn read_response_body_lossy(response: axum::response::Response) -> String {
    use http_body_util::BodyExt;
    const MAX: usize = 2048;
    let bytes = match response.into_body().collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return String::new(),
    };
    let slice = &bytes[..bytes.len().min(MAX)];
    String::from_utf8_lossy(slice).into_owned()
}
