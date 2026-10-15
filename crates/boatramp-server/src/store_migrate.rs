//! The **control-plane store migration** admin surface (`/api/store-migrate/*`) — the console
//! wizard's back end for the default-scope re-home (the Finding-8 migration-safety work).
//!
//! DISTINCT from the per-project SQL **schema** migration (`/api/migrate/*`, `Project·Admin`): this is
//! a NODE-DESTRUCTIVE control-plane *store layout* migration and MUST be `System·Admin`. It lives at a
//! singular-hyphen path (`/api/store-migrate/*`) that cannot match the `starts_with("/api/migrate/")`
//! per-project matcher (exactly as `blob-purge`/`kv-export` dodge `/api/blobs/`), gated `System·Admin`
//! in the authoritative authz table AND re-checked defense-in-depth in each mutating handler.
//!
//! Endpoints (all run the engine on the RAW control-plane KV — [`DeployStore::kv`] — never the
//! compat-decorated data-plane handle):
//! - `GET  /api/store-migrate/status`  (`System·Read`)  — the [`migrate::plan`] (status + the
//!   operator-answerable decisions + a forward summary) plus any ARMED answers.
//! - `POST /api/store-migrate/arm`     (`System·Admin`) — validate + persist the operator's answers
//!   ([`migrate::arm_answers`]); the stage then runs at the NEXT RESTART via `serve --auto-migrate`,
//!   BEFORE the runtime is built — so no process ever serves through a stale layout decorator.
//! - `POST /api/store-migrate/abort`   (`System·Admin`) — un-arm pending answers, or roll back a
//!   staged (dual-soak) store via [`migrate::abort`].
//!
//! The destructive FINALIZE is deliberately NOT exposed online: it must run AFTER the restart (fresh
//! runtime, no stale decorator) and after the blob + libsql re-home, with the substrate-complete gate
//! — so it stays the explicit `boatramp migrate --finalize` CLI step the wizard points the operator
//! at. Staging is non-destructive and `abort` is lossless, so the online surface is safe.

use super::*;

use boatramp_core::migrate::{self, MigrateError, MigrationAnswers, RouteAction};

/// Defense-in-depth (mirrors [`assert_blob_purge_is_system_admin`](crate::blob_purge)): re-derive the
/// right the authoritative table requires for `path` and assert it is node-global `System·Admin`
/// before mutating. The auth middleware already enforced it; this catches a future routing/table
/// regression that might silently downgrade a node-destructive store migration to a project right.
fn assert_store_migrate_is_system_admin(path: &str) -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required("POST", path) {
        Some(right)
            if right.resource == Resource::System
                && right.target.is_none()
                && right.action == Action::Admin =>
        {
            None
        }
        _ => Some(
            (
                StatusCode::FORBIDDEN,
                "store migration requires System·Admin\n",
            )
                .into_response(),
        ),
    }
}

/// Map a migration-engine error to an HTTP response: the operator-actionable refusals (an unresolved
/// collision, an un-abortable/divergent state) are 409 CONFLICT with the message; everything else 500.
fn migrate_error_response(e: MigrateError) -> Response {
    let code = match e {
        MigrateError::DefaultNamedResource { .. }
        | MigrateError::AbortNothingStaged
        | MigrateError::AbortMidFlight
        | MigrateError::AbortNotSupported { .. }
        | MigrateError::AbortWouldLoseData { .. } => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (code, format!("{e}\n")).into_response()
}

/// Build a [`migrate::BlobScopeScanner`] over the node's DEFAULT-project blob backend, so the
/// data-aware collision gate (feature A) can prove a commingle has no blob footprint. `None` when
/// handlers are disabled (no blob backend) — the gate then treats every commingle as blocking
/// (conservative).
///
/// Scans the RAW (undecorated) DEFAULT backend ([`HandlerRuntime::raw_default_blob_backend`], Security
/// LOW-A2) so this admin view of the bare `hblob/{name}/…` keyspace matches the migration-authoritative
/// boot stage's raw scan — the default-scope `TranslatingStorage`/fallback decorator carries a
/// construction-time project snapshot, and a colliding tenant project created AFTER this serve booted
/// is absent from it, so the decorated backend would translate/hide `hblob/{name}/…` and the wizard
/// could under-report. Falls back to the resolver's `backend(DEFAULT)` only when no raw handle was
/// wired (a global/undecorated runtime, where the two are identical).
fn blob_scope_scanner(handlers: &HandlerRuntime) -> Option<migrate::StorageBlobScopeScanner> {
    // `handlers`-feature-gated; without it the node has no object backend at all, so there is nothing
    // to scan ⇒ `None` ⇒ the gate treats every commingle as blocking.
    #[cfg(feature = "handlers")]
    {
        let backend = handlers.raw_default_blob_backend().or_else(|| {
            handlers
                .blob_backends()
                .map(|b| b.backend(boatramp_core::project::ProjectRef::DEFAULT))
        })?;
        Some(migrate::StorageBlobScopeScanner::new(backend))
    }
    #[cfg(not(feature = "handlers"))]
    {
        let _ = handlers;
        None
    }
}

/// `GET /api/store-migrate/status` (`System·Read`) — the migration plan + any armed answers.
pub(super) async fn store_migrate_status(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
) -> Response {
    let kv = deploy.kv().as_ref();
    let scanner = blob_scope_scanner(&handlers);
    let plan = match migrate::plan(
        kv,
        scanner
            .as_ref()
            .map(|s| s as &dyn migrate::BlobScopeScanner),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return migrate_error_response(e),
    };
    let armed = match migrate::read_armed_answers(kv).await {
        Ok(a) => a,
        Err(e) => return migrate_error_response(e),
    };
    Json(serde_json::json!({ "plan": plan, "armed": armed })).into_response()
}

/// `POST /api/store-migrate/arm` (`System·Admin`) — validate the operator's answers against the live
/// plan and persist them for the next boot-time stage. Rejects (409) if a collision is left neither
/// skipped nor resolved (so the boot stage can't refuse); `abort` arms a "do not stage".
pub(super) async fn store_migrate_arm(
    State(deploy): State<DeployStore>,
    Extension(handlers): Extension<Arc<HandlerRuntime>>,
    Json(answers): Json<MigrationAnswers>,
) -> Response {
    if let Some(forbidden) = assert_store_migrate_is_system_admin("/api/store-migrate/arm") {
        return forbidden;
    }
    let kv = deploy.kv().as_ref();

    // Validate GENERICALLY against the live plan, keying off each chosen route's `action` (the engine's
    // migration-agnostic contract) — never off a route-`key` string. Every live decision must resolve
    // to a `Stage` route (the migration will honor it) unless the operator chose an `Abort` route (then
    // the whole thing is a "do not migrate" and the other answers don't matter). A decision answered
    // with an `External` route (e.g. rename — the operator re-creates the resource via the deploy flow)
    // is NOT yet resolved: it must be done out-of-band so the decision is gone from the plan BEFORE
    // arming, else the boot stage would refuse. An unanswered decision is likewise unresolved. The blob
    // scanner feeds the plan's feature-A data-aware gate (a no-footprint commingle won't surface here).
    let scanner = blob_scope_scanner(&handlers);
    let plan = match migrate::plan(
        kv,
        scanner
            .as_ref()
            .map(|s| s as &dyn migrate::BlobScopeScanner),
    )
    .await
    {
        Ok(p) => p,
        Err(e) => return migrate_error_response(e),
    };
    let mut aborting = false;
    let mut unresolved: Vec<&str> = Vec::new();
    for d in &plan.decisions {
        match answers
            .route(&d.id)
            .and_then(|k| d.routes.iter().find(|r| r.key == k))
        {
            Some(route) => match route.action {
                RouteAction::Abort => aborting = true,
                RouteAction::Stage => {}
                RouteAction::External => unresolved.push(d.id.as_str()),
            },
            None => unresolved.push(d.id.as_str()),
        }
    }
    if !aborting && !unresolved.is_empty() {
        return (
            StatusCode::CONFLICT,
            format!(
                "cannot arm: unresolved decision(s) {unresolved:?} — resolve each (e.g. re-deploy a \
                 colliding resource under a non-colliding name so it leaves the plan), or abort.\n"
            ),
        )
            .into_response();
    }

    if let Err(e) = migrate::arm_answers(kv, &answers).await {
        return migrate_error_response(e);
    }
    // Durable: the armed answers rode `put_durable_checkpointed`; a belt-and-suspenders flush too.
    let _ = deploy.kv().flush().await;
    Json(serde_json::json!({
        "armed": true,
        "aborted": aborting,
        "restart_required": true,
        "next": "Restart the node: `serve --auto-migrate` stages the re-home at boot (before the \
                 runtime is built). Then re-home blob + libsql and run `boatramp migrate --finalize`."
    }))
    .into_response()
}

/// `POST /api/store-migrate/abort` (`System·Admin`) — roll back a staged (dual-soak) store, or un-arm
/// pending answers if nothing is staged yet.
pub(super) async fn store_migrate_abort(State(deploy): State<DeployStore>) -> Response {
    if let Some(forbidden) = assert_store_migrate_is_system_admin("/api/store-migrate/abort") {
        return forbidden;
    }
    let kv = deploy.kv().as_ref();
    let status = match migrate::status(kv).await {
        Ok(s) => s,
        Err(e) => return migrate_error_response(e),
    };
    if status == migrate::Status::Dual {
        if let Err(e) = migrate::abort(kv).await {
            return migrate_error_response(e);
        }
        let _ = deploy.kv().flush().await;
        return Json(serde_json::json!({ "action": "rolled-back", "status": "needs-migration" }))
            .into_response();
    }
    // Not staged: un-arm any pending answers.
    if let Err(e) = migrate::clear_armed_answers(kv).await {
        return migrate_error_response(e);
    }
    let _ = deploy.kv().flush().await;
    Json(serde_json::json!({ "action": "unarmed" })).into_response()
}

#[cfg(test)]
mod tests {
    use boatramp_core::authz::{Action, AuthzPolicy, GrantedRole, Resource, Right};

    #[test]
    fn store_migrate_authz_is_system_admin_not_per_project() {
        // The mutating verbs ⇒ node-global System·Admin (target None).
        for path in ["/api/store-migrate/arm", "/api/store-migrate/abort"] {
            let r = Right::required("POST", path)
                .unwrap_or_else(|| panic!("{path} resolves to a required right"));
            assert_eq!(
                r,
                Right::new(Resource::System, None, Action::Admin),
                "{path} must require node-global System·Admin"
            );
        }
        // status ⇒ System·Read.
        let status = Right::required("GET", "/api/store-migrate/status").unwrap();
        assert_eq!(status, Right::new(Resource::System, None, Action::Read));

        // CRITICAL: the store migration must NOT inherit the per-project `/api/migrate/` arm, which
        // resolves to Project·Admin on the DEFAULT project. The two must be distinct rights.
        let arm = Right::required("POST", "/api/store-migrate/arm").unwrap();
        let sql_schema = Right::required("POST", "/api/migrate/apply")
            .expect("/api/migrate/* resolves to a required right");
        assert_ne!(
            arm, sql_schema,
            "store-migrate must NOT resolve to the per-project SQL-migration right"
        );
        assert_eq!(arm.resource, Resource::System);
        assert!(
            arm.target.is_none(),
            "store-migrate is node-global, never scoped to a project"
        );

        // A `project_admin` on `default` (which DOES satisfy the per-project /api/migrate/ right) must
        // NOT satisfy the store-migration System·Admin right; nor may publisher/deployer. Only a global
        // admin reaches it.
        let policy = AuthzPolicy::default_policy();
        for grant in [
            GrantedRole::scoped("project_admin", "default"),
            GrantedRole::scoped("publisher", "default/site"),
            GrantedRole::scoped("deployer", "default/site"),
        ] {
            let role = grant.name.clone();
            let rights = policy.rights_for(&[grant]);
            assert!(
                !rights.allows(&arm),
                "role {role} must NOT satisfy the store-migrate System·Admin right"
            );
            assert!(
                !rights.allows(&status),
                "role {role} must NOT satisfy the store-migrate System·Read right"
            );
        }
        let admin = policy.rights_for(&[GrantedRole::global("admin")]);
        assert!(
            admin.allows(&arm),
            "global admin must reach store-migrate arm"
        );
        assert!(
            admin.allows(&status),
            "global admin must reach store-migrate status"
        );
    }
}
