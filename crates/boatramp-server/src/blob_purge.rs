//! The general blob purge (`POST /api/blob-purge`, System·Admin, v0.6.4) + the structured blob
//! transition status (`GET /api/blob-status`, System·Read).
//!
//! v0.6.3 added the daemon-mediated blob DRAIN (`POST /api/blob-drain`), which copies the node's
//! configured `[serve.blob_fallback]` secondary → primary. This module adds the two remaining
//! operator surfaces the owner asked for — a GENERAL purge (not migration-only) whose scope is
//! **provably-safe only**, and a way to QUERY the transition state structurally instead of grepping
//! a startup WARNING:
//!
//! ## `POST /api/blob-purge` — a general reclaim, dry-run by default, fail-closed
//! Two modes, both dry-run unless `apply=true`, both streaming an **NDJSON** report (reusing the
//! drain's streaming shape):
//! - **`unreferenced`** — the everyday on-demand garbage-collect front door: it calls
//!   [`DeployStore::collect_garbage`](boatramp_core::deploy) (dry-run or apply), which deletes only
//!   blobs no live manifest points at (nothing serving can break). Because GC's union `list` over a
//!   primary-only `delete` is unsafe while a read-fallback secondary is attached, `collect_garbage`
//!   REFUSES (`PruneUnsafeWithFallback`) an apply-prune in that state; this handler maps that to a
//!   clear **409** ("drop [serve].blob_fallback before an unreferenced GC purge").
//! - **`drained_source`** — the migration decommission: it reclaims the OLD read-only secondary of a
//!   `FallbackStorage` composite by deleting each source key ONLY once it is provably duplicated in
//!   the primary (via [`boatramp_storage::blob_purge::purge_drained_source`], whose safety rests on
//!   the pure [`drained_source_deletable`](boatramp_storage::blob_purge) predicate). No fallback
//!   configured (`drain_pair() == None`) ⇒ **422**.
//!
//! ## `GET /api/blob-status` — structured transition-mode state
//! Returns `{ "blob_fallback_active": <bool> }` (room to grow) so an operator/console can query
//! whether the node is mid-migration (a read-fallback secondary attached) without parsing a log line.
//!
//! Both routes are gated in the authoritative authz table (`/api/blob-purge` → System·Admin,
//! `/api/blob-status` → System·Read) at a SINGULAR HYPHEN path that cannot collide with the
//! `/api/blobs/` (Blobs·Deploy) prefix matcher; `blob-purge` is additionally re-checked
//! defense-in-depth in the handler (mirroring `assert_blob_drain_is_system_admin`).

use super::*;

use boatramp_storage::blob_migrate;
use boatramp_storage::blob_purge::{self, PurgeReport};

/// The mode of a `POST /api/blob-purge`: which provably-safe object set to reclaim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PurgeMode {
    /// Reclaim content-addressed blobs no live deploy manifest references — on-demand garbage
    /// collection (the everyday reclaim). SAFE: nothing serving points at them. Refused (409) while
    /// a read-fallback secondary is attached (GC's union-list/primary-delete asymmetry is unsafe).
    Unreferenced,
    /// Reclaim the OLD read-only secondary of a blob-backend migration by deleting each source key
    /// ONLY once it is provably duplicated (present at matching size) in the primary. Requires a
    /// configured `[serve.blob_fallback]` (else 422). Fail-closed: an unconfirmed key survives.
    DrainedSource,
}

/// The `POST /api/blob-purge` request body. Rejects unknown fields (a typo'd mode/knob is a 422, not
/// a silent default). `apply` defaults to `false` (dry-run — report only, delete nothing); `prefix`
/// restricts the scope (drained-source only) to keys under it.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PurgeRequest {
    /// Which provably-safe object set to reclaim.
    pub mode: PurgeMode,
    /// Actually delete (`true`) vs dry-run report only (`false`, the default).
    #[serde(default)]
    pub apply: bool,
    /// Restrict a `drained_source` purge to source keys under this prefix; `None`/absent ⇒ all.
    /// (Ignored by `unreferenced`, which GCs the whole content-addressed keyspace.)
    #[serde(default)]
    pub prefix: Option<String>,
}

/// Defense-in-depth (mirrors [`assert_blob_drain_is_system_admin`](crate::blob_drain)): re-derive the
/// right the authoritative table requires for `POST /api/blob-purge` and assert it is `System·Admin`
/// before purging. The auth middleware already enforced it; this is a second, independent check so a
/// future routing/table regression can't silently downgrade a node-level destructive purge to a
/// project-scoped right. Returns `Some(403)` if — against expectation — the required right is not
/// `System·Admin`.
fn assert_blob_purge_is_system_admin() -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required("POST", "/api/blob-purge") {
        Some(right)
            if right.resource == Resource::System
                && right.target.is_none()
                && right.action == Action::Admin =>
        {
            None
        }
        _ => Some((StatusCode::FORBIDDEN, "blob purge requires System·Admin\n").into_response()),
    }
}

/// Reclaim a provably-safe blob set (`POST /api/blob-purge`, `System·Admin`), streaming an NDJSON
/// report. Dry-run by default (`apply=false`); `apply=true` deletes.
///
/// - `unreferenced` ⇒ [`DeployStore::collect_garbage`]; a `PruneUnsafeWithFallback` refusal (a
///   read-fallback secondary is attached) is a **409** with a clear JSON error.
/// - `drained_source` ⇒ [`blob_purge::purge_drained_source`] over the composite's `drain_pair`; no
///   fallback ⇒ **422**.
pub(super) async fn blob_purge(
    State(deploy): State<DeployStore>,
    Json(req): Json<PurgeRequest>,
) -> Response {
    // Defense-in-depth: never run a node-level destructive purge unless the authoritative table still
    // gates this path at System·Admin (the middleware already checked; a table regression must not slip).
    if let Some(forbidden) = assert_blob_purge_is_system_admin() {
        return forbidden;
    }

    match req.mode {
        PurgeMode::Unreferenced => purge_unreferenced(&deploy, req.apply).await,
        PurgeMode::DrainedSource => {
            purge_drained_source(&deploy, req.apply, req.prefix.unwrap_or_default()).await
        }
    }
}

/// `unreferenced` mode: on-demand GC of blobs no live manifest references. Emits a start NDJSON line
/// + a final line carrying the [`GcReport`]. A `PruneUnsafeWithFallback` refusal is a 409.
async fn purge_unreferenced(deploy: &DeployStore, apply: bool) -> Response {
    match deploy.collect_garbage(apply).await {
        Ok(report) => {
            // A single start line + a final report line (NDJSON), so the shape matches the
            // drained-source + drain streams (the client consumes both uniformly).
            let start = serde_json::json!({
                "type": "progress",
                "mode": "unreferenced",
                "apply": apply,
                "message": "scanning for unreferenced blobs",
            });
            let final_line = gc_report_line(&report, apply);
            ndjson_response(vec![format!("{start}\n"), final_line])
        }
        // GC refuses an apply-prune while a read-fallback secondary is attached (its union `list`
        // over a primary-only `delete` would phantom-reclaim a secondary-only orphan). Map that to a
        // clear 409 — the operator must drain + drop the fallback first, THEN GC.
        Err(boatramp_core::DeployError::PruneUnsafeWithFallback) => (
            StatusCode::CONFLICT,
            [(header::CONTENT_TYPE, "application/json")],
            "{\"error\":\"an unreferenced GC purge is unsafe while a read-fallback secondary is \
             attached ([serve].blob_fallback): its union list over a primary-only delete would \
             phantom-reclaim a secondary-only orphan. Drain (POST /api/blob-drain or blob purge \
             --drained-source), drop [serve].blob_fallback, restart the node, then purge \
             --unreferenced.\"}\n",
        )
            .into_response(),
        // Any other deploy/storage error: a 500 with the error text (never a silent success).
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "application/json")],
            format!(
                "{{\"error\":{}}}\n",
                serde_json::Value::String(e.to_string())
            ),
        )
            .into_response(),
    }
}

/// `drained_source` mode: reclaim the composite's read-only secondary via the purge engine, streaming
/// NDJSON progress + a final [`PurgeReport`]. No configured fallback ⇒ 422.
async fn purge_drained_source(deploy: &DeployStore, apply: bool, prefix: String) -> Response {
    // The daemon purges EXACTLY its own configured pair — the client names no backends. A single
    // ordinary backend (no `[serve.blob_fallback]`) has no drained secondary ⇒ 422, not a silent no-op.
    let Some(pair) = deploy.storage().drain_pair() else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            [(header::CONTENT_TYPE, "application/json")],
            "{\"error\":\"no blob_fallback configured; there is no drained secondary to purge\"}\n",
        )
            .into_response();
    };

    // A bounded channel of already-serialized NDJSON lines: the engine's progress sink pushes a
    // (single, terminal) progress line via non-blocking `try_send`, then the spawned task pushes the
    // final report line and drops the sender, closing the stream. Same shape as the drain.
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);

    let progress_tx = tx.clone();
    let on_progress: blob_migrate::ProgressSink =
        std::sync::Arc::new(move |p: blob_migrate::MigrateProgress| {
            let _ = progress_tx.try_send(purge_progress_line(&p));
        });

    let source = pair.source.clone();
    let dest = pair.dest.clone();
    tokio::spawn(async move {
        let result =
            blob_purge::purge_drained_source(source, dest, &prefix, apply, Some(on_progress)).await;
        let final_line = purge_report_line(result, apply);
        let _ = tx.send(final_line).await;
        // `tx` (and `progress_tx`, dropped by the sink) drop here → the stream ends.
    });

    let stream = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv()
            .await
            .map(|line| (Ok::<_, std::io::Error>(bytes::Bytes::from(line)), rx))
    });

    let mut resp = Body::from_stream(stream).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    resp
}

/// The structured blob transition-mode state (`GET /api/blob-status`, `System·Read`): whether a
/// read-fallback secondary is currently attached (the node is mid-migration). Answers the owner's
/// "query the state, don't grep a startup WARNING" concern; shaped as an object so it can grow.
pub(super) async fn blob_status(State(deploy): State<DeployStore>) -> Response {
    let active = deploy.storage().drain_pair().is_some();
    Json(serde_json::json!({ "blob_fallback_active": active })).into_response()
}

/// Serialize the final `unreferenced` (GC) report line (trailing `\n`), tagged `"type":"report"`.
fn gc_report_line(report: &GcReport, apply: bool) -> String {
    let message = if apply {
        format!(
            "unreferenced GC complete: removed {} blob(s) ({} byte(s)) and {} orphan manifest(s)",
            report.blobs_removed, report.bytes_reclaimed, report.manifests_removed
        )
    } else {
        format!(
            "dry-run: would remove {} unreferenced blob(s) ({} byte(s)) and {} orphan manifest(s)",
            report.blobs_removed, report.bytes_reclaimed, report.manifests_removed
        )
    };
    let value = serde_json::json!({
        "type": "report",
        "mode": "unreferenced",
        "apply": apply,
        "manifests_total": report.manifests_total,
        "manifests_removed": report.manifests_removed,
        "blobs_total": report.blobs_total,
        "blobs_removed": report.blobs_removed,
        "bytes_reclaimed": report.bytes_reclaimed,
        "message": message,
    });
    format!("{value}\n")
}

/// Serialize one drained-source purge progress snapshot to an NDJSON line (trailing `\n`), tagged
/// `"type":"progress"`. The engine emits a single terminal snapshot (a head+delete pass has no
/// per-object cadence), so this mostly carries the running totals for a large purge.
fn purge_progress_line(p: &blob_migrate::MigrateProgress) -> String {
    format!(
        "{}\n",
        serde_json::json!({
            "type": "progress",
            "mode": "drained_source",
            "done": p.done,
            "total": p.total,
            "purged": p.copied,
            "skipped_unconfirmed": p.skipped,
            "purged_bytes": p.copied_bytes,
            "dry_run": p.dry_run,
        })
    )
}

/// Serialize the FINAL drained-source purge report line (trailing `\n`), tagged `"type":"report"`.
/// On success it carries the [`PurgeReport`] fields; on a storage error it carries `error` + a
/// human message (the client exits non-zero).
fn purge_report_line(result: Result<PurgeReport, blob_purge::PurgeError>, apply: bool) -> String {
    let value = match result {
        Ok(report) => {
            let message = if apply {
                format!(
                    "drained-source purge complete: reclaimed {} confirmed-duplicated object(s) \
                     ({} byte(s)); kept {} unconfirmed",
                    report.purged, report.purged_bytes, report.skipped_unconfirmed
                )
            } else {
                format!(
                    "dry-run: would reclaim {} confirmed-duplicated object(s); would keep {} \
                     unconfirmed ({} considered)",
                    report.would_purge, report.skipped_unconfirmed, report.considered
                )
            };
            serde_json::json!({
                "type": "report",
                "mode": "drained_source",
                "apply": apply,
                "considered": report.considered,
                "purged": report.purged,
                "would_purge": report.would_purge,
                "skipped_unconfirmed": report.skipped_unconfirmed,
                "purged_bytes": report.purged_bytes,
                "message": message,
            })
        }
        Err(e) => serde_json::json!({
            "type": "report",
            "mode": "drained_source",
            "apply": apply,
            "error": e.to_string(),
            "message": format!("drained-source purge FAILED: {e}"),
        }),
    };
    format!("{value}\n")
}

/// Build a static-body NDJSON response from a set of pre-serialized (trailing-`\n`) lines — used by
/// the `unreferenced` mode, whose GC is a single call (no streaming engine) so the lines are known
/// up front. `drained_source` streams via `Body::from_stream` instead.
fn ndjson_response(lines: Vec<String>) -> Response {
    let body = lines.concat();
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-ndjson")],
        body,
    )
        .into_response()
}

// ================================================================================================
// Route-level integration for the ROBUST purge gate (v0.6.4). Ordinary `#[tokio::test]`s — NO
// feature flag, NO env-var seam, NO println marker: they drive the REAL handlers over a REAL
// `DeployStore`, and their pass/fail (the test-runner exit code) is the contract. These complement
// the pure-predicate + engine mutation-matrix tests in `boatramp_storage::blob_purge` (the safety
// decision lives there); here we cover the two ROUTE behaviors the storage engine can't:
//   (d) an `unreferenced` apply-purge is REFUSED (409) while a read-fallback secondary is attached;
//   (e) a `drained_source` purge with no configured fallback is a 422;
// plus the happy-path drained-source through the handler (fail-closed survivors), and the authz
// arms (System·Admin / System·Read at a hyphen path that can't collide with `/api/blobs/`).
// ================================================================================================
#[cfg(test)]
mod route_tests {
    use super::*;
    use boatramp_core::Storage;
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::kv::MemoryKv;
    use boatramp_storage::{FallbackStorage, FallbackWhen, FsStorage};
    use std::sync::Arc;
    use std::time::Duration;

    fn allow_all() -> FallbackWhen {
        Arc::new(|_k: &str| true)
    }

    async fn put(store: &Arc<dyn Storage>, key: &str, bytes: &[u8]) {
        use boatramp_core::{ByteStream, PutMeta};
        use futures::StreamExt;
        let owned = bytes.to_vec();
        let body: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from(owned)) }).boxed();
        store
            .put(key, body, PutMeta::default())
            .await
            .expect("seed put");
    }

    async fn head_ok(store: &Arc<dyn Storage>, key: &str) -> bool {
        store.head(key).await.is_ok()
    }

    /// Read the whole response body, returning the LAST NDJSON `"type":"report"` line as JSON (or the
    /// single JSON object for a plain body).
    async fn last_report(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("collect body");
        let text = String::from_utf8_lossy(&bytes);
        let mut last = None;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line.trim())
                && v.get("type").and_then(serde_json::Value::as_str) == Some("report")
            {
                last = Some(v);
            }
        }
        last.unwrap_or_else(|| serde_json::from_str(text.trim()).unwrap_or(serde_json::Value::Null))
    }

    /// A `DeployStore` over a `FallbackStorage(primary=fs, secondary=fs)` seeded MID-DRAIN: a
    /// confirmed-duplicated key, an absent-from-primary key, and a size-mismatched key.
    async fn fallback_deploy(
        tmp: &std::path::Path,
    ) -> (DeployStore, Arc<dyn Storage>, Arc<dyn Storage>) {
        let primary: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.join("primary")));
        let secondary: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.join("secondary")));
        // CONFIRMED (both, matching), ABSENT (secondary only), MISMATCH (both, different sizes).
        put(&secondary, "hblob/p~s/confirmed", b"drained-confirmed").await;
        put(&primary, "hblob/p~s/confirmed", b"drained-confirmed").await;
        put(&secondary, "hblob/p~s/absent", b"never-drained").await;
        put(&secondary, "hblob/p~s/mismatch", b"the-full-original").await;
        put(&primary, "hblob/p~s/mismatch", b"short").await;
        let composite: Arc<dyn Storage> = Arc::new(FallbackStorage::new(
            primary.clone(),
            secondary.clone(),
            allow_all(),
            Duration::from_secs(5),
        ));
        let deploy = DeployStore::new(composite, Arc::new(MemoryKv::new()));
        (deploy, primary, secondary)
    }

    // ---- (d) unreferenced apply refused (409) while a fallback is attached ----------------------

    #[tokio::test]
    async fn unreferenced_apply_refused_409_with_fallback() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (deploy, _primary, _secondary) = fallback_deploy(tmp.path()).await;

        // apply=true ⇒ collect_garbage refuses (PruneUnsafeWithFallback) ⇒ 409.
        let resp = purge_unreferenced(&deploy, true).await;
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "an unreferenced apply-purge must be refused 409 while a read-fallback secondary is attached"
        );

        // A DRY-RUN unreferenced purge is NOT refused (collect_garbage(false) is a report, unaffected
        // by the fallback) — it returns a 200 report.
        let dry = purge_unreferenced(&deploy, false).await;
        assert_eq!(
            dry.status(),
            StatusCode::OK,
            "a dry-run unreferenced purge is a report, unaffected by the fallback"
        );
    }

    #[tokio::test]
    async fn unreferenced_apply_ok_without_fallback() {
        // A plain (non-fallback) backend allows an apply-prune (nothing to reclaim here ⇒ empty
        // report, but a 200 — proving the 409 above is specifically the fallback refusal).
        let tmp = tempfile::tempdir().expect("tempdir");
        let plain: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("plain")));
        let deploy = DeployStore::new(plain, Arc::new(MemoryKv::new()));
        let resp = purge_unreferenced(&deploy, true).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "an apply-prune is allowed on a plain backend (no fallback)"
        );
    }

    // ---- (e) drained-source with no configured fallback ⇒ 422 -----------------------------------

    #[tokio::test]
    async fn drained_source_no_fallback_422() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let plain: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("plain")));
        let deploy = DeployStore::new(plain, Arc::new(MemoryKv::new()));

        let resp = purge_drained_source(&deploy, true, String::new()).await;
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a drained-source purge with no [serve.blob_fallback] must be 422 (never a silent no-op)"
        );
    }

    // ---- (a/b/c through the handler) drained-source apply is fail-closed ------------------------

    #[tokio::test]
    async fn drained_source_apply_is_fail_closed_through_handler() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (deploy, primary, secondary) = fallback_deploy(tmp.path()).await;

        // apply=true, whole keyspace: only the confirmed-duplicated key is purged.
        let resp = purge_drained_source(&deploy, true, String::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let report = last_report(resp).await;
        assert_eq!(report["mode"], "drained_source");
        assert_eq!(report["considered"], 3);
        assert_eq!(
            report["purged"], 1,
            "only the confirmed-duplicated key is purged"
        );
        assert_eq!(
            report["skipped_unconfirmed"], 2,
            "the absent + mismatched keys are kept (fail-closed)"
        );

        // The confirmed key is gone from the source; the primary (dest) still has it; the two
        // unconfirmed source keys SURVIVE.
        assert!(!head_ok(&secondary, "hblob/p~s/confirmed").await);
        assert!(head_ok(&primary, "hblob/p~s/confirmed").await);
        assert!(
            head_ok(&secondary, "hblob/p~s/absent").await,
            "fail-closed: an absent-from-primary source key survives"
        );
        assert!(
            head_ok(&secondary, "hblob/p~s/mismatch").await,
            "fail-closed: a size-mismatched source key survives"
        );
    }

    #[tokio::test]
    async fn drained_source_dry_run_deletes_nothing_through_handler() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (deploy, _primary, secondary) = fallback_deploy(tmp.path()).await;

        let resp = purge_drained_source(&deploy, false, String::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let report = last_report(resp).await;
        assert_eq!(report["purged"], 0, "dry-run deletes nothing");
        assert_eq!(report["would_purge"], 1, "dry-run counts the confirmed key");
        for k in [
            "hblob/p~s/confirmed",
            "hblob/p~s/absent",
            "hblob/p~s/mismatch",
        ] {
            assert!(head_ok(&secondary, k).await, "dry-run kept {k}");
        }
    }

    // ---- blob-status structured state -----------------------------------------------------------

    #[tokio::test]
    async fn blob_status_reflects_fallback_presence() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (deploy, _p, _s) = fallback_deploy(tmp.path()).await;
        let resp = blob_status(State(deploy)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let v: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(v["blob_fallback_active"], true);

        let plain: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("plain")));
        let deploy2 = DeployStore::new(plain, Arc::new(MemoryKv::new()));
        let resp2 = blob_status(State(deploy2)).await;
        let bytes2 = axum::body::to_bytes(resp2.into_body(), usize::MAX)
            .await
            .expect("body");
        let v2: serde_json::Value = serde_json::from_slice(&bytes2).expect("json");
        assert_eq!(v2["blob_fallback_active"], false);
    }

    // ---- authz arms: System·Admin / System·Read at a non-colliding hyphen path ------------------

    #[test]
    fn authz_arms_are_correct_and_non_colliding() {
        use boatramp_core::authz::{Action, AuthzPolicy, GrantedRole, Resource, Right};

        // POST /api/blob-purge ⇒ System·Admin (a node-level destructive op, like drain/prune/scrub).
        let purge = Right::required("POST", "/api/blob-purge")
            .expect("POST /api/blob-purge resolves to a required right");
        assert_eq!(
            purge,
            Right::new(Resource::System, None, Action::Admin),
            "POST /api/blob-purge must require System·Admin, not a project-scoped right"
        );

        // GET /api/blob-status ⇒ System·Read (a read-only node status like /api/sites, /api/metrics).
        let status = Right::required("GET", "/api/blob-status")
            .expect("GET /api/blob-status resolves to a required right");
        assert_eq!(
            status,
            Right::new(Resource::System, None, Action::Read),
            "GET /api/blob-status must require System·Read"
        );

        // Neither collides with the `/api/blobs/<hash>` (Blobs·Deploy) prefix matcher — the SINGULAR
        // hyphen path is why (`starts_with("/api/blobs/")` is false for `/api/blob-purge|status`).
        let blobs = Right::required("PUT", "/api/blobs/abc123")
            .expect("/api/blobs/<hash> resolves to a required right");
        assert_eq!(blobs, Right::new(Resource::Blobs, None, Action::Deploy));
        assert_ne!(purge, blobs, "blob-purge must not resolve to Blobs·Deploy");
        assert_ne!(
            status, blobs,
            "blob-status must not resolve to Blobs·Deploy"
        );

        // A ship-only publisher/deployer/project_admin must NOT satisfy the destructive purge's right.
        let policy = AuthzPolicy::default_policy();
        for grant in [
            GrantedRole::scoped("publisher", "default/site"),
            GrantedRole::scoped("deployer", "default/site"),
            GrantedRole::scoped("project_admin", "default"),
        ] {
            let role = grant.name.clone();
            let rights = policy.rights_for(&[grant]);
            assert!(
                !rights.allows(&purge),
                "role {role} must NOT satisfy the blob-purge System·Admin right"
            );
        }
        let admin = policy.rights_for(&[GrantedRole::global("admin")]);
        assert!(admin.allows(&purge), "admin must reach blob-purge");
        assert!(admin.allows(&status), "admin must reach blob-status");
    }
}
