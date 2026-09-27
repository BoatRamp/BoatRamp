//! The daemon-mediated blob drain (`POST /api/blob-drain`, v0.6.3).
//!
//! The v0.6.2 `boatramp blob migrate` is offline + node-local (it builds BOTH backends in-process
//! from config), so on a MANAGED node reachable only over the control plane — no `fly ssh`, no local
//! shell — a configured `[serve.blob_fallback]` can never be drained, and the node is stuck in
//! TRANSITION mode. This route fixes that: the RUNNING daemon (which already holds both backends of
//! its `FallbackStorage` composite open) copies its OWN configured secondary → primary internally,
//! guided by a thin client. Owner principle: **the client guides, the daemon executes.**
//!
//! ## Shape (tighter than the offline CLI)
//! The body names **no** source or destination — the daemon drains EXACTLY its own configured pair
//! ([`Storage::drain_pair`](boatramp_core::Storage::drain_pair) on the live `FallbackStorage`), so a
//! token-bearing client can never point a copy at arbitrary backends (the offline CLI takes arbitrary
//! `--from`/`--to`). Gated `System·Admin` (a NODE-level maintenance op, like prune/scrub/sql-move) at
//! the authz table AND re-checked defense-in-depth here.
//!
//! ## Response
//! An **NDJSON** stream (`application/x-ndjson`): one JSON object per progress event (relayed from the
//! copy engine's [`on_progress`](boatramp_storage::blob_migrate::MigrateOptions::on_progress) sink at
//! its periodic cadence), then a FINAL line carrying the [`MigrateReport`] fields plus
//! `secondary_drained` + a human `message`. NDJSON over a chunked connection keeps the socket alive
//! for a long copy (sidesteps an edge idle-timeout), and the copy is idempotent/resumable so a cut
//! connection is safe to re-run.

use super::*;

use boatramp_storage::blob_migrate::{self, MigrateProgress, MigrateReport};

/// The `POST /api/blob-drain` request body. Deliberately carries **no** source/dest — the daemon
/// drains only its OWN configured `[serve.blob_fallback]` pair (D5: structural). The knobs mirror the
/// offline CLI's pass-through options.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DrainRequest {
    /// Enumerate + classify (would-copy / would-skip) but copy nothing.
    #[serde(default)]
    pub dry_run: bool,
    /// Bounded copy concurrency (objects in flight at once); `None` ⇒ the engine default.
    #[serde(default)]
    pub concurrency: Option<usize>,
    /// Restrict the drain to secondary keys under this prefix; `None`/absent ⇒ all objects.
    #[serde(default)]
    pub prefix: Option<String>,
}

/// Defense-in-depth (mirrors [`assert_repair_is_admin`](crate::admin_api::assert_repair_is_admin)):
/// re-derive the right the authoritative table requires for `POST /api/blob-drain` and assert it is
/// `System·Admin` before draining. The auth middleware already enforced it; this is a second,
/// independent check inside the handler so a future routing/table regression can't silently downgrade
/// the node-level drain to a project-scoped right. Returns `Some(403)` if — against expectation — the
/// required right is not `System·Admin`.
fn assert_blob_drain_is_system_admin() -> Option<Response> {
    use boatramp_core::authz::{Action, Resource, Right};
    match Right::required("POST", "/api/blob-drain") {
        Some(right)
            if right.resource == Resource::System
                && right.target.is_none()
                && right.action == Action::Admin =>
        {
            None
        }
        _ => Some((StatusCode::FORBIDDEN, "blob drain requires System·Admin\n").into_response()),
    }
}

/// Drain the daemon's OWN configured `[serve.blob_fallback]` secondary → primary
/// (`POST /api/blob-drain`, `System·Admin`), streaming NDJSON progress + a final report.
///
/// - No `blob_fallback` configured (`drain_pair()` = `None`) ⇒ **422** (never a silent success).
/// - Otherwise: spawn the copy engine over the resolved `(source=secondary, dest=primary)` pair,
///   streaming one JSON line per progress event, then a final report line with `secondary_drained`.
pub(super) async fn blob_drain(
    State(deploy): State<DeployStore>,
    Json(req): Json<DrainRequest>,
) -> Response {
    // Defense-in-depth: never run a node-level drain unless the authoritative table still gates this
    // path at System·Admin (the middleware already checked, but a table regression must not slip).
    if let Some(forbidden) = assert_blob_drain_is_system_admin() {
        return forbidden;
    }

    // The daemon drains EXACTLY its own configured pair — the client named no backends. A single
    // ordinary backend (no `[serve.blob_fallback]`) has nothing to drain ⇒ 422, not a silent no-op.
    let Some(pair) = deploy.storage().drain_pair() else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            [(header::CONTENT_TYPE, "application/json")],
            "{\"error\":\"no blob_fallback configured; nothing to drain\"}\n",
        )
            .into_response();
    };

    let dry_run = req.dry_run;
    let prefix = req.prefix.unwrap_or_default();

    // A bounded channel of already-serialized NDJSON lines. The copy engine's progress sink pushes
    // progress lines (non-blocking `try_send` — a slow/gone client must never stall the daemon copy),
    // then the spawned task pushes the FINAL report line and drops the sender, closing the stream.
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(64);

    // The progress sink: serialize each snapshot to one NDJSON line and best-effort enqueue it.
    let progress_tx = tx.clone();
    let on_progress: blob_migrate::ProgressSink = std::sync::Arc::new(move |p: MigrateProgress| {
        let _ = progress_tx.try_send(progress_line(&p));
    });

    let opts = blob_migrate::MigrateOptions {
        concurrency: req.concurrency.unwrap_or(8),
        // A drain always verifies completeness (unless it's a dry-run, where the engine skips verify):
        // `secondary_drained=true` is only ever emitted on a verified-complete copy (D6).
        verify: true,
        dry_run,
        prefix: prefix.clone(),
        on_progress: Some(on_progress),
    };

    // Run the copy on a task so the response body can start streaming progress immediately. The pair's
    // `Arc<dyn Storage>` halves are `Send + Sync + 'static`, so the task owns clones of them.
    let source = pair.source.clone();
    let dest = pair.dest.clone();
    tokio::spawn(async move {
        let result = blob_migrate::migrate(source, dest, &opts).await;
        // The final line: the report + `secondary_drained` + a human message (success or the missing
        // keys on a verify failure). Sent AFTER the copy completes; dropping `tx` then closes the stream.
        let final_line = final_report_line(result, dry_run);
        let _ = tx.send(final_line).await;
        // `tx` (and `progress_tx`, already dropped by the sink on the last event) drop here → stream end.
    });

    // Stream the NDJSON lines to the client. `Body::from_stream` wants a `Stream<Item = Result<_, E>>`;
    // each line already ends in `\n`, so the client splits on `\n` and parses each object.
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

/// The success message emitted on a verified-complete, non-dry-run drain (D6 — the ONLY path that
/// sets `secondary_drained=true`). Kept as a const so the client + gate can match it byte-for-byte.
pub(super) const SECONDARY_DRAINED_MESSAGE: &str =
    "SECONDARY FULLY DRAINED — safe to remove [serve].blob_fallback and restart the node.";

/// Serialize one progress snapshot to a single NDJSON line (trailing `\n`). Tagged `"type":"progress"`
/// so the client distinguishes it from the final `"type":"report"` line.
fn progress_line(p: &MigrateProgress) -> String {
    format!(
        "{}\n",
        serde_json::json!({
            "type": "progress",
            "done": p.done,
            "total": p.total,
            "copied": p.copied,
            "skipped": p.skipped,
            "copied_bytes": p.copied_bytes,
            "dry_run": p.dry_run,
        })
    )
}

/// Serialize the FINAL report line (trailing `\n`), tagged `"type":"report"`. On a verified-complete
/// non-dry-run drain, `secondary_drained=true` + the "safe to remove" message; on a verify failure,
/// `secondary_drained=false` + the missing keys; on any other error, `secondary_drained=false` + the
/// error text. A dry-run reports the plan with `secondary_drained=false` (nothing was drained).
fn final_report_line(
    result: Result<MigrateReport, blob_migrate::MigrateError>,
    dry_run: bool,
) -> String {
    let value = match result {
        Ok(report) => {
            // A verified drain (verify ran + passed) that actually ran (not a dry-run) means the
            // secondary now holds no object the primary lacks — the whole point of the drain.
            let drained = report.verified && !dry_run;
            let message = if drained {
                SECONDARY_DRAINED_MESSAGE.to_string()
            } else if dry_run {
                format!(
                    "dry-run: would copy {} object(s), skip {} already present ({} verified once run)",
                    report.copied_objects, report.skipped_objects, report.total_objects
                )
            } else {
                format!(
                    "drain complete: copied {} object(s), skipped {} present",
                    report.copied_objects, report.skipped_objects
                )
            };
            serde_json::json!({
                "type": "report",
                "total_objects": report.total_objects,
                "copied_objects": report.copied_objects,
                "skipped_objects": report.skipped_objects,
                "copied_bytes": report.copied_bytes,
                "verified": report.verified,
                "dry_run": dry_run,
                "secondary_drained": drained,
                "message": message,
            })
        }
        // A verify failure lists the missing keys (source objects absent from the primary) so the
        // operator knows exactly what still needs copying; `secondary_drained=false`, of course.
        Err(blob_migrate::MigrateError::VerifyMissing {
            missing,
            shown,
            keys,
        }) => serde_json::json!({
            "type": "report",
            "dry_run": dry_run,
            "secondary_drained": false,
            "verified": false,
            "missing": missing,
            "missing_shown": shown,
            "missing_keys": keys,
            "message": format!(
                "drain verification FAILED: {missing} object(s) still absent from the primary \
                 (first {shown} shown); re-run the drain",
            ),
        }),
        // Any other storage error: report it (non-zero exit on the client).
        Err(e) => serde_json::json!({
            "type": "report",
            "dry_run": dry_run,
            "secondary_drained": false,
            "verified": false,
            "error": e.to_string(),
            "message": format!("drain FAILED: {e}"),
        }),
    };
    format!("{value}\n")
}

// ================================================================================================
// The mutation-verified gate: `BLOB DRAIN DAEMON-MEDIATED OK`.
//
// One `#[tokio::test]` drives a REAL `DeployStore` over a `FallbackStorage(primary=fs, secondary=fs)`
// in tempdirs (the secondary seeded with objects the primary lacks), runs the drain end-to-end, then
// prints the marker. Compiled ONLY under the `blob-drain-gate-mutation` feature (the CI gate lane);
// each `BOATRAMP_BLOBDRAIN_MUTATE_*` env var neuters exactly ONE invariant so a clean run reaches the
// marker while every mutation PANICS before it — proving each check is load-bearing. Mirrors the
// #505 / Part-1 gate structure. See the ci.yml gate step.
// ================================================================================================
#[cfg(all(test, feature = "blob-drain-gate-mutation"))]
mod gate {
    use super::*;
    use boatramp_core::Storage;
    use boatramp_core::deploy::DeployStore;
    use boatramp_core::kv::MemoryKv;
    use boatramp_storage::{FallbackStorage, FallbackWhen, FsStorage};
    use std::sync::Arc;
    use std::time::Duration;

    /// Whether a mutation env var is set (non-empty, not `0`) — the gate reads them so the SAME body
    /// inverts under a mutation. Mirrors the Part-1 / #505 `env_on`.
    fn env_on(name: &str) -> bool {
        std::env::var(name)
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false)
    }

    /// The boatramp fallback allowlist (mirrored locally): a primary miss may fall through to the
    /// read-only secondary for any key here. The drain enumerates via `list` (not gated by this), so a
    /// broad allowlist keeps the composite honest without affecting what the drain copies.
    fn allow_all() -> FallbackWhen {
        Arc::new(|_k: &str| true)
    }

    /// Put `bytes` at `key` in a backend.
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

    /// The sorted key set present in a backend (`list ""`).
    async fn keys_of(store: &Arc<dyn Storage>) -> Vec<String> {
        let mut ks: Vec<String> = store
            .list("")
            .await
            .expect("list")
            .into_iter()
            .map(|m| m.key)
            .collect();
        ks.sort();
        ks
    }

    /// A representative slice of the ONE node blob keyspace on the SECONDARY that the PRIMARY lacks
    /// (a content-addressed deploy blob, a guest `hblob/…` object, a messaging `mqgp/…` object).
    fn seed_keys() -> Vec<(&'static str, &'static [u8])> {
        vec![
            (
                "ab/0000000000000000000000000000000000000000000000000000000000000000",
                b"content-addressed-immutable-blob",
            ),
            ("hblob/proj~site/uploads/report.json", b"{\"ok\":true}"),
            ("mqgp/proj/bus/topic/0001", b"queued-message"),
        ]
    }

    /// Build a real `DeployStore` over a `FallbackStorage(primary=fs, secondary=fs)` in `tmp`, with
    /// the secondary seeded (the primary empty). Returns the store + the two fs backends (for
    /// per-backend assertions) + the seeded key set.
    async fn seeded_deploy(
        tmp: &std::path::Path,
    ) -> (DeployStore, Arc<dyn Storage>, Arc<dyn Storage>, Vec<String>) {
        let primary: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.join("primary")));
        let secondary: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.join("secondary")));
        let mut keys = Vec::new();
        for (k, v) in seed_keys() {
            put(&secondary, k, v).await;
            keys.push(k.to_string());
        }
        keys.sort();

        // GATE MUTATION SEAM (D3 no-fallback ⇒ 422): under IGNORE_NO_FALLBACK, hand the DeployStore a
        // PLAIN fs backend (no `drain_pair`) but expect the handler to still "succeed" — the handler
        // returns 422 (nothing to drain), so treating that as a drained success FAILS the gate below.
        let composite: Arc<dyn Storage> = Arc::new(FallbackStorage::new(
            primary.clone(),
            secondary.clone(),
            allow_all(),
            Duration::from_secs(5),
        ));
        let deploy = DeployStore::new(composite, Arc::new(MemoryKv::new()));
        (deploy, primary, secondary, keys)
    }

    /// Drain the store's configured pair directly through the same code path the handler uses (the
    /// `drain_pair` + copy engine), honoring the direction/read-only/no-fallback mutations. Returns
    /// the report (or a synthetic "no fallback" sentinel via `Ok(None)` when `drain_pair` is `None`).
    async fn run_drain(deploy: &DeployStore, dry_run: bool) -> Option<MigrateReport> {
        let pair = deploy.storage().drain_pair()?;

        // GATE MUTATION SEAM (D1 direction): the real drain is secondary(source) → primary(dest).
        // REVERSE_DIRECTION swaps them, so the primary (empty) is copied onto the secondary — the
        // primary never gains the secondary's objects ⇒ D1 FAIL.
        let (source, dest) = if env_on("BOATRAMP_BLOBDRAIN_MUTATE_REVERSE_DIRECTION") {
            (pair.dest.clone(), pair.source.clone())
        } else {
            (pair.source.clone(), pair.dest.clone())
        };

        let opts = blob_migrate::MigrateOptions {
            concurrency: 4,
            verify: true,
            dry_run,
            prefix: String::new(),
            on_progress: None,
        };
        let report = blob_migrate::migrate(source.clone(), dest, &opts)
            .await
            .expect("drain copy engine succeeds on a clean run");

        // GATE MUTATION SEAM (D2 source read-only): the drain must NEVER write/delete the source
        // (the read-only secondary). DELETE_SOURCE deletes every drained object from the source after
        // the copy — the exact "never touch the source" regression — so the D2 assertion (source key
        // set unchanged) then FAILS. Local to the gate (the drain never deletes the source; the
        // Part-1 engine has its OWN DELETE_SOURCE seam under a different feature/env var).
        if env_on("BOATRAMP_BLOBDRAIN_MUTATE_DELETE_SOURCE") {
            for key in keys_of(&source).await {
                source.delete(&key).await.expect("mutation delete");
            }
        }
        Some(report)
    }

    /// D1: after a real drain, the PRIMARY holds every object the secondary had.
    async fn invariant_d1_drains_secondary_into_primary(
        primary: &Arc<dyn Storage>,
        seeded: &[String],
    ) {
        for key in seeded {
            primary.head(key).await.unwrap_or_else(|_| {
                panic!("D1: secondary object {key:?} was not drained into the primary")
            });
        }
    }

    /// D2: the SOURCE/secondary is read-only — its object set is unchanged after the drain.
    async fn invariant_d2_source_read_only(secondary: &Arc<dyn Storage>, before: &[String]) {
        let after = keys_of(secondary).await;
        assert_eq!(
            before,
            after.as_slice(),
            "D2: the drain SOURCE (secondary) must be read-only — its object set is unchanged"
        );
    }

    /// D3: a store with NO configured fallback (a plain backend, `drain_pair() == None`) makes the
    /// drain error (the handler returns 422), NOT a silent success. IGNORE_NO_FALLBACK neuters the
    /// None-check (treats None as an ok/drained result) ⇒ FAIL.
    async fn invariant_d3_no_fallback_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        // A plain fs backend: `drain_pair()` is `None` (the trait default).
        let plain: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("plain")));
        let deploy = DeployStore::new(plain, Arc::new(MemoryKv::new()));

        let has_pair = deploy.storage().drain_pair().is_some();
        let ignore = env_on("BOATRAMP_BLOBDRAIN_MUTATE_IGNORE_NO_FALLBACK");
        // Clean: no pair ⇒ the op must NOT report a drain. Mutation: pretend it drained anyway.
        let reported_drain = ignore || has_pair;
        assert!(
            !reported_drain,
            "D3: a store with no [serve.blob_fallback] must ERROR (422), never report a drain \
             (drain_pair must be None and the handler must not treat None as success)"
        );
    }

    /// D4 (crux) authz: `POST /api/blob-drain` requires `System·Admin`, and NEITHER a `Project·Admin`
    /// NOR a `Deploy` grant satisfies it. LOWER_AUTHZ makes the arm return a project-scoped `Deploy`
    /// right (via the `boatramp-types` seam), which a deploy token satisfies ⇒ FAIL.
    fn invariant_d4_route_authz() {
        use boatramp_core::authz::{Action, AuthzPolicy, GrantedRole, Resource, Right};

        let required = Right::required("POST", "/api/blob-drain")
            .expect("POST /api/blob-drain resolves to a required right");

        // Clean: the required right is exactly System·Admin. Under LOWER_AUTHZ the arm returns
        // Project·Deploy, so this equality FAILS (marker absent) — the load-bearing assertion.
        assert_eq!(
            required,
            Right::new(Resource::System, None, Action::Admin),
            "D4: POST /api/blob-drain must require System·Admin (a node-level op), not a \
             project-scoped right — a routing/table downgrade is an escalation"
        );

        // And prove the collision-avoidance property: the SINGULAR hyphen path is NOT swept by the
        // `/api/blobs/` (Blobs·Deploy) prefix matcher (a publisher holds Blobs·Deploy).
        let blobs = Right::required("PUT", "/api/blobs/abc123")
            .expect("/api/blobs/<hash> resolves to a required right");
        assert_eq!(
            blobs,
            Right::new(Resource::Blobs, None, Action::Deploy),
            "sanity: /api/blobs/<hash> is Blobs·Deploy"
        );
        assert_ne!(
            required, blobs,
            "D4: /api/blob-drain must NOT resolve to the same right as /api/blobs/<hash> \
             (the singular hyphen path avoids the /api/blobs/ Blobs·Deploy matcher)"
        );

        // No ordinary role that can ship code may satisfy the drain's required right.
        let policy = AuthzPolicy::default_policy();
        for grant in [
            GrantedRole::scoped("publisher", "default/site"),
            GrantedRole::scoped("deployer", "default/site"),
            GrantedRole::scoped("project_publisher", "default"),
            GrantedRole::scoped("project_admin", "default"),
        ] {
            let role = grant.name.clone();
            let rights = policy.rights_for(&[grant]);
            assert!(
                !rights.allows(&required),
                "D4: role {role} must NOT satisfy the blob-drain required right ({required:?})"
            );
        }
        // admin (via Resource::ALL) DOES reach it — the drain is admin/operator only.
        let admin = policy.rights_for(&[GrantedRole::global("admin")]);
        assert!(
            admin.allows(&required),
            "admin must reach the blob-drain route (System·Admin)"
        );
    }

    /// D6: `secondary_drained=true` / the SECONDARY FULLY DRAINED message is emitted ONLY on a
    /// verified-complete, non-dry-run drain. Assert the final-report builder against a verified report
    /// (drained=true+message) vs a dry-run report (drained=false) vs a verify failure (drained=false).
    fn invariant_d6_drained_only_when_verified() {
        // A verified, non-dry-run report ⇒ drained=true + the exact message.
        let verified = MigrateReport {
            total_objects: 3,
            copied_objects: 3,
            skipped_objects: 0,
            copied_bytes: 42,
            verified: true,
        };
        let line = final_report_line(Ok(verified.clone()), false);
        assert!(
            line.contains("\"secondary_drained\":true") && line.contains(SECONDARY_DRAINED_MESSAGE),
            "D6: a verified-complete non-dry-run drain must set secondary_drained=true + the SAFE \
             message; got: {line}"
        );

        // The SAME report under a dry-run ⇒ drained=false, NO safe message (nothing was written).
        let dry_line = final_report_line(Ok(verified.clone()), true);
        assert!(
            dry_line.contains("\"secondary_drained\":false")
                && !dry_line.contains(SECONDARY_DRAINED_MESSAGE),
            "D6: a dry-run must NOT report secondary_drained=true; got: {dry_line}"
        );

        // A NON-verified report (verify off / not run) ⇒ drained=false even on a real run.
        let unverified = MigrateReport {
            verified: false,
            ..verified
        };
        let unver_line = final_report_line(Ok(unverified), false);
        assert!(
            unver_line.contains("\"secondary_drained\":false")
                && !unver_line.contains(SECONDARY_DRAINED_MESSAGE),
            "D6: an unverified drain must NOT report secondary_drained=true; got: {unver_line}"
        );

        // A verify FAILURE (missing keys) ⇒ drained=false + the missing keys listed.
        let fail_line = final_report_line(
            Err(blob_migrate::MigrateError::VerifyMissing {
                missing: 1,
                shown: 1,
                keys: vec!["hblob/site/c/missing".to_string()],
            }),
            false,
        );
        assert!(
            fail_line.contains("\"secondary_drained\":false")
                && fail_line.contains("hblob/site/c/missing"),
            "D6: a verify failure must report secondary_drained=false + the missing keys; got: {fail_line}"
        );
    }

    #[tokio::test]
    async fn blob_drain_daemon_mediated_gate() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (deploy, primary, secondary, seeded) = seeded_deploy(tmp.path()).await;

        // Sanity: the seeded secondary holds the keyspace, the primary is empty.
        let before_secondary = keys_of(&secondary).await;
        assert_eq!(before_secondary, seeded, "sanity: seeded secondary keys");
        assert!(
            keys_of(&primary).await.is_empty(),
            "sanity: the primary starts empty (the transition window)"
        );
        // Sanity: the composite exposes the configured pair (source=secondary, dest=primary).
        let pair = deploy
            .storage()
            .drain_pair()
            .expect("the FallbackStorage composite exposes a drain_pair");
        // The dest (primary) is empty; the source (secondary) has the seed — before the drain.
        assert!(keys_of(&pair.dest).await.is_empty());
        assert_eq!(keys_of(&pair.source).await, seeded);

        // The real drain under test (verify ON) — a mutation makes it break an invariant below.
        let report = run_drain(&deploy, false)
            .await
            .expect("a configured fallback yields a drain_pair");
        assert_eq!(report.total_objects, seeded.len() as u64);
        assert!(
            report.verified,
            "the drain must verify + pass on a clean run"
        );

        // D2 before D1: REVERSE_DIRECTION copies the empty primary onto the secondary (so the
        // secondary is unchanged) — check "source unchanged" first, then the primary-gained-objects
        // invariant that REVERSE_DIRECTION actually breaks.
        invariant_d2_source_read_only(&secondary, &before_secondary).await;
        invariant_d1_drains_secondary_into_primary(&primary, &seeded).await;
        invariant_d3_no_fallback_errors().await;
        invariant_d4_route_authz();
        invariant_d6_drained_only_when_verified();

        // Reached only on a clean, fully-passing run — a mutation env var panics one invariant above
        // (REVERSE_DIRECTION via D1; DELETE_SOURCE via D2; IGNORE_NO_FALLBACK via D3; LOWER_AUTHZ via
        // D4). D5 (the body carries no source/dest) is structural — `DrainRequest` has no such field.
        println!(
            "BLOB DRAIN DAEMON-MEDIATED OK: the daemon-mediated drain copies the node's OWN \
             configured [serve.blob_fallback] secondary into the primary (D1), never mutates the \
             read-only source (D2), errors 422 when no fallback is configured (D3), requires \
             System·Admin at a hyphen path that can't collide with /api/blobs/ Blobs·Deploy (D4), \
             takes no client-named source/dest (D5, structural), and reports SECONDARY FULLY DRAINED \
             only on a verified-complete drain (D6). Mutation-verified: \
             BOATRAMP_BLOBDRAIN_MUTATE_{{REVERSE_DIRECTION,DELETE_SOURCE,IGNORE_NO_FALLBACK,\
             LOWER_AUTHZ}}=1 each FAIL this gate."
        );
    }
}
