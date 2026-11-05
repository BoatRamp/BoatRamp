//! Live capability gate for the node-side SELECTIVE-SYNC KV endpoint
//! (`GET`/`POST /api/project-kv-stratum`) that `project sync` carries the NON-SECRET control-plane
//! KV strata over (settings / graphql / history) — the gap this release closes.
//!
//! It stands up TWO in-process nodes — a SOURCE `router()` over one `DeployStore` and a DEST
//! `router()` over another — and drives the REAL endpoints end-to-end over the real axum stack
//! (`tower::oneshot`), the same idiom the `dns_publish_serve_wiring` / clone gates use. No Docker,
//! no managed DB: the transport is pure control-plane KV, so two in-memory stores suffice.
//!
//! What it asserts (each a release precondition):
//!   1. **Round-trip + coherence.** settings/graphql/history read from the SOURCE land byte-for-byte
//!      on the DEST, under the DEST's own project prefixes.
//!   2. **History→siteconfig dependency (PLAN rule 3).** A `current/`/`history/` pointer whose site
//!      has a config body on the dest CARRIES; one whose site does NOT is SKIPPED-and-reported,
//!      never written — the dest's prior state left intact.
//!   3. **Idempotent resync.** A second carry of the unchanged source re-writes the same bytes and
//!      leaves the dest identical (same source ⇒ same state).
//!   4. **Cross-tenant isolation (the ≥2-tenant tenancy gate, MANDATORY for a KV transport).** With
//!      the SOURCE holding BOTH tenant `acme` and tenant `globex`, a sync NAMING `acme` reads ZERO
//!      of `globex`'s keys; and a crafted write body carrying a `globex`/global/sealed key under an
//!      `acme`-scoped write is REFUSED fail-closed, leaving `globex` on the dest with ZERO bytes.
//!
//! `#[ignore]`d + wired into `.github/workflows/capability.yml` as a HARD gate that asserts the
//! success marker, so a silent skip or a scoping regression fails the merge (the
//! ignore-gated-tests-not-evidence discipline). Run locally with:
//!   `cargo test -p boatramp-server --test project_kv_stratum_sync_live -- --ignored --nocapture`

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use base64::Engine;
use boatramp_core::config::SiteConfig;
use boatramp_core::deploy::DeployStore;
use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_core::project::ProjectRef;
use boatramp_server::{Auth, HandlerRuntime, router};
use boatramp_storage::FsStorage;
use tower::ServiceExt;

type App = axum::Router;

/// A node = a `DeployStore` (its KV held for seeding/verification) + the REAL full `router()` over
/// it with auth disabled (the token layer; the handler's own `Project·Admin` re-check still runs).
struct Node {
    kv: Arc<MemoryKv>,
    deploy: DeployStore,
    app: App,
}

fn node(tag: &str) -> Node {
    let kv = Arc::new(MemoryKv::new());
    let dir = std::env::temp_dir().join(format!("br-kv-stratum-{tag}-{}", std::process::id()));
    let storage = Arc::new(FsStorage::new(dir));
    let deploy = DeployStore::new(storage, kv.clone());
    let app = router(deploy.clone(), Auth::disabled(), HandlerRuntime::disabled());
    Node { kv, deploy, app }
}

fn b64(v: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(v)
}

/// The SOURCE read: `GET /api/project-kv-stratum?project=&piece=`. Returns `(status, json)`.
async fn read_stratum(app: &App, project: &str, piece: &str) -> (StatusCode, serde_json::Value) {
    let uri = format!("/api/project-kv-stratum?project={project}&piece={piece}");
    let mut r = Request::builder()
        .method("GET")
        .uri(&uri)
        .body(Body::empty())
        .unwrap();
    r.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let resp = app.clone().oneshot(r).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// The DEST write: `POST /api/project-kv-stratum?project=&piece=` with a body. Returns `(status, json)`.
async fn write_stratum(
    app: &App,
    project: &str,
    piece: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let uri = format!("/api/project-kv-stratum?project={project}&piece={piece}");
    let mut r = Request::builder()
        .method("POST")
        .uri(&uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    r.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let resp = app.clone().oneshot(r).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// Build a `source_project`+entries write body from a read response's entries (the exact relay the
/// CLI executor performs), with the given coherence excludes.
fn relay_body(src_project: &str, read: &serde_json::Value, excludes: &[&str]) -> serde_json::Value {
    serde_json::json!({
        "source_project": src_project,
        "exclude_prefixes": excludes,
        "entries": read["entries"].clone(),
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "capability gate: run via ci.yml / capability.yml live-gate-kv-stratum-sync or with --ignored"]
async fn kv_stratum_sync_gate() {
    let src = node("src");
    let dst = node("dst");

    // ---- Seed the SOURCE: tenant `acme` (the one we sync) AND tenant `globex` (the victim) -------
    // acme settings + graphql.
    src.kv
        .put(
            "project/acme/config/tenancy",
            br#"{"schema":"acme-v1"}"#.to_vec(),
        )
        .await
        .unwrap();
    src.kv
        .put("graphql/acme/web", b"type Query { ok: Boolean }".to_vec())
        .await
        .unwrap();
    src.kv
        .put("hapq/acme/sha-abc", b"query { ok }".to_vec())
        .await
        .unwrap();
    // acme history for two sites: `web` (will be coherent on the dest) + `ghost` (will NOT be).
    src.kv
        .put("project/acme/current/web", b"deploy-web-1".to_vec())
        .await
        .unwrap();
    src.kv
        .put(
            "project/acme/current-principal/web",
            b"system:deploy-web-1".to_vec(),
        )
        .await
        .unwrap();
    src.kv
        .put(
            "project/acme/history/web",
            br#"[{"id":"deploy-web-1"}]"#.to_vec(),
        )
        .await
        .unwrap();
    src.kv
        .put("project/acme/current/ghost", b"deploy-ghost-1".to_vec())
        .await
        .unwrap();
    src.kv
        .put(
            "project/acme/history/ghost",
            br#"[{"id":"deploy-ghost-1"}]"#.to_vec(),
        )
        .await
        .unwrap();
    // globex (tenant B) — the keys a sync of `acme` must NEVER read or carry.
    src.kv
        .put(
            "project/globex/config/tenancy",
            br#"{"schema":"globex-SECRET"}"#.to_vec(),
        )
        .await
        .unwrap();
    src.kv
        .put(
            "graphql/globex/web",
            b"type Query { secret: String }".to_vec(),
        )
        .await
        .unwrap();
    src.kv
        .put("project/globex/current/web", b"globex-deploy".to_vec())
        .await
        .unwrap();

    // ---- The DEST already serves acme's `web` site (so history/web is coherent) but NOT `ghost` --
    dst.deploy
        .set_site_config(ProjectRef::new("acme"), "web", &SiteConfig::default())
        .await
        .unwrap();

    // ============================================================================================
    // 1) ROUND-TRIP + COHERENCE: settings + graphql carry byte-for-byte onto the dest.
    // ============================================================================================
    for (piece, keys) in [
        ("settings", vec!["project/acme/config/tenancy"]),
        ("graphql", vec!["graphql/acme/web", "hapq/acme/sha-abc"]),
    ] {
        let (st, read) = read_stratum(&src.app, "acme", piece).await;
        assert_eq!(st, StatusCode::OK, "source read of {piece} is 200");
        // The source slice carries ONLY acme keys — ZERO globex (cross-tenant read isolation).
        let read_keys: Vec<&str> = read["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["key"].as_str().unwrap())
            .collect();
        assert!(
            read_keys.iter().all(|k| !k.contains("globex")),
            "{piece} source slice leaked a globex key: {read_keys:?}"
        );
        for k in &keys {
            assert!(read_keys.contains(k), "{piece} slice missing {k}");
        }

        let (st, wrote) =
            write_stratum(&dst.app, "acme", piece, relay_body("acme", &read, &[])).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "dest write of {piece} is 200: {wrote:?}"
        );
        assert!(
            wrote["skipped"].as_array().unwrap().is_empty(),
            "{piece} nothing skipped"
        );

        // The bytes landed on the dest, identical to the source.
        for k in &keys {
            let got = dst.kv.get(k).await.unwrap();
            let want = src.kv.get(k).await.unwrap();
            assert_eq!(got, want, "{piece} key {k} did not land byte-identical");
        }
    }

    // ============================================================================================
    // 2) HISTORY→SITECONFIG DEPENDENCY: `web` (coherent) carries; `ghost` (no dest config) skips.
    // ============================================================================================
    let (st, read) = read_stratum(&src.app, "acme", "history").await;
    assert_eq!(st, StatusCode::OK);
    let (st, wrote) =
        write_stratum(&dst.app, "acme", "history", relay_body("acme", &read, &[])).await;
    assert_eq!(st, StatusCode::OK, "history write is 200: {wrote:?}");

    // web's pointers landed…
    assert_eq!(
        dst.kv.get("project/acme/current/web").await.unwrap(),
        Some(b"deploy-web-1".to_vec()),
        "coherent site `web` current pointer carried"
    );
    assert!(
        dst.kv
            .get("project/acme/history/web")
            .await
            .unwrap()
            .is_some(),
        "coherent site `web` history carried"
    );
    // …ghost's did NOT (skipped + reported, dest prior state intact = absent).
    assert!(
        dst.kv
            .get("project/acme/current/ghost")
            .await
            .unwrap()
            .is_none(),
        "incoherent site `ghost` current pointer must NOT be written"
    );
    let skipped = wrote["skipped"].as_array().unwrap();
    assert!(
        skipped
            .iter()
            .any(|s| s["key"].as_str().unwrap().contains("ghost")
                && s["reason"].as_str().unwrap().contains("siteconfig")),
        "history must skip-and-report ghost's pointers (dependency): {skipped:?}"
    );

    // ============================================================================================
    // 3) IDEMPOTENT RESYNC: re-carry settings; the dest value is unchanged (same source ⇒ same).
    // ============================================================================================
    let (_st, read) = read_stratum(&src.app, "acme", "settings").await;
    let (st, _wrote) =
        write_stratum(&dst.app, "acme", "settings", relay_body("acme", &read, &[])).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(
        dst.kv.get("project/acme/config/tenancy").await.unwrap(),
        src.kv.get("project/acme/config/tenancy").await.unwrap(),
        "resync is idempotent (same bytes)"
    );

    // ============================================================================================
    // 4) CROSS-TENANT ISOLATION: the mandatory ≥2-tenant tenancy gate (ZERO foreign bytes).
    // ============================================================================================
    // (a) A crafted write NAMING acme but carrying a globex key (source_project=acme ⇒ no re-key, so
    //     the key stays `project/globex/…`) is REFUSED — it is outside acme's settings prefix.
    let evil_globex = serde_json::json!({
        "source_project": "acme",
        "exclude_prefixes": [],
        "entries": [{ "key": "project/globex/config/tenancy", "value_b64": b64(b"PWNED") }],
    });
    let (st, _) = write_stratum(&dst.app, "acme", "settings", evil_globex).await;
    assert_eq!(
        st,
        StatusCode::FORBIDDEN,
        "a cross-tenant globex key under an acme write is refused"
    );

    // (b) A crafted write carrying a GLOBAL routing key is refused (not under any acme piece prefix).
    let evil_global = serde_json::json!({
        "source_project": "acme",
        "exclude_prefixes": [],
        "entries": [{ "key": "domain/victim.example", "value_b64": b64(b"PWNED") }],
    });
    let (st, _) = write_stratum(&dst.app, "acme", "settings", evil_global).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "a global routing key is refused");

    // (c) A crafted write carrying a SEALED secret key (target-owned but sealed) is refused.
    let evil_sealed = serde_json::json!({
        "source_project": "acme",
        "exclude_prefixes": [],
        "entries": [{ "key": "project/acme/secret/stripe", "value_b64": b64(b"PWNED") }],
    });
    let (st, _) = write_stratum(&dst.app, "acme", "settings", evil_sealed).await;
    assert_eq!(st, StatusCode::FORBIDDEN, "a sealed-secret key is refused");

    // (d) The `secrets` piece itself is refused outright over this endpoint (sealed, never crosses).
    let (st, _) = read_stratum(&src.app, "acme", "secrets").await;
    assert_eq!(
        st,
        StatusCode::BAD_REQUEST,
        "the secrets piece is not carryable here"
    );

    // (e) ZERO FOREIGN BYTES: after every refused write, the dest holds NOT ONE globex key, and no
    //     global routing / sealed acme key the crafted writes tried to plant.
    let globex_on_dest = dst.kv.list_prefix("project/globex/").await.unwrap();
    assert!(
        globex_on_dest.is_empty(),
        "tenant globex has ZERO bytes on the dest: {globex_on_dest:?}"
    );
    assert!(dst.kv.get("domain/victim.example").await.unwrap().is_none());
    assert!(
        dst.kv
            .get("project/acme/secret/stripe")
            .await
            .unwrap()
            .is_none()
    );

    println!(
        "KV STRATUM SYNC GATE OK: settings+graphql+history carried coherent+idempotent; history→siteconfig dependency skipped ghost; cross-tenant acme-only read + fail-closed write left globex with zero bytes"
    );
}
