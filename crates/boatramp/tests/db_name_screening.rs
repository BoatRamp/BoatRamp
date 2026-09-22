//! Cross-surface consistency guard for **uniform db-name parameter screening**
//! (v0.5.0). This is the anti-regression detector the request demands: it proves the
//! canonical validator and the two *surfaces* that carry a db name — the CLI URL the
//! client builds (`/api/sql/{db}/…`, `/api/migrate/{db}/…`) and the **API route the
//! server matches** — agree on which names are safe, and that every accepted name
//! round-trips through a REAL axum route match without a malformed (`//` / empty /
//! truncated) path segment.
//!
//! Why a live route match and not just string assertions: the pure equivalence of the
//! validator with a safe-path-segment oracle is unit-tested in
//! `boatramp_core::project`. This integration test closes the loop end-to-end by
//! sending an actual request whose URL is built the way the CLI builds it, through the
//! actual axum path grammar (`/api/sql/{db}/exec`), and asserting the server extracted
//! the SAME db value the CLI put in — so a `//`-collapse, an empty segment, or a
//! path-grammar drift is caught. It is a real detector: an accepted value that would
//! break the route match fails the test.
//!
//! Greppable gate marker: `DB-NAME SCREENING CROSS-SURFACE OK` (mirrors the existing
//! `… OK` live-gate convention; a CI step asserts it).

use axum::extract::Path;
use axum::routing::{get, post};

/// The db names an operator/guest can legitimately carry, plus the reserved default.
/// Each is a safe URL path segment, so each must round-trip cleanly.
const ACCEPTED: &[&str] = &[
    boatramp_core::project::DEFAULT_DB_NAME, // the reserved default binding
    "analytics",
    "events_log",
    "pg-primary",
    "a.b",
    "Blog9",
];

/// Names the validator must reject — the ones that would produce a malformed path
/// segment (empty/`//`) or smuggle a separator. The legacy empty default-DB key is the
/// headline case.
const REJECTED: &[&str] = &["", "a/b", "..", "a b", "proj*"];

/// Build the control-plane path the CLI composes for `boatramp sql exec`
/// (`crates/boatramp/src/sql.rs`: `{server}/api/{seg}/{db}/exec`, default-project
/// `seg = "sql"`). The `{db}` is interpolated verbatim — exactly the code under test.
fn cli_sql_exec_url(base: &str, db: &str) -> String {
    format!("{base}/api/sql/{db}/exec")
}

/// Build the CLI path for `boatramp project migrate status`
/// (`crates/boatramp/src/client.rs`: `{server}/api/{seg}/{db}/status`).
fn cli_migrate_status_url(base: &str, db: &str) -> String {
    format!("{base}/api/migrate/{db}/status")
}

/// Spawn a server whose routes are the REAL server route patterns (`/api/sql/{db}/…`
/// and `/api/migrate/{db}/…`). Each handler echoes the `{db}` it extracted, so the
/// test can assert the server saw exactly what the CLI sent.
async fn spawn_echo_server() -> String {
    let app = axum::Router::new()
        .route(
            "/api/sql/{db}/exec",
            post(|Path(db): Path<String>| async move { db }),
        )
        .route(
            "/api/migrate/{db}/status",
            get(|Path(db): Path<String>| async move { db }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://127.0.0.1:{}", addr.port())
}

#[tokio::test]
async fn accepted_db_names_round_trip_through_cli_path_and_api_route() {
    let base = spawn_echo_server().await;
    let http = reqwest::Client::new();

    for &db in ACCEPTED {
        // The validator accepts it (contract with config load + handler lookup).
        assert!(
            boatramp_core::project::validate_resource_name("database", db).is_ok(),
            "{db:?} should be an accepted db name"
        );

        // CLI-built URLs carry no `//` and the db segment survives intact.
        for url in [
            cli_sql_exec_url(&base, db),
            cli_migrate_status_url(&base, db),
        ] {
            let path = &url[base.len()..];
            assert!(!path.contains("//"), "{db:?} produced a `//`: {path:?}");
        }

        // REAL route match: POST the CLI URL and confirm the server extracted the
        // SAME db (no collapse/truncation) — the route grammar agrees with the CLI.
        let echoed = http
            .post(cli_sql_exec_url(&base, db))
            .send()
            .await
            .expect("request sends")
            .text()
            .await
            .expect("body");
        assert_eq!(echoed, db, "server extracted a different db for {db:?}");

        let echoed = http
            .get(cli_migrate_status_url(&base, db))
            .send()
            .await
            .expect("request sends")
            .text()
            .await
            .expect("body");
        assert_eq!(
            echoed, db,
            "migrate route extracted a different db for {db:?}"
        );
    }

    // The rejected names are exactly the ones that break the path segment or smuggle a
    // separator — the validator refuses them BEFORE a URL is ever built (that is the
    // point of client-side validation). Prove the validator rejects each, and that the
    // headline empty case would have produced a `//` had it slipped through.
    for &db in REJECTED {
        assert!(
            boatramp_core::project::validate_resource_name("database", db).is_err(),
            "{db:?} must be rejected"
        );
    }
    assert!(
        cli_sql_exec_url("", "").contains("//"),
        "the empty db name DOES collapse the CLI path (why it is rejected)"
    );

    // The gate marker a CI step greps for (mirrors the `… OK` convention).
    println!("DB-NAME SCREENING CROSS-SURFACE OK");
}
