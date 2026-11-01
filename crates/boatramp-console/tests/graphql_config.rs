//! Tests for the GraphQL console slice's load-bearing, DOM-free logic.
//!
//! Like `tests/overlay_policy.rs`, this binary deliberately does NOT call
//! `wasm_bindgen_test_configure!(run_in_browser)`, so it runs under Node (which
//! this repo's wasm test lane provides) rather than requiring a browser driver —
//! nothing here touches the DOM. It exercises the real re-exported logic + the
//! real wire-mirror types, so a regression in the safelist invariant or a drift
//! between a GraphQL-registry response and its typed model is caught here.

use boatramp_console::{SafelistOp, SupergraphSummary, set_enforce_safelist};
use boatramp_types::config::{HandlerGraphqlConfig, SiteConfig};
use wasm_bindgen_test::*;

/// The plan invariant: enabling safelist enforcement is strictly stronger than
/// APQ, so it also turns persisted queries on; disabling enforcement leaves the
/// (independent) APQ flag as it was.
#[wasm_bindgen_test]
fn enforce_safelist_implies_persisted_queries() {
    let mut g = HandlerGraphqlConfig::default();
    assert!(!g.enforce_safelist);
    assert!(!g.persisted_queries);

    set_enforce_safelist(&mut g, true);
    assert!(g.enforce_safelist, "enforcement set");
    assert!(
        g.persisted_queries,
        "enforcement implies persisted queries (safelist is stronger)"
    );

    // Disabling enforcement does not forcibly turn APQ off (they are distinct).
    set_enforce_safelist(&mut g, false);
    assert!(!g.enforce_safelist, "enforcement cleared");
    assert!(
        g.persisted_queries,
        "APQ left as-is when enforcement cleared"
    );
}

/// The composed-supergraph summary deserializes from the server's
/// `graphql_registry::summary_json` shape, including the `rootQuery` /
/// `rootMutation` camelCase keys (a rename the model must honor).
#[wasm_bindgen_test]
fn supergraph_summary_deserializes_server_shape() {
    let json = r#"{
        "subgraphs": ["accounts", "reviews"],
        "entities": { "User": { "key": "id", "subgraphs": ["accounts", "reviews"] } },
        "rootQuery": { "me": "accounts", "topReviews": "reviews" },
        "rootMutation": { "addReview": "reviews" }
    }"#;
    let s: SupergraphSummary = serde_json::from_str(json).expect("summary deserializes");
    assert_eq!(s.subgraphs, vec!["accounts", "reviews"]);
    assert_eq!(s.root_query.get("me").map(String::as_str), Some("accounts"));
    assert_eq!(
        s.root_mutation.get("addReview").map(String::as_str),
        Some("reviews")
    );
    let user = s.entities.get("User").expect("User entity present");
    assert_eq!(user.key, "id");
    assert_eq!(user.subgraphs, vec!["accounts", "reviews"]);
}

/// An empty project (no registered subgraphs) still deserializes cleanly — the
/// view renders the "nothing composed" empty state rather than erroring.
#[wasm_bindgen_test]
fn empty_supergraph_summary_deserializes() {
    let s: SupergraphSummary = serde_json::from_str("{}").expect("empty summary deserializes");
    assert!(s.subgraphs.is_empty());
    assert!(s.root_query.is_empty());
    assert!(s.entities.is_empty());
}

/// A safelist row deserializes from the server's `{ hash, query }` shape, both
/// as a single row and as the list the manager renders.
#[wasm_bindgen_test]
fn safelist_op_deserializes() {
    let one: SafelistOp =
        serde_json::from_str(r#"{ "hash": "deadbeef", "query": "query { me { id } }" }"#)
            .expect("one op deserializes");
    assert_eq!(one.hash, "deadbeef");
    assert_eq!(one.query, "query { me { id } }");

    let list: Vec<SafelistOp> = serde_json::from_str(
        r#"[{ "hash": "a1", "query": "query A { a }" }, { "hash": "b2", "query": "query B { b }" }]"#,
    )
    .expect("op list deserializes");
    assert_eq!(list.len(), 2);
    assert_eq!(list[1].hash, "b2");
}

/// No-data-loss: a `SiteConfig` carrying the new GraphQL + cookie-auth blocks
/// round-trips through the verbatim `from_json` → `to_json` → `from_json` path
/// (the console's save contract) with every field — and the unrelated sibling
/// (`domains.primary`) — preserved intact.
#[wasm_bindgen_test]
fn site_config_graphql_round_trip_preserves_siblings() {
    let json = r#"{
        "domains": { "primary": "example.com" },
        "handlers": {
            "enabled": true,
            "allow_imports": ["graphql", "sql"],
            "graphql": {
                "enabled": true,
                "max_depth": 12,
                "introspection": false,
                "persisted_queries": true,
                "enforce_safelist": true,
                "federated": true,
                "data": {
                    "enabled": true,
                    "source": "appdb",
                    "tables": { "orders": { "columns": ["id", "total"],
                                            "row_filter": [{ "column": "tenant", "claim": "tid" }] } }
                }
            },
            "cookie_auth": { "cookie_name": "__Host-session",
                             "allowed_origins": ["https://app.example.com"] }
        }
    }"#;

    let cfg = SiteConfig::from_json(json.as_bytes()).expect("initial parse");
    let bytes = cfg.to_json().expect("serialize");
    let again = SiteConfig::from_json(&bytes).expect("reparse");

    // Sibling preserved.
    assert_eq!(again.domains.primary.as_deref(), Some("example.com"));

    let h = again.handlers.expect("handlers present");
    assert!(h.enabled);
    assert!(h.allow_imports.iter().any(|i| i == "graphql"));

    let g = h.graphql.expect("graphql present");
    assert!(g.enabled);
    assert_eq!(g.max_depth, Some(12));
    assert_eq!(g.introspection, Some(false));
    assert!(g.enforce_safelist);
    assert!(g.persisted_queries);
    assert!(g.federated);

    let d = g.data.expect("data connector present");
    assert!(d.enabled);
    assert_eq!(d.source, "appdb");
    let orders = d.tables.get("orders").expect("orders table present");
    assert_eq!(orders.columns, vec!["id", "total"]);
    assert_eq!(orders.row_filter.len(), 1);
    assert_eq!(orders.row_filter[0].column, "tenant");
    assert_eq!(orders.row_filter[0].claim, "tid");

    let ca = h.cookie_auth.expect("cookie_auth present");
    assert_eq!(ca.cookie_name, "__Host-session");
    assert_eq!(ca.allowed_origins, vec!["https://app.example.com"]);
}
