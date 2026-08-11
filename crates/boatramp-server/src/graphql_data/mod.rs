//! The declarative GraphQL **data connector**: a GraphQL API generated from a managed
//! database.
//!
//! boatramp already runs the site's database as a managed workload and owns the
//! connection, credentials, and per-tenant isolation. This connector turns that database
//! into a GraphQL API with no resolver code: it introspects the schema, generates the
//! GraphQL SDL, and answers each query by compiling it to **one deterministic,
//! parameterized SQL statement** — a *compiler*, never an execution engine. A query it
//! cannot lower is rejected, not partially run; execution happens in the database, which
//! already has correct semantics.
//!
//! It composes with the wasm-resolver model (GraphQL→Wasi) through the federation
//! `SubgraphRunner` seam, and sits underneath the existing aware-edge (guard, persisted
//! queries, cache). Exposure is deny-by-default and fail-closed — a database-derived API
//! must never leak by default.
//!
//! Landing incrementally: the schema model + SDL generation first, then policy, the query
//! compiler, introspection + serving, relationships, federation, and mutations.
#![allow(dead_code)] // wired into serving by a later landing

pub(crate) mod compile;
pub(crate) mod dialect;
pub(crate) mod introspect;
pub(crate) mod policy;
pub(crate) mod runner;
pub(crate) mod schema;
pub(crate) mod sdl;

use boatramp_core::config::HandlerGraphqlDataConfig;
use boatramp_core::sql::SqlValue;
use policy::{Claims, DataPolicy, RowOp, RowPredicate, RowTerm, RowValue, TablePolicy};
use std::collections::BTreeMap;

/// Build the connector's [`DataPolicy`] from a site's `[handlers.graphql.data]` config.
/// Deny-by-default is inherent: only the configured tables/columns become exposed.
pub(crate) fn policy_from_config(cfg: &HandlerGraphqlDataConfig) -> DataPolicy {
    let mut policy = DataPolicy::new();
    for (table, table_cfg) in &cfg.tables {
        let mut table_policy = TablePolicy::columns(table_cfg.columns.iter().cloned());
        if !table_cfg.row_filter.is_empty() {
            table_policy = table_policy.with_rows(RowPredicate {
                terms: table_cfg
                    .row_filter
                    .iter()
                    .map(|term| RowTerm {
                        column: term.column.clone(),
                        op: RowOp::Eq,
                        value: RowValue::Claim(term.claim.clone()),
                    })
                    .collect(),
            });
        }
        policy = policy.with_table(table.clone(), table_policy);
    }
    policy
}

/// The host-asserted request claims a row predicate binds against. The tenant `project` is
/// always available and host-asserted; verified token claims can extend this later.
pub(crate) fn request_claims(project: &str) -> Claims {
    Claims::new(BTreeMap::from([(
        "project".to_string(),
        SqlValue::Text(project.to_string()),
    )]))
}
