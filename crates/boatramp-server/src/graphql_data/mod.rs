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

pub(crate) mod schema;
pub(crate) mod sdl;
