//! GraphQL edge query-guard: parse an incoming operation and decide whether it is
//! within a site's depth/complexity limits and introspection policy — **before** the
//! handler runs.
//!
//! Pure and deterministic — no I/O. This is defense-in-depth over the per-request fuel
//! cap: a query that is cheap per field but pathologically deep or wide (a classic
//! GraphQL denial-of-service) is rejected at the edge. boatramp stays GraphQL-*aware*,
//! not a GraphQL engine: it parses only far enough to measure depth/breadth and spot
//! introspection; execution semantics stay in the handler.

use graphql_parser::query::{Definition, Document, OperationDefinition, Selection, SelectionSet};
use std::collections::{HashMap, HashSet};

/// The site's GraphQL guard limits (resolved from `[handlers.graphql]`).
#[derive(Debug, Clone)]
pub(crate) struct GraphqlLimits {
    /// Deepest allowed selection-set nesting (fragments expanded).
    pub max_depth: u32,
    /// Largest allowed total field count (a schema-free complexity proxy).
    pub max_complexity: u32,
    /// Whether an introspection query (`__schema` / `__type` at the root) is allowed.
    pub allow_introspection: bool,
}

/// The guard's decision for one operation.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GuardVerdict {
    /// The query is within limits and may run.
    Allow,
    /// The query is refused; the string is a client-facing reason for a GraphQL error.
    Reject(String),
}

/// Largest POST body the edge guard will buffer to inspect the query. A GraphQL
/// request (query + variables) is small; a larger body is passed through unguarded
/// rather than buffered, so this can't become a memory-exhaustion vector.
pub(crate) const MAX_QUERY_BYTES: usize = 1024 * 1024;

/// A GraphQL-shaped `400` error (`{"errors":[{"message": …}]}`) for a rejected query.
pub(crate) fn error_response(reason: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    let body = serde_json::json!({ "errors": [ { "message": reason } ] }).to_string();
    (
        axum::http::StatusCode::BAD_REQUEST,
        [(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

/// Default depth limit when the site config doesn't set one — generous for real APIs,
/// tight enough to stop a pathologically nested query.
const DEFAULT_MAX_DEPTH: u32 = 15;
/// Default field-count (complexity) limit when the site config doesn't set one.
const DEFAULT_MAX_COMPLEXITY: u32 = 1000;

/// Build the runtime limits from the site's `[handlers.graphql]` config. Introspection
/// is **off unless explicitly enabled** (the safe default; a posture-aware default is a
/// later refinement).
pub(crate) fn limits_from(cfg: &boatramp_core::config::HandlerGraphqlConfig) -> GraphqlLimits {
    GraphqlLimits {
        max_depth: cfg.max_depth.unwrap_or(DEFAULT_MAX_DEPTH),
        max_complexity: cfg.max_complexity.unwrap_or(DEFAULT_MAX_COMPLEXITY),
        allow_introspection: cfg.introspection.unwrap_or(false),
    }
}

/// Extract the GraphQL query text from a request body: a JSON `{"query": "…"}` payload
/// (the common transport) or a raw `application/graphql` body. Returns `None` when the
/// body isn't a recognizable GraphQL request (the guard then lets it through — the
/// handler will reject a non-GraphQL POST itself).
pub(crate) fn query_from_body(content_type: Option<&str>, body: &[u8]) -> Option<String> {
    if content_type.is_some_and(|ct| ct.contains("application/graphql")) {
        return Some(String::from_utf8_lossy(body).into_owned());
    }
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    value.get("query")?.as_str().map(str::to_string)
}

/// Parse `query` and check it against `limits`. An unparsable query is rejected (the
/// handler would reject it anyway; failing at the edge is cheaper and consistent).
/// The document is parsed to owned strings so the AST needs only one borrow lifetime.
pub(crate) fn guard_query(query: &str, limits: &GraphqlLimits) -> GuardVerdict {
    let doc = match graphql_parser::query::parse_query::<String>(query) {
        Ok(doc) => doc,
        Err(err) => return GuardVerdict::Reject(format!("invalid GraphQL query: {err}")),
    };
    if !limits.allow_introspection && has_root_introspection(&doc) {
        return GuardVerdict::Reject("introspection is disabled".to_string());
    }
    let (depth, complexity) = measure(&doc);
    if depth > limits.max_depth {
        return GuardVerdict::Reject(format!(
            "query depth {depth} exceeds the limit of {}",
            limits.max_depth
        ));
    }
    if complexity > limits.max_complexity {
        return GuardVerdict::Reject(format!(
            "query complexity {complexity} exceeds the limit of {}",
            limits.max_complexity
        ));
    }
    GuardVerdict::Allow
}

/// The selection set of any operation shape (named query/mutation/subscription or the
/// bare `{ … }` shorthand). `'a` is the AST's content lifetime; `'b` the borrow.
fn operation_selection_set<'a, 'b>(
    op: &'b OperationDefinition<'a, String>,
) -> &'b SelectionSet<'a, String> {
    match op {
        OperationDefinition::Query(q) => &q.selection_set,
        OperationDefinition::Mutation(m) => &m.selection_set,
        OperationDefinition::Subscription(s) => &s.selection_set,
        OperationDefinition::SelectionSet(ss) => ss,
    }
}

/// Whether any operation selects `__schema` or `__type` at its root — a schema
/// introspection query. `__typename` (allowed anywhere) is deliberately not counted.
fn has_root_introspection(doc: &Document<'_, String>) -> bool {
    doc.definitions.iter().any(|def| {
        let Definition::Operation(op) = def else {
            return false;
        };
        operation_selection_set(op).items.iter().any(
            |sel| matches!(sel, Selection::Field(f) if f.name == "__schema" || f.name == "__type"),
        )
    })
}

/// Measure `(max depth, total field count)` across every operation, expanding named
/// fragments (cycle-guarded) so a query can't hide depth behind a fragment.
fn measure(doc: &Document<'_, String>) -> (u32, u32) {
    let fragments: HashMap<&str, &SelectionSet<'_, String>> = doc
        .definitions
        .iter()
        .filter_map(|def| match def {
            Definition::Fragment(f) => Some((f.name.as_str(), &f.selection_set)),
            _ => None,
        })
        .collect();

    let mut max_depth = 0;
    let mut complexity = 0;
    for def in &doc.definitions {
        if let Definition::Operation(op) = def {
            let mut visiting = HashSet::new();
            let (d, c) = walk(operation_selection_set(op), &fragments, 1, &mut visiting);
            max_depth = max_depth.max(d);
            complexity += c;
        }
    }
    (max_depth, complexity)
}

/// Recursively measure one selection set: `depth` is the nesting level of the fields in
/// `ss`; a field with children recurses at `depth + 1`. Returns the deepest level
/// reached and the number of fields counted.
fn walk<'a, 'b>(
    ss: &'b SelectionSet<'a, String>,
    fragments: &HashMap<&'b str, &'b SelectionSet<'a, String>>,
    depth: u32,
    visiting: &mut HashSet<&'b str>,
) -> (u32, u32) {
    let mut max_depth = depth;
    let mut count = 0;
    for sel in &ss.items {
        match sel {
            Selection::Field(field) => {
                count += 1;
                if !field.selection_set.items.is_empty() {
                    let (d, c) = walk(&field.selection_set, fragments, depth + 1, visiting);
                    max_depth = max_depth.max(d);
                    count += c;
                }
            }
            // Inline fragments contribute their fields at the same depth.
            Selection::InlineFragment(inline) => {
                let (d, c) = walk(&inline.selection_set, fragments, depth, visiting);
                max_depth = max_depth.max(d);
                count += c;
            }
            // A named fragment expands to its selection set at the same depth; the
            // `visiting` set breaks a fragment cycle (which the parser permits).
            Selection::FragmentSpread(spread) => {
                let name = spread.fragment_name.as_str();
                if visiting.insert(name) {
                    if let Some(frag_ss) = fragments.get(name) {
                        let (d, c) = walk(frag_ss, fragments, depth, visiting);
                        max_depth = max_depth.max(d);
                        count += c;
                    }
                    visiting.remove(name);
                }
            }
        }
    }
    (max_depth, count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits(max_depth: u32, max_complexity: u32, allow_introspection: bool) -> GraphqlLimits {
        GraphqlLimits {
            max_depth,
            max_complexity,
            allow_introspection,
        }
    }

    #[test]
    fn flat_query_is_depth_one() {
        let v = guard_query("{ a b c }", &limits(3, 100, true));
        assert_eq!(v, GuardVerdict::Allow);
    }

    #[test]
    fn nested_query_depth_is_measured_and_capped() {
        // a > b > c  is depth 3.
        let q = "{ a { b { c } } }";
        assert_eq!(guard_query(q, &limits(3, 100, true)), GuardVerdict::Allow);
        match guard_query(q, &limits(2, 100, true)) {
            GuardVerdict::Reject(r) => assert!(r.contains("depth 3") && r.contains("limit of 2")),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn complexity_counts_all_fields_including_nested() {
        // a, b, c, d = 4 fields.
        let q = "{ a { b c } d }";
        assert_eq!(guard_query(q, &limits(10, 4, true)), GuardVerdict::Allow);
        match guard_query(q, &limits(10, 3, true)) {
            GuardVerdict::Reject(r) => assert!(r.contains("complexity 4")),
            other => panic!("expected reject, got {other:?}"),
        }
    }

    #[test]
    fn fragments_are_expanded_for_depth_so_they_cannot_hide_nesting() {
        // Without expansion this looks shallow; expanded it is a { b { c } } = depth 3.
        let q = "{ a { ...F } } fragment F on T { b { c } }";
        assert_eq!(guard_query(q, &limits(3, 100, true)), GuardVerdict::Allow);
        assert!(matches!(
            guard_query(q, &limits(2, 100, true)),
            GuardVerdict::Reject(_)
        ));
    }

    #[test]
    fn a_fragment_cycle_does_not_loop_forever() {
        // The parser accepts a cyclic fragment; the guard must terminate.
        let q = "{ a { ...F } } fragment F on T { b { ...F } }";
        // Just assert it returns (any verdict) without hanging.
        let _ = guard_query(q, &limits(100, 100, true));
    }

    #[test]
    fn introspection_is_gated() {
        let q = "{ __schema { types { name } } }";
        assert!(matches!(
            guard_query(q, &limits(100, 100, false)),
            GuardVerdict::Reject(r) if r.contains("introspection")
        ));
        assert_eq!(guard_query(q, &limits(100, 100, true)), GuardVerdict::Allow);
        // __typename is not introspection.
        assert_eq!(
            guard_query("{ a __typename }", &limits(100, 100, false)),
            GuardVerdict::Allow
        );
    }

    #[test]
    fn unparsable_query_is_rejected() {
        assert!(matches!(
            guard_query("{ a { b ", &limits(10, 10, true)),
            GuardVerdict::Reject(r) if r.contains("invalid GraphQL")
        ));
    }
}
