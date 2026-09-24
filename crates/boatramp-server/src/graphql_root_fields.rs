//! Shared root-field enumeration for the edge query walks.
//!
//! Three edge-side walks need to know *every root field an operation selects*, by field
//! **name** (not alias): the federation planner's root grouping ([`crate::graphql_plan`]),
//! the target-eligibility ceiling ([`crate::graphql_gateway::target_root_fields`]), and the
//! introspection gate ([`crate::graphql_guard`]). Each historically inspected only the
//! operation's top-level `Selection::Field` and **silently skipped** `FragmentSpread` /
//! `InlineFragment` — a latent bypass (a fragment-wrapped `__schema` slips past the
//! introspection-off gate; a fragment-wrapped edge-hidden or target root field evades its
//! guard). This module is the single place that expands fragments so no walk can be
//! fragment-blind again.
//!
//! The expansion is modelled on [`crate::graphql_guard`]'s `walk`: it descends inline
//! fragments and named fragment spreads and is **cycle-guarded** (the parser accepts a
//! cyclic fragment; enumeration must terminate). Pure and deterministic.

use async_graphql_parser::types::{
    ExecutableDocument, FragmentDefinition, OperationDefinition, OperationType, Selection,
    SelectionSet,
};
use async_graphql_parser::Positioned;
use async_graphql_value::Name;
use std::collections::{HashMap, HashSet};

/// The GraphQL root operation type a root field belongs to. `Display`s as the type name
/// (`"Query"` / `"Mutation"` / `"Subscription"`) the supergraph's `edge_hidden_roots` keys on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootType {
    Query,
    Mutation,
    Subscription,
}

impl RootType {
    /// The GraphQL type name for this root — the exact spelling used as the first element of an
    /// `edge_hidden_roots` `(root_type, field)` pair.
    pub(crate) fn type_name(self) -> &'static str {
        match self {
            Self::Query => "Query",
            Self::Mutation => "Mutation",
            Self::Subscription => "Subscription",
        }
    }

    fn from_operation(ty: OperationType) -> Self {
        match ty {
            OperationType::Query => Self::Query,
            OperationType::Mutation => Self::Mutation,
            OperationType::Subscription => Self::Subscription,
        }
    }
}

/// The document's fragment definitions projected to the `name → selection-set` shape the
/// expansion needs (the same projection [`crate::graphql_guard`] builds). Borrowed from the
/// parsed document; cheap.
pub(crate) fn document_fragments(doc: &ExecutableDocument) -> HashMap<&str, &SelectionSet> {
    doc.fragments
        .iter()
        .map(|(name, f): (&Name, &Positioned<FragmentDefinition>)| {
            (name.as_str(), &f.node.selection_set.node)
        })
        .collect()
}

/// Every **root** field `op` selects, expanded across inline fragments and named fragment
/// spreads, as `(root_type, field_name)` pairs by field **name** (an alias is ignored — the
/// name is what the supergraph resolves and what `edge_hidden_roots` keys on). A field is
/// enumerated **once per selection occurrence** (duplicates preserved) — a caller that wants a
/// set collects into one. Cycle-guarded on the fragment graph so a cyclic fragment terminates.
///
/// Only the operation's **root** selection set (and the fragments reachable from it at the root
/// level) is walked — nested selection sets under a root field are that field's children, not
/// roots, and are not enumerated here.
pub(crate) fn expanded_root_fields(
    op: &OperationDefinition,
    fragments: &HashMap<&str, &SelectionSet>,
) -> Vec<(RootType, String)> {
    let root = RootType::from_operation(op.ty);
    let mut out = Vec::new();
    let mut visiting = HashSet::new();
    collect_root_fields(
        &op.selection_set.node,
        fragments,
        root,
        &mut visiting,
        &mut out,
    );
    out
}

/// Walk one selection set **at the root level**, pushing each `Selection::Field`'s name and
/// following fragment spreads / inline fragments (which contribute their fields at the same
/// root level). `visiting` breaks a fragment cycle exactly as [`crate::graphql_guard`]'s walk
/// does. A field's own child selection set is **not** descended — a root walk enumerates only
/// the roots.
fn collect_root_fields<'a>(
    ss: &'a SelectionSet,
    fragments: &HashMap<&'a str, &'a SelectionSet>,
    root: RootType,
    visiting: &mut HashSet<&'a str>,
    out: &mut Vec<(RootType, String)>,
) {
    for sel in &ss.items {
        match &sel.node {
            Selection::Field(field) => {
                out.push((root, field.node.name.node.to_string()));
            }
            // An inline fragment's selections sit at the same (root) level.
            Selection::InlineFragment(inline) => {
                collect_root_fields(
                    &inline.node.selection_set.node,
                    fragments,
                    root,
                    visiting,
                    out,
                );
            }
            // A named fragment expands to its selection set at the same (root) level; the
            // `visiting` set breaks a fragment cycle (which the parser permits).
            Selection::FragmentSpread(spread) => {
                let name = spread.node.fragment_name.node.as_str();
                if visiting.insert(name) {
                    if let Some(frag_ss) = fragments.get(name) {
                        collect_root_fields(frag_ss, fragments, root, visiting, out);
                    }
                    visiting.remove(name);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Parse `query` and enumerate its first operation's root fields as a set of
    /// `(type_name, field)` — the shape a caller uses to match against `edge_hidden_roots`.
    fn roots(query: &str) -> BTreeSet<(String, String)> {
        let doc = async_graphql_parser::parse_query(query).expect("parses");
        let fragments = document_fragments(&doc);
        let op = match &doc.operations {
            async_graphql_parser::types::DocumentOperations::Single(op) => &op.node,
            async_graphql_parser::types::DocumentOperations::Multiple(m) => {
                &m.values().next().unwrap().node
            }
        };
        expanded_root_fields(op, &fragments)
            .into_iter()
            .map(|(t, f)| (t.type_name().to_string(), f))
            .collect()
    }

    #[test]
    fn a_direct_root_field_is_enumerated_by_name() {
        assert_eq!(
            roots("{ visibleOp hiddenOp }"),
            BTreeSet::from([
                ("Query".into(), "visibleOp".into()),
                ("Query".into(), "hiddenOp".into()),
            ])
        );
    }

    #[test]
    fn an_alias_is_ignored_the_field_name_is_enumerated() {
        // `foo: hiddenOp` must enumerate `hiddenOp`, not `foo` — the supergraph resolves the
        // real field name, so hiding keys on it.
        assert_eq!(
            roots("{ foo: hiddenOp }"),
            BTreeSet::from([("Query".into(), "hiddenOp".into())])
        );
    }

    #[test]
    fn an_inline_fragment_root_field_is_expanded() {
        // `{ ... on Query { hiddenOp } }` — the pre-existing introspection bypass in its general
        // form. The field must surface, at the root level.
        assert_eq!(
            roots("{ ... on Query { hiddenOp } }"),
            BTreeSet::from([("Query".into(), "hiddenOp".into())])
        );
    }

    #[test]
    fn a_named_fragment_spread_root_field_is_expanded() {
        assert_eq!(
            roots("query { ...F } fragment F on Query { hiddenOp }"),
            BTreeSet::from([("Query".into(), "hiddenOp".into())])
        );
    }

    #[test]
    fn a_mutation_fragment_spread_is_typed_as_mutation() {
        assert_eq!(
            roots("mutation { ...M } fragment M on Mutation { hiddenOp }"),
            BTreeSet::from([("Mutation".into(), "hiddenOp".into())])
        );
    }

    #[test]
    fn mixed_direct_inline_and_spread_are_all_expanded() {
        // A single op mixing a direct field, an inline fragment, and a named spread — every root
        // must be enumerated so a mixed op fails as a whole (no partial execution).
        assert_eq!(
            roots("query { visibleOp ... on Query { a } ...F } fragment F on Query { b }"),
            BTreeSet::from([
                ("Query".into(), "visibleOp".into()),
                ("Query".into(), "a".into()),
                ("Query".into(), "b".into()),
            ])
        );
    }

    #[test]
    fn a_nested_fragment_spread_is_expanded_transitively() {
        assert_eq!(
            roots("query { ...F } fragment F on Query { ...G } fragment G on Query { hiddenOp }"),
            BTreeSet::from([("Query".into(), "hiddenOp".into())])
        );
    }

    #[test]
    fn a_child_selection_is_not_enumerated_as_a_root() {
        // `hiddenOp` under `visibleOp` is a child field, not a root — only `visibleOp` is a root.
        assert_eq!(
            roots("{ visibleOp { hiddenOp } }"),
            BTreeSet::from([("Query".into(), "visibleOp".into())])
        );
    }

    #[test]
    fn a_fragment_cycle_terminates() {
        // The parser accepts a cyclic fragment; enumeration must not loop forever.
        let query = "query { ...F } fragment F on Query { a ...G } fragment G on Query { b ...F }";
        let got = roots(query);
        // It terminates and still surfaces both concrete fields reachable before the cycle closes.
        assert!(got.contains(&("Query".into(), "a".into())));
        assert!(got.contains(&("Query".into(), "b".into())));
    }

    #[test]
    fn duplicate_occurrences_are_preserved_in_the_vec() {
        // The raw Vec preserves per-occurrence duplicates (a caller that wants a set collects one);
        // this guards the "expand every occurrence" contract the planner relies on.
        let doc = async_graphql_parser::parse_query("{ a a }").unwrap();
        let fragments = document_fragments(&doc);
        let op = match &doc.operations {
            async_graphql_parser::types::DocumentOperations::Single(op) => &op.node,
            _ => unreachable!(),
        };
        assert_eq!(expanded_root_fields(op, &fragments).len(), 2);
    }
}
