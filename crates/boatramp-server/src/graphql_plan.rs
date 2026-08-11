//! GraphQL federation query planner.
//!
//! Decompose an operation against a composed supergraph into an ordered list of
//! **fetches**: a root fetch per root field's owning subgraph, plus dependent
//! `_entities` fetches that resolve fields owned by another subgraph — joined on the
//! entity's `@key`. The executor (a later landing) runs the plan, dispatching each fetch
//! to its subgraph via streaming invoke and stitching the results by key.
//!
//! Scope is **core federation**: root-field grouping and `@key` entity jumps (nested
//! jumps recurse). `@requires`/`@provides` chains and interface entities are deferred.
//! Pure and deterministic — operation + model in, plan out; no I/O.

use crate::graphql_federation::Supergraph;
use graphql_parser::query::{Definition, Field, OperationDefinition, Selection, SelectionSet};
use std::collections::{BTreeMap, VecDeque};

/// One fetch in a query plan.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Fetch {
    /// The subgraph this fetch is sent to.
    pub subgraph: String,
    /// The GraphQL query text to send.
    pub query: String,
    /// For a dependent (entity) fetch: the entity type + key it joins on, the index of
    /// the fetch that supplies the representations, and the response path (root-field
    /// names) at which those entities live in that provider. `None` for a root fetch.
    pub requires: Option<Requires>,
}

/// The join a dependent entity fetch performs.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Requires {
    pub type_name: String,
    pub key: Vec<String>,
    pub provider: usize,
    pub path: Vec<String>,
}

/// An ordered plan: `fetches[i]`'s `requires.provider` is always `< i` (topological).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct QueryPlan {
    pub fetches: Vec<Fetch>,
}

/// Why planning failed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum PlanError {
    Parse(String),
    NoOperation,
    /// A root field that no subgraph owns (the supergraph doesn't define it).
    UnknownRootField(String),
    /// Subscriptions are not planned by the federation gateway (they route directly).
    Unsupported(&'static str),
}

/// A dependent entity fetch collected during planning, before it is assigned an index.
struct DepFetch {
    subgraph: String,
    type_name: String,
    key: Vec<String>,
    /// The response path (root-field names) at which the entities live in the provider.
    path: Vec<String>,
    /// The selection to resolve on the entity in `subgraph` (the `... on Type { … }` body).
    selection: String,
    /// Nested dependent fetches from within `selection`.
    deps: Vec<Self>,
}

/// Plan `query` against the composed supergraph `sg`.
pub(crate) fn plan(query: &str, sg: &Supergraph) -> Result<QueryPlan, PlanError> {
    let doc = graphql_parser::query::parse_query::<String>(query)
        .map_err(|e| PlanError::Parse(e.to_string()))?;
    let op = doc
        .definitions
        .iter()
        .find_map(|d| match d {
            Definition::Operation(op) => Some(op),
            _ => None,
        })
        .ok_or(PlanError::NoOperation)?;
    let (root_sel, root_type, roots) = match op {
        OperationDefinition::Query(q) => (&q.selection_set, "Query", &sg.root_query),
        OperationDefinition::SelectionSet(ss) => (ss, "Query", &sg.root_query),
        OperationDefinition::Mutation(m) => (&m.selection_set, "Mutation", &sg.root_mutation),
        OperationDefinition::Subscription(_) => return Err(PlanError::Unsupported("subscription")),
    };

    // Group the root fields by the subgraph that owns them → one root fetch per subgraph.
    let mut by_subgraph: BTreeMap<String, Vec<&Field<'_, String>>> = BTreeMap::new();
    for sel in &root_sel.items {
        if let Selection::Field(field) = sel {
            let owner = roots
                .get(&field.name)
                .cloned()
                .ok_or_else(|| PlanError::UnknownRootField(field.name.clone()))?;
            by_subgraph.entry(owner).or_default().push(field);
        }
    }

    let mut fetches = Vec::new();
    let mut queue: VecDeque<(DepFetch, usize)> = VecDeque::new();
    for (subgraph, fields) in by_subgraph {
        let idx = fetches.len();
        let mut selection = String::from("{ ");
        for field in fields {
            let (text, deps) = plan_field(sg, field, root_type, &subgraph);
            selection.push_str(&text);
            selection.push(' ');
            for d in deps {
                queue.push_back((d, idx));
            }
        }
        selection.push('}');
        fetches.push(Fetch {
            subgraph,
            query: selection,
            requires: None,
        });
    }

    // Materialize dependent entity fetches in breadth-first (provider-before-dependent)
    // order, so each fetch's provider index already exists.
    while let Some((dep, provider)) = queue.pop_front() {
        let idx = fetches.len();
        fetches.push(Fetch {
            subgraph: dep.subgraph,
            query: entity_fetch_query(&dep.type_name, &dep.selection),
            requires: Some(Requires {
                type_name: dep.type_name,
                key: dep.key,
                provider,
                path: dep.path,
            }),
        });
        for d in dep.deps {
            queue.push_back((d, idx));
        }
    }

    Ok(QueryPlan { fetches })
}

/// Plan a selection set that runs in `subgraph` against `parent_type`. Returns the
/// selection text for this fetch and the dependent entity fetches its cross-subgraph
/// fields trigger.
fn plan_selection(
    sg: &Supergraph,
    sel_set: &SelectionSet<'_, String>,
    parent_type: &str,
    subgraph: &str,
) -> (String, Vec<DepFetch>) {
    let mut local = String::from("{ ");
    let mut deps = Vec::new();
    let is_entity = sg.entities.contains_key(parent_type);
    let mut key_injected = false;
    for sel in &sel_set.items {
        let Selection::Field(field) = sel else {
            continue; // fragments are not planned in the core scope
        };
        match owner_of(sg, parent_type, &field.name, subgraph) {
            // A field owned by another subgraph on an entity type → an entity jump.
            Some(owner) if owner != subgraph && is_entity => {
                if !key_injected {
                    // The provider must select the key + __typename to build the join.
                    local.push_str("__typename ");
                    for k in &sg.entities[parent_type].key {
                        local.push_str(k);
                        local.push(' ');
                    }
                    key_injected = true;
                }
                let (selection, nested) = plan_field(sg, field, parent_type, &owner);
                deps.push(DepFetch {
                    subgraph: owner,
                    type_name: parent_type.to_string(),
                    key: sg.entities[parent_type].key.clone(),
                    path: Vec::new(),
                    selection,
                    deps: nested,
                });
            }
            // Local (same-subgraph, or an unowned scalar like __typename).
            _ => {
                let (text, field_deps) = plan_field(sg, field, parent_type, subgraph);
                local.push_str(&text);
                local.push(' ');
                deps.extend(field_deps);
            }
        }
    }
    local.push('}');
    (local, deps)
}

/// Plan one field (`name` or `name { … }`) in `subgraph`, prefixing this field's name onto
/// the response path of any dependent fetch found inside it.
fn plan_field(
    sg: &Supergraph,
    field: &Field<'_, String>,
    parent_type: &str,
    subgraph: &str,
) -> (String, Vec<DepFetch>) {
    if field.selection_set.items.is_empty() {
        return (field.name.clone(), Vec::new());
    }
    let child_type = sg
        .field_types
        .get(&(parent_type.to_string(), field.name.clone()))
        .cloned()
        .unwrap_or_default();
    let (child_sel, child_deps) = plan_selection(sg, &field.selection_set, &child_type, subgraph);
    let deps = child_deps
        .into_iter()
        .map(|mut d| {
            d.path.insert(0, field.name.clone());
            d
        })
        .collect();
    (format!("{} {}", field.name, child_sel), deps)
}

/// Which subgraph resolves `field` on `parent_type` from the vantage of `current` — the
/// current subgraph if it owns it (keep the fetch local), else the first owner.
fn owner_of(sg: &Supergraph, parent_type: &str, field: &str, current: &str) -> Option<String> {
    if parent_type == "Query" {
        return sg.root_query.get(field).cloned();
    }
    if parent_type == "Mutation" {
        return sg.root_mutation.get(field).cloned();
    }
    match sg
        .field_owners
        .get(&(parent_type.to_string(), field.to_string()))
    {
        Some(owners) if owners.iter().any(|o| o == current) => Some(current.to_string()),
        Some(owners) => owners.first().cloned(),
        None => None,
    }
}

/// The `_entities` query that resolves `selection` on entities of `type_name`.
fn entity_fetch_query(type_name: &str, selection: &str) -> String {
    format!(
        "query($representations:[_Any!]!){{ _entities(representations:$representations){{ ... on {type_name} {{ {selection} }} }} }}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphql_federation::compose;

    const ACCOUNTS: &str = r#"
        type Query { me: User }
        type User @key(fields: "id") { id: ID! name: String }
    "#;
    const REVIEWS: &str = r#"
        type Query { topReviews: [Review] }
        type Review { id: ID! body: String }
        extend type User @key(fields: "id") { id: ID! @external reviews: [Review] }
    "#;

    fn supergraph() -> Supergraph {
        compose(&[
            ("accounts".into(), ACCOUNTS.into()),
            ("reviews".into(), REVIEWS.into()),
        ])
        .unwrap()
    }

    #[test]
    fn a_single_subgraph_query_is_one_fetch() {
        let plan = plan("{ me { name } }", &supergraph()).unwrap();
        assert_eq!(plan.fetches.len(), 1);
        assert_eq!(plan.fetches[0].subgraph, "accounts");
        assert!(plan.fetches[0].query.contains("me"));
        assert!(plan.fetches[0].requires.is_none());
    }

    #[test]
    fn distinct_roots_split_into_a_fetch_per_owning_subgraph() {
        let plan = plan("{ me { name } topReviews { body } }", &supergraph()).unwrap();
        assert_eq!(plan.fetches.len(), 2);
        let subgraphs: Vec<&str> = plan.fetches.iter().map(|f| f.subgraph.as_str()).collect();
        assert!(subgraphs.contains(&"accounts") && subgraphs.contains(&"reviews"));
        assert!(plan.fetches.iter().all(|f| f.requires.is_none()));
    }

    #[test]
    fn a_cross_subgraph_entity_field_becomes_a_dependent_entities_fetch() {
        let plan = plan("{ me { name reviews { body } } }", &supergraph()).unwrap();
        assert_eq!(plan.fetches.len(), 2);

        // Fetch 0: accounts resolves `me`, and must select the key + __typename to join.
        let root = &plan.fetches[0];
        assert_eq!(root.subgraph, "accounts");
        assert!(root.query.contains("name"));
        assert!(root.query.contains("__typename"));
        assert!(root.query.contains("id"));
        assert!(root.requires.is_none());

        // Fetch 1: reviews resolves `reviews` via `_entities`, joined on User.id at path `me`.
        let dep = &plan.fetches[1];
        assert_eq!(dep.subgraph, "reviews");
        assert!(dep.query.contains("_entities"));
        assert!(dep.query.contains("... on User"));
        assert!(dep.query.contains("reviews"));
        let req = dep.requires.as_ref().expect("dependent fetch");
        assert_eq!(req.type_name, "User");
        assert_eq!(req.key, vec!["id".to_string()]);
        assert_eq!(req.provider, 0);
        assert_eq!(req.path, vec!["me".to_string()]);
    }

    #[test]
    fn an_unknown_root_field_is_an_error() {
        assert!(matches!(
            plan("{ nope }", &supergraph()),
            Err(PlanError::UnknownRootField(f)) if f == "nope"
        ));
    }
}
