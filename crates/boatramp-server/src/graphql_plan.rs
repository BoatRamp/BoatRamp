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
use graphql_parser::query::{
    Definition, Field, OperationDefinition, Selection, SelectionSet, Value,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
    /// Operation variables referenced within `selection` — their definitions are added to
    /// the `_entities` fetch so a nested field argument like `field(first: $n)` still binds.
    used_vars: BTreeSet<String>,
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
    let (root_sel, root_type, roots, var_types) = match op {
        OperationDefinition::Query(q) => (
            &q.selection_set,
            "Query",
            &sg.root_query,
            var_type_map(&q.variable_definitions),
        ),
        OperationDefinition::SelectionSet(ss) => (ss, "Query", &sg.root_query, BTreeMap::new()),
        OperationDefinition::Mutation(m) => (
            &m.selection_set,
            "Mutation",
            &sg.root_mutation,
            var_type_map(&m.variable_definitions),
        ),
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
        let mut used = BTreeSet::new();
        let mut body = String::new();
        for field in fields {
            let (text, deps) = plan_field(sg, field, root_type, &subgraph, &mut used);
            body.push_str(&text);
            body.push(' ');
            for d in deps {
                queue.push_back((d, idx));
            }
        }
        fetches.push(Fetch {
            subgraph,
            query: build_root_operation(root_type, &used, &var_types, &body),
            requires: None,
        });
    }

    // Materialize dependent entity fetches in breadth-first (provider-before-dependent)
    // order, so each fetch's provider index already exists.
    while let Some((dep, provider)) = queue.pop_front() {
        let idx = fetches.len();
        fetches.push(Fetch {
            subgraph: dep.subgraph,
            query: entity_fetch_query(&dep.type_name, &dep.selection, &dep.used_vars, &var_types),
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
    used: &mut BTreeSet<String>,
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
                // The entity sub-query is a distinct operation (a different subgraph), so it
                // carries its own variable references, not this fetch's.
                let mut dep_used = BTreeSet::new();
                let (selection, nested) = plan_field(sg, field, parent_type, &owner, &mut dep_used);
                deps.push(DepFetch {
                    subgraph: owner,
                    type_name: parent_type.to_string(),
                    key: sg.entities[parent_type].key.clone(),
                    path: Vec::new(),
                    selection,
                    used_vars: dep_used,
                    deps: nested,
                });
            }
            // Local (same-subgraph, or an unowned scalar like __typename).
            _ => {
                let (text, field_deps) = plan_field(sg, field, parent_type, subgraph, used);
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
    used: &mut BTreeSet<String>,
) -> (String, Vec<DepFetch>) {
    // Field arguments must survive into the subgraph fetch — `agent(input: $x)`, not `agent`.
    // Any `$var` referenced is recorded so its definition is emitted on this fetch's operation.
    let args = render_arguments(&field.arguments, used);
    if field.selection_set.items.is_empty() {
        return (format!("{}{args}", field.name), Vec::new());
    }
    let child_type = sg
        .field_types
        .get(&(parent_type.to_string(), field.name.clone()))
        .cloned()
        .unwrap_or_default();
    let (child_sel, child_deps) =
        plan_selection(sg, &field.selection_set, &child_type, subgraph, used);
    let deps = child_deps
        .into_iter()
        .map(|mut d| {
            d.path.insert(0, field.name.clone());
            d
        })
        .collect();
    (format!("{}{args} {child_sel}", field.name), deps)
}

/// Render a field's arguments as ` (name: value, …)` (empty when there are none), recording
/// every `$var` referenced (recursively, into lists/objects) so the fetch operation can define
/// it. Values render via `graphql-parser`'s `Display` — correct GraphQL literal syntax including
/// `$var` references, unquoted enum values, lists, and input objects.
fn render_arguments(args: &[(String, Value<'_, String>)], used: &mut BTreeSet<String>) -> String {
    if args.is_empty() {
        return String::new();
    }
    let mut out = String::from("(");
    for (i, (name, value)) in args.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(name);
        out.push_str(": ");
        out.push_str(&value.to_string());
        collect_vars(value, used);
    }
    out.push(')');
    out
}

/// Record every variable (`$name`) referenced inside `value`, descending into lists and objects.
fn collect_vars(value: &Value<'_, String>, used: &mut BTreeSet<String>) {
    match value {
        Value::Variable(name) => {
            used.insert(name.clone());
        }
        Value::List(items) => items.iter().for_each(|v| collect_vars(v, used)),
        Value::Object(fields) => fields.values().for_each(|v| collect_vars(v, used)),
        _ => {}
    }
}

/// The variable name → type-string map from an operation's variable definitions (types render
/// via `Type`'s `Display`, e.g. `AgentInput!`).
fn var_type_map(
    defs: &[graphql_parser::query::VariableDefinition<'_, String>],
) -> BTreeMap<String, String> {
    defs.iter()
        .map(|d| (d.name.clone(), d.var_type.to_string()))
        .collect()
}

/// The ` ($a: TA, $b: TB)` variable-definition list for exactly the `used` variables, in a
/// stable order — empty when none are used. A subgraph operation must define every variable it
/// uses (and, per the spec, none it doesn't), so this is subset to the fetch's own references.
fn render_var_defs(used: &BTreeSet<String>, types: &BTreeMap<String, String>) -> String {
    let defs: Vec<String> = used
        .iter()
        .filter_map(|n| types.get(n).map(|t| format!("${n}: {t}")))
        .collect();
    if defs.is_empty() {
        String::new()
    } else {
        format!("({})", defs.join(", "))
    }
}

/// Build a root fetch's operation string. A var-less **query** stays the anonymous `{ … }` form
/// (unchanged); a **mutation** (or any operation using variables) is a named operation with its
/// keyword + variable definitions, so the subgraph executes it against the right root type and
/// binds its arguments.
fn build_root_operation(
    root_type: &str,
    used: &BTreeSet<String>,
    types: &BTreeMap<String, String>,
    body: &str,
) -> String {
    if root_type == "Query" && used.is_empty() {
        return format!("{{ {body}}}");
    }
    let keyword = if root_type == "Mutation" {
        "mutation"
    } else {
        "query"
    };
    format!("{keyword}{} {{ {body}}}", render_var_defs(used, types))
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

/// The `_entities` query that resolves `selection` on entities of `type_name`. Entity hydration
/// is always a `query` (regardless of the operation's root type); any variables the entity
/// `selection` references are added to its definition list alongside `$representations`.
fn entity_fetch_query(
    type_name: &str,
    selection: &str,
    used_vars: &BTreeSet<String>,
    types: &BTreeMap<String, String>,
) -> String {
    let extra: String = used_vars
        .iter()
        .filter_map(|n| types.get(n).map(|t| format!(", ${n}: {t}")))
        .collect();
    format!(
        "query($representations:[_Any!]!{extra}){{ _entities(representations:$representations){{ ... on {type_name} {{ {selection} }} }} }}"
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

    // A subgraph that owns a `Mutation` root field (plus a query, as a subgraph conventionally has).
    const AGENT: &str = r#"
        type Query { ping: String }
        type Mutation { agent(input: String): String }
    "#;

    fn supergraph_with_mutation() -> Supergraph {
        compose(&[
            ("accounts".into(), ACCOUNTS.into()),
            ("agent".into(), AGENT.into()),
        ])
        .unwrap()
    }

    #[test]
    fn a_mutation_root_fetch_is_dispatched_as_a_mutation_with_its_arguments() {
        let mplan = plan(
            "mutation { agent(input: \"hi\") }",
            &supergraph_with_mutation(),
        )
        .unwrap();
        assert_eq!(mplan.fetches.len(), 1);
        assert_eq!(mplan.fetches[0].subgraph, "agent");
        let q = mplan.fetches[0].query.trim_start();
        // The operation is a `mutation` (else the subgraph parses it as a query and the field,
        // which lives on Mutation, never resolves) …
        assert!(
            q.starts_with("mutation {"),
            "a Mutation must be dispatched as a `mutation`, got: {q}"
        );
        // … and the field's arguments survive into the fetch (not just `agent`).
        assert!(
            q.contains("agent(input: \"hi\")"),
            "field arguments must reach the subgraph, got: {q}"
        );
        // A query operation must NOT get the mutation keyword.
        let qplan = plan("{ me { name } }", &supergraph_with_mutation()).unwrap();
        assert!(
            !qplan.fetches[0].query.trim_start().starts_with("mutation"),
            "a Query operation's root fetch must stay a query"
        );
    }

    #[test]
    fn a_mutation_forwards_variables_and_defines_them_on_the_fetch() {
        // The common client shape: arguments passed as operation variables.
        let mplan = plan(
            "mutation Turn($input: AgentInput!) { agent(input: $input) }",
            &supergraph_with_mutation(),
        )
        .unwrap();
        let q = &mplan.fetches[0].query;
        // The fetch must (a) declare the variable it uses — a subgraph rejects an undefined
        // variable — and (b) reference it in the argument.
        assert!(
            q.contains("mutation($input: AgentInput!)"),
            "the fetch must define the variable it uses, got: {q}"
        );
        assert!(
            q.contains("agent(input: $input)"),
            "the argument must reference the variable, got: {q}"
        );
    }

    // An entity whose field takes an argument, to prove nested-field args + variable defs reach
    // the `_entities` fetch too (not only the root).
    const REVIEWS_ARG: &str = r#"
        type Query { topReviews: [Review] }
        type Review { id: ID! body: String }
        extend type User @key(fields: "id") { id: ID! @external reviews(first: Int): [Review] }
    "#;

    #[test]
    fn an_entity_fetch_carries_nested_field_arguments_and_their_variable_defs() {
        let sg = compose(&[
            ("accounts".into(), ACCOUNTS.into()),
            ("reviews".into(), REVIEWS_ARG.into()),
        ])
        .unwrap();
        let plan = plan(
            "query Q($n: Int){ me { reviews(first: $n) { body } } }",
            &sg,
        )
        .unwrap();
        let dep = &plan.fetches[1];
        assert!(
            dep.query.contains("_entities"),
            "expected an entities fetch: {}",
            dep.query
        );
        assert!(
            dep.query.contains("reviews(first: $n)"),
            "nested field argument must survive into the entities fetch, got: {}",
            dep.query
        );
        assert!(
            dep.query.contains("$n: Int"),
            "the entities fetch must define the variable it uses, got: {}",
            dep.query
        );
    }
}
