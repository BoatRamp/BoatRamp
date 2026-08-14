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
use async_graphql_parser::types::{
    DocumentOperations, Field, OperationType, Selection, SelectionSet, VariableDefinition,
};
use async_graphql_parser::Positioned;
use async_graphql_value::{Name, Value};
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
    let doc =
        async_graphql_parser::parse_query(query).map_err(|e| PlanError::Parse(e.to_string()))?;
    // The operation to plan: the sole operation, or the first of a multi-operation document
    // (the federation gateway plans one operation). An anonymous `{ … }` shorthand parses as a
    // single query operation, so no separate arm is needed.
    let op = match &doc.operations {
        DocumentOperations::Single(op) => &op.node,
        DocumentOperations::Multiple(map) => {
            &map.values().next().ok_or(PlanError::NoOperation)?.node
        }
    };
    let (root_type, roots) = match op.ty {
        OperationType::Query => ("Query", &sg.root_query),
        OperationType::Mutation => ("Mutation", &sg.root_mutation),
        OperationType::Subscription => return Err(PlanError::Unsupported("subscription")),
    };
    let var_types = var_type_map(&op.variable_definitions);

    // Group the root fields by the subgraph that owns them → one root fetch per subgraph.
    let mut by_subgraph: BTreeMap<String, Vec<&Field>> = BTreeMap::new();
    for sel in &op.selection_set.node.items {
        if let Selection::Field(field) = &sel.node {
            let fname = field.node.name.node.as_str();
            let owner = roots
                .get(fname)
                .cloned()
                .ok_or_else(|| PlanError::UnknownRootField(fname.to_string()))?;
            by_subgraph.entry(owner).or_default().push(&field.node);
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
    sel_set: &SelectionSet,
    parent_type: &str,
    subgraph: &str,
    used: &mut BTreeSet<String>,
) -> (String, Vec<DepFetch>) {
    let mut local = String::from("{ ");
    let mut deps = Vec::new();
    let is_entity = sg.entities.contains_key(parent_type);
    let mut key_injected = false;
    for sel in &sel_set.items {
        let Selection::Field(field) = &sel.node else {
            continue; // fragments are not planned in the core scope
        };
        let field = &field.node;
        match owner_of(sg, parent_type, field.name.node.as_str(), subgraph) {
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
    field: &Field,
    parent_type: &str,
    subgraph: &str,
    used: &mut BTreeSet<String>,
) -> (String, Vec<DepFetch>) {
    let field_name = field.name.node.as_str();
    // Field arguments must survive into the subgraph fetch — `agent(input: $x)`, not `agent`.
    // Any `$var` referenced is recorded so its definition is emitted on this fetch's operation.
    let args = render_arguments(&field.arguments, used);
    if field.selection_set.node.items.is_empty() {
        return (format!("{field_name}{args}"), Vec::new());
    }
    let child_type = sg
        .field_types
        .get(&(parent_type.to_string(), field_name.to_string()))
        .cloned()
        .unwrap_or_default();
    let (child_sel, child_deps) =
        plan_selection(sg, &field.selection_set.node, &child_type, subgraph, used);
    let deps = child_deps
        .into_iter()
        .map(|mut d| {
            d.path.insert(0, field_name.to_string());
            d
        })
        .collect();
    (format!("{field_name}{args} {child_sel}"), deps)
}

/// Render a field's arguments as ` (name: value, …)` (empty when there are none), recording
/// every `$var` referenced (recursively, into lists/objects) so the fetch operation can define
/// it. Values render via `async-graphql-value`'s `Display` — correct GraphQL literal syntax
/// including `$var` references, unquoted enum values, lists, and input objects.
fn render_arguments(
    args: &[(Positioned<Name>, Positioned<Value>)],
    used: &mut BTreeSet<String>,
) -> String {
    if args.is_empty() {
        return String::new();
    }
    let mut out = String::from("(");
    for (i, (name, value)) in args.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(name.node.as_str());
        out.push_str(": ");
        out.push_str(&value.node.to_string());
        collect_vars(&value.node, used);
    }
    out.push(')');
    out
}

/// Record every variable (`$name`) referenced inside `value`, descending into lists and objects.
fn collect_vars(value: &Value, used: &mut BTreeSet<String>) {
    match value {
        Value::Variable(name) => {
            used.insert(name.to_string());
        }
        Value::List(items) => items.iter().for_each(|v| collect_vars(v, used)),
        Value::Object(fields) => fields.values().for_each(|v| collect_vars(v, used)),
        _ => {}
    }
}

/// The variable name → type-string map from an operation's variable definitions (types render
/// via `Type`'s `Display`, e.g. `AgentInput!`).
fn var_type_map(defs: &[Positioned<VariableDefinition>]) -> BTreeMap<String, String> {
    defs.iter()
        .map(|d| {
            (
                d.node.name.node.to_string(),
                d.node.var_type.node.to_string(),
            )
        })
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
        // Exact-output assertion (not `.contains()`): the whole emitted fetch string must be
        // byte-for-byte correct. The operation must be a `mutation` (else the subgraph parses
        // it as a query and the Mutation-typed field never resolves — the shipped bug) AND the
        // argument must be present (dropping it was the second half of the bug). A `.contains()`
        // on a fragment would pass even for a malformed splice; exact equality cannot.
        assert_eq!(mplan.fetches[0].query, "mutation { agent(input: \"hi\") }");
        // A query operation must NOT get the mutation keyword — also asserted exactly.
        let qplan = plan("{ me { name } }", &supergraph_with_mutation()).unwrap();
        assert_eq!(qplan.fetches[0].query, "{ me { name } }");
    }

    #[test]
    fn a_mutation_forwards_variables_and_defines_them_on_the_fetch() {
        // The common client shape: arguments passed as operation variables. Exact-output:
        // the fetch must be a `mutation`, declare exactly the variable it uses (a subgraph
        // rejects an undefined — or unused — variable), and reference it in the argument.
        let mplan = plan(
            "mutation Turn($input: AgentInput!) { agent(input: $input) }",
            &supergraph_with_mutation(),
        )
        .unwrap();
        assert_eq!(
            mplan.fetches[0].query,
            "mutation($input: AgentInput!) { agent(input: $input) }"
        );
        let q = &mplan.fetches[0].query;
        // Redundant sub-assertions kept as intent documentation on top of the exact match.
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

    /// The invariant Incident 1 violated in its general form: **no root field and no argument
    /// is ever silently dropped** from a plan. For a range of operation shapes, every root
    /// field name and every argument token in the input must appear somewhere in the emitted
    /// fetches. A table-driven check (a lightweight stand-in for a property test) so a
    /// regression in argument/field serialization fails loudly regardless of the exact shape.
    #[test]
    fn no_root_field_or_argument_is_ever_dropped_from_a_plan() {
        let sg = supergraph_with_mutation();
        // (operation, tokens that MUST survive into some fetch)
        let cases: &[(&str, &[&str])] = &[
            ("{ me { name } }", &["me", "name"]),
            (
                "mutation { agent(input: \"hi\") }",
                &["agent", "input:", "\"hi\""],
            ),
            (
                "mutation T($x: String){ agent(input: $x) }",
                &["agent", "input:", "$x"],
            ),
        ];
        for (op, must_survive) in cases {
            let plan = plan(op, &sg).unwrap();
            let all: String = plan.fetches.iter().map(|f| f.query.as_str()).collect();
            for tok in *must_survive {
                assert!(
                    all.contains(tok),
                    "planning `{op}` dropped `{tok}` — emitted fetches: {all}"
                );
            }
        }
    }

    /// Multiple arguments and variables nested inside list/object argument values —
    /// exact-output. This closes three weak spots a mutation-testing run surfaced (no test
    /// exercised: the comma between multiple arguments; a `$var` inside a list value; a `$var`
    /// inside an object value). All three are the general form of the argument/variable
    /// serialization that shipped broken in the federated-mutation bug.
    #[test]
    fn renders_multiple_arguments_and_variables_nested_in_lists_and_objects() {
        let sg = supergraph_with_mutation();
        let plan = plan(
            "mutation T($n: Int, $t: Int, $o: Int){ agent(input: \"hi\", count: $n, tags: [$t], meta: {k: $o}) }",
            &sg,
        )
        .unwrap();
        let q = &plan.fetches[0].query;
        // Exact multi-argument rendering — the `, ` separators must be present (a single-arg
        // test can't catch a broken separator), and the list/object literals intact.
        assert_eq!(
            *q,
            "mutation($n: Int, $o: Int, $t: Int) { agent(input: \"hi\", count: $n, tags: [$t], meta: {k: $o}) }"
        );
        // Every variable is defined — including `$t` (nested in a list) and `$o` (nested in an
        // object), which are only reached by descending into those argument values.
        for v in ["$n: Int", "$t: Int", "$o: Int"] {
            assert!(q.contains(v), "missing var def `{v}` in: {q}");
        }
    }

    /// A `@shareable` field co-owned by the current subgraph must resolve **locally**, not jump
    /// to another owner — even when that other owner sorts first. Here `reviews` co-owns
    /// `User.name`, and a fetch rooted in `reviews` must keep `name` local (one fetch, no
    /// `_entities` jump), though `accounts` sorts first among the owners. (Closes the
    /// `owner_of` locality-guard weak spot a mutation-testing run surfaced.)
    #[test]
    fn a_shareable_field_the_current_subgraph_owns_stays_local() {
        let accounts =
            "type Query { me: User } type User @key(fields: \"id\") { id: ID! name: String @shareable }";
        let reviews =
            "type Query { topReviewer: User } extend type User @key(fields: \"id\") { id: ID! @external name: String @shareable }";
        let sg = compose(&[
            ("accounts".into(), accounts.into()),
            ("reviews".into(), reviews.into()),
        ])
        .unwrap();
        let plan = plan("{ topReviewer { name } }", &sg).unwrap();
        assert_eq!(
            plan.fetches.len(),
            1,
            "expected `name` resolved locally (no entity jump), got: {:?}",
            plan.fetches
        );
        assert_eq!(plan.fetches[0].subgraph, "reviews");
        assert!(
            plan.fetches[0].requires.is_none(),
            "no dependent fetch expected"
        );
    }
}
