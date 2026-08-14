//! Federation composition: parse subgraph SDL and compose N subgraphs into a supergraph
//! model — which subgraph resolves each field, which types are entities (`@key`) + their
//! keys and resolving subgraphs, and which subgraph owns each root field. The query
//! planner (a later landing) plans against this model.
//!
//! Scope is **core federation**: `@key` entities, field ownership, `@external` references,
//! and `@shareable` fields. Pure and deterministic — SDL in, model out; no I/O.
//!
//! This is the foundation of the federation gateway: the schema registry composes on
//! publish, and the query planner (a later landing) plans against this model.

use async_graphql_parser::types::{
    ConstDirective, FieldDefinition, TypeKind, TypeSystemDefinition,
};
use async_graphql_value::ConstValue;
use std::collections::{BTreeMap, BTreeSet};

/// One federated entity type: its key field names and the subgraphs that can fetch it by
/// that key (those declaring `@key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entity {
    pub key: Vec<String>,
    pub subgraphs: Vec<String>,
}

/// The composed supergraph model the query planner plans against.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Supergraph {
    /// `(type, field)` → subgraphs that resolve it (own it, not merely `@external`-reference
    /// it). A non-root, non-`@shareable` field with more than one owner is a conflict.
    pub field_owners: BTreeMap<(String, String), Vec<String>>,
    /// Entity type name → its key + resolving subgraphs.
    pub entities: BTreeMap<String, Entity>,
    /// Root `Query` field → owning subgraph.
    pub root_query: BTreeMap<String, String>,
    /// Root `Mutation` field → owning subgraph.
    pub root_mutation: BTreeMap<String, String>,
    /// `(type, field)` → the field's base return type name (list/non-null unwrapped),
    /// recorded for every field including roots and `@external` ones, so the query
    /// planner can walk a selection and know each field's child type.
    pub field_types: BTreeMap<(String, String), String>,
}

/// A composition failure.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CompositionError {
    /// A subgraph's SDL did not parse.
    Parse { subgraph: String, message: String },
    /// A field is resolved by more than one subgraph without `@shareable`.
    FieldConflict {
        type_name: String,
        field: String,
        subgraphs: Vec<String>,
    },
}

impl std::fmt::Display for CompositionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse { subgraph, message } => {
                write!(f, "subgraph `{subgraph}` SDL did not parse: {message}")
            }
            Self::FieldConflict {
                type_name,
                field,
                subgraphs,
            } => write!(
                f,
                "field `{type_name}.{field}` is resolved by multiple subgraphs \
                 ({}) without @shareable",
                subgraphs.join(", ")
            ),
        }
    }
}

/// Compose the named subgraphs (each `(name, sdl)`) into a supergraph model, validating
/// that no field is co-owned without `@shareable`.
pub(crate) fn compose(subgraphs: &[(String, String)]) -> Result<Supergraph, CompositionError> {
    let mut sg = Supergraph::default();
    let mut shareable: BTreeSet<(String, String)> = BTreeSet::new();

    for (name, sdl) in subgraphs {
        // `async-graphql-parser` is the parser async-graphql itself uses, so it accepts the
        // federation-v2 `extend schema @link(...)` preamble a real subgraph's `_service { sdl }`
        // emits natively (the pre-v2 `graphql-parser` 0.4 rejected it, and needed a preprocessing
        // strip). A `type` and its `extend type` counterpart are unified under one
        // `TypeDefinition` with an `extend` flag, so both fold in through one arm; composition
        // reads only object types and their `@key`/`@external`/`@shareable` directives.
        let doc = async_graphql_parser::parse_schema(sdl).map_err(|e| CompositionError::Parse {
            subgraph: name.clone(),
            message: e.to_string(),
        })?;
        for def in &doc.definitions {
            if let TypeSystemDefinition::Type(ty) = def {
                if let TypeKind::Object(obj) = &ty.node.kind {
                    ingest_object(
                        &mut sg,
                        &mut shareable,
                        name,
                        ty.node.name.node.as_str(),
                        &ty.node.directives,
                        &obj.fields,
                    );
                }
            }
        }
    }

    for ((type_name, field), owners) in &sg.field_owners {
        if owners.len() > 1 && !shareable.contains(&(type_name.clone(), field.clone())) {
            return Err(CompositionError::FieldConflict {
                type_name: type_name.clone(),
                field: field.clone(),
                subgraphs: owners.clone(),
            });
        }
    }

    // Canonicalize the order-dependent lists so composition is **deterministic**: the same set
    // of subgraphs must yield the same supergraph regardless of the order they were composed in
    // (registry list order / deploy order is caller-driven). Without this, the `entity.subgraphs`
    // and `field_owners` lists reflect ingestion order, so the `/api/graphql/supergraph` summary
    // would change spuriously across recompositions. The planner doesn't consume this order (it
    // resolves by `@key`), so sorting is purely canonicalizing.
    for entity in sg.entities.values_mut() {
        entity.subgraphs.sort();
    }
    for owners in sg.field_owners.values_mut() {
        owners.sort();
    }
    Ok(sg)
}

/// Fold one object type (or `extend type`) from subgraph `subgraph` into the model.
fn ingest_object(
    sg: &mut Supergraph,
    shareable: &mut BTreeSet<(String, String)>,
    subgraph: &str,
    type_name: &str,
    directives: &[async_graphql_parser::Positioned<ConstDirective>],
    fields: &[async_graphql_parser::Positioned<FieldDefinition>],
) {
    // An `@key` makes this type an entity resolvable by that key from this subgraph.
    if let Some(key) = key_fields(directives) {
        let entity = sg.entities.entry(type_name.to_string()).or_insert(Entity {
            key: key.clone(),
            subgraphs: Vec::new(),
        });
        if !entity.subgraphs.iter().any(|s| s == subgraph) {
            entity.subgraphs.push(subgraph.to_string());
        }
    }

    for field in fields {
        let field = &field.node;
        let field_name = field.name.node.as_str();
        // Record every field's return type (roots + @external included) for the planner.
        sg.field_types
            .entry((type_name.to_string(), field_name.to_string()))
            .or_insert_with(|| base_type_name(&field.ty.node));
        // An `@external` field is a reference to a field owned elsewhere; it does not make
        // this subgraph a resolver of it.
        if has_directive(&field.directives, "external") {
            continue;
        }
        if has_directive(&field.directives, "shareable") {
            shareable.insert((type_name.to_string(), field_name.to_string()));
        }
        match type_name {
            "Query" => {
                sg.root_query
                    .insert(field_name.to_string(), subgraph.to_string());
            }
            "Mutation" => {
                sg.root_mutation
                    .insert(field_name.to_string(), subgraph.to_string());
            }
            _ => {
                let owners = sg
                    .field_owners
                    .entry((type_name.to_string(), field_name.to_string()))
                    .or_default();
                if !owners.iter().any(|s| s == subgraph) {
                    owners.push(subgraph.to_string());
                }
            }
        }
    }
}

fn has_directive(dirs: &[async_graphql_parser::Positioned<ConstDirective>], name: &str) -> bool {
    dirs.iter().any(|d| d.node.name.node == name)
}

/// The base named type of a field type, unwrapping `[T]` and `T!` wrappers.
fn base_type_name(ty: &async_graphql_parser::types::Type) -> String {
    use async_graphql_parser::types::BaseType;
    match &ty.base {
        BaseType::Named(name) => name.to_string(),
        BaseType::List(inner) => base_type_name(inner),
    }
}

/// The field names of the first `@key(fields: "…")` directive on a type, if any.
fn key_fields(dirs: &[async_graphql_parser::Positioned<ConstDirective>]) -> Option<Vec<String>> {
    let key = dirs.iter().find(|d| d.node.name.node == "key")?;
    let (_, value) = key
        .node
        .arguments
        .iter()
        .find(|(name, _)| name.node == "fields")?;
    match &value.node {
        ConstValue::String(s) => Some(s.split_whitespace().map(str::to_string).collect()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two subgraphs sharing the `User` entity: `accounts` owns `id`/`name`, `reviews`
    // extends `User` with `reviews` and provides a `Query.topReviews` root.
    const ACCOUNTS: &str = r#"
        type Query { me: User }
        type User @key(fields: "id") { id: ID! name: String }
    "#;
    const REVIEWS: &str = r#"
        type Query { topReviews: [Review] }
        type Review { id: ID! body: String author: User }
        extend type User @key(fields: "id") { id: ID! @external reviews: [Review] }
    "#;

    fn sub(name: &str, sdl: &str) -> (String, String) {
        (name.to_string(), sdl.to_string())
    }

    /// A **real** async-graphql federation subgraph: build a schema, emit its SDL exactly
    /// as a live subgraph's `_service { sdl }` returns it, and compose that. This proves the
    /// composer accepts real federation-v2 output — the `extend schema @link(...)` preamble,
    /// `@key`, and the `_Entity`/`_Service` plumbing — not just the hand-written SDL above
    /// (the class of gap behind the federation-v2-SDL-rejected incident).
    #[test]
    fn composes_sdl_emitted_by_a_real_async_graphql_subgraph() {
        use async_graphql::{EmptyMutation, EmptySubscription, Object, Schema, SimpleObject, ID};

        #[derive(SimpleObject)]
        struct User {
            id: ID,
            name: String,
        }

        struct Query;

        #[Object]
        impl Query {
            async fn me(&self) -> User {
                User {
                    id: ID::from("1"),
                    name: "Ada".into(),
                }
            }
            // A federation entity resolver ⇒ async-graphql emits `User @key(fields: "id")`.
            #[graphql(entity)]
            async fn find_user_by_id(&self, id: ID) -> User {
                User {
                    id,
                    name: "Ada".into(),
                }
            }
        }

        let schema = Schema::build(Query, EmptyMutation, EmptySubscription).finish();
        let sdl = schema.sdl_with_options(async_graphql::SDLExportOptions::new().federation());

        let sg = compose(&[sub("accounts", &sdl)]).expect("compose real subgraph SDL");
        // The real subgraph's root `me: User` is owned by accounts.
        assert_eq!(
            sg.root_query.get("me").map(String::as_str),
            Some("accounts")
        );
        // `User` is composed as an entity keyed by `id`, parsed from the exact federation
        // SDL async-graphql emits.
        let user = sg.entities.get("User").expect("User is an entity");
        assert_eq!(user.key, vec!["id".to_string()]);
        assert_eq!(user.subgraphs, vec!["accounts".to_string()]);
    }

    #[test]
    fn composes_root_fields_by_owning_subgraph() {
        let sg = compose(&[sub("accounts", ACCOUNTS), sub("reviews", REVIEWS)]).unwrap();
        assert_eq!(
            sg.root_query.get("me").map(String::as_str),
            Some("accounts")
        );
        assert_eq!(
            sg.root_query.get("topReviews").map(String::as_str),
            Some("reviews")
        );
    }

    #[test]
    fn user_is_an_entity_resolvable_by_both_subgraphs() {
        let sg = compose(&[sub("accounts", ACCOUNTS), sub("reviews", REVIEWS)]).unwrap();
        let user = sg.entities.get("User").expect("User is an entity");
        assert_eq!(user.key, vec!["id".to_string()]);
        assert_eq!(user.subgraphs, vec!["accounts", "reviews"]);
    }

    #[test]
    fn field_ownership_splits_across_subgraphs_and_external_is_not_owned() {
        let sg = compose(&[sub("accounts", ACCOUNTS), sub("reviews", REVIEWS)]).unwrap();
        // `User.name` is owned by accounts; `User.reviews` by reviews.
        assert_eq!(
            sg.field_owners.get(&("User".into(), "name".into())),
            Some(&vec!["accounts".to_string()])
        );
        assert_eq!(
            sg.field_owners.get(&("User".into(), "reviews".into())),
            Some(&vec!["reviews".to_string()])
        );
        // `User.id` is @external in reviews, so only accounts owns it.
        assert_eq!(
            sg.field_owners.get(&("User".into(), "id".into())),
            Some(&vec!["accounts".to_string()])
        );
    }

    #[test]
    fn co_owned_field_without_shareable_is_a_conflict() {
        let a = "type Query { x: Int } type T { f: Int }";
        let b = "type T { f: Int }";
        let err = compose(&[sub("a", a), sub("b", b)]).unwrap_err();
        assert!(matches!(&err, CompositionError::FieldConflict { field, .. } if field == "f"));
        // The message must name the conflicting field + cite @shareable (guides the fix).
        let msg = err.to_string();
        assert!(
            msg.contains("T.f") && msg.contains("@shareable"),
            "unexpected message: {msg}"
        );
    }

    #[test]
    fn shareable_allows_co_ownership() {
        let a = "type Query { x: Int } type T { f: Int @shareable }";
        let b = "type T { f: Int @shareable }";
        assert!(compose(&[sub("a", a), sub("b", b)]).is_ok());
    }

    // The verbatim `_service { sdl }` a real async-graphql (v7) `.enable_federation()` subgraph
    // emits: a federation-v2 document with the `extend schema @link(...)` preamble, descriptions,
    // and built-in directive definitions. `graphql-parser` 0.4 rejects `extend schema` outright,
    // so this is the regression that proves a real subgraph composes.
    const ASYNC_GRAPHQL_V2: &str = r#"type Query {
	users: [User!]!
}

type User @key(fields: "id") {
	id: ID!
	name: String!
}

"""
Directs the executor to include this field or fragment only when the `if` argument is true.
"""
directive @include(if: Boolean!) on FIELD | FRAGMENT_SPREAD | INLINE_FRAGMENT
"""
Directs the executor to skip this field or fragment when the `if` argument is true.
"""
directive @skip(if: Boolean!) on FIELD | FRAGMENT_SPREAD | INLINE_FRAGMENT
extend schema @link(
	url: "https://specs.apollo.dev/federation/v2.5",
	import: ["@key", "@tag", "@shareable", "@inaccessible", "@override", "@external", "@provides", "@requires", "@composeDirective", "@interfaceObject", "@requiresScopes"]
)
"#;

    #[test]
    fn composes_a_real_federation_v2_subgraph_with_link_preamble() {
        // Before the fix this errored at `extend schema` (a `CompositionError::Parse`).
        let sg = compose(&[sub("accounts", ASYNC_GRAPHQL_V2)]).expect("v2 SDL must compose");
        // The `@link` preamble is ignored, but every type-system fact is intact.
        assert_eq!(
            sg.root_query.get("users").map(String::as_str),
            Some("accounts")
        );
        let user = sg.entities.get("User").expect("User is an entity");
        assert_eq!(user.key, vec!["id".to_string()]);
        assert_eq!(user.subgraphs, vec!["accounts".to_string()]);
    }

    #[test]
    fn extend_type_and_extend_schema_are_handled() {
        // `extend type` folds into the model like a `type`; `extend schema @link(...)` (the
        // federation-v2 preamble) parses natively and is ignored by composition.
        let base = "type User @key(fields: \"id\") { id: ID! }";
        let ext = concat!(
            "extend schema @link(url: \"https://specs.apollo.dev/federation/v2.5\", import: [\"@key\"])\n",
            "extend type User @key(fields: \"id\") { id: ID! @external tag: String }\n",
        );
        let sg = compose(&[sub("a", base), sub("b", ext)]).unwrap();
        // `User.tag` (added via `extend type` in subgraph b) is owned by b.
        assert_eq!(
            sg.field_owners.get(&("User".into(), "tag".into())),
            Some(&vec!["b".to_string()])
        );
    }

    #[test]
    fn unparsable_sdl_is_a_composition_error() {
        let err = compose(&[sub("bad", "type Query { ")]).unwrap_err();
        assert!(matches!(&err, CompositionError::Parse { subgraph, .. } if subgraph == "bad"));
        // The operator-facing message must name the subgraph + say it didn't parse (the Display
        // impl is otherwise untested — a mutant that blanks it survives without this).
        let msg = err.to_string();
        assert!(
            msg.contains("bad") && msg.contains("did not parse"),
            "unexpected message: {msg}"
        );
    }

    /// Property: composition is **order-independent**. A supergraph is a set-like merge of its
    /// subgraphs, so composing them in any permutation must yield the same entities, keys, and
    /// root ownership. (A lightweight stand-in for a proptest — a fixed set of permutations.)
    /// Composition order is caller-driven (registry list order, deploy order), so an
    /// order-sensitive bug would be a subtle, hard-to-reproduce corruption; this pins it out.
    #[test]
    fn composition_is_order_independent() {
        let a = sub(
            "accounts",
            "type Query { me: User } type User @key(fields: \"id\") { id: ID! name: String }",
        );
        let b = sub(
            "reviews",
            "type Query { top: [Review] } type Review { id: ID! } extend type User @key(fields: \"id\") { id: ID! @external reviews: [Review] }",
        );
        let c = sub(
            "catalog",
            "type Query { items: [Item] } type Item @key(fields: \"sku\") { sku: ID! }",
        );

        let baseline = compose(&[a.clone(), b.clone(), c.clone()]).unwrap();
        for perm in [
            [c.clone(), a.clone(), b.clone()],
            [b.clone(), c.clone(), a.clone()],
            [b.clone(), a.clone(), c.clone()],
        ] {
            let sg = compose(&perm).unwrap();
            // The whole supergraph model must be identical regardless of input order.
            assert_eq!(sg.entities, baseline.entities, "entities differ by order");
            assert_eq!(
                sg.root_query, baseline.root_query,
                "root_query differs by order"
            );
            assert_eq!(
                sg.field_owners, baseline.field_owners,
                "field_owners differ by order"
            );
            // Every `@key` entity survives every ordering.
            assert!(sg.entities.contains_key("User") && sg.entities.contains_key("Item"));
        }
    }
}
