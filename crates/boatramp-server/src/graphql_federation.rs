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

use graphql_parser::schema::{Definition, Directive, Field, TypeDefinition, TypeExtension, Value};
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
        let doc = graphql_parser::schema::parse_schema::<String>(sdl).map_err(|e| {
            CompositionError::Parse {
                subgraph: name.clone(),
                message: e.to_string(),
            }
        })?;
        for def in &doc.definitions {
            match def {
                Definition::TypeDefinition(TypeDefinition::Object(obj)) => {
                    ingest_object(
                        &mut sg,
                        &mut shareable,
                        name,
                        &obj.name,
                        &obj.directives,
                        &obj.fields,
                    );
                }
                Definition::TypeExtension(TypeExtension::Object(ext)) => {
                    ingest_object(
                        &mut sg,
                        &mut shareable,
                        name,
                        &ext.name,
                        &ext.directives,
                        &ext.fields,
                    );
                }
                _ => {}
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
    Ok(sg)
}

/// Fold one object type (or `extend type`) from subgraph `subgraph` into the model.
fn ingest_object(
    sg: &mut Supergraph,
    shareable: &mut BTreeSet<(String, String)>,
    subgraph: &str,
    type_name: &str,
    directives: &[Directive<'_, String>],
    fields: &[Field<'_, String>],
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
        // An `@external` field is a reference to a field owned elsewhere; it does not make
        // this subgraph a resolver of it.
        if has_directive(&field.directives, "external") {
            continue;
        }
        if has_directive(&field.directives, "shareable") {
            shareable.insert((type_name.to_string(), field.name.clone()));
        }
        match type_name {
            "Query" => {
                sg.root_query
                    .insert(field.name.clone(), subgraph.to_string());
            }
            "Mutation" => {
                sg.root_mutation
                    .insert(field.name.clone(), subgraph.to_string());
            }
            _ => {
                let owners = sg
                    .field_owners
                    .entry((type_name.to_string(), field.name.clone()))
                    .or_default();
                if !owners.iter().any(|s| s == subgraph) {
                    owners.push(subgraph.to_string());
                }
            }
        }
    }
}

fn has_directive(dirs: &[Directive<'_, String>], name: &str) -> bool {
    dirs.iter().any(|d| d.name == name)
}

/// The field names of the first `@key(fields: "…")` directive on a type, if any.
fn key_fields(dirs: &[Directive<'_, String>]) -> Option<Vec<String>> {
    let key = dirs.iter().find(|d| d.name == "key")?;
    let (_, value) = key.arguments.iter().find(|(name, _)| name == "fields")?;
    match value {
        Value::String(s) => Some(s.split_whitespace().map(str::to_string).collect()),
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
        assert!(matches!(err, CompositionError::FieldConflict { field, .. } if field == "f"));
    }

    #[test]
    fn shareable_allows_co_ownership() {
        let a = "type Query { x: Int } type T { f: Int @shareable }";
        let b = "type T { f: Int @shareable }";
        assert!(compose(&[sub("a", a), sub("b", b)]).is_ok());
    }

    #[test]
    fn unparsable_sdl_is_a_composition_error() {
        let err = compose(&[sub("bad", "type Query { ")]).unwrap_err();
        assert!(matches!(err, CompositionError::Parse { subgraph, .. } if subgraph == "bad"));
    }
}
