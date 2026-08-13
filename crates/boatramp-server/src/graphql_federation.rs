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
        // graphql-parser 0.4 predates federation v2 and rejects the `extend schema
        // @link(...)` preamble a v2 subgraph's `_service { sdl }` emits (async-graphql,
        // Apollo, and graphql-js all emit it). Composition reads only object types and
        // their `@key`/`@external`/`@shareable` directives, so drop schema-level
        // definitions before parsing — see [`strip_schema_definitions`].
        let sdl = strip_schema_definitions(sdl);
        let doc = graphql_parser::schema::parse_schema::<String>(&sdl).map_err(|e| {
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
        // Record every field's return type (roots + @external included) for the planner.
        sg.field_types
            .entry((type_name.to_string(), field.name.clone()))
            .or_insert_with(|| base_type_name(&field.field_type));
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

/// The base named type of a field type, unwrapping `[T]` and `T!` wrappers.
fn base_type_name(ty: &graphql_parser::schema::Type<'_, String>) -> String {
    use graphql_parser::schema::Type;
    match ty {
        Type::NamedType(name) => name.clone(),
        Type::ListType(inner) | Type::NonNullType(inner) => base_type_name(inner),
    }
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

/// Remove every top-level `schema` / `extend schema` definition from `sdl`, returning the
/// rest of the type system unchanged.
///
/// Federation v2 subgraph SDL carries an `extend schema @link(url: "https://specs.apollo.dev/
/// federation/v2.x", import: [...])` preamble, which the pre-federation `graphql-parser` 0.4
/// cannot parse (it has no schema-extension support). Composition never reads schema-level
/// definitions — only object types and their `@key`/`@external`/`@shareable` directives — so
/// dropping them lets a real v2 subgraph compose while changing nothing the composer looks at.
///
/// The scan is string- and comment-aware: a `schema`/`@link` inside a description, a field, or
/// a directive argument is left untouched, and `extend type`/`extend interface`/… are preserved
/// (only `extend schema` is dropped).
fn strip_schema_definitions(sdl: &str) -> String {
    let chars: Vec<char> = sdl.chars().collect();
    let n = chars.len();
    let mut out = String::with_capacity(sdl.len());
    let mut i = 0usize;
    let mut depth: i32 = 0;
    while i < n {
        let c = chars[i];
        match c {
            // Line comment — copy to end of line.
            '#' => {
                while i < n && chars[i] != '\n' {
                    out.push(chars[i]);
                    i += 1;
                }
            }
            // String / block string — copy the whole literal so its contents never affect
            // brace depth or keyword detection.
            '"' => {
                let (lit, next) = read_string_literal(&chars, i);
                out.push_str(&lit);
                i = next;
            }
            '{' => {
                depth += 1;
                out.push(c);
                i += 1;
            }
            '}' => {
                depth -= 1;
                out.push(c);
                i += 1;
            }
            // A definition keyword only starts at top level (brace depth 0).
            _ if depth == 0 && (c.is_ascii_alphabetic() || c == '_') => {
                let start = i;
                while i < n && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                match word.as_str() {
                    // A `schema` definition: drop the keyword and its body.
                    "schema" => i = skip_schema_body(&chars, i),
                    // `extend schema` → drop; any other `extend <kind>` → keep verbatim.
                    "extend" => {
                        let after_extend = i;
                        let ws_end = skip_ws_and_comments(&chars, i);
                        let mut k = ws_end;
                        while k < n && (chars[k].is_ascii_alphanumeric() || chars[k] == '_') {
                            k += 1;
                        }
                        if chars[ws_end..k].iter().collect::<String>() == "schema" {
                            i = skip_schema_body(&chars, k);
                        } else {
                            out.push_str(&word);
                            i = after_extend;
                        }
                    }
                    _ => out.push_str(&word),
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// Skip a `schema` definition's body starting just after the `schema` keyword: any directives
/// (`@name(...)`) followed by an optional `{ … }` operation-type block. Returns the index past it.
fn skip_schema_body(chars: &[char], mut i: usize) -> usize {
    let n = chars.len();
    loop {
        i = skip_ws_and_comments(chars, i);
        if i < n && chars[i] == '@' {
            i += 1; // '@'
            while i < n && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let j = skip_ws_and_comments(chars, i);
            if j < n && chars[j] == '(' {
                i = skip_balanced(chars, j, '(', ')');
            } else {
                i = j;
            }
        } else {
            break;
        }
    }
    i = skip_ws_and_comments(chars, i);
    if i < n && chars[i] == '{' {
        i = skip_balanced(chars, i, '{', '}');
    }
    i
}

/// Skip whitespace, commas, and line comments; return the next significant index.
fn skip_ws_and_comments(chars: &[char], mut i: usize) -> usize {
    let n = chars.len();
    while i < n {
        let c = chars[i];
        if c.is_whitespace() || c == ',' {
            i += 1;
        } else if c == '#' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
        } else {
            break;
        }
    }
    i
}

/// Skip a balanced `open`…`close` span (nesting-aware, string-aware), assuming `chars[i] ==
/// open`. Returns the index just past the matching `close`.
fn skip_balanced(chars: &[char], mut i: usize, open: char, close: char) -> usize {
    let n = chars.len();
    let mut depth = 0i32;
    while i < n {
        let c = chars[i];
        if c == '"' {
            i = read_string_literal(chars, i).1;
        } else if c == '#' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
        } else if c == open {
            depth += 1;
            i += 1;
        } else if c == close {
            depth -= 1;
            i += 1;
            if depth == 0 {
                break;
            }
        } else {
            i += 1;
        }
    }
    i
}

/// Read a GraphQL string literal (regular `"…"` with escapes, or a `"""…"""` block string)
/// starting at `chars[i] == '"'`. Returns the literal text and the index just past it.
fn read_string_literal(chars: &[char], mut i: usize) -> (String, usize) {
    let n = chars.len();
    let mut out = String::new();
    // Block string `"""…"""`.
    if i + 2 < n && chars[i] == '"' && chars[i + 1] == '"' && chars[i + 2] == '"' {
        out.push_str("\"\"\"");
        i += 3;
        while i < n {
            if chars[i] == '\\' && i + 1 < n {
                out.push(chars[i]);
                out.push(chars[i + 1]);
                i += 2;
                continue;
            }
            if i + 2 < n && chars[i] == '"' && chars[i + 1] == '"' && chars[i + 2] == '"' {
                out.push_str("\"\"\"");
                return (out, i + 3);
            }
            out.push(chars[i]);
            i += 1;
        }
        return (out, i);
    }
    // Regular string.
    out.push('"');
    i += 1;
    while i < n {
        let c = chars[i];
        out.push(c);
        i += 1;
        if c == '\\' && i < n {
            out.push(chars[i]);
            i += 1;
        } else if c == '"' {
            break;
        }
    }
    (out, i)
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
    fn strip_drops_schema_extensions_but_keeps_the_type_system() {
        // `extend schema @link(...)` (directives only, no block) is dropped…
        let stripped = strip_schema_definitions(ASYNC_GRAPHQL_V2);
        assert!(
            !stripped.contains("extend schema"),
            "schema extension not dropped"
        );
        assert!(!stripped.contains("@link"), "@link preamble not dropped");
        // …while the object types, entity key, and directive defs the composer/parser need remain.
        assert!(stripped.contains("type User @key(fields: \"id\")"));
        assert!(stripped.contains("type Query"));
        assert!(stripped.contains("directive @skip"));
    }

    #[test]
    fn strip_drops_a_schema_definition_block() {
        let sdl = "schema @link(url: \"x\") { query: Query }\ntype Query { a: Int }";
        let stripped = strip_schema_definitions(sdl);
        assert!(
            !stripped.contains("schema"),
            "schema block not dropped: {stripped}"
        );
        assert!(stripped.contains("type Query { a: Int }"));
        // And it still parses + composes.
        let sg = compose(&[sub("s", sdl)]).unwrap();
        assert_eq!(sg.root_query.get("a").map(String::as_str), Some("s"));
    }

    #[test]
    fn strip_preserves_extend_type_and_string_contents() {
        // `extend type` must survive (only `extend schema` is dropped); a `schema`/`@link`
        // living inside a description or a field must be left untouched.
        let sdl = concat!(
            "\"\"\"a schema @link doc string\"\"\"\n",
            "type Query { schemaVersion: String }\n",
            "extend type Query @key(fields: \"id\") { extra: Int }\n",
        );
        let stripped = strip_schema_definitions(sdl);
        assert!(
            stripped.contains("extend type Query"),
            "extend type dropped: {stripped}"
        );
        assert!(
            stripped.contains("schemaVersion"),
            "field name mangled: {stripped}"
        );
        assert!(
            stripped.contains("schema @link doc string"),
            "string contents mangled"
        );
    }

    #[test]
    fn unparsable_sdl_is_a_composition_error() {
        let err = compose(&[sub("bad", "type Query { ")]).unwrap_err();
        assert!(matches!(err, CompositionError::Parse { subgraph, .. } if subgraph == "bad"));
    }
}
