//! Federation-introspection synthesis (per-site subgraph composition, S3).
//!
//! The federation gateway plans + executes against the routing model ([`crate::graphql_federation`]'s
//! `Supergraph`), which carries field ownership but NOT a full type system — so `__schema`/`__type`
//! never planned on the federated edge. This module closes that: it retains a merged, PUBLIC type
//! system of exactly the composed (subset) subgraphs, and answers an introspection query from it.
//!
//! The result is the marquee guarantee of per-site composition: a site's introspection honestly
//! reflects ONLY its subset. An excluded subgraph's types + roots are genuinely absent from
//! `__schema` (not merely unreachable) — because the type system is BUILT from the subset's SDLs, so
//! the excluded SDL never enters it. Federation machinery (`@key`/`@external`/`@shareable`/`@tenant`/
//! `@edgeHidden`/`@link` directives, the `_Service`/`_Entity`/`_Any`/`_FieldSet` types, the
//! `Query._service`/`Query._entities` roots) is stripped — introspection shows the public graph, not
//! the federation plumbing. Edge-hidden roots (the effective `edge_hidden_*` set) are ALSO removed
//! from the synthesized schema, so introspection can never become an oracle for a root that plans as
//! `UnknownRootField` (the no-oracle property the reachability layer relies on).
//!
//! Pure + deterministic: SDLs + the effective-hidden set in, an introspection JSON response out; no
//! I/O. Built once per composition and cached beside the `Supergraph` in [`crate::graphql_cache`].

use async_graphql_parser::types::{
    BaseType, ExecutableDocument, Selection, SelectionSet, TypeKind,
};
use async_graphql_value::{ConstValue, Value};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A GraphQL type reference — the recursive `LIST`/`NON_NULL` wrapper over a `NAMED` type, the exact
/// shape `__Type.ofType` walks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TypeRef {
    Named(String),
    NonNull(Box<Self>),
    List(Box<Self>),
}

/// One argument / input field (`__InputValue`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InputValueDef {
    pub name: String,
    pub description: Option<String>,
    pub ty: TypeRef,
    /// The default value rendered as a GraphQL literal (introspection's `defaultValue` is a string).
    pub default_value: Option<String>,
}

/// One object/interface field (`__Field`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FieldDef {
    pub name: String,
    pub description: Option<String>,
    pub args: Vec<InputValueDef>,
    pub ty: TypeRef,
    pub deprecated: bool,
    pub deprecation_reason: Option<String>,
}

/// One enum value (`__EnumValue`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnumValueDef {
    pub name: String,
    pub description: Option<String>,
    pub deprecated: bool,
    pub deprecation_reason: Option<String>,
}

/// A public type definition, federation-stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TypeDef {
    Object {
        description: Option<String>,
        fields: Vec<FieldDef>,
        interfaces: Vec<String>,
    },
    Interface {
        description: Option<String>,
        fields: Vec<FieldDef>,
        interfaces: Vec<String>,
    },
    Union {
        description: Option<String>,
        possible_types: Vec<String>,
    },
    Enum {
        description: Option<String>,
        values: Vec<EnumValueDef>,
    },
    InputObject {
        description: Option<String>,
        input_fields: Vec<InputValueDef>,
    },
    Scalar {
        description: Option<String>,
    },
}

/// The composed PUBLIC type system of a (subset of) subgraphs — everything `__schema`/`__type` needs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SchemaTypes {
    /// Every public type by name (user types, the built-in scalars, the root operation types).
    pub types: BTreeMap<String, TypeDef>,
    pub query_type: Option<String>,
    pub mutation_type: Option<String>,
    pub subscription_type: Option<String>,
}

impl SchemaTypes {
    /// A view of this schema with the effective edge-hidden ROOT fields removed from the root
    /// `Query`/`Mutation` types — so introspection never advertises a root that the planner treats
    /// as unknown (no-oracle). `hidden` is the already-resolved `(root_type, field)` set; empty ⇒
    /// `self` unchanged (no clone).
    fn with_hidden_removed<'a>(
        &'a self,
        hidden: &BTreeSet<(String, String)>,
    ) -> std::borrow::Cow<'a, Self> {
        if hidden.is_empty() {
            return std::borrow::Cow::Borrowed(self);
        }
        let mut out = self.clone();
        for root in ["Query", "Mutation"] {
            if let Some(TypeDef::Object { fields, .. }) = out.types.get_mut(root) {
                fields.retain(|f| !hidden.contains(&(root.to_string(), f.name.clone())));
            }
        }
        std::borrow::Cow::Owned(out)
    }
}

/// A standard GraphQL directive (`__Directive`) — the fixed set every schema advertises.
struct DirectiveDef {
    name: &'static str,
    description: &'static str,
    locations: &'static [&'static str],
    args: Vec<InputValueDef>,
    repeatable: bool,
}

// ---- Composition: subgraph SDLs → the merged public type system --------------------------------

/// Whether `name` is a federation-internal type that must never surface in the public schema:
/// the `_`-prefixed federation types (`_Service`, `_Entity`, `_Any`, `_FieldSet`) and the
/// `@link`/`federation` namespaced imports (`link__Purpose`, `federation__*`).
fn is_federation_type(name: &str) -> bool {
    name.starts_with('_') || name.starts_with("link__") || name.starts_with("federation__")
}

/// Whether a root `Query` field is federation plumbing (`_service`, `_entities`) rather than a
/// public operation.
fn is_federation_root_field(type_name: &str, field_name: &str) -> bool {
    type_name == "Query" && (field_name == "_service" || field_name == "_entities")
}

/// Convert a parser `Type` into the recursive introspection [`TypeRef`] (preserving list / non-null
/// wrappers, which the routing model's `base_type_name` discards).
fn type_ref(ty: &async_graphql_parser::types::Type) -> TypeRef {
    let core = match &ty.base {
        BaseType::Named(n) => TypeRef::Named(n.to_string()),
        BaseType::List(inner) => TypeRef::List(Box::new(type_ref(inner))),
    };
    if ty.nullable {
        core
    } else {
        TypeRef::NonNull(Box::new(core))
    }
}

/// Read a `@deprecated` directive into `(deprecated, reason)`. A bare `@deprecated` ⇒
/// `(true, "No longer supported")` (the spec default); `@deprecated(reason: "…")` ⇒ that reason.
fn deprecation(
    dirs: &[async_graphql_parser::Positioned<async_graphql_parser::types::ConstDirective>],
) -> (bool, Option<String>) {
    let Some(d) = dirs.iter().find(|d| d.node.name.node == "deprecated") else {
        return (false, None);
    };
    let reason = d
        .node
        .arguments
        .iter()
        .find(|(n, _)| n.node == "reason")
        .and_then(|(_, v)| match &v.node {
            ConstValue::String(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_else(|| "No longer supported".to_string());
    (true, Some(reason))
}

fn has_external(
    dirs: &[async_graphql_parser::Positioned<async_graphql_parser::types::ConstDirective>],
) -> bool {
    dirs.iter().any(|d| d.node.name.node == "external")
}

fn opt_desc(d: &Option<async_graphql_parser::Positioned<String>>) -> Option<String> {
    d.as_ref().map(|d| d.node.clone())
}

fn convert_input_value(iv: &async_graphql_parser::types::InputValueDefinition) -> InputValueDef {
    InputValueDef {
        name: iv.name.node.to_string(),
        description: opt_desc(&iv.description),
        ty: type_ref(&iv.ty.node),
        default_value: iv.default_value.as_ref().map(|v| v.node.to_string()),
    }
}

/// Convert a type's fields to public [`FieldDef`]s, dropping `@external` references (owned
/// elsewhere) and the federation root fields (`_service`/`_entities`).
fn convert_fields(
    type_name: &str,
    fields: &[async_graphql_parser::Positioned<async_graphql_parser::types::FieldDefinition>],
) -> Vec<FieldDef> {
    fields
        .iter()
        .map(|f| &f.node)
        .filter(|f| !has_external(&f.directives))
        .filter(|f| !is_federation_root_field(type_name, f.name.node.as_str()))
        .map(|f| {
            let (deprecated, deprecation_reason) = deprecation(&f.directives);
            FieldDef {
                name: f.name.node.to_string(),
                description: opt_desc(&f.description),
                args: f
                    .arguments
                    .iter()
                    .map(|a| convert_input_value(&a.node))
                    .collect(),
                ty: type_ref(&f.ty.node),
                deprecated,
                deprecation_reason,
            }
        })
        .collect()
}

/// Merge an object/interface type's fields + interfaces into an existing entry (union by field
/// name — the first subgraph to own a field keeps it; a shareable field defined identically in
/// several subgraphs dedupes), or insert it.
fn merge_object(
    types: &mut BTreeMap<String, TypeDef>,
    name: &str,
    description: Option<String>,
    new_fields: Vec<FieldDef>,
    new_interfaces: Vec<String>,
    is_interface: bool,
) {
    match types.get_mut(name) {
        Some(TypeDef::Object {
            fields, interfaces, ..
        })
        | Some(TypeDef::Interface {
            fields, interfaces, ..
        }) => {
            for f in new_fields {
                if !fields.iter().any(|existing| existing.name == f.name) {
                    fields.push(f);
                }
            }
            for i in new_interfaces {
                if !interfaces.contains(&i) {
                    interfaces.push(i);
                }
            }
        }
        _ => {
            let td = if is_interface {
                TypeDef::Interface {
                    description,
                    fields: new_fields,
                    interfaces: new_interfaces,
                }
            } else {
                TypeDef::Object {
                    description,
                    fields: new_fields,
                    interfaces: new_interfaces,
                }
            };
            types.insert(name.to_string(), td);
        }
    }
}

/// Compose the PUBLIC type system of exactly the given subgraphs. An unparsable SDL is skipped (the
/// routing composer is the authority on composition errors — this is a best-effort introspection
/// view built from the same SDLs, so it never fails the request; a subgraph whose SDL the routing
/// composer accepted parses here too). Built-in scalars are always present.
pub(crate) fn compose_schema_types(subgraphs: &[(String, String)]) -> SchemaTypes {
    let mut types: BTreeMap<String, TypeDef> = BTreeMap::new();

    for (_name, sdl) in subgraphs {
        let Ok(doc) = async_graphql_parser::parse_schema(sdl) else {
            continue;
        };
        for def in &doc.definitions {
            let async_graphql_parser::types::TypeSystemDefinition::Type(ty) = def else {
                continue;
            };
            let td = &ty.node;
            let name = td.name.node.as_str();
            if is_federation_type(name) {
                continue;
            }
            match &td.kind {
                TypeKind::Object(obj) => merge_object(
                    &mut types,
                    name,
                    opt_desc(&td.description),
                    convert_fields(name, &obj.fields),
                    obj.implements.iter().map(|i| i.node.to_string()).collect(),
                    false,
                ),
                TypeKind::Interface(iface) => merge_object(
                    &mut types,
                    name,
                    opt_desc(&td.description),
                    convert_fields(name, &iface.fields),
                    iface
                        .implements
                        .iter()
                        .map(|i| i.node.to_string())
                        .collect(),
                    true,
                ),
                TypeKind::Union(u) => {
                    types
                        .entry(name.to_string())
                        .or_insert_with(|| TypeDef::Union {
                            description: opt_desc(&td.description),
                            possible_types: u.members.iter().map(|m| m.node.to_string()).collect(),
                        });
                }
                TypeKind::Enum(e) => {
                    types
                        .entry(name.to_string())
                        .or_insert_with(|| TypeDef::Enum {
                            description: opt_desc(&td.description),
                            values: e
                                .values
                                .iter()
                                .map(|v| {
                                    let (deprecated, deprecation_reason) =
                                        deprecation(&v.node.directives);
                                    EnumValueDef {
                                        name: v.node.value.node.to_string(),
                                        description: opt_desc(&v.node.description),
                                        deprecated,
                                        deprecation_reason,
                                    }
                                })
                                .collect(),
                        });
                }
                TypeKind::InputObject(io) => {
                    types
                        .entry(name.to_string())
                        .or_insert_with(|| TypeDef::InputObject {
                            description: opt_desc(&td.description),
                            input_fields: io
                                .fields
                                .iter()
                                .map(|f| convert_input_value(&f.node))
                                .collect(),
                        });
                }
                TypeKind::Scalar => {
                    types.entry(name.to_string()).or_insert(TypeDef::Scalar {
                        description: opt_desc(&td.description),
                    });
                }
            }
        }
    }

    // Built-in scalars are implicitly part of every schema (clients' `buildClientSchema` resolves
    // field types against the `types` list).
    for s in ["Int", "Float", "String", "Boolean", "ID"] {
        types
            .entry(s.to_string())
            .or_insert(TypeDef::Scalar { description: None });
    }

    // Root operation types are present only if the composed set actually declares one with fields.
    let has_fields = |n: &str| matches!(types.get(n), Some(TypeDef::Object { fields, .. }) if !fields.is_empty());
    SchemaTypes {
        query_type: has_fields("Query").then(|| "Query".to_string()),
        mutation_type: has_fields("Mutation").then(|| "Mutation".to_string()),
        subscription_type: has_fields("Subscription").then(|| "Subscription".to_string()),
        types,
    }
}

// ---- Execution: an introspection query → a JSON response ---------------------------------------

/// Whether `doc` is a PURE introspection query: every root field (fragments expanded) is a meta-field
/// (`__schema`/`__type`/`__typename`) and at least one is `__schema`/`__type`. A query mixing
/// introspection with data roots is NOT intercepted (it plans as before — where `__schema` is an
/// unknown root — so there is no behavior change for such a degenerate query).
pub(crate) fn is_pure_introspection(doc: &ExecutableDocument) -> bool {
    let fragments = crate::graphql_root_fields::document_fragments(doc);
    let roots: Vec<(crate::graphql_root_fields::RootType, String)> = operations(doc)
        .iter()
        .flat_map(|op| crate::graphql_root_fields::expanded_root_fields(op, &fragments))
        .collect();
    !roots.is_empty()
        && roots
            .iter()
            .all(|(_, n)| n == "__schema" || n == "__type" || n == "__typename")
        && roots.iter().any(|(_, n)| n == "__schema" || n == "__type")
}

fn operations(doc: &ExecutableDocument) -> Vec<&async_graphql_parser::types::OperationDefinition> {
    use async_graphql_parser::types::DocumentOperations;
    match &doc.operations {
        DocumentOperations::Single(op) => vec![&op.node],
        DocumentOperations::Multiple(m) => m.values().map(|o| &o.node).collect(),
    }
}

/// Execute an introspection query against the composed type system, honoring the effective
/// edge-hidden root set (hidden roots are absent from the synthesized schema). Returns the GraphQL
/// response body (`{"data": …}`). The introspection POLICY (allow/deny) is enforced upstream by the
/// query guard, so reaching here means introspection is permitted on this site.
pub(crate) fn execute(
    doc: &ExecutableDocument,
    schema: &SchemaTypes,
    hidden: &BTreeSet<(String, String)>,
) -> serde_json::Value {
    let schema = schema.with_hidden_removed(hidden);
    let schema = schema.as_ref();
    let fragments = crate::graphql_root_fields::document_fragments(doc);
    // The sole query operation of an introspection request (the first query op if several ops exist).
    let Some(op) = operations(doc)
        .into_iter()
        .find(|op| op.ty == async_graphql_parser::types::OperationType::Query)
    else {
        return serde_json::json!({ "errors": [{ "message": "no query operation" }] });
    };

    let mut data = serde_json::Map::new();
    visit_selection(&op.selection_set.node, &fragments, &mut |field| {
        let key = field
            .alias
            .as_ref()
            .map(|a| a.node.to_string())
            .unwrap_or_else(|| field.name.node.to_string());
        let value = match field.name.node.as_str() {
            "__schema" => resolve_object(
                &INode::Schema,
                &field.selection_set.node,
                &fragments,
                schema,
            ),
            "__type" => match string_arg(field, "name") {
                Some(name) if schema.types.contains_key(&name) => resolve_object(
                    &INode::Type(TypeRef::Named(name)),
                    &field.selection_set.node,
                    &fragments,
                    schema,
                ),
                _ => serde_json::Value::Null,
            },
            "__typename" => serde_json::Value::String(
                schema
                    .query_type
                    .clone()
                    .unwrap_or_else(|| "Query".to_string()),
            ),
            _ => serde_json::Value::Null,
        };
        data.insert(key, value);
    });
    serde_json::json!({ "data": data })
}

/// A resolved introspection object node.
enum INode<'a> {
    Schema,
    Type(TypeRef),
    Field(&'a FieldDef),
    InputValue(&'a InputValueDef),
    EnumValue(&'a EnumValueDef),
    Directive(&'a DirectiveDef),
}

/// Walk a selection set, expanding inline fragments + named fragment spreads (cycle-guarded), and
/// call `f` for each concrete field selection. `@skip`/`@include` are not honored — introspection
/// queries do not use them.
fn visit_selection<'a>(
    sel: &'a SelectionSet,
    fragments: &HashMap<&'a str, &'a SelectionSet>,
    f: &mut dyn FnMut(&'a async_graphql_parser::types::Field),
) {
    visit_inner(sel, fragments, f, &mut Vec::new());
}

fn visit_inner<'a>(
    sel: &'a SelectionSet,
    fragments: &HashMap<&'a str, &'a SelectionSet>,
    f: &mut dyn FnMut(&'a async_graphql_parser::types::Field),
    stack: &mut Vec<&'a str>,
) {
    for item in &sel.items {
        match &item.node {
            Selection::Field(field) => f(&field.node),
            Selection::InlineFragment(inl) => {
                visit_inner(&inl.node.selection_set.node, fragments, f, stack);
            }
            Selection::FragmentSpread(fs) => {
                let name = fs.node.fragment_name.node.as_str();
                if stack.contains(&name) {
                    continue; // cyclic fragment — terminate
                }
                if let Some(frag) = fragments.get(name) {
                    stack.push(name);
                    visit_inner(frag, fragments, f, stack);
                    stack.pop();
                }
            }
        }
    }
}

/// Resolve `node` against `sel`, returning a JSON object with one entry per selected field.
fn resolve_object(
    node: &INode,
    sel: &SelectionSet,
    fragments: &HashMap<&str, &SelectionSet>,
    schema: &SchemaTypes,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    // Collect selections eagerly (visit_selection borrows for 'a tied to `sel`; here `sel` is the
    // caller's, so gather field refs then resolve).
    let mut fields: Vec<&async_graphql_parser::types::Field> = Vec::new();
    visit_selection(sel, fragments, &mut |field| fields.push(field));
    for field in fields {
        let key = field
            .alias
            .as_ref()
            .map(|a| a.node.to_string())
            .unwrap_or_else(|| field.name.node.to_string());
        obj.insert(
            key,
            resolve_field(node, field, &field.selection_set.node, fragments, schema),
        );
    }
    serde_json::Value::Object(obj)
}

fn resolve_field(
    node: &INode,
    field: &async_graphql_parser::types::Field,
    sub: &SelectionSet,
    fragments: &HashMap<&str, &SelectionSet>,
    schema: &SchemaTypes,
) -> serde_json::Value {
    let fname = field.name.node.as_str();
    use serde_json::Value::Null;
    match node {
        INode::Schema => match fname {
            "__typename" => "__Schema".into(),
            "description" => Null,
            "queryType" => type_or_null(&schema.query_type, sub, fragments, schema),
            "mutationType" => type_or_null(&schema.mutation_type, sub, fragments, schema),
            "subscriptionType" => type_or_null(&schema.subscription_type, sub, fragments, schema),
            "types" => serde_json::Value::Array(
                schema
                    .types
                    .keys()
                    .map(|n| {
                        resolve_object(
                            &INode::Type(TypeRef::Named(n.clone())),
                            sub,
                            fragments,
                            schema,
                        )
                    })
                    .collect(),
            ),
            "directives" => serde_json::Value::Array(
                standard_directives()
                    .iter()
                    .map(|d| resolve_object(&INode::Directive(d), sub, fragments, schema))
                    .collect(),
            ),
            _ => Null,
        },
        INode::Type(tref) => resolve_type_field(tref, field, fname, sub, fragments, schema),
        INode::Field(fd) => match fname {
            "__typename" => "__Field".into(),
            "name" => fd.name.clone().into(),
            "description" => opt_str(&fd.description),
            "args" => serde_json::Value::Array(
                fd.args
                    .iter()
                    .map(|a| resolve_object(&INode::InputValue(a), sub, fragments, schema))
                    .collect(),
            ),
            "type" => resolve_object(&INode::Type(fd.ty.clone()), sub, fragments, schema),
            "isDeprecated" => fd.deprecated.into(),
            "deprecationReason" => opt_str(&fd.deprecation_reason),
            _ => Null,
        },
        INode::InputValue(iv) => match fname {
            "__typename" => "__InputValue".into(),
            "name" => iv.name.clone().into(),
            "description" => opt_str(&iv.description),
            "type" => resolve_object(&INode::Type(iv.ty.clone()), sub, fragments, schema),
            "defaultValue" => opt_str(&iv.default_value),
            _ => Null,
        },
        INode::EnumValue(ev) => match fname {
            "__typename" => "__EnumValue".into(),
            "name" => ev.name.clone().into(),
            "description" => opt_str(&ev.description),
            "isDeprecated" => ev.deprecated.into(),
            "deprecationReason" => opt_str(&ev.deprecation_reason),
            _ => Null,
        },
        INode::Directive(d) => match fname {
            "__typename" => "__Directive".into(),
            "name" => d.name.into(),
            "description" => d.description.into(),
            "isRepeatable" => d.repeatable.into(),
            "locations" => {
                serde_json::Value::Array(d.locations.iter().map(|l| (*l).into()).collect())
            }
            "args" => serde_json::Value::Array(
                d.args
                    .iter()
                    .map(|a| resolve_object(&INode::InputValue(a), sub, fragments, schema))
                    .collect(),
            ),
            _ => Null,
        },
    }
}

fn resolve_type_field(
    tref: &TypeRef,
    field: &async_graphql_parser::types::Field,
    fname: &str,
    sub: &SelectionSet,
    fragments: &HashMap<&str, &SelectionSet>,
    schema: &SchemaTypes,
) -> serde_json::Value {
    use serde_json::Value::Null;
    // Wrapper types (LIST / NON_NULL) answer only kind + ofType; everything else is null.
    let named = match tref {
        TypeRef::NonNull(inner) => {
            return match fname {
                "__typename" => "__Type".into(),
                "kind" => "NON_NULL".into(),
                "ofType" => resolve_object(&INode::Type((**inner).clone()), sub, fragments, schema),
                _ => Null,
            };
        }
        TypeRef::List(inner) => {
            return match fname {
                "__typename" => "__Type".into(),
                "kind" => "LIST".into(),
                "ofType" => resolve_object(&INode::Type((**inner).clone()), sub, fragments, schema),
                _ => Null,
            };
        }
        TypeRef::Named(n) => n,
    };
    let def = schema.types.get(named);
    match fname {
        "__typename" => "__Type".into(),
        "name" => named.clone().into(),
        "kind" => kind_str(def).into(),
        "description" => match def {
            Some(TypeDef::Object { description, .. })
            | Some(TypeDef::Interface { description, .. })
            | Some(TypeDef::Union { description, .. })
            | Some(TypeDef::Enum { description, .. })
            | Some(TypeDef::InputObject { description, .. })
            | Some(TypeDef::Scalar { description }) => opt_str(description),
            None => Null,
        },
        "ofType" => Null, // a named type has no ofType
        "specifiedByURL" => Null,
        "fields" => match def {
            Some(TypeDef::Object { fields, .. }) | Some(TypeDef::Interface { fields, .. }) => {
                let include_deprecated = bool_arg(field, "includeDeprecated");
                serde_json::Value::Array(
                    fields
                        .iter()
                        .filter(|f| include_deprecated || !f.deprecated)
                        .map(|f| resolve_object(&INode::Field(f), sub, fragments, schema))
                        .collect(),
                )
            }
            _ => Null,
        },
        "inputFields" => match def {
            Some(TypeDef::InputObject { input_fields, .. }) => serde_json::Value::Array(
                input_fields
                    .iter()
                    .map(|iv| resolve_object(&INode::InputValue(iv), sub, fragments, schema))
                    .collect(),
            ),
            _ => Null,
        },
        "interfaces" => match def {
            Some(TypeDef::Object { interfaces, .. })
            | Some(TypeDef::Interface { interfaces, .. }) => serde_json::Value::Array(
                interfaces
                    .iter()
                    .map(|i| {
                        resolve_object(
                            &INode::Type(TypeRef::Named(i.clone())),
                            sub,
                            fragments,
                            schema,
                        )
                    })
                    .collect(),
            ),
            _ => Null,
        },
        "possibleTypes" => match def {
            Some(TypeDef::Union { possible_types, .. }) => serde_json::Value::Array(
                possible_types
                    .iter()
                    .map(|p| {
                        resolve_object(
                            &INode::Type(TypeRef::Named(p.clone())),
                            sub,
                            fragments,
                            schema,
                        )
                    })
                    .collect(),
            ),
            Some(TypeDef::Interface { .. }) => serde_json::Value::Array(
                // Objects/interfaces that implement this interface.
                schema
                    .types
                    .iter()
                    .filter_map(|(n, td)| match td {
                        TypeDef::Object { interfaces, .. }
                        | TypeDef::Interface { interfaces, .. }
                            if interfaces.iter().any(|i| i == named) =>
                        {
                            Some(resolve_object(
                                &INode::Type(TypeRef::Named(n.clone())),
                                sub,
                                fragments,
                                schema,
                            ))
                        }
                        _ => None,
                    })
                    .collect(),
            ),
            _ => Null,
        },
        "enumValues" => match def {
            Some(TypeDef::Enum { values, .. }) => {
                let include_deprecated = bool_arg(field, "includeDeprecated");
                serde_json::Value::Array(
                    values
                        .iter()
                        .filter(|v| include_deprecated || !v.deprecated)
                        .map(|v| resolve_object(&INode::EnumValue(v), sub, fragments, schema))
                        .collect(),
                )
            }
            _ => Null,
        },
        _ => Null,
    }
}

fn kind_str(def: Option<&TypeDef>) -> &'static str {
    match def {
        Some(TypeDef::Object { .. }) => "OBJECT",
        Some(TypeDef::Interface { .. }) => "INTERFACE",
        Some(TypeDef::Union { .. }) => "UNION",
        Some(TypeDef::Enum { .. }) => "ENUM",
        Some(TypeDef::InputObject { .. }) => "INPUT_OBJECT",
        // A referenced-but-unknown name (should not occur — built-ins are present) renders as a
        // scalar rather than crashing.
        Some(TypeDef::Scalar { .. }) | None => "SCALAR",
    }
}

fn type_or_null(
    name: &Option<String>,
    sub: &SelectionSet,
    fragments: &HashMap<&str, &SelectionSet>,
    schema: &SchemaTypes,
) -> serde_json::Value {
    match name {
        Some(n) => resolve_object(
            &INode::Type(TypeRef::Named(n.clone())),
            sub,
            fragments,
            schema,
        ),
        None => serde_json::Value::Null,
    }
}

fn opt_str(s: &Option<String>) -> serde_json::Value {
    match s {
        Some(s) => serde_json::Value::String(s.clone()),
        None => serde_json::Value::Null,
    }
}

/// A string-valued literal argument (`__type(name: "X")`). Variables are not supported for
/// introspection arguments (clients pass literals).
fn string_arg(field: &async_graphql_parser::types::Field, name: &str) -> Option<String> {
    field
        .arguments
        .iter()
        .find(|(n, _)| n.node == name)
        .and_then(|(_, v)| match &v.node {
            Value::String(s) => Some(s.clone()),
            _ => None,
        })
}

/// A boolean literal argument (`fields(includeDeprecated: true)`); default `false`.
fn bool_arg(field: &async_graphql_parser::types::Field, name: &str) -> bool {
    field
        .arguments
        .iter()
        .find(|(n, _)| n.node == name)
        .and_then(|(_, v)| match &v.node {
            Value::Boolean(b) => Some(*b),
            _ => None,
        })
        .unwrap_or(false)
}

/// The fixed standard directive set every schema advertises (`@include`, `@skip`, `@deprecated`,
/// `@specifiedBy`) — so a client's `__schema { directives { … } }` is well-formed.
fn standard_directives() -> Vec<DirectiveDef> {
    let if_arg = |desc: &'static str| InputValueDef {
        name: "if".to_string(),
        description: Some(desc.to_string()),
        ty: TypeRef::NonNull(Box::new(TypeRef::Named("Boolean".to_string()))),
        default_value: None,
    };
    vec![
        DirectiveDef {
            name: "include",
            description: "Directs the executor to include this field or fragment only when the `if` argument is true.",
            locations: &["FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"],
            args: vec![if_arg("Included when true.")],
            repeatable: false,
        },
        DirectiveDef {
            name: "skip",
            description: "Directs the executor to skip this field or fragment when the `if` argument is true.",
            locations: &["FIELD", "FRAGMENT_SPREAD", "INLINE_FRAGMENT"],
            args: vec![if_arg("Skipped when true.")],
            repeatable: false,
        },
        DirectiveDef {
            name: "deprecated",
            description: "Marks an element of a GraphQL schema as no longer supported.",
            locations: &[
                "FIELD_DEFINITION",
                "ARGUMENT_DEFINITION",
                "INPUT_FIELD_DEFINITION",
                "ENUM_VALUE",
            ],
            args: vec![InputValueDef {
                name: "reason".to_string(),
                description: Some("Explains why this element was deprecated.".to_string()),
                ty: TypeRef::Named("String".to_string()),
                default_value: Some("\"No longer supported\"".to_string()),
            }],
            repeatable: false,
        },
        DirectiveDef {
            name: "specifiedBy",
            description: "Exposes a URL that specifies the behavior of this scalar.",
            locations: &["SCALAR"],
            args: vec![InputValueDef {
                name: "url".to_string(),
                description: Some(
                    "The URL that specifies the behavior of this scalar.".to_string(),
                ),
                ty: TypeRef::NonNull(Box::new(TypeRef::Named("String".to_string()))),
                default_value: None,
            }],
            repeatable: false,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNTS: &str = r#"
        type Query { me: User }
        type User @key(fields: "id") { id: ID! name: String }
    "#;
    const REVIEWS: &str = r#"
        type Query { topReviews: [Review] }
        type Review { id: ID! body: String author: User }
        extend type User @key(fields: "id") { id: ID! @external reviews: [Review] }
    "#;

    fn subgraphs(set: &[(&str, &str)]) -> Vec<(String, String)> {
        set.iter()
            .map(|(n, s)| (n.to_string(), s.to_string()))
            .collect()
    }

    fn run(query: &str, schema: &SchemaTypes) -> serde_json::Value {
        let doc = async_graphql_parser::parse_query(query).unwrap();
        assert!(
            is_pure_introspection(&doc),
            "query must be pure introspection"
        );
        execute(&doc, schema, &BTreeSet::new())
    }

    #[test]
    fn full_set_merges_types_and_strips_federation() {
        let st = compose_schema_types(&subgraphs(&[("accounts", ACCOUNTS), ("reviews", REVIEWS)]));
        // The merged `User` carries fields from BOTH subgraphs (id + name from accounts, reviews from
        // reviews), and the `@external` reference does not duplicate `id`.
        let TypeDef::Object { fields, .. } = st.types.get("User").expect("User") else {
            panic!("User is an object");
        };
        let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["id", "name", "reviews"]);
        // Federation internals are absent from the public schema.
        assert!(!st.types.contains_key("_Service"), "_Service stripped");
        assert!(!st.types.contains_key("_Entity"), "_Entity stripped");
        assert!(!st.types.contains_key("_Any"), "_Any stripped");
        // Root Query has the public roots, not `_service`/`_entities`.
        let TypeDef::Object { fields: q, .. } = st.types.get("Query").expect("Query") else {
            panic!("Query object");
        };
        let roots: BTreeSet<&str> = q.iter().map(|f| f.name.as_str()).collect();
        assert!(roots.contains("me") && roots.contains("topReviews"));
        assert!(!roots.contains("_service") && !roots.contains("_entities"));
        // Built-in scalars are present.
        assert!(matches!(st.types.get("ID"), Some(TypeDef::Scalar { .. })));
    }

    #[test]
    fn subset_omits_the_excluded_subgraphs_types_and_roots() {
        // Compose ONLY accounts → reviews' `Review` type + `topReviews` root are genuinely absent.
        let st = compose_schema_types(&subgraphs(&[("accounts", ACCOUNTS)]));
        assert!(st.types.contains_key("User"));
        assert!(
            !st.types.contains_key("Review"),
            "excluded Review is absent"
        );
        let TypeDef::Object { fields: q, .. } = st.types.get("Query").unwrap() else {
            panic!();
        };
        let roots: BTreeSet<&str> = q.iter().map(|f| f.name.as_str()).collect();
        assert!(roots.contains("me"));
        assert!(!roots.contains("topReviews"), "excluded root absent");
        // `User` here has no `reviews` field (that lives in the excluded subgraph).
        let TypeDef::Object { fields: u, .. } = st.types.get("User").unwrap() else {
            panic!();
        };
        let unames: BTreeSet<&str> = u.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(unames, BTreeSet::from(["id", "name"]));
    }

    #[test]
    fn introspection_reflects_the_subset() {
        let full =
            compose_schema_types(&subgraphs(&[("accounts", ACCOUNTS), ("reviews", REVIEWS)]));
        let sub = compose_schema_types(&subgraphs(&[("accounts", ACCOUNTS)]));
        let q = "{ __schema { queryType { name } types { name } } }";

        let names = |v: &serde_json::Value| -> BTreeSet<String> {
            v["data"]["__schema"]["types"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect()
        };
        let full_names = names(&run(q, &full));
        assert!(full_names.contains("User") && full_names.contains("Review"));
        let sub_names = names(&run(q, &sub));
        assert!(sub_names.contains("User"));
        assert!(
            !sub_names.contains("Review"),
            "subset introspection hides Review"
        );
        // Query root type is named.
        assert_eq!(
            run(q, &sub)["data"]["__schema"]["queryType"]["name"],
            "Query"
        );
    }

    #[test]
    fn type_query_renders_wrappers_and_args() {
        let st = compose_schema_types(&subgraphs(&[("accounts", ACCOUNTS), ("reviews", REVIEWS)]));
        let q = r#"{ __type(name: "User") { kind name fields { name type { kind name ofType { kind name } } } } }"#;
        let v = run(q, &st);
        let t = &v["data"]["__type"];
        assert_eq!(t["kind"], "OBJECT");
        assert_eq!(t["name"], "User");
        let fields = t["fields"].as_array().unwrap();
        // `id: ID!` → NON_NULL wrapping the named ID scalar.
        let id = fields.iter().find(|f| f["name"] == "id").unwrap();
        assert_eq!(id["type"]["kind"], "NON_NULL");
        assert_eq!(id["type"]["ofType"]["name"], "ID");
        // `name: String` → nullable named scalar (no wrapper).
        let name = fields.iter().find(|f| f["name"] == "name").unwrap();
        assert_eq!(name["type"]["kind"], "SCALAR");
        assert_eq!(name["type"]["name"], "String");
    }

    #[test]
    fn type_query_for_an_excluded_type_is_null() {
        let sub = compose_schema_types(&subgraphs(&[("accounts", ACCOUNTS)]));
        let v = run(r#"{ __type(name: "Review") { name } }"#, &sub);
        assert_eq!(v["data"]["__type"], serde_json::Value::Null);
    }

    #[test]
    fn hidden_roots_are_absent_from_introspection() {
        let st = compose_schema_types(&subgraphs(&[("accounts", ACCOUNTS), ("reviews", REVIEWS)]));
        let doc =
            async_graphql_parser::parse_query("{ __type(name: \"Query\") { fields { name } } }")
                .unwrap();
        let hidden = BTreeSet::from([("Query".to_string(), "topReviews".to_string())]);
        let v = execute(&doc, &st, &hidden);
        let roots: BTreeSet<String> = v["data"]["__type"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap().to_string())
            .collect();
        assert!(roots.contains("me"));
        assert!(
            !roots.contains("topReviews"),
            "edge-hidden root absent from introspection (no oracle)"
        );
    }

    #[test]
    fn fragment_wrapped_introspection_is_detected_and_resolved() {
        let st = compose_schema_types(&subgraphs(&[("accounts", ACCOUNTS)]));
        let q = "query { ...F } fragment F on Query { __schema { queryType { name } } }";
        let doc = async_graphql_parser::parse_query(q).unwrap();
        assert!(is_pure_introspection(&doc));
        let v = execute(&doc, &st, &BTreeSet::new());
        assert_eq!(v["data"]["__schema"]["queryType"]["name"], "Query");
    }

    #[test]
    fn a_data_query_is_not_pure_introspection() {
        let doc = async_graphql_parser::parse_query("{ me { id } }").unwrap();
        assert!(!is_pure_introspection(&doc));
        let doc2 =
            async_graphql_parser::parse_query("{ __schema { queryType { name } } me { id } }")
                .unwrap();
        assert!(
            !is_pure_introspection(&doc2),
            "mixed query falls through to the planner"
        );
    }
}
