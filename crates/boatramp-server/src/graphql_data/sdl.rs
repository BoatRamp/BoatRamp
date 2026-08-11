//! GraphQL SDL generation from a [`DbSchema`].
//!
//! Deterministic and pure: a relational schema in, a GraphQL schema (SDL string) out. Each
//! exposed table becomes an object type plus the inputs and root fields for reading it —
//! a Hasura-shaped surface (`<table>`, `<table>_by_pk`, `where`/`order_by`/`limit`/`offset`)
//! that the query compiler lowers to SQL. The raw table/column names are used verbatim for
//! type, field, and root names, so the GraphQL↔SQL mapping is unambiguous.
//!
//! Relationship fields (from foreign keys) and the federation `@key` directive are added by
//! later landings; this module emits the scalar read surface.

use super::schema::{DbSchema, ScalarType, Table};
use std::fmt::Write;

/// The dialect-independent shared inputs: the ordering enum and one comparison-expression
/// input per scalar. Generated once per schema.
const SHARED_INPUTS: &str = "\
enum order_by { asc desc }

input Int_comparison_exp { _eq: Int _neq: Int _gt: Int _gte: Int _lt: Int _lte: Int _in: [Int!] _is_null: Boolean }
input Float_comparison_exp { _eq: Float _neq: Float _gt: Float _gte: Float _lt: Float _lte: Float _in: [Float!] _is_null: Boolean }
input String_comparison_exp { _eq: String _neq: String _gt: String _gte: String _lt: String _lte: String _in: [String!] _like: String _is_null: Boolean }
input Boolean_comparison_exp { _eq: Boolean _neq: Boolean _is_null: Boolean }
input ID_comparison_exp { _eq: ID _neq: ID _in: [ID!] _is_null: Boolean }
";

/// Generate the GraphQL SDL for `schema`'s read surface.
pub(crate) fn generate_sdl(schema: &DbSchema) -> String {
    let mut out = String::new();
    out.push_str(SHARED_INPUTS);
    for table in &schema.tables {
        out.push('\n');
        push_object_type(&mut out, table);
        push_bool_exp(&mut out, table);
        push_order_by(&mut out, table);
    }
    out.push('\n');
    push_query_root(&mut out, schema);
    out
}

/// Generate the **federation** SDL for `schema` (already policy-projected): each entity
/// table becomes a `@key`-typed object plus argless root fields, so the composition model
/// (`graphql_federation`) treats it as a subgraph. Kept minimal — the federation planner
/// sends argless root and `_entities` fetches, so the filter inputs are unneeded here.
pub(crate) fn generate_federation_sdl(schema: &DbSchema) -> String {
    let mut out = String::new();
    for table in &schema.tables {
        if table.primary_key.is_empty() {
            push_object_type(&mut out, table);
        } else {
            let key = table.primary_key.join(" ");
            let _ = writeln!(out, "type {} @key(fields: \"{key}\") {{", table.name);
            for col in &table.columns {
                let bang = if col.nullable { "" } else { "!" };
                let _ = writeln!(out, "  {}: {}{bang}", col.name, col.ty.graphql_name());
            }
            out.push_str("}\n");
        }
    }
    out.push_str("type Query {\n");
    for table in &schema.tables {
        let _ = writeln!(out, "  {t}: [{t}!]!", t = table.name);
        if !table.primary_key.is_empty() {
            let _ = writeln!(out, "  {t}_by_pk({}): {t}", pk_args(table), t = table.name);
        }
    }
    out.push_str("}\n");
    out
}

/// `type <t> { <col>: <Scalar>[!] … }`
fn push_object_type(out: &mut String, table: &Table) {
    let _ = writeln!(out, "type {} {{", table.name);
    for col in &table.columns {
        let bang = if col.nullable { "" } else { "!" };
        let _ = writeln!(out, "  {}: {}{bang}", col.name, col.ty.graphql_name());
    }
    out.push_str("}\n");
}

/// `input <t>_bool_exp { _and _or _not <col>: <Scalar>_comparison_exp … }`
fn push_bool_exp(out: &mut String, table: &Table) {
    let _ = writeln!(out, "input {}_bool_exp {{", table.name);
    let _ = writeln!(out, "  _and: [{}_bool_exp!]", table.name);
    let _ = writeln!(out, "  _or: [{}_bool_exp!]", table.name);
    let _ = writeln!(out, "  _not: {}_bool_exp", table.name);
    for col in &table.columns {
        let _ = writeln!(
            out,
            "  {}: {}_comparison_exp",
            col.name,
            col.ty.graphql_name()
        );
    }
    out.push_str("}\n");
}

/// `input <t>_order_by { <col>: order_by … }`
fn push_order_by(out: &mut String, table: &Table) {
    let _ = writeln!(out, "input {}_order_by {{", table.name);
    for col in &table.columns {
        let _ = writeln!(out, "  {}: order_by", col.name);
    }
    out.push_str("}\n");
}

/// The `Query` root: a list field and (when a primary key exists) a `_by_pk` field per table.
fn push_query_root(out: &mut String, schema: &DbSchema) {
    out.push_str("type Query {\n");
    for table in &schema.tables {
        let _ = writeln!(
            out,
            "  {t}(where: {t}_bool_exp, order_by: [{t}_order_by!], limit: Int, offset: Int): [{t}!]!",
            t = table.name
        );
        if !table.primary_key.is_empty() {
            let args = pk_args(table);
            let _ = writeln!(out, "  {t}_by_pk({args}): {t}", t = table.name);
        }
    }
    out.push_str("}\n");
}

/// The `_by_pk` argument list: each primary-key column as a required scalar argument.
fn pk_args(table: &Table) -> String {
    table
        .primary_key
        .iter()
        .map(|pk| {
            let ty = table
                .column(pk)
                .map_or(ScalarType::Id, |c| c.ty)
                .graphql_name();
            format!("{pk}: {ty}!")
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::super::schema::{Column, DbSchema, ForeignKey, ScalarType, Table};
    use super::*;

    fn users_and_posts() -> DbSchema {
        DbSchema {
            tables: vec![
                Table {
                    name: "users".into(),
                    columns: vec![
                        Column {
                            name: "id".into(),
                            ty: ScalarType::Id,
                            nullable: false,
                        },
                        Column {
                            name: "name".into(),
                            ty: ScalarType::String,
                            nullable: true,
                        },
                    ],
                    primary_key: vec!["id".into()],
                    foreign_keys: vec![],
                },
                Table {
                    name: "posts".into(),
                    columns: vec![
                        Column {
                            name: "id".into(),
                            ty: ScalarType::Id,
                            nullable: false,
                        },
                        Column {
                            name: "author_id".into(),
                            ty: ScalarType::Id,
                            nullable: false,
                        },
                        Column {
                            name: "views".into(),
                            ty: ScalarType::Int,
                            nullable: true,
                        },
                    ],
                    primary_key: vec!["id".into()],
                    foreign_keys: vec![ForeignKey {
                        columns: vec!["author_id".into()],
                        ref_table: "users".into(),
                        ref_columns: vec!["id".into()],
                    }],
                },
            ],
        }
    }

    #[test]
    fn emits_an_object_type_per_table_with_nullability() {
        let sdl = generate_sdl(&users_and_posts());
        assert!(sdl.contains("type users {"));
        assert!(sdl.contains("  id: ID!"));
        assert!(sdl.contains("  name: String\n")); // nullable → no `!`
        assert!(sdl.contains("type posts {"));
        assert!(sdl.contains("  views: Int\n"));
    }

    #[test]
    fn emits_list_and_by_pk_root_fields() {
        let sdl = generate_sdl(&users_and_posts());
        assert!(sdl.contains(
            "users(where: users_bool_exp, order_by: [users_order_by!], limit: Int, offset: Int): [users!]!"
        ));
        assert!(sdl.contains("users_by_pk(id: ID!): users"));
    }

    #[test]
    fn a_pkless_table_gets_no_by_pk_field() {
        let schema = DbSchema {
            tables: vec![Table {
                name: "events".into(),
                columns: vec![Column {
                    name: "kind".into(),
                    ty: ScalarType::String,
                    nullable: false,
                }],
                primary_key: vec![],
                foreign_keys: vec![],
            }],
        };
        let sdl = generate_sdl(&schema);
        assert!(sdl.contains("events(where:"));
        assert!(!sdl.contains("events_by_pk"));
    }

    #[test]
    fn federation_sdl_gives_entities_a_key_directive() {
        let sdl = generate_federation_sdl(&users_and_posts());
        assert!(sdl.contains(r#"type users @key(fields: "id") {"#));
        assert!(sdl.contains(r#"type posts @key(fields: "id") {"#));
        // Argless root fields (the planner sends argless root + `_entities` fetches).
        assert!(sdl.contains("users: [users!]!"));
        assert!(sdl.contains("users_by_pk(id: ID!): users"));
    }

    #[test]
    fn emits_shared_and_per_table_filter_inputs() {
        let sdl = generate_sdl(&users_and_posts());
        assert!(sdl.contains("enum order_by { asc desc }"));
        assert!(sdl.contains("input String_comparison_exp"));
        assert!(sdl.contains("input users_bool_exp {"));
        assert!(sdl.contains("  name: String_comparison_exp"));
        assert!(sdl.contains("input users_order_by {"));
        assert!(sdl.contains("  id: order_by"));
    }
}
