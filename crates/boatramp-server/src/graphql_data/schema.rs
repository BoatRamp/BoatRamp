//! The relational schema model — the input to SDL generation and query compilation.
//!
//! A [`DbSchema`] is a dialect-independent description of the tables, columns, primary
//! keys, and foreign keys the connector exposes as a GraphQL API. It is produced by
//! introspecting a managed database (a later landing) and consumed by `sdl` (schema →
//! GraphQL SDL) and `compile` (query → SQL). boatramp stays a *compiler*: this model
//! carries only what is needed to generate a schema and lower a query to one SQL
//! statement, never execution semantics.

/// A GraphQL scalar a SQL column maps to. Deliberately small and dialect-independent — a
/// column whose SQL type doesn't map cleanly is carried as [`ScalarType::String`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScalarType {
    Int,
    Float,
    String,
    Boolean,
    /// A primary-key / identifier column (GraphQL `ID`).
    Id,
}

impl ScalarType {
    /// The GraphQL scalar type name.
    pub(crate) fn graphql_name(self) -> &'static str {
        match self {
            Self::Int => "Int",
            Self::Float => "Float",
            Self::String => "String",
            Self::Boolean => "Boolean",
            Self::Id => "ID",
        }
    }
}

/// One column of a [`Table`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Column {
    pub name: String,
    pub ty: ScalarType,
    /// Whether the column admits `NULL` (drives the `!` non-null marker in SDL).
    pub nullable: bool,
}

/// A foreign key from one table's `columns` to `ref_table`'s `ref_columns`, the basis for
/// a generated relationship field (a later landing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForeignKey {
    pub columns: Vec<String>,
    pub ref_table: String,
    pub ref_columns: Vec<String>,
}

/// One relational table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Table {
    pub name: String,
    pub columns: Vec<Column>,
    /// The primary-key column names (empty if the table has no primary key — then no
    /// `_by_pk` root field or `@key` is generated for it).
    pub primary_key: Vec<String>,
    pub foreign_keys: Vec<ForeignKey>,
}

impl Table {
    /// The column named `name`, if present.
    pub(crate) fn column(&self, name: &str) -> Option<&Column> {
        self.columns.iter().find(|c| c.name == name)
    }
}

/// A relational schema: the exposed tables in a stable (introspection) order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DbSchema {
    pub tables: Vec<Table>,
}

impl DbSchema {
    /// The table named `name`, if present.
    pub(crate) fn table(&self, name: &str) -> Option<&Table> {
        self.tables.iter().find(|t| t.name == name)
    }

    /// The relationship fields of `table`, derived from foreign keys: a **to-one** field per
    /// outgoing FK (follow it to the referenced row) and a **to-many** field per incoming FK
    /// (the rows that reference this one). Deterministic and schema-derived; exposure is the
    /// policy's job.
    pub(crate) fn relationships(&self, table: &str) -> Vec<Relationship> {
        let mut out = Vec::new();
        let Some(t) = self.table(table) else {
            return out;
        };
        for fk in &t.foreign_keys {
            out.push(Relationship {
                field: to_one_field_name(fk),
                kind: RelKind::ToOne,
                target_table: fk.ref_table.clone(),
                local_columns: fk.columns.clone(),
                target_columns: fk.ref_columns.clone(),
            });
        }
        for other in &self.tables {
            if other.name == table {
                continue; // self-references are exposed via the to-one side only, for now
            }
            for fk in &other.foreign_keys {
                if fk.ref_table == table {
                    out.push(Relationship {
                        field: other.name.clone(),
                        kind: RelKind::ToMany,
                        target_table: other.name.clone(),
                        local_columns: fk.ref_columns.clone(),
                        target_columns: fk.columns.clone(),
                    });
                }
            }
        }
        out
    }
}

/// Whether a relationship follows an FK (one row) or reverses it (many rows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelKind {
    ToOne,
    ToMany,
}

/// A relationship field on a table: its GraphQL name, direction, the target table, and the
/// column pair (`local` on this table, `target` on the other) that joins them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Relationship {
    pub field: String,
    pub kind: RelKind,
    pub target_table: String,
    pub local_columns: Vec<String>,
    pub target_columns: Vec<String>,
}

/// The to-one field name for an FK: a single `<name>_id` column becomes `<name>`, else the
/// referenced table name.
fn to_one_field_name(fk: &ForeignKey) -> String {
    if fk.columns.len() == 1 {
        if let Some(stripped) = fk.columns[0].strip_suffix("_id") {
            if !stripped.is_empty() {
                return stripped.to_string();
            }
        }
    }
    fk.ref_table.clone()
}
