//! Introspecting a live database into a [`DbSchema`].
//!
//! The managed default is libsql (SQLite), whose structure is read via `sqlite_master` and
//! the `table_info` / `foreign_key_list` pragmas. The table names come from the database
//! itself (never request text), so interpolating them into a pragma is safe. Postgres/MySQL
//! introspection (via `information_schema`) arrives with bring-your-own databases.

use super::schema::{Column, DbSchema, ForeignKey, ScalarType, Table};
use boatramp_core::sql::{SqlBackend, SqlError, SqlValue};

/// Introspect a SQLite/libsql database into a [`DbSchema`] (base tables only; views and the
/// internal `sqlite_%` tables are skipped).
pub(crate) async fn introspect_sqlite(backend: &dyn SqlBackend) -> Result<DbSchema, SqlError> {
    let mut tx = backend.begin_read_only().await?;
    let table_rows = tx
        .query(
            "SELECT name FROM sqlite_master WHERE type = 'table' \
             AND name NOT LIKE 'sqlite_%' ORDER BY name",
            &[],
        )
        .await?;
    let names: Vec<String> = table_rows
        .rows
        .iter()
        .filter_map(|r| r.first().and_then(as_text))
        .collect();

    let mut tables = Vec::with_capacity(names.len());
    for name in names {
        let quoted = name.replace('"', "\"\"");
        let info = tx
            .query(&format!("PRAGMA table_info(\"{quoted}\")"), &[])
            .await?;
        let mut columns = Vec::new();
        let mut pk: Vec<(i64, String)> = Vec::new();
        for row in &info.rows {
            // table_info columns: cid, name, type, notnull, dflt_value, pk.
            let col_name = row.get(1).and_then(as_text).unwrap_or_default();
            let decl_type = row.get(2).and_then(as_text).unwrap_or_default();
            let not_null = row.get(3).and_then(as_int).unwrap_or(0) != 0;
            let pk_pos = row.get(5).and_then(as_int).unwrap_or(0);
            let is_pk = pk_pos > 0;
            if is_pk {
                pk.push((pk_pos, col_name.clone()));
            }
            columns.push(Column {
                name: col_name,
                ty: if is_pk {
                    ScalarType::Id
                } else {
                    scalar_of(&decl_type)
                },
                nullable: !not_null && !is_pk,
            });
        }
        pk.sort_by_key(|(pos, _)| *pos);
        let primary_key = pk.into_iter().map(|(_, n)| n).collect();

        let fk_rows = tx
            .query(&format!("PRAGMA foreign_key_list(\"{quoted}\")"), &[])
            .await?;
        let foreign_keys = group_foreign_keys(&fk_rows.rows);

        tables.push(Table {
            name,
            columns,
            primary_key,
            foreign_keys,
        });
    }
    let _ = tx.rollback().await;
    Ok(DbSchema { tables })
}

/// Map a SQLite declared column type to a GraphQL scalar by type affinity.
fn scalar_of(decl_type: &str) -> ScalarType {
    let t = decl_type.to_ascii_uppercase();
    if t.contains("INT") {
        ScalarType::Int
    } else if t.contains("CHAR") || t.contains("CLOB") || t.contains("TEXT") {
        ScalarType::String
    } else if t.contains("REAL") || t.contains("FLOAT") || t.contains("DOUBLE") {
        ScalarType::Float
    } else if t.contains("BOOL") {
        ScalarType::Boolean
    } else {
        ScalarType::String
    }
}

/// Group `foreign_key_list` rows (id, seq, table, from, to, …) into foreign keys, ordering a
/// composite key's columns by `seq`.
fn group_foreign_keys(rows: &[Vec<SqlValue>]) -> Vec<ForeignKey> {
    use std::collections::BTreeMap;
    // The referenced table + its ordered (seq, from-col, to-col) column mapping.
    type FkGroup = (String, Vec<(i64, String, String)>);
    // id → the columns of that one foreign key.
    let mut by_id: BTreeMap<i64, FkGroup> = BTreeMap::new();
    for row in rows {
        let id = row.first().and_then(as_int).unwrap_or(0);
        let seq = row.get(1).and_then(as_int).unwrap_or(0);
        let ref_table = row.get(2).and_then(as_text).unwrap_or_default();
        let from = row.get(3).and_then(as_text).unwrap_or_default();
        let to = row.get(4).and_then(as_text).unwrap_or_default();
        let entry = by_id.entry(id).or_insert_with(|| (ref_table, Vec::new()));
        entry.1.push((seq, from, to));
    }
    by_id
        .into_values()
        .map(|(ref_table, mut cols)| {
            cols.sort_by_key(|(seq, _, _)| *seq);
            ForeignKey {
                columns: cols.iter().map(|(_, f, _)| f.clone()).collect(),
                ref_table,
                ref_columns: cols.iter().map(|(_, _, t)| t.clone()).collect(),
            }
        })
        .collect()
}

fn as_text(v: &SqlValue) -> Option<String> {
    match v {
        SqlValue::Text(s) => Some(s.clone()),
        _ => None,
    }
}

fn as_int(v: &SqlValue) -> Option<i64> {
    match v {
        SqlValue::Integer(i) => Some(*i),
        _ => None,
    }
}
