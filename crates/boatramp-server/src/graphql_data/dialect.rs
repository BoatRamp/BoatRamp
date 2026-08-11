//! SQL dialect differences the compiler must respect: identifier quoting and bind
//! placeholders. Identifiers always come from the introspected + exposed schema (never
//! request text), so quoting is about correctness (reserved words), not safety; values are
//! always bound parameters. The default managed backend is libsql (SQLite); Postgres/MySQL
//! dialects arrive with bring-your-own introspection.

/// The SQL syntax knobs the compiler varies by backend.
pub(crate) trait Dialect {
    /// Quote a schema identifier (table/column) for this dialect.
    fn quote_ident(&self, ident: &str) -> String;

    /// The bind placeholder for the 1-based parameter `index` (some dialects number them,
    /// some don't).
    fn placeholder(&self, index: usize) -> String;
}

/// SQLite / libsql — the managed default. `"ident"` quoting, positional `?` placeholders.
pub(crate) struct Sqlite;

impl Dialect for Sqlite {
    fn quote_ident(&self, ident: &str) -> String {
        format!("\"{}\"", ident.replace('"', "\"\""))
    }

    fn placeholder(&self, _index: usize) -> String {
        "?".to_string()
    }
}
