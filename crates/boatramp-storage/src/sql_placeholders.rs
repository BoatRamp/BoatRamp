//! Strict, fail-closed placeholder normalizer for the handler `sql` binding.
//!
//! The `boatramp:handlers/sql-query` WIT contract is **SQLite-style numbered
//! placeholders** — `?1`, `?2`, … — uniformly, regardless of which engine backs
//! a site's database. The engines disagree on wire syntax (libsql/SQLite take
//! `?N` natively, Postgres wants `$N`, MySQL wants positional `?`), so this module
//! is the *single* place that reconciles the contract to the bound engine:
//!
//! - It **validates** every statement against the canonical `?N` contract on
//!   **all** backends (not just the ones that need rewriting) — rejecting bare
//!   `?`, native `$N` / `:name` / `@name`, out-of-range indices, and any mismatch
//!   between the placeholders used and the parameters bound. This is a security
//!   boundary: the handler `sql` binding's tenant/row scoping rides on positional
//!   parameter binding, so an ambiguous or miscounted placeholder must **fail
//!   closed**, never silently bind the wrong value.
//! - It **rewrites** `?N` to the engine's native form only where the driver
//!   demands it (Postgres `$N`, MySQL positional `?` with the bound parameters
//!   reordered to match).
//!
//! Placeholder detection is delegated to `sqlparser`'s dialect-aware tokenizer,
//! so `?`/`$` characters inside string literals, dollar-quoted strings, comments,
//! and quoted identifiers are never mistaken for placeholders. Each backend is
//! tokenized with the dialect matching its real lexical rules.

use std::borrow::Cow;

use boatramp_core::sql::{SqlError, SqlValue};
use sqlparser::dialect::{Dialect, GenericDialect, MySqlDialect, SQLiteDialect};
use sqlparser::tokenizer::{Token, Tokenizer};

/// The placeholder syntax the bound engine's driver expects on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlaceholderDialect {
    /// libsql / SQLite: `?N` is native — validate only, no rewrite. Constructed
    /// only by the libsql backend.
    #[cfg_attr(not(feature = "sql"), allow(dead_code))]
    Sqlite,
    /// Postgres: `?N` → `$N` (same numbering; bound in natural order). Constructed
    /// only by the sqlx Postgres backend.
    #[cfg_attr(not(feature = "sql-postgres"), allow(dead_code))]
    Postgres,
    /// MySQL: `?N` → positional `?`, with the bound parameters reordered/duplicated
    /// to the placeholders' appearance order. Constructed only by the sqlx MySQL
    /// backend.
    #[cfg_attr(not(feature = "sql-mysql"), allow(dead_code))]
    MySql,
}

impl PlaceholderDialect {
    /// The `sqlparser` tokenizer dialect whose lexical rules match this engine —
    /// so its own comment/string/identifier syntax is skipped correctly. Postgres
    /// uses the generic dialect because `PostgreSqlDialect` does not tokenize `?N`
    /// as a placeholder (Postgres has no `?` params); the generic dialect does,
    /// while still handling dollar-quotes, E-strings, and `"…"` identifiers.
    fn tokenizer(self) -> Box<dyn Dialect> {
        match self {
            Self::Sqlite => Box::new(SQLiteDialect {}),
            Self::MySql => Box::new(MySqlDialect {}),
            Self::Postgres => Box::new(GenericDialect {}),
        }
    }
}

/// A normalized statement plus how to bind its parameters.
pub(crate) struct Normalized<'a> {
    /// The statement rewritten to the engine's native placeholder syntax (borrowed
    /// unchanged for libsql, which needs no rewrite).
    pub sql: Cow<'a, str>,
    /// The order to bind parameters in. `None` = natural order (`params[0..n]`),
    /// for libsql (`?N`) and Postgres (`$N`, by number). `Some(order)` = bind
    /// `params[order[0]], params[order[1]], …` — MySQL positional `?`, one entry
    /// per placeholder occurrence in appearance order (so repeats duplicate).
    pub bind_order: Option<Vec<usize>>,
}

impl Normalized<'_> {
    /// Apply [`bind_order`](Self::bind_order) to `params`, yielding the parameter
    /// slice to bind positionally. Borrows for the natural-order case.
    pub fn reorder<'p>(&self, params: &'p [SqlValue]) -> Cow<'p, [SqlValue]> {
        match &self.bind_order {
            None => Cow::Borrowed(params),
            Some(order) => Cow::Owned(order.iter().map(|&i| params[i].clone()).collect()),
        }
    }
}

/// One located placeholder: its 1-based parameter index and the source span (as
/// 1-based line/column, matching `sqlparser`'s locations) of its `?N` text.
struct Placeholder {
    index: usize,
    line: u64,
    column: u64,
    /// The placeholder's source text (`"?1"`), so the rewriter knows how many
    /// characters to consume.
    text: String,
}

/// Validate `sql` against the canonical `?N` contract for `n_params` bound
/// parameters, and rewrite it to `dialect`'s native placeholder syntax.
///
/// `Err(SqlError::Syntax)` — fail closed — on any of: a non-`?N` placeholder
/// (bare `?`, `$N`, `:name`, `@name`), an index outside `1..=n_params`, a bound
/// parameter never referenced, or a statement the tokenizer rejects.
pub(crate) fn normalize(
    sql: &str,
    dialect: PlaceholderDialect,
    n_params: usize,
) -> Result<Normalized<'_>, SqlError> {
    let placeholders = locate(sql, dialect)?;
    validate_indices(&placeholders, n_params)?;

    match dialect {
        // libsql speaks `?N` natively — validation is the whole job.
        PlaceholderDialect::Sqlite => Ok(Normalized {
            sql: Cow::Borrowed(sql),
            bind_order: None,
        }),
        // Postgres `$N` keeps the number, so binding stays in natural order.
        PlaceholderDialect::Postgres => Ok(Normalized {
            sql: Cow::Owned(rewrite(sql, &placeholders, Substitution::Dollar)),
            bind_order: None,
        }),
        // MySQL positional `?` binds by appearance, so reorder the parameters.
        PlaceholderDialect::MySql => {
            let bind_order = placeholders.iter().map(|p| p.index - 1).collect();
            Ok(Normalized {
                sql: Cow::Owned(rewrite(sql, &placeholders, Substitution::Positional)),
                bind_order: Some(bind_order),
            })
        }
    }
}

/// Tokenize `sql` with `dialect`'s lexer and collect every placeholder, enforcing
/// the canonical `?N` shape. Placeholders inside strings/comments/identifiers are
/// never surfaced by the tokenizer, so they cannot be rewritten.
fn locate(sql: &str, dialect: PlaceholderDialect) -> Result<Vec<Placeholder>, SqlError> {
    let d = dialect.tokenizer();
    let tokens = Tokenizer::new(d.as_ref(), sql)
        .tokenize_with_location()
        .map_err(|e| SqlError::Syntax(format!("cannot tokenize statement: {e}")))?;

    let mut placeholders = Vec::new();
    for t in &tokens {
        let Token::Placeholder(text) = &t.token else {
            continue;
        };
        let index = parse_index(text)?;
        placeholders.push(Placeholder {
            index,
            line: t.span.start.line,
            column: t.span.start.column,
            text: text.clone(),
        });
    }
    Ok(placeholders)
}

/// A placeholder must be `?` followed by a positive decimal index (`?1`, `?2`,
/// `?10`) — the canonical WIT contract. Everything else (bare `?`, `$N`, `:name`,
/// `@name`, `?0`) is refused so no engine's placeholder leniency can slip a
/// differently-shaped marker past the parameter-count check.
fn parse_index(text: &str) -> Result<usize, SqlError> {
    let rejected = || {
        SqlError::Syntax(format!(
            "unsupported SQL placeholder `{text}`: use numbered `?N` (`?1`, `?2`, …)"
        ))
    };
    let digits = text.strip_prefix('?').ok_or_else(rejected)?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(rejected());
    }
    match digits.parse::<usize>() {
        Ok(n) if n >= 1 => Ok(n),
        _ => Err(rejected()),
    }
}

/// Every placeholder index must fall in `1..=n_params`, and every bound parameter
/// must be referenced at least once (repeats are fine). This is what makes a
/// miscount fail closed instead of binding the wrong parameter.
fn validate_indices(placeholders: &[Placeholder], n_params: usize) -> Result<(), SqlError> {
    let mut referenced = vec![false; n_params];
    for p in placeholders {
        if p.index > n_params {
            return Err(SqlError::Syntax(format!(
                "placeholder `?{}` is out of range: {n_params} parameter(s) bound",
                p.index
            )));
        }
        referenced[p.index - 1] = true;
    }
    if let Some(missing) = referenced.iter().position(|&r| !r) {
        return Err(SqlError::Syntax(format!(
            "parameter {} was bound but never referenced (expected `?{}`)",
            missing + 1,
            missing + 1
        )));
    }
    Ok(())
}

/// How to render a placeholder in the target dialect.
enum Substitution {
    /// Postgres: `?N` → `$N` (keep the number).
    Dollar,
    /// MySQL: `?N` → `?` (positional; number dropped, binding reordered).
    Positional,
}

/// Rebuild `sql` with each placeholder replaced, splicing the *original* text
/// everywhere else (so only placeholder characters change — literals, comments,
/// and identifiers are byte-identical). Walks characters tracking 1-based
/// line/column to match the tokenizer's locations; placeholders are single-line
/// ASCII, so consuming `text.len()` characters at each is exact.
fn rewrite(sql: &str, placeholders: &[Placeholder], sub: Substitution) -> String {
    // Placeholders come out of the token stream already in source order.
    let mut out = String::with_capacity(sql.len());
    let mut next = placeholders.iter().peekable();
    let (mut line, mut col) = (1u64, 1u64);
    let mut chars = sql.chars().peekable();

    while let Some(&ch) = chars.peek() {
        if let Some(p) = next.peek() {
            if p.line == line && p.column == col {
                // Emit the substitution, consume the placeholder's source chars.
                match sub {
                    Substitution::Dollar => {
                        out.push('$');
                        out.push_str(&p.text[1..]); // the digits after `?`
                    }
                    Substitution::Positional => out.push('?'),
                }
                for _ in p.text.chars() {
                    chars.next();
                    col += 1;
                }
                next.next();
                continue;
            }
        }
        out.push(ch);
        chars.next();
        if ch == '\n' {
            line += 1;
            col = 1;
        } else {
            col += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::PlaceholderDialect::{MySql, Postgres, Sqlite};
    use super::*;

    fn norm(
        sql: &str,
        d: PlaceholderDialect,
        n: usize,
    ) -> Result<(String, Option<Vec<usize>>), String> {
        normalize(sql, d, n)
            .map(|x| (x.sql.into_owned(), x.bind_order))
            .map_err(|e| e.to_string())
    }

    #[test]
    fn postgres_rewrites_qmark_to_dollar_keeping_number() {
        let (sql, order) = norm("SELECT * FROM t WHERE a = ?1 AND b = ?2", Postgres, 2).unwrap();
        assert_eq!(sql, "SELECT * FROM t WHERE a = $1 AND b = $2");
        assert!(order.is_none()); // natural bind order
    }

    #[test]
    fn postgres_out_of_order_indices_bind_by_number() {
        // `?2, ?1` -> `$2, $1`; Postgres binds by number, so natural order is right.
        let (sql, order) = norm("SELECT ?2, ?1", Postgres, 2).unwrap();
        assert_eq!(sql, "SELECT $2, $1");
        assert!(order.is_none());
    }

    #[test]
    fn mysql_rewrites_to_positional_and_reorders_binds() {
        let (sql, order) = norm("SELECT ?2, ?1", MySql, 2).unwrap();
        assert_eq!(sql, "SELECT ?, ?");
        assert_eq!(order, Some(vec![1, 0])); // first `?`=param[1], second=param[0]
    }

    #[test]
    fn mysql_repeated_placeholder_duplicates_the_bind() {
        let (sql, order) = norm("SELECT ?1 WHERE a = ?1", MySql, 1).unwrap();
        assert_eq!(sql, "SELECT ? WHERE a = ?");
        assert_eq!(order, Some(vec![0, 0]));
    }

    #[test]
    fn sqlite_validates_without_rewriting() {
        let (sql, order) = norm("SELECT ?1 WHERE a = ?2", Sqlite, 2).unwrap();
        assert_eq!(sql, "SELECT ?1 WHERE a = ?2");
        assert!(order.is_none());
    }

    #[test]
    fn multi_digit_indices() {
        let (sql, _) = norm(&format!("SELECT {}", vec_ph(12)), Postgres, 12).unwrap();
        assert!(sql.contains("$10") && sql.contains("$12"));
    }

    fn vec_ph(n: usize) -> String {
        (1..=n)
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    // ---- the security-critical cases: placeholders must NOT be found inside
    // literals / comments / identifiers, and rewriting must leave them intact ----

    #[test]
    fn qmark_inside_string_literal_is_not_a_placeholder() {
        // The `?` in the string is literal; only the trailing `?1` is a placeholder.
        let (sql, _) = norm("SELECT 'is it? yes' WHERE a = ?1", Postgres, 1).unwrap();
        assert_eq!(sql, "SELECT 'is it? yes' WHERE a = $1");
    }

    #[test]
    fn qmark_in_escaped_string_is_untouched() {
        let (sql, _) = norm("SELECT 'it''s ?9 ok' WHERE a = ?1", Postgres, 1).unwrap();
        assert_eq!(sql, "SELECT 'it''s ?9 ok' WHERE a = $1");
    }

    #[test]
    fn placeholder_in_dollar_quote_is_untouched() {
        let (sql, _) = norm("SELECT $$ has ?1 inside $$ WHERE a = ?1", Postgres, 1).unwrap();
        assert_eq!(sql, "SELECT $$ has ?1 inside $$ WHERE a = $1");
    }

    #[test]
    fn placeholder_in_comment_is_untouched() {
        let (sql, _) = norm("SELECT a -- ?1 note\n WHERE a = ?1", Postgres, 1).unwrap();
        assert_eq!(sql, "SELECT a -- ?1 note\n WHERE a = $1");
        let (sql, _) = norm("SELECT a /* ?1 */ WHERE a = ?1", Postgres, 1).unwrap();
        assert_eq!(sql, "SELECT a /* ?1 */ WHERE a = $1");
    }

    #[test]
    fn cast_after_placeholder_survives() {
        let (sql, _) = norm("SELECT a WHERE a = ?1::int", Postgres, 1).unwrap();
        assert_eq!(sql, "SELECT a WHERE a = $1::int");
    }

    #[test]
    fn qmark_in_mysql_backtick_ident_is_untouched() {
        let (sql, _) = norm("SELECT `c?1` WHERE a = ?1", MySql, 1).unwrap();
        assert_eq!(sql, "SELECT `c?1` WHERE a = ?");
    }

    #[test]
    fn placeholder_in_sqlite_bracket_ident_is_untouched() {
        // SQLite `[...]` identifiers must not have their `?1` treated as a param.
        let (sql, _) = norm("SELECT [weird?1col] WHERE a = ?1", Sqlite, 1).unwrap();
        assert_eq!(sql, "SELECT [weird?1col] WHERE a = ?1");
    }

    // ---- fail-closed rejections ----

    #[test]
    fn bare_qmark_is_rejected() {
        assert!(norm("SELECT ?", Postgres, 1).unwrap_err().contains("`?`"));
        assert!(norm("SELECT ?", MySql, 1).unwrap_err().contains("?N"));
    }

    #[test]
    fn native_dollar_is_rejected() {
        // A guest writing native Postgres `$1` is refused — the contract is `?N`.
        assert!(norm("SELECT $1", Postgres, 1).unwrap_err().contains("$1"));
    }

    #[test]
    fn named_placeholders_rejected() {
        assert!(norm("SELECT :name", Postgres, 1).is_err());
        assert!(norm("SELECT @name", MySql, 1).is_err());
    }

    #[test]
    fn out_of_range_index_is_rejected() {
        let e = norm("SELECT ?3", Postgres, 2).unwrap_err();
        assert!(e.contains("out of range"), "{e}");
    }

    #[test]
    fn unreferenced_bound_param_is_rejected() {
        let e = norm("SELECT ?1", Postgres, 2).unwrap_err();
        assert!(e.contains("never referenced"), "{e}");
    }

    #[test]
    fn placeholder_without_params_is_rejected() {
        assert!(norm("SELECT ?1", Postgres, 0).is_err());
    }

    #[test]
    fn no_placeholders_no_params_is_ok() {
        let (sql, order) = norm("SELECT 1", Postgres, 0).unwrap();
        assert_eq!(sql, "SELECT 1");
        assert!(order.is_none());
    }

    // ---- property: rewriting only ever changes placeholder markers ----

    #[test]
    fn property_rewrite_only_touches_placeholders() {
        // A statement whose only `?`/`$` outside a placeholder are inside a string,
        // a comment, and a dollar-quote must have those regions byte-identical after
        // rewrite; only the two real placeholders change.
        let src = "UPDATE t /* keep ?1 */ SET x = $$dollar ?2 quote$$, y = 'lit ? $1' \
                   WHERE k = ?1 AND j = ?2";
        let (out, _) = norm(src, Postgres, 2).unwrap();
        // The literal/comment/dollar-quote regions are unchanged.
        assert!(out.contains("/* keep ?1 */"));
        assert!(out.contains("$$dollar ?2 quote$$"));
        assert!(out.contains("'lit ? $1'"));
        // The two real placeholders became $N.
        assert!(out.contains("WHERE k = $1 AND j = $2"));
        // And no stray `?N` leaked into the rewritten tail.
        assert!(!out.contains("k = ?1"));
    }
}
