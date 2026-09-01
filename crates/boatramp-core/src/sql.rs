//! A small, engine-agnostic SQL backend contract for the handler `sql` binding.
//!
//! The handler engine exposes a `sql` capability to guests, but *which* database
//! serves it is a deployment detail — the same seam as the blob ([`Storage`])
//! and KV ([`kv::KvStore`]) backends. [`SqlBackend`] is that seam, so the guest
//! interface and the server UX stay identical across single-node and cluster
//! deployments. The one implementation is **libsql** (SQLite-compatible): an
//! embedded file per site (single-node) or a sqld namespace per site (cluster,
//! read-replicable) — one engine, the split being config, not a backend choice.
//!
//! Each backend instance is **scoped to one site**; the engine/transport and the
//! per-site database mapping live behind the trait, so a handler can never
//! address another site's data ([`crate::deploy`]-style isolation).
//!
//! The contract is deliberately tiny — `begin` a transaction, `query`/`execute`
//! within it, then `commit`/`rollback` — and the trait keeps the engine
//! decoupled from libsql's specifics (and lets tests substitute a fake). The
//! handler engine wraps each invocation in one transaction (commit on success,
//! roll back on trap/error).
//!
//! [`Storage`]: crate::Storage
//! [`kv::KvStore`]: crate::kv::KvStore

use std::sync::Arc;

use async_trait::async_trait;

/// A single SQL value. `Boolean` is carried as a distinct class (so a guest can
/// express one and a strictly-typed engine could bind a native `BOOL`); libsql,
/// being SQLite-family, maps it to `0`/`1`.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    /// SQL `NULL`.
    Null,
    /// A boolean (a native `BOOL` where the engine has one, else `0`/`1`).
    Boolean(bool),
    /// A 64-bit signed integer.
    Integer(i64),
    /// A 64-bit float.
    Real(f64),
    /// UTF-8 text.
    Text(String),
    /// A byte string.
    Blob(Vec<u8>),
    /// A JSON document (its JSON text). Bound with the engine's JSON column type
    /// (`jsonb`/`json` on Postgres, a JSON string on MySQL, text on SQLite), so a
    /// guest can write a `jsonb` column with no `::jsonb` cast. Read back as
    /// [`Text`](Self::Text) (the engines stringify JSON on the way out).
    Json(String),
}

/// The rows a [`SqlTransaction::query`] returned: column names plus row-major
/// cells (each row's length equals `columns.len()`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SqlRows {
    /// Column names, in result order.
    pub columns: Vec<String>,
    /// Rows, each a vector of cells aligned to `columns`.
    pub rows: Vec<Vec<SqlValue>>,
}

/// Why a SQL operation failed.
#[derive(Debug, Clone, thiserror::Error)]
pub enum SqlError {
    /// The statement could not be parsed or planned.
    #[error("sql syntax error: {0}")]
    Syntax(String),
    /// A constraint (unique, type, foreign key, ...) was violated.
    #[error("sql constraint error: {0}")]
    Constraint(String),
    /// Any other backend/transport error (I/O, connection, ...).
    #[error("sql error: {0}")]
    Other(String),
}

impl SqlError {
    /// Wrap any displayable error as [`SqlError::Other`].
    pub fn other<E: std::fmt::Display>(err: E) -> Self {
        Self::Other(err.to_string())
    }
}

/// The SQL dialect a backend speaks. The `orm` compiler is `?N`-portable for almost
/// everything (the backend rewrites the placeholders), and only consults this for the
/// handful of constructs whose *syntax* genuinely differs across engines — currently JSON
/// extraction (`json_extract(...)` on SQLite/MySQL vs `#>>` on Postgres).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Dialect {
    /// SQLite family (libsql). The default.
    #[default]
    Sqlite,
    Postgres,
    Mysql,
}

/// A per-site SQL backend (libsql — a local file or a remote sqld namespace).
///
/// One instance serves one site. The handler engine calls [`begin`] once per
/// invocation that uses SQL and drives the resulting [`SqlTransaction`] to a
/// commit (on a successful response) or rollback (on trap/error).
///
/// [`begin`]: SqlBackend::begin
#[async_trait]
pub trait SqlBackend: Send + Sync {
    /// The SQL dialect this backend speaks — used by the `orm` compiler for the few
    /// dialect-divergent constructs (e.g. JSON extraction). Defaults to SQLite-family
    /// (libsql); the Postgres/MySQL backends override it.
    fn dialect(&self) -> Dialect {
        Dialect::Sqlite
    }

    /// Open a new read-write transaction. Backends are free to draw the
    /// underlying connection from a pool, a fresh embedded connection, or a
    /// remote session. Writes always land on the primary.
    async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError>;

    /// Open a transaction for a **read-only** invocation, which a backend
    /// configured with a read replica may route to that replica (separate read
    /// vs write endpoint: reads → replicas, writes →
    /// primary). A replica may lag the primary, so such reads are
    /// **eventually consistent**; issuing a write on this transaction is a
    /// caller error (it hits the read endpoint, which a replica rejects).
    ///
    /// The default has no replica and simply opens a normal transaction, so
    /// single-node and replica-less deployments behave identically.
    async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
        self.begin().await
    }

    /// Run a multi-statement SQL **script** as one unit (the simple-query protocol),
    /// for operator migrations: `CREATE EXTENSION` and long chains of DDL/DML that the
    /// parameterized per-statement path can't express. Only the external
    /// Postgres/MySQL backends implement it (the per-site libsql backend rejects it);
    /// it is an operator tool, not a guest capability.
    async fn run_script(&self, _sql: &str) -> Result<(), SqlError> {
        Err(SqlError::Other(
            "this database does not support running a raw SQL script".into(),
        ))
    }

    /// Run one row-returning statement directly, in its own short-lived read-only
    /// transaction — backs the operator `sql query`. The default composes the existing
    /// transaction methods, so every backend supports it.
    async fn run_query(&self, sql: &str) -> Result<SqlRows, SqlError> {
        let mut tx = self.begin_read_only().await?;
        let result = tx.query(sql, &[]).await;
        // Read-only: always roll back so nothing lingers and no write can slip through.
        let _ = tx.rollback().await;
        result
    }

    /// Whether this backend injects a **reserved** boatramp session context
    /// (`rls_session` — the `boatramp.project` / `boatramp.site` GUC on Postgres, or
    /// the `@boatramp_project` / `@boatramp_site` MySQL session var) that an app's
    /// row-level-security policy keys on. Default `false`.
    ///
    /// When `true`, the guest `sql` binding must **refuse** any guest statement that
    /// would set/reset those reserved keys (see [`reject_reserved_session_writes`]):
    /// otherwise a hostile guest could spoof its injected tenant and defeat the app's
    /// RLS. This is a security signal, not a routing one — see the `rls_session` doc for
    /// the trust model (the real isolation boundary is the per-tenant database + role).
    fn injects_session_context(&self) -> bool {
        false
    }
}

/// Reject a guest SQL statement that would set or reset a **boatramp-reserved**
/// session key — the `boatramp.*` GUC (Postgres) or an `@boatramp_*` user variable
/// (MySQL). Used by the guest `sql` binding when the backend
/// [`injects_session_context`](SqlBackend::injects_session_context): with `rls_session`
/// on, boatramp injects the request's tenant into those keys for the app's RLS, so a
/// guest that could overwrite them would spoof its tenant and defeat that RLS.
///
/// The statement is **tokenized with `sqlparser`** (the [`GenericDialect`], which lexes
/// Postgres `"idents"`, MySQL backticks, `@vars`, and comments), not string-matched, so
/// the earlier naive filter's bypasses are closed: comments and whitespace are normalized
/// away (`SET/*x*/ boatramp.project`, `/*c*/SET …`), casing is folded, and a
/// concatenated / non-literal `set_config` argument can no longer smuggle the reserved
/// name past the check. The match stays **narrow** — ordinary app SQL
/// (`SET statement_timeout = …`, `SET search_path TO …`, `set_config('search_path', …)`,
/// a `SELECT` merely mentioning "set" or "boatramp.project") is untouched.
///
/// Recognised hostile forms (all rejected):
///
/// - a **deferred-execution or persistent-default** construct, whose body the tokenizer
///   cannot see into and where a reserved-key write could hide: any **dollar-quoted**
///   token (`$$…$$` / `$tag$…$tag$` — a `DO` block, a routine body, or a string literal),
///   a leading `DO` / `CALL`, a `CREATE`/`ALTER … FUNCTION|PROCEDURE`, or an
///   `ALTER ROLE|DATABASE|USER|SYSTEM … boatramp.*`. A guest on the RLS path has no
///   legitimate need for procedural code, so these whole classes are refused (the
///   operator keeps them via trusted operator SQL); `$1`/`$2` bind params are unaffected
///   (they lex as placeholders, not dollar-quoted strings);
/// - a statement whose leading keyword is `SET` / `SET SESSION` / `SET LOCAL` /
///   `RESET` / `DISCARD` whose target is a `boatramp.*` GUC or an `@boatramp_*` var
///   (`RESET ALL` / `DISCARD ALL` reset custom GUCs too, so they are refused);
/// - any `set_config(<arg1>, …)` call — anywhere, incl. inside a `SELECT` — whose first
///   argument is a single-quoted string literal naming `boatramp` / `boatramp.*`, **or**
///   whose first argument is not a single simple string literal at all (a concatenation
///   or other expression could construct `boatramp.*` at runtime; a legitimate caller
///   always passes a plain literal such as `'search_path'`).
///
/// **Fail-closed:** if the tokenizer cannot lex the statement at all, it is rejected — a
/// guest statement the guard cannot understand must not slip through while a session
/// context is injected.
///
/// Returns [`SqlError::Other`] with a clear message on a match, else `Ok(())`.
pub fn reject_reserved_session_writes(sql: &str) -> Result<(), SqlError> {
    use sqlparser::dialect::GenericDialect;
    use sqlparser::tokenizer::{Token, Tokenizer, Word};

    /// The reserved GUC namespace (Postgres) — the first dotted segment, lowercased.
    const GUC_NAMESPACE: &str = "boatramp";
    /// The reserved MySQL user-var prefix, lowercased (an `@`-prefixed identifier).
    const MYSQL_VAR_PREFIX: &str = "@boatramp_";

    let refused = || {
        Err(SqlError::Other(
            "setting a boatramp-reserved session key (boatramp.* / @boatramp_*) is not \
             permitted from a handler: it is managed by rls_session and reserved for \
             per-request tenant isolation"
                .to_string(),
        ))
    };

    // Tokenize with the generic dialect: it lexes Postgres `"idents"`, MySQL backticks,
    // `@vars`, and both comment styles, folding comments/whitespace into `Whitespace`
    // tokens we then drop. A statement the tokenizer rejects fails closed (below).
    let dialect = GenericDialect {};
    let Ok(raw) = Tokenizer::new(&dialect, sql).tokenize() else {
        // Fail closed: an unlexable guest statement (e.g. an unbalanced backtick like
        // `SET @`boatramp_project`=1`) must not pass while a context is injected.
        return refused();
    };

    // Drop whitespace/comment tokens so a comment cannot split a keyword or hide inside
    // a `set_config(` call. What remains are the statement's significant tokens.
    let toks: Vec<&Token> = raw
        .iter()
        .filter(|t| !matches!(t, Token::Whitespace(_)))
        .collect();

    // The unquoted, case-folded text of a `Word` token, or `None` for any other token.
    // Quoted identifiers keep their inner text (so a backtick-/double-quoted reserved
    // name is still recognized), just without the quotes.
    fn word_lc(tok: &Token) -> Option<String> {
        match tok {
            Token::Word(Word { value, .. }) => Some(value.to_ascii_lowercase()),
            _ => None,
        }
    }

    // Whether a case-folded identifier names a reserved key: the MySQL `@boatramp_*`
    // user var, or (as the leading segment of a GUC) the `boatramp` namespace.
    let is_reserved_var = |w: &str| w.starts_with(MYSQL_VAR_PREFIX);

    // ---- (0) Deferred-execution / persistent-default constructs the token scan below
    // cannot see into. `sqlparser` lexes a **dollar-quoted body** (`$$…$$`, `$tag$…$tag$`)
    // — a `DO` block or a `CREATE FUNCTION` body — as ONE opaque `DollarQuotedString`
    // token, and a **single-quoted** `DO`/function body as a `SingleQuotedString`, so a
    // reserved-key write hidden inside either (`DO $$ … set_config('boatramp.project', …,
    // false) … $$`) is invisible to (a)/(b). A guest on the RLS path has no legitimate
    // need for procedural code, so under an injected context these whole classes are
    // refused outright — the operator keeps them via operator SQL, which is trusted and
    // unguarded. Refused:
    //   - any dollar-quoted token (a `$$…$$` / `$tag$…$tag$` body or string literal);
    //   - a leading `DO` (anonymous block) or `CALL` (invoke a procedure that could set it);
    //   - `CREATE`/`ALTER … FUNCTION|PROCEDURE` (defines a body the tokenizer can't inspect);
    //   - `ALTER ROLE|DATABASE|USER|SYSTEM … boatramp.*` (sets a *persistent* default GUC).
    // `$1`/`$2` bind params lex as `Placeholder`, not `DollarQuotedString`, so ordinary
    // parameterized guest queries are unaffected.
    if toks
        .iter()
        .any(|t| matches!(t, Token::DollarQuotedString(_)))
    {
        return refused();
    }
    {
        let leading = toks.first().and_then(|t| word_lc(t));
        let has_word = |w: &str| toks.iter().any(|t| word_lc(t).as_deref() == Some(w));
        let names_reserved = || {
            toks.iter()
                .any(|t| word_lc(t).is_some_and(|w| w == GUC_NAMESPACE || is_reserved_var(&w)))
        };
        match leading.as_deref() {
            // Anonymous code block / procedure call: procedural bodies we can't inspect.
            Some("do") | Some("call") => return refused(),
            // Defining a routine (single- or dollar-quoted body) on the guest path.
            Some("create") | Some("alter") if has_word("function") || has_word("procedure") => {
                return refused()
            }
            // A persistent GUC default: `ALTER ROLE/DATABASE/USER/SYSTEM … SET boatramp.*`
            // (scoped to those targets so an `ALTER TABLE`/`INDEX` isn't caught).
            Some("alter")
                if matches!(
                    toks.get(1).and_then(|t| word_lc(t)).as_deref(),
                    Some("role") | Some("database") | Some("user") | Some("system")
                ) && names_reserved() =>
            {
                return refused()
            }
            _ => {}
        }
    }

    // ---- (a) A leading SET / RESET / DISCARD targeting a reserved key. ----
    if let Some(first) = toks.first().and_then(|t| word_lc(t)) {
        match first.as_str() {
            // DISCARD [ALL|…]: DISCARD ALL resets every session GUC (incl. ours); any
            // DISCARD is a broad session reset, so refuse it outright under a context.
            "discard" => return refused(),
            "reset" => {
                // `RESET boatramp.project` (target segment == namespace) or `RESET ALL`
                // (clears custom GUCs too).
                if let Some(target) = toks.get(1).and_then(|t| word_lc(t)) {
                    if target == "all" || target == GUC_NAMESPACE || is_reserved_var(&target) {
                        return refused();
                    }
                }
            }
            "set" => {
                // Skip an optional SESSION / LOCAL qualifier, then inspect the target.
                let mut idx = 1;
                if matches!(
                    toks.get(idx).and_then(|t| word_lc(t)).as_deref(),
                    Some("session") | Some("local")
                ) {
                    idx += 1;
                }
                if let Some(target) = toks.get(idx).and_then(|t| word_lc(t)) {
                    // A GUC is `boatramp` `.` `project` (dotted); the MySQL var is the
                    // single `@boatramp_*` word. Either way the first identifier decides.
                    if target == GUC_NAMESPACE || is_reserved_var(&target) {
                        return refused();
                    }
                }
            }
            _ => {}
        }
    }

    // ---- (b) A `set_config(<arg1>, …)` call anywhere (it can hide inside a SELECT, and
    // more than one can appear). For each `set_config` word immediately followed by `(`,
    // inspect the first argument: reject unless it is a single simple string literal that
    // does NOT start with `boatramp.`. A concatenation/expression first arg is refused
    // (it could build `boatramp.*` at runtime). ----
    for (i, tok) in toks.iter().enumerate() {
        if word_lc(tok).as_deref() != Some("set_config") {
            continue;
        }
        // Must be a call: the next significant token is `(`.
        if !matches!(toks.get(i + 1), Some(Token::LParen)) {
            continue;
        }
        // The first argument token and the token following it.
        let arg0 = toks.get(i + 2);
        let after = toks.get(i + 3);
        match (arg0, after) {
            // A single simple **string literal** delimited by `,` or `)` — the only form
            // a legitimate caller uses for the setting name (`set_config('search_path', …)`).
            // Allow it iff it does not name the reserved GUC namespace. Note the generic
            // dialect lexes a double-quoted `"…"` as a *delimited identifier* (a quoted
            // `Word`), not a string literal, so it falls through to the catch-all below —
            // a non-idiomatic double-quoted first arg is refused, which is fine.
            (Some(Token::SingleQuotedString(s)), Some(Token::Comma | Token::RParen)) => {
                let name = s.to_ascii_lowercase();
                // `boatramp` itself or `boatramp.<anything>` (`.` as the namespace boundary).
                if name == GUC_NAMESPACE || name.starts_with(&format!("{GUC_NAMESPACE}.")) {
                    return refused();
                }
            }
            // Anything else as the first argument (a concatenation, a function call, a
            // quoted identifier, a bind param, an empty `()`, …) cannot be proven safe →
            // refuse: a non-literal could construct `boatramp.*` at runtime.
            _ => return refused(),
        }
    }

    Ok(())
}

/// How a **preview** deployment's SQL database relates to the site's live one
/// (operator policy; see the per-site/server config). The default is the safe,
/// isolated choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PreviewSqlMode {
    /// A fresh, empty database isolated from live (optionally seeded by an init
    /// script). Can never read or clobber live data.
    #[default]
    Empty,
    /// A consistent **copy** of the live database at branch time — realistic
    /// data, but writes stay in the preview's copy.
    Branch,
    /// The site's **live** database, shared with production traffic. The preview
    /// reads and writes real data — use only when that's intended.
    Shared,
}

/// Resolves a site's named SQL databases to [`SqlBackend`]s — the seam the
/// server's handler runtime uses to obtain a per-site database on demand
/// (opening/caching it lazily). The concrete mapping (a libsql file per site,
/// or a sqld namespace per site) lives behind this, so the server stays
/// storage-agnostic.
#[async_trait]
pub trait SqlBackends: Send + Sync {
    /// Open (or reuse) the database called `name` for `site` within tenant
    /// `project` (the empty name is the site's default database). Per-tenant +
    /// per-site isolation is the implementation's responsibility — a handler can
    /// only ever reach its own project's site's data.
    ///
    /// `project` and `site` are **separately** validated by the implementation
    /// and composed internally via
    /// [`ProjectRef::qualified`](crate::project::ProjectRef::qualified) (the
    /// reserved `default` project keeps the byte-identical, pre-project identity
    /// for back-compat; any other project prefixes `"<project>/"`). Passing a
    /// single already-composed `"<project>/<site>"` string as `site` would be
    /// rejected — the two names are kept apart so each is validated on its own.
    async fn database(
        &self,
        project: &str,
        site: &str,
        name: &str,
    ) -> Result<Arc<dyn SqlBackend>, SqlError>;

    /// Open (or reuse) the database for a **preview** deployment `preview` of
    /// `site` within tenant `project`. The implementation applies its configured
    /// [`PreviewSqlMode`]. The default is [`PreviewSqlMode::Empty`] — an isolated
    /// database keyed by project+site+preview, so a preview can never touch live
    /// state. The default composition qualifies `site` by `project` first, then
    /// appends the trusted `_preview/{preview}` suffix (both from validated
    /// parts), and delegates to [`database`](Self::database) under the reserved
    /// `default` project so the already-qualified identity is not re-qualified.
    async fn preview_database(
        &self,
        project: &str,
        site: &str,
        name: &str,
        preview: &str,
    ) -> Result<Arc<dyn SqlBackend>, SqlError> {
        let qualified = crate::project::ProjectRef::new(project).qualified(site);
        self.database(
            crate::project::DEFAULT_PROJECT,
            &format!("{qualified}/_preview/{preview}"),
            name,
        )
        .await
    }
}

/// The operator-facing SQL capability for a **managed** database: run a migration
/// script or a single query against a compute-backed database boatramp runs, using
/// its sealed managed credential (resolved server-side — the credential never leaves
/// the node). Backs `POST /api/sql/{db}/{exec,query}` and the `boatramp sql` CLI.
/// Distinct from [`SqlBackends`] (the per-site guest binding): this is a
/// project-scoped **operator** tool, admin-gated at the API.
#[async_trait]
pub trait OperatorSql: Send + Sync {
    /// Run a multi-statement migration `script` against managed database `db` in
    /// `project` (the simple-query protocol — `CREATE EXTENSION` + chained DDL).
    async fn exec_script(&self, project: &str, db: &str, script: &str) -> Result<(), SqlError>;

    /// Run one row-returning `sql` statement against managed database `db`.
    async fn query(&self, project: &str, db: &str, sql: &str) -> Result<SqlRows, SqlError>;
}

/// Tear down a deleted tenant's **managed** databases — the delete-time counterpart
/// to the create-time provisioning of a per-tenant managed `sql` binding. When a
/// project (or site) is deleted through the control plane, boatramp drops *that
/// tenant's* databases + login roles + sealed credentials — exactly that tenant's,
/// nothing else — so a deleted tenant leaves no orphaned data plane behind.
///
/// **Best-effort by contract.** Both methods return `()`: a deprovision failure is
/// the implementation's to log, and must never block or fail the delete it hangs off
/// (an orphaned database is a lesser evil than a delete that can't complete). The
/// reserved `default` project is never touched — its "tenant" is the whole
/// single-tenant install. Wired by the node when a compute-backed managed database
/// exists; the delete handlers call it after the store delete succeeds.
#[async_trait]
pub trait TenantDeprovisioner: Send + Sync {
    /// Deprovision every `Project`-scoped managed binding for the deleted `project`.
    async fn deprovision_project(&self, project: &str);

    /// Deprovision every `Site`-scoped managed binding for the deleted `site` of
    /// `project`.
    async fn deprovision_site(&self, project: &str, site: &str);
}

/// One transaction's worth of work. Dropping it without [`commit`] must leave
/// the database unchanged (the engine rolls back).
///
/// [`commit`]: SqlTransaction::commit
#[async_trait]
pub trait SqlTransaction: Send {
    /// Run a row-returning statement (e.g. `SELECT`), binding `params` to the
    /// statement's positional placeholders.
    async fn query(&mut self, sql: &str, params: &[SqlValue]) -> Result<SqlRows, SqlError>;

    /// Run a non-row statement (`INSERT`/`UPDATE`/`DELETE`/DDL), binding
    /// `params`. Returns the number of affected rows (0 for DDL).
    async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError>;

    /// Commit the transaction.
    async fn commit(self: Box<Self>) -> Result<(), SqlError>;

    /// Roll the transaction back.
    async fn rollback(self: Box<Self>) -> Result<(), SqlError>;
}

#[cfg(test)]
mod reserved_session_writes_tests {
    use super::reject_reserved_session_writes as check;

    fn rejected(sql: &str) -> bool {
        check(sql).is_err()
    }

    // ---- hostile statements that spoof the injected tenant MUST be rejected ----

    #[test]
    fn set_config_on_reserved_guc_is_rejected() {
        assert!(rejected(
            "SELECT set_config('boatramp.project','victim',false)"
        ));
        assert!(rejected("select set_config('boatramp.site', 'x', true)"));
        // Tolerant of whitespace around the call and the quote.
        assert!(rejected(
            "SELECT set_config ( 'boatramp.project' , 'v', false )"
        ));
        // Double-quoted first arg (unusual but a literal in some dialects).
        assert!(rejected(
            "SELECT set_config(\"boatramp.project\", 'v', false)"
        ));
        // A reserved set_config hiding AFTER a benign one in the same statement is
        // still caught (every occurrence is checked, not just the first).
        assert!(rejected(
            "SELECT set_config('search_path','app',false), \
             set_config('boatramp.project','v',false)"
        ));
    }

    #[test]
    fn set_reserved_guc_is_rejected() {
        assert!(rejected("SET boatramp.project = 'victim'"));
        assert!(rejected("set boatramp.project='victim'")); // no spaces
        assert!(rejected("SET SESSION boatramp.site = 'x'"));
        assert!(rejected("SET LOCAL boatramp.project TO 'x'"));
    }

    #[test]
    fn set_reserved_mysql_var_is_rejected() {
        assert!(rejected("SET @boatramp_project = 'victim'"));
        assert!(rejected("set @boatramp_site='x'"));
        assert!(rejected("SET @boatramp_project := 'x'")); // MySQL := assignment
        assert!(rejected("SET SESSION @boatramp_project = 'x'"));
    }

    #[test]
    fn reset_and_discard_of_reserved_state_is_rejected() {
        assert!(rejected("RESET boatramp.project"));
        assert!(rejected("RESET ALL")); // clears our GUC too
        assert!(rejected("DISCARD ALL"));
        assert!(rejected("discard all"));
    }

    // ---- legitimate app SQL MUST be allowed (narrow match) ----

    #[test]
    fn unrelated_set_statements_are_allowed() {
        assert!(!rejected("SET statement_timeout = 5000"));
        assert!(!rejected("SET search_path TO app, public"));
        assert!(!rejected("SET SESSION time_zone = '+00:00'"));
        assert!(!rejected("SET @my_var = 1")); // a non-reserved MySQL user var
        assert!(!rejected("RESET statement_timeout"));
    }

    #[test]
    fn a_select_mentioning_set_in_an_identifier_is_allowed() {
        // "set" appears only as an identifier / column word, not a SET statement.
        assert!(!rejected("SELECT settings FROM boatramp_projects"));
        assert!(!rejected(
            "SELECT * FROM offset_table WHERE reset_at > now()"
        ));
        // A normal SELECT that happens to filter on a column literally named similarly.
        assert!(!rejected("SELECT * FROM t WHERE name = 'boatramp.project'"));
    }

    #[test]
    fn set_config_on_a_non_reserved_guc_is_allowed() {
        assert!(!rejected("SELECT set_config('search_path','app',false)"));
        assert!(!rejected(
            "SELECT set_config('statement_timeout', '5000', true)"
        ));
    }

    // ---- bypasses of the earlier naive string filter, now closed by the tokenizer ----

    /// A comment spliced into the keyword or between the function name and `(` used to
    /// defeat the substring match; the tokenizer folds comments into whitespace we drop.
    #[test]
    fn inline_comment_splitting_the_keyword_is_rejected() {
        assert!(rejected("SET/*x*/ boatramp.project='x'"));
        assert!(rejected("set_config/*c*/('boatramp.project','x')"));
    }

    /// A leading comment used to push the real keyword out of the string's head.
    #[test]
    fn leading_comment_before_set_is_rejected() {
        assert!(rejected("/*c*/SET boatramp.project='x'"));
        assert!(rejected("/* hi */ set_config('boatramp.site','x')"));
    }

    /// String-concatenating the setting name hid `boatramp.` from a literal-prefix check;
    /// a non-simple-literal first argument is now refused wholesale.
    #[test]
    fn set_config_with_concatenated_name_is_rejected() {
        assert!(rejected(
            "SELECT set_config('boat'||'ramp.project','x',false)"
        ));
        assert!(rejected(
            "SELECT set_config('boatramp.'||'project','x',false)"
        ));
    }

    /// MySQL quoting variants around the reserved user var.
    #[test]
    fn mysql_quoted_reserved_var_is_rejected() {
        // Backtick-quoted whole var: `@boatramp_project` (one delimited identifier).
        assert!(rejected("SET `@boatramp_project`=1"));
        // `@` then a backtick-quoted name — an unbalanced/oddly-lexing form fails closed.
        assert!(rejected("SET @`boatramp_project`=1"));
    }

    /// Casing of the keyword and of the `set_config` function name is folded.
    #[test]
    fn case_variants_are_rejected() {
        assert!(rejected("sEt boatramp.project=1"));
        assert!(rejected("SeT_config('boatramp.project','x')"));
    }

    /// The `set_config` guard tolerates whitespace/comments around the call and catches a
    /// reserved call hiding after a benign one in the same statement.
    #[test]
    fn set_config_edge_forms_are_rejected() {
        assert!(rejected(
            "SELECT set_config ( 'boatramp.project' , 'v', false )"
        ));
        assert!(rejected(
            "SELECT set_config('search_path','app',false), \
             set_config('boatramp.project','v',false)"
        ));
    }

    // ---- deferred-execution bypasses (the tokenizer can't see into a body) ----

    /// The proven Round-1 High: a reserved write hidden in a **dollar-quoted** `DO`
    /// block. `$$…$$` / `$tag$…$tag$` lex as one opaque token, so the inner
    /// `set_config`/`SET` was invisible to the token scan — now the whole
    /// dollar-quoted class is refused under an injected context.
    #[test]
    fn dollar_quoted_do_block_reserved_write_is_rejected() {
        assert!(rejected(
            "DO $$ BEGIN PERFORM set_config('boatramp.project','victim',false); END $$;"
        ));
        assert!(rejected(
            "DO $$ BEGIN SET boatramp.project = 'victim'; END $$;"
        ));
        assert!(rejected(
            "DO $tag$ PERFORM set_config('boatramp.project','v',false); $tag$;"
        ));
        // A dollar-quoted string literal anywhere is refused too (a guest has no need
        // for one on the RLS path; it could carry a hidden body).
        assert!(rejected(
            "SELECT set_config($$boatramp.project$$, 'v', false)"
        ));
    }

    /// The rest of the deferred-execution / persistent-default class: a single-quoted
    /// `DO` body, `CALL`, defining a routine (single- or dollar-quoted body), and a
    /// persistent GUC default via `ALTER ROLE/DATABASE`.
    #[test]
    fn procedural_and_persistent_constructs_are_rejected() {
        assert!(rejected(
            "DO 'BEGIN PERFORM set_config(''boatramp.project'',''v'',false); END'"
        ));
        assert!(rejected("CALL do_evil()"));
        assert!(rejected(
            "CREATE FUNCTION e() RETURNS void AS $$ SELECT set_config('boatramp.project','v',false) $$ LANGUAGE sql"
        ));
        assert!(rejected(
            "CREATE FUNCTION e() RETURNS void AS 'BEGIN PERFORM set_config(''boatramp.project'',''v'',false); END' LANGUAGE plpgsql"
        ));
        assert!(rejected(
            "CREATE OR REPLACE PROCEDURE p() LANGUAGE sql AS $$ SELECT 1 $$"
        ));
        assert!(rejected(
            "ALTER ROLE tenant_role SET boatramp.project = 'victim'"
        ));
        assert!(rejected("ALTER DATABASE app SET boatramp.site = 'victim'"));
    }

    // ---- legit forms must still parse-and-pass (no regression) ----

    #[test]
    fn legit_set_and_set_config_forms_still_pass() {
        assert!(!rejected("SET statement_timeout = '5s'"));
        assert!(!rejected("SET search_path TO myschema"));
        assert!(!rejected("SET SESSION time_zone = '+00:00'"));
        assert!(!rejected("SET @my_var = 1"));
        assert!(!rejected("RESET statement_timeout"));
        assert!(!rejected("set_config('search_path','x',false)"));
        assert!(!rejected("set_config('statement_timeout','5s',true)"));
        // "set" / "boatramp.project" appearing only in identifiers or string literals.
        assert!(!rejected(
            "SELECT settings FROM t WHERE k = 'boatramp.project'"
        ));
        // Ordinary app SQL on the RLS path is untouched: parameterized queries ($1 is a
        // Placeholder, not a dollar-quoted body), plain DML, and non-routine DDL.
        assert!(!rejected("SELECT * FROM orders WHERE id = $1"));
        assert!(!rejected("INSERT INTO orders (id, total) VALUES ($1, $2)"));
        assert!(!rejected("UPDATE orders SET total = $1 WHERE id = $2"));
        assert!(!rejected(
            "CREATE TABLE orders (id bigint primary key, total numeric)"
        ));
        assert!(!rejected("ALTER TABLE orders ADD COLUMN note text"));
    }
}
