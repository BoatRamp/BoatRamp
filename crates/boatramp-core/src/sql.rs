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
    /// A JSON document (its JSON text) — the portable "JSON document" value, bound to
    /// each engine's canonical document type: `jsonb` on Postgres (validated,
    /// canonical, operator- and index-capable), the binary `JSON` type on MySQL, text
    /// (json1) on SQLite. So a guest writes a `jsonb`/`JSON` column with no `::` cast,
    /// AND the value **type-unifies** with such a column in `COALESCE`/comparison/`||`,
    /// not only on INSERT. Note Postgres `jsonb` validates on write (malformed JSON is
    /// rejected). Postgres's raw-text `json` type is out of the portable model — use
    /// raw SQL with an explicit `::json` cast for it. Read back as
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

impl SqlRows {
    /// Encode the rows as a compact JSON string: an object with `columns` (the column names) and
    /// `rows` (an array of row arrays), each cell a JSON scalar — `null`, a number (Integer/Real), a
    /// bool, or a string (Text; Json passthrough as its JSON text; Blob as lossy UTF-8). This is the
    /// wire form the `migrate-ddl` `query` verb returns to a migration function for verification.
    pub fn to_json_string(&self) -> String {
        use serde_json::{Map, Number, Value};
        let cell = |v: &SqlValue| -> Value {
            match v {
                SqlValue::Null => Value::Null,
                SqlValue::Boolean(b) => Value::Bool(*b),
                SqlValue::Integer(n) => Value::Number((*n).into()),
                SqlValue::Real(f) => Number::from_f64(*f)
                    .map(Value::Number)
                    .unwrap_or(Value::Null),
                SqlValue::Text(s) => Value::String(s.clone()),
                SqlValue::Json(s) => {
                    serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.clone()))
                }
                SqlValue::Blob(b) => Value::String(String::from_utf8_lossy(b).into_owned()),
            }
        };
        let rows: Vec<Value> = self
            .rows
            .iter()
            .map(|r| Value::Array(r.iter().map(cell).collect()))
            .collect();
        let mut obj = Map::new();
        obj.insert(
            "columns".into(),
            Value::Array(
                self.columns
                    .iter()
                    .map(|c| Value::String(c.clone()))
                    .collect(),
            ),
        );
        obj.insert("rows".into(), Value::Array(rows));
        Value::Object(obj).to_string()
    }
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
    /// The backend is **not ready yet** — a host-MANAGED database that is still starting,
    /// recovering, or has no healthy replica (distinct from a permanent config/transport error).
    /// This is **transient**: the caller should retry, or return a retryable `503` — never treat it
    /// as a permanent "not configured"/"not granted" failure. Emitted only by the managed-compute
    /// resolver; an external/local backend's outages stay [`Other`](SqlError::Other) (per-DB
    /// resilience, no readiness gate).
    #[error("sql backend not ready: {0}")]
    Unavailable(String),
}

impl SqlError {
    /// Wrap any displayable error as [`SqlError::Other`].
    pub fn other<E: std::fmt::Display>(err: E) -> Self {
        Self::Other(err.to_string())
    }

    /// Wrap a displayable error as [`SqlError::Unavailable`] — a transient "managed backend not
    /// ready yet" condition (still starting / recovering / no healthy replica).
    pub fn unavailable<E: std::fmt::Display>(err: E) -> Self {
        Self::Unavailable(err.to_string())
    }

    /// Whether this is the transient [`Unavailable`](SqlError::Unavailable) not-ready condition
    /// (the caller may retry or gate with a retryable `503`).
    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable(_))
    }
}

/// Operator-configured SQL session-context GUC names carrying the host-resolved tenant (and the
/// anonymous session) to an app's **Postgres RLS**, so its policies (`current_setting(name, true)`)
/// mirror boatramp's injected tenancy predicate as a defense-in-depth backstop. Set on a managed /
/// external SQL binding (the `rls_session` flag + these names, e.g. `app.tenant_id`). **Postgres
/// only** — the backstop is the `current_setting` RLS pattern; a libsql/MySQL backend leaves these
/// unset. The guest can NEVER set them itself (the reserved-write guard blocks the configured names,
/// [`reject_reserved_session_writes`]); the host derives the value from the SAME resolution the
/// injected predicate uses (own / target / session) or, for a posture-vetted `all` write, from the
/// row/statement being written — the DB's `WITH CHECK` / `USING` is the final arbiter of a mismatch.
#[derive(Debug, Clone)]
pub struct RlsGuc {
    /// The GUC carrying the resolved TENANT (e.g. `app.tenant_id`).
    pub tenant: String,
    /// The GUC carrying the anonymous SESSION id (e.g. `app.session_id`), if the operator uses one.
    pub session: Option<String>,
    /// A reserved, host-controlled sentinel written to [`Self::tenant`] on an **`all`-scoped READ**
    /// (v0.4.21) — a value the operator guarantees can never be a real tenant id, so a table that
    /// opts in with `USING (tenant_id = current_setting(name, true) OR current_setting(name, true) =
    /// '<marker>')` opens cross-tenant for the audited `all` twins while every other table (and every
    /// write) stays strict. `None` ⇒ `all` reads leave the GUC untouched (v0.4.20 behavior:
    /// fail-closed). The guest can never set it — the whole [`Self::tenant`] namespace is reserved.
    pub all_marker: Option<String>,
}

impl RlsGuc {
    /// The configured GUC names, lowercased — the EXTRA reserved keys a guest may not set (on top of
    /// the always-reserved `boatramp.*` / `@boatramp_*`), so a guest can't forge the RLS backstop.
    pub fn reserved_names(&self) -> Vec<String> {
        let mut v = vec![self.tenant.to_ascii_lowercase()];
        if let Some(s) = &self.session {
            v.push(s.to_ascii_lowercase());
        }
        v
    }
}

/// Render a **transaction-local Postgres** GUC set (`SELECT set_config($1, $2, true)`). Both the
/// setting NAME and the VALUE are BOUND parameters (never interpolated), so a dotted operator name
/// like `app.tenant_id` and any value are injection-safe; the `true` scopes the setting to the
/// current transaction (auto-cleared at COMMIT/ROLLBACK, like the `boatramp.project`/`site` context).
/// The value is bound as TEXT (`set_config`'s argument type); the operator's RLS policy casts if its
/// key column isn't text. Postgres only — callers gate on [`Dialect::Postgres`].
pub fn render_set_local_guc(name: &str, value: &SqlValue) -> (String, Vec<SqlValue>) {
    let text = match value {
        SqlValue::Text(s) => s.clone(),
        SqlValue::Integer(i) => i.to_string(),
        SqlValue::Boolean(b) => b.to_string(),
        SqlValue::Real(r) => r.to_string(),
        // A tenant/session key is realistically text or an integer; anything else (blob/json/null)
        // has no meaningful GUC text — bind empty so RLS `= current_setting(...)` denies (fail-safe).
        SqlValue::Blob(_) | SqlValue::Null | SqlValue::Json(_) => String::new(),
    };
    (
        "SELECT set_config(?1, ?2, true)".to_string(),
        vec![SqlValue::Text(name.to_string()), SqlValue::Text(text)],
    )
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

    /// The operator-configured RLS session-GUC names ([`RlsGuc`]) this backend carries, or `None`
    /// (the common case). When `Some` **and** [`dialect`](Self::dialect) is
    /// [`Postgres`](Dialect::Postgres), the handler `sql`/`orm` binding sets the host-resolved tenant
    /// (own/target/session) per transaction, and the row's tenant per `all` write, via
    /// [`render_set_local_guc`], so an app's RLS mirrors the injected predicate. The guest can never
    /// set these itself ([`reject_reserved_session_writes`] blocks the configured names).
    fn rls_guc(&self) -> Option<&RlsGuc> {
        None
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
/// - **any** `@boatramp_*` MySQL user-var token appearing *anywhere* in the statement
///   — MySQL writes it not only as the leading `SET` target but after a comma
///   (`SET @x=1, @boatramp_project=…`, incl. `:=`) or via `SELECT … INTO @boatramp_*`
///   (no `SET` at all); the reserved namespace is refused position-independently
///   (Postgres has no such token and a MySQL app never names the reserved var);
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
/// `extra_namespaces` are additional reserved GUC namespaces (lowercased leading segments, e.g.
/// `app` for a configured `app.tenant_id`/`app.session_id` RLS GUC) — a guest must not set the
/// operator's RLS session keys either, or it could forge the defense-in-depth backstop. Reserving
/// the whole namespace (like `boatramp`) is the safe, simple superset.
///
/// Returns [`SqlError::Other`] with a clear message on a match, else `Ok(())`.
pub fn reject_reserved_session_writes(
    sql: &str,
    extra_namespaces: &[String],
) -> Result<(), SqlError> {
    use sqlparser::dialect::GenericDialect;
    use sqlparser::tokenizer::{Token, Tokenizer, Word};

    /// The reserved GUC namespace (Postgres) — the first dotted segment, lowercased.
    const GUC_NAMESPACE: &str = "boatramp";
    /// The reserved MySQL user-var prefix, lowercased (an `@`-prefixed identifier).
    const MYSQL_VAR_PREFIX: &str = "@boatramp_";

    // A reserved GUC namespace (leading dotted segment): boatramp's own, or an operator RLS one.
    let is_reserved_ns = |w: &str| w == GUC_NAMESPACE || extra_namespaces.iter().any(|n| n == w);

    let refused = || {
        Err(SqlError::Other(
            "setting a reserved session key (boatramp.* / @boatramp_*, or the operator's \
             rls_session tenant GUC) is not permitted from a handler: it is managed by \
             rls_session and reserved for per-request tenant isolation"
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

    // ---- (0b) A reserved MySQL user var (`@boatramp_*`) appearing ANYWHERE. MySQL
    // writes it not only via a leading `SET` but also mid-`SET` after a comma
    // (`SET @x=1, @boatramp_project='v'` — a `:=` variant too) and via
    // `SELECT … INTO @boatramp_project` (no `SET` keyword at all), none of which the
    // leading-token check (a) sees. Postgres has no legitimate `@boatramp_*` token and
    // a MySQL app never needs to name the reserved var, so a **position-independent**
    // refusal (like the `set_config` scan) closes the whole family — comma-assign,
    // `SELECT … INTO`, `:=`, and case/quote variants. ----
    if toks
        .iter()
        .any(|t| word_lc(t).is_some_and(|w| is_reserved_var(&w)))
    {
        return refused();
    }
    {
        let leading = toks.first().and_then(|t| word_lc(t));
        let has_word = |w: &str| toks.iter().any(|t| word_lc(t).as_deref() == Some(w));
        let names_reserved = || {
            toks.iter()
                .any(|t| word_lc(t).is_some_and(|w| is_reserved_ns(&w) || is_reserved_var(&w)))
        };
        match leading.as_deref() {
            // Anonymous code block / procedure call / prepared-statement indirection:
            // deferred execution the token scan can't see through. `DO`/`CALL` run a
            // body; `PREPARE s FROM '<text>'` + `EXECUTE s` (MySQL, same pooled
            // connection within one invocation) hides the reserved write inside a
            // *string literal* — which we must NOT scan (a literal naming the key is
            // legitimate data), so refuse the deferral construct instead. The guest
            // `sql` binding parameterizes via bind params (`$1`/`?`), never SQL-level
            // PREPARE/EXECUTE, so refusing these on the RLS path costs nothing.
            Some("do") | Some("call") | Some("prepare") | Some("execute") => return refused(),
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
                    if target == "all" || is_reserved_ns(&target) || is_reserved_var(&target) {
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
                    if is_reserved_ns(&target) || is_reserved_var(&target) {
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
                // A reserved namespace itself, or `<ns>.<anything>` (`.` as the boundary) — for
                // boatramp's own namespace AND any operator RLS namespace (e.g. `app.tenant_id`).
                let ns_of = name.split('.').next().unwrap_or(&name);
                if is_reserved_ns(ns_of) {
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

/// The migration-guard **tokenizer dialect** — selects the sqlparser lexer rules so a script is
/// tokenized the way the target engine will read it. Postgres/generic strip `--` + `/* */` comments,
/// `'…'` strings and `$$…$$` dollar-quoted bodies; MySQL additionally treats `# …` as a line comment
/// and `` `…` `` as a quoted identifier. Using the engine's own rules keeps a guard from being
/// evaded by an engine-specific comment/quote form the generic lexer wouldn't strip (e.g. a MySQL
/// `# COMMIT` line comment, or a keyword hidden behind a `#`-comment on MySQL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardDialect {
    /// Postgres / generic lexer rules (the historical default).
    Postgres,
    /// MySQL lexer rules (`#` line comments, backtick identifiers).
    Mysql,
}

impl From<Dialect> for GuardDialect {
    fn from(d: Dialect) -> Self {
        match d {
            Dialect::Mysql => Self::Mysql,
            // SQLite/libsql shares the generic/Postgres comment + quoting rules for guard purposes.
            Dialect::Postgres | Dialect::Sqlite => Self::Postgres,
        }
    }
}

/// Strip MySQL/MariaDB comments **faithfully to how the server itself lexes them**, so the guard's
/// word scan sees exactly the tokens the server will EXECUTE. This replaces the earlier
/// context-blind `neutralize_mysql_executable_comments` + raw-byte belt (Security review CRITICAL-1
/// **re-review**, task #489). Those closed the reported `/*! COMMIT */` string but left two more
/// evasions, both verified live (guard PASS + a real statement executed via `sqlx::raw_sql`, which
/// forwards comments to the server verbatim):
///   1. `/* /*! */ <kw> -- */` — the old neutralizer treated a `/*!` occurring INSIDE an ordinary
///      `/* … */` comment as an executable-comment opener and consumed that ordinary comment's own
///      `*/`, un-closing it so the guard's lexer swallowed the following LIVE statement while MySQL
///      ran it.
///   2. `/* a /* b */ <kw> -- */` — no `/*!` at all: **sqlparser's MySqlDialect NESTS `/* … */`
///      block comments, but MySQL/MariaDB do NOT** (the first `*/` closes), so a nested-looking
///      comment hid a live keyword from the tokenizer while the server executed it.
///
/// One MySQL-faithful lexical pass:
///   - `'…'` / `"…"` strings and `` `…` `` quoted identifiers are copied **verbatim** (so a `/*`
///     inside a string is never mistaken for a comment, and the tokenizer still sees the string /
///     identifier for quote-immunity), honoring `\`-escapes (default `sql_mode`) and doubled-quote
///     escapes; an unterminated one returns `None` (→ guards fail closed).
///   - `-- ` (dash-dash then whitespace/EOL) and `#` line comments run to end-of-line and collapse
///     to a single space — a **token separator**, so `create/**/extension` stays two words.
///   - ordinary `/* … */` block comments are **non-nesting** (first `*/` closes, matching the
///     server) and collapse to a single space.
///   - `/*! … */` (MySQL) and `/*M! … */` (MariaDB) **executable** comments have their framing (and
///     any `/*!NNNNN` / `/*M!NNNNNN` version digits) blanked and their body copied **verbatim as
///     live text**, so a `COMMIT` / ledger write / `CREATE EXTENSION` hidden in one is scanned and
///     classified rather than dropped.
///
/// The result contains **no comments**, so when [`significant_words_in`] hands it to sqlparser the
/// nesting bug (evasion 2) can never fire; strings/backticks survive so quote-immunity is kept.
/// Called ONLY on the MySQL guard path; Postgres/generic lexing is untouched.
fn mysql_strip_comments_faithfully(script: &str) -> Option<String> {
    let b = script.as_bytes();
    let n = b.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let mut i = 0;
    // How many executable comments (`/*!` / `/*M!`) are currently open. Their bodies lex as NORMAL
    // SQL (so inner ordinary `/* */` comments, strings and line comments are consumed while we look
    // for the top-level `*/` that closes the executable comment) — matching the server, which
    // executes a `/*! /* */ COMMIT */` (the inner `/* */` is a nested comment, the exec closes at the
    // LAST `*/`). Verified live: a first-literal-`*/` scan wrongly kept `COMMIT` hidden here.
    let mut exec_depth: u32 = 0;
    while i < n {
        let c = b[i];
        match c {
            // String literals: copy verbatim, honoring `\` escapes and doubled-quote escapes. A `*/`
            // inside a string is string content (not an exec close), exactly as the server lexes an
            // exec body.
            b'\'' | b'"' => {
                let quote = c;
                out.push(c);
                i += 1;
                loop {
                    if i >= n {
                        return None; // unterminated string
                    }
                    let d = b[i];
                    if d == b'\\' {
                        out.push(d);
                        i += 1;
                        if i >= n {
                            return None; // trailing backslash — unterminated
                        }
                        out.push(b[i]);
                        i += 1;
                        continue;
                    }
                    if d == quote {
                        // Doubled quote inside the string is an escaped quote, not the end.
                        if i + 1 < n && b[i + 1] == quote {
                            out.push(quote);
                            out.push(quote);
                            i += 2;
                            continue;
                        }
                        out.push(quote);
                        i += 1;
                        break; // string closed
                    }
                    out.push(d);
                    i += 1;
                }
            }
            // Backtick-quoted identifier: copy verbatim, doubled backtick escapes.
            b'`' => {
                out.push(c);
                i += 1;
                loop {
                    if i >= n {
                        return None; // unterminated identifier
                    }
                    let d = b[i];
                    if d == b'`' {
                        if i + 1 < n && b[i + 1] == b'`' {
                            out.push(b'`');
                            out.push(b'`');
                            i += 2;
                            continue;
                        }
                        out.push(b'`');
                        i += 1;
                        break;
                    }
                    out.push(d);
                    i += 1;
                }
            }
            // `#` line comment to EOL → one separator space (keep the newline for the next line).
            b'#' => {
                out.push(b' ');
                i += 1;
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            // `-- ` line comment: MySQL requires whitespace/EOL after the double dash.
            b'-' if i + 1 < n
                && b[i + 1] == b'-'
                && (i + 2 >= n || b[i + 2].is_ascii_whitespace()) =>
            {
                out.push(b' ');
                i += 2;
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            // A top-level `*/` while an executable comment is open closes it (its body was emitted
            // live). A bare `*/` in normal SQL (`exec_depth == 0`) is not special — fall through.
            b'*' if i + 1 < n && b[i + 1] == b'/' && exec_depth > 0 => {
                out.extend_from_slice(b"  ");
                exec_depth -= 1;
                i += 2;
            }
            // Block comment — ordinary vs executable.
            b'/' if i + 1 < n && b[i + 1] == b'*' => {
                let after = i + 2;
                let is_exec_mysql = after < n && b[after] == b'!';
                let is_exec_maria =
                    after + 1 < n && (b[after] == b'M' || b[after] == b'm') && b[after + 1] == b'!';
                if is_exec_mysql || is_exec_maria {
                    // Executable comment: blank the framing (+ version digits) and keep lexing the
                    // body in NORMAL mode until its matching top-level `*/` (handled by the `*/` arm
                    // above). The body's live tokens are therefore scanned + classified.
                    let mut j = if is_exec_mysql {
                        out.extend_from_slice(b"   "); // blank `/*!`
                        after + 1
                    } else {
                        out.extend_from_slice(b"    "); // blank `/*M!`
                        after + 2
                    };
                    while j < n && b[j].is_ascii_digit() {
                        out.push(b' ');
                        j += 1;
                    }
                    exec_depth += 1;
                    i = j;
                } else {
                    // Ordinary block comment, NON-NESTING: first `*/` closes → one separator space.
                    // (Applies inside an exec body too — the server treats it as a nested comment.)
                    let mut k = i + 2;
                    loop {
                        if k + 1 >= n {
                            return None; // unterminated block comment
                        }
                        if b[k] == b'*' && b[k + 1] == b'/' {
                            break;
                        }
                        k += 1;
                    }
                    out.push(b' ');
                    i = k + 2;
                }
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    if exec_depth != 0 {
        return None; // unterminated executable comment — fail closed
    }
    // `out` is only original bytes or ASCII spaces, so it is valid UTF-8 whenever `script` was.
    String::from_utf8(out).ok()
}

/// Tokenize `script` under `dialect` into its significant **word** tokens (lowercased), dropping
/// whitespace + comments and treating string / dollar-quoted bodies as opaque single tokens (so a
/// `--`/`/* */`/`#` comment, a `'…'` literal, or a `$$ … $$` function body can neither hide nor
/// forge a keyword). `None` if the script cannot be lexed — the migration guards then fail
/// **closed** (refuse), so an unlexable step can never smuggle a guarded construct past a naive byte
/// scan.
///
/// This backs the owner-gated migration guards ([`script_has_txn_control`],
/// [`script_references_word`], [`script_has_create_extension`]): the earlier byte-scan versions were
/// comment- and casing-evadable (`/*c*/BEGIN`, `COMMIT-- x`, `COMMIT# x` on MySQL) — the engine
/// strips comments before parse, so a scan of the raw bytes saw a different statement than the
/// server ran.
fn significant_words_in(script: &str, dialect: GuardDialect) -> Option<Vec<String>> {
    use sqlparser::dialect::{GenericDialect, MySqlDialect};
    use sqlparser::tokenizer::{Token, Tokenizer, Word};
    // Tokenize with the engine's own lexer so its comment/quote forms are honored (MySQL `#`
    // comments + backtick identifiers). `GenericDialect` for Postgres/SQLite keeps the historical
    // behavior byte-for-byte.
    let raw = match dialect {
        GuardDialect::Mysql => {
            // MySQL/MariaDB comment semantics diverge from sqlparser's MySqlDialect in two ways that
            // are guard-evasion vectors (Security review CRITICAL-1 + re-review, task #489):
            //   - `/*! … */` (MySQL) / `/*M! … */` (MariaDB) **executable comments** are EXECUTED by
            //     the server but DROPPED as ordinary comments by sqlparser — so a `COMMIT` / ledger
            //     write / `CREATE EXTENSION` hidden in one would lex to nothing.
            //   - sqlparser **nests** `/* … */`; the server does **not** (first `*/` closes) — so a
            //     `/* a /* b */ <kw> -- */` hides a live keyword from sqlparser while the server runs
            //     it.
            // So we do our OWN MySQL-faithful comment strip first (executable bodies exposed as live
            // text, ordinary/line comments removed non-nesting, strings/backticks preserved) and hand
            // sqlparser a comment-free string where neither divergence can occur. Fails **closed**
            // (`None` → guards refuse) on any unterminated string/identifier/comment.
            let stripped = mysql_strip_comments_faithfully(script)?;
            Tokenizer::new(&MySqlDialect {}, &stripped)
                .tokenize()
                .ok()?
        }
        GuardDialect::Postgres => Tokenizer::new(&GenericDialect {}, script).tokenize().ok()?,
    };
    Some(
        raw.iter()
            .filter_map(|t| match t {
                // Quoted identifiers keep their inner (unquoted) text, so a `"boatramp_migrations"`
                // (or a MySQL `` `boatramp_migrations` ``) still matches — quote-immune as well as
                // comment-immune.
                Token::Word(Word { value, .. }) => Some(value.to_ascii_lowercase()),
                _ => None,
            })
            .collect(),
    )
}

/// Whether `words` (already-tokenized, lowercased) issue transaction control — see
/// [`script_has_txn_control`].
fn words_have_txn_control(words: &[String]) -> bool {
    let mut case_depth: u32 = 0;
    for w in words {
        match w.as_str() {
            "case" => case_depth += 1,
            "end" => {
                if case_depth == 0 {
                    return true; // a bare `END` = COMMIT
                }
                case_depth -= 1;
            }
            "begin" | "start" | "commit" | "rollback" | "abort" | "savepoint" | "release" => {
                return true
            }
            _ => {}
        }
    }
    false
}

/// Whether `script` issues its own **transaction control** — `BEGIN`/`START`/`COMMIT`/`END`/
/// `ROLLBACK`/`ABORT`/`SAVEPOINT`/`RELEASE` as a keyword token. Comment-, casing-, string- and
/// dollar-quote-immune (a PL/pgSQL `$$ BEGIN … END $$` body is one opaque token, so it is NOT
/// flagged — fixing a latent false positive the byte scan had). `END` is flagged only at CASE-depth
/// 0, so a `CASE … END` expression is not mistaken for a transaction end. Fails **closed** (returns
/// `true`) if the script cannot be lexed. Postgres/generic lexer; see
/// [`script_has_txn_control_in`] for a dialect-aware variant.
pub fn script_has_txn_control(script: &str) -> bool {
    script_has_txn_control_in(script, GuardDialect::Postgres)
}

/// Dialect-aware [`script_has_txn_control`] — tokenizes under `dialect` so a MySQL `# COMMIT` line
/// comment (which the generic lexer would not strip) can't hide transaction control. On MySQL a
/// `/*! … */` executable comment is un-hidden by the tokenizer-honest neutralization in
/// [`significant_words_in`] (its body lexes live), so a `/*! COMMIT */` is caught here as
/// transaction control (Security review CRITICAL-1).
pub fn script_has_txn_control_in(script: &str, dialect: GuardDialect) -> bool {
    match significant_words_in(script, dialect) {
        Some(words) => words_have_txn_control(&words),
        None => true, // fail closed
    }
}

/// Whether `script` references identifier `needle` (case-insensitive) as a **word** token — a string
/// literal, comment, or dollar-quoted body never matches. Backs the ledger-schema guard (`needle =
/// "boatramp_migrations"`). Fails **closed** (returns `true`) if the script cannot be lexed.
/// Postgres/generic lexer; see [`script_references_word_in`] for a dialect-aware variant.
pub fn script_references_word(script: &str, needle: &str) -> bool {
    script_references_word_in(script, needle, GuardDialect::Postgres)
}

/// Dialect-aware [`script_references_word`]. On MySQL a `/*! … */` executable comment is handled by
/// the tokenizer-honest neutralization in [`significant_words_in`] (its body lexes as LIVE tokens),
/// so a `boatramp_migrations` reference hidden in one is caught by the normal word scan and — unlike
/// the txn-control / create-extension guards — classified precisely as a ledger reference rather than
/// blanket-refused, so `OwnerDdl::guard`'s ledger-then-txn ordering reports the RIGHT reason for an
/// executable-comment `COMMIT` vs an executable-comment ledger write (Security review CRITICAL-1). A
/// marker that survives (neutralization can't resolve) makes `significant_words_in` return `None` →
/// this guard fails closed anyway.
pub fn script_references_word_in(script: &str, needle: &str, dialect: GuardDialect) -> bool {
    let needle = needle.to_ascii_lowercase();
    match significant_words_in(script, dialect) {
        Some(words) => words.contains(&needle),
        None => true, // fail closed
    }
}

/// Whether `script` contains `CREATE EXTENSION` as adjacent word tokens (comment-/casing-immune).
/// Fails **closed** (returns `true`) if the script cannot be lexed. Postgres/generic lexer; see
/// [`script_has_create_extension_in`] for a dialect-aware variant.
pub fn script_has_create_extension(script: &str) -> bool {
    script_has_create_extension_in(script, GuardDialect::Postgres)
}

/// Dialect-aware [`script_has_create_extension`]. On MySQL a `/*! … */` executable comment is
/// un-hidden by the tokenizer-honest neutralization in [`significant_words_in`] (its body lexes
/// live), so a `/*! CREATE EXTENSION x */` is caught here as a create-extension (Security review
/// CRITICAL-1).
pub fn script_has_create_extension_in(script: &str, dialect: GuardDialect) -> bool {
    match significant_words_in(script, dialect) {
        Some(words) => words
            .windows(2)
            .any(|w| w[0] == "create" && w[1] == "extension"),
        None => true, // fail closed
    }
}

#[cfg(test)]
mod migration_guard_tests {
    use super::{script_has_create_extension, script_has_txn_control, script_references_word};

    #[test]
    fn txn_control_is_comment_and_casing_immune() {
        // Plain forms.
        for s in [
            "BEGIN; DROP TABLE t; COMMIT",
            "commit",
            "ROLLBACK",
            "abort",
            "SAVEPOINT x",
            "RELEASE SAVEPOINT x",
            "END",
        ] {
            assert!(script_has_txn_control(s), "should flag: {s:?}");
        }
        // Comment-evasion attempts the byte scan missed.
        for s in [
            "/*c*/BEGIN",
            "COMMIT-- trailing",
            "COMMIT/**/",
            "BEGIN--\nDROP TABLE t",
            "cOmMiT",
        ] {
            assert!(
                script_has_txn_control(s),
                "should flag (comment/casing): {s:?}"
            );
        }
    }

    #[test]
    fn txn_control_does_not_false_positive() {
        // A CASE…END expression is not transaction control.
        assert!(!script_has_txn_control(
            "UPDATE t SET s = CASE WHEN x > 0 THEN 'a' ELSE 'b' END"
        ));
        // A PL/pgSQL body's BEGIN/END lives inside a dollar-quoted (opaque) token.
        assert!(!script_has_txn_control(
            "CREATE FUNCTION f() RETURNS int AS $$ BEGIN RETURN 1; END $$ LANGUAGE plpgsql"
        ));
        // `commit` inside a string literal is not control.
        assert!(!script_has_txn_control(
            "INSERT INTO log (msg) VALUES ('commit happened')"
        ));
        // Plain DDL.
        assert!(!script_has_txn_control(
            "CREATE TABLE t (id int primary key)"
        ));
    }

    #[test]
    fn ledger_schema_reference_is_comment_and_quote_immune() {
        assert!(script_references_word(
            "SELECT * FROM boatramp_migrations.schema_migrations",
            "boatramp_migrations"
        ));
        assert!(script_references_word(
            "DROP TABLE /*x*/ boatramp_migrations.schema_migrations",
            "boatramp_migrations"
        ));
        assert!(script_references_word(
            "SELECT * FROM \"boatramp_migrations\".t",
            "boatramp_migrations"
        ));
        // Not referenced inside a string literal.
        assert!(!script_references_word(
            "INSERT INTO t (note) VALUES ('boatramp_migrations is host-owned')",
            "boatramp_migrations"
        ));
        assert!(!script_references_word(
            "CREATE TABLE app.widget (id int)",
            "boatramp_migrations"
        ));
    }

    #[test]
    fn create_extension_is_comment_immune() {
        assert!(script_has_create_extension("CREATE EXTENSION pgcrypto"));
        assert!(script_has_create_extension(
            "create/**/extension if not exists citext"
        ));
        assert!(!script_has_create_extension("CREATE TABLE t (id int)"));
        // The word 'extension' alone (e.g. a column) is not CREATE EXTENSION.
        assert!(!script_has_create_extension(
            "CREATE TABLE t (extension text)"
        ));
    }

    #[test]
    fn unlexable_fails_closed() {
        // An unterminated string can't be lexed → every guard refuses.
        let bad = "SELECT 'unterminated";
        assert!(script_has_txn_control(bad));
        assert!(script_references_word(bad, "boatramp_migrations"));
        assert!(script_has_create_extension(bad));
    }

    #[test]
    fn mysql_dialect_guards_honor_hash_comments_and_backticks() {
        use super::{script_has_txn_control_in, script_references_word_in, GuardDialect};
        // MySQL `#` line comment: a `# COMMIT` following a real statement IS transaction control the
        // MySQL server will execute (the text after `#` is stripped as a comment, so the `COMMIT`
        // must be BEFORE it to matter). A `COMMIT` hidden AFTER a `#` is a comment and must NOT flag.
        assert!(
            script_has_txn_control_in("DROP TABLE t; COMMIT # done", GuardDialect::Mysql),
            "a real COMMIT before a # comment is transaction control"
        );
        assert!(
            !script_has_txn_control_in("CREATE TABLE t (id int) # COMMIT", GuardDialect::Mysql),
            "COMMIT inside a MySQL # line comment is stripped, not control"
        );
        // A backtick-quoted identifier matching the ledger schema is still caught (quote-immune).
        assert!(script_references_word_in(
            "SELECT * FROM `boatramp_migrations`.`schema_migrations`",
            "boatramp_migrations",
            GuardDialect::Mysql,
        ));
        // The ledger name inside a MySQL # comment is NOT a reference.
        assert!(!script_references_word_in(
            "CREATE TABLE t (id int) # touches boatramp_migrations later",
            "boatramp_migrations",
            GuardDialect::Mysql,
        ));
        // Plain MySQL DDL is not transaction control.
        assert!(!script_has_txn_control_in(
            "CREATE TABLE `widget` (id int primary key)",
            GuardDialect::Mysql,
        ));
    }

    /// Security review CRITICAL-1: MySQL's `/*! … */` (and version-gated `/*!NNNNN … */`) executable
    /// comment is EXECUTED by MySQL but dropped as an ordinary block comment by the lexer, so its
    /// body could smuggle a `COMMIT` (S4), a `boatramp_migrations` write (S3), or a `CREATE
    /// EXTENSION` past the word-scan guards. Under the MySQL dialect every guard must REFUSE such a
    /// script — via BOTH the raw-marker backstop and the tokenizer-honest neutralization (each
    /// input is caught even if the other layer were removed).
    #[test]
    fn mysql_executable_comment_is_refused_by_every_guard() {
        use super::{
            script_has_create_extension_in, script_has_txn_control_in, script_references_word_in,
            GuardDialect,
        };
        // S4 — transaction control hidden in an executable comment.
        for s in [
            "/*! COMMIT */",
            "/*!40000 COMMIT */",
            "CREATE TABLE z(a int); /*! COMMIT */",
            "/*!50000 ROLLBACK */",
        ] {
            assert!(
                script_has_txn_control_in(s, GuardDialect::Mysql),
                "MySQL must refuse txn-control in an executable comment: {s:?}"
            );
        }
        // S3 — a ledger write hidden in an executable comment.
        for s in [
            "/*! DELETE FROM boatramp_migrations.schema_migrations */",
            "/*!40000 DELETE FROM boatramp_migrations.schema_migrations */",
        ] {
            assert!(
                script_references_word_in(s, "boatramp_migrations", GuardDialect::Mysql),
                "MySQL must refuse a ledger reference in an executable comment: {s:?}"
            );
        }
        // Extension — a `CREATE EXTENSION` hidden in an executable comment.
        for s in [
            "/*! CREATE EXTENSION evil */",
            "/*!40000 CREATE EXTENSION x */",
        ] {
            assert!(
                script_has_create_extension_in(s, GuardDialect::Mysql),
                "MySQL must refuse CREATE EXTENSION in an executable comment: {s:?}"
            );
        }
        // Classification precision (so the substrate/OwnerDdl ordering reports the RIGHT reason):
        // a `/*! COMMIT */` is txn-control ONLY — not a create-extension nor a ledger reference —
        // and a `/*! DELETE … boatramp_migrations … */` is a ledger reference ONLY. This is what a
        // blanket byte-scan belt could not give (it would flag whichever guard runs first).
        let commit = "CREATE TABLE z(a int); /*! COMMIT */";
        assert!(script_has_txn_control_in(commit, GuardDialect::Mysql));
        assert!(!script_has_create_extension_in(commit, GuardDialect::Mysql));
        assert!(!script_references_word_in(
            commit,
            "boatramp_migrations",
            GuardDialect::Mysql
        ));
        let ledger = "/*! DELETE FROM boatramp_migrations.schema_migrations */";
        assert!(script_references_word_in(
            ledger,
            "boatramp_migrations",
            GuardDialect::Mysql
        ));
        assert!(!script_has_txn_control_in(ledger, GuardDialect::Mysql));
        assert!(!script_has_create_extension_in(ledger, GuardDialect::Mysql));
    }

    /// Security review CRITICAL-1 (the PG-unchanged assertion): Postgres/generic treats `/*! … */`
    /// as an inert block comment (there is no executable-comment special form), so the SAME inputs
    /// behave as before under the Postgres dialect — the comment body is dropped and NOT flagged.
    /// This proves the CRITICAL-1 fix is scoped to `GuardDialect::Mysql` and never regresses PG.
    #[test]
    fn postgres_treats_executable_comment_syntax_as_inert() {
        use super::{
            script_has_create_extension_in, script_has_txn_control_in, script_references_word_in,
            GuardDialect,
        };
        // A `/*! COMMIT */` is a plain comment on Postgres — no transaction control.
        assert!(!script_has_txn_control_in(
            "/*! COMMIT */",
            GuardDialect::Postgres
        ));
        assert!(!script_has_txn_control_in(
            "/*!40000 COMMIT */",
            GuardDialect::Postgres
        ));
        // A ledger name inside the comment is not a reference on Postgres.
        assert!(!script_references_word_in(
            "/*! DELETE FROM boatramp_migrations.schema_migrations */",
            "boatramp_migrations",
            GuardDialect::Postgres,
        ));
        // A `CREATE EXTENSION` inside the comment is not flagged on Postgres.
        assert!(!script_has_create_extension_in(
            "/*! CREATE EXTENSION evil */",
            GuardDialect::Postgres,
        ));
        // A real Postgres statement AROUND the inert comment still lexes normally (the neutralizer
        // is never run on the PG path, so a genuine COMMIT outside the comment is still caught).
        assert!(script_has_txn_control_in(
            "DROP TABLE t; /*! nop */ COMMIT",
            GuardDialect::Postgres
        ));
    }

    /// The MySQL-faithful strip exposes executable-comment bodies as live text, removes ordinary/line
    /// comments (non-nesting), and preserves strings/identifiers — so a real statement around a
    /// comment is still lexed and a benign script is left semantically intact.
    #[test]
    fn mysql_faithful_strip_exposes_and_preserves() {
        use super::{mysql_strip_comments_faithfully, script_has_txn_control_in, GuardDialect};
        // The real statement survives; the executable-comment COMMIT is un-hidden and flagged.
        assert!(script_has_txn_control_in(
            "CREATE TABLE z(a int); /*! COMMIT */",
            GuardDialect::Mysql
        ));
        // A plain MySQL script with no comment is byte-for-byte unchanged (backtick ident preserved).
        assert_eq!(
            mysql_strip_comments_faithfully("CREATE TABLE `t` (id int)").unwrap(),
            "CREATE TABLE `t` (id int)"
        );
        // An unterminated executable comment fails closed (None → guards refuse).
        assert!(mysql_strip_comments_faithfully("/*! COMMIT").is_none());
        assert!(script_has_txn_control_in("/*! COMMIT", GuardDialect::Mysql));
        // Non-ASCII content around a stripped comment is preserved intact (UTF-8 safety): the strings
        // survive verbatim and the executable-comment body `x` is exposed live.
        let s = mysql_strip_comments_faithfully("SELECT 'café' /*! x */ , 'naïve'").unwrap();
        assert!(s.contains("'café'") && s.contains("'naïve'") && s.contains(" x "));
        assert!(!s.contains("/*") && !s.contains("*/"));
        // TWO executable comments in one script are both un-hidden (each keyword un-hidden).
        assert!(script_has_txn_control_in(
            "/*! SELECT 1 */ CREATE TABLE t(a int); /*!40000 ROLLBACK */",
            GuardDialect::Mysql
        ));
        // An empty-bodied `/*!*/` and a version-only `/*!40000 */` strip to whitespace with no
        // smuggled token.
        assert!(!script_has_txn_control_in(
            "SELECT 1 /*!*/",
            GuardDialect::Mysql
        ));
        assert!(!script_has_txn_control_in(
            "SELECT 1 /*!40000 */",
            GuardDialect::Mysql
        ));
        // Ordinary + line comments collapse to a single separator space (so adjacent tokens stay
        // separate — `create/**/extension` remains two words).
        assert_eq!(mysql_strip_comments_faithfully("a/* c */b").unwrap(), "a b");
        assert_eq!(
            mysql_strip_comments_faithfully("SELECT 1 -- x\nSELECT 2").unwrap(),
            "SELECT 1  \nSELECT 2"
        );
    }

    /// Security review CRITICAL-1 **re-review** (task #489): two more evasions the first fix
    /// (`2bee40f`) missed, both verified live (guard PASS + a real statement executed via
    /// `sqlx::raw_sql`). Each MUST now be REFUSED by every guard under the MySQL dialect. These are
    /// the mutation gate — reverting the faithful strip re-opens them.
    #[test]
    fn mysql_comment_confusion_bypasses_are_refused() {
        use super::{
            script_has_create_extension_in, script_has_txn_control_in, script_references_word_in,
            GuardDialect,
        };
        // (1) A `/*!` INSIDE an ordinary `/* … */` comment must NOT let the ordinary comment's `*/`
        //     be consumed and the following live keyword swallowed.
        for s in [
            "/* /*! */ COMMIT -- */",
            "/* /*! */ COMMIT /* x */",
            "CREATE TABLE ok(a int); /* /*! */ COMMIT /* */",
        ] {
            assert!(
                script_has_txn_control_in(s, GuardDialect::Mysql),
                "must refuse comment-nested /*! txn evasion: {s:?}"
            );
        }
        assert!(script_references_word_in(
            "/* /*! */ DELETE FROM boatramp_migrations -- */",
            "boatramp_migrations",
            GuardDialect::Mysql,
        ));
        assert!(script_has_create_extension_in(
            "/* /*! */ CREATE EXTENSION evil -- */",
            GuardDialect::Mysql,
        ));
        // (2) sqlparser NESTS `/* */` but MySQL does not — a nested-looking comment must not hide a
        //     live keyword. No `/*!` needed.
        for s in [
            "/* a /* b */ COMMIT -- */",
            "/* /* */ COMMIT -- */",
            "SELECT 1; /* x /* y */ COMMIT -- */",
        ] {
            assert!(
                script_has_txn_control_in(s, GuardDialect::Mysql),
                "must refuse nested-comment txn evasion: {s:?}"
            );
        }
        assert!(script_references_word_in(
            "/* a /* b */ INSERT INTO boatramp_migrations VALUES(1) -- */",
            "boatramp_migrations",
            GuardDialect::Mysql,
        ));
        // (3) An executable comment whose body contains an inner `/* */` (or is empty) does NOT
        //     close at the first `*/`: the server lexes the body as normal SQL and closes at the
        //     top-level `*/`, EXECUTING the keyword after the inner comment. Verified live (a real
        //     CREATE TABLE ran). Must be flagged.
        for s in [
            "/*! /* */ COMMIT */",
            "/*!/**/COMMIT*/",
            "/*! /* nested */ DROP */ COMMIT */",
        ] {
            assert!(
                script_has_txn_control_in(s, GuardDialect::Mysql),
                "must refuse exec-comment body with inner comment: {s:?}"
            );
        }
        // (4) MariaDB executable comment `/*M! … */` is also EXECUTED by the server — un-hide it.
        assert!(script_has_txn_control_in(
            "/*M! COMMIT */",
            GuardDialect::Mysql
        ));
        assert!(script_has_txn_control_in(
            "/*M!100000 ROLLBACK */",
            GuardDialect::Mysql
        ));
        // Negative: a keyword genuinely inside a string is NOT flagged (no false positive), matching
        // the server (adjacent-string splicing keeps it a literal).
        assert!(!script_has_txn_control_in(
            "INSERT INTO t(note) VALUES('/*! COMMIT */')",
            GuardDialect::Mysql
        ));
    }
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

    /// **Relocate** the database `from_name` of `site` within tenant `project` to
    /// `to_name` (same project + site), data intact — a destructive, operator-grade
    /// maintenance op backing `boatramp sql move`. The general use is giving a
    /// libsql binding a real name (e.g. moving the default `""`/`"default"` database
    /// to `"analytics"`), but it is **not** special-cased to the default.
    ///
    /// The default implementation refuses: a backend that has no relocatable notion
    /// (an external/shared or managed database is a single fixed endpoint — its data
    /// does not move by renaming a binding) returns [`SqlError::Other`]. Only the
    /// single-node libsql backend implements a real, data-preserving move.
    async fn move_database(
        &self,
        _project: &str,
        _site: &str,
        _from_name: &str,
        _to_name: &str,
    ) -> Result<MoveDatabaseReport, SqlError> {
        Err(SqlError::Other(
            "database move is not supported for this backend (only a single-node libsql \
             database can be relocated; an external or managed binding is a fixed endpoint)"
                .to_string(),
        ))
    }
}

/// The outcome of a [`SqlBackends::move_database`] relocation — the resolved
/// `(project, site)` the relocation ran against plus the source/destination
/// locators and the verified integrity signal, for the operator's JSON report.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MoveDatabaseReport {
    /// The project the relocation ran against (echoed so the operator can confirm
    /// which tenant's database was moved, not just the filesystem paths).
    pub project: String,
    /// The site the relocation ran against — for the default binding this is the
    /// site whose default was relocated.
    pub site: String,
    /// The resolved source locator (a filesystem path in single-node mode).
    pub from: String,
    /// The resolved destination locator.
    pub to: String,
    /// The `PRAGMA integrity_check` result on the destination (`"ok"` on success).
    pub integrity: String,
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

    /// Probe every replica of managed database `db`'s compute workload — an **active**
    /// TCP reachability check, independent of the stored health flag. Lets an operator
    /// tell "the DB is actually down" (`tcp_reachable: false`) from "the DB is up but
    /// the endpoint resolver won't serve it" (`tcp_reachable: true, healthy: false` —
    /// the reachable-but-not-served signature). Never runs a query or presents a
    /// credential; it only opens (and immediately drops) a TCP connection.
    async fn ping(&self, project: &str, db: &str) -> Result<Vec<SqlPingReplica>, SqlError>;
}

/// One replica's reachability, returned by [`OperatorSql::ping`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlPingReplica {
    /// The replica's endpoint (`host:port`).
    pub endpoint: String,
    /// The stored health flag (what the endpoint resolver gates serving on).
    pub healthy: bool,
    /// The replica's lifecycle phase (`running` / `zero`).
    pub phase: String,
    /// Whether a TCP connection to the endpoint succeeded just now.
    pub tcp_reachable: bool,
}

/// One ordered step in a schema migration set. A step has a stable, author-given `id`
/// (recorded in the ledger and NEVER re-ordered or renumbered — the ledger enforces
/// prefix-consistency against the recorded order) and an [`action`](MigrationAction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationStep {
    /// Stable migration identity, e.g. `"0001_init"`. Unique within a set.
    pub id: String,
    /// What the step does.
    pub action: MigrationAction,
}

/// What a [`MigrationStep`] applies. Deliberately NOT arbitrary SQL-anytime: a `Sql`
/// step is refused if it contains `CREATE EXTENSION`, so the ONLY way to enable an
/// extension is an [`Extension`](MigrationAction::Extension) step — which is
/// allowlist-gated and host-templated. (Hook steps — a normal wasm invocation for
/// data verification / backfills — are a planned follow-up workstation, not this set.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationAction {
    /// A DDL/DML script applied as the project **owner** role (a non-superuser role
    /// confined to the project's own database). Rejected fail-closed if it contains
    /// `CREATE EXTENSION`. `no_transaction` applies it OUTSIDE a wrapping transaction —
    /// for the DDL Postgres forbids inside one (`CREATE INDEX CONCURRENTLY`,
    /// `CREATE DATABASE`, `ALTER TYPE … ADD VALUE`, `VACUUM`); the ledger row is then
    /// recorded in a following statement, so the author owns that step's idempotency.
    Sql {
        /// The migration SQL (one or more statements).
        script: String,
        /// Apply outside a wrapping transaction (for non-transactional DDL).
        no_transaction: bool,
    },
    /// Enable a Postgres extension by name — validated against the operator's
    /// trusted-extension allowlist and run through a host-templated
    /// `CREATE EXTENSION IF NOT EXISTS "<name>"` (no guest SQL, no injection). The only
    /// admitted extension path; a name not on the allowlist is refused fail-closed.
    Extension {
        /// The extension name (allowlist-checked; quoted as an identifier when emitted).
        name: String,
    },
    /// **The base step:** invoke a project **function** that does arbitrary migration work — data
    /// verification, external-source sync, DML, and DDL (the latter via the host-mediated owner-role
    /// `migrate-ddl` capability, granted ONLY for a migration-step invocation). The orchestrator runs
    /// it on the async lane, quota-exempt, under a host-set migration context; the function's own
    /// DDL is no more powerful than a `Sql` step (both = the confined owner role). At-least-once +
    /// author-idempotent (a crash mid-function leaves the step unrecorded → it re-runs whole; the
    /// author owns within-step idempotency). Its ledger row is written by the orchestrator only after
    /// the invocation returns delivered-success.
    Function {
        /// The project function to invoke (resolved strictly within the caller's own project).
        name: String,
        /// The pinned deploy version to run for a deterministic re-apply; `None` ⇒ the orchestrator
        /// pins the active version's component blob hash at apply time and records it, so replay runs
        /// identical bytes. Never `function.active` re-resolved on each apply.
        version: Option<String>,
        /// Canonical (stable-serialized) invocation arguments, folded into the content hash so a
        /// changed arg set under a used id is caught.
        args: Option<String>,
    },
}

impl MigrationStep {
    /// The ledger `kind` tag for this step.
    pub fn kind(&self) -> &'static str {
        match self.action {
            MigrationAction::Sql { .. } => "sql",
            MigrationAction::Extension { .. } => "extension",
            MigrationAction::Function { .. } => "function",
        }
    }

    /// A stable **intrinsic** content hash over the step's identity + kind + body — recorded in the
    /// ledger so re-submitting an already-applied `id` with a CHANGED body is detected and refused
    /// (tamper/drift evidence), and so re-ordering is caught. For a `Function` step this covers
    /// name + version + canonical args; the orchestrator additionally binds the RESOLVED component
    /// blob hash via [`effective_hash`](Self::effective_hash) so a redeploy under the same version
    /// tag is caught (a `Function`'s body is a reference, not self-contained text).
    pub fn content_hash(&self) -> String {
        let body = match &self.action {
            MigrationAction::Sql {
                script,
                no_transaction,
            } => format!("sql:{no_transaction}:{script}"),
            MigrationAction::Extension { name } => format!("extension:{name}"),
            MigrationAction::Function {
                name,
                version,
                args,
            } => format!(
                "function:{name}:{}:{}",
                version.as_deref().unwrap_or("active"),
                args.as_deref().unwrap_or_default()
            ),
        };
        crate::deploy::sha256_hex(format!("{}\n{body}", self.id).as_bytes())
    }

    /// The hash the ledger records + prefix-consistency compares. For `Sql`/`Extension` it is the
    /// intrinsic [`content_hash`](Self::content_hash). For a `Function` step the orchestrator passes
    /// the RESOLVED component blob hash (content-addressed wasm bytes it pinned), and this binds it in
    /// — so re-apply provably runs identical bytes and a redeploy-under-same-version-tag is refused
    /// (Backend BR-6 / Security immutability). `resolved_blob` is `None` for non-function steps.
    pub fn effective_hash(&self, resolved_blob: Option<&str>) -> String {
        match resolved_blob {
            Some(blob) => {
                crate::deploy::sha256_hex(format!("{}\n{blob}", self.content_hash()).as_bytes())
            }
            None => self.content_hash(),
        }
    }
}

/// One applied migration as recorded in the `schema_migrations` ledger.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppliedMigration {
    /// The migration id.
    pub id: String,
    /// Its application order (0-based).
    pub ordinal: i64,
    /// The **effective** hash recorded at apply time (for a `function` step this binds the resolved
    /// component blob; for `sql`/`extension` it equals the intrinsic content hash).
    pub content_hash: String,
    /// The ledger `kind` (`sql` / `extension` / `function`).
    pub kind: String,
    /// When it was applied (RFC3339, best-effort formatting from the engine).
    pub applied_at: String,
    /// How the row entered the ledger — `"apply"` (the step ran here) or `"baseline"` (an owner
    /// assertion that it was already applied; the step was NOT run here). U6 origin marker; older
    /// rows without the column read back as `"apply"`.
    #[serde(default = "default_origin")]
    pub origin: String,
}

/// The default ledger origin for a row (and for pre-U6 rows lacking the column): the step ran here.
fn default_origin() -> String {
    LedgerOrigin::Apply.as_str().to_string()
}

/// How a ledger row came to be — an executed step, or an owner *assertion* (baseline) that recorded
/// it as already-applied without running it. Persisted in the ledger's `applied_by` column so an
/// operator can later tell a baselined prefix (never run on this DB) from a genuinely applied one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerOrigin {
    /// The step was executed on this database and then recorded.
    Apply,
    /// The step was recorded as already-applied WITHOUT running it (the `baseline` verb).
    Baseline,
}

impl LedgerOrigin {
    /// The stable string persisted in the ledger.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Baseline => "baseline",
        }
    }
}

/// The outcome of a migration apply / dry-run / baseline (the server orchestrator over
/// [`MigrationSubstrate`]).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MigrationReport {
    /// Ids applied by THIS call, in order.
    pub newly_applied: Vec<String>,
    /// Ids skipped because they were already recorded (idempotent no-op).
    pub already_applied: Vec<String>,
    /// Ids that WOULD apply (populated only for a dry run; empty on a real apply).
    pub pending: Vec<String>,
    /// The step that failed (application halts there; the prefix before it is applied).
    pub failed: Option<MigrationFailure>,
    /// Per-reported-id `kind` (`sql` / `extension` / `function`), so a thin client can tell what
    /// each id in `newly_applied` / `already_applied` / `pending` / `failed` was without re-parsing
    /// the bundle (U3). Covers every id the report mentions.
    #[serde(default)]
    pub kinds: std::collections::BTreeMap<String, String>,
}

/// A failed migration step, surfaced structurally so a thin client can show which one
/// failed and why without server-log access.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MigrationFailure {
    /// The failing step's id.
    pub id: String,
    /// The (sanitized) failure reason.
    pub error: String,
}

/// The applied-migration state of a database's ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MigrationStatus {
    /// Every applied migration, in application order.
    pub applied: Vec<AppliedMigration>,
}

/// A failure from a migration apply/dry-run/baseline.
#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    /// The managed backend is still starting (transient — retry / `503`), mirrors
    /// [`SqlError::Unavailable`].
    #[error("migration backend not ready: {0}")]
    Unavailable(String),
    /// The requested set diverges from the recorded application order (a reordered or
    /// gapped prefix) — refused fail-closed rather than silently applying out of order.
    #[error("migration order diverged from the recorded ledger: {0}")]
    PrefixDivergence(String),
    /// An already-applied `id` was re-submitted with a different body.
    #[error("migration {0} was modified after it was applied (content-hash mismatch)")]
    ContentChanged(String),
    /// An `Extension` step named an extension not on the operator allowlist.
    #[error("extension {0:?} is not on the operator trusted-extension allowlist")]
    ExtensionNotAllowed(String),
    /// A raw `Sql` step contained `CREATE EXTENSION` (use an `Extension` step instead).
    #[error(
        "a sql migration step may not CREATE EXTENSION — use an extension step (allowlist-gated)"
    )]
    RawCreateExtension,
    /// No managed SQL is configured on this node (mirrors the `501` of the sql-exec API).
    #[error("managed sql is not configured on this node")]
    NotConfigured,
    /// A backend/transport error during application.
    #[error(transparent)]
    Sql(#[from] SqlError),
    /// Anything else.
    #[error("{0}")]
    Other(String),
}

/// Why a host-mediated owner-role DDL call ([`MigrateDdl`]) was refused or failed. The guest sees
/// a self-explaining variant (never a bare access-denied), so a migration author can tell a
/// protected-schema attempt from its own bad DDL.
#[derive(Debug, thiserror::Error)]
pub enum MigrateDdlError {
    /// The statement referenced the host-owned migration-ledger schema (`boatramp_migrations`). The
    /// owner role owns that schema, so an unguarded `exec` could corrupt prefix-consistency — refused
    /// host-side (S3).
    #[error("migrate: the migration-ledger schema is host-owned and may not be touched by a migration step")]
    LedgerProtected,
    /// The statement issued its own transaction control (`BEGIN`/`COMMIT`/`ROLLBACK`). Each `exec`
    /// auto-commits on the host-held owner connection; a guest-managed transaction would desync the
    /// host's per-step ledger contract — refused (S4).
    #[error("migrate: a migration step may not issue its own BEGIN/COMMIT/ROLLBACK — each exec auto-commits")]
    TxnControl,
    /// The underlying owner-connection SQL error (sanitized).
    #[error("migrate: {0}")]
    Sql(String),
}

/// The **host-mediated owner-role DDL seam** backing the guest `boatramp:handlers/migrate-ddl`
/// capability (Security S5). Implemented by the node over the migration orchestrator's **owner-role**
/// connection for one `(project, db)`; the guest never holds the credential — it calls the host
/// functions and the host runs each statement on the owner connection it owns (v0.4.25 BR-7). The
/// binding is attached **only** for a `Project·Admin` migration-step invocation (context-gated, S2);
/// a normal request/consumer/cron invocation has no binding (`access-denied`). The implementation
/// enforces the ledger-schema (S3) and transaction-control (S4) guards before touching the wire; each
/// `exec` auto-commits.
#[async_trait]
pub trait MigrateDdl: Send + Sync {
    /// Run a DDL/DML `script` (one or more statements) as the owner role; auto-commits on success.
    async fn exec(&self, script: &str) -> Result<(), MigrateDdlError>;
    /// Run several scripts in order, each auto-committing (a convenience over repeated `exec`).
    async fn exec_batch(&self, scripts: Vec<String>) -> Result<(), MigrateDdlError>;
    /// Run a read `query` as the owner role and return the rows (for in-migration verification —
    /// the owner sees all rows, which is correct for a schema/data migration check).
    async fn query(&self, sql: &str) -> Result<SqlRows, MigrateDdlError>;
}

/// The outcome of running one substrate (`sql`/`extension`) step via [`MigrationSubstrate`].
#[derive(Debug)]
pub enum SubstrateStepOutcome {
    /// The step ran and its ledger row was recorded.
    Applied,
    /// The step failed (sanitized reason) — apply halts, the prior prefix stands.
    Failed(String),
}

/// The node-side **substrate** the server-side migration orchestrator (A1) drives: the DDL-identity
/// connection, the host-owned `schema_migrations` ledger, and the direct `sql`/`extension` execution
/// path. The orchestrator owns ordering, prefix-consistency, `function`-step invocation (which needs
/// the server's invoke kernel and cannot live here), and dry-run planning; this seam owns the
/// database IO. The DDL identity is always **distinct from the runtime tenant user** — on Postgres
/// the per-project non-superuser **owner role** (never the cluster superuser); on MySQL an
/// operator-supplied DDL login distinct from the runtime user (refused fail-closed if absent, since
/// MySQL has no owner/runtime role split). The allowlist-gated host-templated `CREATE EXTENSION` is
/// Postgres-only (refused on MySQL). Backend-honest per engine: Postgres DDL is transactional
/// (atomic per step), MySQL DDL implicitly commits (per-step, non-atomic — a mid-step failure is
/// reported as partially applied).
#[async_trait]
pub trait MigrationSubstrate: Send + Sync {
    /// Engine gate (Postgres + MySQL; the embedded libsql backend is a later parity phase), ensure
    /// the ledger schema/database + table exist, and return the applied rows in order. `Unavailable`
    /// (managed DB still starting) maps to a retryable 503.
    async fn preflight(
        &self,
        project: &str,
        db: &str,
    ) -> Result<Vec<AppliedMigration>, MigrationError>;

    /// Execute a `sql` or `extension` `step` as the owner role and record its ledger row (atomically
    /// for a transactional `sql` step). `ordinal` is its 0-based position; `effective_hash` is the
    /// hash the orchestrator computed (== the intrinsic content hash for these kinds). A `function`
    /// step must NOT be passed here — the orchestrator invokes it and calls [`record`](Self::record).
    async fn apply_substrate_step(
        &self,
        project: &str,
        db: &str,
        step: &MigrationStep,
        ordinal: usize,
        effective_hash: &str,
    ) -> Result<SubstrateStepOutcome, MigrationError>;

    /// Record a ledger row WITHOUT running the step — for a `function` step after a successful
    /// invocation (the orchestrator ran it via the invoke kernel), and for every step of a
    /// `baseline`. `origin` distinguishes the two (U6).
    async fn record(
        &self,
        project: &str,
        db: &str,
        step: &MigrationStep,
        ordinal: usize,
        effective_hash: &str,
        origin: LedgerOrigin,
    ) -> Result<(), MigrationError>;

    /// The owner-role DDL seam for `(project, db)` backing the `migrate-ddl` capability of a
    /// `function` step (S5). Returned as an `Arc<dyn MigrateDdl>` the orchestrator hands to the
    /// function invocation's binding; the owner credential never leaves this seam.
    async fn owner_ddl(
        &self,
        project: &str,
        db: &str,
    ) -> Result<std::sync::Arc<dyn MigrateDdl>, MigrationError>;
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
        check(sql, &[]).is_err()
    }

    /// Rejected when the operator's RLS GUC namespace (`app`) is reserved.
    fn rejected_with_app(sql: &str) -> bool {
        check(sql, &["app".to_string()]).is_err()
    }

    #[test]
    fn operator_rls_guc_is_rejected_only_when_its_namespace_is_reserved() {
        // With `app` reserved (a configured `app.tenant_id` RLS GUC), a guest cannot forge it
        // via any form — direct SET, set_config, or a RESET of the namespace.
        assert!(rejected_with_app("SET app.tenant_id = 'victim'"));
        assert!(rejected_with_app("set local app.tenant_id = 'victim'"));
        assert!(rejected_with_app(
            "SELECT set_config('app.tenant_id','victim',false)"
        ));
        assert!(rejected_with_app("RESET app.tenant_id"));
        // Without the reservation, an ordinary `app.*` set is NOT the guard's business (only
        // boatramp's own namespace is always reserved).
        assert!(!rejected("SET app.tenant_id = 'x'"));
        assert!(!rejected("SELECT set_config('app.tenant_id','x',true)"));
        // The always-reserved boatramp namespace is still blocked regardless of extras.
        assert!(rejected_with_app("SET boatramp.project = 'x'"));
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

    /// Round-2 High: MySQL writes the reserved `@boatramp_*` user var without it being
    /// the first `SET` target — via a comma-list, a `:=` variant, or
    /// `SELECT … INTO @var` (no `SET` at all) — evading the leading-target check. A
    /// position-independent reserved-var refusal closes the whole family.
    #[test]
    fn mysql_reserved_var_anywhere_is_rejected() {
        assert!(rejected("SET @x=1, @boatramp_project='victim'"));
        assert!(rejected("SET @a=1, @b=2, @boatramp_project='victim'"));
        assert!(rejected("SET @x:=1, @boatramp_project:='victim'"));
        assert!(rejected("SELECT 'victim' INTO @boatramp_project"));
        assert!(rejected("SELECT 'victim' AS v INTO @boatramp_project"));
        assert!(rejected("SELECT 1,'victim' INTO @junk, @boatramp_project"));
        assert!(rejected("select 'victim' into @boatramp_project"));
        assert!(rejected("SELECT 'v' INTO @boatramp_site"));
    }

    /// Prepared-statement indirection hides the reserved write inside a string literal
    /// (which is legitimate data elsewhere, so must not be scanned): refuse the
    /// deferral construct itself. The guest binding never issues SQL-level
    /// PREPARE/EXECUTE (it parameterizes via bind params), so this costs nothing.
    #[test]
    fn prepared_statement_indirection_is_rejected() {
        assert!(rejected(
            "PREPARE s FROM 'SET @boatramp_project=''victim'''"
        ));
        assert!(rejected("EXECUTE s"));
        assert!(rejected(
            "prepare s from 'SELECT ''v'' INTO @boatramp_site'"
        ));
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
        // Non-reserved MySQL user vars (comma-list and `SELECT … INTO`) are untouched —
        // only the `@boatramp_*` namespace is refused.
        assert!(!rejected("SET @x = 1, @y = 2"));
        assert!(!rejected("SELECT 42 INTO @myvar"));
        assert!(!rejected("SELECT total INTO @t FROM orders WHERE id = $1"));
    }
}
