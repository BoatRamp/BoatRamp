//! A typed DDL (schema-change) AST and an injection-safe SQL emitter — the schema-creation
//! counterpart to the pure [`crate::orm`] query compiler.
//!
//! The emitter turns a typed [`Ddl`] operation (create-table / add-column / create-index /
//! create-type, plus destructive drop/alter/rename behind an explicit acknowledgement) into a
//! validated SQL script. It is **pure** (no I/O, no wasm/wit deps, no credential) so it is fully
//! unit-testable, exactly like [`orm`](crate::orm). The emitted string is handed to the
//! already-gated **owner-role** migration seam (`project migrate` → `Project·Admin`,
//! `MigrationAction::Sql`), so the builder grants **zero new runtime authority** — it is pure
//! codegen that makes migration DDL typed and identifier-safe. The runtime `orm`/`sql` plane
//! (a different, `NOBYPASSRLS`, non-owner role) still cannot DDL at all.
//!
//! # Safety invariants (mirroring the `orm` compiler)
//! - **Identifiers are validated** by the one shared rule ([`crate::orm::plain_ident_ok`],
//!   `[A-Za-z_][A-Za-z0-9_]*`) and emitted unquoted. The DDL builder additionally **rejects any
//!   dot**, so it can never emit a schema-qualified name — single-schema confinement for free.
//! - **The host-owned migration ledger is off-limits.** An object named for the reserved
//!   `boatramp_migrations` schema / `schema_migrations` ledger is refused ([`DdlError::ReservedName`]);
//!   the node seam's `ledger-protected` guard fires regardless, this is defense-in-depth.
//! - **Defaults are a closed enum** ([`ScalarDefault`] = literal / `now()` / `null` /
//!   `gen_random_uuid()`), never a free-SQL string. A text literal is inlined with the same escaping
//!   the RLS-GUC path uses ([`crate::sql::pg_quote_literal`]), so a default can't inject.
//! - **No `CREATE EXTENSION`.** There is no operation that emits it; enabling an extension stays the
//!   operator-allowlisted `Extension` migration step. The builder assumes `pgvector` present.
//! - **Destructive ops require an explicit `destructive: true` acknowledgement.** This is a DX guard
//!   against accidental data loss, NOT a new authority boundary — a raw `Sql` migration step can
//!   already `DROP` at the same owner altitude in the same `Project·Admin` context.
//!
//! # Dialect coverage (Postgres-first)
//! The portable scalar column subset renders on Postgres / SQLite / MySQL. The richer Postgres
//! surface — `vector(N)` / `uuid` / `jsonb` / `serial` column types, the tenant-scoped RLS table
//! variant, `CREATE INDEX … USING <method>` (incl. hnsw/ivfflat opclasses), `DROP INDEX`, and
//! `CREATE TYPE … AS ENUM` — is **Postgres-only** and fails closed elsewhere
//! ([`DdlError::NotPostgres`]); there is no correct portable fallback.

use crate::orm::{Metric, plain_ident_ok};
use crate::sql::{Dialect, SqlValue, pg_quote_literal};

/// The reserved host-owned migration-ledger schema (Postgres) / database (MySQL). An object named
/// for it — or any name under its reserved namespace — is refused by the builder. Kept in lockstep
/// with the node seam's `LEDGER_SCHEMA` guard (`boatramp-node::managed_sql`).
const LEDGER_SCHEMA: &str = "boatramp_migrations";
/// The reserved migration-ledger table name.
const LEDGER_TABLE: &str = "schema_migrations";

/// An error from building/emitting DDL. Every variant is a fail-closed refusal — the emitter never
/// produces SQL it could not fully validate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DdlError {
    /// An identifier was not a plain `[A-Za-z_][A-Za-z0-9_]*` name (a dot — a schema-qualified name —
    /// is always rejected).
    #[error("invalid identifier: {0:?}")]
    InvalidIdentifier(String),
    /// An object was named for the host-owned migration ledger (`boatramp_migrations` /
    /// `schema_migrations`). Refused fail-closed (the node `ledger-protected` guard also fires).
    #[error("reserved host-owned name refused: {0:?}")]
    ReservedName(String),
    /// A Postgres-only construct (`vector`/`uuid`/`jsonb`/`serial` type, tenant-scoped RLS,
    /// `CREATE INDEX`/`DROP INDEX`, `CREATE TYPE … ENUM`) was emitted for a non-Postgres dialect.
    #[error("{0} is Postgres-only (fails closed on this dialect)")]
    NotPostgres(&'static str),
    /// A structurally empty operation (a table/index with no columns, an enum with no labels, …).
    #[error("empty: {0}")]
    Empty(&'static str),
    /// A destructive operation (`DROP`/`ALTER COLUMN TYPE`/rename) was emitted without an explicit
    /// `destructive: true` acknowledgement.
    #[error("destructive operation requires an explicit `destructive: true` acknowledgement: {0}")]
    DestructiveNotAcknowledged(&'static str),
    /// A `DEFAULT` was not an admissible closed scalar (a `NULL`/`BLOB`/`JSON` literal, or a
    /// non-finite number). The closed [`ScalarDefault`] enum is the no-injection property.
    #[error("bad default: {0}")]
    BadDefault(&'static str),
    /// A `vector(N)` dimension or a `varchar(N)` length was zero (no valid SQL form).
    #[error("bad column: {0}")]
    BadColumn(&'static str),
    /// A metric↔index-method coupling was violated — a vector index method (`hnsw`/`ivfflat`) whose
    /// column carries no [`Metric`], or a non-vector method whose column carries one. The metric
    /// picks the operator class, so it is required for exactly the vector methods.
    #[error("metric/opclass coupling: {0}")]
    MetricCoupling(&'static str),
    /// A tenant-scoped `CreateTable` named a tenant column that is not one of the table's columns.
    #[error("tenant-scoped table: tenant column {0:?} is not one of the table's columns")]
    UnknownTenantColumn(String),
    /// A tenant-GUC name was not a dotted sequence of plain identifier segments (e.g. `app.tenant_id`).
    #[error("invalid session-GUC name: {0:?}")]
    InvalidGuc(String),
}

// ---- identifier / name validation -----------------------------------------

/// Validate a plain column/attribute identifier (no dot, no schema qualification).
fn ident(name: &str) -> Result<&str, DdlError> {
    if plain_ident_ok(name) {
        Ok(name)
    } else {
        Err(DdlError::InvalidIdentifier(name.to_string()))
    }
}

/// Whether `name` is in the reserved host-owned migration-ledger namespace (case-insensitive).
fn is_reserved_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == LEDGER_TABLE || lower.starts_with(LEDGER_SCHEMA)
}

/// Validate a top-level object name (table / index / type / policy) — a plain identifier that is
/// also not in the reserved host-owned namespace.
fn object_ident(name: &str) -> Result<&str, DdlError> {
    let name = ident(name)?;
    if is_reserved_name(name) {
        return Err(DdlError::ReservedName(name.to_string()));
    }
    Ok(name)
}

/// Quote a string **value** as a SQL literal for safe inlining (a `DEFAULT`, an enum label).
/// Dialect-aware, because the engines disagree on whether a backslash is an escape character inside
/// a `'…'` string:
/// - **Postgres** — the backslash-safe `E'…'` form ([`pg_quote_literal`]), robust under either
///   `standard_conforming_strings` setting.
/// - **MySQL** — its default `sql_mode` (no `NO_BACKSLASH_ESCAPES`) treats `\` as an escape, so a
///   value ending in `\` could consume the closing quote; escape `\`→`\\` **and** double the quote.
/// - **SQLite** — `\` is NOT special, so ONLY the quote is doubled (escaping `\` would corrupt the
///   stored value by turning it into a literal double backslash).
fn quote_str(dialect: Dialect, s: &str) -> String {
    match dialect {
        Dialect::Postgres => pg_quote_literal(s),
        Dialect::Mysql => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "''")),
        Dialect::Sqlite => format!("'{}'", s.replace('\'', "''")),
    }
}

// ---- column types ----------------------------------------------------------

/// A column type. The portable scalar subset renders on every dialect; the Postgres-specific types
/// (`Serial`/`BigSerial`/`Uuid`/`Json`/`Jsonb`/`Enum`/`Vector`) fail closed elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ColumnType {
    SmallInt,
    Integer,
    BigInt,
    /// Postgres auto-incrementing 4-byte identity (`serial`).
    Serial,
    /// Postgres auto-incrementing 8-byte identity (`bigserial`).
    BigSerial,
    Real,
    Double,
    /// Fixed-point `numeric(precision, scale)`.
    Numeric {
        precision: u32,
        scale: u32,
    },
    Boolean,
    Text,
    /// `varchar(len)` — `len` must be non-zero.
    Varchar {
        len: u32,
    },
    /// A byte string (`bytea` on Postgres, `blob` elsewhere).
    Bytea,
    /// Postgres `uuid`.
    Uuid,
    Date,
    Time,
    /// `timestamp`; `tz` ⇒ Postgres `timestamptz` (the `tz` form is Postgres-only).
    Timestamp {
        tz: bool,
    },
    /// Postgres text `json`.
    Json,
    /// Postgres binary `jsonb` (the portable [`SqlValue::Json`] document type).
    Jsonb,
    /// A reference to a user-defined `CREATE TYPE … AS ENUM` type, by its (validated) name.
    Enum(String),
    /// A pgvector `vector(dim)` column — Postgres-only; `dim` must be non-zero.
    Vector {
        dim: u32,
    },
}

impl ColumnType {
    /// Render the type keyword for `dialect`, failing closed for a Postgres-only type on a
    /// non-Postgres dialect.
    fn render(&self, dialect: Dialect) -> Result<String, DdlError> {
        let pg = dialect == Dialect::Postgres;
        Ok(match self {
            Self::SmallInt => "smallint".into(),
            Self::Integer => "integer".into(),
            Self::BigInt => "bigint".into(),
            Self::Serial if pg => "serial".into(),
            Self::BigSerial if pg => "bigserial".into(),
            Self::Serial | Self::BigSerial => {
                return Err(DdlError::NotPostgres("a serial column type"));
            }
            Self::Real => "real".into(),
            Self::Double => "double precision".into(),
            Self::Numeric { precision, scale } => format!("numeric({precision},{scale})"),
            Self::Boolean => "boolean".into(),
            Self::Text => "text".into(),
            Self::Varchar { len } => {
                if *len == 0 {
                    return Err(DdlError::BadColumn("varchar length must be non-zero"));
                }
                format!("varchar({len})")
            }
            Self::Bytea if pg => "bytea".into(),
            Self::Bytea => "blob".into(),
            Self::Uuid if pg => "uuid".into(),
            Self::Uuid => return Err(DdlError::NotPostgres("the uuid type")),
            Self::Date => "date".into(),
            Self::Time => "time".into(),
            Self::Timestamp { tz: true } if pg => "timestamptz".into(),
            Self::Timestamp { tz: true } => {
                return Err(DdlError::NotPostgres("a timestamptz column type"));
            }
            Self::Timestamp { tz: false } => "timestamp".into(),
            Self::Json if pg => "json".into(),
            Self::Json => return Err(DdlError::NotPostgres("the json type")),
            Self::Jsonb if pg => "jsonb".into(),
            Self::Jsonb => return Err(DdlError::NotPostgres("the jsonb type")),
            Self::Enum(name) if pg => object_ident(name)?.to_string(),
            Self::Enum(_) => return Err(DdlError::NotPostgres("an enum column type")),
            Self::Vector { dim } if pg => {
                if *dim == 0 {
                    return Err(DdlError::BadColumn("vector dimension must be non-zero"));
                }
                format!("vector({dim})")
            }
            Self::Vector { .. } => return Err(DdlError::NotPostgres("the vector type")),
        })
    }
}

// ---- defaults (closed enum — no free SQL) ----------------------------------

/// A column `DEFAULT`, as a **closed enum** — never a free-SQL string, so a default can't inject
/// (the ORM's no-injection property, carried to DDL).
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum ScalarDefault {
    /// A typed scalar literal, inlined with strict per-type escaping. Only `Boolean`/`Integer`/
    /// `Real`/`Text` are admissible; a `Null`/`Blob`/`Json` literal (or a non-finite number) is
    /// refused ([`DdlError::BadDefault`]) — use [`ScalarDefault::Null`] for a null default.
    Literal(SqlValue),
    /// `now()` (Postgres) / `CURRENT_TIMESTAMP` (portable).
    Now,
    /// `NULL`.
    Null,
    /// `gen_random_uuid()` — Postgres-only (pgcrypto / built-in since pg13).
    GenRandomUuid,
}

impl ScalarDefault {
    fn render(&self, dialect: Dialect) -> Result<String, DdlError> {
        Ok(match self {
            Self::Null => "NULL".into(),
            Self::Now if dialect == Dialect::Postgres => "now()".into(),
            Self::Now => "CURRENT_TIMESTAMP".into(),
            Self::GenRandomUuid if dialect == Dialect::Postgres => "gen_random_uuid()".into(),
            Self::GenRandomUuid => return Err(DdlError::NotPostgres("gen_random_uuid()")),
            Self::Literal(v) => match v {
                SqlValue::Boolean(b) => if *b { "true" } else { "false" }.into(),
                SqlValue::Integer(i) => i.to_string(),
                SqlValue::Real(f) => {
                    if !f.is_finite() {
                        return Err(DdlError::BadDefault("a non-finite number"));
                    }
                    f.to_string()
                }
                SqlValue::Text(s) => quote_str(dialect, s),
                SqlValue::Null => {
                    return Err(DdlError::BadDefault(
                        "use ScalarDefault::Null for a null default",
                    ));
                }
                SqlValue::Blob(_) | SqlValue::Json(_) => {
                    return Err(DdlError::BadDefault(
                        "a blob/json literal is not an admissible closed default",
                    ));
                }
            },
        })
    }
}

// ---- columns + constraints -------------------------------------------------

/// A column definition: name, type, nullability, and an optional closed default.
#[derive(Debug, Clone, PartialEq)]
pub struct ColumnDef {
    /// The column name (validated plain identifier).
    pub name: String,
    /// The column type.
    pub ty: ColumnType,
    /// Whether the column admits `NULL` (`false` ⇒ `NOT NULL`).
    pub nullable: bool,
    /// An optional closed default.
    pub default: Option<ScalarDefault>,
}

impl ColumnDef {
    /// Convenience: a `NOT NULL`, no-default column.
    pub fn new(name: impl Into<String>, ty: ColumnType) -> Self {
        Self {
            name: name.into(),
            ty,
            nullable: false,
            default: None,
        }
    }

    fn render(&self, dialect: Dialect) -> Result<String, DdlError> {
        let name = ident(&self.name)?;
        let ty = self.ty.render(dialect)?;
        let mut s = format!("{name} {ty}");
        if !self.nullable {
            s.push_str(" NOT NULL");
        }
        if let Some(d) = &self.default {
            s.push_str(&format!(" DEFAULT {}", d.render(dialect)?));
        }
        Ok(s)
    }
}

/// A table-level constraint. Deliberately NOT free-form `CHECK` (deferred to raw SQL) — only the
/// structural, identifier-safe keyed constraints.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TableConstraint {
    /// `PRIMARY KEY (col, …)`.
    PrimaryKey { columns: Vec<String> },
    /// `UNIQUE (col, …)`.
    Unique { columns: Vec<String> },
}

impl TableConstraint {
    fn render(&self) -> Result<String, DdlError> {
        let (kw, cols) = match self {
            Self::PrimaryKey { columns } => ("PRIMARY KEY", columns),
            Self::Unique { columns } => ("UNIQUE", columns),
        };
        if cols.is_empty() {
            return Err(DdlError::Empty("a key constraint has no columns"));
        }
        let rendered: Result<Vec<&str>, _> = cols.iter().map(|c| ident(c)).collect();
        Ok(format!("{kw} ({})", rendered?.join(", ")))
    }
}

// ---- the emitted result ----------------------------------------------------

/// A validated DDL script plus whether it must run **outside** a wrapping transaction. Maps directly
/// to a `MigrationAction::Sql { script, no_transaction }`: `no_transaction` is `true` for a
/// `CONCURRENTLY` index op (which Postgres forbids inside a transaction).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedDdl {
    /// The SQL (one or more `;`-separated statements).
    pub sql: String,
    /// Whether the script must ride a `no_transaction` migration step.
    pub no_transaction: bool,
}

impl EmittedDdl {
    fn txn(sql: String) -> Self {
        Self {
            sql,
            no_transaction: false,
        }
    }
}

// ---- operations ------------------------------------------------------------

/// The tenant-scoped flavour of [`CreateTable`]: alongside the table it emits the RLS policy
/// (keyed on the tenant-GUC convention) + `FORCE ROW LEVEL SECURITY`, so a builder-made tenant
/// table can never ship RLS-less. Postgres-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantScope {
    /// The table column the RLS predicate keys on (must be one of the table's columns).
    pub tenant_column: String,
    /// The session-GUC carrying the host-resolved tenant (e.g. `app.tenant_id`) — a dotted sequence
    /// of plain identifier segments. Matches the `rls_session` GUC convention.
    pub guc: String,
    /// The RLS policy name (validated object name).
    pub policy: String,
}

/// `CREATE TABLE`. With a [`TenantScope`] it additionally emits `ENABLE`/`FORCE ROW LEVEL SECURITY`
/// and the tenant-GUC RLS policy (Postgres-only).
#[derive(Debug, Clone, PartialEq)]
pub struct CreateTable {
    /// The table name (validated object name).
    pub table: String,
    /// `IF NOT EXISTS` guard.
    pub if_not_exists: bool,
    /// The columns.
    pub columns: Vec<ColumnDef>,
    /// Table-level key constraints.
    pub constraints: Vec<TableConstraint>,
    /// `Some` ⇒ the tenant-scoped RLS variant (Postgres-only).
    pub tenant_scope: Option<TenantScope>,
}

impl CreateTable {
    fn emit(&self, dialect: Dialect) -> Result<EmittedDdl, DdlError> {
        let table = object_ident(&self.table)?;
        if self.columns.is_empty() {
            return Err(DdlError::Empty("CREATE TABLE has no columns"));
        }
        let mut items: Vec<String> = Vec::new();
        for c in &self.columns {
            items.push(c.render(dialect)?);
        }
        for k in &self.constraints {
            items.push(k.render()?);
        }
        let not_exists = if self.if_not_exists {
            "IF NOT EXISTS "
        } else {
            ""
        };
        let mut stmts = vec![format!(
            "CREATE TABLE {not_exists}{table} ({})",
            items.join(", ")
        )];

        if let Some(ts) = &self.tenant_scope {
            if dialect != Dialect::Postgres {
                return Err(DdlError::NotPostgres("a tenant-scoped (RLS) table"));
            }
            // The tenant column must be a real column of this table.
            let tcol = ident(&ts.tenant_column)?;
            if !self.columns.iter().any(|c| c.name == tcol) {
                return Err(DdlError::UnknownTenantColumn(tcol.to_string()));
            }
            let policy = object_ident(&ts.policy)?;
            let guc = validate_guc(&ts.guc)?;
            // `validate_guc` restricts the name to `[A-Za-z0-9_.]` (no quote/backslash), so a plain
            // single-quoted literal is both safe and byte-identical to the documented `rls_session`
            // convention (`current_setting('app.tenant_id', true)`).
            let guc_lit = format!("'{guc}'");
            // `USING` filters reads; `WITH CHECK` constrains writes — both to the resolved tenant,
            // exactly as the `rls_session` convention / the provisioning event trigger produce.
            let pred = format!("{tcol} = current_setting({guc_lit}, true)");
            stmts.push(format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"));
            stmts.push(format!("ALTER TABLE {table} FORCE ROW LEVEL SECURITY"));
            stmts.push(format!(
                "CREATE POLICY {policy} ON {table} USING ({pred}) WITH CHECK ({pred})"
            ));
        }
        Ok(EmittedDdl::txn(stmts.join(";\n")))
    }
}

/// Validate a dotted session-GUC name (`app.tenant_id`) — each `.`-segment a plain identifier —
/// returning it unchanged.
fn validate_guc(guc: &str) -> Result<String, DdlError> {
    let ok = !guc.is_empty() && guc.split('.').all(plain_ident_ok);
    if ok {
        Ok(guc.to_string())
    } else {
        Err(DdlError::InvalidGuc(guc.to_string()))
    }
}

/// `ALTER TABLE … ADD COLUMN`.
#[derive(Debug, Clone, PartialEq)]
pub struct AddColumn {
    /// The table (validated object name).
    pub table: String,
    /// The column to add.
    pub column: ColumnDef,
    /// `IF NOT EXISTS` guard.
    pub if_not_exists: bool,
}

impl AddColumn {
    fn emit(&self, dialect: Dialect) -> Result<EmittedDdl, DdlError> {
        let table = object_ident(&self.table)?;
        let col = self.column.render(dialect)?;
        let not_exists = if self.if_not_exists {
            "IF NOT EXISTS "
        } else {
            ""
        };
        Ok(EmittedDdl::txn(format!(
            "ALTER TABLE {table} ADD COLUMN {not_exists}{col}"
        )))
    }
}

/// A pgvector index access method (`hnsw`/`ivfflat`) or a standard one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IndexMethod {
    Btree,
    Hash,
    Gin,
    Gist,
    Hnsw,
    Ivfflat,
}

impl IndexMethod {
    fn keyword(self) -> &'static str {
        match self {
            Self::Btree => "btree",
            Self::Hash => "hash",
            Self::Gin => "gin",
            Self::Gist => "gist",
            Self::Hnsw => "hnsw",
            Self::Ivfflat => "ivfflat",
        }
    }
    /// Whether this is a pgvector method whose indexed column needs a [`Metric`]-derived opclass.
    fn is_vector(self) -> bool {
        matches!(self, Self::Hnsw | Self::Ivfflat)
    }
}

/// One indexed column. For a vector method (`hnsw`/`ivfflat`) the [`Metric`] is **required** and
/// selects the operator class (`vector_cosine_ops`/`vector_l2_ops`); for a non-vector method it must
/// be absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexColumn {
    /// The column name (validated plain identifier).
    pub column: String,
    /// The vector metric (required iff the method is `hnsw`/`ivfflat`).
    pub metric: Option<Metric>,
}

impl IndexColumn {
    /// Convenience: a plain (non-vector) indexed column.
    pub fn plain(column: impl Into<String>) -> Self {
        Self {
            column: column.into(),
            metric: None,
        }
    }
    /// Convenience: a vector indexed column with its metric-derived opclass.
    pub fn vector(column: impl Into<String>, metric: Metric) -> Self {
        Self {
            column: column.into(),
            metric: Some(metric),
        }
    }
}

/// `CREATE [UNIQUE] INDEX [CONCURRENTLY] … USING <method> (…)`. **Postgres-only** in v1 (the
/// `USING <method>` + opclass form is Postgres-specific). `concurrently` ⇒ the output must ride a
/// `no_transaction` step (surfaced on [`EmittedDdl`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateIndex {
    /// The index name (validated object name).
    pub name: String,
    /// The table (validated object name).
    pub table: String,
    /// The access method.
    pub method: IndexMethod,
    /// The indexed columns.
    pub columns: Vec<IndexColumn>,
    /// `UNIQUE`.
    pub unique: bool,
    /// `IF NOT EXISTS`.
    pub if_not_exists: bool,
    /// `CONCURRENTLY` — forces `no_transaction` on the emitted step.
    pub concurrently: bool,
}

impl CreateIndex {
    fn emit(&self, dialect: Dialect) -> Result<EmittedDdl, DdlError> {
        if dialect != Dialect::Postgres {
            return Err(DdlError::NotPostgres("CREATE INDEX … USING <method>"));
        }
        let name = object_ident(&self.name)?;
        let table = object_ident(&self.table)?;
        if self.columns.is_empty() {
            return Err(DdlError::Empty("CREATE INDEX has no columns"));
        }
        let mut cols = Vec::with_capacity(self.columns.len());
        for c in &self.columns {
            let col = ident(&c.column)?;
            match (self.method.is_vector(), c.metric) {
                // Vector method: the metric picks the opclass, and MUST pair with the kNN query
                // operator the `orm` `Distance` uses — both come from the one `Metric`, never drift.
                (true, Some(m)) => cols.push(format!("{col} {}", m.vector_opclass())),
                (true, None) => {
                    return Err(DdlError::MetricCoupling(
                        "a vector index method requires a metric on each column",
                    ));
                }
                (false, Some(_)) => {
                    return Err(DdlError::MetricCoupling(
                        "a non-vector index method must not carry a metric",
                    ));
                }
                (false, None) => cols.push(col.to_string()),
            }
        }
        let unique = if self.unique { "UNIQUE " } else { "" };
        let conc = if self.concurrently {
            "CONCURRENTLY "
        } else {
            ""
        };
        let not_exists = if self.if_not_exists {
            "IF NOT EXISTS "
        } else {
            ""
        };
        let sql = format!(
            "CREATE {unique}INDEX {conc}{not_exists}{name} ON {table} USING {} ({})",
            self.method.keyword(),
            cols.join(", ")
        );
        Ok(EmittedDdl {
            sql,
            no_transaction: self.concurrently,
        })
    }
}

/// The body of a `CREATE TYPE`. Enum-only in v1.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TypeBody {
    /// `AS ENUM ('a', 'b', …)` — the labels are string values, inlined as safely-quoted literals.
    Enum(Vec<String>),
}

/// `CREATE TYPE <name> AS ENUM (…)`. Postgres-only, enum-only in v1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateType {
    /// The type name (validated object name).
    pub name: String,
    /// The type body.
    pub body: TypeBody,
}

impl CreateType {
    fn emit(&self, dialect: Dialect) -> Result<EmittedDdl, DdlError> {
        if dialect != Dialect::Postgres {
            return Err(DdlError::NotPostgres("CREATE TYPE"));
        }
        let name = object_ident(&self.name)?;
        match &self.body {
            TypeBody::Enum(labels) => {
                if labels.is_empty() {
                    return Err(DdlError::Empty("CREATE TYPE … AS ENUM has no labels"));
                }
                let quoted: Vec<String> = labels
                    .iter()
                    .map(|l| quote_str(Dialect::Postgres, l))
                    .collect();
                Ok(EmittedDdl::txn(format!(
                    "CREATE TYPE {name} AS ENUM ({})",
                    quoted.join(", ")
                )))
            }
        }
    }
}

/// `DROP TABLE` — destructive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropTable {
    /// The table (validated object name).
    pub table: String,
    /// `IF EXISTS`.
    pub if_exists: bool,
    /// `CASCADE`.
    pub cascade: bool,
    /// Explicit data-loss acknowledgement (required).
    pub destructive: bool,
}

impl DropTable {
    fn emit(&self, _dialect: Dialect) -> Result<EmittedDdl, DdlError> {
        if !self.destructive {
            return Err(DdlError::DestructiveNotAcknowledged("DROP TABLE"));
        }
        let table = object_ident(&self.table)?;
        let ie = if self.if_exists { "IF EXISTS " } else { "" };
        let cascade = if self.cascade { " CASCADE" } else { "" };
        Ok(EmittedDdl::txn(format!("DROP TABLE {ie}{table}{cascade}")))
    }
}

/// `ALTER TABLE … DROP COLUMN` — destructive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropColumn {
    /// The table (validated object name).
    pub table: String,
    /// The column (validated identifier).
    pub column: String,
    /// `IF EXISTS`.
    pub if_exists: bool,
    /// `CASCADE`.
    pub cascade: bool,
    /// Explicit data-loss acknowledgement (required).
    pub destructive: bool,
}

impl DropColumn {
    fn emit(&self, _dialect: Dialect) -> Result<EmittedDdl, DdlError> {
        if !self.destructive {
            return Err(DdlError::DestructiveNotAcknowledged("DROP COLUMN"));
        }
        let table = object_ident(&self.table)?;
        let col = ident(&self.column)?;
        let ie = if self.if_exists { "IF EXISTS " } else { "" };
        let cascade = if self.cascade { " CASCADE" } else { "" };
        Ok(EmittedDdl::txn(format!(
            "ALTER TABLE {table} DROP COLUMN {ie}{col}{cascade}"
        )))
    }
}

/// `DROP INDEX` — destructive. Postgres-only (matching [`CreateIndex`]). `concurrently` ⇒
/// `no_transaction`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropIndex {
    /// The index name (validated object name).
    pub name: String,
    /// `IF EXISTS`.
    pub if_exists: bool,
    /// `CONCURRENTLY` — forces `no_transaction` on the emitted step.
    pub concurrently: bool,
    /// Explicit acknowledgement (required).
    pub destructive: bool,
}

impl DropIndex {
    fn emit(&self, dialect: Dialect) -> Result<EmittedDdl, DdlError> {
        if dialect != Dialect::Postgres {
            return Err(DdlError::NotPostgres("DROP INDEX"));
        }
        if !self.destructive {
            return Err(DdlError::DestructiveNotAcknowledged("DROP INDEX"));
        }
        let name = object_ident(&self.name)?;
        let conc = if self.concurrently {
            "CONCURRENTLY "
        } else {
            ""
        };
        let ie = if self.if_exists { "IF EXISTS " } else { "" };
        Ok(EmittedDdl {
            sql: format!("DROP INDEX {conc}{ie}{name}"),
            no_transaction: self.concurrently,
        })
    }
}

/// `ALTER TABLE … ALTER COLUMN … TYPE …` — destructive (a type change can rewrite/truncate data).
/// The plain assignment-cast form only; an incompatible rewrite needing `USING` goes to raw SQL.
#[derive(Debug, Clone, PartialEq)]
pub struct AlterColumnType {
    /// The table (validated object name).
    pub table: String,
    /// The column (validated identifier).
    pub column: String,
    /// The new column type.
    pub new_type: ColumnType,
    /// Explicit acknowledgement (required).
    pub destructive: bool,
}

impl AlterColumnType {
    fn emit(&self, dialect: Dialect) -> Result<EmittedDdl, DdlError> {
        if !self.destructive {
            return Err(DdlError::DestructiveNotAcknowledged("ALTER COLUMN … TYPE"));
        }
        let table = object_ident(&self.table)?;
        let col = ident(&self.column)?;
        let ty = self.new_type.render(dialect)?;
        Ok(EmittedDdl::txn(format!(
            "ALTER TABLE {table} ALTER COLUMN {col} TYPE {ty}"
        )))
    }
}

/// `ALTER TABLE … RENAME TO …` — destructive (a breaking rename).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameTable {
    /// The current table name (validated object name).
    pub table: String,
    /// The new table name (validated object name).
    pub new_name: String,
    /// Explicit acknowledgement (required).
    pub destructive: bool,
}

impl RenameTable {
    fn emit(&self, _dialect: Dialect) -> Result<EmittedDdl, DdlError> {
        if !self.destructive {
            return Err(DdlError::DestructiveNotAcknowledged("RENAME TABLE"));
        }
        let table = object_ident(&self.table)?;
        let new_name = object_ident(&self.new_name)?;
        Ok(EmittedDdl::txn(format!(
            "ALTER TABLE {table} RENAME TO {new_name}"
        )))
    }
}

/// `ALTER TABLE … RENAME COLUMN … TO …` — destructive (a breaking rename).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameColumn {
    /// The table (validated object name).
    pub table: String,
    /// The current column name (validated identifier).
    pub column: String,
    /// The new column name (validated identifier).
    pub new_name: String,
    /// Explicit acknowledgement (required).
    pub destructive: bool,
}

impl RenameColumn {
    fn emit(&self, _dialect: Dialect) -> Result<EmittedDdl, DdlError> {
        if !self.destructive {
            return Err(DdlError::DestructiveNotAcknowledged("RENAME COLUMN"));
        }
        let table = object_ident(&self.table)?;
        let col = ident(&self.column)?;
        let new_name = ident(&self.new_name)?;
        Ok(EmittedDdl::txn(format!(
            "ALTER TABLE {table} RENAME COLUMN {col} TO {new_name}"
        )))
    }
}

/// One typed DDL operation. [`emit`](Ddl::emit) turns it into a validated [`EmittedDdl`] for the
/// owner-role migration seam.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum Ddl {
    CreateTable(CreateTable),
    AddColumn(AddColumn),
    CreateIndex(CreateIndex),
    CreateType(CreateType),
    DropTable(DropTable),
    DropColumn(DropColumn),
    DropIndex(DropIndex),
    AlterColumnType(AlterColumnType),
    RenameTable(RenameTable),
    RenameColumn(RenameColumn),
}

impl Ddl {
    /// Emit the validated SQL for `dialect`, or fail closed. The result is pure codegen — it grants
    /// no authority and runs only on the already-gated owner-role migration seam.
    pub fn emit(&self, dialect: Dialect) -> Result<EmittedDdl, DdlError> {
        match self {
            Self::CreateTable(op) => op.emit(dialect),
            Self::AddColumn(op) => op.emit(dialect),
            Self::CreateIndex(op) => op.emit(dialect),
            Self::CreateType(op) => op.emit(dialect),
            Self::DropTable(op) => op.emit(dialect),
            Self::DropColumn(op) => op.emit(dialect),
            Self::DropIndex(op) => op.emit(dialect),
            Self::AlterColumnType(op) => op.emit(dialect),
            Self::RenameTable(op) => op.emit(dialect),
            Self::RenameColumn(op) => op.emit(dialect),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PG: Dialect = Dialect::Postgres;

    fn sql(op: &Ddl) -> String {
        op.emit(PG).expect("emits on postgres").sql
    }

    #[test]
    fn create_table_portable_scalars_and_pk() {
        let op = Ddl::CreateTable(CreateTable {
            table: "note".into(),
            if_not_exists: true,
            columns: vec![
                ColumnDef::new("id", ColumnType::BigInt),
                ColumnDef {
                    name: "title".into(),
                    ty: ColumnType::Varchar { len: 200 },
                    nullable: true,
                    default: None,
                },
                ColumnDef {
                    name: "created".into(),
                    ty: ColumnType::Timestamp { tz: true },
                    nullable: false,
                    default: Some(ScalarDefault::Now),
                },
            ],
            constraints: vec![TableConstraint::PrimaryKey {
                columns: vec!["id".into()],
            }],
            tenant_scope: None,
        });
        assert_eq!(
            sql(&op),
            "CREATE TABLE IF NOT EXISTS note (id bigint NOT NULL, title varchar(200), \
             created timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (id))"
        );
    }

    #[test]
    fn create_table_vector_uuid_jsonb() {
        let op = Ddl::CreateTable(CreateTable {
            table: "docs".into(),
            if_not_exists: false,
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    ty: ColumnType::Uuid,
                    nullable: false,
                    default: Some(ScalarDefault::GenRandomUuid),
                },
                ColumnDef::new("embedding", ColumnType::Vector { dim: 1536 }),
                ColumnDef {
                    name: "meta".into(),
                    ty: ColumnType::Jsonb,
                    nullable: true,
                    default: None,
                },
            ],
            constraints: vec![TableConstraint::PrimaryKey {
                columns: vec!["id".into()],
            }],
            tenant_scope: None,
        });
        assert_eq!(
            sql(&op),
            "CREATE TABLE docs (id uuid NOT NULL DEFAULT gen_random_uuid(), \
             embedding vector(1536) NOT NULL, meta jsonb, PRIMARY KEY (id))"
        );
    }

    #[test]
    fn tenant_scoped_create_table_emits_forced_rls_policy() {
        let op = Ddl::CreateTable(CreateTable {
            table: "note".into(),
            if_not_exists: false,
            columns: vec![
                ColumnDef::new("tenant_id", ColumnType::Text),
                ColumnDef::new("body", ColumnType::Text),
            ],
            constraints: vec![],
            tenant_scope: Some(TenantScope {
                tenant_column: "tenant_id".into(),
                guc: "app.tenant_id".into(),
                policy: "tenant_isolation".into(),
            }),
        });
        assert_eq!(
            sql(&op),
            "CREATE TABLE note (tenant_id text NOT NULL, body text NOT NULL);\n\
             ALTER TABLE note ENABLE ROW LEVEL SECURITY;\n\
             ALTER TABLE note FORCE ROW LEVEL SECURITY;\n\
             CREATE POLICY tenant_isolation ON note \
             USING (tenant_id = current_setting('app.tenant_id', true)) \
             WITH CHECK (tenant_id = current_setting('app.tenant_id', true))"
        );
    }

    #[test]
    fn tenant_scope_unknown_column_refused() {
        let op = Ddl::CreateTable(CreateTable {
            table: "note".into(),
            if_not_exists: false,
            columns: vec![ColumnDef::new("body", ColumnType::Text)],
            constraints: vec![],
            tenant_scope: Some(TenantScope {
                tenant_column: "tenant_id".into(),
                guc: "app.tenant_id".into(),
                policy: "p".into(),
            }),
        });
        assert_eq!(
            op.emit(PG),
            Err(DdlError::UnknownTenantColumn("tenant_id".into()))
        );
    }

    #[test]
    fn tenant_scope_is_postgres_only() {
        let op = Ddl::CreateTable(CreateTable {
            table: "note".into(),
            if_not_exists: false,
            columns: vec![ColumnDef::new("tenant_id", ColumnType::Text)],
            constraints: vec![],
            tenant_scope: Some(TenantScope {
                tenant_column: "tenant_id".into(),
                guc: "app.tenant_id".into(),
                policy: "p".into(),
            }),
        });
        assert!(matches!(
            op.emit(Dialect::Sqlite),
            Err(DdlError::NotPostgres(_))
        ));
    }

    #[test]
    fn tenant_scope_bad_guc_refused() {
        let op = Ddl::CreateTable(CreateTable {
            table: "note".into(),
            if_not_exists: false,
            columns: vec![ColumnDef::new("tenant_id", ColumnType::Text)],
            constraints: vec![],
            tenant_scope: Some(TenantScope {
                tenant_column: "tenant_id".into(),
                guc: "app.tenant_id'); DROP TABLE note;--".into(),
                policy: "p".into(),
            }),
        });
        assert!(matches!(op.emit(PG), Err(DdlError::InvalidGuc(_))));
    }

    #[test]
    fn create_index_hnsw_cosine_opclass() {
        let op = Ddl::CreateIndex(CreateIndex {
            name: "docs_embedding_hnsw".into(),
            table: "docs".into(),
            method: IndexMethod::Hnsw,
            columns: vec![IndexColumn::vector("embedding", Metric::Cosine)],
            unique: false,
            if_not_exists: false,
            concurrently: false,
        });
        let e = op.emit(PG).unwrap();
        assert_eq!(
            e.sql,
            "CREATE INDEX docs_embedding_hnsw ON docs USING hnsw (embedding vector_cosine_ops)"
        );
        assert!(!e.no_transaction);
    }

    #[test]
    fn create_index_concurrently_sets_no_transaction() {
        let op = Ddl::CreateIndex(CreateIndex {
            name: "docs_embedding_ivf".into(),
            table: "docs".into(),
            method: IndexMethod::Ivfflat,
            columns: vec![IndexColumn::vector("embedding", Metric::L2)],
            unique: false,
            if_not_exists: true,
            concurrently: true,
        });
        let e = op.emit(PG).unwrap();
        assert_eq!(
            e.sql,
            "CREATE INDEX CONCURRENTLY IF NOT EXISTS docs_embedding_ivf ON docs \
             USING ivfflat (embedding vector_l2_ops)"
        );
        assert!(
            e.no_transaction,
            "CONCURRENTLY must ride a no_transaction step"
        );
    }

    #[test]
    fn create_index_btree_plain() {
        let op = Ddl::CreateIndex(CreateIndex {
            name: "note_created_idx".into(),
            table: "note".into(),
            method: IndexMethod::Btree,
            columns: vec![IndexColumn::plain("created")],
            unique: true,
            if_not_exists: false,
            concurrently: false,
        });
        assert_eq!(
            sql(&op),
            "CREATE UNIQUE INDEX note_created_idx ON note USING btree (created)"
        );
    }

    #[test]
    fn index_metric_coupling_is_enforced() {
        // vector method, no metric → refused.
        let no_metric = Ddl::CreateIndex(CreateIndex {
            name: "i".into(),
            table: "docs".into(),
            method: IndexMethod::Hnsw,
            columns: vec![IndexColumn::plain("embedding")],
            unique: false,
            if_not_exists: false,
            concurrently: false,
        });
        assert!(matches!(
            no_metric.emit(PG),
            Err(DdlError::MetricCoupling(_))
        ));
        // non-vector method carrying a metric → refused.
        let stray_metric = Ddl::CreateIndex(CreateIndex {
            name: "i".into(),
            table: "docs".into(),
            method: IndexMethod::Btree,
            columns: vec![IndexColumn::vector("c", Metric::Cosine)],
            unique: false,
            if_not_exists: false,
            concurrently: false,
        });
        assert!(matches!(
            stray_metric.emit(PG),
            Err(DdlError::MetricCoupling(_))
        ));
    }

    #[test]
    fn index_is_postgres_only() {
        let op = Ddl::CreateIndex(CreateIndex {
            name: "i".into(),
            table: "t".into(),
            method: IndexMethod::Btree,
            columns: vec![IndexColumn::plain("c")],
            unique: false,
            if_not_exists: false,
            concurrently: false,
        });
        assert!(matches!(
            op.emit(Dialect::Mysql),
            Err(DdlError::NotPostgres(_))
        ));
    }

    #[test]
    fn metric_opclass_operator_coupling_is_consistent() {
        // The one source of truth: the index opclass and the kNN query operator both come from the
        // same `Metric`, so an index built for a metric is only used by a query with its operator.
        for (m, opclass, op) in [
            (Metric::Cosine, "vector_cosine_ops", "<=>"),
            (Metric::L2, "vector_l2_ops", "<->"),
        ] {
            assert_eq!(m.vector_opclass(), opclass);
            assert_eq!(m.operator(), op);
        }
    }

    #[test]
    fn create_type_enum() {
        let op = Ddl::CreateType(CreateType {
            name: "mood".into(),
            body: TypeBody::Enum(vec!["sad".into(), "ok".into(), "happy".into()]),
        });
        // Labels are arbitrary user text, so they use the robust backslash-safe `E'…'` quoter
        // (defense-in-depth, independent of `standard_conforming_strings`), not plain quoting.
        assert_eq!(
            sql(&op),
            "CREATE TYPE mood AS ENUM (E'sad', E'ok', E'happy')"
        );
        assert!(matches!(
            op.emit(Dialect::Sqlite),
            Err(DdlError::NotPostgres(_))
        ));
    }

    #[test]
    fn add_column() {
        let op = Ddl::AddColumn(AddColumn {
            table: "note".into(),
            column: ColumnDef {
                name: "views".into(),
                ty: ColumnType::Integer,
                nullable: false,
                default: Some(ScalarDefault::Literal(SqlValue::Integer(0))),
            },
            if_not_exists: true,
        });
        assert_eq!(
            sql(&op),
            "ALTER TABLE note ADD COLUMN IF NOT EXISTS views integer NOT NULL DEFAULT 0"
        );
    }

    #[test]
    fn destructive_ops_require_acknowledgement() {
        let drop = |ack: bool| {
            Ddl::DropTable(DropTable {
                table: "note".into(),
                if_exists: true,
                cascade: false,
                destructive: ack,
            })
        };
        assert!(matches!(
            drop(false).emit(PG),
            Err(DdlError::DestructiveNotAcknowledged(_))
        ));
        assert_eq!(sql(&drop(true)), "DROP TABLE IF EXISTS note");

        // DropColumn / AlterColumnType / rename all gate the same way.
        for op in [
            Ddl::DropColumn(DropColumn {
                table: "note".into(),
                column: "body".into(),
                if_exists: false,
                cascade: false,
                destructive: false,
            }),
            Ddl::AlterColumnType(AlterColumnType {
                table: "note".into(),
                column: "body".into(),
                new_type: ColumnType::Text,
                destructive: false,
            }),
            Ddl::RenameTable(RenameTable {
                table: "note".into(),
                new_name: "memo".into(),
                destructive: false,
            }),
            Ddl::RenameColumn(RenameColumn {
                table: "note".into(),
                column: "body".into(),
                new_name: "content".into(),
                destructive: false,
            }),
            Ddl::DropIndex(DropIndex {
                name: "i".into(),
                if_exists: false,
                concurrently: false,
                destructive: false,
            }),
        ] {
            assert!(
                matches!(op.emit(PG), Err(DdlError::DestructiveNotAcknowledged(_))),
                "unacknowledged destructive op must be refused: {op:?}"
            );
        }
    }

    #[test]
    fn destructive_ops_emit_when_acknowledged() {
        assert_eq!(
            sql(&Ddl::DropColumn(DropColumn {
                table: "note".into(),
                column: "body".into(),
                if_exists: true,
                cascade: true,
                destructive: true,
            })),
            "ALTER TABLE note DROP COLUMN IF EXISTS body CASCADE"
        );
        assert_eq!(
            sql(&Ddl::AlterColumnType(AlterColumnType {
                table: "note".into(),
                column: "n".into(),
                new_type: ColumnType::BigInt,
                destructive: true,
            })),
            "ALTER TABLE note ALTER COLUMN n TYPE bigint"
        );
        assert_eq!(
            sql(&Ddl::RenameTable(RenameTable {
                table: "note".into(),
                new_name: "memo".into(),
                destructive: true,
            })),
            "ALTER TABLE note RENAME TO memo"
        );
        assert_eq!(
            sql(&Ddl::RenameColumn(RenameColumn {
                table: "note".into(),
                column: "body".into(),
                new_name: "content".into(),
                destructive: true,
            })),
            "ALTER TABLE note RENAME COLUMN body TO content"
        );
        let di = Ddl::DropIndex(DropIndex {
            name: "docs_embedding_hnsw".into(),
            if_exists: true,
            concurrently: true,
            destructive: true,
        })
        .emit(PG)
        .unwrap();
        assert_eq!(
            di.sql,
            "DROP INDEX CONCURRENTLY IF EXISTS docs_embedding_hnsw"
        );
        assert!(di.no_transaction);
    }

    #[test]
    fn closed_default_text_is_escaped_not_injectable() {
        let op = Ddl::AddColumn(AddColumn {
            table: "note".into(),
            column: ColumnDef {
                name: "label".into(),
                ty: ColumnType::Text,
                nullable: false,
                default: Some(ScalarDefault::Literal(SqlValue::Text(
                    "O'Brien'); DROP TABLE note;--".into(),
                ))),
            },
            if_not_exists: false,
        });
        // The injection attempt is wholly contained inside ONE escaped `E'…'` literal — the `'`, the
        // `)`, the `;` and the `DROP` are all inside the quotes, so there is no bare second statement.
        assert_eq!(
            sql(&op),
            "ALTER TABLE note ADD COLUMN label text NOT NULL \
             DEFAULT E'O''Brien''); DROP TABLE note;--'"
        );
    }

    #[test]
    fn default_rejects_non_closed_values() {
        for bad in [
            SqlValue::Null,
            SqlValue::Blob(vec![1, 2]),
            SqlValue::Json("{}".into()),
            SqlValue::Real(f64::INFINITY),
        ] {
            let op = Ddl::AddColumn(AddColumn {
                table: "t".into(),
                column: ColumnDef {
                    name: "c".into(),
                    ty: ColumnType::Text,
                    nullable: true,
                    default: Some(ScalarDefault::Literal(bad.clone())),
                },
                if_not_exists: false,
            });
            assert!(
                matches!(op.emit(PG), Err(DdlError::BadDefault(_))),
                "a {bad:?} literal default must be refused"
            );
        }
    }

    #[test]
    fn text_default_quoting_is_dialect_correct_for_backslashes() {
        // A value with a backslash AND a quote: `a\b'c`. MySQL's default sql_mode treats `\` as an
        // escape, so it must be doubled (else a trailing `\` eats the closing quote); SQLite must NOT
        // escape it (that would store a literal double-backslash). Both double the embedded quote.
        let col = |v: &str| {
            Ddl::AddColumn(AddColumn {
                table: "t".into(),
                column: ColumnDef {
                    name: "c".into(),
                    ty: ColumnType::Text,
                    nullable: true,
                    default: Some(ScalarDefault::Literal(SqlValue::Text(v.into()))),
                },
                if_not_exists: false,
            })
        };
        assert_eq!(
            col("a\\b'c").emit(Dialect::Mysql).unwrap().sql,
            "ALTER TABLE t ADD COLUMN c text DEFAULT 'a\\\\b''c'",
            "MySQL must escape the backslash (\\ -> \\\\) and double the quote"
        );
        assert_eq!(
            col("a\\b'c").emit(Dialect::Sqlite).unwrap().sql,
            "ALTER TABLE t ADD COLUMN c text DEFAULT 'a\\b''c'",
            "SQLite must NOT escape the backslash (only double the quote)"
        );
    }

    #[test]
    fn identifiers_are_validated_and_schema_qualification_rejected() {
        for bad in ["bad name", "foo;DROP", "public.note", "note.body", ""] {
            let op = Ddl::CreateTable(CreateTable {
                table: bad.into(),
                if_not_exists: false,
                columns: vec![ColumnDef::new("c", ColumnType::Text)],
                constraints: vec![],
                tenant_scope: None,
            });
            assert!(
                matches!(op.emit(PG), Err(DdlError::InvalidIdentifier(_))),
                "invalid/qualified name {bad:?} must be refused"
            );
        }
    }

    #[test]
    fn reserved_ledger_names_are_refused() {
        for reserved in [
            "boatramp_migrations",
            "schema_migrations",
            "boatramp_migrations_schema_migrations",
            "BOATRAMP_MIGRATIONS",
        ] {
            let op = Ddl::CreateTable(CreateTable {
                table: reserved.into(),
                if_not_exists: false,
                columns: vec![ColumnDef::new("c", ColumnType::Text)],
                constraints: vec![],
                tenant_scope: None,
            });
            assert!(
                matches!(op.emit(PG), Err(DdlError::ReservedName(_))),
                "reserved host name {reserved:?} must be refused"
            );
        }
    }

    #[test]
    fn vector_and_varchar_dimension_guards() {
        let zero_vec = Ddl::CreateTable(CreateTable {
            table: "t".into(),
            if_not_exists: false,
            columns: vec![ColumnDef::new("v", ColumnType::Vector { dim: 0 })],
            constraints: vec![],
            tenant_scope: None,
        });
        assert!(matches!(zero_vec.emit(PG), Err(DdlError::BadColumn(_))));
        let zero_varchar = Ddl::CreateTable(CreateTable {
            table: "t".into(),
            if_not_exists: false,
            columns: vec![ColumnDef::new("s", ColumnType::Varchar { len: 0 })],
            constraints: vec![],
            tenant_scope: None,
        });
        assert!(matches!(zero_varchar.emit(PG), Err(DdlError::BadColumn(_))));
    }

    #[test]
    fn no_operation_ever_emits_create_extension() {
        // The builder must NEVER emit CREATE EXTENSION (it stays the operator-allowlisted path); a
        // representative emit of every op family confirms the string never appears.
        let ops = vec![
            Ddl::CreateTable(CreateTable {
                table: "docs".into(),
                if_not_exists: false,
                columns: vec![ColumnDef::new("embedding", ColumnType::Vector { dim: 3 })],
                constraints: vec![],
                tenant_scope: None,
            }),
            Ddl::CreateIndex(CreateIndex {
                name: "i".into(),
                table: "docs".into(),
                method: IndexMethod::Hnsw,
                columns: vec![IndexColumn::vector("embedding", Metric::Cosine)],
                unique: false,
                if_not_exists: false,
                concurrently: false,
            }),
            Ddl::CreateType(CreateType {
                name: "mood".into(),
                body: TypeBody::Enum(vec!["a".into()]),
            }),
        ];
        for op in ops {
            let out = op.emit(PG).unwrap().sql.to_ascii_uppercase();
            assert!(!out.contains("CREATE EXTENSION"), "{out}");
        }
    }

    #[test]
    fn portable_scalar_table_renders_on_sqlite() {
        // The trivially-portable scalar subset renders on a non-Postgres dialect too.
        let op = Ddl::CreateTable(CreateTable {
            table: "note".into(),
            if_not_exists: false,
            columns: vec![
                ColumnDef::new("id", ColumnType::Integer),
                ColumnDef::new("body", ColumnType::Text),
            ],
            constraints: vec![TableConstraint::PrimaryKey {
                columns: vec!["id".into()],
            }],
            tenant_scope: None,
        });
        assert_eq!(
            op.emit(Dialect::Sqlite).unwrap().sql,
            "CREATE TABLE note (id integer NOT NULL, body text NOT NULL, PRIMARY KEY (id))"
        );
    }

    #[test]
    fn postgres_only_types_fail_closed_on_sqlite() {
        for ty in [
            ColumnType::Vector { dim: 4 },
            ColumnType::Jsonb,
            ColumnType::Uuid,
            ColumnType::Serial,
            ColumnType::Timestamp { tz: true },
        ] {
            let op = Ddl::CreateTable(CreateTable {
                table: "t".into(),
                if_not_exists: false,
                columns: vec![ColumnDef::new("c", ty.clone())],
                constraints: vec![],
                tenant_scope: None,
            });
            assert!(
                matches!(op.emit(Dialect::Sqlite), Err(DdlError::NotPostgres(_))),
                "{ty:?} must fail closed on sqlite"
            );
        }
    }

    #[test]
    fn swap_equivalence_handwritten_tokenfield_shape() {
        // GATE (§6/§7): the typed builder emits the SAME DDL tokenfield hand-writes today — a
        // `vector(1536)` column + an hnsw `vector_cosine_ops` index, byte-for-byte.
        let table = Ddl::CreateTable(CreateTable {
            table: "embeddings".into(),
            if_not_exists: false,
            columns: vec![
                ColumnDef {
                    name: "id".into(),
                    ty: ColumnType::Uuid,
                    nullable: false,
                    default: Some(ScalarDefault::GenRandomUuid),
                },
                ColumnDef::new("tenant_id", ColumnType::Text),
                ColumnDef::new("embedding", ColumnType::Vector { dim: 1536 }),
                ColumnDef {
                    name: "content".into(),
                    ty: ColumnType::Text,
                    nullable: true,
                    default: None,
                },
            ],
            constraints: vec![TableConstraint::PrimaryKey {
                columns: vec!["id".into()],
            }],
            tenant_scope: None,
        });
        let index = Ddl::CreateIndex(CreateIndex {
            name: "embeddings_embedding_hnsw".into(),
            table: "embeddings".into(),
            method: IndexMethod::Hnsw,
            columns: vec![IndexColumn::vector("embedding", Metric::Cosine)],
            unique: false,
            if_not_exists: false,
            concurrently: false,
        });
        const HAND_TABLE: &str = "CREATE TABLE embeddings (id uuid NOT NULL DEFAULT gen_random_uuid(), tenant_id text NOT NULL, embedding vector(1536) NOT NULL, content text, PRIMARY KEY (id))";
        const HAND_INDEX: &str = "CREATE INDEX embeddings_embedding_hnsw ON embeddings USING hnsw (embedding vector_cosine_ops)";
        assert_eq!(table.emit(PG).unwrap().sql, HAND_TABLE);
        assert_eq!(index.emit(PG).unwrap().sql, HAND_INDEX);
    }
}
