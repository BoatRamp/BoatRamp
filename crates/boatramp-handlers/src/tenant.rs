//! Host-resolved in-site tenancy for one guest invocation — the **applied** side of the
//! tenant-isolation model (the declared side is [`boatramp_core::tenancy`]).
//!
//! The server resolves the tenant *value* from the verified source and the (posture-capped)
//! per-axis access modes, then hands the binding a [`HostTenancy`]. The binding **forces** it
//! onto every ORM query node ([`orm::Select::force_scope`] et al.) and **fills** the raw-SQL
//! [`SCOPE_MARKER`] — the guest can neither see nor set it. Absent a `HostTenancy` ⇒ plain queries
//! (no scoping; the project=database boundary is the whole isolation).
//!
//! Applying to **both** surfaces is the load-bearing invariant: scoping only the ORM would let a
//! guest that also imports raw `sql` read/write across tenants and bypass the whole model.

use boatramp_core::orm::{Scope, ScopeMode};
use boatramp_core::sql::SqlValue;
use boatramp_core::tenancy::AccessMode;

/// The reserved token a scoped-tenancy guest places in a raw-SQL statement to mark **where** the
/// host injects the tenant predicate (the host, not the guest, decides *what* it is). A scoped
/// statement without it is refused (fail-closed); an unscoped statement never needs it.
pub const SCOPE_MARKER: &str = "{scope}";

/// Which axis of a function's grant an operation exercises. Reads (`SELECT`) use the read grant;
/// writes (`INSERT`/`UPDATE`/`DELETE`) use the write grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Axis {
    Read,
    Write,
}

/// Why a scoped operation is refused **before** it reaches the backend (always fail-closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantDenied {
    /// The axis grants no access at all ([`AccessMode::None`]).
    NoAccess,
    /// The mode needs a resolved "own" tenant, but the source produced none (anonymous request,
    /// or a source not yet wired) — so the query is refused rather than run unscoped.
    NoSource,
    /// The configured tenant column is not a valid SQL identifier (operator/app misconfig).
    BadColumn,
}

impl TenantDenied {
    /// A short, guest-safe reason string (no tenant values leaked).
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoAccess => "tenancy: this function is not granted access on this axis",
            Self::NoSource => "tenancy: no verified tenant source for this request",
            Self::BadColumn => "tenancy: misconfigured tenant column",
        }
    }
}

/// The host-resolved tenancy for one invocation. Built server-side: `value` is the tenant resolved
/// from the verified source (`None` for anonymous / null-only), and `read`/`write` are the access
/// modes **already capped by the operator posture** (so an `all` here is a deliberately-permitted
/// cross-tenant grant, never an un-vetted one). Shared by the `sql` and `orm` bindings.
#[derive(Debug, Clone)]
pub struct HostTenancy {
    column: String,
    value: Option<SqlValue>,
    read: AccessMode,
    write: AccessMode,
    /// Per-table tenant-key resolution from the project [`TenancySchema`](boatramp_core::tenancy::TenancySchema)
    /// (Stage 1 / R2). `Uniform` (no project schema) ⇒ every table scopes on `column`; `PerTable`
    /// ⇒ the identity table on its own PK, `Unscoped` tables skipped, undeclared tables refused.
    keys: boatramp_core::orm::TableKeys,
}

impl HostTenancy {
    /// Build a resolved tenancy. `column` is the default tenant column; `value` the resolved tenant
    /// (if any); `read`/`write` the posture-capped access modes. Per-table keys default to
    /// `Uniform` (legacy single-column); attach a project schema with [`with_schema`](Self::with_schema).
    pub fn new(
        column: impl Into<String>,
        value: Option<SqlValue>,
        read: AccessMode,
        write: AccessMode,
    ) -> Self {
        Self {
            column: column.into(),
            value,
            read,
            write,
            keys: boatramp_core::orm::TableKeys::Uniform,
        }
    }

    /// Attach the project's per-table tenancy map (R2), so each table scopes on its own key (the
    /// identity table on its PK, `Unscoped` tables skipped, undeclared tables refused).
    ///
    /// A **present** schema (`Some`) is authoritative — it becomes `PerTable` **even when empty**, so
    /// an empty (or [`deny_all`](boatramp_core::tenancy::TenancySchema::deny_all)) schema refuses
    /// every table rather than silently reverting to single-column scoping. Only an **absent** schema
    /// (`None` — the project declared none) keeps the legacy `Uniform` behavior. This is the
    /// fail-closed contract the bind path relies on: a project that has adopted a schema can never be
    /// downgraded to `Uniform` by an empty map. Chained by the host at bind time.
    #[must_use]
    pub fn with_schema(mut self, schema: Option<&boatramp_core::tenancy::TenancySchema>) -> Self {
        if let Some(s) = schema {
            self.keys = boatramp_core::orm::TableKeys::PerTable(s.table_key_map());
        }
        self
    }

    /// The resolved tenant value, if any. Used by the host to **propagate** the caller's tenant
    /// down an in-project invoke chain (host-carried — never read from a guest-supplied invoke
    /// request), so an invoked sibling inherits the caller's tenant identity while applying its
    /// own grant.
    pub fn value(&self) -> Option<&SqlValue> {
        self.value.as_ref()
    }

    fn mode(&self, axis: Axis) -> AccessMode {
        match axis {
            Axis::Read => self.read,
            Axis::Write => self.write,
        }
    }

    fn valid_column(&self) -> bool {
        is_ident(&self.column)
    }

    /// The core ORM [`Scope`] to force onto a query for `axis`, or a [`TenantDenied`]
    /// (fail-closed). `Ok(None)` means *no scope* — cross-tenant [`AccessMode::All`], which runs
    /// unscoped by design (its grant was posture-vetted upstream).
    pub fn orm_scope(&self, axis: Axis) -> Result<Option<Scope>, TenantDenied> {
        if !self.valid_column() {
            return Err(TenantDenied::BadColumn);
        }
        let mode = match self.mode(axis) {
            AccessMode::None => return Err(TenantDenied::NoAccess),
            AccessMode::All => return Ok(None),
            AccessMode::Null => ScopeMode::NullOnly,
            AccessMode::Own => ScopeMode::Own,
            AccessMode::OwnOrNull => ScopeMode::OwnOrNull,
        };
        // NullOnly never references the value; own/own+null require a resolved one.
        let value = if matches!(mode, ScopeMode::NullOnly) {
            SqlValue::Null
        } else {
            self.value.clone().ok_or(TenantDenied::NoSource)?
        };
        Ok(Some(Scope {
            column: self.column.clone(),
            value,
            mode,
            // The project schema's per-table key map (R2), resolved at `HostTenancy::new`; `Uniform`
            // when the project declared no schema (byte-identical to the pre-schema behavior).
            keys: self.keys.clone(),
        }))
    }

    /// Whether raw SQL on `axis` must carry the [`SCOPE_MARKER`]. True whenever the axis actually
    /// restricts rows (null/own/own+null); false for cross-tenant `all` (nothing to inject) — a
    /// `None`-grant axis "requires" it moot-ly since it's denied outright.
    pub fn requires_marker(&self, axis: Axis) -> bool {
        !matches!(self.mode(axis), AccessMode::All)
    }

    /// Fill the raw-SQL [`SCOPE_MARKER`] for `axis`, given the guest's current positional-param
    /// count. Returns the predicate SQL to substitute for the marker plus an optional value to
    /// **append** to the params (the predicate references it as `?<param_count+1>`, so it is safe
    /// wherever the marker sits). `all` yields a tautology (`1 = 1`) and no appended value.
    pub fn sql_marker(
        &self,
        axis: Axis,
        param_count: usize,
    ) -> Result<(String, Option<SqlValue>), TenantDenied> {
        if !self.valid_column() {
            return Err(TenantDenied::BadColumn);
        }
        let col = &self.column;
        match self.mode(axis) {
            AccessMode::None => Err(TenantDenied::NoAccess),
            AccessMode::All => Ok(("1 = 1".to_string(), None)),
            AccessMode::Null => Ok((format!("{col} IS NULL"), None)),
            AccessMode::Own => {
                let v = self.value.clone().ok_or(TenantDenied::NoSource)?;
                Ok((format!("{col} = ?{}", param_count + 1), Some(v)))
            }
            AccessMode::OwnOrNull => {
                let v = self.value.clone().ok_or(TenantDenied::NoSource)?;
                Ok((
                    format!("({col} = ?{} OR {col} IS NULL)", param_count + 1),
                    Some(v),
                ))
            }
        }
    }
}

/// A conservative SQL-identifier check for the tenant column (host/operator-set, still validated):
/// non-empty, ASCII alphanumeric or `_`, not starting with a digit.
fn is_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> SqlValue {
        SqlValue::Text(s.to_string())
    }

    #[test]
    fn orm_scope_maps_each_mode() {
        let ht = HostTenancy::new(
            "tenant_id",
            Some(t("ten_1")),
            AccessMode::Own,
            AccessMode::Own,
        );
        let s = ht.orm_scope(Axis::Read).unwrap().unwrap();
        assert_eq!(s.column, "tenant_id");
        assert_eq!(s.value, t("ten_1"));
        assert_eq!(s.mode, ScopeMode::Own);

        let ht = HostTenancy::new(
            "tenant_id",
            Some(t("ten_1")),
            AccessMode::OwnOrNull,
            AccessMode::All,
        );
        assert_eq!(
            ht.orm_scope(Axis::Read).unwrap().unwrap().mode,
            ScopeMode::OwnOrNull
        );
        // `all` on the write axis → no scope (unscoped by design).
        assert_eq!(ht.orm_scope(Axis::Write).unwrap(), None);
    }

    #[test]
    fn with_schema_puts_per_table_keys_on_the_scope() {
        use boatramp_core::orm::TableKeys;
        use boatramp_core::tenancy::{TableScope, TenancySchema};
        let mut schema = TenancySchema::default();
        schema.tables.insert("orders".into(), TableScope::Tenant);
        schema.tables.insert(
            "tenant".into(),
            TableScope::TenantKeyed { key: "id".into() },
        );
        schema
            .tables
            .insert("countries".into(), TableScope::Unscoped);
        let ht = HostTenancy::new(
            "tenant_id",
            Some(t("acme")),
            AccessMode::Own,
            AccessMode::Own,
        )
        .with_schema(Some(&schema));
        let scope = ht.orm_scope(Axis::Read).unwrap().unwrap();
        match &scope.keys {
            TableKeys::PerTable(m) => {
                assert_eq!(m.get("orders"), Some(&Some("tenant_id".to_string())));
                assert_eq!(m.get("tenant"), Some(&Some("id".to_string()))); // identity table on its PK
                assert_eq!(m.get("countries"), Some(&None)); // unscoped
                assert_eq!(m.get("secrets"), None); // undeclared → refused at injection
            }
            other => panic!("expected PerTable, got {other:?}"),
        }
        // No project schema (absent) ⇒ Uniform (legacy single-column).
        let ht2 = HostTenancy::new(
            "tenant_id",
            Some(t("acme")),
            AccessMode::Own,
            AccessMode::Own,
        );
        assert!(matches!(
            ht2.orm_scope(Axis::Read).unwrap().unwrap().keys,
            TableKeys::Uniform
        ));
        // A PRESENT but empty (deny-all) schema is authoritative ⇒ PerTable(empty), NOT Uniform, so
        // every table is undeclared and refused. This is the fail-closed posture the bind path binds
        // when the stored schema can't be read — an empty map must never downgrade to Uniform.
        let ht3 = HostTenancy::new(
            "tenant_id",
            Some(t("acme")),
            AccessMode::Own,
            AccessMode::Own,
        )
        .with_schema(Some(&TenancySchema::deny_all()));
        match ht3.orm_scope(Axis::Read).unwrap().unwrap().keys {
            TableKeys::PerTable(m) => assert!(m.is_empty(), "deny-all is an empty PerTable map"),
            other => panic!("deny-all must be PerTable(empty), got {other:?}"),
        }
    }

    #[test]
    fn own_without_a_value_fails_closed() {
        let ht = HostTenancy::new("tenant_id", None, AccessMode::Own, AccessMode::None);
        assert_eq!(ht.orm_scope(Axis::Read), Err(TenantDenied::NoSource));
        // A None-grant axis denies outright.
        assert_eq!(ht.orm_scope(Axis::Write), Err(TenantDenied::NoAccess));
    }

    #[test]
    fn null_only_needs_no_value() {
        let ht = HostTenancy::new("tenant_id", None, AccessMode::Null, AccessMode::Null);
        let s = ht.orm_scope(Axis::Read).unwrap().unwrap();
        assert_eq!(s.mode, ScopeMode::NullOnly);
        assert_eq!(s.value, SqlValue::Null);
    }

    #[test]
    fn sql_marker_references_appended_param() {
        let ht = HostTenancy::new(
            "tenant_id",
            Some(t("ten_1")),
            AccessMode::Own,
            AccessMode::Own,
        );
        // Two guest params already ⇒ the injected predicate binds ?3.
        let (pred, val) = ht.sql_marker(Axis::Read, 2).unwrap();
        assert_eq!(pred, "tenant_id = ?3");
        assert_eq!(val, Some(t("ten_1")));

        let ht = HostTenancy::new(
            "tenant_id",
            Some(t("ten_1")),
            AccessMode::OwnOrNull,
            AccessMode::Own,
        );
        let (pred, _) = ht.sql_marker(Axis::Read, 0).unwrap();
        assert_eq!(pred, "(tenant_id = ?1 OR tenant_id IS NULL)");
    }

    #[test]
    fn sql_marker_all_is_a_tautology_and_null_binds_nothing() {
        let ht = HostTenancy::new("tenant_id", None, AccessMode::All, AccessMode::Null);
        assert_eq!(
            ht.sql_marker(Axis::Read, 3).unwrap(),
            ("1 = 1".to_string(), None)
        );
        assert!(!ht.requires_marker(Axis::Read));
        assert_eq!(
            ht.sql_marker(Axis::Write, 3).unwrap(),
            ("tenant_id IS NULL".to_string(), None)
        );
        assert!(ht.requires_marker(Axis::Write));
    }

    #[test]
    fn a_bad_column_is_refused() {
        let ht = HostTenancy::new(
            "tenant_id; DROP",
            Some(t("x")),
            AccessMode::Own,
            AccessMode::Own,
        );
        assert_eq!(ht.orm_scope(Axis::Read), Err(TenantDenied::BadColumn));
        assert_eq!(ht.sql_marker(Axis::Read, 0), Err(TenantDenied::BadColumn));
    }
}
