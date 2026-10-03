//! **Live** proof (v0.12.5) that the `write:"null"` base-write grant on a `tenant_or_base` table
//! writes ONLY the shared `tenant_id IS NULL` baseline on a REAL SQL engine — the write analog of
//! the base-row READ fold — while the table's tenant partition keeps its per-tenant isolation, and a
//! TARGET route is refused the base write. Built exactly as the host binding builds a write
//! (`force_scope` + `compile`), run against a real embedded libsql file. The capability itself ships
//! since v0.4.16 (`AccessMode::Null` → `ScopeMode::NullOnly`); this gate regression-locks it for the
//! construens global event-catalog (`reference_entity`) use case and proves the v0.12.5 target-route
//! refusal live. Prints `CATALOG BASE-WRITE OK` so a silent skip can't masquerade as a pass.
//!
//! The mutation-verified anti-hollow proof for `write_target`'s NULL stamp + the target refusal lives
//! in the fast `boatramp-core` unit gate `base_write_target_stamps_null_and_refuses_target`
//! (`BOATRAMP_BASEWRITE_MUTATION=leak_stamp|skip_target_guard`); this file is the LIVE end-to-end
//! companion.
#![cfg(feature = "sql")]

use boatramp_core::orm::{
    Assignment, Expr, Insert, OrmError, Predicate, RowValues, Scope, ScopeMode, Select, SelectItem,
    TableKeys, Update,
};
use boatramp_core::sql::{Dialect, SqlBackends, SqlTransaction, SqlValue};
use boatramp_core::tenancy::ResolvedScope;
use boatramp_storage::LibsqlSqlBackends;

fn t(s: &str) -> SqlValue {
    SqlValue::Text(s.into())
}
fn item(e: Expr) -> SelectItem {
    SelectItem {
        expr: e,
        alias: None,
    }
}

/// The per-table key map: `reference_entity` is the one `tenant_or_base` table (base⊕own on
/// `tenant_id`), exactly as the host threads it onto every scope for this schema.
fn keys() -> TableKeys {
    TableKeys::PerTable(std::collections::BTreeMap::from([(
        "reference_entity".to_string(),
        ResolvedScope::TenantOrBase {
            tenant: "tenant_id".into(),
        },
    )]))
}

/// A non-target base-write scope (`write:"null"` → `NullOnly`) — writes the shared baseline.
fn base_write() -> Scope {
    Scope {
        column: "tenant_id".into(),
        value: Some(t("admin")), // a resolved principal is present; a base write ignores it (stamps NULL)
        session: None,
        mode: ScopeMode::NullOnly,
        keys: keys(),
        unscoped_writes: std::collections::BTreeSet::new(),
        pass_unresolved: false,
    }
}

/// An ordinary own-write scope for tenant `A`.
fn own_write(tenant: &str) -> Scope {
    Scope {
        column: "tenant_id".into(),
        value: Some(t(tenant)),
        session: None,
        mode: ScopeMode::Own,
        keys: keys(),
        unscoped_writes: std::collections::BTreeSet::new(),
        pass_unresolved: false,
    }
}

async fn tenant_of(tx: &mut dyn SqlTransaction, id: &str) -> SqlValue {
    tx.query(
        "SELECT tenant_id FROM reference_entity WHERE id = ?1",
        &[t(id)],
    )
    .await
    .unwrap()
    .rows
    .into_iter()
    .next()
    .map(|r| r.into_iter().next().unwrap())
    .unwrap_or(SqlValue::Null)
}

async fn status_of(tx: &mut dyn SqlTransaction, id: &str) -> String {
    match tx
        .query(
            "SELECT status FROM reference_entity WHERE id = ?1",
            &[t(id)],
        )
        .await
        .unwrap()
        .rows
        .into_iter()
        .next()
    {
        Some(r) => match r.into_iter().next() {
            Some(SqlValue::Text(s)) => s,
            _ => String::new(),
        },
        None => String::new(),
    }
}

// `#[ignore]` by default (same rationale as `orm_tenant_isolation`: a static-musl test binary
// segfaults in libsql's bundled SQLite). The `test-orm-tenancy` CI job runs it unignored on the host
// toolchain and asserts the `CATALOG BASE-WRITE OK` marker.
#[tokio::test]
#[ignore = "run via the test-orm-tenancy CI job on the host toolchain (static-musl test binary segfaults in libsql's bundled SQLite)"]
async fn catalog_base_write_isolates_on_a_real_engine() {
    let dir = std::env::temp_dir().join(format!("boatramp-catalog-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let db = LibsqlSqlBackends::local(&dir)
        .database("default", "catalog", "")
        .await
        .unwrap();

    // reference_entity: a base (NULL) curated row + tenant A's and tenant B's own candidates.
    {
        let mut tx = db.begin().await.unwrap();
        tx.execute(
            "CREATE TABLE reference_entity (id TEXT PRIMARY KEY, tenant_id TEXT, match_key TEXT, status TEXT, name TEXT)",
            &[],
        )
        .await
        .unwrap();
        for (id, tenant, mk, status, name) in [
            ("base1", None, "fair-x", "curated", "Fair X (global)"),
            (
                "a1",
                Some("tenant_A"),
                "fair-x",
                "candidate",
                "A's Fair X proposal",
            ),
            (
                "b1",
                Some("tenant_B"),
                "fair-y",
                "candidate",
                "B's Fair Y proposal",
            ),
        ] {
            tx.execute(
                "INSERT INTO reference_entity (id, tenant_id, match_key, status, name) VALUES (?1,?2,?3,?4,?5)",
                &[t(id), tenant.map_or(SqlValue::Null, t), t(mk), t(status), t(name)],
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    }

    // (1) A base INSERT stamps tenant_id = NULL (joins the shared catalog, not any tenant partition).
    {
        let mut ins = Insert {
            table: "reference_entity".into(),
            rows: vec![RowValues {
                cells: vec![
                    Assignment {
                        column: "id".into(),
                        value: Expr::val(t("base2")),
                    },
                    // A forged tenant_id is overridden to NULL by the base-write stamp.
                    Assignment {
                        column: "tenant_id".into(),
                        value: Expr::val(t("tenant_A")),
                    },
                    Assignment {
                        column: "match_key".into(),
                        value: Expr::val(t("fair-z")),
                    },
                    Assignment {
                        column: "status".into(),
                        value: Expr::val(t("draft")),
                    },
                    Assignment {
                        column: "name".into(),
                        value: Expr::val(t("Fair Z (global)")),
                    },
                ],
            }],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: None,
        };
        ins.force_scope(Some(&base_write()), Some(&base_write()))
            .unwrap();
        let (sql, params) = ins.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        assert_eq!(
            tenant_of(tx.as_mut(), "base2").await,
            SqlValue::Null,
            "a base write stamps tenant_id = NULL (forged tenant ignored)"
        );
        tx.commit().await.unwrap();
    }

    // (2) A base UPDATE confines to tenant_id IS NULL: it curates the base row, and can touch NEITHER
    //     tenant A's nor tenant B's candidate (even the one sharing match_key 'fair-x').
    {
        let mut upd = Update {
            table: "reference_entity".into(),
            set: vec![Assignment {
                column: "status".into(),
                value: Expr::val(t("curated-v2")),
            }],
            filter: Predicate::And(Vec::new()), // all rows the scope admits
            scope: None,
            returning: vec![],
        };
        upd.force_scope(&base_write()).unwrap();
        let (sql, params) = upd.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        assert_eq!(
            status_of(tx.as_mut(), "base1").await,
            "curated-v2",
            "the base UPDATE curates the NULL-base row"
        );
        assert_eq!(
            status_of(tx.as_mut(), "a1").await,
            "candidate",
            "tenant A's candidate (same match_key) is untouched by the base write"
        );
        assert_eq!(
            status_of(tx.as_mut(), "b1").await,
            "candidate",
            "tenant B's candidate is untouched by the base write"
        );
        tx.commit().await.unwrap();
    }

    // (3) An ordinary own-write (tenant A) stamps/confines to A: it curates A's candidate and can
    //     touch NEITHER the base row nor B's.
    {
        let mut upd = Update {
            table: "reference_entity".into(),
            set: vec![Assignment {
                column: "status".into(),
                value: Expr::val(t("a-edited")),
            }],
            filter: Predicate::And(Vec::new()),
            scope: None,
            returning: vec![],
        };
        upd.force_scope(&own_write("tenant_A")).unwrap();
        let (sql, params) = upd.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        assert_eq!(
            status_of(tx.as_mut(), "a1").await,
            "a-edited",
            "A edits its own"
        );
        assert_eq!(
            status_of(tx.as_mut(), "base1").await,
            "curated-v2",
            "A's own-write cannot touch the base row"
        );
        assert_eq!(
            status_of(tx.as_mut(), "b1").await,
            "candidate",
            "A's own-write cannot touch B's candidate"
        );
        tx.commit().await.unwrap();
    }

    // (4) A read on the base-write route still folds base ⊕ its own (NullOnly reads the base only).
    {
        let mut sel = Select {
            columns: vec![item(Expr::col("name"))],
            ..Select::from("reference_entity")
        };
        sel.force_scope(&base_write()).unwrap();
        let (sql, params) = sel.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        let rows = tx.query(&sql, &params).await.unwrap();
        tx.commit().await.unwrap();
        let names: Vec<String> = rows
            .rows
            .into_iter()
            .flatten()
            .filter_map(|v| match v {
                SqlValue::Text(s) => Some(s),
                _ => None,
            })
            .collect();
        assert!(
            names.iter().all(|n| n.contains("global")),
            "a NullOnly read sees ONLY the NULL-base rows, never a tenant candidate: {names:?}"
        );
    }

    // (5) A TARGET route carrying the base-write grant is REFUSED (target + base = cross-boundary).
    {
        let target = Scope {
            column: "tenant_id".into(),
            value: Some(t("tenant_B")),
            session: None,
            mode: ScopeMode::NullOnly,
            keys: TableKeys::PerTableTarget {
                keys: std::collections::BTreeMap::from([(
                    "reference_entity".to_string(),
                    ResolvedScope::TenantOrBase {
                        tenant: "tenant_id".into(),
                    },
                )]),
                public: std::collections::BTreeMap::new(),
                write: std::collections::BTreeSet::from(["name".to_string()]),
                require_public: false,
            },
            unscoped_writes: std::collections::BTreeSet::new(),
            pass_unresolved: false,
        };
        let mut ins = Insert {
            table: "reference_entity".into(),
            rows: vec![RowValues {
                cells: vec![Assignment {
                    column: "name".into(),
                    value: Expr::val(t("sneaky")),
                }],
            }],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: None,
        };
        let err = ins
            .force_scope(Some(&target), Some(&target))
            .expect_err("a target base write must be refused");
        assert!(
            matches!(err, OrmError::TargetBaseWrite(ref tbl) if tbl == "reference_entity"),
            "target base write refused as TargetBaseWrite, got {err:?}"
        );
    }

    println!("CATALOG BASE-WRITE OK");
}
