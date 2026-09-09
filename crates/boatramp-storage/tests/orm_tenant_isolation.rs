//! **Live** proof that the Stage 0 in-site tenant scope actually isolates tenants on a **real**
//! SQL engine (embedded libsql / SQLite), not just in the compiler's string output. This is the
//! [[ignore-gated-tests-not-evidence]] guard for the ORM tenant model: it drives host-scoped
//! queries — built exactly as the host binding builds them (`force_scope` + `compile`) — against
//! a shared database holding two tenants' rows plus a NULL baseline, and asserts each mode reaches
//! only what it should. Runs unconditionally in normal CI (needs only a temp SQLite file), so a
//! cross-tenant regression fails the build, and prints a success marker so a silent skip can't
//! masquerade as a pass.
#![cfg(feature = "sql")]

use boatramp_core::orm::{
    Assignment, CmpOp, Delete, Direction, Expr, Insert, OrderBy, Predicate, RowValues, Scope,
    ScopeMode, Select, SelectItem, TableKeys, Update,
};
use boatramp_core::sql::{Dialect, SqlBackends, SqlTransaction, SqlValue};
use boatramp_storage::LibsqlSqlBackends;

fn t(s: &str) -> SqlValue {
    SqlValue::Text(s.into())
}
fn scope(mode: ScopeMode, value: &str) -> Scope {
    Scope {
        column: "tenant_id".into(),
        value: Some(t(value)),
        session: None,
        mode,
        keys: TableKeys::Uniform,
    }
}
fn item(e: Expr) -> SelectItem {
    SelectItem {
        expr: e,
        alias: None,
    }
}

/// Run a compiled (sql, params) on the backend, returning the single-column text rows sorted.
async fn run_query(tx: &mut dyn SqlTransaction, sql: &str, params: &[SqlValue]) -> Vec<String> {
    let rows = tx.query(sql, params).await.expect("query runs");
    let mut out: Vec<String> = rows
        .rows
        .into_iter()
        .flatten()
        .filter_map(|v| match v {
            SqlValue::Text(s) => Some(s),
            _ => None,
        })
        .collect();
    out.sort();
    out
}

// `#[ignore]` by default so the general workspace test lane skips it (a skip is not evidence
// there): built for the **static-musl** target and run under musl's default malloc, libsql's
// bundled SQLite SIGSEGVs — a test-harness quirk, NOT a logic issue and NOT a production one (the
// shipped musl binary uses jemalloc; managed libsql is proven on musl by the container capability
// gate + real deployments). The dedicated `test-orm-tenancy` CI job runs it **unignored** on the
// host glibc toolchain (`-- --ignored`) and asserts the success marker — that job is the evidence.
#[tokio::test]
#[ignore = "run via the test-orm-tenancy CI job on the host toolchain (static-musl test binary segfaults in libsql's bundled SQLite)"]
async fn orm_in_site_tenant_scope_isolates_on_a_real_engine() {
    let dir = std::env::temp_dir().join(format!("boatramp-orm-tenancy-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let backends = LibsqlSqlBackends::local(&dir);
    let db = backends.database("default", "shop", "").await.unwrap();

    // A shared multi-tenant table: acme + globex rows, plus a NULL-baseline (shared) row.
    {
        let mut tx = db.begin().await.unwrap();
        tx.execute(
            "CREATE TABLE notes (id TEXT PRIMARY KEY, tenant_id TEXT, body TEXT)",
            &[],
        )
        .await
        .unwrap();
        for (id, tenant, body) in [
            ("a1", Some("acme"), "acme-secret"),
            ("g1", Some("globex"), "globex-secret"),
            ("s1", None, "shared-baseline"),
        ] {
            tx.execute(
                "INSERT INTO notes (id, tenant_id, body) VALUES (?1, ?2, ?3)",
                &[t(id), tenant.map_or(SqlValue::Null, t), t(body)],
            )
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();
    }

    // Helper: run a host-scoped SELECT of `body` for the given read mode (as the host would).
    let select_bodies = |mode: ScopeMode, tenant: &str| {
        let mut s = Select {
            columns: vec![item(Expr::col("body"))],
            ..Select::from("notes")
        };
        s.force_scope(&scope(mode, tenant)).unwrap();
        s.compile(Dialect::Sqlite).unwrap()
    };

    // 1) read: own (acme) sees ONLY acme — never globex, never the baseline.
    {
        let mut tx = db.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::Own, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-secret".to_string()],
            "own must be acme-only"
        );
        tx.commit().await.unwrap();
    }

    // 2) own+null (acme) sees acme + the shared baseline, but NOT globex.
    {
        let mut tx = db.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::OwnOrNull, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-secret".to_string(), "shared-baseline".to_string()],
            "own+null = acme + baseline, no globex"
        );
        tx.commit().await.unwrap();
    }

    // 3) null-only sees ONLY the shared baseline.
    {
        let mut tx = db.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::NullOnly, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(got, vec!["shared-baseline".to_string()]);
        tx.commit().await.unwrap();
    }

    // 4) all (cross-tenant) sees everything — the deliberately-opened grant.
    {
        let mut tx = db.begin().await.unwrap();
        let (sql, params) = select_bodies(ScopeMode::All, "acme");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(got.len(), 3, "all sees every row");
        tx.commit().await.unwrap();
    }

    // 5) A scoped INSERT stamps the tenant; a guest-forged tenant_id is overridden to own.
    {
        let mut ins = Insert {
            table: "notes".into(),
            rows: vec![RowValues {
                cells: vec![
                    Assignment {
                        column: "id".into(),
                        value: Expr::val(t("a2")),
                    },
                    Assignment {
                        column: "tenant_id".into(),
                        value: Expr::val(t("globex")), // forgery attempt
                    },
                    Assignment {
                        column: "body".into(),
                        value: Expr::val(t("acme-new")),
                    },
                ],
            }],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: None,
        };
        ins.force_scope(
            Some(&scope(ScopeMode::Own, "acme")),
            Some(&scope(ScopeMode::Own, "acme")),
        )
        .unwrap();
        let (sql, params) = ins.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        // The new row is acme's, not globex's — confirm via the DB.
        let owner = tx
            .query("SELECT tenant_id FROM notes WHERE id = 'a2'", &[])
            .await
            .unwrap();
        assert_eq!(
            owner.rows[0][0],
            t("acme"),
            "insert stamped own, forgery ignored"
        );
        tx.commit().await.unwrap();
    }

    // 6) A scoped UPDATE only touches own rows AND can't reassign the tenant. acme updates its own
    //    body and tries SET tenant_id = globex — globex's row is untouched and acme keeps its rows.
    {
        let mut upd = Update {
            table: "notes".into(),
            set: vec![
                Assignment {
                    column: "tenant_id".into(),
                    value: Expr::val(t("globex")), // reassignment attempt
                },
                Assignment {
                    column: "body".into(),
                    value: Expr::val(t("acme-edited")),
                },
            ],
            filter: Predicate::And(Vec::new()),
            scope: None,
            returning: vec![],
        };
        upd.force_scope(&scope(ScopeMode::Own, "acme")).unwrap();
        let (sql, params) = upd.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        // globex's row is untouched (still globex, still its secret).
        let g = tx
            .query("SELECT body FROM notes WHERE id = 'g1'", &[])
            .await
            .unwrap();
        assert_eq!(
            g.rows[0][0],
            t("globex-secret"),
            "globex row untouched by acme's update"
        );
        // acme's rows are all still acme (tenant never reassigned).
        let owners = run_query(
            tx.as_mut(),
            "SELECT DISTINCT tenant_id FROM notes WHERE body LIKE 'acme%'",
            &[],
        )
        .await;
        assert_eq!(owners, vec!["acme".to_string()], "acme rows stay acme");
        tx.commit().await.unwrap();
    }

    // 7) A scoped DELETE only removes own rows. acme deletes-all → globex + baseline survive.
    {
        let mut del = Delete {
            table: "notes".into(),
            filter: Predicate::And(Vec::new()),
            scope: None,
            returning: vec![],
        };
        del.force_scope(&scope(ScopeMode::Own, "acme")).unwrap();
        let (sql, params) = del.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        let survivors = run_query(tx.as_mut(), "SELECT id FROM notes", &[]).await;
        assert_eq!(
            survivors,
            vec!["g1".to_string(), "s1".to_string()],
            "acme's DELETE-all left globex + baseline"
        );
        tx.commit().await.unwrap();
    }

    // 8) A scoped SELECT with a guest JOIN scopes BOTH tables — a joined victim table can't leak.
    {
        let mut tx = db.begin().await.unwrap();
        tx.execute(
            "CREATE TABLE lines (id TEXT, tenant_id TEXT, note_id TEXT, detail TEXT)",
            &[],
        )
        .await
        .unwrap();
        // Re-seed a globex note + globex + acme lines to prove the join can't reach globex lines.
        tx.execute(
            "INSERT INTO notes (id, tenant_id, body) VALUES ('g2','globex','g-body')",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO lines (id, tenant_id, note_id, detail) VALUES ('l_a','globex','g2','GLOBEX-LINE'),('l_b','globex','g2','GLOBEX-LINE2')",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // acme, own: SELECT detail FROM notes o JOIN lines l ON l.note_id = o.id.
        let mut sel = Select {
            table: "notes".into(),
            table_alias: Some("o".into()),
            columns: vec![item(Expr::col("l.detail"))],
            joins: vec![boatramp_core::orm::Join {
                kind: boatramp_core::orm::JoinKind::Inner,
                table: "lines".into(),
                alias: Some("l".into()),
                on: Predicate::Cmp {
                    left: Expr::col("l.note_id"),
                    op: CmpOp::Eq,
                    right: Expr::col("o.id"),
                },
            }],
            ..Select::from("notes")
        };
        sel.force_scope(&scope(ScopeMode::Own, "acme")).unwrap();
        let (sql, params) = sel.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert!(
            got.is_empty(),
            "a scoped join must not surface globex's lines, got {got:?}"
        );
        tx.commit().await.unwrap();
    }

    // 9) own_first(): on an own+null read, the tenant's override sorts ahead of the shared base
    //    (and falls back to the base with no override) — `ORDER BY is_own DESC LIMIT 1`, without
    //    the guest naming tenant_id.
    {
        let mut tx = db.begin().await.unwrap();
        tx.execute(
            "INSERT INTO notes (id, tenant_id, body) VALUES \
             ('ovr_b', NULL, 'pref-base'), ('ovr_o', 'acme', 'pref-own'), ('base_only', NULL, 'only-base')",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let own_first = |tenant: &str, like: &str| {
            let mut s = Select {
                columns: vec![item(Expr::col("body"))],
                filter: Some(Predicate::Like {
                    expr: Expr::col("body"),
                    pattern: like.to_string(),
                    insensitive: false,
                    negated: false,
                }),
                order: vec![OrderBy {
                    expr: Expr::IsOwn,
                    dir: Direction::Desc,
                }],
                limit: Some(1),
                ..Select::from("notes")
            };
            s.force_scope(&scope(ScopeMode::OwnOrNull, tenant)).unwrap();
            s.compile(Dialect::Sqlite).unwrap()
        };

        let mut tx = db.begin().await.unwrap();
        let (sql, params) = own_first("acme", "pref-%");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["pref-own".to_string()],
            "own_first returns the tenant's override over the base"
        );
        let (sql, params) = own_first("globex", "only-%");
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["only-base".to_string()],
            "own_first falls back to the shared base when there's no override"
        );
        tx.commit().await.unwrap();
    }

    println!(
        "ORM IN-SITE TENANT ISOLATION OK: own=acme-only, own+null=acme+baseline, null=baseline, \
         all=every-row; scoped insert stamps own (forgery ignored); scoped update/delete touch \
         own only and can't reassign tenant; a scoped JOIN can't reach another tenant's table; \
         own_first prefers the tenant's override over the base"
    );
}

/// **Live** proof of the Stage 1 *per-table-key* tenancy model on a real libsql engine — the
/// project [`TenancySchema`](boatramp_core::tenancy::TenancySchema) is authoritative and each
/// table-ref is scoped on the key the schema declares for **that** table, not one global column:
///
///   * a `Tenant` table (`orders`) is scoped on the schema's `default_tenant_key` (`tenant_id`);
///   * a `TenantKeyed` **identity** table (`tenant`) is scoped on its own PK (`id`) — the carve-out
///     that lets a tenant read its *own* row from a table that has no `tenant_id` column at all;
///   * an `Unscoped` reference table (`countries`) gets **no** tenant predicate (globally readable);
///   * an **undeclared** table (`secrets_shadow`) is **refused at compile** (deny-by-default) — no
///     SQL ever reaches the engine.
///
/// The [`Scope`] is built exactly as the host builds it —
/// `HostTenancy::with_schema(&schema).orm_scope()` yields `column = default_tenant_key`,
/// `keys = PerTable(schema.table_key_map())` — so this exercises the real injector, not a
/// hand-rolled predicate. A **control** proves the per-table key is load-bearing: a legacy
/// `Uniform` `tenant_id` scope on the identity table compiles to `tenant_id = ?` and the engine
/// **rejects** it (no such column), which the schema-driven per-table key avoids.
///
/// Same `#[ignore]` rationale as the sibling above (static-musl libsql segfault); the
/// `test-orm-tenancy` CI job runs it unignored on the host toolchain and greps the marker.
#[tokio::test]
#[ignore = "run via the test-orm-tenancy CI job on the host toolchain (static-musl test binary segfaults in libsql's bundled SQLite)"]
async fn orm_per_table_key_scope_isolates_on_a_real_engine() {
    use boatramp_core::orm::{Join, JoinKind};
    use boatramp_core::tenancy::{TableScope, TenancySchema};
    use std::collections::BTreeMap;

    let dir = std::env::temp_dir().join(format!("boatramp-orm-pertable-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let backends = LibsqlSqlBackends::local(&dir);
    let db = backends.database("default", "shop", "").await.unwrap();

    // The project's declared schema: `orders` keyed on the default `tenant_id`; the identity
    // table `tenant` keyed on its own PK `id`; `member` keyed on `account_id` (a real key that is
    // NOT the default, and the table ALSO carries a shared/denormalized `tenant_id` — the exact
    // shape a wrong-key subquery would leak through); `countries` a global reference (Unscoped).
    // `secrets_shadow` is DELIBERATELY absent → deny-by-default.
    let schema = TenancySchema {
        default_tenant_key: "tenant_id".into(),
        session_key: None,
        tables: BTreeMap::from([
            ("orders".into(), TableScope::Tenant),
            (
                "tenant".into(),
                TableScope::TenantKeyed { key: "id".into() },
            ),
            (
                "member".into(),
                TableScope::TenantKeyed {
                    key: "account_id".into(),
                },
            ),
            ("countries".into(), TableScope::Unscoped),
        ]),
        ..Default::default()
    };
    // Build the scope exactly as `HostTenancy::with_schema(&schema).orm_scope()` does.
    let keys = TableKeys::PerTable(schema.table_key_map());
    let scope_for = |tenant: &str| Scope {
        column: "tenant_id".into(),
        value: Some(t(tenant)),
        session: None,
        mode: ScopeMode::Own,
        keys: keys.clone(),
    };

    // Seed: two tenants' orders; a `tenant` identity table whose PK IS the tenant (no tenant_id
    // column); a global `countries` reference (no tenant_id column).
    {
        let mut tx = db.begin().await.unwrap();
        tx.execute(
            "CREATE TABLE orders (id TEXT PRIMARY KEY, tenant_id TEXT, item TEXT)",
            &[],
        )
        .await
        .unwrap();
        tx.execute("CREATE TABLE tenant (id TEXT PRIMARY KEY, plan TEXT)", &[])
            .await
            .unwrap();
        tx.execute(
            "CREATE TABLE countries (code TEXT PRIMARY KEY, name TEXT)",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO orders (id, tenant_id, item) VALUES ('o_a','acme','acme-widget'),('o_g','globex','globex-gadget')",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO tenant (id, plan) VALUES ('acme','pro'),('globex','free')",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO countries (code, name) VALUES ('US','United States'),('FR','France')",
            &[],
        )
        .await
        .unwrap();
        // `member(account_id, tenant_id, secret)`: BOTH rows share `tenant_id='acme'` (a
        // denormalized/forged shared value) while `account_id` is the real isolation key. So a
        // subquery wrongly scoped on `tenant_id` would surface globex's secret to acme; a subquery
        // correctly scoped on the declared `account_id` cannot.
        tx.execute(
            "CREATE TABLE member (account_id TEXT PRIMARY KEY, tenant_id TEXT, secret TEXT)",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO member (account_id, tenant_id, secret) VALUES ('acme','acme','acme-secret'),('globex','acme','globex-secret')",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    // 1) `orders` (Tenant) scoped on `tenant_id` → acme sees ONLY its own order.
    {
        let mut s = Select {
            columns: vec![item(Expr::col("item"))],
            ..Select::from("orders")
        };
        s.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = s.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(got, vec!["acme-widget".to_string()], "orders is acme-only");
        tx.commit().await.unwrap();
    }

    // 2) `tenant` (TenantKeyed on `id`) scoped on its OWN PK → acme sees only id='acme'. The
    //    generated predicate names `id`, not `tenant_id` (which this table lacks).
    {
        let mut s = Select {
            columns: vec![item(Expr::col("plan"))],
            ..Select::from("tenant")
        };
        s.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = s.compile(Dialect::Sqlite).unwrap();
        assert!(
            sql.contains("id = ?") && !sql.contains("tenant_id = ?"),
            "identity table must scope on its own PK `id`, not tenant_id: {sql}"
        );
        let mut tx = db.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["pro".to_string()],
            "acme sees only its own identity row"
        );
        tx.commit().await.unwrap();
    }

    // 2b) CONTROL — the per-table key is load-bearing, not cosmetic: a legacy `Uniform`
    //     `tenant_id` scope on the identity table compiles to `tenant_id = ?` and the REAL engine
    //     rejects it (no such column). The schema-driven per-table key is what avoids this.
    {
        let mut bad = Select {
            columns: vec![item(Expr::col("plan"))],
            ..Select::from("tenant")
        };
        bad.force_scope(&Scope {
            column: "tenant_id".into(),
            value: Some(t("acme")),
            session: None,
            mode: ScopeMode::Own,
            keys: TableKeys::Uniform,
        })
        .unwrap();
        let (bad_sql, bad_params) = bad.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        assert!(
            tx.query(&bad_sql, &bad_params).await.is_err(),
            "a uniform tenant_id scope must FAIL on the identity table (no such column): {bad_sql}"
        );
    }

    // 3) `countries` (Unscoped) → NO tenant predicate: acme sees EVERY country (global reference).
    {
        let mut s = Select {
            columns: vec![item(Expr::col("name"))],
            ..Select::from("countries")
        };
        s.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = s.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["France".to_string(), "United States".to_string()],
            "an Unscoped reference table is globally readable"
        );
        tx.commit().await.unwrap();
    }

    // 4) A JOIN scopes EACH ref on ITS OWN key: `o.tenant_id = acme AND t.id = acme`. acme's
    //    joined row surfaces; globex can't leak in through either side.
    {
        let mut sel = Select {
            table: "orders".into(),
            table_alias: Some("o".into()),
            columns: vec![item(Expr::col("o.item"))],
            joins: vec![Join {
                kind: JoinKind::Inner,
                table: "tenant".into(),
                alias: Some("t".into()),
                on: Predicate::Cmp {
                    left: Expr::col("t.id"),
                    op: CmpOp::Eq,
                    right: Expr::col("o.tenant_id"),
                },
            }],
            ..Select::from("orders")
        };
        sel.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = sel.compile(Dialect::Sqlite).unwrap();
        assert!(
            sql.contains("o.tenant_id = ?") && sql.contains("t.id = ?"),
            "each joined ref scoped on its own key: {sql}"
        );
        let mut tx = db.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-widget".to_string()],
            "the join surfaces only acme's row"
        );
        tx.commit().await.unwrap();
    }

    // 5) DENY-BY-DEFAULT: a SELECT on the UNDECLARED table is refused at compile — no SQL emitted.
    {
        let mut undeclared = Select {
            columns: vec![item(Expr::col("v"))],
            ..Select::from("secrets_shadow")
        };
        undeclared.force_scope(&scope_for("acme")).unwrap();
        assert!(
            matches!(
                undeclared.compile(Dialect::Sqlite),
                Err(boatramp_core::orm::OrmError::TenancyUndeclared(tbl)) if tbl == "secrets_shadow"
            ),
            "an undeclared table must be refused, not silently unscoped"
        );
    }

    // 6) SUBQUERY keyed correctly (the CRITICAL regression guard): an `IN (SELECT … FROM member …)`
    //    scopes the subquery's `member` table on its DECLARED key `account_id`, never the default
    //    `tenant_id`. Because both member rows share `tenant_id='acme'`, a wrong key on `tenant_id`
    //    would surface globex's row to the subquery — the exact cross-tenant leak. The SQL-shape
    //    assertion fails closed if the subquery injector ever regresses to `scope.column`.
    {
        let mut s = Select {
            table: "orders".into(),
            table_alias: Some("o".into()),
            columns: vec![item(Expr::col("o.item"))],
            filter: Some(Predicate::InSubquery {
                expr: Expr::col("o.tenant_id"),
                column: "account_id".into(),
                table: "member".into(),
                filter: Box::new(Predicate::And(Vec::new())),
                negated: false,
            }),
            ..Select::from("orders")
        };
        s.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = s.compile(Dialect::Sqlite).unwrap();
        assert!(
            sql.contains("member.account_id = ?"),
            "subquery must scope member on its declared key account_id: {sql}"
        );
        assert!(
            !sql.contains("member.tenant_id"),
            "subquery must NOT scope member on the default tenant_id (the cross-tenant leak): {sql}"
        );
        let mut tx = db.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-widget".to_string()],
            "the subquery-filtered read stays acme-only and the SQL is valid on a real engine"
        );
        tx.commit().await.unwrap();
    }

    // 7) SUBQUERY on an `Unscoped` reference table adds NO tenant predicate to that subquery.
    {
        let mut s = Select {
            table: "orders".into(),
            table_alias: Some("o".into()),
            columns: vec![item(Expr::col("o.item"))],
            filter: Some(Predicate::InSubquery {
                expr: Expr::col("o.item"),
                column: "code".into(),
                table: "countries".into(),
                filter: Box::new(Predicate::And(Vec::new())),
                negated: true, // NOT IN, so a real reference lookup that doesn't filter everything out
            }),
            ..Select::from("orders")
        };
        s.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = s.compile(Dialect::Sqlite).unwrap();
        assert!(
            !sql.contains("countries."),
            "an Unscoped subquery table must carry no tenant predicate: {sql}"
        );
        let mut tx = db.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-widget".to_string()],
            "unscoped subquery is a plain reference"
        );
        tx.commit().await.unwrap();
    }

    // 8) SUBQUERY deny-by-default (the other half of the CRITICAL fix): an `IN (SELECT … FROM
    //    <undeclared> …)` is REFUSED at scope injection — `force_scope` returns `TenancyUndeclared`
    //    and no SQL is ever built. Before the fix the injector silently emitted `<undeclared>.
    //    tenant_id = ?`, voiding deny-by-default for the entire subquery surface.
    {
        let mut s = Select {
            columns: vec![item(Expr::col("item"))],
            filter: Some(Predicate::InSubquery {
                expr: Expr::col("id"),
                column: "v".into(),
                table: "secrets_shadow".into(),
                filter: Box::new(Predicate::And(Vec::new())),
                negated: false,
            }),
            ..Select::from("orders")
        };
        assert!(
            matches!(
                s.force_scope(&scope_for("acme")),
                Err(boatramp_core::orm::OrmError::TenancyUndeclared(tbl)) if tbl == "secrets_shadow"
            ),
            "a subquery on an undeclared table must be refused at injection, not silently scoped"
        );
    }

    // Helper: `WHERE <col> = <text>`.
    let eq = |col: &str, v: &str| Predicate::Cmp {
        left: Expr::col(col),
        op: CmpOp::Eq,
        right: Expr::Value(t(v)),
    };

    // 9) WRITE target keyed on its DECLARED column (the write-axis counterpart of case 6): a guest
    //    DELETE that targets globex's row by a non-tenant predicate is scoped on `member.account_id`
    //    — NOT the shared `tenant_id` (='acme' on both rows) — so as acme it matches ZERO rows and
    //    cannot delete globex's row cross-tenant. A `tenant_id`-keyed DELETE (the pre-fix bug) would
    //    delete it. The affected-row count is the proof; the SQL-shape assertion guards a revert.
    {
        let mut del = Delete {
            table: "member".into(),
            filter: eq("secret", "globex-secret"),
            scope: None,
            returning: vec![],
        };
        del.force_scope(&scope_for("acme")).unwrap();
        let (sql, params) = del.compile(Dialect::Sqlite).unwrap();
        assert!(
            sql.contains("account_id = ?") && !sql.contains("tenant_id = ?"),
            "DELETE must bound member on its declared key account_id: {sql}"
        );
        let mut tx = db.begin().await.unwrap();
        let affected = tx.execute(&sql, &params).await.unwrap();
        assert_eq!(
            affected, 0,
            "acme's DELETE keyed on account_id must not reach globex's row"
        );
        tx.commit().await.unwrap();
    }

    // 10) WRITE deny-by-default: a DELETE (or UPDATE/INSERT) targeting an UNDECLARED table is
    //     refused at compile — the write axis is no weaker than the read axis.
    {
        let mut del = Delete {
            table: "secrets_shadow".into(),
            filter: eq("x", "y"),
            scope: None,
            returning: vec![],
        };
        del.force_scope(&scope_for("acme")).unwrap();
        assert!(
            matches!(
                del.compile(Dialect::Sqlite),
                Err(boatramp_core::orm::OrmError::TenancyUndeclared(tbl)) if tbl == "secrets_shadow"
            ),
            "an undeclared write target must be refused deny-by-default"
        );
    }

    // 11) UPDATE is bounded on the declared key AND the tenant column can't be reassigned: a guest
    //     `SET account_id = 'globex'` is dropped (never donate a row to another tenant), and the
    //     WHERE is keyed on `account_id`, not the default `tenant_id`.
    {
        let mut upd = Update {
            table: "member".into(),
            set: vec![
                Assignment {
                    column: "account_id".into(), // reassignment attempt — must be dropped
                    value: Expr::val(t("globex")),
                },
                Assignment {
                    column: "secret".into(),
                    value: Expr::val(t("edited")),
                },
            ],
            filter: eq("secret", "acme-secret"),
            scope: None,
            returning: vec![],
        };
        upd.force_scope(&scope_for("acme")).unwrap();
        let (sql, _params) = upd.compile(Dialect::Sqlite).unwrap();
        assert!(
            sql.contains("account_id = ?"),
            "UPDATE must bound member on its declared key account_id: {sql}"
        );
        assert!(
            !sql.contains("SET account_id") && sql.contains("SET secret ="),
            "the tenant-key assignment must be dropped (no tenant reassignment): {sql}"
        );
    }

    // 12) WRITE to an `Unscoped` (global reference) table is REFUSED — reads of `countries` are
    //     global (case 3), but a guest write to it is a cross-tenant blast, so it is deny-by-default
    //     (the TableScope::Unscoped contract). Every write verb refuses it.
    {
        let mut del = Delete {
            table: "countries".into(),
            filter: eq("code", "US"),
            scope: None,
            returning: vec![],
        };
        del.force_scope(&scope_for("acme")).unwrap();
        assert!(
            matches!(
                del.compile(Dialect::Sqlite),
                Err(boatramp_core::orm::OrmError::UnscopedWrite(tbl)) if tbl == "countries"
            ),
            "a guest write to an Unscoped reference table must be refused"
        );
        // INSERT into an Unscoped table is refused at force_scope (target-column resolution).
        let mut ins = Insert {
            table: "countries".into(),
            rows: vec![RowValues {
                cells: vec![Assignment {
                    column: "code".into(),
                    value: Expr::val(t("XX")),
                }],
            }],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: None,
        };
        assert!(
            matches!(
                ins.force_scope(Some(&scope_for("acme")), Some(&scope_for("acme"))),
                Err(boatramp_core::orm::OrmError::UnscopedWrite(tbl)) if tbl == "countries"
            ),
            "a guest INSERT into an Unscoped reference table must be refused"
        );
    }

    println!(
        "ORM PER-TABLE-KEY TENANCY OK: Tenant table scoped on default tenant_id; identity \
         TenantKeyed table scoped on its own PK (uniform tenant_id scope rejected by the engine — \
         key is load-bearing); Unscoped reference table globally readable; per-ref join keys each \
         on its own column; a subquery scopes its inner table on that table's declared key (never \
         the default) and is refused deny-by-default on an undeclared table; a WRITE (UPDATE/DELETE/\
         INSERT) is bounded + stamped on the target's declared key, can't reassign the tenant, \
         refuses an undeclared target, AND refuses a write to an Unscoped reference table; a \
         top-level undeclared table refused deny-by-default"
    );
}

/// **Live** proof of the Stage 3 R3 **anonymous-first disjunct** (`TableScope::TenantOrSession`) on a
/// real libsql engine: a table whose rows are owned EITHER by a resolved tenant (`tenant_id = T`) OR
/// by an anonymous session (`session_id = S`, on `tenant_id IS NULL` rows). Proves, end to end, that
///   * an anonymous (`Session`-only) actor reads/writes **only its own session** rows — never another
///     session's, never any tenant's (the disjoint columns confine it structurally);
///   * an authenticated (`Tenant`-only) actor reads **only its tenant** rows;
///   * an actor carrying BOTH facts reads the **union** `Or([tenant_id = T, session_id = S])`;
///   * an anonymous WRITE stamps `session_id = S` (with `tenant_id` NULL), landing in the session
///     partition, and cannot forge a tenant;
///   * a `TenantOrSession` read with **no** principal (neither fact) is **refused** (fail closed).
///
/// The [`Scope`] is built exactly as `HostTenancy::with_schema(&schema).orm_scope()` yields it:
/// `keys = PerTable(schema.table_key_map())` with the `TenantOrSession { tenant_id, session_id }`
/// resolution, `value` = the tenant fact (or `None`), `session` = the session fact. Same `#[ignore]`
/// rationale + `test-orm-tenancy` CI gate as the siblings above.
#[tokio::test]
#[ignore = "run via the test-orm-tenancy CI job on the host toolchain (static-musl test binary segfaults in libsql's bundled SQLite)"]
async fn orm_tenant_or_session_disjunct_isolates_on_a_real_engine() {
    use boatramp_core::tenancy::{TableScope, TenancySchema};
    use std::collections::BTreeMap;

    let dir = std::env::temp_dir().join(format!("boatramp-orm-tos-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let backends = LibsqlSqlBackends::local(&dir);
    let db = backends.database("default", "shop", "").await.unwrap();

    // `carts` is anonymous-first: a resolved tenant owns `tenant_id = T` rows; an anon session owns
    // `session_id = S` rows (with `tenant_id` NULL). The schema declares it `TenantOrSession` and
    // sets `session_key`.
    let schema = TenancySchema {
        default_tenant_key: "tenant_id".into(),
        session_key: Some("session_id".into()),
        tables: BTreeMap::from([("carts".into(), TableScope::TenantOrSession)]),
        ..Default::default()
    };
    let keys = TableKeys::PerTable(schema.table_key_map());
    // A read/write scope carrying whichever axis facts the request holds (mode `own`).
    let scope = |tenant: Option<&str>, session: Option<&str>| Scope {
        column: "tenant_id".into(),
        value: tenant.map(t),
        session: session.map(t),
        mode: ScopeMode::Own,
        keys: keys.clone(),
    };

    {
        let mut tx = db.begin().await.unwrap();
        tx.execute(
            "CREATE TABLE carts (id TEXT PRIMARY KEY, tenant_id TEXT, session_id TEXT, item TEXT)",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO carts (id, tenant_id, session_id, item) VALUES \
             ('c_acme','acme',NULL,'acme-cart'), \
             ('c_glob','globex',NULL,'globex-cart'), \
             ('c_s1',NULL,'sess-1','anon-cart-1'), \
             ('c_s2',NULL,'sess-2','anon-cart-2')",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    // Helper: SELECT item FROM carts under `scope`, sorted.
    let read_items = |sc: &Scope| {
        let mut s = Select {
            columns: vec![item(Expr::col("item"))],
            ..Select::from("carts")
        };
        s.force_scope(sc).unwrap();
        s.compile(Dialect::Sqlite).unwrap()
    };

    // 1) Anonymous (session-only) actor reads ONLY its own session's rows — never another session's,
    //    never any tenant's. The predicate keys on `session_id`, not `tenant_id`.
    {
        let (sql, params) = read_items(&scope(None, Some("sess-1")));
        assert!(
            sql.contains("session_id = ?") && !sql.contains("tenant_id = ?"),
            "anon read must key on session_id only: {sql}"
        );
        let mut tx = db.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["anon-cart-1".to_string()],
            "anon session reads only its own cart"
        );
        tx.commit().await.unwrap();
    }

    // 2) Authenticated (tenant-only) actor reads ONLY its tenant's rows.
    {
        let (sql, params) = read_items(&scope(Some("acme"), None));
        assert!(
            sql.contains("tenant_id = ?") && !sql.contains("session_id = ?"),
            "authed read must key on tenant_id only: {sql}"
        );
        let mut tx = db.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-cart".to_string()],
            "tenant reads only its cart"
        );
        tx.commit().await.unwrap();
    }

    // 3) An actor carrying BOTH facts reads the disjunction `Or([tenant_id = T, session_id = S])` —
    //    its tenant rows PLUS its anon-session rows, and nothing else.
    {
        let (sql, params) = read_items(&scope(Some("acme"), Some("sess-1")));
        assert!(
            sql.contains("tenant_id = ?") && sql.contains("session_id = ?"),
            "combined read must Or both axes: {sql}"
        );
        let mut tx = db.begin().await.unwrap();
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-cart".to_string(), "anon-cart-1".to_string()],
            "both-fact read = own tenant + own session, nothing else"
        );
        tx.commit().await.unwrap();
    }

    // 4) An anonymous WRITE stamps `session_id = S` (tenant_id NULL) — lands in the session partition,
    //    can't forge a tenant. Insert a guest-forged tenant_id + session_id; the host overrides both.
    {
        let mut ins = Insert {
            table: "carts".into(),
            rows: vec![RowValues {
                cells: vec![
                    Assignment {
                        column: "id".into(),
                        value: Expr::val(t("c_new")),
                    },
                    Assignment {
                        column: "tenant_id".into(),
                        value: Expr::val(t("globex")), // forgery — must be dropped (anon has no tenant)
                    },
                    Assignment {
                        column: "session_id".into(),
                        value: Expr::val(t("sess-EVIL")), // forgery — must be host-overridden to sess-1
                    },
                    Assignment {
                        column: "item".into(),
                        value: Expr::val(t("new-anon")),
                    },
                ],
            }],
            conflict: None,
            scope: None,
            returning: vec![],
            from_select: None,
        };
        let sc = scope(None, Some("sess-1"));
        ins.force_scope(Some(&sc), Some(&sc)).unwrap();
        let (sql, params) = ins.compile(Dialect::Sqlite).unwrap();
        let mut tx = db.begin().await.unwrap();
        tx.execute(&sql, &params).await.unwrap();
        // The new row is session sess-1's, not the forged session/tenant.
        let row = tx
            .query(
                "SELECT tenant_id, session_id FROM carts WHERE id = 'c_new'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(
            row.rows[0][1],
            t("sess-1"),
            "anon write stamped its own session"
        );
        assert_ne!(
            row.rows[0][1],
            t("sess-EVIL"),
            "the guest-forged session must be overridden"
        );
        tx.commit().await.unwrap();
    }

    // 5) A `TenantOrSession` read with NO principal (neither a tenant nor a session fact) is refused
    //    at compile — fail closed, never an unscoped read of every cart.
    {
        let mut s = Select {
            columns: vec![item(Expr::col("item"))],
            ..Select::from("carts")
        };
        s.force_scope(&scope(None, None)).unwrap();
        assert!(
            matches!(
                s.compile(Dialect::Sqlite),
                Err(boatramp_core::orm::OrmError::TenancyNoPrincipal)
            ),
            "a TenantOrSession read with no principal must be refused"
        );
    }

    // 6) PROMOTE (D7): a returning visitor authenticates as `acme` and claims their sess-1 rows. The
    //    verb lowers to `UPDATE carts SET tenant_id = ? WHERE (session_id = ? AND tenant_id IS NULL)`
    //    — the `IS NULL` anti-widening guard means it can ONLY claim not-yet-owned session rows.
    {
        let sc = scope(Some("acme"), Some("sess-1"));
        let (sql, params) =
            boatramp_core::orm::compile_promote(&sc, "carts", Dialect::Sqlite).unwrap();
        assert!(
            sql.contains("SET tenant_id = ?")
                && sql.contains("session_id = ?")
                && sql.contains("tenant_id IS NULL"),
            "promote must set tenant_id where session matches AND tenant IS NULL: {sql}"
        );
        let mut tx = db.begin().await.unwrap();
        let affected = tx.execute(&sql, &params).await.unwrap();
        assert_eq!(
            affected, 1,
            "promote claims exactly sess-1's one not-yet-owned cart"
        );
        // sess-1's cart is now acme's (session_id preserved); acme (tenant-only) now reads it.
        let acme_carts = {
            let (rsql, rparams) = read_items(&scope(Some("acme"), None));
            run_query(tx.as_mut(), &rsql, &rparams).await
        };
        assert_eq!(
            acme_carts,
            vec!["acme-cart".to_string(), "anon-cart-1".to_string()],
            "after promote, acme owns its original cart + the claimed session cart"
        );
        // Anti-widening: sess-2's cart was NOT claimed (different session) and stays anon.
        let sess2 = {
            let (rsql, rparams) = read_items(&scope(None, Some("sess-2")));
            run_query(tx.as_mut(), &rsql, &rparams).await
        };
        assert_eq!(
            sess2,
            vec!["anon-cart-2".to_string()],
            "a different session's cart is untouched by acme's promotion"
        );
        // Idempotent / race-safe: a second promote matches nothing (the rows are no longer NULL).
        let (sql2, params2) =
            boatramp_core::orm::compile_promote(&sc, "carts", Dialect::Sqlite).unwrap();
        assert_eq!(
            tx.execute(&sql2, &params2).await.unwrap(),
            0,
            "re-promoting is a no-op (IS NULL guard)"
        );
        tx.commit().await.unwrap();
    }

    // 7) Promote is deny-by-default: it needs BOTH facts (an anon-only or tenant-only principal is
    //    refused), and only on a TenantOrSession table.
    {
        assert!(
            matches!(
                boatramp_core::orm::compile_promote(
                    &scope(None, Some("sess-1")),
                    "carts",
                    Dialect::Sqlite
                ),
                Err(boatramp_core::orm::OrmError::TenancyNoPrincipal)
            ),
            "promote with no tenant fact must be refused"
        );
        assert!(
            matches!(
                boatramp_core::orm::compile_promote(
                    &scope(Some("acme"), None),
                    "carts",
                    Dialect::Sqlite
                ),
                Err(boatramp_core::orm::OrmError::TenancyNoPrincipal)
            ),
            "promote with no session fact must be refused"
        );
    }

    println!(
        "ORM TENANT-OR-SESSION DISJUNCT OK: anon session reads/writes only its own session rows \
         (keyed on session_id, never tenant_id); an authenticated actor reads only its tenant rows; \
         both-fact reads the Or of the two disjoint columns; an anon write stamps its own session \
         (forged tenant/session overridden); a read with no principal is refused deny-by-default; \
         promote (D7) claims only this session's not-yet-owned rows (IS NULL anti-widening, \
         idempotent), needs both facts, and can't touch another session's or tenant's rows"
    );
}

/// **Live** proof of the Stage 4 *durable signed-context* lane (R1) end-to-end on real
/// infrastructure: a producer publishes to a **real** messaging store (`LogMessaging` over a
/// temp-dir blob store + in-memory KV) with a host-minted COSE signed-context envelope
/// (`mint_context`, signed by a real `LocalSigner`); the envelope survives the durable
/// publish→claim round-trip on **both** the default work-queue and a consumer group (the grouped
/// path re-reads the index record via `read_ctx`); the consumer verifies it against the fleet
/// anchor (`verify_context`) and the recovered tenant scopes a query on a **real** libsql engine to
/// that tenant's rows only. Two fail-closed cases: a **stranger-signed** envelope fails
/// verification, and an **unstamped** publish carries no context — in both the consumer recovers
/// **no** tenant, so an "own" op fails closed (the `boatramp-server` resolver's `SignedContext`
/// arm, unit-tested there, returns `None` for exactly these inputs).
///
/// Boundary: this battery lives in `boatramp-storage` (no dep on `boatramp-server`), so it drives
/// the real durable store + real crypto + real engine and replicates the consumer's one-line
/// resolution (`verify_context` → tenant → [`Scope`]); the server glue that turns a verified tenant
/// into `FnTenant::Durable`→`resolve_host_tenancy` is covered by the server unit test. Same
/// `#[ignore]` rationale as the siblings (static-musl libsql segfault); the `test-orm-tenancy` CI
/// job runs it unignored on the host toolchain and greps the marker.
#[tokio::test]
#[ignore = "run via the test-orm-tenancy CI job on the host toolchain (static-musl test binary segfaults in libsql's bundled SQLite)"]
async fn orm_durable_signed_context_isolates_on_a_real_engine() {
    use boatramp_core::cose::{mint_context, verify_context, LocalSigner, Signer, TokenAlg};
    use boatramp_core::kv::{KvStore, MemoryKv};
    use boatramp_core::messaging::{LogMessaging, Messaging, StartPosition};
    use boatramp_core::Storage;
    use std::sync::Arc;
    use std::time::Duration;

    let now = boatramp_core::time::now_unix();

    // A real durable messaging store: a temp-dir blob store for payloads + an in-memory KV for the
    // index records the signed context rides on (exactly the shape `LogMessaging` uses in prod).
    let mqdir =
        std::env::temp_dir().join(format!("boatramp-durable-ctx-mq-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&mqdir);
    let storage: Arc<dyn Storage> = Arc::new(boatramp_storage::FsStorage::new(&mqdir));
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let mq = LogMessaging::new(storage, kv);

    // The fleet signer mints + verifies the durable context envelope; a *stranger* signer models a
    // forger who does not hold the fleet key.
    let fleet = LocalSigner::generate(TokenAlg::Es256);
    let anchor = fleet.public_key();
    let stranger = LocalSigner::generate(TokenAlg::Es256);

    // A shared multi-tenant table on a real libsql engine: acme + globex rows.
    let dbdir =
        std::env::temp_dir().join(format!("boatramp-durable-ctx-db-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dbdir);
    let backends = LibsqlSqlBackends::local(&dbdir);
    let db = backends.database("default", "shop", "").await.unwrap();
    {
        let mut tx = db.begin().await.unwrap();
        tx.execute(
            "CREATE TABLE notes (id TEXT PRIMARY KEY, tenant_id TEXT, body TEXT)",
            &[],
        )
        .await
        .unwrap();
        tx.execute(
            "INSERT INTO notes VALUES ('1','acme','acme-note'), ('2','globex','globex-note')",
            &[],
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();
    }

    // The consumer's own-scoped SELECT, built exactly as the host builds it from the recovered
    // tenant (`force_scope` + `compile`) — the same injector the other batteries exercise.
    let scoped_bodies = |tenant: &str| {
        let mut s = Select {
            columns: vec![item(Expr::col("body"))],
            ..Select::from("notes")
        };
        s.force_scope(&scope(ScopeMode::Own, tenant)).unwrap();
        s.compile(Dialect::Sqlite).unwrap()
    };

    // The host-minted envelope carrying acme's own-tenant (the guest never names it).
    let envelope = mint_context("acme", 3600, now, &fleet).await.unwrap();

    // 1) DEFAULT WORK-QUEUE: publish stamps the context; claim carries it back verbatim.
    mq.publish_ctx("jobs-ok", b"job", Some(&envelope))
        .await
        .unwrap();
    let claimed = mq
        .claim("jobs-ok", Duration::from_secs(30), 10, 5)
        .await
        .unwrap();
    assert_eq!(claimed.len(), 1, "the published message is claimable");
    assert_eq!(
        claimed[0].signed_context.as_deref(),
        Some(envelope.as_str()),
        "the signed context survives the durable publish->claim round-trip (work-queue)"
    );
    // The consumer verifies against the fleet anchor and recovers acme, then scopes the real engine.
    let tenant =
        verify_context(claimed[0].signed_context.as_deref().unwrap(), &anchor, now).unwrap();
    assert_eq!(tenant, "acme");
    {
        let mut tx = db.begin().await.unwrap();
        let (sql, params) = scoped_bodies(&tenant);
        let got = run_query(tx.as_mut(), &sql, &params).await;
        assert_eq!(
            got,
            vec!["acme-note".to_string()],
            "the recovered tenant scopes the real engine to acme's rows only (never globex)"
        );
        tx.commit().await.unwrap();
    }

    // 2) CONSUMER GROUP (fan-out): the group must be registered before the publish so the message is
    // retained for it; the grouped claim recovers the context by re-reading the index record.
    let _ = mq
        .claim_grouped(
            "events",
            "g1",
            StartPosition::Earliest,
            Duration::from_secs(30),
            10,
            5,
        )
        .await
        .unwrap();
    mq.publish_ctx("events", b"evt", Some(&envelope))
        .await
        .unwrap();
    let grouped = mq
        .claim_grouped(
            "events",
            "g1",
            StartPosition::Earliest,
            Duration::from_secs(30),
            10,
            5,
        )
        .await
        .unwrap();
    assert_eq!(grouped.len(), 1, "the group receives the published message");
    assert_eq!(
        grouped[0].signed_context.as_deref(),
        Some(envelope.as_str()),
        "the signed context survives the durable round-trip on the consumer-group path too"
    );
    assert_eq!(
        verify_context(grouped[0].signed_context.as_deref().unwrap(), &anchor, now).unwrap(),
        "acme"
    );

    // 3) FORGED: a stranger-signed envelope fails verification ⇒ the consumer recovers NO tenant.
    let forged = mint_context("globex", 3600, now, &stranger).await.unwrap();
    mq.publish_ctx("jobs-forged", b"job", Some(&forged))
        .await
        .unwrap();
    let claimed = mq
        .claim("jobs-forged", Duration::from_secs(30), 10, 5)
        .await
        .unwrap();
    assert_eq!(
        claimed[0].signed_context.as_deref(),
        Some(forged.as_str()),
        "the forged envelope is carried opaquely (the store never trusts it)"
    );
    assert!(
        verify_context(claimed[0].signed_context.as_deref().unwrap(), &anchor, now).is_err(),
        "a stranger-signed envelope fails verification ⇒ no tenant ⇒ an own op fails closed \
         (it can never masquerade as globex)"
    );

    // 4) UNSTAMPED: a plain publish carries no context ⇒ the consumer recovers NO tenant.
    mq.publish("jobs-plain", b"job").await.unwrap();
    let claimed = mq
        .claim("jobs-plain", Duration::from_secs(30), 10, 5)
        .await
        .unwrap();
    assert_eq!(
        claimed[0].signed_context, None,
        "an unstamped publish carries no context ⇒ the consumer's own op fails closed"
    );

    println!(
        "ORM DURABLE SIGNED-CONTEXT ISOLATION OK: a host-minted envelope survives the real \
         publish->claim round-trip on both the work-queue and a consumer group; the fleet anchor \
         verifies it and the recovered tenant scopes a real libsql engine to its own rows only; a \
         stranger-signed envelope fails verification and an unstamped message carries no context, \
         so both fail an own op closed (never cross-tenant)"
    );
}
