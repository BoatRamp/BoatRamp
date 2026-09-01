//! A handler `sql` backend sourced from a database **boatramp runs** as a compute
//! workload: it resolves the workload's live endpoint on demand and builds the
//! connection, so there is no URL to hand-map and it follows the workload across
//! restarts (PLAN-managed-compute-sql). Endpoint lookup is injected as a
//! [`ComputeEndpointResolver`] so this crate stays decoupled from the control
//! plane — `boatramp-node` provides the `DeployStore`-backed impl.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::sql::{SqlBackend, SqlError, SqlTransaction, SqlValue};

use crate::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};

/// A logical session-context key injected at every transaction start when the
/// binding opts into RLS session-injection (`rls_session = true`). The two
/// recognised keys mirror the request's tenant identity so hand-written **native
/// RLS** can key on them per-request. Postgres exposes them as the GUCs
/// `boatramp.project` / `boatramp.site` (read with `current_setting('boatramp.project')`);
/// MySQL exposes them as the session variables `@boatramp_project` / `@boatramp_site`
/// (read with `@boatramp_project`). The value is always **bound**, never interpolated.
pub const SESSION_KEY_PROJECT: &str = "project";
/// See [`SESSION_KEY_PROJECT`].
pub const SESSION_KEY_SITE: &str = "site";

/// Resolves a compute workload's healthy replica endpoints as `(host, port)`,
/// **primary-first** (the caller connects to the first). Implemented in
/// `boatramp-node` over the `DeployStore`'s replica-state records.
#[async_trait]
pub trait ComputeEndpointResolver: Send + Sync {
    /// Healthy endpoints for `workload`, primary-first (empty ⇒ nothing running).
    async fn endpoints(&self, workload: &str) -> Result<Vec<(String, u16)>, SqlError>;
}

/// Percent-encode a URL userinfo component (user / password): over-encode
/// everything outside the RFC 3986 *unreserved* set, so a password containing
/// `@`, `:`, `/`, spaces, etc. can't corrupt the connection URL.
fn encode_userinfo(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build a connection URL for `kind` from the resolved parts.
pub fn build_url(
    kind: ExternalSqlKind,
    user: &str,
    password: &str,
    host: &str,
    port: u16,
    database: &str,
) -> String {
    let scheme = match kind {
        ExternalSqlKind::Postgres => "postgres",
        ExternalSqlKind::Mysql => "mysql",
    };
    format!(
        "{scheme}://{}:{}@{host}:{port}/{database}",
        encode_userinfo(user),
        encode_userinfo(password),
    )
}

/// A [`SqlBackend`] whose connection is **derived from a compute workload's live
/// endpoint**. On each transaction it resolves the endpoint, builds the URL, and
/// reuses a cached sqlx pool — rebuilding only when the endpoint (hence the URL)
/// changed, so a DB restart on a new host port is followed with no config change.
pub struct ComputeResolvedSqlBackend {
    resolver: Arc<dyn ComputeEndpointResolver>,
    workload: String,
    kind: ExternalSqlKind,
    database: String,
    user: String,
    password: String,
    pool_max: Option<u32>,
    read_only: bool,
    connect_timeout: Option<Duration>,
    // Opt-in RLS session context (`rls_session = true`): logical `(key, value)`
    // pairs — `("project", …)` / `("site", …)` — applied at the start of **every**
    // transaction (both read-write and read-only), right after the tx opens, so a
    // hand-written native RLS policy can read the request's tenant identity. Empty
    // ⇒ no injection (the common case). The value is always **bound**, never
    // interpolated into the SQL text.
    session_context: Vec<(&'static str, String)>,
    // (resolved-url, pool). Rebuilt when the resolved URL changes. The guard is
    // never held across an `.await` (the URL is resolved before locking, and
    // `connect` is synchronous), so a plain `std::sync::Mutex` is correct.
    cached: Mutex<Option<(String, Arc<dyn SqlBackend>)>>,
}

impl ComputeResolvedSqlBackend {
    /// Build a compute-resolved backend. `password` is already resolved (from the
    /// binding's `password_env` today; a managed/generated secret later).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        resolver: Arc<dyn ComputeEndpointResolver>,
        workload: impl Into<String>,
        kind: ExternalSqlKind,
        database: impl Into<String>,
        user: impl Into<String>,
        password: impl Into<String>,
        pool_max: Option<u32>,
        read_only: bool,
        connect_timeout: Option<Duration>,
    ) -> Self {
        Self {
            resolver,
            workload: workload.into(),
            kind,
            database: database.into(),
            user: user.into(),
            password: password.into(),
            pool_max,
            read_only,
            connect_timeout,
            session_context: Vec::new(),
            cached: Mutex::new(None),
        }
    }

    /// Attach the opt-in RLS **session context** applied at every transaction start
    /// (see the [`session_context`](Self::session_context) field). Pass the request's
    /// tenant identity as `[(SESSION_KEY_PROJECT, project), (SESSION_KEY_SITE, site)]`;
    /// an empty vec is a no-op. Builder-style so the per-tenant resolver can add it
    /// only when the binding sets `rls_session = true`.
    pub fn with_session_context(mut self, ctx: Vec<(&'static str, String)>) -> Self {
        self.session_context = ctx;
        self
    }

    /// Apply the session context onto a freshly-opened transaction (a no-op when
    /// empty, or when the backend's dialect has no session-scoped setting to key RLS
    /// on — SQLite/libsql). Runs one bound statement per key so a value containing SQL
    /// metacharacters can never escape into the statement text.
    async fn apply_session_context(
        &self,
        tx: &mut Box<dyn SqlTransaction>,
    ) -> Result<(), SqlError> {
        if self.session_context.is_empty() {
            return Ok(());
        }
        for (key, value) in &self.session_context {
            let (sql, params): (String, Vec<SqlValue>) = match self.kind {
                // `set_config(setting_name, new_value, is_local)` with `is_local = true`
                // scopes the GUC to the current transaction. The setting *name* is a
                // fixed literal (`'boatramp.project'`/`'boatramp.site'`) built from our
                // own key constant — never guest input — and the value is bound (`$1`),
                // so nothing tenant-supplied reaches the statement text.
                ExternalSqlKind::Postgres => (
                    format!("SELECT set_config('boatramp.{key}', ?1, true)"),
                    vec![SqlValue::Text(value.clone())],
                ),
                // Session variable with a fixed name and a bound value. `SET` can't take
                // a placeholder for the *variable name*, so the name is a fixed literal
                // from our constant; the value is bound.
                ExternalSqlKind::Mysql => (
                    format!("SET @boatramp_{key} = ?1"),
                    vec![SqlValue::Text(value.clone())],
                ),
            };
            tx.execute(&sql, &params).await?;
        }
        Ok(())
    }

    /// Resolve the workload's primary healthy endpoint and build the connection URL.
    async fn resolve_url(&self) -> Result<String, SqlError> {
        let (host, port) = self
            .resolver
            .endpoints(&self.workload)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| {
                SqlError::other(format!(
                    "managed sql `{}` has no healthy replica to connect to",
                    self.workload
                ))
            })?;
        Ok(build_url(
            self.kind,
            &self.user,
            &self.password,
            &host,
            port,
            &self.database,
        ))
    }

    /// The current sqlx backend, (re)built when the resolved URL changed.
    async fn pool(&self) -> Result<Arc<dyn SqlBackend>, SqlError> {
        let url = self.resolve_url().await?;
        let mut cached = self.cached.lock().expect("sql-compute pool cache poisoned");
        if let Some((cached_url, backend)) = cached.as_ref() {
            if *cached_url == url {
                return Ok(Arc::clone(backend));
            }
        }
        let opts = ExternalSqlOptions::new(url.clone())
            .with_max_connections(self.pool_max)
            .read_only(self.read_only)
            .with_connect_timeout(self.connect_timeout);
        let backend = connect(self.kind, &opts)?;
        *cached = Some((url, Arc::clone(&backend)));
        Ok(backend)
    }
}

#[async_trait]
impl SqlBackend for ComputeResolvedSqlBackend {
    fn dialect(&self) -> boatramp_core::sql::Dialect {
        match self.kind {
            ExternalSqlKind::Postgres => boatramp_core::sql::Dialect::Postgres,
            ExternalSqlKind::Mysql => boatramp_core::sql::Dialect::Mysql,
        }
    }

    async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
        let mut tx = self.pool().await?.begin().await?;
        self.apply_session_context(&mut tx).await?;
        Ok(tx)
    }
    async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
        let mut tx = self.pool().await?.begin_read_only().await?;
        self.apply_session_context(&mut tx).await?;
        Ok(tx)
    }
    async fn run_script(&self, sql: &str) -> Result<(), SqlError> {
        // Resolve the live endpoint + connect, then delegate to the concrete
        // Postgres/MySQL backend's simple-query script path (operator migrations).
        self.pool().await?.run_script(sql).await
    }
    async fn run_query(&self, sql: &str) -> Result<boatramp_core::sql::SqlRows, SqlError> {
        self.pool().await?.run_query(sql).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A resolver whose endpoints can be swapped mid-test (to model a DB restart).
    struct MockResolver(Mutex<Vec<(String, u16)>>);
    #[async_trait]
    impl ComputeEndpointResolver for MockResolver {
        async fn endpoints(&self, _workload: &str) -> Result<Vec<(String, u16)>, SqlError> {
            Ok(self.0.lock().unwrap().clone())
        }
    }

    #[test]
    fn build_url_per_engine_encodes_userinfo() {
        assert_eq!(
            build_url(
                ExternalSqlKind::Postgres,
                "app",
                "s3cret",
                "10.0.0.5",
                5432,
                "analytics"
            ),
            "postgres://app:s3cret@10.0.0.5:5432/analytics"
        );
        // A password with URL-special chars is percent-encoded so it can't corrupt
        // the connection string.
        assert_eq!(
            build_url(
                ExternalSqlKind::Mysql,
                "app",
                "p@ss:w/rd",
                "db",
                3306,
                "shop"
            ),
            "mysql://app:p%40ss%3Aw%2Frd@db:3306/shop"
        );
    }

    #[tokio::test]
    async fn resolve_url_follows_the_workload_endpoint() {
        let mock = Arc::new(MockResolver(Mutex::new(vec![("10.0.0.5".into(), 5432)])));
        let be = ComputeResolvedSqlBackend::new(
            mock.clone(),
            "pg",
            ExternalSqlKind::Postgres,
            "analytics",
            "app",
            "pw",
            None,
            false,
            None,
        );
        assert_eq!(
            be.resolve_url().await.unwrap(),
            "postgres://app:pw@10.0.0.5:5432/analytics"
        );
        // The DB restarts on a new host port; the next resolve follows it (the pool
        // would rebuild on the changed URL).
        *mock.0.lock().unwrap() = vec![("10.0.0.9".into(), 6000)];
        assert_eq!(
            be.resolve_url().await.unwrap(),
            "postgres://app:pw@10.0.0.9:6000/analytics"
        );
    }

    #[tokio::test]
    async fn no_healthy_replica_is_a_clear_error() {
        let mock = Arc::new(MockResolver(Mutex::new(vec![])));
        let be = ComputeResolvedSqlBackend::new(
            mock,
            "pg",
            ExternalSqlKind::Postgres,
            "db",
            "u",
            "p",
            None,
            false,
            None,
        );
        let err = be.resolve_url().await.unwrap_err();
        assert!(err.to_string().contains("no healthy replica"), "got: {err}");
    }

    // ---- RLS session-context injection -----------------------------------

    /// The recorded `(sql, params)` of each `execute` a test transaction saw.
    type Recorded = Arc<Mutex<Vec<(String, Vec<SqlValue>)>>>;

    /// A transaction that records the `(sql, params)` of every `execute`, so a test
    /// can inspect the session-context statements the backend injects.
    struct RecordingTx {
        seen: Recorded,
    }
    #[async_trait]
    impl SqlTransaction for RecordingTx {
        async fn query(
            &mut self,
            _sql: &str,
            _params: &[SqlValue],
        ) -> Result<boatramp_core::sql::SqlRows, SqlError> {
            Ok(boatramp_core::sql::SqlRows {
                columns: Vec::new(),
                rows: Vec::new(),
            })
        }
        async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
            self.seen
                .lock()
                .unwrap()
                .push((sql.to_string(), params.to_vec()));
            Ok(0)
        }
        async fn commit(self: Box<Self>) -> Result<(), SqlError> {
            Ok(())
        }
        async fn rollback(self: Box<Self>) -> Result<(), SqlError> {
            Ok(())
        }
    }

    fn backend_with_ctx(
        kind: ExternalSqlKind,
        ctx: Vec<(&'static str, String)>,
    ) -> ComputeResolvedSqlBackend {
        let mock = Arc::new(MockResolver(Mutex::new(vec![("h".into(), 1)])));
        ComputeResolvedSqlBackend::new(mock, "w", kind, "db", "u", "p", None, false, None)
            .with_session_context(ctx)
    }

    #[tokio::test]
    async fn session_context_postgres_uses_bound_set_config() {
        let be = backend_with_ctx(
            ExternalSqlKind::Postgres,
            vec![
                (SESSION_KEY_PROJECT, "acme".to_string()),
                (SESSION_KEY_SITE, "blog".to_string()),
            ],
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut tx: Box<dyn SqlTransaction> = Box::new(RecordingTx { seen: seen.clone() });
        be.apply_session_context(&mut tx).await.unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "one bound statement per key");
        // The setting NAME is a fixed literal (`boatramp.project`), the VALUE is bound
        // (`?1`), so nothing tenant-supplied reaches the statement text.
        assert_eq!(seen[0].0, "SELECT set_config('boatramp.project', ?1, true)");
        assert_eq!(seen[0].1, vec![SqlValue::Text("acme".into())]);
        assert_eq!(seen[1].0, "SELECT set_config('boatramp.site', ?1, true)");
        assert_eq!(seen[1].1, vec![SqlValue::Text("blog".into())]);
    }

    #[tokio::test]
    async fn session_context_mysql_uses_bound_session_var() {
        let be = backend_with_ctx(
            ExternalSqlKind::Mysql,
            vec![(SESSION_KEY_PROJECT, "acme".to_string())],
        );
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut tx: Box<dyn SqlTransaction> = Box::new(RecordingTx { seen: seen.clone() });
        be.apply_session_context(&mut tx).await.unwrap();

        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "SET @boatramp_project = ?1");
        assert_eq!(seen[0].1, vec![SqlValue::Text("acme".into())]);
    }

    #[tokio::test]
    async fn empty_session_context_injects_nothing() {
        let be = backend_with_ctx(ExternalSqlKind::Postgres, Vec::new());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut tx: Box<dyn SqlTransaction> = Box::new(RecordingTx { seen: seen.clone() });
        be.apply_session_context(&mut tx).await.unwrap();
        assert!(
            seen.lock().unwrap().is_empty(),
            "no context ⇒ no statements"
        );
    }
}
