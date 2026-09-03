//! A handler `sql` backend sourced from a database **boatramp runs** as a compute
//! workload: it resolves the workload's live endpoint on demand and builds the
//! connection, so there is no URL to hand-map and it follows the workload across
//! restarts (PLAN-managed-compute-sql). Endpoint lookup is injected as a
//! [`ComputeEndpointResolver`] so this crate stays decoupled from the control
//! plane — `boatramp-node` provides the `DeployStore`-backed impl.
//!
//! # RLS session context — trust model
//!
//! When a binding opts into `rls_session`, this backend injects the request's tenant
//! (`boatramp.project` / `boatramp.site`) into the SQL session so an app's hand-written
//! RLS can key on it. This **provides** the tenant; it is **not** a hostile-guest
//! boundary on its own:
//!
//! - The reserved keys are protected from guest override at the `sql` binding
//!   (`boatramp_core::sql::reject_reserved_session_writes`), so a guest cannot spoof
//!   its injected tenant.
//! - The real tenant-isolation boundary is the **per-tenant database + role**
//!   (`Single` / `Shared`), which a compromised handler cannot cross. Claim-sourced
//!   enforcement (the GraphQL connector) is the model for untrusted data. See the
//!   `rls_session` config field doc for the full statement.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use boatramp_core::sql::{SqlBackend, SqlError, SqlTransaction, SqlValue};

use crate::sql_sqlx::{connect, ExternalSqlKind, ExternalSqlOptions};

/// Fallback timeout for the C1 managed-DB readiness probe (`SELECT 1` on a
/// freshly-built pool) when the binding sets no `connect_timeout`. Short by design: a
/// listening-but-not-answering DB (recovery / initializing / overloaded) should be
/// reported not-ready quickly rather than block the caller.
const DEFAULT_READINESS_TIMEOUT: Duration = Duration::from_secs(3);

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

/// One replica observed for a workload, for a **diagnostic** "why is there no healthy
/// endpoint" message. Not on the hot path — resolved only when [`endpoints`] came back
/// empty, so a clear reachability/health error can name what exists-but-is-unhealthy.
///
/// [`endpoints`]: ComputeEndpointResolver::endpoints
#[derive(Debug, Clone)]
pub struct ReplicaDiag {
    /// The replica's endpoint, `"ip:port"` (the health probe's TCP target).
    pub endpoint: String,
    /// Whether the last readiness probe passed.
    pub healthy: bool,
    /// The replica's lifecycle phase (e.g. `Running`, `Zero`), for the operator.
    pub phase: String,
}

/// Resolves a compute workload's healthy replica endpoints as `(host, port)`,
/// **primary-first** (the caller connects to the first). Implemented in
/// `boatramp-node` over the `DeployStore`'s replica-state records.
#[async_trait]
pub trait ComputeEndpointResolver: Send + Sync {
    /// Healthy endpoints for `workload`, primary-first (empty ⇒ nothing running).
    async fn endpoints(&self, workload: &str) -> Result<Vec<(String, u16)>, SqlError>;

    /// **Diagnostic** (off the hot path): every replica the resolver can see for
    /// `workload`, healthy or not, so an empty-`endpoints` error can honestly say
    /// whether replicas exist but none passed the readiness probe (a
    /// reachability/health problem) vs the workload simply having no replicas (a
    /// missing/never-launched workload). Default: `Vec::new()` — a resolver that can't
    /// cheaply enumerate replica states just yields the plainer message.
    async fn replica_diagnostics(&self, _workload: &str) -> Vec<ReplicaDiag> {
        Vec::new()
    }
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

    /// Whether this backend injects a **connection-lifetime** MySQL session var that
    /// must be scrubbed before a connection returns to the pool. Postgres's
    /// `set_config(..., is_local => true)` is transaction-local (unset at COMMIT/
    /// ROLLBACK by the engine), so only MySQL needs the explicit reset.
    fn needs_mysql_session_reset(&self) -> bool {
        matches!(self.kind, ExternalSqlKind::Mysql) && !self.session_context.is_empty()
    }

    /// Wrap `tx` in a [`MysqlSessionScopedTx`] when this backend sets a
    /// connection-lifetime MySQL var, so the var is scrubbed to `NULL` before the
    /// transaction ends and the pooled connection returns clean (L1). A no-op wrapper
    /// otherwise (Postgres, or no session context): the transaction is returned as-is.
    fn scope_mysql_session(&self, tx: Box<dyn SqlTransaction>) -> Box<dyn SqlTransaction> {
        if !self.needs_mysql_session_reset() {
            return tx;
        }
        Box::new(MysqlSessionScopedTx {
            inner: tx,
            keys: self.session_context.iter().map(|(k, _)| *k).collect(),
        })
    }

    /// Prepend `SET @boatramp_<key> = NULL` statements to a raw MySQL script when this
    /// backend sets connection-lifetime vars, so a `run_script` on a reused pooled
    /// connection starts from a clean session (L1). `NULL` is a literal, so nothing is
    /// bound. Returns `sql` unchanged for Postgres / no session context.
    fn mysql_reset_prefixed(&self, sql: &str) -> String {
        if !self.needs_mysql_session_reset() {
            return sql.to_string();
        }
        let mut prefix = String::new();
        for (key, _value) in &self.session_context {
            prefix.push_str(&format!("SET @boatramp_{key} = NULL;\n"));
        }
        format!("{prefix}{sql}")
    }

    /// Resolve the workload's primary healthy endpoint and build the connection URL.
    async fn resolve_url(&self) -> Result<String, SqlError> {
        let endpoint = self
            .resolver
            .endpoints(&self.workload)
            .await?
            .into_iter()
            .next();
        let (host, port) = match endpoint {
            Some(hp) => hp,
            // No healthy endpoint. Ask the resolver what replicas exist (off the hot
            // path) so the error distinguishes a reachability/health problem (replicas
            // running but none passed the readiness probe) from a genuinely missing
            // workload — the operator's #1 question when a `SELECT` fails.
            None => return Err(self.no_endpoint_error().await),
        };
        Ok(build_url(
            self.kind,
            &self.user,
            &self.password,
            &host,
            port,
            &self.database,
        ))
    }

    /// Build the "no healthy replica" error, enriched with what the resolver can see.
    /// - No replicas at all ⇒ the workload is missing / never launched.
    /// - Replicas exist but none healthy ⇒ a reachability/health problem: they are
    ///   running but no replica passed the readiness (TCP-connect) probe. The message
    ///   names a probe target (`ip:port`) so the operator can correlate it with the
    ///   `compute health` / `compute-net-debug` logs (e.g. an EHOSTUNREACH on the fly
    ///   guest). Never over-engineered — one clear, honest sentence.
    async fn no_endpoint_error(&self) -> SqlError {
        let diags = self.resolver.replica_diagnostics(&self.workload).await;
        if diags.is_empty() {
            return SqlError::other(format!(
                "managed sql `{}` has no replica to connect to: the workload has no running \
                 replica (it may not be launched yet)",
                self.workload
            ));
        }
        let running = diags.iter().filter(|d| d.phase == "Running").count();
        // A probe target to point the operator at (the first replica's endpoint).
        let target = diags
            .first()
            .map(|d| d.endpoint.as_str())
            .unwrap_or("unknown");
        SqlError::other(format!(
            "managed sql `{}`: {} replica(s) exist ({} running) but none is healthy — no replica \
             passed the readiness probe, so this is a reachability/health problem, not a missing \
             workload (last probe target `{}`; see the `compute health` / `compute-net-debug:` logs \
             for the raw connect error)",
            self.workload,
            diags.len(),
            running,
            target,
        ))
    }

    /// The current sqlx backend, (re)built when the resolved URL changed.
    ///
    /// C1 managed-DB **readiness gate**: sqlx's `connect` builds a *lazy* pool — it
    /// succeeds against a broken-but-listening database (mid-recovery, auth-broken, or
    /// still initializing), so a bare TCP-liveness health check would treat it as
    /// usable. Before this backend caches + hands out a freshly-built pool it runs one
    /// real `SELECT 1` (the driver's ping): a database that can't answer is reported as
    /// **not ready** rather than handed to the caller. The probe runs only on a
    /// (re)build — the cached hot path (same URL) skips it, so there is no per-statement
    /// cost. A probe failure is NOT cached, so the next call re-resolves + re-probes as
    /// the DB finishes coming up.
    async fn pool(&self) -> Result<Arc<dyn SqlBackend>, SqlError> {
        let url = self.resolve_url().await?;
        // Fast path: reuse the cached pool for an unchanged endpoint (already probed
        // ready when it was built). The guard is not held across an await.
        {
            let cached = self.cached.lock().expect("sql-compute pool cache poisoned");
            if let Some((cached_url, backend)) = cached.as_ref() {
                if *cached_url == url {
                    return Ok(Arc::clone(backend));
                }
            }
        }
        // (Re)build the pool for a new endpoint, then gate it on a real readiness probe
        // before caching. `connect` itself is synchronous (a lazy pool); the probe is
        // the async part, which is why the cache guard is dropped above / re-taken below.
        let opts = ExternalSqlOptions::new(url.clone())
            .with_max_connections(self.pool_max)
            .read_only(self.read_only)
            .with_connect_timeout(self.connect_timeout);
        let backend = connect(self.kind, &opts).map_err(|e| self.hint_stale_volume(e))?;
        self.probe_ready(&backend).await?;
        let mut cached = self.cached.lock().expect("sql-compute pool cache poisoned");
        *cached = Some((url, Arc::clone(&backend)));
        Ok(backend)
    }

    /// Run the C1 readiness probe against a freshly-built `backend`: one real
    /// `SELECT 1` in a short-lived read-only transaction (the driver actually opens a
    /// connection + round-trips, unlike the lazy pool build). Bounded by
    /// `connect_timeout` (a `DEFAULT_READINESS_TIMEOUT` fallback) so a hung/recovering
    /// DB fails fast rather than blocking the caller. A stale-volume auth failure is
    /// still surfaced with the reclaim hint; any other failure is reported as a
    /// not-ready condition naming the workload.
    async fn probe_ready(&self, backend: &Arc<dyn SqlBackend>) -> Result<(), SqlError> {
        let timeout = self.connect_timeout.unwrap_or(DEFAULT_READINESS_TIMEOUT);
        let probe = backend.run_query("SELECT 1");
        match tokio::time::timeout(timeout, probe).await {
            Ok(Ok(_)) => Ok(()),
            // The DB answered with an error — surface auth-vs-other via the existing hint.
            Ok(Err(e)) => Err(self.hint_stale_volume(SqlError::other(format!(
                "managed sql `{}` is not ready: its readiness probe (`SELECT 1`) failed: {e}",
                self.workload
            )))),
            // The probe did not return within the timeout — the DB is listening but not
            // answering queries (recovery / initializing / overloaded): not ready.
            Err(_) => Err(SqlError::other(format!(
                "managed sql `{}` is not ready: its readiness probe (`SELECT 1`) did not \
                 complete within {}s — the database is listening but not answering queries \
                 (still initializing, in recovery, or overloaded)",
                self.workload,
                timeout.as_secs().max(1)
            ))),
        }
    }

    /// Turn a bare password-authentication failure into an actionable operator hint.
    /// A managed workload's container bakes its credential at first `initdb`; if its
    /// data volume was initialized with a *different* credential (a stale volume
    /// re-attached — e.g. carried over from before the sealed credential rotated or a
    /// KEK it can't be unsealed under), the container keeps the old password and every
    /// connection fails auth. There is no way to reset a container's own superuser
    /// password from outside, so the fix is to reclaim the volume and let it re-`initdb`
    /// against the current credential — point the operator at `compute volume rm`.
    fn hint_stale_volume(&self, err: SqlError) -> SqlError {
        let msg = err.to_string();
        if msg.contains("password authentication failed") || msg.contains("Access denied for user")
        {
            return SqlError::other(format!(
                "{msg} — the managed workload `{w}`'s data volume was initialized with a \
                 different credential than the current sealed one. Reclaim it so it \
                 re-initializes against the current credential: `boatramp compute rm {w}` \
                 then `boatramp compute volume rm {w}` (destroys that workload's data).",
                w = self.workload
            ));
        }
        err
    }
}

/// Wraps a MySQL transaction so its `@boatramp_*` session vars are reset to `NULL`
/// **just before** the transaction ends, scrubbing the pooled connection so the
/// connection-lifetime var can never linger for a later reuse (L1). Only used for
/// the MySQL path with a configured session context; the Postgres GUC is
/// transaction-local and needs no wrapper. `keys` are our own reserved key constants
/// (never guest input); `NULL` is a literal, so the reset binds nothing.
struct MysqlSessionScopedTx {
    inner: Box<dyn SqlTransaction>,
    keys: Vec<&'static str>,
}

impl MysqlSessionScopedTx {
    /// Reset every `@boatramp_<key>` var on the inner transaction. Best-effort at end:
    /// on the error paths a failure here must not mask the real commit/rollback outcome.
    async fn reset(&mut self) -> Result<(), SqlError> {
        for key in &self.keys {
            self.inner
                .execute(&format!("SET @boatramp_{key} = NULL"), &[])
                .await?;
        }
        Ok(())
    }
}

#[async_trait]
impl SqlTransaction for MysqlSessionScopedTx {
    async fn query(
        &mut self,
        sql: &str,
        params: &[SqlValue],
    ) -> Result<boatramp_core::sql::SqlRows, SqlError> {
        self.inner.query(sql, params).await
    }
    async fn execute(&mut self, sql: &str, params: &[SqlValue]) -> Result<u64, SqlError> {
        self.inner.execute(sql, params).await
    }
    async fn commit(mut self: Box<Self>) -> Result<(), SqlError> {
        // Scrub before COMMIT so the connection returns to the pool clean; a reset
        // failure fails the commit (the connection would otherwise be poisoned).
        self.reset().await?;
        self.inner.commit().await
    }
    async fn rollback(mut self: Box<Self>) -> Result<(), SqlError> {
        // Reset (its own statement, unaffected by the ROLLBACK — MySQL user vars are
        // connection- not transaction-scoped) before rolling back the actual work.
        let reset = self.reset().await;
        let rolled = self.inner.rollback().await;
        reset.and(rolled)
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

    /// This backend injects the reserved `boatramp.*` / `@boatramp_*` session context
    /// exactly when `rls_session` gave it a non-empty context — so the guest `sql`
    /// binding rejects any guest statement that would overwrite those reserved keys
    /// (H1: a guest must not be able to spoof its injected tenant and defeat app RLS).
    fn injects_session_context(&self) -> bool {
        !self.session_context.is_empty()
    }

    async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
        let mut tx = self.pool().await?.begin().await?;
        self.apply_session_context(&mut tx).await?;
        Ok(self.scope_mysql_session(tx))
    }
    async fn begin_read_only(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
        let mut tx = self.pool().await?.begin_read_only().await?;
        self.apply_session_context(&mut tx).await?;
        Ok(self.scope_mysql_session(tx))
    }
    async fn run_script(&self, sql: &str) -> Result<(), SqlError> {
        // Resolve the live endpoint + connect, then delegate to the concrete
        // Postgres/MySQL backend's simple-query script path (operator migrations).
        // L1: `run_script` acquires a *pooled* connection that a prior transaction may
        // have left carrying an `@boatramp_*` MySQL var. This operator path must not
        // inherit a tenant's RLS context, so scrub the vars first (prepended into the
        // same script → same connection). Postgres needs nothing (transaction-local GUC).
        let sql = self.mysql_reset_prefixed(sql);
        self.pool().await?.run_script(&sql).await
    }
    async fn run_query(&self, sql: &str) -> Result<boatramp_core::sql::SqlRows, SqlError> {
        // L1: same as `run_script` — a reused pooled connection may carry a stale
        // `@boatramp_*`. Run the query inside a read-only transaction that resets the
        // vars first, so the operator query sees no tenant's RLS context.
        if self.needs_mysql_session_reset() {
            let mut tx = self.pool().await?.begin_read_only().await?;
            for (key, _value) in &self.session_context {
                tx.execute(&format!("SET @boatramp_{key} = NULL"), &[])
                    .await?;
            }
            let result = tx.query(sql, &[]).await;
            let _ = tx.rollback().await;
            return result;
        }
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

    /// A resolver with no healthy endpoints but a set of replica diagnostics — models a
    /// container that is running yet unreachable (the fly-guest reachability failure).
    struct DiagResolver(Vec<ReplicaDiag>);
    #[async_trait]
    impl ComputeEndpointResolver for DiagResolver {
        async fn endpoints(&self, _workload: &str) -> Result<Vec<(String, u16)>, SqlError> {
            Ok(Vec::new()) // nothing healthy
        }
        async fn replica_diagnostics(&self, _workload: &str) -> Vec<ReplicaDiag> {
            self.0.clone()
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
    async fn no_replica_at_all_is_a_clear_missing_workload_error() {
        // No endpoints AND no diagnostics (default) ⇒ the workload has no replica: the
        // "missing / not launched yet" message, distinct from the reachability one.
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
        let msg = be.resolve_url().await.unwrap_err().to_string();
        assert!(
            msg.contains("managed sql `pg`"),
            "names the workload: {msg}"
        );
        assert!(
            msg.contains("no running replica"),
            "explains the workload is not launched: {msg}"
        );
    }

    #[tokio::test]
    async fn unhealthy_replicas_yield_a_reachability_error_naming_the_probe_target() {
        // A replica is running but no probe passed — the fly-guest reachability failure.
        // The error must name the workload, that a replica exists but is unhealthy, and a
        // probe target, so the operator knows it's health/reachability, not a missing DB.
        let diag = Arc::new(DiagResolver(vec![ReplicaDiag {
            endpoint: "10.201.0.7:5432".into(),
            healthy: false,
            phase: "Running".into(),
        }]));
        let be = ComputeResolvedSqlBackend::new(
            diag,
            "pg-construens",
            ExternalSqlKind::Postgres,
            "db",
            "u",
            "p",
            None,
            false,
            None,
        );
        let msg = be.resolve_url().await.unwrap_err().to_string();
        assert!(
            msg.contains("managed sql `pg-construens`"),
            "names the workload: {msg}"
        );
        assert!(
            msg.contains("1 replica(s) exist") && msg.contains("1 running"),
            "says a replica exists + is running: {msg}"
        );
        assert!(
            msg.contains("none is healthy") && msg.contains("readiness probe"),
            "explains none passed the readiness probe: {msg}"
        );
        assert!(
            msg.contains("10.201.0.7:5432"),
            "names the last probe target: {msg}"
        );
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

    // ---- L1: MySQL connection-lifetime var must not leak on pooled reuse -----

    /// The wrapper resets every `@boatramp_*` var to NULL on COMMIT so the pooled
    /// connection can't carry a prior tenant's value into a later reuse.
    #[tokio::test]
    async fn mysql_session_scoped_tx_resets_on_commit() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let inner: Box<dyn SqlTransaction> = Box::new(RecordingTx { seen: seen.clone() });
        let tx: Box<dyn SqlTransaction> = Box::new(MysqlSessionScopedTx {
            inner,
            keys: vec![SESSION_KEY_PROJECT, SESSION_KEY_SITE],
        });
        tx.commit().await.unwrap();

        let seen = seen.lock().unwrap();
        // Both reserved vars reset to the NULL literal (no bound params).
        assert_eq!(seen.len(), 2, "one reset per reserved key before commit");
        assert_eq!(seen[0].0, "SET @boatramp_project = NULL");
        assert!(seen[0].1.is_empty(), "NULL is a literal, nothing bound");
        assert_eq!(seen[1].0, "SET @boatramp_site = NULL");
    }

    /// The reset also happens on ROLLBACK (the var is connection-scoped, so a rollback
    /// of the transaction would not clear it — the explicit SET does).
    #[tokio::test]
    async fn mysql_session_scoped_tx_resets_on_rollback() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let inner: Box<dyn SqlTransaction> = Box::new(RecordingTx { seen: seen.clone() });
        let tx: Box<dyn SqlTransaction> = Box::new(MysqlSessionScopedTx {
            inner,
            keys: vec![SESSION_KEY_PROJECT],
        });
        tx.rollback().await.unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, "SET @boatramp_project = NULL");
    }

    /// `scope_mysql_session` wraps only the MySQL-with-context case; Postgres (whose
    /// GUC is transaction-local) and the empty-context case are returned unwrapped, so
    /// a plain transaction issues NO reset on commit.
    #[tokio::test]
    async fn scope_mysql_session_is_a_noop_for_postgres_and_empty() {
        // Postgres + context: not wrapped ⇒ no reset statements at commit.
        let be = backend_with_ctx(
            ExternalSqlKind::Postgres,
            vec![(SESSION_KEY_PROJECT, "acme".to_string())],
        );
        assert!(!be.needs_mysql_session_reset());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let tx = be.scope_mysql_session(Box::new(RecordingTx { seen: seen.clone() }));
        tx.commit().await.unwrap();
        assert!(
            seen.lock().unwrap().is_empty(),
            "postgres GUC is transaction-local — no explicit reset"
        );

        // MySQL + empty context: also not wrapped.
        let be = backend_with_ctx(ExternalSqlKind::Mysql, Vec::new());
        assert!(!be.needs_mysql_session_reset());
    }

    /// `run_script` on a MySQL backend with a session context prepends the NULL resets
    /// to the raw script (same pooled connection), so an operator migration never
    /// inherits a tenant's stale `@boatramp_*`. Postgres is untouched.
    #[test]
    fn mysql_reset_prefixed_prepends_for_mysql_context_only() {
        let mysql = backend_with_ctx(
            ExternalSqlKind::Mysql,
            vec![
                (SESSION_KEY_PROJECT, "acme".to_string()),
                (SESSION_KEY_SITE, "blog".to_string()),
            ],
        );
        let out = mysql.mysql_reset_prefixed("CREATE TABLE t (id INT)");
        assert_eq!(
            out,
            "SET @boatramp_project = NULL;\nSET @boatramp_site = NULL;\nCREATE TABLE t (id INT)"
        );

        // Postgres: script unchanged (transaction-local GUC, no leak).
        let pg = backend_with_ctx(
            ExternalSqlKind::Postgres,
            vec![(SESSION_KEY_PROJECT, "acme".to_string())],
        );
        assert_eq!(pg.mysql_reset_prefixed("SELECT 1"), "SELECT 1");

        // MySQL without a session context: also unchanged.
        let mysql_no_ctx = backend_with_ctx(ExternalSqlKind::Mysql, Vec::new());
        assert_eq!(mysql_no_ctx.mysql_reset_prefixed("SELECT 1"), "SELECT 1");
    }

    // ---- C1: managed-DB readiness gate -----------------------------------

    /// How a fake DB responds to the readiness probe's `SELECT 1`.
    enum ProbeBehavior {
        Ready,
        Errors(&'static str),
        Hangs,
    }

    /// A `SqlBackend` whose `run_query` models a managed DB's readiness: it answers
    /// `SELECT 1` (ready), errors (broken/auth), or never returns (recovery/overload).
    /// Only `run_query` matters here; `begin` is unused by the probe.
    struct ProbeBackend(ProbeBehavior);
    #[async_trait]
    impl SqlBackend for ProbeBackend {
        async fn begin(&self) -> Result<Box<dyn SqlTransaction>, SqlError> {
            Err(SqlError::other("unused"))
        }
        async fn run_query(&self, _sql: &str) -> Result<boatramp_core::sql::SqlRows, SqlError> {
            match self.0 {
                ProbeBehavior::Ready => Ok(boatramp_core::sql::SqlRows {
                    columns: vec!["?column?".into()],
                    rows: vec![vec![SqlValue::Integer(1)]],
                }),
                ProbeBehavior::Errors(msg) => Err(SqlError::other(msg)),
                // Sleep well past any test timeout so `probe_ready`'s timeout fires.
                ProbeBehavior::Hangs => {
                    tokio::time::sleep(Duration::from_secs(3600)).await;
                    unreachable!()
                }
            }
        }
    }

    /// A backend with a short readiness timeout, for driving `probe_ready` directly.
    fn probe_backend() -> ComputeResolvedSqlBackend {
        let mock = Arc::new(MockResolver(Mutex::new(vec![("h".into(), 1)])));
        ComputeResolvedSqlBackend::new(
            mock,
            "pg",
            ExternalSqlKind::Postgres,
            "db",
            "u",
            "p",
            None,
            false,
            Some(Duration::from_millis(150)), // short probe timeout
        )
    }

    #[tokio::test]
    async fn readiness_probe_passes_a_ready_db() {
        let be = probe_backend();
        let db: Arc<dyn SqlBackend> = Arc::new(ProbeBackend(ProbeBehavior::Ready));
        assert!(
            be.probe_ready(&db).await.is_ok(),
            "a DB that answers SELECT 1 is ready"
        );
    }

    #[tokio::test]
    async fn readiness_probe_fails_a_broken_but_listening_db() {
        // The exact C1 case: sqlx's lazy `connect` would have succeeded, but the DB
        // can't actually serve a query (in recovery / auth-broken) — not ready.
        let be = probe_backend();
        let db: Arc<dyn SqlBackend> = Arc::new(ProbeBackend(ProbeBehavior::Errors(
            "the database system is in recovery mode",
        )));
        let err = be.probe_ready(&db).await.expect_err("must be not-ready");
        let msg = err.to_string();
        assert!(msg.contains("not ready"), "surfaces not-ready: {msg}");
        assert!(msg.contains("pg"), "names the workload: {msg}");
    }

    #[tokio::test]
    async fn readiness_probe_auth_failure_gets_the_stale_volume_hint() {
        // A password-auth failure on the probe is surfaced with the reclaim hint (the
        // stale-volume path), so the operator gets the actionable message.
        let be = probe_backend();
        let db: Arc<dyn SqlBackend> = Arc::new(ProbeBackend(ProbeBehavior::Errors(
            "password authentication failed for user \"app\"",
        )));
        let msg = be.probe_ready(&db).await.unwrap_err().to_string();
        assert!(
            msg.contains("compute volume rm"),
            "auth failure carries the stale-volume reclaim hint: {msg}"
        );
    }

    #[tokio::test]
    async fn readiness_probe_times_out_a_hung_db() {
        // Listening but not answering (the TCP check would pass): the probe's timeout
        // fires and reports not-ready rather than blocking the caller forever. The
        // fake's "hang" future is cancelled when `probe_ready`'s (150ms) timeout wins,
        // so this resolves quickly without a real long sleep.
        let be = probe_backend();
        let db: Arc<dyn SqlBackend> = Arc::new(ProbeBackend(ProbeBehavior::Hangs));
        let msg = be.probe_ready(&db).await.unwrap_err().to_string();
        assert!(
            msg.contains("did not complete within"),
            "a hung DB times out as not-ready: {msg}"
        );
    }
}
