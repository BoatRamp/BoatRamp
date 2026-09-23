//! Host-side implementations of the standard WASI capability interfaces a
//! handler may import: `wasi:keyvalue`, `wasi:blobstore`,
//! and the boatramp `sql` interface. Each is generated from vendored WIT
//! (`wit/`) via `bindgen!` and backed by boatramp's own traits — `KvStore`,
//! `Storage` — with **per-site** namespacing so no handler can address another
//! site's data (tenant isolation).
//!
//! Capabilities are granted per invocation through [`Bindings`]: a field left
//! `None` is a capability the handler was not granted, and the corresponding
//! host calls fail with `access-denied` — deny by default.

#[cfg(feature = "sql")]
use std::collections::HashMap;
use std::sync::Arc;

use boatramp_core::kv::KvStore;
#[cfg(feature = "messaging")]
use boatramp_core::messaging::Messaging;
#[cfg(feature = "sql")]
use boatramp_core::sql::SqlBackend;
use boatramp_core::Storage;

#[cfg(feature = "admin")]
pub mod admin;
pub mod blobstore;
#[cfg(feature = "capability")]
pub mod capability;
#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "graphql")]
pub mod graphql;
#[cfg(feature = "invoke")]
pub mod invoke;
pub mod keyvalue;
#[cfg(feature = "messaging")]
pub mod messaging;
/// The read-only `messaging-stats` binding: surface the ALREADY-computed per-topic bus gauges
/// (dead-letter count / backlog / in-flight / per-group depth) to a granted guest, tenant-scoped by a
/// host-filled `{tenant}` template. A messaging-substrate concern, so gated with `messaging`.
#[cfg(feature = "messaging")]
pub mod messaging_stats;
#[cfg(feature = "migrate")]
pub mod migrate;
#[cfg(feature = "sql")]
pub mod orm;
#[cfg(feature = "session")]
pub mod session;
#[cfg(feature = "sql")]
pub mod sql;
#[cfg(feature = "sql")]
pub mod target_context;
/// Gap 3: `present-token` host-seals an in-guest-verified tenant onto the producer-context cell the
/// `messaging` binding stamps — a messaging-lane concern, so gated with `messaging`.
#[cfg(feature = "messaging")]
pub mod tenancy;
/// The per-tenant sealed-secret binding (`boatramp:handlers/tenant-secrets`, task #493): a granted
/// guest reads/writes secrets sealed to THIS invocation's host-resolved tenant. Its own off-by-
/// default `tenant-secrets` feature (the store lives in boatramp-core, so the control-plane path
/// compiles without it).
#[cfg(feature = "tenant-secrets")]
pub mod tenant_secrets;
pub mod wasi_logging;

/// The per-site capability handles for one handler invocation.
///
/// Built once per site (cheaply cloned per request — every field is an `Arc` or
/// a small string). A `None` capability is one the handler is not granted.
#[derive(Clone, Default)]
pub struct Bindings {
    keyvalue: Option<keyvalue::KvBinding>,
    blobstore: Option<blobstore::BlobBinding>,
    /// The site's named SQL databases (`name -> backend`); the guest selects one
    /// via `sql.open(name)`. Empty = SQL not granted.
    #[cfg(feature = "sql")]
    sql: HashMap<String, Arc<dyn SqlBackend>>,
    /// The host-resolved in-site tenancy for this invocation, applied to **both** the `sql` and
    /// `orm` bindings (Stage 0). `None` ⇒ plain queries (no row scoping).
    #[cfg(feature = "sql")]
    tenancy: Option<crate::tenant::HostTenancy>,
    /// The `wasi:messaging` producer grant (backend + topic-namespace prefix).
    /// `None` = messaging not granted.
    #[cfg(feature = "messaging")]
    messaging: Option<messaging::MessagingBinding>,
    /// The `invoke` grant (function-to-function calls): the resolver, the target
    /// allowlist, and this invocation's call depth. `None` = invoke not granted.
    #[cfg(feature = "invoke")]
    invoke: Option<invoke::InvokeBinding>,
    /// The `graphql` grant (run an op against the project supergraph): the server's
    /// runner + this invocation's call depth. `None` = graphql not granted.
    #[cfg(feature = "graphql")]
    graphql: Option<graphql::GraphqlBinding>,
    /// The `email` grant (submit a message to the per-project SMTP gateway): the
    /// project, its host-held SMTP profiles, and the shared node spool. `None` =
    /// email not granted.
    #[cfg(feature = "email")]
    email: Option<email::EmailBinding>,
    /// The `admin` grant (reconfigure the guest's own project): a project-scoped controller +
    /// the granted config surfaces. `None` = admin not granted.
    #[cfg(feature = "admin")]
    admin: Option<admin::AdminBinding>,
    /// The `migrate-ddl` grant (a migration function step runs owner-role DDL): the project+db-scoped
    /// owner-DDL seam. `None` = not a migration step (`migrate::*` ⇒ `not-a-migration`).
    #[cfg(feature = "migrate")]
    migrate: Option<migrate::MigrateBinding>,
    /// The `capability` grant (mint a fleet-signed target capability): the project-scoped minter +
    /// the operator TTL ceiling. `None` = capability minting not granted.
    #[cfg(feature = "capability")]
    capability: Option<capability::CapabilityBinding>,
    /// The `session` grant (duplex/resumable session): the controller bound to the current
    /// session. `None` = session not granted.
    #[cfg(feature = "session")]
    session: Option<session::SessionBinding>,
    /// The `tenancy` grant (Gap 3): host-verify a guest-presented tenant credential + seal it onto
    /// the producer-context cell. `None` = not granted (`present-token` ⇒ `access-denied`).
    #[cfg(feature = "messaging")]
    tenancy_present: Option<tenancy::TenancyBinding>,
    /// The read-only `messaging-stats` grant: read per-topic bus gauges (dead-letter, backlog,
    /// in-flight, per-group depth). Bus topics are addressed through a host-filled `{tenant}` template,
    /// so the guest never names a tenant. `None` = not granted (every stats call ⇒ `access-denied`).
    #[cfg(feature = "messaging")]
    messaging_stats: Option<messaging_stats::StatsBinding>,
    /// The `tenant-secrets` grant (task #493): read/write secrets sealed to THIS invocation's
    /// host-resolved tenant. `None` = not granted (every call ⇒ `access-denied`). The binding
    /// carries the two independent rights + the per-component name allowlist; the guest never names
    /// a tenant (the host injects the resolved one).
    #[cfg(feature = "tenant-secrets")]
    tenant_secrets: Option<tenant_secrets::TenantSecretsBinding>,
    /// Where this invocation's captured stdout/stderr is sent.
    /// `None` = the guest's stdio is left inherited (host stdio).
    logging: Option<crate::logging::LoggingBinding>,
    /// Environment variables exposed to the guest: the
    /// deploy's static `env` plus the site's resolved `secrets`. The guest sees
    /// *only* these — the host's own environment is never inherited.
    env: Vec<(String, String)>,
}

impl Bindings {
    /// Bindings for `site` with nothing granted yet.
    pub fn new(_site: impl AsRef<str>) -> Self {
        Self::default()
    }

    /// Grant the `wasi:keyvalue` capability, backed by `store`, with every key
    /// namespaced under `hkv/{site}/` (per-site isolation).
    pub fn with_keyvalue(mut self, site: &str, store: Arc<dyn KvStore>) -> Self {
        self.keyvalue = Some(keyvalue::KvBinding {
            store,
            prefix: format!("hkv/{site}/"),
        });
        self
    }

    /// Grant the `wasi:blobstore` capability, backed by `storage`, with every
    /// container namespaced under `hblob/{site}/` (per-site isolation).
    /// `max_bytes` caps a single host-side read/range/copy (`0` = unlimited),
    /// bounding host memory a handler can allocate via the binding.
    pub fn with_blobstore(mut self, site: &str, storage: Arc<dyn Storage>, max_bytes: u64) -> Self {
        self.blobstore = Some(blobstore::BlobBinding {
            storage,
            prefix: format!("hblob/{site}/"),
            max_bytes,
        });
        self
    }

    /// The granted key/value binding, if any.
    pub(crate) fn keyvalue(&self) -> Option<&keyvalue::KvBinding> {
        self.keyvalue.as_ref()
    }

    /// Grant a named SQL database, served by `backend` (libsql — a file or sqld
    /// namespace). Call once per database the site is granted; the empty name is
    /// the guest's default database.
    #[cfg(feature = "sql")]
    pub fn with_sql(mut self, name: impl Into<String>, backend: Arc<dyn SqlBackend>) -> Self {
        self.sql.insert(name.into(), backend);
        self
    }

    /// Set the host-resolved in-site tenancy applied to this invocation's `sql` + `orm` bindings.
    /// The server builds it from the function/site tenancy decision + the verified tenant source;
    /// the guest can neither see nor override it. `None` ⇒ plain queries.
    #[cfg(feature = "sql")]
    pub fn with_tenancy(mut self, tenancy: Option<crate::tenant::HostTenancy>) -> Self {
        self.tenancy = tenancy;
        self
    }

    /// The host-resolved tenancy for this invocation (consumed by the engine when building the
    /// shared SQL session).
    #[cfg(feature = "sql")]
    pub(crate) fn tenancy(&self) -> Option<crate::tenant::HostTenancy> {
        self.tenancy.clone()
    }

    /// A read-only view of the host-resolved tenancy (the same value the engine applies to the
    /// `sql`/`orm` session AND that propagates onto an `invoke`/`graphql::run` caller principal).
    /// Guest-blind and host-owned; exposed so a host-side test can assert what a per-message
    /// rebuild resolved (e.g. the async-lane `signed_context` consumer dispatch). `None` ⇒ this
    /// invocation carries no tenant fact, so a scoped op fails closed.
    #[cfg(feature = "sql")]
    pub fn resolved_tenancy(&self) -> Option<crate::tenant::HostTenancy> {
        self.tenancy.clone()
    }

    /// The resolved TARGET capability's opaque app-context for this invocation as `(key, value)`
    /// pairs (empty when there is no capability target) — the data the `target-context` binding hands
    /// back to a resolver (Stage D). Only the app-authored context; never the host-forced tenant `B`.
    #[cfg(feature = "sql")]
    pub(crate) fn tenancy_target_context(&self) -> Vec<(String, String)> {
        self.tenancy
            .as_ref()
            .map(|t| {
                t.target_context()
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The granted blob binding, if any.
    pub(crate) fn blobstore(&self) -> Option<&blobstore::BlobBinding> {
        self.blobstore.as_ref()
    }

    /// Capture this invocation's stdout/stderr (and `wasi:logging`) into `sink`, tagged with
    /// `scope` and correlated with `request_id` (the request that produced the output, when the
    /// dispatch layer assigned one). Without this the guest's stdio is discarded.
    pub fn with_logging(
        mut self,
        scope: impl Into<String>,
        request_id: Option<String>,
        sink: Arc<dyn crate::logging::LogSink>,
    ) -> Self {
        self.logging = Some(crate::logging::LoggingBinding {
            sink,
            scope: scope.into(),
            request_id,
        });
        self
    }

    /// The granted logging capture binding, if any.
    pub(crate) fn logging(&self) -> Option<&crate::logging::LoggingBinding> {
        self.logging.as_ref()
    }

    /// Set the guest's environment variables (deploy `env` + resolved secrets).
    /// These are the *only* env vars the guest sees; the host's are never
    /// inherited.
    pub fn with_env(mut self, env: Vec<(String, String)>) -> Self {
        self.env = env;
        self
    }

    /// The guest's environment variables.
    pub(crate) fn env(&self) -> &[(String, String)] {
        &self.env
    }

    /// The granted SQL databases (`name -> backend`).
    #[cfg(feature = "sql")]
    pub(crate) fn sql(&self) -> HashMap<String, Arc<dyn SqlBackend>> {
        self.sql.clone()
    }

    /// The names of the granted SQL databases (sorted). Lets a caller assert *which* databases a
    /// guest can open — the observable result of the named-binding dispatch + authz.
    #[cfg(feature = "sql")]
    pub fn sql_database_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.sql.keys().cloned().collect();
        names.sort();
        names
    }

    /// Grant the `wasi:messaging` producer capability, backed by `messaging`. A
    /// plain topic is namespaced under `prefix` (per-site/alias isolation — the
    /// guest can't publish outside its own namespace); a `bus:<topic>` is
    /// namespaced under `bus_prefix` (the shared `{project}/bus/` space, so a
    /// producer and a consumer in different components can meet on one topic).
    ///
    /// `signed_context` is the host-minted durable signed-context envelope (R1) stamped onto every
    /// message this producer publishes — the producer's own-tenant, sealed for the async lane so a
    /// declaring consumer resolves it. `None` ⇒ an unscoped producer (messages carry no context).
    #[cfg(feature = "messaging")]
    pub fn with_messaging(
        mut self,
        prefix: impl Into<String>,
        bus_prefix: impl Into<String>,
        messaging: Arc<dyn Messaging>,
        signed_context: Option<String>,
    ) -> Self {
        self.messaging = Some(messaging::MessagingBinding {
            messaging,
            prefix: prefix.into(),
            bus_prefix: bus_prefix.into(),
            // Wrap the bind-time value in a shared cell so a `tenancy::present-token` (Gap 3) can
            // host-seal + update it mid-invocation before the guest publishes.
            signed_context: Arc::new(std::sync::Mutex::new(signed_context)),
        });
        self
    }

    /// The granted messaging binding, if any.
    #[cfg(feature = "messaging")]
    pub(crate) fn messaging(&self) -> Option<&messaging::MessagingBinding> {
        self.messaging.as_ref()
    }

    /// The messaging binding's shared **producer-context cell** (Gap 3), if messaging is granted —
    /// so the caller can hand the SAME cell to [`with_tenancy`](Self::with_tenancy) and let a
    /// `present-token` host-seal a tenant onto the messages this invocation publishes. `None` ⇒ no
    /// messaging binding (a `present-token` then seals into its own cell, a no-op for publishing).
    #[cfg(feature = "messaging")]
    pub fn producer_context_cell(&self) -> Option<messaging::ProducerContext> {
        self.messaging.as_ref().map(|m| m.signed_context.clone())
    }

    /// Grant the `invoke` capability: `invoker` resolves + runs a target,
    /// `targets` is the allowlist of callable names (`*`-wildcards allowed), and
    /// `depth` is this invocation's position in the call chain (the host caps the
    /// next hop at [`invoke::MAX_INVOKE_DEPTH`](invoke::MAX_INVOKE_DEPTH)).
    #[cfg(feature = "invoke")]
    pub fn with_invoke(
        mut self,
        invoker: Arc<dyn invoke::Invoker>,
        targets: Vec<String>,
        depth: u32,
    ) -> Self {
        self.invoke = Some(invoke::InvokeBinding {
            invoker,
            targets,
            depth,
        });
        self
    }

    /// The granted invoke binding, if any.
    #[cfg(feature = "invoke")]
    pub(crate) fn invoke(&self) -> Option<&invoke::InvokeBinding> {
        self.invoke.as_ref()
    }

    /// Grant the `graphql` capability: `runner` plans + executes an op against the
    /// project's composed supergraph, and `depth` is this invocation's position in the
    /// call chain (the host caps the next hop at
    /// [`invoke::MAX_INVOKE_DEPTH`](invoke::MAX_INVOKE_DEPTH), shared with `invoke`).
    #[cfg(feature = "graphql")]
    pub fn with_graphql(mut self, runner: Arc<dyn graphql::SupergraphRunner>, depth: u32) -> Self {
        self.graphql = Some(graphql::GraphqlBinding { runner, depth });
        self
    }

    /// The granted graphql binding, if any.
    #[cfg(feature = "graphql")]
    pub(crate) fn graphql(&self) -> Option<&graphql::GraphqlBinding> {
        self.graphql.as_ref()
    }

    /// Grant the `email` capability: `project` owns the profiles, `profiles` are the
    /// host-resolved SMTP profiles (credentials held host-side, never exposed to the
    /// guest), and `spool` is the shared node delivery spool. The guest picks a
    /// profile by name and calls `send`; it can neither read nor reconfigure a
    /// profile (that is the control-plane's job).
    #[cfg(feature = "email")]
    pub fn with_email(
        mut self,
        project: impl Into<String>,
        profiles: std::sync::Arc<
            std::collections::BTreeMap<String, boatramp_core::email_config::EmailProfile>,
        >,
        spool: Arc<dyn email::EmailSpool>,
    ) -> Self {
        self.email = Some(email::EmailBinding {
            project: project.into(),
            profiles,
            spool,
        });
        self
    }

    /// The granted email binding, if any.
    #[cfg(feature = "email")]
    pub(crate) fn email(&self) -> Option<&email::EmailBinding> {
        self.email.as_ref()
    }

    /// Grant the `admin` capability: a project-scoped [`AdminController`](admin::AdminController)
    /// and the set of config [`Surface`](admin::Surface)s the guest may touch (granted imports
    /// ∩ the site allowlist ∩ the operator posture). The guest reconfigures only its own
    /// project; each verb is gated on its surface, and reads are redacted.
    #[cfg(feature = "admin")]
    pub fn with_admin(
        mut self,
        controller: Arc<dyn admin::AdminController>,
        surfaces: std::collections::BTreeSet<admin::Surface>,
    ) -> Self {
        self.admin = Some(admin::AdminBinding {
            controller,
            surfaces,
        });
        self
    }

    /// The granted admin binding, if any.
    #[cfg(feature = "admin")]
    pub(crate) fn admin(&self) -> Option<&admin::AdminBinding> {
        self.admin.as_ref()
    }

    /// Grant the `migrate-ddl` capability for a migration function step: `ddl` is the server-side
    /// owner-role seam for this project+db. SECURITY: the server attaches this ONLY inside a
    /// `Project·Admin` migration run (context-gated); a normal invocation leaves it `None`, so every
    /// `migrate::*` verb returns `not-a-migration`.
    #[cfg(feature = "migrate")]
    pub fn with_migrate(mut self, ddl: Arc<dyn boatramp_core::sql::MigrateDdl>) -> Self {
        self.migrate = Some(migrate::MigrateBinding { ddl });
        self
    }

    /// The granted migrate-ddl binding, if any.
    #[cfg(feature = "migrate")]
    pub(crate) fn migrate(&self) -> Option<&migrate::MigrateBinding> {
        self.migrate.as_ref()
    }

    /// Grant the `capability` capability: `minter` signs a target capability (reaching the fleet
    /// key host-side), `project` is host-stamped as the token's forced audience, and `max_ttl_secs`
    /// is the operator ceiling the mint clamps to. The guest mints a bounded, own-project-only token.
    #[cfg(feature = "capability")]
    pub fn with_capability(
        mut self,
        project: impl Into<String>,
        minter: Arc<dyn capability::CapabilityMinter>,
        max_ttl_secs: u64,
    ) -> Self {
        self.capability = Some(capability::CapabilityBinding {
            project: project.into(),
            minter,
            max_ttl_secs,
        });
        self
    }

    /// The granted capability binding, if any.
    #[cfg(feature = "capability")]
    pub(crate) fn capability(&self) -> Option<&capability::CapabilityBinding> {
        self.capability.as_ref()
    }

    /// Bind the `session` grant: the controller for the current session (host-bound, so the guest
    /// addresses no id). The re-entry driver sets this per invocation.
    #[cfg(feature = "session")]
    pub fn with_session(mut self, controller: Arc<dyn session::SessionController>) -> Self {
        self.session = Some(session::SessionBinding { controller });
        self
    }

    /// The granted session binding, if any.
    #[cfg(feature = "session")]
    pub(crate) fn session(&self) -> Option<&session::SessionBinding> {
        self.session.as_ref()
    }

    /// Grant the `tenancy` capability (Gap 3): `source` host-verifies a guest-presented tenant
    /// credential (against the component's declared `token_claims` + `token` source) and seals it,
    /// and `context` is the SHARED producer-context cell it updates — pass
    /// [`producer_context_cell`](Self::producer_context_cell) so a successful `present-token` stamps
    /// the messages this invocation publishes. Deny-by-default: ungranted ⇒ `present-token` is
    /// `access-denied`.
    #[cfg(feature = "messaging")]
    pub fn with_present_token(
        mut self,
        source: Arc<dyn tenancy::ProducerContextSource>,
        context: messaging::ProducerContext,
    ) -> Self {
        self.tenancy_present = Some(tenancy::TenancyBinding { source, context });
        self
    }

    /// The granted `tenancy` (`present-token`) binding, if any.
    #[cfg(feature = "messaging")]
    pub(crate) fn tenancy_present(&self) -> Option<&tenancy::TenancyBinding> {
        self.tenancy_present.as_ref()
    }

    /// Grant the read-only `messaging-stats` capability: read per-topic bus gauges from `messaging`.
    /// A plain topic resolves under `prefix` (the component-private namespace, identical to
    /// [`with_messaging`](Self::with_messaging)); a `bus:<name>` topic must match one of `bus_templates`
    /// (the component's declared stats-topic templates) and the host substitutes `resolved_tenant` for
    /// each template's `{tenant}` placeholder — so the guest can only ever read stats for its own
    /// namespace or, on the bus, exactly its own resolved tenant's topic. `resolved_tenant` is the
    /// host-resolved tenant value (never guest input); `None` ⇒ a `{tenant}` template is refused.
    #[cfg(feature = "messaging")]
    pub fn with_messaging_stats(
        mut self,
        prefix: impl Into<String>,
        bus_prefix: impl Into<String>,
        messaging: Arc<dyn Messaging>,
        bus_templates: Vec<String>,
        resolved_tenant: Option<String>,
    ) -> Self {
        self.messaging_stats = Some(messaging_stats::StatsBinding {
            messaging,
            prefix: prefix.into(),
            bus_prefix: bus_prefix.into(),
            bus_templates,
            resolved_tenant,
        });
        self
    }

    /// The granted `messaging-stats` binding, if any. Public so a host-side caller (e.g. a live-gate
    /// test) can drive the read-only stats reads against the real substrate without a wasm guest.
    #[cfg(feature = "messaging")]
    pub fn messaging_stats(&self) -> Option<&messaging_stats::StatsBinding> {
        self.messaging_stats.as_ref()
    }

    /// Grant the `tenant-secrets` capability (task #493): `store` is the sealed per-tenant store,
    /// `project` is host-stamped (the guest never names it), `resolved_tenant` is THIS invocation's
    /// host-resolved own-tenant (`None` ⇒ every call is `no-resolved-tenant`), `allow_names` is the
    /// component's `tenant_secret_names` allowlist (empty ⇒ deny-all), and `can_read`/`can_write`
    /// are the two INDEPENDENT rights (`tenant-secrets:read` / `tenant-secrets:admin`). Deny-by-
    /// default: without this grant every call returns `access-denied`. The guest supplies only the
    /// secret name; the host keys `(project, resolved_tenant, name)`.
    #[cfg(feature = "tenant-secrets")]
    #[allow(clippy::too_many_arguments)]
    pub fn with_tenant_secrets(
        mut self,
        store: Arc<boatramp_core::secret_store::TenantSecretStore>,
        project: impl Into<String>,
        resolved_tenant: Option<String>,
        allow_names: Vec<String>,
        can_read: bool,
        can_write: bool,
    ) -> Self {
        self.tenant_secrets = Some(tenant_secrets::TenantSecretsBinding {
            store,
            project: project.into(),
            resolved_tenant,
            allow_names,
            can_read,
            can_write,
        });
        self
    }

    /// The granted `tenant-secrets` binding, if any. Public so a host-side caller (a live-gate test)
    /// can drive the sealed CRUD against the real store + envelope without instantiating a wasm
    /// guest — the same pattern as [`messaging_stats`](Self::messaging_stats).
    #[cfg(feature = "tenant-secrets")]
    pub fn tenant_secrets(&self) -> Option<&tenant_secrets::TenantSecretsBinding> {
        self.tenant_secrets.as_ref()
    }
}
