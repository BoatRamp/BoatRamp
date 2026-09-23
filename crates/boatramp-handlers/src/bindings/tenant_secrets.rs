//! The **`tenant-secrets`** host binding (`boatramp:handlers/tenant-secrets`, task #493): a granted
//! guest reads/writes secrets **sealed to THIS invocation's resolved tenant**. The host keys every
//! op `(project, resolved_tenant, name)` on a [`TenantSecretStore`] and seals with the operator's
//! `[secrets]` envelope; the guest supplies ONLY the secret `name`.
//!
//! # The security model (why a guest can never touch another tenant's secret)
//!
//! 1. **The tenant is host-supplied, never guest-supplied.** The WIT surface has no tenant
//!    parameter. The host holds [`resolved_tenant`](TenantSecretsBinding::resolved_tenant) — the
//!    own-`tenant` fact the SQL scope injector resolves — and keys the store with it. A guest cannot
//!    name, override, or forge it (mirrors the `messaging-stats` `{tenant}` template crux).
//! 2. **Deny-by-default.** No grant ⇒ no binding ([`TenantSecretsHost::new(None)`]) ⇒ every call
//!    returns `access-denied`.
//! 3. **No single resolved tenant ⇒ `no-resolved-tenant`, before any store access.** An
//!    `all`/anonymous/unscoped handler has no tenant to confine to; the binding fails closed rather
//!    than fall back to a project-wide or "first" tenant. (Distinct from `access-denied` — UX C1.)
//! 4. **Independent rights, re-checked per call.** `get`/`list` need [`can_read`], `set`/`delete`
//!    need [`can_write`]; the two derive from the SEPARATE `tenant-secrets:read` /
//!    `tenant-secrets:admin` grants, neither implied by deploy/publish.
//! 5. **A per-component name allowlist.** [`allow_names`](TenantSecretsBinding::allow_names) filters
//!    WHICH names are reachable: empty ⇒ deny-all; a name not in it ⇒ `access-denied` (before store
//!    access). Least-privilege (UX C2).
//! 6. **The tenant + name are re-validated fail-closed INSIDE the store** (`validate_resource_name`
//!    / `validate_name`) before they compose a key — so even a host bug that let a `/`-bearing
//!    tenant through cannot reshape the key to a sibling's (defense in depth).
//! 7. **Values never appear on `list`** — it returns names + metadata only.

use std::sync::Arc;

use boatramp_core::project::ProjectRef;
use boatramp_core::secret_store::{SecretError, TenantSecretStore};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/tenant-secrets-host",
        async: {
            only_imports: ["get", "set", "delete", "list"],
        },
    });
}

use generated::boatramp::handlers::{tenant_secrets, tenant_secrets_types};

/// Why a tenant-secret op was refused (host-native; mapped 1:1 to the WIT `secret-error` for the
/// guest). Public so a host-side live gate can drive the binding's CRUD against the real store +
/// envelope and pattern-match the refusal WITHOUT depending on the generated WIT type. Mirrors the
/// `messaging-stats` [`StatsRefused`](super::messaging_stats::StatsRefused) pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantSecretRefused {
    /// The capability (the needed read/admin right) was not granted, or the name is outside the
    /// component's allowlist — deny-by-default.
    AccessDenied,
    /// This invocation has no single resolved tenant (an `all`/anonymous/unscoped handler) — fail
    /// closed here BEFORE any store access, never a project-wide or "first" tenant.
    NoResolvedTenant,
    /// The secret `name` is not a valid key segment (client-safe message).
    InvalidName(String),
    /// The value exceeds the per-secret size cap (client-safe message).
    ValueTooLarge(String),
    /// Any other host/backend failure (generic; internals logged host-side, never surfaced).
    Other(String),
}

impl TenantSecretRefused {
    /// Map a host-native refusal to the WIT `secret-error` the guest sees.
    fn into_wit(self) -> tenant_secrets_types::SecretError {
        match self {
            Self::AccessDenied => tenant_secrets_types::SecretError::AccessDenied,
            Self::NoResolvedTenant => tenant_secrets_types::SecretError::NoResolvedTenant,
            Self::InvalidName(m) => tenant_secrets_types::SecretError::InvalidName(m),
            Self::ValueTooLarge(m) => tenant_secrets_types::SecretError::ValueTooLarge(m),
            Self::Other(m) => tenant_secrets_types::SecretError::Other(m),
        }
    }
}

/// A per-invocation `tenant-secrets` grant: the sealed store, the owning project, THIS invocation's
/// host-resolved tenant, the per-component name allowlist, and the two independent rights.
///
/// Built by the server's `build_bindings` from the component's grants + the resolved own-tenant
/// fact. `resolved_tenant == None` ⇒ an unscoped invocation (`no-resolved-tenant` on every call).
#[derive(Clone)]
pub struct TenantSecretsBinding {
    /// The sealed per-tenant store (KV + `[secrets]` envelope), keyed `(project, tenant, name)`.
    pub(crate) store: Arc<TenantSecretStore>,
    /// The owning project (host-stamped; the guest never names it).
    pub(crate) project: String,
    /// THIS invocation's host-resolved tenant (the own-`tenant` scope fact, the same value the SQL
    /// scope injector uses). `None` ⇒ no single resolved tenant → every call is `no-resolved-tenant`.
    pub(crate) resolved_tenant: Option<String>,
    /// The component's `tenant_secret_names` allowlist: the names the guest may address. EMPTY ⇒
    /// deny-all (a name not present ⇒ `access-denied`). Least-privilege, matching `stats_topics`.
    pub(crate) allow_names: Vec<String>,
    /// Whether the read right (`tenant-secrets:read`) was granted — gates `get`/`list`.
    pub(crate) can_read: bool,
    /// Whether the admin right (`tenant-secrets:admin`) was granted — gates `set`/`delete`.
    pub(crate) can_write: bool,
}

impl TenantSecretsBinding {
    /// The resolved tenant to confine to, or `NoResolvedTenant` fail-closed. Checked BEFORE any
    /// store access, so an unscoped invocation never reaches the substrate.
    fn tenant(&self) -> Result<&str, TenantSecretRefused> {
        self.resolved_tenant
            .as_deref()
            .ok_or(TenantSecretRefused::NoResolvedTenant)
    }

    /// Whether the guest may address `name`: it must be in the component's allowlist. Empty allowlist
    /// ⇒ deny-all. A refused name is `access-denied` (before any store access), so the guest cannot
    /// distinguish "not allowlisted" from "not configured" for a name outside its grant.
    fn name_allowed(&self, name: &str) -> bool {
        self.allow_names.iter().any(|n| n == name)
    }

    fn project_ref(&self) -> ProjectRef<'_> {
        ProjectRef::new(&self.project)
    }

    /// Host-native `get` (the whole read path, applying the SAME right / allowlist / resolved-tenant
    /// gates the WIT `Host::get` applies). Public so a host-side live gate can drive the real store +
    /// envelope without a wasm guest — the WIT layer delegates here. `Ok(None)` = unset (not an
    /// error); `Err` carries the host-native [`TenantSecretRefused`] a guest would see mapped to WIT.
    pub async fn read(&self, name: &str) -> Result<Option<Vec<u8>>, TenantSecretRefused> {
        if !self.can_read || !self.name_allowed(name) {
            return Err(TenantSecretRefused::AccessDenied);
        }
        let tenant = self.tenant()?;
        self.store
            .get(self.project_ref(), tenant, name)
            .await
            .map_err(refuse)
    }

    /// Host-native `set` (applies the admin right + allowlist + resolved-tenant gates). Public for
    /// the live gate; the WIT `Host::set` delegates here.
    pub async fn write(
        &self,
        name: &str,
        value: &[u8],
    ) -> Result<boatramp_core::secret_store::SecretMeta, TenantSecretRefused> {
        if !self.can_write || !self.name_allowed(name) {
            return Err(TenantSecretRefused::AccessDenied);
        }
        let tenant = self.tenant()?;
        self.store
            .set(self.project_ref(), tenant, name, value)
            .await
            .map_err(refuse)
    }

    /// Host-native `delete` (applies the admin right + allowlist + resolved-tenant gates). Returns
    /// whether the secret existed. Public for the live gate; the WIT `Host::delete` delegates here.
    pub async fn remove(&self, name: &str) -> Result<bool, TenantSecretRefused> {
        if !self.can_write || !self.name_allowed(name) {
            return Err(TenantSecretRefused::AccessDenied);
        }
        let tenant = self.tenant()?;
        self.store
            .delete(self.project_ref(), tenant, name)
            .await
            .map_err(refuse)
    }

    /// Host-native `list` (read right; only the resolved tenant's own, allowlisted names; never a
    /// value). Public for the live gate; the WIT `Host::list` delegates here.
    pub async fn names(
        &self,
    ) -> Result<Vec<boatramp_core::secret_store::SecretMeta>, TenantSecretRefused> {
        if !self.can_read {
            return Err(TenantSecretRefused::AccessDenied);
        }
        let tenant = self.tenant()?;
        let metas = self
            .store
            .list(self.project_ref(), tenant)
            .await
            .map_err(refuse)?;
        Ok(metas
            .into_iter()
            .filter(|m| self.name_allowed(&m.name))
            .collect())
    }
}

/// Per-invocation view over the (optional) `tenant-secrets` grant. `None` ⇒ not granted
/// (deny-by-default: every call ⇒ `access-denied`).
pub struct TenantSecretsHost<'a> {
    binding: Option<&'a TenantSecretsBinding>,
}

impl<'a> TenantSecretsHost<'a> {
    /// Build a view; `None` means the capability was not granted.
    pub fn new(binding: Option<&'a TenantSecretsBinding>) -> Self {
        Self { binding }
    }
}

/// Map a host-native [`SecretError`] to a [`TenantSecretRefused`]. A **client** error (invalid name,
/// oversized value) surfaces its request-shaped message; a **backend** error is logged host-side and
/// returned generically (never leaking KV key shapes / KMS detail). An `InvalidTenant` should be
/// impossible here (the host resolves the tenant as a single segment) — but if the store rejects it,
/// do NOT echo the tenant; return a generic refusal.
fn refuse(err: SecretError) -> TenantSecretRefused {
    match err {
        SecretError::InvalidName(m) => TenantSecretRefused::InvalidName(m),
        SecretError::InvalidTenant(_) => {
            TenantSecretRefused::Other("invalid resolved tenant".to_string())
        }
        // The size message describes the request (a byte count + the max), never the value bytes.
        e @ SecretError::ValueTooLarge { .. } => TenantSecretRefused::ValueTooLarge(e.to_string()),
        SecretError::TooManyNames { max } => TenantSecretRefused::Other(format!(
            "this tenant already holds the maximum of {max} secret names"
        )),
        SecretError::Backend(detail) => {
            tracing::warn!(%detail, "tenant-secrets backend error");
            TenantSecretRefused::Other("tenant-secrets backend error".to_string())
        }
    }
}

/// Map the store's value-free metadata to the WIT record.
fn meta_to_wit(m: boatramp_core::secret_store::SecretMeta) -> tenant_secrets_types::SecretMeta {
    tenant_secrets_types::SecretMeta {
        name: m.name,
        created_at: m.created_at,
        updated_at: m.updated_at,
        revision: m.revision,
    }
}

impl tenant_secrets::Host for TenantSecretsHost<'_> {
    async fn get(
        &mut self,
        name: String,
    ) -> Result<Option<Vec<u8>>, tenant_secrets_types::SecretError> {
        // Deny-by-default: no grant ⇒ no binding ⇒ access-denied. The binding then applies the
        // read right + allowlist + resolved-tenant gates (all before any store access).
        match self.binding {
            Some(b) => b.read(&name).await.map_err(TenantSecretRefused::into_wit),
            None => Err(tenant_secrets_types::SecretError::AccessDenied),
        }
    }

    async fn set(
        &mut self,
        name: String,
        value: Vec<u8>,
    ) -> Result<tenant_secrets_types::SecretMeta, tenant_secrets_types::SecretError> {
        match self.binding {
            Some(b) => b
                .write(&name, &value)
                .await
                .map(meta_to_wit)
                .map_err(TenantSecretRefused::into_wit),
            None => Err(tenant_secrets_types::SecretError::AccessDenied),
        }
    }

    async fn delete(&mut self, name: String) -> Result<bool, tenant_secrets_types::SecretError> {
        match self.binding {
            Some(b) => b.remove(&name).await.map_err(TenantSecretRefused::into_wit),
            None => Err(tenant_secrets_types::SecretError::AccessDenied),
        }
    }

    async fn list(
        &mut self,
    ) -> Result<Vec<tenant_secrets_types::SecretMeta>, tenant_secrets_types::SecretError> {
        match self.binding {
            Some(b) => b
                .names()
                .await
                .map(|metas| metas.into_iter().map(meta_to_wit).collect())
                .map_err(TenantSecretRefused::into_wit),
            None => Err(tenant_secrets_types::SecretError::AccessDenied),
        }
    }
}

/// Add the `tenant-secrets` interface to `linker`, resolving the per-invocation
/// [`TenantSecretsHost`] via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> TenantSecretsHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    tenant_secrets::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::tenant_secrets::Host;
    use super::*;
    use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
    use boatramp_core::kv::MemoryKv;

    struct XorEnvelope;
    #[async_trait::async_trait]
    impl KeyEnvelope for XorEnvelope {
        async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(plaintext.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(wrapped.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    fn store() -> Arc<TenantSecretStore> {
        Arc::new(TenantSecretStore::new(
            Arc::new(MemoryKv::new()),
            Arc::new(XorEnvelope),
        ))
    }

    fn binding(
        store: Arc<TenantSecretStore>,
        tenant: Option<&str>,
        allow: &[&str],
        can_read: bool,
        can_write: bool,
    ) -> TenantSecretsBinding {
        TenantSecretsBinding {
            store,
            project: "acme".to_string(),
            resolved_tenant: tenant.map(str::to_owned),
            allow_names: allow.iter().map(ToString::to_string).collect(),
            can_read,
            can_write,
        }
    }

    #[tokio::test]
    async fn ungranted_calls_are_access_denied() {
        let mut host = TenantSecretsHost::new(None);
        assert!(matches!(
            host.get("oauth_secret".into()).await.unwrap_err(),
            tenant_secrets_types::SecretError::AccessDenied
        ));
        assert!(matches!(
            host.set("oauth_secret".into(), b"x".to_vec())
                .await
                .unwrap_err(),
            tenant_secrets_types::SecretError::AccessDenied
        ));
        assert!(matches!(
            host.list().await.unwrap_err(),
            tenant_secrets_types::SecretError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn set_get_round_trip_within_the_resolved_tenant() {
        let s = store();
        let b = binding(s.clone(), Some("firm-a"), &["oauth_secret"], true, true);
        let mut host = TenantSecretsHost::new(Some(&b));
        let meta = host
            .set("oauth_secret".into(), b"s3cr3t".to_vec())
            .await
            .unwrap();
        assert_eq!(meta.name, "oauth_secret");
        assert_eq!(meta.revision, 1);
        let got = host.get("oauth_secret".into()).await.unwrap();
        assert_eq!(got.as_deref(), Some(&b"s3cr3t"[..]));
    }

    #[tokio::test]
    async fn a_different_tenant_cannot_read_the_value_isolation() {
        // THE isolation property at the binding layer: tenant A sets `oauth_secret`; a binding over
        // the SAME store resolving to tenant B gets `none` for the same name.
        let s = store();
        let a = binding(s.clone(), Some("firm-a"), &["oauth_secret"], true, true);
        TenantSecretsHost::new(Some(&a))
            .set("oauth_secret".into(), b"a-secret".to_vec())
            .await
            .unwrap();
        let b = binding(s.clone(), Some("firm-b"), &["oauth_secret"], true, true);
        let got = TenantSecretsHost::new(Some(&b))
            .get("oauth_secret".into())
            .await
            .unwrap();
        assert!(got.is_none(), "tenant B must not see tenant A's secret");
    }

    #[tokio::test]
    async fn unconfigured_name_is_ok_none_not_an_error() {
        let s = store();
        let b = binding(s, Some("firm-a"), &["oauth_secret"], true, true);
        let got = TenantSecretsHost::new(Some(&b))
            .get("oauth_secret".into())
            .await
            .unwrap();
        assert!(got.is_none(), "an unset name is ok(none), never an error");
    }

    #[tokio::test]
    async fn no_resolved_tenant_is_refused_before_store_access() {
        // An unscoped (all/anonymous) invocation: no resolved tenant ⇒ no-resolved-tenant on every
        // call, distinct from access-denied, and BEFORE the store is touched.
        let s = store();
        let b = binding(s, None, &["oauth_secret"], true, true);
        let mut host = TenantSecretsHost::new(Some(&b));
        assert!(matches!(
            host.get("oauth_secret".into()).await.unwrap_err(),
            tenant_secrets_types::SecretError::NoResolvedTenant
        ));
        assert!(matches!(
            host.set("oauth_secret".into(), b"x".to_vec())
                .await
                .unwrap_err(),
            tenant_secrets_types::SecretError::NoResolvedTenant
        ));
        assert!(matches!(
            host.list().await.unwrap_err(),
            tenant_secrets_types::SecretError::NoResolvedTenant
        ));
    }

    #[tokio::test]
    async fn read_right_alone_cannot_write() {
        // Independent rights: a read-only binding refuses set/delete with access-denied, even with a
        // resolved tenant and an allowlisted name.
        let s = store();
        let b = binding(s, Some("firm-a"), &["oauth_secret"], true, false);
        let mut host = TenantSecretsHost::new(Some(&b));
        assert!(matches!(
            host.set("oauth_secret".into(), b"x".to_vec())
                .await
                .unwrap_err(),
            tenant_secrets_types::SecretError::AccessDenied
        ));
        assert!(matches!(
            host.delete("oauth_secret".into()).await.unwrap_err(),
            tenant_secrets_types::SecretError::AccessDenied
        ));
        // But get/list are fine.
        assert!(host.get("oauth_secret".into()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn admin_right_alone_cannot_read() {
        let s = store();
        let b = binding(s, Some("firm-a"), &["oauth_secret"], false, true);
        let mut host = TenantSecretsHost::new(Some(&b));
        assert!(matches!(
            host.get("oauth_secret".into()).await.unwrap_err(),
            tenant_secrets_types::SecretError::AccessDenied
        ));
        assert!(matches!(
            host.list().await.unwrap_err(),
            tenant_secrets_types::SecretError::AccessDenied
        ));
        // But set is fine.
        assert!(host.set("oauth_secret".into(), b"x".to_vec()).await.is_ok());
    }

    #[tokio::test]
    async fn a_name_outside_the_allowlist_is_access_denied() {
        let s = store();
        // Allowlist permits only `oauth_secret`; a different name is refused before store access.
        let b = binding(s, Some("firm-a"), &["oauth_secret"], true, true);
        let mut host = TenantSecretsHost::new(Some(&b));
        assert!(matches!(
            host.get("stripe_key".into()).await.unwrap_err(),
            tenant_secrets_types::SecretError::AccessDenied
        ));
        assert!(matches!(
            host.set("stripe_key".into(), b"x".to_vec())
                .await
                .unwrap_err(),
            tenant_secrets_types::SecretError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn empty_allowlist_denies_every_name() {
        let s = store();
        let b = binding(s, Some("firm-a"), &[], true, true);
        let mut host = TenantSecretsHost::new(Some(&b));
        assert!(matches!(
            host.get("oauth_secret".into()).await.unwrap_err(),
            tenant_secrets_types::SecretError::AccessDenied
        ));
        // list is right-gated (can_read) but returns an empty set for an empty allowlist.
        assert!(host.list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_returns_only_allowlisted_names_and_never_values() {
        let s = store();
        // Seed two names for firm-a directly via the store (both real), but the component's
        // allowlist only covers `oauth_secret` — so list shows only that one.
        let writer = binding(
            s.clone(),
            Some("firm-a"),
            &["oauth_secret", "stripe_key"],
            true,
            true,
        );
        TenantSecretsHost::new(Some(&writer))
            .set("oauth_secret".into(), b"a".to_vec())
            .await
            .unwrap();
        TenantSecretsHost::new(Some(&writer))
            .set("stripe_key".into(), b"b".to_vec())
            .await
            .unwrap();
        let reader = binding(s, Some("firm-a"), &["oauth_secret"], true, true);
        let metas = TenantSecretsHost::new(Some(&reader)).list().await.unwrap();
        let names: Vec<_> = metas.iter().map(|m| m.name.clone()).collect();
        assert_eq!(names, vec!["oauth_secret".to_string()]);
        // secret-meta structurally has no value field — nothing to assert away, but confirm the
        // record carries only metadata.
        assert_eq!(metas[0].revision, 1);
    }
}
