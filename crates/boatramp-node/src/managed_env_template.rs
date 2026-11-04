//! The shared **managed-env template engine + render stage** (PLAN-compute-managed-resources
//! Phase 3).
//!
//! A compute workload's operator writes its env as plain `{{key}}` templates referencing a
//! `{surface}.*` namespace — `{{sql.dsn}}`, `{{kv.url}}`, `{{kv.token}}`, `{{blob.access_key}}`,
//! `{{messaging.token}}`, `{{secret.NAME}}` — and boatramp fills them SERVER-SIDE at launch from
//! the resolved bindings + minted credentials. Phase 1 rendered only `{{sql.*}}` (inside the
//! managed-DB DSN resolver); Phase 3 promotes the expander here so EVERY surface resolver
//! contributes a [`SurfaceContribution`] and ONE stage ([`apply_env_render`]) renders the whole
//! `env` against the union, failing CLOSED on an unknown key so a workload never receives a
//! half-rendered secret/DSN/token.
//!
//! - [`render`] / [`referenced_keys`] — the pure `{{key}}` expander (single-pass, fail-closed),
//!   the ONE place a template is expanded (moved here from `managed_db_dsn`, unchanged behavior).
//! - [`apply_env_render`] — the render stage: unseal referenced `{{secret.NAME}}`s, render each
//!   templated `env` value once against the union vars, then fold the per-surface defaults for
//!   the keys the operator did not set.
//! - [`RenderStageResolver`] — the top-level [`ComputeBindingResolver`] the node hands the
//!   reconcile: it wraps the per-surface resolver chain, calls
//!   [`contribute`](ComputeBindingResolver::contribute) to gather the union, and renders once.
//!   The per-surface resolvers (the sql DSN injector + the kv/blob/messaging shims) no longer
//!   render — they only CONTRIBUTE vars + defaults.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::compute::{ComputeBinding, ComputeBindingResolver, SurfaceContribution};
use boatramp_core::project::ProjectRef;
use boatramp_core::secret_store::SecretStore;

/// A fail-closed `{{key}}` template error. A typed `thiserror` enum (never an untyped error box)
/// so the render stage can log a distinct reason; the raw template is then left in place
/// (diagnosable) and nothing is injected for that key.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TemplateError {
    /// A `{{key}}` placeholder names a variable not in the resolved set (an unknown surface key,
    /// a misspelling, or an unresolved `{{secret.NAME}}`). Fail closed — never inject a blank.
    #[error("unknown placeholder `{{{{{0}}}}}`")]
    UnknownKey(String),
    /// A `{{` with no closing `}}` — a malformed template. Fail closed.
    #[error("unclosed `{{{{` placeholder")]
    Unclosed,
}

/// The template keys referenced by `{{key}}` placeholders in `text` (keys trimmed). A minimal,
/// documented placeholder syntax: `{{` opens, `}}` closes; an unclosed `{{` ends the scan. Used
/// to pre-collect `secret.<NAME>` references so they are unsealed before the (synchronous)
/// [`render`].
pub fn referenced_keys(text: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            break;
        };
        let key = after[..close].trim();
        if !key.is_empty() {
            keys.push(key.to_string());
        }
        rest = &after[close + 2..];
    }
    keys
}

/// Render `{{key}}` placeholders in `template` from `vars`. Literal text passes through; an
/// unknown placeholder or an unclosed `{{` is an error (fail closed — the caller then leaves the
/// raw template in place rather than inject a half-rendered value). The one place a template is
/// expanded.
pub fn render(template: &str, vars: &BTreeMap<String, String>) -> Result<String, TemplateError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let close = after.find("}}").ok_or(TemplateError::Unclosed)?;
        let key = after[..close].trim();
        let value = vars
            .get(key)
            .ok_or_else(|| TemplateError::UnknownKey(key.to_string()))?;
        out.push_str(value);
        rest = &after[close + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The **unified render stage**: given a surface `contribution` (the union of every resolver's
/// `{surface}.*` vars + per-surface defaults) and the operator's `env`, (1) unseal any
/// `{{secret.NAME}}` the env references via `secret_store`, (2) render each templated `env` value
/// ONCE against the combined vars, and (3) fold the defaults for the keys the operator did not
/// set. Returns the `(env_key, value)` pairs to inject at launch (the reconcile's `launch_one`
/// fold then applies them: a rendered template REPLACES the raw `{{…}}` value; a default fills an
/// unset key; a hand-set literal always wins).
///
/// Fail-closed throughout: an unresolvable `{{secret.NAME}}` is left out of the vars so the render
/// of any value that references it errors and injects NOTHING for that key (the raw template stays,
/// diagnosable); a render error likewise injects nothing. Secrets are unsealed transiently and
/// NEVER logged.
pub async fn apply_env_render(
    project: &str,
    workload: &str,
    env: &BTreeMap<String, String>,
    contribution: SurfaceContribution,
    secret_store: Option<&Arc<SecretStore>>,
) -> Vec<(String, String)> {
    let mut vars = contribution.vars;

    // 1. Unseal any `{{secret.<NAME>}}` referenced by a templated env value — SERVER-SIDE. An
    //    absent/unavailable secret is left unresolved so the render fails closed for that value.
    let mut secret_names: BTreeSet<String> = BTreeSet::new();
    for value in env.values() {
        if value.contains("{{") {
            for key in referenced_keys(value) {
                if let Some(name) = key.strip_prefix("secret.") {
                    secret_names.insert(name.to_string());
                }
            }
        }
    }
    for name in &secret_names {
        match resolve_secret(secret_store, project, name).await {
            Ok(Some(value)) => {
                vars.insert(format!("secret.{name}"), value);
            }
            Ok(None) => tracing::warn!(
                %project,
                %workload,
                secret = %name,
                "managed-env render: referenced secret is unset or no secret store configured"
            ),
            Err(e) => tracing::warn!(
                %project,
                %workload,
                secret = %name,
                error = %e,
                "managed-env render: referenced secret could not be unsealed"
            ),
        }
    }

    let mut out: Vec<(String, String)> = Vec::new();

    // 2. Render the operator's env templates. A render error leaves the raw template in place
    //    (diagnosable) and injects nothing for that key.
    for (key, value) in env {
        if !value.contains("{{") {
            continue;
        }
        match render(value, &vars) {
            Ok(rendered) => out.push((key.clone(), rendered)),
            Err(e) => tracing::warn!(
                %project,
                %workload,
                key = %key,
                error = %e,
                "managed-env render: env template left unrendered"
            ),
        }
    }

    // 3. Defaults: inject each surface default ONLY for a key the operator did not set (a hand-set
    //    literal or an operator template for that key always wins).
    for (key, value) in contribution.defaults {
        if !env.contains_key(&key) {
            out.push((key, value));
        }
    }

    out
}

/// Unseal the project-scoped sealed secret `name` to its UTF-8 value. `Ok(None)` when no secret
/// store is wired or the secret is absent. The value is NEVER logged.
async fn resolve_secret(
    secret_store: Option<&Arc<SecretStore>>,
    project: &str,
    name: &str,
) -> Result<Option<String>, String> {
    let Some(store) = secret_store else {
        return Ok(None);
    };
    match store.get(ProjectRef::new(project), name).await {
        Ok(Some(bytes)) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| format!("secret {name:?} is not valid UTF-8")),
        Ok(None) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// The top-level [`ComputeBindingResolver`] the node hands the reconcile: it WRAPS the per-surface
/// resolver chain and performs the ONE [`apply_env_render`] stage at launch.
///
/// - [`resolve_with_env`](ComputeBindingResolver::resolve_with_env) (launch) gathers the chain's
///   [`SurfaceContribution`] via [`contribute`](ComputeBindingResolver::contribute) — which
///   registers every surface's per-replica shim state (tokens / minted creds) — then renders the
///   operator `env` once against the union + folds the defaults.
/// - [`resolve`](ComputeBindingResolver::resolve) (the per-tick repopulation path, no env)
///   delegates to the chain's `resolve`, re-registering the cheap shim tokens WITHOUT re-minting
///   any launch-only credential.
/// - [`release`](ComputeBindingResolver::release) delegates to the chain (deregister tokens).
pub struct RenderStageResolver {
    inner: Arc<dyn ComputeBindingResolver>,
    secret_store: Option<Arc<SecretStore>>,
}

impl RenderStageResolver {
    /// Wrap `inner` (the per-surface resolver chain). `secret_store` backs `{{secret.<NAME>}}`
    /// (`None` ⇒ a secret reference fails closed for that value).
    pub fn wrap(
        inner: Arc<dyn ComputeBindingResolver>,
        secret_store: Option<Arc<SecretStore>>,
    ) -> Arc<dyn ComputeBindingResolver> {
        Arc::new(Self {
            inner,
            secret_store,
        })
    }
}

#[async_trait]
impl ComputeBindingResolver for RenderStageResolver {
    async fn resolve(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) -> Vec<(String, String)> {
        // No operator env (the reconcile's per-tick token-repopulation path): just re-register the
        // shim tokens via the chain. No launch-only credential is minted here.
        self.inner
            .resolve(project, workload, replica, bindings)
            .await
    }

    async fn resolve_with_env(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
        workload_env: &BTreeMap<String, String>,
    ) -> Vec<(String, String)> {
        let contribution = self
            .inner
            .contribute(project, workload, replica, bindings, workload_env)
            .await;
        apply_env_render(
            project,
            workload,
            workload_env,
            contribution,
            self.secret_store.as_ref(),
        )
        .await
    }

    async fn contribute(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
        workload_env: &BTreeMap<String, String>,
    ) -> SurfaceContribution {
        // Passthrough: a wrapped render stage still exposes the union (so nesting is coherent).
        self.inner
            .contribute(project, workload, replica, bindings, workload_env)
            .await
    }

    async fn release(
        &self,
        project: &str,
        workload: &str,
        replica: u32,
        bindings: &[ComputeBinding],
    ) {
        self.inner
            .release(project, workload, replica, bindings)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("sql.host".to_string(), "pg-acme".to_string()),
            ("sql.port".to_string(), "5432".to_string()),
            ("sql.user".to_string(), "app".to_string()),
            ("sql.password".to_string(), "s3cr3t".to_string()),
            ("sql.database".to_string(), "appdb".to_string()),
            ("kv.url".to_string(), "http://10.0.0.1:8084".to_string()),
            ("kv.token".to_string(), "kvtok".to_string()),
            ("secret.API_KEY".to_string(), "xyz".to_string()),
        ])
    }

    #[test]
    fn render_fills_placeholders_and_passes_literals() {
        let v = vars();
        assert_eq!(
            render(
                "postgres://{{sql.user}}:{{sql.password}}@{{sql.host}}:{{sql.port}}/{{sql.database}}?sslmode=require",
                &v
            )
            .unwrap(),
            "postgres://app:s3cr3t@pg-acme:5432/appdb?sslmode=require"
        );
        // Discrete + whitespace in the placeholder + a static literal mixed in.
        assert_eq!(render("{{ sql.host }}", &v).unwrap(), "pg-acme");
        assert_eq!(
            render("key={{secret.API_KEY}};x=1", &v).unwrap(),
            "key=xyz;x=1"
        );
        // A single value may interleave surfaces (the whole point of ONE render stage).
        assert_eq!(
            render("{{sql.host}}|{{kv.url}}|{{kv.token}}", &v).unwrap(),
            "pg-acme|http://10.0.0.1:8084|kvtok"
        );
        assert_eq!(
            render("no placeholders here", &v).unwrap(),
            "no placeholders here"
        );
    }

    #[test]
    fn render_fails_closed_on_unknown_or_unclosed() {
        let v = vars();
        assert_eq!(
            render("{{sql.nope}}", &v),
            Err(TemplateError::UnknownKey("sql.nope".to_string()))
        );
        assert_eq!(
            render("{{secret.MISSING}}", &v),
            Err(TemplateError::UnknownKey("secret.MISSING".to_string()))
        );
        assert_eq!(render("{{sql.host", &v), Err(TemplateError::Unclosed));
    }

    #[test]
    fn referenced_keys_collects_each_placeholder() {
        let keys = referenced_keys("{{sql.user}}@{{sql.host}} {{secret.API_KEY}}");
        assert_eq!(keys, vec!["sql.user", "sql.host", "secret.API_KEY"]);
        // Only `secret.*` keys become secret lookups.
        let secrets: Vec<&str> = keys
            .iter()
            .filter_map(|k| k.strip_prefix("secret."))
            .collect();
        assert_eq!(secrets, vec!["API_KEY"]);
    }

    /// The render stage renders a templated env value AND injects a default for an unset key, but
    /// NEVER a default for a key the operator already set (literal or template).
    #[tokio::test]
    async fn apply_env_render_renders_then_folds_defaults() {
        let contribution = SurfaceContribution {
            vars: BTreeMap::from([
                ("kv.url".to_string(), "http://10.0.0.1:8084".to_string()),
                ("kv.token".to_string(), "kvtok".to_string()),
            ]),
            defaults: vec![
                (
                    "BOATRAMP_KV_URL".to_string(),
                    "http://10.0.0.1:8084".to_string(),
                ),
                (
                    "BOATRAMP_KV_URL_AUTH_TOKEN".to_string(),
                    "kvtok".to_string(),
                ),
            ],
        };
        let env = BTreeMap::from([
            // A template into an arbitrary env var — rendered from the union vars.
            ("REDIS_URL".to_string(), "{{kv.url}}".to_string()),
            // A hand-set literal for a default key — the default must NOT override it.
            ("BOATRAMP_KV_URL".to_string(), "http://hand-set".to_string()),
        ]);
        let out = apply_env_render("default", "api", &env, contribution, None).await;
        let get = |k: &str| {
            out.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("REDIS_URL"), Some("http://10.0.0.1:8084"));
        // The operator's literal is not clobbered — no default emitted for that key.
        assert_eq!(get("BOATRAMP_KV_URL"), None);
        // The unset token default IS injected.
        assert_eq!(get("BOATRAMP_KV_URL_AUTH_TOKEN"), Some("kvtok"));
    }

    /// An unresolved key (no var, no secret store) fails closed: the templated value is dropped,
    /// never injected half-rendered.
    #[tokio::test]
    async fn apply_env_render_fails_closed_on_unresolved() {
        let contribution = SurfaceContribution::default();
        let env = BTreeMap::from([
            ("X".to_string(), "{{secret.MISSING}}".to_string()),
            ("Y".to_string(), "{{kv.nope}}".to_string()),
        ]);
        let out = apply_env_render("default", "api", &env, contribution, None).await;
        assert!(
            out.is_empty(),
            "unresolved templates inject nothing: {out:?}"
        );
    }
}
