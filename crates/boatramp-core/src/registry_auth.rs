//! Authenticated **private registry pull** for compute workloads (PLAN-compute-registry-auth).
//!
//! A workload whose [`RootSource::Image`](boatramp_types::compute::RootSource::Image) names a
//! private image needs a registry credential to pull it. boatramp never puts that credential in
//! plaintext anywhere: it is a **sealed secret** (the SAME `[secrets]` envelope + project
//! [`SecretStore`](crate::secret_store::SecretStore) that seal a managed-DB credential), resolved
//! HOST-SIDE at materialize time and handed to the backend as a transient [`RegistryAuth`].
//!
//! # Two credential scopes
//!
//! - **Project author / tenant-scoped** — the workload's spec names a
//!   [`pull_secret`](boatramp_types::compute::ComputeSpec::pull_secret): a sealed secret in the
//!   workload's OWN project (`project/<proj>/secret/<name>`). The owning project comes from the
//!   workload's key, NEVER from guest input, so a workload can only ever resolve a credential from
//!   its own project — the same structural tenancy boundary as a `sql` binding.
//! - **Operator / node-wide** — a `[compute].registry_auth` host → secret-ref map an operator sets
//!   (System-level authority). When an image's registry host matches, the referenced sealed secret
//!   (stored under the reserved, tenant-unreachable [`OPERATOR_REGISTRY_PROJECT`]) authenticates the
//!   pull. For operator-provisioned fleet images; auto-applied by host match.
//!
//! # Resolution order (per image)
//!
//! 1. The spec names a `pull_secret` → resolve it from the workload's project. Missing/malformed ⇒
//!    **FAIL CLOSED** ([`RegistryAuthError`]); NEVER a silent anonymous fallback.
//! 2. Else the image's registry host matches an operator `[compute].registry_auth` entry → resolve
//!    the referenced operator secret. Missing/malformed ⇒ **FAIL CLOSED** (the operator intended
//!    auth for this host).
//! 3. Else → `Ok(None)`: an **anonymous** pull (only when NO credential is referenced AND no
//!    operator host match exists).
//!
//! # No plaintext, ever
//!
//! Only secret NAMES/refs live in the spec, the config, and the error messages. The credential VALUE
//! exists only transiently as a [`RegistryCredential`] (unsealed) → [`RegistryAuth`] (passed to the
//! backend). Both have a **redacting `Debug`** so a credential can never reach a log, a `tracing`
//! event, or a surfaced error, however carelessly it is formatted (proven by
//! `redacting_debug_never_leaks_the_password`).

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::secret_store::{SecretError, SecretStore};

/// The default registry host an un-prefixed image reference (`nginx:latest`,
/// `library/alpine`) resolves to — Docker Hub. Operator `[compute].registry_auth` keys match
/// against the value [`registry_host_of`] returns, so a Hub credential is keyed on exactly this.
pub const DEFAULT_REGISTRY_HOST: &str = "docker.io";

/// The reserved, **tenant-unreachable** project under which operator node-wide registry
/// credentials are sealed (`project/.boatramp-registry/secret/<ref>`). The `.boatramp*` namespace
/// is reserved — a tenant project can never be named this (see `crate::project`) — so an operator
/// node-wide credential can never collide with, or be reached by, any tenant's project secret
/// store. Used ONLY host-side (the resolver + the System·Admin operator endpoint); never exposed in
/// a URL path a tenant could hit.
pub const OPERATOR_REGISTRY_PROJECT: &str = ".boatramp-registry";

/// A registry credential's **plaintext** — the JSON that a sealed registry-auth secret holds
/// (`{ "username": …, "password": … }`), for BOTH scopes. Unsealed transiently at resolve time; the
/// VALUE never leaves the host. `Debug` is hand-written to REDACT the password (see the module
/// docs) — do not derive it.
#[derive(Clone, Serialize, Deserialize)]
pub struct RegistryCredential {
    /// The registry username.
    pub username: String,
    /// The registry password / token. REDACTED by `Debug`.
    pub password: String,
}

impl std::fmt::Debug for RegistryCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryCredential")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// A **resolved** registry pull credential, handed transiently to a backend's materialize/pull
/// path. Carries the `serveraddress` (the registry host the credential is for) so the backend can
/// set it on the wire auth. `Debug` REDACTS the password — never derive it.
#[derive(Clone)]
pub struct RegistryAuth {
    /// The registry username.
    pub username: String,
    /// The registry password / token. REDACTED by `Debug`.
    pub password: String,
    /// The registry host this credential authenticates against (e.g. `ghcr.io`,
    /// `docker.io`), for the backend's wire auth `serveraddress`.
    pub serveraddress: String,
}

impl std::fmt::Debug for RegistryAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryAuth")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("serveraddress", &self.serveraddress)
            .finish()
    }
}

impl RegistryAuth {
    fn from_credential(cred: RegistryCredential, host: &str) -> Self {
        Self {
            username: cred.username,
            password: cred.password,
            serveraddress: host.to_string(),
        }
    }
}

/// A registry-auth **resolution** failure — all FAIL-CLOSED (the pull is refused, never downgraded
/// to anonymous). Every message names only the NON-secret ref/host — never the credential value.
#[derive(Debug, thiserror::Error)]
pub enum RegistryAuthError {
    /// The spec named a project `pull_secret` that does not exist in the workload's project secret
    /// store. Fail closed — do NOT fall back to an anonymous pull.
    #[error(
        "registry pull-secret {secret:?} is not set in this project's secret store \
         (set it with `boatramp compute registry-auth set`); refusing to pull anonymously"
    )]
    MissingProjectSecret {
        /// The referenced secret NAME (not a credential).
        secret: String,
    },
    /// The image's host matched an operator `[compute].registry_auth` entry, but the referenced
    /// operator secret is not set. Fail closed.
    #[error(
        "operator registry credential {secret:?} for host {host:?} is not set; \
         refusing to pull anonymously"
    )]
    MissingOperatorSecret {
        /// The operator secret REF (not a credential).
        secret: String,
        /// The registry host that matched.
        host: String,
    },
    /// A resolved sealed secret did not deserialize as a `{ "username", "password" }`
    /// [`RegistryCredential`]. The detail is NOT included (it could echo the sealed plaintext) —
    /// fail closed with only the ref.
    #[error(
        "registry credential {secret:?} is malformed (expected JSON \
         {{\"username\":…,\"password\":…}}); refusing to pull"
    )]
    MalformedCredential {
        /// The secret ref whose plaintext failed to parse (not the plaintext).
        secret: String,
    },
    /// The underlying secret store failed (a KV / envelope error). The detail is backend-level
    /// (not client-safe) and is surfaced only as the store's own already-sanitized message.
    #[error("resolving registry credential {secret:?}: {source}")]
    Store {
        /// The secret ref being resolved (not a credential).
        secret: String,
        /// The underlying store error (never carries a plaintext value).
        #[source]
        source: SecretError,
    },
}

/// Host-side resolution of an image's registry pull credential. Mirrors
/// [`ComputeBindingResolver`](crate::compute::ComputeBindingResolver): the concrete impl holds the
/// sealed-secret store + operator map; the reconcile only calls this trait and passes the resolved
/// [`RegistryAuth`] (if any) to the backend.
#[async_trait]
pub trait RegistryAuthResolver: Send + Sync {
    /// Resolve the pull credential for `image_reference` launched by `project`, honoring an optional
    /// project-scoped `pull_secret` first, then the operator node-wide host map, else anonymous
    /// (`Ok(None)`). A referenced-but-missing / malformed credential is a FAIL-CLOSED
    /// [`RegistryAuthError`], never a silent anonymous downgrade.
    async fn resolve(
        &self,
        project: &str,
        image_reference: &str,
        pull_secret: Option<&str>,
    ) -> Result<Option<RegistryAuth>, RegistryAuthError>;
}

/// The **registry host** an OCI image reference pulls from, by Docker's canonical rule: the first
/// `/`-segment is the host IFF it contains a `.` or `:` or is exactly `localhost`; otherwise the
/// reference is a Docker Hub image and the host is [`DEFAULT_REGISTRY_HOST`]. A tag/digest suffix
/// does not affect the host. Used to match an image against the operator `[compute].registry_auth`
/// host map.
///
/// Examples: `ghcr.io/o/a:tag` → `ghcr.io`; `registry.example.com:5000/a` → `registry.example.com:5000`;
/// `localhost:5000/a` → `localhost:5000`; `nginx:latest` → `docker.io`; `library/alpine` → `docker.io`.
#[must_use]
pub fn registry_host_of(reference: &str) -> String {
    match reference.split_once('/') {
        Some((first, _rest))
            if first.contains('.') || first.contains(':') || first == "localhost" =>
        {
            first.to_string()
        }
        _ => DEFAULT_REGISTRY_HOST.to_string(),
    }
}

/// The default [`RegistryAuthResolver`]: sealed project secrets (project scope) + an operator
/// host → secret-ref map backed by sealed secrets under [`OPERATOR_REGISTRY_PROJECT`]. Two cheap
/// `Arc`s + a small map, built once in the node and threaded into the reconcile.
#[derive(Clone)]
pub struct SealedRegistryAuthResolver {
    /// The project-scoped sealed secret store (the SAME `Arc` the admin secrets API + managed-DB
    /// credential paths use). Also used for the reserved operator project.
    store: Arc<SecretStore>,
    /// Operator node-wide `registry-host → sealed-secret-ref` map (`[compute].registry_auth`). The
    /// ref names a secret under [`OPERATOR_REGISTRY_PROJECT`]. Empty ⇒ operator scope off.
    operator: BTreeMap<String, String>,
}

impl SealedRegistryAuthResolver {
    /// Build from the project secret store + the operator host map.
    #[must_use]
    pub fn new(store: Arc<SecretStore>, operator: BTreeMap<String, String>) -> Self {
        Self { store, operator }
    }

    /// Fetch + unseal a credential by `(project, ref)`, mapping each failure to a fail-closed
    /// [`RegistryAuthError`] whose message names only the ref (never the plaintext). `missing`
    /// builds the "not set" error so the project vs operator scope reports distinctly.
    async fn load(
        &self,
        project: crate::project::ProjectRef<'_>,
        secret_ref: &str,
        host: &str,
        missing: impl FnOnce() -> RegistryAuthError,
    ) -> Result<RegistryAuth, RegistryAuthError> {
        let bytes = self
            .store
            .get(project, secret_ref)
            .await
            .map_err(|source| RegistryAuthError::Store {
                secret: secret_ref.to_string(),
                source,
            })?
            .ok_or_else(missing)?;
        let cred: RegistryCredential = serde_json::from_slice(&bytes).map_err(|_e| {
            // NEVER include `_e` / the bytes — a parse error message can echo the plaintext.
            RegistryAuthError::MalformedCredential {
                secret: secret_ref.to_string(),
            }
        })?;
        Ok(RegistryAuth::from_credential(cred, host))
    }
}

#[async_trait]
impl RegistryAuthResolver for SealedRegistryAuthResolver {
    async fn resolve(
        &self,
        project: &str,
        image_reference: &str,
        pull_secret: Option<&str>,
    ) -> Result<Option<RegistryAuth>, RegistryAuthError> {
        let host = registry_host_of(image_reference);
        // 1) Project-scoped reference wins. The project comes from the workload's key (the caller),
        //    so a workload can only ever resolve a secret in its OWN project — structural tenancy.
        if let Some(name) = pull_secret.filter(|s| !s.is_empty()) {
            let proj = crate::project::ProjectRef::new(project);
            let auth = self
                .load(proj, name, &host, || {
                    RegistryAuthError::MissingProjectSecret {
                        secret: name.to_string(),
                    }
                })
                .await?;
            return Ok(Some(auth));
        }
        // 2) Operator node-wide host match (operator authority; reserved keyspace).
        if let Some(secret_ref) = self.operator.get(&host) {
            let proj = crate::project::ProjectRef::new(OPERATOR_REGISTRY_PROJECT);
            let auth = self
                .load(proj, secret_ref, &host, || {
                    RegistryAuthError::MissingOperatorSecret {
                        secret: secret_ref.clone(),
                        host: host.clone(),
                    }
                })
                .await?;
            return Ok(Some(auth));
        }
        // 3) No credential referenced + no operator host match ⇒ anonymous pull.
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::{EnvelopeError, KeyEnvelope};
    use crate::kv::MemoryKv;
    use crate::project::ProjectRef;

    /// A reversible test envelope (XOR) so a "sealed" blob differs from the plaintext yet
    /// round-trips — lets us assert at-rest confidentiality AND unseal in-test.
    struct XorEnvelope;
    #[async_trait]
    impl KeyEnvelope for XorEnvelope {
        async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(plaintext.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(wrapped.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    fn cred_json(username: &str, password: &str) -> Vec<u8> {
        serde_json::to_vec(&RegistryCredential {
            username: username.to_string(),
            password: password.to_string(),
        })
        .unwrap()
    }

    fn resolver(
        operator: BTreeMap<String, String>,
    ) -> (SealedRegistryAuthResolver, Arc<SecretStore>) {
        let store = Arc::new(SecretStore::new(
            Arc::new(MemoryKv::new()),
            Arc::new(XorEnvelope),
        ));
        (
            SealedRegistryAuthResolver::new(store.clone(), operator),
            store,
        )
    }

    #[test]
    fn host_parse_follows_docker_rules() {
        assert_eq!(registry_host_of("ghcr.io/owner/app:tag"), "ghcr.io");
        assert_eq!(
            registry_host_of("registry.example.com:5000/team/app"),
            "registry.example.com:5000"
        );
        assert_eq!(registry_host_of("localhost:5000/app"), "localhost:5000");
        // No `.`/`:`/localhost in the first segment ⇒ Docker Hub default.
        assert_eq!(registry_host_of("nginx:latest"), DEFAULT_REGISTRY_HOST);
        assert_eq!(registry_host_of("library/alpine"), DEFAULT_REGISTRY_HOST);
        assert_eq!(registry_host_of("nginx"), DEFAULT_REGISTRY_HOST);
        // A digest-pinned reference keeps the host.
        assert_eq!(registry_host_of("ghcr.io/o/a@sha256:abc"), "ghcr.io");
    }

    #[test]
    fn redacting_debug_never_leaks_the_password() {
        // The single non-negotiable: a credential formatted with `{:?}` (the shape a careless log /
        // tracing event / error takes) must NOT contain the secret. Mutating either redacting Debug
        // to print the real password turns this RED.
        let cred = RegistryCredential {
            username: "robot".into(),
            password: "sup3r-s3cret-token".into(),
        };
        let d = format!("{cred:?}");
        assert!(!d.contains("sup3r-s3cret-token"), "password leaked: {d}");
        assert!(d.contains("robot") && d.contains("<redacted>"));

        let auth = RegistryAuth {
            username: "robot".into(),
            password: "sup3r-s3cret-token".into(),
            serveraddress: "ghcr.io".into(),
        };
        let d = format!("{auth:?}");
        assert!(!d.contains("sup3r-s3cret-token"), "password leaked: {d}");
        assert!(d.contains("robot") && d.contains("ghcr.io") && d.contains("<redacted>"));
    }

    #[test]
    fn resolver_errors_never_echo_the_secret_value() {
        // Every fail-closed error names only the ref/host — never a credential value. (A malformed
        // credential's parse error is deliberately dropped so it can't echo the sealed plaintext.)
        for e in [
            RegistryAuthError::MissingProjectSecret {
                secret: "ghcr".into(),
            },
            RegistryAuthError::MissingOperatorSecret {
                secret: "fleet".into(),
                host: "ghcr.io".into(),
            },
            RegistryAuthError::MalformedCredential {
                secret: "ghcr".into(),
            },
        ] {
            let msg = e.to_string();
            assert!(!msg.contains("hunter2"), "{msg}");
        }
    }

    #[tokio::test]
    async fn project_pull_secret_resolves_from_its_own_project() {
        let (r, store) = resolver(BTreeMap::new());
        store
            .set(
                ProjectRef::new("acme"),
                "ghcr",
                &cred_json("acme-bot", "hunter2"),
            )
            .await
            .unwrap();
        let auth = r
            .resolve("acme", "ghcr.io/acme/app:1", Some("ghcr"))
            .await
            .unwrap()
            .expect("a project credential resolves");
        assert_eq!(auth.username, "acme-bot");
        assert_eq!(auth.password, "hunter2");
        assert_eq!(auth.serveraddress, "ghcr.io");
    }

    #[tokio::test]
    async fn two_tenant_isolation_a_cannot_pull_with_bs_credential() {
        // THE tenancy property (≥2 tenants, shared keyspace, zero cross-tenant reach): projects A and
        // B each set a pull secret of the SAME name with DIFFERENT credentials. A's workload resolves
        // A's credential; B's resolves B's — and A's resolution never yields B's bytes. The project
        // is threaded from the workload's key, so there is no API for A to name B's project at all.
        let (r, store) = resolver(BTreeMap::new());
        store
            .set(
                ProjectRef::new("acme"),
                "reg",
                &cred_json("acme-bot", "acme-pw"),
            )
            .await
            .unwrap();
        store
            .set(
                ProjectRef::new("globex"),
                "reg",
                &cred_json("globex-bot", "globex-pw"),
            )
            .await
            .unwrap();

        let a = r
            .resolve("acme", "ghcr.io/x/y:1", Some("reg"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(a.username, "acme-bot");
        assert_eq!(a.password, "acme-pw");
        assert_ne!(a.password, "globex-pw", "A must NEVER see B's credential");

        let b = r
            .resolve("globex", "ghcr.io/x/y:1", Some("reg"))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(b.username, "globex-bot");
        assert_eq!(b.password, "globex-pw");

        // A project that set NO secret of this name fails closed — it does NOT borrow a sibling's.
        let err = r
            .resolve("initech", "ghcr.io/x/y:1", Some("reg"))
            .await
            .expect_err("a missing project secret must fail closed");
        assert!(
            matches!(err, RegistryAuthError::MissingProjectSecret { .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn missing_project_secret_fails_closed_no_anonymous_fallback() {
        let (r, store) = resolver(BTreeMap::new());
        // Even with an operator entry for the SAME host present, a referenced-but-missing PROJECT
        // secret fails closed — it does not silently fall through to the operator cred or anonymous.
        store
            .set(
                ProjectRef::new(OPERATOR_REGISTRY_PROJECT),
                "fleet",
                &cred_json("op", "op-pw"),
            )
            .await
            .unwrap();
        let (r2, _s2) = {
            let mut op = BTreeMap::new();
            op.insert("ghcr.io".to_string(), "fleet".to_string());
            (SealedRegistryAuthResolver::new(r.store.clone(), op), ())
        };
        let err = r2
            .resolve("acme", "ghcr.io/x/y:1", Some("absent-name"))
            .await
            .expect_err("must fail closed");
        assert!(
            matches!(err, RegistryAuthError::MissingProjectSecret { .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn operator_host_match_resolves_when_no_project_secret() {
        let mut op = BTreeMap::new();
        op.insert("ghcr.io".to_string(), "fleet".to_string());
        let (r, store) = resolver(op);
        store
            .set(
                ProjectRef::new(OPERATOR_REGISTRY_PROJECT),
                "fleet",
                &cred_json("fleet-bot", "fleet-pw"),
            )
            .await
            .unwrap();
        // No pull_secret ⇒ the operator host map applies.
        let auth = r
            .resolve("acme", "ghcr.io/acme/app:1", None)
            .await
            .unwrap()
            .expect("operator cred resolves by host");
        assert_eq!(auth.username, "fleet-bot");
        assert_eq!(auth.password, "fleet-pw");

        // A host with NO operator entry + no project secret ⇒ anonymous (Ok(None)).
        assert!(
            r.resolve("acme", "docker.io/library/nginx:1", None)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn operator_configured_but_secret_missing_fails_closed() {
        let mut op = BTreeMap::new();
        op.insert("ghcr.io".to_string(), "fleet".to_string());
        let (r, _store) = resolver(op);
        // The operator configured a host entry but never set the referenced secret: fail closed,
        // NEVER anonymous (the operator intended auth for this host).
        let err = r
            .resolve("acme", "ghcr.io/x/y:1", None)
            .await
            .expect_err("a configured-but-unset operator secret must fail closed");
        assert!(
            matches!(err, RegistryAuthError::MissingOperatorSecret { .. }),
            "{err}"
        );
    }

    #[tokio::test]
    async fn malformed_credential_fails_closed_without_echoing_plaintext() {
        let (r, store) = resolver(BTreeMap::new());
        // A sealed value that is not a {username,password} JSON — e.g. a bare token someone set by
        // hand. Fail closed, and the error must NOT echo the (sealed) plaintext.
        store
            .set(ProjectRef::new("acme"), "reg", b"raw-token-hunter2")
            .await
            .unwrap();
        let err = r
            .resolve("acme", "ghcr.io/x/y:1", Some("reg"))
            .await
            .expect_err("malformed credential must fail closed");
        assert!(
            matches!(err, RegistryAuthError::MalformedCredential { .. }),
            "{err}"
        );
        assert!(
            !err.to_string().contains("hunter2"),
            "plaintext leaked: {err}"
        );
    }

    #[tokio::test]
    async fn anonymous_pull_when_nothing_referenced() {
        let (r, _store) = resolver(BTreeMap::new());
        // No pull_secret, no operator map ⇒ Ok(None) ⇒ the backend pulls anonymously (public image).
        assert!(
            r.resolve("acme", "nginx:latest", None)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            r.resolve("acme", "ghcr.io/public/app:1", None)
                .await
                .unwrap()
                .is_none()
        );
    }
}
