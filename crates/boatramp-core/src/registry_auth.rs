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
//! A credential that is REFERENCED (case 1 or 2) on a node with **no `[secrets]` key envelope**
//! (no sealed-secret backend to unseal it) also **FAILS CLOSED**
//! ([`RegistryAuthError::NoSecretBackend`]) — never a silent anonymous downgrade, which would
//! ignore the named secret and could let a same-named PUBLIC image be substituted for the intended
//! private one (Security MEDIUM-1). Anonymous is correct ONLY in case 3.
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
    /// A credential was REFERENCED — a project `pull_secret`, or an image host that matches an
    /// operator `[compute].registry_auth` entry — but this node has **no sealed-secret backend**
    /// (no `[secrets]` key envelope), so there is nothing to unseal it with. Fail CLOSED: the pull
    /// is refused, NEVER downgraded to an anonymous pull (Security MEDIUM-1). Downgrading would
    /// silently ignore the named secret and could let a same-named PUBLIC image be substituted for
    /// the intended private one. Anonymous is only correct when NO credential is referenced/matched.
    #[error(
        "{scope} registry credential {secret:?} is referenced, but this node has no \
         [secrets] key envelope to unseal it; refusing to pull anonymously"
    )]
    NoSecretBackend {
        /// The referenced secret ref/name (not a credential).
        secret: String,
        /// Which scope referenced it (`"project pull-secret"` / `"operator"`).
        scope: &'static str,
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

/// The **repository path** of an OCI image reference — the part AFTER the registry host (if any)
/// and BEFORE the tag/digest. Used to match an image against an operator entry's `repos` prefix
/// allowlist (Security MEDIUM-2). The host is stripped by the same rule as [`registry_host_of`];
/// a Docker Hub reference keeps its bare repo path (no implicit `library/` is added — the operator
/// configures prefixes against what they write).
///
/// Examples: `ghcr.io/myorg/base-api:1` → `myorg/base-api`;
/// `registry.example.com:5000/team/app` → `team/app`; `localhost:5000/app:1` → `app`;
/// `ghcr.io/o/a@sha256:abc` → `o/a`; `ghcr.io/o/a:1@sha256:abc` → `o/a`; `nginx:latest` → `nginx`;
/// `library/alpine` → `library/alpine`.
///
/// This is a PURE parse (no validation); the scope gate's structural fail-closed against traversal
/// refs lives in [`OperatorRegistryAuth::applies_to_repo`].
#[must_use]
pub fn registry_repo_of(reference: &str) -> String {
    // Strip the host if the first `/`-segment is one (same rule as `registry_host_of`).
    let after_host = match reference.split_once('/') {
        Some((first, rest))
            if first.contains('.') || first.contains(':') || first == "localhost" =>
        {
            rest
        }
        _ => reference,
    };
    // Drop the digest first (`@sha256:…` is always the suffix) so the tag strip below sees a clean
    // `repo[:tag]` with no digest `:` to confuse it — this also clears the `:tag` residue a
    // `name:tag@digest` ref would otherwise leave.
    let no_digest = after_host
        .split_once('@')
        .map_or(after_host, |(repo, _digest)| repo);
    // Then strip a tag — a `:` in the LAST path component (a registry `host:port` and the digest are
    // already gone, so any remaining `:` is the tag's). `rfind(':')` is safe for the same reason.
    let last = no_digest.rsplit('/').next().unwrap_or(no_digest);
    if last.contains(':')
        && let Some(idx) = no_digest.rfind(':')
    {
        return no_digest[..idx].to_string();
    }
    no_digest.to_string()
}

/// Whether a parsed repository path is **well-formed** for scope matching: non-empty and free of any
/// empty or `..` path segment. A traversal/malformed ref (`myorg/base-/../../secret`, `a//b`, a
/// leading/trailing `/`) is NOT well-formed — [`OperatorRegistryAuth::applies_to_repo`] refuses to
/// match it against ANY prefix, so a node-wide operator credential is never attached to it. This
/// makes the scope gate SELF-SUFFICIENT (Security LOW): it never relies on the downstream puller to
/// reject a `..` ref before it reaches a registry.
fn repo_path_is_well_formed(repo: &str) -> bool {
    !repo.is_empty() && !repo.split('/').any(|seg| seg.is_empty() || seg == "..")
}

/// An operator node-wide registry credential binding (`[compute].registry_auth` value): a
/// sealed-secret ref, OPTIONALLY scoped to a set of repository-path prefixes (Security MEDIUM-2).
/// Deserializes from EITHER a bare string (host-wide, back-compat) OR a struct `{ secret, repos }`.
///
/// - Host-wide (`"ghcr.io": "fleet-ghcr"`): the credential applies to EVERY image at that host.
/// - Prefix-scoped (`"ghcr.io": ( secret: "fleet", repos: ["myorg/base-"] )`): the credential
///   applies ONLY when the image's repository path ([`registry_repo_of`]) starts with one of the
///   prefixes — so a tenant cannot borrow a node-wide credential to pull UNRELATED private repos at
///   the same host. A non-matching image falls through exactly as a host-no-match does (a named
///   project `pull_secret` still resolves per its own rules; otherwise anonymous).
/// - An empty `repos` list is treated as host-wide.
///
/// Prefix match is byte-prefix (not regex), **case-sensitive** (registries are).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum OperatorRegistryAuth {
    /// Host-wide: the sealed-secret ref, applied to every image at the host (back-compat shorthand).
    HostWide(String),
    /// Prefix-scoped: the sealed-secret ref plus a repository-path-prefix allowlist.
    Scoped {
        /// The sealed-secret ref (a secret name under [`OPERATOR_REGISTRY_PROJECT`]).
        secret: String,
        /// Repository-path prefixes this credential is limited to. Empty ⇒ host-wide.
        #[serde(default)]
        repos: Vec<String>,
    },
}

impl From<&str> for OperatorRegistryAuth {
    fn from(s: &str) -> Self {
        Self::HostWide(s.to_string())
    }
}

impl From<String> for OperatorRegistryAuth {
    fn from(s: String) -> Self {
        Self::HostWide(s)
    }
}

impl OperatorRegistryAuth {
    /// The sealed-secret ref this binding names.
    #[must_use]
    pub fn secret(&self) -> &str {
        match self {
            Self::HostWide(s) => s,
            Self::Scoped { secret, .. } => secret,
        }
    }

    /// Whether this binding applies to an image whose repository path is `repo`. Host-wide (or an
    /// empty `repos`) matches any WELL-FORMED repo; a prefix-scoped binding matches only when `repo`
    /// starts with one of the configured prefixes (byte prefix, case-sensitive).
    ///
    /// A malformed/traversal `repo` (an empty or `..` path segment, e.g. `myorg/base-/../../secret`)
    /// matches NOTHING — not even a host-wide binding — so the node-wide operator credential is never
    /// attached to it (Security LOW: the scope gate is self-sufficient and does not rely on the
    /// downstream puller to reject a `..` ref). The pull then falls through to the project
    /// `pull_secret` rules / anonymous, exactly as a non-matching repo does.
    #[must_use]
    pub fn applies_to_repo(&self, repo: &str) -> bool {
        if !repo_path_is_well_formed(repo) {
            return false;
        }
        match self {
            Self::HostWide(_) => true,
            Self::Scoped { repos, .. } if repos.is_empty() => true,
            Self::Scoped { repos, .. } => repos.iter().any(|p| repo.starts_with(p.as_str())),
        }
    }
}

/// The default [`RegistryAuthResolver`]: sealed project secrets (project scope) + an operator
/// host → secret-ref map backed by sealed secrets under [`OPERATOR_REGISTRY_PROJECT`]. A cheap
/// `Option<Arc>` + a small map, built once in the node and threaded into the reconcile.
///
/// The store is `Option` on purpose: a node with NO `[secrets]` key envelope has no sealed-secret
/// backend, yet the resolver is STILL built (so it can enforce fail-closed). On such a node a
/// workload that references a credential (project `pull_secret`, or an operator host match) fails
/// CLOSED with [`RegistryAuthError::NoSecretBackend`] — never a silent anonymous downgrade (Security
/// MEDIUM-1). A workload that references nothing still resolves `Ok(None)` (a public/anonymous pull).
#[derive(Clone)]
pub struct SealedRegistryAuthResolver {
    /// The project-scoped sealed secret store (the SAME `Arc` the admin secrets API + managed-DB
    /// credential paths use); also used for the reserved operator project. `None` ⇒ this node has no
    /// `[secrets]` envelope, so a referenced credential fails closed.
    store: Option<Arc<SecretStore>>,
    /// Operator node-wide `registry-host → `[`OperatorRegistryAuth`]` map (`[compute].registry_auth`):
    /// a sealed-secret ref under [`OPERATOR_REGISTRY_PROJECT`], optionally scoped to repository-path
    /// prefixes. Empty ⇒ operator scope off.
    operator: BTreeMap<String, OperatorRegistryAuth>,
}

impl SealedRegistryAuthResolver {
    /// Build from the (optional) project secret store + the operator host map. Pass `None` for the
    /// store on a node with no `[secrets]` envelope — the resolver still enforces fail-closed.
    #[must_use]
    pub fn new(
        store: Option<Arc<SecretStore>>,
        operator: BTreeMap<String, OperatorRegistryAuth>,
    ) -> Self {
        Self { store, operator }
    }

    /// Fetch + unseal a credential by `(project, ref)`, mapping each failure to a fail-closed
    /// [`RegistryAuthError`] whose message names only the ref (never the plaintext). `missing`
    /// builds the "not set" error so the project vs operator scope reports distinctly. A node with
    /// no secret backend fails closed with [`NoSecretBackend`](RegistryAuthError::NoSecretBackend).
    async fn load(
        &self,
        project: crate::project::ProjectRef<'_>,
        secret_ref: &str,
        host: &str,
        scope: &'static str,
        missing: impl FnOnce() -> RegistryAuthError,
    ) -> Result<RegistryAuth, RegistryAuthError> {
        // No `[secrets]` envelope ⇒ no backend to unseal the REFERENCED credential ⇒ FAIL CLOSED,
        // never anonymous (Security MEDIUM-1).
        let Some(store) = self.store.as_ref() else {
            return Err(RegistryAuthError::NoSecretBackend {
                secret: secret_ref.to_string(),
                scope,
            });
        };
        let bytes = store
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
                .load(proj, name, &host, "project pull-secret", || {
                    RegistryAuthError::MissingProjectSecret {
                        secret: name.to_string(),
                    }
                })
                .await?;
            return Ok(Some(auth));
        }
        // 2) Operator node-wide host match (operator authority; reserved keyspace). The binding may
        //    be scoped to repository-path prefixes (MEDIUM-2): it applies ONLY when the image's repo
        //    path matches, so a tenant can't borrow a node-wide credential for UNRELATED private
        //    repos at the same host. A host-match-but-repo-no-match falls through to anonymous
        //    exactly as a host-no-match does (there is no project pull_secret here — case 1 handled
        //    it), never attaching the operator credential.
        if let Some(entry) = self.operator.get(&host) {
            let repo = registry_repo_of(image_reference);
            if entry.applies_to_repo(&repo) {
                let secret_ref = entry.secret();
                let proj = crate::project::ProjectRef::new(OPERATOR_REGISTRY_PROJECT);
                let auth = self
                    .load(proj, secret_ref, &host, "operator", || {
                        RegistryAuthError::MissingOperatorSecret {
                            secret: secret_ref.to_string(),
                            host: host.clone(),
                        }
                    })
                    .await?;
                return Ok(Some(auth));
            }
        }
        // 3) No credential referenced + no applicable operator entry ⇒ anonymous pull.
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
        operator: BTreeMap<String, OperatorRegistryAuth>,
    ) -> (SealedRegistryAuthResolver, Arc<SecretStore>) {
        let store = Arc::new(SecretStore::new(
            Arc::new(MemoryKv::new()),
            Arc::new(XorEnvelope),
        ));
        (
            SealedRegistryAuthResolver::new(Some(store.clone()), operator),
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
    fn repo_parse_strips_host_and_tag() {
        assert_eq!(
            registry_repo_of("ghcr.io/myorg/base-api:1"),
            "myorg/base-api"
        );
        assert_eq!(
            registry_repo_of("registry.example.com:5000/team/app"),
            "team/app"
        );
        assert_eq!(registry_repo_of("localhost:5000/app:1"), "app");
        assert_eq!(registry_repo_of("ghcr.io/o/a@sha256:abc"), "o/a");
        // A `name:tag@digest` ref yields a CLEAN repo (no `:tag` residue — digest dropped first,
        // then the tag).
        assert_eq!(registry_repo_of("ghcr.io/o/a:1@sha256:abc"), "o/a");
        assert_eq!(
            registry_repo_of("myorg/app:2.1@sha256:deadbeef"),
            "myorg/app"
        );
        // Docker Hub refs keep their bare repo path (no implicit library/ added).
        assert_eq!(registry_repo_of("nginx:latest"), "nginx");
        assert_eq!(registry_repo_of("library/alpine"), "library/alpine");
    }

    #[test]
    fn operator_entry_repo_scoping() {
        // Host-wide (string shorthand) matches everything.
        let hw = OperatorRegistryAuth::HostWide("fleet".into());
        assert!(hw.applies_to_repo("anyorg/anything"));
        assert_eq!(hw.secret(), "fleet");
        // Empty repos ⇒ host-wide.
        let empty = OperatorRegistryAuth::Scoped {
            secret: "f".into(),
            repos: vec![],
        };
        assert!(empty.applies_to_repo("x/y"));
        // Prefix-scoped: matches a configured prefix, not an unrelated repo at the same host.
        let scoped = OperatorRegistryAuth::Scoped {
            secret: "f".into(),
            repos: vec!["myorg/base-".into(), "myorg/runtime-".into()],
        };
        assert!(scoped.applies_to_repo("myorg/base-api"));
        assert!(scoped.applies_to_repo("myorg/runtime-x"));
        assert!(!scoped.applies_to_repo("myorg/secret-service"));
        assert!(!scoped.applies_to_repo("otherorg/base-api"));
        // Case-sensitive (registries are).
        assert!(!scoped.applies_to_repo("MyOrg/base-api"));

        // Security LOW (structural fail-closed): a traversal ref that BYTE-matches a prefix must
        // NOT match — the `..`/empty-segment guard makes the scope gate self-sufficient (it does not
        // rely on the downstream puller to reject a `..` ref). Deleting the `repo_path_is_well_formed`
        // check turns these RED (the raw `starts_with` would let the traversal through).
        assert!(
            !scoped.applies_to_repo("myorg/base-/../../secret-service"),
            "a `..` traversal that byte-matches the prefix must NOT attach the operator cred"
        );
        assert!(
            !scoped.applies_to_repo("myorg/base-/../secret"),
            "a single `..` segment is still a traversal"
        );
        assert!(
            !scoped.applies_to_repo("myorg/base-//evil"),
            "an empty path segment is malformed and must NOT match"
        );
        // Even a host-wide binding refuses a malformed/traversal ref (it matches nothing).
        assert!(!hw.applies_to_repo("myorg/base-/../../secret"));
        assert!(!hw.applies_to_repo(""));
        assert!(!empty.applies_to_repo("a//b"));
    }

    #[test]
    fn operator_entry_deserializes_both_short_and_long_forms() {
        // Back-compat: a bare string is host-wide.
        let short: OperatorRegistryAuth = serde_json::from_str("\"fleet-ghcr\"").unwrap();
        assert_eq!(short, OperatorRegistryAuth::HostWide("fleet-ghcr".into()));
        // Long form carries the optional repos allowlist.
        let long: OperatorRegistryAuth =
            serde_json::from_str(r#"{"secret":"fleet","repos":["myorg/base-"]}"#).unwrap();
        assert_eq!(
            long,
            OperatorRegistryAuth::Scoped {
                secret: "fleet".into(),
                repos: vec!["myorg/base-".into()],
            }
        );
        // repos defaults to empty when omitted.
        let no_repos: OperatorRegistryAuth = serde_json::from_str(r#"{"secret":"fleet"}"#).unwrap();
        assert_eq!(
            no_repos,
            OperatorRegistryAuth::Scoped {
                secret: "fleet".into(),
                repos: vec![],
            }
        );
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
            op.insert("ghcr.io".to_string(), "fleet".into());
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
    async fn envelope_less_node_fails_closed_when_a_credential_is_referenced() {
        // Security MEDIUM-1: a node with NO `[secrets]` envelope has no sealed-secret backend
        // (store = None). A workload that NAMES a project `pull_secret`, OR whose image host matches
        // an operator entry, must FAIL CLOSED — NEVER a silent anonymous pull (which would ignore
        // the named secret and could let a same-named PUBLIC image be substituted). A workload that
        // references NOTHING still pulls anonymously (a genuinely public image).
        let mut op = BTreeMap::new();
        op.insert("ghcr.io".to_string(), "fleet".into());
        let r = SealedRegistryAuthResolver::new(None, op);

        // (a) project pull_secret named, no backend ⇒ closed.
        let err = r
            .resolve("acme", "ghcr.io/x/y:1", Some("reg"))
            .await
            .expect_err("a named pull_secret with no backend must fail closed");
        assert!(
            matches!(
                err,
                RegistryAuthError::NoSecretBackend {
                    scope: "project pull-secret",
                    ..
                }
            ),
            "{err}"
        );

        // (b) operator host match, no backend ⇒ closed (never falls through to anonymous).
        let err = r
            .resolve("acme", "ghcr.io/x/y:1", None)
            .await
            .expect_err("an operator host match with no backend must fail closed");
        assert!(
            matches!(
                err,
                RegistryAuthError::NoSecretBackend {
                    scope: "operator",
                    ..
                }
            ),
            "{err}"
        );
        // The error names only the ref — never a credential value.
        assert!(!err.to_string().contains("hunter2"));

        // (c) nothing referenced + no operator match ⇒ anonymous pull is STILL correct (a public
        //     image on an envelope-less node must not be blocked).
        assert!(
            r.resolve("acme", "docker.io/library/nginx:1", None)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn operator_host_match_resolves_when_no_project_secret() {
        let mut op = BTreeMap::new();
        op.insert("ghcr.io".to_string(), "fleet".into());
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
        op.insert("ghcr.io".to_string(), "fleet".into());
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
    async fn operator_repo_prefix_scoping_attaches_only_to_matching_repos() {
        // Security MEDIUM-2: an operator credential scoped to `repos: ["myorg/base-"]` at ghcr.io IS
        // attached for a matching image, but is NOT attached for an UNRELATED private repo at the
        // SAME host — so a tenant can't borrow the node-wide credential for repos it shouldn't reach.
        // Mutation-sensitive: dropping the `applies_to_repo` gate (always-true) makes the no-match
        // case resolve the cred instead of anonymous, turning the second assertion RED.
        let mut op = BTreeMap::new();
        op.insert(
            "ghcr.io".to_string(),
            OperatorRegistryAuth::Scoped {
                secret: "fleet".into(),
                repos: vec!["myorg/base-".into()],
            },
        );
        let (r, store) = resolver(op);
        store
            .set(
                ProjectRef::new(OPERATOR_REGISTRY_PROJECT),
                "fleet",
                &cred_json("fleet-bot", "fleet-pw"),
            )
            .await
            .unwrap();

        // Matching repo ⇒ the operator credential is attached.
        let auth = r
            .resolve("acme", "ghcr.io/myorg/base-api:1", None)
            .await
            .unwrap()
            .expect("operator cred attaches to a matching repo");
        assert_eq!(auth.username, "fleet-bot");
        assert_eq!(auth.password, "fleet-pw");

        // UNRELATED repo at the SAME host, no project pull_secret ⇒ NOT attached ⇒ anonymous
        // (Ok(None)), NOT the operator credential.
        assert!(
            r.resolve("acme", "ghcr.io/myorg/secret-service:1", None)
                .await
                .unwrap()
                .is_none(),
            "a non-prefix-matching repo must NOT borrow the node-wide operator credential"
        );

        // Security LOW: a `..` traversal ref that BYTE-matches the `myorg/base-` prefix must NOT
        // attach the operator credential either — the scope gate rejects it structurally, so it
        // falls through to anonymous (Ok(None)) rather than reaching `secret-service` with the
        // node-wide cred. End-to-end proof the gate does not rely on the docker daemon's `..` reject.
        assert!(
            r.resolve("acme", "ghcr.io/myorg/base-/../../secret-service:1", None)
                .await
                .unwrap()
                .is_none(),
            "a `..` traversal that byte-matches the prefix must NOT borrow the node-wide credential"
        );

        // A non-matching repo that DOES name its own project pull_secret still resolves that per the
        // project rules (the operator scoping never widens or blocks the project path).
        store
            .set(
                ProjectRef::new("acme"),
                "mine",
                &cred_json("acme-bot", "acme-pw"),
            )
            .await
            .unwrap();
        let a = r
            .resolve("acme", "ghcr.io/myorg/secret-service:1", Some("mine"))
            .await
            .unwrap()
            .expect("the project pull_secret still resolves regardless of operator scoping");
        assert_eq!(a.password, "acme-pw");
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
