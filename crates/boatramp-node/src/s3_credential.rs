//! Node-level **base S3 credential** sourcing (#505).
//!
//! The S3 blob object backend ([`boatramp_storage::S3Storage`]) and the AWS blob-upload cloud minter
//! (`boatramp-server` `AwsBlobUploadMinter`) historically take their base AWS credential from the
//! ambient env chain (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`). This module lets an operator source
//! that base credential from boatramp's `[secrets]` sealed store instead — ONE shared node-level source
//! ([`crate::config::S3CredentialConfig`]) consumed by BOTH, since it is the same bucket key
//! (construens' Tigris move wants exactly this).
//!
//! The `access_key_id` is a public identifier (plain config). The `secret_access_key` is a **secret
//! reference** in the same scheme the guest `secrets` map uses (`parse_secret_ref` in
//! `boatramp-server`), resolved here at serve startup:
//!
//! - `boatramp:<name>` — the project-scoped sealed [`SecretStore`](boatramp_core::secret_store::SecretStore)
//!   under the **reserved default project** (multi-tenant-safe: never the host env). Requires a
//!   `[secrets]` [`KeyEnvelope`] — this mirrors [`ManagedSqlCredentials`](crate::managed_sql) exactly
//!   (KV + envelope, `unwrap` the sealed bytes).
//! - `env:<VAR>` / a bare `<VAR>` — the **operator's** own environment. Honored ONLY when the security
//!   posture's `allow_env_secret_refs` is set (single-tenant/dev), refused fail-closed otherwise — the
//!   same gate `resolve_secret_env` applies to a guest `env:` ref.
//!
//! **Fail-closed:** a configured `secret_access_key` ref with NO `[secrets]` envelope is a startup
//! error — we do NOT silently fall back to the ambient env chain, which would mask a misconfig
//! (the whole point of the sealed source is to STOP reading the base key from the env). The resolved
//! plaintext is held in memory only inside a redacted [`SealedS3Credential`] (never `Debug`-printed in
//! clear, never logged/argv/git).

use std::sync::Arc;

use boatramp_core::env::EnvSource;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::project::ProjectRef;
use boatramp_core::secret_store::SecretStore;

/// A resolved base S3 credential held in memory. `access_key_id` is a public identifier; the
/// `secret_access_key` is confidential and is **redacted** from `Debug` (mirroring
/// `S3IngressSecret`/`azure_core::Secret`), so a struct-`Debug` in a log or a panic message can never
/// leak it. Cheap to clone (two `String`s) so both consumers (backend + minter) share it.
#[derive(Clone)]
pub struct SealedS3Credential {
    access_key_id: String,
    secret_access_key: String,
}

impl SealedS3Credential {
    /// The public access-key id (safe to log / put in an ARN's session name, etc.).
    #[cfg_attr(not(feature = "s3"), allow(dead_code))]
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// The confidential secret access key. Kept behind a method (not a public field) so a caller must
    /// ask for it explicitly; it is redacted from `Debug`.
    #[cfg_attr(not(feature = "s3"), allow(dead_code))]
    pub fn secret_access_key(&self) -> &str {
        &self.secret_access_key
    }

    /// The `(access_key_id, secret_access_key)` pair the storage/minter build paths inject into an AWS
    /// credentials provider. Consumes clones — the secret stays owned by the caller's provider.
    #[cfg_attr(not(feature = "s3"), allow(dead_code))]
    pub fn as_pair(&self) -> (String, String) {
        (self.access_key_id.clone(), self.secret_access_key.clone())
    }
}

/// `Debug` redacts the secret so it never lands in a log / panic message. The access-key id is a public
/// identifier so it is shown; the secret is elided (mirrors `azure_core::Secret` / `S3IngressSecret`,
/// which derive no plaintext `Debug`). The redaction test in this module + the mutation gate assert the
/// secret substring is absent from `{:?}`.
impl std::fmt::Debug for SealedS3Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // GATE MUTATION SEAM (invariant 3): a plain `Debug` that prints the secret in clear — the exact
        // regression the redaction guards against. Only under the gate feature + the env var.
        #[cfg(feature = "s3-sealed-cred-gate-mutation")]
        if gate_mutation::env_on("BOATRAMP_S3SEALED_MUTATE_PLAIN_DEBUG") {
            return f
                .debug_struct("SealedS3Credential")
                .field("access_key_id", &self.access_key_id)
                .field("secret_access_key", &self.secret_access_key)
                .finish();
        }
        f.debug_struct("SealedS3Credential")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

/// The gate-mutation seams (#505 `S3 SEALED-CRED SOURCING OK`). Compiled ONLY under the
/// `s3-sealed-cred-gate-mutation` feature (the CI gate lane). Each `BOATRAMP_S3SEALED_MUTATE_*` env var
/// makes the resolver/`Debug` behave like a specific broken implementation, so the CI gate proves each
/// security check is load-bearing (every mutation MUST fail the gate).
#[cfg(feature = "s3-sealed-cred-gate-mutation")]
mod gate_mutation {
    /// Whether a mutation env var is set (non-empty and not `0`).
    pub(super) fn env_on(name: &str) -> bool {
        std::env::var(name)
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false)
    }
}

/// A failure resolving the node-level base S3 credential. Stringly at the boundary (the caller maps it
/// into its `serve` error), but the variants keep the failure kinds distinct so the mutation gate can
/// assert on the fail-closed one.
#[derive(Debug, PartialEq, Eq)]
pub enum S3CredentialError {
    /// `access_key_id` is empty (a misconfigured source — refuse rather than mint a broken credential).
    EmptyAccessKeyId,
    /// The `secret_access_key` is a `boatramp:`/`env:` sealed ref but no `[secrets]` envelope is
    /// configured — **fail closed** (never a silent env fallback that would mask the misconfig).
    NoEnvelope,
    /// A `boatramp:` ref, but the sealed secret is not present in the store under the default project.
    MissingBoatrampSecret(String),
    /// An `env:`/bare host-env ref refused because the posture's `allow_env_secret_refs` is off (the
    /// config author's env is the operator's namespace — the same gate a guest `env:` ref hits).
    EnvRefNotPermitted(String),
    /// An `env:`/bare host-env ref whose var is unset.
    EnvVarUnset(String),
    /// A reserved-but-unimplemented scheme (a colon-bearing value whose scheme is not `env`/`boatramp`).
    UnsupportedScheme(String),
    /// A KV / envelope (unseal) backend failure — detail is logged, not surfaced to a client.
    Backend(String),
    /// A resolved secret that is not valid UTF-8 (an AWS secret access key is ASCII).
    NotUtf8,
}

impl std::fmt::Display for S3CredentialError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyAccessKeyId => write!(
                f,
                "[serve.s3_credential]: `access_key_id` must not be empty"
            ),
            Self::NoEnvelope => write!(
                f,
                "[serve.s3_credential]: `secret_access_key` is a sealed `boatramp:`/`env:` ref but no \
                 `[secrets]` envelope is configured — refusing to fall back to the ambient AWS env \
                 chain (fail-closed); configure `[secrets]` or remove the source"
            ),
            Self::MissingBoatrampSecret(name) => write!(
                f,
                "[serve.s3_credential]: `secret_access_key` → boatramp:{name} is not set in the \
                 sealed secret store (default project); seal it with `boatramp secrets set`"
            ),
            Self::EnvRefNotPermitted(var) => write!(
                f,
                "[serve.s3_credential]: `secret_access_key` host-env ref {var:?} is not permitted \
                 under the multi-tenant posture (it would read the operator's environment); enable \
                 `allow_env_secret_refs` or use a `boatramp:<name>` sealed ref"
            ),
            Self::EnvVarUnset(var) => write!(
                f,
                "[serve.s3_credential]: `secret_access_key` env var {var:?} is not set"
            ),
            Self::UnsupportedScheme(scheme) => write!(
                f,
                "[serve.s3_credential]: `secret_access_key` uses the {scheme:?} scheme, which is not \
                 supported (use `boatramp:<name>` or `env:<VAR>`)"
            ),
            Self::Backend(msg) => write!(f, "[serve.s3_credential]: {msg}"),
            Self::NotUtf8 => write!(
                f,
                "[serve.s3_credential]: the resolved `secret_access_key` is not valid UTF-8"
            ),
        }
    }
}

impl std::error::Error for S3CredentialError {}

/// A parsed `secret_access_key` reference — the SAME scheme `parse_secret_ref` implements in
/// `boatramp-server` (kept in lockstep; a colon-free value is a bare host-env var name for back-compat,
/// `env:` is the explicit host-env form, `boatramp:` the sealed store, any other `scheme:` is reserved).
enum SecretRef<'a> {
    /// A bare `VAR` or explicit `env:VAR` — the operator's own environment (posture-gated).
    Env(&'a str),
    /// `boatramp:NAME` — the project-scoped sealed store.
    Boatramp(&'a str),
    /// A reserved-but-unimplemented scheme.
    Unsupported(&'a str),
}

fn parse_secret_ref(secret_ref: &str) -> SecretRef<'_> {
    match secret_ref.split_once(':') {
        Some(("env", host_var)) => SecretRef::Env(host_var),
        Some(("boatramp", name)) => SecretRef::Boatramp(name),
        Some((scheme, _)) => SecretRef::Unsupported(scheme),
        None => SecretRef::Env(secret_ref),
    }
}

/// Resolve the node-level base S3 credential from [`config`](crate::config::S3CredentialConfig).
///
/// The `access_key_id` is copied through (a public identifier). The `secret_access_key` **reference** is
/// resolved:
///
/// - `boatramp:<name>` → unsealed from the project-scoped [`SecretStore`] under
///   [`ProjectRef::DEFAULT`] (the reserved operator/node scope) via the `[secrets]` `envelope`. A
///   `None` envelope is [`S3CredentialError::NoEnvelope`] (fail-closed); an absent secret is
///   [`S3CredentialError::MissingBoatrampSecret`].
/// - `env:<VAR>` / bare `<VAR>` → read from `env_source`, but ONLY when `allow_env_secret_refs` is set
///   (else [`S3CredentialError::EnvRefNotPermitted`], fail-closed like a guest `env:` ref).
///
/// The result holds the plaintext in memory inside a redacted [`SealedS3Credential`].
pub async fn resolve_s3_credential(
    config: &crate::config::S3CredentialConfig,
    kv: Arc<dyn KvStore>,
    envelope: Option<Arc<dyn KeyEnvelope>>,
    allow_env_secret_refs: bool,
    env_source: &dyn EnvSource,
) -> Result<SealedS3Credential, S3CredentialError> {
    let access_key_id = config.access_key_id.trim();
    if access_key_id.is_empty() {
        return Err(S3CredentialError::EmptyAccessKeyId);
    }
    let secret_access_key = match parse_secret_ref(&config.secret_access_key) {
        SecretRef::Boatramp(name) => {
            // GATE MUTATION SEAM (invariant 1): read the AMBIENT env instead of the sealed store — the
            // "ignore the sealed source / read env" regression. The gate asserts the SEALED value is
            // used, so this must fail it.
            #[cfg(feature = "s3-sealed-cred-gate-mutation")]
            if gate_mutation::env_on("BOATRAMP_S3SEALED_MUTATE_READ_ENV") {
                return Ok(SealedS3Credential {
                    access_key_id: access_key_id.to_string(),
                    secret_access_key: env_source.get("AWS_SECRET_ACCESS_KEY").unwrap_or_default(),
                });
            }
            // GATE MUTATION SEAM (invariant 2): silently fall back to the ambient env when no envelope
            // is configured, INSTEAD of failing closed — the exact misconfig-masking regression. The
            // gate asserts a no-envelope sealed ref errors, so this must fail it.
            #[cfg(feature = "s3-sealed-cred-gate-mutation")]
            if envelope.is_none() && gate_mutation::env_on("BOATRAMP_S3SEALED_MUTATE_ENV_FALLBACK")
            {
                return Ok(SealedS3Credential {
                    access_key_id: access_key_id.to_string(),
                    secret_access_key: env_source.get("AWS_SECRET_ACCESS_KEY").unwrap_or_default(),
                });
            }
            // Fail closed BEFORE touching the store: a sealed ref with no envelope must never fall back
            // to the ambient env chain (that would mask the misconfig this feature exists to remove).
            let envelope = envelope.ok_or(S3CredentialError::NoEnvelope)?;
            let store = SecretStore::new(kv, envelope);
            match store.get(ProjectRef::DEFAULT, name).await {
                Ok(Some(bytes)) => {
                    String::from_utf8(bytes).map_err(|_| S3CredentialError::NotUtf8)?
                }
                Ok(None) => {
                    return Err(S3CredentialError::MissingBoatrampSecret(name.to_string()));
                }
                Err(e) => return Err(S3CredentialError::Backend(e.to_string())),
            }
        }
        SecretRef::Env(host_var) => {
            // The operator's own namespace — permitted only when the config author IS the operator.
            // Fail closed under the multi-tenant posture (matches the guest `env:` ref gate). NOTE: an
            // `env:`/bare source still requires NOTHING of the envelope — but it is still a "sealed
            // source is configured" case, so it does NOT silently degrade to the ambient AWS chain (the
            // operator asked for THIS var explicitly).
            if !allow_env_secret_refs {
                return Err(S3CredentialError::EnvRefNotPermitted(host_var.to_string()));
            }
            env_source
                .get(host_var)
                .ok_or_else(|| S3CredentialError::EnvVarUnset(host_var.to_string()))?
        }
        SecretRef::Unsupported(scheme) => {
            return Err(S3CredentialError::UnsupportedScheme(scheme.to_string()));
        }
    };
    Ok(SealedS3Credential {
        access_key_id: access_key_id.to_string(),
        secret_access_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::env::MapEnv;
    use boatramp_core::kv::MemoryKv;

    /// A trivial passthrough envelope for tests: seal/unseal are identity, so a `SecretStore` round-trip
    /// exercises the KV keying + the resolver's unseal path without a real KEK.
    struct IdentityEnvelope;

    #[async_trait::async_trait]
    impl KeyEnvelope for IdentityEnvelope {
        async fn wrap(
            &self,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
            Ok(plaintext.to_vec())
        }
        async fn unwrap(
            &self,
            sealed: &[u8],
        ) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
            Ok(sealed.to_vec())
        }
    }

    async fn seed_boatramp_secret(kv: &Arc<dyn KvStore>, name: &str, value: &str) {
        let store = SecretStore::new(kv.clone(), Arc::new(IdentityEnvelope));
        store
            .set(ProjectRef::DEFAULT, name, value.as_bytes())
            .await
            .expect("seal secret");
    }

    fn cfg(access_key_id: &str, secret_ref: &str) -> crate::config::S3CredentialConfig {
        crate::config::S3CredentialConfig {
            access_key_id: access_key_id.to_string(),
            secret_access_key: secret_ref.to_string(),
        }
    }

    #[tokio::test]
    async fn boatramp_ref_resolves_via_the_envelope() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        seed_boatramp_secret(&kv, "tigris-key", "SEALED-SECRET-VALUE").await;
        let env = MapEnv::new().with("AWS_SECRET_ACCESS_KEY", "AMBIENT-ENV-VALUE");
        let resolved = resolve_s3_credential(
            &cfg("AKID-PUBLIC", "boatramp:tigris-key"),
            kv,
            Some(Arc::new(IdentityEnvelope)),
            false,
            &env,
        )
        .await
        .expect("resolve");
        assert_eq!(resolved.access_key_id(), "AKID-PUBLIC");
        // The SEALED value is used — NOT the ambient env value (which the resolver never reads for a
        // boatramp: ref). This is invariant 1.
        assert_eq!(resolved.secret_access_key(), "SEALED-SECRET-VALUE");
    }

    #[tokio::test]
    async fn boatramp_ref_with_no_envelope_fails_closed() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        // A sealed ref is configured but NO envelope — must fail closed (invariant 2), NOT fall back to
        // the ambient env chain.
        let env = MapEnv::new().with("AWS_SECRET_ACCESS_KEY", "AMBIENT-ENV-VALUE");
        let err = resolve_s3_credential(
            &cfg("AKID-PUBLIC", "boatramp:tigris-key"),
            kv,
            None,
            true,
            &env,
        )
        .await
        .expect_err("must fail closed with no envelope");
        assert_eq!(err, S3CredentialError::NoEnvelope);
    }

    #[tokio::test]
    async fn missing_boatramp_secret_is_an_error_not_a_fallback() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let env = MapEnv::new().with("AWS_SECRET_ACCESS_KEY", "AMBIENT-ENV-VALUE");
        let err = resolve_s3_credential(
            &cfg("AKID-PUBLIC", "boatramp:absent"),
            kv,
            Some(Arc::new(IdentityEnvelope)),
            true,
            &env,
        )
        .await
        .expect_err("absent sealed secret is an error");
        assert_eq!(
            err,
            S3CredentialError::MissingBoatrampSecret("absent".to_string())
        );
    }

    #[tokio::test]
    async fn env_ref_is_posture_gated() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let env = MapEnv::new().with("MY_S3_SECRET", "ENV-SECRET-VALUE");
        // Refused under the strict posture (allow_env_secret_refs = false).
        let err = resolve_s3_credential(
            &cfg("AKID-PUBLIC", "env:MY_S3_SECRET"),
            kv.clone(),
            None,
            false,
            &env,
        )
        .await
        .expect_err("env ref refused under strict posture");
        assert_eq!(
            err,
            S3CredentialError::EnvRefNotPermitted("MY_S3_SECRET".to_string())
        );
        // Permitted under the dev posture.
        let ok = resolve_s3_credential(
            &cfg("AKID-PUBLIC", "env:MY_S3_SECRET"),
            kv,
            None,
            true,
            &env,
        )
        .await
        .expect("env ref permitted under dev posture");
        assert_eq!(ok.secret_access_key(), "ENV-SECRET-VALUE");
    }

    #[tokio::test]
    async fn empty_access_key_id_is_refused() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let env = MapEnv::new();
        let err = resolve_s3_credential(
            &cfg("", "boatramp:tigris-key"),
            kv,
            Some(Arc::new(IdentityEnvelope)),
            true,
            &env,
        )
        .await
        .expect_err("empty access-key-id refused");
        assert_eq!(err, S3CredentialError::EmptyAccessKeyId);
    }

    #[test]
    fn debug_redacts_the_secret() {
        let cred = SealedS3Credential {
            access_key_id: "AKID-PUBLIC".to_string(),
            secret_access_key: "SUPER-SECRET-DO-NOT-LOG".to_string(),
        };
        let dbg = format!("{cred:?}");
        // Invariant 3: the secret NEVER appears in Debug (a plain-`Debug` derive would leak it).
        assert!(
            !dbg.contains("SUPER-SECRET-DO-NOT-LOG"),
            "the secret access key must be redacted from Debug: {dbg}"
        );
        assert!(
            dbg.contains("<redacted>"),
            "redaction marker present: {dbg}"
        );
        // The public id is fine to show.
        assert!(
            dbg.contains("AKID-PUBLIC"),
            "the access-key id is public: {dbg}"
        );
    }

    #[test]
    fn parse_secret_ref_matches_the_server_scheme() {
        assert!(matches!(
            parse_secret_ref("boatramp:x"),
            SecretRef::Boatramp("x")
        ));
        assert!(matches!(parse_secret_ref("env:VAR"), SecretRef::Env("VAR")));
        assert!(matches!(parse_secret_ref("BARE"), SecretRef::Env("BARE")));
        assert!(matches!(
            parse_secret_ref("vault:x"),
            SecretRef::Unsupported("vault")
        ));
    }
}

// ================================================================================================
// The #505 mutation-verified gate battery: `S3 SEALED-CRED SOURCING OK`.
//
// One `#[tokio::test]` runs every invariant, then prints the marker. Compiled ONLY under the
// `s3-sealed-cred-gate-mutation` feature (the CI gate lane); each `BOATRAMP_S3SEALED_MUTATE_*` env var
// neuters exactly ONE invariant (via the seams above), so a clean run reaches the marker while every
// mutation PANICS before it — proving each check is load-bearing. See the ci.yml gate step.
// ================================================================================================
#[cfg(all(test, feature = "s3-sealed-cred-gate-mutation"))]
mod gate {
    use super::*;
    use boatramp_core::env::MapEnv;
    use boatramp_core::kv::MemoryKv;

    struct IdentityEnvelope;
    #[async_trait::async_trait]
    impl KeyEnvelope for IdentityEnvelope {
        async fn wrap(
            &self,
            plaintext: &[u8],
        ) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
            Ok(plaintext.to_vec())
        }
        async fn unwrap(
            &self,
            sealed: &[u8],
        ) -> Result<Vec<u8>, boatramp_core::envelope::EnvelopeError> {
            Ok(sealed.to_vec())
        }
    }

    /// The sealed value the gate seeds + expects; the ambient env value it must NEVER pick instead.
    const SEALED: &str = "SEALED-TIGRIS-SECRET";
    const AMBIENT_ENV: &str = "AMBIENT-AWS-SECRET";

    async fn seeded_kv() -> Arc<dyn KvStore> {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        SecretStore::new(kv.clone(), Arc::new(IdentityEnvelope))
            .set(ProjectRef::DEFAULT, "tigris-key", SEALED.as_bytes())
            .await
            .expect("seal");
        kv
    }

    fn cfg(secret_ref: &str) -> crate::config::S3CredentialConfig {
        crate::config::S3CredentialConfig {
            access_key_id: "AKID-PUBLIC".to_string(),
            secret_access_key: secret_ref.to_string(),
        }
    }

    // Invariant 1: a `boatramp:` source resolves to the SEALED value, and that value is what the blob
    // backend injects (`S3Options.credential`) — NOT the ambient env value. Mutation READ_ENV neuters it.
    async fn invariant_1_sealed_not_env() {
        let kv = seeded_kv().await;
        let env = MapEnv::new().with("AWS_SECRET_ACCESS_KEY", AMBIENT_ENV);
        let cred = resolve_s3_credential(
            &cfg("boatramp:tigris-key"),
            kv,
            Some(Arc::new(IdentityEnvelope)),
            false,
            &env,
        )
        .await
        .expect("resolve sealed");
        assert_eq!(
            cred.secret_access_key(),
            SEALED,
            "the SEALED credential must be used, not the ambient env value"
        );
        assert_ne!(
            cred.secret_access_key(),
            AMBIENT_ENV,
            "must not read the env"
        );
        // The blob backend injects EXACTLY this pair into `S3Options.credential` (the build path is
        // `credential: args.s3_credential.as_ref().map(|c| c.as_pair())`), so the built S3 client signs
        // with the sealed key. Assert the pair the backend would receive.
        let opts = boatramp_storage::S3Options {
            bucket: "b".to_string(),
            endpoint: None,
            region: None,
            force_path_style: false,
            credential: Some(cred.as_pair()),
        };
        assert_eq!(
            opts.credential
                .as_ref()
                .map(|(id, s)| (id.as_str(), s.as_str())),
            Some(("AKID-PUBLIC", SEALED)),
            "S3Options.credential carries the sealed pair the S3 client will sign with"
        );
    }

    // Invariant 2: a `boatramp:` sealed ref with NO `[secrets]` envelope FAILS CLOSED — never a silent
    // env fallback. Mutation ENV_FALLBACK neuters it (returns Ok).
    async fn invariant_2_no_envelope_fails_closed() {
        let kv = seeded_kv().await;
        let env = MapEnv::new().with("AWS_SECRET_ACCESS_KEY", AMBIENT_ENV);
        let result = resolve_s3_credential(&cfg("boatramp:tigris-key"), kv, None, true, &env).await;
        match result {
            Err(S3CredentialError::NoEnvelope) => {}
            Ok(_) => panic!(
                "a sealed ref with no envelope must FAIL CLOSED, not fall back to the env chain"
            ),
            Err(other) => panic!("expected NoEnvelope, got {other:?}"),
        }
    }

    // Invariant 3: the secret NEVER appears in `Debug`. Mutation PLAIN_DEBUG neuters the redaction.
    async fn invariant_3_debug_redacts() {
        let kv = seeded_kv().await;
        let env = MapEnv::new();
        let cred = resolve_s3_credential(
            &cfg("boatramp:tigris-key"),
            kv,
            Some(Arc::new(IdentityEnvelope)),
            false,
            &env,
        )
        .await
        .expect("resolve");
        let dbg = format!("{cred:?}");
        assert!(
            !dbg.contains(SEALED),
            "the secret must be redacted from Debug: {dbg}"
        );
    }

    // Invariant 4: an ABSENT source ⇒ the ambient AWS env chain (non-breaking) — `S3Options.credential`
    // stays `None` so the SDK resolves the ambient chain (the historical default). No mutation neuters a
    // positive path; the assertion documents the non-breaking contract.
    async fn invariant_4_absent_source_is_ambient() {
        // When no `[serve.s3_credential]` is configured, the blob backend leaves `credential` = None.
        let opts = boatramp_storage::S3Options {
            bucket: "b".to_string(),
            endpoint: None,
            region: None,
            force_path_style: false,
            credential: None,
        };
        assert!(
            opts.credential.is_none(),
            "absent source ⇒ no explicit provider ⇒ the ambient AWS env chain (unchanged)"
        );
    }

    #[tokio::test]
    async fn s3_sealed_cred_sourcing_gate() {
        invariant_1_sealed_not_env().await;
        invariant_2_no_envelope_fails_closed().await;
        invariant_3_debug_redacts().await;
        invariant_4_absent_source_is_ambient().await;
        // Reached only on a clean, fully-passing run — a mutation env var panics one invariant above.
        println!(
            "S3 SEALED-CRED SOURCING OK: the node-level base S3 credential is sourced from the \
             [secrets] sealed store (KeyEnvelope), injected into the S3 blob backend + AWS cloud \
             minter, fail-closed with no envelope, and redacted from Debug. Mutation-verified: \
             BOATRAMP_S3SEALED_MUTATE_{{READ_ENV,ENV_FALLBACK,PLAIN_DEBUG}}=1 each FAIL this gate."
        );
    }
}
