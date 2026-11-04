//! `type:value` config-pointer resolution for the per-zone DNS providers (`[serve.dns_providers]`,
//! cap-req #27).
//!
//! Each DNS provider field is a standard boatramp config pointer, resolved independently at serve
//! startup against the control-plane KV + the `[secrets]` envelope — the SAME sealed-store + posture
//! primitives the node-level base S3 credential (#505, [`crate::s3_credential`]) uses, so a DNS token is
//! sourced exactly like the S3 secret key:
//!
//! - `boatramp:<name>` — unsealed from the project-scoped
//!   [`SecretStore`](boatramp_core::secret_store::SecretStore) under the reserved default project via
//!   the `[secrets]` [`KeyEnvelope`]. A `boatramp:` ref with NO envelope is a **fail-closed** startup
//!   error (never a silent env fallback); an absent secret is an error (never a silent skip).
//! - `env:<VAR>` — the operator's own environment, honored ONLY when the security posture's
//!   `allow_env_secret_refs` is set (the same gate a guest `env:` ref hits), else refused fail-closed.
//! - a **bare literal** — the value itself. This is the one grammar difference from
//!   [`crate::s3_credential`] (where a bare value is an env var NAME): here a `zone_id` / `region` /
//!   `hosted_zone_id` is naturally a literal, so a value with no recognized `env:`/`boatramp:` scheme is
//!   taken verbatim.
//!
//! **No secrets in config:** a field marked SECRET (a token / API key / client secret) MUST be a
//! `env:`/`boatramp:` ref — a bare literal in a secret field is refused at startup
//! ([`ConfigRefError::LiteralSecretRefused`]), mirroring how `[serve.s3_credential].secret_access_key`
//! refuses an in-file plaintext secret. The resolved plaintext is held in a [`ResolvedValue`] whose
//! `Debug` redacts a secret, so it never lands in a log / panic message.

use std::sync::Arc;

use boatramp_core::env::EnvSource;
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::kv::KvStore;
use boatramp_core::project::ProjectRef;
use boatramp_core::secret_store::SecretStore;

/// A resolved DNS-provider config value held in memory. A SECRET value is **redacted** from `Debug`
/// (mirroring [`crate::s3_credential::SealedS3Credential`]), so a struct-`Debug` in a log or panic can
/// never leak a token; a non-secret identifier is shown.
#[derive(Clone)]
pub struct ResolvedValue {
    value: String,
    secret: bool,
}

impl ResolvedValue {
    /// Borrow the resolved value (to pass into an adapter constructor).
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Consume into the owned `String` (the adapter takes ownership of the credential).
    pub fn into_string(self) -> String {
        self.value
    }
}

impl std::fmt::Debug for ResolvedValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.secret {
            f.debug_struct("ResolvedValue")
                .field("value", &"<redacted>")
                .finish()
        } else {
            f.debug_struct("ResolvedValue")
                .field("value", &self.value)
                .finish()
        }
    }
}

/// A failure resolving a DNS-provider config pointer. Variants mirror
/// [`crate::s3_credential::S3CredentialError`] (same sealed-store semantics), plus
/// [`Self::LiteralSecretRefused`] for the no-secrets-in-config rule.
#[derive(Debug, PartialEq, Eq)]
pub enum ConfigRefError {
    /// A SECRET field was given a bare literal (a plaintext secret in config) — refused fail-closed; use
    /// a `env:<VAR>` or `boatramp:<name>` reference. Carries the field name.
    LiteralSecretRefused(String),
    /// A `boatramp:`/`env:` ref resolved to an empty value — refused fail-closed (an empty credential
    /// would fail at request-time, not startup). Carries the field name.
    EmptyValue(String),
    /// A `boatramp:<name>` ref but no `[secrets]` envelope is configured — fail closed (never a silent
    /// env fallback). Carries the field name.
    NoEnvelope(String),
    /// A `boatramp:<name>` ref whose secret is not present in the sealed store. Carries the field name
    /// and the secret name.
    MissingBoatrampSecret { field: String, name: String },
    /// An `env:`/bare host-env ref refused because the posture's `allow_env_secret_refs` is off. Carries
    /// the field name and the env var.
    EnvRefNotPermitted { field: String, var: String },
    /// An `env:<VAR>` ref whose var is unset. Carries the field name and the env var.
    EnvVarUnset { field: String, var: String },
    /// A resolved sealed value that is not valid UTF-8. Carries the field name.
    NotUtf8(String),
    /// A KV / envelope (unseal) backend failure. Carries the field name and a detail string.
    Backend { field: String, detail: String },
}

impl std::fmt::Display for ConfigRefError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LiteralSecretRefused(field) => write!(
                f,
                "dns_providers: field `{field}` is a secret and must be a `env:<VAR>` or \
                 `boatramp:<name>` reference, never a plaintext literal in the config"
            ),
            Self::EmptyValue(field) => write!(
                f,
                "dns_providers: field `{field}` resolved to an empty value — refusing to build a \
                 provider from an empty credential/identifier (fail-closed)"
            ),
            Self::NoEnvelope(field) => write!(
                f,
                "dns_providers: field `{field}` is a `boatramp:` sealed ref but no `[secrets]` \
                 envelope is configured — refusing to fall back (fail-closed); configure `[secrets]`"
            ),
            Self::MissingBoatrampSecret { field, name } => write!(
                f,
                "dns_providers: field `{field}` → boatramp:{name} is not set in the sealed secret \
                 store (default project); seal it with `boatramp secrets set`"
            ),
            Self::EnvRefNotPermitted { field, var } => write!(
                f,
                "dns_providers: field `{field}` host-env ref {var:?} is not permitted under the \
                 multi-tenant posture; enable `allow_env_secret_refs` or use a `boatramp:<name>` ref"
            ),
            Self::EnvVarUnset { field, var } => write!(
                f,
                "dns_providers: field `{field}` env var {var:?} is not set"
            ),
            Self::NotUtf8(field) => write!(
                f,
                "dns_providers: field `{field}` resolved to a value that is not valid UTF-8"
            ),
            Self::Backend { field, detail } => {
                write!(f, "dns_providers: field `{field}`: {detail}")
            }
        }
    }
}

impl std::error::Error for ConfigRefError {}

/// A parsed config pointer — the DNS-provider grammar (bare ⇒ literal, unlike `parse_secret_ref`).
enum ConfigRef<'a> {
    /// A bare literal value (used verbatim; refused for a secret field).
    Literal(&'a str),
    /// `env:<VAR>` — the operator's own environment (posture-gated).
    Env(&'a str),
    /// `boatramp:<name>` — the project-scoped sealed store.
    Boatramp(&'a str),
}

fn parse_config_ref(value: &str) -> ConfigRef<'_> {
    match value.split_once(':') {
        Some(("env", var)) => ConfigRef::Env(var),
        Some(("boatramp", name)) => ConfigRef::Boatramp(name),
        // A bare value, or any other `scheme:value`, is a LITERAL (no reserved-scheme errors here: the
        // DNS fields are literal-by-default, and a secret literal is refused separately below).
        _ => ConfigRef::Literal(value),
    }
}

/// Resolve one `[serve.dns_providers]` field pointer against the sealed store / env / literal.
///
/// `field` is the field name (for error messages). `is_secret` enforces the no-secrets-in-config rule:
/// a bare literal in a secret field is refused. `project` scopes a `boatramp:` ref (the serve's
/// host-resolved project, never guest input; the DNS registry uses [`ProjectRef::DEFAULT`]).
///
/// The resolved value is returned in a [`ResolvedValue`] whose `Debug` redacts a secret.
#[allow(clippy::too_many_arguments)]
pub async fn resolve_config_ref(
    field: &str,
    value: &str,
    is_secret: bool,
    project: ProjectRef<'_>,
    kv: &Arc<dyn KvStore>,
    envelope: &Option<Arc<dyn KeyEnvelope>>,
    allow_env_secret_refs: bool,
    env_source: &dyn EnvSource,
) -> Result<ResolvedValue, ConfigRefError> {
    let resolved = match parse_config_ref(value) {
        ConfigRef::Literal(lit) => {
            if is_secret {
                return Err(ConfigRefError::LiteralSecretRefused(field.to_string()));
            }
            lit.to_string()
        }
        ConfigRef::Boatramp(name) => {
            // Fail closed BEFORE touching the store: a sealed ref with no envelope must never fall back.
            let envelope = envelope
                .clone()
                .ok_or_else(|| ConfigRefError::NoEnvelope(field.to_string()))?;
            let store = SecretStore::new(kv.clone(), envelope);
            match store.get(project, name).await {
                Ok(Some(bytes)) => String::from_utf8(bytes)
                    .map_err(|_| ConfigRefError::NotUtf8(field.to_string()))?,
                Ok(None) => {
                    return Err(ConfigRefError::MissingBoatrampSecret {
                        field: field.to_string(),
                        name: name.to_string(),
                    });
                }
                Err(e) => {
                    return Err(ConfigRefError::Backend {
                        field: field.to_string(),
                        detail: e.to_string(),
                    });
                }
            }
        }
        ConfigRef::Env(var) => {
            // The operator's own namespace — permitted only when the config author IS the operator
            // (same gate a guest `env:` ref hits), else fail closed under the multi-tenant posture.
            if !allow_env_secret_refs {
                return Err(ConfigRefError::EnvRefNotPermitted {
                    field: field.to_string(),
                    var: var.to_string(),
                });
            }
            env_source
                .get(var)
                .ok_or_else(|| ConfigRefError::EnvVarUnset {
                    field: field.to_string(),
                    var: var.to_string(),
                })?
        }
    };
    if resolved.trim().is_empty() {
        return Err(ConfigRefError::EmptyValue(field.to_string()));
    }
    Ok(ResolvedValue {
        value: resolved,
        secret: is_secret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::env::MapEnv;
    use boatramp_core::envelope::EnvelopeError;
    use boatramp_core::kv::MemoryKv;

    /// Passthrough envelope (seal/unseal are identity) so a `SecretStore` round-trip exercises the KV
    /// keying + unseal path without a real KEK — same double the s3_credential tests use.
    struct IdentityEnvelope;
    #[async_trait::async_trait]
    impl KeyEnvelope for IdentityEnvelope {
        async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(plaintext.to_vec())
        }
        async fn unwrap(&self, sealed: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(sealed.to_vec())
        }
    }

    async fn seed(kv: &Arc<dyn KvStore>, name: &str, value: &str) {
        SecretStore::new(kv.clone(), Arc::new(IdentityEnvelope))
            .set(ProjectRef::DEFAULT, name, value.as_bytes())
            .await
            .expect("seal");
    }

    #[tokio::test]
    async fn literal_non_secret_is_used_verbatim() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let env = MapEnv::new();
        let r = resolve_config_ref(
            "zone_id",
            "741f56abc",
            false,
            ProjectRef::DEFAULT,
            &kv,
            &None,
            false,
            &env,
        )
        .await
        .expect("literal non-secret resolves");
        assert_eq!(r.as_str(), "741f56abc");
    }

    #[tokio::test]
    async fn literal_in_a_secret_field_is_refused() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let env = MapEnv::new();
        let err = resolve_config_ref(
            "token",
            "super-secret-token",
            true,
            ProjectRef::DEFAULT,
            &kv,
            &None,
            true,
            &env,
        )
        .await
        .expect_err("a plaintext secret literal must be refused");
        assert_eq!(
            err,
            ConfigRefError::LiteralSecretRefused("token".to_string())
        );
    }

    #[tokio::test]
    async fn env_ref_is_posture_gated() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let env = MapEnv::new().with("CF_TOKEN", "ENV-TOKEN-VALUE");
        // Refused under the strict posture.
        let err = resolve_config_ref(
            "token",
            "env:CF_TOKEN",
            true,
            ProjectRef::DEFAULT,
            &kv,
            &None,
            false,
            &env,
        )
        .await
        .expect_err("env ref refused under strict posture");
        assert_eq!(
            err,
            ConfigRefError::EnvRefNotPermitted {
                field: "token".to_string(),
                var: "CF_TOKEN".to_string()
            }
        );
        // Permitted under the dev posture.
        let ok = resolve_config_ref(
            "token",
            "env:CF_TOKEN",
            true,
            ProjectRef::DEFAULT,
            &kv,
            &None,
            true,
            &env,
        )
        .await
        .expect("env ref permitted under dev posture");
        assert_eq!(ok.as_str(), "ENV-TOKEN-VALUE");
    }

    #[tokio::test]
    async fn boatramp_ref_resolves_via_the_envelope() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        seed(&kv, "CF_TOKEN_MAILROOM", "SEALED-CF-TOKEN").await;
        let env = MapEnv::new().with("CF_TOKEN_MAILROOM", "AMBIENT-SHOULD-NOT-BE-READ");
        let r = resolve_config_ref(
            "token",
            "boatramp:CF_TOKEN_MAILROOM",
            true,
            ProjectRef::DEFAULT,
            &kv,
            &Some(Arc::new(IdentityEnvelope)),
            false,
            &env,
        )
        .await
        .expect("boatramp ref resolves");
        assert_eq!(r.as_str(), "SEALED-CF-TOKEN");
    }

    #[tokio::test]
    async fn boatramp_ref_with_no_envelope_fails_closed() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let env = MapEnv::new();
        let err = resolve_config_ref(
            "token",
            "boatramp:CF_TOKEN",
            true,
            ProjectRef::DEFAULT,
            &kv,
            &None,
            true,
            &env,
        )
        .await
        .expect_err("a sealed ref with no envelope must fail closed");
        assert_eq!(err, ConfigRefError::NoEnvelope("token".to_string()));
    }

    #[tokio::test]
    async fn missing_boatramp_secret_is_an_error() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let err = resolve_config_ref(
            "token",
            "boatramp:absent",
            true,
            ProjectRef::DEFAULT,
            &kv,
            &Some(Arc::new(IdentityEnvelope)),
            true,
            &MapEnv::new(),
        )
        .await
        .expect_err("absent sealed secret is an error");
        assert_eq!(
            err,
            ConfigRefError::MissingBoatrampSecret {
                field: "token".to_string(),
                name: "absent".to_string()
            }
        );
    }

    #[tokio::test]
    async fn empty_resolved_value_fails_closed() {
        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let env = MapEnv::new().with("EMPTY", "");
        let err = resolve_config_ref(
            "token",
            "env:EMPTY",
            true,
            ProjectRef::DEFAULT,
            &kv,
            &None,
            true,
            &env,
        )
        .await
        .expect_err("empty env value fails closed");
        assert_eq!(err, ConfigRefError::EmptyValue("token".to_string()));
    }

    #[test]
    fn debug_redacts_a_secret_value() {
        let secret = ResolvedValue {
            value: "SUPER-SECRET".to_string(),
            secret: true,
        };
        let dbg = format!("{secret:?}");
        assert!(!dbg.contains("SUPER-SECRET"), "secret redacted: {dbg}");
        assert!(dbg.contains("<redacted>"));
        let public = ResolvedValue {
            value: "zone-id-123".to_string(),
            secret: false,
        };
        assert!(
            format!("{public:?}").contains("zone-id-123"),
            "non-secret shown"
        );
    }
}
