//! Secret-blind root config resolution + the spawn-environment contract
//! (privsep Phase 1 — WS-B; design `PLAN-privsep-phase1.md` §4.1, findings F1,
//! F11-A, F11-B). **SECURITY-CRITICAL — this is the root's secret-blindness.**
//!
//! The privsep **root** is the minimal TCB floor (design §4): it resolves the
//! TOPOLOGY + non-secret config shapes and **nothing else** — it unseals no KEK,
//! holds no signer key, opens no pool, and in particular **materializes no key
//! input of any §1.2 authority** (the KEK, the token-signer key, the image-signer
//! key, the overlay seed `OverlayServeConfig.identity`, the s3ingress HKDF root,
//! the cluster-join root, plus any inline-capable cert key). This module is the
//! PURE, exhaustively-testable core of that guarantee; the OS-level supervisor
//! (`boatramp`'s `crate::privsep`) wraps it.
//!
//! Two guarantees, both fail-closed:
//!
//! 1. **[`screen_secret_blind`] (F1 + F11-A)** — under `[privsep]`, an INLINE or
//!    ENV-VALUED raw value for any §1.2 authority key input is a HARD load refusal.
//!    Only a **path / env-NAME reference** is permitted; the root carries those as
//!    opaque reference tokens it NEVER dereferences (each holding instance resolves
//!    its own secret later, behind its own Landlock grant). Because a resolved
//!    config is screened for every raw-secret VALUE (inline or env-sourced — the
//!    figment pipeline has already merged env/flags by the time we screen), a
//!    `[privsep]` config that LOADS is secret-blind by construction: the root's
//!    in-memory config holds no §1.2-key / `SECRET_FIELDS` plaintext. The scope is
//!    DECOUPLED from the `SECRET_FIELDS` redaction constant and widened to the §1.2
//!    key inputs — notably the inline-capable overlay seed, which `SECRET_FIELDS`
//!    omits (design F11-A).
//!
//! 2. **[`build_instance_env`] (F11-B)** — the root builds an EXPLICITLY MINIMAL
//!    per-instance environment on spawn, SCRUBBING every secret-bearing env var. The
//!    default `fork`+`exec` full-environment inheritance is the footgun this kills: a
//!    frontend must not inherit `VAULT_TOKEN` / a KMS token / `BOATRAMP_*` secret
//!    overlays. The root is **never the courier of a live credential** — it never
//!    POPULATES a secret into a child's env; a KMS/Vault token the signer needs is
//!    delivered by FILE/FD and resolved by the holding instance itself (design
//!    §4.1(c), Round 3). Reference-shaped env vars (`*_FILE` paths, `*_ENV` var
//!    names) carry a reference, not a value, so they are NOT secrets and pass.
//!
//! **Phase-1 scope of env-valued credentials (deliberate, design §4.1).** The
//! existing env-token integrations — a Vault secrets envelope (`VAULT_TOKEN`), an
//! env-token KMS/Vault **signer** (`token_env` / `access_token_env` / `pin_env`) —
//! read their LIVE credential from an env var, so under `[privsep]` the root would
//! have to courier that token to the signer, contradicting the no-courier invariant.
//! Adding a file/fd token-source to those integrations is a documented **Phase-2 /
//! signer follow-on**; the Phase-1 cut therefore supports the **file-based local
//! KEK** + **file / KMS-without-env-token signers** (AWS-KMS via the ambient IAM /
//! instance-role chain), and an env-token backend under `[privsep]` is refused at
//! load (fail-closed, not silently starved). A non-privsep (monolith) node is
//! unaffected — the env-token path is unchanged there.

use std::collections::BTreeMap;

use boatramp_core::privsep::HostAuthority;

use crate::config::{AuthSignerConfig, ServerConfig};

// =============================================================================
// 1. The secret-blind screen (F1 + F11-A)
// =============================================================================

/// One fail-closed secret-blindness refusal (design §4.1, F1/F11-A). Each names the
/// offending config location and why the root may not carry it as a raw value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretBlindViolation {
    /// A `SECRET_FIELDS`-class field holds a raw secret VALUE (inline in the file, or
    /// env-sourced through the pipeline) somewhere in the resolved config. The root
    /// must carry a REFERENCE (path / env-name), never the value (design F11-A). The
    /// `json_path` is the dotted location (e.g. `serve.auth_root_private_key`,
    /// `serve.blob_fallback.azure_access_key`).
    RawSecretValue {
        /// The dotted config path to the offending field.
        json_path: String,
        /// The secret field name (one of the raw-secret `SECRET_FIELDS`).
        field: String,
    },
    /// `[overlay].identity` is an INLINE `ed25519:<hex>` seed — the crown-jewel
    /// `overlay.dial-signer` key input. Under `[privsep]` it must be a FILE PATH the
    /// signer instance resolves itself; the root never parses the seed (design F11-A).
    InlineOverlaySeed,
    /// `[cluster].join_token` is an inline literal or an `env:` live-token reference —
    /// the cluster-join credential. Under `[privsep]` it must be a `path:` reference
    /// (an `env:`/inline token would make the root the courier of a live credential;
    /// the env-token source is a Phase-2 follow-on, design §4.1(c)).
    RawOrEnvClusterJoinToken {
        /// The offending form, redacted to its scheme/prefix only (never the value).
        form: &'static str,
    },
    /// `[serve.signer]` is an ENV-TOKEN KMS/Vault variant (`Vault` / `GcpKms` /
    /// `AzureKv` / `Pkcs11`) — it reads a live token from an env var, which under
    /// `[privsep]` the root would have to courier to the signer. A documented Phase-2
    /// / signer follow-on (design §4.1); the Phase-1 cut supports an in-instance
    /// file/KMS-without-env-token signer (`AwsKms`).
    EnvTokenSigner {
        /// The refused signer variant.
        variant: &'static str,
    },
    /// `[secrets]` selects the **Vault Transit** envelope — it reads `VAULT_TOKEN`
    /// (a live token) from the env, the same courier problem as [`Self::EnvTokenSigner`].
    /// A Phase-2 follow-on; the Phase-1 cut supports the file-based local KEK (design
    /// §4.1).
    EnvTokenSecretsEnvelope,
}

impl std::fmt::Display for SecretBlindViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RawSecretValue { json_path, field } => write!(
                f,
                "config field `{json_path}` holds a raw secret value — under [privsep] the \
                 root is secret-blind: express `{field}` as a path / env-name REFERENCE \
                 (the holding instance resolves it), never a raw value"
            ),
            Self::InlineOverlaySeed => write!(
                f,
                "[overlay].identity is an inline `ed25519:<hex>` seed (the overlay.dial-signer \
                 crown-jewel key) — under [privsep] it must be a key-FILE PATH the signer \
                 instance resolves itself; the root never parses the seed"
            ),
            Self::RawOrEnvClusterJoinToken { form } => write!(
                f,
                "[cluster].join_token is {form} — under [privsep] it must be a `path:` \
                 reference; an inline or `env:` live token would make the root a credential \
                 courier (an env-token source is a Phase-2 follow-on)"
            ),
            Self::EnvTokenSigner { variant } => write!(
                f,
                "[serve.signer] = {variant} reads a live token from an env var — unsupported \
                 under [privsep] in Phase 1 (the root must not courier it to the signer). Use \
                 an `AwsKms` (ambient IAM / instance-role) signer; env-token KMS/Vault is a \
                 documented Phase-2 / signer follow-on"
            ),
            Self::EnvTokenSecretsEnvelope => write!(
                f,
                "[secrets].envelope = \"vault\" reads VAULT_TOKEN (a live token) from the env — \
                 unsupported under [privsep] in Phase 1 (the root must not courier it). Use the \
                 file-based local KEK; env-token Vault Transit is a documented Phase-2 follow-on"
            ),
        }
    }
}

/// A fail-closed secret-blindness REFUSAL: one or more [`SecretBlindViolation`]s. The
/// root must refuse to load the composition and spawn nothing (design §4.1, F1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretBlindError {
    /// Every violation found — the whole picture, so an operator sees all faults at once.
    pub violations: Vec<SecretBlindViolation>,
}

impl std::fmt::Display for SecretBlindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[privsep] root secret-blindness refused ({} violation(s)): ",
            self.violations.len()
        )?;
        for (i, v) in self.violations.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{v}")?;
        }
        Ok(())
    }
}

impl std::error::Error for SecretBlindError {}

/// A clean [`screen_secret_blind`] pass: the composition is secret-blind — every
/// §1.2 authority key input is a path / env-name reference the root carries opaquely
/// and never dereferences.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretBlindReport {
    /// The count of opaque secret references the root carries (for the operator log).
    /// It is a tally only — the references' VALUES are never surfaced here.
    pub opaque_reference_count: usize,
}

/// The raw-secret `SECRET_FIELDS` field names that are ALWAYS a raw value (never a
/// reference) — a present, non-empty one anywhere in the resolved config is a refusal.
///
/// This is the `SECRET_FIELDS` redaction constant (`config.rs`) MINUS the two
/// reference-shaped names handled specially below:
/// - `join_token` (`env:`/`path:`/inline — [`check_cluster_join_token`] allows only `path:`);
/// - `secret_access_key` (a `boatramp:`/`env:` reference by design — never a raw value).
///
/// A drift guard test asserts this set ∪ {those two} ⊇ `SECRET_FIELDS`, so a new
/// redacted field can never silently escape the root-blindness screen.
const RAW_SECRET_VALUE_FIELDS: &[&str] = &[
    "auth_root_private_key",
    "bootstrap_secret",
    "azure_access_key",
    "private_key",
];

/// Screen the resolved [`ServerConfig`] for the root's secret-blindness (design §4.1,
/// F1 + F11-A). Returns `Err` — fail-closed — if ANY §1.2 authority key input (or any
/// raw-secret `SECRET_FIELDS` value) is present as an inline or env-VALUED raw value;
/// `Ok` with a [`SecretBlindReport`] when the config is reference-only.
///
/// **Only invoked for an explicitly-present `[privsep]` composition.** A monolith
/// (absent `[privsep]`) is never screened — inline secrets remain permitted there
/// (today's behavior, unchanged). The caller gates on `config.privsep.is_some()`.
///
/// Every violation is collected (not short-circuited) so an operator sees the whole
/// picture before fixing the config.
pub fn screen_secret_blind(cfg: &ServerConfig) -> Result<SecretBlindReport, SecretBlindError> {
    let mut violations = Vec::new();

    // --- (a) Generic raw-secret VALUE catch over the whole resolved tree. ---
    // Serializing the config to JSON and walking for the raw-secret field names is the
    // SAME field-name discipline the `dump_redacted` redactor uses, so a raw secret
    // ANYWHERE (incl. nested `serve.blob_fallback.azure_access_key`, a signer's inline
    // `private_key`) is caught without hand-reaching into every struct. A serialization
    // failure is itself fail-closed: we cannot prove the config secret-blind, so we
    // refuse via a synthetic violation.
    match serde_json::to_value(cfg) {
        Ok(value) => walk_raw_secret_values(&value, "", &mut violations),
        Err(_) => violations.push(SecretBlindViolation::RawSecretValue {
            json_path: "<config>".to_string(),
            field: "<unserializable>".to_string(),
        }),
    }

    // --- (b) Typed §1.2 checks the name-walk cannot express. ---
    // Matches the serve loader's own inline-vs-path rule (`serve::load_overlay_identity`):
    // an `ed25519:`-tagged value is an inline seed; anything else is a path.
    if let Some(overlay) = &cfg.overlay
        && let Some(identity) = &overlay.identity
        && identity.starts_with("ed25519:")
    {
        violations.push(SecretBlindViolation::InlineOverlaySeed);
    }

    if let Some(cluster) = &cfg.cluster
        && let Some(token) = &cluster.join_token
        && let Some(form) = check_cluster_join_token(token)
    {
        violations.push(SecretBlindViolation::RawOrEnvClusterJoinToken { form });
    }

    if let Some(serve) = &cfg.serve
        && let Some(signer) = &serve.signer
        && let Some(variant) = env_token_signer_variant(signer)
    {
        violations.push(SecretBlindViolation::EnvTokenSigner { variant });
    }

    if let Some(secrets) = &cfg.secrets
        && (secrets.envelope.eq_ignore_ascii_case("vault") || secrets.vault.is_some())
    {
        violations.push(SecretBlindViolation::EnvTokenSecretsEnvelope);
    }

    if violations.is_empty() {
        Ok(SecretBlindReport {
            opaque_reference_count: count_opaque_references(cfg),
        })
    } else {
        Err(SecretBlindError { violations })
    }
}

/// Recurse a serialized config value, flagging any [`RAW_SECRET_VALUE_FIELDS`] key
/// whose value is a non-empty string (a present raw secret). `prefix` is the dotted
/// path accumulated so far.
fn walk_raw_secret_values(
    value: &serde_json::Value,
    prefix: &str,
    out: &mut Vec<SecretBlindViolation>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                let is_present_raw_secret = RAW_SECRET_VALUE_FIELDS.contains(&k.as_str())
                    && matches!(v, serde_json::Value::String(s) if !s.is_empty());
                if is_present_raw_secret {
                    out.push(SecretBlindViolation::RawSecretValue {
                        json_path: path,
                        field: k.clone(),
                    });
                } else {
                    walk_raw_secret_values(v, &path, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                walk_raw_secret_values(item, &format!("{prefix}[{i}]"), out);
            }
        }
        _ => {}
    }
}

/// Classify a `[cluster].join_token` value. `None` ⇒ an acceptable `path:` reference;
/// `Some(form)` ⇒ a refused inline literal or `env:` live-token reference (the returned
/// `form` is the scheme only — never the value).
fn check_cluster_join_token(token: &str) -> Option<&'static str> {
    if token.starts_with("path:") {
        None
    } else if token.starts_with("env:") {
        Some("an `env:` live-token reference")
    } else {
        Some("an inline literal token")
    }
}

/// The refused env-token signer variant name, or `None` for a supported
/// (reference-free / ambient-credential) signer. `AwsKms` is supported under
/// `[privsep]` Phase 1 (it uses the ambient IAM / instance-role chain, not an env
/// token); `Local` carries a raw `private_key` already caught by the raw-value walk.
fn env_token_signer_variant(signer: &AuthSignerConfig) -> Option<&'static str> {
    match signer {
        AuthSignerConfig::Vault { .. } => Some("Vault"),
        AuthSignerConfig::GcpKms { .. } => Some("GcpKms"),
        AuthSignerConfig::AzureKv { .. } => Some("AzureKv"),
        AuthSignerConfig::Pkcs11 { .. } => Some("Pkcs11"),
        AuthSignerConfig::Local { .. } | AuthSignerConfig::AwsKms { .. } => None,
    }
}

/// Count the opaque secret REFERENCES the root carries (path / env-name) for the
/// operator log. Tallies the §1.2 key-input reference slots that are present — never
/// their values.
fn count_opaque_references(cfg: &ServerConfig) -> usize {
    let mut n = 0;
    if let Some(serve) = &cfg.serve {
        n += usize::from(serve.s3_ingress_secret_file.is_some());
        n += usize::from(matches!(
            &serve.signer,
            Some(AuthSignerConfig::AwsKms { .. })
        ));
    }
    if let Some(secrets) = &cfg.secrets {
        n += usize::from(secrets.kek_file.is_some());
    }
    if let Some(overlay) = &cfg.overlay {
        // A surviving identity here is necessarily a PATH (an inline seed was refused).
        n += usize::from(overlay.identity.is_some());
    }
    if let Some(cluster) = &cfg.cluster {
        n += usize::from(cluster.join_token.is_some());
        n += usize::from(cluster.mesh.as_ref().is_some_and(|m| m.key_file.is_some()));
    }
    n
}

// =============================================================================
// 2. The spawn-environment contract (F11-B)
// =============================================================================

/// The explicitly-minimal env-var ALLOWLIST (exact names). Everything else an
/// instance's process does not need is dropped (no default full-environment
/// inheritance). `BOATRAMP_*` config-overlay vars and `LC_*` are allowed by prefix in
/// [`env_name_allowed`]; secret-bearing vars are then scrubbed on top
/// ([`is_secret_bearing_env_var`]), so a secret `BOATRAMP_*` never survives.
const ENV_ALLOWLIST_EXACT: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "USER",
    "LOGNAME",
    "LANG",
    "LANGUAGE",
    "TZ",
    "TERM",
    "SHELL",
    "PWD",
    "HOSTNAME",
    "RUST_LOG",
    "RUST_BACKTRACE",
    "RUST_LIB_BACKTRACE",
    "BOATRAMP_LOG_FORMAT",
];

/// The explicit secret-VALUE env vars (the `BOATRAMP_*` overlays that map to a
/// raw-secret config field, plus well-known cloud/DB credential vars). A var here is
/// ALWAYS scrubbed. The pattern catch in [`env_name_looks_secret`] covers the long
/// tail; this exact list makes the common cases deterministic (and drift-guarded).
const EXPLICIT_SECRET_ENV_VARS: &[&str] = &[
    // boatramp raw-secret overlays (the BOATRAMP_* names of the raw-secret config).
    "BOATRAMP_AUTH_ROOT_PRIVATE_KEY",
    "BOATRAMP_BOOTSTRAP_SECRET",
    "BOATRAMP_AZURE_ACCESS_KEY",
    "BOATRAMP_JOIN_TOKEN",
    "BOATRAMP_CLUSTER_JOIN_TOKEN",
    "BOATRAMP_SQL_TOKEN",
    "BOATRAMP_ALERTS_WEBHOOK_URL_SECRET",
    // well-known cloud / datastore credential vars that carry a live secret value.
    "VAULT_TOKEN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_STORAGE_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "PGPASSWORD",
    "MYSQL_PWD",
];

/// Whether `name` is permitted into a spawned instance's environment at all (the
/// explicitly-minimal allowlist — design F11-B). This is the POSITIVE gate;
/// [`is_secret_bearing_env_var`] then removes any secret var the allowlist let through
/// by prefix.
fn env_name_allowed(name: &str) -> bool {
    ENV_ALLOWLIST_EXACT.contains(&name)
        || name.starts_with("LC_")
        // Non-secret `BOATRAMP_*` config overlays pass so the instance resolves the
        // same config the root saw; secret `BOATRAMP_*` are scrubbed below.
        || name.starts_with("BOATRAMP_")
}

/// Whether `name` carries a live secret VALUE and must be scrubbed from every spawned
/// instance's environment (design F11-B — the no-courier rule). Reference-shaped vars
/// (`*_FILE` paths, `*_ENV` var names) carry a REFERENCE, not a value, so they are not
/// secrets and are kept (the holding instance resolves the file/pointed-to var itself).
pub fn is_secret_bearing_env_var(name: &str) -> bool {
    EXPLICIT_SECRET_ENV_VARS.contains(&name) || env_name_looks_secret(name)
}

/// Name-pattern catch-all for secret-bearing env vars (the long tail beyond
/// [`EXPLICIT_SECRET_ENV_VARS`]). Biased to OVER-scrub (fail-closed): a false positive
/// only drops a var an instance did not need; a false negative leaks a secret.
fn env_name_looks_secret(name: &str) -> bool {
    // Reference-shaped: `*_ENV` names another var, `*_FILE` names a path — neither is a
    // live value, so neither is scrubbed (e.g. BOATRAMP_SECRETS_KEK_FILE,
    // BOATRAMP_S3_INGRESS_SECRET_FILE, BOATRAMP_HANDLERS_SQL_TOKEN_ENV).
    if name.ends_with("_ENV") || name.ends_with("_FILE") {
        return false;
    }
    const SECRET_SUFFIXES: &[&str] = &[
        "_TOKEN",
        "_SECRET",
        "_PASSWORD",
        "_PASSWD",
        "_PWD",
        "_PRIVATE_KEY",
        "_ACCESS_KEY",
        "_PIN",
        "_KEK",
    ];
    if SECRET_SUFFIXES.iter().any(|s| name.ends_with(s)) {
        return true;
    }
    // A couple of well-known names that match no `_`-prefixed suffix rule.
    name == "PGPASSWORD"
}

/// Build the EXPLICITLY MINIMAL, secret-scrubbed environment for one spawned instance
/// (design §4.1 F11-B). Takes the parent (root) environment as `(name, value)` pairs,
/// keeps only allowlisted, non-secret vars, and returns the child's complete env — the
/// supervisor spawns with `Command::env_clear().envs(result)`, so nothing else is
/// inherited and no secret is ever couriered in.
///
/// `caps` is the instance's authority set. In Phase 1 NO instance legitimately needs a
/// secret env var (the file KEK is read from disk by the sealer behind its Landlock
/// grant; an `AwsKms` signer uses the ambient IAM / instance-role chain, not an env
/// token), so every secret-bearing var is scrubbed from every instance. Capability-aware
/// RETENTION of a specifically-needed secret env var is the Phase-2 env-token
/// follow-on; [`needed_secret_env_vars`] is the extension seam.
pub fn build_instance_env<I>(parent: I, caps: &[HostAuthority]) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let needed = needed_secret_env_vars(caps);
    parent
        .into_iter()
        .filter(|(name, _)| {
            if !env_name_allowed(name) {
                return false;
            }
            if is_secret_bearing_env_var(name) {
                // TODO(privsep WS-C / Phase-2): a file/fd token-source lets an instance
                // resolve its own credential; until then, no secret env var is couriered.
                return needed.contains(&name.as_str());
            }
            true
        })
        .collect()
}

/// The secret env vars an instance's capability set legitimately needs couriered.
/// **Phase 1: always empty** (see [`build_instance_env`]). The `caps` parameter + the
/// returned set are the Phase-2 / WS-C extension seam (when file/fd token-sources land,
/// e.g. a `token.signer` holding an env-token KMS signer could retain its token var).
///
/// TODO(privsep WS-C / Phase-2): populate per the capability set once env-token
/// integrations gain a file/fd source.
pub fn needed_secret_env_vars(_caps: &[HostAuthority]) -> std::collections::BTreeSet<&'static str> {
    std::collections::BTreeSet::new()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use boatramp_core::privsep::HostAuthority;

    use super::*;
    use crate::config::{
        AuthSignerConfig, ClusterConfig, OverlayServeConfig, SecretsConfig, ServeConfig,
        ServerConfig,
    };

    // ---- helpers ----

    fn serve_only() -> ServerConfig {
        ServerConfig {
            serve: Some(ServeConfig::default()),
            ..Default::default()
        }
    }

    // ---- secret-blind screen: ACCEPT reference-only configs ----

    #[test]
    fn reference_only_config_is_secret_blind() {
        let mut cfg = serve_only();
        // File-KEK secrets envelope (local) — a path reference, not a value.
        cfg.secrets = Some(SecretsConfig {
            envelope: "local".to_string(),
            kek_file: Some(PathBuf::from("/var/lib/boatramp/kek")),
            vault: None,
        });
        // A path-referenced overlay identity (not an inline seed).
        cfg.overlay = Some(OverlayServeConfig {
            identity: Some("/var/lib/boatramp/overlay/identity.key".to_string()),
            ..Default::default()
        });
        // AwsKms signer — a KMS-without-env-token signer (supported).
        if let Some(s) = cfg.serve.as_mut() {
            s.signer = Some(AuthSignerConfig::AwsKms {
                key_id: "arn:aws:kms:...:key/abc".to_string(),
                region: Some("us-east-1".to_string()),
            });
            s.s3_ingress_secret_file = Some(PathBuf::from("/var/lib/boatramp/s3ingress.root"));
        }
        let report = screen_secret_blind(&cfg).expect("reference-only config is secret-blind");
        assert!(report.opaque_reference_count >= 3, "{report:?}");
    }

    #[test]
    fn default_serve_config_is_secret_blind() {
        // A bare serve config names no secret at all.
        screen_secret_blind(&serve_only()).expect("a bare serve config is secret-blind");
    }

    // ---- secret-blind screen: REFUSE inline / env-valued §1.2 secrets ----

    #[test]
    fn refuses_inline_auth_root_private_key() {
        let mut cfg = serve_only();
        cfg.serve.as_mut().unwrap().auth_root_private_key = Some("ed25519:deadbeef".to_string());
        let err = screen_secret_blind(&cfg).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            SecretBlindViolation::RawSecretValue { field, .. } if field == "auth_root_private_key"
        )));
    }

    #[test]
    fn refuses_inline_bootstrap_secret() {
        let mut cfg = serve_only();
        cfg.serve.as_mut().unwrap().bootstrap_secret = Some("s3cr3t".to_string());
        let err = screen_secret_blind(&cfg).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            SecretBlindViolation::RawSecretValue { field, .. } if field == "bootstrap_secret"
        )));
    }

    #[test]
    fn refuses_inline_signer_private_key() {
        let mut cfg = serve_only();
        cfg.serve.as_mut().unwrap().signer = Some(AuthSignerConfig::Local {
            private_key: "ed25519:cafe".to_string(),
        });
        let err = screen_secret_blind(&cfg).unwrap_err();
        // The Local signer's raw `private_key` is caught by the raw-value walk.
        assert!(err.violations.iter().any(|v| matches!(
            v,
            SecretBlindViolation::RawSecretValue { field, .. } if field == "private_key"
        )));
    }

    #[test]
    fn refuses_nested_azure_access_key_in_blob_fallback() {
        let cfg = serve_only();
        // Reach the nested fallback cred without hand-constructing the whole struct:
        // round-trip through JSON asserts the WALK reaches nested secrets.
        let mut v = serde_json::to_value(&cfg).unwrap();
        v["serve"]["blob_fallback"] = serde_json::json!({ "azure_access_key": "RAWKEY==" });
        let cfg: ServerConfig = serde_json::from_value(v).unwrap();
        let err = screen_secret_blind(&cfg).unwrap_err();
        assert!(err.violations.iter().any(|v| matches!(
            v,
            SecretBlindViolation::RawSecretValue { json_path, field }
                if field == "azure_access_key" && json_path.contains("blob_fallback")
        )));
    }

    #[test]
    fn refuses_inline_overlay_seed() {
        let mut cfg = serve_only();
        cfg.overlay = Some(OverlayServeConfig {
            identity: Some("ed25519:00112233".to_string()),
            ..Default::default()
        });
        let err = screen_secret_blind(&cfg).unwrap_err();
        assert!(
            err.violations
                .iter()
                .any(|v| matches!(v, SecretBlindViolation::InlineOverlaySeed))
        );
    }

    #[test]
    fn accepts_path_overlay_identity() {
        let mut cfg = serve_only();
        cfg.overlay = Some(OverlayServeConfig {
            identity: Some("overlay/identity.key".to_string()),
            ..Default::default()
        });
        screen_secret_blind(&cfg).expect("a path identity is a reference, not a seed");
    }

    #[test]
    fn refuses_inline_and_env_cluster_join_token_but_accepts_path() {
        let base = |tok: &str| {
            let mut cfg = serve_only();
            cfg.cluster = Some(ClusterConfig {
                listen: "127.0.0.1:7000".parse().unwrap(),
                root_pubkeys: Vec::new(),
                seeds: Vec::new(),
                join_token: Some(tok.to_string()),
                store_dir: None,
                mesh: None,
            });
            cfg
        };
        assert!(
            screen_secret_blind(&base("rawtoken")).is_err(),
            "inline literal refused"
        );
        assert!(
            screen_secret_blind(&base("env:JOIN")).is_err(),
            "env: live ref refused"
        );
        screen_secret_blind(&base("path:/etc/boatramp/join.tok"))
            .expect("a path: reference is accepted");
    }

    #[test]
    fn refuses_env_token_signer_variants_but_accepts_awskms() {
        let mk = |signer: AuthSignerConfig| {
            let mut cfg = serve_only();
            cfg.serve.as_mut().unwrap().signer = Some(signer);
            cfg
        };
        assert!(
            screen_secret_blind(&mk(AuthSignerConfig::Vault {
                address: "https://vault:8200".to_string(),
                key: "k".to_string(),
                token_env: "VAULT_TOKEN".to_string(),
                alg: Default::default(),
            }))
            .is_err(),
            "Vault signer refused (env-token Phase-2 follow-on)"
        );
        assert!(
            screen_secret_blind(&mk(AuthSignerConfig::GcpKms {
                key_version: "projects/p/.../1".to_string(),
                access_token_env: "GCP_TOKEN".to_string(),
            }))
            .is_err(),
            "GcpKms signer refused"
        );
        screen_secret_blind(&mk(AuthSignerConfig::AwsKms {
            key_id: "arn:...".to_string(),
            region: None,
        }))
        .expect("AwsKms (ambient IAM) signer accepted");
    }

    #[test]
    fn refuses_vault_secrets_envelope_but_accepts_local_kek() {
        let mut cfg = serve_only();
        cfg.secrets = Some(SecretsConfig {
            envelope: "vault".to_string(),
            kek_file: None,
            vault: None,
        });
        assert!(screen_secret_blind(&cfg).is_err(), "Vault envelope refused");

        cfg.secrets = Some(SecretsConfig {
            envelope: "local".to_string(),
            kek_file: Some(PathBuf::from("/kek")),
            vault: None,
        });
        screen_secret_blind(&cfg).expect("local file-KEK accepted");
    }

    #[test]
    fn collects_every_violation_at_once() {
        let mut cfg = serve_only();
        cfg.serve.as_mut().unwrap().auth_root_private_key = Some("ed25519:aa".to_string());
        cfg.serve.as_mut().unwrap().bootstrap_secret = Some("bs".to_string());
        cfg.overlay = Some(OverlayServeConfig {
            identity: Some("ed25519:bb".to_string()),
            ..Default::default()
        });
        let err = screen_secret_blind(&cfg).unwrap_err();
        assert!(err.violations.len() >= 3, "all faults reported: {err}");
    }

    // ---- drift guard: no SECRET_FIELDS name escapes the screen ----

    #[test]
    fn every_secret_field_is_screened() {
        // The raw-value walk ∪ the two specially-handled names must cover the ENTIRE
        // SECRET_FIELDS redaction constant, so a newly-redacted field can never slip
        // past the root-blindness screen unnoticed.
        let specially_handled = ["join_token", "secret_access_key"];
        for name in crate::config::figment_resolve::secret_field_names() {
            let covered =
                RAW_SECRET_VALUE_FIELDS.contains(name) || specially_handled.contains(name);
            assert!(
                covered,
                "SECRET_FIELDS name {name:?} is neither in the raw-value walk nor specially \
                 handled — the root-blindness screen would miss it"
            );
        }
    }

    // ---- spawn-environment contract (F11-B) ----

    #[test]
    fn instance_env_is_minimal_and_scrubbed() {
        let parent = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("HOME".to_string(), "/root".to_string()),
            ("RUST_LOG".to_string(), "info".to_string()),
            (
                "BOATRAMP_SERVE_ADDR".to_string(),
                "0.0.0.0:8080".to_string(),
            ),
            // secrets — every one must be scrubbed:
            ("VAULT_TOKEN".to_string(), "s.LIVE".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "LIVE".to_string()),
            (
                "BOATRAMP_AUTH_ROOT_PRIVATE_KEY".to_string(),
                "ed25519:LIVE".to_string(),
            ),
            ("BOATRAMP_BOOTSTRAP_SECRET".to_string(), "LIVE".to_string()),
            ("BOATRAMP_JOIN_TOKEN".to_string(), "LIVE".to_string()),
            ("GITHUB_TOKEN".to_string(), "ghp_LIVE".to_string()),
            ("MY_APP_PASSWORD".to_string(), "LIVE".to_string()),
            // reference-shaped — kept (the holding instance resolves it itself):
            (
                "BOATRAMP_SECRETS_KEK_FILE".to_string(),
                "/var/lib/boatramp/kek".to_string(),
            ),
            (
                "BOATRAMP_S3_INGRESS_SECRET_FILE".to_string(),
                "/var/lib/s3.root".to_string(),
            ),
            // arbitrary non-allowlisted var — dropped (explicitly minimal):
            ("SOME_RANDOM_VAR".to_string(), "x".to_string()),
        ];
        let env = build_instance_env(parent, &[HostAuthority::ListenHttpParse]);

        // Allowlisted non-secrets kept.
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
        assert_eq!(env.get("HOME").map(String::as_str), Some("/root"));
        assert_eq!(env.get("RUST_LOG").map(String::as_str), Some("info"));
        assert_eq!(
            env.get("BOATRAMP_SERVE_ADDR").map(String::as_str),
            Some("0.0.0.0:8080")
        );
        // Reference-shaped vars kept.
        assert!(env.contains_key("BOATRAMP_SECRETS_KEK_FILE"));
        assert!(env.contains_key("BOATRAMP_S3_INGRESS_SECRET_FILE"));
        // Every secret scrubbed.
        for secret in [
            "VAULT_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "BOATRAMP_AUTH_ROOT_PRIVATE_KEY",
            "BOATRAMP_BOOTSTRAP_SECRET",
            "BOATRAMP_JOIN_TOKEN",
            "GITHUB_TOKEN",
            "MY_APP_PASSWORD",
        ] {
            assert!(!env.contains_key(secret), "{secret} must be scrubbed");
        }
        // Non-allowlisted var dropped.
        assert!(!env.contains_key("SOME_RANDOM_VAR"));
    }

    #[test]
    fn no_instance_env_courier_even_for_the_signer() {
        // Even a crown-jewel signer instance gets NO secret env var in Phase 1 (its
        // credential is file/KMS-resolved, not couriered — the no-courier invariant).
        let parent = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            ("VAULT_TOKEN".to_string(), "s.LIVE".to_string()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), "LIVE".to_string()),
        ];
        let env = build_instance_env(
            parent,
            &[
                HostAuthority::SecretsSealer,
                HostAuthority::TokenSigner,
                HostAuthority::ImageSigner,
            ],
        );
        assert!(!env.contains_key("VAULT_TOKEN"));
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
    }

    #[test]
    fn reference_shaped_env_vars_are_not_secrets() {
        assert!(!is_secret_bearing_env_var("BOATRAMP_SECRETS_KEK_FILE"));
        assert!(!is_secret_bearing_env_var(
            "BOATRAMP_S3_INGRESS_SECRET_FILE"
        ));
        assert!(!is_secret_bearing_env_var(
            "BOATRAMP_HANDLERS_SQL_TOKEN_ENV"
        ));
        assert!(is_secret_bearing_env_var("VAULT_TOKEN"));
        assert!(is_secret_bearing_env_var("BOATRAMP_AUTH_ROOT_PRIVATE_KEY"));
        assert!(is_secret_bearing_env_var("ANYTHING_SECRET"));
        assert!(is_secret_bearing_env_var("DB_PASSWORD"));
    }
}
