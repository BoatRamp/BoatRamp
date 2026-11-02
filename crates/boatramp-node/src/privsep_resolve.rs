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
    /// A REFERENCE-SHAPED secret field ([`REFERENCE_SHAPED_SECRET_FIELDS`] — e.g.
    /// `serve.s3_credential.secret_access_key`, `serve.alerts.webhook.url_secret`) holds a
    /// value the secret-blind root cannot carry: either a RAW inline secret, or an `env:`
    /// live reference the root would have to courier (Phase-1 no-courier). Only a sealed
    /// `boatramp:<name>` or a `path:` reference is permitted — the holding instance
    /// resolves it itself (design F1/F11-A). These fields are reference-by-design, so a
    /// present value is NOT automatically a fault (unlike [`Self::RawSecretValue`]); only a
    /// raw/`env:` value is.
    UncourierableSecretReference {
        /// The dotted config path to the offending field.
        json_path: String,
        /// The reference-shaped secret field name (`secret_access_key` / `url_secret`).
        field: String,
        /// The offending form — scheme/shape only, never the value.
        form: &'static str,
    },
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
            Self::UncourierableSecretReference {
                json_path,
                field,
                form,
            } => write!(
                f,
                "config field `{json_path}` ({field}) is {form} — under [privsep] a \
                 reference-shaped secret must be a sealed `boatramp:<name>` or a `path:` \
                 reference the holding instance resolves itself, never a raw inline value nor \
                 an `env:` live reference (the root must neither carry nor courier it)"
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

/// Config field names that ALWAYS hold a raw secret value (never a reference) — a
/// present, non-empty one anywhere in the resolved config is a refusal.
///
/// This is the raw-value subset of the `SECRET_FIELDS` redaction constant (`config.rs`)
/// MINUS the reference-shaped names handled specially:
/// - [`REFERENCE_SHAPED_SECRET_FIELDS`] (`secret_access_key`, `url_secret`) — permitted
///   only as a `boatramp:`/`path:` reference; [`walk_raw_secret_values`] flags a raw or
///   `env:` value for these (a plain `boatramp:`/`path:` value is fine);
/// - `join_token` ([`check_cluster_join_token`] — `env:`/`path:`/inline, allows only `path:`).
///
/// A drift guard test asserts this set ∪ [`REFERENCE_SHAPED_SECRET_FIELDS`] ∪ {`join_token`}
/// ⊇ `SECRET_FIELDS`, so a newly-redacted field can never silently escape the screen.
const RAW_SECRET_VALUE_FIELDS: &[&str] = &[
    "auth_root_private_key",
    "bootstrap_secret",
    "azure_access_key",
    "private_key",
];

/// Reference-shaped secret fields: reference-BY-DESIGN, so a present value is not itself a
/// fault — but under `[privsep]` only a sealed `boatramp:<name>` or a `path:` reference the
/// holding instance resolves itself is permitted. A raw inline value, or an `env:` live
/// reference the root cannot courier (Phase-1 no-courier), is a refusal
/// ([`SecretBlindViolation::UncourierableSecretReference`]). These are the Security-review
/// Finding 2 gaps: `secret_access_key` was declared "specially handled" but checked by
/// nothing, and `url_secret` was absent from the screen entirely.
const REFERENCE_SHAPED_SECRET_FIELDS: &[&str] = &["secret_access_key", "url_secret", "key_ref"];

/// Config field names whose VALUE is the NAME of an env var carrying a live secret (a
/// bring-your-own DB connection URL/password, a KMS/admin/signer token, a PKCS#11 PIN).
/// The root carries the NAME opaquely, but the pointed-to env var's VALUE is a live
/// credential that must be SCRUBBED from every spawned instance's environment in Phase 1
/// (no courier — design §4.1(c)/F11-B; Security-review Finding 1).
/// [`declared_secret_env_var_names`] collects these VALUES from the resolved config so the
/// scrub is CONFIG-DRIVEN, not name-pattern-guessed — the robust fix for the F11-A footgun
/// that a suffix denylist is inherently incomplete (a `..._DB_URL` matches no secret suffix
/// yet carries a password). The booleans `*_resolve_from_env` / `figment_env` /
/// `serve_from_env` and the PUBLIC `jwks_env` are deliberately excluded — they name no
/// secret value.
const SECRET_ENV_NAME_FIELDS: &[&str] = &[
    "url_env",
    "read_url_env",
    "migration_url_env",
    "password_env",
    "token_env",
    "admin_token_env",
    "access_token_env",
    "pin_env",
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
                if RAW_SECRET_VALUE_FIELDS.contains(&k.as_str())
                    && matches!(v, serde_json::Value::String(s) if !s.is_empty())
                {
                    out.push(SecretBlindViolation::RawSecretValue {
                        json_path: path,
                        field: k.clone(),
                    });
                } else if REFERENCE_SHAPED_SECRET_FIELDS.contains(&k.as_str())
                    && let serde_json::Value::String(s) = v
                    && !s.is_empty()
                    && !is_privsep_safe_reference(s)
                {
                    // Reference-by-design, but a raw inline value — or an `env:` reference
                    // the root cannot courier in Phase 1 — defeats the root's blindness.
                    out.push(SecretBlindViolation::UncourierableSecretReference {
                        json_path: path,
                        field: k.clone(),
                        form: if s.starts_with("env:") {
                            "an `env:` live reference"
                        } else {
                            "a raw inline value"
                        },
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

/// Whether a reference-shaped secret value is one the secret-blind root can safely carry:
/// a sealed `boatramp:<name>` reference (resolved from the holding instance's sealed store)
/// or a `path:<file>` reference (read behind the instance's Landlock grant). A raw inline
/// value, or an `env:` reference the root cannot courier in Phase 1, is NOT safe.
fn is_privsep_safe_reference(value: &str) -> bool {
    value.starts_with("boatramp:") || value.starts_with("path:")
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
        // `Sealed` carries a `boatramp:`/`path:` REFERENCE (screened by the reference-shaped
        // walk via `key_ref`), not an env token — supported under `[privsep]`. `Local` carries a
        // raw `private_key` caught by the raw-value walk.
        AuthSignerConfig::Local { .. }
        | AuthSignerConfig::AwsKms { .. }
        | AuthSignerConfig::Sealed { .. } => None,
    }
}

/// The sealed signer key reference, if `[serve.signer]` is the [`AuthSignerConfig::Sealed`] variant
/// (a `boatramp:<name>` or `path:<file>` reference the `token.signer` instance resolves via a
/// `secrets.sealer` over the feature-link). `None` for any other signer (in-process / KMS / absent).
/// The root derives the sealed-signer composition-closure fact + the per-link unseal allowlist from
/// this (the wasm-clean types layer does not see `AuthSignerConfig`).
#[must_use]
pub fn sealed_signer_key_ref(cfg: &ServerConfig) -> Option<&str> {
    match cfg.serve.as_ref()?.signer.as_ref()? {
        AuthSignerConfig::Sealed { key_ref } => Some(key_ref.as_str()),
        _ => None,
    }
}

/// The on-disk FILE path a `[serve.signer] = Sealed { key_ref: "path:<file>" }` names — the
/// KEK-sealed signer-key blob the SEALER reads + unwraps. `None` for a `boatramp:<name>`
/// (sealed-store) source or any non-sealed signer. Used to grant that file READ-ONLY to the
/// `secrets.sealer` holder (never the `token.signer` holder — the signer never has it on disk).
#[must_use]
pub fn sealed_signer_key_file(cfg: &ServerConfig) -> Option<PathBuf> {
    sealed_signer_key_ref(cfg)
        .and_then(|r| r.strip_prefix("path:"))
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
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
            // An AwsKms signer carries a key-ARN reference; a Sealed signer carries a
            // `boatramp:`/`path:` sealed-key reference — both are opaque refs the root carries,
            // never dereferences.
            Some(AuthSignerConfig::AwsKms { .. } | AuthSignerConfig::Sealed { .. })
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

/// Collect the env-var NAMES the resolved config declares as secret-bearing references
/// (the [`SECRET_ENV_NAME_FIELDS`] field VALUES anywhere in the tree). This is the
/// config-driven secret-env set [`build_instance_env`] scrubs from every spawned instance
/// — the robust, non-guessed catch for Security-review Finding 1 (a BYO-DB connection URL
/// in a var like `BOATRAMP_MAIN_DB_URL` matches no name suffix yet is a live credential).
/// Walking the serialized config by field name is the SAME discipline as
/// [`walk_raw_secret_values`]: it reaches nested handler/database entries without
/// hand-reaching into every struct, and it is config-DECLARED rather than name-pattern
/// guessed. (On a serialization failure it returns empty — but [`screen_secret_blind`]
/// runs first in `plan_root` and fail-closes on that same failure, so the config is
/// serializable by the time this is reached.)
#[must_use]
pub fn declared_secret_env_var_names(cfg: &ServerConfig) -> std::collections::BTreeSet<String> {
    let mut out = std::collections::BTreeSet::new();
    if let Ok(value) = serde_json::to_value(cfg) {
        collect_secret_env_names(&value, &mut out);
    }
    out
}

/// Recurse a serialized config value, inserting the VALUE of every [`SECRET_ENV_NAME_FIELDS`]
/// key that is a non-empty string (the declared secret-env var name).
fn collect_secret_env_names(
    value: &serde_json::Value,
    out: &mut std::collections::BTreeSet<String>,
) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                if SECRET_ENV_NAME_FIELDS.contains(&k.as_str())
                    && let serde_json::Value::String(s) = v
                    && !s.is_empty()
                {
                    out.insert(s.clone());
                } else {
                    collect_secret_env_names(v, out);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                collect_secret_env_names(item, out);
            }
        }
        _ => {}
    }
}

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
        // Defense-in-depth beyond the config-driven [`declared_secret_env_var_names`] set
        // (Finding 1): these name-tails are unambiguously credential-bearing. `_URL` is
        // deliberately NOT here — a public base URL an instance legitimately needs ends
        // `_URL` too; a SECRET connection URL is caught structurally by its `url_env`
        // declaration instead.
        "_SEED",
        "_DSN",
        "_PASSPHRASE",
        "_CREDENTIAL",
        "_CREDENTIALS",
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
///
/// `declared_secret_env` is the config-driven secret-env set from
/// [`declared_secret_env_var_names`] — env-var names the config itself declared as
/// secret-bearing references (`url_env` / `password_env` / `token_env` / …). A var in that
/// set is scrubbed even when its NAME matches no secret suffix (Security-review Finding 1:
/// a BYO-DB `BOATRAMP_MAIN_DB_URL` is a live credential a name-only denylist misses).
pub fn build_instance_env<I>(
    parent: I,
    caps: &[HostAuthority],
    declared_secret_env: &std::collections::BTreeSet<String>,
) -> BTreeMap<String, String>
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
            // Secret-bearing = the name pattern/explicit list says so, OR the resolved
            // config DECLARED this var as a secret-env reference. The config-declared set
            // is the robust, non-guessed catch (design F11-A; Finding 1).
            if is_secret_bearing_env_var(name) || declared_secret_env.contains(name.as_str()) {
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

// =============================================================================
// 3. Per-instance sandbox-derivation inputs (WS-C — honoring BOTH hard contracts)
// =============================================================================

use std::path::{Path, PathBuf};

use boatramp_server::sandbox::{
    KeyInputPaths, SandboxDerivationInputs, backend_authority_state_dirs,
    instance_backend_state_grants,
};

/// The node data directory (`serve.data_dir`, default `./data`) — the single source of truth the
/// sandbox-input builder + the composition grant-disjointness check both key off (matching the
/// monolith serve path, `boatramp::serve`). NOT yet normalized — the caller normalizes via
/// [`SandboxDerivationInputs::into_normalized`] / `lexically_normalize`.
#[must_use]
pub fn resolve_data_dir(cfg: &ServerConfig) -> PathBuf {
    cfg.serve
        .as_ref()
        .and_then(|s| s.data_dir.clone())
        .unwrap_or_else(|| PathBuf::from("./data"))
}

/// Resolve the on-disk PATHS of every §1.2 crown-jewel key input from the resolved config — the
/// PATH references only (never a dereferenced value; the config is already secret-blind by
/// [`screen_secret_blind`], so each is a path/KMS ref, not a secret). EVERY instance is given this
/// FULL map (not just its own keys): [`boatramp_server::sandbox::derive_profile`] grants ONLY the
/// instance's own held key paths, and uses the NON-held entries to run its fail-closed leak check
/// (a non-holder's grant must not transitively expose a sibling's key path). Passing a sibling's
/// key PATH is not a secret leak — the path is a string, the instance holds no grant to the file.
///
/// Phase-1 scope: `kek_file` (default `<data_dir>/secrets/kek`), the overlay seed
/// (`overlay.identity`, a path once the inline-seed screen has passed), `s3_ingress_secret_file`,
/// and the cluster mesh `key_file` (default `<data_dir>/mesh/identity.key`) are the path-shaped
/// inputs. `token.signer` / `image.signer` keys are `None` in Phase 1 — a privsep signer uses an
/// `AwsKms` ambient signer (no key file) or the sealed-credential source (owner decision; the
/// sealer-unseals-to-signer path is the documented follow-on), so no plaintext key file exists to
/// grant here.
#[must_use]
pub fn resolve_key_input_paths(cfg: &ServerConfig, data_dir: &Path) -> KeyInputPaths {
    let kek_file = cfg
        .secrets
        .as_ref()
        .and_then(|s| s.kek_file.clone())
        .or_else(|| Some(data_dir.join("secrets/kek")));
    let overlay_seed = cfg
        .overlay
        .as_ref()
        .and_then(|o| o.identity.clone())
        .map(PathBuf::from);
    let s3_ingress_secret = cfg
        .serve
        .as_ref()
        .and_then(|s| s.s3_ingress_secret_file.clone());
    let cluster_root_key = cfg.cluster.as_ref().map(|c| {
        c.mesh
            .as_ref()
            .and_then(|m| m.key_file.clone())
            .unwrap_or_else(|| data_dir.join("mesh/identity.key"))
    });
    KeyInputPaths {
        kek_file,
        // A `[serve.signer] = Sealed { key_ref: "path:<file>" }` names a KEK-sealed signer-key
        // blob the SEALER reads + unwraps; grant that file READ-ONLY to the `secrets.sealer`
        // holder (never the signer, which gets the plaintext over the link). `boatramp:<name>`
        // (sealed-store) + non-sealed signers resolve without a dedicated file ⇒ `None`.
        sealed_signer_key_file: sealed_signer_key_file(cfg),
        // AwsKms-ambient / sealed-cred in Phase 1 (no PLAINTEXT signer key file to grant: a Sealed
        // signer's key is never on the signer's disk — it arrives over the link). Follow-on.
        token_signer_key: None,
        image_signer_key: None,
        overlay_seed,
        s3_ingress_secret,
        cluster_root_key,
    }
}

/// Build the fully-formed, NORMALIZED [`SandboxDerivationInputs`] for one instance holding `caps`
/// — honoring BOTH WS-C hard contracts, so the caller can hand the result straight to
/// [`boatramp_server::sandbox::derive_profile`]:
///
/// - **Contract #1 (canonicalize):** every path — `data_dir`, the config-dir read grant, the
///   instance's own backend-state read-write grants, the system temp dirs, and every key path —
///   is made absolute + lexically normalized (and `fs::canonicalize`d when it already exists) by
///   [`SandboxDerivationInputs::into_normalized`], so `derive_profile`'s lexical FS checks match
///   the fd-based Landlock install. `cwd` is the process working directory a relative grant
///   resolves against (the same CWD the install's `PathFd` uses); the instance's OWN state dirs are
///   pre-created first so a holder's grant canonicalizes through symlinks.
/// - **Contract #2 (populate `authority_state_dirs`):** the FULL per-backend-authority state map
///   ([`backend_authority_state_dirs`]) is attached, so `derive_profile`'s cross-authority leak
///   check is not inert; this instance's `base_read_write` is ONLY its OWN backend authorities'
///   state subtrees (never `data_dir` itself — refused). The composition-layer disjointness of
///   those grants is enforced separately in the root
///   ([`boatramp_server::sandbox::check_grant_disjointness`]).
///
/// `exec_self` is the per-tenant-router self-exec pin: for the `exec.compute` holder (the compute
/// -plane spawner / per-tenant router) ONLY, the caller passes this instance's own executable so it
/// lands read+EXECUTE in the Landlock view and the router can re-exec the boatramp binary to fork
/// per-tenant children — mirroring the root's execute-pin ([`boatramp_server::sandbox::root_supervisor_policy`]).
/// The caller resolves it via `std::env::current_exe()` and fails closed on a resolve error exactly
/// as the root does; it passes `None` for every non-`exec.compute` instance, and the gate below
/// also keys on the capability, so a non-router's execute grant is never widened.
#[must_use]
pub fn build_instance_sandbox_inputs(
    cfg: &ServerConfig,
    caps: &[HostAuthority],
    config_path: &Path,
    cwd: &Path,
    exec_self: Option<&Path>,
) -> SandboxDerivationInputs {
    let data_dir = resolve_data_dir(cfg);
    // Grant the config FILE read-only (a single-file rule), NOT its parent dir: a config dir that
    // CONTAINS data_dir (the common `/var/lib/boatramp/{boatramp.toml,data/}` layout) would be an
    // ancestor of data_dir and refused as an OverbroadStateGrant. The instance only re-reads this
    // one file at boot; its key/state files are granted on their own paths.
    let config_read = Some(config_path)
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf);
    let mut inputs = SandboxDerivationInputs::for_instance(data_dir.clone(), config_read);

    let held: std::collections::BTreeSet<HostAuthority> = caps.iter().copied().collect();
    // This instance's OWN backend state subtrees (its narrow read-write grant). NEVER data_dir
    // itself — `derive_profile` refuses that (OverbroadStateGrant).
    inputs.base_read_write = instance_backend_state_grants(&held, &data_dir);
    // The FULL per-backend-authority state map, so the cross-authority leak check is live.
    inputs.authority_state_dirs = backend_authority_state_dirs(&data_dir);
    // The FULL crown-jewel key-path set (holder-only granting + non-holder leak-checking happen in
    // `derive_profile`).
    inputs.keys = resolve_key_input_paths(cfg, &data_dir);

    // WS-C exec.compute self-exec pin. A per-tenant router (the `exec.compute` holder) forks its
    // per-tenant children by re-execing THIS boatramp binary, so — exactly like the privsep root
    // ([`boatramp_server::sandbox::root_supervisor_policy`]) — it needs its OWN executable in its
    // Landlock read view, which is installed via `landlock::AccessFs::from_read` and so ALSO carries
    // EXECUTE. Granted ONLY to an `exec.compute` holder (the same capability the seccomp `EXEC_SPAWN`
    // allow keys off); every other instance keeps `execve` seccomp-killed AND Landlock-blocked, so
    // the default is never widened. `exec_self` is the raw `std::env::current_exe()` the caller
    // resolved + fail-closed just as the root does — it is normalized here by `into_normalized`, the
    // SAME transform the root applies to its own binary via `normalize_for_landlock`.
    if held.contains(&HostAuthority::ExecCompute)
        && let Some(exe) = exec_self
    {
        inputs.base_read_only.push(exe.to_path_buf());
    }

    inputs.into_normalized(cwd)
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
    fn sealed_signer_accepts_boatramp_and_path_refs_refuses_raw_and_env() {
        let mk = |key_ref: &str| {
            let mut cfg = serve_only();
            cfg.serve.as_mut().unwrap().signer = Some(AuthSignerConfig::Sealed {
                key_ref: key_ref.to_string(),
            });
            cfg
        };
        // Accepted: a sealed-store ref + a KEK-sealed key-file path (the signer resolves these NOT
        // inline — via the sealer over the link).
        screen_secret_blind(&mk("boatramp:auth-root-signer"))
            .expect("a boatramp: sealed signer ref is accepted");
        screen_secret_blind(&mk("path:/var/lib/boatramp/secrets/signer.sealed"))
            .expect("a path: sealed signer-key file is accepted");
        // Refused (the root is secret-blind + the no-courier rule): a raw inline spec, or an `env:`
        // live reference the root would have to courier. Caught via the reference-shaped `key_ref`.
        let raw = screen_secret_blind(&mk("es256:deadbeef")).unwrap_err();
        assert!(
            raw.violations.iter().any(|v| matches!(
                v,
                SecretBlindViolation::UncourierableSecretReference { field, .. }
                    if field == "key_ref"
            )),
            "a raw inline sealed-signer key_ref is refused: {raw}"
        );
        assert!(
            screen_secret_blind(&mk("env:AUTH_ROOT_KEY")).is_err(),
            "an env: sealed-signer key_ref is uncourierable under [privsep]"
        );
    }

    #[test]
    fn sealed_signer_key_ref_and_file_helpers() {
        let mut cfg = serve_only();
        assert_eq!(sealed_signer_key_ref(&cfg), None);
        assert_eq!(sealed_signer_key_file(&cfg), None);

        cfg.serve.as_mut().unwrap().signer = Some(AuthSignerConfig::Sealed {
            key_ref: "path:/keys/signer.sealed".to_string(),
        });
        assert_eq!(
            sealed_signer_key_ref(&cfg),
            Some("path:/keys/signer.sealed")
        );
        assert_eq!(
            sealed_signer_key_file(&cfg),
            Some(PathBuf::from("/keys/signer.sealed"))
        );

        cfg.serve.as_mut().unwrap().signer = Some(AuthSignerConfig::Sealed {
            key_ref: "boatramp:auth-root".to_string(),
        });
        assert_eq!(sealed_signer_key_ref(&cfg), Some("boatramp:auth-root"));
        // A boatramp: (sealed-store) ref has no dedicated on-disk file to grant.
        assert_eq!(sealed_signer_key_file(&cfg), None);

        // A non-sealed signer yields neither.
        cfg.serve.as_mut().unwrap().signer = Some(AuthSignerConfig::AwsKms {
            key_id: "arn:...".to_string(),
            region: None,
        });
        assert_eq!(sealed_signer_key_ref(&cfg), None);
        assert_eq!(sealed_signer_key_file(&cfg), None);
    }

    #[test]
    fn sealed_signer_path_file_is_granted_to_the_sealer_not_the_signer() {
        use boatramp_server::sandbox;
        // A `path:` sealed signer-key file must be in the SEALER's FS view (read-only), and MUST
        // NOT leak into a non-sealer instance (e.g. the token.signer holder). Place it outside the
        // backend state subtrees (a dedicated secrets dir) so the leak check is clean for holders.
        let mut cfg = serve_only();
        cfg.serve.as_mut().unwrap().data_dir = Some(PathBuf::from("/srv/node"));
        cfg.serve.as_mut().unwrap().signer = Some(AuthSignerConfig::Sealed {
            key_ref: "path:/srv/node/secrets/signer.sealed".to_string(),
        });
        // Also give the sealer a `[secrets]` KEK (it holds secrets.sealer).
        cfg.secrets = Some(crate::config::SecretsConfig {
            envelope: "local".to_string(),
            kek_file: Some(PathBuf::from("/srv/node/secrets/kek")),
            vault: None,
        });

        // The SEALER (holds secrets.sealer) is granted the sealed signer-key file read-only.
        let sealer_caps = [HostAuthority::SecretsSealer];
        let sealer_inputs = build_instance_sandbox_inputs(
            &cfg,
            &sealer_caps,
            Path::new("/etc/boatramp/boatramp.cfg"),
            Path::new("/cwd"),
            None,
        );
        assert_eq!(
            sealer_inputs.keys.sealed_signer_key_file,
            Some(PathBuf::from("/srv/node/secrets/signer.sealed"))
        );
        let sealer_held: std::collections::BTreeSet<HostAuthority> =
            sealer_caps.iter().copied().collect();
        let sealer_profile = sandbox::derive_profile(
            &sealer_held,
            boatramp_core::privsep::SandboxPosture::Derived,
            &sealer_inputs,
        )
        .expect("sealer derives a clean profile");
        assert!(
            sealer_profile
                .policy
                .read_only_paths
                .contains(&PathBuf::from("/srv/node/secrets/signer.sealed")),
            "the sealer is granted the sealed signer-key file read-only"
        );

        // The SIGNER (holds token.signer, NOT secrets.sealer) must NOT be granted it — and since it
        // has no FS grant that is an ancestor of the file, derivation is clean (the file is simply
        // absent from its view). A HYPOTHETICAL over-broad grant WOULD be refused by the key-leak
        // check (proven by the sandbox crate's CrownJewelKeyLeak tests).
        let signer_caps = [HostAuthority::TokenSigner];
        let signer_inputs = build_instance_sandbox_inputs(
            &cfg,
            &signer_caps,
            Path::new("/etc/boatramp/boatramp.cfg"),
            Path::new("/cwd"),
            None,
        );
        let signer_held: std::collections::BTreeSet<HostAuthority> =
            signer_caps.iter().copied().collect();
        let signer_profile = sandbox::derive_profile(
            &signer_held,
            boatramp_core::privsep::SandboxPosture::Derived,
            &signer_inputs,
        )
        .expect("signer derives a clean profile (the sealed key file is not in its view)");
        assert!(
            !signer_profile
                .policy
                .read_only_paths
                .iter()
                .chain(signer_profile.policy.read_write_paths.iter())
                .any(|p| p == &PathBuf::from("/srv/node/secrets/signer.sealed")),
            "the signer never has the sealed signer-key file on disk"
        );
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
        // The raw-value walk ∪ the reference-shaped set ∪ the typed join_token check must
        // cover the ENTIRE SECRET_FIELDS redaction constant, so a newly-redacted field can
        // never slip past the root-blindness screen unnoticed. (Finding 2: `secret_access_key`
        // is now ACTUALLY covered — by [`REFERENCE_SHAPED_SECRET_FIELDS`] with a behavioral
        // test below — not merely declared "specially handled" by a comment.)
        for name in crate::config::figment_resolve::secret_field_names() {
            let covered = RAW_SECRET_VALUE_FIELDS.contains(name)
                || REFERENCE_SHAPED_SECRET_FIELDS.contains(name)
                || *name == "join_token";
            assert!(
                covered,
                "SECRET_FIELDS name {name:?} is neither in the raw-value walk, the \
                 reference-shaped set, nor the typed join_token check — the root-blindness \
                 screen would miss it"
            );
        }
    }

    // ---- Finding 2: reference-shaped secret fields (raw / env: refused) ----

    #[test]
    fn refuses_raw_or_env_secret_access_key_but_accepts_sealed_reference() {
        // `serve.s3_credential.secret_access_key` is a `boatramp:`/`env:` reference by
        // design; a raw inline value (or an `env:` reference the root cannot courier) must
        // be refused. url_secret shares this exact walk branch + const set.
        let mk = |val: &str| {
            let cfg = serve_only();
            let mut v = serde_json::to_value(&cfg).unwrap();
            v["serve"]["s3_credential"] =
                serde_json::json!({ "access_key_id": "AKIAEXAMPLE", "secret_access_key": val });
            serde_json::from_value::<ServerConfig>(v).expect("s3_credential round-trips")
        };
        let raw_err =
            screen_secret_blind(&mk("RAWSECRETKEY40CHARSxxxxxxxxxxxxxxxxxxxxx")).unwrap_err();
        assert!(
            raw_err.violations.iter().any(|v| matches!(
                v,
                SecretBlindViolation::UncourierableSecretReference { field, .. }
                    if field == "secret_access_key"
            )),
            "a raw secret_access_key is refused: {raw_err}"
        );
        assert!(
            screen_secret_blind(&mk("env:AWS_SECRET")).is_err(),
            "an env: secret_access_key is uncourierable under [privsep]"
        );
        screen_secret_blind(&mk("boatramp:s3cred"))
            .expect("a sealed boatramp: reference is accepted");
        screen_secret_blind(&mk("path:/var/lib/boatramp/s3.key"))
            .expect("a path: reference is accepted");
    }

    #[test]
    fn url_secret_is_a_reference_shaped_screened_field() {
        // url_secret is wired into the SAME reference-shaped mechanism (const set + walk
        // branch, proven by the secret_access_key behavioral test) and into SECRET_FIELDS
        // (so the drift guard enforces its coverage). Assert the wiring directly.
        assert!(REFERENCE_SHAPED_SECRET_FIELDS.contains(&"url_secret"));
        assert!(
            crate::config::figment_resolve::secret_field_names().contains(&"url_secret"),
            "url_secret must be in SECRET_FIELDS so it is redacted AND drift-guarded"
        );
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
        let env = build_instance_env(
            parent,
            &[HostAuthority::ListenHttpParse],
            &std::collections::BTreeSet::new(),
        );

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
            &std::collections::BTreeSet::new(),
        );
        assert!(!env.contains_key("VAULT_TOKEN"));
        assert!(!env.contains_key("AWS_SECRET_ACCESS_KEY"));
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
    }

    #[test]
    fn config_declared_secret_env_var_is_scrubbed_even_without_a_secret_suffix() {
        // Finding 1: a BYO-DB connection URL lives in BOATRAMP_MAIN_DB_URL (ends `_URL`,
        // matches no secret suffix) — it would leak to EVERY instance under a name-only
        // denylist. The config declares it via `url_env`, so the config-driven set scrubs it.
        let mut declared = std::collections::BTreeSet::new();
        declared.insert("BOATRAMP_MAIN_DB_URL".to_string());
        let parent = vec![
            ("PATH".to_string(), "/usr/bin".to_string()),
            (
                "BOATRAMP_MAIN_DB_URL".to_string(),
                "postgres://u:PASSWORD@h/db".to_string(),
            ),
        ];
        let env = build_instance_env(parent, &[HostAuthority::ListenHttpParse], &declared);
        assert!(
            !env.contains_key("BOATRAMP_MAIN_DB_URL"),
            "a config-declared secret env var must be scrubbed from every instance"
        );
        assert_eq!(env.get("PATH").map(String::as_str), Some("/usr/bin"));
    }

    #[test]
    fn declared_secret_env_var_names_collects_config_url_env() {
        // The config-driven collector walks nested handler/database entries for the
        // SECRET_ENV_NAME_FIELDS and returns the declared env-var NAMES.
        let cfg = serve_only();
        let mut v = serde_json::to_value(&cfg).unwrap();
        v["handlers"] = serde_json::json!({
            "databases": { "main": { "url_env": "BOATRAMP_MAIN_DB_URL", "password_env": "BOATRAMP_MAIN_DB_PW" } }
        });
        // Deserialize-tolerant: if the handlers shape round-trips, assert collection; the
        // collector operates on the serialized tree regardless.
        let names = collect_names_from_value(&v);
        assert!(names.contains("BOATRAMP_MAIN_DB_URL"));
        assert!(names.contains("BOATRAMP_MAIN_DB_PW"));
    }

    fn collect_names_from_value(v: &serde_json::Value) -> std::collections::BTreeSet<String> {
        let mut out = std::collections::BTreeSet::new();
        super::collect_secret_env_names(v, &mut out);
        out
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

    // ---- WS-C: per-instance sandbox-derivation inputs (both hard contracts) ----

    #[test]
    fn resolve_key_input_paths_resolves_configured_paths_and_defaults() {
        let data_dir = PathBuf::from("/data");
        // Bare config: kek + cluster-root fall back to their data_dir defaults; no overlay/s3.
        let bare = resolve_key_input_paths(&serve_only(), &data_dir);
        assert_eq!(bare.kek_file, Some(PathBuf::from("/data/secrets/kek")));
        assert_eq!(bare.overlay_seed, None);
        assert_eq!(bare.s3_ingress_secret, None);
        // A cluster block is absent in serve_only ⇒ no cluster root key.
        assert_eq!(bare.cluster_root_key, None);
        // Phase-1: no plaintext signer key files (AwsKms ambient / sealed-cred follow-on).
        assert_eq!(bare.token_signer_key, None);
        assert_eq!(bare.image_signer_key, None);

        // Explicit paths resolve verbatim.
        let mut cfg = serve_only();
        cfg.secrets = Some(SecretsConfig {
            envelope: "local".to_string(),
            kek_file: Some(PathBuf::from("/keys/kek")),
            vault: None,
        });
        cfg.overlay = Some(OverlayServeConfig {
            identity: Some("/keys/overlay.seed".to_string()),
            ..Default::default()
        });
        cfg.serve.as_mut().unwrap().s3_ingress_secret_file = Some(PathBuf::from("/keys/s3.root"));
        cfg.cluster = Some(ClusterConfig {
            listen: "127.0.0.1:7000".parse().unwrap(),
            root_pubkeys: Vec::new(),
            seeds: Vec::new(),
            join_token: Some("path:/etc/join.tok".to_string()),
            store_dir: None,
            mesh: None,
        });
        let keys = resolve_key_input_paths(&cfg, &data_dir);
        assert_eq!(keys.kek_file, Some(PathBuf::from("/keys/kek")));
        assert_eq!(keys.overlay_seed, Some(PathBuf::from("/keys/overlay.seed")));
        assert_eq!(keys.s3_ingress_secret, Some(PathBuf::from("/keys/s3.root")));
        // No mesh.key_file ⇒ cluster root defaults under data_dir.
        assert_eq!(
            keys.cluster_root_key,
            Some(PathBuf::from("/data/mesh/identity.key"))
        );
    }

    #[test]
    fn build_instance_sandbox_inputs_honors_both_contracts_and_derives() {
        use boatramp_core::privsep::SandboxPosture;
        use boatramp_server::sandbox;

        // A storage instance (the four backends) on an explicit absolute data_dir.
        let mut cfg = serve_only();
        cfg.serve.as_mut().unwrap().data_dir = Some(PathBuf::from("/srv/node"));
        let caps = [
            HostAuthority::BackendKv,
            HostAuthority::BackendSql,
            HostAuthority::BackendBlob,
            HostAuthority::BackendMessaging,
        ];
        let inputs = build_instance_sandbox_inputs(
            &cfg,
            &caps,
            Path::new("/etc/boatramp/boatramp.cfg"),
            Path::new("/cwd"),
            None,
        );

        // Contract #2: the FULL backend state map is populated (never inert).
        for a in [
            HostAuthority::BackendKv,
            HostAuthority::BackendSql,
            HostAuthority::BackendBlob,
            HostAuthority::BackendMessaging,
        ] {
            assert!(inputs.authority_state_dirs.contains_key(&a), "{}", a.tag());
        }
        // This instance's own grants are its backend subtrees — NOT data_dir itself.
        assert!(
            inputs
                .base_read_write
                .contains(&PathBuf::from("/srv/node/kv"))
        );
        assert!(!inputs.base_read_write.contains(&PathBuf::from("/srv/node")));
        // Contract #1: data_dir is absolute + normalized; the config FILE (not its parent dir) is
        // the read grant — a config dir that contains data_dir would be refused as overbroad.
        assert_eq!(inputs.data_dir, PathBuf::from("/srv/node"));
        assert!(
            inputs
                .base_read_only
                .contains(&PathBuf::from("/etc/boatramp/boatramp.cfg"))
        );
        assert!(
            !inputs
                .base_read_only
                .contains(&PathBuf::from("/etc/boatramp")),
            "the config DIR must not be granted (only the file)"
        );

        // The assembled inputs derive cleanly for the holder (a storage instance legitimately
        // reaches its own backend state; it holds no crown-jewel key, so no key grant leaks).
        let held: std::collections::BTreeSet<HostAuthority> = caps.iter().copied().collect();
        sandbox::derive_profile(&held, SandboxPosture::Derived, &inputs)
            .expect("storage instance inputs derive a clean profile");

        // A frontend (no backends) given the SAME full map but no backend grant also derives
        // clean — and crucially would be REFUSED if it were granted a sibling's state subtree
        // (proven by the sandbox crate's cross-authority leak tests).
        let fe = [HostAuthority::ListenHttpParse];
        let fe_inputs = build_instance_sandbox_inputs(
            &cfg,
            &fe,
            Path::new("/etc/boatramp/boatramp.cfg"),
            Path::new("/cwd"),
            None,
        );
        assert!(
            fe_inputs.base_read_write.is_empty(),
            "a frontend holds no backend state grant"
        );
        let fe_held: std::collections::BTreeSet<HostAuthority> = fe.iter().copied().collect();
        sandbox::derive_profile(&fe_held, SandboxPosture::Derived, &fe_inputs)
            .expect("frontend inputs derive a clean profile (no backend/key grants)");
    }

    #[test]
    fn relative_data_dir_is_made_absolute_against_cwd() {
        // The `./data` default must become absolute (against the CWD the Landlock PathFd uses) so
        // the derivation's lexical checks match the fd-based install (Contract #1).
        let cfg = serve_only(); // no data_dir ⇒ ./data
        let inputs = build_instance_sandbox_inputs(
            &cfg,
            &[HostAuthority::BackendKv],
            Path::new("boatramp.cfg"),
            Path::new("/srv/app"),
            None,
        );
        assert_eq!(inputs.data_dir, PathBuf::from("/srv/app/data"));
        assert!(
            inputs
                .base_read_write
                .contains(&PathBuf::from("/srv/app/data/kv"))
        );
    }

    #[test]
    fn exec_compute_router_gets_its_own_binary_read_execute_pinned() {
        use boatramp_core::privsep::SandboxPosture;
        use boatramp_server::sandbox;

        let mut cfg = serve_only();
        cfg.serve.as_mut().unwrap().data_dir = Some(PathBuf::from("/srv/node"));
        // A deterministic, absolute, NON-existent binary path (so `into_normalized` keeps it lexical
        // — no `fs::canonicalize` surprise). The exe is a SINGLE-FILE read grant, which `derive_profile`
        // only ever refuses when it is an ANCESTOR of `data_dir` (`OverbroadStateGrant`) or overlaps a
        // NON-held authority's state subtree (`CrossAuthorityStateLeak`); a single-file grant merely
        // *sitting under* `data_dir` is neither, so it would be harmless there too. This path sidesteps
        // both to keep the test self-evidently clean.
        let exe = PathBuf::from("/opt/boatramp/bin/boatramp");

        // The per-tenant router holds `exec.compute` (+ `backend.kv`, its Host→project resolver): its
        // OWN binary is pinned into the read view (installed read+EXECUTE via `AccessFs::from_read`)
        // so it can re-exec to fork per-tenant children — the root's execute-pin, mirrored.
        let router_caps = [HostAuthority::ExecCompute, HostAuthority::BackendKv];
        let router_inputs = build_instance_sandbox_inputs(
            &cfg,
            &router_caps,
            Path::new("/etc/boatramp/boatramp.cfg"),
            Path::new("/cwd"),
            Some(&exe),
        );
        assert!(
            router_inputs.base_read_only.contains(&exe),
            "an exec.compute router pins its own executable read+EXECUTE"
        );
        // ...and it survives into the derived Landlock policy's read_only_paths (the execute grant).
        let router_held: std::collections::BTreeSet<HostAuthority> =
            router_caps.iter().copied().collect();
        let router_profile =
            sandbox::derive_profile(&router_held, SandboxPosture::Derived, &router_inputs)
                .expect("router inputs derive a clean profile");
        assert!(
            router_profile.policy.read_only_paths.contains(&exe),
            "the router's own binary is in the installed read+EXECUTE view"
        );

        // A non-exec.compute instance must NOT get an execute grant on the binary — EVEN if a path is
        // (mistakenly) supplied: the gate keys on the capability, so the default is never widened.
        let backend_caps = [HostAuthority::BackendKv];
        let backend_inputs = build_instance_sandbox_inputs(
            &cfg,
            &backend_caps,
            Path::new("/etc/boatramp/boatramp.cfg"),
            Path::new("/cwd"),
            Some(&exe),
        );
        assert!(
            !backend_inputs.base_read_only.contains(&exe),
            "a non-exec.compute instance never gets an execute grant on the binary"
        );

        // An exec.compute instance whose caller could not resolve its exe (`None`) simply has no pin
        // — the caller fails the node closed before serving (mirrors the root); nothing is widened.
        let no_exe = build_instance_sandbox_inputs(
            &cfg,
            &router_caps,
            Path::new("/etc/boatramp/boatramp.cfg"),
            Path::new("/cwd"),
            None,
        );
        assert!(
            !no_exe.base_read_only.contains(&exe),
            "no exe supplied ⇒ no pin (the caller fail-closes the node instead)"
        );
    }
}
