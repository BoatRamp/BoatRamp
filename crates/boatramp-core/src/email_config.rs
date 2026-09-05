//! Project-scoped SMTP email-profile store.
//!
//! A per-project set of **named** SMTP delivery profiles for the `email` guest
//! capability (`boatramp:handlers/email`). Each profile is the connection config
//! (host / port / security / AUTH username + default sender) for one SMTP relay;
//! the **password is envelope-sealed** and stored under
//! `project/<proj>/email/<name>` ([`crate::deploy::keys::email_profile`]) — exactly
//! like [`crate::secret_store::SecretStore`], two `Arc` handles (KV + envelope),
//! cheap to clone.
//!
//! Unlike the generic secret store, the non-secret connection config is stored in
//! the clear and read back — **password-redacted** ([`EmailProfileInfo`]) — so an
//! operator can inspect and reconfigure a profile over the admin API. The full
//! profile (incl. the unsealed password) is resolved **host-side only**, at
//! handler/function instantiation ([`EmailProfileStore::resolve_all`]), to build
//! the send binding: it never leaves over the API and is never exposed to guest
//! code (the guest only ever calls `send`). This is the credential-isolation model
//! — a managed service the guest *uses* but whose config it cannot *read*.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::envelope::KeyEnvelope;
use crate::kv::KvStore;
use crate::project::ProjectRef;

/// Max profile-name length (it is a KV key segment).
const MAX_PROFILE_NAME_LEN: usize = 128;
/// Max length of a hostname / address / credential field. Generous but bounded so
/// a project admin can't seal an arbitrarily large blob into the replicated
/// control-plane KV (a Raft-amplified write-DoS on the shared plane).
const MAX_FIELD_LEN: usize = 1024;

/// The default profile name a guest selects when it passes no `profile`.
pub const DEFAULT_PROFILE: &str = "default";

/// How a profile's SMTP connection is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpSecurity {
    /// Opportunistic upgrade on the submission port (usually 587): connect
    /// plaintext, then `STARTTLS` before AUTH.
    StartTls,
    /// Implicit TLS from the first byte (SMTPS, usually 465).
    Tls,
    /// No transport encryption — only for a trusted local relay.
    Plaintext,
}

impl SmtpSecurity {
    /// The conventional submission port for this security mode.
    #[must_use]
    pub fn default_port(self) -> u16 {
        match self {
            Self::StartTls => 587,
            Self::Tls => 465,
            Self::Plaintext => 25,
        }
    }

    /// The lowercase wire spelling (matches the serde representation + the CLI flag).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StartTls => "starttls",
            Self::Tls => "tls",
            Self::Plaintext => "plaintext",
        }
    }
}

impl std::str::FromStr for SmtpSecurity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "starttls" => Ok(Self::StartTls),
            "tls" | "smtps" | "implicit" => Ok(Self::Tls),
            "plaintext" | "none" | "plain" => Ok(Self::Plaintext),
            other => Err(format!(
                "unknown SMTP security {other:?} (expected starttls|tls|plaintext)"
            )),
        }
    }
}

impl std::fmt::Display for SmtpSecurity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One named SMTP profile: the connection config plus the AUTH password. This is
/// the **host-side resolved** form (the password is present) used to build the
/// send binding; the admin API only ever exposes [`EmailProfileInfo`] (redacted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailProfile {
    /// SMTP relay hostname.
    pub host: String,
    /// SMTP relay port.
    pub port: u16,
    /// Transport security mode.
    pub security: SmtpSecurity,
    /// SMTP AUTH username; `None` = an unauthenticated relay.
    pub username: Option<String>,
    /// SMTP AUTH password; `None` = an unauthenticated relay. Present only in the
    /// host-side resolved form — never serialized to the admin API.
    pub password: Option<String>,
    /// The default (and only permitted) envelope `From` address for this profile.
    pub from: String,
    /// Whether sends through this profile default to the durable spool (the guest
    /// may still override per-send via the message's `durable` field).
    pub durable: bool,
}

impl EmailProfile {
    /// Whether `addr` is a permitted sender for this profile. A guest may only send
    /// as the profile's configured `from` (case-insensitive) — it can't spoof an
    /// arbitrary sender. `None` (guest sent no `from`) always resolves to `from`.
    #[must_use]
    pub fn sender_allowed(&self, addr: &str) -> bool {
        addr.eq_ignore_ascii_case(&self.from)
    }
}

/// A password-redacted view of a profile for the admin API / `email ls|show`. The
/// sealed password is **never** carried here, so it is safe to return.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailProfileInfo {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub security: SmtpSecurity,
    pub username: Option<String>,
    pub from: String,
    pub durable: bool,
    /// Whether a password is configured (the value itself is never returned).
    pub has_password: bool,
    pub created_at: u64,
    pub updated_at: u64,
    pub revision: u32,
}

/// Clear (non-secret) connection config, stored unsealed alongside the sealed
/// password. Names/hosts/ports aren't secret, so keeping them clear lets the admin
/// read the config back for inspection/reconfiguration.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClearConfig {
    host: String,
    port: u16,
    security: SmtpSecurity,
    username: Option<String>,
    from: String,
    durable: bool,
}

/// The record stored at `project/<proj>/email/<name>`: clear config + sealed
/// password + small clear metadata (pinned schema `version = 1`).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EmailRecord {
    version: u32,
    created_at: u64,
    updated_at: u64,
    revision: u32,
    config: ClearConfig,
    /// Envelope-sealed AUTH password; `None` = an unauthenticated relay.
    sealed_password: Option<Vec<u8>>,
}

impl EmailRecord {
    fn info(&self, name: &str) -> EmailProfileInfo {
        EmailProfileInfo {
            name: name.to_string(),
            host: self.config.host.clone(),
            port: self.config.port,
            security: self.config.security,
            username: self.config.username.clone(),
            from: self.config.from.clone(),
            durable: self.config.durable,
            has_password: self.sealed_password.is_some(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            revision: self.revision,
        }
    }
}

/// An email-profile-store failure, classified so the API returns the right status
/// and never leaks backend internals. [`InvalidName`](Self::InvalidName) and
/// [`InvalidConfig`](Self::InvalidConfig) are **client** errors (safe to return,
/// map to `400`); [`Backend`](Self::Backend) is a KV/envelope failure whose detail
/// is logged server-side and not returned (maps to `500`).
#[derive(Debug)]
pub enum EmailProfileError {
    /// The profile name is not a valid KV key segment.
    InvalidName(String),
    /// A config field is missing or malformed (e.g. empty host, `from` without `@`).
    InvalidConfig(String),
    /// A KV or envelope (seal/unseal) failure — detail is not client-safe.
    Backend(String),
}

impl std::fmt::Display for EmailProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName(m) | Self::InvalidConfig(m) | Self::Backend(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for EmailProfileError {}

impl EmailProfileError {
    /// Whether this is a client error (its message describes the request and is
    /// safe to return) vs a backend error (logged, returned generically).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        matches!(self, Self::InvalidName(_) | Self::InvalidConfig(_))
    }
}

/// A project-scoped SMTP email-profile store over a KV + a key envelope.
#[derive(Clone)]
pub struct EmailProfileStore {
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
}

impl EmailProfileStore {
    #[must_use]
    pub fn new(kv: Arc<dyn KvStore>, envelope: Arc<dyn KeyEnvelope>) -> Self {
        Self { kv, envelope }
    }

    /// Seal `profile`'s password and store the profile at
    /// `project/<proj>/email/<name>`, overwriting an existing one (reconfigure).
    /// Preserves the original `created_at`, bumps `revision`. Returns the
    /// **redacted** [`EmailProfileInfo`] (never the password). Rejects an invalid
    /// name / config fail-closed before touching the store.
    pub async fn set(
        &self,
        project: ProjectRef<'_>,
        name: &str,
        profile: &EmailProfile,
    ) -> Result<EmailProfileInfo, EmailProfileError> {
        validate_name(name)?;
        validate_config(profile)?;
        let key = crate::deploy::keys::email_profile(project, name);
        let now = crate::time::now_unix();
        let prev = self.load_record(&key).await?;
        let created_at = prev.as_ref().map_or(now, |r| r.created_at);
        let revision = prev.as_ref().map_or(0, |r| r.revision) + 1;
        // Seal the password before writing; a wrap failure leaves any prior profile
        // untouched.
        let sealed_password = match &profile.password {
            Some(pw) => Some(
                self.envelope
                    .wrap(pw.as_bytes())
                    .await
                    .map_err(|e| EmailProfileError::Backend(e.to_string()))?,
            ),
            None => None,
        };
        let record = EmailRecord {
            version: 1,
            created_at,
            updated_at: now,
            revision,
            config: ClearConfig {
                host: profile.host.clone(),
                port: profile.port,
                security: profile.security,
                username: profile.username.clone(),
                from: profile.from.clone(),
                durable: profile.durable,
            },
            sealed_password,
        };
        let bytes =
            serde_json::to_vec(&record).map_err(|e| EmailProfileError::Backend(e.to_string()))?;
        self.kv
            .put(&key, bytes)
            .await
            .map_err(|e| EmailProfileError::Backend(e.to_string()))?;
        Ok(record.info(name))
    }

    /// Fetch and **unseal** a profile's full config (incl. password). `None` if
    /// absent. Host-only: used by the binding builder at instantiation — the
    /// password is never exposed over the API.
    pub async fn get(
        &self,
        project: ProjectRef<'_>,
        name: &str,
    ) -> Result<Option<EmailProfile>, EmailProfileError> {
        validate_name(name)?;
        let key = crate::deploy::keys::email_profile(project, name);
        match self.load_record(&key).await? {
            Some(r) => Ok(Some(self.unseal(r).await?)),
            None => Ok(None),
        }
    }

    /// Redacted metadata for one profile (`email show`). `None` if absent.
    pub async fn get_info(
        &self,
        project: ProjectRef<'_>,
        name: &str,
    ) -> Result<Option<EmailProfileInfo>, EmailProfileError> {
        validate_name(name)?;
        let key = crate::deploy::keys::email_profile(project, name);
        Ok(self.load_record(&key).await?.map(|r| r.info(name)))
    }

    /// Redacted metadata for every profile in the project, sorted by name
    /// (`email ls`). A record that fails to parse is skipped, never surfaced.
    pub async fn list(
        &self,
        project: ProjectRef<'_>,
    ) -> Result<Vec<EmailProfileInfo>, EmailProfileError> {
        let prefix = crate::deploy::keys::email_profile_prefix(project);
        let mut out = Vec::new();
        for key in self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(|e| EmailProfileError::Backend(e.to_string()))?
        {
            let name = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
            if let Some(bytes) = self
                .kv
                .get(&key)
                .await
                .map_err(|e| EmailProfileError::Backend(e.to_string()))?
            {
                if let Ok(record) = serde_json::from_slice::<EmailRecord>(&bytes) {
                    out.push(record.info(&name));
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Resolve **every** profile in the project into its full host-side form (incl.
    /// the unsealed password), keyed by name. Called host-side when building a
    /// guest's `email` binding — the guest sees only the verb, never this map.
    /// A record that fails to parse/unseal is skipped (logged by the caller if it
    /// cares), so one corrupt profile can't block the rest.
    pub async fn resolve_all(
        &self,
        project: ProjectRef<'_>,
    ) -> Result<BTreeMap<String, EmailProfile>, EmailProfileError> {
        let prefix = crate::deploy::keys::email_profile_prefix(project);
        let mut out = BTreeMap::new();
        for key in self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(|e| EmailProfileError::Backend(e.to_string()))?
        {
            let name = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
            if let Some(bytes) = self
                .kv
                .get(&key)
                .await
                .map_err(|e| EmailProfileError::Backend(e.to_string()))?
            {
                if let Ok(record) = serde_json::from_slice::<EmailRecord>(&bytes) {
                    if let Ok(profile) = self.unseal(record).await {
                        out.insert(name, profile);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Delete a profile. Returns whether it existed.
    pub async fn delete(
        &self,
        project: ProjectRef<'_>,
        name: &str,
    ) -> Result<bool, EmailProfileError> {
        validate_name(name)?;
        let key = crate::deploy::keys::email_profile(project, name);
        let existed = self
            .kv
            .get(&key)
            .await
            .map_err(|e| EmailProfileError::Backend(e.to_string()))?
            .is_some();
        if existed {
            self.kv
                .delete(&key)
                .await
                .map_err(|e| EmailProfileError::Backend(e.to_string()))?;
        }
        Ok(existed)
    }

    async fn unseal(&self, record: EmailRecord) -> Result<EmailProfile, EmailProfileError> {
        let password = match &record.sealed_password {
            Some(sealed) => {
                let bytes = self
                    .envelope
                    .unwrap(sealed)
                    .await
                    .map_err(|e| EmailProfileError::Backend(e.to_string()))?;
                Some(
                    String::from_utf8(bytes)
                        .map_err(|e| EmailProfileError::Backend(e.to_string()))?,
                )
            }
            None => None,
        };
        Ok(EmailProfile {
            host: record.config.host,
            port: record.config.port,
            security: record.config.security,
            username: record.config.username,
            password,
            from: record.config.from,
            durable: record.config.durable,
        })
    }

    async fn load_record(&self, key: &str) -> Result<Option<EmailRecord>, EmailProfileError> {
        match self
            .kv
            .get(key)
            .await
            .map_err(|e| EmailProfileError::Backend(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice::<EmailRecord>(&bytes)
                .map(Some)
                .map_err(|e| {
                    EmailProfileError::Backend(format!("corrupt email profile at {key}: {e}"))
                }),
            None => Ok(None),
        }
    }
}

/// Validate a profile name used as a KV key segment: non-empty, `≤
/// MAX_PROFILE_NAME_LEN`, only `[A-Za-z0-9._-]` (so it can't inject a `/` and reach
/// another keyspace), not `.`/`..`. Fail-closed — the name is tenant-supplied.
fn validate_name(name: &str) -> Result<(), EmailProfileError> {
    if name.is_empty() || name.len() > MAX_PROFILE_NAME_LEN {
        return Err(EmailProfileError::InvalidName(format!(
            "email profile name must be 1..={MAX_PROFILE_NAME_LEN} characters"
        )));
    }
    if name == "." || name == ".." {
        return Err(EmailProfileError::InvalidName(
            "email profile name must not be '.' or '..'".to_string(),
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(EmailProfileError::InvalidName(
            "email profile name may contain only [A-Za-z0-9._-]".to_string(),
        ));
    }
    Ok(())
}

/// Validate the connection config fail-closed before sealing/storing.
fn validate_config(profile: &EmailProfile) -> Result<(), EmailProfileError> {
    let bounded = |field: &str, value: &str| -> Result<(), EmailProfileError> {
        if value.is_empty() {
            return Err(EmailProfileError::InvalidConfig(format!(
                "{field} is required"
            )));
        }
        if value.len() > MAX_FIELD_LEN {
            return Err(EmailProfileError::InvalidConfig(format!(
                "{field} exceeds {MAX_FIELD_LEN} bytes"
            )));
        }
        Ok(())
    };
    bounded("host", &profile.host)?;
    bounded("from", &profile.from)?;
    if profile.port == 0 {
        return Err(EmailProfileError::InvalidConfig(
            "port must be non-zero".into(),
        ));
    }
    // A minimal sanity check on the sender: a single `@` with non-empty local/domain
    // parts. Not full RFC 5322 — just enough to reject an obviously-wrong value.
    match profile.from.split_once('@') {
        Some((local, domain)) if !local.is_empty() && domain.contains('.') => {}
        _ => {
            return Err(EmailProfileError::InvalidConfig(
                "from must be a valid email address (local@domain)".into(),
            ))
        }
    }
    if let Some(u) = &profile.username {
        bounded("username", u)?;
    }
    if let Some(p) = &profile.password {
        if p.len() > MAX_FIELD_LEN {
            return Err(EmailProfileError::InvalidConfig(format!(
                "password exceeds {MAX_FIELD_LEN} bytes"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvelopeError;
    use crate::kv::MemoryKv;

    /// A reversible test envelope: XOR with a constant, so a "sealed" blob is
    /// visibly different from the plaintext yet round-trips.
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

    fn store() -> EmailProfileStore {
        EmailProfileStore::new(Arc::new(MemoryKv::new()), Arc::new(XorEnvelope))
    }

    fn profile() -> EmailProfile {
        EmailProfile {
            host: "smtp.example.com".into(),
            port: 587,
            security: SmtpSecurity::StartTls,
            username: Some("apikey".into()),
            password: Some("s3cr3t".into()),
            from: "no-reply@example.com".into(),
            durable: false,
        }
    }

    #[tokio::test]
    async fn set_get_round_trips_and_password_is_sealed_at_rest() {
        let s = store();
        let p = ProjectRef::new("acme");
        let info = s.set(p, "default", &profile()).await.unwrap();
        assert_eq!(info.revision, 1);
        assert!(info.has_password);
        let got = s.get(p, "default").await.unwrap().unwrap();
        assert_eq!(got, profile());

        // The password must be sealed at rest — the plaintext must not appear in KV.
        let kv = Arc::new(MemoryKv::new());
        let s2 = EmailProfileStore::new(kv.clone(), Arc::new(XorEnvelope));
        s2.set(p, "default", &profile()).await.unwrap();
        let raw = kv
            .get(&crate::deploy::keys::email_profile(p, "default"))
            .await
            .unwrap()
            .unwrap();
        assert!(
            !raw.windows(6).any(|w| w == b"s3cr3t"),
            "password must never be stored in the clear"
        );
    }

    #[tokio::test]
    async fn info_and_list_redact_the_password() {
        let s = store();
        let p = ProjectRef::new("acme");
        s.set(p, "default", &profile()).await.unwrap();
        // The redacted views must be password-free (they don't carry the field at
        // all) yet report the non-secret config, incl. that a password is set.
        let info = s.get_info(p, "default").await.unwrap().unwrap();
        assert_eq!(info.host, "smtp.example.com");
        assert_eq!(info.from, "no-reply@example.com");
        assert!(info.has_password);
        let json = serde_json::to_string(&info).unwrap();
        assert!(
            !json.contains("s3cr3t"),
            "redacted info leaked the password: {json}"
        );
        let listed = s.list(p).await.unwrap();
        assert_eq!(listed.len(), 1);
        assert!(!serde_json::to_string(&listed).unwrap().contains("s3cr3t"));
    }

    #[tokio::test]
    async fn reconfigure_preserves_created_at_and_bumps_revision() {
        let s = store();
        let p = ProjectRef::new("acme");
        let m1 = s.set(p, "default", &profile()).await.unwrap();
        let mut p2 = profile();
        p2.host = "smtp2.example.com".into();
        let m2 = s.set(p, "default", &p2).await.unwrap();
        assert_eq!(m2.revision, 2);
        assert_eq!(m2.created_at, m1.created_at);
        assert_eq!(
            s.get(p, "default").await.unwrap().unwrap().host,
            "smtp2.example.com"
        );
    }

    #[tokio::test]
    async fn profiles_are_isolated_per_project() {
        let s = store();
        s.set(ProjectRef::new("acme"), "default", &profile())
            .await
            .unwrap();
        assert!(s
            .get(ProjectRef::new("globex"), "default")
            .await
            .unwrap()
            .is_none());
        assert!(s.list(ProjectRef::new("globex")).await.unwrap().is_empty());
        assert!(s
            .resolve_all(ProjectRef::new("globex"))
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn resolve_all_returns_full_profiles_by_name() {
        let s = store();
        let p = ProjectRef::new("acme");
        s.set(p, "default", &profile()).await.unwrap();
        let mut marketing = profile();
        marketing.from = "hello@example.com".into();
        s.set(p, "marketing", &marketing).await.unwrap();
        let all = s.resolve_all(p).await.unwrap();
        assert_eq!(all.len(), 2);
        // Full form incl. the unsealed password (host-side only).
        assert_eq!(all["default"].password.as_deref(), Some("s3cr3t"));
        assert_eq!(all["marketing"].from, "hello@example.com");
    }

    #[tokio::test]
    async fn an_unauthenticated_relay_has_no_password() {
        let s = store();
        let p = ProjectRef::new("acme");
        let mut relay = profile();
        relay.username = None;
        relay.password = None;
        let info = s.set(p, "relay", &relay).await.unwrap();
        assert!(!info.has_password);
        assert_eq!(s.get(p, "relay").await.unwrap().unwrap().password, None);
    }

    #[tokio::test]
    async fn delete_reports_existence_then_removes() {
        let s = store();
        let p = ProjectRef::new("acme");
        s.set(p, "default", &profile()).await.unwrap();
        assert!(s.delete(p, "default").await.unwrap());
        assert!(!s.delete(p, "default").await.unwrap());
        assert!(s.get(p, "default").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn invalid_names_are_refused_fail_closed() {
        let s = store();
        let p = ProjectRef::new("acme");
        for bad in ["", "has/slash", "..", ".", "space bad", &"x".repeat(129)] {
            assert!(
                s.set(p, bad, &profile()).await.is_err(),
                "name {bad:?} must be rejected"
            );
        }
        assert!(s.set(p, "ok.name_1-2", &profile()).await.is_ok());
    }

    #[tokio::test]
    async fn invalid_config_is_refused() {
        let s = store();
        let p = ProjectRef::new("acme");
        let bad_from = EmailProfile {
            from: "not-an-email".into(),
            ..profile()
        };
        let e = s.set(p, "x", &bad_from).await.unwrap_err();
        assert!(matches!(e, EmailProfileError::InvalidConfig(_)) && e.is_client_error());
        let empty_host = EmailProfile {
            host: String::new(),
            ..profile()
        };
        assert!(s.set(p, "y", &empty_host).await.is_err());
        let zero_port = EmailProfile {
            port: 0,
            ..profile()
        };
        assert!(s.set(p, "z", &zero_port).await.is_err());
    }

    #[test]
    fn sender_allowed_matches_case_insensitively_only_the_configured_from() {
        let pr = profile();
        assert!(pr.sender_allowed("no-reply@example.com"));
        assert!(pr.sender_allowed("No-Reply@Example.COM"));
        assert!(!pr.sender_allowed("someone-else@example.com"));
    }

    #[test]
    fn security_parses_and_has_conventional_ports() {
        use std::str::FromStr;
        assert_eq!(
            SmtpSecurity::from_str("STARTTLS").unwrap(),
            SmtpSecurity::StartTls
        );
        assert_eq!(SmtpSecurity::from_str("tls").unwrap(), SmtpSecurity::Tls);
        assert_eq!(
            SmtpSecurity::from_str("plaintext").unwrap(),
            SmtpSecurity::Plaintext
        );
        assert!(SmtpSecurity::from_str("bogus").is_err());
        assert_eq!(SmtpSecurity::StartTls.default_port(), 587);
        assert_eq!(SmtpSecurity::Tls.default_port(), 465);
    }
}
