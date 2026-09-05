//! The `email` capability host binding: a handler/function submits a **finished**
//! message (`boatramp:handlers/email`), which the host delivers through one of the
//! project's operator-configured SMTP profiles.
//!
//! Credential isolation is the point: the SMTP host/port/username/password live
//! **host-side** (resolved from [`boatramp_core::email_config`] into the
//! [`EmailBinding`]); the guest only ever calls `send` and never sees a credential
//! or the relay config. Reading/reconfiguring a profile is a control-plane action
//! (the admin API / `boatramp email`), gated by a boatramp token — never something
//! the guest can do.
//!
//! Deny by default: a handler not granted `email` has no binding, and `send` fails
//! with `access-denied`.
//!
//! `send` is **accepted-for-delivery**: the [`EmailHost`] validates the message,
//! resolves the profile, and hands it to the [`EmailSpool`] — delivery is
//! asynchronous (in-memory best-effort by default, or a durable persisted+retried
//! queue when the message opts in). The concrete spool + the durable delivery
//! worker live in the server (they own the mpsc + the messaging fabric); the
//! actual SMTP put lives behind [`SmtpBackend`] ([`LettreBackend`]).

use std::collections::BTreeMap;
use std::sync::Arc;

use boatramp_core::email_config::{EmailProfile, DEFAULT_PROFILE};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/email-host",
        async: {
            only_imports: ["send"],
        },
    });
}

use generated::boatramp::handlers::{email_sender, email_types};

/// A finished outbound message in the host's own vocabulary — the validated,
/// profile-resolved form of the guest's `email-message`. It is `serde`-encodable
/// so the durable spool can persist it onto the messaging fabric (the profile's
/// **credentials are never** part of it — the durable worker re-resolves them
/// host-side from `project` + `profile`, so plaintext creds never hit the queue).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OutboundEmail {
    /// The owning project (used by the durable worker to re-resolve the profile).
    pub project: String,
    /// The resolved profile name to deliver through.
    pub profile: String,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub bcc: Vec<String>,
    /// The resolved (profile-permitted) `From` address.
    pub from: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub text: Option<String>,
    pub html: Option<String>,
    /// Whether this message chose the durable spool (already folded in the profile
    /// default at enqueue time).
    pub durable: bool,
}

/// The host delivery seam: accept a validated message for delivery through
/// `profile`. Returns once the message is **enqueued** (not delivered). The
/// concrete implementation (best-effort mpsc and/or the durable fabric queue)
/// lives in the server.
#[async_trait::async_trait]
pub trait EmailSpool: Send + Sync {
    async fn enqueue(&self, profile: EmailProfile, message: OutboundEmail) -> Result<(), String>;
}

/// The actual SMTP put — the layer that talks to a relay. Split from [`EmailSpool`]
/// so both the best-effort drain task and the durable delivery worker share one
/// implementation ([`LettreBackend`]) and the spool logic stays testable with a
/// fake backend.
#[async_trait::async_trait]
pub trait SmtpBackend: Send + Sync {
    async fn send(&self, profile: &EmailProfile, message: &OutboundEmail) -> Result<(), String>;
}

/// A per-project `email` grant: the owning project, the resolved SMTP profiles
/// (host-held, incl. sealed-then-unsealed credentials — never exposed to the
/// guest), and the shared node spool. `None` in [`Bindings`] = not granted.
#[derive(Clone)]
pub struct EmailBinding {
    pub(crate) project: String,
    pub(crate) profiles: Arc<BTreeMap<String, EmailProfile>>,
    pub(crate) spool: Arc<dyn EmailSpool>,
}

/// Max envelope recipients (`to` + `cc` + `bcc`) per message. Bounds a granted
/// guest's fan-out abuse of the operator's shared SMTP egress (mass mail is the
/// residual risk once the guest is trusted to send at all — it still can't read
/// the credentials). Generous for transactional mail; well below relay limits.
const MAX_RECIPIENTS: usize = 100;
/// Max total message size (`subject` + `text` + `html`) in bytes. Bounds relay
/// abuse and durable-spool amplification. 2 MiB is far above any real HTML email.
const MAX_MESSAGE_BYTES: usize = 2 * 1024 * 1024;

/// Per-invocation view over the (optional) email grant.
pub struct EmailHost<'a> {
    binding: Option<&'a EmailBinding>,
}

impl<'a> EmailHost<'a> {
    /// Build a view; `None` means the capability was not granted.
    pub fn new(binding: Option<&'a EmailBinding>) -> Self {
        Self { binding }
    }
}

impl email_sender::Host for EmailHost<'_> {
    async fn send(
        &mut self,
        message: email_types::EmailMessage,
    ) -> Result<(), email_types::EmailError> {
        use email_types::EmailError as E;
        let Some(binding) = self.binding else {
            return Err(E::AccessDenied);
        };
        let profile_name = match &message.profile {
            Some(p) if !p.is_empty() => p.as_str(),
            _ => DEFAULT_PROFILE,
        };
        let Some(profile) = binding.profiles.get(profile_name) else {
            return Err(E::UnknownProfile(profile_name.to_string()));
        };

        // Validate before spooling (fail-closed on an obviously-bad message).
        if message.to.iter().all(|r| r.trim().is_empty()) {
            return Err(E::InvalidMessage(
                "at least one `to` recipient is required".to_string(),
            ));
        }
        if message.subject.trim().is_empty() {
            return Err(E::InvalidMessage("subject is required".to_string()));
        }
        let has_body = message.text.as_ref().is_some_and(|t| !t.is_empty())
            || message.html.as_ref().is_some_and(|h| !h.is_empty());
        if !has_body {
            return Err(E::InvalidMessage(
                "a text or html body is required".to_string(),
            ));
        }
        // Bound fan-out + size per message: a guest can't *read* the shared relay's
        // credentials, but an unbounded `send` would still let a granted tenant
        // weaponize the operator's SMTP egress (mass mail, reputation/quota burn) —
        // and, on the durable path, amplify into the shared messaging fabric. Cap
        // both fail-closed, applied here so BOTH spool paths inherit the bound.
        let recipients = message.to.len() + message.cc.len() + message.bcc.len();
        if recipients > MAX_RECIPIENTS {
            return Err(E::InvalidMessage(format!(
                "too many recipients ({recipients}); the maximum is {MAX_RECIPIENTS}"
            )));
        }
        let body_bytes = message.subject.len()
            + message.text.as_deref().map_or(0, str::len)
            + message.html.as_deref().map_or(0, str::len);
        if body_bytes > MAX_MESSAGE_BYTES {
            return Err(E::InvalidMessage(format!(
                "message is {body_bytes} bytes; the maximum is {MAX_MESSAGE_BYTES}"
            )));
        }

        // The sender must be permitted by the profile — a guest can't spoof an
        // arbitrary `From`; `none`/empty falls back to the profile's default.
        let from = match &message.from {
            Some(f) if !f.is_empty() => {
                if !profile.sender_allowed(f) {
                    return Err(E::InvalidMessage(format!(
                        "from {f:?} is not permitted by profile {profile_name:?}"
                    )));
                }
                f.clone()
            }
            _ => profile.from.clone(),
        };

        let durable = message.durable.unwrap_or(profile.durable);
        let outbound = OutboundEmail {
            project: binding.project.clone(),
            profile: profile_name.to_string(),
            to: message.to,
            cc: message.cc,
            bcc: message.bcc,
            from,
            reply_to: message.reply_to,
            subject: message.subject,
            text: message.text,
            html: message.html,
            durable,
        };
        binding
            .spool
            .enqueue(profile.clone(), outbound)
            .await
            .map_err(E::SpoolFailed)
    }
}

/// Add the `email-sender` interface to `linker`, resolving the per-invocation
/// [`EmailHost`] view via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> EmailHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    email_sender::add_to_linker_get_host(linker, host)
}

// ---------------------------------------------------------------------------
// The `lettre` SMTP backend.
// ---------------------------------------------------------------------------

use boatramp_core::email_config::SmtpSecurity;
use lettre::message::{Mailbox, Message, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Tokio1Executor};

/// The default SMTP backend: delivers a message through a relay via `lettre`
/// (pure-rustls, no OpenSSL). Applies the SSRF gate to the relay host so a tenant
/// can't aim it at an internal service.
pub struct LettreBackend {
    /// Whether a private/loopback relay host is permitted (mirrors the guest
    /// private-egress posture). When `false`, a relay resolving to a non-global IP
    /// is refused — so an untrusted tenant's profile can't reach internal services.
    allow_private_relay: bool,
}

impl LettreBackend {
    #[must_use]
    pub fn new(allow_private_relay: bool) -> Self {
        Self {
            allow_private_relay,
        }
    }

    /// SSRF gate on the relay host: unless private relays are permitted, resolve
    /// the host and require **every** address to be globally-routable.
    async fn check_relay_host(&self, host: &str, port: u16) -> Result<(), String> {
        if self.allow_private_relay {
            return Ok(());
        }
        let mut any = false;
        for addr in tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| format!("SMTP relay DNS resolution failed for {host:?}: {e}"))?
        {
            any = true;
            if !boatramp_core::access::is_global_ip(addr.ip()) {
                return Err(format!(
                    "SMTP relay {host:?} resolves to non-global address {} (blocked by security posture)",
                    addr.ip()
                ));
            }
        }
        if !any {
            return Err(format!("SMTP relay {host:?} resolved to no addresses"));
        }
        Ok(())
    }
}

/// Build a `lettre` [`Message`] from a resolved profile + outbound message.
/// Separated out so it is unit-testable without a live relay.
fn build_message(message: &OutboundEmail) -> Result<Message, String> {
    let parse = |what: &str, addr: &str| -> Result<Mailbox, String> {
        addr.parse::<Mailbox>()
            .map_err(|e| format!("invalid {what} address {addr:?}: {e}"))
    };
    let mut builder = Message::builder()
        .from(parse("from", &message.from)?)
        .subject(message.subject.clone());
    for to in &message.to {
        if !to.trim().is_empty() {
            builder = builder.to(parse("to", to)?);
        }
    }
    for cc in &message.cc {
        if !cc.trim().is_empty() {
            builder = builder.cc(parse("cc", cc)?);
        }
    }
    for bcc in &message.bcc {
        if !bcc.trim().is_empty() {
            builder = builder.bcc(parse("bcc", bcc)?);
        }
    }
    if let Some(reply_to) = &message.reply_to {
        if !reply_to.trim().is_empty() {
            builder = builder.reply_to(parse("reply-to", reply_to)?);
        }
    }
    let built = match (&message.text, &message.html) {
        (Some(text), Some(html)) => builder.multipart(MultiPart::alternative_plain_html(
            text.clone(),
            html.clone(),
        )),
        (Some(text), None) => builder.singlepart(SinglePart::plain(text.clone())),
        (None, Some(html)) => builder.singlepart(SinglePart::html(html.clone())),
        (None, None) => return Err("message has no text or html body".to_string()),
    };
    built.map_err(|e| format!("building the email failed: {e}"))
}

#[async_trait::async_trait]
impl SmtpBackend for LettreBackend {
    async fn send(&self, profile: &EmailProfile, message: &OutboundEmail) -> Result<(), String> {
        self.check_relay_host(&profile.host, profile.port).await?;
        let builder = match profile.security {
            SmtpSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&profile.host)
                .map_err(|e| format!("SMTP relay setup failed: {e}"))?,
            SmtpSecurity::StartTls => {
                AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&profile.host)
                    .map_err(|e| format!("SMTP STARTTLS relay setup failed: {e}"))?
            }
            SmtpSecurity::Plaintext => {
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(profile.host.clone())
            }
        };
        let builder = builder.port(profile.port);
        let builder = match (&profile.username, &profile.password) {
            (Some(user), Some(pass)) => {
                builder.credentials(Credentials::new(user.clone(), pass.clone()))
            }
            _ => builder,
        };
        let mailer = builder.build();
        let email = build_message(message)?;
        mailer
            .send(email)
            .await
            .map(|_| ())
            .map_err(|e| format!("SMTP delivery failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::email_sender::Host;
    use super::*;
    use std::sync::Mutex;

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

    /// Records every enqueued (profile, message) pair.
    #[derive(Default)]
    struct FakeSpool {
        enqueued: Mutex<Vec<(EmailProfile, OutboundEmail)>>,
    }
    #[async_trait::async_trait]
    impl EmailSpool for FakeSpool {
        async fn enqueue(
            &self,
            profile: EmailProfile,
            message: OutboundEmail,
        ) -> Result<(), String> {
            self.enqueued.lock().unwrap().push((profile, message));
            Ok(())
        }
    }

    fn binding(spool: Arc<FakeSpool>) -> EmailBinding {
        let mut profiles = BTreeMap::new();
        profiles.insert("default".to_string(), profile());
        EmailBinding {
            project: "acme".into(),
            profiles: Arc::new(profiles),
            spool,
        }
    }

    fn message() -> email_types::EmailMessage {
        email_types::EmailMessage {
            profile: None,
            to: vec!["dest@example.org".into()],
            cc: vec![],
            bcc: vec![],
            from: None,
            reply_to: None,
            subject: "Hi".into(),
            text: Some("hello".into()),
            html: None,
            durable: None,
        }
    }

    #[tokio::test]
    async fn ungranted_send_is_denied() {
        let mut host = EmailHost::new(None);
        let err = host.send(message()).await.unwrap_err();
        assert!(matches!(err, email_types::EmailError::AccessDenied));
    }

    #[tokio::test]
    async fn send_spools_with_the_resolved_default_profile_and_from() {
        let spool = Arc::new(FakeSpool::default());
        let binding = binding(spool.clone());
        let mut host = EmailHost::new(Some(&binding));
        host.send(message()).await.unwrap();
        let enqueued = spool.enqueued.lock().unwrap();
        assert_eq!(enqueued.len(), 1);
        let (p, m) = &enqueued[0];
        assert_eq!(p.host, "smtp.example.com");
        assert_eq!(m.profile, "default");
        assert_eq!(m.project, "acme");
        // No guest `from` → the profile default.
        assert_eq!(m.from, "no-reply@example.com");
        assert!(!m.durable);
    }

    #[tokio::test]
    async fn oversized_recipients_or_body_are_refused_before_spooling() {
        let spool = Arc::new(FakeSpool::default());
        let binding = binding(spool.clone());
        let mut host = EmailHost::new(Some(&binding));
        // Too many recipients (spread across to/cc/bcc) is refused.
        let mut many = message();
        many.to = (0..MAX_RECIPIENTS + 1)
            .map(|i| format!("r{i}@example.org"))
            .collect();
        assert!(matches!(
            host.send(many).await.unwrap_err(),
            email_types::EmailError::InvalidMessage(_)
        ));
        // An oversized body is refused.
        let mut big = message();
        big.html = Some("x".repeat(MAX_MESSAGE_BYTES + 1));
        assert!(matches!(
            host.send(big).await.unwrap_err(),
            email_types::EmailError::InvalidMessage(_)
        ));
        // Nothing over-limit was ever spooled.
        assert!(spool.enqueued.lock().unwrap().is_empty());
        // A message at the recipient ceiling is accepted.
        let mut at_limit = message();
        at_limit.to = (0..MAX_RECIPIENTS)
            .map(|i| format!("r{i}@example.org"))
            .collect();
        host.send(at_limit).await.unwrap();
        assert_eq!(spool.enqueued.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn unknown_profile_is_rejected() {
        let spool = Arc::new(FakeSpool::default());
        let binding = binding(spool);
        let mut host = EmailHost::new(Some(&binding));
        let mut m = message();
        m.profile = Some("marketing".into());
        let err = host.send(m).await.unwrap_err();
        assert!(
            matches!(err, email_types::EmailError::UnknownProfile(name) if name == "marketing")
        );
    }

    #[tokio::test]
    async fn a_spoofed_from_is_refused_but_the_profile_sender_is_allowed() {
        let spool = Arc::new(FakeSpool::default());
        let binding = binding(spool.clone());
        let mut host = EmailHost::new(Some(&binding));
        // A `from` outside the profile is refused (anti-spoofing).
        let mut spoof = message();
        spoof.from = Some("ceo@victim.example".into());
        assert!(matches!(
            host.send(spoof).await.unwrap_err(),
            email_types::EmailError::InvalidMessage(_)
        ));
        // The profile's own sender is accepted.
        let mut ok = message();
        ok.from = Some("no-reply@example.com".into());
        host.send(ok).await.unwrap();
        assert_eq!(spool.enqueued.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_empty_message_is_refused() {
        let spool = Arc::new(FakeSpool::default());
        let binding = binding(spool);
        let mut host = EmailHost::new(Some(&binding));
        // No recipients.
        let mut no_to = message();
        no_to.to = vec![];
        assert!(matches!(
            host.send(no_to).await.unwrap_err(),
            email_types::EmailError::InvalidMessage(_)
        ));
        // No body.
        let mut no_body = message();
        no_body.text = None;
        no_body.html = None;
        assert!(matches!(
            host.send(no_body).await.unwrap_err(),
            email_types::EmailError::InvalidMessage(_)
        ));
        // Blank subject.
        let mut no_subject = message();
        no_subject.subject = "   ".into();
        assert!(matches!(
            host.send(no_subject).await.unwrap_err(),
            email_types::EmailError::InvalidMessage(_)
        ));
    }

    #[tokio::test]
    async fn per_message_durable_opt_in_overrides_the_profile_default() {
        let spool = Arc::new(FakeSpool::default());
        let binding = binding(spool.clone());
        let mut host = EmailHost::new(Some(&binding));
        let mut m = message();
        m.durable = Some(true);
        host.send(m).await.unwrap();
        assert!(spool.enqueued.lock().unwrap()[0].1.durable);
    }

    fn outbound() -> OutboundEmail {
        OutboundEmail {
            project: "acme".into(),
            profile: "default".into(),
            to: vec!["dest@example.org".into()],
            cc: vec![],
            bcc: vec![],
            from: "no-reply@example.com".into(),
            reply_to: Some("support@example.com".into()),
            subject: "Hi".into(),
            text: Some("hello".into()),
            html: Some("<p>hello</p>".into()),
            durable: false,
        }
    }

    #[test]
    fn build_message_produces_a_multipart_alternative() {
        // A text+html message builds without error (exercises the MIME assembly).
        assert!(build_message(&outbound()).is_ok());
        // A body-less message is refused at the builder too (defensive).
        let mut empty = outbound();
        empty.text = None;
        empty.html = None;
        assert!(build_message(&empty).is_err());
        // A malformed recipient is a build error, not a panic.
        let mut bad = outbound();
        bad.to = vec!["not an address".into()];
        assert!(build_message(&bad).is_err());
    }

    #[tokio::test]
    async fn ssrf_gate_blocks_a_private_relay_unless_permitted() {
        let mut p = profile();
        p.host = "127.0.0.1".into();
        p.port = 25;
        p.security = SmtpSecurity::Plaintext;
        p.username = None;
        p.password = None;
        // Locked down: a loopback relay is refused before any connection.
        let strict = LettreBackend::new(false);
        assert!(strict.send(&p, &outbound()).await.is_err());
        // The check itself: a private address is rejected...
        assert!(strict.check_relay_host("127.0.0.1", 25).await.is_err());
        // ...but permitted when the posture allows private relays.
        let loose = LettreBackend::new(true);
        assert!(loose.check_relay_host("127.0.0.1", 25).await.is_ok());
    }
}
