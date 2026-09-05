//! The node-side email delivery spool backing the `email` capability.
//!
//! [`NodeEmailSpool::enqueue`] accepts a validated [`OutboundEmail`] and routes it
//! by durability:
//!
//! - **best-effort** (default): push onto a bounded in-memory channel drained by a
//!   detached task that delivers via the [`SmtpBackend`] with a few retries. Lost on
//!   crash — the trade for zero persistence overhead. The guest's `send` never
//!   blocks on SMTP.
//! - **durable** (opt-in): publish the serialized message onto a reserved
//!   node-internal messaging topic; a detached worker claims it (lease + retry +
//!   dead-letter via the existing messaging fabric) and delivers, **re-resolving the
//!   SMTP credentials host-side** from the project's profile store — so plaintext
//!   credentials never ride the persisted queue. Survives a restart.
//!
//! The reserved topic is host-internal: a guest can never name it (it only reaches
//! the spool through the host `send` path, which stamps the correct project on each
//! message), so a tenant can't inject into another tenant's outbound mail.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use boatramp_core::access::RateLimit;
use boatramp_core::email_config::{EmailProfile, EmailProfileStore};
use boatramp_core::messaging::Messaging;
use boatramp_core::project::ProjectRef;
use boatramp_handlers::{EmailSpool, OutboundEmail, SmtpBackend};

use crate::ratelimit::RateLimiter;

/// The reserved node-internal messaging topic the durable spool uses. Not a project
/// bus topic — a guest can't name it; only the host `send` path publishes here.
const DURABLE_TOPIC: &str = "_boatramp/email/outbound";

/// Sustained per-project send rate (messages/second) enforced across BOTH the
/// best-effort and durable paths. A granted (credential-isolated) guest can still
/// loop `send`; without a per-project quota that floods the operator's shared relay
/// and — on the durable path — the shared messaging fabric + dead-letter store. The
/// per-message caps (`MAX_RECIPIENTS`/`MAX_MESSAGE_BYTES` in the binding) bound each
/// message; this bounds the *rate*. Per-node (like the default visitor limiter);
/// generous for transactional bursts, but a runaway loop is throttled ~1000x.
const EMAIL_SENDS_PER_SEC: u32 = 5;
/// Burst capacity for the per-project send bucket (a signup wave, a batch).
const EMAIL_SEND_BURST: u32 = 50;
/// Fixed key-suffix for the per-project token bucket (the limiter keys on
/// `(project, ip)`; email has no client IP, so a constant stands in and the bucket
/// is effectively per-project).
const EMAIL_RL_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Best-effort in-memory queue capacity (messages awaiting the SMTP put).
const BEST_EFFORT_CAPACITY: usize = 1024;
/// Best-effort delivery attempts before the message is dropped (and logged).
const BEST_EFFORT_ATTEMPTS: u32 = 3;
/// Durable claim lease — how long a claimed message is invisible before redelivery.
const DURABLE_LEASE: Duration = Duration::from_secs(60);
/// Durable poll cadence when the queue is empty.
const DURABLE_POLL: Duration = Duration::from_secs(2);
/// Durable claim batch size.
const DURABLE_BATCH: usize = 16;
/// Durable delivery attempts before the message is dead-lettered by the fabric.
const DURABLE_MAX_ATTEMPTS: u32 = 5;

/// The shared node email spool. Cheap to clone (channel sender + optional messaging
/// handle); handed to the handler runtime as an `Arc<dyn EmailSpool>`.
pub struct NodeEmailSpool {
    tx: tokio::sync::mpsc::Sender<(EmailProfile, OutboundEmail)>,
    messaging: Option<Arc<dyn Messaging>>,
    /// Per-project send-rate token buckets (keyed on the project name).
    rate: RateLimiter,
    /// The per-project send budget applied to every `enqueue`.
    limit: RateLimit,
}

impl NodeEmailSpool {
    /// Build the spool and spawn its background workers, returning the
    /// `Arc<dyn EmailSpool>` to wire into the runtime. `backend` performs the SMTP
    /// put; `messaging` (when present) backs the durable path; `store` re-resolves
    /// credentials for durable delivery.
    pub fn spawn(
        backend: Arc<dyn SmtpBackend>,
        messaging: Option<Arc<dyn Messaging>>,
        store: Arc<EmailProfileStore>,
    ) -> Arc<dyn EmailSpool> {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<(EmailProfile, OutboundEmail)>(BEST_EFFORT_CAPACITY);
        // Best-effort drain: deliver each queued message, retrying a few times.
        {
            let backend = backend.clone();
            tokio::spawn(async move {
                while let Some((profile, msg)) = rx.recv().await {
                    deliver_with_retry(backend.as_ref(), &profile, &msg, BEST_EFFORT_ATTEMPTS)
                        .await;
                }
            });
        }
        // Durable worker: drive the reserved topic through the messaging fabric's
        // lease/retry/dead-letter. Only when messaging is configured.
        if let Some(messaging) = messaging.clone() {
            let backend = backend.clone();
            let store = store.clone();
            tokio::spawn(async move { durable_worker(backend, messaging, store).await });
        }
        Arc::new(Self {
            tx,
            messaging,
            rate: RateLimiter::new(),
            limit: RateLimit {
                rps: EMAIL_SENDS_PER_SEC,
                burst: EMAIL_SEND_BURST,
            },
        })
    }
}

#[async_trait::async_trait]
impl EmailSpool for NodeEmailSpool {
    async fn enqueue(&self, profile: EmailProfile, message: OutboundEmail) -> Result<(), String> {
        // Per-project send-rate quota, charged once per `send` BEFORE routing — so a
        // runaway guest loop can't flood the shared relay or the durable fabric,
        // whichever path it picks. The project is stamped host-side (a guest can't
        // forge it), so the bucket is genuinely per-tenant.
        if !self.rate.check(&message.project, EMAIL_RL_IP, &self.limit) {
            return Err(format!(
                "per-project email send rate exceeded (limit {} msg/s, burst {}); slow down",
                self.limit.rps, self.limit.burst
            ));
        }
        if message.durable {
            let Some(messaging) = &self.messaging else {
                return Err(
                    "durable email requested but this node has no messaging backend configured"
                        .to_string(),
                );
            };
            // The persisted payload carries project + profile name (not the creds) —
            // the durable worker re-resolves the sealed credentials host-side.
            let payload = serde_json::to_vec(&message)
                .map_err(|e| format!("serializing durable email failed: {e}"))?;
            messaging
                .publish(DURABLE_TOPIC, &payload)
                .await
                .map_err(|e| format!("enqueuing durable email failed: {e}"))
        } else {
            // Non-blocking hand-off: a full queue is a spool-failure the guest sees,
            // never a stall.
            self.tx.try_send((profile, message)).map_err(|e| match e {
                tokio::sync::mpsc::error::TrySendError::Full(_) => {
                    "email spool is full (best-effort queue saturated)".to_string()
                }
                tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                    "email spool is shut down".to_string()
                }
            })
        }
    }
}

/// Deliver `msg` via `backend`, retrying up to `attempts` times with a small linear
/// backoff. Best-effort: a message still failing after the last attempt is dropped
/// (logged at `error`).
async fn deliver_with_retry(
    backend: &dyn SmtpBackend,
    profile: &EmailProfile,
    msg: &OutboundEmail,
    attempts: u32,
) {
    let mut last = String::new();
    for attempt in 1..=attempts {
        match backend.send(profile, msg).await {
            Ok(()) => return,
            Err(e) => {
                last = e;
                tracing::warn!(
                    project = %msg.project,
                    profile = %msg.profile,
                    attempt,
                    error = %last,
                    "best-effort email delivery attempt failed"
                );
                if attempt < attempts {
                    tokio::time::sleep(Duration::from_millis(500 * u64::from(attempt))).await;
                }
            }
        }
    }
    tracing::error!(
        project = %msg.project,
        profile = %msg.profile,
        error = %last,
        "best-effort email dropped after retries"
    );
}

/// The durable delivery worker: claim from the reserved topic, re-resolve the
/// profile host-side, deliver, and ack/nack — letting the messaging fabric handle
/// lease renewal, retry, and dead-lettering (operable via `boatramp dlq`).
async fn durable_worker(
    backend: Arc<dyn SmtpBackend>,
    messaging: Arc<dyn Messaging>,
    store: Arc<EmailProfileStore>,
) {
    loop {
        let claimed = match messaging
            .claim(
                DURABLE_TOPIC,
                DURABLE_LEASE,
                DURABLE_BATCH,
                DURABLE_MAX_ATTEMPTS,
            )
            .await
        {
            Ok(claimed) => claimed,
            Err(err) => {
                tracing::warn!(%err, "durable email claim failed");
                tokio::time::sleep(DURABLE_POLL).await;
                continue;
            }
        };
        if claimed.is_empty() {
            tokio::time::sleep(DURABLE_POLL).await;
            continue;
        }
        for msg in claimed {
            let outbound: OutboundEmail = match serde_json::from_slice(&msg.payload) {
                Ok(o) => o,
                Err(err) => {
                    // A corrupt payload will never parse — ack it away rather than
                    // redeliver-then-dead-letter the same garbage repeatedly.
                    tracing::warn!(id = %msg.id, %err, "dropping unparsable durable email");
                    let _ = messaging.ack(&msg).await;
                    continue;
                }
            };
            // Re-resolve the profile host-side (the sealed credentials never rode the
            // queue). A vanished profile is dropped; a transient store error retries.
            let profile = match store
                .get(
                    ProjectRef::new(outbound.project.as_str()),
                    &outbound.profile,
                )
                .await
            {
                Ok(Some(p)) => p,
                Ok(None) => {
                    tracing::warn!(
                        project = %outbound.project,
                        profile = %outbound.profile,
                        "durable email profile no longer exists; dropping"
                    );
                    let _ = messaging.ack(&msg).await;
                    continue;
                }
                Err(err) => {
                    tracing::warn!(%err, "resolving durable email profile failed; will retry");
                    let _ = messaging.nack(&msg).await;
                    continue;
                }
            };
            match backend.send(&profile, &outbound).await {
                Ok(()) => {
                    let _ = messaging.ack(&msg).await;
                }
                Err(err) => {
                    tracing::warn!(
                        id = %msg.id,
                        attempts = msg.attempts,
                        %err,
                        "durable email delivery failed; redelivering (dead-letters after max attempts)"
                    );
                    let _ = messaging.nack(&msg).await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::email_config::SmtpSecurity;
    use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
    use boatramp_core::kv::MemoryKv;
    use std::sync::Mutex;

    /// An identity "envelope" — the store needs one; sealing isn't under test here.
    struct NoopEnvelope;
    #[async_trait::async_trait]
    impl KeyEnvelope for NoopEnvelope {
        async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(p.to_vec())
        }
        async fn unwrap(&self, c: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(c.to_vec())
        }
    }

    /// A backend that just counts (and always succeeds) — the drain calls it.
    #[derive(Default)]
    struct CountingBackend {
        sent: Mutex<usize>,
    }
    #[async_trait::async_trait]
    impl SmtpBackend for CountingBackend {
        async fn send(&self, _p: &EmailProfile, _m: &OutboundEmail) -> Result<(), String> {
            *self.sent.lock().unwrap() += 1;
            Ok(())
        }
    }

    fn outbound(project: &str) -> OutboundEmail {
        OutboundEmail {
            project: project.into(),
            profile: "default".into(),
            to: vec!["d@example.org".into()],
            cc: vec![],
            bcc: vec![],
            from: "no-reply@example.com".into(),
            reply_to: None,
            subject: "hi".into(),
            text: Some("x".into()),
            html: None,
            durable: false,
        }
    }

    fn profile() -> EmailProfile {
        EmailProfile {
            host: "localhost".into(),
            port: 25,
            security: SmtpSecurity::Plaintext,
            username: None,
            password: None,
            from: "no-reply@example.com".into(),
            durable: false,
        }
    }

    #[tokio::test]
    async fn per_project_send_rate_is_enforced_and_is_per_project() {
        let store = Arc::new(EmailProfileStore::new(
            Arc::new(MemoryKv::new()),
            Arc::new(NoopEnvelope),
        ));
        let spool = NodeEmailSpool::spawn(Arc::new(CountingBackend::default()), None, store);
        // The token bucket starts full at the burst; the first ~burst sends pass and
        // then (with sub-second elapsed, so no meaningful refill) the next is rejected.
        let mut ok = 0usize;
        let mut limited = false;
        for _ in 0..(EMAIL_SEND_BURST + 5) {
            match spool.enqueue(profile(), outbound("acme")).await {
                Ok(()) => ok += 1,
                Err(e) => {
                    assert!(e.contains("rate exceeded"), "unexpected error: {e}");
                    limited = true;
                }
            }
        }
        assert!(
            (EMAIL_SEND_BURST as usize..=EMAIL_SEND_BURST as usize + 1).contains(&ok),
            "expected ~{EMAIL_SEND_BURST} to pass, got {ok}"
        );
        assert!(
            limited,
            "a runaway send loop must eventually be rate-limited"
        );
        // A different project has its own bucket — acme's spend doesn't throttle it.
        assert!(
            spool.enqueue(profile(), outbound("globex")).await.is_ok(),
            "the rate limit must be per-project, not global"
        );
    }
}
