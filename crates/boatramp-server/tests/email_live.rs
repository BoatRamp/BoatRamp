//! Live-seam gate for the per-project `email` capability: prove a message actually
//! **delivers over SMTP** through the real `lettre` backend + the node spool — the
//! one thing the unit tests (which use a fake backend) can't cover. Wired into
//! `.github/workflows/capability.yml` as a hard gate that asserts the success
//! marker, so a silent skip fails the job (the anti-`#[ignore]`-as-evidence rule).
//!
//! No privileges, no secrets, no network egress: an in-process SMTP **sink** binds a
//! loopback port on the ephemeral runner and captures the delivered message. Both
//! spool paths are exercised end to end — best-effort (in-memory drain → lettre) and
//! durable (messaging fabric → worker re-resolves the profile host-side → lettre).
//!
//! `#[ignore]`d (it drives real sockets + the ~2s durable poll); run it with
//! `cargo test -p boatramp-server --features email --test email_live -- --ignored`.

#![cfg(feature = "email")]

use std::sync::Arc;
use std::time::Duration;

use boatramp_core::email_config::{EmailProfile, EmailProfileStore, SmtpSecurity};
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::kv::MemoryKv;
use boatramp_core::messaging::{LogMessaging, Messaging};
use boatramp_core::project::ProjectRef;
use boatramp_handlers::{LettreBackend, OutboundEmail};
use boatramp_server::NodeEmailSpool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// An identity envelope — the store needs one; sealing isn't under test here.
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

/// Start a minimal loopback SMTP sink. Returns the bound port and a receiver that
/// yields the full client transcript (commands + DATA) of each delivered message.
/// Speaks just enough ESMTP for lettre's plaintext, no-AUTH path: greeting, EHLO,
/// MAIL/RCPT, DATA (read to the lone `.`), QUIT.
async fn spawn_smtp_sink() -> (u16, tokio::sync::mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sink");
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = tokio::sync::mpsc::channel::<String>(8);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                break;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let (r, mut w) = socket.into_split();
                let mut reader = BufReader::new(r);
                let mut transcript = String::new();
                if w.write_all(b"220 sink ESMTP\r\n").await.is_err() {
                    return;
                }
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    transcript.push_str(&line);
                    let cmd = line.trim_end().to_ascii_uppercase();
                    let reply: &[u8] = if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                        b"250 sink\r\n"
                    } else if cmd == "DATA" {
                        // Enter DATA mode: accumulate until a lone `.`, then 250.
                        let _ = w
                            .write_all(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                            .await;
                        loop {
                            line.clear();
                            match reader.read_line(&mut line).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                            if line.trim_end() == "." {
                                break;
                            }
                            transcript.push_str(&line);
                        }
                        b"250 OK queued\r\n"
                    } else if cmd == "QUIT" {
                        let _ = w.write_all(b"221 Bye\r\n").await;
                        break;
                    } else {
                        // MAIL FROM / RCPT TO / RSET / NOOP / anything: be lenient.
                        b"250 OK\r\n"
                    };
                    if w.write_all(reply).await.is_err() {
                        break;
                    }
                }
                let _ = tx.send(transcript).await;
            });
        }
    });
    (port, rx)
}

fn outbound(subject: &str, durable: bool) -> OutboundEmail {
    OutboundEmail {
        project: "acme".into(),
        profile: "default".into(),
        to: vec!["dest@example.org".into()],
        cc: vec![],
        bcc: vec![],
        from: "no-reply@example.com".into(),
        reply_to: None,
        subject: subject.into(),
        text: Some("hello-live".into()),
        html: Some("<p>hello-live</p>".into()),
        durable,
    }
}

#[tokio::test]
#[ignore = "live SMTP seam — runs in capability.yml (needs a loopback sink + the ~2s durable poll)"]
async fn live_email_delivers_over_real_smtp_best_effort_and_durable() {
    let (port, mut rx) = spawn_smtp_sink().await;

    // A `default` profile for `acme` pointing at the sink (plaintext, no AUTH). The
    // durable worker re-resolves this from the store by (project, profile).
    let store = Arc::new(EmailProfileStore::new(
        Arc::new(MemoryKv::new()),
        Arc::new(NoopEnvelope),
    ));
    let profile = EmailProfile {
        host: "127.0.0.1".into(),
        port,
        security: SmtpSecurity::Plaintext,
        username: None,
        password: None,
        from: "no-reply@example.com".into(),
        durable: false,
    };
    store
        .set(ProjectRef::new("acme"), "default", &profile)
        .await
        .expect("set profile");

    // A real messaging fabric for the durable path, and a REAL lettre backend that
    // permits the loopback relay (the SSRF gate is off for this test double).
    let storage = Arc::new(boatramp_storage::FsStorage::new(std::env::temp_dir()));
    let messaging: Arc<dyn Messaging> =
        Arc::new(LogMessaging::new(storage, Arc::new(MemoryKv::new())));
    let backend = Arc::new(LettreBackend::new(true));
    let spool = NodeEmailSpool::spawn(backend, Some(messaging), store.clone());

    // Best-effort (drained in-memory, delivered ~immediately).
    spool
        .enqueue(profile.clone(), outbound("Live gate be", false))
        .await
        .expect("enqueue best-effort");
    // Durable (published to the fabric; the worker claims + re-resolves + delivers).
    spool
        .enqueue(profile.clone(), outbound("Live gate durable", true))
        .await
        .expect("enqueue durable");

    // Collect BOTH deliveries at the sink (best-effort fast; durable within ~2-4s).
    let mut transcripts = Vec::new();
    for _ in 0..2 {
        let t = tokio::time::timeout(Duration::from_secs(20), rx.recv())
            .await
            .expect("timed out waiting for an SMTP delivery")
            .expect("sink channel closed");
        transcripts.push(t);
    }
    let all = transcripts.join("\n----\n");

    // Envelope + headers + body arrived over the wire on both paths.
    assert!(
        all.contains("no-reply@example.com"),
        "MAIL FROM missing:\n{all}"
    );
    assert!(all.contains("dest@example.org"), "RCPT TO missing:\n{all}");
    assert!(
        all.contains("Live gate be"),
        "best-effort subject missing:\n{all}"
    );
    assert!(
        all.contains("Live gate durable"),
        "durable subject missing:\n{all}"
    );
    assert!(
        all.matches("hello-live").count() >= 2,
        "body missing on a path:\n{all}"
    );

    // Printed ONLY after both paths delivered — the capability gate's success marker.
    println!(
        "EMAIL LIVE SEND OK: best-effort + durable delivered over real SMTP to the loopback sink"
    );
}
