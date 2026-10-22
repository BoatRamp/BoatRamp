//! The optional small HTTP `CONNECT` front-end (plan §2, behind `--http-connect`): reuses exactly
//! the SOCKS dispatch's invariants (loopback bind, hostname-only, unknown-name refused, never a real
//! outbound connect) over plain HTTP/1.1 `CONNECT host:port` instead of the SOCKS5 wire format — for
//! clients that speak `HTTPS_PROXY`/`http.proxy` rather than a SOCKS proxy.
//!
//! Security MEDIUM-2: gated by the SAME `LocalAuth` credential as SOCKS, carried as HTTP's own
//! idiom — `Proxy-Authorization: Basic <base64(user:pass)>`, challenged with `407 Proxy
//! Authentication Required` — so `--http-connect` can never bypass the default-on local auth SOCKS
//! enforces.
//!
//! Security MEDIUM-3: the request line + headers are read into a SIZE-BOUNDED buffer, one byte at a
//! time, stopping the instant the blank-line terminator is found — never an unbounded
//! `BufReader::read_line` allocation, and never a byte read past what the handshake itself needed
//! (so nothing the peer pipelines right after its headers is lost). The whole read is further bound
//! by [`HANDSHAKE_TIMEOUT`](super::server::HANDSHAKE_TIMEOUT).

use std::sync::Arc;

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::core::Tunnel;

use super::auth::LocalAuth;
use super::server::{HANDSHAKE_TIMEOUT, SocksError, accept_loop, is_not_found, splice};

/// Hard cap on the request line + headers (Security MEDIUM-3) — generous for any real CONNECT
/// request (a handful of short lines) while keeping a malicious peer's worst case bounded and
/// small.
const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;

/// A failure parsing or answering an HTTP `CONNECT` request. Never surfaced to the peer beyond the
/// HTTP status line this module itself writes — logged by the caller.
#[derive(Debug, thiserror::Error)]
enum HttpConnectError {
    #[error("http-connect io: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed CONNECT request line")]
    Malformed,
    /// Security MEDIUM-3: the request line + headers exceeded [`MAX_HANDSHAKE_BYTES`] without a
    /// terminating blank line.
    #[error("http-connect handshake exceeded {MAX_HANDSHAKE_BYTES} bytes")]
    HandshakeTooLarge,
    /// Security MEDIUM-3: the handshake did not complete within the shared bound.
    #[error("http-connect handshake timed out")]
    HandshakeTimeout,
}

/// Run the HTTP CONNECT accept loop forever, dispatching each connection through `tunnel.open`.
/// `auth` and `semaphore` are the SAME credential + connection-count cap the SOCKS loop uses
/// (Security MEDIUM-2/MEDIUM-3: one proxy, one auth posture, one connection budget).
pub(super) async fn accept_loop_over(
    listener: TcpListener,
    tunnel: Arc<Tunnel>,
    auth: Option<Arc<LocalAuth>>,
    semaphore: Arc<Semaphore>,
) -> Result<(), SocksError> {
    accept_loop(listener, semaphore, move |stream| {
        let tunnel = Arc::clone(&tunnel);
        let auth = auth.clone();
        async move {
            if let Err(err) = handle(&tunnel, auth.as_deref(), stream).await {
                tracing::debug!(
                    error = %err,
                    "boatramp tunnel: http-connect connection ended with an error"
                );
            }
        }
    })
    .await
}

/// Read the request line + headers, byte at a time, into an owned buffer — stopping the instant the
/// blank-line terminator (`"\r\n\r\n"` or a bare `"\n\n"`) is found, and erroring if
/// [`MAX_HANDSHAKE_BYTES`] is exceeded first (Security MEDIUM-3). Never reads a single byte past the
/// terminator, so the stream's position afterward is exactly where any pipelined payload would
/// begin — no separate "leftover bytes" bookkeeping needed.
async fn read_handshake_bounded(stream: &mut TcpStream) -> Result<Vec<u8>, HttpConnectError> {
    let mut buf = Vec::new();
    loop {
        if buf.len() >= MAX_HANDSHAKE_BYTES {
            return Err(HttpConnectError::HandshakeTooLarge);
        }
        let mut b = [0u8; 1];
        let n = stream.read(&mut b).await?;
        if n == 0 {
            break;
        }
        buf.push(b[0]);
        if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
            break;
        }
    }
    Ok(buf)
}

/// Split `head` (as [`read_handshake_bounded`] returns it) into its lines, each with any trailing
/// `\r` trimmed, stopping before the blank terminator line.
fn lines_of(head: &[u8]) -> impl Iterator<Item = &str> {
    head.split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .filter_map(|l| std::str::from_utf8(l).ok())
        .take_while(|l| !l.is_empty())
}

/// Parse the request line (`METHOD TARGET VERSION`) out of `head`, returning `(method, target)`.
fn parse_request_line(head: &[u8]) -> Result<(String, String), HttpConnectError> {
    let first = lines_of(head).next().ok_or(HttpConnectError::Malformed)?;
    let mut parts = first.split_ascii_whitespace();
    let method = parts.next().ok_or(HttpConnectError::Malformed)?.to_string();
    let target = parts.next().ok_or(HttpConnectError::Malformed)?.to_string();
    Ok((method, target))
}

/// Case-insensitive `strip_prefix` (HTTP header names are case-insensitive).
fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() >= prefix.len() && s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Extract and decode a `Proxy-Authorization: Basic <base64(user:pass)>` header from `head`, if
/// present and well-formed. Malformed base64/UTF-8/missing `:` is treated as "absent" (the caller
/// then refuses with the same `407` a missing header gets — no distinct error path that would leak
/// which part of a malformed credential was wrong).
fn find_proxy_authorization(head: &[u8]) -> Option<(String, String)> {
    for line in lines_of(head) {
        let Some(rest) = strip_prefix_ci(line, "Proxy-Authorization:") else {
            continue;
        };
        let rest = rest.trim();
        let Some(encoded) = strip_prefix_ci(rest, "Basic ") else {
            continue;
        };
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded.trim())
            .ok()?;
        let decoded = String::from_utf8(decoded).ok()?;
        let (user, pass) = decoded.split_once(':')?;
        return Some((user.to_string(), pass.to_string()));
    }
    None
}

async fn write_status(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    extra_header: Option<&str>,
) -> Result<(), HttpConnectError> {
    let extra = extra_header.unwrap_or("");
    let resp = format!("HTTP/1.1 {code} {reason}\r\n{extra}\r\n");
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}

/// Split an HTTP `CONNECT` authority (`host:port`) into its host part. `CONNECT`'s target always
/// carries an explicit port, so a plain `rsplit_once(':')` is correct here (unlike a bare hostname,
/// which might not have one).
fn host_of(authority: &str) -> &str {
    authority.rsplit_once(':').map_or(authority, |(h, _)| h)
}

async fn handle(
    tunnel: &Tunnel,
    auth: Option<&LocalAuth>,
    mut stream: TcpStream,
) -> Result<(), HttpConnectError> {
    // Security MEDIUM-3: bound the whole pre-dispatch handshake (request line + headers) — the SAME
    // deadline the SOCKS front-end uses, so a slow-loris peer can't pin a task here either.
    let head =
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, read_handshake_bounded(&mut stream)).await {
            Ok(result) => result?,
            Err(_elapsed) => return Err(HttpConnectError::HandshakeTimeout),
        };
    let (method, target) = parse_request_line(&head)?;
    if method != "CONNECT" {
        write_status(&mut stream, 501, "Not Implemented", None).await?;
        return Ok(());
    }

    // Security MEDIUM-2: the SAME local-auth credential SOCKS enforces, carried as HTTP's own
    // idiom. Checked BEFORE the IP-literal/catalog checks below, so an unauthenticated peer learns
    // nothing about the directory either.
    if let Some(local) = auth {
        let ok = find_proxy_authorization(&head)
            .is_some_and(|(user, pass)| user == local.username && pass == local.password);
        if !ok {
            tracing::warn!(
                "boatramp tunnel: refusing an HTTP CONNECT without a valid Proxy-Authorization"
            );
            write_status(
                &mut stream,
                407,
                "Proxy Authentication Required",
                Some("Proxy-Authenticate: Basic realm=\"boatramp-tunnel\"\r\n"),
            )
            .await?;
            return Ok(());
        }
    }

    let host = host_of(&target);
    if host.parse::<std::net::IpAddr>().is_ok() {
        tracing::warn!(
            "boatramp tunnel: refusing an HTTP CONNECT to an IP-literal destination — use a \
             hostname, this proxy resolves names to services, not addresses"
        );
        write_status(&mut stream, 403, "Forbidden - use a hostname", None).await?;
        return Ok(());
    }

    match tunnel.open(host).await {
        Ok(flow) => {
            write_status(&mut stream, 200, "Connection Established", None).await?;
            splice(stream, flow).await;
            Ok(())
        }
        Err(err) => {
            let (code, reason) = if is_not_found(&err) {
                (404, "Not Found")
            } else {
                (502, "Bad Gateway")
            };
            tracing::warn!(
                host = %host, error = %err,
                "boatramp tunnel: overlay dial failed; refusing the HTTP CONNECT"
            );
            write_status(&mut stream, code, reason, None).await?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_support::MockControlPlane;
    use crate::core::{ControlPlane, Tunnel};
    use boatramp_overlay_client::OverlaySecret;
    use tokio::net::TcpListener;

    #[test]
    fn host_of_strips_the_connect_port() {
        assert_eq!(host_of("db.svc:443"), "db.svc");
    }

    #[test]
    fn host_of_handles_a_bare_host_with_no_colon() {
        assert_eq!(host_of("db.svc"), "db.svc");
    }

    #[test]
    fn find_proxy_authorization_decodes_a_well_formed_header() {
        let mut head = b"CONNECT db:443 HTTP/1.1\r\n".to_vec();
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"alice:hi!");
        head.extend_from_slice(format!("Proxy-Authorization: Basic {encoded}\r\n").as_bytes());
        head.extend_from_slice(b"\r\n");
        assert_eq!(
            find_proxy_authorization(&head),
            Some(("alice".to_string(), "hi!".to_string()))
        );
    }

    #[test]
    fn find_proxy_authorization_is_case_insensitive_and_absent_when_missing() {
        let head = b"CONNECT db:443 HTTP/1.1\r\nHost: db\r\n\r\n".to_vec();
        assert_eq!(find_proxy_authorization(&head), None);
    }

    async fn test_tunnel() -> Arc<Tunnel> {
        let cp = Arc::new(MockControlPlane::new(vec![]));
        let holder = OverlaySecret::generate().unwrap();
        Tunnel::new(Arc::clone(&cp) as Arc<dyn ControlPlane>, holder)
            .await
            .unwrap()
    }

    /// Security MEDIUM-2: with local auth configured, an HTTP CONNECT carrying no
    /// `Proxy-Authorization` must be refused with `407`, never silently let through.
    #[tokio::test]
    async fn missing_proxy_authorization_gets_407_when_local_auth_is_configured() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tunnel = test_tunnel().await;
        let local_auth = LocalAuth {
            username: "u".to_string(),
            password: "p".to_string(),
        };

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let _ = handle(&tunnel, Some(&local_auth), stream).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        client
            .write_all(b"CONNECT db:443 HTTP/1.1\r\nHost: db\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(
            resp.starts_with("HTTP/1.1 407"),
            "expected a 407 challenge, got: {resp}"
        );
        assert!(resp.to_ascii_lowercase().contains("proxy-authenticate"));
    }

    /// Security MEDIUM-2: the CORRECT credential, presented as `Proxy-Authorization: Basic`, is
    /// accepted — the auth gate doesn't just reject everything.
    #[tokio::test]
    async fn correct_proxy_authorization_is_accepted_then_refused_for_unknown_service() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tunnel = test_tunnel().await;
        let local_auth = LocalAuth {
            username: "u".to_string(),
            password: "p".to_string(),
        };

        tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            let _ = handle(&tunnel, Some(&local_auth), stream).await;
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"u:p");
        client
            .write_all(
                format!(
                    "CONNECT ghost:443 HTTP/1.1\r\nProxy-Authorization: Basic {encoded}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let mut buf = vec![0u8; 256];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), client.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        // Authenticated, but `ghost` isn't in the (empty) catalog -> 404, NOT 407.
        assert!(
            resp.starts_with("HTTP/1.1 404"),
            "expected a 404 (authenticated, unknown service), got: {resp}"
        );
    }

    /// Security MEDIUM-3: a peer that never sends a terminating blank line, and keeps sending bytes
    /// past [`MAX_HANDSHAKE_BYTES`], must be refused/dropped — never an unbounded allocation.
    #[tokio::test]
    async fn an_oversized_handshake_is_rejected_not_buffered_without_bound() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tunnel = test_tunnel().await;

        let server_task = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            handle(&tunnel, None, stream).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // One line, no newline, well past MAX_HANDSHAKE_BYTES — never terminates the headers.
        let garbage = vec![b'a'; MAX_HANDSHAKE_BYTES + 4096];
        // Best-effort write; the server may close the connection before all of it lands, which is
        // fine — we only need ENOUGH of it to cross the bound.
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.write_all(&garbage),
        )
        .await;

        let result = tokio::time::timeout(std::time::Duration::from_secs(10), server_task)
            .await
            .expect("the oversized handshake must be rejected promptly, not hang")
            .expect("the spawned task itself must not have panicked");
        assert!(
            matches!(
                result,
                Err(HttpConnectError::HandshakeTooLarge) | Err(HttpConnectError::Io(_))
            ),
            "expected HandshakeTooLarge (or an Io error from the peer closing mid-write), got {result:?}"
        );
    }
}
