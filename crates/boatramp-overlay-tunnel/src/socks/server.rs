//! The SOCKS5 accept loop + request dispatch (plan §2): the only place a destination name is turned
//! into an [`crate::core::Tunnel::open`] call. `codec.rs` is pure framing with zero overlay
//! knowledge; `auth.rs` is pure credential generation/persistence; this module is the thin glue.
//!
//! **Open-relay prevention (plan §5), by construction:** every code path in [`handle`] either (a)
//! calls `tunnel.open(name)` for a hostname the codec parsed, or (b) writes a refusal reply and
//! returns. There is no third path — no `TcpStream::connect`/`UdpSocket` or any other call to a
//! caller-controlled remote address anywhere in this file. An IP-literal destination, an unknown
//! service name, and an unsupported command are ALL refused before `open` is ever reached.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

use crate::core::{Tunnel, TunnelError};

use super::auth::LocalAuth;
use super::codec::{self, AddrSpec, AuthMethod, CodecError, Command};

/// How long a connection's pre-dispatch handshake may take before it is dropped — the SOCKS
/// greeting + optional auth + the `CONNECT` request itself, or (in `http_connect.rs`) the HTTP
/// request line + headers. Security MEDIUM-3: bounds a slow-loris peer from pinning a task (and a
/// connection-semaphore permit) indefinitely. Deliberately does NOT bound the dial/splice phase
/// that follows a successful handshake — a long-lived tunnel is the whole point of this proxy.
pub(super) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default cap on concurrent accepted connections (SOCKS + HTTP CONNECT combined) absent an
/// explicit override. Security MEDIUM-3: bounds a local attacker opening connections faster than
/// they are served from exhausting file descriptors / memory.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// A failure standing up or running the SOCKS5 front-end.
#[derive(Debug, thiserror::Error)]
pub enum SocksError {
    #[error("binding {0}: {1}")]
    Bind(SocketAddr, #[source] std::io::Error),
    #[error("accept: {0}")]
    Accept(#[source] std::io::Error),
}

/// A bound SOCKS5 (+ optional HTTP CONNECT) front-end, ready to [`serve`](Self::serve).
pub struct SocksServer {
    tunnel: Arc<Tunnel>,
    auth: Option<Arc<LocalAuth>>,
    socks_listener: TcpListener,
    http_listener: Option<TcpListener>,
    max_connections: usize,
}

impl SocksServer {
    /// Bind the SOCKS listener at `socks_addr` and, if `http_connect_addr` is given, a second
    /// listener there for the optional small HTTP `CONNECT` front-end (plan §2) — the SAME `auth`
    /// credential gates both (Security MEDIUM-2: there is no "SOCKS-authenticated but HTTP-open"
    /// posture). Binding (not serving) is split out so a caller can print the actually-bound
    /// address (relevant for `:0`) before blocking in [`serve`](Self::serve). `max_connections`
    /// caps concurrent accepted connections across BOTH front-ends combined (Security MEDIUM-3) —
    /// pass [`DEFAULT_MAX_CONNECTIONS`] absent a reason to choose otherwise.
    pub async fn bind(
        tunnel: Arc<Tunnel>,
        auth: Option<LocalAuth>,
        socks_addr: SocketAddr,
        http_connect_addr: Option<SocketAddr>,
        max_connections: usize,
    ) -> Result<Self, SocksError> {
        let socks_listener = TcpListener::bind(socks_addr)
            .await
            .map_err(|e| SocksError::Bind(socks_addr, e))?;
        let http_listener = match http_connect_addr {
            Some(addr) => Some(
                TcpListener::bind(addr)
                    .await
                    .map_err(|e| SocksError::Bind(addr, e))?,
            ),
            None => None,
        };
        Ok(Self {
            tunnel,
            auth: auth.map(Arc::new),
            socks_listener,
            http_listener,
            max_connections,
        })
    }

    /// The actually-bound SOCKS address (resolves `:0` to the OS-assigned port).
    pub fn socks_addr(&self) -> std::io::Result<SocketAddr> {
        self.socks_listener.local_addr()
    }

    /// The actually-bound HTTP CONNECT address, if that front-end was requested.
    pub fn http_connect_addr(&self) -> std::io::Result<Option<SocketAddr>> {
        self.http_listener
            .as_ref()
            .map(TcpListener::local_addr)
            .transpose()
    }

    /// Serve both accept loops until one of them hits a fatal accept error. Each accepted
    /// connection is handled on its own task, gated by a shared connection-count semaphore; a
    /// single connection's failure never takes down the listener.
    pub async fn serve(self) -> Result<(), SocksError> {
        let Self {
            tunnel,
            auth,
            socks_listener,
            http_listener,
            max_connections,
        } = self;
        let semaphore = Arc::new(Semaphore::new(max_connections));

        let socks_loop = {
            let tunnel = Arc::clone(&tunnel);
            let auth = auth.clone();
            accept_loop(socks_listener, Arc::clone(&semaphore), move |stream| {
                let tunnel = Arc::clone(&tunnel);
                let auth = auth.clone();
                async move {
                    if let Err(err) = handle(&tunnel, auth.as_deref(), stream).await {
                        tracing::debug!(error = %err, "boatramp tunnel: socks connection ended with an error");
                    }
                }
            })
        };

        match http_listener {
            Some(http_listener) => {
                let http_loop =
                    super::http_connect::accept_loop_over(http_listener, tunnel, auth, semaphore);
                tokio::try_join!(socks_loop, http_loop)?;
            }
            None => socks_loop.await?,
        }
        Ok(())
    }
}

/// Run `listener.accept()` forever, spawning `handler(stream)` per connection — gated by
/// `semaphore`: a permit is acquired BEFORE spawning (a saturated cap backpressures the accept loop
/// itself rather than piling up unbounded spawned tasks waiting on a permit) and held for the
/// connection's whole lifetime, released automatically when its task ends. Shared by the SOCKS and
/// HTTP CONNECT loops (the latter lives in `http_connect.rs` and calls this too) — one semaphore,
/// passed in by the caller, caps BOTH front-ends' connections together.
pub(super) async fn accept_loop<F, Fut>(
    listener: TcpListener,
    semaphore: Arc<Semaphore>,
    handler: F,
) -> Result<(), SocksError>
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    loop {
        let (stream, _peer) = listener.accept().await.map_err(SocksError::Accept)?;
        // `acquire_owned` only errors if the semaphore is `close()`d, which this code never does —
        // an invariant WE control. (Unlike the handshake's auth-method selection, which used to
        // reach a now-removed `.expect()` on attacker-controlled input — see `perform_handshake`.)
        let permit = Arc::clone(&semaphore)
            .acquire_owned()
            .await
            .expect("the connection semaphore is never closed");
        let fut = handler(stream);
        tokio::spawn(async move {
            let _permit = permit;
            fut.await;
        });
    }
}

/// Handle one accepted SOCKS5 connection end to end: greeting/auth, the `CONNECT` request, dispatch,
/// splice. Every return (including every `Ok(())`) represents either a completed/spliced flow or a
/// deliberately-refused request with its reply already written — never a silent fall-through.
async fn handle(
    tunnel: &Tunnel,
    auth: Option<&LocalAuth>,
    stream: TcpStream,
) -> Result<(), CodecError> {
    handle_with_handshake_timeout(tunnel, auth, stream, HANDSHAKE_TIMEOUT).await
}

/// [`handle`], with the handshake bound injectable — the production entry point always passes
/// [`HANDSHAKE_TIMEOUT`]; tests pass a short one so the timeout path doesn't cost real wall-clock
/// seconds per run.
async fn handle_with_handshake_timeout(
    tunnel: &Tunnel,
    auth: Option<&LocalAuth>,
    mut stream: TcpStream,
    handshake_timeout: Duration,
) -> Result<(), CodecError> {
    // Security MEDIUM-3: bound the whole pre-dispatch handshake — NOT the dial/splice that follows
    // a successful one.
    let request =
        match tokio::time::timeout(handshake_timeout, perform_handshake(&mut stream, auth)).await {
            Ok(result) => result?,
            Err(_elapsed) => return Err(CodecError::HandshakeTimeout),
        };

    if request.command != Command::Connect {
        tracing::debug!(command = ?request.command, "boatramp tunnel: refusing a non-CONNECT SOCKS command");
        codec::write_reply(&mut stream, codec::reply::COMMAND_NOT_SUPPORTED).await?;
        return Ok(());
    }

    let name = match request.addr {
        AddrSpec::Domainname(name) => name,
        AddrSpec::Ipv4(_) | AddrSpec::Ipv6(_) => {
            tracing::warn!(
                "boatramp tunnel: refusing a SOCKS CONNECT to an IP-literal destination — use a \
                 hostname, this proxy resolves names to services, not addresses"
            );
            codec::write_reply(&mut stream, codec::reply::NOT_ALLOWED_BY_RULESET).await?;
            return Ok(());
        }
    };

    match tunnel.open(&name).await {
        Ok(flow) => {
            codec::write_reply(&mut stream, codec::reply::SUCCEEDED).await?;
            splice(stream, flow).await;
            Ok(())
        }
        Err(err) => {
            // Service-not-found and every other overlay/control-plane failure both refuse the SAME
            // way at the SOCKS layer: a reply is written and the connection closes. NEVER does an
            // unresolved/failed name fall through to a real outbound connect (the open-relay
            // invariant plan §5 requires) — `open` is the only thing that could ever reach the
            // network here, and it already failed.
            let rep = if is_not_found(&err) {
                codec::reply::HOST_UNREACHABLE
            } else {
                codec::reply::GENERAL_FAILURE
            };
            tracing::warn!(name = %name, error = %err, "boatramp tunnel: overlay dial failed; refusing the SOCKS CONNECT");
            codec::write_reply(&mut stream, rep).await?;
            Ok(())
        }
    }
}

/// The greeting + (if required) auth + the `CONNECT` request itself — the portion [`handle`] bounds
/// with [`HANDSHAKE_TIMEOUT`].
async fn perform_handshake(
    stream: &mut TcpStream,
    auth: Option<&LocalAuth>,
) -> Result<codec::Request, CodecError> {
    let required = auth.map(|_| AuthMethod::UserPass);
    let method = codec::negotiate_auth(stream, required).await?;
    if method == AuthMethod::UserPass {
        match auth {
            Some(a) => codec::verify_userpass(stream, &a.username, &a.password).await?,
            // Security LOW-1: `negotiate_auth` never selects `UserPass` when `require` is `None`
            // (no credential store to check against) — this arm is unreachable from any
            // attacker-controlled input. Refuse rather than panic if that invariant is ever
            // violated by a future change to the codec.
            None => return Err(CodecError::NoAcceptableAuthMethod),
        }
    }
    codec::read_request(stream).await
}

/// Whether `err` is specifically "service not in the directory" (plan §2's exact `0x04` case),
/// versus every other overlay/control-plane failure (which refuses with the generic `0x01`).
/// `pub(super)` — shared with the HTTP CONNECT front-end's own analogous status-code choice.
pub(super) fn is_not_found(err: &TunnelError) -> bool {
    matches!(
        err,
        TunnelError::ControlPlane(crate::core::ControlPlaneError::NotFound(_))
    )
}

/// Splice the local client stream with the opened overlay [`boatramp_overlay_client::Flow`] until
/// either side closes, then await the flow's own finish to surface (log) any late transport error.
/// Generic over the local stream type (`pub(super)`, shared with the HTTP CONNECT front-end).
pub(super) async fn splice<L>(mut local: L, mut flow: boatramp_overlay_client::Flow)
where
    L: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if let Err(err) = tokio::io::copy_bidirectional(&mut local, &mut flow).await {
        tracing::debug!(error = %err, "boatramp tunnel: socks splice ended with an io error");
    }
    if let Err(err) = flow.finish().await {
        tracing::debug!(error = %err, "boatramp tunnel: overlay flow finished with an error");
    }
}

#[cfg(test)]
mod unit_tests {
    use super::*;
    use crate::core::test_support::MockControlPlane;
    use boatramp_overlay_client::OverlaySecret;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn test_tunnel() -> Arc<Tunnel> {
        let cp = Arc::new(MockControlPlane::new(vec![]));
        let holder = OverlaySecret::generate().unwrap();
        Tunnel::new(
            Arc::clone(&cp) as Arc<dyn crate::core::ControlPlane>,
            holder,
        )
        .await
        .unwrap()
    }

    /// Security MEDIUM-3: a client that connects and then sends NOTHING must be dropped within the
    /// handshake bound, not held forever. Real `TcpStream`s on both ends (not a duplex mock) — the
    /// bound is injected short so the test doesn't cost real wall-clock seconds.
    #[tokio::test]
    async fn handshake_timeout_fires_on_a_silent_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tunnel = test_tunnel().await;

        let server_task = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            handle_with_handshake_timeout(&tunnel, None, stream, Duration::from_millis(100)).await
        });

        // Connect but never write a byte — the greeting read must time out, not hang.
        let _client = TcpStream::connect(addr).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("the handshake timeout must fire well within the test's own outer bound")
            .unwrap();
        assert!(
            matches!(result, Err(CodecError::HandshakeTimeout)),
            "expected a HandshakeTimeout, got {result:?}"
        );
    }

    /// Security LOW-1: with NO local-auth credential store configured, a client offering ONLY
    /// `UserPass` must be refused (`0xFF`), never silently "authenticated" against nothing — and
    /// never panic. Drives the real `handle` path end to end over a `TcpStream` pair.
    #[tokio::test]
    async fn a_userpass_only_offer_with_no_local_auth_is_refused_not_panicked() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tunnel = test_tunnel().await;

        let server_task = tokio::spawn(async move {
            let (stream, _peer) = listener.accept().await.unwrap();
            // `auth: None` — no local-auth credential store, exactly `--no-local-auth`'s posture.
            handle(&tunnel, None, stream).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        // Offer ONLY user/pass (0x02) — the exact input that used to select `UserPass` via
        // `offered.first()` and then panic on `auth.expect(...)`.
        client.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
        let mut reply = [0u8; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(
            reply,
            [0x05, 0xFF],
            "no acceptable method must be reported, not a selected UserPass"
        );

        let result = tokio::time::timeout(Duration::from_secs(5), server_task)
            .await
            .expect("the task must finish (not panic/hang)")
            .expect("the spawned task itself must not have panicked");
        assert!(matches!(result, Err(CodecError::NoAcceptableAuthMethod)));
    }
}
