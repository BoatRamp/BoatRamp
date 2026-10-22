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

use tokio::net::{TcpListener, TcpStream};

use crate::core::{Tunnel, TunnelError};

use super::auth::LocalAuth;
use super::codec::{self, AddrSpec, AuthMethod, CodecError, Command};

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
}

impl SocksServer {
    /// Bind the SOCKS listener at `socks_addr` and, if `http_connect_addr` is given, a second
    /// listener there for the optional small HTTP `CONNECT` front-end (plan §2). Binding (not
    /// serving) is split out so a caller can print the actually-bound address (relevant for `:0`)
    /// before blocking in [`serve`](Self::serve).
    pub async fn bind(
        tunnel: Arc<Tunnel>,
        auth: Option<LocalAuth>,
        socks_addr: SocketAddr,
        http_connect_addr: Option<SocketAddr>,
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
    /// connection is handled on its own task; a single connection's failure never takes down the
    /// listener.
    pub async fn serve(self) -> Result<(), SocksError> {
        let Self {
            tunnel,
            auth,
            socks_listener,
            http_listener,
        } = self;

        let socks_loop = {
            let tunnel = Arc::clone(&tunnel);
            let auth = auth.clone();
            accept_loop(socks_listener, move |stream| {
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
                let http_loop = super::http_connect::accept_loop_over(http_listener, tunnel);
                tokio::try_join!(socks_loop, http_loop)?;
            }
            None => socks_loop.await?,
        }
        Ok(())
    }
}

/// Run `listener.accept()` forever, spawning `handler(stream)` per connection. Shared by the SOCKS
/// and HTTP CONNECT loops (the latter lives in `http_connect.rs` and calls this too).
pub(super) async fn accept_loop<F, Fut>(listener: TcpListener, handler: F) -> Result<(), SocksError>
where
    F: Fn(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    loop {
        let (stream, _peer) = listener.accept().await.map_err(SocksError::Accept)?;
        tokio::spawn(handler(stream));
    }
}

/// Handle one accepted SOCKS5 connection end to end: greeting/auth, the `CONNECT` request, dispatch,
/// splice. Every return (including every `Ok(())`) represents either a completed/spliced flow or a
/// deliberately-refused request with its reply already written — never a silent fall-through.
async fn handle(
    tunnel: &Tunnel,
    auth: Option<&LocalAuth>,
    mut stream: TcpStream,
) -> Result<(), CodecError> {
    let required = auth.map(|_| AuthMethod::UserPass);
    let method = codec::negotiate_auth(&mut stream, required).await?;
    if method == AuthMethod::UserPass {
        // `required` is only `Some` when `auth` is `Some`, and `negotiate_auth` only returns
        // `UserPass` when it was offered AND (if required) matched — so `auth` is populated here.
        let auth = auth.expect("UserPass is only selected when local auth is configured");
        codec::verify_userpass(&mut stream, &auth.username, &auth.password).await?;
    }

    let request = codec::read_request(&mut stream).await?;

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
/// Generic over the local stream type (`pub(super)`, shared with the HTTP CONNECT front-end): SOCKS
/// hands it the raw `TcpStream`, HTTP CONNECT hands it its `BufReader<TcpStream>` (so any bytes the
/// client pipelined right after its headers, still sitting in the buffered reader, are not lost by
/// unwrapping to the bare socket first).
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
