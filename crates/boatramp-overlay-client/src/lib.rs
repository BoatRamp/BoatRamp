//! # boatramp overlay client SDK
//!
//! A lean, embeddable client for the boatramp **overlay fabric** — the relay-blind, end-to-end
//! encrypted QUIC-on-raw-public-key-TLS mesh. An external program links this crate to **dial**,
//! **forward**, **expose**, and **pair** over the overlay without reaching into the overlay runtime's
//! internals or linking any of its server-side roles.
//!
//! It is the single-source client core that `boatramp forward` / `expose` / `pair` themselves consume
//! (dogfood), and the Rust foundation the increment-2 C-ABI / UniFFI mobile bindings (iOS/Android)
//! build on — this crate is `crate-type = ["lib", "staticlib", "cdylib"]` for exactly that.
//!
//! ## Why a standalone crate
//!
//! The SDK depends on [`boatramp_overlay`] with `default-features = false, features = ["client"]`, so
//! the relay/egress/control-plane + cluster-mesh roles (and their rpktls mesh types) are never
//! linked. Built on its own, the dependency graph is **ring-free** and **rustls-platform-verifier
//! -free** — the overlay uses `aws-lc-rs` as its one crypto provider and raw-public-key TLS with no
//! platform trust store, so a mobile cross-compile has a clean, self-contained crypto graph.
//!
//! ## Shape
//!
//! Build an [`OverlayClient`] from an identity (and, for forwarding/exposing, a relay and egress),
//! then:
//!
//! - [`OverlayClient::dial`] — open a [`Flow`] (a byte-stream handle) to an in-cluster service;
//! - [`OverlayClient::forward_socket`] / [`OverlayClient::forward_connected_fd`] — splice an existing
//!   connected TCP socket (or its owned fd) over the overlay to a service;
//! - [`OverlayClient::forward_stream`] — the generic splice primitive over any async duplex stream;
//! - [`OverlayClient::serve_egress`] — publish a LOCAL backend INTO the cluster (the exposer edge);
//! - [`OverlayClient::pair`] — run the commit-then-reveal SAS pairing handshake over an established
//!   bi-stream.
//!
//! Every overlay authorization property (relay-blind E2EE, zero-trust egress re-authorization,
//! holder-bound capabilities, SAS-gated pairing) is preserved verbatim — this crate only re-packages
//! the client-edge entry points behind a stable, versioned API; it adds no new authority.

// The SDK confines `unsafe` to exactly ONE function — the connected-fd adoption seam
// ([`tcp_stream_from_connected_fd`]) — enforced crate-wide: any other `unsafe` fails to compile.
// (The `-overlay` / `-overlay-proto` crates keep `#![forbid(unsafe_code)]`; this crate cannot, because
// adopting a raw OS descriptor from a future C-ABI caller is inherently unsafe.)
#![deny(unsafe_code)]

use std::net::SocketAddr;
use std::time::Duration;

// Internal-only overlay entry points + types the SDK builds on but does not surface.
use boatramp_overlay::quinn::Endpoint;
use boatramp_overlay::{
    OverlayPeerPolicy, client_endpoint, client_endpoint_server_auth, forward_flow, pair_handshake,
    run_published_service,
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream};
use tokio::net::TcpStream;

// Consumer-facing re-exports, so an embedder names every overlay type through this one crate (these
// are used internally too). The identity/secret, the dial request + path mode, the pairing SAS code,
// role, and fingerprint, the dial trust-root, and the error vocabulary the SDK's error wraps.
pub use boatramp_overlay::{
    DialRequest, Fingerprint, NetError, OverlayId, OverlayIdError, OverlaySecret, PairError,
    PathMode, QuicError, RegisterReject, Role, SasCode, TokenPublicKey, identity_fp,
};

/// In-memory pipe size for a [`Flow`] (the buffer bridging the embedder's reads/writes to the
/// background splice). Matches the overlay's own sealed-pipe buffer order of magnitude.
const FLOW_PIPE_BUF: usize = 64 * 1024;

/// A stable, versioned error for every overlay client operation. The transport
/// ([`NetError`]) and pairing ([`PairError`]) errors are mapped through transparently so a consumer
/// can match on the underlying cause while the enum's shape stays stable across SDK versions.
#[derive(Debug, thiserror::Error)]
pub enum OverlayClientError {
    /// A forwarded-flow / transport failure (dial, E2EE handshake, splice, registration).
    #[error("overlay transport: {0}")]
    Net(#[from] NetError),
    /// A pairing-handshake failure (fail-closed: no SAS, no pin).
    #[error("overlay pairing: {0}")]
    Pair(#[from] PairError),
    /// Building the dial/relay QUIC endpoint failed (bad pin, identity, TLS config).
    #[error("overlay endpoint: {0}")]
    Quic(#[from] QuicError),
    /// Deriving an overlay identity from a seed failed.
    #[error("overlay identity: {0}")]
    Identity(#[from] OverlayIdError),
    /// A local I/O error (e.g. adopting a connected socket fd).
    #[error("overlay client io: {0}")]
    Io(#[from] std::io::Error),
    /// A forwarding/dialing operation needs a relay, but none was configured — call
    /// [`OverlayClientBuilder::relay`] before building the client.
    #[error("no relay configured — set `.relay(addr, id)` on the builder")]
    MissingRelay,
    /// A dial/forward needs the egress identity to pin the end-to-end E2EE session, but none was
    /// configured — call [`OverlayClientBuilder::egress`] before building the client.
    #[error("no egress configured — set `.egress(id)` on the builder before dialing/forwarding")]
    MissingEgress,
    /// The background splice task driving a [`Flow`] could not be joined (it panicked).
    #[error("overlay flow task failed to join: {0}")]
    FlowJoin(String),
}

/// A configured relay: its socket address, its pinned overlay identity, and the dial endpoint built
/// to reach it (mutual-pin, or server-auth-only for a capability-only relay).
struct Relay {
    addr: SocketAddr,
    id: OverlayId,
    endpoint: Endpoint,
}

/// The embeddable overlay client. Cheap to hold; the dial endpoint is built once at [`build`] time.
///
/// [`build`]: OverlayClientBuilder::build
pub struct OverlayClient {
    secret: OverlaySecret,
    relay: Option<Relay>,
    egress_id: Option<OverlayId>,
    default_path_mode: PathMode,
}

/// Builder for [`OverlayClient`].
///
/// Only an identity is required; a relay + egress are required to forward/dial, and the relay alone
/// to [`serve_egress`](OverlayClient::serve_egress). Pairing needs neither (it is point-to-point).
pub struct OverlayClientBuilder {
    secret: OverlaySecret,
    relay: Option<(SocketAddr, OverlayId)>,
    egress_id: Option<OverlayId>,
    path_mode: PathMode,
    capability_only: bool,
}

impl OverlayClient {
    /// Start building a client from this overlay `identity`.
    #[must_use]
    pub fn builder(identity: OverlaySecret) -> OverlayClientBuilder {
        OverlayClientBuilder {
            secret: identity,
            relay: None,
            egress_id: None,
            // A tunnel's sensible default: try a direct path, fall back to the relay. The explicit
            // forward methods take their own `PathMode`; this is the default `dial` uses.
            path_mode: PathMode::PreferDirect,
            capability_only: false,
        }
    }

    /// This client's overlay identity.
    #[must_use]
    pub fn id(&self) -> OverlayId {
        self.secret.id()
    }

    fn relay(&self) -> Result<&Relay, OverlayClientError> {
        self.relay.as_ref().ok_or(OverlayClientError::MissingRelay)
    }

    fn require_egress(&self) -> Result<OverlayId, OverlayClientError> {
        self.egress_id.ok_or(OverlayClientError::MissingEgress)
    }

    /// Rebuild an owned copy of this client's secret (the seed is zeroized, so it is not `Clone`).
    fn clone_secret(&self) -> Result<OverlaySecret, OverlayClientError> {
        Ok(OverlaySecret::from_seed_hex(
            self.secret.seed_hex().as_str(),
        )?)
    }

    fn dial_request(service: &str, cap: &str) -> DialRequest {
        DialRequest {
            service: service.to_string(),
            token: cap.to_string(),
            // The SDK always requires end-to-end encryption to the egress (the overlay's zero-trust
            // posture); a relay/egress that does not enforce it would refuse a cleartext dial anyway.
            e2ee: true,
        }
    }

    /// Dial `service`, presenting the dial capability `cap`, and splice `local` (any async duplex
    /// stream) over the relay-blind E2EE overlay, running until either side closes. This is the
    /// generic forwarding primitive the socket/fd helpers wrap; an embedder with its own transport
    /// (a pipe, a TLS stream, a tunnelled fd) uses it directly.
    pub async fn forward_stream<L>(
        &self,
        local: L,
        service: &str,
        cap: &str,
        path_mode: PathMode,
    ) -> Result<(), OverlayClientError>
    where
        L: AsyncRead + AsyncWrite + Unpin,
    {
        let relay = self.relay()?;
        let egress_id = self.require_egress()?;
        forward_flow(
            local,
            &relay.endpoint,
            relay.addr,
            &self.secret,
            egress_id,
            Self::dial_request(service, cap),
            path_mode,
        )
        .await?;
        Ok(())
    }

    /// Splice an already-connected TCP `socket` over the overlay to `service`. The headline native
    /// entry point — a local listener's accepted connection is forwarded with one call.
    pub async fn forward_socket(
        &self,
        socket: TcpStream,
        service: &str,
        cap: &str,
        path_mode: PathMode,
    ) -> Result<(), OverlayClientError> {
        self.forward_stream(socket, service, cap, path_mode).await
    }

    /// Adopt a connected, owned TCP socket `fd` and splice it over the overlay to `service`.
    ///
    /// This is the fd-adoption seam the native/mobile client is built around: increment 2's C-ABI /
    /// UniFFI layer hands a connected socket descriptor across the FFI boundary, and this is the Rust
    /// entry point it funnels into. Taking an [`OwnedFd`](std::os::fd::OwnedFd) (not a bare `RawFd`)
    /// makes the ownership transfer explicit and checkable at the Rust API.
    #[cfg(unix)]
    pub async fn forward_connected_fd(
        &self,
        fd: std::os::fd::OwnedFd,
        service: &str,
        cap: &str,
        path_mode: PathMode,
    ) -> Result<(), OverlayClientError> {
        let socket = tcp_stream_from_connected_fd(fd)?;
        self.forward_socket(socket, service, cap, path_mode).await
    }

    /// Dial `service` with capability `cap` and return a [`Flow`] — a readable/writable byte-stream
    /// handle to the in-cluster service. The dial + E2EE handshake + splice run on a background task;
    /// errors surface when the flow is used, or on [`Flow::finish`]. Uses the builder's default
    /// [`PathMode`]. Must be called within a Tokio runtime.
    pub fn dial(&self, service: &str, cap: &str) -> Result<Flow, OverlayClientError> {
        let relay = self.relay()?;
        let egress_id = self.require_egress()?;
        let endpoint = relay.endpoint.clone();
        let relay_addr = relay.addr;
        let secret = self.clone_secret()?;
        let request = Self::dial_request(service, cap);
        let path_mode = self.default_path_mode;
        let (near, far) = tokio::io::duplex(FLOW_PIPE_BUF);
        let task = tokio::spawn(async move {
            forward_flow(
                far, &endpoint, relay_addr, &secret, egress_id, request, path_mode,
            )
            .await
        });
        Ok(Flow {
            stream: near,
            task: Some(task),
        })
    }

    /// Publish a LOCAL backend at `backend_addr` INTO the cluster overlay as `service` (the exposer
    /// edge): dial the relay OUTBOUND, register `service` (proving holder-binding to the relay with
    /// `publish_cap`), then terminate each inbound per-flow stream over the local backend,
    /// independently re-authorizing every client dial against `trust_root`. `ready` fires ONCE, the
    /// instant registration succeeds and before serving begins. Returns when the relay connection
    /// drops or on a registration failure. Requires a relay on the builder.
    pub async fn serve_egress<R>(
        &self,
        service: &str,
        backend_addr: SocketAddr,
        publish_cap: &str,
        trust_root: TokenPublicKey,
        ready: R,
    ) -> Result<(), OverlayClientError>
    where
        R: FnOnce(),
    {
        let relay = self.relay()?;
        let service_for_backend = service.to_string();
        let resolve_backend =
            move |s: &str| (s == service_for_backend.as_str()).then_some(backend_addr);
        run_published_service(
            &relay.endpoint,
            relay.addr,
            relay.id,
            &self.secret,
            service.to_string(),
            publish_cap.to_string(),
            resolve_backend,
            trust_root,
            // The overlay reverse-ingress path is always end-to-end E2EE client↔exposer.
            true,
            ready,
        )
        .await?;
        Ok(())
    }

    /// Run the commit-then-reveal SAS pairing handshake over an already-established bi-stream
    /// `(send, recv)` as `role`, bounded by `deadline`. Returns the derived [`SasCode`] (for the two
    /// operators to compare out-of-band) and the peer's E2EE-proven [`OverlayId`] (the identity to
    /// pin on confirm — never operator-typed). Fail-closed on any error. The embedder establishes the
    /// stream (the initiator dials with [`boatramp_overlay::pair_dial_endpoint`]); this wraps the
    /// handshake itself.
    pub async fn pair<S, R>(
        &self,
        send: &mut S,
        recv: &mut R,
        role: Role,
        deadline: Duration,
    ) -> Result<(SasCode, OverlayId), OverlayClientError>
    where
        S: AsyncWrite + Unpin,
        R: AsyncRead + Unpin,
    {
        let out = pair_handshake(send, recv, &self.secret, role, deadline).await?;
        Ok(out)
    }
}

impl OverlayClientBuilder {
    /// Set the relay to dial: its socket `addr` and its pinned overlay `id`.
    #[must_use]
    pub fn relay(mut self, addr: SocketAddr, id: OverlayId) -> Self {
        self.relay = Some((addr, id));
        self
    }

    /// Set the egress/terminator overlay `id` to pin for the end-to-end E2EE session (forward/dial).
    #[must_use]
    pub fn egress(mut self, id: OverlayId) -> Self {
        self.egress_id = Some(id);
        self
    }

    /// Set the default [`PathMode`] used by [`OverlayClient::dial`] (the explicit forward methods
    /// take their own). Defaults to [`PathMode::PreferDirect`].
    #[must_use]
    pub fn path_mode(mut self, path_mode: PathMode) -> Self {
        self.path_mode = path_mode;
        self
    }

    /// Dial the relay **server-auth-only** (present NO client certificate) — for a *capability-only*
    /// relay where the egress, not the relay's client allowlist, is the authority. Default `false`
    /// (mutual-pin: the client presents its raw-public-key certificate to the relay).
    #[must_use]
    pub fn capability_only(mut self, capability_only: bool) -> Self {
        self.capability_only = capability_only;
        self
    }

    /// Build the client. Constructs the dial endpoint now if a relay is set (mutual-pin, or
    /// server-auth-only when [`capability_only`](Self::capability_only) is set); a pairing-only client
    /// needs no relay.
    pub fn build(self) -> Result<OverlayClient, OverlayClientError> {
        let relay = match self.relay {
            Some((addr, id)) => {
                let endpoint = if self.capability_only {
                    client_endpoint_server_auth(&OverlayPeerPolicy::Pin(id))?
                } else {
                    client_endpoint(&self.secret, &OverlayPeerPolicy::Pin(id))?
                };
                Some(Relay { addr, id, endpoint })
            }
            None => None,
        };
        Ok(OverlayClient {
            secret: self.secret,
            relay,
            egress_id: self.egress_id,
            default_path_mode: self.path_mode,
        })
    }
}

/// A live overlay flow: a byte-stream handle to an in-cluster service opened by [`OverlayClient::dial`].
///
/// Implements [`AsyncRead`] + [`AsyncWrite`] — read/write it like a socket. The dial + E2EE splice
/// runs on a background task; dropping the `Flow` aborts it, and [`Flow::finish`] awaits it to
/// surface the final transport result.
pub struct Flow {
    stream: DuplexStream,
    task: Option<tokio::task::JoinHandle<Result<(), NetError>>>,
}

impl Flow {
    /// Signal end-of-stream to the service and await the background splice, returning its transport
    /// result. Consumes the flow (no further reads/writes).
    pub async fn finish(mut self) -> Result<(), OverlayClientError> {
        // Dropping the local pipe end signals EOF to the splice so `forward_flow` can drain + finish.
        drop(std::mem::replace(
            &mut self.stream,
            // A throwaway, immediately-dropped stub so `self.stream` stays valid (Drop runs next).
            tokio::io::duplex(1).0,
        ));
        let Some(task) = self.task.take() else {
            return Ok(());
        };
        match task.await {
            Ok(result) => result.map_err(OverlayClientError::from),
            Err(join) if join.is_cancelled() => Ok(()),
            Err(join) => Err(OverlayClientError::FlowJoin(join.to_string())),
        }
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        // Detach/cancel the background splice when the handle is dropped without `finish`.
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl AsyncRead for Flow {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for Flow {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

/// Adopt a connected, owned TCP socket `fd` as a nonblocking [`tokio::net::TcpStream`].
///
/// The crate's single `unsafe` site. Taking an [`OwnedFd`](std::os::fd::OwnedFd) means the caller has
/// already proven, at the type level, that the descriptor is valid, open, and exclusively owned; this
/// function only reconstitutes a std `TcpStream` from it and hands ownership on.
///
/// # Safety invariant
///
/// The one `unsafe` reconstitutes a `std::net::TcpStream` from the raw descriptor produced by
/// `OwnedFd::into_raw_fd`. It is sound because:
/// - the descriptor comes from an `OwnedFd`, so it is a valid, open file descriptor;
/// - `into_raw_fd` transfers sole ownership to the new `TcpStream`, which closes it on drop — there
///   is no other live handle, hence no aliasing and no double-close.
///
/// The caller's remaining contract (carried by the `OwnedFd` type, which only a connected-socket
/// caller should construct): the descriptor is a **connected TCP stream** socket. A non-socket or
/// unconnected descriptor is not unsound — it surfaces as an ordinary I/O error on first use.
#[cfg(unix)]
#[allow(unsafe_code)]
fn tcp_stream_from_connected_fd(fd: std::os::fd::OwnedFd) -> std::io::Result<TcpStream> {
    use std::os::fd::{FromRawFd, IntoRawFd};

    let raw = fd.into_raw_fd();
    // SAFETY: `raw` was just produced by `OwnedFd::into_raw_fd`, so it is a valid, open descriptor
    // whose sole ownership we transfer into this `TcpStream` (closed on drop). No other live handle
    // references it, so there is no aliasing and no double-close.
    let std_stream = unsafe { std::net::TcpStream::from_raw_fd(raw) };
    // `tokio::net::TcpStream::from_std` REQUIRES the socket be nonblocking; an accepted/dialed OS
    // socket is typically blocking, so set it explicitly before handing it to the reactor.
    std_stream.set_nonblocking(true)?;
    TcpStream::from_std(std_stream)
}
