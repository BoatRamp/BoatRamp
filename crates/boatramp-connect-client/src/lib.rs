//! # boatramp-connect-client
//!
//! The boatramp-authored **Connect / gRPC-web client shim** (PLAN-connect-grpc §9, IU-5): the
//! client-direction analog of the `boatramp-connect` serving shim. Where the serving shim maps an
//! inbound Connect RPC onto a managed handler, this crate lets a Rust caller — the `boatramp` CLI,
//! a host service, or (once vendored into the shim repo) a guest making an outbound call — INVOKE a
//! Connect **unary** or **server-streaming** method on a live boatramp Connect service.
//!
//! It is built on the SAME shared [`boatramp_connect_frame`] codec the host serving path and the
//! guest serving shim use, so there is exactly one wire vocabulary. The Connect protocol version it
//! speaks is [`CONNECT_PROTOCOL_VERSION`] (`"1"`), the identical constant the serving shim reports —
//! the versions match because both crates read it from the one shared codec.
//!
//! ## What the codegen generates on top of this
//!
//! `just codegen` emits, per service in a `.proto`, the `prost` message types plus a typed client
//! whose methods are one-liners over [`call_unary`] / [`call_server_stream`]:
//!
//! ```ignore
//! // GENERATED (see examples/connect-clients/src/generated/):
//! pub struct GreeterClient;
//! impl GreeterClient {
//!     pub const SERVICE: &'static str = "connect.greeter.v1.Greeter";
//!     pub fn say_hello<T: ::boatramp_connect_client::Transport>(
//!         transport: &T, endpoint: &::boatramp_connect_client::Endpoint, req: SayHelloRequest,
//!     ) -> Result<SayHelloResponse, ::boatramp_connect_client::ConnectClientError> {
//!         ::boatramp_connect_client::call_unary(transport, endpoint, Self::SERVICE, "SayHello", &req)
//!     }
//! }
//! ```
//!
//! ## Invoking a method
//!
//! ```ignore
//! use boatramp_connect_client::{Endpoint, PlaintextHttpTransport};
//! let transport = PlaintextHttpTransport::new();
//! let endpoint = Endpoint::new("http://127.0.0.1:8080/_sites/mysite").with_token("…");
//! let reply = GreeterClient::say_hello(&transport, &endpoint, SayHelloRequest { name: "ada".into() })?;
//! assert_eq!(reply.greeting, "hello, ada!");
//! ```
//!
//! ## Transports — and production HTTPS
//!
//! The protocol logic is transport-agnostic (the [`Transport`] trait). The shipped
//! [`PlaintextHttpTransport`] speaks `http://` only. A production boatramp endpoint is `https://`,
//! so a host caller implements [`Transport`] over its own TLS client — about ten lines over a
//! blocking HTTP client, e.g.:
//!
//! ```ignore
//! struct ReqwestTransport(reqwest::blocking::Client);
//! impl boatramp_connect_client::Transport for ReqwestTransport {
//!     fn send(&self, req: boatramp_connect_client::HttpRequest)
//!         -> Result<boatramp_connect_client::HttpResponse, boatramp_connect_client::TransportError> {
//!         let mut rb = self.0.post(&req.url);
//!         for (k, v) in &req.headers { rb = rb.header(k, v); }
//!         let resp = rb.body(req.body).send().map_err(|e| TransportError::Io(e.to_string()))?;
//!         let status = resp.status().as_u16();
//!         let headers = resp.headers().iter()
//!             .map(|(k, v)| (k.as_str().to_ascii_lowercase(), v.to_str().unwrap_or("").to_string()))
//!             .collect();
//!         let body = resp.bytes().map_err(|e| TransportError::Io(e.to_string()))?.to_vec();
//!         Ok(boatramp_connect_client::HttpResponse { status, headers, body })
//!     }
//! }
//! ```
//!
//! ## Out of scope (this transport)
//!
//! Client-streaming and bidi are out of scope (PLAN §1) — the same boundary the serving shim keeps.
//! The JSON codec is a later ergonomics add (the server reports `unimplemented` for it); this client
//! speaks binary proto (`application/proto` / `application/connect+proto` / `application/grpc-web+proto`).

#![forbid(unsafe_code)]

pub mod transport;

use boatramp_connect_frame as frame;
use prost::Message;

#[doc(inline)]
pub use boatramp_connect_frame::{Code, Status, CONNECT_PROTOCOL_VERSION};
#[doc(inline)]
pub use transport::{HttpRequest, HttpResponse, PlaintextHttpTransport, Transport, TransportError};

/// Which Connect / gRPC-web wire a client call uses. Both carry binary protobuf; they differ in how
/// end-of-call status is framed (see [`boatramp_connect_frame`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientProtocol {
    /// Connect: unary is a bare message (`application/proto`); a server-stream is enveloped frames +
    /// an in-body EndStream frame (`application/connect+proto`). The default.
    #[default]
    Connect,
    /// gRPC-web (binary): enveloped frames + an in-body trailers frame; the HTTP status is always
    /// `200` and the RPC status rides the trailers (`application/grpc-web+proto`).
    GrpcWeb,
}

/// A boatramp Connect endpoint: the base URL a service's RPCs hang off, an optional boatramp bearer
/// token, and the wire to speak.
///
/// The RPC URL for a call is `{base_url}/{package}.{Service}/{Method}`. For a boatramp deployment
/// the base URL is the site origin (optionally with the `/_sites/{site}` prefix the host routes on),
/// e.g. `https://app.example.com` or `http://127.0.0.1:8080/_sites/mysite`.
#[derive(Debug, Clone)]
pub struct Endpoint {
    base_url: String,
    token: Option<String>,
    protocol: ClientProtocol,
}

impl Endpoint {
    /// An endpoint at `base_url` (trailing slash trimmed), Connect wire, no token.
    pub fn new(base_url: impl Into<String>) -> Self {
        let mut base_url = base_url.into();
        while base_url.ends_with('/') {
            base_url.pop();
        }
        Self {
            base_url,
            token: None,
            protocol: ClientProtocol::Connect,
        }
    }

    /// Attach a boatramp bearer token (sent as `Authorization: Bearer <token>`).
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    /// Choose the wire ([`ClientProtocol::Connect`] default, or [`ClientProtocol::GrpcWeb`]).
    pub fn with_protocol(mut self, protocol: ClientProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// The wire this endpoint speaks.
    pub fn protocol(&self) -> ClientProtocol {
        self.protocol
    }

    /// The absolute RPC URL `{base_url}/{service}/{method}`.
    pub fn rpc_url(&self, service: &str, method: &str) -> String {
        format!("{}/{service}/{method}", self.base_url)
    }

    /// The request headers for a call on `content_type`. Adds `accept-encoding: identity` (the
    /// client never decompresses; a boatramp site only compresses when a client opts in, and the
    /// host never HTTP-compresses a framed body — so identity is always safe), the
    /// `connect-protocol-version` header for a Connect-unary request, and the bearer token.
    fn headers(&self, content_type: &str, is_connect_unary: bool) -> Vec<(String, String)> {
        let mut h = vec![
            ("content-type".to_string(), content_type.to_string()),
            ("accept-encoding".to_string(), "identity".to_string()),
        ];
        if is_connect_unary {
            h.push((
                "connect-protocol-version".to_string(),
                CONNECT_PROTOCOL_VERSION.to_string(),
            ));
        }
        if let Some(token) = &self.token {
            h.push(("authorization".to_string(), format!("Bearer {token}")));
        }
        h
    }
}

/// A failure invoking a Connect / gRPC-web RPC.
#[derive(Debug, thiserror::Error)]
pub enum ConnectClientError {
    /// The HTTP request/response failed (socket, URL, malformed response).
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The RPC completed but returned a non-ok [`Status`] (the server's business error).
    #[error("rpc error: {0}")]
    Rpc(Status),
    /// The response body could not be decoded as the expected protobuf message.
    #[error("response decode: {0}")]
    Decode(String),
    /// The response did not match the Connect / gRPC-web wire shape (missing frame, bad framing).
    #[error("protocol: {0}")]
    Protocol(String),
}

impl ConnectClientError {
    /// The RPC [`Status`] if this is an [`ConnectClientError::Rpc`], else `None`.
    pub fn status(&self) -> Option<&Status> {
        match self {
            ConnectClientError::Rpc(s) => Some(s),
            _ => None,
        }
    }
}

/// The `Content-Type` a unary request uses for `protocol`.
fn unary_content_type(protocol: ClientProtocol) -> &'static str {
    match protocol {
        ClientProtocol::Connect => "application/proto",
        ClientProtocol::GrpcWeb => "application/grpc-web+proto",
    }
}

/// The `Content-Type` a server-stream request uses for `protocol`.
fn stream_content_type(protocol: ClientProtocol) -> &'static str {
    match protocol {
        ClientProtocol::Connect => "application/connect+proto",
        ClientProtocol::GrpcWeb => "application/grpc-web+proto",
    }
}

/// Invoke a **unary** Connect / gRPC-web RPC: encode `req`, send it to
/// `{endpoint}/{service}/{method}`, and decode the single reply message — or surface the server's
/// [`Status`] as [`ConnectClientError::Rpc`].
pub fn call_unary<Req, Resp, T>(
    transport: &T,
    endpoint: &Endpoint,
    service: &str,
    method: &str,
    req: &Req,
) -> Result<Resp, ConnectClientError>
where
    Req: Message,
    Resp: Message + Default,
    T: Transport,
{
    let protocol = endpoint.protocol;
    let msg = req.encode_to_vec();
    let body = match protocol {
        // gRPC-web wraps the request message in one data frame; Connect-unary sends it bare.
        ClientProtocol::GrpcWeb => frame::encode_envelope(0, &msg),
        ClientProtocol::Connect => msg,
    };
    let http = HttpRequest {
        url: endpoint.rpc_url(service, method),
        headers: endpoint.headers(
            unary_content_type(protocol),
            protocol == ClientProtocol::Connect,
        ),
        body,
    };
    let resp = transport.send(http)?;
    match protocol {
        ClientProtocol::GrpcWeb => decode_grpc_web_unary::<Resp>(&resp.body),
        ClientProtocol::Connect => decode_connect_unary::<Resp>(resp.status, &resp.body),
    }
}

/// Decode a Connect-unary response: a `200` is the bare reply message; anything else is a Connect
/// error body (`{"code","message"}`) + HTTP-status fallback.
fn decode_connect_unary<Resp: Message + Default>(
    status: u16,
    body: &[u8],
) -> Result<Resp, ConnectClientError> {
    if status == 200 {
        Resp::decode(body).map_err(|e| ConnectClientError::Decode(e.to_string()))
    } else {
        Err(ConnectClientError::Rpc(frame::parse_connect_unary_error(
            status, body,
        )))
    }
}

/// Decode a gRPC-web unary response body: `[data frame][trailers frame]` on success, or a lone
/// trailers frame on error. The RPC status rides the trailers (the HTTP status is always `200`).
fn decode_grpc_web_unary<Resp: Message + Default>(body: &[u8]) -> Result<Resp, ConnectClientError> {
    let mut data: Option<Resp> = None;
    let mut status: Option<Status> = None;
    for frame in frame::frames(body) {
        let frame = frame.map_err(|e| ConnectClientError::Protocol(e.to_string()))?;
        if frame.is_grpc_web_trailer() {
            status = Some(frame::parse_grpc_web_trailers(frame.payload));
        } else if frame.is_data() && data.is_none() {
            data = Some(
                Resp::decode(frame.payload)
                    .map_err(|e| ConnectClientError::Decode(e.to_string()))?,
            );
        }
    }
    let status = status.ok_or_else(|| {
        ConnectClientError::Protocol("gRPC-web unary response had no trailers frame".into())
    })?;
    if !status.is_ok() {
        return Err(ConnectClientError::Rpc(status));
    }
    data.ok_or_else(|| {
        ConnectClientError::Protocol("gRPC-web unary response had no data frame (status ok)".into())
    })
}

/// Invoke a **server-streaming** Connect / gRPC-web RPC: encode `req`, open the stream, and return a
/// [`ServerStream`] that yields each decoded reply message and, at the end, the terminal [`Status`].
///
/// Iterating the returned [`ServerStream`] yields `Ok(Resp)` for each data frame; a non-ok terminal
/// status is surfaced as a final `Err(ConnectClientError::Rpc(status))`, so `for m in stream { m?; }`
/// propagates a server-side stream error. [`ServerStream::status`] holds the terminal status after
/// the stream ends.
pub fn call_server_stream<Req, Resp, T>(
    transport: &T,
    endpoint: &Endpoint,
    service: &str,
    method: &str,
    req: &Req,
) -> Result<ServerStream<Resp>, ConnectClientError>
where
    Req: Message,
    Resp: Message + Default,
    T: Transport,
{
    let protocol = endpoint.protocol;
    // A server-stream request is always one enveloped data frame (both wires).
    let body = frame::encode_envelope(0, &req.encode_to_vec());
    let http = HttpRequest {
        url: endpoint.rpc_url(service, method),
        // Streaming content-types are not "connect-unary", so no connect-protocol-version header
        // (connect-es omits it on streaming calls too).
        headers: endpoint.headers(stream_content_type(protocol), false),
        body,
    };
    let resp = transport.send(http)?;
    // Both wires commit a 200 head for a stream; a non-200 is a gateway/transport-level failure.
    if resp.status != 200 {
        return Err(ConnectClientError::Protocol(format!(
            "server-stream head was HTTP {} (expected 200; the RPC status rides the in-body end frame)",
            resp.status
        )));
    }
    Ok(ServerStream::new(protocol, resp.body))
}

/// A reader over a buffered server-stream response body: it yields each data frame decoded to `Resp`
/// and records the terminal [`Status`] from the end-of-stream frame.
pub struct ServerStream<Resp> {
    body: Vec<u8>,
    pos: usize,
    protocol: ClientProtocol,
    done: bool,
    status: Option<Status>,
    _resp: std::marker::PhantomData<Resp>,
}

impl<Resp: Message + Default> ServerStream<Resp> {
    fn new(protocol: ClientProtocol, body: Vec<u8>) -> Self {
        Self {
            body,
            pos: 0,
            protocol,
            done: false,
            status: None,
            _resp: std::marker::PhantomData,
        }
    }

    /// The terminal [`Status`] of the stream, available once iteration has reached the end frame.
    /// `None` until then.
    pub fn status(&self) -> Option<&Status> {
        self.status.as_ref()
    }

    /// Drain the stream into a `Vec` of messages, returning the terminal [`Status`] alongside. A
    /// non-ok status is returned (not an `Err`) so a caller can inspect partial progress; use the
    /// [`Iterator`] with `?` if an error should short-circuit.
    pub fn collect_all(mut self) -> Result<(Vec<Resp>, Status), ConnectClientError> {
        let mut out = Vec::new();
        for item in &mut self {
            match item {
                Ok(m) => out.push(m),
                // The only Err the iterator yields terminally is the RPC status; fold it into the
                // returned status rather than discarding the messages already collected.
                Err(ConnectClientError::Rpc(s)) => return Ok((out, s)),
                Err(e) => return Err(e),
            }
        }
        let status = self.status.clone().unwrap_or_else(Status::ok);
        Ok((out, status))
    }
}

impl<Resp: Message + Default> Iterator for ServerStream<Resp> {
    type Item = Result<Resp, ConnectClientError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        loop {
            if self.pos >= self.body.len() {
                // The body ended without an explicit end frame — treat a clean EOF as an ok close
                // (the server finished the stream and closed the connection).
                self.done = true;
                self.status.get_or_insert_with(Status::ok);
                return None;
            }
            let (frame, consumed) = match frame::decode_one(&self.body[self.pos..]) {
                Ok(f) => f,
                Err(e) => {
                    self.done = true;
                    return Some(Err(ConnectClientError::Protocol(e.to_string())));
                }
            };
            self.pos += consumed;

            let is_end = match self.protocol {
                ClientProtocol::GrpcWeb => frame.is_grpc_web_trailer(),
                ClientProtocol::Connect => frame.is_connect_end_stream(),
            };
            if is_end {
                let status = match self.protocol {
                    ClientProtocol::GrpcWeb => frame::parse_grpc_web_trailers(frame.payload),
                    ClientProtocol::Connect => frame::parse_connect_end_stream(frame.payload),
                };
                let ok = status.is_ok();
                self.status = Some(status.clone());
                self.done = true;
                return if ok {
                    None
                } else {
                    Some(Err(ConnectClientError::Rpc(status)))
                };
            }
            if frame.is_data() {
                return Some(
                    Resp::decode(frame.payload)
                        .map_err(|e| ConnectClientError::Decode(e.to_string())),
                );
            }
            // A frame that is neither data nor the expected end frame (e.g. a stray compressed/
            // unknown flag) — skip it and continue.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_connect_frame as frame;
    use boatramp_connect_frame::{
        encode_connect_end_stream, encode_envelope, encode_grpc_web_trailers,
    };

    #[derive(Clone, PartialEq, prost::Message)]
    struct Ping {
        #[prost(string, tag = "1")]
        name: String,
    }
    #[derive(Clone, PartialEq, prost::Message)]
    struct Pong {
        #[prost(string, tag = "1")]
        greeting: String,
    }

    /// A transport that records the request it was handed and replies with a canned response.
    struct MockTransport {
        reply: HttpResponse,
        seen: std::cell::RefCell<Option<HttpRequest>>,
    }
    impl MockTransport {
        fn new(reply: HttpResponse) -> Self {
            Self {
                reply,
                seen: std::cell::RefCell::new(None),
            }
        }
    }
    impl Transport for MockTransport {
        fn send(&self, req: HttpRequest) -> Result<HttpResponse, TransportError> {
            *self.seen.borrow_mut() = Some(req);
            Ok(self.reply.clone())
        }
    }

    fn resp(status: u16, content_type: &str, body: Vec<u8>) -> HttpResponse {
        HttpResponse {
            status,
            headers: vec![("content-type".into(), content_type.into())],
            body,
        }
    }

    #[test]
    fn connect_unary_success_bare_message_and_request_shape() {
        let reply = Pong {
            greeting: "hello, ada!".into(),
        };
        let t = MockTransport::new(resp(200, "application/proto", reply.encode_to_vec()));
        let endpoint = Endpoint::new("http://host/_sites/s/").with_token("tok");
        let got: Pong = call_unary(
            &t,
            &endpoint,
            "connect.greeter.v1.Greeter",
            "SayHello",
            &Ping { name: "ada".into() },
        )
        .unwrap();
        assert_eq!(got.greeting, "hello, ada!");

        // The request was a bare protobuf body to the right URL, with the Connect headers.
        let seen = t.seen.borrow();
        let seen = seen.as_ref().unwrap();
        assert_eq!(
            seen.url,
            "http://host/_sites/s/connect.greeter.v1.Greeter/SayHello"
        );
        assert_eq!(seen.body, Ping { name: "ada".into() }.encode_to_vec());
        assert!(seen
            .headers
            .iter()
            .any(|(k, v)| k == "content-type" && v == "application/proto"));
        assert!(seen
            .headers
            .iter()
            .any(|(k, v)| k == "connect-protocol-version" && v == "1"));
        assert!(seen
            .headers
            .iter()
            .any(|(k, v)| k == "authorization" && v == "Bearer tok"));
    }

    #[test]
    fn connect_unary_error_maps_status() {
        let body =
            frame::connect_error_json(&Status::new(Code::PermissionDenied, "no")).into_bytes();
        let t = MockTransport::new(resp(403, "application/json", body));
        let endpoint = Endpoint::new("http://host");
        let err =
            call_unary::<Ping, Pong, _>(&t, &endpoint, "svc", "M", &Ping::default()).unwrap_err();
        let status = err.status().expect("rpc status");
        assert_eq!(status.code, Code::PermissionDenied);
        assert_eq!(status.message, "no");
    }

    #[test]
    fn grpc_web_unary_success_data_then_trailers() {
        let reply = Pong {
            greeting: "ok".into(),
        };
        let mut body = encode_envelope(0, &reply.encode_to_vec());
        body.extend_from_slice(&encode_grpc_web_trailers(&Status::ok(), &[]));
        let t = MockTransport::new(resp(200, "application/grpc-web+proto", body));
        let endpoint = Endpoint::new("http://host").with_protocol(ClientProtocol::GrpcWeb);
        let got: Pong = call_unary(&t, &endpoint, "svc", "M", &Ping::default()).unwrap();
        assert_eq!(got.greeting, "ok");
        // The gRPC-web request body is an enveloped (framed) message.
        let seen = t.seen.borrow();
        assert_eq!(seen.as_ref().unwrap().body[0], 0, "data frame flags");
    }

    #[test]
    fn grpc_web_unary_error_lone_trailers() {
        let body = encode_grpc_web_trailers(&Status::new(Code::NotFound, "gone"), &[]);
        let t = MockTransport::new(resp(200, "application/grpc-web+proto", body));
        let endpoint = Endpoint::new("http://host").with_protocol(ClientProtocol::GrpcWeb);
        let err =
            call_unary::<Ping, Pong, _>(&t, &endpoint, "svc", "M", &Ping::default()).unwrap_err();
        assert_eq!(err.status().unwrap().code, Code::NotFound);
    }

    #[test]
    fn connect_server_stream_yields_messages_then_ok_end() {
        let mut body = encode_envelope(
            0,
            &Pong {
                greeting: "a".into(),
            }
            .encode_to_vec(),
        );
        body.extend_from_slice(&encode_envelope(
            0,
            &Pong {
                greeting: "b".into(),
            }
            .encode_to_vec(),
        ));
        body.extend_from_slice(&encode_connect_end_stream(&Status::ok(), &[]));
        let t = MockTransport::new(resp(200, "application/connect+proto", body));
        let endpoint = Endpoint::new("http://host");
        let stream =
            call_server_stream::<Ping, Pong, _>(&t, &endpoint, "svc", "Sub", &Ping::default())
                .unwrap();
        let (msgs, status) = stream.collect_all().unwrap();
        assert_eq!(
            msgs.iter().map(|m| m.greeting.clone()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert!(status.is_ok());
    }

    #[test]
    fn grpc_web_server_stream_error_end_is_terminal_err() {
        let mut body = encode_envelope(
            0,
            &Pong {
                greeting: "x".into(),
            }
            .encode_to_vec(),
        );
        body.extend_from_slice(&encode_grpc_web_trailers(
            &Status::new(Code::Internal, "boom"),
            &[],
        ));
        let t = MockTransport::new(resp(200, "application/grpc-web+proto", body));
        let endpoint = Endpoint::new("http://host").with_protocol(ClientProtocol::GrpcWeb);
        let mut stream =
            call_server_stream::<Ping, Pong, _>(&t, &endpoint, "svc", "Sub", &Ping::default())
                .unwrap();
        assert_eq!(stream.next().unwrap().unwrap().greeting, "x");
        let err = stream.next().unwrap().unwrap_err();
        assert_eq!(err.status().unwrap().code, Code::Internal);
        assert!(stream.next().is_none());
        assert_eq!(stream.status().unwrap().code, Code::Internal);
    }
}
