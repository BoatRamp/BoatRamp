//! # boatramp-connect-frame
//!
//! Connect / gRPC-web **wire framing** — the one codec the host serving path (the `boatramp-server`
//! stream fan-out's Connect framing mode, PLAN-connect-grpc §7 / IU-4) and the guest-side
//! `boatramp-connect` serving shim share, so the 5-byte envelope is never hand-rolled twice.
//!
//! Three on-the-wire shapes, all reachable over the **existing** boatramp wasi:http / h2+h1
//! streaming body — none needs HTTP/2 trailers (see PLAN-connect-grpc §4):
//!
//! * **Connect unary** (`application/proto` / `application/json`): the request body is the single
//!   bare encoded message; the response is the single bare encoded message (success) or a JSON
//!   `{"code","message"}` error body with the mapped HTTP status.
//! * **Connect streaming** (`application/connect+proto` / `application/connect+json`): a sequence
//!   of length-prefixed *envelope* frames terminated by an in-body **EndStream** frame
//!   (`flags = 0x02`) carrying a JSON `{error?, metadata?}` trailer block.
//! * **gRPC-web** (`application/grpc-web+proto` / `application/grpc-web`): the same 5-byte
//!   envelope; the stream (and the unary response) terminate with a **trailers** frame
//!   (`flags = 0x80`) whose payload is an HTTP/1-style `grpc-status: N\r\ngrpc-message: …\r\n`
//!   block. The HTTP status is always `200`; the RPC status rides the trailers frame.
//!
//! The envelope is identical for Connect-streaming and gRPC-web:
//!
//! ```text
//! ┌────────┬───────────────────┬──────────────────┐
//! │ flags  │ length (u32, BE)  │ payload (length) │
//! │ 1 byte │ 4 bytes           │ length bytes     │
//! └────────┴───────────────────┴──────────────────┘
//! ```
//!
//! This crate is pure byte-manipulation — no protobuf runtime, no wasm, no host — so it unit-tests
//! natively and compiles unchanged for the host triple and wasm32-wasip2 alike.

#![forbid(unsafe_code)]

use std::fmt;

/// The high (MSB) envelope flag: a gRPC-web **trailers** frame.
pub const FLAG_GRPC_WEB_TRAILER: u8 = 0b1000_0000;
/// The Connect-streaming **EndStream** frame flag (bit 1).
pub const FLAG_CONNECT_END_STREAM: u8 = 0b0000_0010;
/// The envelope **compression** flag (bit 0). The shim emits uncompressed frames; an inbound
/// compressed frame is refused (the shim negotiates identity-only for now).
pub const FLAG_COMPRESSED: u8 = 0b0000_0001;

/// The Connect protocol version the shim implements. Connect clients send it as the
/// `Connect-Protocol-Version` header on unary requests (PLAN §11.3: confirm it matches the
/// clients — it is `1`).
pub const CONNECT_PROTOCOL_VERSION: &str = "1";

/// The wire protocol a request/response uses, selected by its `Content-Type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// Connect unary: the body is one bare message; errors use the HTTP status + a JSON body.
    ConnectUnary,
    /// Connect streaming: enveloped frames + an in-body EndStream frame.
    ConnectStreaming,
    /// gRPC-web (binary): enveloped frames + an in-body trailers frame; HTTP status always 200.
    GrpcWeb,
}

/// The message codec within a protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    /// Binary protobuf (`prost`).
    Proto,
    /// JSON. Recognized at the framing layer; message-level proto⇔JSON transcoding is a later
    /// increment (needs proto descriptors), so the serving layer reports `unimplemented` for it.
    Json,
}

/// A parsed `Content-Type`: the protocol plus its codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wire {
    pub protocol: Protocol,
    pub codec: Codec,
}

impl Wire {
    /// Does this wire terminate the response with an in-body end-of-stream frame (vs the bare
    /// Connect-unary shape)?
    pub fn is_enveloped(&self) -> bool {
        matches!(
            self.protocol,
            Protocol::ConnectStreaming | Protocol::GrpcWeb
        )
    }

    /// The `Content-Type` to echo on the response for this wire.
    pub fn response_content_type(&self) -> &'static str {
        match (self.protocol, self.codec) {
            (Protocol::ConnectUnary, Codec::Proto) => "application/proto",
            (Protocol::ConnectUnary, Codec::Json) => "application/json",
            (Protocol::ConnectStreaming, Codec::Proto) => "application/connect+proto",
            (Protocol::ConnectStreaming, Codec::Json) => "application/connect+json",
            (Protocol::GrpcWeb, Codec::Proto) => "application/grpc-web+proto",
            (Protocol::GrpcWeb, Codec::Json) => "application/grpc-web+json",
        }
    }
}

/// Recognize a Connect / gRPC-web `Content-Type` (parameters such as `; charset=…` are ignored).
/// Returns `None` for anything the shim does not serve — the caller answers `415`.
///
/// The exact set the host must route as streaming-capable (PLAN §5.1):
/// `application/connect+proto`, `application/connect+json`, `application/grpc-web+proto`,
/// `application/grpc-web`, plus the Connect-unary `application/proto` / `application/json`.
pub fn parse_content_type(content_type: &str) -> Option<Wire> {
    let main = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let wire = match main.as_str() {
        "application/proto" | "application/protobuf" | "application/x-protobuf" => Wire {
            protocol: Protocol::ConnectUnary,
            codec: Codec::Proto,
        },
        "application/json" => Wire {
            protocol: Protocol::ConnectUnary,
            codec: Codec::Json,
        },
        "application/connect+proto" => Wire {
            protocol: Protocol::ConnectStreaming,
            codec: Codec::Proto,
        },
        "application/connect+json" => Wire {
            protocol: Protocol::ConnectStreaming,
            codec: Codec::Json,
        },
        // Bare `application/grpc-web` defaults to proto (connect-es / grpc-web convention).
        "application/grpc-web+proto" | "application/grpc-web" => Wire {
            protocol: Protocol::GrpcWeb,
            codec: Codec::Proto,
        },
        "application/grpc-web+json" => Wire {
            protocol: Protocol::GrpcWeb,
            codec: Codec::Json,
        },
        _ => return None,
    };
    Some(wire)
}

/// The canonical gRPC / Connect status codes (0‥=16). The one status vocabulary both protocols
/// carry — Connect by its lower-snake-case name, gRPC-web by its number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Ok,
    Canceled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    Unavailable,
    DataLoss,
    Unauthenticated,
}

impl Code {
    /// The gRPC numeric status (the `grpc-status` trailer value).
    pub fn grpc_status(self) -> u32 {
        match self {
            Code::Ok => 0,
            Code::Canceled => 1,
            Code::Unknown => 2,
            Code::InvalidArgument => 3,
            Code::DeadlineExceeded => 4,
            Code::NotFound => 5,
            Code::AlreadyExists => 6,
            Code::PermissionDenied => 7,
            Code::ResourceExhausted => 8,
            Code::FailedPrecondition => 9,
            Code::Aborted => 10,
            Code::OutOfRange => 11,
            Code::Unimplemented => 12,
            Code::Internal => 13,
            Code::Unavailable => 14,
            Code::DataLoss => 15,
            Code::Unauthenticated => 16,
        }
    }

    /// The Connect lower-snake-case name (the `code` field of a Connect error body / EndStream).
    pub fn connect_name(self) -> &'static str {
        match self {
            Code::Ok => "ok",
            Code::Canceled => "canceled",
            Code::Unknown => "unknown",
            Code::InvalidArgument => "invalid_argument",
            Code::DeadlineExceeded => "deadline_exceeded",
            Code::NotFound => "not_found",
            Code::AlreadyExists => "already_exists",
            Code::PermissionDenied => "permission_denied",
            Code::ResourceExhausted => "resource_exhausted",
            Code::FailedPrecondition => "failed_precondition",
            Code::Aborted => "aborted",
            Code::OutOfRange => "out_of_range",
            Code::Unimplemented => "unimplemented",
            Code::Internal => "internal",
            Code::Unavailable => "unavailable",
            Code::DataLoss => "data_loss",
            Code::Unauthenticated => "unauthenticated",
        }
    }

    /// The HTTP status a **Connect unary** error maps to (the Connect protocol error-code table).
    /// Streaming + gRPC-web never use this — their head is always `200` and the RPC status rides
    /// the in-body end frame.
    pub fn http_status(self) -> u16 {
        match self {
            Code::Ok => 200,
            Code::Canceled => 499,
            Code::Unknown => 500,
            Code::InvalidArgument => 400,
            Code::DeadlineExceeded => 504,
            Code::NotFound => 404,
            Code::AlreadyExists => 409,
            Code::PermissionDenied => 403,
            Code::ResourceExhausted => 429,
            Code::FailedPrecondition => 412,
            Code::Aborted => 409,
            Code::OutOfRange => 400,
            Code::Unimplemented => 501,
            Code::Internal => 500,
            Code::Unavailable => 503,
            Code::DataLoss => 500,
            Code::Unauthenticated => 401,
        }
    }
}

/// An RPC status: a [`Code`] and a human-readable message (empty for `Ok`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub code: Code,
    pub message: String,
}

impl Status {
    /// An `ok` status (no message).
    pub fn ok() -> Self {
        Self {
            code: Code::Ok,
            message: String::new(),
        }
    }

    /// A status with `code` and `message`.
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Is this the success status?
    pub fn is_ok(&self) -> bool {
        self.code == Code::Ok
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(f, "{}", self.code.connect_name())
        } else {
            write!(f, "{}: {}", self.code.connect_name(), self.message)
        }
    }
}

/// A framing error: a malformed inbound envelope, or a frame the shim will not accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The 5-byte envelope prefix is incomplete.
    ShortPrefix,
    /// The declared payload length overruns the buffer.
    ShortPayload { declared: usize, available: usize },
    /// A compressed inbound frame (the shim negotiates identity-only for now).
    Compressed,
    /// No data frame was present where one message was required.
    MissingMessage,
    /// The frame's flags marked it as an end/trailers frame where a data frame was expected.
    UnexpectedEndFrame,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::ShortPrefix => write!(f, "truncated envelope prefix"),
            FrameError::ShortPayload {
                declared,
                available,
            } => write!(
                f,
                "envelope declares {declared} payload bytes but only {available} are present"
            ),
            FrameError::Compressed => {
                write!(
                    f,
                    "compressed frames are not supported (identity encoding only)"
                )
            }
            FrameError::MissingMessage => write!(f, "expected one request message, found none"),
            FrameError::UnexpectedEndFrame => {
                write!(f, "expected a data frame, found an end-of-stream frame")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Encode one envelope frame: `flags`, a big-endian `u32` length, then `payload`.
pub fn encode_envelope(flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(flags);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// One decoded envelope frame borrowed out of a buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub flags: u8,
    pub payload: &'a [u8],
}

impl Frame<'_> {
    /// Is this a gRPC-web trailers frame?
    pub fn is_grpc_web_trailer(&self) -> bool {
        self.flags & FLAG_GRPC_WEB_TRAILER != 0
    }
    /// Is this a Connect-streaming EndStream frame?
    pub fn is_connect_end_stream(&self) -> bool {
        self.flags & FLAG_CONNECT_END_STREAM != 0
    }
    /// Is this a plain data (message) frame?
    pub fn is_data(&self) -> bool {
        self.flags & (FLAG_GRPC_WEB_TRAILER | FLAG_CONNECT_END_STREAM) == 0
    }
}

/// Decode exactly one envelope frame from the front of `buf`, returning the frame and the number
/// of bytes it consumed. Refuses a compressed frame.
pub fn decode_one(buf: &[u8]) -> Result<(Frame<'_>, usize), FrameError> {
    if buf.len() < 5 {
        return Err(FrameError::ShortPrefix);
    }
    let flags = buf[0];
    if flags & FLAG_COMPRESSED != 0 {
        return Err(FrameError::Compressed);
    }
    let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let end = 5 + len;
    if buf.len() < end {
        return Err(FrameError::ShortPayload {
            declared: len,
            available: buf.len() - 5,
        });
    }
    Ok((
        Frame {
            flags,
            payload: &buf[5..end],
        },
        end,
    ))
}

/// Pull the **single request message** out of an inbound body for a given wire. For
/// [`Protocol::ConnectUnary`] the body *is* the message; for the enveloped protocols it is the
/// first data frame's payload. (Unary + server-stream both take exactly one request message.)
pub fn request_message<'a>(wire: &Wire, body: &'a [u8]) -> Result<&'a [u8], FrameError> {
    if !wire.is_enveloped() {
        return Ok(body);
    }
    if body.is_empty() {
        return Err(FrameError::MissingMessage);
    }
    let (frame, _) = decode_one(body)?;
    if !frame.is_data() {
        return Err(FrameError::UnexpectedEndFrame);
    }
    Ok(frame.payload)
}

/// Percent-encode a gRPC status message for the `grpc-message` trailer (RFC 7230 token-safe: the
/// trailer block is `name: value\r\n` lines, so bytes outside `0x20‥0x7E` and `%` are escaped).
fn pct_encode(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    for &b in message.as_bytes() {
        if (0x20..=0x7e).contains(&b) && b != b'%' {
            out.push(b as char);
        } else {
            out.push('%');
            out.push_str(&format!("{b:02X}"));
        }
    }
    out
}

/// Encode a **gRPC-web trailers** frame carrying `status` (and any `metadata`), as the trailers
/// block `grpc-status: N\r\ngrpc-message: …\r\n` wrapped in an envelope with the MSB flag set.
pub fn encode_grpc_web_trailers(status: &Status, metadata: &[(String, String)]) -> Vec<u8> {
    let mut block = String::new();
    block.push_str(&format!("grpc-status: {}\r\n", status.code.grpc_status()));
    if !status.message.is_empty() {
        block.push_str(&format!(
            "grpc-message: {}\r\n",
            pct_encode(&status.message)
        ));
    }
    for (k, v) in metadata {
        block.push_str(&format!("{}: {}\r\n", k.to_ascii_lowercase(), v));
    }
    encode_envelope(FLAG_GRPC_WEB_TRAILER, block.as_bytes())
}

/// Encode a **Connect EndStream** frame: `{"error":{"code","message"}?,"metadata":{…}?}` wrapped
/// in an envelope with the EndStream flag set. An `ok` status with no metadata is the empty `{}`.
pub fn encode_connect_end_stream(status: &Status, metadata: &[(String, String)]) -> Vec<u8> {
    let payload = connect_end_stream_json(status, metadata);
    encode_envelope(FLAG_CONNECT_END_STREAM, payload.as_bytes())
}

/// The JSON object body of a Connect EndStream frame (also the shape of a unary error body's
/// `error` member).
fn connect_end_stream_json(status: &Status, metadata: &[(String, String)]) -> String {
    let mut obj = String::from("{");
    let mut first = true;
    if !status.is_ok() {
        obj.push_str(&format!("\"error\":{}", connect_error_json(status)));
        first = false;
    }
    if !metadata.is_empty() {
        if !first {
            obj.push(',');
        }
        obj.push_str("\"metadata\":{");
        for (i, (k, v)) in metadata.iter().enumerate() {
            if i > 0 {
                obj.push(',');
            }
            // Connect metadata values are arrays of strings.
            obj.push_str(&format!(
                "{}:[{}]",
                json_string(&k.to_ascii_lowercase()),
                json_string(v)
            ));
        }
        obj.push('}');
    }
    obj.push('}');
    obj
}

/// The JSON body of a **Connect unary error**: `{"code":"…","message":"…"}`.
pub fn connect_error_json(status: &Status) -> String {
    let mut obj = format!("{{\"code\":{}", json_string(status.code.connect_name()));
    if !status.message.is_empty() {
        obj.push_str(&format!(",\"message\":{}", json_string(&status.message)));
    }
    obj.push('}');
    obj
}

/// Minimal JSON string escaping (the only JSON we emit is a status code/message + metadata, so a
/// full serde dependency is unwarranted here).
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Split a Connect/gRPC request path `"/pkg.Service/Method"` into `("pkg.Service", "Method")`.
/// A leading slash is required; a trailing query is ignored.
pub fn split_rpc_path(path: &str) -> Option<(&str, &str)> {
    let path = path.split('?').next().unwrap_or(path);
    let rest = path.strip_prefix('/')?;
    let (service, method) = rest.rsplit_once('/')?;
    if service.is_empty() || method.is_empty() || method.contains('/') {
        return None;
    }
    Some((service, method))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types_round_trip() {
        assert_eq!(
            parse_content_type("application/connect+proto"),
            Some(Wire {
                protocol: Protocol::ConnectStreaming,
                codec: Codec::Proto
            })
        );
        assert_eq!(
            parse_content_type("application/grpc-web+proto"),
            Some(Wire {
                protocol: Protocol::GrpcWeb,
                codec: Codec::Proto
            })
        );
        assert_eq!(
            parse_content_type("application/grpc-web"),
            Some(Wire {
                protocol: Protocol::GrpcWeb,
                codec: Codec::Proto
            })
        );
        assert_eq!(
            parse_content_type("application/proto"),
            Some(Wire {
                protocol: Protocol::ConnectUnary,
                codec: Codec::Proto
            })
        );
        assert_eq!(
            parse_content_type("application/json; charset=utf-8"),
            Some(Wire {
                protocol: Protocol::ConnectUnary,
                codec: Codec::Json
            })
        );
        assert_eq!(parse_content_type("text/html"), None);
    }

    #[test]
    fn envelope_round_trip() {
        let body = b"hello world";
        let framed = encode_envelope(0, body);
        assert_eq!(framed.len(), 5 + body.len());
        assert_eq!(framed[0], 0);
        assert_eq!(&framed[1..5], &(body.len() as u32).to_be_bytes());
        let (frame, consumed) = decode_one(&framed).unwrap();
        assert_eq!(consumed, framed.len());
        assert!(frame.is_data());
        assert_eq!(frame.payload, body);
    }

    #[test]
    fn decode_rejects_compressed_and_short() {
        let mut framed = encode_envelope(0, b"x");
        framed[0] = FLAG_COMPRESSED;
        assert_eq!(decode_one(&framed), Err(FrameError::Compressed));
        assert_eq!(decode_one(&[0, 0, 0]), Err(FrameError::ShortPrefix));
        // declares 10 bytes, provides 1
        assert_eq!(
            decode_one(&[0, 0, 0, 0, 10, b'x']),
            Err(FrameError::ShortPayload {
                declared: 10,
                available: 1
            })
        );
    }

    #[test]
    fn request_message_bare_vs_enveloped() {
        let unary = Wire {
            protocol: Protocol::ConnectUnary,
            codec: Codec::Proto,
        };
        assert_eq!(request_message(&unary, b"raw").unwrap(), b"raw");

        let streaming = Wire {
            protocol: Protocol::ConnectStreaming,
            codec: Codec::Proto,
        };
        let framed = encode_envelope(0, b"msg");
        assert_eq!(request_message(&streaming, &framed).unwrap(), b"msg");
        assert_eq!(
            request_message(&streaming, b""),
            Err(FrameError::MissingMessage)
        );
    }

    #[test]
    fn grpc_web_trailers_frame() {
        let framed = encode_grpc_web_trailers(&Status::new(Code::NotFound, "no room"), &[]);
        let (frame, _) = decode_one(&framed).unwrap();
        assert!(frame.is_grpc_web_trailer());
        let block = std::str::from_utf8(frame.payload).unwrap();
        assert!(block.contains("grpc-status: 5\r\n"), "{block}");
        // The gRPC `grpc-message` percent-encoding keeps printable ASCII 0x20-0x7E except `%`, so a
        // plain space stays literal; a control/high byte is escaped.
        assert!(block.contains("grpc-message: no room\r\n"), "{block}");
    }

    #[test]
    fn grpc_message_percent_encodes_non_printable() {
        let framed = encode_grpc_web_trailers(&Status::new(Code::Internal, "a\nb%c"), &[]);
        let (frame, _) = decode_one(&framed).unwrap();
        let block = std::str::from_utf8(frame.payload).unwrap();
        assert!(block.contains("grpc-message: a%0Ab%25c\r\n"), "{block}");
    }

    #[test]
    fn connect_end_stream_ok_is_empty_object() {
        let framed = encode_connect_end_stream(&Status::ok(), &[]);
        let (frame, _) = decode_one(&framed).unwrap();
        assert!(frame.is_connect_end_stream());
        assert_eq!(frame.payload, b"{}");
    }

    #[test]
    fn connect_end_stream_error() {
        let framed = encode_connect_end_stream(&Status::new(Code::PermissionDenied, "nope"), &[]);
        let (frame, _) = decode_one(&framed).unwrap();
        let json = std::str::from_utf8(frame.payload).unwrap();
        assert_eq!(
            json,
            "{\"error\":{\"code\":\"permission_denied\",\"message\":\"nope\"}}"
        );
    }

    #[test]
    fn connect_unary_error_body() {
        assert_eq!(
            connect_error_json(&Status::new(Code::InvalidArgument, "bad")),
            "{\"code\":\"invalid_argument\",\"message\":\"bad\"}"
        );
    }

    #[test]
    fn status_http_mapping() {
        assert_eq!(Code::Unauthenticated.http_status(), 401);
        assert_eq!(Code::PermissionDenied.http_status(), 403);
        assert_eq!(Code::NotFound.http_status(), 404);
        assert_eq!(Code::Internal.http_status(), 500);
        assert_eq!(Code::Unauthenticated.grpc_status(), 16);
    }

    #[test]
    fn rpc_path_split() {
        assert_eq!(
            split_rpc_path("/pms.v1.Reservations/Watch"),
            Some(("pms.v1.Reservations", "Watch"))
        );
        assert_eq!(
            split_rpc_path("/pms.v1.Reservations/Watch?x=1"),
            Some(("pms.v1.Reservations", "Watch"))
        );
        assert_eq!(split_rpc_path("/nomethod"), None);
        assert_eq!(split_rpc_path("noslash/Method"), None);
    }
}
