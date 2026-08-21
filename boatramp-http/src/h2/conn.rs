//! The HTTP/2 connection driver: preface, SETTINGS negotiation, and the
//! read/dispatch loop that enforces framing, stream state (via [`crate::h2::stream`]),
//! flow control, and the connection-vs-stream error split. Single-task; the driver
//! talks only to [`crate::h2::wire::Wire`], so it is identical whether the transport is a
//! plain buffered stream (tests, plaintext h2c) or a splice-capable kTLS socket
//! (`serve_connection_ktls`) where the response body is moved kernel-to-kernel.

use std::collections::HashMap;

#[cfg(target_os = "linux")]
use tokio::io::AsyncReadExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::StreamExt as _;

use crate::h2::error::{ErrorCode, H2Error};
use crate::h2::frame::{self, flag, FrameHeader, FrameType};
use crate::h2::hpack::Hpack;
use crate::h2::http::{self, Handler, Response};
use crate::h2::settings::{self, Settings};
use crate::h2::stream::StreamState;
use crate::h2::wire::Wire;
use crate::h2::CLIENT_PREFACE;

/// Our advertised SETTINGS_MAX_FRAME_SIZE. 16 KiB (the default + minimum) keeps
/// the frame-size checks simple and matches what the proxy body path wants anyway.
const OUR_MAX_FRAME_SIZE: u32 = settings::DEFAULT_MAX_FRAME_SIZE;
/// Our advertised SETTINGS_INITIAL_WINDOW_SIZE for streams the client opens.
const OUR_INITIAL_WINDOW: i32 = settings::DEFAULT_INITIAL_WINDOW_SIZE as i32;
/// Ceiling on a single emitted DATA frame, so the splice path's coalescing pipe
/// (grown to 256 KiB) never overflows. Well above the usual 16 KiB negotiated
/// SETTINGS_MAX_FRAME_SIZE, so it only bites a client that raises the limit.
const MAX_OUT_FRAME: usize = 128 * 1024;
/// Bound on a single request's accumulated header block (HEADERS + CONTINUATION) and
/// on the number of CONTINUATION frames per block — a CONTINUATION flood guard
/// (CVE-2024-27316): unbounded/empty CONTINUATION frames would otherwise grow memory
/// or burn CPU without ever completing a header block.
const MAX_HEADER_BLOCK: usize = 64 * 1024;
const MAX_CONTINUATION_FRAMES: u32 = 64;

struct Stream {
    state: StreamState,
    /// Our remaining send window for this stream (governed by the peer).
    send_window: i64,
    /// The peer's remaining send window into us (we grant it back as we consume).
    recv_window: i64,
    /// In-progress header block awaiting END_HEADERS (HEADERS + CONTINUATION).
    header_buf: Vec<u8>,
    /// True once END_STREAM has been seen from the client for this stream.
    end_stream: bool,
    /// The parsed request, held from when the initial header block completes until
    /// END_STREAM (so a second HEADERS is trailers, not a new request).
    request: Option<http::Request>,
    headers_done: bool,
    /// Declared `content-length`, validated against the DATA total at END_STREAM.
    content_length: Option<u64>,
    body: Vec<u8>,
    body_len: u64,
    /// Unsent response body + how far we've sent. When `out_active`, a window
    /// increase (WINDOW_UPDATE / SETTINGS) resumes sending from `out_off` (§6.9).
    /// A `Body::Splice` is streamed kernel-to-kernel (see `flush_stream`).
    out: http::Body,
    out_off: usize,
    out_active: bool,
}

impl Stream {
    fn new(peer_initial_window: i64) -> Self {
        Self {
            state: StreamState::Idle,
            send_window: peer_initial_window,
            recv_window: settings::DEFAULT_INITIAL_WINDOW_SIZE as i64,
            header_buf: Vec::new(),
            end_stream: false,
            request: None,
            headers_done: false,
            content_length: None,
            body: Vec::new(),
            body_len: 0,
            out: http::Body::Bytes(Vec::new()),
            out_off: 0,
            out_active: false,
        }
    }
}

struct Conn {
    peer: Settings,
    streams: HashMap<u32, Stream>,
    hpack: Hpack,
    conn_send_window: i64,
    /// Highest client stream id seen — new ids must strictly increase (§5.1.1).
    last_client_id: u32,
    /// If set, only a CONTINUATION on this stream is legal next (§6.2).
    expecting_continuation: Option<u32>,
    /// END_STREAM already latched on the pending header block.
    pending_end_stream: bool,
    /// CONTINUATION frames seen for the in-progress header block (flood guard).
    continuation_count: u32,
}

/// Serve one HTTP/2 connection to completion over any `AsyncRead + AsyncWrite`
/// transport (buffered path: tests, plaintext h2c). Returns `Ok(())` on a clean
/// close (client EOF or GOAWAY exchange); framing/protocol violations are turned
/// into a `GOAWAY` and also return `Ok(())` — the connection is done either way.
pub async fn serve_connection<IO, H>(io: IO, handler: H) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let mut wire = Wire::Buffered(io);
    serve_connection_wire(&mut wire, handler).await
}

/// The transport-agnostic connection loop: everything reads/writes through `wire`.
async fn serve_connection_wire<IO, H>(wire: &mut Wire<IO>, handler: H) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    // Client connection preface (RFC 7540 §3.5).
    let mut preface = [0u8; 24];
    if wire.read_exact(&mut preface).await.is_err() {
        return Ok(());
    }
    if preface != CLIENT_PREFACE {
        // Invalid preface (§3.5): terminate the connection. §3.5 allows omitting
        // GOAWAY, and sending one races the drop into a RST; a graceful write-side
        // shutdown FINs cleanly, which is what conformance expects.
        let _ = wire.shutdown().await;
        return Ok(());
    }
    // Our SETTINGS (empty = all defaults), then run the loop.
    let mut out = Vec::new();
    frame::write_frame(&mut out, FrameType::Settings, 0, 0, &[]);
    wire.write_all(&out).await?;

    let mut conn = Conn {
        peer: Settings::default(),
        streams: HashMap::new(),
        hpack: Hpack::new(),
        conn_send_window: settings::DEFAULT_CONNECTION_WINDOW,
        last_client_id: 0,
        expecting_continuation: None,
        pending_end_stream: false,
        continuation_count: 0,
    };

    loop {
        // Read one frame header.
        let mut hdr = [0u8; frame::FRAME_HEADER_LEN];
        if wire.read_exact(&mut hdr).await.is_err() {
            return Ok(()); // client closed
        }
        let header = FrameHeader::parse(&hdr);

        // Frame size limit (§4.2): oversize is a connection FRAME_SIZE_ERROR.
        if header.length > OUR_MAX_FRAME_SIZE {
            return goaway(wire, conn.last_client_id, ErrorCode::FrameSizeError).await;
        }
        let mut payload = vec![0u8; header.length as usize];
        if header.length > 0 && wire.read_exact(&mut payload).await.is_err() {
            return Ok(());
        }

        // While mid-header-block, only a CONTINUATION on the same stream is legal (§6.2).
        if let Some(sid) = conn.expecting_continuation {
            if header.kind != FrameType::Continuation || header.stream_id != sid {
                return goaway(wire, conn.last_client_id, ErrorCode::ProtocolError).await;
            }
        }

        match dispatch(&mut conn, wire, header, payload, &handler).await {
            Ok(true) => {} // continue
            Ok(false) => {
                // The peer sent GOAWAY: finish and close cleanly with a FIN (a
                // GOAWAY-then-drop races into a RST, which conformance rejects).
                let _ = wire.shutdown().await;
                return Ok(());
            }
            Err(H2Error::Connection(code)) => {
                return goaway(wire, conn.last_client_id, code).await;
            }
            Err(H2Error::Stream { id, code }) => {
                if let Some(s) = conn.streams.get_mut(&id) {
                    s.state = StreamState::Closed;
                }
                wire.write_all(&frame::rst_stream(id, code)).await?;
            }
        }
    }
}

/// Handle one frame. Returns `Ok(true)` to continue, `Ok(false)` to shut down, or a
/// scoped [`H2Error`].
async fn dispatch<IO, H>(
    conn: &mut Conn,
    wire: &mut Wire<IO>,
    header: FrameHeader,
    payload: Vec<u8>,
    handler: &H,
) -> Result<bool, H2Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    match header.kind {
        FrameType::Settings => {
            if header.stream_id != 0 {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            if header.has_flag(flag::ACK) {
                if !payload.is_empty() {
                    return Err(H2Error::conn(ErrorCode::FrameSizeError));
                }
                return Ok(true);
            }
            let old_iws = conn.peer.initial_window_size;
            for (id, value) in frame::parse_settings(&payload)? {
                conn.peer.apply(id, value)?;
            }
            // A change to SETTINGS_INITIAL_WINDOW_SIZE shifts every open stream's
            // send window by the delta (§6.9.2); an overflow past 2^31-1 is a
            // connection error of type FLOW_CONTROL_ERROR.
            let new_iws = conn.peer.initial_window_size;
            if new_iws != old_iws {
                let delta = i64::from(new_iws) - i64::from(old_iws);
                for s in conn.streams.values_mut() {
                    s.send_window += delta;
                    if s.send_window > i64::from(settings::MAX_WINDOW_SIZE) {
                        return Err(H2Error::conn(ErrorCode::FlowControlError));
                    }
                }
            }
            wire.write_all(&settings_ack())
                .await
                .map_err(|_| H2Error::conn(ErrorCode::InternalError))?;
            // A larger SETTINGS_INITIAL_WINDOW_SIZE may unblock stalled bodies.
            flush_all(conn, wire).await?;
            Ok(true)
        }

        FrameType::Ping => {
            if header.stream_id != 0 {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            let data = frame::parse_ping(&payload)?;
            if !header.has_flag(flag::ACK) {
                let mut out = Vec::with_capacity(frame::FRAME_HEADER_LEN + 8);
                frame::write_frame(&mut out, FrameType::Ping, flag::ACK, 0, &data);
                wire.write_all(&out)
                    .await
                    .map_err(|_| H2Error::conn(ErrorCode::InternalError))?;
            }
            Ok(true)
        }

        FrameType::GoAway => {
            frame::parse_goaway(&payload)?;
            Ok(false)
        }

        FrameType::WindowUpdate => {
            let inc = frame::parse_window_update(&payload)?;
            if header.stream_id == 0 {
                if inc == 0 {
                    return Err(H2Error::conn(ErrorCode::ProtocolError));
                }
                conn.conn_send_window += i64::from(inc);
                if conn.conn_send_window > i64::from(settings::MAX_WINDOW_SIZE) {
                    return Err(H2Error::conn(ErrorCode::FlowControlError));
                }
            } else {
                // WINDOW_UPDATE on an idle (never-opened) stream is a connection
                // error of type PROTOCOL_ERROR (§5.1 idle).
                if !conn.streams.contains_key(&header.stream_id)
                    && header.stream_id > conn.last_client_id
                {
                    return Err(H2Error::conn(ErrorCode::ProtocolError));
                }
                if inc == 0 {
                    return Err(H2Error::stream(header.stream_id, ErrorCode::ProtocolError));
                }
                if let Some(s) = conn.streams.get_mut(&header.stream_id) {
                    s.send_window += i64::from(inc);
                    if s.send_window > i64::from(settings::MAX_WINDOW_SIZE) {
                        return Err(H2Error::stream(
                            header.stream_id,
                            ErrorCode::FlowControlError,
                        ));
                    }
                }
            }
            // A window increase may unblock a stalled response body (§6.9).
            if header.stream_id == 0 {
                flush_all(conn, wire).await?;
            } else {
                flush_stream(conn, wire, header.stream_id).await?;
            }
            Ok(true)
        }

        FrameType::RstStream => {
            if header.stream_id == 0 {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            let _ = frame::parse_rst_stream(&payload)?;
            // An RST_STREAM for an idle stream is a connection error (§5.1).
            if !conn.streams.contains_key(&header.stream_id)
                && header.stream_id > conn.last_client_id
            {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            if let Some(s) = conn.streams.get_mut(&header.stream_id) {
                s.state = StreamState::Closed;
            }
            Ok(true)
        }

        FrameType::Priority => {
            if header.stream_id == 0 {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            let prio = frame::parse_priority(&payload)?;
            // A stream cannot depend on itself (§5.3.1) — stream PROTOCOL_ERROR.
            if prio.dependency == header.stream_id {
                return Err(H2Error::stream(header.stream_id, ErrorCode::ProtocolError));
            }
            Ok(true)
        }

        FrameType::Headers => headers_frame(conn, wire, header, payload, handler).await,

        FrameType::Continuation => {
            // A CONTINUATION MUST be preceded by a HEADERS/CONTINUATION without
            // END_HEADERS (§6.10); otherwise a connection PROTOCOL_ERROR.
            let sid = header.stream_id;
            if conn.expecting_continuation != Some(sid) {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            conn.continuation_count += 1;
            if conn.continuation_count > MAX_CONTINUATION_FRAMES {
                return Err(H2Error::conn(ErrorCode::EnhanceYourCalm));
            }
            if let Some(s) = conn.streams.get_mut(&sid) {
                if s.header_buf.len() + payload.len() > MAX_HEADER_BLOCK {
                    return Err(H2Error::conn(ErrorCode::EnhanceYourCalm));
                }
                s.header_buf.extend_from_slice(&payload);
            }
            if header.has_flag(flag::END_HEADERS) {
                conn.expecting_continuation = None;
                finish_headers(conn, wire, sid, handler).await?;
            }
            Ok(true)
        }

        FrameType::Data => data_frame(conn, wire, header, payload, handler).await,

        // SETTINGS/PING/GOAWAY on non-zero streams were handled above; PUSH_PROMISE
        // from a client is illegal; unknown types are ignored (§4.1, §5.5).
        FrameType::PushPromise => Err(H2Error::conn(ErrorCode::ProtocolError)),
        FrameType::Unknown(_) => Ok(true),
    }
}

async fn headers_frame<IO, H>(
    conn: &mut Conn,
    wire: &mut Wire<IO>,
    header: FrameHeader,
    payload: Vec<u8>,
    handler: &H,
) -> Result<bool, H2Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let sid = header.stream_id;
    // Client streams are odd and strictly increasing (§5.1.1).
    if sid == 0 || sid % 2 == 0 {
        return Err(H2Error::conn(ErrorCode::ProtocolError));
    }
    let new_stream = !conn.streams.contains_key(&sid);
    if new_stream && sid <= conn.last_client_id {
        return Err(H2Error::conn(ErrorCode::ProtocolError));
    }
    // HEADERS on a stream already closed (by END_STREAM) is a connection error of
    // type STREAM_CLOSED (§5.1 closed).
    if conn
        .streams
        .get(&sid)
        .is_some_and(|s| s.state == StreamState::Closed)
    {
        return Err(H2Error::conn(ErrorCode::StreamClosed));
    }

    // Strip padding, then the optional priority section (§6.2).
    let mut block = frame::strip_padding(&payload, header.has_flag(flag::PADDED))?;
    if header.has_flag(flag::PRIORITY) {
        if block.len() < 5 {
            return Err(H2Error::conn(ErrorCode::FrameSizeError));
        }
        let prio = frame::parse_priority(&block[..5])?;
        // A stream cannot depend on itself (§5.3.1).
        if prio.dependency == sid {
            return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
        }
        block = &block[5..];
    }

    if new_stream {
        conn.last_client_id = sid;
        conn.streams
            .insert(sid, Stream::new(i64::from(conn.peer.initial_window_size)));
    }
    // Advance the stream state for receiving HEADERS.
    let end_stream = header.has_flag(flag::END_STREAM);
    let st = {
        let s = conn.streams.get(&sid).unwrap();
        s.state.on_recv(sid, FrameType::Headers, end_stream)?
    };
    if block.len() > MAX_HEADER_BLOCK {
        return Err(H2Error::conn(ErrorCode::EnhanceYourCalm));
    }
    conn.continuation_count = 0;
    let s = conn.streams.get_mut(&sid).unwrap();
    s.state = st;
    s.end_stream = end_stream;
    s.header_buf.extend_from_slice(block);

    if header.has_flag(flag::END_HEADERS) {
        finish_headers(conn, wire, sid, handler).await?;
    } else {
        conn.expecting_continuation = Some(sid);
        conn.pending_end_stream = end_stream;
    }
    Ok(true)
}

/// Decode a completed header block, validate the request, and — if END_STREAM has
/// arrived — run the handler and send the response.
async fn finish_headers<IO, H>(
    conn: &mut Conn,
    wire: &mut Wire<IO>,
    sid: u32,
    handler: &H,
) -> Result<(), H2Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let (block, headers_done) = match conn.streams.get_mut(&sid) {
        Some(s) => (std::mem::take(&mut s.header_buf), s.headers_done),
        None => return Err(H2Error::conn(ErrorCode::ProtocolError)),
    };
    let headers = conn.hpack.decode(&block)?; // COMPRESSION_ERROR is a connection error
    if headers_done {
        // A second header block is trailers (§8.1.2.3): they MUST carry END_STREAM
        // and MUST NOT contain pseudo-header fields. M1 doesn't surface the fields.
        if !conn.streams.get(&sid).is_some_and(|s| s.end_stream) {
            return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
        }
        if headers.iter().any(|(n, _)| n.first() == Some(&b':')) {
            return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
        }
    } else {
        let req = http::request_from_headers(sid, headers)?;
        let cl = req
            .headers()
            .get(::http::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
        let s = conn.streams.get_mut(&sid).unwrap();
        s.content_length = cl;
        s.request = Some(req);
        s.headers_done = true;
    }
    if conn.streams.get(&sid).is_some_and(|s| s.end_stream) {
        maybe_respond(conn, wire, sid, handler).await?;
    }
    Ok(())
}

/// On END_STREAM: validate the declared content-length against the DATA total
/// (§8.1.2.6) and run the handler with the stored request.
async fn maybe_respond<IO, H>(
    conn: &mut Conn,
    wire: &mut Wire<IO>,
    sid: u32,
    handler: &H,
) -> Result<(), H2Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let (cl, body_len) = {
        let s = conn
            .streams
            .get(&sid)
            .ok_or_else(|| H2Error::conn(ErrorCode::ProtocolError))?;
        (s.content_length, s.body_len)
    };
    if cl.is_some_and(|cl| cl != body_len) {
        return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
    }
    let (req, body) = {
        let s = conn.streams.get_mut(&sid).unwrap();
        (s.request.take(), std::mem::take(&mut s.body))
    };
    if let Some(mut req) = req {
        *req.body_mut() = crate::ReqBody::from_bytes(bytes::Bytes::from(body));
        respond(conn, wire, sid, handler, req).await?;
    }
    Ok(())
}

async fn data_frame<IO, H>(
    conn: &mut Conn,
    wire: &mut Wire<IO>,
    header: FrameHeader,
    payload: Vec<u8>,
    handler: &H,
) -> Result<bool, H2Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let sid = header.stream_id;
    if sid == 0 {
        return Err(H2Error::conn(ErrorCode::ProtocolError));
    }
    // Connection-level flow control counts the *whole* payload incl. padding (§6.9.1).
    // Advance stream state first (rejects DATA on idle/half-closed/closed).
    let end_stream = header.has_flag(flag::END_STREAM);
    let state = conn
        .streams
        .get(&sid)
        .ok_or_else(|| H2Error::conn(ErrorCode::ProtocolError))?
        .state;
    let next = state.on_recv(sid, FrameType::Data, end_stream)?;
    let data = frame::strip_padding(&payload, header.has_flag(flag::PADDED))?;

    // Replenish the receive window immediately (M1 buffers small bodies).
    let n = payload.len() as i32;
    let s = conn.streams.get_mut(&sid).unwrap();
    s.state = next;
    s.body.extend_from_slice(data);
    s.body_len += data.len() as u64;
    s.end_stream = end_stream;
    let _ = s.recv_window; // full flow-control accounting lands with the M4 body path

    if n > 0 {
        // WINDOW_UPDATE for the connection and the stream, keeping the window open.
        let mut out = Vec::new();
        frame::write_frame(
            &mut out,
            FrameType::WindowUpdate,
            0,
            0,
            &(n as u32).to_be_bytes(),
        );
        frame::write_frame(
            &mut out,
            FrameType::WindowUpdate,
            0,
            sid,
            &(n as u32).to_be_bytes(),
        );
        wire.write_all(&out)
            .await
            .map_err(|_| H2Error::conn(ErrorCode::InternalError))?;
    }

    if end_stream {
        maybe_respond(conn, wire, sid, handler).await?;
    }
    Ok(true)
}

/// Run the handler and write the response (HEADERS + DATA). M1 buffers the body and
/// assumes it fits the send window (h2spec responses are tiny); the large-body path
/// is the M4 splice seam.
async fn respond<IO, H>(
    conn: &mut Conn,
    wire: &mut Wire<IO>,
    sid: u32,
    handler: &H,
    req: http::Request,
) -> Result<(), H2Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let resp: Response = handler.handle(req).await;
    let (parts, body) = resp.into_parts();
    // The serial driver can't interleave a streamed body, so drain it to bytes here
    // (the mux driver streams it natively). Done before content-length is derived.
    let body = match body {
        http::Body::Stream(mut stream) => {
            let mut buf = Vec::new();
            while let Some(item) = stream.next().await {
                match item {
                    Ok(chunk) => buf.extend_from_slice(&chunk),
                    Err(_) => break, // upstream failed mid-stream; serve what we have
                }
            }
            http::Body::Bytes(buf)
        }
        other => other,
    };
    let status = parts.status.as_u16().to_string();
    let mut fields: Vec<(&[u8], &[u8])> = vec![(b":status", status.as_bytes())];
    for (n, v) in &parts.headers {
        // Drop connection-specific headers HTTP/2 forbids (§8.1.2.2); the shared
        // handler also serves h1, where these are legal (see `is_connection_specific`).
        if crate::h2::http::is_connection_specific(n.as_str().as_bytes()) {
            continue;
        }
        fields.push((n.as_str().as_bytes(), v.as_bytes()));
    }
    let clen;
    let has_body = !body.is_empty();
    if has_body {
        clen = body.len().to_string();
        fields.push((b"content-length", clen.as_bytes()));
    }
    let block = conn.hpack.encode(&fields);

    let mut hflags = flag::END_HEADERS;
    if !has_body {
        hflags |= flag::END_STREAM;
    }
    let mut out = Vec::new();
    frame::write_frame(&mut out, FrameType::Headers, hflags, sid, &block);
    wire.write_all(&out)
        .await
        .map_err(|_| H2Error::conn(ErrorCode::InternalError))?;

    if let Some(s) = conn.streams.get_mut(&sid) {
        if has_body {
            s.out = body;
            s.out_off = 0;
            s.out_active = true;
        } else {
            // Bodyless response: HEADERS carried END_STREAM.
            s.state = if s.state == StreamState::HalfClosedRemote {
                StreamState::Closed
            } else {
                StreamState::HalfClosedLocal
            };
        }
    }
    if has_body {
        flush_stream(conn, wire, sid).await?;
    }
    let _ = OUR_INITIAL_WINDOW;
    Ok(())
}

/// Send as much of a stream's pending response body as the stream + connection send
/// windows allow, END_STREAM on the final DATA frame. Called when the response is
/// queued and again whenever a window increase (WINDOW_UPDATE / SETTINGS) reopens
/// capacity (§6.9).
///
/// A `Body::Bytes` is copied into the frame in userspace. A `Body::Splice` on a
/// splice-capable wire (kTLS socket) is moved kernel-to-kernel — the DATA header and
/// the upstream body drain through one pipe into the connection fd with `splice()`,
/// the kernel encrypting on TX — with only the 9-byte header touching userspace; on a
/// buffered wire (plaintext h2c) it degrades to a userspace read+write.
async fn flush_stream<IO>(conn: &mut Conn, wire: &mut Wire<IO>, sid: u32) -> Result<(), H2Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let remaining = match conn.streams.get(&sid) {
            Some(s) if s.out_active => s.out.len() - s.out_off,
            _ => return Ok(()),
        };
        let swin = conn.streams.get(&sid).map_or(0, |s| s.send_window.max(0));
        let win = swin
            .min(conn.conn_send_window.max(0))
            .min(i64::from(conn.peer.max_frame_size))
            .min(MAX_OUT_FRAME as i64) as usize;
        if win == 0 {
            return Ok(()); // window exhausted; resume on the next WINDOW_UPDATE
        }
        let chunk = remaining.min(win);
        let is_last = chunk == remaining;
        let off = conn.streams.get(&sid).unwrap().out_off;
        let hdr = frame::data_header(sid, chunk as u32, is_last);
        #[cfg(target_os = "linux")]
        let can_splice = wire.can_splice();
        match &mut conn.streams.get_mut(&sid).unwrap().out {
            http::Body::Bytes(b) => {
                let mut buf = Vec::with_capacity(frame::FRAME_HEADER_LEN + chunk);
                buf.extend_from_slice(&hdr);
                buf.extend_from_slice(&b[off..off + chunk]);
                wire.write_all(&buf)
                    .await
                    .map_err(|_| H2Error::conn(ErrorCode::InternalError))?;
            }
            #[cfg(target_os = "linux")]
            http::Body::Splice { upstream, .. } => {
                if can_splice {
                    // Zero-copy: splice(upstream -> pipe -> connection fd); the DATA
                    // header rides in the same TLS record as the body.
                    wire.splice_data_frame(upstream, &hdr, chunk)
                        .await
                        .map_err(|_| H2Error::conn(ErrorCode::InternalError))?;
                } else {
                    // Buffered wire (plaintext h2c): stream `chunk` bytes from the
                    // upstream through userspace.
                    let mut buf = Vec::with_capacity(frame::FRAME_HEADER_LEN + chunk);
                    buf.extend_from_slice(&hdr);
                    let start = buf.len();
                    buf.resize(start + chunk, 0);
                    upstream
                        .read_exact(&mut buf[start..])
                        .await
                        .map_err(|_| H2Error::conn(ErrorCode::InternalError))?;
                    wire.write_all(&buf)
                        .await
                        .map_err(|_| H2Error::conn(ErrorCode::InternalError))?;
                }
            }
            // `respond` drains a streamed body to `Bytes` before it is ever queued, so
            // the serial driver never flushes a `Stream`.
            http::Body::Stream(_) => {
                unreachable!("serial driver buffers stream bodies in respond")
            }
        }
        conn.conn_send_window -= chunk as i64;
        let s = conn.streams.get_mut(&sid).unwrap();
        s.out_off += chunk;
        s.send_window -= chunk as i64;
        if is_last {
            s.out_active = false;
            s.out = http::Body::Bytes(Vec::new());
            s.state = if s.state == StreamState::HalfClosedRemote {
                StreamState::Closed
            } else {
                StreamState::HalfClosedLocal
            };
            return Ok(());
        }
    }
}

/// Serve one HTTP/2 connection over a plaintext TCP socket (h2c). `Body::Splice`
/// routes through the userspace streaming path in `flush_stream`; the kernel splice +
/// kTLS zero-copy body is `serve_connection_ktls`.
#[cfg(target_os = "linux")]
pub async fn serve_connection_tcp<H>(tcp: tokio::net::TcpStream, handler: H) -> std::io::Result<()>
where
    H: Handler,
{
    serve_connection(tcp, handler).await
}

/// Serve one HTTP/2 connection over **kTLS**: perform the rustls handshake, hand the
/// socket off to the kernel TLS state machine, then drive the h2 loop over the raw fd
/// — so a `Body::Splice` response is moved upstream→pipe→socket with `splice()` and
/// the kernel encrypts on TX. The `ServerConfig` behind `acceptor` MUST have
/// `enable_secret_extraction = true` and advertise ALPN `h2`.
#[cfg(target_os = "linux")]
pub async fn serve_connection_ktls<H>(
    tcp: tokio::net::TcpStream,
    acceptor: tokio_rustls::TlsAcceptor,
    handler: H,
) -> std::io::Result<()>
where
    H: Handler,
{
    tcp.set_nodelay(true).ok();
    // CorkStream makes rustls read one TLS record at a time so the handshake ends on
    // a record boundary — a prerequisite for the kTLS handoff.
    let tls = acceptor.accept(ktls::CorkStream::new(tcp)).await?;
    let kstream = ktls::config_ktls_server(tls)
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("ktls: {e}")))?;
    // Reclaim the owned TcpStream + any plaintext rustls drained before kTLS took over
    // the socket (a raw recv() would otherwise miss those bytes). `config_ktls_server`
    // unwraps the CorkStream, so `into_raw` yields the bare TcpStream.
    let (drained, sock) = kstream.into_raw();
    let sock = crate::h2::wire::Socket::new(sock, drained.unwrap_or_default())?;
    let mut wire: Wire<tokio::net::TcpStream> = Wire::Socket(sock);
    serve_connection_wire(&mut wire, handler).await
}

/// Resume every stream with a pending response (after a connection-level window
/// increase or a SETTINGS_INITIAL_WINDOW_SIZE bump).
async fn flush_all<IO>(conn: &mut Conn, wire: &mut Wire<IO>) -> Result<(), H2Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let ids: Vec<u32> = conn
        .streams
        .iter()
        .filter(|(_, s)| s.out_active)
        .map(|(id, _)| *id)
        .collect();
    for id in ids {
        flush_stream(conn, wire, id).await?;
    }
    Ok(())
}

fn settings_ack() -> Vec<u8> {
    let mut out = Vec::with_capacity(frame::FRAME_HEADER_LEN);
    frame::write_frame(&mut out, FrameType::Settings, flag::ACK, 0, &[]);
    out
}

async fn goaway<IO>(wire: &mut Wire<IO>, last: u32, code: ErrorCode) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    wire.write_all(&frame::goaway(last, code, &[])).await?;
    Ok(())
}
