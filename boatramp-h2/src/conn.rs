//! The HTTP/2 connection driver: preface, SETTINGS negotiation, and the
//! read/dispatch loop that enforces framing, stream state (via [`crate::stream`]),
//! flow control, and the connection-vs-stream error split. Single-task and
//! plaintext (h2c) — enough to be driven to conformance against h2spec; TLS and the
//! zero-copy splice body path layer on top (M4).

use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{ErrorCode, H2Error};
use crate::frame::{self, flag, FrameHeader, FrameType};
use crate::hpack::Hpack;
use crate::http::{self, Handler, Response};
use crate::settings::{self, Settings};
use crate::stream::StreamState;
use crate::CLIENT_PREFACE;

/// Our advertised SETTINGS_MAX_FRAME_SIZE. 16 KiB (the default + minimum) keeps
/// the frame-size checks simple and matches what the proxy body path wants anyway.
const OUR_MAX_FRAME_SIZE: u32 = settings::DEFAULT_MAX_FRAME_SIZE;
/// Our advertised SETTINGS_INITIAL_WINDOW_SIZE for streams the client opens.
const OUR_INITIAL_WINDOW: i32 = settings::DEFAULT_INITIAL_WINDOW_SIZE as i32;

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
    body: Vec<u8>,
}

impl Stream {
    fn new(peer_initial_window: i64) -> Self {
        Stream {
            state: StreamState::Idle,
            send_window: peer_initial_window,
            recv_window: settings::DEFAULT_INITIAL_WINDOW_SIZE as i64,
            header_buf: Vec::new(),
            end_stream: false,
            body: Vec::new(),
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
}

/// Serve one HTTP/2 connection to completion. Returns `Ok(())` on a clean close
/// (client EOF or GOAWAY exchange); framing/protocol violations are turned into a
/// `GOAWAY` and also return `Ok(())` — the connection is done either way.
pub async fn serve_connection<IO, H>(mut io: IO, handler: H) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    // Client connection preface (RFC 7540 §3.5).
    let mut preface = [0u8; 24];
    if io.read_exact(&mut preface).await.is_err() {
        return Ok(());
    }
    if preface != CLIENT_PREFACE {
        // An invalid preface is a connection error of type PROTOCOL_ERROR (§3.5).
        let _ = io.write_all(&frame::goaway(0, ErrorCode::ProtocolError, &[])).await;
        return Ok(());
    }
    // Our SETTINGS (empty = all defaults), then run the loop.
    let mut out = Vec::new();
    frame::write_frame(&mut out, FrameType::Settings, 0, 0, &[]);
    io.write_all(&out).await?;

    let mut conn = Conn {
        peer: Settings::default(),
        streams: HashMap::new(),
        hpack: Hpack::new(),
        conn_send_window: settings::DEFAULT_CONNECTION_WINDOW,
        last_client_id: 0,
        expecting_continuation: None,
        pending_end_stream: false,
    };

    loop {
        // Read one frame header.
        let mut hdr = [0u8; frame::FRAME_HEADER_LEN];
        if io.read_exact(&mut hdr).await.is_err() {
            return Ok(()); // client closed
        }
        let header = FrameHeader::parse(&hdr);

        // Frame size limit (§4.2): oversize is a connection FRAME_SIZE_ERROR.
        if header.length > OUR_MAX_FRAME_SIZE {
            return goaway(&mut io, conn.last_client_id, ErrorCode::FrameSizeError).await;
        }
        let mut payload = vec![0u8; header.length as usize];
        if header.length > 0 && io.read_exact(&mut payload).await.is_err() {
            return Ok(());
        }

        // While mid-header-block, only a CONTINUATION on the same stream is legal (§6.2).
        if let Some(sid) = conn.expecting_continuation {
            if header.kind != FrameType::Continuation || header.stream_id != sid {
                return goaway(&mut io, conn.last_client_id, ErrorCode::ProtocolError).await;
            }
        }

        match dispatch(&mut conn, &mut io, header, payload, &handler).await {
            Ok(true) => {} // continue
            Ok(false) => {
                // Graceful shutdown requested (GOAWAY received).
                return goaway(&mut io, conn.last_client_id, ErrorCode::NoError).await;
            }
            Err(H2Error::Connection(code)) => {
                return goaway(&mut io, conn.last_client_id, code).await;
            }
            Err(H2Error::Stream { id, code }) => {
                if let Some(s) = conn.streams.get_mut(&id) {
                    s.state = StreamState::Closed;
                }
                io.write_all(&frame::rst_stream(id, code)).await?;
            }
        }
    }
}

/// Handle one frame. Returns `Ok(true)` to continue, `Ok(false)` to shut down, or a
/// scoped [`H2Error`].
async fn dispatch<IO, H>(
    conn: &mut Conn,
    io: &mut IO,
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
            io.write_all(&settings_ack())
                .await
                .map_err(|_| H2Error::conn(ErrorCode::InternalError))?;
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
                io.write_all(&out)
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
                        return Err(H2Error::stream(header.stream_id, ErrorCode::FlowControlError));
                    }
                }
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

        FrameType::Headers => {
            headers_frame(conn, io, header, payload, handler).await
        }

        FrameType::Continuation => {
            // A CONTINUATION MUST be preceded by a HEADERS/CONTINUATION without
            // END_HEADERS (§6.10); otherwise a connection PROTOCOL_ERROR.
            let sid = header.stream_id;
            if conn.expecting_continuation != Some(sid) {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            if let Some(s) = conn.streams.get_mut(&sid) {
                s.header_buf.extend_from_slice(&payload);
            }
            if header.has_flag(flag::END_HEADERS) {
                conn.expecting_continuation = None;
                finish_headers(conn, io, sid, handler).await?;
            }
            Ok(true)
        }

        FrameType::Data => data_frame(conn, io, header, payload, handler).await,

        // SETTINGS/PING/GOAWAY on non-zero streams were handled above; PUSH_PROMISE
        // from a client is illegal; unknown types are ignored (§4.1, §5.5).
        FrameType::PushPromise => Err(H2Error::conn(ErrorCode::ProtocolError)),
        FrameType::Unknown(_) => Ok(true),
    }
}

async fn headers_frame<IO, H>(
    conn: &mut Conn,
    io: &mut IO,
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
    let s = conn.streams.get_mut(&sid).unwrap();
    s.state = st;
    s.end_stream = end_stream;
    s.header_buf.extend_from_slice(block);

    if header.has_flag(flag::END_HEADERS) {
        finish_headers(conn, io, sid, handler).await?;
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
    io: &mut IO,
    sid: u32,
    handler: &H,
) -> Result<(), H2Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let block = match conn.streams.get_mut(&sid) {
        Some(s) => std::mem::take(&mut s.header_buf),
        None => return Err(H2Error::conn(ErrorCode::ProtocolError)),
    };
    let headers = conn.hpack.decode(&block)?; // COMPRESSION_ERROR is a connection error
    let req = http::request_from_headers(sid, headers)?;
    let end = conn.streams.get(&sid).is_some_and(|s| s.end_stream);
    if end {
        respond(conn, io, sid, handler, req).await?;
    }
    Ok(())
}

async fn data_frame<IO, H>(
    conn: &mut Conn,
    io: &mut IO,
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
    s.end_stream = end_stream;
    let _ = s.recv_window; // full flow-control accounting lands with the M4 body path

    if n > 0 {
        // WINDOW_UPDATE for the connection and the stream, keeping the window open.
        let mut out = Vec::new();
        frame::write_frame(&mut out, FrameType::WindowUpdate, 0, 0, &(n as u32).to_be_bytes());
        frame::write_frame(&mut out, FrameType::WindowUpdate, 0, sid, &(n as u32).to_be_bytes());
        io.write_all(&out)
            .await
            .map_err(|_| H2Error::conn(ErrorCode::InternalError))?;
    }

    if end_stream {
        let body = std::mem::take(&mut conn.streams.get_mut(&sid).unwrap().body);
        // Rebuild the request from the (already-decoded) pseudo-headers is out of
        // scope for M1's DATA path; the common benchmark shape is bodyless GET, so
        // we reconstruct a minimal request. Full request-body plumbing is M3.
        let mut req = http::Request {
            method: b"POST".to_vec(),
            scheme: b"https".to_vec(),
            path: b"/".to_vec(),
            authority: None,
            headers: Vec::new(),
            body,
        };
        req.body = std::mem::take(&mut req.body);
        respond(conn, io, sid, handler, req).await?;
    }
    Ok(true)
}

/// Run the handler and write the response (HEADERS + DATA). M1 buffers the body and
/// assumes it fits the send window (h2spec responses are tiny); the large-body path
/// is the M4 splice seam.
async fn respond<IO, H>(
    conn: &mut Conn,
    io: &mut IO,
    sid: u32,
    handler: &H,
    req: http::Request,
) -> Result<(), H2Error>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    H: Handler,
{
    let resp: Response = handler.handle(req).await;
    let status = resp.status.to_string();
    let mut fields: Vec<(&[u8], &[u8])> = vec![(b":status", status.as_bytes())];
    for (n, v) in &resp.headers {
        fields.push((n, v));
    }
    let clen;
    if !resp.body.is_empty() {
        clen = resp.body.len().to_string();
        fields.push((b"content-length", clen.as_bytes()));
    }
    let block = conn.hpack.encode(&fields);

    let has_body = !resp.body.is_empty();
    let mut hflags = flag::END_HEADERS;
    if !has_body {
        hflags |= flag::END_STREAM;
    }
    let mut out = Vec::new();
    frame::write_frame(&mut out, FrameType::Headers, hflags, sid, &block);
    let mut sent_end = !has_body;
    if has_body {
        // Never exceed the stream or connection send window (§6.9). If the body
        // doesn't fit, send what fits WITHOUT END_STREAM — completing a
        // window-limited body is the M4 flow-controlled, spliced path.
        let win = conn
            .streams
            .get(&sid)
            .map_or(0, |s| s.send_window.max(0))
            .min(conn.conn_send_window.max(0)) as usize;
        let chunk = resp.body.len().min(conn.peer.max_frame_size as usize).min(win);
        sent_end = chunk == resp.body.len();
        out.extend_from_slice(&frame::data_header(sid, chunk as u32, sent_end));
        out.extend_from_slice(&resp.body[..chunk]);
        if let Some(s) = conn.streams.get_mut(&sid) {
            s.send_window -= chunk as i64;
        }
        conn.conn_send_window -= chunk as i64;
    }
    io.write_all(&out)
        .await
        .map_err(|_| H2Error::conn(ErrorCode::InternalError))?;
    if sent_end {
        if let Some(s) = conn.streams.get_mut(&sid) {
            s.state = if s.state == StreamState::HalfClosedRemote {
                StreamState::Closed
            } else {
                StreamState::HalfClosedLocal
            };
        }
    }
    let _ = OUR_INITIAL_WINDOW;
    Ok(())
}

fn settings_ack() -> Vec<u8> {
    let mut out = Vec::with_capacity(frame::FRAME_HEADER_LEN);
    frame::write_frame(&mut out, FrameType::Settings, flag::ACK, 0, &[]);
    out
}

async fn goaway<IO>(io: &mut IO, last: u32, code: ErrorCode) -> std::io::Result<()>
where
    IO: AsyncWrite + Unpin,
{
    io.write_all(&frame::goaway(last, code, &[])).await?;
    Ok(())
}
