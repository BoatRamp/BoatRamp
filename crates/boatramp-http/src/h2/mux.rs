//! The **concurrent multiplexed** connection driver (M4c). Unlike the serial
//! [`crate::h2::conn`] driver — which reads one frame, runs the handler to completion,
//! and flushes the whole body before reading the next frame (a ~340 req/s
//! per-connection ceiling) — this driver only ever *moves bytes*, exactly like the
//! `h2` crate:
//!
//! - a **reader** half drains inbound frames, routing them to per-stream state and
//!   spawning a handler task per request (never running a handler inline);
//! - each **handler** task produces its response into the stream's outbox and wakes
//!   the writer;
//! - a **writer** half drains ready streams' outboxes into one batched write,
//!   respecting two-tier (connection + per-stream) flow control.
//!
//! Reads never block on handler progress and handlers never touch the socket, so one
//! connection multiplexes all its streams concurrently. HPACK decode lives in the
//! reader and encode in the writer — HTTP/2 uses independent compression contexts
//! per direction, so these are two separate, unsynchronized tables.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, LazyLock, Mutex};

use bytes::Bytes;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_stream::StreamExt as _;

use crate::h2::error::{ErrorCode, H2Error};
use crate::h2::frame::{self, flag, FrameHeader, FrameType};
use crate::h2::hpack::Hpack;
use crate::h2::http::{self, Handler, Response};
use crate::h2::settings::{self, Settings};
use crate::h2::stream::StreamState;
use crate::h2::CLIENT_PREFACE;

const OUR_MAX_FRAME_SIZE: u32 = settings::DEFAULT_MAX_FRAME_SIZE;
/// Cap on a single emitted DATA frame (keeps batches bounded; well above the usual
/// 16 KiB negotiated max-frame).
const MAX_OUT_FRAME: usize = 128 * 1024;
/// Bound on a single request's accumulated header block (HEADERS + CONTINUATION), to
/// cap memory against a CONTINUATION flood (CVE-2024-27316).
const MAX_HEADER_BLOCK: usize = 64 * 1024;
/// Bound on CONTINUATION frames per header block, to cap CPU against a flood of
/// *empty* CONTINUATION frames (which add no bytes but force frame parsing).
const MAX_CONTINUATION_FRAMES: u32 = 64;
/// A connection may reset this many streams "for free"; past it, resetting more than
/// half of all opened streams is treated as a Rapid Reset flood (CVE-2023-44487) and
/// the connection is closed with ENHANCE_YOUR_CALM. Legitimate clients reset a small
/// fraction of their streams; a rapid-reset attacker resets ~all of them.
const RAPID_RESET_MIN: u64 = 100;
/// The `SETTINGS_MAX_CONCURRENT_STREAMS` we advertise and enforce (§5.1.2): a hard
/// cap on a connection's simultaneously-active streams, bounding per-connection
/// memory and a further mitigation for stream-concurrency floods (CVE-2023-44487).
/// 256 is well above any legitimate multiplexing need; the (limit + 1)th concurrent
/// stream is refused with `RST_STREAM(REFUSED_STREAM)`, which a client may retry on a
/// new connection. Matches the cap the previous hyper serving path advertised.
const MAX_CONCURRENT_STREAMS: u32 = 256;
/// Soft target for one batched socket write: keep draining ready streams into the
/// buffer until it reaches this, then write and start a fresh batch.
const WRITE_BATCH_TARGET: usize = 64 * 1024;
/// A streaming producer stops pulling its source once this many response bytes are
/// queued-but-unsent for its stream (the writer is behind — usually a flow-control
/// window the slow client hasn't opened). Bounds per-stream memory regardless of body
/// size; large enough to keep the writer fed across a batch + a window.
///
/// The dominant per-stream resident cost under h2 concurrency (256 streams × this),
/// so it is tunable via `BOATRAMP_H2_HIGH_WATER_KB` (default 256) to trade steady-state
/// RSS against producer stalls on memory-constrained hosts.
static STREAM_HIGH_WATER: LazyLock<usize> =
    LazyLock::new(|| env_kb("BOATRAMP_H2_HIGH_WATER_KB", 256));
/// A parked streaming producer resumes once the writer drains the per-stream buffer
/// back below this. **Derived** as half the high-water (not an independent knob) so the
/// hysteresis gap is always valid: a hand-set low-water above the high-water inverts the
/// pause/resume logic and stalls the stream (measured — a 64 KiB high-water against the
/// old fixed 128 KiB low-water collapsed 100 KiB h2 throughput to ~210 rps). Half gives a
/// generous gap while tracking the high-water automatically; default 256→128 as before.
static STREAM_LOW_WATER: LazyLock<usize> = LazyLock::new(|| *STREAM_HIGH_WATER / 2);

/// Read a kibibyte-valued env knob, falling back to `default_kb` when unset/invalid.
fn env_kb(name: &str, default_kb: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(default_kb * 1024, |kb| kb * 1024)
}
/// How long the reader keeps draining inbound bytes after we've decided to close,
/// before giving up and letting the socket drop. Bounds a graceful close against a
/// peer that never closes its side; a well-behaved peer closes as soon as it sees
/// our GOAWAY/FIN, so this rarely elapses.
const GRACEFUL_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A response frame a handler has produced, awaiting the writer + flow control.
enum OutFrame {
    Headers {
        fields: Vec<(Vec<u8>, Vec<u8>)>,
        end_stream: bool,
    },
    Data {
        bytes: Bytes,
        off: usize,
        end_stream: bool,
    },
}

struct MuxStream {
    state: StreamState,
    send_window: i64,
    outbox: VecDeque<OutFrame>,
    /// Whether this stream is currently in the ready queue (dedup guard).
    queued: bool,
    /// Reset by the peer or a local stream error — drop its pending output.
    reset: bool,
    /// Bytes of DATA queued in `outbox` but not yet written — the per-stream send
    /// buffer depth. A streaming producer pauses when this crosses [`STREAM_HIGH_WATER`]
    /// and resumes (via [`MuxStream::drain`]) once the writer drains it below
    /// [`STREAM_LOW_WATER`], so a slow client can't force the whole body into memory.
    unsent: usize,
    /// Woken by the writer when `unsent` falls below the low-water mark, to resume a
    /// producer parked on backpressure.
    drain: Arc<Notify>,
}

impl MuxStream {
    fn new(peer_initial_window: i64) -> Self {
        Self {
            state: StreamState::Idle,
            send_window: peer_initial_window,
            outbox: VecDeque::new(),
            queued: false,
            reset: false,
            unsent: 0,
            drain: Arc::new(Notify::new()),
        }
    }
}

/// State shared between the reader, the writer, and the per-stream handler tasks.
struct Shared {
    streams: HashMap<u32, MuxStream>,
    /// Streams that have a frame ready *and* window to send it.
    ready: VecDeque<u32>,
    conn_send_window: i64,
    peer: Settings,
    /// Pre-encoded control frames (SETTINGS ack, PING ack, WINDOW_UPDATE, RST_STREAM,
    /// GOAWAY) the writer flushes ahead of stream data.
    ctrl: Vec<u8>,
    /// Handler tasks still running — the writer must not exit until this hits 0.
    active_handlers: u32,
    /// The reader has stopped (client EOF, GOAWAY, or a connection error).
    reader_done: bool,
    /// Streams opened + streams reset by the peer, for Rapid Reset detection.
    opened: u64,
    resets: u64,
}

impl Shared {
    /// Enqueue a stream for the writer if it has sendable output and isn't already
    /// queued or reset.
    fn mark_ready(&mut self, id: u32) {
        if let Some(s) = self.streams.get_mut(&id) {
            if !s.queued && !s.reset && !s.outbox.is_empty() {
                s.queued = true;
                self.ready.push_back(id);
            }
        }
    }
}

type Conn = Arc<Mutex<Shared>>;

/// Serve one HTTP/2 connection with the concurrent multiplexed driver.
pub async fn serve_connection_mux<IO, H>(io: IO, handler: H) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    H: Handler,
{
    let (rd, wr) = tokio::io::split(io);
    let shared: Conn = Arc::new(Mutex::new(Shared {
        streams: HashMap::new(),
        ready: VecDeque::new(),
        conn_send_window: settings::DEFAULT_CONNECTION_WINDOW,
        peer: Settings::default(),
        ctrl: Vec::new(),
        active_handlers: 0,
        reader_done: false,
        opened: 0,
        resets: 0,
    }));
    let notify = Arc::new(Notify::new());
    let handler = Arc::new(handler);

    let reader = reader_loop(rd, shared.clone(), notify.clone(), handler);
    let writer = writer_loop(wr, shared.clone(), notify.clone());
    let (_r, w) = tokio::join!(reader, writer);
    w
}

// ------------------------------------------------------------------ reader ----

async fn reader_loop<R, H>(mut rd: R, shared: Conn, notify: Arc<Notify>, handler: Arc<H>)
where
    R: AsyncRead + Unpin,
    H: Handler,
{
    let _ = read_and_dispatch(&mut rd, &shared, &notify, &handler).await;
    {
        let mut s = shared.lock().unwrap();
        s.reader_done = true;
        // Wake any producers parked on backpressure so they observe the teardown and
        // stop (a window-blocked stream can no longer make progress once the client is
        // gone), rather than parking forever.
        for st in s.streams.values() {
            st.drain.notify_one();
        }
    }
    notify.notify_one();
    // Graceful close: once we've stopped reading meaningful frames (client EOF, a
    // GOAWAY, an invalid preface, or a connection error), keep draining and discarding
    // inbound bytes until the peer closes (EOF) or the drain times out. Closing a
    // socket that still has unread data in its receive buffer makes the kernel send
    // RST instead of FIN (RFC 1122 §4.2.2.13) — a peer that pipelined bytes we won't
    // process (a SETTINGS after a bad preface, a PING after its GOAWAY) would then see
    // "connection reset" instead of the clean close h2spec (§3.5, §3.8) requires. The
    // writer sends our GOAWAY + FIN concurrently, so a well-behaved peer closes at once
    // and this returns immediately.
    drain_to_eof(&mut rd).await;
}

/// Read and discard from `rd` until the peer closes (EOF), a read error, or
/// [`GRACEFUL_DRAIN_TIMEOUT`] — so the socket's receive buffer is empty when it drops
/// and the kernel sends a clean FIN rather than a RST. See [`reader_loop`].
async fn drain_to_eof<R>(rd: &mut R)
where
    R: AsyncRead + Unpin,
{
    let mut scratch = [0u8; 4096];
    let _ = tokio::time::timeout(GRACEFUL_DRAIN_TIMEOUT, async {
        loop {
            match rd.read(&mut scratch).await {
                Ok(0) | Err(_) => break, // peer closed (EOF) or errored → done
                Ok(_) => {}              // discard and keep draining
            }
        }
    })
    .await;
}

/// Per-request reader-local state accumulated between HEADERS and END_STREAM.
#[derive(Default)]
struct ReaderState {
    /// In-progress header block awaiting END_HEADERS (HEADERS + CONTINUATION).
    header_buf: Vec<u8>,
    header_sid: u32,
    header_end_stream: bool,
    expecting_continuation: bool,
    /// CONTINUATION frames seen for the current header block (flood guard).
    continuation_count: u32,
    last_client_id: u32,
    /// Header-complete requests awaiting their body's END_STREAM.
    requests: HashMap<u32, http::Request>,
    bodies: HashMap<u32, Vec<u8>>,
    content_len: HashMap<u32, Option<u64>>,
}

async fn read_and_dispatch<R, H>(
    rd: &mut R,
    shared: &Conn,
    notify: &Arc<Notify>,
    handler: &Arc<H>,
) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    H: Handler,
{
    let mut preface = [0u8; 24];
    rd.read_exact(&mut preface).await?;
    if preface != CLIENT_PREFACE {
        return Ok(());
    }
    // Our initial SETTINGS: advertise the concurrent-stream cap (§5.1.2); the rest
    // stay at their spec defaults.
    push_ctrl(shared, notify, |out| {
        let mut payload = Vec::with_capacity(6);
        payload.extend_from_slice(&0x3u16.to_be_bytes()); // SETTINGS_MAX_CONCURRENT_STREAMS
        payload.extend_from_slice(&MAX_CONCURRENT_STREAMS.to_be_bytes());
        frame::write_frame(out, FrameType::Settings, 0, 0, &payload);
    });

    let mut hpack = Hpack::new();
    let mut rs = ReaderState::default();

    loop {
        let mut hdr = [0u8; frame::FRAME_HEADER_LEN];
        if rd.read_exact(&mut hdr).await.is_err() {
            return Ok(()); // client closed
        }
        let header = FrameHeader::parse(&hdr);
        if header.length > OUR_MAX_FRAME_SIZE {
            goaway(shared, notify, rs.last_client_id, ErrorCode::FrameSizeError);
            return Ok(());
        }
        let mut payload = vec![0u8; header.length as usize];
        if header.length > 0 && rd.read_exact(&mut payload).await.is_err() {
            return Ok(());
        }
        if rs.expecting_continuation
            && (header.kind != FrameType::Continuation || header.stream_id != rs.header_sid)
        {
            goaway(shared, notify, rs.last_client_id, ErrorCode::ProtocolError);
            return Ok(());
        }

        match dispatch(
            shared, notify, handler, &mut hpack, &mut rs, header, payload,
        ) {
            Ok(true) => {}
            Ok(false) => return Ok(()), // GOAWAY received
            Err(H2Error::Connection(code)) => {
                goaway(shared, notify, rs.last_client_id, code);
                return Ok(());
            }
            Err(H2Error::Stream { id, code }) => {
                {
                    let mut s = shared.lock().unwrap();
                    if let Some(st) = s.streams.get_mut(&id) {
                        st.state = StreamState::Closed;
                        st.reset = true;
                        st.drain.notify_one(); // wake a producer parked on backpressure
                    }
                }
                push_ctrl(shared, notify, |out| {
                    out.extend_from_slice(&frame::rst_stream(id, code));
                });
            }
        }
    }
}

fn dispatch<H>(
    shared: &Conn,
    notify: &Arc<Notify>,
    handler: &Arc<H>,
    hpack: &mut Hpack,
    rs: &mut ReaderState,
    header: FrameHeader,
    payload: Vec<u8>,
) -> Result<bool, H2Error>
where
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
            let mut s = shared.lock().unwrap();
            let old_iws = s.peer.initial_window_size;
            for (id, value) in frame::parse_settings(&payload)? {
                s.peer.apply(id, value)?;
            }
            let new_iws = s.peer.initial_window_size;
            if new_iws != old_iws {
                let delta = i64::from(new_iws) - i64::from(old_iws);
                let ids: Vec<u32> = s.streams.keys().copied().collect();
                for id in &ids {
                    if let Some(st) = s.streams.get_mut(id) {
                        st.send_window += delta;
                        if st.send_window > i64::from(settings::MAX_WINDOW_SIZE) {
                            return Err(H2Error::conn(ErrorCode::FlowControlError));
                        }
                    }
                }
                for id in ids {
                    s.mark_ready(id);
                }
            }
            let mut ack = Vec::new();
            frame::write_frame(&mut ack, FrameType::Settings, flag::ACK, 0, &[]);
            s.ctrl.extend_from_slice(&ack);
            drop(s);
            notify.notify_one();
            Ok(true)
        }
        FrameType::Ping => {
            if header.stream_id != 0 {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            let data = frame::parse_ping(&payload)?;
            if !header.has_flag(flag::ACK) {
                push_ctrl(shared, notify, |out| {
                    frame::write_frame(out, FrameType::Ping, flag::ACK, 0, &data);
                });
            }
            Ok(true)
        }
        FrameType::GoAway => {
            frame::parse_goaway(&payload)?;
            Ok(false)
        }
        FrameType::WindowUpdate => {
            let inc = frame::parse_window_update(&payload)?;
            let mut s = shared.lock().unwrap();
            if header.stream_id == 0 {
                if inc == 0 {
                    return Err(H2Error::conn(ErrorCode::ProtocolError));
                }
                s.conn_send_window += i64::from(inc);
                if s.conn_send_window > i64::from(settings::MAX_WINDOW_SIZE) {
                    return Err(H2Error::conn(ErrorCode::FlowControlError));
                }
                let ids: Vec<u32> = s.streams.keys().copied().collect();
                for id in ids {
                    s.mark_ready(id);
                }
            } else {
                if !s.streams.contains_key(&header.stream_id)
                    && header.stream_id > rs.last_client_id
                {
                    return Err(H2Error::conn(ErrorCode::ProtocolError));
                }
                if inc == 0 {
                    return Err(H2Error::stream(header.stream_id, ErrorCode::ProtocolError));
                }
                if let Some(st) = s.streams.get_mut(&header.stream_id) {
                    st.send_window += i64::from(inc);
                    if st.send_window > i64::from(settings::MAX_WINDOW_SIZE) {
                        return Err(H2Error::stream(
                            header.stream_id,
                            ErrorCode::FlowControlError,
                        ));
                    }
                }
                s.mark_ready(header.stream_id);
            }
            drop(s);
            notify.notify_one();
            Ok(true)
        }
        FrameType::RstStream => {
            if header.stream_id == 0 {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            let _ = frame::parse_rst_stream(&payload)?;
            let mut s = shared.lock().unwrap();
            if !s.streams.contains_key(&header.stream_id) && header.stream_id > rs.last_client_id {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            if let Some(st) = s.streams.get_mut(&header.stream_id) {
                st.state = StreamState::Closed;
                st.reset = true;
                st.drain.notify_one(); // wake a producer parked on backpressure
            }
            // Rapid Reset (CVE-2023-44487): a stream reset by the peer frees its
            // concurrency slot, so a flood of open-then-reset lets an attacker force
            // unbounded work under one connection. Once past a free allowance, if the
            // peer has reset more than half the streams it opened, close the connection.
            s.resets += 1;
            if s.resets >= RAPID_RESET_MIN && s.resets.saturating_mul(2) > s.opened {
                return Err(H2Error::conn(ErrorCode::EnhanceYourCalm));
            }
            Ok(true)
        }
        FrameType::Priority => {
            if header.stream_id == 0 {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            let prio = frame::parse_priority(&payload)?;
            if prio.dependency == header.stream_id {
                return Err(H2Error::stream(header.stream_id, ErrorCode::ProtocolError));
            }
            Ok(true)
        }
        FrameType::Headers => {
            let sid = header.stream_id;
            if sid == 0 || sid % 2 == 0 {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            let mut block = frame::strip_padding(&payload, header.has_flag(flag::PADDED))?;
            if header.has_flag(flag::PRIORITY) {
                if block.len() < 5 {
                    return Err(H2Error::conn(ErrorCode::FrameSizeError));
                }
                let prio = frame::parse_priority(&block[..5])?;
                if prio.dependency == sid {
                    return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
                }
                block = &block[5..];
            }
            let end_stream = header.has_flag(flag::END_STREAM);
            {
                let mut s = shared.lock().unwrap();
                let new_stream = !s.streams.contains_key(&sid);
                if new_stream && sid <= rs.last_client_id {
                    return Err(H2Error::conn(ErrorCode::ProtocolError));
                }
                if s.streams
                    .get(&sid)
                    .is_some_and(|x| x.state == StreamState::Closed)
                {
                    return Err(H2Error::conn(ErrorCode::StreamClosed));
                }
                if new_stream {
                    rs.last_client_id = sid;
                    s.opened += 1;
                    let iw = i64::from(s.peer.initial_window_size);
                    s.streams.insert(sid, MuxStream::new(iw));
                }
                let cur = s.streams.get(&sid).unwrap().state;
                let next = cur.on_recv(sid, FrameType::Headers, end_stream)?;
                s.streams.get_mut(&sid).unwrap().state = next;
            }
            rs.header_buf.clear();
            rs.continuation_count = 0;
            if block.len() > MAX_HEADER_BLOCK {
                return Err(H2Error::conn(ErrorCode::EnhanceYourCalm));
            }
            rs.header_buf.extend_from_slice(block);
            rs.header_sid = sid;
            rs.header_end_stream = end_stream;
            if header.has_flag(flag::END_HEADERS) {
                finish_headers(shared, notify, handler, hpack, rs, sid, end_stream)?;
            } else {
                rs.expecting_continuation = true;
            }
            Ok(true)
        }
        FrameType::Continuation => {
            let sid = header.stream_id;
            if !rs.expecting_continuation || sid != rs.header_sid {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            rs.continuation_count += 1;
            if rs.continuation_count > MAX_CONTINUATION_FRAMES
                || rs.header_buf.len() + payload.len() > MAX_HEADER_BLOCK
            {
                return Err(H2Error::conn(ErrorCode::EnhanceYourCalm));
            }
            rs.header_buf.extend_from_slice(&payload);
            if header.has_flag(flag::END_HEADERS) {
                rs.expecting_continuation = false;
                let end = rs.header_end_stream;
                finish_headers(shared, notify, handler, hpack, rs, sid, end)?;
            }
            Ok(true)
        }
        FrameType::Data => {
            let sid = header.stream_id;
            if sid == 0 {
                return Err(H2Error::conn(ErrorCode::ProtocolError));
            }
            let end_stream = header.has_flag(flag::END_STREAM);
            {
                let mut s = shared.lock().unwrap();
                let cur = s
                    .streams
                    .get(&sid)
                    .ok_or_else(|| H2Error::conn(ErrorCode::ProtocolError))?
                    .state;
                let next = cur.on_recv(sid, FrameType::Data, end_stream)?;
                s.streams.get_mut(&sid).unwrap().state = next;
            }
            let data = frame::strip_padding(&payload, header.has_flag(flag::PADDED))?;
            rs.bodies.entry(sid).or_default().extend_from_slice(data);
            let n = payload.len() as u32;
            if n > 0 {
                push_ctrl(shared, notify, |out| {
                    frame::write_frame(out, FrameType::WindowUpdate, 0, 0, &n.to_be_bytes());
                    frame::write_frame(out, FrameType::WindowUpdate, 0, sid, &n.to_be_bytes());
                });
            }
            if end_stream {
                let cl = rs.content_len.get(&sid).copied().flatten();
                let body = rs.bodies.remove(&sid).unwrap_or_default();
                if cl.is_some_and(|c| c != body.len() as u64) {
                    return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
                }
                let req = rs.requests.remove(&sid);
                spawn_request(shared, notify, handler, sid, req, body);
            }
            Ok(true)
        }
        FrameType::PushPromise => Err(H2Error::conn(ErrorCode::ProtocolError)),
        FrameType::Unknown(_) => Ok(true),
    }
}

fn finish_headers<H>(
    shared: &Conn,
    notify: &Arc<Notify>,
    handler: &Arc<H>,
    hpack: &mut Hpack,
    rs: &mut ReaderState,
    sid: u32,
    end_stream: bool,
) -> Result<(), H2Error>
where
    H: Handler,
{
    let headers = hpack.decode(&rs.header_buf)?;
    // A second header block on a stream whose request is already parsed is trailers
    // (§8.1.2.3): it MUST carry END_STREAM and MUST NOT contain pseudo-header fields.
    // Deliver the stashed request + accumulated body to the handler.
    if let Some(req) = rs.requests.remove(&sid) {
        if !end_stream || headers.iter().any(|(n, _)| n.first() == Some(&b':')) {
            rs.requests.insert(sid, req);
            return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
        }
        let body = rs.bodies.remove(&sid).unwrap_or_default();
        if rs
            .content_len
            .get(&sid)
            .copied()
            .flatten()
            .is_some_and(|c| c != body.len() as u64)
        {
            return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
        }
        spawn_request(shared, notify, handler, sid, Some(req), body);
        return Ok(());
    }
    // Enforce SETTINGS_MAX_CONCURRENT_STREAMS (§5.1.2): if this freshly-opened stream
    // pushes the active count past the advertised cap, refuse it with
    // RST_STREAM(REFUSED_STREAM) — the client may retry on a new connection. The
    // header block was decoded above, so the shared HPACK context stays consistent.
    // Fast path: total map entries ≤ cap ⇒ certainly under it (active ≤ total), so
    // skip the precise scan — the writer reaps closed streams, so on the hot path the
    // map stays small and this stays O(1) under the lock. Only when the map exceeds
    // the cap do we pay the active-only count (open/half-closed; closed & reset don't
    // count, per §5.1.2, and may linger until reaped).
    let over_cap = {
        let s = shared.lock().unwrap();
        s.streams.len() > MAX_CONCURRENT_STREAMS as usize
            && s.streams
                .values()
                .filter(|st| st.state != StreamState::Closed && !st.reset)
                .count()
                > MAX_CONCURRENT_STREAMS as usize
    };
    if over_cap {
        rs.content_len.remove(&sid);
        rs.bodies.remove(&sid);
        reset_local(shared, notify, sid, ErrorCode::RefusedStream);
        return Ok(());
    }
    let req = http::request_from_headers(sid, headers)?;
    let cl = req
        .headers()
        .get(::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    rs.content_len.insert(sid, cl);
    if end_stream {
        let body = rs.bodies.remove(&sid).unwrap_or_default();
        if cl.is_some_and(|c| c != body.len() as u64) {
            return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
        }
        spawn_request(shared, notify, handler, sid, Some(req), body);
    } else {
        rs.requests.insert(sid, req);
    }
    Ok(())
}

fn spawn_request<H>(
    shared: &Conn,
    notify: &Arc<Notify>,
    handler: &Arc<H>,
    sid: u32,
    req: Option<http::Request>,
    body: Vec<u8>,
) where
    H: Handler,
{
    let Some(mut req) = req else { return };
    *req.body_mut() = crate::ReqBody::from_bytes(Bytes::from(body));
    {
        let mut s = shared.lock().unwrap();
        s.active_handlers += 1;
    }
    let shared = shared.clone();
    let notify = notify.clone();
    let handler = handler.clone();
    tokio::spawn(async move {
        let resp = handler.handle(req).await;
        emit_response(&shared, &notify, sid, resp).await;
        {
            let mut s = shared.lock().unwrap();
            s.active_handlers -= 1;
        }
        notify.notify_one();
    });
}

/// Queue a response onto its stream's outbox, waking the writer. A buffered body
/// (`Bytes`) is queued all at once; a [`http::Body::Stream`] is drained chunk
/// by chunk over time and forwarded as DATA frames — so the writer streams it without
/// the whole body ever being held (the reverse-proxy fast-path).
async fn emit_response(shared: &Conn, notify: &Arc<Notify>, sid: u32, resp: Response) {
    let (parts, body) = resp.into_parts();
    match body {
        http::Body::Stream(mut stream) => {
            // HEADERS carry the response's own headers verbatim — any content-length is
            // the producer's (we don't re-derive one for a streamed body).
            let fields = response_fields(&parts, None);
            if !push_out(
                shared,
                notify,
                sid,
                OutFrame::Headers {
                    fields,
                    end_stream: false,
                },
            ) {
                return;
            }
            // The per-stream drain signal the writer uses to wake us off backpressure.
            let drain = match shared.lock().unwrap().streams.get(&sid) {
                Some(st) if !st.reset => st.drain.clone(),
                _ => return,
            };
            // Poll the stream directly in this per-stream task — no channel, no
            // producer task; the writer frames each chunk as it arrives.
            while let Some(item) = stream.next().await {
                let chunk = match item {
                    Ok(chunk) => chunk,
                    // The source failed mid-stream (e.g. a proxy upstream dropped): reset
                    // the client stream so a truncated body is never framed as complete.
                    Err(_) => {
                        reset_local(shared, notify, sid, ErrorCode::InternalError);
                        return;
                    }
                };
                if chunk.is_empty() {
                    continue;
                }
                if !push_out(
                    shared,
                    notify,
                    sid,
                    OutFrame::Data {
                        bytes: chunk,
                        off: 0,
                        end_stream: false,
                    },
                ) {
                    return; // the stream was reset — stop pulling from the producer
                }
                // Backpressure: once the per-stream send buffer crosses the high-water
                // mark (the writer is behind — usually a flow-control window the slow
                // client hasn't opened), stop pulling the source until the writer
                // drains it below the low-water mark. Bounds per-stream memory to
                // ~STREAM_HIGH_WATER regardless of body size.
                loop {
                    let over = {
                        let s = shared.lock().unwrap();
                        match s.streams.get(&sid) {
                            // A reset/gone stream, or a torn-down connection whose window
                            // can no longer reopen, means we stop producing.
                            Some(st) if st.reset => return,
                            Some(st) if st.unsent > *STREAM_HIGH_WATER => {
                                if s.reader_done {
                                    return;
                                }
                                true
                            }
                            Some(_) => false,
                            None => return,
                        }
                    };
                    if !over {
                        break;
                    }
                    drain.notified().await;
                }
            }
            // The source ended: close the stream with an empty END_STREAM DATA frame.
            push_out(
                shared,
                notify,
                sid,
                OutFrame::Data {
                    bytes: Bytes::new(),
                    off: 0,
                    end_stream: true,
                },
            );
        }
        other => {
            let frames = response_to_frames(parts, other).await;
            // Seed the backpressure counter with this response's unsent DATA bytes so
            // the writer's accounting stays balanced (a buffered body never parks).
            let unsent: usize = frames
                .iter()
                .map(|f| match f {
                    OutFrame::Data { bytes, off, .. } => bytes.len() - off,
                    _ => 0,
                })
                .sum();
            {
                let mut s = shared.lock().unwrap();
                if let Some(st) = s.streams.get_mut(&sid) {
                    if !st.reset {
                        st.unsent = unsent;
                        st.outbox = frames;
                    }
                }
                s.mark_ready(sid);
            }
            notify.notify_one();
        }
    }
}

/// Build the h2 response header list (`:status` first, then the response's headers) as
/// `(name, value)` byte pairs for HPACK. `content_length`, when given, is appended
/// only if the response doesn't already carry one.
fn response_fields(
    parts: &::http::response::Parts,
    content_length: Option<usize>,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut fields = Vec::with_capacity(parts.headers.len() + 2);
    fields.push((
        b":status".to_vec(),
        parts.status.as_u16().to_string().into_bytes(),
    ));
    for (name, value) in &parts.headers {
        // Drop connection-specific headers HTTP/2 forbids (§8.1.2.2): the shared
        // handler also serves h1, where an upstream `Connection`/`Transfer-Encoding`
        // is legal — framing them here would make an invalid h2 response.
        if crate::h2::http::is_connection_specific(name.as_str().as_bytes()) {
            continue;
        }
        fields.push((name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec()));
    }
    if let Some(len) = content_length {
        if !parts.headers.contains_key(::http::header::CONTENT_LENGTH) {
            fields.push((b"content-length".to_vec(), len.to_string().into_bytes()));
        }
    }
    fields
}

/// Append one frame to a stream's outbox, mark it ready, and wake the writer. Returns
/// `false` if the stream was reset or gone (the caller should stop producing). DATA
/// bytes are added to the stream's `unsent` depth for backpressure accounting.
fn push_out(shared: &Conn, notify: &Arc<Notify>, sid: u32, frame: OutFrame) -> bool {
    {
        let mut s = shared.lock().unwrap();
        match s.streams.get_mut(&sid) {
            Some(st) if !st.reset => {
                if let OutFrame::Data { bytes, off, .. } = &frame {
                    st.unsent += bytes.len() - off;
                }
                st.outbox.push_back(frame);
            }
            _ => return false,
        }
        s.mark_ready(sid);
    }
    notify.notify_one();
    true
}

/// Reset a stream locally: mark it reset (so the writer drops its pending output) and
/// queue an RST_STREAM to the client. Used when a streamed body's source fails
/// mid-stream — the client then sees an aborted response, not a silently truncated one.
fn reset_local(shared: &Conn, notify: &Arc<Notify>, sid: u32, code: ErrorCode) {
    {
        let mut s = shared.lock().unwrap();
        match s.streams.get_mut(&sid) {
            Some(st) if !st.reset => {
                st.reset = true;
                st.state = StreamState::Closed;
            }
            _ => return, // already reset or gone
        }
    }
    push_ctrl(shared, notify, |out| {
        out.extend_from_slice(&frame::rst_stream(sid, code));
    });
}

/// Turn a [`Response`] into queued HEADERS (+ DATA) frames (buffered path; a streamed
/// body is emitted chunk-by-chunk by `emit_response`, not here).
async fn response_to_frames(
    parts: ::http::response::Parts,
    body: http::Body,
) -> VecDeque<OutFrame> {
    let body = body_bytes(body).await;
    let has_body = !body.is_empty();
    let fields = response_fields(&parts, has_body.then_some(body.len()));
    let mut out = VecDeque::new();
    out.push_back(OutFrame::Headers {
        fields,
        end_stream: !has_body,
    });
    if has_body {
        out.push_back(OutFrame::Data {
            bytes: Bytes::from(body),
            off: 0,
            end_stream: true,
        });
    }
    out
}

async fn body_bytes(body: http::Body) -> Vec<u8> {
    match body {
        http::Body::Bytes(b) => b,
        // `emit_response` streams a `Body::Stream` directly and never routes it here;
        // buffer it if it ever does, so this stays correct. A mid-stream error ends the
        // drain (best-effort — this fallback is only reached if a stream is ever routed
        // through the buffered path).
        http::Body::Stream(mut stream) => {
            let mut buf = Vec::new();
            while let Some(item) = stream.next().await {
                match item {
                    Ok(chunk) => buf.extend_from_slice(&chunk),
                    Err(_) => break,
                }
            }
            buf
        }
    }
}

// ------------------------------------------------------------------ writer ----

/// One write segment. Frame headers + control frames live in the batch's `scratch`
/// buffer; DATA payloads are the response's own ref-counted `Bytes` (never copied),
/// referenced in place. The writer turns the segments into `IoSlice`s and does one
/// vectored write — so a 100 KiB body is handed straight to rustls without a copy
/// through our buffer (a profile showed that copy, `memmove`, was the top cost).
enum Seg {
    Scratch(usize, usize),
    Body(Bytes),
}

/// A batched write: `scratch` holds all the small owned bytes (frame headers, control
/// frames), `segs` is the ordered segment list, `len` the total wire bytes.
struct Batch {
    scratch: Vec<u8>,
    segs: Vec<Seg>,
    len: usize,
}

impl Batch {
    fn new() -> Self {
        Self {
            scratch: Vec::with_capacity(16 * 1024),
            segs: Vec::with_capacity(64),
            len: 0,
        }
    }
    fn clear(&mut self) {
        self.scratch.clear();
        self.segs.clear();
        self.len = 0;
    }
    fn is_empty(&self) -> bool {
        self.segs.is_empty()
    }
    /// Copy owned bytes (a control frame) into scratch as one segment.
    fn push_owned(&mut self, bytes: &[u8]) {
        let start = self.scratch.len();
        self.scratch.extend_from_slice(bytes);
        self.segs.push(Seg::Scratch(start, bytes.len()));
        self.len += bytes.len();
    }
    /// Record everything appended to `scratch` since `start` as one segment (a frame
    /// header block written in place).
    fn seal(&mut self, start: usize) {
        let len = self.scratch.len() - start;
        self.segs.push(Seg::Scratch(start, len));
        self.len += len;
    }
    /// Reference a ref-counted body slice in place (no copy).
    fn push_body(&mut self, body: Bytes) {
        self.len += body.len();
        self.segs.push(Seg::Body(body));
    }
    fn io_slices(&self) -> Vec<std::io::IoSlice<'_>> {
        self.segs
            .iter()
            .map(|seg| match seg {
                Seg::Scratch(start, len) => {
                    std::io::IoSlice::new(&self.scratch[*start..*start + *len])
                }
                Seg::Body(b) => std::io::IoSlice::new(&b[..]),
            })
            .collect()
    }
}

async fn writer_loop<W>(mut wr: W, shared: Conn, notify: Arc<Notify>) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut hpack = Hpack::new();
    // One reused batch for the whole connection — allocating per write was a top
    // allocation source in the profile.
    let mut batch = Batch::new();
    loop {
        loop {
            batch.clear();
            build_batch(&shared, &mut hpack, &mut batch);
            if batch.is_empty() {
                break;
            }
            write_all_vectored(&mut wr, &batch).await?;
        }
        {
            let s = shared.lock().unwrap();
            if s.reader_done && s.active_handlers == 0 && s.ready.is_empty() && s.ctrl.is_empty() {
                break;
            }
        }
        notify.notified().await;
    }
    let _ = wr.shutdown().await;
    Ok(())
}

/// Write every segment with vectored I/O, handling partial writes.
async fn write_all_vectored<W>(wr: &mut W, batch: &Batch) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut owned = batch.io_slices();
    let mut slices: &mut [std::io::IoSlice] = &mut owned;
    while !slices.is_empty() {
        let n = wr.write_vectored(slices).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "write returned zero",
            ));
        }
        std::io::IoSlice::advance_slices(&mut slices, n);
    }
    Ok(())
}

/// Build one batched (vectored) write: all pending control frames, then a fair
/// round-robin of ready streams' frames — HEADERS free, each DATA clamped by
/// connection + stream windows and the negotiated max-frame, one DATA frame per stream
/// visit. Leaves `batch` empty when nothing is currently sendable.
fn build_batch(shared: &Conn, hpack: &mut Hpack, batch: &mut Batch) {
    let mut s = shared.lock().unwrap();

    if !s.ctrl.is_empty() {
        batch.push_owned(&s.ctrl);
        s.ctrl.clear();
    }

    let max_frame = i64::from(s.peer.max_frame_size).min(MAX_OUT_FRAME as i64);
    // Drain ready streams round-robin into ONE batch until it reaches the target size
    // or no stream can make progress. Coalescing many frames into a single `write_all`
    // is the whole game: a profile showed the writer was syscall-bound (`writev`), and
    // the previous one-frame-per-pass cap turned a 100 KiB response into ~7 writes.
    while batch.len < WRITE_BATCH_TARGET {
        let Some(id) = s.ready.pop_front() else { break };
        if let Some(st) = s.streams.get_mut(&id) {
            st.queued = false;
        }
        if s.streams.get(&id).is_none_or(|st| st.reset) {
            continue;
        }
        // Peek the front frame's kind, releasing the borrow before we mutate.
        let is_headers = matches!(
            s.streams.get(&id).and_then(|st| st.outbox.front()),
            Some(OutFrame::Headers { .. })
        );
        if s.streams.get(&id).is_none_or(|st| st.outbox.is_empty()) {
            continue;
        }

        if is_headers {
            let Some(OutFrame::Headers { fields, end_stream }) =
                s.streams.get_mut(&id).unwrap().outbox.pop_front()
            else {
                continue;
            };
            let refs: Vec<(&[u8], &[u8])> = fields
                .iter()
                .map(|(n, v)| (n.as_slice(), v.as_slice()))
                .collect();
            let block = hpack.encode(&refs);
            let mut hflags = flag::END_HEADERS;
            if end_stream {
                hflags |= flag::END_STREAM;
                close_local(&mut s, id);
            }
            let start = batch.scratch.len();
            frame::write_frame(&mut batch.scratch, FrameType::Headers, hflags, id, &block);
            batch.seal(start);
        } else {
            // DATA frame — read off/len/end without holding a mutable borrow.
            let (off, total, end_stream) = match s.streams.get(&id).unwrap().outbox.front() {
                Some(OutFrame::Data {
                    bytes,
                    off,
                    end_stream,
                }) => (*off, bytes.len(), *end_stream),
                _ => continue,
            };
            let remaining = total - off;
            // An empty DATA frame (a streamed body's trailing END_STREAM marker)
            // carries no bytes, so it isn't flow-controlled and goes out even with the
            // window exhausted. A non-empty frame is clamped by both windows + max-frame.
            let chunk = if remaining == 0 {
                0
            } else {
                let swin = s.streams.get(&id).map_or(0, |st| st.send_window.max(0));
                let win = swin.min(s.conn_send_window.max(0)).min(max_frame) as usize;
                if win == 0 {
                    // Window-blocked: leave in outbox; reader requeues on WINDOW_UPDATE.
                    continue;
                }
                remaining.min(win)
            };
            let is_last = chunk == remaining;
            batch.push_owned(&frame::data_header(id, chunk as u32, is_last && end_stream));
            if let Some(OutFrame::Data { bytes, .. }) = s.streams.get(&id).unwrap().outbox.front() {
                // Reference the body slice in place — no copy into the write buffer.
                batch.push_body(bytes.slice(off..off + chunk));
            }
            s.conn_send_window -= chunk as i64;
            let wake = {
                let st = s.streams.get_mut(&id).unwrap();
                st.send_window -= chunk as i64;
                if let Some(OutFrame::Data { off, .. }) = st.outbox.front_mut() {
                    *off += chunk;
                }
                if is_last {
                    st.outbox.pop_front();
                }
                // Backpressure release: if draining this chunk brought the per-stream
                // send buffer below the low-water mark, wake a producer parked on it.
                let before = st.unsent;
                st.unsent = st.unsent.saturating_sub(chunk);
                (before > *STREAM_LOW_WATER && st.unsent <= *STREAM_LOW_WATER)
                    .then(|| st.drain.clone())
            };
            if let Some(drain) = wake {
                drain.notify_one();
            }
            if is_last && end_stream {
                close_local(&mut s, id);
            }
        }

        // Requeue if the stream has more to send and can make progress now: the next
        // frame is HEADERS (never flow-controlled) or DATA with an open window. Only
        // one DATA frame is emitted per visit, so requeuing gives round-robin fairness
        // across streams; a window-blocked stream drops out of `ready` and is
        // re-readied on WINDOW_UPDATE.
        let next_headers = matches!(
            s.streams.get(&id).and_then(|st| st.outbox.front()),
            Some(OutFrame::Headers { .. })
        );
        let has_win = {
            let st = s.streams.get(&id);
            st.is_some_and(|st| st.send_window > 0) && s.conn_send_window > 0
        };
        let more = s.streams.get(&id).is_some_and(|st| !st.outbox.is_empty());
        if more && (next_headers || has_win) {
            if let Some(st) = s.streams.get_mut(&id) {
                st.queued = true;
            }
            s.ready.push_back(id);
        }

        // Drop a fully-finished stream so the map can't grow unbounded across a
        // long-lived connection.
        if s.streams
            .get(&id)
            .is_some_and(|st| st.state == StreamState::Closed && st.outbox.is_empty())
        {
            s.streams.remove(&id);
        }
    }
}

/// Advance a stream's state when we send END_STREAM.
fn close_local(s: &mut Shared, id: u32) {
    if let Some(st) = s.streams.get_mut(&id) {
        st.state = if st.state == StreamState::HalfClosedRemote {
            StreamState::Closed
        } else {
            StreamState::HalfClosedLocal
        };
    }
}

// ------------------------------------------------------------------ util ----

/// Append control-frame bytes under the lock and wake the writer.
fn push_ctrl<F: FnOnce(&mut Vec<u8>)>(shared: &Conn, notify: &Arc<Notify>, build: F) {
    let mut buf = Vec::new();
    build(&mut buf);
    {
        let mut s = shared.lock().unwrap();
        s.ctrl.extend_from_slice(&buf);
    }
    notify.notify_one();
}

fn goaway(shared: &Conn, notify: &Arc<Notify>, last: u32, code: ErrorCode) {
    push_ctrl(shared, notify, |out| {
        out.extend_from_slice(&frame::goaway(last, code, &[]));
    });
    let mut s = shared.lock().unwrap();
    s.reader_done = true;
}
