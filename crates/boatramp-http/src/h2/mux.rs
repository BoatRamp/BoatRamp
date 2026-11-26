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

use std::collections::{HashMap, HashSet, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tokio_stream::{Stream, StreamExt as _};

use crate::h2::CLIENT_PREFACE;
use crate::h2::error::{ErrorCode, H2Error};
use crate::h2::frame::{self, FrameHeader, FrameType, flag};
use crate::h2::hpack::Hpack;
use crate::h2::http::{self, Handler, Response};
use crate::h2::settings::{self, Settings};
use crate::h2::stream::StreamState;
use crate::shutdown::GracefulShutdown;

const OUR_MAX_FRAME_SIZE: u32 = settings::DEFAULT_MAX_FRAME_SIZE;
/// Cap on a single emitted DATA frame (keeps batches bounded; well above the usual
/// 16 KiB negotiated max-frame).
const MAX_OUT_FRAME: usize = 128 * 1024;
/// Default bound on a single request's accumulated header block (HEADERS + CONTINUATION),
/// to cap memory against a CONTINUATION flood (CVE-2024-27316). Overridable per connection
/// via [`MuxConfig::max_header_block`].
pub const MAX_HEADER_BLOCK: usize = 64 * 1024;
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
/// new connection. Matches the cap the previous hyper serving path advertised. Overridable
/// per connection via [`MuxConfig::max_concurrent_streams`].
pub const MAX_CONCURRENT_STREAMS: u32 = 256;
/// Soft target for one batched socket write: keep draining ready streams into the
/// buffer until it reaches this, then write and start a fresh batch.
const WRITE_BATCH_TARGET: usize = 64 * 1024;
/// Depth of a dispatched request's **bounded** body channel — the reader hands each DATA
/// frame's payload into it and parks on a full channel, so a handler that stops draining
/// its request body stops the reader from buffering the upload without limit. Mirrors the
/// h1 body pump's `mpsc::channel(4)`. Paired with consume-gated receive flow control (the
/// per-stream `WINDOW_UPDATE` is withheld until the handler takes a chunk — see the DATA
/// path in [`dispatch`]) so a well-behaved uploader is throttled at the protocol level
/// (its stream window closes) before the reader ever has to park.
const REQ_BODY_CHANNEL_DEPTH: usize = 4;
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
const GRACEFUL_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Per-connection tuning for the concurrent HTTP/2 mux driver. Every field defaults to the
/// value the driver historically hardcoded, so [`MuxConfig::default`] reproduces the old
/// behavior exactly and existing callers are unaffected; the unified dispatcher
/// ([`crate::Config`]) threads its own values through here.
#[derive(Clone, Copy, Debug)]
pub struct MuxConfig {
    /// `SETTINGS_MAX_CONCURRENT_STREAMS` advertised and enforced — the (limit + 1)th
    /// concurrent stream is `RST_STREAM(REFUSED_STREAM)`'d (default
    /// [`MAX_CONCURRENT_STREAMS`] = 256).
    pub max_concurrent_streams: u32,
    /// Cap on a single request's accumulated header block (HEADERS + CONTINUATION), a
    /// CONTINUATION-flood guard (default [`MAX_HEADER_BLOCK`] = 64 KiB).
    pub max_header_block: usize,
    /// Optional idle timeout: when the connection has no open streams and no running
    /// handlers, how long to wait for the next frame before a graceful `GOAWAY` + close.
    /// `None` (default) waits indefinitely — the historical behavior.
    pub idle_timeout: Option<Duration>,
    /// Optional cap on a single request's buffered body; a body that exceeds it resets the
    /// stream with `ENHANCE_YOUR_CALM`. `None` (default) is unbounded.
    pub body_limit: Option<u64>,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: MAX_CONCURRENT_STREAMS,
            max_header_block: MAX_HEADER_BLOCK,
            idle_timeout: None,
            body_limit: None,
        }
    }
}

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
    /// **Receive-side** flow control for this stream's request body: bytes of request DATA
    /// handed toward the handler's body channel but not yet returned to the peer with a
    /// stream-level `WINDOW_UPDATE`. The handler's body reader releases these as it consumes
    /// each chunk (consume-driven replenishment — see [`ConsumeGatedBody`]); a non-draining
    /// handler stops releasing, so the peer's stream window closes and the uploader is
    /// backpressured at the protocol level. The reader flushes the remainder ([`drain_recv_window`])
    /// if the handler abandons the body, so an abandoned upload can still drain to its end.
    recv_unreleased: u32,
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
            recv_unreleased: 0,
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
    /// A graceful shutdown has been triggered: a `GOAWAY` was queued and new streams above
    /// `goaway_last` are refused so in-flight work can drain.
    shutting_down: bool,
    /// The highest client stream id opened so far — the `GOAWAY` last-stream-id captured at
    /// shutdown, so streams ≤ it still complete and streams above it are refused.
    last_opened: u32,
    /// Snapshot of `last_opened` taken when the graceful shutdown was triggered.
    goaway_last: u32,
}

impl Shared {
    /// Enqueue a stream for the writer if it has sendable output and isn't already
    /// queued or reset.
    fn mark_ready(&mut self, id: u32) {
        if let Some(s) = self.streams.get_mut(&id)
            && !s.queued
            && !s.reset
            && !s.outbox.is_empty()
        {
            s.queued = true;
            self.ready.push_back(id);
        }
    }
}

type Conn = Arc<Mutex<Shared>>;

/// Serve one HTTP/2 connection with the concurrent multiplexed driver and default
/// [`MuxConfig`] (no idle timeout, no body limit — the historical behavior).
pub async fn serve_connection_mux<IO, H>(io: IO, handler: H) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    H: Handler,
{
    serve_connection_mux_with(io, handler, MuxConfig::default(), None).await
}

/// Serve one HTTP/2 connection with explicit [`MuxConfig`] limits and an optional
/// [`GracefulShutdown`] signal. When the signal is triggered, the driver emits a `GOAWAY`
/// (last-stream-id = the highest stream it has accepted) and lets its in-flight handlers
/// finish; streams opened after the `GOAWAY` are refused with `REFUSED_STREAM`. The
/// connection then closes once the peer closes its side (the caller imposes any hard
/// deadline by dropping this future — see [`GracefulShutdown`]).
pub async fn serve_connection_mux_with<IO, H>(
    io: IO,
    handler: H,
    config: MuxConfig,
    shutdown: Option<GracefulShutdown>,
) -> std::io::Result<()>
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
        shutting_down: false,
        last_opened: 0,
        goaway_last: 0,
    }));
    let notify = Arc::new(Notify::new());
    let handler = Arc::new(handler);

    let reader = reader_loop(rd, shared.clone(), notify.clone(), handler, config);
    let writer = writer_loop(wr, shared.clone(), notify.clone());

    match shutdown {
        // No graceful-shutdown handle: run the reader + writer exactly as before.
        None => {
            let (_r, w) = tokio::join!(reader, writer);
            w
        }
        // A handle is present: race a watcher that, on trigger, queues the GOAWAY and marks
        // the connection shutting-down. The watcher parks forever after acting, so the
        // `select!` is resolved by the serve join (the connection draining), and the watcher
        // is then dropped — no leaked task, and no graceful path when the handle never fires.
        Some(sd) => {
            let watch_shared = shared.clone();
            let watch_notify = notify.clone();
            let watcher = async move {
                sd.watch().await;
                let last = {
                    let mut s = watch_shared.lock().unwrap();
                    s.shutting_down = true;
                    s.goaway_last = s.last_opened;
                    s.last_opened
                };
                push_ctrl(&watch_shared, &watch_notify, |out| {
                    out.extend_from_slice(&frame::goaway(last, ErrorCode::NoError, &[]));
                });
                std::future::pending::<()>().await;
            };
            let serve = async { tokio::join!(reader, writer).1 };
            tokio::select! {
                w = serve => w,
                _ = watcher => unreachable!("watcher parks forever after queuing GOAWAY"),
            }
        }
    }
}

// ------------------------------------------------------------------ reader ----

async fn reader_loop<R, H>(
    mut rd: R,
    shared: Conn,
    notify: Arc<Notify>,
    handler: Arc<H>,
    config: MuxConfig,
) where
    R: AsyncRead + Unpin,
    H: Handler,
{
    let _ = read_and_dispatch(&mut rd, &shared, &notify, &handler, config).await;
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

/// Per-request reader-local state accumulated across a stream's frames.
///
/// The request is **dispatched to the handler as soon as its HEADERS are complete** (not
/// at END_STREAM): a request that carries a body hands the handler a streaming
/// [`ReqBody`](crate::ReqBody) whose chunks the reader feeds in from DATA frames as they
/// arrive, so a large h2 upload streams straight through to the handler (a reverse proxy)
/// without ever being buffered whole — mirroring the h1 loop's body pump.
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
    /// Per-stream declared `content-length` (validated against the DATA total, §8.1.2.6).
    content_len: HashMap<u32, Option<u64>>,
    /// Per-stream running total of received DATA bytes — checked against `body_limit` and
    /// the declared `content-length`.
    received: HashMap<u32, u64>,
    /// The open request-body sink of a dispatched streaming request: the reader pushes each
    /// DATA chunk into its **bounded** channel (parking on a full channel — backpressure),
    /// and dropping the sender ends the handler's body stream. Present from a stream's first
    /// (non-END_STREAM) HEADERS until its body ends (END_STREAM / trailers) or the stream is
    /// reset. A clean end drops the sink; an abnormal end ([`fail_body`]) first sets the
    /// sink's truncation flag so the handler sees a `BodyError` rather than a clean short read.
    body_tx: HashMap<u32, BodySink>,
    /// Streams whose request has already been dispatched to the handler, so a later header
    /// block on the same stream is trailers (§8.1.2.3), not a fresh request. Only streams
    /// with an open body are tracked here (a bodyless request can take no trailers), and an
    /// entry is cleared when the body ends or the stream resets, so it stays bounded.
    dispatched: HashSet<u32>,
    /// The connection's configured limits, threaded through dispatch (header-block size,
    /// concurrent-stream cap, request-body cap).
    max_header_block: usize,
    max_concurrent_streams: u32,
    body_limit: Option<u64>,
}

/// The reader's half of a dispatched request's streaming body.
///
/// Chunks flow through a **bounded** channel (`tx`); the reader parks on a full channel, so
/// a non-draining handler cannot make it buffer the upload without limit. The channel
/// carries plain `Bytes`: whether the body ended *cleanly* (sender dropped → the handler's
/// stream yields `None`) or was *truncated* (RST, a malformed content-length, or connection
/// teardown) is signalled out of band by `truncated`, set before the sender is dropped. This
/// keeps the "never a clean short read" property independent of channel capacity — an
/// in-band error marker could not be delivered into an already-full bounded channel, but a
/// flag always can.
struct BodySink {
    tx: mpsc::Sender<Bytes>,
    truncated: Arc<AtomicBool>,
}

impl BodySink {
    /// Mark the body as truncated so the handler's reader surfaces a [`http::BodyError`]
    /// instead of a clean end once the channel closes. Idempotent; the sender is dropped by
    /// the caller (removing the sink from [`ReaderState::body_tx`]).
    fn truncate(&self) {
        self.truncated.store(true, Ordering::Release);
    }
}

/// The handler-facing half of a streaming request body: a bounded-channel receiver that
/// **drives consume-gated receive flow control**. Each chunk it hands to the handler
/// releases that chunk's bytes of the stream's receive window back to the peer (a
/// stream-level `WINDOW_UPDATE`), so the window reopens exactly as fast as the handler
/// drains it — a legitimate large upload flows continuously, while a handler that stops
/// reading stops the window and backpressures the uploader. On channel close it yields a
/// final [`http::BodyError`] iff the body was truncated (see [`BodySink`]).
///
/// It also drives `Expect: 100-continue` the way Go's `net/http2` server does — **lazily**:
/// the interim `100 (Continue)` is emitted on the handler's **first body read**, not eagerly
/// when the request HEADERS arrive. A reverse-proxy handler's forward leg reads this body to
/// stream the upload upstream, and that first read is exactly the point the client (which is
/// withholding its DATA until it sees the `100`) must be told to proceed. Without this the
/// handler blocks on a read that never completes — 0 body bytes, nothing forwarded upstream,
/// the client times out and retries forever (the git-lfs-over-h2 deadlock). The `100` is a
/// genuine INTERIM response (a `:status 100` HEADERS with NO END_STREAM — see
/// [`emit_continue`]); the handler's real final response is emitted afterward on the same
/// stream and is unaffected. A client that did not wait and sent its DATA anyway simply gets
/// a (harmless) late `100` and its already-buffered chunk on this same poll.
struct ConsumeGatedBody {
    rx: mpsc::Receiver<Bytes>,
    truncated: Arc<AtomicBool>,
    shared: Conn,
    notify: Arc<Notify>,
    sid: u32,
    /// Set once the truncation `BodyError` has been yielded, so the stream then ends.
    errored: bool,
    /// The request carried `Expect: 100-continue` and the interim `100` has not been sent
    /// yet. Emitted (and cleared) on the first `poll_next` — the lazy, Go-aligned trigger.
    needs_continue: bool,
}

impl Stream for ConsumeGatedBody {
    type Item = Result<Bytes, http::BodyError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.errored {
            return Poll::Ready(None);
        }
        // `Expect: 100-continue`, resolved lazily: the handler is reading the body for the
        // first time, so tell the client to send it (RFC 9110 §10.1.1). Sent once; a client
        // that didn't wait and already streamed its DATA gets a late — and harmless — `100`,
        // then its buffered chunk from `rx` on this very poll. Mirrors Go's
        // `net/http2` `requestBody.Read` → `write100ContinueHeaders`.
        if self.needs_continue {
            self.needs_continue = false;
            emit_continue(&self.shared, &self.notify, self.sid);
        }
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                // The handler is taking this chunk: return its bytes to the peer's stream
                // window now (consume-driven replenishment).
                let n = chunk.len() as u32;
                release_recv_window(&self.shared, &self.notify, self.sid, n);
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(None) => {
                // Channel closed. A truncated body surfaces as one BodyError, never a clean
                // end that a reverse-proxy handler would forward upstream as complete.
                if self.truncated.load(Ordering::Acquire) {
                    self.errored = true;
                    Poll::Ready(Some(Err(http::BodyError)))
                } else {
                    Poll::Ready(None)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Outcome of reading the next frame header (see [`next_frame_header`]).
enum FrameRead {
    /// A full frame header was read into the buffer.
    Ok,
    /// The peer closed or the read errored.
    Closed,
    /// The connection sat idle (no streams, no handlers) past the idle timeout.
    Idle,
}

/// Read the next 9-byte frame header, bounding the wait by `idle_timeout` **only** while the
/// connection is idle (no open streams and no running handlers — a keep-alive connection
/// between requests). During active work the read is unbounded, so a long server-streamed
/// response is never cut off; `None` leaves it unbounded always (the historical behavior).
async fn next_frame_header<R>(
    rd: &mut R,
    shared: &Conn,
    idle_timeout: Option<Duration>,
    hdr: &mut [u8; frame::FRAME_HEADER_LEN],
) -> FrameRead
where
    R: AsyncRead + Unpin,
{
    let idle_bound = match idle_timeout {
        Some(t) => {
            let s = shared.lock().unwrap();
            (s.active_handlers == 0 && s.streams.is_empty()).then_some(t)
        }
        None => None,
    };
    match idle_bound {
        // Not cancel-safe, but on a timeout we close the connection, so a partially-read
        // header is discarded with it.
        Some(t) => match tokio::time::timeout(t, rd.read_exact(&mut hdr[..])).await {
            Ok(Ok(_)) => FrameRead::Ok,
            Ok(Err(_)) => FrameRead::Closed,
            Err(_) => FrameRead::Idle,
        },
        None => match rd.read_exact(&mut hdr[..]).await {
            Ok(_) => FrameRead::Ok,
            Err(_) => FrameRead::Closed,
        },
    }
}

async fn read_and_dispatch<R, H>(
    rd: &mut R,
    shared: &Conn,
    notify: &Arc<Notify>,
    handler: &Arc<H>,
    config: MuxConfig,
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
    // Our initial SETTINGS: advertise the configured concurrent-stream cap (§5.1.2); the
    // rest stay at their spec defaults.
    push_ctrl(shared, notify, |out| {
        let mut payload = Vec::with_capacity(6);
        payload.extend_from_slice(&0x3u16.to_be_bytes()); // SETTINGS_MAX_CONCURRENT_STREAMS
        payload.extend_from_slice(&config.max_concurrent_streams.to_be_bytes());
        frame::write_frame(out, FrameType::Settings, 0, 0, &payload);
    });

    let mut hpack = Hpack::new();
    let mut rs = ReaderState {
        max_header_block: config.max_header_block,
        max_concurrent_streams: config.max_concurrent_streams,
        body_limit: config.body_limit,
        ..ReaderState::default()
    };

    loop {
        let mut hdr = [0u8; frame::FRAME_HEADER_LEN];
        // Bound an idle keep-alive wait (no open streams, no running handlers) by the
        // configured idle timeout, if any. During active work the read is never bounded, so
        // a long-running streamed response is unaffected. `None` leaves the read unbounded —
        // the historical behavior.
        match next_frame_header(rd, shared, config.idle_timeout, &mut hdr).await {
            FrameRead::Ok => {}
            FrameRead::Closed => break, // client closed
            FrameRead::Idle => {
                // Idle past the timeout: tell the peer with a GOAWAY and close cleanly.
                goaway(shared, notify, rs.last_client_id, ErrorCode::NoError);
                break;
            }
        }
        let header = FrameHeader::parse(&hdr);
        if header.length > OUR_MAX_FRAME_SIZE {
            goaway(shared, notify, rs.last_client_id, ErrorCode::FrameSizeError);
            break;
        }
        let mut payload = vec![0u8; header.length as usize];
        if header.length > 0 && rd.read_exact(&mut payload).await.is_err() {
            break;
        }
        if rs.expecting_continuation
            && (header.kind != FrameType::Continuation || header.stream_id != rs.header_sid)
        {
            goaway(shared, notify, rs.last_client_id, ErrorCode::ProtocolError);
            break;
        }

        match dispatch(
            shared, notify, handler, &mut hpack, &mut rs, header, payload,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => break, // GOAWAY received
            Err(H2Error::Connection(code)) => {
                goaway(shared, notify, rs.last_client_id, code);
                break;
            }
            Err(H2Error::Stream { id, code }) => {
                // Unblock any handler still reading this stream's request body (a no-op if
                // the raising site already ended it).
                fail_body(&mut rs, id);
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
    // Connection teardown: fail every request body still open (never reached END_STREAM),
    // so a handler reading one sees a truncation (BodyError), not a clean end it would
    // forward upstream as complete — mirroring the h1 pump's truncated-body behavior. The
    // flag is set before each sink drops (closing its channel), so the signal reaches the
    // handler regardless of whether the bounded channel had room.
    for (_, sink) in rs.body_tx.drain() {
        sink.truncate();
    }
    Ok(())
}

async fn dispatch<H>(
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
            // End any in-flight request body for this stream so a handler reading it
            // unblocks (the request is cancelled; its response is dropped below).
            fail_body(rs, header.stream_id);
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
            if sid == 0 || sid.is_multiple_of(2) {
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
                    s.last_opened = sid;
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
            if block.len() > rs.max_header_block {
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
                || rs.header_buf.len() + payload.len() > rs.max_header_block
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
            // §6.9.1: the WHOLE padded frame payload counts against flow control; §8.1.2.6:
            // only the de-padded DATA counts toward content-length and the request-body cap.
            let padded_len = payload.len() as u32;
            let data_len = data.len() as u32;
            let overhead = padded_len - data_len; // pad-length byte + padding; never delivered

            // Connection-level receive flow control: replenish EAGERLY by the full padded
            // length, as before. Keeping the connection window open means a single slow
            // stream never head-of-line blocks its siblings at the connection level; the
            // per-stream, consume-gated backpressure below is what bounds our buffering. The
            // connection window therefore never shrinks below its initial size, so nothing
            // under-runs it across the concurrent streams.
            if padded_len > 0 {
                push_ctrl(shared, notify, |out| {
                    frame::write_frame(
                        out,
                        FrameType::WindowUpdate,
                        0,
                        0,
                        &padded_len.to_be_bytes(),
                    );
                });
            }
            // Account the de-padded bytes for the request-body cap + content-length validation.
            let total = {
                let r = rs.received.entry(sid).or_insert(0);
                *r += data_len as u64;
                *r
            };
            // Over the optional request-body cap: reset the stream (the connection
            // survives). `None` is unbounded — the historical behavior.
            if rs.body_limit.is_some_and(|lim| total > lim) {
                fail_body(rs, sid);
                return Err(H2Error::stream(sid, ErrorCode::EnhanceYourCalm));
            }
            // Declared content-length over-run (§8.1.2.6) — malformed; reset the stream.
            if rs
                .content_len
                .get(&sid)
                .copied()
                .flatten()
                .is_some_and(|c| total > c)
            {
                fail_body(rs, sid);
                return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
            }
            // The stream survives this frame. Return the padding/overhead window immediately
            // (it is consumed the instant it arrives — never handed to the handler).
            if overhead > 0 {
                push_ctrl(shared, notify, |out| {
                    frame::write_frame(
                        out,
                        FrameType::WindowUpdate,
                        0,
                        sid,
                        &overhead.to_be_bytes(),
                    );
                });
            }
            // Hand the DATA to the handler's body with CONSUME-GATED stream flow control: the
            // window for these bytes is returned only as the handler takes each chunk (see
            // `ConsumeGatedBody`), so a non-draining handler stops the window and the uploader
            // is backpressured at the protocol level. If no handler is reading this body any
            // more (it abandoned the upload), discard the bytes and return their window at
            // once so the upload still drains to its end.
            if data_len > 0 {
                if let Some(tx) = rs.body_tx.get(&sid).map(|sink| sink.tx.clone()) {
                    // Reserve the window for these bytes before the hand-off, so a mid-send
                    // handler-drop can flush exactly what went un-consumed.
                    reserve_recv_window(shared, sid, data_len);
                    // Bounded hand-off: the reader PARKS here on a full channel — a
                    // non-draining handler stops it from buffering the upload without limit
                    // (mirrors the h1 body pump's bounded, backpressuring `send`).
                    if tx.send(Bytes::copy_from_slice(data)).await.is_err() {
                        // The handler dropped its body: stop feeding, flush the reserved but
                        // un-consumed window so the peer can finish, then discard + replenish
                        // eagerly for any further DATA (handled by the `else` branch below).
                        rs.body_tx.remove(&sid);
                        drain_recv_window(shared, notify, sid);
                    }
                } else {
                    // No reader (abandoned body): discard and return the window at once.
                    push_ctrl(shared, notify, |out| {
                        frame::write_frame(
                            out,
                            FrameType::WindowUpdate,
                            0,
                            sid,
                            &data_len.to_be_bytes(),
                        );
                    });
                }
            }
            if end_stream {
                // Declared content-length under-run (§8.1.2.6) — malformed; reset.
                if rs
                    .content_len
                    .get(&sid)
                    .copied()
                    .flatten()
                    .is_some_and(|c| total != c)
                {
                    fail_body(rs, sid);
                    return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
                }
                // Clean end of the request body: drop the sender so the handler's body
                // stream terminates.
                end_body(rs, sid);
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
    // A second header block on an already-dispatched stream is trailers (§8.1.2.3): it
    // MUST carry END_STREAM and MUST NOT contain pseudo-header fields. The request is
    // already running with its body streaming; trailers simply end that body (their field
    // values are not delivered to the handler — the buffered path discarded them too).
    if rs.dispatched.contains(&sid) {
        if !end_stream || headers.iter().any(|(n, _)| n.first() == Some(&b':')) {
            fail_body(rs, sid);
            return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
        }
        // Validate the declared content-length against the DATA total before ending.
        if content_len_mismatch(rs, sid) {
            fail_body(rs, sid);
            return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
        }
        end_body(rs, sid);
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
    // After a graceful shutdown, refuse a brand-new stream opened past the GOAWAY's
    // last-stream-id (§6.8) so the drain can finish; streams ≤ that id (accepted before the
    // GOAWAY) still complete. The header block was decoded above, keeping the shared HPACK
    // context consistent.
    let refuse_shutdown = {
        let s = shared.lock().unwrap();
        s.shutting_down && sid > s.goaway_last
    };
    if refuse_shutdown {
        reset_local(shared, notify, sid, ErrorCode::RefusedStream);
        return Ok(());
    }
    let max_concurrent = rs.max_concurrent_streams as usize;
    let over_cap = {
        let s = shared.lock().unwrap();
        s.streams.len() > max_concurrent
            && s.streams
                .values()
                .filter(|st| st.state != StreamState::Closed && !st.reset)
                .count()
                > max_concurrent
    };
    if over_cap {
        reset_local(shared, notify, sid, ErrorCode::RefusedStream);
        return Ok(());
    }
    let mut req = http::request_from_headers(sid, headers)?;
    let cl = req
        .headers()
        .get(::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse::<u64>().ok());
    rs.content_len.insert(sid, cl);
    if end_stream {
        // No body follows. A non-zero declared content-length with no DATA is a mismatch.
        if cl.is_some_and(|c| c != 0) {
            rs.content_len.remove(&sid);
            return Err(H2Error::stream(sid, ErrorCode::ProtocolError));
        }
        rs.content_len.remove(&sid);
        *req.body_mut() = http::ReqBody::empty();
        spawn(shared, notify, handler, sid, req);
    } else {
        // A body follows: hand the handler a streaming body the reader feeds from DATA
        // frames over a BOUNDED channel, and dispatch now so the upload streams straight
        // through. The handler's `ConsumeGatedBody` returns each chunk's receive window as it
        // drains it (consume-driven replenishment), so a slow/non-draining handler is
        // backpressured both in-process (the full bounded channel parks the reader) and at
        // the protocol level (the un-replenished stream window closes on the peer).
        //
        // `Expect: 100-continue` (RFC 9110 §10.1.1): a bodied request carrying it waits for an
        // interim `100` before sending DATA. The h1 path detects it the same way
        // (`h1::serve`); here the `100` is emitted LAZILY, on the handler's first body read
        // (see [`ConsumeGatedBody`]), which matches Go's `net/http2` server and is what a
        // reverse proxy wants: the forward leg's first read of this body is the signal to let
        // the client proceed, and the proxy terminates the handshake locally rather than
        // relaying an upstream `100`.
        let expect_continue = req
            .headers()
            .get_all(::http::header::EXPECT)
            .iter()
            .any(|v| v.as_bytes().eq_ignore_ascii_case(b"100-continue"));
        let (tx, rx) = mpsc::channel(REQ_BODY_CHANNEL_DEPTH);
        let truncated = Arc::new(AtomicBool::new(false));
        let body = ConsumeGatedBody {
            rx,
            truncated: truncated.clone(),
            shared: shared.clone(),
            notify: notify.clone(),
            sid,
            errored: false,
            needs_continue: expect_continue,
        };
        *req.body_mut() = http::ReqBody::from_stream(body);
        rs.body_tx.insert(sid, BodySink { tx, truncated });
        rs.received.insert(sid, 0);
        rs.dispatched.insert(sid);
        spawn(shared, notify, handler, sid, req);
    }
    Ok(())
}

/// Whether a stream's declared `content-length` disagrees with its received DATA total.
fn content_len_mismatch(rs: &ReaderState, sid: u32) -> bool {
    rs.content_len
        .get(&sid)
        .copied()
        .flatten()
        .is_some_and(|c| rs.received.get(&sid).copied().unwrap_or(0) != c)
}

/// End a stream's request body **cleanly**: drop the body sender so the handler's body
/// stream terminates, and clear the per-stream reader state.
fn end_body(rs: &mut ReaderState, sid: u32) {
    rs.body_tx.remove(&sid);
    rs.received.remove(&sid);
    rs.content_len.remove(&sid);
    rs.dispatched.remove(&sid);
}

/// Fail a stream's request body: tell the handler (if still reading) the body source
/// failed — so a truncated/malformed body is never seen as a clean end — and clear the
/// per-stream reader state. The truncation flag is set before the sink drops, so the signal
/// reaches the handler even if the bounded channel is full.
fn fail_body(rs: &mut ReaderState, sid: u32) {
    if let Some(sink) = rs.body_tx.remove(&sid) {
        sink.truncate();
    }
    rs.received.remove(&sid);
    rs.content_len.remove(&sid);
    rs.dispatched.remove(&sid);
}

/// Reserve `n` bytes of a stream's receive window as "handed toward the handler but not yet
/// returned to the peer". Paired with [`release_recv_window`] (as the handler consumes each
/// chunk) and [`drain_recv_window`] (if the handler abandons the body).
fn reserve_recv_window(shared: &Conn, sid: u32, n: u32) {
    let mut s = shared.lock().unwrap();
    if let Some(st) = s.streams.get_mut(&sid) {
        st.recv_unreleased = st.recv_unreleased.saturating_add(n);
    }
}

/// Return `n` bytes of a stream's receive window to the peer (a stream-level `WINDOW_UPDATE`)
/// as the handler consumes a chunk — the consume-driven replenishment that makes the receive
/// window track handler progress. Skipped once the peer can no longer send DATA on the stream
/// (it reached END_STREAM → half-closed-remote, was reset, or is gone), so a `WINDOW_UPDATE`
/// is never emitted on a closed/half-closed-remote stream. Locks once — updating the tally
/// and queueing the frame together — so it never re-enters the lock through [`push_ctrl`].
fn release_recv_window(shared: &Conn, notify: &Arc<Notify>, sid: u32, n: u32) {
    if n == 0 {
        return;
    }
    {
        let mut s = shared.lock().unwrap();
        match s.streams.get_mut(&sid) {
            Some(st)
                if !st.reset
                    && matches!(st.state, StreamState::Open | StreamState::HalfClosedLocal) =>
            {
                st.recv_unreleased = st.recv_unreleased.saturating_sub(n);
                frame::write_frame(
                    &mut s.ctrl,
                    FrameType::WindowUpdate,
                    0,
                    sid,
                    &n.to_be_bytes(),
                );
            }
            _ => return,
        }
    }
    notify.notify_one();
}

/// Flush a stream's remaining reserved-but-un-consumed receive window back to the peer when
/// the handler abandons its body, so an abandoned upload can still drain to its end rather
/// than stalling behind a window we would otherwise never reopen. A no-op once the stream can
/// no longer receive DATA.
fn drain_recv_window(shared: &Conn, notify: &Arc<Notify>, sid: u32) {
    let n = {
        let mut s = shared.lock().unwrap();
        match s.streams.get_mut(&sid) {
            Some(st)
                if !st.reset
                    && matches!(st.state, StreamState::Open | StreamState::HalfClosedLocal) =>
            {
                std::mem::take(&mut st.recv_unreleased)
            }
            _ => return,
        }
    };
    if n > 0 {
        push_ctrl(shared, notify, |out| {
            frame::write_frame(out, FrameType::WindowUpdate, 0, sid, &n.to_be_bytes());
        });
    }
}

/// Spawn the handler task for a fully-built request (its body already set), bumping the
/// in-flight-handler count the writer waits on. Unlike the buffered path, this runs the
/// handler as soon as the request HEADERS are complete, concurrently with the reader
/// feeding the request body in.
fn spawn<H>(shared: &Conn, notify: &Arc<Notify>, handler: &Arc<H>, sid: u32, req: http::Request)
where
    H: Handler,
{
    {
        let mut s = shared.lock().unwrap();
        s.active_handlers += 1;
    }
    let shared = shared.clone();
    let notify = notify.clone();
    let handler = handler.clone();
    tokio::spawn(async move {
        // The request method is part of the response's HTTP framing: a HEAD request (like a
        // 1xx/204/304 status) carries NO body, so the writer must send HEADERS (keeping the
        // declared `content-length`) + END_STREAM and no DATA — and must NOT mistake the
        // expected empty body for a declared-length under-run (which would wrongly RST the
        // stream). Capture it before `handle` consumes the request; mirrors the h1 writer's
        // `no_body` rule (`h1::serve::write_response`).
        let method = req.method().clone();
        let resp = handler.handle(req).await;
        emit_response(&shared, &notify, sid, &method, resp).await;
        {
            let mut s = shared.lock().unwrap();
            s.active_handlers -= 1;
        }
        notify.notify_one();
    });
}

/// Emit a genuine **interim** `100 (Continue)` on a stream: a `:status 100` HEADERS frame
/// with NO END_STREAM, so the stream stays open for the handler's real final response (which
/// is queued onto the same outbox afterward and framed as usual). This is the h2 interim-1xx
/// primitive — distinct from `emit_response`'s `no_body` branch, which frames a 1xx that a
/// *handler* returns as a terminal (END_STREAM) response; the `100-continue` handshake is
/// generated by the codec itself, never by the handler, and must never close the stream.
///
/// Called at most once per stream, from [`ConsumeGatedBody`]'s first poll (the lazy,
/// Go-aligned trigger). `push_out` is a no-op if the stream was already reset or is gone, so
/// a client that reset mid-request neither double-sends nor stalls here.
fn emit_continue(shared: &Conn, notify: &Arc<Notify>, sid: u32) {
    push_out(
        shared,
        notify,
        sid,
        OutFrame::Headers {
            fields: vec![(b":status".to_vec(), b"100".to_vec())],
            end_stream: false,
        },
    );
}

/// Queue a response onto its stream's outbox, waking the writer. A buffered body
/// (`Bytes`) is queued all at once; a [`http::Body::Stream`] / [`http::Body::StreamSized`]
/// is drained chunk by chunk over time and forwarded as DATA frames — so the writer streams
/// it without the whole body ever being held (the reverse-proxy fast-path). `StreamSized`
/// additionally carries a `content-length` header so the client gets a known length.
async fn emit_response(
    shared: &Conn,
    notify: &Arc<Notify>,
    sid: u32,
    method: &::http::Method,
    resp: Response,
) {
    let (parts, body) = resp.into_parts();
    // No-body responses carry HEADERS (keeping the declared `content-length`) + END_STREAM and
    // NO DATA — the identical rule the h1 writer applies (`h1::serve::write_response`'s
    // `no_body`). For a HEAD the handler still produces the body a GET would (so the declared
    // length is right), but those bytes must never reach the wire; and a declared-length body
    // that is (expectedly) empty here must NOT be treated as a §8.1.2.6 under-run and RST.
    let status = parts.status.as_u16();
    let no_body = *method == ::http::Method::HEAD
        || (100..200).contains(&status)
        || status == 204
        || status == 304;
    match body {
        // A streamed body with no declared length: frame it with the producer's own headers
        // (no re-derived content-length) — the stream ending delimits it.
        http::Body::Stream(stream) => {
            emit_streaming(shared, notify, sid, &parts, None, no_body, stream).await;
        }
        // A streamed body with a declared length: emit a `content-length` header (if the
        // producer didn't already) so the client gets progress/range, then stream the body.
        http::Body::StreamSized { stream, len } => {
            emit_streaming(
                shared,
                notify,
                sid,
                &parts,
                Some(len as usize),
                no_body,
                stream,
            )
            .await;
        }
        other => {
            let frames = response_to_frames(parts, other, no_body).await;
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
                if let Some(st) = s.streams.get_mut(&sid)
                    && !st.reset
                {
                    st.unsent = unsent;
                    st.outbox = frames;
                }
                s.mark_ready(sid);
            }
            notify.notify_one();
        }
    }
}

/// Stream a response body chunk-by-chunk onto its stream's outbox (shared by the
/// unsized [`http::Body::Stream`] and the declared-length [`http::Body::StreamSized`]
/// paths): push HEADERS (with `content_length` appended when `Some`, so a sized body
/// gets a client-visible length), then forward each chunk as a DATA frame under the
/// per-stream backpressure bound, and finally an empty END_STREAM marker. A mid-stream
/// [`http::BodyError`] resets the client stream so a truncated body is never framed as a
/// clean end.
async fn emit_streaming(
    shared: &Conn,
    notify: &Arc<Notify>,
    sid: u32,
    parts: &::http::response::Parts,
    content_length: Option<usize>,
    no_body: bool,
    mut stream: std::pin::Pin<Box<dyn tokio_stream::Stream<Item = http::BodyChunk> + Send>>,
) {
    let fields = response_fields(parts, content_length);
    // A no-body response (HEAD / 1xx / 204 / 304): emit the HEADERS — INCLUDING the declared
    // `content-length`, so a HEAD reports the length its GET would carry — with END_STREAM, and
    // stop. No DATA frame, and crucially none of the declared-length under-run RST below runs:
    // the empty body is EXPECTED here, not a truncation. h1-parity with `write_response`'s
    // `no_body` short-circuit. (The genuine under-run RST stays in force for every other
    // response — a GET whose body falls short of its declared length still resets.)
    if no_body {
        push_out(
            shared,
            notify,
            sid,
            OutFrame::Headers {
                fields,
                end_stream: true,
            },
        );
        return;
    }
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
    // For a declared-length (`StreamSized`) body, the bytes still owed against its committed
    // `content-length`. `None` for an unsized `Body::Stream` (no length to enforce).
    let mut remaining = content_length;
    // Poll the stream directly in this per-stream task — no channel, no producer task;
    // the writer frames each chunk as it arrives.
    while let Some(item) = stream.next().await {
        let chunk = match item {
            Ok(chunk) => chunk,
            // The source failed mid-stream (e.g. a proxy upstream dropped): reset the
            // client stream so a truncated body is never framed as complete.
            Err(_) => {
                reset_local(shared, notify, sid, ErrorCode::InternalError);
                return;
            }
        };
        if chunk.is_empty() {
            continue;
        }
        // Declared-length OVER-run (§8.1.2.6): a `StreamSized` body whose source yields more
        // than its committed `content-length`. RST rather than frame bytes past the length,
        // so the client never sees a cleanly-ended body that is actually wrong — defense-in-
        // depth parity with the h1 writer's force-close (the client's own §8.1.2.6 check is
        // the backstop). An unsized body (`remaining` is `None`) is unaffected.
        if let Some(rem) = remaining.as_mut() {
            if chunk.len() > *rem {
                reset_local(shared, notify, sid, ErrorCode::InternalError);
                return;
            }
            *rem -= chunk.len();
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
        // Backpressure: once the per-stream send buffer crosses the high-water mark (the
        // writer is behind — usually a flow-control window the slow client hasn't opened),
        // stop pulling the source until the writer drains it below the low-water mark.
        // Bounds per-stream memory to ~STREAM_HIGH_WATER regardless of body size.
        loop {
            let over = {
                let s = shared.lock().unwrap();
                match s.streams.get(&sid) {
                    // A reset/gone stream, or a torn-down connection whose window can no
                    // longer reopen, means we stop producing.
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
    // Declared-length UNDER-run (§8.1.2.6): a `StreamSized` body whose source ended short of
    // its committed `content-length` is truncated. RST rather than a clean END_STREAM, so the
    // client sees an error, not a silently short body (h1-parity).
    if remaining.is_some_and(|rem| rem != 0) {
        reset_local(shared, notify, sid, ErrorCode::InternalError);
        return;
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
    if let Some(len) = content_length
        && !parts.headers.contains_key(::http::header::CONTENT_LENGTH)
    {
        fields.push((b"content-length".to_vec(), len.to_string().into_bytes()));
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
    no_body: bool,
) -> VecDeque<OutFrame> {
    // A no-body response (HEAD / 1xx / 204 / 304): emit HEADERS + END_STREAM and no DATA, while
    // keeping the `content-length` the body WOULD carry (a HEAD reports its GET's length) —
    // taken from the body's declared length WITHOUT reading it (a `File`/`Bytes` body knows its
    // size). h1-parity: `write_response` likewise short-circuits before touching the body.
    if no_body {
        let len = body.len();
        let fields = response_fields(&parts, (len > 0).then_some(len));
        let mut out = VecDeque::new();
        out.push_back(OutFrame::Headers {
            fields,
            end_stream: true,
        });
        return out;
    }
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
        // A `sendfile` file body has no HTTP/2 zero-copy analogue; materialize the
        // region (positioned read). Only a plaintext-h2c large static reaches this.
        http::Body::File { file, offset, len } => {
            crate::serving::read_file_region(&file, offset, len).unwrap_or_default()
        }
        // `emit_response` streams a `Body::Stream` / `Body::StreamSized` directly and never
        // routes either here; buffer it if it ever does, so this stays correct. A mid-stream
        // error ends the drain (best-effort — this fallback is only reached if a stream is
        // ever routed through the buffered path).
        http::Body::Stream(mut stream) | http::Body::StreamSized { mut stream, .. } => {
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
        let mut wrote = false;
        loop {
            batch.clear();
            build_batch(&shared, &mut hpack, &mut batch);
            if batch.is_empty() {
                break;
            }
            write_all_vectored(&mut wr, &batch).await?;
            wrote = true;
        }
        // Flush before idling. `write_all_vectored` only writes what the transport's
        // `poll_write` accepts; a buffering writer (userspace rustls) accepts the plaintext
        // but, when the TCP socket is backpressured, leaves the matching *encrypted* records
        // queued in its own buffer and returns anyway. With the outbox drained the writer is
        // about to park on `notify` with no further `poll_write`/`poll_flush` scheduled, so
        // those queued records — the tail of the response — would sit unsent until the next
        // frame (which, for a completed response, never comes) and the peer hangs waiting for
        // bytes the server already considers "written". A 0-RTT loopback never fills the
        // socket so this is invisible there; a real-RTT / rate-limited / lossy path fills it
        // and strands the tail. Draining the transport here makes the queued records reach the
        // peer before we park. (`flush` on a plain `TcpStream` is a cheap no-op, so the serial
        // h1/h2 paths and h2c are unaffected; `poll_flush` yields on backpressure, releasing
        // the split lock so the reader keeps processing inbound frames.)
        if wrote {
            wr.flush().await?;
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

        // Requeue if the stream's next frame can make progress *now*. Only one DATA
        // frame is emitted per visit, so requeuing (rather than looping here) gives
        // round-robin fairness across streams; a stream that can't progress drops out of
        // `ready` and is re-readied by `mark_ready` on a WINDOW_UPDATE / SETTINGS bump.
        //
        // A frame can make progress when it needs no flow-control window — a HEADERS
        // frame, or a *zero-length* DATA frame (the streamed-body END_STREAM marker,
        // which is exempt from flow control per RFC 7540 §6.9.1) — or when it is a
        // non-empty DATA frame and both windows are open. The zero-length case is
        // essential: a stream whose only remaining output is the END_STREAM marker, left
        // with a closed window by its body's final bytes, must still be re-queued or the
        // response never completes (the peer has the whole body but never sees
        // END_STREAM). `build_batch` already emits such a frame regardless of the window;
        // this makes sure the stream is scheduled to be visited so it can.
        let has_win = {
            let st = s.streams.get(&id);
            st.is_some_and(|st| st.send_window > 0) && s.conn_send_window > 0
        };
        let next_sendable = match s.streams.get(&id).and_then(|st| st.outbox.front()) {
            Some(OutFrame::Headers { .. }) => true,
            Some(OutFrame::Data { bytes, off, .. }) => bytes.len() - *off == 0 || has_win,
            None => false,
        };
        if next_sendable {
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
