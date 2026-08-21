# M4c — the concurrent multiplexed driver (redesign)

## Why

M4b's kTLS+splice path is correct but ~half of Envoy and livelocks at c256. Root
cause (confirmed by reading the `h2` crate source and Envoy's architecture): the
serial driver in `conn.rs` **fuses "read a frame" with "run the handler to
completion and flush the whole body"**, so one connection can't multiplex streams
(~340 req/s/conn ceiling, h2load). The splice savings are dwarfed by this tax — the
serial+splice server (~22k) even loses to plain hyper (~33k).

## The fix (mirrors `h2` `proto/connection.rs` + `streams/prioritize.rs`)

Decouple the connection driver from the handler; the driver only **moves bytes**.

Two halves per connection over `tokio::io::split(io)`, sharing `Arc<Mutex<Shared>>`
plus a `tokio::sync::Notify` (the "driver waker"):

- **Reader task** (owns read half): read one frame → update `Shared` → for HEADERS+
  END_STREAM, spawn a handler task → for DATA, push to the stream inbox + wake its
  consumer → for WINDOW_UPDATE/SETTINGS, adjust windows and `notify` the writer.
  Never runs a handler. HPACK **decode** happens here (single decoder, serialized).
- **Handler task** (one per request stream): run `Handler::handle`, then push response
  frames (semantic, not encoded) into the stream's **outbox**, mark the stream
  `ready`, and `notify` the writer. Never touches the socket.
- **Writer task** (owns write half): wait on `Notify`; then loop: lock `Shared`,
  drain `ready` streams' outboxes into one buffer respecting **two-tier flow control**
  (conn window + per-stream window, per-frame ≤ max_frame), unlock, `write_all` the
  buffer. HPACK **encode** happens here (single encoder, serialized). Requeue any
  stream with remaining outbox/window. Batches many frames into few syscalls.

### Shared state
```
struct Shared {
    streams: HashMap<u32, Stream>,
    ready: VecDeque<u32>,          // streams with sendable frames; Stream.queued dedups
    conn_send_window: i64,
    peer: Settings,                // peer's SETTINGS (max_frame_size, initial_window)
    hpack_enc: fluke_hpack::Encoder,  // writer-only
    goaway: Option<ErrorCode>,
    last_client_id: u32,
    closed: bool,
}
struct Stream {
    state: StreamState,
    send_window: i64,
    outbox: VecDeque<OutFrame>,    // OutFrame::Headers(fields,end) | Data(Vec<u8>,end)
    queued: bool,
    // recv (request body): inbox + waker — GETs have none; wire minimally.
}
```
HPACK encode/decode are each single-instance and confined to one task (writer/reader
respectively), so the dynamic tables stay correct without locking them per-frame.

### Splice, later
Once the userspace path reaches Envoy-class, re-add splice as a **writer-side**
`OutFrame::Splice { upstream_fd, remaining }`: the writer, when it reaches that frame,
splices `min(window, max_frame)` from the upstream fd into the connection fd. One
writer = one fd owner, so concurrent streams' splices interleave chunk-by-chunk
through the ready-queue. kTLS optional and measured separately (Envoy shows TLS isn't
the bottleneck at 100 KiB; kTLS gave Envoy a ~5% regression). Fix the c256 spin by
never busy-re-splicing on EAGAIN.

### Proxy example changes (independent of the driver)
- **Upstream connection pool**: reuse warm HTTP/1.1 keep-alive upstream connections
  (one in-flight request per conn), not `Connection: close` per request.
- Read the upstream head in bulk (not byte-at-a-time).

## Build order (each step compiles + tested + benchmarked)
1. `mux.rs`: Shared state + reader/writer/handler split, **userspace bodies only**,
   plaintext (buffered) first. Port the h2spec conformance checks from `conn.rs`
   (frame validation, stream states, flow control, error scope). Prove multiplexing
   with an h2load `-m` test (per-conn throughput must exceed ~340).
2. Rustls (userspace TLS, no kTLS) proxy example + upstream pool → benchmark
   tls-proxy-h2-100k vs Envoy. Target: beat hyper's ~33k, approach Envoy ~38k.
3. Re-run h2spec (buffered + TLS) → must stay conformant.
4. Only if 2 clears Envoy: add the splice writer-side path + measure the delta.
5. Fold back into M5 (fuzz/harden) + M6 (opt-in wiring) with the winning driver.

## Guardrails
- Keep the serial `conn.rs` intact as the conformance reference during the build.
- Flow-control correctness is the top risk: a large body must chunk by
  min(max_frame, stream_window, conn_window) and requeue the remainder; a
  window-starved stream sits out of `ready` until a WINDOW_UPDATE refills it.
- Don't hold the `Shared` lock across the socket write.
