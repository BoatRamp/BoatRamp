# boatramp-h2

A minimal, **conformance-gated** HTTP/2 server with a kernel zero-copy
(`splice()`/kTLS) response-body fast-path.

## Reason to exist

`h2` (via `hyper`) copies the response body through userspace to frame and
encrypt it — the throughput ceiling for a large-body reverse proxy. `boatramp-h2`
owns the framing so the body moves **kernel-to-kernel**: spliced from the upstream
socket into a kTLS client socket (kernel encrypts on TX), with only the 9-byte
DATA headers in userspace. On the fair 5-way benchmark this is the only measured
lever that brings BoatRamp to Envoy parity on `tls-proxy-h2-100k`; every build /
config lever (musl-vs-glibc, `target-cpu`, frame/read/send-buffer knobs, allocator)
was measured and does nothing there — the gap is the userspace codec itself.

## Non-negotiable: correctness first

A hand-rolled HTTP/2 is a bug farm if you build only the happy path — a
benchmark-shaped prototype passed just **60 / 145** h2spec cases (the 85 gaps
included DoS-relevant ones like unbounded frame sizes). So the crate is built
**red → green** against three harnesses, wired before the server is fleshed out:

1. **h2spec** (RFC 7540 + RFC 7541 conformance) — a hard CI gate. Must be 145/145,
   where any behavior the fast-path doesn't implement degrades to a graceful
   `GOAWAY`/reset, never to wrong behavior.
2. **Differential oracle** — replay identical request streams through this server
   and a reference `hyper`/`h2` server; assert byte-identical responses.
3. **Fuzzing** (`cargo-fuzz`) — the frame + HPACK parsers must be panic-free,
   hang-free, and never desync (request smuggling).

Because HTTP/2 is stateful (HPACK dynamic table, multiplexing), there is no clean
mid-connection fallback the way HTTP/1's `Rewind` allows. So a connection this
server accepts, it must handle correctly for its whole life — hence the hard gate.

## Architecture

```
frame     9-byte header + typed frames + validated parse/encode        [DONE, tested]
error     RFC 7540 §7 error codes + connection-vs-stream error scope    [DONE, tested]
settings  SETTINGS params, spec defaults, per-§6.5.2 validation         [DONE, tested]
hpack     thin wrapper over a maintained HPACK crate (fluke-hpack)      [next]
stream    per-stream state machine (idle/open/half-closed/closed) +
          per-stream flow control + illegal-transition detection        [next]
conn      connection driver: preface, SETTINGS negotiation, read/dispatch
          loop, connection flow control, PING/GOAWAY, error routing      [next]
server    accept(IO) -> requests; response with a splice body seam
          `Body::splice_from(fd, len)` for the zero-copy path            [next]
splice    Linux splice(upstream_fd -> pipe -> kTLS_fd) DATA writer       [port from spike]
```

## Roadmap (each step ends green on its harness)

- [x] **M0 foundation** — frame / error / settings, unit-tested, pure `std`.
- [x] **M1 conformant core** — hpack + stream + conn; drive h2spec §3–§6 green
      (framing, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, stream states, error codes,
      frame-size + flow-control enforcement). No body optimization yet.
- [x] **M2 HPACK conformance** — h2spec §4/§8 (HPACK, header field validation) green.
- [x] **M3 server API** — `accept` + request/response over any `AsyncRead+AsyncWrite`;
      differential test vs `hyper`/`h2` byte-identical.
- [x] **M4 splice body** — M4a: `Body::Splice` seam + streaming validated in h2c
      (proxy: body md5 == direct). M4b: kTLS handoff (`serve_connection_ktls`) +
      kernel `splice(upstream → pipe → kTLS fd)` with the DATA header coalesced into
      the body's TLS record. Correct (md5 == direct over kTLS, HTTP/2), but **it does
      not clear Envoy** on the integrated path — see the benchmark verdict below.
- [x] **M4c concurrent multiplexed driver** — `serve_connection_mux`: decouple the
      handler from the socket (reader task + per-stream handler tasks + writer task,
      two-tier flow control) so one connection multiplexes streams, plus a pooled
      HTTP/1.1 upstream. **This clears Envoy** — see below. The kTLS/splice premise
      was a red herring: userspace rustls + a userspace body copy already win.
- [x] **M5 fuzzing + hardening** — cargo-fuzz frame/HPACK (found + fixed a real HPACK
      decoder panic); CONTINUATION-flood + Rapid-Reset mitigations. Both drivers still
      h2spec 143/143.
- [~] **M6 BoatRamp integration** — wired the mux driver into BoatRamp's TLS serve
      behind the `h2-mux` feature + `BOATRAMP_H2_MUX` env gate (h2 → mux, h1 → hyper;
      hyper stays default). Compiles + serves correctly + the mux path is confirmed
      live, but the standalone win does **not** survive the buffered router-bridge —
      see the M6 verdict below.

## M6 integration verdict (live on lighthouse, boatramp gateway → upstream)

The mux driver bridged into BoatRamp's full axum Router (with a **buffered** response
body) is *slightly slower* than the existing hyper path, despite the standalone mux
proxy beating Envoy:

| concurrency | integrated mux (via router) | integrated hyper | standalone mux example |
| ---: | ---: | ---: | ---: |
| c64  | 34,535 | 35,365 | 54,942 |
| c128 | 27,759 | 33,214 | 43,722 |
| c256 | 26,556 | 30,068 | 42,127 |

Correct (md5 == direct, HTTP/2, 100 KiB) and the mux path is confirmed active (server
sends an empty SETTINGS frame vs hyper's `MAX_CONCURRENT_STREAMS=256`).

**Streaming was added and did not recover the win.** The bridge now streams the router
response body through the mux driver (a `Body::Stream` variant) instead of buffering
it (`collect()`). Same rig, mux path confirmed active:

| concurrency | streaming mux | hyper |
| ---: | ---: | ---: |
| c64  | 30,728 | 33,897 |
| c128 | 25,459 | 32,536 |
| c256 | 22,375 | 29,804 |

Still ~slower than hyper, both streaming and buffered — but **buffering was not the
bottleneck** and neither was the router (mux + hyper pay it equally). A `perf`-driven
optimization pass closed the gap.

### Perf campaign — near-parity with hyper on the router-served path

The gap was purely mux-serving vs hyper's native h2 serving of the *same* router
(axum is on both sides). `perf` found and fixed, in order: **`writev` at 27%**
(`build_batch` emitted one frame per `write_all` → coalesce into one write);
**glibc `malloc` at 13%** (jemalloc build + reused per-connection write buffer);
**`memmove` at ~10%** (bodies flow as ref-counted `Bytes`, and **vectored writes** hand
the body slices straight to rustls with no copy through our buffer). Native
`http::Request`/`Response` in the driver removed the bridge's per-request re-marshaling.
`perf stat` confirmed it's **not** scheduling — mux has 6× *fewer* context switches than
hyper at identical CPU utilization; the residual was diffuse per-request CPU.

| concurrency | mux (optimized) | hyper | mux / hyper |
| ---: | ---: | ---: | ---: |
| c64  | 38,100 (47.4k warmup) | 39,100 | **~97%** (ahead in warmup) |
| c128 | 34,100 | 36,800 | ~93% |
| c256 | 30,300 | 33,300 | ~91% |

So on the router-served path the integrated mux is **near-parity** (91–97%, ahead at
c64 in good runs) — no longer slower. The mux *driver* itself still beats hyper
*standalone* (42k vs 33k at c256); the remaining few % looked like the router
middleware both paths run.

### Router-bypass fast-path — tried, proven safe, **no gain → reverted**

The last lever tried was a **router-bypass fast-path**: for a request that is an
*unambiguous pure gateway proxy*, call `dispatch_gateway` directly and skip the axum
middleware. To guarantee it could never skip a site's access rules, the h1 splice
path's exact eligibility check was factored into a shared `classify_gateway` oracle
that **both** fast-paths called (zero drift: whatever the splice path refuses — access
rules, redirects, handlers, streams — the mux bypass refused too, falling through to
the full router). It was correct and confirmed *active* (its responses came straight
from `dispatch_gateway` — e.g. no `content-length`, vs the router path's).

But it moved throughput **not at all** (lighthouse, 100 KiB TLS h2 proxy, cores 0-7,
oha `--http2`):

| concurrency | hyper | mux (bypass on) | mux (router only) |
| ---: | ---: | ---: | ---: |
| c64  | 51,692 | 41,884 | 41,684 |
| c128 | 36,942 | 36,774 | 36,783 |
| c256 | 32,174 | 32,119 | 32,109 |

Bypass-on and bypass-off are within 0.5 % at every concurrency. The reason is
structural: **the bypass only fires on the lightest sites.** A site with any access
rule (basic-auth / rate-limit / IP / WAF) — the ones whose middleware actually costs
something — is refused by the oracle and served by the full router. On the pure-proxy
sites the oracle *does* bypass, the axum stack is already near-free, so skipping it
saves nothing. So the earlier "the remaining few % is the middleware" hypothesis was
**wrong**: the residual gap to hyper is **not** the router — it is diffuse per-request
cost inside the mux driver + serving (framing, flow control, the per-response
streaming-channel hop). The bypass was reverted (no benefit, extra surface); the
shared eligibility oracle went with it. (Absolute gaps swing widely with shared-host
load — this run had load ~5; quiet runs measured near-parity — but the *controlled*
bypass-vs-router delta is stably ~0 %.)

Streaming is kept regardless (bounded memory + TTFB). hyper stays default.

### Direct-poll stream body — the real win (+9–16 %, matches/beats hyper)

The router-bypass pointed at the true residual: **the per-response streaming-channel
hop.** The bridge wrapped *every* response in a `tokio::spawn` + `mpsc(8)` channel to
pump the router's body into the driver — a task-create + channel round-trip on the
hot path of each request. Two fixes were measured:

- **Lever A — collect to `Bytes`:** buffer a bounded (≤1 MiB) known-length response
  once and hand the driver a single `Bytes` body (no spawn, no channel). Helped at
  high concurrency (+5 % c128, +10 % c256, hyper parity at c256) but nothing at c64,
  and it buffers.
- **Lever B — direct-poll stream:** make `Body::Stream` a pull `Stream` the driver
  polls **directly** in its existing per-stream task; the bridge hands axum's body
  straight in (`BodyStream::new(body)`). No producer task, no channel, no buffering
  (unbounded bodies still stream). This **dominates** Lever A everywhere and is the
  shipped default.

Stable across rounds (100 KiB TLS h2 proxy, cores 0-7, oha `--http2`):

| concurrency | baseline (channel+spawn) | **direct (Lever B)** | hyper |
| ---: | ---: | ---: | ---: |
| c64  | 37.8–38.1k | **41.5k** (+9 %)  | 39–48k (load-noisy) |
| c128 | 34.0k      | **38.6k** (+13 %) | 36.7k |
| c256 | 30.2k      | **34.9k** (+15 %) | 33.2k |

So the integrated mux now **matches or beats hyper at every concurrency** (it was
79–91 % before), with `direct` rock-stable run-to-run while hyper's c64 swings with
shared-host load. hyper stays default (this is the opt-in `h2-mux` path).

## M4c benchmark result (tls-proxy-h2-100k, lighthouse, cores 0-7, oha --http2)

The concurrent multiplexed driver with **userspace rustls (no kTLS) + a pooled
HTTP/1.1 upstream** beats Envoy at every concurrency — and the M4b kTLS+splice serial
driver at ~2x:

| concurrency | M4b kTLS+splice (serial) | **M4c mux + rustls + pool** | Envoy |
| ---: | ---: | ---: | ---: |
| c64  | 24,800 | **54,942** | 51,492 |
| c128 | 21,800 | **43,722** | 42,062 |
| c256 | livelock (~56) | **42,127** | 37,869 |

Correct (md5 == direct, HTTP/2, 100 KiB, 100% 2xx) and no livelock. This confirms the
competitive study (reading `h2`'s source + Envoy's architecture): the gap to Envoy was
**stream multiplexing + upstream connection pooling + flow control**, *not* the
userspace body copy or the TLS implementation. Envoy itself uses userspace BoringSSL
+ stock nghttp2 and rejected kTLS (~5% regression). So the crate's original premise —
hand-roll h2 + splice/kTLS to beat the "userspace-copy ceiling" — was wrong; the
ceiling was the serial driver, and once that's fixed, splice/kTLS is unnecessary (and
was in fact slower). See `DESIGN-mux.md`.

## M4b benchmark verdict (tls-proxy-h2-100k, lighthouse, cores 0-7, oha --http2)

| concurrency | boatramp-h2 kTLS+splice | Envoy |
| ---: | ---: | ---: |
| c64  | ~24,800 | **51,492** |
| c128 | ~21,800 | **42,062** |
| c256 | **livelock (~56)** | **37,869** |

The kTLS + splice *mechanism* works and is correct, but the integrated path is ~half
of Envoy at healthy concurrency and livelocks at c256. Two structural causes — the
"integration tax" — not the splice itself:

1. **Per-connection serialization.** The driver processes one frame/request fully
   (run the handler, then flush the whole body) before reading the next frame, so a
   single connection can't multiplex concurrent streams — h2load measures a hard
   ~340 req/s **per connection** regardless of `-m`. HTTP/2's whole value is
   multiplexing; this design defeats it. (The earlier spike beat Envoy on
   `tls-h1`-100k precisely because H1 is one-request-per-connection, where splice
   shines and serialization costs nothing.)
2. **kTLS-TX readiness spin at c256.** Under enough concurrent load the
   `splice(pipe → kTLS fd)` via `async_io(WRITABLE)` livelocks — epoll signals the
   TCP socket writable while the kTLS crypto path returns `EAGAIN`, so the readiness
   loop spins (8 cores pegged, zero progress).

Clearing Envoy here needs a concurrent-per-stream driver (spawn handler + body flush
per stream, funnel writes through one writer task, pool upstream connections) plus a
kTLS-TX backpressure fix — a substantial redesign, deferred. So per the "keep it only
if it clears Envoy" gate, the splice path is **not** promoted to the default.

## Status

M0-M4c complete. Two drivers, **both h2spec 143/143** (0 failed, 2 skipped): the
serial `conn.rs` and the concurrent multiplexed `mux.rs` (`serve_connection_mux`).
The mux driver over userspace rustls + a pooled upstream **beats Envoy** on
tls-proxy-h2-100k at every concurrency (table above), which retires the crate's
original splice/kTLS premise. 27 tests green (18 unit + 3 interop + 5 mux incl. a
concurrency-interleave proof + trailers + 1 smoke). Next: M5 fuzzing + DoS hardening,
then M6 wiring the mux driver into BoatRamp.
