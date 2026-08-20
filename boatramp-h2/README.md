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
- [ ] **M5 fuzzing + hardening** — cargo-fuzz frame/HPACK; CONTINUATION-flood and
      RST-flood (Rapid Reset) mitigations.
- [ ] **M6 BoatRamp integration** — wire the mux driver behind the serve eligibility
      gate as the fast-path with graceful fallback to hyper for anything non-eligible.

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

M0-M4c complete. Two drivers: the serial `conn.rs` (h2spec 143/143, the conformance
reference) and the concurrent multiplexed `mux.rs` (`serve_connection_mux`). The mux
driver over userspace rustls + a pooled upstream **beats Envoy** on tls-proxy-h2-100k
at every concurrency (table above), which retires the crate's original splice/kTLS
premise. 26 tests green (18 unit + 3 interop + 4 mux incl. a concurrency-interleave
proof + 1 smoke). Next: run h2spec against the mux driver (conformance parity with
the serial driver), then M5 fuzzing + DoS hardening, then M6 wiring into BoatRamp.
