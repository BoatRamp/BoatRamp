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
- [ ] **M5 fuzzing + hardening** — cargo-fuzz frame/HPACK; CONTINUATION-flood and
      RST-flood (Rapid Reset) mitigations.
- [ ] **M6 BoatRamp integration** — wire behind the serve eligibility gate as an
      opt-in fast-path with graceful fallback to hyper for anything non-eligible.
      Given the M4b verdict, hyper stays the default; the splice path is opt-in only.

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

M0-M4 complete: a runnable, RFC 7540 + RFC 7541 conformant HTTP/2 server over both
plaintext (buffered) and kTLS (splice) transports — h2spec 143/143 (0 failed, 2
skipped), 18 unit + 4 e2e/interop tests, body integrity validated over kTLS. The
kTLS+splice fast-path is correct but does not beat Envoy (verdict above); it stays an
opt-in path behind hyper. Next: M5 fuzzing + DoS hardening, then M6 opt-in wiring.
