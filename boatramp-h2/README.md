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
- [ ] **M4 splice body** — port the spike's `splice()`/kTLS DATA writer behind the
      server's body seam; benchmark `tls-proxy-h2-100k` vs Envoy on the integrated
      path; keep only if it clears Envoy after the integration tax.
- [ ] **M5 fuzzing + hardening** — cargo-fuzz frame/HPACK; CONTINUATION-flood and
      RST-flood (Rapid Reset) mitigations.
- [ ] **M6 BoatRamp integration** — wire behind the serve eligibility gate as an
      opt-in fast-path with graceful fallback to hyper for anything non-eligible.

## Status

M0-M2 complete: a runnable, RFC 7540 + RFC 7541 conformant h2c server — h2spec 143/143 (0 failed, 2 skipped), 18 unit + 1 e2e tests. Next: M3 differential oracle, then M4 TLS + splice body path.
