# DESIGN — unified boatramp HTTP serving (h1 + h2, one owned stack)

Status: **design, pre-implementation.** Companion to `DESIGN-mux.md` (the h2 driver)
and `README.md` (the perf campaign). This proposes the *final* serving architecture the
h2-mux graduation should land on, so we don't ship an interim "mux for h2 / hyper for
h1" split and refactor later.

## Why unify (beyond perf-tweaking)

Today a TLS connection is served: `accept → TLS → ALPN → { h2: boatramp-h2 mux driver,
h1: hyper }`. Two serving stacks, two `Body` types, two sets of limits / timeouts /
logging / error behavior, and the plaintext splice fast-path is a *peek/rewind bolt-on*
(`crates/boatramp-server/src/splice.rs`) wrapped around the listener because hyper owns
the connection.

Owning **both** codecs buys four things that are not just perf polish:

1. **kTLS + splice for `tls-proxy-h1` — an Envoy-beating lever hyper structurally cannot
   do.** (This corrects an earlier claim in the perf notes that "tls-h1 can't be
   spliced.") Plain `splice()` can't, but **kernel-TLS** can: with the client socket in
   kTLS mode the kernel encrypts on TX, so `splice(upstream → pipe → kTLS_socket)` moves
   a reverse-proxy body **kernel-to-kernel with the kernel doing the crypto** — the body
   never enters userspace. hyper always reads the body into userspace and encrypts via
   rustls there. H1 is one-request-per-connection, so splice shines and there is no
   multiplexing to serialize — this is exactly why the original spike **beat Envoy on
   `tls-h1-100k`**. That win is not in the product today because it requires owning the
   h1 serving loop. The mechanism already exists here: `conn.rs::serve_connection_ktls`
   + `wire.rs::splice_data_frame`.
2. **One serving model.** A single accept loop and a single `Handler`/`Request`/
   `Response`/`Body` abstraction for both protocols → consistent timeouts, body/header
   limits, access logging, metrics, and error/`GOAWAY`/`close` behavior. Cross-cutting
   features get implemented once, not twice.
3. **Uniform DoS hardening.** boatramp-h2 bounds *everything* explicitly (CONTINUATION
   flood, rapid-reset, header caps, response backpressure). h1 currently inherits
   hyper's defaults; owning it lets us apply the same "bound it or reject it" discipline
   (slowloris, request-line/header caps, keep-alive request caps).
4. **In-loop splice.** The plaintext splice fast-path becomes a branch in the h1 loop —
   no non-consuming peek, no `Rewind`, no double-parse.

**The counterweight — h1 is far more dangerous to hand-roll than h2.** HTTP/1.1's
Content-Length vs Transfer-Encoding ambiguity is *the* classic request-smuggling /
desync surface, and hyper is battle-hardened against it after years of CVEs. h2 had
**h2spec** as a ready-made conformance gate; **there is no h2spec-for-h1.** So the h1
codec cannot ship until it clears a purpose-built safety gate (below). This is the
whole risk of the project and the reason it is a separate, multi-stage effort — not a
fold-in to the h2 graduation.

## Target architecture

```
                         one boatramp-owned serving crate
  ┌───────────────────────────────────────────────────────────────────────┐
  │  serve_connection(io, service, limits)                                  │
  │    • plaintext: sniff h2c preface ─┐        • TLS: negotiated ALPN ─┐   │
  │                        h1 ◄─────────┴──► h2c   h2 ◄─────────────────┘   │
  │    ┌──────────────┐            ┌──────────────────────────┐            │
  │    │ boatramp-h1  │            │ boatramp-h2 (mux driver) │            │
  │    │ codec (new)  │            │ (exists, h2spec 143/143) │            │
  │    └──────┬───────┘            └───────────┬──────────────┘            │
  │           └──────────► service.call(Request) ◄──────────┘             │
  │                 http::Request<ReqBody> → http::Response<Body>          │
  └───────────────────────────────────────────────────────────────────────┘
        service = the axum Router (tower Service) — unchanged
```

### Common types (already exist in boatramp-h2 — promote them)
- `Request = http::Request<ReqBody>`, `Response = http::Response<Body>`.
- `Body = Bytes | Stream(pull stream, with backpressure) | Splice{upstream,len}` — the
  `Splice` variant is what unlocks the kTLS fast-path; `Stream` already has the
  backpressure + `BodyError` reset semantics from the hardening pass.
- **New: a streaming `ReqBody`** (incoming). h2 already accumulates DATA; h1 adds
  chunked/CL decoding. Large POST/upload bodies must *stream* to the upstream, not
  buffer — mirror the response-side backpressure.

### Service abstraction — **recommend: native `tower::Service`**
The current mux `Handler` trait + `RouterHandler` bridge exists only because the driver
predates this unification. Recommend the codecs invoke a
`tower::Service<http::Request<ReqBody>, Response = http::Response<Body>>` directly, so
the **axum Router plugs in with no bridge** (hyper's exact shape). One adapter deleted,
one fewer request/response copy. `Handler` can remain as a thin convenience for embedders.

### Crate layout — **recommend: `boatramp-http` (types + serve) + `boatramp-h1` + keep the h2 codec**
- `boatramp-http`: the common `Request`/`Response`/`Body`/`ReqBody`/limits + the
  `serve_connection` dispatcher + the splice/kTLS wire helpers.
- The existing h2 mux driver + the new h1 codec are codecs over `boatramp-http`.
- `boatramp-h2` (workspace-excluded spike) folds into this on graduation.

## The h1 codec + its safety gate (the crux)

Codec scope: request-line + header parse; **strict** framing; chunked transfer decode;
keep-alive (with a request cap); `Expect: 100-continue`; `Connection: close`;
response framing (Content-Length when known, else chunked); trailers; upgrades.

**Anti-smuggling rules (reject, never guess):**
- `Content-Length` **and** `Transfer-Encoding` both present → 400 (no CL/TE desync).
- Multiple `Content-Length`, or non-numeric / conflicting values → 400.
- `Transfer-Encoding` present but final coding ≠ `chunked` → 400.
- No obs-fold (leading-whitespace header continuation) → 400.
- Bare `\n` line terminators / whitespace before `:` / non-token header names → 400.
- Bound the request line, header block, header count, chunk-size line, chunk extensions.

**Safety gate (the h1 analogue of h2spec — must pass before it ships):**
1. **Differential vs hyper.** Feed identical raw byte streams to `boatramp-h1` and
   `hyper::server::conn::http1`; assert identical parse (method/URI/headers/body
   framing) **or** identical rejection. This is the primary oracle (same pattern as the
   h2 differential vs `h2`/`hyper`).
2. **Smuggling corpus.** The known CL/TE / chunked desync vectors (the PortSwigger set +
   the HTTP-Garden / http-smuggling corpora) → assert safe rejection/normalization, and
   that boatramp-h1 and the upstream never disagree on message boundaries.
3. **Fuzzing** the request parser (cargo-fuzz + a stable randomized smoke, like the
   HPACK fuzz that caught a real panic).
4. **RFC 9112 conformance subset** as targeted unit tests.
- Promotion rule, same discipline as the crate's "keep it only if it clears the gate":
  h1 stays behind hyper until the gate is green.

## kTLS + splice for `tls-proxy-h1`

Reuse `serve_connection_ktls` (CorkStream → `config_ktls_server` → raw fd, leftover
drain) + `splice_data_frame`. In the h1 loop, for a **splice-eligible** request (reuse
`splice.rs`'s conservative gateway-proxy classifier — single plaintext-HTTP upstream, no
access rules / redirects / handlers), after the TLS handshake enable kTLS and
`splice(upstream → pipe → kTLS_fd)` for the response body; the 9-byte-free h1 chunk/CL
framing rides ahead of the body. Everything else stays userspace.

**The one unsolved M4b problem to fix here:** under enough concurrent connections,
`splice(pipe → kTLS_fd)` via `async_io(WRITABLE)` **livelocked** (epoll signals the TCP
socket writable while the kTLS crypto path returns `EAGAIN`, so the readiness loop spun,
cores pegged, zero progress). A real backpressure/readiness fix is a prerequisite for
enabling kTLS by default; until then kTLS-splice is capability-detected + bounded, with
a clean fall-through to the userspace h1 path.

## Migration (each stage independently green + gated; behavior-preserving until flipped)

0. **h2 graduation onto the interim seam is *paused*** in favor of landing on this base.
1. **Extract** the common types into `boatramp-http`; the h2 mux driver depends on it.
   Pure refactor, h2spec still 143/143.
2. **Build `boatramp-h1` userspace codec + the full safety gate** (differential +
   smuggling + fuzz). No kTLS yet. It does *not* serve production traffic until the gate
   is green.
3. **Unified `serve_connection`** (ALPN + h2c sniff → h1/h2), fold `splice.rs` in-loop,
   and route every TLS mode (custom / ACME / ACME-DNS / RPK) **and** the plaintext path
   through it. Remove the `h2-mux` feature + `BOATRAMP_H2_MUX` env gate — one codec set,
   always on. hyper leaves the *serving* path (it stays only as the upstream client).
4. **kTLS + splice `tls-h1`** fast-path + the readiness/backpressure fix.

ACME note: rustls-acme's `acme-tls/1` challenge is answered by its cert resolver during
the handshake; `serve_connection` must include `acme-tls/1` in the acceptor ALPN and
drop a challenge-only connection (no app bytes) — otherwise ACME cert provisioning
breaks. Verify against a Pebble test CA before flipping the ACME mode.

## Risks (ranked)
1. **Request smuggling** — mitigated only by the gate; this gates the whole project.
2. **kTLS livelock** (M4b's unsolved c256 spin) — kTLS stays opt-in/bounded until fixed.
3. **Upgrades / WebSocket** — must be reimplemented (hyper handles them today); until
   then, CONNECT/`Upgrade` requests fall through to a hyper connection.
4. **Maintenance** — a second forever-owned codec.
5. **Scope** — multi-session; larger than the h2 graduation it replaces.

## Open decisions (need a call before Stage 1)
1. **Service abstraction:** native `tower::Service` (recommended, deletes the bridge) vs
   keep the `Handler` trait + adapter?
2. **Crate layout:** `boatramp-http` + `boatramp-h1` + fold in the h2 codec
   (recommended) vs keep `boatramp-h2` standalone + a thin serving crate?
3. **kTLS timing:** design/land the userspace unified codec first (Stages 1-3), kTLS as
   Stage 4 (recommended) vs bring kTLS forward?
4. **Safety bar for promotion:** is "differential-vs-hyper green + smuggling corpus green
   + fuzz clean" sufficient to let boatramp-h1 serve production, or do you want a soak /
   staged rollout behind a per-site opt-in first?
