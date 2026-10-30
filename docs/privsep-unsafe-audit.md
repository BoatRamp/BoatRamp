# privsep phase 0 (WS3): fuzzing + unsafe audit for the untrusted-byte parsers

Scope: the hand-rolled parsers that take bytes an unauthenticated network peer fully controls
and turn them into structured host state, plus the `unsafe` Rust and C/native dependencies on
or near those paths. This is WS3 of privsep phase 0 — a hardening/verification pass, not a new
capability. Methodology: `grep -rn 'unsafe' crates/ --include='*.rs'`, filtered by hand to the
code reachable from the parsers below (their own module + what they call), cross-checked
against each crate's `Cargo.toml` for the native libraries behind the Rust API.

## 1. Fuzz coverage

| Surface | Parser | Fuzz target(s) | Status |
|---|---|---|---|
| HTTP/1 request line/headers | `boatramp_http::h1::parse_request_head` | `fuzz_parse`, `fuzz_differential` (vs hyper) | pre-existing |
| HTTP/1 chunked body | `boatramp_http::h1::chunked::scan` | `fuzz_chunked` | pre-existing |
| HTTP/2 frame header + fixed-frame payloads | `boatramp_http::h2::frame::{FrameHeader::parse, parse_settings, parse_window_update, parse_rst_stream, parse_ping, parse_priority, parse_goaway, strip_padding}` | `fuzz_frame` | pre-existing |
| HTTP/2 HPACK header-block decode | `boatramp_http::h2::hpack::Hpack::decode` | `fuzz_hpack` | pre-existing |
| HTTP/2 SETTINGS *apply* (not just decode) | `boatramp_http::h2::Settings::apply` | `fuzz_settings` (new) | **added** |
| HTTP/2 decoded headers → validated `Request` | `boatramp_http::h2::http::request_from_headers` | `fuzz_h2_headers` (new; composes HPACK decode + this) | **added**, required bumping `request_from_headers` `pub(crate)` → `pub` |
| overlay TUN netstack ingress (smoltcp) | `boatramp_overlay_tunnel` TUN front-end | `fuzz_netstack_ingress` | pre-existing |
| overlay SOCKS5 front-end codec | `boatramp_overlay_tunnel` SOCKS5 codec | `fuzz_socks_codec` | pre-existing |
| **overlay circuit frame codec** | `boatramp_overlay_proto::circuit::XgressFrame::decode` | `fuzz_circuit_frame` (new) | **added** — this is the "core boatramp-overlay frame parser"; it lives in the pure-core crate `boatramp-overlay-proto` (`#![forbid(unsafe_code)]`), which `boatramp-overlay`'s runtime circuit pump depends on and calls directly (`crates/boatramp-overlay/src/circuit.rs:195`) |
| HTTP `Range:` byte-range header | `boatramp_server::content::parse_ranges` | `fuzz_byte_range` (new) | **added**, required bumping `mod content` + `parse_ranges` from private/`pub(super)` to `pub` |
| STARTTLS trigger line (SMTP/IMAP/POP3) | `boatramp_server::tcp_starttls::match_trigger` | `fuzz_starttls_trigger` (new) | **added**, required bumping `match_trigger` to `pub` — see §1a |
| GraphQL query text | `async_graphql_parser::parse_query` (third-party; boatramp calls it directly) | `fuzz_graphql_query` (new) | **added** — see §1b |
| blob/image decode | — | — | **no target — see §1c: there is no host-side decoder** |

### 1a. SMTP/IMAP: there is no host-side command grammar

`crates/boatramp-server/src/tcp_starttls.rs` is explicit about this by design: "The guest owns
the whole plaintext dialog (greeting, capability advertisement, everything post-TLS) ... There
are **no** SMTP/IMAP/POP3 string literals in this module." The host's entire hand-rolled
SMTP/IMAP/POP3 surface is the one `match_trigger` line-matcher that decides when to start the
STARTTLS upgrade; every other byte of the dialog (EHLO, LOGIN, FETCH, ...) is parsed by the
guest's own wasm handler, which is a *separate* trust boundary (sandboxed guest code, not raw
host-side byte parsing) and out of scope for this host-parser audit. `fuzz_starttls_trigger`
covers that one function against both grammar shapes boatramp ships (untagged SMTP/POP3,
tagged IMAP).

### 1b. GraphQL: boatramp has no grammar of its own

`graphql_plan.rs`, `graphql_data/compile.rs` and `graphql_gateway.rs` all call
`async_graphql_parser::parse_query(query)` directly on the client-supplied query text — the
same parser `async-graphql` itself uses (chosen, per the crate's `Cargo.toml` comment, so
boatramp parses "exactly what a subgraph emits"). There is no boatramp wrapper worth fuzzing
independently of the library call, so `fuzz_graphql_query` fuzzes that third-party entry point
directly, exactly as boatramp calls it.

### 1c. Blob/image serving: there is no pixel/image decoder on the host

Searched for an `image`-crate dependency, a `DynamicImage`/`ImageFormat` use, or any
`fn decode_image`-shaped function: none exist anywhere in the workspace. `crates/boatramp-storage`
(`fs.rs`, `s3.rs`, `gcs.rs`, `azure.rs`, ...) stores and serves blobs as **opaque, content-addressed
byte ranges** — the host never decodes image/media content into pixels; it streams bytes and the
client (browser, guest) interprets them. The one hand-rolled untrusted-byte parser actually on
that serving path is the HTTP `Range:` header (`content::parse_ranges`, §1), which decides which
byte range of the opaque blob to stream — that is now fuzzed. The compressed-body transcoders on
the same path (`content.rs`'s on-the-fly gzip/brotli via `async-compression`) are pure-Rust
stream encoders over the *response* boatramp itself produced, not a decoder of attacker bytes, so
they are out of scope here (see §3's compression note).

## 2. Unsafe audit — on or directly reachable from the fuzzed parsers

Everything in this section is `unsafe` Rust in the same crate as a parser above, on the request
path that parser feeds.

### boatramp-http (h1/h2)

The whole `h1`/`h2` module tree has exactly two `unsafe` sites in the crate; both are sound,
narrow, and already covered by an existing invariant comment:

- `crates/boatramp-http/src/h1/client.rs:254` — `unsafe { self.buf.advance_mut(n) }` in the
  reverse-proxy **client**'s `poll_fill` (reads an upstream response into a `BytesMut`).
  Invariant: `n == rb.filled().len()` from the immediately-preceding `poll_read`, i.e. exactly
  `n` bytes of the buffer's spare capacity were just initialized — the standard sound pattern
  for `BytesMut::advance_mut` paired with `ReadBuf`. Reachable from an upstream's response
  bytes when boatramp proxies (`crates/boatramp-server/src/proxy.rs`); not removable without
  losing the zero-copy read (an initialize-then-copy would defeat the point), and not risky as
  written.
- `crates/boatramp-http/src/serve.rs:174` — `unsafe { libc::sendfile(sock_fd, file_fd, &mut off, want) }`,
  the Linux zero-copy response body send. `off`/`want` are computed from the **already-parsed**
  response (a static file's size, or a `parse_ranges` result on the Range-serving path — see
  below); the raw syscall itself only reads/advances a kernel-tracked file offset, no Rust
  memory is touched unsafely. Sound as written; flagged only because it is the one place a
  parsed byte-range value reaches a raw syscall argument.

No unsafe in `h2/frame.rs`, `h2/hpack/*`, `h2/settings.rs`, `h2/http.rs`, `h2/stream.rs`, or
`h1/parse.rs` — the parsers `fuzz_frame`/`fuzz_hpack`/`fuzz_settings`/`fuzz_h2_headers`/
`fuzz_parse`/`fuzz_chunked` exercise are all safe Rust end to end.

### boatramp-overlay-proto / boatramp-overlay (circuit framing)

`boatramp-overlay-proto` (`XgressFrame::decode`, the fuzzed parser) and `boatramp-overlay` (the
duplex pump that calls it, `crates/boatramp-overlay/src/circuit.rs`) both carry
**`#![forbid(unsafe_code)]`** at the crate root. Zero unsafe Rust anywhere on this parser's
path — the strongest result in this audit. (`boatramp-overlay-tunnel`, the sibling crate with
the pre-existing `fuzz_netstack_ingress`/`fuzz_socks_codec` targets, is the same:
`#![forbid(unsafe_code)]`.)

`boatramp-overlay-client` is the one overlay crate that is NOT `forbid(unsafe_code)` (it is
`#![deny(unsafe_code)]` with a single documented exception):

- `crates/boatramp-overlay-client/src/lib.rs:476` — `unsafe { std::net::TcpStream::from_raw_fd(raw) }`
  in `tcp_stream_from_connected_fd`, used on the direct-path "promote" handoff. Invariant
  (spelled out in the function's own doc, lines 455–467): `raw` comes from an `OwnedFd` that
  just transferred sole ownership via `into_raw_fd`, so there is no other live handle and no
  double-close; a non-socket/unconnected fd is not unsound, just an I/O error on first use.
  Sound as written.

### boatramp-server (Range header, STARTTLS trigger, GraphQL)

`content.rs` (`parse_ranges`) and `tcp_starttls.rs` (`match_trigger`, the whole STARTTLS pump)
contain **no `unsafe`** at all — both are pure safe Rust over `&str`/`&[u8]`.
`async_graphql_parser::parse_query` is a third-party dependency; its internals are out of this
audit's grep scope (see §4 for the native-dependency angle on the GraphQL/crypto/libsql stack
generally).

The one `unsafe` genuinely adjacent to the Range-serving path is the `sendfile` call in
`boatramp-http::serve` above, plus the kernel-`splice` reverse-proxy body relay in the same
crate family:

- `crates/boatramp-server/src/splice.rs:728,741,766,783` — `libc::pipe2`/`libc::splice`/
  `libc::close` moving `n` bytes socket→pipe→socket with no userspace copy, where `n` derives
  from a parsed `Content-Length` on the upstream response head (parsed by `find_head_end` a few
  lines above, in the same file). Invariant: the pipe fds are created fresh per call and closed
  on every exit path (including the error path, via the `result` binding before the final
  `unsafe { close(pr); close(pw); }`); `async_io` return values are checked and converted to
  `io::Error` before use. A hostile/truncated `Content-Length` cannot cause an OOB read/write
  here — worst case is the already-handled "upstream closed before content-length" error — but
  it is the one place a parsed header value feeds a raw syscall length argument on this crate's
  hot path, so it earns a flag even though it looks sound.

## 3. Notable unsafe *outside* the fuzzed-parser set, still worth flagging

These are not reachable from the six parser surfaces above, but they sit on or very near other
untrusted/cross-trust-boundary byte paths elsewhere in the workspace, and are severe enough to
call out explicitly rather than let the grep noise bury them:

- **`crates/boatramp-handlers/src/engine.rs:2079`** — `unsafe { Component::deserialize(&self.engine, artifact) }`.
  The function's own doc says it plainly: *"Passing unverified bytes here is arbitrary code
  execution."* `artifact` is a precompiled AOT wasm cache blob that can arrive from another
  cluster node; wasmtime's deserialize is only lightly validated (an embedded version check,
  explicitly **not** integrity protection against a same-version forgery). The one thing making
  this sound today is that the caller MUST have already verified the cluster-keyed AOT MAC
  (`boatramp-server::aot`) over exactly these bytes before calling in — i.e. soundness here is
  an **external, caller-enforced invariant**, not something the function itself checks. This is
  the single highest-severity unsafe-adjacent-to-untrusted-bytes finding in the audit; it is
  outside WS3's parser list (it's an inter-node artifact-cache path, not a client-facing
  parser) but should be on any follow-up privsep worklist's radar — e.g. a fuzz/property test
  that confirms a MAC-less or tampered artifact is *always* rejected before reaching this line.
- **`crates/boatramp-storage/src/sql_libsql_changeset.rs`** — ~20 `unsafe` sites, all raw
  `libsql-ffi`/SQLite-C-API calls (`sqlite3_open_v2`, `sqlite3session_*`, `sqlite3_step`,
  `sqlite3_column_text`, `sqlite3_free`, plus two `unsafe extern "C"` callback trampolines,
  `apply_filter`/`apply_conflict`, invoked BY SQLite with a raw `*mut c_void` context pointer).
  The module's own doc states the trust model directly: "A changeset member crosses the SAME
  trust boundary as the streamed `.dump` and the pg/mysql deltas: its bundle SHA is integrity,
  not authenticity, so a crafted member can carry arbitrary row operations" — and structurally
  confines that via a per-file isolation guarantee (no cross-database `ATTACH`) plus a
  base-table `xFilter` that skips any table outside the restored base's own schema. Each raw
  call's safety rests on SQLite's own C-API contract (valid pointers, `sqlite3_free` only on
  SQLite-owned allocations, `CStr::from_ptr` only on NUL-terminated SQLite output) rather than a
  single reusable Rust abstraction — correct as far as this audit can tell by inspection, but
  this is exactly the kind of surface cargo-fuzz (pure-Rust, in-process) cannot reach: see §4.
- **`crates/boatramp-storage/src/fs.rs:81`** — `unsafe { memmap2::Mmap::map(&file) }` in the
  blob-storage `mapped()` fast path. Invariant (stated in the existing `SAFETY` comment): sound
  only because the blob keyspace is content-addressed and immutable, so a mapped file is never
  truncated/rewritten while the mapping is live — that is an invariant *this* function trusts
  but does not itself enforce. Worth a one-time check (not done as part of this audit — it's a
  cross-file argument, not a parser) that every blob write/GC/rehome path really does write a
  new content-addressed key rather than mutate an existing one in place.

## 4. Excluded: unsafe reachable only from operator/node-driven paths, or test-only

Explicitly out of scope — not reachable from a client/peer's untrusted bytes:

- Container/VM lifecycle syscalls: `boatramp-container/src/{net,exec,worker,backend}.rs`
  (`fork`, bridge `ioctl`, `fcntl`), `boatramp-firecracker/src/*` (KVM ioctls, raw snapshot
  struct reinterpretation), `boatramp-vz/src/vm.rs` (the Virtualization.framework Objective-C
  bridge). All operator/node-driven (deploy/start/stop a workload), never parsing a byte stream
  a request sender controls.
- `crates/boatramp-server/src/{health_alert,operator}.rs`'s `libc::statvfs` — local disk-usage
  probes, no attacker input.
- Every `unsafe { std::env::set_var(...) }` / `remove_var(...)` across `boatramp-core`,
  `boatramp-storage`, `boatramp-server`, `boatramp-handlers`, `boatramp-node` — these are all
  `#[cfg(test)]`-gated mutation-injection seams for fault-injection tests (e.g.
  `BOATRAMP_KVSQL_MUTATION`), not production code reachable by any request.
- `crates/boatramp-node/src/repair.rs:1246` and similar — false positives from this audit's
  grep: a variable literally named `unsafe_attr`, not the `unsafe` keyword.

## 5. C/native dependency surface (part d): what cargo-fuzz's pure-Rust harnesses can't see

Fuzzing in-process, pure-Rust parsers (§1) does not exercise the C/assembly code those parsers'
neighbors hand bytes to. The native dependencies that sit on or immediately next to the
untrusted-byte paths above:

- **Crypto — `aws-lc-rs` (AWS-LC, a BoringSSL-derived C/assembly library).** Depended on
  directly by `boatramp-rpktls` (the RFC 7250 raw-public-key TLS boatramp's HTTP/overlay
  listeners terminate with) and by `boatramp-overlay-proto` (`e2ee.rs`'s AEAD record
  seal/open, X25519 key agreement, ML-KEM-768 encapsulation, HKDF — the whole relay-blind
  handshake that runs on attacker-reachable KEM-offer and AEAD-record bytes received right
  after a circuit frame is decoded by `XgressFrame::decode`, §1). Every TLS-terminated HTTP/2
  connection and every overlay session's crypto ultimately calls into this C surface; it is
  outside Rust-level fuzzing here, but AWS-LC ships and maintains its own extensive upstream
  fuzzing/FIPS validation, so the incremental value of boatramp re-fuzzing it directly is low —
  the exposure that matters is correct *use* (nonce/key handling), which the pure-Rust wrapper
  in `e2ee.rs` is responsible for and which Rust's type system covers reasonably well.
  `boatramp-acme` additionally depends on the `ring` crate (a separate, independent C/assembly
  crypto backend) — smaller blast radius (ACME-only, operator-driven, not a per-request path).
- **SQLite/libsql — `libsql-ffi`.** Two distinct exposures: (1) the live serving connection
  (`libsql` crate, used by the handler `sql` binding — every guest SQL query a tenant issues
  ultimately reaches SQLite's C parser/VDBE through this FFI, a large and well-fuzzed-upstream
  C codebase but the single largest "pure-C parser" surface boatramp ships); (2) the
  `sql-delta-libsql` feature's raw FFI session/changeset API (`sql_libsql_changeset.rs`, §3) —
  smaller, more custom, and the one with boatramp-authored `unsafe extern "C"` callbacks, so it
  is the higher-marginal-risk half of the two.
- **Compression — pure Rust, not a native-dependency exposure.** `async-compression`'s
  gzip/brotli backends here are explicitly pulled in "pure-Rust" per the `compression` feature's
  own `Cargo.toml` comment — no C zlib/libbrotli. This is the one item on the task's example
  list (crypto/libsql/compression/codecs) that does **not** apply to boatramp: there is no C
  compression library in the request/response path.
- **Codecs / guest execution — wasmtime + Cranelift.** The handler engine JIT-compiles and runs
  guest wasm components (`boatramp-handlers`). Cranelift itself is pure Rust; wasmtime's runtime
  has its own small unsafe surface (VM memory mapping, signal-based trap handling) that is
  upstream's responsibility and already extensively OSS-Fuzzed — out of this audit's scope,
  but see §3's `Component::deserialize` finding for the one boatramp-side invariant that gates
  it (the AOT-cache MAC check).
- **No C image/media codec.** Consistent with §1c: there is no `libjpeg`/`libpng`/`libwebp`/etc.
  anywhere in the dependency tree — blob/image bytes are never decoded by the host, only
  streamed opaquely.

## 6. Visibility changes made to support fuzzing (no behavior change)

Four items were bumped from private/`pub(crate)`/`pub(super)` to `pub` *solely* so an external
`cargo-fuzz` binary crate (which only sees a library's public API) can reach them — matching
the pattern `boatramp-http`'s pre-existing targets already rely on (`h1::parse_request_head`,
`h1::chunked::scan` are `pub` for the same reason). No logic changed in any of the four:

- `boatramp_http::h2::http::request_from_headers` (`pub(crate)` → `pub`)
- `boatramp_server`'s `content` module (private `mod` → `pub mod`) and
  `content::parse_ranges` (`pub(super)` → `pub`)
- `boatramp_server::tcp_starttls::match_trigger` (private `fn` → `pub fn`; the module itself was
  already `pub`)

`content.rs` also gained two `#[cfg(test)]` unit tests for `parse_ranges` (it previously had
none at the unit level) — these double as `fuzz_byte_range`'s documented seed/regression cases,
matching the split `boatramp-http/fuzz` already uses between its nightly `cargo-fuzz` targets
and its crates' own `tests/*_smoke.rs`/inline unit tests as the "stable regression net."
