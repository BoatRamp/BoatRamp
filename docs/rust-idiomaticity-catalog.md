# Rust idiomaticity catalog

A whole-workspace conceptual idiomaticity review. The question behind every entry
is not "does clippy complain" (default clippy is already clean) but **would a human
Rust developer feel at home reading this?** — is behaviour on the type a reader
expects, are domain concepts real types, do conversions use the standard traits,
are the module seams where a reader would reach for them, and is the same concept
modelled the same way everywhere.

Produced by six parallel expert reviewers, one per crate-slice plus one cross-crate
consistency sweep, then triaged and deduped here. Every recommendation is
**behaviour-preserving**: identical HTTP routes, CLI surface, wire/serde formats, KV
keys, and Raft log format. Anything that would touch a serialized boundary is
flagged loudly and gets a byte-identity test.

Campaigns are grouped into **six approvable groups (A–F)**, ordered by value/risk.
Each campaign lists dimension(s), the "feel at home" rationale, representative
locations (not exhaustive), behaviour-preservation risk, and effort/risk/breadth.
The user triages per group (or per campaign) before any code changes.

---

## The rubric (12 dimensions)

1. **Behaviour placement** — a free fn taking `&T`/`T` that should be a method or
   associated constructor on `T`.
2. **Domain newtypes / primitive obsession** — `String`/`&str`/`u64` at boundaries
   carrying an invariant (Host, SiteName, Token, ids); transposable same-typed args.
3. **Type-state** — an illegal state is representable and a phantom-typed state
   would make it a compile error (only where it genuinely clarifies).
4. **Conversion traits** — inherent `as_str`/`to_x`/`from_x` that should be
   `Display`/`AsRef`/`From`/`TryFrom`/`FromStr`.
5. **Trait seams** — a concrete type wanting a small trait; or an over-abstracted
   trait with one impl.
6. **Error modelling** — stringly `Backend(String)`/catch-all variants that erase
   structure; missing `#[from]`; hand-rolled `Display`+`Error` where thiserror fits.
7. **Naming** — Rust API-guideline conformance (`as_/to_/into_` prefixes, `iter`
   naming, getters, `is_/has_` predicates).
8. **Iterator-first** — index loops / manual accumulation that read better as chains.
9. **Encapsulation** — `pub` fields that should be constructor-guarded; leaking
   internal/SDK types across crate boundaries.
10. **Module organisation** — monolith files a reader cannot navigate; behaviour
    that belongs next to its type.
11. **Ownership ergonomics** — `&String`/`&Vec` params, needless clones, `Cow`.
12. **Cross-crate consistency** — the same concept modelled two ways in two crates.

Reference convention observed workspace-wide: **`boatramp-types` is the source of
truth** for domain types and their string/serde rendering (`as_str` + `Display` +
`FromStr`, `to_json`/`from_json` → `ConfigError`); **`boatramp-core` owns the
canonical KV/deploy logic**. Where a concept is modelled two ways, converge on the
version nearest those two crates. `VerificationMethod`
(`boatramp-types/src/domain_verify.rs:52`, has `as_str` + `Display` + `FromStr`) and
`StorageError` (`boatramp-core/src/error.rs`, thiserror + `#[from]` + a `backend()`
constructor) are the positive templates the outliers should match.

---

## Group A — Zero-risk dedup & naming (pure wins)

Small, behaviour-preserving, no serialized boundary. Immediate "at home" payoff.

### A1. Collapse the `now_unix` / `now_ms` clock-helper sprawl
- **Dimensions:** 12, 1. **Effort:** M · **Risk:** low · **Breadth:** 6 crates, ~15 copies.
- ~12 byte-identical `SystemTime::now() → UNIX_EPOCH → as_secs` bodies under four
  names (`now_unix`, `unix_now`, `now_secs`) plus three `now_ms` copies.
- Locations: `boatramp-server/src/{lib.rs:677, auth.rs:501, domain_verify.rs:30}`,
  `boatramp/src/{client.rs:244, token.rs:337, operator/executor.rs:49}`,
  `boatramp-core/src/deploy.rs:71`, `boatramp-acme/src/{oci.rs:224, akamai.rs:220}`,
  `boatramp/src/acme_dns.rs:204`, `boatramp-handlers/src/bindings/blobstore.rs:138`;
  ms copies at `boatramp-core/src/messaging.rs:440`,
  `boatramp-cluster/src/messaging.rs:182`, `boatramp-server/src/logs.rs:174`.
- **Fix:** `boatramp_types::time::{now_unix, now_unix_ms}`; replace all copies.
- **Preservation:** none (identical bodies). Keep the secs/ms split per call site.
  Leave `boatramp-console/src/format.rs:4` alone — it is `js_sys::Date` under wasm
  (justified divergence).

### A2. Rename the `host_matches` name collision (two different match policies)
- **Dimensions:** 12, 7. **Effort:** S · **Risk:** low · **Breadth:** server + CLI.
- `boatramp-server/src/console.rs:87` `host_matches` — `*.suffix` matches the apex
  **and** any-depth `label.suffix`. `boatramp/src/acme_dns.rs:175` `host_matches` —
  `*.suffix` matches **exactly one** label and not the apex. Two legitimately
  different policies (mount routing vs TLS-SNI cert matching) sharing one name, so a
  reader assumes they are interchangeable.
- **Fix:** rename the SNI one to `sni_matches` / `cert_host_matches` + doc. Do **not**
  merge the bodies. Cheapest high-value fix in the review.

### A3. Deduplicate reinvented helpers: `conn()`, `to_hex`/`from_hex`
- **Dimensions:** 12, 1, 8. **Effort:** S–M · **Risk:** low · **Breadth:** CLI, cluster, rpktls, core.
- `boatramp/src/function.rs:1046` and `boatramp/src/workflow.rs:224` are a
  character-identical private `conn()`; the same `resolve_server + http_client(token)`
  triple is inlined ~25–39× across the CLI. `to_hex`/`from_hex` are byte-identical in
  `boatramp-cluster/src/mesh.rs:101/111` and `boatramp-rpktls/src/lib.rs:752/762`,
  while 29 other sites call `hex::encode`/`hex::decode` directly.
- **Fix:** one `client::connect(server, config)` in `boatramp/src/client.rs` (folds
  into C-group's connection type if that is approved); the two hex copies call the
  `hex` crate (already a dependency). Preservation: pure dedup.

### A4. Naming drift: `all_sites` → `list_sites`; stale `add_auto`
- **Dimensions:** 7. **Effort:** S · **Risk:** low.
- `boatramp-core/src/deploy.rs:514` `all_sites` is the lone `all_` among a wall of
  `list_stored_functions`/`list_triggers`/`list_invocations`/… Rename to `list_sites`.
  `boatramp/src/domains.rs:233` `async fn add_auto` is named for the removed `--auto`
  flag (now `--provider`); rename `add_via_provider`. Internal only.

### A5. `HostCommand::display()` → `Display`; `Tap::as_raw_fd()` → `AsRawFd`
- **Dimensions:** 4, 7, 9. **Effort:** S · **Risk:** low · **Breadth:** ~12 call sites.
- `boatramp-firecracker/src/net.rs:29` `HostCommand::display(&self) -> String` is a
  logs/tests renderer — exactly `Display`'s job. `boatramp-firecracker/src/tap.rs:99`
  `Tap::as_raw_fd(&self) -> RawFd` shadows the canonical `std::os::unix::io::AsRawFd`
  trait; implementing it lets `Tap` flow into `PollFd::new`/`BorrowedFd` generically.
- **Preservation:** identical strings / fd. (`FcMachine::to_config_json` is correctly
  NOT a Display candidate — it is a JSON artifact; leave it.)

---

## Group B — Conversion-trait sweep

Give the enum vocabulary the standard traits a reader reaches for
(`format!("{x}")`, `s.parse()`), matching the `VerificationMethod` template. Keep
the inherent `as_str(self) -> &'static str` (the accepted idiom for a `'static`
return — avoids the `.to_string()` alloc); **add** `Display`/`FromStr`, don't remove.

### B1. Enum `as_str` → add `Display` (+ `FromStr` where a paired parser exists)
- **Dimensions:** 4, 7. **Effort:** M · **Risk:** low · **Breadth:** small per enum.
- `boatramp-types/src/authz.rs:64/78` `Resource::as_str`/`Action::as_str` (2 consumers);
  `boatramp-types/src/security.rs:78` `SecurityProfile::as_str` + `:68` `from_name`
  (a `Display`/`FromStr` pair in disguise — `from_name` → `FromStr` via
  `SecurityError::UnknownProfile`); `boatramp-core/src/cose.rs:211` `TokenAlg::label`
  (misnamed → `as_str` + `Display`); `boatramp-acme/src/dns.rs:24` `RecordKind::as_str`;
  `boatramp-cloudflare/src/lib.rs:46` `InstanceType::as_str`;
  `boatramp-types/src/gateway.rs:142` `LbPolicy` (has `is_default`, no `as_str`).
- **Preservation:** `Display` must emit byte-identical tokens (they appear in serde,
  DNS request bodies, URLs). serde stays derive-based; `Display` is additive.

### B2. Kill the `format!("{:?}", runtime).to_ascii_lowercase()` anti-pattern
- **Dimensions:** 4, 6. **Effort:** S · **Risk:** med (wire). **Breadth:** 2 sites.
- `boatramp-server/src/lib.rs:1588` and `:1603` render a function-runtime enum via
  `Debug`-lowercase into an **API JSON response**. Give the runtime enum an `as_str`
  in `boatramp-types` and use it. **Preservation:** `as_str` must reproduce exactly
  what `Debug`-lowercase produces today (pin with a test before switching).

### B3. Free-fn formatters → `Display`; small placement fixes
- **Dimensions:** 4, 1. **Effort:** S · **Risk:** low.
- `boatramp-server/src/lib.rs:1546` `owner_str(&Owner) -> String` → `Display for Owner`;
  `:1617` `render_trigger(&Trigger) -> String` → `Display for Trigger` — both feed the
  `FunctionSummary` JSON, so byte-identical output required. `boatramp-core/src/compute.rs:139`
  `Endpoint::url` hand-formats the scheme; give `Scheme` a string form and reuse it.
  `GrantedRole::parse` (`authz.rs:378`) reads as `FromStr` (`"…".parse::<GrantedRole>()`)
  — but see the note: the lenient parse is used in `create_token`, so only add
  `FromStr` if it does not change that leniency.

---

## Group C — Error-modelling convergence

Two error styles coexist: thiserror + `#[from]` (the reference) and hand-rolled
`impl Display`/`impl Error` with stringly catch-all variants. Converge on thiserror,
**keeping every `#[error("…")]` string identical** (some surface into HTTP bodies
and WIT guest errors).

### C1. Compute `BackendError`: structure it; stop flattening to `format!`
- **Dimensions:** 6, 4, 12. **Effort:** M · **Risk:** low · **Breadth:** ~70 sites, 4 crates.
- `boatramp-core/src/compute.rs:180` `BackendError { Materialize/Launch/Stop/Other(String) }`
  has no `#[from]`, so every backend ends in `.map_err(|e| BackendError::Launch(e.to_string()))`
  (firecracker/container/docker), and `boatramp-container/src/backend.rs:508` invents an
  `ArchiveError` *only* because the boundary can't carry a typed cause.
- **Fix:** add `Io(#[from] std::io::Error)` / a source-carrying variant + `#[from]`s;
  keep `Display` identical (it feeds `ReconcileReport.errors`, not serialized).

### C2. DNS `DnsError`: add `NotFound`; delete the 52 stringly closures
- **Dimensions:** 6, 1, 7. **Effort:** M · **Risk:** low · **Breadth:** ~52 sites, 11 files.
- `map_err(|e| DnsError::Backend(e.to_string()))` appears 52× across the ACME crate,
  and `boatramp-acme/src/route53.rs:103` decides "record already gone" by
  substring-matching a message it *itself* stringified (`msg.contains("not found")`).
  `boatramp-acme/src/dns.rs:49` `DnsError` is hand-rolled with only `Config`/`Backend`.
- **Fix:** thiserror + `NotFound` + `From<reqwest::Error>` (and SDK `From`s); replace
  the route53 substring match with the typed variant. Preservation: keep route53's
  "absent → Ok" semantics exactly; runtime-only type, not serialized.

### C3. Cloud storage SDK error mapping: consistent + structural NotFound
- **Dimensions:** 6, 12, 1. **Effort:** M · **Risk:** low · **Breadth:** ~18 sites, 3 files.
- S3/GCS/Azure each map SDK errors differently: GCS routes some calls through
  `gcs_err(err,key)` (404→NotFound) but 8 sites fall back to bare
  `StorageError::backend(err.to_string())`; Azure has 6 such fallbacks; S3 copy-pastes
  the NotFound check inline 3× with no `s3_err` helper. Same op loses the NotFound
  distinction depending on the line.
- Locations: `boatramp-storage/src/gcs.rs:{197,220,237}`, `azure.rs:{200,224,236,282}`,
  `s3.rs:{198,239,328}`. **Fix:** a per-backend `*_err(err,key)` helper used uniformly;
  preserve exactly which HTTP statuses currently reach the caller as NotFound.

### C4. Hand-rolled `Display`+`Error` → thiserror; add `serde_json` `#[from]`
- **Dimensions:** 6, 12. **Effort:** M · **Risk:** med (guest-visible text). **Breadth:** ~4 enums + ~30 sites.
- Hand-rolled: `boatramp-core/src/messaging.rs:66` `MessagingError`, `sql.rs:59` `SqlError`,
  `blob_provision.rs:19` `ProvisionError`, `boatramp-handlers/src/engine.rs:130`
  `HandlerError` (with a manual `From<wasmtime::Error>` thiserror would generate).
  serde_json is `#[from]` in `boatramp/src/config_cmd.rs:27` but hand-`map_err`'d
  elsewhere; `boatramp-types/src/blob_notify.rs:107/112` `to_json`/`from_json` return
  raw `serde_json::Error` while every sibling returns `ConfigError`.
- **Fix:** thiserror with identical `#[error]` strings (Sql/Handler text is guest-visible
  via WIT — byte-identical required); add `Json(#[from])` where the target is the crate's
  own enum; converge blob_notify on `ConfigError`.

### C5. Small stringly `Result<(), String>` on a domain type
- **Dimensions:** 6. **Effort:** S · **Risk:** low · **Breadth:** ~2–3 sites.
- `boatramp-types/src/function.rs:296` `rollback` and `:306` `set_alias` return
  `Result<(), String>` for a single "unknown version id" failure → a one-variant enum
  (`UnknownVersion { function, id }`) lets the server map a 404 without string-sniffing.

---

## Group D — Module organisation (pure moves + `pub use`)

Behaviour-preserving code movement only; no logic edits in a move commit; `pub use`
re-exports keep public paths unchanged. Feature-gate (`#[cfg]`) placement is the
only fiddly part.

### D1. Split the 9,834-LOC `boatramp-server/src/lib.rs`
- **Dimensions:** 10. **Effort:** L · **Risk:** low–med · **Breadth:** whole file.
- A reader hunting "where are tokens minted" or "the host router" scrolls a 9.8K-LOC
  file that interleaves routing, auth/mint, WASM dispatch, gateway proxy, and the serve
  pipeline — clusters already fenced with `// ---- …` banners. Proposed modules (rough
  ranges): `runtime.rs` (78–560), `router.rs` (687–1223), `handlers/deploy.rs`
  (1357–1525), `handlers/functions.rs` (1526–3151), `handlers/tokens.rs` (mint,
  3263–3810), `handlers/admin.rs` (3810–4235), `host.rs` (4238–4620, incl. the host
  fns), `serve.rs` (4622–5442), `content.rs` (5442–5942), `proxy.rs` (5942–6890),
  `wasm.rs` (6890–7350, `#[cfg(handlers)]`), `scheduler.rs` (7311–7870), `stream.rs`
  (7872–8207), `operator.rs` (8207–8582). Shared privates become `pub(crate)`; test
  modules move next to their code. Do this **after** the Host campaign (E1) or the
  `host.rs` boundary shifts twice.

### D2. Split the CLI `serve.rs` (3,121) and `function.rs` (1,257)
- **Dimensions:** 10. **Effort:** M–L · **Risk:** low.
- `boatramp/src/serve.rs` already carries `// ---- section ----` banners: extract
  `serve/backends.rs` (`build_blobs`/`build_azure`/`build_gcs`/`build_s3`/`build_kv`,
  2813–3021), `serve/tls.rs` (`serve_custom`/`serve_rpk`/`serve_acme`, 2533–2810),
  `serve/cluster.rs` (`MeshWriteAuthz`/`build_mesh_write_gate`/`run_cluster`, 1189–1452),
  `serve/acme_dns.rs` (1899–2255). `boatramp/src/function.rs` fuses three concerns →
  `function/scaffold.rs` (664–746, `include_dir!` templates), `function/build.rs`
  (755–879, subprocess), `function/mod.rs` (API). `#[cfg]` stub pairs must move together.

### D3. Extract `deploy::keys`; split `raft.rs`/`node.rs`
- **Dimensions:** 10, 12. **Effort:** M · **Risk:** low.
- `boatramp-core/src/deploy.rs` (3,434) smears ~15 KV key-builders through one
  3000-line impl (`:135–160`, `:328–364`, `:1465`, `:1737`); the codebase already has
  the idiomatic answer next door — `boatramp-types/src/function.rs:574 pub mod keys`.
  Extract a `deploy::keys` module (format strings byte-identical — they define the
  persisted keyspace). `boatramp-cluster/src/raft.rs` (1,697) and `node.rs` (1,590)
  carry their own section headers (`:418/:525/:734/:845`) that are de-facto module
  seams → `raft/{store,network,facade,membership}.rs`, keeping the serialized
  `WriteOp`/`TypeConfig`/`NodeId` and `raft/log/*` key constants together.

---

## Group E — Deep domain modelling (the "redesign" tier)

The heart of the user's "deep idiomatic redesign". Higher risk (touches serialized
boundaries) and must be **workspace-wide, not slice-local** — a newtype introduced
in one crate only would create the exact cross-crate inconsistency dimension 12
warns against. Each newtype ships with `Deref`/`AsRef`/`From`/`Display` +
`#[serde(transparent)]` so existing `&str` call sites migrate incrementally.

### E1. `Host` type: converge the scattered normalization (FLAGSHIP)
- **Dimensions:** 12, 1, 2, 4. **Effort:** L · **Risk:** high · **Breadth:** ~50 sites, 3 crates.
- The single most dangerous cluster. "Canonicalize a routing host" exists in 8+ places
  with **subtly different, genuinely incompatible wildcard/case semantics** that all
  feed KV keys: `boatramp-core/src/deploy.rs:84 canon_host` (lowercases `*.` in place),
  `boatramp-server/src/lib.rs:3173 canon_domain_entry` (**preserves** `*.`),
  `boatramp-types/src/domain_verify.rs:210 normalize_host` (**strips** `*.`), plus
  inline variants at `config.rs:113`, `deploy.rs:1256`/`2052`, `server/domain_verify.rs:420`,
  and the host-fn cluster `strip_port`/`is_local_host`/`parse_deploy_host`
  (`lib.rs:4474/4491/4557`). A `*.x` written via one path and looked up via another can
  mismatch — a real hijack-guard hazard, not just style.
- **Fix:** a `Host` type (or `boatramp_types::host` module) exposing the **three
  distinct normalizations as three named constructors/methods** (routing-key,
  domain-entry wildcard-preserving, verify wildcard-stripping) — **not** merged into
  one — plus `strip_port`/`is_local`/`dns_record_name` as methods. Every call site maps
  to the semantically-identical named operation.
- **Preservation:** HIGH care. Must reproduce each variant byte-for-byte (KV keys
  `domain/<host>`, `domainverify/<site>/<host>`, TXT record names) and `DomainVerification.host`
  serde. `#[serde(transparent)]` + KV-key round-trip tests + the existing deploy.rs /
  `local_host_tests` as the oracle. Collapsing the three into one is the trap — do not.

### E2. `SiteName` newtype: close the transposable `(site, host)` hazard
- **Dimensions:** 2, 9, 12. **Effort:** M · **Risk:** low (transparent serde). **Breadth:** ~30 sites.
- Core APIs take `(site: &str, host: &str)` pairs that are silently swappable:
  `boatramp-core/src/deploy.rs:474 attach_verified_domain`, `:1170 is_domain_verified`,
  `:1103 remove_managed_dns`, `:348 domain_verification_key`; ~15 handlers take
  `Path<String>` site. A `SiteName` (paired with E1's `Host`) makes the transposition a
  compile error. `#[serde(transparent)]`, KV-key formatting preserved.

### E3. CLI connection type: free fns `(client, server, site, …)` → methods
- **Dimensions:** 1, 2, 9. **Effort:** L · **Risk:** low (pure internal). **Breadth:** ~20 fns, ~60 sites.
- `boatramp/src/client.rs:273–591` is ~20 free `pub async fn f(client, server, site, …)`
  with the client/base/site re-threaded by hand; the five `*_domain_verification` fns
  take adjacent swappable `(site, host)`. Two modules already invented a private
  `conn()` (A3) — the "connection" concept wants to be a type. `ControlPlane { http,
  base }` + `SiteEndpoint` with the current free fns as inherent methods; `base`/`site`
  private, constructed once. URLs/bodies/headers byte-identical (no wire change).

### E4. Move wire DTOs into `boatramp-types`; delete the CLI/console copies
- **Dimensions:** 12, 2. **Effort:** M–L · **Risk:** med (wire). **Breadth:** ~6 DTOs, types+server+CLI+console.
- CLI (`client.rs`, `token.rs`) and console (`models.rs`) re-declare structs the server
  owns: `TokenMeta`/`GrantedRole` (canonical at `boatramp-types/src/authz.rs:581/350`,
  CLI copy at `token.rs:183`), `LogEntry`/`LogsResponse` (`server/logs.rs:30`, copies at
  `client.rs:504` + `console/models.rs:83`), `CheckResult` (`server/domain_verify.rs:231`
  vs `console/models.rs:23`), `FunctionSummary` (`server/lib.rs:1532` vs
  `function.rs:288`). Root cause: several wire DTOs live in the server crate, so the two
  clients *can't* share them and re-declare lossy subsets.
- **Fix:** move the wire DTOs to `boatramp-types`; server/CLI/console all use them.
  Preservation: keep field names + serde attrs byte-identical; the current subsets omit
  fields, so the shared type keeps those present-but-`#[serde(default)]` on the reader
  side. The console already does this right (deserializes into `boatramp-types`) — that
  is the direction. (The two `ApiClient`s stay separate: native reqwest vs wasm gloo-net
  is a justified divergence; only the DTOs converge.)

---

## Group F — Borderline / lower-value (default: defer)

Real but marginal, or with a risk/breadth ratio that argues for leaving them unless
an adjacent campaign is already touching the code. Listed for completeness.

- **F1. Notify-provider shared queue-name helper** — dedupe `fnv1a` + truncation +
  `is_not_found` across `s3_notify.rs`/`azure_notify.rs`/`gcs_notify.rs`
  (`boatramp-storage`). *Risk:* med — the names are ledger-persisted (`ManagedNotification`);
  needs output-pinning tests first. GCS currently lacks a truncation guard (a latent
  inconsistency the helper would surface).
- **F2. `KvStore` `put(Vec<u8>)` → `Bytes`/`&[u8]`** — value is moved then cloned to
  bridge owned-vs-borrowed (`boatramp-core/src/kv.rs:40/231/253`), SlateDB only needs
  `&value`. Broad trait-signature ripple for small (metadata-sized) payloads; do only
  if bundled with another KV-trait change.
- **F3. Compute IP/MAC round-trips + `encode_ref`/`decode_ref` codecs** — `mac_for ->
  String` re-parsed by `parse_mac` (`ipam.rs:95`) is a safe `[u8;6]` win; the IP-as-String
  and the `<pid>@<ip>:<port>` codecs are **serialized** (`WorkerConfig`, `backend_ref`,
  `Snapshot.data_ref`) so they stay strings — a `Display`/`FromStr` refactor is
  cosmetic-only and borderline. Control-protocol literals `"ready"`/`"go"` → named
  consts (alongside the already-good `SNAPSHOT_CMD`).
- **F4. `Region` alias, base64 alias, key-builder style** — use `geo::Region`
  (`geo.rs:14`) in the compute/config region fields (zero runtime change) or drop the
  alias; a `B64URL` `use`-alias to cut base64 noise (do **not** collapse STANDARD vs
  URL_SAFE — load-bearing per site); unify key-builders on one style (free fn vs `mod
  keys` vs impl method) only opportunistically.
- **F5. CLI value-parsers → `FromStr`/`ValueEnum`** — `parse_region_tag`
  (`gateway.rs:32`), `parse_dns_provider` (`serve.rs:2089`), `parse_rotation_interval`
  (`serve.rs:1155`). *Risk:* med — moving `--acme-dns-provider` to `ValueEnum` changes
  `--help` text and rejects values the free parser tolerates (**CLI-surface change**);
  the internal ones (`RegionTag`, rotation-interval) are safe.
- **F6. Storage `connect` signature uniformity** — S3's `connect` is infallible while
  GCS/Azure return `Result` (`s3.rs:74` vs `gcs.rs:104`/`azure.rs:61`). Making S3
  fallible is additive (happy path byte-compatible) but touches serve wiring.
- **F7. `raft::WriteOp` rename** — clashes with `core::kv::WriteOp` (aliased as
  `KvWriteOp` at `persist.rs:26`, the tell); `ReplicatedOp`/`Command` reads truer. But
  it rides the **Raft log serde format**; safe only if every `#[serde]` variant/field
  name is untouched, and the risk/breadth ratio is poor. Leave unless a serde-name-pin
  harness exists.

---

## Explicitly out of scope (not behaviour-preserving)

- **Firecracker `net.rs` shell-out → `rtnetlink`** — `boatramp-firecracker/src/net.rs`
  builds `ip`/`nft`/`sysctl` command sequences while the sibling
  `boatramp-container/src/net.rs` does the same over `rtnetlink`, against the workspace
  "prefer syscall crates" policy. But converting NAT/forwarding setup changes syscalls
  and error surfaces and rewrites string-equality tests — **not** a behaviour-preserving
  idiomaticity pass. Track as a separate, deliberately-scoped task (or accept the split
  and document that the external-Firecracker path mirrors upstream jailer tooling).

## Justified as-is (looks non-idiomatic, has a reason)

- **VMM/container lifecycle type-state** — evaluated honestly; the orderable steps
  already live as pure data plans (`LaunchPlan` + `Executor::provision`, `SandboxPlan`)
  validated by construction, and a phantom-typed `Vmm<Booted>` would fight the
  `kvm-ioctls`/`ComputeBackend` `&self` API for no illegal-transition class it actually
  closes. The `RunningVm` registry is the right model.
- **RAII/Drop vs explicit teardown in compute** — cleanup is deliberately explicit
  (success keeps the tap/IP, failure frees, `stop` frees later via a reconstructed
  handle); a `Drop` guard can't express that asymmetry or await. `Tap`/`EmbeddedVmm`
  *do* use Drop where fd/mmap ownership fits.
- **FFI-shaped code** (`tap.rs` `ioctl_write_ptr_bad!`/`IfReq`, `pre_exec`/`dup2` fd
  inheritance, virtqueue/e820/MMIO index loops, `worker.rs` `unshare`/`pivot_root`
  ordering) — legitimately low-level; crate-level `allow`, not a rewrite.
- **Genuinely multi-impl traits** (`Storage`/`KvStore`/`SqlBackend`/`DnsProvider`/
  `WatchProvider`/`ComputeBackend`/`Signer`/`VirtioDeviceOps`, and the `LedgerSink`/
  `DomainProbe` test seams) — real backends or real test seams; keep.
- **`NodeId`/`PeerId` = `u64` aliases** — bound by openraft's own `u64` node-id
  contract; a newtype fights the `TypeConfig` associated type for no invariant.
- **`port: u16` everywhere** — uniform already; a newtype would be ceremony.
- **`Auth = Option<Arc<AuthInner>>` with a guarded `expect`** — the `Option` is the
  honest model for a single axum `Extension<Auth>`; type-state would fracture every
  extractor. The `expect` is guarded and documented.
- **axum handlers with `#[allow(clippy::too_many_arguments)]`** — extractor lists, not
  real parameter lists; the allow is honest. Do not bundle into a struct.
- **`manifest::to_bytes`/`from_bytes`** (vs sibling `to_json`) — "bytes" names the
  content-hashed representation deliberately (`sha256_hex(&self.to_bytes())`).
- **`cluster` `e_*` named error closures** — wrap a *foreign* openraft `StorageError`
  that can't take `#[from]`; the closure idiom is the right local answer.
- **`console` `ApiClient` (wasm/gloo-net) vs CLI `ApiClient` (native/reqwest)** — different
  runtimes; a shared impl is impossible. Only the DTOs converge (E4).

---

## Phase 0 — mechanical lint floor (foundation, optional to bundle)

Independent of the conceptual campaigns: a curated `[workspace.lints]` + `clippy.toml`
that locks in the easy wins so new code can't drift and the conceptual work isn't
re-litigating whitespace. From a 667 pedantic/nursery-warning sample on two crates,
~440 are noise to `allow` (`module_name_repetitions`, `must_use_candidate`,
`missing_errors_doc`, …) and ~200 are valuable — chiefly `use_self` (135), needless
casts, and combinator/`map_or` simplifications. Enable the valuable set as `warn`,
apply staged `cargo clippy --fix` sweeps (one lint family per reviewable commit),
promote to `deny` once clean; crate-level `allow`s for the FFI-shaped
firecracker/container/rpktls code. Gates that stay green after every change:
`cargo clippy --workspace --all-targets --all-features -D warnings`, the lean lane
(`--no-default-features --features fs,slatedb`), `nix build .#checks.x86_64-linux.clippy`,
`cargo test` (default + handlers + cluster).

---

## Suggested sequencing (once approved)

1. **Group A** + **Phase 0** — pure wins / floor; land first, each a small commit.
2. **Group B** + **Group C** — conversion + error sweeps; contained, mostly low risk.
3. **Group E1 (Host)** — the hazard fix; deliberate, deploy.rs/local_host tests as oracle.
4. **Group D** — module splits; D1 after E1 so the `host.rs` boundary settles once.
5. **Group E2–E4** + **Group F (if any)** — remaining newtypes and the DTO move; last,
   with byte-diff checks on every serialized boundary.

Each campaign is its own reviewable commit and must keep all four gates green; a
campaign that can't stay green is split smaller or bounced back to triage.
