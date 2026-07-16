<div align="center">

# boatramp

**Launch the web from your own shore.** A self-hosted, streaming-first platform
for publishing static sites *and the functions that run beside them* — from a
laptop to an edge-compute cluster — shipped as one Rust binary.

[![CI](https://github.com/BoatRamp/BoatRamp/actions/workflows/ci.yml/badge.svg)](https://github.com/BoatRamp/BoatRamp/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/badge/docs-boatramp.dev-2088c1.svg)](https://docs.boatramp.dev/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust 1.82+](https://img.shields.io/badge/rust-1.82%2B-orange.svg)](https://www.rust-lang.org)
[![Single binary](https://img.shields.io/badge/deploy-single%20binary-success.svg)](#install)

</div>

boatramp is what you reach for when you like how Vercel or Netlify *feel* but you
want to **own the whole stack** — the server, the storage, the certificates, and
the compute — on your own hardware, your cloud, or the edge. One `boatramp`
binary is the web server, the HTTP publishing API, and the CLI, for static sites
and the functions that run beside them. Start it on a laptop, drop it behind
systemd on a VPS, or scale it into a Raft-replicated cluster with the *same
commands and the same config*.

> **Streaming, not buffering.** Every byte path streams: uploads flow from the
> client straight into the backend, downloads flow from the backend straight to
> the client, and files are hashed in fixed-size chunks. No file is ever held
> whole in memory — not on the client, the server, or in any backend. A 4 GiB
> video deploys with a flat memory profile.

> **Atomic, content-addressed deploys.** `boatramp sync` publishes a folder as an
> immutable deployment and flips the site to it in one atomic operation. Readers
> always see the previous deploy or the new one *in full* — never a half-written
> mix. Identical bytes are stored once (dedup), unchanged files are never
> re-uploaded, and rollback is just re-activating an older deployment — instant,
> zero upload.

---

## Highlights

**Publish**
- Atomic, content-addressed deployments with cross-deploy dedup and delta uploads
- Instant, upload-free rollback to any prior deployment
- Framework-agnostic build step, or an in-process JS/TS + CSS bundler (Rolldown + lightningcss)
- Named aliases for staging/preview, plus per-deploy immutable preview hosts
- **Agent-ready**: ships an `AGENTS.md` so an AI coding agent (Claude Code, Codex, …) can build on boatramp and deploy out of the box

**Serve**
- Fast static serving with range requests, conditional GETs / strong ETags, and Brotli/gzip
- Virtualhost routing: attach any number of hostnames (exact or wildcard) to a site
- Redirects, rewrites, header rules, and clean URLs — with **conditional (`when`) routing** over a bounded CEL subset (edge logic without a handler)
- Drop-in **Netlify / Cloudflare Pages** `_redirects` + `_headers` compatibility
- Visitor access control at the edge: basic auth, IP allow/deny, and rate limiting
- Automatic HTTPS via ACME (HTTP-01), wildcard certs via DNS-01 (10 managed DNS providers), or your own cert
- HTTP/1.1, HTTP/2, and **HTTP/3 (QUIC)**

**Functions — everything that runs is a function**
- One portable **WASI 0.2 component**, many doors: run it behind a route, **invoke it by name** (sync or async, durable + idempotency-keyed), put it on a **cron**, or drive it from a **queue**
- Author in **Rust, JavaScript (jco), or Python (componentize-py)** — scaffold, build, and test locally (`function init · build · test · dev`)
- Per-function bindings: a **SQL** database, KV, a blob store, and a durable message queue (`wasi:messaging`), plus captured logs
- Durable **workflows** — chain functions into a DAG with fan-out, barrier fan-in, per-step retries, and saga compensation; runs survive restarts
- Event triggers (signature-verified webhooks, blob-change events), per-invocation metering, and fail-closed rate/concurrency quotas

**Compute**
- Pick a per-function **runtime**: the Wasm sandbox, an **OCI container** (native self-jail or remote Docker), a **Firecracker-class microVM** (embedded rust-vmm, SMP, snapshot/restore, scale-to-zero), or **Cloudflare Containers**
- The backend is a config choice — the workload and the commands don't change

**Scale**
- Self-hosted **HA clustering**: embedded Raft over a mutually-authenticated (raw-public-key TLS) peer mesh, a real database per site
- A built-in **reverse-proxy gateway**: publish private services through the edge with **geo-aware (nearest-region)** load balancing, passive + active health checks, retries, and DNS-based discovery

**Secure**
- Control-plane API on **COSE/CWT tokens + Cedar policies**, a pluggable signer (in-process, Vault, PKCS#11/HSM, or AWS/GCP/Azure KMS), OIDC login, per-request **DPoP** proof-of-possession, and offline delegation
- Per-site visitor access control at the edge (basic auth, IP allow/deny, rate limiting)

**Operate**
- Prometheus metrics, structured (JSON-optional) logs, live log tailing, and handler stats
- Integrity scrub, garbage collection, and a **built-in web console** (Yew/WASM SPA) served at a hidden path when enabled

**Ship**
- One static binary; the heavy backends live behind cargo features so the default build stays lean
- Prebuilt binaries for Linux/macOS/Windows, `.deb`/`.rpm` packages, a Homebrew tap, a hardened
  systemd unit, a **NixOS module + overlay**, a reproducible OCI image, and a **Kubernetes operator + Helm chart**
- The **same UX on every target** — bare metal, systemd, NixOS, Docker/OCI, Kubernetes, Cloudflare, and a cluster

> **Status:** boatramp is pre-1.0 (`v0.1`) and honest about it — interfaces may
> still shift before the first stable release, but what's here is real and
> **dogfooded** (both [boatramp.dev](https://boatramp.dev) and
> [docs.boatramp.dev](https://docs.boatramp.dev) run on it). The default build
> (`fs` blobs + embedded KV) is the smallest, fully-functional core — every other
> capability is an additive cargo feature. If you like owning your stack and
> shaping tools early, [come crew it](https://github.com/BoatRamp/BoatRamp/discussions).

---

## Quick start

Publish a folder in three commands. The default build needs nothing but the binary
(filesystem blobs + an embedded KV store, state under `./data`).

```sh
# 1. Run the server.
boatramp serve                      # listens on 127.0.0.1:8080

# 2. Publish a folder as a new atomic deployment and switch to it.
boatramp sync ./public --server http://127.0.0.1:8080 --site my-site

# 3. It's live — the only site, so it answers at the root.
curl http://127.0.0.1:8080/
```

Re-running `sync` on an unchanged tree uploads nothing. Change one file and only
that new blob is uploaded, then the site flips atomically.

```sh
boatramp status      --site my-site        # current deployment: id, age, size
boatramp deployments --site my-site        # history, newest first; * = live
boatramp rollback    --site my-site        # re-activate the previous deployment
boatramp prune                             # reclaim orphaned deploys + dead blobs
```

### Build before you ship

Point boatramp at any build tool in `project.cfg` and `sync` runs it first, then
publishes the output:

```ron
(
    publish: ( server: "http://127.0.0.1:8080", site: "my-site" ),
    build:   ( command: "npm run build", output: "dist" ),   // vite, webpack, esbuild, …
)
```

```sh
boatramp sync        # builds, then publishes ./dist
boatramp bundle      # or use the built-in Rolldown + lightningcss bundler
```

---

## Install

**The one-liner** — grab the latest prebuilt binary (into `~/.local/bin`):

```sh
curl -sSf https://boatramp.dev/launch | sh
```

**From a release** — prebuilt binaries (`x86_64`/`aarch64` Linux, Intel/Apple-silicon
macOS, `x86_64` Windows), `.deb`/`.rpm` packages, and a Homebrew tap are published on
the [Releases](../../releases) page.

**With Nix** (flakes):

```sh
nix run github:BoatRamp/BoatRamp -- serve      # run without installing
nix profile install github:BoatRamp/BoatRamp   # install the binary
```

**From source** (Rust 1.82+):

```sh
cargo build --release                          # fs blobs + embedded KV
cargo build --release --features "s3,tls,handlers,cluster"   # opt into more
```

---

## Functions: everything that runs is a function

boatramp serves more than files. A **function** is one portable **WASI 0.2
component** — write it in Rust, JavaScript, or Python — and you reach the same
component through many doors: run it as a route **handler**, **invoke it by name**
(sync or async, durable and idempotency-keyed), put it on a **cron**, or drive it
from a **queue**. boatramp validates the component at deploy time (parseable
component, required export, declared-imports policy) and runs it in a fuel-metered
wasmtime sandbox, with a per-site **SQL** database, KV, a blob store, a durable
message queue (`wasi:messaging`), and captured logs. Chain functions into durable
**workflows** — fan-out, barrier fan-in, per-step retries, saga compensation — that
survive restarts.

For heavier or non-Wasm workloads, the same function targets a different
**runtime**: an **OCI container** (a native self-jailing runtime or a remote
Docker host), a **Firecracker-class microVM** (an embedded rust-vmm VMM with
jailing, SMP, snapshot/restore, and scale-to-zero), or **Cloudflare Containers**.
The runtime is a config choice — the workload and the commands don't change.

See [Deploy & invoke a function](https://docs.boatramp.dev/how-to/functions.html)
and [`examples/handlers`](examples/handlers) to get started.

---

## Scale out: clustering & the gateway

Run boatramp as a **highly-available cluster** with a single flag — `serve --mode
cluster` brings up embedded Raft over the HTTP peer mesh (mutually authenticated
with raw-public-key TLS), a durable per-node Raft store, and a real **database per
site** (libsql: an embedded file per site on one node, a sqld namespace per site
across the cluster). Membership is managed with signed join tokens.

The built-in **gateway** turns boatramp into an edge for your own services:
`boatramp gateway` reverse-proxies to upstream pools with **geo-aware
(nearest-region)** load balancing, passive and active health checks, automatic
retries, and DNS-based discovery — all behind the same TLS, access-control, and
observability stack as your static sites.

On Kubernetes, the same binary is the **operator**: `boatramp operator` is an
in-cluster controller for `BoatRampCluster`/`Site`/`Function` custom resources,
shipped with a Helm chart. One image, one version — the operator is the binary
that serves.

See [Deploy a self-hosted cluster](https://docs.boatramp.dev/how-to/deploy-cluster.html),
[Run on Kubernetes](https://docs.boatramp.dev/how-to/kubernetes.html), and
[Deploy on Cloudflare](https://docs.boatramp.dev/how-to/deploy-cloudflare.html).

---

## Storage backends

Backends are compile-time cargo features; `serve` then selects among the compiled-in
options at runtime. The default build is self-contained.

| Layer         | Backend                          | Feature                     |
| ------------- | -------------------------------- | --------------------------- |
| Blobs         | Filesystem                       | `fs` *(default)*            |
| Blobs         | S3-compatible (AWS, R2, MinIO)   | `s3`                        |
| Blobs         | Google Cloud Storage             | `gcs`                       |
| Blobs         | Azure Blob Storage               | `azure`                     |
| Metadata KV   | Embedded LSM (SlateDB)           | `slatedb` *(default)*       |
| Metadata KV   | In-memory                        | *(always on)*               |
| Metadata KV   | Cloudflare KV                    | `cloudflare-kv`             |
| Function SQL  | libsql (managed, file or namespace) | `handlers`               |
| Function SQL  | External Postgres / MySQL (BYO)  | `sql-postgres` / `sql-mysql`|

SlateDB is a transactional LSM store over an `object_store` backend (local disk by
default, or S3/R2/GCS/Azure), so the same durable KV runs everywhere. Blobs are
keyed by SHA-256; small, hot metadata is fronted by an in-memory LRU cache. The
server never holds a whole file — or a whole site — in memory.

The per-function **SQL** binding defaults to **libsql** — a managed real database
per site (an embedded file on one node, a sqld namespace across the cluster). An
operator can instead point named databases at an **external Postgres or MySQL**
(bring-your-own, via `sql-postgres` / `sql-mysql`); the isolation is then theirs.

```sh
# S3-compatible blobs (e.g. MinIO), embedded KV. AWS_* env for credentials.
boatramp serve --blobs s3 --s3-bucket my-bucket \
  --s3-endpoint http://127.0.0.1:9000 --s3-path-style

# Cloudflare KV metadata (CF_ACCOUNT_ID / CF_KV_NAMESPACE_ID / CF_API_TOKEN).
boatramp serve --kv cloudflare
```

Adding a backend (GCS, Azure, Redis, …) is a new module implementing the same
trait — nothing else changes.

---

## Deploy anywhere, same UX

*One hull, every port.*

| Target                 | How                                                                    |
| ---------------------- | --------------------------------------------------------------------- |
| Bare metal / VPS       | Drop the binary, `boatramp serve`                                     |
| systemd                | Hardened unit (`ProtectSystem=strict`, `CAP_NET_BIND_SERVICE` only)   |
| NixOS                  | `services.boatramp.enable = true;` (flake module + overlay)          |
| Docker / OCI           | Reproducible, non-root, minimal image (`nix build .#container`)       |
| Kubernetes             | In-binary `boatramp operator` (controller) + a Helm chart            |
| Cloudflare             | `boatramp cloudflare` generates a Worker + Containers deployment      |
| Cluster                | `serve --mode cluster` — embedded Raft over the peer mesh             |

The commands, flags, and config files are identical across all of them —
environment differences live behind backends, never in the UX.

---

## How it works

```
boatramp sync                          boatramp serve
─────────────                          ──────────────
walk dir, hash files (streamed)        GET /  (host-routed) · /_sites/<site>/<path>
        │                                      │
        ▼  POST manifest                       ▼  resolve current → manifest → hash
server: store manifest, report missing server: stream blob from Storage
        │                                      │
        ▼  PUT only missing blobs (streamed)   ▼
        ▼  POST …/activate  ── atomic ──▶  KV: current/<site> = <deployment id>
```

- **Blobs** (file contents, keyed by SHA-256) live in a streaming `Storage` backend.
- **Metadata** (deploy manifests + the per-site `current` pointer) is small and read
  on every request, so it lives in a `KvStore` fronted by an in-memory LRU cache.

### Workspace layout

| Crate                 | Responsibility                                                          |
| --------------------- | ---------------------------------------------------------------------- |
| `boatramp-types`      | Shared types: routing, config, the authz vocabulary.                   |
| `boatramp-core`       | `Storage`/`KvStore` traits, content-addressed `DeployStore`, COSE/Cedar authz. |
| `boatramp-storage`    | Backends: blobs (`fs`, `s3`, `gcs`, `azure`), KV (`SlateKv`, `CloudflareKv`), and function SQL (libsql, external Postgres/MySQL). |
| `boatramp-server`     | Axum HTTP server + publishing API (library).                           |
| `boatramp-handlers`   | The WebAssembly (`wasi:http`) handler engine.                          |
| `boatramp-firecracker`| Embedded microVM backend (rust-vmm).                                   |
| `boatramp-container`  | Native self-jailing OCI container runtime.                             |
| `boatramp-docker`     | Remote Docker-host container backend.                                  |
| `boatramp-cluster`    | Embedded Raft + the peer mesh.                                         |
| `boatramp-acme`       | ACME DNS-01 wildcard issuance + DNS providers.                         |
| `boatramp-cloudflare` | Cloudflare Worker + Containers deployment generator.                   |
| `boatramp-console`    | Web console (Yew/WASM SPA).                                            |
| `boatramp`            | The single binary: `serve`, `sync`, `function`, `compute`, the k8s `operator`, and every operator command. |

---

## Build from source

Prerequisites: [Nix](https://nixos.org) with flakes (Determinate Nix works out of
the box); [direnv](https://direnv.net) is optional but recommended.

```sh
nix develop          # dev shell: pinned toolchain, just, git hooks, tooling
# or: direnv allow
just                 # list tasks
just build           # build
just lint            # fmt + clippy (-D warnings)
just test            # workspace tests
```

Nix outputs:

```sh
nix build              # the boatramp binary (default features)
nix build .#console    # the web console
nix build .#container  # the OCI image (Linux)
nix flake check        # clippy, format/typo hooks, and the NixOS service test
```

---

## Documentation

📖 **[docs.boatramp.dev](https://docs.boatramp.dev/)** — the full
guide: installation, the CLI, configuration, TLS, access control, functions & edge
compute, clustering, Kubernetes, Cloudflare, and the architecture reference.

The site is built from [`docs/`](docs/) (mdBook) and republished on every change.
Preview locally with `mdbook serve docs`.

---

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this project by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
