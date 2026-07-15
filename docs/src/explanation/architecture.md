# Architecture Overview

boatramp is a Rust workspace of feature-gated crates that compose into one
binary:

| Crate | Responsibility |
| --- | --- |
| `boatramp-core` | Domain types, the streaming `Storage` trait, the pluggable `KvStore`, content-addressed deploys, routing, config, access/WAF, messaging. No runtime/engine. |
| `boatramp-storage` | Backends: `FsStorage`, S3/GCS/Azure blob, SlateDB + Cloudflare KV, libsql + external Postgres/MySQL SQL. |
| `boatramp-server` | The axum HTTP server: serving pipeline, control-plane API, auth, limits. |
| `boatramp-handlers` | The wasmtime engine + host bindings for Wasm components. |
| `boatramp-acme` | ACME (incl. DNS-01) + the `DnsProvider` abstraction. |
| `boatramp-cluster` | openraft integration: `RaftKv`, `RaftMessaging`, persistence, membership. |
| `boatramp-firecracker` | The microVM compute backend: an embedded rust-vmm VMM and an external-Firecracker driver, with snapshot/restore. |
| `boatramp-container` | The container compute backend: a jailed worker with namespaces, cgroups, and a seccomp filter. |
| `boatramp-docker` | The remote-Docker compute backend. |
| `boatramp-cloudflare` | The Cloudflare Containers compute backend + edge-Worker generator. |
| `boatramp` | The CLI (`serve`, `sync`, `domain`, …) and deploy generators. |

The `ComputeBackend` trait, scheduler, and reconcile loop live in
`boatramp-core::compute`; each backend above is a separate, capability-detected
crate. See [Compute: handlers vs containers vs microVMs](./compute-model.md).

## Two kinds of data

boatramp keeps two very different things apart, so nothing is ever buffered
whole in memory:

- **Blobs** — file contents — stream through a `Storage` backend (fs / S3 / R2),
  content-addressed by SHA-256.
- **Metadata** — small, read on every request — lives in a `KvStore` (deploy
  manifests, the per-site current pointer, site config, tokens, certs).

See [Storage & KV](./storage.md) and the [KV Keyspace](../reference/keyspace.md).

## The request pipeline

One ordered pipeline, each stage driven by config:

1. **Host → site** (virtualhost), with an optional default site.
2. **TLS / transport** — HTTPS redirect + HSTS (proxy-aware via
   `X-Forwarded-Proto`).
3. **Access control** — WAF → IP rules → rate limit → basic auth.
4. **Path normalization** — clean URLs, trailing-slash policy, dot-segment
   collapsing (traversal-safe).
5. **Redirects**, then **handlers**, then **rewrites / SPA / reverse-proxy**.
6. **Resolve** to a manifest entry (directory index, custom error documents).
7. **HTTP correctness** — conditional `304`, `Range`/`206`, ETag, headers,
   `Cache-Control`, compression negotiation.

The routing logic (steps 4–7) is pure and lives in `boatramp_core::route`, so it
is unit-tested in isolation — and reused by the Cloudflare edge Worker, so the
edge and the origin route identically.

## Deployment modes, one UX

The same commands and config run on a single node, a self-hosted Raft cluster,
or Cloudflare Containers. Environment differences hide behind the `Storage` /
`KvStore` / `Messaging` trait seams, not in the UX. See
[Deployment topologies](./topologies.md).
