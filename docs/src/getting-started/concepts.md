# Concepts

A few ideas explain most of how boatramp behaves.

## Deployments are immutable and content-addressed

A **deployment** is an immutable manifest mapping each site path to the SHA-256
of its bytes. File contents ("blobs") are stored once, keyed by their hash, so:

- **Dedup is automatic** — identical bytes share a key, across files and across
  deployments.
- **Unchanged files never re-upload** — `sync` negotiates which blobs the server
  is missing and streams only those.
- **Rollback is free** — it's just pointing the site at an older manifest.

## Activation is atomic

Publishing uploads any missing blobs, stores the manifest, then flips the site's
"current" pointer in a single atomic operation. A reader always sees the
previous deployment or the new one in full — never a half-written mix.

## Sites, domains, and routing

A **site** is a named project. A site answers on the explicit
`/sites/<name>/…` route always, and on any **domains** you attach to it. Domains
are resolved from the `Host` header; attaching a custom domain requires
[ownership verification](../guide/domains.md) first.

## Two storage layers

boatramp keeps two very different kinds of data apart:

- **Blobs** — the (large) file contents — live in a streaming `Storage` backend
  (filesystem, S3, R2).
- **Metadata** — manifests, pointers, site config, tokens, certs — is small and
  read on every request, so it lives in a `KvStore` (SlateDB, Cloudflare KV, or
  the replicated Raft state in a cluster).

This split is why no whole file is ever resident in memory. See
[Architecture](../architecture/overview.md).

## Streaming everywhere

Uploads flow request → backend, downloads flow backend → response, and bytes are
hashed in fixed-size chunks. Limits (max upload size, idle timeout, concurrency)
are enforced *without* buffering, so streaming is never broken to apply them.
