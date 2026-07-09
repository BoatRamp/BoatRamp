# Deployment topologies & the one-UX seam

boatramp runs as a single node, a self-hosted Raft cluster, or on Cloudflare
Containers. The same binary, commands, and config work in all three. The
differences live behind trait seams — `Storage`, `KvStore`, `Messaging` — not in
the way you operate it. This page explains the topologies and the seam that keeps
them uniform.

## The seam

boatramp keeps two kinds of state apart: **blobs** (file contents, streamed and
content-addressed) behind the `Storage` trait, and **metadata** (manifests, the
per-site current pointer, config, tokens, certs) behind the `KvStore` trait.
Swapping a backend is swapping a trait implementation, so the CLI, the routing,
and the config never change. That is why "the same commands run everywhere" is
true rather than a slogan — the environment-specific code is confined to the
backends, and everything above them is shared.

## Single node

One process, local disk: `FsStorage` for blobs, embedded SlateDB for the KV. It
is a single writer and a single point of failure, which is the right trade for
most sites. SlateDB runs over any object store, so a single node can keep its KV
on S3 or R2 too. See [Deploy a single node](../how-to/deploy-single-node.md).

## Shared-store frontends

Several stateless serving processes can share one KV over an object store, with a
changelog keeping their in-memory caches coherent. This scales reads horizontally
without Raft: the processes hold no authoritative state of their own, so you add
and remove them freely. See [Cache coherence](./cache-coherence.md).

## Self-hosted cluster

A Raft cluster replicates the control plane. Writes commit to the leader's
replicated log; every node serves reads from its local applied state. Voters form
the quorum in one region; learners in other regions serve local reads and forward
writes, so a far-region node gives low-latency reads without a WAN round-trip on
every request. The peer mesh runs over raw-public-key mutual TLS. See
[Deploy a self-hosted cluster](../how-to/deploy-cluster.md).

## Cloudflare Containers

The same binary runs in Cloudflare Containers as a cluster, with a thin edge
Worker in front. The Worker runs the pure `boatramp_core::route` logic compiled
to Wasm, so the edge routes exactly as the origin does — there is no separate
routing implementation to keep in sync, and no separate coordinator service. Blob
and metadata durability move to R2 and D1 behind the same `Storage` / `KvStore`
seams. See [Deploy on Cloudflare Containers](../how-to/deploy-cloudflare.md).

## Choosing

- One host, most sites → single node.
- Read scale without HA writes → shared-store frontends.
- Highly available control-plane writes, multi-region reads → cluster.
- Cloudflare's edge and managed backends → Cloudflare Containers.

The choice is an operational one. Because it is a backend choice behind the seam,
you can start on one node and move to a cluster later without rewriting anything.
