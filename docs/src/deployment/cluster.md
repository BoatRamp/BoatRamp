# Clustering

Cluster mode replicates the control plane with **Raft** (via openraft). Writes
go to the leader and are committed to a replicated log; reads are served from
each node's local applied state. The same binary, the same UX — clustering is a
`[cluster]` config section, not a different product.

```toml
[cluster]
node_id   = 1
listen    = "0.0.0.0:7000"          # the peer mesh (/raft + /stream)
bootstrap = true                    # node 1 only
store_dir = "/var/lib/boatramp/raft"
voters    = [1, 2, 3]

[cluster.peers]
"1" = "http://node-1:7000"
"2" = "http://node-2:7000"
"3" = "http://node-3:7000"
```

Run `boatramp serve` on each node with its own `node_id` and `bootstrap`.

## Voters and learners

- **Voters** form the consensus quorum (keep it odd: 3 or 5). Put them in one
  low-latency region.
- **Learners** replicate the log and serve **local reads**, but don't vote — add
  them in other regions for fast reads everywhere. Writes forward to the leader.

Membership is dynamic (`add_voter` / `remove_voter` / learner roles).

## What the cluster gives you

- A replicated `KvStore` (`RaftKv`) — no cache-coherence concern (every node's
  applied state is current; there is no LRU in front).
- A single-writer **messaging coordinator** = the Raft leader; **crons fire only
  on the leader**.
- **Cluster-managed TLS**: the leader issues each cert once (sole writer of the
  DNS-01 record — no races) and stores it in the replicated control plane; every
  node serves it and hot-swaps on renewal.

## Per-node storage

Each node keeps its **own** durable Raft store (`store_dir`) — this is *not*
shared (sharing a Raft log breaks Raft). Blobs (S3/R2) and the per-site SQL
backend (a sqld namespace per site) are shared. See
[Storage & KV](../architecture/storage.md).

> Validation of a live multi-host cluster is exercised on real hosts; the
> mechanism is gate-tested in-process and over localhost HTTP.
