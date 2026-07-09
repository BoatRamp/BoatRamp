# Deploy a self-hosted cluster

A cluster replicates the control plane with Raft. Writes go to the leader and
commit to a replicated log; every node serves reads from its local applied
state. It is the same binary and the same commands as a single node — clustering
is a `cluster:` section in `boatramp.cfg`, not a separate mode.

Use a cluster when you need highly available control-plane writes, or
low-latency reads in more than one region. For the topology and its trade-offs,
see [Deployment topologies](../explanation/topologies.md).

## Before you start

- An odd number of **voters** (3 or 5) in one low-latency region for the quorum.
  Add **learners** in other regions for local reads; a learner replicates the
  log and serves reads, forwards writes to the leader, and never votes.
- A shared blob backend (S3 / R2) so every node serves the same content, and — if
  you use the `sql` handler binding — a shared `sqld`. Each node keeps its **own**
  Raft store on local disk.
- One node designated to bootstrap the cluster.

> **Warning:** never point two nodes at the same Raft `store_dir`. Each node must
> have its own durable store; sharing one corrupts the log.

## 1. Write each node's config

Config is RON, in `boatramp.cfg`. The peer mesh runs over RFC 7250 raw-public-key
**mutual TLS**: each node generates an Ed25519 mesh identity on first start and
logs its public key. You put every node's public key in the `peers` map — that
map is the genesis trust set. A non-loopback `listen` refuses to start without
it.

`node-1`, the bootstrap node:

```ron
(
    serve: (
        addr: "0.0.0.0:8080",
        blobs: "s3",
        kv: "slatedb",
        auth_root_private_key: "es256:…",
    ),
    cluster: (
        node_id: 1,
        listen: "0.0.0.0:7000",          // the Raft peer mesh, distinct from serve.addr
        bootstrap: true,                 // set on exactly ONE node, at first bring-up
        voters: [1, 2, 3],
        store_dir: "/var/lib/boatramp/raft",
        peers: {
            "1": (url: "https://10.0.0.1:7000", pubkey: "…node-1 hex…"),
            "2": (url: "https://10.0.0.2:7000", pubkey: "…node-2 hex…"),
            "3": (url: "https://10.0.0.3:7000", pubkey: "…node-3 hex…"),
        },
    ),
)
```

`node-2` and `node-3` are identical except for `node_id`, and they omit
`bootstrap`. See the full schema in the
[boatramp.cfg reference](../reference/boatramp-cfg.md).

## 2. Collect the mesh public keys

Start each node once. It generates its identity and logs the key:

```sh
boatramp serve --config boatramp.cfg
```

```text
mesh identity ed25519:9f86d081… (/var/lib/boatramp/mesh/identity.key)
cluster listen 0.0.0.0:7000 — waiting for peers [2, 3]
```

Copy each node's `pubkey` into every node's `peers` map, then restart. Until the
trust set is complete, nodes reject each other's mesh connections.

## 3. Bring up the cluster

Start the bootstrap node first, then the others:

```sh
boatramp serve --config boatramp.cfg
```

The bootstrap node forms a single-voter cluster; the others join as voters per
`voters`. Confirm membership and the leader:

```sh
boatramp status --server https://10.0.0.1:8080
```

```text
cluster: 3 nodes, leader = 1, term 4
node 1  voter    applied 128
node 2  voter    applied 128
node 3  voter    applied 128
```

## 4. Publish and verify replication

Publish to any node — writes forward to the leader — and read from another:

```sh
boatramp sync ./dist --site my-site --server https://10.0.0.1:8080
curl https://10.0.0.3:8080/sites/my-site/     # served from node-3's applied state
```

## Certificates in a cluster

The leader issues each certificate once and stores it in the replicated control
plane; every node serves the replicated cert and hot-swaps it on renewal. See
[Manage certificates in a cluster](./cluster-certs.md).

## Membership changes

Add a learner by giving it a config with its own `node_id`, starting it, and
adding it through the membership API; it replicates the log and serves local
reads without joining the quorum. Promote it to a voter, or remove a node, with
the same API.

## Reference

- Full `cluster:` schema: [boatramp.cfg schema](../reference/boatramp-cfg.md).
- Per-node Raft keys: [KV keyspace](../reference/keyspace.md).
