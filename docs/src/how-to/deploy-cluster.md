# Deploy a self-hosted cluster

A cluster replicates the control plane with Raft. Writes go to the leader and
commit to a replicated log; every node serves reads from its local applied
state. It is the same binary and the same commands as a single node — clustering
is a `cluster:` section in `boatramp.cfg`, not a separate mode.

Use a cluster when you need highly available control-plane writes, or
low-latency reads in more than one region. For the topology and its trade-offs,
see [Deployment topologies](../explanation/topologies.md).

A cluster **is defined by one root of trust** — the control-plane root key. Every
node knows only that anchor; there is **no peer map**. A new node generates its
own mesh keypair on first boot, derives its own id from it, and **joins** by
redeeming a single-use ticket — the seed admits it, and it learns the current
members (each individually root-signed) from the join response. Growing the
cluster is two commands and one paste.

## Before you start

- The **control-plane root key** — a cluster is its root key. It signs join
  tokens, member assertions, and each node's TLS attestation. Custody is your
  choice (a local key or an external KMS/HSM/Vault signer), at **any** posture,
  with no hard gate — see
  [Mesh identity & the single root anchor](../explanation/SECURITY-mesh-identity.md).
- A shared blob backend (S3 / R2) so every node serves the same content, and — if
  you use the `sql` handler binding — a shared `sqld`. Each node keeps its **own**
  Raft store on local disk.

> **Warning:** never point two nodes at the same Raft `store_dir`. Each node must
> have its own durable store; sharing one corrupts the log.

## 1. Found the first node (one command)

Found a brand-new cluster from one node. Founding is **explicit and one-time** —
you pass `--cluster-init`. A node never self-founds by accident (no state + no
seeds fails closed, never a silent second genesis).

```ron
(
    serve: (
        addr: "0.0.0.0:8080",
        blobs: "s3",
        kv: "slatedb",
        auth_root_private_key: "es256:…",     // the cluster's root of trust
    ),
    cluster: (
        listen: "0.0.0.0:7000",               // the Raft peer mesh, distinct from serve.addr
        store_dir: "/var/lib/boatramp/raft",
    ),
)
```

```sh
boatramp serve --config boatramp.cfg --cluster-init
```

The node generates its mesh identity, derives its id, and bootstraps a 1-node
cluster. No `node_id`, no `voters`, no `bootstrap` flag, no `peers` map.

## 2. Grow the cluster (two commands, one paste)

On the running node, mint a **join ticket**. It bundles a single-use token, the
seed address the joiner should reach, and the root anchor the joiner verifies
everything against:

```sh
# The root anchor is the public key of your serve.auth_root_private_key:
root_pub=$(boatramp auth pubkey --private-key "$BOATRAMP_AUTH_ROOT_PRIVATE_KEY")
boatramp cluster add --server https://10.0.0.1:8080 --root-pubkey "$root_pub"
```

```text
brjoin1.eyJzZWVkcyI6WyJodHRwczovLzEwLjAuMC4xOjgwODAiXSwi…
single-use join ticket — hand it to exactly one new node, e.g.:
  boatramp serve --mode cluster --cluster-join brjoin1.eyJz…
```

On the **new** node, paste the ticket. It has only its own config (bind address,
store dir) — no peer map, no id:

```sh
boatramp serve --config boatramp.cfg --cluster-join brjoin1.eyJz…
```

The joiner:

1. fetches the seed's attestation and **verifies it against the root anchor**
   (the same `auth pin` flow), pinning the seed;
2. proves possession of its own mesh key (a signature the seed checks — a stolen
   token alone admits nothing);
3. is admitted, added as a learner, and **adopts each returned member only after
   verifying its root-signed assertion** — a malicious or stale seed cannot inject
   a fabricated member.

Repeat `cluster add` → `--cluster-join` for each node. In Kubernetes the operator
does this for you (the ordinal-0 pod founds; the rest join).

## 3. Check membership

`cluster status` is **address-primary** — the address is the handle you use for
`remove`:

```sh
boatramp cluster status --server https://10.0.0.1:8080
```

```text
ADDRESS                       ROLE      NODE              STATE
https://10.0.0.1:7000         leader    9f86d081          ready
https://10.0.0.2:7000         voter     3a7bd3e2          ready
https://10.0.0.3:7000         learner   1b4f0e98          lagging
```

Add `--full` for whole node ids.

## 4. Publish and verify replication

Publish to any node — writes forward to the leader — and read from another:

```sh
boatramp sync ./dist --site my-site --server https://10.0.0.1:8080
curl https://10.0.0.3:8080/_sites/my-site/    # by name from node-3's applied state
```

## 5. Remove a node

`cluster remove` takes the **address** shown by `status` (or a raw node id). It
deletes the node's trust cluster-wide, drops it from the quorum, and leaves a
durable revocation tombstone — a **fresh token cannot silently re-admit a
just-removed key** without an explicit un-revoke.

```sh
boatramp cluster remove https://10.0.0.3:7000 --server https://10.0.0.1:8080
```

## Restart & resume

A node that already has durable Raft state **resumes** from it on restart — it
never re-founds and never re-joins. A former member whose volume was wiped must
**rejoin** via a seed (it refuses to re-found), which closes the split-brain
footgun.

## Certificates in a cluster

The leader issues each certificate once and stores it in the replicated control
plane; every node serves the replicated cert and hot-swaps it on renewal. See
[Manage certificates in a cluster](./cluster-certs.md).

## Migrating the root key

Because a cluster is its root key, moving custody (local ⇄ KMS/HSM/Vault) is a
first-class operation — see [Migrate the root key](./migrate-root-key.md).

## Reference

- Full `cluster:` schema: [boatramp.cfg schema](../reference/boatramp-cfg.md).
- Mesh identity & blast radius: [SECURITY-mesh-identity](../explanation/SECURITY-mesh-identity.md).
- Per-node Raft keys: [KV keyspace](../reference/keyspace.md).
