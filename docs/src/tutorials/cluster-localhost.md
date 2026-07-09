# Run a three-node cluster locally

In this tutorial you run a real three-node Raft cluster on one machine, publish
to it, read from a different node, and watch it stay up when the leader stops. It
uses loopback addresses and separate data directories, so nothing conflicts. You
need a `boatramp` binary built with the `cluster` feature.

For the production version of this, see
[Deploy a self-hosted cluster](../how-to/deploy-cluster.md).

## 1. Write three configs

Each node gets its own `boatramp.cfg`: a distinct `node_id`, serve port, mesh
`listen` port, and `store_dir`. All three list the same `peers` and `voters`.
Only node 1 sets `bootstrap`.

`node1.cfg`:

```ron
(
    serve: ( addr: "127.0.0.1:8001", data_dir: "/tmp/br1" ),
    cluster: (
        node_id: 1,
        listen: "127.0.0.1:7001",
        bootstrap: true,
        voters: [1, 2, 3],
        store_dir: "/tmp/br1/raft",
        peers: {
            "1": (url: "https://127.0.0.1:7001", pubkey: "…node-1…"),
            "2": (url: "https://127.0.0.1:7002", pubkey: "…node-2…"),
            "3": (url: "https://127.0.0.1:7003", pubkey: "…node-3…"),
        },
    ),
)
```

`node2.cfg` and `node3.cfg` are identical except `serve.addr`
(`127.0.0.1:8002` / `:8003`), `data_dir` (`/tmp/br2` / `/tmp/br3`), `node_id`
(`2` / `3`), `listen` (`:7002` / `:7003`), `store_dir` — and they omit
`bootstrap`.

## 2. Collect the mesh public keys

The peer mesh runs over raw-public-key mutual TLS, so each node must know the
others' keys. Start each node once to generate and log its key:

```sh
boatramp serve --config node1.cfg
```

```text
mesh identity ed25519:9f86d081… (/tmp/br1/mesh/identity.key)
cluster listen 127.0.0.1:7001 — waiting for peers [2, 3]
```

Do the same for `node2.cfg` and `node3.cfg`, copy each logged `pubkey` into the
`peers` map of all three configs, then stop the nodes.

## 3. Bring up the cluster

Start node 1 (the bootstrap node) first, then 2 and 3, each in its own terminal:

```sh
boatramp serve --config node1.cfg
boatramp serve --config node2.cfg
boatramp serve --config node3.cfg
```

Confirm membership and the leader:

```sh
boatramp status --server https://127.0.0.1:8001
```

```text
cluster: 3 nodes, leader = 1, term 3
node 1  voter  applied 12
node 2  voter  applied 12
node 3  voter  applied 12
```

## 4. Publish to one node, read from another

Writes forward to the leader; every node serves reads from its applied state.
Publish to node 1 and read the same content from node 3:

```sh
boatramp sync ./site --site my-site --server https://127.0.0.1:8001
curl https://127.0.0.1:8003/
```

`my-site` is the only site, so every node serves it at the root. The page served
from node 3 is the deployment you published to node 1 — the write replicated
through Raft.

## 5. Watch it survive a leader loss

Stop node 1 (Ctrl-C its terminal). The remaining two nodes still have a quorum,
so they elect a new leader. Ask a survivor:

```sh
boatramp status --server https://127.0.0.1:8002
```

```text
cluster: 3 nodes, leader = 2, term 4
node 2  voter  applied 12
node 3  voter  applied 12
node 1  down
```

Reads and writes continue against the new leader. Restart node 1 and it rejoins
and catches up from the log.
