# Run a three-node cluster locally

In this tutorial you run a real three-node Raft cluster on one machine using the
[dynamic-join](../how-to/deploy-cluster.md) model: one node **founds**, the others
**join** with a one-paste ticket, and you promote them to voters so the cluster
survives a leader loss. It uses loopback addresses and separate data directories,
so nothing conflicts. You need a `boatramp` binary built with the `cluster` (and
`tls`) features.

## 1. A root key + three configs

A cluster is defined by its root key. Generate one:

```sh
eval "$(boatramp auth init | grep '^BOATRAMP_AUTH_ROOT_')"
```

Each node gets a tiny `boatramp.cfg` — just its ports and store. There is **no**
`node_id`, `peers`, `voters`, or `bootstrap`: ids are derived and membership is
dynamic.

`node1.cfg` (the founder):

```ron
(
    serve: ( addr: "127.0.0.1:8001", auth_root_public_key: "es256:…" ),
    cluster: ( listen: "127.0.0.1:7001", store_dir: "/tmp/br1/raft" ),
)
```

`node2.cfg` / `node3.cfg` are identical except `serve.addr` (`:8002`/`:8003`),
`cluster.listen` (`:7002`/`:7003`), and `store_dir` (`/tmp/br2`/`/tmp/br3`). Put
your `BOATRAMP_AUTH_ROOT_PUBLIC_KEY` in each `auth_root_public_key`.

## 2. Found node 1

Found the cluster, over raw-public-key TLS (so joiners can pin it), with a
single-use bootstrap secret to mint the first admin token. Keep
`BOATRAMP_AUTH_ROOT_PRIVATE_KEY` exported:

```sh
boatramp --config node1.cfg serve --cluster-init --tls rpk \
  --bootstrap-secret s3cret
```

It logs its control-plane pin (`--server-pubkey …`) — export it so the CLI trusts
node 1, then mint an admin token:

```sh
export BOATRAMP_SERVER_PUBKEY=…            # from node 1's startup log
export BOATRAMP_TOKEN=$(BOATRAMP_BOOTSTRAP_SECRET=s3cret \
  boatramp token bootstrap --role admin --server https://127.0.0.1:8001 | head -1)
```

## 3. Join nodes 2 and 3

For each joiner, mint a **one-paste ticket** on node 1, then start the joiner with
it (each ticket is single-use — mint one per node):

```sh
ROOT=$(boatramp auth pubkey --private-key "$BOATRAMP_AUTH_ROOT_PRIVATE_KEY")
T2=$(boatramp cluster add --server https://127.0.0.1:8001 --root-pubkey "$ROOT" | head -1)
boatramp --config node2.cfg serve --cluster-join "$T2" \
  --cluster-advertise-addr https://127.0.0.1:7002
```

Repeat with a fresh ticket `T3` for `node3.cfg` (advertise `:7003`). Confirm
membership — address-primary, the founder is the leader, the joiners are learners
catching up:

```sh
boatramp cluster status --server https://127.0.0.1:8001
```

```text
ADDRESS                  ROLE      NODE       STATE
https://127.0.0.1:7001   leader    9f86d081   ready
https://127.0.0.1:7002   learner   3a7bd3e2   ready
https://127.0.0.1:7003   learner   1b4f0e98   ready
```

## 4. Promote to a voting quorum

Joiners start as read-only learners. Promote both so all three vote (needed to
survive a leader loss). In Kubernetes the operator does this automatically:

```sh
boatramp cluster promote https://127.0.0.1:7002 --server https://127.0.0.1:8001
boatramp cluster promote https://127.0.0.1:7003 --server https://127.0.0.1:8001
```

`cluster status` now shows all three as `voter`/`leader`.

## 5. Publish to one node, read from another

Writes forward to the leader; every node serves reads from its applied state:

```sh
boatramp sync ./site --site my-site --server https://127.0.0.1:8001
curl http://127.0.0.1:8003/          # the page replicated from node 1
```

## 6. Watch it survive a leader loss

Stop node 1 (Ctrl-C). The remaining two voters hold a quorum and elect a new
leader — ask a survivor:

```sh
boatramp cluster status --server https://127.0.0.1:8002
```

Reads and writes continue against the new leader. Restart node 1 and it
**resumes** from its durable store and catches up from the log.

For the production version, see
[Deploy a self-hosted cluster](../how-to/deploy-cluster.md) and
[Run on Kubernetes](../how-to/kubernetes.md).
