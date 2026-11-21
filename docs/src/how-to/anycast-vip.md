# Expose a cluster behind an Anycast VIP

**For: operators**

Announce **one IP address from every node** via BGP/ECMP and let the network
steer each client to the nearest node. The front-end (a BGP speaker such as
bird/exabgp/keepalived — boatramp does **not** run it) advertises a single
**Anycast VIP**; routers deliver each new connection to whichever node is closest.

boatramp's cluster is already Anycast-safe in its data and control plane
(replicated KV, shared blobs, replicated certs, a unicast Raft mesh). This guide
covers the operator configuration that makes a multi-PoP Anycast VIP **correct and
clean**, and the one transport caveat (HTTP/3 over QUIC).

For the topology and its trade-offs, see
[Deployment topologies](../explanation/topologies.md). This page assumes you have
already stood up a [self-hosted cluster](./deploy-cluster.md).

```text
                Anycast VIP 203.0.113.10   (BGP-announced from every PoP)
                              │
      ┌───────────────┬───────┴────────┬───────────────┐
      ▼               ▼                 ▼               ▼
   node A          node B            node C          node D
  serve.addr=VIP  serve.addr=VIP    serve.addr=VIP  serve.addr=VIP
  cluster.listen= cluster.listen=   …               …
   10.0.0.1:7000   10.0.0.2:7000  ◀── the Raft peer mesh is UNICAST (never the VIP)
      └──────── shared blob backend (S3) + replicated KV (Raft) ──────────┘
```

The defining property of Anycast: **any new connection may land on any node**, and
the node can differ between connections from the same client. So every node must
fully serve every request, and nothing may assume a client sticks to one node.

## The Anycast contract

On **every** node:

1. **Identical reads** — any node returns the same site/deploy/config/blob. Use a
   **shared** blob backend (S3/R2/GCS/Azure) and the cluster KV, **not** node-local
   `fs`.
2. **Identical TLS** — any node can terminate TLS for any domain. Issue certs via
   **DNS-01** or the cluster-managed cert store; **not** TLS-ALPN-01.
3. **Consistent limits** — enable **cluster-wide** KV-backed rate limiting, so a
   limit counts fleet-wide rather than per node.
4. **Clean drain** — a node leaving rotation withdraws its BGP announcement
   **before** it stops accepting connections. Health-gate the BGP speaker on
   `/readyz` (below).
5. **Mesh isolation** — the Raft peer mesh uses per-node **unicast** addresses
   (`cluster.listen` / the join ticket's seed), **never** the VIP.

## Configure each node

```ron
(
    serve: (
        addr: "0.0.0.0:8080",          // reachable as the Anycast VIP on every node
        blobs: "s3",                    // SHARED object store — not node-local fs
        s3_bucket: "my-cluster-blobs",
        cluster_rate_limit: true,       // KV-backed, fleet-wide rate limits
        drain_delay_secs: 5,            // graceful-drain hold on shutdown (see below)
    ),
    cluster: (
        listen: "10.0.0.1:7000",        // the UNICAST per-node mesh address, never the VIP
        store_dir: "/var/lib/boatramp/raft",
    ),
)
```

Each node sets `cluster.listen` to its **own** unicast address. When you grow the
cluster, the [join ticket](./deploy-cluster.md) carries the seed's unicast address
— never put the VIP in the mesh.

## TLS: use DNS-01, not `--tls acme`

`--tls acme` is **TLS-ALPN-01**: the CA validates by connecting to a single node's
listener. Behind Anycast the validation connection can reach **any** node, but only
the order-initiating node holds the challenge certificate, so validation fails.

boatramp **refuses `--tls acme` at startup** in a clustered posture, naming the
cure. The Anycast-safe modes are:

- `--tls acme-dns` — **DNS-01** issuance (no per-node origin reachability; also
  issues wildcard preview certs), or
- the **cluster-managed cert store** (the leader issues; followers serve the
  replicated cert) — see [Manage certificates in a cluster](./cluster-certs.md).

## Drain cleanly on every deploy (readiness-gated BGP)

Health-gate your BGP speaker on **`GET /readyz`**. On `SIGTERM` (every deploy,
restart, or rolling upgrade) a node:

1. flips `/readyz` to **`503`** immediately (while `/healthz` stays `200`, so a
   liveness probe does **not** restart it), then
2. keeps its listeners **open** for `drain_delay_secs` (default **5s**), so the BGP
   speaker's next `/readyz` poll fails and **withdraws the Anycast route before the
   node stops accepting connections**.

Without this, a node would withdraw its route only *after* it stopped accepting —
a connection-loss blip on every deploy. Set the hold with `--drain-delay <secs>` or
`[serve] drain_delay_secs`; size it above your BGP speaker's health-poll interval.
Point the speaker's health check at `/readyz` (not `/healthz`):

```sh
# exabgp/bird health check (illustrative): announce only while /readyz is 200
curl -fsS http://127.0.0.1:8080/readyz >/dev/null && echo "announce" || echo "withdraw"
```

## HTTP/3 over Anycast (QUIC)

HTTP/3 runs over **UDP/QUIC**. A TCP connection (HTTP/1.1, HTTP/2) is ECMP-pinned
for its lifetime, so it is unaffected by Anycast. But an ECMP **rehash** (a routing
change, a node added/removed) can deliver the packets of one QUIC connection to a
**different** node, breaking it — unless the load balancer steers QUIC by its
**Connection ID**. You have two options:

### Option A — routable Connection IDs (keep H3)

Give each node a distinct **node id** and configure your L4 load balancer to steer
QUIC by the Connection ID. boatramp then stamps the node id into every CID it
issues:

```ron
serve: (
    http3: true,              // serve HTTP/3 on the UDP port
    anycast_node_id: 1,       // 0..=255, DISTINCT per node (node B = 2, node C = 3, …)
)
```

or `--anycast-node-id 1`. **The CID-steering contract** — what you configure on the
LB:

- Every Connection ID is **8 bytes**.
- **Byte 0 is the node id** (`0..=255`); bytes 1–7 are cryptographic-grade random.
- Configure the L4 LB to route a QUIC **short-header (1-RTT)** packet to the node
  whose id equals the **first byte of the packet's Destination Connection ID**.

The handshake's *initial* packets carry a client-chosen (random) Destination CID,
so the first packet lands on whichever node ECMP picks; that node then issues its
own node-id-tagged CID, and every subsequent packet is steerable back to it. This
is the standard [QUIC-LB](https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/)
routable-CID approach. A node with **no** `anycast_node_id` uses quinn's default
random CIDs — correct for a single / non-Anycast node, but **not** steerable.

### Option B — disable H3 advertisement (stay on TCP)

Behind a **plain** Anycast VIP with no QUIC-aware steering, keep clients on HTTP/2
over TCP by not advertising H3:

```ron
serve: (
    http3_advertise: false,   // do not send Alt-Svc; clients stay on H2/TCP
)
```

or `--http3-advertise false`. Clients then never discover an h3 endpoint, so no
connection can break on a rehash. (Simply leaving `--http3` off also works.)

## Startup self-check

On a clustered node bound to a non-loopback address, boatramp emits a loud startup
**warning** for Anycast-unsafe combinations — a node-local `fs` blob backend,
per-node (non-KV) rate limiting, or HTTP/3 advertised without `--anycast-node-id`.
These are warnings, not failures (except `--tls acme`, which is refused outright);
treat them as a checklist against this page.

## See also

- [Deploy a self-hosted cluster](./deploy-cluster.md)
- [Deployment topologies](../explanation/topologies.md)
- [Manage certificates in a cluster](./cluster-certs.md)
