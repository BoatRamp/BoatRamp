# Manage certificates in a cluster

In a cluster the leader owns TLS. It issues each certificate once, stores it in
the replicated control plane, and every node serves that replicated cert and
hot-swaps it on renewal. You configure ACME on the cluster, not on each node.

For single-node issuance, see [Get an automatic certificate](./acme-cert.md). To
stand a cluster up first, see [Deploy a self-hosted cluster](./deploy-cluster.md).

## How cluster certs work

- **One writer.** The leader runs the ACME account and drives the DNS-01 /
  HTTP challenge, so competing nodes never race to answer the same challenge or
  double-register an account.
- **Replicated storage.** An issued certificate commits to the Raft log like any
  other control-plane write. Every voter and learner applies it and holds the
  same cert.
- **Local serving.** Each node serves TLS from its own applied copy. A node that
  joins later replicates the existing certs before it accepts traffic.
- **Hot-swap on renewal.** When the leader renews, the new cert replicates and
  each node swaps it in on the next handshake. Live connections stay up and you
  restart nothing.

Set the ACME options in `boatramp.cfg` once and apply the same config to every
node. Do not point individual nodes at their own file-cache certs.

## List managed certificates

`boatramp cert-status` reads the replicated store and prints each managed
certificate with its domain and days to expiry. It never prints key material:

```sh
boatramp cert-status --server https://10.0.0.1:8080
```

```text
example.com  (74d left)
www.example.com  (74d left)
api.example.com  (12d left)
```

The `--server` flag (or the `BOATRAMP_SERVER` environment variable) points at any
node; every node returns the same replicated list. A certificate past its expiry
shows `(EXPIRED)` instead of a day count. When the control plane holds no managed
certificates, the command prints `no cluster-managed certificates` — you also see
this on a single node using a local file cache (`--tls acme`), which is not
cluster-managed.

## Renewal

Renewal is automatic. The leader tracks each certificate's expiry, renews ahead
of time, and replicates the result. Run `cert-status` to watch the day count
reset after a renewal; you do not renew by hand and you do not restart nodes.

If the day count stops falling near expiry, check that the leader reaches the
ACME provider and that the challenge still resolves — the same credentials you
set for [ACME issuance](./acme-cert.md).
