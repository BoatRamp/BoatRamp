# Upgrade boatramp to a new version

**For: operators**

boatramp is a single binary — server and CLI in one — so upgrading is replacing
that binary (or container image) and restarting. There is **no self-update
command**: you fetch the new release the same way you first installed it. This
guide covers the general flow, rolling a cluster, the store migrations some
releases require, reading the release notes, and rolling back.

> **boatramp is pre-1.0 — there is no cross-version compatibility guarantee.**
> Config formats, CLI flags, and the KV keyspace may change between releases
> (see [Maturity, validation & support](../explanation/maturity.md)). Always
> **read the release notes, pin a version, and back up before upgrading.**

## Before you start

- A recent **backup** you can restore from — this is your only rollback (see
  [Rollback](#rollback) and [Back up & restore](./backup.md)).
- The **release notes** for every version between the one you run and the one you
  are moving to. Read the repository
  [`CHANGELOG.md`](https://github.com/BoatRamp/BoatRamp/blob/main/CHANGELOG.md)
  and the [GitHub releases](https://github.com/BoatRamp/BoatRamp/releases), and
  note anything flagged **breaking** or any **store/schema migration** (below).
- Know what you run now. `boatramp version` reports this binary's version;
  `boatramp version --server <url>` (or `--remote` for the configured server)
  reports a **running daemon's**, so you can confirm what is actually live before
  and after.

## 1. The general upgrade flow

1. **Read the release notes** for the span you are crossing, and back up.
2. **Fetch the new binary or image** the way you installed boatramp — the
   install script, `cargo install boatramp@<version> --locked`, a release archive
   from the [releases page](https://github.com/BoatRamp/BoatRamp/releases), or the
   `ghcr.io/boatramp/boatramp:<tag>` container image. See
   [Install boatramp](./install.md). **Pin an explicit version** rather than
   tracking `latest`, so a restart never silently crosses a release boundary.
3. **Run any required store migration** (below) if the release notes call for one.
4. **Restart `serve`** on the new binary. On a single node this is one restart; on
   a cluster, roll it node by node (below).
5. **Verify** with `boatramp version --server <url>` and a live request, exactly
   as you verify a fresh install.

The binary and the CLI are the same artifact, so upgrade the control-plane CLI you
run from a workstation at the same time — a newer CLI against an older daemon (or
the reverse) is subject to the same no-guarantee caveat as everything else pre-1.0.

## 2. Between-release store / schema migrations

boatramp records a `schema/version` marker in its control-plane store. Most
releases read an existing store unchanged. When a release **re-keys the store**,
`serve` **refuses to start on the un-migrated store** and tells you to migrate —
it never silently rewrites your data on startup. The canonical example is the
0.2.0 project-scoping re-key, run with the top-level `boatramp migrate` command:

```bash
boatramp migrate --dry-run   # scan + print what would change, write nothing
boatramp migrate             # copy → verify → delete, recording schema/version
```

The migration is online, idempotent, and resumable, and **no content-addressed
body ever moves**. For the full procedure — including the staged
`--stage` / `--finalize` soak window and the `--auto-migrate` startup option — see
[Upgrade a store to project scoping](./upgrade-store-to-projects.md). That guide is
specific to the 0.2.0 re-key; treat it as the **pattern** a future store migration
would follow (a release that needs one will say so in its notes and `serve` will
refuse the old store until you run it).

Two adjacent, separate migrations — don't confuse them with the store re-key:

- **`apply` manifests** carry their own `version:` and migrate forward on the
  client with `boatramp config migrate <file>` (purely client-side; it never
  contacts a server). See the
  [`config migrate` reference](../reference/cli.md#config-migrate).
- **Your application's own database schema** is a different concern entirely —
  evolve it with [owner-gated schema migrations](./in-app-migrations.md), not with
  a boatramp version upgrade.

## 3. Roll a cluster node by node

A cluster is the same binary and the same commands as a single node. Upgrade it
**one node at a time**, keeping the cluster above quorum throughout:

1. Fetch the new binary/image on one node.
2. Restart that node's `serve`. A node that already has durable Raft state
   **resumes** from it on restart — it never re-founds and never re-joins — so a
   plain restart on the new binary rejoins the existing cluster. (A node whose
   Raft volume was wiped must rejoin via a seed; see
   [Deploy a self-hosted cluster](./deploy-cluster.md#restart--resume).)
3. Wait for it to report `ready` in `boatramp cluster status` before moving to the
   next node, so you never take two voters down at once.
4. Repeat for each node.

**Leader-aware ordering.** Restarting the **current leader** triggers a
sub-second Raft re-election (a brief write pause; there is no explicit
leadership-transfer call today). To minimise elections, roll the **followers
first and the leader last** — `cluster status` marks which node is `leader`.

**Certificates need no per-node work.** In a cluster the leader owns TLS issuance
and every node serves the **replicated** certificate, hot-swapping on renewal, so
a rolling restart does not re-issue or move certs. See
[Manage certificates in a cluster](./cluster-certs.md).

**On Kubernetes this is automated.** The in-binary operator drives a
**quorum-aware** rolling upgrade when you bump `spec.image` — it pauses the
StatefulSet rollout whenever the cluster lacks a spare ready voter, so the upgrade
never drops below quorum. See [Rolling upgrades](./kubernetes.md#rolling-upgrades).

> **Mixed versions are a transient, not a supported steady state.** A rolling
> upgrade briefly runs two versions at once. Pre-1.0 there is no cross-version
> compatibility guarantee, so this window is only safe when the release notes
> flag **no** store/keyspace/Raft-log change across the span. A release that
> **does** require a `boatramp migrate` is **not** a drop-in rolling upgrade —
> plan a coordinated maintenance window, run the migration once (against the
> leader, which replicates it to every follower), and expect the old binary to
> refuse the migrated store.

## Rollback

There is **no in-place downgrade**. An older binary may refuse a store a newer
release has migrated forward, and pre-1.0 the keyspace can change between
versions — so rolling back is **restore-from-backup**, not a version flag:

1. Stop `serve`.
2. Restore the pre-upgrade backup — blob store, then KV store, then the KEK if you
   use `secrets: local` (and, in a cluster, each node's own Raft store). See
   [Back up & restore](./backup.md#restore).
3. Start the **previous** binary against the restored store.

If a release's store migration supports the staged `--stage` → soak →
`--finalize` flow, the soak window (before `--finalize`) is your low-risk
rollback point: the server dual-reads the new and old layouts, so you can revert
to the previous binary without a restore until you finalize. Once finalized, the
old-layout keys are gone and the backup is the only way back.

> **Not the same as `boatramp rollback`.** The [`rollback`](../reference/cli.md#boatramp-rollback)
> command (and `function rollback`) rolls back a **site's or function's
> deployment** to an earlier version of *your* content — it does **not** downgrade
> the boatramp server itself.

## See also

- [Install boatramp](./install.md) — how to fetch the binary/image.
- [Back up & restore](./backup.md) — your rollback.
- [Upgrade a store to project scoping](./upgrade-store-to-projects.md) — the store-migration pattern.
- [Deploy a self-hosted cluster](./deploy-cluster.md) · [Manage certificates in a cluster](./cluster-certs.md).
- [Maturity, validation & support](../explanation/maturity.md) — the pre-1.0 support stance.
