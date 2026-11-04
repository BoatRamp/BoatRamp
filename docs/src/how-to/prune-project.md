# Prune a project's orphaned control-plane state

**For: operators**

`boatramp project prune <project>` garbage-collects a single project's
**provably-orphaned** control-plane state — the leftovers a
[`clone --force` commingle](./clone-project.md#import-a-bundle) (or a routine
`deploy apply` that rewrote a site's domains) leaves behind, without touching
anything live. It is the scalpel to [`project rm --force`](./projects.md)'s
guillotine: `rm` tears a whole project down; `prune` reclaims the dead edges of
a project you want to keep.

> **Scope:** this verb cleans ONE project's OWN control-plane keys. For the
> node-wide reclamation of shared, content-addressed **deploy blobs and
> manifests** (the disk-heavy stuff), use [`boatramp prune`](./prune-scrub.md)
> — a `System·Admin` operation. The two are complementary.

## What it removes (and what it never touches)

The whole design is **fail-closed**: a key is removed ONLY when the node can
PROVE nothing live references it. On any uncertainty, the key is **kept**.

It removes two provable-orphan classes:

| Class | What it is |
| --- | --- |
| **Dead-site leftovers** | The per-site routing/config keys (`site/`, `history/`, `sitecontexts/`, `alias/`, `domainverify/`, the activator-class record) of a site that has **no** resolvable config **and no** active deployment — a site that serves nothing. |
| **Foreign, dead domain-verification records** | A domain-verification (`domainverify/<site>/<host>`) entry for a host the site's **current** config no longer answers to **and** whose challenge is **unverified and expired** — a stale, never-completed commingle leftover. A **verified** ownership proof and an **unexpired pending** challenge for such a host are *kept* (see below). |

It **never** touches:

- **The auto-DNS ledger (`dnsmanaged/<site>/<host>`)** — each entry fronts an
  external DNS record boatramp published at a provider, and its lifecycle (retract
  the provider record, *then* drop the ledger) is owned by the auto-DNS reconcile
  sweep. Deleting the ledger directly would strand the external record — a leaked
  dangling hostname the reconcile GC could never reclaim. So prune leaves every
  `dnsmanaged/` key alone, for a dead site **and** a live site's foreign host; the
  reconcile sweep retracts a stale/foreign one correctly.
- **A verified domain-ownership proof, or an unexpired pending challenge**, even
  for a host no longer in the config — a verified record proves ownership (a
  DNS-verified parent still authorizes on-demand TLS for its subtree); removing it
  is a `domain rm`, not GC. A pending challenge is a verify-before-attach in
  flight. Only an *unverified, expired* record for a not-in-config host is a
  provable dead orphan.
- **Sealed secrets, per-tenant secrets, email profiles, and managed-SQL
  credentials** — excluded structurally, before anything is classified. Losing
  one is unrecoverable.
- **Another project's keys, or the global routing/TLS keyspace** (`domain/`,
  `wildcard/`, `cert/`) — the scan is confined to the named project's own
  `project/<p>/…` subtree (the cross-tenant-isolation boundary).
- **Live project resources** — a site with a resolvable config or an active
  deployment, project config, managed-DB declarations, functions, and compute.
- **GraphQL subgraph SDLs (`graphql/<p>/…`) and persisted APQ (`hapq/<p>/…`)** —
  a registered subgraph is a live member of the composed supergraph and an APQ
  entry is a live trusted-operation safelist row; neither is provably orphaned
  from the control-plane layer. Remove a subgraph with `graphql unpublish`, not
  prune.

## 1. Preview what prune would remove (the default)

`project prune` is a **dry-run by default** — it reports every orphan and *why*,
and changes nothing:

```sh
boatramp project prune acme
```

```text
project `acme`: 1 orphaned control-plane key(s) [prunable]
  - project/acme/domainverify/shop/old.example.net [foreign-domain-verify]: host `old.example.net` is not answered by site `shop`'s current config and its verification challenge is unverified + expired — a stale/foreign domain-verification record
(dry-run — nothing deleted; re-run with --apply to remove the above)
kept live site(s): shop
note: shared content-addressed deploy blobs/manifests are reclaimed by the node-global `boatramp prune` (System·Admin), not this per-project verb
```

A clean project reports so and exits:

```text
project `acme` is clean — no provably-orphaned control-plane state found
```

## 2. Apply the prune

Re-run with `--apply` to delete exactly the reported set. Because deletes are
irreversible, `--apply` first re-prints the plan and asks you to **type the
project name to confirm** (parity with `project rm --force`); pass `-y` / `--yes`
to skip the prompt for automation (required when stdin is not a TTY):

```sh
boatramp project prune acme --apply        # previews, then prompts
boatramp project prune acme --apply --yes  # unattended
```

```text
project `acme`: 1 orphaned control-plane key(s) [pruned]
  - project/acme/domainverify/shop/old.example.net [foreign-domain-verify]: …
removed 1 key(s)
kept live site(s): shop
```

The apply is idempotent — a second run on a now-clean project removes nothing.
Scripts can take the machine-readable form with `--output-format json`.

> **Degraded KV:** if the control-plane KV booted into a self-healed /
> quarantined state (a torn WAL tail was dropped — see `boatramp kv status`),
> `--apply` is **refused** fail-closed: a transiently-absent site pointer in the
> recovered view could misclassify a live site as dead. The refusal is keyed on a
> **boot-time snapshot**, so review, `boatramp kv status --ack`, then **restart
> the node** (so it re-reads the cleared breadcrumb) before re-running the prune —
> `--ack` alone does not lift the refusal in the running process. The dry-run
> report still works while degraded.

## Authorization

`project prune` needs a **`Project·Admin`** token on the target project — the
same grade as [export / import / clone](./clone-project.md#authorization-and-tenancy)
and the managed-DB owner operations. A Project·Admin for one project can prune
only that project, never another tenant's, and never reaches the node-global
`System·Admin` reclamation.

## See also

- [Export, import & clone a project](./clone-project.md) — the `--force`
  commingle whose leftovers this verb cleans up.
- [Garbage-collect & verify integrity](./prune-scrub.md) — the node-global
  `boatramp prune` for shared deploy blobs & manifests, and `scrub` for integrity.
- [Organize sites into a project](./projects.md) — `project rm` for a full teardown.
