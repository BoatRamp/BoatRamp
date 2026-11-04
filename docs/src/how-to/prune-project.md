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
| **Dead-site leftovers** | The per-site routing/config keys (`site/`, `history/`, `sitecontexts/`, `alias/`, `domainverify/`, `dnsmanaged/`, the activator-class record) of a site that has **no** resolvable config **and no** active deployment — a site that serves nothing. |
| **Foreign-domain records** | A domain-verification (`domainverify/<site>/<host>`) or auto-DNS (`dnsmanaged/<site>/<host>`) ledger entry for a host the site's **current** config no longer answers to — the motivating commingle leftover. |

It **never** touches:

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
project `acme`: 2 orphaned control-plane key(s) [prunable]
  - project/acme/domainverify/shop/old.example.net [foreign-domain-verify]: host `old.example.net` is not answered by site `shop`'s current config — a stale/foreign domain-verification record
  - project/acme/dnsmanaged/shop/old.example.net [foreign-managed-dns]: host `old.example.net` is not answered by site `shop`'s current config — a stale/foreign managed-DNS record
(dry-run — nothing deleted; re-run with --apply to remove the above)
kept live site(s): shop
note: shared content-addressed deploy blobs/manifests are reclaimed by the node-global `boatramp prune` (System·Admin), not this per-project verb
```

A clean project reports so and exits:

```text
project `acme` is clean — no provably-orphaned control-plane state found
```

## 2. Apply the prune

Re-run with `--apply` to delete exactly the reported set:

```sh
boatramp project prune acme --apply
```

```text
project `acme`: 2 orphaned control-plane key(s) [pruned]
  - project/acme/domainverify/shop/old.example.net [foreign-domain-verify]: …
  - project/acme/dnsmanaged/shop/old.example.net [foreign-managed-dns]: …
removed 2 key(s)
kept live site(s): shop
```

The apply is idempotent — a second run on a now-clean project removes nothing.
Scripts can take the machine-readable form with `--output-format json`.

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
