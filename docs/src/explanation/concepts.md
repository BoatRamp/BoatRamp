# Core concepts

boatramp is built on a small set of ideas. Understand these and the rest of the
docs follow. This page explains the deployment model and the three configuration
tiers; for exact fields, see the reference pages linked below.

## Content is content-addressed

Every file boatramp serves is a **blob** — the raw bytes of one file, stored once
and keyed by the SHA-256 of its contents. Because the key *is* the hash,
identical bytes share a key across files, across sites, and across time. Two
deployments that share an unchanged asset point at the same blob; no copy is
made.

A **deployment** is an immutable **manifest**: a map from each site path to the
hash of the blob that answers it. The manifest names content by hash rather than
storing it, so a deployment is small, and once written it never changes. Routing
config authored in `project.cfg` is folded into the manifest, so it is versioned
and rolls back with the content it describes.

## Publishing uploads only what is missing

When you publish, the client computes the manifest and asks the server which
blobs it already holds. Only the missing blobs stream up; everything the server
has seen before — from this site or any other — is skipped. A rebuild that
touches one file uploads one blob.

Once the blobs are present, the server stores the new manifest and **activates**
it by flipping the site's current pointer in a single atomic step. A reader sees
the previous deployment or the new one in full, never a half-written mix. Because
every past manifest still exists and its blobs are still addressable, rollback is
instant: activation points the **site** at an older manifest, with nothing to
re-upload.

## Aliases are named pointers

A site's current pointer is one such reference; an **alias** is another. An alias
is a named pointer — `staging`, a per-branch preview — that resolves to a
specific deployment independently of the live pointer. You publish to an alias to
review a build, then activate it for the site when it is ready. Promotion is a
pointer move, not a rebuild.

## Compute is a function

Dynamic code is a **function** — a portable WASI component plus the capabilities it
is granted. A function is reached through a **trigger**: an HTTP route (a
*handler*), a queue topic (a *consumer*), a schedule (a *cron*), or a call by name.
The component and its sandbox are the same in every case; only the door differs.
A site's `handlers`, `consumers`, and `crons` *are* functions with triggers, and a
top-level function adds its own version line so it can be invoked, aliased, and
rolled back on its own. See [Functions: the compute primitive](./functions.md).

## Three configuration tiers

Configuration is split by audience across three surfaces, so each concern lives
where the right person controls it:

- **`project.cfg`** — the per-project client config, authored beside your code
  and read by `sync`, `build`, and `validate`. It covers where and how to
  publish, an optional build step, and deploy-scoped `routing`. See
  [`project.cfg`](../reference/project-cfg.md).
- **`boatramp.cfg`** — the server config, read by `serve`. It covers the bind
  address, storage backends, TLS, request limits, and any `cluster` section. See
  [`boatramp.cfg`](../reference/boatramp-cfg.md).
- **Per-site config** — domains, transport security, access control,
  compression, and **handler** policy. This lives in the control-plane store, not
  a file, so it travels with the server and is edited through the API and the
  `domain` and `access` subcommands.

The first two are RON files; the third is operator state. For every canonical
term used here, see the [glossary](../reference/glossary.md).
