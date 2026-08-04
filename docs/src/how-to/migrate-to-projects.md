# Upgrade a store to project scoping

boatramp 0.2.0 makes [projects](./projects.md) a first-class boundary and **re-keys
the control-plane store** so every mutable per-name record lives under
`project/<proj>/…`. A store written by an earlier release must be migrated to the new
layout before 0.2.0 will serve it. The migration is online, idempotent, and
resumable, and **no content-addressed body ever moves** — only the mutable pointers
re-key and the domain-routing index values are rewritten — so the blast radius is
small.

This is a one-time, per-store upgrade. A brand-new 0.2.0 store is already in the new
layout and needs nothing.

## What changes

- Sites, functions, compute, workflows, invocations, metering, aliases, and domain
  verifications move under `project/default/…`.
- The domain index (`domain/<host>`, `wildcard/<suffix>`, `httpchallenge/…`) keeps its
  global key; its value is rewritten from a bare site name to `{project: "default",
  site}`. A tolerant reader accepts both forms, so lookups never break mid-migration.
- A `projectmeta/default` record and an `owner/*` reverse index are created.
- Content-addressed bodies (blobs, manifests, site/compute config) do **not** move.

Everything lands in the reserved `default` project, so URLs and behaviour are
unchanged after the upgrade (`/api/sites/<name>` and an omitted `--project` are
byte-identical to before).

## Before you start

- **Back up the store first.** See [Back up & restore](./backup.md). The migration is
  copy-before-delete and resumable, but a backup is your rollback.
- Plan a short maintenance window. `serve` refuses to start on an unmigrated store
  unless you opt into auto-migration (below), so schedule the upgrade with the
  restart.

## 1. Dry-run

Scan the store and print exactly what would be re-keyed and rewritten, writing
nothing:

```bash
boatramp migrate --dry-run
```

A non-zero exit flags an anomaly (for example a domain value it cannot interpret).
Resolve those before proceeding.

## 2a. Migrate in one shot

For a single node or a small store, run the full migration:

```bash
boatramp migrate
```

It copies each key family to its new layout, verifies the copy, then deletes the old
keys — recording progress in a `schema/version` marker so an interrupted run resumes
to completion on the next invocation (re-running a finished migration is a no-op).

## 2b. Or stage it (copy → soak → finalize)

For a larger or busier store, split the copy from the delete so you can soak on the
dual-read layout before committing:

```bash
boatramp migrate --stage      # copy + verify, flip to the 2-dual layout
# ... serve; readers use the new keys and fall back to the old ...
boatramp migrate --finalize   # delete the old keys, flip to layout 2
```

During the `2-dual` stage the server reads the new keys with an old-key fallback, so
traffic is served throughout. `--finalize` runs only the delete pass.

## 3. Serve

Start the server as usual:

```bash
boatramp serve
```

On an **unmigrated** store `serve` refuses to start and tells you to migrate. If you
would rather migrate automatically at startup (for example in an appliance image),
pass `--auto-migrate`:

```bash
boatramp serve --auto-migrate
```

### Clusters

Run the migration **once**. Execute `boatramp migrate` against the leader (it writes
through Raft, so the new keys replicate to every follower for free). A follower that
starts on a store still marked unmigrated blocks on the `schema/version` marker rather
than racing its own copy.

## Verify

After migrating, confirm both a site and its routing still serve:

```bash
boatramp project ls            # shows `default`
boatramp --project default sync ./dist --site <name>   # a no-op re-deploy uploads nothing
curl -sSf https://<your-host>/ >/dev/null && echo ok
```

## See also

- [Organize sites into a project](./projects.md)
- [Back up & restore](./backup.md)
- [KV keyspace](../reference/keyspace.md)
