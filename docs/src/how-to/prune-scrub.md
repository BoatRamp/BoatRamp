# Garbage-collect & verify integrity

`boatramp prune` reclaims disk by deleting orphaned deployments and the blobs no
deployment references. `boatramp scrub` re-hashes every stored blob to confirm
its content still matches its key. Run prune to recover space; run scrub to catch
bit-rot, tampering, or unreadable blobs — for example after restoring a
[backup](./backup.md).

> **Warning:** prune **deletes data**. Deleted deployments and blobs are gone.
> Keep enough deployment history to roll back to, and preview with `--dry-run`
> before you delete anything.

## 1. Preview what prune would delete

Run a read-only pass first. Nothing is deleted:

```sh
boatramp prune --dry-run
```

```text
scanning 3 site(s), 4213 blob(s)…
my-site      12 deployment(s), keep 10, prune 2
other-site    5 deployment(s), keep  5, prune 0
would delete 2 orphaned deployment(s), 87 unreferenced blob(s) — 214 MiB
dry run: nothing deleted
```

## 2. Prune

Prune previews, asks for confirmation, then deletes. A **grace window**
(`--grace`, default 3600s) protects a just-uploaded, not-yet-activated deployment
from being collected mid-publish. Aliased deployments are retention-protected.

```sh
boatramp prune --keep-last 10 --keep-age 604800
```

```text
prune 2 orphaned deployment(s), 87 unreferenced blob(s) — 214 MiB. proceed? [y/N] y
deleted 2 deployment(s), 87 blob(s) — reclaimed 214 MiB
```

- `--keep-last N` — keep the N most recent deployments per site.
- `--keep-age SECONDS` — also keep anything activated within that age.
- `--yes` — skip the confirmation prompt (for cron).

Prune also reclaims orphaned content-addressed site-config bodies once no site
points at them.

## 3. Scrub

`boatramp scrub` re-hashes every stored blob and reports any whose content no
longer matches its key, or that cannot be read. It is read-only:

```sh
boatramp scrub
```

```text
4213 blob(s) verified, all intact
```

Scrub **exits non-zero** on any finding, so it fits a cron or health check. A
failure names the offending key:

```text
blob 9f86d081… corrupt: content hash mismatch
1 of 4213 blob(s) failed verification
```

Verification is offline by design: the serving path cannot re-hash a blob without
buffering it whole, which would break streaming. Run scrub after restoring a
[backup](./backup.md) to confirm every restored blob is intact before you serve
traffic.

## On-demand blob GC over the control plane

`boatramp prune` above is the node-local sweep (deployments + blobs) run against a
data directory. For reclaiming just the **unreferenced blobs** — the
content-addressed objects that **no live deployment manifest references** — over
the **control plane** (no shell access to the node), use `boatramp blob purge
--unreferenced`. It is the everyday, on-demand front door to blob garbage
collection: nothing serving can break, because it only ever deletes blobs nothing
points at.

It is **dry-run by default** — report what *would* be reclaimed, delete nothing.
Add `--apply` to actually delete:

```console
$ boatramp blob purge --unreferenced --server https://cp.acme.com            # dry-run
blob purge: would reclaim 87 unreferenced blob(s) (214 MiB) — dry run
$ boatramp blob purge --unreferenced --apply --server https://cp.acme.com    # reclaim
blob purge: reclaimed 87 unreferenced blob(s) (214 MiB)
```

- Gated at **`System·Admin`** (the node operator) — a project admin, publisher,
  or deployer cannot reach it.
- `--json` emits the structured report.
- **Refused with a `409`** while a read-fallback secondary is attached
  (`[serve.blob_fallback]`): a union `list` over a primary-only `delete` would
  otherwise reclaim a secondary-only object that a read could resurrect. **Drain
  and drop the fallback first**, restart the node, then purge — see
  [Switch the blob backend with zero downtime](./blob-backend-migration.md).

> `--unreferenced` reclaims blobs nothing *references*. Its sibling
> `boatramp blob purge --drained-source` reclaims a **migration's** drained
> old backend (delete a source object only once it is byte-confirmed in the
> primary) — a different, migration-only mode covered in
> [Switch the blob backend with zero downtime](./blob-backend-migration.md).
