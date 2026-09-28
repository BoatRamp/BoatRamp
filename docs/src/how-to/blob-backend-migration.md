# Switch the blob backend with zero downtime

boatramp stores every deployment's content-addressed blobs, every `hblob/…`
ingress object, and the message-queue payloads (`mqgp/…`) in **one** blob
backend — the node's `[serve]` `blobs` selector (`fs`, `s3`, `gcs`, `azure`).
Sooner or later you outgrow the one you started on: local disk to a cloud object
store, one provider to another, one region to another.

**Don't just flip `--blobs`.** A bare backend switch points the serving path at
an *empty* store — the new backend holds none of the existing objects yet — so
every site 404s until you re-upload and re-`apply` everything. This how-to walks
the safe path instead: attach the old backend as a read-through fallback (no
serving gap), copy the data across, verify it, then reclaim the old store's
space. The whole rollout is online.

## The shape of the migration

1. **Configure** the NEW backend as the primary and the OLD backend as a
   read-only `[serve.blob_fallback]` secondary. Restart. Serving now reads the
   new backend first and falls through to the old one on a miss — **no gap**.
2. **Copy** every object OLD → NEW. Idempotent, resumable, read-only on the
   source. Two ways to run it (offline vs daemon-mediated) — pick one.
3. **Verify + reclaim** — on a verified copy the tool prints `SECONDARY FULLY
   DRAINED`; then delete the old backend's now-duplicated objects with a
   fail-closed purge.
4. **Finish** — remove `[serve].blob_fallback` and restart. The node is on the
   new backend alone.

## 1. Attach the old backend as a read-through fallback

Point `[serve]` at the **new** backend as usual, and add a
[`[serve.blob_fallback]`](../reference/boatramp-cfg.md#serveblob_fallback) block
describing the **old** one. It takes the same backend-descriptor shape as the
primary — a `blobs` selector plus the matching per-backend option fields.

```ron
serve: (
    blobs: s3,                                  // the NEW (primary) backend
    s3_bucket: "acme-blobs-new",
    s3_region: "auto",

    blob_fallback: (                            // the OLD backend, read-only
        blobs: fs,                              // was local disk
        secondary_timeout_secs: 5,
    ),
)
```

Restart the node. While the fallback is attached:

- Serving reads the **primary first** and falls through to the secondary **only
  on a definitive miss** of a boatramp-owned key. A *transient* primary error
  propagates — the node never serves stale bytes on a blip.
- The fall-through is prefix-allowlisted (content-addressed blobs, `hblob/`,
  `mqgp/`), keys are forwarded byte-identical (tenant isolation is preserved),
  and `put`/`delete` are **primary-only** — the secondary is never written.
- The node logs a prominent transition-mode **WARNING** at startup, and blob GC
  refuses to prune (see [Garbage-collect & verify integrity](./prune-scrub.md)).

There is now **no serving gap**: a request for an object still only on the old
backend is answered off the fallback while you copy.

## 2. Copy the data across

The copy is `get` → `put` per object, skipping any already present in the
destination at a matching size. Because content-addressed blobs are immutable, a
re-run after an interruption is a near-no-op — the copy is **idempotent and
resumable**, and it reads the source **read-only** (it never deletes). Choose the
runner that matches your access to the node:

### Option A — offline (`boatramp blob migrate`, needs shell access)

A node-local command: it builds both backends **in-process** from node config
files (the `boatramp.cfg` `[serve]` blob block + optional `[secrets]` for a
sealed S3 credential), so it needs local access to the backends' credentials —
**not** a `BOATRAMP_SERVER`. Because a bare `blob migrate` with a configured
`blob_fallback` defaults its source to that fallback and its destination to the
node's own primary, the whole drain is one line:

```console
$ boatramp blob migrate            # source = [serve.blob_fallback], dest = primary
blob migrate: source = fs ./data/blobs
blob migrate:   dest = s3 bucket=acme-blobs-new endpoint=(default) region=auto path_style=false
blob migrate complete: copied 1400 object(s), skipped 0 present, 5312880123 byte(s); VERIFY OK: 1400 object(s) present in destination
SECONDARY FULLY DRAINED — safe to remove [serve].blob_fallback and restart the node.
```

To copy between two *arbitrary* backends (e.g. a pre-boot volume-local copy, or
provider→provider without a running node), name both sides explicitly:

```console
$ boatramp blob migrate --from ./old.cfg --to ./new.cfg
```

Useful flags: `--dry-run` (probe reachability + classify, copy nothing),
`--concurrency N` (objects in flight, default 8), `--prefix <p>` (restrict to a
key prefix), `--no-verify` (skip the post-copy verification pass — on by
default), `--json`. An equal source == destination is refused.

### Option B — daemon-mediated (`boatramp blob drain`, no SSH needed)

On a **managed** node reachable only over the control plane (a fly machine, a
Kubernetes pod — no `fly ssh`, no local disk), the offline command can't run. Use
the daemon-mediated drain instead: the client triggers the **running daemon**
(which already holds both backends of its fallback composite open) to copy its
**own** configured secondary → primary internally, streaming progress back.

```console
$ boatramp blob drain --server https://cp.acme.com
… (NDJSON progress on stderr) …
blob drain: SECONDARY FULLY DRAINED — safe to remove [serve].blob_fallback and restart the node.
```

The client names **no** source or destination — the daemon drains only its own
configured pair, which is a tighter authorization surface than the offline CLI's
arbitrary `--from`/`--to`. It is gated at **`System·Admin`** (a project admin,
publisher, or deployer cannot reach it). No `[serve.blob_fallback]` configured ⇒
`422`. `--dry-run` / `--concurrency` / `--prefix` / `--json` pass through. Because
the copy is resumable, a dropped connection on a long drain is safe to re-run
(re-invoke and it resumes) — this sidesteps an edge idle-timeout.

## 3. Verify, then reclaim the old backend's space

Both runners **verify** by default — after the copy they `head` every source
object in the destination and fail (non-zero exit) on any that is missing. A
verified drain prints the `SECONDARY FULLY DRAINED` signal shown above.

Once that verification passes, the old backend is holding a full duplicate of the
data — pure cost. Reclaim it with a **fail-closed** purge that deletes only the
source objects it can **byte-confirm** are present in the primary:

```console
$ boatramp blob purge --drained-source --server https://cp.acme.com            # dry-run
blob purge: would reclaim 1400 object(s) from the drained secondary (5.0 GiB) — dry run
$ boatramp blob purge --drained-source --apply --server https://cp.acme.com    # do it
blob purge: reclaimed 1400 object(s) from the drained secondary (5.0 GiB)
```

`--drained-source` runs while the fallback is **still attached** — it decides
each key with a pure predicate (deletable iff the primary holds that exact key at
a matching size). An unconfirmed key **survives** — it is never deleted. Dry-run
is the default; add `--apply` to actually delete. `--prefix` restricts the sweep;
`--json` emits the structured report. `System·Admin`; a configured
`[serve.blob_fallback]` is required (else `422`).

## 4. Finish the switch

Remove the `[serve].blob_fallback` block and restart. The node is now on the new
backend alone, the transition-mode warning is gone, and blob GC is re-enabled.

You can check the posture at any time — including from monitoring — without
grepping the startup log:

```console
$ boatramp blob status --server https://cp.acme.com
blob status: a read-fallback secondary is ATTACHED ([serve.blob_fallback]) — the node is mid-migration (TRANSITION mode). Drain it (blob drain / blob purge --drained-source), drop [serve.blob_fallback], and restart to finish.
$ boatramp blob status --json --server https://cp.acme.com
{ "blob_fallback_active": true }
```

`blob status` is read-only (`System·Read`); `blob_fallback_active` flips to
`false` once you drop the block and restart.

## Worked example — local disk → Tigris (S3-compatible) with no SSH

The scenario that motivated this feature: a managed node on fly.io, ~1400
content-addressed objects on the machine's local `fs` volume, moving to
[Tigris](../how-to/secrets-at-rest.md) (an S3-compatible store) — with **zero
downtime** and **no shell access** to the machine.

**1. Point the primary at Tigris, keep fs as the fallback.** The base S3
credential comes from the sealed
[`[serve.s3_credential]`](../reference/boatramp-cfg.md#serves3_credential) store
(seal it once with `boatramp secrets set`), so no secret is in the file:

```ron
serve: (
    blobs: s3,                                  // Tigris (S3-compatible)
    s3_bucket: "acme-prod-blobs",
    s3_endpoint: "https://fly.storage.tigris.dev",
    s3_region: "auto",
    s3_path_style: false,
    s3_credential: (
        access_key_id: "tid_public_akid",
        secret_access_key: "boatramp:tigris-secret",   // a sealed reference
    ),
    blob_fallback: (
        blobs: fs,                              // the OLD local-disk backend
        secondary_timeout_secs: 5,
    ),
)
```

Deploy this config and restart. Serving is uninterrupted — reads that miss the
(empty) Tigris bucket fall through to the fs volume.

**2. Drain fs → Tigris over the control plane** (dry-run first):

```console
$ boatramp blob drain --dry-run --server https://cp.acme.com
blob drain: would copy 1400 object(s), skip 0 present — dry run
$ boatramp blob drain --server https://cp.acme.com
… NDJSON progress …
blob drain: SECONDARY FULLY DRAINED — safe to remove [serve].blob_fallback and restart the node.
```

**3. Reclaim the fs volume, then finish:**

```console
$ boatramp blob purge --drained-source --server https://cp.acme.com          # dry-run
$ boatramp blob purge --drained-source --apply --server https://cp.acme.com  # reclaim
```

Then remove `blob_fallback` from the config and restart. The node runs on Tigris
alone — the entire migration happened online, without ever touching the machine's
shell.

## Not the same as routine GC

`boatramp blob purge --drained-source` is part of the *migration* flow — it
reclaims a **drained secondary**. The everyday, on-demand reclaim of blobs that
**no live deployment references** is `boatramp blob purge --unreferenced`, covered
in [Garbage-collect & verify integrity](./prune-scrub.md#on-demand-blob-gc-over-the-control-plane).
(That mode is refused while a `[serve.blob_fallback]` is attached — drain and drop
the fallback first.)

## See also

- [`serve.blob_fallback` schema](../reference/boatramp-cfg.md#serveblob_fallback)
- [`serve.s3_credential` (sealed base credential)](../reference/boatramp-cfg.md#serves3_credential)
- [`boatramp blob` CLI](../reference/cli.md#boatramp-blob)
- [Garbage-collect & verify integrity](./prune-scrub.md)
