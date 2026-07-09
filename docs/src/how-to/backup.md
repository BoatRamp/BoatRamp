# Back up & restore

boatramp keeps its state in a few well-defined places. Back up each one, and a
restore is putting them back and re-verifying. There is no single dump command —
you snapshot the backends you configured.

## What to back up

| State | Where it lives | Back up |
| --- | --- | --- |
| Blobs (file contents) | `<data-dir>/blobs`, or your S3/R2 bucket | The directory, or the bucket (versioning/replication). |
| Control-plane metadata (deployments, site config, tokens, cert records) | the KV: `<data-dir>/kv-slate`, or the object store SlateDB runs on | The KV store's files/bucket. |
| Per-node Raft store (cluster) | each node's `store_dir` | Each node separately; it is node-local, never shared. |
| Secrets KEK (if `secrets: local`) | `kek_file` | The KEK. Without it, wrapped certificates are unrecoverable. |
| ACME certificate cache | `--acme-cache` (default `<data-dir>/acme`) | Optional — certificates re-issue, but backing it up avoids re-issuance and rate limits. |

Blobs are content-addressed and metadata references them by hash, so the two must
be backed up as a consistent pair — back up the KV no earlier than the blobs so
every referenced blob exists.

## Restore

1. Restore the blob store, then the KV store.
2. Restore the KEK if you use `secrets: local`, so the control plane can unwrap
   cert keys.
3. In a cluster, restore each node's own Raft store; do **not** copy one node's
   store to another.
4. Start the server.
5. Verify blob integrity:

```sh
boatramp scrub
```

```text
scrub: 512 blobs verified, 0 corrupt, 0 missing
```

`scrub` re-hashes every stored blob and confirms it still matches its key, so a
partial or corrupt restore is caught before it serves bad content. If it reports
missing blobs, the KV was restored ahead of the blob store — restore the blobs
and re-run.

> **Warning:** losing the `secrets: local` KEK makes envelope-wrapped certificate
> keys unrecoverable. Back the KEK up with your other secrets, separately from the
> data it protects. See [Encrypt secrets at rest](./secrets-at-rest.md).
