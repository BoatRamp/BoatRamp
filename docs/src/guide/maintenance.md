# Maintenance

## Prune (garbage collection)

`boatramp prune` reclaims orphaned deployments and unreferenced blobs. It
previews with a read-only pass, then asks before deleting:

```sh
boatramp prune --dry-run                 # report only
boatramp prune                           # preview, confirm, delete
boatramp prune --yes --keep-last 10      # keep the 10 most recent per site
boatramp prune --keep-age 604800         # also keep anything activated in 7 days
```

A **grace window** (`--grace`, default 3600s) protects a just-uploaded but
not-yet-activated deployment from being collected mid-publish. Aliased
deployments are retention-protected. Prune also reclaims orphaned
content-addressed `SiteConfig` bodies once no site points at them.

## Scrub (integrity)

`boatramp scrub` re-hashes every stored blob and reports any whose content no
longer matches its key (bit-rot or tampering) or can't be read:

```sh
boatramp scrub
# 4213 blob(s) verified, all intact
```

It is read-only and **exits non-zero** on any finding, so it fits a cron or
healthcheck. Verification is offline by design — the serving path can't reject a
corrupt blob without buffering, which would break streaming.

## Cert status

In a cluster, `boatramp cert-status` lists each cluster-managed cert with its
domain and days-to-expiry (never key material). It is empty when certs live in a
file cache (single-node `--tls acme`) rather than the replicated store.

## Config reload

Site config (domains, access, WAF, security, compression) and tokens live in the
KV and are read per request, so edits take effect immediately. In a
**shared-store** deployment where another process wrote the change, send
`SIGHUP` to drop the local cache (or enable `shared_cache_coherence` for
automatic, targeted invalidation). In a Raft cluster this is unnecessary —
replication keeps every node current.
