# PLAN — blob-backend migration (v0.6.2, additive/non-breaking)

**Branch:** `blob-backend-migration` · **Base:** v0.6.1 (`cf677b3`) · construens
`boatramp-blob-backend-migration-request.md`. Owner: build BOTH parts, one release v0.6.2.

Two parts. Part 1 is bounded (copy verb over existing primitives, like `sql move`) → Security loop +
mutation gate, no panel. Part 2 changes the node **serving read-path** → 3-role panel FIRST, then build +
live gate.

## Existing primitives (recon, v0.6.1)
- `Storage` trait `boatramp-core/src/lib.rs:138` — `get/get_range/put/head/delete/list(prefix)->Vec<ObjectMeta>`
  (+ `mapped`/`local_file`/`supports_watch`/`watch`). `list` is NOT paginated at the trait; each backend
  flattens internally (fs = recursive read_dir; s3/gcs/azure = native paged ListObjects loop).
- `build_blobs(args:&BlobArgs, data_dir, notify_tier, notify_account) -> BuiltBlobs` in
  `boatramp-node/src/blobs.rs:59`. `BlobArgs` holds the selector + per-backend opts +
  `s3_credential: Option<SealedS3Credential>` (#505). `SealedS3Credential::as_pair()->(String,String)`.
- `CachedStorage` `boatramp-storage/src/cache.rs` — the decorator template (wraps `Arc<dyn Storage>`,
  delegates, caches `get` bodies; `put`/`delete` evict; `list` bypasses).
- CLI: `boatramp blob` (`boatramp/src/blob.rs`) = `Put` + `MintUpload`. `boatramp sql move`
  (`boatramp/src/sql.rs`) is the copy/move-verb precedent.
- Key space in the ONE node blob store:
  - **immutable, content-addressed:** `{2hex-shard}/{64hex-sha256}` deploy blobs (`deploy.rs:99` `is_blob_key`).
  - **MUTABLE control-plane records:** `manifests/…`, `siteconfig/…`, `config/…`, `daemonconfig/…`.
  - **MUTABLE guest objects:** `hblob/{qualified-site}/{container}/{key}` (guest picks names; can overwrite).
- Gate convention: a `#[cfg(all(test, feature="…-gate-mutation"))]` module with invariant fns + an
  orchestrator test that prints a marker only on a clean run; ci.yml runs clean (assert marker) + each
  `…_MUTATE_*=1` (assert marker ABSENT). Exemplar: `s3_credential.rs:545` + `ci.yml:1310` (`S3 SEALED-CRED
  SOURCING OK`).

## Part 1 — `boatramp blob migrate --from <config> --to <config>` (offline, node-local)
A NODE-LOCAL command (builds backends in-process, needs the sealed-store envelope; NOT a control-plane HTTP
call). Lives in the `boatramp` binary alongside `serve`. Each `<config>` is a node config file whose
`[serve]` blob block (+ `[secrets]` for sealed refs) defines that side — reuses ALL existing config parsing
+ `build_blobs` + sealed-cred unsealing, symmetric, covers fs→cloud AND region→region. Flags: `--from`,
`--to`, `--concurrency N` (default e.g. 8), `--verify` (default on), `--dry-run`, `--prefix <p>` (optional,
restrict).

**Copy engine** (new module, e.g. `boatramp-node/src/blob_migrate.rs`):
1. Build source + dest via `build_blobs` (notify_tier=None — no watchers needed).
2. Enumerate `source.list(prefix)` (default prefix `""`).
3. Bounded worker pool (`--concurrency`): for each `ObjectMeta`:
   - `dest.head(key)` → if present AND size matches, **SKIP** (idempotent/resumable).
   - else `source.get(key)` → `dest.put(key, body, meta-preserving content_type)`.
4. Progress: periodic log (objects/bytes copied, skipped, total).
5. **Verify** (default): per top-level prefix, assert `dest` count ≥ `source` count (every source key present
   in dest via `head`). Report any missing.
6. **Read-only on source** — never delete. Operator flips `--blobs`/config after verifying; retires old store
   separately.

**Part-1 security invariants (mutation gate `BLOB MIGRATE COMPLETE OK`):**
- I1 completeness: after migrate, EVERY source object is `head`-present in dest (mutation: drop-last-object ⇒ FAIL).
- I2 head-skip soundness: skip only when dest already has the key with matching size (mutation: skip-always ⇒
  a not-present key is left missing ⇒ I1 FAIL).
- I3 key fidelity: dest key == source key byte-exact (no prefix mangling that could collapse a tenant/`hblob`
  boundary) (mutation: rewrite-key ⇒ FAIL).
- I4 source read-only: source object count unchanged after migrate (mutation: delete-on-source ⇒ FAIL).
Gate is fs→fs in a tempdir (no cloud needed), feature `blob-migrate-gate-mutation`, env toggles
`BOATRAMP_BLOBMIG_MUTATE_{DROP_LAST,SKIP_ALWAYS,REWRITE_KEY,DELETE_SOURCE}`.

## PANEL OUTCOME (2026-09-27) — all 3 PASS-WITH-CONDITIONS; converged design below

Backend + UX + Security all PASS-WITH-CONDITIONS. A Backend↔Security factual conflict was resolved by
direct grep (like #501): **the mutable control-plane records (`manifests/siteconfig/config/daemonconfig`)
live in `DeployStoreInner.kv` (KvStore), NOT the blob `storage`** (`deploy.rs:133-134`; every such write is
`self.kv.*` at 1208/2181/2357/…; the ONLY `self.storage` ops are content-addressed `keys::blob(hash)` at
722/757/761/772/806 + GC `list("")`/`delete` at 3598/3611/3668/3735). ⇒ `FallbackStorage` (wraps `Storage`)
**never sees config records** → Security Finding 2b/4 (serve-a-revoked-config, HIGH) is **MOOT**. Real blob
store contents = immutable `{shard}/{hash}` + mutable `hblob/` (guest) + `mqgp/` (messaging, retention-del).

**Converged Part 2 decisions (clears every blocking condition; proportionate — Backend's position, Security-accepted):**
1. **NotFound-ONLY fallback** (Sec F3/G4-err, Backend): fall through iff `Err(StorageError::NotFound)`; ALL
   other errors (`Io`/`Backend`/`Unsupported`/`InvalidKey`) PROPAGATE — never serve secondary on a transient
   primary error. Both-miss ⇒ `NotFound`. `NotFound` is a distinct `StorageError` variant (`error.rs:12`) so
   the match is exact.
2. **Prefix allowlist, fail-closed** (Sec F4/G5-cp as defense-in-depth): fall back ONLY for `is_blob_key(K)`
   OR `hblob/` OR `mqgp/`. Any other key ⇒ primary-only (so if a config record EVER lands in the blob store
   later, it can't silently resurrect). A synthetic `config/…` on secondary must NOT fall back (gate G5-cp).
3. **GC refusal with a secondary attached** (Sec F5/G8-gc — the live fail-open): add `Storage::allows_prune()
   -> bool { true }`; `FallbackStorage` returns `false`; `DeployStore::collect_garbage(prune=true)` (and
   `scrub` prune) REFUSE (return error) when `!storage.allows_prune()`. Structural = the "drain→drop→then GC"
   doctrine. Removes the phantom-reclaim entirely without a tombstone.
4. **NO tombstone in v0.6.2** — with (1)+(2)+(3) the only residual is a MEDIUM `hblob/` within-tenant
   delete-during-window resurrection (guest deletes its own object mid-transition; key scheme preserved ⇒
   NOT cross-tenant). Addressed by transition doctrine + a repeating startup WARNING (names guest-delete as
   the one hazard) + the migrate "SAFE TO DROP FALLBACK" signal. Tombstone (reserved `.boatramp-tomb/`
   keyspace + list-subtract + re-put-clears) documented as the future escalation if a live-delete workload
   needs it (Security accepted: "tombstone only needed for hblob, can be scoped as such").
5. **`mapped`/`local_file` are PRIMARY-ONLY** (Sec G10 over Backend C1): a primary `None` is ambiguous
   (missing vs remote-opaque) — `or_else(secondary)` would serve STALE fs bytes for a mutable `hblob/` key
   when primary is cloud. Primary-only is safe; the caller already streams via `get` on `None` (which falls
   back correctly). Zero-copy loss is negligible + bounded to the window.
6. Backend C3–C7: `CachedStorage` wraps OUTSIDE `FallbackStorage` (cache→fallback→{primary,secondary});
   `get_range` forwards `(offset,len)` to `secondary.get_range`; `list` union dedups via `HashSet<key>`;
   secondary built `notify_tier=None`, its watch_provider/provision_tier discarded, `supports_watch`=primary;
   secondary supports #505 sealed creds via its own `blob_fallback` `BlobArgs` → reuse `resolve_s3_credential`
   (Sec C6a), and is NEVER handed to the upload/STS minter (Sec C6b, minter stays primary-only).
7. **Bounded secondary timeout** (Backend C2): a wedged secondary must degrade a primary-miss to `NotFound`
   quickly, not hang the serve path.
8. **Key fidelity** (Sec G9/F1): composite forwards the key BYTE-IDENTICAL to both backends — no
   normalize/prefix/case-fold. This is the cross-tenant backstop (tenancy is enforced ABOVE `Storage`).

**UX conditions folded into Part 1 CLI (below):** `--to` defaults to the running node config; bare
`blob migrate` with a configured `blob_fallback` ⇒ source=fallback, dest=primary (one-liner rollout); refuse
if from==to; echo resolved source/dest identity before copying; preflight per-prefix object/byte counts;
progress line = copied+skipped+errors+bytes+ETA; **verify by per-key head-presence (NOT count), list the
specific missing keys, non-zero exit on any miss/error**; `--dry-run` probes reachability + dest writability;
`--json`; on a verified fallback→primary drain print "SECONDARY FULLY DRAINED — safe to remove
[serve].blob_fallback"; help on BOTH `blob migrate` and top-level `migrate` cross-disambiguates the collision.

## Part 2 — `FallbackStorage` composite (zero-downtime) — build per converged decisions above
`boatramp-storage/src/fallback.rs`: `FallbackStorage { primary: Arc<dyn Storage>, secondary: Arc<dyn Storage> }`.
- `get`/`get_range`/`head`/`mapped`/`local_file`: try primary; on **NotFound ONLY** fall through to secondary.
  A primary transient error PROPAGATES (do NOT silently serve secondary on error — only on a definitive miss).
- `put`/`delete`: **primary only.** Secondary is strictly read-only (never written, never deleted).
- `list(prefix)`: union — primary entries + secondary entries whose key is absent from primary (primary meta
  wins on dup). Needed so a mid-transition guest `wasi:blobstore` list + a `blob migrate` enumeration see all.
- `watch`: primary only; `supports_watch()` = primary's.
- `[serve]` config: a `blob_fallback` block (same backend-descriptor shape as the primary; read-only role).
  `build_blobs`-style construction of the secondary; wire `FallbackStorage::new(primary, secondary)` when set.

**THE central risk for the panel** (the store is NOT all-immutable): a key **deleted on primary** but still
present on **secondary** during the live window ⇒ read-fallback-on-miss **resurrects** it (stale/deleted
record served). Applies to mutable prefixes (`manifests/`, `siteconfig/`, `config/`, `daemonconfig/`) and
mutable `hblob/` guest objects; content-addressed `{shard}/{hash}` blobs are immune (immutable). Candidate
mitigations for the panel to weigh:
  (a) **Transition-mode doctrine**: fallback is a bounded transition aid — operator runs `blob migrate` to
      drain secondary→primary, verifies, then DROPS the fallback; document "avoid deletes during the window."
  (b) **Delete tombstone**: `delete` writes a primary tombstone that suppresses the secondary fallback for
      that key (heavier; correct under live deletes).
  (c) **Immutable-only fallback**: restrict fallback to content-addressed keys — but that FAILS the goal
      (manifests/siteconfig must resolve to avoid the 404s the request is about), so rejected unless combined.
Panel + Security decide (a) vs (b) [vs a hybrid]. Also confirm: fallback preserves tenant isolation (same
key scheme on both backends → no cross-tenant read); failure semantics (secondary down ⇒ primary still
serves; primary miss + secondary down ⇒ NotFound, not a hang).

**Part-2 live gate `BLOB FALLBACK ZERO-GAP OK`** (real fs backends, tempdirs):
- G1 primary-miss reads from secondary (put on secondary only, get via fallback ⇒ bytes).
- G2 primary HIT never consults secondary (divergent bytes on each for same key ⇒ fallback returns PRIMARY's;
  mutation reversing precedence ⇒ FAIL).
- G3 write isolation: `put`/`delete` via fallback touch primary ONLY — secondary object count unchanged
  (mutation writing secondary ⇒ FAIL).
- G4 (whichever delete-mitigation the panel picks) is asserted: (a) documented+no gate beyond G3, or (b)
  tombstone suppresses resurrection (delete via fallback ⇒ subsequent get is NotFound even though secondary
  still has it; mutation skipping the tombstone ⇒ resurrected ⇒ FAIL).

## Release mechanics
Additive → v0.6.2 (bump 17 pins 0.6.1→0.6.2). Full local `--all-features --all-targets` musl clippy + fmt +
typos before tag. No shim (no guest WIT change). RESOLVED note on the request; CHANGELOG [0.6.2]; release
memory. Panel PASS + Security convergence on Part 2 before merge.
