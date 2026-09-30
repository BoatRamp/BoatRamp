# Production roll runbook — boatramp v0.11.0+

The recurring "KV unbootable after a deploy roll" incident class is closed at the
source in v0.11.0. This runbook is what an operator does around a `fly deploy`
roll of a single-node boatramp instance (the `fly.toml` in the repo root is the
reference machine).

## What v0.11.0 changed (so a roll is now boring)

- **fsync on the local control-plane store.** The SlateDB `LocalFileSystem` is
  opened with `with_fsync(true)`, so a manifest/WAL object's final name only
  becomes visible once its data blocks + parent-dir entry are durable. A hard VM
  stop (a fly machine restart hard-stops the VM), a crash-consistent volume
  snapshot mid-write, or power loss can no longer leave a 0-byte "empty manifest"
  (or torn WAL tail) at its final name. This is the highest-leverage fix — it
  stops the corruption from occurring.
- **Auto last-good-generation recovery.** If a *pre-v0.11.0* store already landed
  with an empty/torn **latest manifest**, the next cold open recovers itself: it
  rolls back to the highest manifest generation that decodes (G), quarantines the
  torn suffix (outside `manifest/`), and replays the WAL forward from G's frontier.
  This is **lossless-for-acked** — N-1 + WAL replay is exactly a normal open. A
  case it cannot prove safe (no decodable generation, a WAL GC hole, a torn
  compacted/L0 SST) fails **loud** into the recovery-mode 503 listener rather than
  dropping or resurrecting acked state.

Net: a roll where fly SIGKILLs mid-close is now non-corrupting, and a store that
was already stuck comes back on its own (or fails loud, never silently lossy).

## Before a roll

1. Confirm `kill_timeout` and `close_deadline` leave headroom (see the sizing
   formula in `fly.toml`): `kill_timeout (30) >= close_deadline (25) + margin`, and
   `close_deadline >= measured drain + memtable→L0 freeze time`.
2. **A volume snapshot is DR hygiene, not a roll gate.** You do *not* need to
   snapshot before every roll — fsync makes the roll itself safe. Keep a periodic
   snapshot cadence for disaster recovery (accidental data loss, a bad migration),
   and, if you want a *guaranteed-bootable* point-in-time, take it right after:

   ```sh
   boatramp kv checkpoint --live --server https://<node>   # advance the durable frontier now
   #   → then snapshot the fly volume (fly volumes snapshots create ...)
   ```

## The roll

```sh
just fly-image          # build + push the flake .#container to fly's registry
fly deploy --image <ref>
```

fly sends SIGINT, waits `kill_timeout`, then SIGKILLs. boatramp drains in-flight
requests, quiesces writers, and `close()`s the control-plane store (freeze
memtables → L0, advance the durable frontier). A close-in-progress breadcrumb
(`{root}/CLOSING.json`) is written when the close starts and deleted on a clean
close.

## After a roll — verify

```sh
# Boring roll: state=ok, frontier_source=manifest_latest.
curl -s https://<node>/api/kv-status        # (System·Read; use your control-plane token)
boatramp kv status                          # local: reads the DEGRADED breadcrumb without opening the store
```

- `frontier_source: manifest_latest` + `state: ok` → nothing happened; done.
- `frontier_source: manifest_gen_rollback` → the node auto-recovered from an
  empty/torn latest manifest by rolling back to a last-good generation. `kv status`
  leads **"RECOVERED (lossless)"** for the pure case (zero acked loss). Review the
  quarantined manifest ids, then `boatramp kv status --ack` to clear the breadcrumb.
- `frontier_source: wal_replay` → a torn WAL tail was self-healed (bounded,
  forensic-only loss window on a hard crash). Review + `--ack`.
- Boot WARN "the PREVIOUS graceful close was CUT SHORT" → fly SIGKILLed mid-close
  last time. The store is still fine (fsync), but raise `kill_timeout` /
  `close_deadline` to cover the measured drain+close.

## If the node is in RECOVERY MODE (503 for sites, 200 for probes)

The control-plane store could not open and F2 could not prove a safe recovery.
`/healthz` + `/readyz` stay green (so fly does not flap-restart); `GET
/api/kv-status` returns the diagnosis.

```sh
boatramp kv recover                         # DRY-RUN: diagnose the whole store + print the plan
boatramp kv recover --apply                 # roll back to the last-good generation / quarantine a safe WAL tail, in place
# torn compacted/L0 SST only (beyond in-place recovery):
boatramp kv recover --adopt-volume <mounted-path>          # validate a clean snapshot
boatramp kv recover --adopt-volume <mounted-path> --apply  # verify-open → swap (crashed copy retained)
```

`kv recover` operates on `<data-dir>/kv-slate`. It **refuses** on a cluster node
(a `raft/`/`mesh/` store beside it): a cluster node recovers by wiping its store
and **rejoining peers**, never by self-recovering its node-local Raft log.
