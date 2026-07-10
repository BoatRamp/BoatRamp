# Dynamic daemon config

boatramp splits its configuration into two tiers by **change class**:

- **`restart`** — the trust anchors and listener shape in `boatramp.cfg`. Editing
  them needs a process restart; that is deliberate (see
  [The configuration model](../explanation/config-model.md)).
- **`dynamic`** — operational knobs stored in the control-plane KV, changed with
  [`boatramp config`](./cli.md#boatramp-config). A write converges **fleet-wide
  without a restart** — one node's change replicates to every node (Raft cluster,
  shared store, or a SIGHUP), so there is no per-node file edit or rolling restart.

The effective config is `file baseline ⊕ dynamic overrides`. An unset dynamic key
falls back to the `boatramp.cfg` value.

## Setting dynamic config

```sh
boatramp config set default_site blog       # one key, converges everywhere
boatramp config get                         # the active config + its generation
boatramp config list                        # the settable keys
boatramp config rollback                    # revert to the previous generation
boatramp config apply -f daemon.json        # replace the whole dynamic config
```

Every write is **validated on the server before it commits**, so a bad value is
rejected once (a `400`) rather than converging a broken config to the fleet. Each
committed config has a **generation** hash; every node reports it at `/healthz`
(`ok gen=<hash>`) so you can confirm convergence.

Addressing a `restart`-class key with `config set` fails with a clear pointer to
`boatramp.cfg` — the old "edit the file, send SIGHUP, nothing happens" trap can't
occur.

## Dynamic keys

| Key | Type | Meaning |
| --- | --- | --- |
| `default_site` | string | Catch-all site for an unmatched `Host`. |
| `protect_previews` | bool | Require a token to view `/_deploy` previews. |
| `max_upload_bytes` | int | Blob-upload cap (bytes). **Clamped by the posture ceiling.** |
| `upload_idle_timeout_secs` | int | Abort an upload stalled this long. |
| `max_concurrent_uploads` | int | Cap simultaneous uploads. |
| `cluster_rate_limit` | bool | Rate-limit via the shared KV instead of per-node. |
| `compute.vcpus` | int | Advertised schedulable vCPUs. |
| `compute.mem_mib` | int | Advertised schedulable memory (MiB). |
| `compute.default_kernel` | KernelRef | Fleet default microVM kernel (see below). |
| `posture.oidc_require_audience` | bool | **Tighten-only**: require an OIDC audience. |
| `posture.ratelimit_fail_open` | bool | **Tighten-only**: set `false` to fail closed. |
| `posture.allow_shared_kernel_compute` | bool | **Tighten-only**: set `false` to forbid shared-kernel compute. |

### Ceilings and the tighten-only ratchet

Two safety rules make these knobs safe to expose at runtime:

- **Numeric caps are clamped by a static ceiling.** A dynamic `max_upload_bytes`
  may only *lower* the effective cap relative to the `boatramp.cfg` posture — it
  can never raise it (and `0` = unlimited is unreachable dynamically unless the
  static ceiling is also `0`). A value over the ceiling is rejected.
- **Posture knobs are tighten-only.** A `posture.*` override may move a knob only
  toward the *safe* value (harden a running fleet, e.g. during an incident). A
  value that would *loosen* it is rejected — loosening always requires the static
  file + a restart. This preserves the invariant that a runtime compromise can
  never relax the security posture.

### `compute.default_kernel` (KernelRef)

A microVM that omits its own kernel boots this fleet default. It is a JSON object:

```json
{ "source": "<blob-hash-or-url>", "sha256": "<content hash>", "sig": "<hex sig>" }
```

The kernel is **verified before boot**, scaled by the posture — see
[Run a container or microVM](../how-to/compute.md#the-kernel-and-its-trust). Set
it with:

```sh
boatramp config set compute.default_kernel '{"source":"…","sha256":"…","sig":"…"}'
```

## Cluster convergence

A dynamic write commits on the leader and replicates by the normal control-plane
path, and every node **reloads on the change notification** (a Raft apply, a
shared-store changelog event, or a SIGHUP) — there is no polling. Confirm every
node converged by checking they all report the same `/healthz` generation.
