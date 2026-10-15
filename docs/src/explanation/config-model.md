# The configuration model

boatramp's configuration lives in two tiers, and the split is intentional: it is
drawn by **what should be operator-changeable at runtime** versus **what is a
trust anchor a runtime compromise must not be able to touch**.

## The two tiers

**Static (`boatramp.cfg`).** A per-node file, read once at `serve` startup. It
holds the trust anchors and listener shape: the auth root key / external signer,
the bootstrap secret, TLS, the bind address, the cluster identity, and the
`[security]` posture. Changing any of it needs editing the file and **restarting**
the process. The restart is a feature, not a limitation — a bad file fails fast at
boot, and, crucially, *changing it requires host access*, a stronger credential
than any API token.

**Dynamic (the control plane).** Operational knobs stored in the KV, changed
through the authenticated API with [`boatramp config`](../reference/daemon-config.md).
A write **converges fleet-wide without a restart** — it replicates like any
control-plane object, and every node reloads on the change notification. This is
the tier for the settings an operator actually retunes: the default site, upload
caps, and the fleet [default microVM kernel](./compute-model.md).

The server runs on `effective = file baseline ⊕ dynamic overrides`.

## Resolving the static config

The static `boatramp.cfg` baseline is itself resolved by **one layered pipeline**, lowest to
highest precedence:

```
built-in defaults  →  config file (boatramp.cfg, RON or JSON)  →  BOATRAMP_* environment  →  explicit CLI flags
```

A later layer wins per field. So an env var overrides the file, and a flag you actually type
on the command line overrides both — while a flag left at its default never shadows the file
or env. You can configure a node entirely from the environment (no `boatramp.cfg` at all), or
from a file, or any mix.

**The env surface is uniform across every subcommand.** The same `BOATRAMP_*` variables that
configure `boatramp serve` now also configure the offline operations — `boatramp migrate`,
`boatramp blob …`, `boatramp token …` — which previously ignored most of them. For example
`BOATRAMP_BLOBS` / `BOATRAMP_S3_BUCKET` (and the whole `[serve]` + `[serve.kv]` surface) are
honored by `blob migrate` and `migrate` with no config file, exactly as by `serve`. The env
variable names are unchanged.

Inspect what a node would resolve with [`boatramp config dump`](#inspecting-the-resolved-config).

### Precedence and parsing notes

- **Empty is unset.** `VAR=` (empty or whitespace-only) is treated as unset — it never
  clobbers a file value with `""`.
- **Booleans** accept `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off` (case-insensitive), with
  surrounding whitespace trimmed (so a templated `"true\n"` still parses).
- **Lists** (e.g. kernel trust anchors, the SQL migration extension allowlist) are
  comma-separated, trimmed, with empty items dropped.
- **Dynamic-keyed maps** are populated by scanning the environment:
  `BOATRAMP_HANDLERS_SQL_DB_<NAME>_<FIELD>`, `BOATRAMP_SERVE_BLOB_BACKEND_<PROJECT>_<FIELD>`,
  `BOATRAMP_SERVE_LISTENER_<NAME>_<FIELD>`.
- **A malformed value fails loudly at startup** — a non-numeric number, an unknown enum, a bad
  address is rejected, never silently defaulted.
- **Validation runs on the merged result:** a `[cluster]` section is rejected if it has no
  `listen`, and the SQL-db-name / blob-project / listener checks run over the fully merged
  (file + env + flags) config, so an invalid entry from any layer fails closed at boot.

### Inspecting the resolved config

`boatramp config dump [--file boatramp.cfg] [--explain]` prints the fully resolved static
config (file + `BOATRAMP_*` env) as JSON, with the **secret-bearing fields redacted** (the auth
root key, bootstrap secret, azure access key, external-signer key, sealed-credential refs, and
`cluster.join_token` show as `<redacted>`). It is client-side — no server is contacted — and is
the quickest way to see what a node *would* load. (This is distinct from `boatramp config
get`/`set`, which read and write the live **dynamic** config over the control-plane API.)

## Why the anchors stay static

The static file's security value is that **mutating it needs host access, not an
API token**. If the trust anchors or the trust-*relaxing* posture knobs were
API-writable, a single stolen admin token — or a compromised cluster leader —
could re-root trust or disable a defense across the whole fleet. So those settings
are deliberately *not* fields of the dynamic config: the burden of proof is on
making a knob dynamic, not on keeping it static.

Two rules keep the dynamic tier safe even for the knobs that *are* exposed:

- **Static ceilings.** A dynamic numeric cap may only move *within* the posture's
  bound — it can tighten, never exceed it.
- **Tighten-only posture.** A dynamic `posture.*` override may only move a knob
  toward the safe value (harden a running fleet); loosening always requires the
  file + a restart.

So an operator gets no-restart, cluster-wide changes for the things they retune,
without any trust boundary moving onto the network-reachable tier.

## Change class

Every setting has a **change class** you can query:

| Class | Where | How to change |
| --- | --- | --- |
| `dynamic` | KV / control plane | `boatramp config set …` — fleet-wide, no restart |
| `restart` | `boatramp.cfg` | edit the file on each node + restart |

`boatramp config describe <key>` reports a key's class, and `config set` on a
`restart`-class key fails with a pointer to `boatramp.cfg` — so editing the file
and expecting a live reload can't silently do nothing.

See the [dynamic daemon config reference](../reference/daemon-config.md) for the
full key list, ceilings, and the ratchet.
