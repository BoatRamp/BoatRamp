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
