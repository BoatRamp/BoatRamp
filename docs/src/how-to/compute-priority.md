# Prioritize & preempt compute workloads

When a node runs out of capacity, boatramp decides **which workloads get the scarce
CPU/memory** using a two-axis priority on each workload. On a contended node a
higher-priority workload can **preempt** (evict) a lower-priority one to make room; when
capacity frees up, the evicted workload is re-placed automatically.

Priority lives on the **mutable workload**, never on the content-addressed spec — so
re-prioritizing is a cheap pointer update that never stops or relaunches a running replica.

## The two axes

| Axis | Who owns it | What it does |
|------|-------------|--------------|
| **class** | the operator (cross-tenant) | names a **tier** — `system`, `standard` (default), or `spot` |
| **rank** | you, the tenant | orders **your own** workloads only; a bigger rank can never leapfrog another project |

The global ordering is **tier → project → rank → name**. Because `project` outranks `rank`,
your rank only reshuffles *your* workloads — it can never jump ahead of another tenant.

### The built-in classes

| Class | Tier | Preemption authority | Preemptible as a victim |
|-------|------|----------------------|-------------------------|
| `system` | highest | may preempt **across tenants** (operator-reserved) | no (protected) |
| `standard` | middle (default) | preempts only **within its own project** | no by default (protected at its replica count) |
| `spot` | lowest | within its own project | **yes, freely** |

An un-annotated workload is `standard`, rank 0 — so turning this feature on changes the
relative order of nothing and evicts nothing.

## Set a workload's priority

```console
# A best-effort batch job: lowest tier, freely preemptible.
$ boatramp compute set batch --image ghcr.io/acme/crunch:1 --port 0 --priority-class spot

# Order your own workloads with rank (tenant-owned; never crosses a project boundary).
$ boatramp compute set api --image ghcr.io/acme/api:1 --port 8080 --priority-rank 100

# Protect a workload from preemption with a minimum-available floor (PodDisruptionBudget-style).
$ boatramp compute set api --image ghcr.io/acme/api:1 --port 8080 --replicas 3 --min-available 2
```

A **project** may only request a class at or below its **ceiling** (default `standard`), so a
tenant can never self-assign `system`. Requesting above the ceiling is refused, naming the
allowed maximum:

```console
$ boatramp compute set api --image … --priority-class system
error: priority class `system` (tier 100) exceeds this project's ceiling `standard` (tier 0);
       the operator must raise the project ceiling to allow it
```

An operator raises a trusted project's ceiling alongside its backend policy:

```console
$ boatramp compute policy set --project trusted-team --priority-ceiling system
```

## Preview the blast radius before committing (`--dry-run`)

`--dry-run` previews which replicas a priority **would** evict, without applying anything. A
tenant view aggregates cross-tenant impact (it never names another project's workloads); the
operator view names them.

```console
$ boatramp compute set api --image … --priority-class system --dry-run
DRY-RUN: priority for `api` → class system (tier 100; project ceiling: system)
nothing was applied.
would EVICT (your project):
  worker rep 0 on node 2 (2vcpu/2048MiB)
could also displace 3 lower-priority replica(s) across 2 other project(s), freeing up to
  6vcpu/6144MiB (identities withheld)
```

## How preemption works

- **Triggered by pressure.** Preemption only fires when a higher-priority workload can't be
  placed and freeing a lower-priority replica would let it fit.
- **Dry-run-before-evict.** boatramp never evicts a victim it can't actually use — it proves
  the preemptor fits *after* the eviction first. This is also what keeps placement from
  oscillating.
- **Tenancy boundary.** Within a project, a strictly-higher-rank workload may preempt a
  lower one. **Across** projects, only a `system`-tier workload (operator-opted) ever reaches
  another tenant — two `standard` tenants are fully isolated and never preempt each other.
- **`min_available`.** Preemption won't drop a workload below its floor within its own
  tier (a hard limit); a strictly-higher operator tier may override it (advisory), so a
  `system` workload can still displace a node-hogging lower tier.
- **Disposition.** A scale-to-zero-capable victim is **parked** (snapshot → zero) and wakes
  automatically when capacity frees; otherwise it is **drained** (graceful stop; its volume
  survives) and re-placed on a later pass.

Delegated backends (`cloudflare`, `kubernetes`) never participate in boatramp's own preemption
— boatramp owns neither their capacity nor their eviction. For Kubernetes, a workload's tier is
instead mapped to a native k8s `PriorityClass` (`boatramp-<class>`) on the generated
Deployment/StatefulSet, so the cluster's own scheduler honors the ordering. (The operator
creates those PriorityClass objects once, with values that mirror the boatramp tiers.)

## See what happened

`compute status` shows a **PRI** column (the class) and a **REASON** column for non-running
replicas (`PREEMPTED` / `OUTBID` / `INSUFFICIENT` — never a bare "unresolved"):

```console
$ boatramp compute status
PROJECT/WORKLOAD   REP  PRI       HEALTHY  ENDPOINT      PHASE    READINESS   REASON       AGE  BACKEND
acme/api             0  system    yes      10.0.0.5:80   running  provisioned -            30s  container
acme/worker          0  spot      NO       10.0.0.6:80   running  preempted   PREEMPTED    5s   container  (preempted by a higher-priority workload)
```

`compute events <workload>` prints the durable, attributed eviction timeline:

```console
$ boatramp compute events worker
preemption events for worker:
  replica 0 (node 2) EVICTED — preempted by a higher-priority workload
```

`compute get <workload>` prints the resolved priority above the desired state:

```console
$ boatramp compute get api
priority: system (tier 100; rank 0)
{ … }
```
