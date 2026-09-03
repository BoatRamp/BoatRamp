# Diagnose & work around compute issues

When a co-located workload or managed database misbehaves — a database that is
reachable but "has no healthy replica", a container stuck after launch, two
replicas fighting over one IP — you need to *see* what the reconcile plane
actually believes and, where possible, *fix it live* rather than wait for a new
binary. These operator subcommands give you both.

They are node-global operator instruments: every one is gated at `system·admin`
(a project-scoped token cannot reach them, and cannot read another tenant's
state), except `sql ping`, which is project-owned like the rest of the `sql`
family. Run them with an admin token (`boatramp token mint --role admin`, or your
configured operator token).

## See what the reconcile plane believes

`compute status` prints the *observed* per-replica state — the exact record the
endpoint resolver reads to decide "is there a healthy replica to serve?".

```sh
boatramp compute status              # every workload, every tenant
boatramp compute status pg           # just the `pg` workload
boatramp compute status --format json
```

```
PROJECT/WORKLOAD               REP  HEALTHY  ENDPOINT               PHASE       AGE  BACKEND
acme/pg                          0  NO       10.0.0.2:5432          running     47s  container
```

`HEALTHY=NO` on a `running` replica that *has* an endpoint is the signature of
"reachable but not served": the container is up, but the stored health flag the
resolver gates on says otherwise. Confirm it is genuinely reachable with an
active probe:

```sh
boatramp compute netdiag pg          # node → each replica TCP probe
boatramp sql ping                    # same, for a managed database's replicas
```

```
REP  ENDPOINT               REACHABLE  HEALTHY  PHASE    BACKEND
  0  10.0.0.2:5432          yes        NO       running  container
```

`REACHABLE=yes` + `HEALTHY=NO` means the data plane is fine and the *control*
plane's health record is stale — force-serve it (below). `REACHABLE=NO` points
at a real network or launch fault; keep digging with the IP and DNS views.

## Find an IP collision

If two replicas were handed the same address, the gateway and internal DNS will
route unpredictably. `compute ip ls` lists every replica's assigned IP and flags
duplicates:

```sh
boatramp compute ip ls
```

```
IP                OWNER                           HEALTHY  PHASE
10.0.0.2          acme/pg#0                       yes      running  <-- COLLISION
10.0.0.2          globex/pg#0                     yes      running  <-- COLLISION

1 duplicate IP(s) detected: 10.0.0.2
```

Restart one of the colliding replicas (below) to force a fresh allocation.

## Check internal name resolution

`compute dns ls` shows the internal service-discovery map a co-located guest
resolves — each workload's internal name and the healthy replica IPs it answers
with. An empty answer set means the name currently resolves to nothing.

```sh
boatramp compute dns ls
boatramp compute dns resolve pg      # resolve one name in the --project tenant
```

```
NAME                              REPS  HEALTHY ADDRS
pg.acme                              1  10.0.0.2
web.acme                             2  (none — unresolved)
```

## Work around it live

Three levers, in increasing bluntness:

- **Force a reconcile pass** — the loop converges now instead of at the next
  tick. Use it after fixing config, or to nudge a launch that needs re-attempting:

  ```sh
  boatramp compute reconcile
  boatramp compute status            # read the result
  ```

- **Restart a replica** — stop it and let the reconcile loop relaunch a fresh
  one, re-running IP allocation. The fix for a wedged replica or a collision:

  ```sh
  boatramp compute restart pg 0
  ```

- **Force the stored health flag** — the escape hatch when a recovered replica is
  stuck `healthy=false` (so the resolver won't serve it) and you have confirmed
  with `netdiag`/`sql ping` that it is genuinely up. This edits the control-plane
  record directly:

  ```sh
  boatramp compute set-health pg 0 --healthy true
  boatramp sql query 'SELECT 1'      # the resolver serves it again
  ```

  `set-health` is a manual override, not a fix — if the reconcile loop's own
  probe disagrees on the next pass it will overwrite your value. Use it to restore
  service immediately, then address the root cause.

All of these target the `--project` tenant's workload; pass `--project <name>`
(or set `BOATRAMP_PROJECT`) to act on a specific tenant.
