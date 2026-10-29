# Alert on node & system health

A slow-building node failure — a `/data` volume quietly filling to 100%, a managed
Postgres replica stuck `HEALTHY=NO`, replicas the reconcile plane has stranded — should
be caught *early*, not discovered as an outage. boatramp's node/system-health alerting is
a **daemon-side, leader-gated** facility that evaluates these signals on a cadence and
tells you when a threshold is crossed (and when it clears).

It comes in two parts:

- **Observe (read-only).** `GET /api/node-health` and `boatramp stats --instances` expose
  the raw figures (`/data` used/total, per-subtree breakdown, unhealthy replicas) so an
  external monitor can scrape them. This needs no configuration.
- **Alert (this page).** A `[serve.alerts]` block turns on an evaluation loop that pushes
  an alert to an operator **webhook** and/or **email** when a signal crosses a threshold,
  and a **resolve** when it clears — de-duplicated so a sustained condition does not flood.

Everything here is host/daemon-side. There is **no guest-facing change** — guests are
unaware of it.

## Turn it on

Alerting is **off by default**. Enable it with a `[serve.alerts]` block in `boatramp.cfg`
(RON) — thresholds, cadence, and channels are all operator-set:

```ron
serve: (
    // …
    alerts: (
        enabled: true,
        interval_secs: 60,                              // cadence; default 60, floored at 5
        disk: ( warn_pct: 75.0, critical_pct: 90.0 ),   // /data fullness
        managed_sql: ( grace_secs: 300 ),               // a desired replica HEALTHY=NO past 5m
        orphan: ( grace_secs: 86400 ),                  // orphaned replicas past 1d
        webhook: ( url_secret: "boatramp:node-alert-webhook" ),
        email: ( project: "default", profile: "alerts", to: ["ops@example.com"] ),
    ),
),
```

Every knob is also an environment variable (the `serve` segment dropped), so a file-less
fleet can configure it entirely from the environment — e.g.
`BOATRAMP_ALERTS_ENABLED=true`, `BOATRAMP_ALERTS_DISK_WARN_PCT=75`,
`BOATRAMP_ALERTS_WEBHOOK_URL_SECRET=boatramp:node-alert-webhook`. See the
[boatramp.cfg schema](../reference/boatramp-cfg.md) and the
[environment-variable reference](../reference/env.md) for the full list.

The loop is **leader-gated**: in a cluster only the leader evaluates and delivers, so a
three-node fleet pages once, not three times. A single node is always its own leader.

## The signals

1. **`/data` fullness** — `used_pct = (total − free)/total`. Warns at `warn_pct` (default
   75%), critical at `critical_pct` (default 90%). This is the signal whose absence hid the
   motivating incident: a 100%-full `/data` stopped managed Postgres from creating its
   sandbox and failed every DB-backed request, with no page.
2. **Managed-SQL / compute replica health** — a replica that *has* a desired workload (so
   it is supposed to be serving) but is `phase=running` + `HEALTHY=NO` for longer than
   `managed_sql.grace_secs`. This is the "the database is down" page.
3. **Orphaned compute replicas** — a replica with **no desired workload** and **no live
   container**, stranded past `orphan.grace_secs`. These are what the reaper (below) cleans.

Each alert/resolve carries `{signal, severity, current_value, threshold, node, timestamp}`
plus an `event` (`alert`/`resolve`) and a `subject` (e.g. `default/pg/0`).

## Deliver over a webhook

The webhook URL is **never written in plaintext** — it is a sealed-store reference,
resolved server-side at send time exactly as the S3 credential is. Seal it once:

```sh
boatramp secrets set node-alert-webhook 'https://hooks.example.com/services/XXX/YYY'
```

Then point the config at it with `webhook: ( url_secret: "boatramp:node-alert-webhook" )`.
The POST body is the JSON event shape above. The egress goes through boatramp's **SSRF
floor**: the URL must be `https`, carry no userinfo, and resolve to a globally-routable
address. An operator webhook on a **private** address (an internal collector) is refused
unless you explicitly set `webhook: ( allow_private: true )` — so an alert webhook can
never be turned into an SSRF probe against internal services by default.

## Deliver over email

Email reuses boatramp's existing mail path. Create a per-project email profile (its SMTP
password is sealed in the profile record, never in `boatramp.cfg`):

```sh
boatramp email set alerts --project default \
  --host smtp.example.com --port 587 --security starttls \
  --from alerts@example.com --username apikey --password-stdin
```

Then name it: `email: ( project: "default", profile: "alerts", to: ["ops@example.com"] )`.

You can configure the webhook, email, or both. With neither, the loop still *evaluates*
(so a misconfiguration is visible in the logs) but logs a startup warning that it has
nowhere to deliver.

## Reap stranded replicas

Signal 3 alerts on orphans; the **reaper** cleans them. It is **destructive** — it drops a
replica's record and tears down its (dead) container — so it is conservative by
construction:

- **opt-in** (`reaper.enabled: false` by default);
- **dry-run by default** (`reaper.dry_run` absent ⇒ `true`: it logs/alerts what it *would*
  reap and changes nothing until you set `dry_run: false`);
- it **never reaps a replica that is live or part of a desired spec** — only one with no
  desired workload *and* an affirmatively-gone container, re-checked at the instant of the
  reap (fail-closed: if liveness can't be proven, it is left alone);
- grace-gated (`reaper.grace_secs`, default 7 days — strictly longer than the orphan alert
  grace, so you are paged well before anything is destroyed);
- it **preserves volume staging** (a stranded PGDATA) unless you opt in with
  `reaper.reclaim_volumes: true`;
- every reap is audited (a `tracing` record per replica).

```ron
reaper: ( enabled: true, dry_run: false, grace_secs: 604800, reclaim_volumes: false ),
```

### The manual lever

You can also reap on demand with the CLI (System·Admin). It is **dry-run unless
`--execute`** and applies the same fail-closed checks even for a replica you name:

```sh
# Report every orphan across the node (changes nothing):
boatramp compute reap

# Reap one specific stranded replica:
boatramp compute reap pg-construens_27s1vdlphqoa85d0g3ls5iqfc --replica 0 \
  --project construens --execute

# …and also free its stranded PGDATA staging:
boatramp compute reap <workload> --replica 0 --project <p> --execute --reclaim-volumes
```

A replica that is live, still has a desired workload, or is younger than the grace is
reported as `skipped` with the reason — it is never destroyed.

## Scrape it instead (pull)

`GET /api/node-health` (admin-scoped, `System·Read`) returns the same signals for an
external monitor that would rather poll:

```sh
boatramp api GET /api/node-health | jq
```

```json
{
  "data_bytes_total": 10737418240,
  "data_bytes_used": 9663676416,
  "data_used_pct": 90.0,
  "data_breakdown": { "kv-slate": 8400000000, "handlers-sql": 900000000 },
  "replicas_unhealthy": [ { "project": "construens", "workload": "pg", "replica": 0, "age_secs": 2937600 } ]
}
```

## Authorization

The node-health read is `System·Read`. The reaper (CLI + `POST
/api/compute/maintenance/reap`) and the alerting configuration are **node-global**:
gated `System·Admin` by an explicit authz arm, never a per-project right — a project-scoped
token can never reap another tenant's replica or read node-wide disk/health.
