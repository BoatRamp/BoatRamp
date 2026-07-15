# Orchestrate functions with workflows

A **workflow** chains functions into a small DAG with durable state, retries,
barrier joins, and on-failure compensation. Reach for one when a job is several
steps that must run in order (or fan out and rejoin) and you want the run to
survive a restart and roll back cleanly if a step fails. For single calls, invoke a
[function](./functions.md) directly; a workflow is the multi-step case.

A workflow is deliberately small — a DAG of function invocations, not a general
BPMN engine. Each **step** invokes one function's active version; edges are
`depends_on`.

Writes need `system·admin`; reads need `system·read`.

## Define a workflow

Write the steps as JSON and define the workflow by name:

```json
[
  { "id": "extract", "function": "pull-orders" },
  { "id": "transform", "function": "normalize", "depends_on": ["extract"] },
  { "id": "load", "function": "write-warehouse", "depends_on": ["transform"] }
]
```

```console
$ boatramp workflow define etl --file ./etl.json
defined workflow etl
```

The DAG is validated on define — unique step ids, resolvable dependencies, and no
cycles. A cycle (or a dangling dependency) is rejected with `400`.

### Chain, fan-out, and fan-in

The edges express the shape:

- **Chain** — a linear `depends_on` (`a` → `b` → `c`).
- **Fan-out** — several steps that each `depends_on` the same upstream step; they
  become ready together.
- **Fan-in / barrier join** — a step that `depends_on` *many* steps runs only once
  **all** of them have succeeded.

```json
[
  { "id": "root", "function": "seed" },
  { "id": "a", "function": "work", "depends_on": ["root"] },
  { "id": "b", "function": "work", "depends_on": ["root"] },
  { "id": "join", "function": "reduce", "depends_on": ["a", "b"] }
]
```

A step receives the run's input (root steps) or a JSON object mapping each
dependency's id to its output (downstream steps), as its request body.

## Start and poll a run

```console
$ boatramp workflow run etl --data '{"since":"2026-07-01"}'
started run 9c1e… [running]

$ boatramp workflow run-status etl 9c1e…
9c1e…  [succeeded]
  extract: succeeded (attempts=1)
  transform: succeeded (attempts=1)
  load: succeeded (attempts=1)
```

A run is durable: the executor advances it on the server's scheduler, so it
continues across restarts, and in a cluster each run is driven by the leader
exactly once.

## Retries and compensation

Give a step a retry budget and a compensation function:

```json
[
  { "id": "charge", "function": "charge-card", "retry": { "max_attempts": 3 },
    "compensate": "refund-card" },
  { "id": "ship", "function": "create-shipment", "depends_on": ["charge"] }
]
```

- A failed step is retried up to `max_attempts` (default `1` = no retry). A
  delivery failure is a `5xx` from the engine (a trap, timeout, or a missing
  component); a response the function itself returns — even a `4xx` — counts as a
  successful delivery.
- When a step finally fails, the run **fails** and each already-succeeded step's
  `compensate` function runs **in reverse completion order** — the saga rollback.
  In the example, a failed `ship` triggers `refund-card` for the completed
  `charge` step, which is then marked `compensated`.

## Manage definitions

```console
$ boatramp workflow ls
etl  (3 steps)

$ boatramp workflow get etl
etl
  extract -> pull-orders
  transform -> normalize  (after extract)
  load -> write-warehouse  (after transform)

$ boatramp workflow rm etl
removed workflow etl
```

Removing a definition leaves past runs as history; [`prune`](./prune-scrub.md)
clears them.
