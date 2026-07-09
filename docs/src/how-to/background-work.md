# Run consumers, crons, and streams

Background work runs as WebAssembly handlers that boatramp invokes for you
instead of per HTTP request: **consumers** process messages off a topic, and
**crons** invoke a route on a schedule. You declare each one in the `routing`
section of `project.cfg`, pointing it at a handler, and boatramp runs it for the
live deployment. For the component build and site policy, see
[Deploy a handler](./deploy-handler.md).

## Declare a consumer

A consumer is invoked once per message on its `topic`. Give it a retry budget: a
message that fails is retried up to `max_attempts` times, then dead-lettered.

```ron
routing: (
    consumers: [
        ( topic: "emails", component: "mailer.wasm",
          imports: ["sql", "wasi:messaging"],
          max_attempts: 5 ),
    ],
),
```

## Declare a cron

A cron invokes an existing route on a schedule, using a standard five-field cron
expression. The route runs as if a request arrived for it:

```ron
routing: (
    crons: [
        ( schedule: "0 * * * *", route: "/api/rollup" ),
    ],
),
```

Sync to activate the new routing. Each component is validated at `sync`:

```sh
boatramp sync ./dist --site my-site
```

```text
validated mailer.wasm — consumer topic "emails"
activated my-site -> a1b2c3d4
```

## Operate the dead-letter queue

When a message exhausts `max_attempts`, boatramp dead-letters it and retains the
payload until you clear it. Once you have fixed the cause, requeue the
dead-lettered messages onto the live topic:

```sh
boatramp dlq redrive emails --site my-site
```

```text
redrive: 12 dead-lettered message(s) on topic "emails"
```

If the messages are unrecoverable, drop them and reclaim the space instead:

```sh
boatramp dlq purge emails --site my-site
```

```text
purge: 12 dead-lettered message(s) on topic "emails"
```

To scope either command to a background alias rather than the live site, add
`--alias {site}/{alias}`.

## Watch lag and dead-letters

Check consumer backlog and dead-letter counts with `boatramp stats`:

```sh
boatramp stats --site my-site
```

```text
site my-site
  queue/emails   invocations 512   errors 1   lag 0   dead-letters 0
```

A growing `lag` means consumers are falling behind the incoming rate; a nonzero
dead-letter count is messages waiting for you to redrive or purge. For tailing
guest output and the full metric surface, see
[Observe a running server](./observe.md).
