# Give handlers & functions secrets

A site handler or a function often needs a secret — a third-party API key, a
database URL, a signing token — that must **not** live in the committed config.
boatramp handles this with a `secrets` map whose values are *references*, not
values: the reference is resolved **server-side at instantiation** and injected
into the guest's environment; the secret itself never lands in the manifest, a
log, or an API response.

```ron
// in a site's [handlers] config, or a function's config
secrets: {
    "STRIPE_KEY": "boatramp:stripe-key",   // ← from the sealed internal store
    "DATABASE_URL": "env:DATABASE_URL",     // ← from the serve process env
}
```

The guest sees `STRIPE_KEY` / `DATABASE_URL` in its environment; the config only
ever carries the left-hand names and the right-hand **reference**.

## The reference schemes

A `secrets` value is parsed by its scheme (the part before the first `:`); a
value with **no** colon is a bare host-env var name.

| Reference | Resolves to | Allowed when |
|---|---|---|
| `env:NAME` or bare `NAME` | the **serve process's own** environment variable `NAME` | single-tenant / dev only |
| `boatramp:NAME` | the project-scoped **sealed internal store** (below) | always (multi-tenant-safe) |
| `vault:…`, `aws:…`, any other `scheme:` | reserved for a future resolver | **refused** ("not yet supported") |

A missing referent (an unset env var, or a `boatramp:` secret that isn't set) is
logged and **skipped** — never injected as an empty value. Any scheme boatramp
doesn't resolve is refused rather than misread as a host var, so a value with a
colon is never silently treated as an environment variable.

### Why `env:` is gated to single-tenant

An `env:` / bare reference reads the **operator's** process environment — the
namespace that also holds other tenants' credentials, the managed-database
superuser password, and cloud keys. When the config author is the operator
(single-tenant, dev) that's fine. Under the **multi-tenant** posture the config
author is an untrusted tenant, so a bare/`env:` reference is **refused,
fail-closed** (the host environment is never even read) — otherwise a tenant
could name any host variable and exfiltrate it. Multi-tenant deployments use
`boatramp:` instead, which resolves only within the tenant's own project.

## The internal store: `boatramp secrets`

`boatramp:NAME` reads from boatramp's own **project-scoped, sealed** secret
store. Values are sealed at rest with the [`[secrets]` key
envelope](./secrets-at-rest.md) (the same one that wraps certificate keys and
managed-database credentials) and stored per project, so a `boatramp:` reference
resolves **only** within its own project — never another tenant's secrets, never
the host environment.

Set a secret (the plaintext is sealed **server-side** — the CLI never holds the
KEK, and the value is never written to the manifest or echoed back):

```sh
# preferred: read the value from stdin or a file (no shell-history trail)
printf '%s' "$STRIPE_KEY" | boatramp secrets set stripe-key --stdin
boatramp secrets set stripe-key --file ./stripe.key

# convenient, but leaves the value in shell history / the process table:
boatramp secrets set stripe-key --value sk_live_…
```

List (names + metadata only — **there is no way to read a value back**):

```sh
boatramp secrets ls
```
```text
NAME                              REVISION  UPDATED
stripe-key                               2  1724980000
```

Rotate (an alias for `set` — overwrites, bumps the revision) and remove:

```sh
printf '%s' "$NEW_KEY" | boatramp secrets rotate stripe-key --stdin
boatramp secrets rm stripe-key
```

All of these are **project-scoped** via the global `--project` flag (default
`default`); managing secrets requires a project-admin (or global-admin) token —
a publisher can *reference* `boatramp:stripe-key` but only an admin provisions
it.

> **Requires a `[secrets]` envelope.** The store seals every value, so the
> secret commands (and any `boatramp:` reference) need a `[secrets]` envelope
> configured — see [Encrypt secrets at rest](./secrets-at-rest.md). Without one
> the API replies `501` with a clear message. In a cluster, every node needs the
> same KEK (or Vault Transit) to unwrap, exactly as for certificate keys.

## See also

- [Encrypt secrets at rest](./secrets-at-rest.md) — the envelope that seals the store.
- [Use kv / sql / blobstore / messaging](./handler-bindings.md) — the other guest bindings.
- [Deploy & invoke a function](./functions.md) — a function's `secrets` map works identically.
