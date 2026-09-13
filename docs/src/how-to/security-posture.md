# Choose & inspect a security posture

The **security posture** is the operator's trust model, resolved at startup from
`boatramp.cfg`. It decides defaults for hazards a site writer must not control:
whether a public bind may run without auth, upload and component size caps,
whether a site may reach private-network upstreams, whether compute may share
the host kernel, and whether a database-opening handler may skip an in-site
[tenancy declaration](./tenant-isolation.md) or reach across tenants. The posture
is operator-only — it is never part of site config,
so a `site-write` principal cannot relax it. For why the model exists, see
[The security posture model](../explanation/security-posture.md).

## Pick a profile

Set `security.profile` in `boatramp.cfg`:

```ron
security: ( profile: "single-tenant" )
```

| Profile | For |
| --- | --- |
| `multi-tenant` (default) | untrusted site writers on an untrusted network — strict. |
| `single-tenant` | one operator who owns every site — relaxed. |
| `dev` | local development — loopback-loose. |

A profile is sugar over the individual knobs; the knobs are the source of truth.

## Override individual knobs

Layer `overrides` on the profile to tune one setting without leaving the strict
baseline:

```ron
security: (
    profile: "multi-tenant",
    overrides: (
        max_upload_bytes: 104857600,        // 100 MiB (0 = unlimited)
        allow_site_private_upstreams: true, // let sites' gateways reach private IPs
    ),
)
```

The full knob list is in the
[boatramp.cfg schema](../reference/boatramp-cfg.md#security).

## Per-project overrides (v0.4.7)

The four **tenancy/capability** knobs — `require_tenancy_declaration`, `allow_cross_tenant_db`,
`allow_guest_mint_capability`, `max_guest_capability_ttl_secs` — can be overridden **per project**,
so one serve process can host a strict-isolation project beside a looser one on a shared,
multi-project machine:

```ron
security: (
    profile: "multi-tenant",                 // the fleet default
    projects: {
        "acme-preview": (                     // looser, just for this project
            allow_cross_tenant_db: true,
            allow_guest_mint_capability: true,
        ),
    },
)
```

Only these four in-project knobs are per-project; every other knob (egress, upload caps, domain
verification, …) stays fleet-wide. **Cross-project isolation is structural** (project = database) —
never a knob, so a per-project override can only tune that project's own in-project strictness and
its guests' capability-mint ceiling, never its reach into another project. The three knobs
**compose**: you can require an explicit tenancy declaration *and* permit specific components to be
`all` *and* allow guest capability minting, all at once.

These four knobs (and the other posture bools) are also `BOATRAMP_SECURITY_*` env-settable — e.g.
`BOATRAMP_SECURITY_ALLOW_CROSS_TENANT_DB=true` — so a 12-factor deploy needn't ship a `boatramp.cfg`
just to tune them. (Per-project overrides are config-file only.)

## Inspect the resolved posture

`security explain` prints the effective posture — every knob's value and where it
came from (profile or override):

```sh
boatramp security explain --config boatramp.cfg
```

```text
posture: multi-tenant (+2 overrides)
  allow_unauthenticated_public_bind  false   (profile)
  max_upload_bytes                   104857600  (override)
  allow_site_private_upstreams       true    (override)
  allow_shared_kernel_compute        false   (profile)
  …
```

Run this before exposing a server: it is the authoritative answer to "what will
this server allow?"

## Define a named profile

For a reusable posture, declare it under `profiles` and select it:

```ron
security: (
    profile: "ci",
    profiles: {
        "ci": ( allow_unauthenticated_public_bind: true ),
    },
)
```

Each named profile is a set of overrides layered over the strict multi-tenant
baseline.
