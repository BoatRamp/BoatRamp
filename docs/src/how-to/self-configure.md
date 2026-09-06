# Let an app configure its own project

Some apps need to reconfigure **their own project** from inside the sandbox — a SaaS
adding a customer's custom domain, a setup wizard writing its own SMTP profile, an
installer rotating a secret. The usual way is to embed a `project_admin` bearer token
in the app and call the admin API — but that's a standing, over-broad credential you
have to rotate forever.

The `admin` capability replaces the token. A guest imports the specific config
**surfaces** it needs; boatramp confers the power at **deploy time** (grant + posture),
bounded to the guest's **own project** and the granted surfaces, with **nothing to
rotate**. It is strictly *less* authority than a project-admin token: no cross-project
reach, no critical/node ops, verb-scoped, rate-limited, and audited.

This is the "manage config" companion to [`email`](./send-email.md) (send) and
[`secrets`](./secrets.md) (use): those let a guest *use* managed config; `admin` lets a
guest *manage* a curated slice of it.

## The four surfaces

Each surface is a separate grant (`admin:<surface>`); a bare `admin` grants nothing.

| Surface | Grant | Verbs |
|---|---|---|
| Domains | `admin:domains` | `domain-add`, `domain-verify`, `domain-remove`, `domain-list` |
| Email | `admin:email` | `email-set`, `email-delete`, `email-list` |
| Site config | `admin:site` | `site-config-get`, `site-config-put` |
| Secrets | `admin:secrets` | `secret-set`, `secret-delete`, `secret-list` |

**What is never reachable:** project create/delete, tokens, authz policy, root
anchors, cluster membership, blobs, cache purge, prune/scrub, daemon config, `compute
exec`, `sql exec/query`, and all node-global compute (volumes/DNS/IPAM/…). There is no
verb and no binding for any of these — ever.

## Grant it

Add the surface(s) to the handler/function `imports` in the routing manifest, and to
the site's `allow_imports` ceiling. The effective grant is the intersection:
`imports ∩ allow_imports ∩ posture`.

```ron
// routing manifest — the handler declares what it needs
handlers: [(
  route: "/admin/*",
  component: "setup.wasm",
  imports: ["admin:domains", "admin:email"],   // this handler self-configures domains + email
)],
```

```sh
# the site's ceiling must also permit those surfaces
boatramp handlers set --site app --allow-imports admin:domains,admin:email
```

Declare the requirement in a function manifest's `requires` too, so a deploy is
**refused** on a host where the posture disables `admin`, rather than failing at first
call.

## Use it from a guest

```wit
use boatramp:handlers/admin.{domain-add, domain-verify, email-set};
use boatramp:handlers/admin-types.{email-profile};
```

Add a customer's custom domain (the guest never holds a token):

```rust
// 1) start verification — returns the challenge token to publish
let challenge = domain_add("app", "shop.customer.com", "http")?;
//    publish `challenge.token` at the challenge location for the customer's domain
//    (a /.well-known/… file for http, a TXT record for dns)

// 2) prove ownership — boatramp runs the SAME real-network probe as the normal flow
if domain_verify("app", "shop.customer.com")? {
    // verified + attached: routing now serves shop.customer.com for site "app"
}
```

Set an SMTP profile (a create-or-merge; unset fields keep the stored value, exactly
like [`boatramp email set`](./send-email.md)):

```rust
email_set("default", &EmailProfile {
    host: Some("smtp.example.com".into()),
    port: Some(587),
    security: Some("starttls".into()),
    username: Some("apikey".into()),
    password: Some(secret_from_your_config),   // sealed host-side; never returned
    from: Some("no-reply@customer.com".into()),
    durable: None,
    clear_auth: false,
})?;
```

The `site` argument on the domain/site verbs must be one of the **guest's own
project's** sites — it is validated within the host-stamped project, so a crafted
string can't reach another tenant (or another project).

## Invariants (why it's safe to hand config power to untrusted code)

- **Project-scoped, host-stamped.** The controller is bound to the guest's own project
  at instantiation (never from guest input). Cross-tenant configuration is
  *structurally impossible*, not merely checked — the project is the un-escapable KV
  key prefix.
- **Domain ownership stays proven.** `domain-verify` runs the same real-network probe
  as the normal flow; a wildcard still needs DNS-01. There is **no** guest path to
  attach an unverified domain (that route is `System·Admin` only). A `site-config-put`
  that references a not-yet-verified domain is refused for the same reason.
- **Deny-by-default, per-surface.** Only the granted, site-allowed surfaces attach;
  an ungranted verb is `access-denied`.
- **Write-only credentials.** A guest may *set* an SMTP password or a secret, but no
  verb ever returns a password/secret value — reads are redacted name lists only.
- **Rate-limited + audited.** Every operation is charged to a per-project quota
  (sustained 2/s, burst 20 — config changes are rare), and every mutation writes a
  structured audit record (project, surface, verb, target, outcome) to the host's
  `boatramp::audit` log target — never the rate-capped guest log stream, so an audit
  event is never dropped.

## Security posture

The `admin` capability is governed per surface by the
[posture](./security-posture.md) knobs `allow_guest_admin_domains`,
`allow_guest_admin_email`, `allow_guest_admin_site`, and `allow_guest_admin_secrets`:
**all off under `multi-tenant`** (untrusted tenants can't self-configure until the
operator opts in), **all on under `single-tenant`/`dev`**. When a surface's knob is
off, no binding for it attaches and its verbs return `access-denied`. Override an
individual knob (e.g. enable only `admin:domains` fleet-wide) the same way as any
posture field — see [Choose & inspect a security posture](./security-posture.md).

> **Email/secrets surfaces need a `[secrets]` envelope.** `admin:email` and
> `admin:secrets` seal values at rest, so they require a `[secrets]` envelope — see
> [Encrypt secrets at rest](./secrets-at-rest.md). Without one those verbs fail closed
> with a clear message; `admin:domains`/`admin:site` work regardless.

## See also

- [Send email from a function or handler](./send-email.md) — the `email` *use* capability the `admin:email` surface configures.
- [Give handlers & functions secrets](./secrets.md) — the sealed store `admin:secrets` writes into.
- [Attach a custom domain](./custom-domain.md) — the operator-side flow `admin:domains` mirrors.
- [Choose & inspect a security posture](./security-posture.md) — the `allow_guest_admin_*` knobs.
