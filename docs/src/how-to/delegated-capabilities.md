# Mint a delegated capability

Sometimes a guest wants to hand a **scoped, time-bounded read** of its own project's public
data to another party — an embed, a share link, an agent-to-agent handoff — or to narrow a
single client's access within a tenant. The usual reach for this is a bearer token, but
minting a boatramp token from inside the sandbox would be a standing, over-broad credential,
and it would force the guest to name a tenant it should never be able to name.

The `capability` capability replaces that. A guest **attenuates a bounded slice of its own
authority** into a fleet-signed (COSE) bearer it can give away: the token names a target
tenant `B`, a public subset, and an opaque app-context, and is redeemable **only at the
minting project**, over that project's own data. The guest never sees the signing key and
never gets more authority than the project already holds — this is object-capability
delegation, not token minting.

It pairs with a [target field](./graphql.md#cross-tenant-target-fields): the party you hand
the token to redeems it as the `via: [capability]` source, and the host confines the read to
tenant `B`.

## Mint it from a guest

Import `boatramp:handlers/capability` and call `mint`:

```wit
use boatramp:handlers/capability-minter.{mint};
use boatramp:handlers/capability-types.{mint-request};
```

```rust
let token = mint(&MintRequest {
    target_tenant: "tenant_B".into(),      // the app's tenant tag the capability grants
    public_subset: "storefront".into(),    // must match a redeeming route's `public`
    app_context: vec![("sub".into(), "client-42".into())],  // opaque; the host never reads it
    ttl_seconds: 300,                       // clamped to the operator ceiling
})?;
// hand `token` to the client / embed / peer — it is an opaque bearer
```

The returned string is the encoded token. Everything security-relevant is **host-forced**, so
a malicious or buggy guest cannot widen it:

- **Audience is your own project.** The guest never names the audience — the host stamps the
  minting project, so a token is never redeemable anywhere else.
- **TTL is clamped** to the operator ceiling `max_guest_capability_ttl_secs`; a longer request
  is silently clamped down, never up.
- **Deny-by-default.** Minting is gated by the `allow_guest_mint_capability`
  [posture](./security-posture.md) knob (off under `multi-tenant`). Without the `capability`
  grant, or with the knob off, there is no binding and `mint` returns `access-denied`.
- The `app-context` is **size-bounded** (a few small entries) and carried with integrity; the
  host never interprets it.

## Redeem it

The bearer is presented on a GraphQL field whose source is `via: [capability]` (see
[Cross-tenant target fields](./graphql.md#cross-tenant-target-fields)). At redeem the host
verifies the capability once — audience `== project`, a non-expired `exp`, and the capability's
subset matching an operator-declared, target-eligible route's `public` — and confines the query
to `tenant = B`.

**The enforcement ceiling lives at redeem, not mint.** A minted token is *inert* wherever the
operator has not opened a matching `via: [capability]` route: the capability carries no write
allowlist (the route does), and a subset that no route accepts resolves nothing. So a guest can
never mint past the operator's declaration, for another project, or for more than the project
already holds — the mint side only enforces audience-forcing, the TTL clamp, and the size bounds.

## Read the app-context back (`target-context`)

The `via: [capability]` field confines to `tenant = B`, but a **per-client** filter (e.g. show
one client's own invoices *within* `B`) is within-tenant authorization, not a tenancy axis — so
it stays in your resolver's own query. Recover the opaque `sub` the capability carried with the
`boatramp:handlers/target-context` binding:

```wit
use boatramp:handlers/target-context.{get};
```

```rust
let ctx = get();   // list of (key, value) pairs; empty for any non-capability principal
let sub = ctx.iter().find(|(k, _)| k == "sub").map(|(_, v)| v.clone());
// add `client_id = sub` to your own query — the host floor (tenant = B) already applied
```

Two things make this safe to expose with **no grant**: the host-forced target tenant `B` is
**never** returned (only the app-authored context round-trips, preserving guest-blindness for
host facts), and the content is your own signed data (you minted it), so there is nothing to
leak. The list is empty for any own / session / `domain` / `handle` principal.

## Target writes to a session table are refused

A capability can back a target **write** (with a route write-allowlist), but a target write to a
`TenantOrSession` (anonymous-session-keyed) table is **refused fail-closed** (since v0.4.5): a
target principal carries only `B` and no session fact, so such a write could only silently claim
an anon/session-owned row for `B`. Split the resolver — write the session-keyed rows on the
own/session path, never under a target scope.

## See also

- [Cross-tenant target fields](./graphql.md#cross-tenant-target-fields) — the `via: [capability]`
  source that redeems a minted token.
- [Isolate tenants within a project](./tenant-isolation.md) — the access-mode model the target
  axis sits beside.
- [Choose & inspect a security posture](./security-posture.md) — the `allow_guest_mint_capability`
  knob and the TTL ceiling.
