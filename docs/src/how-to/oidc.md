# Sign in with OIDC

Enable OIDC on `serve` so users sign in with an identity provider you already run
(Okta, Keycloak, Auth0, Entra ID), then exchange the provider's JWT for a
boatramp token. The control plane only ever authorizes boatramp tokens — the IdP
JWT buys you one, and nothing more. For minting tokens without an IdP, see
[Bootstrap authentication](./auth-bootstrap.md); for why the exchange works this
way, see [Authentication & authorization](../explanation/auth-model.md).

## Before you start

- A configured root **private** key on the issuing node — the exchange mints
  tokens, so it needs the signer.
- A binary built with the `oidc` feature.
- Your IdP's issuer URL, the audience it stamps for boatramp, and the claim that
  carries role values.

## 1. Enable OIDC on serve

Pass the three OIDC flags alongside the root key:

```sh
boatramp serve --auth-root-private-key "$KEY" \
  --oidc-issuer https://idp.example.com \
  --oidc-audience boatramp-api \
  --oidc-scope-claim scope
```

```text
control-plane auth enabled (issuer)
oidc exchange enabled — issuer https://idp.example.com, audience boatramp-api
serving https://0.0.0.0:8080
```

Each flag has an environment variable — `BOATRAMP_OIDC_ISSUER`,
`BOATRAMP_OIDC_AUDIENCE`, `BOATRAMP_OIDC_SCOPE_CLAIM` — and a `boatramp.cfg`
entry. On startup the server fetches the issuer's JWKS and refreshes it
periodically, so a key rollover at the IdP needs no restart.

- `--oidc-issuer` names the trusted issuer; the server validates each JWT's
  `iss`, `aud`, and `exp` against that issuer's keys.
- `--oidc-audience` is the audience the JWT must carry. Set it: one issuer mints
  JWTs for many clients, and without an audience check a JWT minted for another
  client at the same issuer would exchange for a boatramp token. The server
  rejects any JWT whose `aud` does not match.
- `--oidc-scope-claim` names the claim whose values map to boatramp roles — here
  the `scope` claim's values become roles like `publisher:my-site`.

## 2. Exchange a JWT for a boatramp token

Send the IdP JWT as the bearer to `/api/auth/exchange` on your boatramp server —
not the IdP:

```sh
curl -X POST https://pad.example.com/api/auth/exchange \
  -H "Authorization: Bearer $OIDC_JWT"
```

```text
{"token":"eyJhbGciOiJFUzI1NiIs…","roles":["publisher:my-site"],"expires_in":3600}
```

The server validates the JWT against the issuer's JWKS, maps the scope-claim
values to roles, mints a short-TTL boatramp token, and returns it. Use that token
as `Authorization: Bearer` (or `BOATRAMP_TOKEN`) for every control-plane call. A
rejected JWT — wrong `aud`, expired, or an unknown signing key — returns `401`,
and no token is minted.
