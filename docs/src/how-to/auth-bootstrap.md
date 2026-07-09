# Bootstrap authentication & mint tokens

The control-plane API (publishing, config, tokens) authenticates; public serving
never does. This guide takes a fresh server from no auth to a working admin
token you can mint scoped tokens with. For the model behind it — COSE/CWT
tokens, Cedar RBAC, offline verification — see
[Authentication & authorization](../explanation/auth-model.md).

## 1. Generate the root key

```sh
boatramp auth init
```

```text
BOATRAMP_AUTH_ROOT_PRIVATE_KEY=es256:6f2c…
BOATRAMP_AUTH_ROOT_PUBLIC_KEY=es256:03a1…
```

This is an ES256 (P-256) key pair. The **private** key belongs to an issuing node
— it verifies requests and mints tokens. The **public** key is the verification
trust anchor; a verify-only node sets just that. To keep the private key out of
process memory entirely, use an
[external signer](./external-signer.md) (KMS / HSM / Vault) instead.

## 2. Start the server with the key

```sh
boatramp serve --auth-root-private-key "$BOATRAMP_AUTH_ROOT_PRIVATE_KEY"
```

```text
control-plane auth enabled (issuer)
```

Any of `--auth-root-private-key`, the `BOATRAMP_AUTH_ROOT_PRIVATE_KEY`
environment variable, or `serve.auth_root_private_key` in `boatramp.cfg` enables
auth.

> **Warning:** with no root key configured, auth is **disabled** — every
> control-plane request is accepted. Under the default `multi-tenant` posture the
> server refuses to start this way on a non-loopback address. Never run a
> public, auth-off server.

## 3. Redeem a single-use bootstrap secret

`token create` mints through `POST /api/tokens`, which itself requires an admin
token — a chicken-and-egg on a fresh deploy. Break it with a single-use
**bootstrap secret**: set it on the server, redeem it once for an admin token,
then remove it. The server mints with its own root key, so nothing sensitive
leaves it, and the token comes back in the response body — never a log.

Set the secret on the server (alongside the root key):

```sh
boatramp serve \
  --auth-root-private-key "$BOATRAMP_AUTH_ROOT_PRIVATE_KEY" \
  --bootstrap-secret "$SECRET"
```

Redeem it from anywhere that can reach the server — no admin token needed:

```sh
BOATRAMP_BOOTSTRAP_SECRET="$SECRET" \
  boatramp token bootstrap --role admin --server https://pad.example.com
```

```text
eyJ…                       # the admin token — store it now, it is shown once
id: fb156b4f58909058        # metadata id, for `token ls` / `token rm`
```

The secret is single-use: redeeming it again returns `409`. Store the admin
token, then remove the secret from the server. To bootstrap again later (a lost
admin token, key rotation), set a **new** secret and redeem it.

> **Note:** a key holder can also mint entirely offline with `boatramp token
> mint`, which signs locally through the configured signer (including a KMS/HSM)
> with no server round-trip. Reserve it for recovery when the server is
> unreachable; `token bootstrap` is the normal path, and its tokens are recorded
> and revocable.

## 4. Mint scoped tokens

Put the admin token in `BOATRAMP_TOKEN`, then mint narrower tokens through the
API:

```sh
export BOATRAMP_TOKEN=eyJ…
boatramp token create ci-deploy --role publisher:my-site
boatramp token create reader    --role viewer:my-site --ttl-secs 86400
```

```text
eyJ…                       # the new token — shown once
id: 024619fb948511f5
```

An admin token can mint any token, including another admin — so rotate a
long-lived admin token before it expires instead of re-bootstrapping. Inspect and
revoke tokens by their metadata id:

```sh
boatramp token ls          # id, label, roles, expiry — never the token itself
boatramp token rm <id>     # revoke the token and any delegations minted from it
```

`--role` is `<role>` (global) or `<role>:<site>` (site-scoped). See the full role
and rights model in [RBAC roles, actions & resources](../reference/rbac.md).

## Next steps

- [Make a scoped CI deploy token](./ci-token.md) — including offline attenuation.
- [Sign in with OIDC](./oidc.md).
- [Hold the signing key in a KMS/HSM/Vault](./external-signer.md).
