# Make a scoped CI deploy token

Give a CI job a token that can deploy exactly one site and nothing else. You mint
a site-scoped `publisher` token, store it as a CI secret, and — if you hand it
onward — narrow it further offline first.

This page assumes an admin token already exists in `BOATRAMP_TOKEN`. If not, mint
one first: see [Bootstrap authentication & mint tokens](./auth-bootstrap.md).

## 1. Mint a site-scoped token

A role written as `<role>:<site>` grants that role on one site only.
`publisher:my-site` lets the holder deploy `my-site` and gives it no access to
any other site:

```sh
boatramp token create ci-deploy --role publisher:my-site
```

```text
eyJ0…<the token, shown once>…9Qb
id: 3f9a2c1b7d04
```

The token prints to stdout once and is not recoverable; the `id:` prints to
stderr. Copy the token, and keep the id to revoke by later. For the role and
rights model, see [RBAC roles, actions & resources](../reference/rbac.md).

## 2. Store it as a CI secret

Put the token in your CI provider's secret store as `BOATRAMP_TOKEN`. The CLI
reads that variable directly, so the deploy step needs no extra flags:

```sh
boatramp sync ./dist --site my-site --server https://pad.example.com
```

```text
uploading 12 missing blob(s)… done
activated my-site -> 4f3a2b2c
```

Because the token is scoped to `my-site`, a job that tries to touch another site
is rejected by the server.

## 3. Revoke when the job or key rotates

List issued tokens to find the id, then remove it. Revocation also revokes
anything delegated from the token:

```sh
boatramp token ls
```

```text
3f9a2c1b7d04  ci-deploy  [publisher:my-site]
```

```sh
boatramp token rm 3f9a2c1b7d04
```

```text
revoked 3f9a2c1b7d04
```

## Narrow it further offline

To hand a further-restricted credential to a third party, attenuate the token
offline — signing a restrict-only block with a holder key, no server and no root
key involved. Attenuation can only **subtract** authority, never widen it.

Mint the token as delegatable first (`--holder-pub <hex>`, from `boatramp auth
init`), then narrow it to read-only on the one site with an expiry:

```sh
boatramp token attenuate "$BOATRAMP_TOKEN" \
  --holder-key "$HOLDER_KEY" \
  --only-site my-site --read-only --not-after 1767225600
```

```text
eyJ0…<narrowed credential>…Lm4
```

The narrowed credential verifies against the same root public key and is
presented in place of the original. Add `--next-holder-pub <hex>` to permit one
more attenuation down the chain. Revoking the original with `token rm` revokes
every credential delegated from it.
