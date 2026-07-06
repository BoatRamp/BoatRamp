# Authentication

The **control-plane API** (publishing, config, tokens) authenticates; public
serving never does. boatramp signs control-plane credentials as **COSE/CWT
tokens** (`COSE_Sign1` over a CWT claim set — RFC 8392/9052) and authorizes them
with granular **RBAC** (action × resource) decided by
[Cedar](https://www.cedarpolicy.com/). If no root key is configured, auth is
**disabled** (development only).

Verification needs only the **public key** (no per-request DB lookup), and the
**signing key can live outside the process** — a local key, a cloud KMS
(AWS / GCP / Azure), HashiCorp Vault, or a PKCS#11 HSM. A *delegatable* token can
be **attenuated offline** into a narrower credential without contacting the
issuer.

## 1. Generate the root key

```sh
boatramp auth init
```

This prints an **ES256** (P-256) private key (the issuing node — it mints tokens
and runs the OIDC exchange) and the matching public key (the verification trust
anchor for every node). Keys are tagged `<alg>:<hex>`:

```
BOATRAMP_AUTH_ROOT_PRIVATE_KEY=es256:…
BOATRAMP_AUTH_ROOT_PUBLIC_KEY=es256:…
```

> ES256 is the portable default — every KMS/HSM can sign it. Ed25519 is also
> supported for local, AWS, and Vault deployments.

## 2. Run the server with the key

```sh
# Issuing node — verifies AND mints (token create, OIDC exchange):
boatramp serve --auth-root-private-key "$BOATRAMP_AUTH_ROOT_PRIVATE_KEY"

# Verify-only node — can authorize requests but not issue tokens:
boatramp serve --auth-root-public-key "$BOATRAMP_AUTH_ROOT_PUBLIC_KEY"
```

Either flag (or `[serve].auth_root_private_key` / `auth_root_public_key`, or the
env vars) enables auth. To keep the root key out of process memory entirely, use
an [external signer](#external-signers-kms--hsm--vault) instead.

## 3. Bootstrap the first token

`token create` mints through `POST /api/tokens`, which itself requires an admin
token — so on a **fresh** deploy there's a chicken-and-egg. Break it with a
single-use **bootstrap secret**: set it on the server (alongside the root key),
redeem it once for an admin token, then unset it.

```sh
# On the server: set a random single-use secret (e.g. a fly.io secret / env var).
#   serve --bootstrap-secret "$SECRET"   (or BOATRAMP_BOOTSTRAP_SECRET / [serve].bootstrap_secret)

# From anywhere that can reach the server — no admin token needed:
BOATRAMP_BOOTSTRAP_SECRET="$SECRET" boatramp token bootstrap --role admin
```

The server mints through its own root key (nothing sensitive leaves it), records
the token (revocable, listable), and returns it in the response — never a log.
The secret is single-use (redeem again → `409`); **rotate it to re-bootstrap**
(recovery), and **unset it** once you've minted your real tokens.

> **Air-gapped / recovery:** a key-holder can also mint entirely offline with
> `boatramp token mint` (signs locally via the configured signer, incl. KMS/HSM) —
> no server round-trip. Prefer `token bootstrap` for the normal path.

## 4. Mint tokens (issuing node)

With an admin token in `BOATRAMP_TOKEN`, mint scoped tokens through the API:

```sh
boatramp token create ci-deploy --role publisher:my-site
boatramp token create reader    --role viewer:my-site --ttl-secs 86400
boatramp token ls          # id, label, roles, expiry — never the token
boatramp token rm <id>     # revoke (the token and any delegations off it)
```

`--role` is `<role>` (global) or `<role>:<site>` (site-scoped). The token is
shown **once** at creation; only its metadata is stored (`authz/tokens/<id>`).
Clients send it as `Authorization: Bearer` from `BOATRAMP_TOKEN` or
`publish.token`. A caller can see its own roles via `GET /api/auth/whoami`.

## Roles & the RBAC policy

Rights are an **action** (`read`, `write`, `deploy`, `admin`) over a **resource**
(`site`, `blobs`, `tokens`, `certs`, `cache`, `system`); `admin` implies the
lesser actions. The default roles:

| Role               | Grants                                                       |
| ------------------ | ------------------------------------------------------------ |
| `admin`            | everything                                                   |
| `publisher:<site>` | read/write/deploy that site + blob upload                    |
| `deployer:<site>`  | read + deploy that site + blob upload (no config writes)     |
| `viewer:<site>`    | read that site                                               |
| `operator`         | system + cert read, cache write (no site access)             |

The policy is overridable (roles → right templates), stored at the `authz/policy`
KV key (the built-in default applies when absent). A replacement is compiled to
Cedar and rejected if invalid, so a bad policy can never brick the edge:

```sh
boatramp auth policy get              # print the active policy as JSON
boatramp auth policy set policy.json  # validated server-side before storing
```

## External signers (KMS / HSM / Vault)

The root signing key never has to touch process memory. Build with the backend's
feature and select it under `serve.signer`; the server resolves the key's public
half at startup (the trust anchor) and signs each token through the backend.
Verification stays offline, so only the *issuing* node needs the backend. Secrets
(Vault tokens, HSM PINs, cloud access tokens) come from **environment variables**,
never from config on disk.

| Backend         | Cargo feature   | `serve.signer` variant |
| --------------- | --------------- | ---------------------- |
| Local key       | (built-in)      | `Local(private_key)` |
| AWS KMS         | `signer-aws`    | `AwsKms(key_id, region?)` |
| GCP Cloud KMS   | `signer-gcp`    | `GcpKms(key_version, access_token_env)` |
| Azure Key Vault | `signer-azure`  | `AzureKv(vault_url, key, key_version, access_token_env)` |
| HashiCorp Vault | `signer-vault`  | `Vault(address, key, token_env, alg?)` |
| PKCS#11 HSM     | `signer-pkcs11` | `Pkcs11(module, token_label, key_label, pin_env, alg?)` |

The cloud KMS backends are **ES256-only**; `Vault` / `Pkcs11` / `Local` accept an
optional `alg: Es256` (default) or `alg: Ed25519`. Example (`boatramp.cfg`):

```ron
(
    serve: (
        // AWS KMS — credentials from the standard AWS provider chain:
        signer: AwsKms(key_id: "arn:aws:kms:eu-west-1:…:key/…", region: "eu-west-1"),

        // …or Vault Transit (token from $VAULT_TOKEN):
        // signer: Vault(address: "https://vault:8200", key: "boatramp-root", token_env: "VAULT_TOKEN"),

        // …or a PKCS#11 HSM (PIN from $HSM_PIN):
        // signer: Pkcs11(module: "/usr/lib/softhsm/libsofthsm2.so", token_label: "boatramp", key_label: "root", pin_env: "HSM_PIN"),
    ),
)
```

Build the binary with the matching feature, e.g. `cargo build -p boatramp
--features signer-aws`. When `serve.signer` is set it supersedes
`auth_root_private_key`.

## Offline delegation (attenuation)

A **delegatable** token embeds a *holder* public key; the holder of the matching
private key can then **narrow** it — offline, with no server and no root key — by
signing a restrict-only delegation block. This lets you hand a short-lived,
single-site, read-only credential to a CI job from a broad token you keep.

```sh
# 1. The holder generates its own keypair (reuse `auth init`):
boatramp auth init            # → HOLDER_PRIVATE / HOLDER_PUBLIC

# 2. The issuer mints a delegatable token bound to the holder's public key:
boatramp token create ci --role admin --holder-pub "$HOLDER_PUBLIC"

# 3. The holder narrows it offline — read-only, one site, expiring soon:
boatramp token attenuate "$TOKEN" \
  --holder-key "$HOLDER_PRIVATE" \
  --only-site my-site --read-only --not-after 1735689600
```

Attenuation can only **subtract** authority (`--only-site` / `--read-only` /
`--not-after`); the narrowed credential is presented in place of the original and
verifies against the same root public key. `--next-holder-pub` permits one more
attenuation down the chain. Revoking the original token (`token rm`) revokes every
credential delegated from it.

## OIDC (exchange for a token)

With the `oidc` feature, an IdP JWT is **exchanged** for a short-TTL token — the
edge only ever authorizes boatramp tokens:

```sh
boatramp serve --auth-root-private-key "$KEY" \
  --oidc-issuer https://idp.example.com \
  --oidc-audience boatramp-api \
  --oidc-scope-claim scope
```

A client POSTs its JWT (as the Bearer) to `/api/auth/exchange`; the server
validates `iss`/`aud`/`exp` against the issuer's JWKS (fetched at startup,
refreshed periodically so a key rollover needs no restart), maps the configured
claim's values to **roles**, and returns a token. The web console does this
automatically after OIDC sign-in.

## Secrets at rest

The root **private** key is the crown jewel — keep it only on the issuing node
(env var / secrets manager / an [external signer](#external-signers-kms--hsm--vault)),
never in the KV. Verify-only nodes hold just the public key. Issued tokens are
never stored (only metadata); revocation is a marker at `authz/revoked/<id>`. TLS
private keys live in the ACME cache or the replicated cert store — protect those
with filesystem permissions or backend encryption. Cloud/provider credentials
come from the environment.
