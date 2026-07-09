# Hold the signing key in a KMS/HSM/Vault

Keep the token root signing key outside the boatramp process so it never sits in
process memory. The server resolves the key's public half at startup — the trust
anchor — and calls the backend to sign each minted token; the private key stays
in the KMS, HSM, or Vault. Configure this under `serve.signer` in `boatramp.cfg`.

Verification needs only the public key and stays offline: every node authorizes
requests without contacting the signer. Only *minting* — token creation, OIDC
exchange, offline `token mint` — calls the backend, so only the issuing node
needs it. For the wider picture, see
[Authentication & authorization](../explanation/auth-model.md).

## Before you start

- Provision the root key in your backend as an **ES256** (P-256) signing key. The
  cloud KMS backends sign ES256 only; `Vault`, `Pkcs11`, and `Local` also take
  `alg: Ed25519`.
- Build the binary with the backend's Cargo feature.
- Put the backend's credential in an environment variable. The config names the
  variable; the secret itself never goes in the file.

## Sign through a cloud KMS (AWS)

Build with `signer-aws` and point `serve.signer` at the key. AWS credentials come
from the standard provider chain (instance role, `AWS_*` env vars), not the
config:

```sh
cargo build --release -p boatramp --features signer-aws
```

```ron
serve: (
    signer: AwsKms(
        key_id: "arn:aws:kms:eu-west-1:123456789012:key/abcd-…",
        region: "eu-west-1",
    ),
),
```

## Sign through HashiCorp Vault

Build with `signer-vault` and target a Vault Transit key. The Vault token comes
from the environment variable named in `token_env`:

```sh
cargo build --release -p boatramp --features signer-vault
```

```ron
serve: (
    signer: Vault(
        address: "https://vault:8200",
        key: "boatramp-root",
        token_env: "VAULT_TOKEN",
        alg: Es256,
    ),
),
```

Start the server. `serve.signer` supersedes `auth_root_private_key`:

```sh
VAULT_TOKEN="$(vault print token)" boatramp serve --config boatramp.cfg
```

```text
signer: external Vault(boatramp-root) alg=es256
control-plane auth enabled — verification offline, minting via signer
serving https://0.0.0.0:8080
```

## The six backends

Each maps to a `serve.signer` variant and one Cargo feature:

| Backend | Cargo feature | `serve.signer` variant |
| --- | --- | --- |
| Local key | (built-in) | `Local(private_key)` |
| AWS KMS | `signer-aws` | `AwsKms(key_id, region)` |
| GCP Cloud KMS | `signer-gcp` | `GcpKms(key_version, access_token_env)` |
| Azure Key Vault | `signer-azure` | `AzureKv(vault_url, key, key_version, access_token_env)` |
| HashiCorp Vault | `signer-vault` | `Vault(address, key, token_env, alg)` |
| PKCS#11 HSM | `signer-pkcs11` | `Pkcs11(module, token_label, key_label, pin_env, alg)` |

For the full field tables — which fields are optional and the accepted `alg`
values — see the [boatramp.cfg schema](../reference/boatramp-cfg.md).
