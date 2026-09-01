# Encrypt secrets at rest

The control plane stores cluster-managed certificate private keys. By default
they sit cleartext in the (replicated) KV. Envelope encryption wraps each key
with a key-encryption key (KEK) so the stored bytes are ciphertext; only a node
holding the KEK can unwrap them.

Configure it with the `secrets:` section of `boatramp.cfg`. Two backends:

## Local KEK

A machine-local AES-256-GCM key, auto-generated `0600` on first use:

```ron
secrets: (
    envelope: "local",
    kek_file: "/var/lib/boatramp/secrets/kek",
)
```

```sh
boatramp serve --config boatramp.cfg
```

```text
secrets: local envelope (KEK /var/lib/boatramp/secrets/kek)
```

> **Warning:** in a cluster the wrapped certificates replicate to every node, so
> every node needs the **same** KEK file to unwrap them. Distribute the one KEK
> to all nodes, or use the Vault backend instead — a per-node KEK cannot decrypt
> another node's wrapped keys.

## Vault Transit

Delegate wrapping to HashiCorp Vault's Transit engine. No KEK file is
distributed; each node authenticates to Vault. The Vault token comes from the
environment, never the config file:

```ron
secrets: (
    envelope: "vault",
    vault: (
        addr: "https://vault:8200",
        key: "boatramp-certs",
        token_env: "VAULT_TOKEN",
    ),
)
```

```sh
VAULT_TOKEN="$(vault print token)" boatramp serve --config boatramp.cfg
```

```text
secrets: vault envelope (transit key boatramp-certs @ https://vault:8200)
```

Vault avoids the shared-KEK-file problem in a cluster: every node unwraps through
Vault with its own token, so there is no key file to copy between hosts.

## What is protected

The envelope wraps, in the control plane: cluster-managed **certificate private
keys**, **managed-database credentials** (the per-tenant passwords boatramp
generates for a managed Postgres/MySQL), and the **internal secret store** that
backs `boatramp:<name>` references (see [Give handlers & functions
secrets](./secrets.md)). Configuring a `secrets:` envelope is therefore a
prerequisite for the `boatramp secrets` commands.

Back the KEK up alongside your other secrets — losing it makes everything the
envelope wrapped unrecoverable (boatramp re-issues certificates, but stored
secrets and managed-DB credentials cannot be re-derived). See [Back up &
restore](./backup.md).
