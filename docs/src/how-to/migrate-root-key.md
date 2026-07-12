# Migrate the root key

A cluster **is** its root key, so custody of that key (local ⇄ external
KMS/HSM/Vault) is a first-class, low-friction operation — you never rebuild the
cluster or hand-edit every node. There are two paths, depending on whether the
target backend can import your existing key material.

For *why* custody matters and the blast radius it carries, see
[Mesh identity & the single root anchor](../explanation/SECURITY-mesh-identity.md).

## Same-key custody move (zero re-pin)

If the target backend can **import** key material (AWS KMS import, Vault Transit
import, GCP KMS), the **public key — the anchor — is unchanged**. Nothing re-pins
and nothing re-signs: it is purely a custody change.

1. Import your existing key into the external backend (per that backend's docs).
2. Re-point `[serve.signer]` from the local key to the external backend — see
   [Hold the signing key in a KMS/HSM/Vault](./external-signer.md) for the backend
   config.
3. Restart. boatramp verifies the imported key yields the **same** public anchor
   and continues; every node still trusts the same root, so no join re-pins.

This is the reverse, too (external → local, e.g. offboarding a KMS): re-point
`[serve.signer]` back to the local key material.

## New-key rotation (import-less HSMs)

When the backend **cannot** import (keys must be generated in-HSM), the anchor
must rotate. boatramp keeps a **replicated root-anchor set** so both the old and
new anchors are trusted during the overlap — **no window where a node rejects a
valid token** — and no per-node edit:

```sh
# 1. Mint the new anchor in the target backend, then trust it cluster-wide:
boatramp auth rotate-root --add "$(boatramp auth pubkey --private-key "$NEW_KEY")"

# 2. Re-point [serve.signer] / BOATRAMP_AUTH_ROOT_PRIVATE_KEY to the new key so
#    new tokens + node attestations are signed by it, and restart each node.

# 3. Once every node has converged (old + new both trusted), retire the old key:
boatramp auth rotate-root --retire "$OLD_PUBKEY"
```

`auth rotate-root` with no flag lists the currently-trusted extra anchors. Every
node verifies a token against its primary root **and** the replicated anchor set,
so old-key tokens keep working until you retire the old anchor in step 3. The
reverse rotation (new → old) is the same two commands.

## See also

- [Mesh identity & the single root anchor](../explanation/SECURITY-mesh-identity.md)
- [Hold the signing key in a KMS/HSM/Vault](./external-signer.md)
- [Deploy a self-hosted cluster](./deploy-cluster.md)
