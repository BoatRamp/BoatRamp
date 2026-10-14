# Project export/import — the identity model (construens Ask-2 + Ask-4 c/d)

Status: **design for review** (Phase 2 of env-clone / 0.32.0). Nothing here is built yet.
Owner approved the transport-wrap approach ("B / PKCS#12-pattern") 2026-10-13.

## The problem

A FULL `project export` bundle already carries the project's control-plane KV slice —
including every **KEK-sealed secret** (operator/app secrets at `project/<p>/secret/<name>`,
the managed-pg credential, the application **IdP/OIDC signing seed**, cert keys). Those are
ciphertext. They unseal only under the project's **KEK**. So an import onto another node is
only a *faithful* clone if that node holds the **same KEK**; otherwise the sealed bytes are
inert.

Today there is **no** identity story: `ImportOptions = {apply, force, allow_schema_skew}`, a
FULL import copies the KV slice wholesale under `force`, and there is no way to carry or
mint identity. Ask-2/Ask-4(c/d) require an explicit, safe choice.

## Key insight — the KEK is the crux

Everything confidential except the KEK is **KEK-sealed and already in the KV slice**. The
only identity material that lives *outside* the sealed KV is:
1. **The KEK** — `LocalKek` (raw 32 bytes, AES-256-GCM) at `<data_dir>/secrets/kek`. Can't
   wrap itself ⇒ needs separate transport.
2. **On-disk sealed key files** — the mesh key (`[mesh].key_file`) and any issuer/signer key
   file. These are sealed *by the KEK* but stored on disk, not in KV, so the KV slice does
   not carry them. (Enumerate from `[secrets]`/`[mesh]` config at export; include their
   sealed bytes.)

### What the container actually carries (refined 2026-10-14)

Enumerating what boatramp persists *outside* the KEK-sealed KV:
- **KEK** (`secrets/kek`) — carry it (the master; nothing else unseals without it).
- **Mesh key** (`<data_dir>/mesh/identity.key`) — **excluded**: it is the *node's* cluster-
  membership identity, not the project/environment's. A recovered node mints its own.
- **cert keys, sealed operator/app secrets, the IdP/OIDC seed, the managed-pg credential** —
  all **KEK-sealed values in the KV slice**, already carried by the FULL bundle; they unseal
  under the adopted KEK. Nothing separate to carry.
- A control-plane **signer key sourced from config/env** (not a boatramp-persisted artifact)
  is **out of scope** — it is the operator's to redeploy on the recovery node (the construens
  request itself notes identity config lives in "config/env, not in KV"). boatramp exports its
  *persisted state* (KEK + KV slice + pg/mysql/libsql + blobs); the operator deploys the same
  node config. A signer key that IS a sealed KV secret rides in the slice like any other.

So the container payload is, in practice, **just the KEK** (a versioned `{kek, key_files:[]}`
struct keeps room for a future on-disk sealed file, but `key_files` is empty today). This is
the minimal-but-correct boundary; the security review should confirm it.

Therefore **`--include-identity` transports the KEK**, and:
- **adopt** = install the source KEK (+ key files) ⇒ the KV slice's sealed secrets (incl.
  the IdP seed + managed-pg cred) unseal ⇒ faithful clone. *This is what resolves decision
  #4: the IdP seed is not a separate member — it rides in the KV slice and unseals under the
  adopted KEK.*
- **fresh** = do NOT install the source KEK; the target keeps/mints its own ⇒ the source's
  KV-sealed secrets **cannot** unseal on the target (different KEK) ⇒ Ask-4(c) ("zero
  source-sealed artifacts unwrap") holds *for free*, by construction. The operator then
  re-provisions (managed-pg credential, secrets) under the target's own identity.

## Two modes, period (owner, 2026-10-14)

There is NO sharing of one key across *distinct* environments (prod + preview on one key is
bad hygiene — a compromise of the weaker env unseals the stronger one). The import has
exactly two legitimate modes:

- **`adopt` = backup/recovery of the SAME environment.** The same key is reused *because it is
  the same environment* being restored onto new hardware. Local: install the KEK the bundle
  carries. Vault: the recovered node is wired to the same KMS key (nothing to carry). This is
  the construens "faithful clone — sealed creds unwrap, tokens stay valid" case, understood as
  recovery.
- **`fresh` = a DIFFERENT environment.** Different environment ⇒ different key ⇒ adopt is
  impossible ⇒ fresh is enforced: the target mints its own KEK and source-sealed secrets are
  dropped (clean target, re-provision).

## Envelope-type branches (`[secrets].envelope`)

- **`local`** (the `secrets/kek` file): KEK is 32 transportable bytes. `--include-identity`
  supported; adopt installs it as the target's `secrets/kek` (recovery of the same env).
- **`vault`**: the KEK lives in an external KMS and **never leaves Vault**. `--include-identity`
  is **refused** (there is nothing extractable to carry; a KMS exists precisely so keys don't
  leave it). A Vault **recovery** adopt simply restores onto a node already wired to the same
  KMS key (the sealed secrets unseal because it is the same key); a different environment has a
  different key ⇒ `fresh`. There is NO "adopt-external across environments" — that would be the
  one-key-many-envs anti-pattern above.
- **`none`**: nothing is sealed ⇒ `--include-identity` is a no-op/refused (nothing to carry).

## The transport container ("B" / PKCS#12-pattern)

A bundle member `identity/identity.brid` — a passphrase-protected container, same guarantee
as PKCS#12 (portable, tamper-detected, useless without the transport secret) but using our
own key types rather than the X.509/ASN.1 PKCS#12 bags:
- **KDF**: Argon2id over an operator-supplied **transport passphrase** → a 32-byte transport
  key. (Params recorded in the container header: salt, m/t/p.)
- **AEAD**: AES-256-GCM (same primitive as `LocalKek`) under the transport key, over a small
  CBOR payload `{ kek: <32 bytes>, key_files: [{path, sealed_bytes}], envelope_kind }`.
- The transport passphrase is supplied via **`--transport-key-file <path>`** (a file, 0600),
  **never argv** (process args leak) and never the bundle. Env-var fallback
  `BOATRAMP_EXPORT_TRANSPORT_KEY`. Mirrors the pg/mysql credential-non-leak discipline.

## CLI / API surface

- `boatramp project export <p> --out <b> [--include-identity --transport-key-file <f>]`
  — default (no flag) ⇒ **no** identity member (the safe, identity-free bundle). `data_only`
  and `--include-identity` are mutually exclusive (data-only carries no control-plane bytes
  at all).
- `boatramp project import <p> --in <b> --identity {adopt|fresh}` (no default — the operator
  must choose). `adopt` requires an identity member + `--transport-key-file`; a bundle
  without an identity member + `--identity adopt` ⇒ **error** (can't adopt what isn't there).
  `fresh` ignores any identity member.
- `ImportOptions` gains `identity: IdentityChoice { Adopt{transport_key}, Fresh }`.

## Import ordering (so sealed secrets unseal)

For `adopt`: **install KEK (+ key files) FIRST**, then the existing order blobs → pg → kv →
scrub. The KV restore writes sealed ciphertext; the first unseal (handler/function
instantiation, or a scrub-time verify) then succeeds under the adopted KEK.
For `fresh`: skip identity install; KV restore still writes the sealed ciphertext, but it is
inert under the target KEK — the operator re-provisions. (A future refinement: a `fresh`
import could *drop* source-sealed `project/<p>/secret/*` rather than write inert ciphertext;
first cut writes them and documents that they won't unseal. **Open Q — see below.**)

## Ask-4 mutation gates (driver-level, in-process where possible)

- (a) `--data-only` writes no control-plane/identity ✓ DONE (`data_only_export_omits_the_control_plane_kv_slice`).
- (b) import never writes `_cp/*` ✓ (kv_dump layer) — add a driver-level assertion too.
- (c) **fresh leaves zero source-sealed artifacts that unseal**: seed a source secret sealed
  under source-KEK-A; export (full, no identity); import `--identity fresh` into a target
  with KEK-B; assert the restored `project/<p>/secret/<name>` does **not** unseal under B.
- (d) **identity excluded by default / only under the flag**: default export ⇒ no
  `identity/` member; `--include-identity` ⇒ exactly one, and it does **not** contain the raw
  KEK in the clear (grep the bytes); `adopt` on a bundle with no identity member ⇒ error;
  `adopt` with the wrong transport key ⇒ AEAD failure, no partial install.

## Resolved decisions (owner, 2026-10-14)

1. **Transport passphrase supply** — support **all three**, precedence
   `--transport-key-file <0600 path>` → `BOATRAMP_EXPORT_TRANSPORT_KEY` env → interactive
   prompt (fallback). Never argv.
2. **`fresh` + source-sealed secrets** — **drop** them: a fresh import removes source-sealed
   `project/<p>/secret/*` and the managed-pg credential so the target starts clean and
   re-provisions. Makes Ask-4(c) a positive "absent," not "present-but-inert."
3. **Vault** — refuse `--include-identity` on a Vault node (nothing extractable to carry).
   Vault recovery = restore onto a node wired to the same KMS key; a different env ⇒ `fresh`.
   No `adopt-external` / no one-key-many-envs. (See "Two modes, period".)
