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

Therefore **`--include-identity` transports the KEK (+ the on-disk sealed key files)**, and:
- **adopt** = install the source KEK (+ key files) ⇒ the KV slice's sealed secrets (incl.
  the IdP seed + managed-pg cred) unseal ⇒ faithful clone. *This is what resolves decision
  #4: the IdP seed is not a separate member — it rides in the KV slice and unseals under the
  adopted KEK.*
- **fresh** = do NOT install the source KEK; the target keeps/mints its own ⇒ the source's
  KV-sealed secrets **cannot** unseal on the target (different KEK) ⇒ Ask-4(c) ("zero
  source-sealed artifacts unwrap") holds *for free*, by construction. The operator then
  re-provisions (managed-pg credential, secrets) under the target's own identity.

## Envelope-type branches (`[secrets].envelope`)

- **`local`** (the `secrets/kek` file): KEK is 32 transportable bytes. `--include-identity`
  supported. adopt installs it as the target's `secrets/kek`.
- **`vault`**: the KEK lives in an external KMS and **never leaves Vault**. `--include-identity`
  is **refused** with guidance: for a faithful clone, point the target's `[secrets.vault]` at
  the *same* key (shared KMS) and import with `--identity adopt-external` (reuses the shared
  Vault key, no KEK bytes in the bundle); otherwise use `--identity fresh`.
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

## Open questions for the owner

1. **Transport passphrase supply** — `--transport-key-file` (recommended) vs an interactive
   prompt vs env only. Recommend the key-file (scriptable, no-argv-leak).
2. **`fresh` + source-sealed secrets** — write the inert ciphertext and document, or actively
   **drop** `project/<p>/secret/*` (and the managed-pg credential) on a fresh import so the
   target starts clean? Recommend **drop** (cleaner, and makes Ask-4(c) a positive "absent"
   rather than "present-but-inert") — but it changes what a fresh clone looks like.
3. **Vault adopt** — is a shared-KMS `adopt-external` (point both at the same Vault key) worth
   building in this cut, or refuse Vault `--include-identity` entirely and support only
   `fresh` for Vault nodes in 0.32.0?
