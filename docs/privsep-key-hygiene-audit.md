# privsep phase 0 (WS2): key-material hygiene for the crown-jewel key paths

Scope: the long-lived and transient **plaintext** key / secret buffers on boatramp's crown-jewel
paths — the secrets-at-rest KEK, the sealed-state AEAD, the per-project/per-tenant secret store, the
cluster cert private keys, the kernel-trust verifier, and the private-registry pull credential. This
is WS2 of privsep phase 0: a memory-hygiene hardening pass (mlock + zeroize-on-drop + redacting
`Debug` + shortest-window), **not** a redesign of the sealing. No crypto behaviour changed; every
pre-existing fail-closed / tenancy test still passes.

Methodology: read each module named in the WS2 brief, mapped which struct/field actually holds raw
key bytes vs ciphertext vs a public key, then applied the three reflexes to the plaintext holders and
audited each plaintext's flow for lingering copies. Residual risks that need a logic/API change (not
a mechanical hardening) are flagged in §4 for Security review rather than silently reworked.

## 1. Where the key material lives (the map)

| Material | Holder (type · field) | Crate / module | plaintext lifetime |
|---|---|---|---|
| **AES-256-GCM KEK** (secrets-at-rest **and** sealed-state) | `LocalKek.kek` | `boatramp-server/src/envelope.rs` | whole process (behind `Arc<dyn KeyEnvelope>`) |
| Vault bearer token | `VaultEnvelope.token` | `boatramp-server/src/envelope.rs` | whole process |
| Argon2id-derived transport key | `dk` (local, `transport_wrap`/`transport_unwrap`) | `boatramp-server/src/envelope.rs` | one seal/unseal statement |
| Decrypted cert **private key** | `StoredCert.key_pem` | `boatramp-core/src/cert.rs` | per read, handed to rustls |
| Sealed-state cleartext claims | `plaintext` buffer + returned `SealedStateClaims` | `boatramp-core/src/sealed_state.rs` | one seal/unseal + caller |
| Unsealed project/tenant secret | `SecretStore::get` / `TenantSecretStore::get` return `Vec<u8>` | `boatramp-core/src/secret_store.rs` | per resolve, caller-owned |
| Registry pull credential | `RegistryCredential` / `RegistryAuth` (`username`/`password`) + unsealed bytes | `boatramp-core/src/registry_auth.rs` | per pull |
| Overlay Ed25519 seed (reference pattern) | `OverlaySecret.seed` | `boatramp-overlay-proto/src/identity.rs` | pre-existing; already `Zeroizing` |

**Not key material (confirmed, no action):**
- `boatramp-core/src/envelope.rs` — the `KeyEnvelope` **trait** only (the wasm-clean seam); the
  concrete KEK is `LocalKek`, above.
- `boatramp-core/src/kernel_trust.rs` — verifies a kernel against a **public** signing key + a SHA-256
  pin. No private/secret bytes are held; nothing to lock or zeroize.
- `boatramp-core/src/crownjewel.rs` — a CAS-concurrency **test seam** + gate helpers; no key bytes.
- `SecretRecord.sealed` (secret_store) and `StoredCert.key_pem` **at rest** — these hold *ciphertext*
  (envelope-wrapped), not plaintext; confidentiality is the AEAD's job there.

## 2. The shared primitive: `boatramp_core::keyguard::MlockedKey`

A single, auditable home (`crates/boatramp-core/src/keyguard.rs`) for the three reflexes:

- **mlock** — a heap-owned `Box<[u8]>` (stable address, so the lock pins a fixed region regardless of
  where the owner struct moves) is `mlock`ed best-effort at construction. A failure (e.g.
  `RLIMIT_MEMLOCK` too low) is `warn!`-logged once and swallowed — **never fatal** to startup.
- **zeroize-on-drop** — `Drop` zeroizes the bytes **while the pages are still locked**, then
  `munlock`s (order matters: munlock-then-zero could zero a page the kernel already made swappable).
- **redacting `Debug`** — renders `len` + `mlocked` + `"<redacted>"`, never the bytes. No `Display`,
  no `Serialize`. Reads go through `as_slice()` (greppable), not `Deref`.

Portability: `mlock`/`munlock` are `cfg(unix)` (Linux + macOS) via `libc` (pulled only on unix, so the
wasm-clean core still builds on `wasm32`). On any non-unix target the lock is a documented no-op
(`is_locked()` → `false`); zeroize-on-drop and the redacting `Debug` still apply everywhere.

## 3. What was hardened, per path

### 3.1 `LocalKek` — the crown-jewel KEK (boatramp-server/src/envelope.rs)
- `kek: [u8; 32]` → `kek: MlockedKey`: the KEK is now **mlocked + zeroized-on-drop + redacted**. This
  is the single highest-value change — one 32-byte key wraps every secret, every cert private key, and
  every sealed-state login token, and it lives for the whole process.
- Every transient copy made loading/generating the key is zeroized: the file-read buffer
  (`Zeroizing<Vec<u8>>`), the `[u8;32]` passed to `from_bytes` (zeroized inside), and the generated
  array (zeroized after the on-disk write that needed it).
- `#[derive(Debug)]` on `LocalKek` now yields a fully redacted render via `MlockedKey`'s `Debug`.
- Crypto unchanged: `wrap`/`unwrap` still AES-256-GCM with the identical wire format (`BRK1 ‖ nonce ‖
  ct+tag`); the round-trip + wrong-key + tamper tests pass, plus a new
  `local_kek_round_trips_through_the_mlocked_buffer` and `local_kek_debug_never_renders_the_key`.

### 3.2 `VaultEnvelope` (boatramp-server/src/envelope.rs)
- `token: String` → `token: Zeroizing<String>`: the Vault bearer token is zeroized on drop. It is
  **not** mlocked by design — a `String` can reallocate as it is built (leaving stale copies a lock
  would miss), and the token is a bearer credential sent over TLS on every call, not a key persisted to
  swap; zeroize-on-drop is the proportionate hardening. Rationale recorded inline + here.

### 3.3 Transport container KDF (boatramp-server/src/envelope.rs)
- The Argon2id-derived 32-byte key in `transport_wrap`/`transport_unwrap` is now
  `Zeroizing<[u8;32]>`, wiped as soon as `LessSafeKey` has taken its own copy. Transient (one
  statement), so not mlocked.

### 3.4 Sealed-state (boatramp-core/src/sealed_state.rs)
- The cleartext `MAGIC ‖ json(claims)` buffer in `seal_state`, and the AEAD-decrypted buffer in
  `unseal_state`, are now `Zeroizing` — the tenant/pkce/nonce plaintext is wiped the moment the
  seal/unseal returns (shortest in-memory window; the plaintext window is now just the JSON parse).
- `SealedStateClaims` lost its derived `Debug` for a **redacting** one: `tenant`, `pkce`, `nonce` →
  `"<redacted>"`; `project`/`site`/`iat`/`exp` stay visible for diagnostics. (The whole point of the
  seal is that the browser never sees the tenant — it must not leak via a log either.)

### 3.5 Registry auth (boatramp-core/src/registry_auth.rs)
- `RegistryCredential` and `RegistryAuth` already had redacting `Debug` (pre-existing). Added
  **zeroize-on-drop** (`Drop` wiping `password` + `username`). `RegistryAuth::from_credential` uses
  `std::mem::take` to move the Strings out without moving a field out of a `Drop` type (which the
  compiler forbids) — `RegistryAuth` is only ever consumed as `&RegistryAuth` by backends, so the
  `Drop` is safe.
- The unsealed secret JSON (`SecretStore::get` → `Vec<u8>`) is wrapped `Zeroizing` in `load()` so the
  intermediate credential copy is wiped once parsed.

### 3.6 Cert store (boatramp-core/src/cert.rs)
- `StoredCert` lost its derived `Debug` for a **redacting** one: `key_pem` → `"<redacted>"` (on the
  read path this field is the *decrypted* private key), `chain_pem` (public) + expiry stay visible.

## 4. Residual plaintext risks (for Security review — NOT silently reworked)

These need an API/logic change or are outside a userspace-hygiene pass; flagged honestly rather than
hand-waved.

1. **`SecretStore::get` / `TenantSecretStore::get` return a plain `Vec<u8>` plaintext** (R-1, MEDIUM).
   The unsealed secret value is returned un-zeroized and is held by callers (compute instantiation,
   managed-DB credential wiring, registry-auth — which now at least zeroizes its own copy). A durable
   fix is to change the return type to `Zeroizing<Vec<u8>>` and thread it through every resolver
   caller; that is an API change across `compute.rs`/`deploy.rs` and was out of scope for a no-behaviour
   hardening. Recommend as a WS2 follow-up.

2. **`StoredCert.key_pem` decrypted private key is returned by value, un-zeroized** (R-2, MEDIUM).
   `StoredCert` is a serde wire type (also stored at rest, wrapped) and uses struct-update
   (`..cert.clone()`) at `put`, so a `Drop`/zeroize impl can't be added without reworking it and would
   fight the move-checker. Redacting `Debug` is in place; the cleartext key still lands in a `String`
   handed to rustls on-demand TLS (`boatramp/src/on_demand_tls.rs`), whose `CertifiedKey` then holds
   its own copy. A zeroizing key-PEM type is the durable fix; flagged.

3. **The AEAD plaintext inside `LocalKek::wrap`/`unwrap`** (R-3, LOW/MEDIUM). aws-lc-rs seals/opens in
   place over a `plaintext.to_vec()` / `ciphertext.to_vec()`; the decrypted secret/cert-key/claims sits
   in an un-mlocked, un-zeroized heap `Vec` for the duration of the op and is then returned to the
   caller (this is the same plaintext as R-1/R-2, one layer down). The **KEK** bytes copied into
   aws-lc-rs's `UnboundKey`/`LessSafeKey` are managed by aws-lc-rs/BoringSSL (it zeroizes its own key
   material on drop) and are outside our zeroize reach — noted, not a regression.

4. **`SealedStateClaims` returned to the caller** (R-4, LOW). The seal/unseal *buffers* are zeroized,
   but the returned claims carry cleartext `tenant`/`pkce`/`nonce` in `String`s not zeroized on drop
   (same `Drop` + struct-update constraint as R-2; the type is also used with `..claims` in tests).
   Redacting `Debug` is in place. Short-lived (≤15 min seal TTL governs the token, not this in-memory
   copy), hence LOW.

5. **mlock page granularity + best-effort** (R-5, LOW, operational). `mlock` pins whole pages: a
   sub-page key pins its page(s), and `munlock` on drop releases them even if an unrelated allocation
   shares one — the standard trade-off. The dominant key (the KEK) is process-lifetime, so in practice
   its lock is held for the whole run. On a node with a low `RLIMIT_MEMLOCK` (common container default)
   the lock fails → `warn!` + swappable key; an operator needing the guarantee must raise the
   `memlock` ulimit. We lock only the explicit key buffers, **not** `mlockall` — other transient
   plaintext copies (R-1/R-3) are not pinned.

6. **Core-dump / live-memory exposure is out of WS2 scope** (R-6, note). mlock defends against
   swap/hibernation persistence, not a `ptrace`/root read or a core dump taken while the key is live.
   Complementary mitigations — `prctl(PR_SET_DUMPABLE, 0)`, disabling core dumps, and
   `madvise(MADV_DONTDUMP)` on the locked region (Linux) — are recommended follow-ups (WS1 seccomp /
   ops scope); `MADV_DONTDUMP` could be added to `MlockedKey` on Linux as a cheap defense-in-depth.

## 5. Tests added

- `keyguard`: `as_slice` round-trip; `Debug` never renders the bytes (hex **or** decimal); mlock is
  best-effort and never panics (CI containers cap `RLIMIT_MEMLOCK`); empty-key + drop paths don't
  panic.
- `sealed_state::claims_debug_redacts_the_confidential_fields`.
- `cert::stored_cert_debug_redacts_the_private_key`.
- `envelope` (server): `local_kek_debug_never_renders_the_key`,
  `local_kek_round_trips_through_the_mlocked_buffer`.
- Pre-existing coverage reused: `registry_auth::redacting_debug_never_leaks_the_password`, and every
  fail-closed / tenancy / round-trip test in the touched modules (all still green).

No timing/live mlock test was added to the general suite (the lock is environment-dependent; the unit
tests assert only that the best-effort path never panics and the key stays usable either way).
