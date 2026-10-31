//! Secrets-at-rest envelope backends.
//!
//! Concrete [`KeyEnvelope`](boatramp_core::envelope::KeyEnvelope) implementations
//! — kept out of the wasm-clean core because they pull crypto/HTTP deps.
//! [`LocalKek`] wraps with AES-256-GCM under a machine-local key-encryption key.
//!
//! **Cluster note:** cert private keys are wrapped in the *replicated* KV and
//! read by every node, so a local KEK must be the **same file on every node**
//! (the operator distributes it). A central KMS (Vault) avoids that by having
//! every node unwrap through the same service.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine as _;
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::keyguard::MlockedKey;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

/// Wire-format tag: `b"BRK1"`. A wrapped blob is `MAGIC || nonce(12) ||
/// ciphertext+tag`, so `unwrap` fail-closes on a foreign or truncated blob.
const MAGIC: &[u8; 4] = b"BRK1";
/// AES-256 key length.
const KEK_LEN: usize = 32;

/// AES-256-GCM envelope under a machine-local key-encryption key (KEK).
///
/// **Rotation guard — sealed-state tokens (PLAN-sealed-state-source).** This same envelope also seals
/// the short-lived `sealed-state` login tokens (`boatramp_core::sealed_state`), whose whole
/// anti-replay story rests on a ≤[`MAX_STATE_TTL_SECS`](boatramp_core::sealed_state::MAX_STATE_TTL_SECS)
/// (15 min) window. There is NO previous-key fallback today (a single active KEK). IF one is ever
/// added here to make secrets-at-rest KEK rotation seamless, it MUST NOT silently apply to
/// sealed-state tokens: a captured ≤15-min `state` plus a leaked OLD KEK must HARD-FAIL to unseal
/// after a rotation, never resolve a tenant. Concretely, a previous-key path must either refuse
/// sealed-state (domain-tag `BRSS1\0`) blobs outright, or bound previous-key acceptance to strictly
/// LESS than `MAX_STATE_TTL_SECS` — otherwise rotation would widen the replay window the TTL exists to
/// cap. When such a fallback lands, add the asserting test (an old-KEK state fails closed post-rotation).
///
/// **Memory hygiene (privsep Phase 0, WS2).** The raw AES-256-GCM KEK is the crown jewel: it lives
/// for the whole process lifetime (behind an `Arc<dyn KeyEnvelope>`). It is held in an
/// [`MlockedKey`] — the pages are best-effort `mlock`ed so the key never swaps to disk, the bytes are
/// zeroized when the envelope drops, and `Debug` is redacted (so it can never reach a log). Every
/// transient copy made while loading/generating the key is zeroized here too.
#[derive(Debug)]
pub struct LocalKek {
    kek: MlockedKey,
}

impl LocalKek {
    /// Build from a raw 32-byte KEK. The caller's `kek` array is a transient copy and is zeroized
    /// here once the locked buffer owns the bytes.
    pub fn from_bytes(mut kek: [u8; KEK_LEN]) -> Self {
        let locked = MlockedKey::from_slice(&kek);
        kek.zeroize();
        Self { kek: locked }
    }

    /// Load the KEK from `path` (raw 32 bytes), generating + persisting one
    /// (`0600`) if the file does not exist. In a cluster the **same** file must
    /// be present on every node (wrapped certs replicate).
    pub fn load_or_generate(path: &Path) -> Result<Self, EnvelopeError> {
        match std::fs::read(path) {
            Ok(bytes) => {
                // The file bytes are the raw KEK; hold the intermediate read buffer zeroizing so it
                // is wiped once the bytes are copied into the locked `LocalKek`.
                let bytes = Zeroizing::new(bytes);
                let kek: [u8; KEK_LEN] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| EnvelopeError::new("KEK file must be exactly 32 bytes"))?;
                Ok(Self::from_bytes(kek))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut kek = [0u8; KEK_LEN];
                SystemRandom::new()
                    .fill(&mut kek)
                    .map_err(|_| EnvelopeError::new("generating KEK"))?;
                write_private_file(path, &kek).map_err(|e| {
                    EnvelopeError::new(format!("writing KEK {}: {e}", path.display()))
                })?;
                // `from_bytes` copies into the locked buffer and zeroizes its own argument; wipe this
                // generated copy too (it had to outlive the `write_private_file` call above).
                let out = Self::from_bytes(kek);
                kek.zeroize();
                Ok(out)
            }
            Err(e) => Err(EnvelopeError::new(format!(
                "reading KEK {}: {e}",
                path.display()
            ))),
        }
    }

    fn key(&self) -> Result<LessSafeKey, EnvelopeError> {
        let unbound = UnboundKey::new(&AES_256_GCM, self.kek.as_slice())
            .map_err(|_| EnvelopeError::new("invalid KEK"))?;
        Ok(LessSafeKey::new(unbound))
    }
}

#[async_trait]
impl KeyEnvelope for LocalKek {
    async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        let key = self.key()?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        SystemRandom::new()
            .fill(&mut nonce_bytes)
            .map_err(|_| EnvelopeError::new("generating nonce"))?;
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let mut in_out = plaintext.to_vec();
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| EnvelopeError::new("seal failed"))?;
        let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + in_out.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&in_out);
        Ok(out)
    }

    async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        let rest = wrapped
            .strip_prefix(MAGIC.as_slice())
            .ok_or_else(|| EnvelopeError::new("not a local-KEK blob (bad magic)"))?;
        if rest.len() < NONCE_LEN {
            return Err(EnvelopeError::new("truncated blob"));
        }
        let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
            .map_err(|_| EnvelopeError::new("bad nonce"))?;
        let key = self.key()?;
        let mut in_out = ciphertext.to_vec();
        let plaintext = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| EnvelopeError::new("unwrap failed (wrong key or tampered)"))?;
        Ok(plaintext.to_vec())
    }
}

/// A [`KeyEnvelope`] backed by **Vault's Transit** engine: `wrap`/
/// `unwrap` are `transit/encrypt|decrypt/<key>` round-trips, so the KEK never
/// leaves Vault and every cluster node unwraps through the same service (no
/// shared local key file). Any KMS exposing a Vault-compatible Transit API works.
/// The token is passed in from the environment (never stored in config files).
pub struct VaultEnvelope {
    client: reqwest::Client,
    encrypt_url: String,
    decrypt_url: String,
    /// The Vault bearer token — a long-lived secret held for the envelope's lifetime. Zeroized on
    /// drop so it does not linger in freed heap. (It is not `mlock`ed: a `String` can reallocate as
    /// it is built, and the token is a bearer credential sent over TLS, not a swap-persisted key —
    /// zeroize-on-drop is the proportionate hardening. See the audit doc.)
    token: Zeroizing<String>,
}

impl VaultEnvelope {
    /// Configure against `addr` (e.g. `https://vault:8200`), Transit key `key`,
    /// and a Vault `token`.
    pub fn new(addr: &str, key: &str, token: String) -> Self {
        let base = addr.trim_end_matches('/');
        Self {
            client: reqwest::Client::new(),
            encrypt_url: format!("{base}/v1/transit/encrypt/{key}"),
            decrypt_url: format!("{base}/v1/transit/decrypt/{key}"),
            token: Zeroizing::new(token),
        }
    }
}

#[derive(Deserialize)]
struct VaultData<T> {
    data: T,
}
#[derive(Deserialize)]
struct VaultCiphertext {
    ciphertext: String,
}
#[derive(Deserialize)]
struct VaultPlaintext {
    plaintext: String,
}

#[async_trait]
impl KeyEnvelope for VaultEnvelope {
    async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(plaintext);
        let resp: VaultData<VaultCiphertext> = self
            .client
            .post(&self.encrypt_url)
            .header("X-Vault-Token", self.token.as_str())
            .json(&serde_json::json!({ "plaintext": b64 }))
            .send()
            .await
            .map_err(|e| EnvelopeError::new(format!("vault encrypt: {e}")))?
            .error_for_status()
            .map_err(|e| EnvelopeError::new(format!("vault encrypt: {e}")))?
            .json()
            .await
            .map_err(|e| EnvelopeError::new(format!("vault encrypt decode: {e}")))?;
        // Vault's `vault:vN:...` ciphertext string is the opaque wrapped blob.
        Ok(resp.data.ciphertext.into_bytes())
    }

    async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        let ciphertext =
            std::str::from_utf8(wrapped).map_err(|e| EnvelopeError::new(e.to_string()))?;
        let resp: VaultData<VaultPlaintext> = self
            .client
            .post(&self.decrypt_url)
            .header("X-Vault-Token", self.token.as_str())
            .json(&serde_json::json!({ "ciphertext": ciphertext }))
            .send()
            .await
            .map_err(|e| EnvelopeError::new(format!("vault decrypt: {e}")))?
            .error_for_status()
            .map_err(|e| EnvelopeError::new(format!("vault decrypt: {e}")))?
            .json()
            .await
            .map_err(|e| EnvelopeError::new(format!("vault decrypt decode: {e}")))?;
        base64::engine::general_purpose::STANDARD
            .decode(resp.data.plaintext.trim())
            .map_err(|e| EnvelopeError::new(format!("vault plaintext base64: {e}")))
    }
}

/// A resolved secrets-at-rest envelope choice (the caller maps its config to
/// this, resolving any Vault token from the environment — never from a file).
pub enum EnvelopeSpec {
    /// No wrapping — secrets stored cleartext (single-node dev / opt-out).
    None,
    /// Machine-local AES-256-GCM KEK at `kek_file`.
    Local { kek_file: PathBuf },
    /// Vault Transit `key` at `addr`, authenticated by `token`.
    Vault {
        addr: String,
        key: String,
        token: String,
    },
}

/// Build the configured [`KeyEnvelope`], or `None` for cleartext.
pub fn build_envelope(spec: EnvelopeSpec) -> Result<Option<Arc<dyn KeyEnvelope>>, EnvelopeError> {
    Ok(match spec {
        EnvelopeSpec::None => None,
        EnvelopeSpec::Local { kek_file } => Some(Arc::new(LocalKek::load_or_generate(&kek_file)?)),
        EnvelopeSpec::Vault { addr, key, token } => {
            Some(Arc::new(VaultEnvelope::new(&addr, &key, token)))
        }
    })
}

/// Write `bytes` to `path` with `0600` permissions on unix (owner-only).
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

// ---------------------------------------------------------------------------
// Identity transport container (project-export `--include-identity`)
//
// A passphrase-protected, portable container for the exported identity material
// (the raw KEK + on-disk sealed key files). Same guarantees as PKCS#12 — portable,
// tamper-detected, useless without the operator's transport passphrase — but over our
// own key types: an Argon2id KDF turns the passphrase into a 32-byte key and AES-256-GCM
// seals the payload. The container carries its own KDF salt + params and the AEAD nonce;
// the raw payload never appears in the output, and the header (salt + params) is bound as
// AEAD associated data so a tampered KDF parameter fails the open rather than silently
// weakening the derivation.
// ---------------------------------------------------------------------------

/// Magic for the identity transport container (bytes `BRIDT1`: boatramp identity transport, v1).
const TRANSPORT_MAGIC: &[u8; 6] = b"BRIDT1";
/// KDF salt length.
const TRANSPORT_SALT_LEN: usize = 16;
/// Argon2id parameters, recorded in the header so an unwrap derives the same key.
/// 64 MiB / 3 passes / 1 lane — a solid transport-key derivation (not an online check).
const TK_M_COST: u32 = 65_536;
const TK_T_COST: u32 = 3;
const TK_P_COST: u32 = 1;
/// Upper bounds on the Argon2 parameters an UNWRAP will honour from the (pre-authentication)
/// container header. The header is AEAD-AAD-bound, but the KDF necessarily runs BEFORE the tag can
/// be checked, so an attacker-crafted container could otherwise declare gigabytes of Argon2 memory
/// and OOM the importer before authentication (a pre-auth DoS). The wrap always records the fixed
/// `TK_*` costs; these ceilings sit well above them (room for a future cost bump) while capping a
/// single derivation's memory far below a denial-of-service. A too-SMALL value needs no clamp —
/// `Params::new` rejects it cheaply.
const TK_M_COST_MAX: u32 = 262_144; // 256 MiB
const TK_T_COST_MAX: u32 = 16;
const TK_P_COST_MAX: u32 = 16;
/// Header length that precedes the nonce: salt + three u32 params.
const TRANSPORT_HDR_PARAMS: usize = TRANSPORT_SALT_LEN + 4 * 3;

/// Derive a 32-byte key from `passphrase` + `salt` via Argon2id with the given params.
fn transport_kdf(
    passphrase: &[u8],
    salt: &[u8],
    m: u32,
    t: u32,
    p: u32,
) -> Result<[u8; KEK_LEN], EnvelopeError> {
    let params = Params::new(m, t, p, Some(KEK_LEN))
        .map_err(|e| EnvelopeError::new(format!("argon2 params: {e}")))?;
    let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEK_LEN];
    a2.hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| EnvelopeError::new(format!("argon2 kdf: {e}")))?;
    Ok(key)
}

/// Wrap `payload` into a passphrase-protected transport container (the PKCS#12-pattern
/// wrapper for exported identity material). `passphrase` must be non-empty.
pub fn transport_wrap(payload: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if passphrase.is_empty() {
        return Err(EnvelopeError::new("transport passphrase must not be empty"));
    }
    let rng = SystemRandom::new();
    let mut salt = [0u8; TRANSPORT_SALT_LEN];
    rng.fill(&mut salt)
        .map_err(|_| EnvelopeError::new("generating salt"))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| EnvelopeError::new("generating nonce"))?;

    // Fixed header (magic + salt + params): bound as AEAD AAD so tampering the KDF
    // parameters fails the open instead of silently changing the derivation.
    let mut header = Vec::with_capacity(TRANSPORT_MAGIC.len() + TRANSPORT_HDR_PARAMS);
    header.extend_from_slice(TRANSPORT_MAGIC);
    header.extend_from_slice(&salt);
    header.extend_from_slice(&TK_M_COST.to_be_bytes());
    header.extend_from_slice(&TK_T_COST.to_be_bytes());
    header.extend_from_slice(&TK_P_COST.to_be_bytes());

    // The Argon2-derived key is sensitive; hold it zeroizing so it is wiped once `LessSafeKey` owns
    // its own internal copy.
    let dk = Zeroizing::new(transport_kdf(
        passphrase, &salt, TK_M_COST, TK_T_COST, TK_P_COST,
    )?);
    let unbound = UnboundKey::new(&AES_256_GCM, dk.as_slice())
        .map_err(|_| EnvelopeError::new("invalid derived key"))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut in_out = payload.to_vec();
    key.seal_in_place_append_tag(nonce, Aad::from(&header), &mut in_out)
        .map_err(|_| EnvelopeError::new("transport seal failed"))?;

    let mut out = Vec::with_capacity(header.len() + NONCE_LEN + in_out.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&in_out);
    Ok(out)
}

/// Unwrap a [`transport_wrap`] container with `passphrase`. Fails with no partial output on
/// a wrong passphrase or any tamper (including a tampered KDF parameter, via the AAD bind).
pub fn transport_unwrap(container: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if !container.starts_with(TRANSPORT_MAGIC.as_slice()) {
        return Err(EnvelopeError::new("not a transport container (bad magic)"));
    }
    if container.len() < TRANSPORT_MAGIC.len() + TRANSPORT_HDR_PARAMS + NONCE_LEN {
        return Err(EnvelopeError::new("truncated transport container"));
    }
    let (header, body) = container.split_at(TRANSPORT_MAGIC.len() + TRANSPORT_HDR_PARAMS);
    let params = &header[TRANSPORT_MAGIC.len()..];
    let (salt, rest) = params.split_at(TRANSPORT_SALT_LEN);
    let m = u32::from_be_bytes(rest[0..4].try_into().unwrap());
    let t = u32::from_be_bytes(rest[4..8].try_into().unwrap());
    let p = u32::from_be_bytes(rest[8..12].try_into().unwrap());
    let (nonce_bytes, ciphertext) = body.split_at(NONCE_LEN);

    // Clamp the header-declared KDF cost BEFORE deriving: the header is AEAD-AAD-bound, but the
    // derivation runs before the tag is verified, so an unbounded `m` from a crafted container is a
    // pre-authentication memory-exhaustion DoS. Refuse out-of-range params up front.
    if m > TK_M_COST_MAX || t > TK_T_COST_MAX || p > TK_P_COST_MAX {
        return Err(EnvelopeError::new(
            "transport container declares out-of-range KDF parameters (refused before key \
             derivation to prevent a pre-authentication memory-exhaustion DoS)",
        ));
    }

    let dk = Zeroizing::new(transport_kdf(passphrase, salt, m, t, p)?);
    let unbound = UnboundKey::new(&AES_256_GCM, dk.as_slice())
        .map_err(|_| EnvelopeError::new("invalid derived key"))?;
    let key = LessSafeKey::new(unbound);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes)
        .map_err(|_| EnvelopeError::new("bad nonce"))?;
    let mut in_out = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(nonce, Aad::from(header), &mut in_out)
        .map_err(|_| {
            EnvelopeError::new("transport unwrap failed (wrong passphrase or tampered)")
        })?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> LocalKek {
        LocalKek::from_bytes([7u8; KEK_LEN])
    }

    // ---- identity transport container -------------------------------------

    #[test]
    fn transport_round_trips_and_hides_the_payload() {
        // A representative payload: a 32-byte KEK plus a tag.
        let payload = {
            let mut v = vec![0xABu8; KEK_LEN];
            v.extend_from_slice(b"+keyfiles");
            v
        };
        let pass = b"correct horse battery staple";
        let c = transport_wrap(&payload, pass).unwrap();
        // The raw payload never appears in the container bytes.
        assert!(
            !c.windows(payload.len()).any(|w| w == payload.as_slice()),
            "payload must not appear in the container"
        );
        // Each wrap is randomized (fresh salt + nonce) → distinct ciphertext.
        let c2 = transport_wrap(&payload, pass).unwrap();
        assert_ne!(c, c2, "salt+nonce must randomize the container");
        // Round-trips under the same passphrase.
        assert_eq!(transport_unwrap(&c, pass).unwrap(), payload);
    }

    #[test]
    fn transport_rejects_wrong_passphrase_tamper_and_bad_input() {
        let payload = b"the exported identity material".to_vec();
        let pass = b"s3cret-transport-key";
        let c = transport_wrap(&payload, pass).unwrap();

        // Wrong passphrase → AEAD open fails, no partial output.
        assert!(transport_unwrap(&c, b"wrong-key").is_err());

        // Tampered ciphertext (flip the last byte) → fails.
        let mut t = c.clone();
        *t.last_mut().unwrap() ^= 0x01;
        assert!(transport_unwrap(&t, pass).is_err());

        // Tampered KDF parameter (an m_cost byte, bound as AAD) → fails rather than
        // silently weakening the derivation. m_cost starts right after magic + salt.
        let m_off = TRANSPORT_MAGIC.len() + TRANSPORT_SALT_LEN;
        let mut p = c.clone();
        p[m_off] ^= 0x01;
        assert!(transport_unwrap(&p, pass).is_err());

        // Empty passphrase refused at wrap.
        assert!(transport_wrap(&payload, b"").is_err());
        // Bad magic + truncated → clean errors, no panic.
        assert!(transport_unwrap(b"not-a-container", pass).is_err());
        assert!(transport_unwrap(TRANSPORT_MAGIC.as_slice(), pass).is_err());
    }

    /// GATE (M2): a container declaring an absurd Argon2 memory cost is refused BEFORE the KDF
    /// runs, so a crafted bundle cannot OOM the importer at the pre-authentication derivation step.
    /// The m_cost u32 is the four bytes immediately after magic + salt (big-endian).
    #[test]
    fn transport_refuses_out_of_range_kdf_cost_before_derivation() {
        let pass = b"s3cret-transport-key";
        let c = transport_wrap(b"identity material".as_slice(), pass).unwrap();
        let m_off = TRANSPORT_MAGIC.len() + TRANSPORT_SALT_LEN;
        let mut poisoned = c.clone();
        // u32::MAX KiB of Argon2 memory — an OOM weapon. The clamp must reject it outright.
        poisoned[m_off..m_off + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = transport_unwrap(&poisoned, pass).unwrap_err();
        assert!(
            format!("{err}").contains("out-of-range KDF parameters"),
            "a huge m_cost must be refused by the pre-derivation clamp, got: {err}"
        );
        // A value just above the ceiling is also refused (boundary).
        let mut just_over = c.clone();
        just_over[m_off..m_off + 4].copy_from_slice(&(TK_M_COST_MAX + 1).to_be_bytes());
        assert!(transport_unwrap(&just_over, pass).is_err());
    }

    #[tokio::test]
    async fn wrap_unwrap_round_trips() {
        let e = kek();
        let secret = b"-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----";
        let wrapped = e.wrap(secret).await.unwrap();
        // The blob is tagged and doesn't contain the plaintext.
        assert!(wrapped.starts_with(MAGIC));
        assert!(!wrapped.windows(6).any(|w| w == b"secret"));
        assert_eq!(e.unwrap(&wrapped).await.unwrap(), secret);
    }

    /// LOCAL diagnostic for image-serve-latency Ask B-3 follow-up Ask (A): production measured
    /// `secret_env_us` ≈ 313 ms resolving ~18 `boatramp:` secrets per serve, yet a block-cached
    /// control-plane get is ~8µs. This times the FULL real per-secret path — `SecretStore::get`
    /// (KV point-get + JSON decode) + the REAL `LocalKek` AES-256-GCM unseal — for 18 secrets fetched
    /// CONCURRENTLY, over an INSTANT in-memory KV. If this is sub-millisecond (it is), the 313 ms is NOT
    /// the envelope or the get-path code — it's environmental: 18 COLD secret-block reads on the production
    /// network `/data` volume (blocks not retained in the block cache under the node's memory pressure).
    /// The fix is therefore to stop reading unused/cold secrets per serve (scope to the component /
    /// resolved-env cache), not to speed a get that is already µs.
    ///
    /// Run: `cargo test -p boatramp-server secret_resolve_cost_is_microseconds -- --ignored --nocapture`
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "diagnostic; run with --ignored --nocapture"]
    async fn secret_resolve_cost_is_microseconds() {
        use boatramp_core::kv::MemoryKv;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::secret_store::SecretStore;
        use std::sync::Arc;

        let store = SecretStore::new(Arc::new(MemoryKv::new()), Arc::new(kek()));
        // 18 secrets, like a production console site (IDP + social refs).
        let names: Vec<String> = (0..18).map(|i| format!("sec{i:02}")).collect();
        for n in &names {
            store
                .set(
                    ProjectRef::DEFAULT,
                    n,
                    b"a-realistic-oauth-client-secret-value",
                )
                .await
                .unwrap();
        }
        // Warm, then time N concurrent gets (the real get + AES-GCM unseal), as resolve_env does.
        let _ = futures::future::join_all(names.iter().map(|n| store.get(ProjectRef::DEFAULT, n)))
            .await;
        let mut samples = Vec::new();
        for _ in 0..200 {
            let t = std::time::Instant::now();
            let got =
                futures::future::join_all(names.iter().map(|n| store.get(ProjectRef::DEFAULT, n)))
                    .await;
            samples.push(t.elapsed());
            assert!(got.iter().all(|r| matches!(r, Ok(Some(_)))));
        }
        samples.sort();
        println!(
            "SECRET-RESOLVE {} secrets concurrent (real LocalKek AES-GCM + instant KV): p50={:?} p99={:?}",
            names.len(),
            samples[samples.len() / 2],
            samples[samples.len() * 99 / 100],
        );
    }

    #[test]
    fn local_kek_debug_never_renders_the_key() {
        // The KEK is the crown jewel; a `{:?}` render of the envelope (via `MlockedKey`'s redacting
        // Debug) must never expose the raw bytes. A distinctive byte would be obvious if it leaked.
        let e = LocalKek::from_bytes([0xAB; KEK_LEN]);
        let d = format!("{e:?}");
        assert!(!d.contains("171"), "decimal KEK byte leaked: {d}"); // 0xAB
        assert!(!d.contains("abababab"), "hex KEK leaked: {d}");
        assert!(d.contains("<redacted>"), "expected redaction marker: {d}");
    }

    #[tokio::test]
    async fn local_kek_round_trips_through_the_mlocked_buffer() {
        // The KEK now lives in an mlocked, zeroize-on-drop buffer; wrap/unwrap must still round-trip
        // (the memory hygiene must not change the crypto).
        let e = kek();
        let wrapped = e.wrap(b"state-or-secret").await.unwrap();
        assert_eq!(e.unwrap(&wrapped).await.unwrap(), b"state-or-secret");
        // A distinct KEK cannot open it (the bytes really are the key, not a constant).
        let other = LocalKek::from_bytes([9u8; KEK_LEN]);
        assert!(other.unwrap(&wrapped).await.is_err());
    }

    #[tokio::test]
    async fn nonce_is_random_so_ciphertext_differs() {
        let e = kek();
        let a = e.wrap(b"same").await.unwrap();
        let b = e.wrap(b"same").await.unwrap();
        assert_ne!(a, b, "each wrap must use a fresh nonce");
    }

    #[tokio::test]
    async fn wrong_key_and_tamper_are_rejected() {
        let e = kek();
        let wrapped = e.wrap(b"data").await.unwrap();

        // A different KEK cannot unwrap.
        let other = LocalKek::from_bytes([9u8; KEK_LEN]);
        assert!(other.unwrap(&wrapped).await.is_err());

        // Flipping a ciphertext byte breaks the GCM tag.
        let mut tampered = wrapped.clone();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert!(e.unwrap(&tampered).await.is_err());

        // A foreign blob (bad magic) is refused.
        assert!(e.unwrap(b"XXXXnonsense").await.is_err());
    }

    #[test]
    fn vault_builds_transit_urls_trimming_trailing_slash() {
        let v = VaultEnvelope::new("https://vault:8200/", "boatramp-certs", "tok".into());
        assert_eq!(
            v.encrypt_url,
            "https://vault:8200/v1/transit/encrypt/boatramp-certs"
        );
        assert_eq!(
            v.decrypt_url,
            "https://vault:8200/v1/transit/decrypt/boatramp-certs"
        );
    }

    #[tokio::test]
    async fn key_file_round_trips_and_is_stable() {
        let dir = std::env::temp_dir().join(format!("brk-test-{}", std::process::id()));
        let path = dir.join("kek");
        let _ = std::fs::remove_file(&path);
        let a = LocalKek::load_or_generate(&path).unwrap();
        let b = LocalKek::load_or_generate(&path).unwrap(); // loads the same key
        let wrapped = a.wrap(b"x").await.unwrap();
        assert_eq!(b.unwrap(&wrapped).await.unwrap(), b"x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "KEK file must be 0600");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
