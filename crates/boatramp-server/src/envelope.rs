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

use async_trait::async_trait;
use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine as _;
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use serde::Deserialize;

/// Wire-format tag: `b"BRK1"`. A wrapped blob is `MAGIC || nonce(12) ||
/// ciphertext+tag`, so `unwrap` fail-closes on a foreign or truncated blob.
const MAGIC: &[u8; 4] = b"BRK1";
/// AES-256 key length.
const KEK_LEN: usize = 32;

/// AES-256-GCM envelope under a machine-local key-encryption key (KEK).
pub struct LocalKek {
    kek: [u8; KEK_LEN],
}

impl LocalKek {
    /// Build from a raw 32-byte KEK.
    pub fn from_bytes(kek: [u8; KEK_LEN]) -> Self {
        Self { kek }
    }

    /// Load the KEK from `path` (raw 32 bytes), generating + persisting one
    /// (`0600`) if the file does not exist. In a cluster the **same** file must
    /// be present on every node (wrapped certs replicate).
    pub fn load_or_generate(path: &Path) -> Result<Self, EnvelopeError> {
        match std::fs::read(path) {
            Ok(bytes) => {
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
                Ok(Self::from_bytes(kek))
            }
            Err(e) => Err(EnvelopeError::new(format!(
                "reading KEK {}: {e}",
                path.display()
            ))),
        }
    }

    fn key(&self) -> Result<LessSafeKey, EnvelopeError> {
        let unbound = UnboundKey::new(&AES_256_GCM, &self.kek)
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
    token: String,
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
            token,
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
            .header("X-Vault-Token", &self.token)
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
            .header("X-Vault-Token", &self.token)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn kek() -> LocalKek {
        LocalKek::from_bytes([7u8; KEK_LEN])
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

    /// LOCAL diagnostic for image-serve-latency Ask B-3 follow-up Ask (A): construens measured
    /// `secret_env_us` ≈ 313 ms resolving ~18 `boatramp:` secrets per serve, yet a block-cached
    /// control-plane get is ~8µs. This times the FULL real per-secret path — `SecretStore::get`
    /// (KV point-get + JSON decode) + the REAL `LocalKek` AES-256-GCM unseal — for 18 secrets fetched
    /// CONCURRENTLY, over an INSTANT in-memory KV. If this is sub-millisecond (it is), the 313 ms is NOT
    /// the envelope or the get-path code — it's environmental: 18 COLD secret-block reads on construens'
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
        // 18 secrets, like construens' console site (IDP + social refs).
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
