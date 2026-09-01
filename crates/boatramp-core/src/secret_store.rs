//! Project-scoped internal secret store.
//!
//! Operator secrets sealed with the `[secrets]` key envelope and stored in the
//! control-plane KV under `project/<proj>/secret/<name>` ([`crate::deploy::keys::secret`]).
//! Referenced from any `secrets` map via the `boatramp:<name>` scheme, resolved
//! server-side and unsealed only at handler/function instantiation — the plaintext
//! never lands in a manifest, a log, or an API response (the admin API exposes
//! names + metadata only, never values).
//!
//! This is the multi-tenant-safe secret mechanism: a `boatramp:` ref resolves only
//! within its own project's sealed keyspace, so — unlike a bare/`env:` host-env ref
//! (gated off under multi-tenant) — a tenant can never name another tenant's secret
//! or a host env var. Mirrors `ManagedSqlCredentials`: two `Arc` handles (KV +
//! envelope), cheap to clone.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::envelope::KeyEnvelope;
use crate::kv::KvStore;
use crate::project::ProjectRef;

/// Max secret-name length (it is a KV key segment).
const MAX_SECRET_NAME_LEN: usize = 128;

/// Max secret **value** length. A secret is a credential/token, not a payload; the
/// bound stops a tenant (a project admin on their own project) from sealing an
/// arbitrarily large blob into the replicated control-plane KV — a Raft-amplified
/// write-DoS on the shared plane. 64 KiB is far above any real key/token.
const MAX_SECRET_VALUE_LEN: usize = 64 * 1024;

/// A secret-store failure, classified so the API returns the right status and never
/// leaks backend internals. [`InvalidName`](Self::InvalidName) and
/// [`ValueTooLarge`](Self::ValueTooLarge) are **client** errors — the message is about
/// the *request* (safe to return, maps to `400`). [`Backend`](Self::Backend) is a KV /
/// envelope failure whose detail (KV key shapes, a KMS endpoint/status) is logged
/// server-side and **not** returned (maps to `500`).
#[derive(Debug)]
pub enum SecretError {
    /// The secret name is not a valid KV key segment.
    InvalidName(String),
    /// The value exceeds [`MAX_SECRET_VALUE_LEN`].
    ValueTooLarge { len: usize, max: usize },
    /// A KV or envelope (seal/unseal) failure — detail is not client-safe.
    Backend(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName(m) => write!(f, "{m}"),
            Self::ValueTooLarge { len, max } => {
                write!(f, "secret value is {len} bytes; the maximum is {max}")
            }
            Self::Backend(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for SecretError {}

impl SecretError {
    /// Whether this is a client error (the message describes the request and is safe to
    /// return) vs a backend error (logged, returned generically).
    #[must_use]
    pub fn is_client_error(&self) -> bool {
        matches!(self, Self::InvalidName(_) | Self::ValueTooLarge { .. })
    }
}

/// The sealed record stored at `project/<proj>/secret/<name>`. Metadata is stored
/// in the clear (names/timestamps aren't secret); only `sealed` is confidential.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretRecord {
    /// Schema version, pinned at 1 (no migration until release).
    version: u32,
    /// First-set time (preserved across rotations), unix seconds.
    created_at: u64,
    /// Last-set time, unix seconds.
    updated_at: u64,
    /// Write counter — bumped on every `set` so a rotation is observable.
    revision: u32,
    /// Envelope-sealed secret value.
    sealed: Vec<u8>,
}

impl SecretRecord {
    fn meta(&self, name: &str) -> SecretMeta {
        SecretMeta {
            name: name.to_string(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            revision: self.revision,
        }
    }
}

/// Public, **value-free** metadata for `secrets ls`. Never carries the sealed bytes,
/// so it is safe to return over the admin API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMeta {
    pub name: String,
    pub created_at: u64,
    pub updated_at: u64,
    pub revision: u32,
}

/// A project-scoped sealed secret store over a KV + a key envelope.
#[derive(Clone)]
pub struct SecretStore {
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
}

impl SecretStore {
    #[must_use]
    pub fn new(kv: Arc<dyn KvStore>, envelope: Arc<dyn KeyEnvelope>) -> Self {
        Self { kv, envelope }
    }

    /// Seal `plaintext` and store it at `project/<proj>/secret/<name>`, overwriting
    /// an existing value (rotation). Preserves the original `created_at`, bumps
    /// `revision`. Returns the new metadata (**never** the value). Rejects an
    /// invalid name fail-closed before touching the store.
    pub async fn set(
        &self,
        project: ProjectRef<'_>,
        name: &str,
        plaintext: &[u8],
    ) -> Result<SecretMeta, SecretError> {
        validate_name(name)?;
        if plaintext.len() > MAX_SECRET_VALUE_LEN {
            return Err(SecretError::ValueTooLarge {
                len: plaintext.len(),
                max: MAX_SECRET_VALUE_LEN,
            });
        }
        let key = crate::deploy::keys::secret(project, name);
        let now = crate::time::now_unix();
        let prev = self.load_record(&key).await?;
        let created_at = prev.as_ref().map_or(now, |r| r.created_at);
        let revision = prev.as_ref().map_or(0, |r| r.revision) + 1;
        // Seal before writing; a wrap failure leaves any prior value untouched.
        let sealed = self
            .envelope
            .wrap(plaintext)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        let record = SecretRecord {
            version: 1,
            created_at,
            updated_at: now,
            revision,
            sealed,
        };
        let bytes = serde_json::to_vec(&record).map_err(|e| SecretError::Backend(e.to_string()))?;
        self.kv
            .put(&key, bytes)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        Ok(record.meta(name))
    }

    /// Fetch and unseal a secret's value. `None` if absent. Used by the resolver at
    /// handler/function instantiation — the value is **never** exposed over the API.
    pub async fn get(
        &self,
        project: ProjectRef<'_>,
        name: &str,
    ) -> Result<Option<Vec<u8>>, SecretError> {
        validate_name(name)?;
        let key = crate::deploy::keys::secret(project, name);
        match self.load_record(&key).await? {
            Some(r) => Ok(Some(
                self.envelope
                    .unwrap(&r.sealed)
                    .await
                    .map_err(|e| SecretError::Backend(e.to_string()))?,
            )),
            None => Ok(None),
        }
    }

    /// Value-free metadata for every secret in the project, sorted by name
    /// (`secrets ls`). A record that fails to parse is skipped, never surfaced.
    pub async fn list(&self, project: ProjectRef<'_>) -> Result<Vec<SecretMeta>, SecretError> {
        let prefix = crate::deploy::keys::secret_prefix(project);
        let mut out = Vec::new();
        for key in self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?
        {
            let name = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
            if let Some(bytes) = self
                .kv
                .get(&key)
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?
            {
                if let Ok(record) = serde_json::from_slice::<SecretRecord>(&bytes) {
                    out.push(record.meta(&name));
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Delete a secret. Returns whether it existed.
    pub async fn delete(&self, project: ProjectRef<'_>, name: &str) -> Result<bool, SecretError> {
        validate_name(name)?;
        let key = crate::deploy::keys::secret(project, name);
        let existed = self
            .kv
            .get(&key)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?
            .is_some();
        if existed {
            self.kv
                .delete(&key)
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;
        }
        Ok(existed)
    }

    async fn load_record(&self, key: &str) -> Result<Option<SecretRecord>, SecretError> {
        match self
            .kv
            .get(key)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?
        {
            Some(bytes) => serde_json::from_slice::<SecretRecord>(&bytes)
                .map(Some)
                .map_err(|e| SecretError::Backend(format!("corrupt secret record at {key}: {e}"))),
            None => Ok(None),
        }
    }
}

/// Validate a secret name used as a KV key segment: non-empty, `≤ MAX_SECRET_NAME_LEN`,
/// only `[A-Za-z0-9._-]` (so it can't inject a `/` and reach another keyspace), and
/// not `.`/`..`. Fail-closed on anything else — the name is tenant-supplied.
fn validate_name(name: &str) -> Result<(), SecretError> {
    if name.is_empty() || name.len() > MAX_SECRET_NAME_LEN {
        return Err(SecretError::InvalidName(format!(
            "secret name must be 1..={MAX_SECRET_NAME_LEN} characters"
        )));
    }
    if name == "." || name == ".." {
        return Err(SecretError::InvalidName(
            "secret name must not be '.' or '..'".to_string(),
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        return Err(SecretError::InvalidName(
            "secret name may contain only [A-Za-z0-9._-]".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::EnvelopeError;
    use crate::kv::MemoryKv;

    /// A reversible test envelope: XOR with a constant, so a "sealed" blob is
    /// visibly different from the plaintext (lets us assert at-rest confidentiality)
    /// yet round-trips.
    struct XorEnvelope;
    #[async_trait::async_trait]
    impl KeyEnvelope for XorEnvelope {
        async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(plaintext.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(wrapped.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    fn store() -> SecretStore {
        SecretStore::new(Arc::new(MemoryKv::new()), Arc::new(XorEnvelope))
    }

    #[tokio::test]
    async fn set_get_round_trips_and_is_sealed_at_rest() {
        let s = store();
        let p = ProjectRef::new("acme");
        s.set(p, "db-pw", b"hunter2").await.unwrap();
        assert_eq!(
            s.get(p, "db-pw").await.unwrap().as_deref(),
            Some(&b"hunter2"[..])
        );

        // The value stored in the KV must be sealed — the plaintext must not appear.
        let kv = Arc::new(MemoryKv::new());
        let s2 = SecretStore::new(kv.clone(), Arc::new(XorEnvelope));
        s2.set(p, "db-pw", b"hunter2").await.unwrap();
        let raw = kv
            .get(&crate::deploy::keys::secret(p, "db-pw"))
            .await
            .unwrap()
            .unwrap();
        assert!(
            !raw.windows(7).any(|w| w == b"hunter2"),
            "plaintext must never be stored in the clear"
        );
    }

    #[tokio::test]
    async fn get_absent_is_none() {
        assert!(store()
            .get(ProjectRef::new("acme"), "nope")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn rotate_preserves_created_at_and_bumps_revision() {
        let s = store();
        let p = ProjectRef::new("acme");
        let m1 = s.set(p, "api-key", b"v1").await.unwrap();
        assert_eq!(m1.revision, 1);
        let m2 = s.set(p, "api-key", b"v2").await.unwrap();
        assert_eq!(m2.revision, 2);
        assert_eq!(
            m2.created_at, m1.created_at,
            "created_at preserved across rotation"
        );
        assert_eq!(
            s.get(p, "api-key").await.unwrap().as_deref(),
            Some(&b"v2"[..])
        );
    }

    #[tokio::test]
    async fn list_returns_sorted_value_free_metadata() {
        let s = store();
        let p = ProjectRef::new("acme");
        s.set(p, "beta", b"b").await.unwrap();
        s.set(p, "alpha", b"a").await.unwrap();
        let names: Vec<_> = s
            .list(p)
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert_eq!(names, vec!["alpha".to_string(), "beta".to_string()]);
    }

    #[tokio::test]
    async fn secrets_are_isolated_per_project() {
        let s = store();
        s.set(ProjectRef::new("acme"), "shared-name", b"acme-secret")
            .await
            .unwrap();
        // A different project can't read acme's secret of the same name.
        assert!(s
            .get(ProjectRef::new("globex"), "shared-name")
            .await
            .unwrap()
            .is_none());
        assert!(s.list(ProjectRef::new("globex")).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn delete_reports_existence_then_removes() {
        let s = store();
        let p = ProjectRef::new("acme");
        s.set(p, "gone", b"x").await.unwrap();
        assert!(s.delete(p, "gone").await.unwrap());
        assert!(!s.delete(p, "gone").await.unwrap());
        assert!(s.get(p, "gone").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn invalid_names_are_refused_fail_closed() {
        let s = store();
        let p = ProjectRef::new("acme");
        for bad in [
            "",
            "has/slash",
            "..",
            ".",
            "space bad",
            "new\nline",
            &"x".repeat(129),
        ] {
            assert!(
                s.set(p, bad, b"v").await.is_err(),
                "name {bad:?} must be rejected"
            );
            assert!(
                s.get(p, bad).await.is_err(),
                "name {bad:?} must be rejected"
            );
        }
        // A normal name passes.
        assert!(s.set(p, "ok.name_1-2", b"v").await.is_ok());
    }

    #[tokio::test]
    async fn an_oversized_value_is_refused() {
        let s = store();
        let p = ProjectRef::new("acme");
        // At the bound: fine. Over it: refused (before sealing/writing).
        assert!(s
            .set(p, "big", &vec![b'x'; MAX_SECRET_VALUE_LEN])
            .await
            .is_ok());
        let err = s
            .set(p, "toobig", &vec![b'x'; MAX_SECRET_VALUE_LEN + 1])
            .await
            .expect_err("an oversized value must be refused");
        assert!(
            matches!(err, SecretError::ValueTooLarge { .. }) && err.is_client_error(),
            "{err}"
        );
    }

    #[tokio::test]
    async fn error_classification_client_vs_backend() {
        let s = store();
        let p = ProjectRef::new("acme");
        // An invalid name is a client error (safe to surface).
        let e = s.set(p, "bad/name", b"v").await.unwrap_err();
        assert!(matches!(e, SecretError::InvalidName(_)) && e.is_client_error());
    }
}
