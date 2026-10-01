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
pub const MAX_SECRET_VALUE_LEN: usize = 64 * 1024;

/// Max number of distinct secret **names** a single `(project, tenant)` may hold in the
/// [per-tenant store](TenantSecretStore). Each sealed value is a replicated control-plane write
/// (Raft-amplified) and the amplification is multiplied by the tenant count in a shared-mode
/// project, so an unbounded per-tenant name set is a write-DoS lever (Security MEDIUM-3). A firm's
/// per-provider OAuth `client_secret` set is a handful; 256 is far above any real need.
pub const MAX_TENANT_SECRET_NAMES: usize = 256;

/// Sentinel bytes marking a secret record logically **deleted** (a tombstone). `delete` is a
/// value-[`compare_and_swap`](crate::kv::KvStore::compare_and_swap) to this sentinel, NEVER a blind
/// row-delete: a stale concurrent `set` whose CAS expects the pre-delete bytes then fails rather
/// than resurrecting the secret (the MF-1 set-vs-delete resurrection race). The sentinel is not
/// valid [`SecretRecord`] JSON, so [`decode_record`] maps it to `None` (a deleted secret reads as
/// absent) and `list` skips it.
const TOMBSTONE: &[u8] = b"\x00boatramp:secret-tombstone:v1\x00";

/// Bounded CAS re-read budget for the per-tenant name index (reservation under contention).
const INDEX_CAS_RETRIES: usize = 64;

fn is_tombstone(bytes: &[u8]) -> bool {
    bytes == TOMBSTONE
}

/// Decode the RAW stored bytes at a secret key into a live [`SecretRecord`], treating ABSENT and a
/// TOMBSTONE identically as `None` (no live record). A value that is neither a tombstone nor valid
/// `SecretRecord` JSON is a genuine corruption and surfaces as a backend error.
fn decode_record(raw: Option<&[u8]>, key: &str) -> Result<Option<SecretRecord>, SecretError> {
    match raw {
        None => Ok(None),
        Some(b) if is_tombstone(b) => Ok(None),
        Some(b) => serde_json::from_slice::<SecretRecord>(b)
            .map(Some)
            .map_err(|e| SecretError::Backend(format!("corrupt secret record at {key}: {e}"))),
    }
}

/// Decode the RAW stored bytes of a per-tenant name index, treating ABSENT as an empty index. A
/// present-but-unparseable index is a genuine corruption and surfaces as a backend error.
fn decode_index(raw: Option<&[u8]>) -> Result<TenantNameIndex, SecretError> {
    match raw {
        None => Ok(TenantNameIndex::default()),
        Some(b) => serde_json::from_slice::<TenantNameIndex>(b)
            .map_err(|e| SecretError::Backend(format!("corrupt tenant secret-name index: {e}"))),
    }
}

/// Conditionally delete a secret record by a value-CAS to a [`TOMBSTONE`] (shared by both stores).
/// Returns `Ok(true)` when a live record was transitioned to a tombstone, `Ok(false)` when it was
/// already absent/tombstoned (idempotent), and [`SecretError::Conflict`] when a concurrent writer
/// rotated the record between the observe and the CAS (so a blind delete would have clobbered the
/// rotation). Never a blind `delete`, so it cannot erase a concurrent rotation or let a stale set
/// resurrect the value.
async fn conditional_delete(kv: &dyn KvStore, key: &str) -> Result<bool, SecretError> {
    let raw = kv
        .get(key)
        .await
        .map_err(|e| SecretError::Backend(e.to_string()))?;
    match raw.as_deref() {
        None => Ok(false),
        Some(b) if is_tombstone(b) => Ok(false),
        Some(b) => {
            if kv
                .compare_and_swap(key, Some(b), TOMBSTONE.to_vec())
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?
            {
                Ok(true)
            } else {
                // The record changed between the read and the CAS. Re-read to classify: a
                // concurrent delete (now absent/tombstone) is an idempotent no-op; a concurrent
                // rotation (a different live record) is a Conflict — refuse to clobber it.
                match kv
                    .get(key)
                    .await
                    .map_err(|e| SecretError::Backend(e.to_string()))?
                    .as_deref()
                {
                    None => Ok(false),
                    Some(b2) if is_tombstone(b2) => Ok(false),
                    Some(_) => Err(SecretError::Conflict(
                        "the secret was modified concurrently (a rotation raced this delete); \
                         re-read and retry"
                            .to_string(),
                    )),
                }
            }
        }
    }
}

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
    /// The `tenant` key segment (per-tenant store) is not a valid resource name — it is empty,
    /// carries a path separator / `*` / whitespace / control char, or exceeds 63 bytes, so it could
    /// reshape the key to a sibling tenant's. A **client** error (the message describes the request,
    /// safe to return → `400`). Distinct from [`InvalidName`](Self::InvalidName) so a caller can tell
    /// which segment failed.
    InvalidTenant(String),
    /// The value exceeds [`MAX_SECRET_VALUE_LEN`].
    ValueTooLarge { len: usize, max: usize },
    /// A `(project, tenant)` already holds [`MAX_TENANT_SECRET_NAMES`] distinct names and this `set`
    /// would introduce a NEW one (a rotation of an existing name is always allowed). A **client**
    /// error (the message is about the request → `400`), bounding the Raft-amplified write set.
    TooManyNames { max: usize },
    /// A concurrent writer rotated or deleted this secret between the read and the
    /// compare-and-swap, so this write was NOT applied (no silent clobber / no lost rotation). The
    /// caller re-reads and retries. The message is request-level and safe to surface. Mapped to
    /// `409 Conflict` over the admin API.
    Conflict(String),
    /// A KV or envelope (seal/unseal) failure — detail is not client-safe.
    Backend(String),
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidName(m) => write!(f, "{m}"),
            Self::InvalidTenant(m) => write!(f, "{m}"),
            Self::ValueTooLarge { len, max } => {
                write!(f, "secret value is {len} bytes; the maximum is {max}")
            }
            Self::TooManyNames { max } => {
                write!(
                    f,
                    "this tenant already holds the maximum of {max} secret names"
                )
            }
            Self::Conflict(m) => write!(f, "{m}"),
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
        matches!(
            self,
            Self::InvalidName(_)
                | Self::InvalidTenant(_)
                | Self::ValueTooLarge { .. }
                | Self::TooManyNames { .. }
        )
    }

    /// Whether this is an optimistic-concurrency [`Conflict`](Self::Conflict) — a concurrent
    /// crown-jewel write won the race, so this one was refused rather than silently clobbering it.
    /// The admin API maps it to `409 Conflict` (re-read + retry), distinct from a `400` request
    /// error and a `500` backend error.
    #[must_use]
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Conflict(_))
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

/// The per-`(project, tenant)` secret-NAME index stored at
/// [`keys::tenant_secret_index`](crate::deploy::keys::tenant_secret_index): the live secret names a
/// tenant holds, maintained by a value-CAS so the per-tenant name-count CAP is enforced ATOMICALLY
/// (a compare-and-swap admission) instead of the old `list_prefix`-then-check-then-write TOCTOU, in
/// which two racing new-name sets each read `count = max-1` and both wrote, bypassing the cap.
#[derive(Debug, Default, Serialize, Deserialize)]
struct TenantNameIndex {
    /// Sorted, deduped live secret names for this `(project, tenant)`. Bounded by
    /// [`MAX_TENANT_SECRET_NAMES`].
    names: Vec<String>,
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

        // MF-1 mutation (gate only): revert to the pre-MF-1 blind read-modify-write (no CAS), so
        // concurrent rotations silently clobber each other — the gate then goes RED.
        if crate::crownjewel::cas_mutation_active() {
            let prev = self.load_record(&key).await?;
            let created_at = prev.as_ref().map_or(now, |r| r.created_at);
            let revision = prev.as_ref().map_or(0, |r| r.revision) + 1;
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
            let bytes =
                serde_json::to_vec(&record).map_err(|e| SecretError::Backend(e.to_string()))?;
            self.kv
                .put(&key, bytes)
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;
            return Ok(record.meta(name));
        }

        // Read the EXACT prior bytes and compare-and-swap on them: a concurrent rotation/delete
        // between the read and the write changes the bytes, so this CAS loses and returns
        // `Conflict` (the caller re-reads + re-rotates) — never a silent clobber / lost rotation.
        let prev_raw = self
            .kv
            .get(&key)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        let prev = decode_record(prev_raw.as_deref(), &key)?;
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
        let swapped = self
            .kv
            .compare_and_swap(&key, prev_raw.as_deref(), bytes)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        if !swapped {
            return Err(SecretError::Conflict(
                "the secret was rotated or deleted concurrently; re-read and retry".to_string(),
            ));
        }
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
                && let Ok(record) = serde_json::from_slice::<SecretRecord>(&bytes)
            {
                out.push(record.meta(&name));
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Delete a secret. Returns whether it existed. A conditional (value-CAS to a tombstone)
    /// delete, so a concurrent rotation racing the delete is never clobbered and a stale `set`
    /// cannot resurrect the deleted value (MF-1); a concurrent rotation yields
    /// [`SecretError::Conflict`].
    pub async fn delete(&self, project: ProjectRef<'_>, name: &str) -> Result<bool, SecretError> {
        validate_name(name)?;
        let key = crate::deploy::keys::secret(project, name);

        // MF-1 mutation (gate only): the pre-MF-1 blind read-then-delete — no conditional CAS.
        if crate::crownjewel::cas_mutation_active() {
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
            return Ok(existed);
        }

        conditional_delete(self.kv.as_ref(), &key).await
    }

    async fn load_record(&self, key: &str) -> Result<Option<SecretRecord>, SecretError> {
        let raw = self
            .kv
            .get(key)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        decode_record(raw.as_deref(), key)
    }
}

/// A per-**tenant** sealed secret store: the SAME sealed-record + envelope code as
/// [`SecretStore`], re-keyed `project/<proj>/tenant-secret/<tenant>/<name>` (a DISTINCT
/// keyspace from the project `secret/` store — the two never collide even for the same name).
///
/// This backs the runtime `boatramp:handlers/tenant-secrets` guest capability AND the
/// owner-gated control-plane write path. The `tenant` segment is host-supplied — for the guest it
/// is THIS invocation's resolved tenant (never guest input), for the control plane it is the
/// `{tenant}` URL-path segment. Either way it becomes a KV key segment, so EVERY method validates
/// it (via [`crate::project::validate_resource_name`]) AND the `name` (via [`validate_name`])
/// **fail-closed, BEFORE composing the key** — so a guest read and a control-plane write key
/// byte-identical segments and neither can escape the `<tenant>/<name>` prefix (Security HIGH-2 /
/// Backend C1). `list` keys its prefix on the tenant (never project-wide → no cross-tenant name
/// oracle, Security HIGH-3 / Backend C3). Lives in `boatramp-core` (NOT `handlers`-gated) so the
/// control-plane routes compile on a lean node (Backend C5).
///
/// Two `Arc` handles (KV + envelope), cheap to clone — like [`SecretStore`].
#[derive(Clone)]
pub struct TenantSecretStore {
    kv: Arc<dyn KvStore>,
    envelope: Arc<dyn KeyEnvelope>,
}

impl TenantSecretStore {
    #[must_use]
    pub fn new(kv: Arc<dyn KvStore>, envelope: Arc<dyn KeyEnvelope>) -> Self {
        Self { kv, envelope }
    }

    /// Seal `plaintext` under `(project, tenant, name)`, overwriting an existing value (rotation).
    /// Preserves the original `created_at`, bumps `revision`. Returns the value-free metadata.
    /// Validates BOTH segments fail-closed, enforces the value-size + per-`(project,tenant)`
    /// name-count caps, all BEFORE touching the store.
    pub async fn set(
        &self,
        project: ProjectRef<'_>,
        tenant: &str,
        name: &str,
        plaintext: &[u8],
    ) -> Result<SecretMeta, SecretError> {
        validate_tenant(tenant)?;
        validate_name(name)?;
        if plaintext.len() > MAX_SECRET_VALUE_LEN {
            return Err(SecretError::ValueTooLarge {
                len: plaintext.len(),
                max: MAX_SECRET_VALUE_LEN,
            });
        }
        let key = crate::deploy::keys::tenant_secret(project, tenant, name);
        let now = crate::time::now_unix();

        // MF-1 mutation (gate only): the pre-MF-1 blind path — the `list_prefix`-then-check cap
        // TOCTOU + a blind put. Under concurrency two new-name sets both read `count = max-1` and
        // both write, bypassing the cap — so the gate goes RED.
        if crate::crownjewel::cas_mutation_active() {
            let prev = self.load_record(&key).await?;
            if prev.is_none() {
                let prefix = crate::deploy::keys::tenant_secret_prefix(project, tenant);
                let existing = self
                    .kv
                    .list_prefix(&prefix)
                    .await
                    .map_err(|e| SecretError::Backend(e.to_string()))?
                    .len();
                if existing >= MAX_TENANT_SECRET_NAMES {
                    return Err(SecretError::TooManyNames {
                        max: MAX_TENANT_SECRET_NAMES,
                    });
                }
            }
            let created_at = prev.as_ref().map_or(now, |r| r.created_at);
            let revision = prev.as_ref().map_or(0, |r| r.revision) + 1;
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
            let bytes =
                serde_json::to_vec(&record).map_err(|e| SecretError::Backend(e.to_string()))?;
            self.kv
                .put(&key, bytes)
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;
            return Ok(record.meta(name));
        }

        let prev_raw = self
            .kv
            .get(&key)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        let prev = decode_record(prev_raw.as_deref(), &key)?;
        let is_new_name = prev.is_none();
        // A NEW name is admitted against the per-tenant name-count cap ATOMICALLY, via a value-CAS
        // on the per-tenant index record — closing the old list-then-write TOCTOU (two racing
        // new-name sets can no longer both pass a stale count). A rotation of an existing name never
        // counts. The index is keyed on the tenant, so the cap check can never see another tenant's
        // names. `reserved` is true only when THIS call added the name (not a concurrent same-name
        // set), so a lost record-CAS below releases only a slot it actually took.
        let reserved = if is_new_name {
            self.reserve_name(project, tenant, name).await?
        } else {
            false
        };

        let created_at = prev.as_ref().map_or(now, |r| r.created_at);
        let revision = prev.as_ref().map_or(0, |r| r.revision) + 1;
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
        let swapped = self
            .kv
            .compare_and_swap(&key, prev_raw.as_deref(), bytes)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        if !swapped {
            // A concurrent create/rotate/delete of this name won the record race. Release the cap
            // slot if this call reserved it (keeps the count exact).
            if reserved {
                let _ = self.release_name(project, tenant, name).await;
            }
            return Err(SecretError::Conflict(
                "the tenant secret was rotated or deleted concurrently; re-read and retry"
                    .to_string(),
            ));
        }
        Ok(record.meta(name))
    }

    /// Atomically admit `name` against the per-tenant name-count cap by a value-CAS on the index
    /// record: returns `Ok(true)` when THIS call added the name, `Ok(false)` when it was already
    /// present (a concurrent same-name set admitted it first — a rotation, not a new name), and
    /// [`SecretError::TooManyNames`] when the cap is already full. Bounded retry under contention.
    async fn reserve_name(
        &self,
        project: ProjectRef<'_>,
        tenant: &str,
        name: &str,
    ) -> Result<bool, SecretError> {
        let idx_key = crate::deploy::keys::tenant_secret_index(project, tenant);
        for _ in 0..INDEX_CAS_RETRIES {
            let raw = self
                .kv
                .get(&idx_key)
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;
            let mut idx = decode_index(raw.as_deref())?;
            if idx.names.iter().any(|n| n == name) {
                return Ok(false); // already admitted — a rotation, not a new name
            }
            if idx.names.len() >= MAX_TENANT_SECRET_NAMES {
                return Err(SecretError::TooManyNames {
                    max: MAX_TENANT_SECRET_NAMES,
                });
            }
            idx.names.push(name.to_string());
            idx.names.sort();
            let new_bytes =
                serde_json::to_vec(&idx).map_err(|e| SecretError::Backend(e.to_string()))?;
            if self
                .kv
                .compare_and_swap(&idx_key, raw.as_deref(), new_bytes)
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?
            {
                return Ok(true);
            }
            // The index changed under us — re-read and retry.
        }
        Err(SecretError::Conflict(
            "the tenant secret-name index is contended; retry".to_string(),
        ))
    }

    /// Best-effort release of a per-tenant name slot (CAS-removing `name` from the index). A stale
    /// index entry only ever over-counts the cap (fail-safe — never a bypass), so an exhausted
    /// retry budget is swallowed rather than failing the caller.
    async fn release_name(&self, project: ProjectRef<'_>, tenant: &str, name: &str) {
        let idx_key = crate::deploy::keys::tenant_secret_index(project, tenant);
        for _ in 0..INDEX_CAS_RETRIES {
            let Ok(raw) = self.kv.get(&idx_key).await else {
                return;
            };
            let Ok(mut idx) = decode_index(raw.as_deref()) else {
                return;
            };
            let before = idx.names.len();
            idx.names.retain(|n| n != name);
            if idx.names.len() == before {
                return; // not present
            }
            let Ok(new_bytes) = serde_json::to_vec(&idx) else {
                return;
            };
            match self
                .kv
                .compare_and_swap(&idx_key, raw.as_deref(), new_bytes)
                .await
            {
                Ok(true) => return,
                Ok(false) => continue, // contended — retry
                Err(_) => return,
            }
        }
    }

    /// Fetch and unseal `(project, tenant, name)`. `None` if absent (an unconfigured secret is NOT
    /// an error — the guest surface returns `ok(none)`). Validates both segments fail-closed first.
    pub async fn get(
        &self,
        project: ProjectRef<'_>,
        tenant: &str,
        name: &str,
    ) -> Result<Option<Vec<u8>>, SecretError> {
        validate_tenant(tenant)?;
        validate_name(name)?;
        let key = crate::deploy::keys::tenant_secret(project, tenant, name);
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

    /// Value-free metadata for every secret of ONE `(project, tenant)`, sorted by name. Keyed on the
    /// tenant prefix, so it can only ever enumerate the resolved tenant's own names (no cross-tenant
    /// name oracle). Validates the tenant segment fail-closed first.
    pub async fn list(
        &self,
        project: ProjectRef<'_>,
        tenant: &str,
    ) -> Result<Vec<SecretMeta>, SecretError> {
        validate_tenant(tenant)?;
        let prefix = crate::deploy::keys::tenant_secret_prefix(project, tenant);
        let mut out = Vec::new();
        for key in self
            .kv
            .list_prefix(&prefix)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?
        {
            // The strip tail is a single `<name>` segment (the tenant is already in the prefix).
            let name = key.strip_prefix(&prefix).unwrap_or(&key).to_string();
            if let Some(bytes) = self
                .kv
                .get(&key)
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?
                && let Ok(record) = serde_json::from_slice::<SecretRecord>(&bytes)
            {
                out.push(record.meta(&name));
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// Delete `(project, tenant, name)`. Returns whether it existed. A conditional (value-CAS to a
    /// tombstone) delete that also frees the per-tenant cap slot — so a concurrent rotation is
    /// never clobbered and a stale `set` cannot resurrect the value (MF-1).
    pub async fn delete(
        &self,
        project: ProjectRef<'_>,
        tenant: &str,
        name: &str,
    ) -> Result<bool, SecretError> {
        validate_tenant(tenant)?;
        validate_name(name)?;
        let key = crate::deploy::keys::tenant_secret(project, tenant, name);

        // MF-1 mutation (gate only): the pre-MF-1 blind read-then-delete.
        if crate::crownjewel::cas_mutation_active() {
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
            return Ok(existed);
        }

        let removed = conditional_delete(self.kv.as_ref(), &key).await?;
        if removed {
            // Free the per-tenant cap slot (best-effort; a stale index entry is fail-safe).
            self.release_name(project, tenant, name).await;
        }
        Ok(removed)
    }

    async fn load_record(&self, key: &str) -> Result<Option<SecretRecord>, SecretError> {
        let raw = self
            .kv
            .get(key)
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        decode_record(raw.as_deref(), key)
    }
}

/// Validate a `tenant` used as a KV key segment in the [`TenantSecretStore`]. Runs the
/// **key-safety** rule [`validate_key_segment`](crate::project::validate_key_segment)
/// (rejects empty/`/`/`\`/`..`/`.`/`*`/whitespace/control/>63B) — NOT the strict single-label
/// slug of [`validate_resource_name`]. The `tenant` here is a **data-plane** value: the
/// host-resolved `ScopeAxis::Tenant` from a signed `tid` claim, routinely an email
/// (`user@acme.com`) or a dotted domain (`acme.corp`). It must be key-safe (no separator can
/// reshape the key to a sibling tenant's), but must NOT be forced through the operator-
/// identifier slug — that would silently break sealed-secret access for every email/dotted
/// tenant. The guest-read tenant and the `{tenant}` URL-path segment canonicalize identically
/// under this rule. Fail-closed — a `/`-bearing one is refused before any store access. Mapped
/// to the client-safe [`SecretError::InvalidTenant`].
fn validate_tenant(tenant: &str) -> Result<(), SecretError> {
    crate::project::validate_key_segment("tenant", tenant)
        .map_err(|e| SecretError::InvalidTenant(e.to_string()))
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
        assert!(
            store()
                .get(ProjectRef::new("acme"), "nope")
                .await
                .unwrap()
                .is_none()
        );
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
        assert!(
            s.get(ProjectRef::new("globex"), "shared-name")
                .await
                .unwrap()
                .is_none()
        );
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
        assert!(
            s.set(p, "big", &vec![b'x'; MAX_SECRET_VALUE_LEN])
                .await
                .is_ok()
        );
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

    // ---- TenantSecretStore ------------------------------------------------

    fn tenant_store() -> TenantSecretStore {
        TenantSecretStore::new(Arc::new(MemoryKv::new()), Arc::new(XorEnvelope))
    }

    #[tokio::test]
    async fn tenant_set_get_round_trips_and_is_sealed_at_rest() {
        let kv = Arc::new(MemoryKv::new());
        let s = TenantSecretStore::new(kv.clone(), Arc::new(XorEnvelope));
        let p = ProjectRef::new("acme");
        s.set(p, "firm-1", "oauth_secret", b"hunter2")
            .await
            .unwrap();
        assert_eq!(
            s.get(p, "firm-1", "oauth_secret").await.unwrap().as_deref(),
            Some(&b"hunter2"[..])
        );
        // The value stored in the KV must be sealed — the plaintext must not appear at rest.
        let raw = kv
            .get(&crate::deploy::keys::tenant_secret(
                p,
                "firm-1",
                "oauth_secret",
            ))
            .await
            .unwrap()
            .unwrap();
        assert!(
            !raw.windows(7).any(|w| w == b"hunter2"),
            "plaintext must never be stored in the clear"
        );
    }

    #[tokio::test]
    async fn tenant_get_absent_is_none() {
        // An unconfigured secret is `None`, NEVER an error (the guest surface returns ok(none)).
        assert!(
            tenant_store()
                .get(ProjectRef::new("acme"), "firm-1", "nope")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn tenant_rotate_preserves_created_at_and_bumps_revision() {
        let s = tenant_store();
        let p = ProjectRef::new("acme");
        let m1 = s.set(p, "firm-1", "api-key", b"v1").await.unwrap();
        assert_eq!(m1.revision, 1);
        let m2 = s.set(p, "firm-1", "api-key", b"v2").await.unwrap();
        assert_eq!(m2.revision, 2);
        assert_eq!(
            m2.created_at, m1.created_at,
            "created_at preserved across rotation"
        );
        assert_eq!(
            s.get(p, "firm-1", "api-key").await.unwrap().as_deref(),
            Some(&b"v2"[..])
        );
    }

    #[tokio::test]
    async fn secrets_are_isolated_per_tenant_and_list_never_leaks_a_sibling() {
        // THE isolation property: tenant A sets a secret; tenant B — same project, same name —
        // sees NOTHING, and A's `list` never enumerates B's names (no cross-tenant name oracle).
        let s = tenant_store();
        let p = ProjectRef::new("acme");
        s.set(p, "firm-a", "oauth_secret", b"a-secret")
            .await
            .unwrap();
        s.set(p, "firm-b", "stripe_key", b"b-secret").await.unwrap();

        // B cannot read A's secret of the same logical purpose (different tenant segment).
        assert!(s.get(p, "firm-b", "oauth_secret").await.unwrap().is_none());
        // A's list shows ONLY A's names — never `stripe_key` (B's).
        let a_names: Vec<_> = s
            .list(p, "firm-a")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert_eq!(a_names, vec!["oauth_secret".to_string()]);
        let b_names: Vec<_> = s
            .list(p, "firm-b")
            .await
            .unwrap()
            .into_iter()
            .map(|m| m.name)
            .collect();
        assert_eq!(b_names, vec!["stripe_key".to_string()]);
    }

    #[tokio::test]
    async fn tenant_secrets_are_isolated_per_project() {
        let s = tenant_store();
        s.set(ProjectRef::new("acme"), "firm-1", "k", b"acme-secret")
            .await
            .unwrap();
        // A different project can't read acme's secret of the same tenant+name.
        assert!(
            s.get(ProjectRef::new("globex"), "firm-1", "k")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            s.list(ProjectRef::new("globex"), "firm-1")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn tenant_delete_reports_existence_then_removes() {
        let s = tenant_store();
        let p = ProjectRef::new("acme");
        s.set(p, "firm-1", "gone", b"x").await.unwrap();
        assert!(s.delete(p, "firm-1", "gone").await.unwrap());
        assert!(!s.delete(p, "firm-1", "gone").await.unwrap());
        assert!(s.get(p, "firm-1", "gone").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn invalid_tenant_segment_is_refused_fail_closed() {
        // The tenant is a KV key segment; a `/`/`..`/`*`/empty/oversized tenant must be refused
        // (via the canonical validator) BEFORE any store access — else it could reshape the key
        // to a sibling tenant's, the whole point of the capability.
        let s = tenant_store();
        let p = ProjectRef::new("acme");
        for bad in [
            "",
            "has/slash",
            "..",
            ".",
            "star*",
            "back\\slash",
            "space bad",
            "new\nline",
            &"x".repeat(64),
        ] {
            assert!(
                matches!(
                    s.set(p, bad, "k", b"v").await,
                    Err(SecretError::InvalidTenant(_))
                ),
                "tenant {bad:?} must be rejected as InvalidTenant on set"
            );
            assert!(
                matches!(s.get(p, bad, "k").await, Err(SecretError::InvalidTenant(_))),
                "tenant {bad:?} must be rejected on get"
            );
            assert!(
                matches!(s.list(p, bad).await, Err(SecretError::InvalidTenant(_))),
                "tenant {bad:?} must be rejected on list"
            );
            assert!(
                matches!(
                    s.delete(p, bad, "k").await,
                    Err(SecretError::InvalidTenant(_))
                ),
                "tenant {bad:?} must be rejected on delete"
            );
        }
        // A numeric tenant id (the common shared-mode `app.tenant_id`) round-trips.
        assert!(s.set(p, "42", "k", b"v").await.is_ok());
        assert_eq!(
            s.get(p, "42", "k").await.unwrap().as_deref(),
            Some(&b"v"[..])
        );
    }

    #[tokio::test]
    async fn invalid_name_segment_is_refused_fail_closed() {
        let s = tenant_store();
        let p = ProjectRef::new("acme");
        for bad in ["", "has/slash", "..", ".", "space bad", &"x".repeat(129)] {
            assert!(
                matches!(
                    s.set(p, "firm-1", bad, b"v").await,
                    Err(SecretError::InvalidName(_))
                ),
                "name {bad:?} must be rejected"
            );
            assert!(
                matches!(
                    s.get(p, "firm-1", bad).await,
                    Err(SecretError::InvalidName(_))
                ),
                "name {bad:?} must be rejected"
            );
        }
        assert!(s.set(p, "firm-1", "ok.name_1-2", b"v").await.is_ok());
    }

    #[tokio::test]
    async fn tenant_oversized_value_is_refused() {
        let s = tenant_store();
        let p = ProjectRef::new("acme");
        assert!(
            s.set(p, "firm-1", "big", &vec![b'x'; MAX_SECRET_VALUE_LEN])
                .await
                .is_ok()
        );
        let err = s
            .set(p, "firm-1", "toobig", &vec![b'x'; MAX_SECRET_VALUE_LEN + 1])
            .await
            .expect_err("an oversized value must be refused");
        assert!(matches!(err, SecretError::ValueTooLarge { .. }) && err.is_client_error());
    }

    #[tokio::test]
    async fn per_tenant_name_count_cap_is_enforced_but_rotation_is_free() {
        // A fresh store with a tiny effective cap is awkward to construct without exposing the const;
        // instead fill to the real cap. To keep the test fast we set the cap-many names, assert the
        // (cap+1)-th NEW name is refused, but rotating an EXISTING name still works.
        let s = tenant_store();
        let p = ProjectRef::new("acme");
        for i in 0..MAX_TENANT_SECRET_NAMES {
            s.set(p, "firm-1", &format!("k{i}"), b"v").await.unwrap();
        }
        // A brand-new name over the cap is refused.
        let err = s
            .set(p, "firm-1", "one-too-many", b"v")
            .await
            .expect_err("a new name past the cap must be refused");
        assert!(matches!(err, SecretError::TooManyNames { .. }) && err.is_client_error());
        // Rotating an existing name is always allowed (it introduces no new name).
        assert!(s.set(p, "firm-1", "k0", b"rotated").await.is_ok());
        // A DIFFERENT tenant is unaffected by firm-1's saturation.
        assert!(s.set(p, "firm-2", "fresh", b"v").await.is_ok());
    }
}
