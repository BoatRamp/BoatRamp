//! Tenant-scoped snapshot store for **cross-node scale-to-zero** (U14).
//!
//! A scale-to-zero replica's snapshot is raw guest memory (a microVM RAM image, a CRIU
//! checkpoint) — tenant data that may hold secrets. To let a parked workload wake on a node
//! OTHER than the one that parked it, the reconcile exports the snapshot artifact here on
//! park and imports it on the resume node before `restore`. This module is the bridge from
//! [`boatramp_core::compute::SnapshotStore`] to the project's **own** blob
//! [`Storage`](boatramp_core::Storage) backend, reusing the exact per-project credential
//! path + isolation every other tenant-blob access uses (per-project backend selection via
//! [`BlobBackends`], then a project-scoped key).
//!
//! ## Isolation contract (the heart of U14's security)
//! The Storage object for a snapshot is addressed by a **project-scoped key** on the
//! **project's own backend**:
//! - backend = `BlobBackends::backend(project)` — a configured per-project backend gives
//!   PHYSICAL isolation (a separate bucket/credential); an unconfigured project resolves the
//!   node default, where the key prefix is the isolation.
//! - key = `csnap/<project>/<workload>/<replica>.tar` — the `<project>` segment makes one
//!   tenant's key byte-distinct from another's even on a shared backend, so two projects'
//!   same-named `web/0` snapshots can NEVER collide or resolve to each other.
//!
//! A node only ever addresses a snapshot by its OWN `(project, workload, replica)` (the key
//! is derived from the snapshot's own identity, never from caller input), so it can never
//! fetch another tenant's snapshot. The reserved `csnap/` family is control-plane only and
//! never reachable from a guest blob binding (guests are confined to `hblob/<site>/…`).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::blob_backends::BlobBackends;
use boatramp_core::compute::{SnapshotArtifact, SnapshotKey, SnapshotStore, SnapshotStoreError};
use boatramp_core::envelope::KeyEnvelope;
use boatramp_core::project::ProjectRef;
use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
use bytes::Bytes;
use futures::StreamExt;
use sha2::{Digest, Sha256};

/// The reserved blob family prefix for compute scale-to-zero snapshots. Control-plane only
/// (never a guest-reachable key), and project-scoped under it — see the module contract.
const SNAPSHOT_FAMILY: &str = "csnap";

/// Bound (chunks) of the in-flight channel bridging the blocking `tar` reader/writer to the
/// async Storage stream. A full channel backpressures the blocking side, so a multi-gigabyte
/// RAM snapshot never buffers whole in memory — it flows through with O(chunk) memory.
const STREAM_CHUNK_CHANNEL: usize = 4;

/// Default disk-fill bound on an IMPORT unpack (C-ii, symmetric with the OCI pull caps'
/// `DEFAULT_PULL_MAX_IMAGE_BYTES` = 20 GiB): an import whose archive exceeds this is refused
/// → clean cold-start, so a corrupt/planted object can never fill the resume node's disk. Set
/// above any realistic parkable-workload RAM image; an operator who parks genuinely larger
/// microVMs raises it via [`BlobSnapshotStore::with_max_import_bytes`].
const DEFAULT_MAX_IMPORT_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// Cap on a seal sidecar read — the sealed 32-byte digest plus envelope framing is tiny, so a
/// larger "seal" is itself a tamper signal (refused → cold-start).
const MAX_SEAL_BYTES: usize = 64 * 1024;

/// A [`SnapshotStore`] over the node's per-project blob [`BlobBackends`] provider.
pub struct BlobSnapshotStore {
    provider: Arc<dyn BlobBackends>,
    /// The node's secrets envelope (the cluster-shared sealing key — the SAME key that seals
    /// portable tenant secrets, so a resume node can verify a snapshot the parking node sealed).
    /// When present, every exported snapshot carries an authenticated-integrity seal (an HMAC
    /// analogue: the archive digest sealed under the envelope) that import verifies fail-closed,
    /// so snapshot authenticity doesn't rest solely on the `csnap/` prefix confinement. `None`
    /// (no `[secrets]` envelope) ⇒ unsealed (prefix-confinement only), logged once per import.
    envelope: Option<Arc<dyn KeyEnvelope>>,
    /// Disk-fill bound on an import unpack (C-ii).
    max_import_bytes: u64,
}

impl BlobSnapshotStore {
    /// Build the store over the per-project blob-backend provider (the same one the handler
    /// `blobstore` binding resolves through, so snapshots land on the project's own backend)
    /// and the node's secrets envelope (the cluster-shared seal key; `None` ⇒ unsealed).
    pub fn new(provider: Arc<dyn BlobBackends>, envelope: Option<Arc<dyn KeyEnvelope>>) -> Self {
        Self {
            provider,
            envelope,
            max_import_bytes: DEFAULT_MAX_IMPORT_BYTES,
        }
    }

    /// Override the import disk-fill bound (operator tuning / tests).
    pub fn with_max_import_bytes(mut self, cap: u64) -> Self {
        self.max_import_bytes = cap;
        self
    }

    /// The project-scoped Storage key for a snapshot's archive (the isolation boundary).
    fn storage_key(key: &SnapshotKey) -> String {
        format!(
            "{SNAPSHOT_FAMILY}/{}/{}/{}.tar",
            key.project, key.workload, key.replica
        )
    }

    /// The sidecar key holding the archive's sealed-digest (the integrity stamp). Lives under
    /// the SAME `csnap/<project>/` subtree, so the per-project teardown sweep reclaims both.
    fn seal_key(key: &SnapshotKey) -> String {
        format!(
            "{SNAPSHOT_FAMILY}/{}/{}/{}.tar.seal",
            key.project, key.workload, key.replica
        )
    }

    /// The project's own blob backend (physical isolation when a per-project override is
    /// configured; the node default otherwise, where the key prefix is the isolation).
    fn backend_for(&self, key: &SnapshotKey) -> Arc<dyn Storage> {
        self.provider.backend(ProjectRef::new(&key.project))
    }
}

#[async_trait]
impl SnapshotStore for BlobSnapshotStore {
    async fn export(
        &self,
        key: &SnapshotKey,
        art: &SnapshotArtifact,
    ) -> Result<(), SnapshotStoreError> {
        let backend = self.backend_for(key);
        // Archive the artifact's local files into a tar STREAM (never buffered whole),
        // computing the SHA-256 of the exact bytes stored, and put it under the project key.
        let (body, digest_rx) = pack_stream(art.dir.clone(), art.files.clone());
        backend
            .put(
                &Self::storage_key(key),
                body,
                PutMeta {
                    content_type: Some("application/x-tar".to_string()),
                },
            )
            .await
            .map_err(|e| SnapshotStoreError::Storage(e.to_string()))?;

        // Authenticated-integrity SEAL (C-i): seal the archive digest under the cluster-shared
        // secrets envelope and store it as a sidecar. On import a resume node unwraps it (which
        // fail-closes on any blob the envelope did not produce) and checks it against the
        // recomputed digest — so a tampered or planted snapshot is rejected even if the
        // `csnap/` prefix confinement ever regressed. No envelope ⇒ unsealed (logged on import).
        if let Some(envelope) = &self.envelope {
            let digest = digest_rx
                .await
                .map_err(|_| SnapshotStoreError::Archive("pack digest producer dropped".into()))?;
            let sealed = envelope
                .wrap(&digest)
                .await
                .map_err(|e| SnapshotStoreError::Archive(format!("seal snapshot digest: {e}")))?;
            let seal_body = futures::stream::once(async move { Ok(Bytes::from(sealed)) }).boxed();
            backend
                .put(
                    &Self::seal_key(key),
                    seal_body,
                    PutMeta {
                        content_type: Some("application/octet-stream".to_string()),
                    },
                )
                .await
                .map_err(|e| SnapshotStoreError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    async fn import(
        &self,
        key: &SnapshotKey,
        art: &SnapshotArtifact,
    ) -> Result<bool, SnapshotStoreError> {
        let backend = self.backend_for(key);
        let obj = match backend.get(&Self::storage_key(key)).await {
            Ok(obj) => obj,
            // No exported snapshot for this key ⇒ the caller cold-starts.
            Err(StorageError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(SnapshotStoreError::Storage(e.to_string())),
        };

        // Fetch + unwrap the seal FIRST (when we have an envelope to verify with). A missing
        // seal where we COULD verify is itself a fail-closed reject (a planted/legacy unsealed
        // object), as is a seal the envelope refuses to unwrap (foreign/tampered).
        let expected_digest: Option<[u8; 32]> = match &self.envelope {
            Some(envelope) => match backend.get(&Self::seal_key(key)).await {
                Ok(seal_obj) => {
                    let sealed = match read_all_capped(seal_obj.body, MAX_SEAL_BYTES).await {
                        Ok(Some(bytes)) => bytes,
                        // Oversized/failed seal read ⇒ treat as unverifiable ⇒ cold-start.
                        Ok(None) | Err(_) => return Ok(false),
                    };
                    match envelope.unwrap(&sealed).await {
                        Ok(d) if d.len() == 32 => Some(d.try_into().expect("len checked")),
                        // Unwrap refused (foreign/tampered) or wrong length ⇒ reject ⇒ cold-start.
                        _ => return Ok(false),
                    }
                }
                Err(StorageError::NotFound(_)) => {
                    // Envelope present but NO seal: fail-closed (never trust an unsealed object
                    // on a sealing node) → cold-start.
                    return Ok(false);
                }
                Err(e) => return Err(SnapshotStoreError::Storage(e.to_string())),
            },
            None => {
                tracing::warn!(
                    project = %key.project,
                    workload = %key.workload,
                    replica = key.replica,
                    "importing an UNSEALED cross-node snapshot (no [secrets] envelope); \
                     authenticity rests on csnap/ prefix confinement alone",
                );
                None
            }
        };

        // Stage-unpack into a sibling staging dir, bounded by the disk-fill cap and digested as
        // it streams. Nothing lands in the real artifact dir until the digest is verified — so a
        // bad snapshot is a clean cold-start, never a half-restore.
        let staging = staging_dir(&art.dir)?;
        let actual_digest = match stage_unpack(obj.body, &staging, self.max_import_bytes).await {
            Ok(Some(d)) => d,
            Ok(None) => {
                // Over-cap or malformed archive → fail-closed.
                cleanup_dir(&staging).await;
                return Ok(false);
            }
            Err(e) => {
                cleanup_dir(&staging).await;
                return Err(e);
            }
        };
        if let Some(expected) = expected_digest
            && expected != actual_digest
        {
            // Tampered archive (bytes don't match the sealed digest) → fail-closed.
            cleanup_dir(&staging).await;
            return Ok(false);
        }

        // Verified: COMMIT by moving the staged files into the real artifact dir.
        let commit = commit_staged(&staging, &art.dir).await;
        cleanup_dir(&staging).await;
        commit?;
        Ok(true)
    }

    async fn remove(&self, key: &SnapshotKey) -> Result<(), SnapshotStoreError> {
        let backend = self.backend_for(key);
        // Deleting a missing object is not an error (the Storage contract). Remove BOTH the
        // archive and its seal sidecar.
        backend
            .delete(&Self::storage_key(key))
            .await
            .map_err(|e| SnapshotStoreError::Storage(e.to_string()))?;
        backend
            .delete(&Self::seal_key(key))
            .await
            .map_err(|e| SnapshotStoreError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn remove_project(&self, project: &str) -> Result<usize, SnapshotStoreError> {
        let backend = self.provider.backend(ProjectRef::new(project));
        // The whole project-scoped snapshot subtree (archives + seals). Keyed by the project's
        // OWN prefix on its OWN backend, so this can never reach another tenant's objects.
        let prefix = format!("{SNAPSHOT_FAMILY}/{project}/");
        let objs = backend
            .list(&prefix)
            .await
            .map_err(|e| SnapshotStoreError::Storage(e.to_string()))?;
        let mut removed = 0usize;
        for meta in objs {
            backend
                .delete(&meta.key)
                .await
                .map_err(|e| SnapshotStoreError::Storage(e.to_string()))?;
            removed += 1;
        }
        Ok(removed)
    }
}

/// Archive `files` (by name, read from `dir`) into a tar byte STREAM, returning the stream
/// plus a oneshot that yields the SHA-256 of the exact bytes streamed (for the export seal).
/// The blocking `tar` writer runs on a blocking thread and pushes chunks through a bounded
/// channel that an async stream drains — so the archive is produced incrementally with bounded
/// memory (a full channel backpressures the writer). The stream ends when the writer finishes
/// (channel closes); a producer error is delivered as a stream item so the `put` fails loudly.
fn pack_stream(
    dir: PathBuf,
    files: Vec<String>,
) -> (ByteStream, tokio::sync::oneshot::Receiver<[u8; 32]>) {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, StorageError>>(STREAM_CHUNK_CHANNEL);
    let (digest_tx, digest_rx) = tokio::sync::oneshot::channel::<[u8; 32]>();
    tokio::task::spawn_blocking(move || {
        let writer = ChannelWriter {
            tx: tx.clone(),
            hasher: Sha256::new(),
        };
        let mut builder = tar::Builder::new(writer);
        for name in &files {
            if let Err(e) = builder.append_path_with_name(dir.join(name), name) {
                let _ = tx.blocking_send(Err(StorageError::Backend(format!(
                    "snapshot archive append {name}: {e}"
                ))));
                return;
            }
        }
        // `into_inner` finishes the archive (writing the end-of-archive marker through the
        // hashing writer) and hands the writer back so we can finalize the digest.
        match builder.into_inner() {
            Ok(writer) => {
                let digest: [u8; 32] = writer.hasher.finalize().into();
                let _ = digest_tx.send(digest);
            }
            Err(e) => {
                let _ = tx.blocking_send(Err(StorageError::Backend(format!(
                    "snapshot archive finish: {e}"
                ))));
            }
        }
        // `tx` drops here → the channel closes → stream ends.
    });
    let stream = futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|chunk| (chunk, rx))
    })
    .boxed();
    (stream, digest_rx)
}

/// Stream a tar byte stream into `staging` (bounded memory), capping total bytes at `cap` and
/// computing the SHA-256 of the exact bytes received. Returns `Ok(Some(digest))` on a complete
/// under-cap unpack, or `Ok(None)` when the stream exceeds `cap` or the archive is malformed
/// (both fail-closed → the caller cold-starts). `tar::Archive::unpack` refuses any entry that
/// would escape `staging` (absolute paths / `..`), so a crafted archive can never write out of it.
async fn stage_unpack(
    mut body: ByteStream,
    staging: &Path,
    cap: u64,
) -> Result<Option<[u8; 32]>, SnapshotStoreError> {
    tokio::fs::create_dir_all(staging)
        .await
        .map_err(|e| SnapshotStoreError::Archive(format!("create staging: {e}")))?;
    harden_dir(staging).await;
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(STREAM_CHUNK_CHANNEL);
    let dest = staging.to_path_buf();
    let unpack = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let mut archive = tar::Archive::new(ChannelReader::new(rx));
        archive.set_overwrite(true);
        archive.unpack(&dest)
    });
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut over_cap = false;
    while let Some(chunk) = body.next().await {
        let bytes = chunk.map_err(|e| SnapshotStoreError::Storage(e.to_string()))?;
        total = total.saturating_add(bytes.len() as u64);
        if total > cap {
            over_cap = true;
            break; // stop feeding; the unpacker sees a truncated stream
        }
        hasher.update(&bytes);
        if tx.send(bytes).await.is_err() {
            break; // unpacker ended (error) — surfaced below
        }
    }
    drop(tx); // EOF (or abort) to the unpacker
    let unpack_res = unpack
        .await
        .map_err(|e| SnapshotStoreError::Archive(format!("unpack join: {e}")))?;
    if over_cap || unpack_res.is_err() {
        return Ok(None); // fail-closed: oversized or malformed
    }
    Ok(Some(hasher.finalize().into()))
}

/// Move every file in `staging` into `dir` (created `0700`), committing a verified import. Each
/// rename is atomic within the shared filesystem (`staging` is a sibling of `dir`).
async fn commit_staged(staging: &Path, dir: &Path) -> Result<(), SnapshotStoreError> {
    tokio::fs::create_dir_all(dir)
        .await
        .map_err(|e| SnapshotStoreError::Archive(format!("create {}: {e}", dir.display())))?;
    harden_dir(dir).await;
    let mut rd = tokio::fs::read_dir(staging)
        .await
        .map_err(|e| SnapshotStoreError::Archive(format!("read staging: {e}")))?;
    while let Some(entry) = rd
        .next_entry()
        .await
        .map_err(|e| SnapshotStoreError::Archive(format!("staging entry: {e}")))?
    {
        let to = dir.join(entry.file_name());
        tokio::fs::rename(entry.path(), &to)
            .await
            .map_err(|e| SnapshotStoreError::Archive(format!("commit {}: {e}", to.display())))?;
    }
    Ok(())
}

/// A unique sibling staging directory for `dir` (same filesystem ⇒ atomic commit renames).
fn staging_dir(dir: &Path) -> Result<PathBuf, SnapshotStoreError> {
    let mut nonce = [0u8; 8];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| SnapshotStoreError::Archive(format!("nonce: {e}")))?;
    let suffix = format!(".csnap-import-{}", hex::encode(nonce));
    let name = match dir.file_name().and_then(|n| n.to_str()) {
        Some(base) => format!("{base}{suffix}"),
        None => suffix,
    };
    Ok(dir.with_file_name(name))
}

/// Best-effort `0700` on a snapshot directory (raw guest RAM): no non-root host process may
/// even enumerate it. Unix-only; the unpacked files keep their archived `0600`.
async fn harden_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).await;
    }
    #[cfg(not(unix))]
    let _ = dir;
}

/// Best-effort recursive delete of a staging directory.
async fn cleanup_dir(dir: &Path) {
    let _ = tokio::fs::remove_dir_all(dir).await;
}

/// Read a small Storage body fully, refusing anything over `cap` (`Ok(None)` when over-cap).
async fn read_all_capped(
    mut body: ByteStream,
    cap: usize,
) -> Result<Option<Vec<u8>>, SnapshotStoreError> {
    let mut out = Vec::new();
    while let Some(chunk) = body.next().await {
        let bytes = chunk.map_err(|e| SnapshotStoreError::Storage(e.to_string()))?;
        if out.len() + bytes.len() > cap {
            return Ok(None);
        }
        out.extend_from_slice(&bytes);
    }
    Ok(Some(out))
}

/// A synchronous [`std::io::Write`] that forwards each write into a bounded channel as a
/// `Bytes` chunk AND folds it into a running SHA-256 — the bridge from the blocking `tar`
/// writer to the async export stream, plus the export digest. A full channel blocks the writer
/// (backpressure, bounded memory); a closed channel (the consumer dropped) is a broken pipe.
struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<Result<Bytes, StorageError>>,
    hasher: Sha256,
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.hasher.update(buf);
        self.tx
            .blocking_send(Ok(Bytes::copy_from_slice(buf)))
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "snapshot stream closed")
            })?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A synchronous [`std::io::Read`] fed by a bounded channel of `Bytes` — the bridge from the
/// async import stream to the blocking `tar` reader. A closed channel is clean EOF.
struct ChannelReader {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
    current: Bytes,
}

impl ChannelReader {
    fn new(rx: tokio::sync::mpsc::Receiver<Bytes>) -> Self {
        Self {
            rx,
            current: Bytes::new(),
        }
    }
}

impl std::io::Read for ChannelReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.current.is_empty() {
            match self.rx.blocking_recv() {
                Some(chunk) => self.current = chunk,
                None => return Ok(0), // all chunks consumed → clean EOF
            }
        }
        let n = self.current.len().min(buf.len());
        buf[..n].copy_from_slice(&self.current[..n]);
        self.current = self.current.slice(n..);
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::blob_backends::GlobalBlobBackend;
    use boatramp_core::compute::Snapshot;
    use boatramp_core::envelope::EnvelopeError;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// A reversible tagged test envelope (a format tag + byte-reverse) — enough to prove the
    /// store seals/unseals around a real [`KeyEnvelope`] and that a blob the envelope did NOT
    /// produce fails `unwrap` (the authenticity reject the import relies on). Mirrors the
    /// `ReverseEnvelope` pattern used across the secret-store tests.
    struct TagEnvelope;
    #[async_trait]
    impl KeyEnvelope for TagEnvelope {
        async fn wrap(&self, plaintext: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            let mut out = vec![0xEE];
            out.extend(plaintext.iter().rev());
            Ok(out)
        }
        async fn unwrap(&self, wrapped: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            match wrapped.split_first() {
                Some((0xEE, rest)) => Ok(rest.iter().rev().copied().collect()),
                _ => Err(EnvelopeError::new("not a TagEnvelope blob")),
            }
        }
    }

    /// The sealing envelope every test uses (so the seal+verify path is exercised by default).
    fn env() -> Option<Arc<dyn KeyEnvelope>> {
        Some(Arc::new(TagEnvelope))
    }

    /// A trivial in-memory per-project blob provider: each project gets its OWN isolated
    /// in-memory store, so a cross-project read physically cannot see another project's bytes
    /// (the strongest form of the isolation we assert) — mirroring a per-project bucket.
    struct PerProjectMemBackends {
        stores: Mutex<HashMap<String, Arc<MemStore>>>,
    }

    impl PerProjectMemBackends {
        fn new() -> Self {
            Self {
                stores: Mutex::new(HashMap::new()),
            }
        }
        fn store_for(&self, project: &str) -> Arc<MemStore> {
            let mut g = self.stores.lock().unwrap();
            g.entry(project.to_string())
                .or_insert_with(|| Arc::new(MemStore::default()))
                .clone()
        }
    }

    impl BlobBackends for PerProjectMemBackends {
        fn backend(&self, project: ProjectRef<'_>) -> Arc<dyn Storage> {
            self.store_for(&project.to_string())
        }
        fn default_backend(&self) -> Arc<dyn Storage> {
            self.store_for("default")
        }
    }

    #[derive(Default)]
    struct MemStore {
        objects: Mutex<HashMap<String, Vec<u8>>>,
    }

    #[async_trait]
    impl Storage for MemStore {
        async fn get(&self, key: &str) -> Result<boatramp_core::GetObject, StorageError> {
            let bytes = self
                .objects
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            let body = futures::stream::once(async move { Ok(Bytes::from(bytes)) }).boxed();
            Ok(boatramp_core::GetObject {
                meta: boatramp_core::ObjectMeta {
                    key: key.to_string(),
                    ..Default::default()
                },
                body,
            })
        }
        async fn get_range(
            &self,
            key: &str,
            _offset: u64,
            _len: Option<u64>,
        ) -> Result<boatramp_core::GetObject, StorageError> {
            self.get(key).await
        }
        async fn put(
            &self,
            key: &str,
            mut body: ByteStream,
            _meta: PutMeta,
        ) -> Result<boatramp_core::ObjectMeta, StorageError> {
            let mut buf = Vec::new();
            while let Some(chunk) = body.next().await {
                buf.extend_from_slice(&chunk?);
            }
            let size = buf.len() as u64;
            self.objects.lock().unwrap().insert(key.to_string(), buf);
            Ok(boatramp_core::ObjectMeta {
                key: key.to_string(),
                size: Some(size),
                ..Default::default()
            })
        }
        async fn head(&self, key: &str) -> Result<boatramp_core::ObjectMeta, StorageError> {
            let g = self.objects.lock().unwrap();
            let v = g
                .get(key)
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(boatramp_core::ObjectMeta {
                key: key.to_string(),
                size: Some(v.len() as u64),
                ..Default::default()
            })
        }
        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        }
        async fn list(&self, prefix: &str) -> Result<Vec<boatramp_core::ObjectMeta>, StorageError> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(prefix))
                .map(|k| boatramp_core::ObjectMeta {
                    key: k.clone(),
                    ..Default::default()
                })
                .collect())
        }
    }

    /// Write a fake snapshot artifact (two files) into `dir`, returning the descriptor.
    fn seed_artifact(dir: &std::path::Path, id: &str, ram: &[u8]) -> SnapshotArtifact {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(format!("{id}.snap")), ram).unwrap();
        std::fs::write(dir.join(format!("{id}.cfg")), b"cfg-bytes").unwrap();
        SnapshotArtifact {
            dir: dir.to_path_buf(),
            files: vec![format!("{id}.snap"), format!("{id}.cfg")],
            local_data_ref: format!("{}/{id}|10.0.0.5|8080", dir.display()),
        }
    }

    fn snap(project: &str, workload: &str, replica: u32) -> Snapshot {
        Snapshot {
            project: project.to_string(),
            workload: workload.to_string(),
            replica,
            data_ref: "x".into(),
            exported: true,
        }
    }

    #[tokio::test]
    async fn snapshot_round_trips_through_tenant_storage() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("nodeA/web-0");
        let ram = vec![0xABu8; 128 * 1024]; // 128 KiB "guest RAM"
        let art = seed_artifact(&src, "web-0", &ram);

        let store = BlobSnapshotStore::new(Arc::new(PerProjectMemBackends::new()), env());
        let key = SnapshotKey::of_snapshot(&snap("acme", "web", 0));
        store.export(&key, &art).await.unwrap();

        // A DIFFERENT node (empty local dir) imports the same key.
        let dstdir = tmp.path().join("nodeB/web-0");
        let dst_art = SnapshotArtifact {
            dir: dstdir.clone(),
            files: vec![],
            local_data_ref: format!("{}/web-0|10.0.0.5|8080", dstdir.display()),
        };
        assert!(
            store.import(&key, &dst_art).await.unwrap(),
            "object present"
        );
        // The restored files match byte-for-byte.
        assert_eq!(std::fs::read(dstdir.join("web-0.snap")).unwrap(), ram);
        assert_eq!(
            std::fs::read(dstdir.join("web-0.cfg")).unwrap(),
            b"cfg-bytes"
        );
    }

    #[tokio::test]
    async fn missing_snapshot_imports_as_cold_start() {
        let tmp = tempfile::tempdir().unwrap();
        let store = BlobSnapshotStore::new(Arc::new(PerProjectMemBackends::new()), env());
        let key = SnapshotKey::of_snapshot(&snap("acme", "web", 7));
        let art = SnapshotArtifact {
            dir: tmp.path().join("b"),
            files: vec![],
            local_data_ref: "x".into(),
        };
        // Never exported ⇒ import reports "no object" (false) ⇒ caller cold-starts.
        assert!(!store.import(&key, &art).await.unwrap());
    }

    /// The tenancy proof: two projects with the SAME workload/replica; node B restoring
    /// project-B's `web/0` must NEVER read project-A's snapshot. With per-project backends
    /// it is a physical miss; the keys are also byte-distinct.
    #[tokio::test]
    async fn cross_project_fetch_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = Arc::new(PerProjectMemBackends::new());
        let store = BlobSnapshotStore::new(provider.clone(), env());

        // Project A parks a secret-bearing snapshot of web/0.
        let secret = b"PROJECT-A-GUEST-RAM-SECRET".to_vec();
        let a_src = tmp.path().join("a/web-0");
        let a_art = seed_artifact(&a_src, "web-0", &secret);
        let a_key = SnapshotKey::of_snapshot(&snap("tenant-a", "web", 0));
        store.export(&a_key, &a_art).await.unwrap();

        // Project B has NEVER exported web/0. Its import must be a clean miss, not A's bytes.
        let b_key = SnapshotKey::of_snapshot(&snap("tenant-b", "web", 0));
        let b_dst = tmp.path().join("b/web-0");
        let b_art = SnapshotArtifact {
            dir: b_dst.clone(),
            files: vec![],
            local_data_ref: "x".into(),
        };
        assert!(
            !store.import(&b_key, &b_art).await.unwrap(),
            "tenant B must not resolve any object for its own web/0 key",
        );
        assert!(
            !b_dst.join("web-0.snap").exists(),
            "no bytes written for tenant B"
        );

        // The keys are byte-distinct (the project segment is the discriminator)...
        assert_ne!(
            BlobSnapshotStore::storage_key(&a_key),
            BlobSnapshotStore::storage_key(&b_key),
        );
        // ...and project B's physical backend holds nothing under the snapshot family.
        let b_backend = provider.store_for("tenant-b");
        assert!(
            b_backend.list(SNAPSHOT_FAMILY).await.unwrap().is_empty(),
            "tenant B's backend must hold no snapshot object",
        );
        // Project A's own backend, by contrast, holds exactly its own object (sanity).
        let a_backend = provider.store_for("tenant-a");
        // Archive + seal sidecar = two objects, both tenant A's own.
        assert_eq!(a_backend.list(SNAPSHOT_FAMILY).await.unwrap().len(), 2);
    }

    /// Even on a SHARED backend (no per-project override — `GlobalBlobBackend`), the
    /// project-scoped key keeps two tenants' same-named snapshots separate.
    #[tokio::test]
    async fn shared_backend_keeps_projects_key_separated() {
        let tmp = tempfile::tempdir().unwrap();
        let shared: Arc<dyn Storage> = Arc::new(MemStore::default());
        let store = BlobSnapshotStore::new(Arc::new(GlobalBlobBackend::new(shared.clone())), env());

        let a_art = seed_artifact(&tmp.path().join("a/web-0"), "web-0", b"A-RAM");
        store
            .export(
                &SnapshotKey::of_snapshot(&snap("tenant-a", "web", 0)),
                &a_art,
            )
            .await
            .unwrap();

        // Tenant B's own key is absent on the shared backend (A's is under a different key).
        let b_key = SnapshotKey::of_snapshot(&snap("tenant-b", "web", 0));
        let b_art = SnapshotArtifact {
            dir: tmp.path().join("b/web-0"),
            files: vec![],
            local_data_ref: "x".into(),
        };
        assert!(!store.import(&b_key, &b_art).await.unwrap());
        // Both keys coexist distinctly once B exports its own.
        let b_export = seed_artifact(&tmp.path().join("b/export-web-0"), "web-0", b"B-RAM");
        store.export(&b_key, &b_export).await.unwrap();
        // Two projects, each an archive + a seal, all under distinct project-scoped keys.
        assert_eq!(shared.list(SNAPSHOT_FAMILY).await.unwrap().len(), 4);
    }

    /// The export must STREAM (bounded memory), not buffer the whole artifact: a large file
    /// arrives at Storage as MANY chunks, none of them the whole payload. A `tar` entry is
    /// written as a 512-byte header + the file body copied in bounded (<= 8 KiB) reads, so a
    /// multi-megabyte artifact can never materialize as one giant `Bytes`.
    struct ChunkSpyStore {
        chunks: Arc<Mutex<Vec<usize>>>,
    }
    #[async_trait]
    impl Storage for ChunkSpyStore {
        async fn get(&self, key: &str) -> Result<boatramp_core::GetObject, StorageError> {
            Err(StorageError::NotFound(key.to_string()))
        }
        async fn get_range(
            &self,
            key: &str,
            _o: u64,
            _l: Option<u64>,
        ) -> Result<boatramp_core::GetObject, StorageError> {
            self.get(key).await
        }
        async fn put(
            &self,
            key: &str,
            mut body: ByteStream,
            _m: PutMeta,
        ) -> Result<boatramp_core::ObjectMeta, StorageError> {
            let mut total = 0u64;
            while let Some(chunk) = body.next().await {
                let c = chunk?;
                self.chunks.lock().unwrap().push(c.len());
                total += c.len() as u64;
            }
            Ok(boatramp_core::ObjectMeta {
                key: key.to_string(),
                size: Some(total),
                ..Default::default()
            })
        }
        async fn head(&self, key: &str) -> Result<boatramp_core::ObjectMeta, StorageError> {
            Err(StorageError::NotFound(key.to_string()))
        }
        async fn delete(&self, _key: &str) -> Result<(), StorageError> {
            Ok(())
        }
        async fn list(&self, _p: &str) -> Result<Vec<boatramp_core::ObjectMeta>, StorageError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn export_streams_in_bounded_chunks() {
        let tmp = tempfile::tempdir().unwrap();
        // A 4 MiB "RAM" snapshot.
        let ram = vec![0x5Au8; 4 * 1024 * 1024];
        let art = seed_artifact(&tmp.path().join("big/web-0"), "web-0", &ram);

        let chunks = Arc::new(Mutex::new(Vec::new()));
        let spy = Arc::new(ChunkSpyStore {
            chunks: chunks.clone(),
        });
        let store = BlobSnapshotStore::new(Arc::new(GlobalBlobBackend::new(spy)), env());
        store
            .export(&SnapshotKey::of_snapshot(&snap("acme", "web", 0)), &art)
            .await
            .unwrap();

        let recorded = chunks.lock().unwrap();
        assert!(
            recorded.len() > 16,
            "a 4 MiB artifact must stream as many chunks, got {}",
            recorded.len()
        );
        let max = recorded.iter().copied().max().unwrap_or(0);
        assert!(
            max < ram.len(),
            "no single chunk is the whole payload (max chunk {max} vs {} total)",
            ram.len()
        );
    }

    #[tokio::test]
    async fn remove_is_idempotent_and_clears_the_object() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = Arc::new(PerProjectMemBackends::new());
        let store = BlobSnapshotStore::new(provider.clone(), env());
        let key = SnapshotKey::of_snapshot(&snap("acme", "web", 0));
        let art = seed_artifact(&tmp.path().join("a/web-0"), "web-0", b"RAM");
        store.export(&key, &art).await.unwrap();
        // A sealed export writes two objects: the archive + its seal sidecar.
        assert_eq!(
            provider
                .store_for("acme")
                .list(SNAPSHOT_FAMILY)
                .await
                .unwrap()
                .len(),
            2
        );
        store.remove(&key).await.unwrap();
        assert!(
            provider
                .store_for("acme")
                .list(SNAPSHOT_FAMILY)
                .await
                .unwrap()
                .is_empty()
        );
        // Removing again is not an error.
        store.remove(&key).await.unwrap();
    }

    /// C-i fail-closed: a snapshot whose SEAL was tampered (the envelope refuses to unwrap a
    /// blob it did not produce) is rejected → cold-start, and nothing lands in the artifact dir.
    #[tokio::test]
    async fn tampered_seal_is_rejected_cold_start() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = Arc::new(PerProjectMemBackends::new());
        let store = BlobSnapshotStore::new(provider.clone(), env());
        let key = SnapshotKey::of_snapshot(&snap("acme", "web", 0));
        let art = seed_artifact(&tmp.path().join("a/web-0"), "web-0", b"RAM-SECRET");
        store.export(&key, &art).await.unwrap();

        // Overwrite the seal sidecar with a blob the envelope will refuse to unwrap.
        provider.store_for("acme").objects.lock().unwrap().insert(
            BlobSnapshotStore::seal_key(&key),
            b"planted-not-a-real-seal".to_vec(),
        );

        let dst = tmp.path().join("b/web-0");
        let dst_art = SnapshotArtifact {
            dir: dst.clone(),
            files: vec![],
            local_data_ref: "x".into(),
        };
        assert!(
            !store.import(&key, &dst_art).await.unwrap(),
            "a tampered seal must be rejected → cold-start",
        );
        assert!(
            !dst.exists(),
            "nothing lands in the artifact dir on a rejected import"
        );
    }

    /// C-i fail-closed: a snapshot whose ARCHIVE bytes were tampered (digest no longer matches
    /// the sealed digest) is rejected → cold-start, with nothing committed.
    #[tokio::test]
    async fn tampered_archive_is_rejected_cold_start() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = Arc::new(PerProjectMemBackends::new());
        let store = BlobSnapshotStore::new(provider.clone(), env());
        let key = SnapshotKey::of_snapshot(&snap("acme", "web", 0));
        let art = seed_artifact(&tmp.path().join("a/web-0"), "web-0", b"ORIGINAL-RAM");
        store.export(&key, &art).await.unwrap();

        // Swap the archive for a DIFFERENT (validly-formed) tar whose digest won't match the
        // seal: re-pack a different payload under the same key.
        let evil = seed_artifact(&tmp.path().join("evil/web-0"), "web-0", b"EVIL-RAM");
        let (mut evil_body, _d) = pack_stream(evil.dir.clone(), evil.files.clone());
        let mut evil_bytes = Vec::new();
        while let Some(chunk) = evil_body.next().await {
            evil_bytes.extend_from_slice(&chunk.unwrap());
        }
        provider
            .store_for("acme")
            .objects
            .lock()
            .unwrap()
            .insert(BlobSnapshotStore::storage_key(&key), evil_bytes);

        let dst = tmp.path().join("b/web-0");
        let dst_art = SnapshotArtifact {
            dir: dst.clone(),
            files: vec![],
            local_data_ref: "x".into(),
        };
        assert!(
            !store.import(&key, &dst_art).await.unwrap(),
            "a tampered archive (digest mismatch) must be rejected → cold-start",
        );
        assert!(
            !dst.join("web-0.snap").exists(),
            "no bytes committed on digest mismatch"
        );
    }

    /// C-ii fail-closed: an import whose archive exceeds the disk-fill cap is rejected →
    /// cold-start; nothing is committed to the artifact dir.
    #[tokio::test]
    async fn over_cap_import_is_rejected_cold_start() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = Arc::new(PerProjectMemBackends::new());
        // A 256 KiB artifact, but a 4 KiB import cap.
        let store = BlobSnapshotStore::new(provider.clone(), env()).with_max_import_bytes(4 * 1024);
        let key = SnapshotKey::of_snapshot(&snap("acme", "web", 0));
        let art = seed_artifact(&tmp.path().join("a/web-0"), "web-0", &vec![7u8; 256 * 1024]);
        store.export(&key, &art).await.unwrap();

        let dst = tmp.path().join("b/web-0");
        let dst_art = SnapshotArtifact {
            dir: dst.clone(),
            files: vec![],
            local_data_ref: "x".into(),
        };
        assert!(
            !store.import(&key, &dst_art).await.unwrap(),
            "an over-cap import must be rejected → cold-start",
        );
        assert!(
            !dst.join("web-0.snap").exists(),
            "no bytes committed on over-cap import"
        );
    }

    /// A: a project teardown sweeps ALL of that project's parked snapshots (archives + seals),
    /// and touches no other project's.
    #[tokio::test]
    async fn remove_project_sweeps_only_that_project() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = Arc::new(PerProjectMemBackends::new());
        let store = BlobSnapshotStore::new(provider.clone(), env());

        // Project A parks two replicas; project B parks one.
        for (proj, wl, rep) in [
            ("acme", "web", 0u32),
            ("acme", "api", 0),
            ("other", "web", 0),
        ] {
            let art = seed_artifact(&tmp.path().join(format!("{proj}-{wl}-{rep}")), "x", b"RAM");
            store
                .export(&SnapshotKey::of_snapshot(&snap(proj, wl, rep)), &art)
                .await
                .unwrap();
        }
        // A: 2 replicas × (archive+seal) = 4 objects; other: 2.
        assert_eq!(
            provider
                .store_for("acme")
                .list(SNAPSHOT_FAMILY)
                .await
                .unwrap()
                .len(),
            4
        );

        let removed = store.remove_project("acme").await.unwrap();
        assert_eq!(removed, 4, "both A replicas' archives + seals swept");
        assert!(
            provider
                .store_for("acme")
                .list(SNAPSHOT_FAMILY)
                .await
                .unwrap()
                .is_empty(),
            "no orphan snapshot survives the project purge",
        );
        // Project `other` is untouched.
        assert_eq!(
            provider
                .store_for("other")
                .list(SNAPSHOT_FAMILY)
                .await
                .unwrap()
                .len(),
            2
        );
    }

    /// Without an envelope the snapshot is UNSEALED but still round-trips (degraded
    /// prefix-confinement-only mode — e.g. a node with no `[secrets]` envelope).
    #[tokio::test]
    async fn unsealed_without_envelope_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = Arc::new(PerProjectMemBackends::new());
        let store = BlobSnapshotStore::new(provider.clone(), None);
        let key = SnapshotKey::of_snapshot(&snap("acme", "web", 0));
        let ram = vec![0x33u8; 64 * 1024];
        let art = seed_artifact(&tmp.path().join("a/web-0"), "web-0", &ram);
        store.export(&key, &art).await.unwrap();
        // No seal written (unsealed).
        assert_eq!(
            provider
                .store_for("acme")
                .list(SNAPSHOT_FAMILY)
                .await
                .unwrap()
                .len(),
            1
        );

        let dst = tmp.path().join("b/web-0");
        let dst_art = SnapshotArtifact {
            dir: dst.clone(),
            files: vec![],
            local_data_ref: "x".into(),
        };
        assert!(store.import(&key, &dst_art).await.unwrap());
        assert_eq!(std::fs::read(dst.join("web-0.snap")).unwrap(), ram);
    }
}
