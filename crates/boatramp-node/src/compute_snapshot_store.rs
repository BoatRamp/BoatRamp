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

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::blob_backends::BlobBackends;
use boatramp_core::compute::{SnapshotArtifact, SnapshotKey, SnapshotStore, SnapshotStoreError};
use boatramp_core::project::ProjectRef;
use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
use bytes::Bytes;
use futures::StreamExt;

/// The reserved blob family prefix for compute scale-to-zero snapshots. Control-plane only
/// (never a guest-reachable key), and project-scoped under it — see the module contract.
const SNAPSHOT_FAMILY: &str = "csnap";

/// Bound (chunks) of the in-flight channel bridging the blocking `tar` reader/writer to the
/// async Storage stream. A full channel backpressures the blocking side, so a multi-gigabyte
/// RAM snapshot never buffers whole in memory — it flows through with O(chunk) memory.
const STREAM_CHUNK_CHANNEL: usize = 4;

/// A [`SnapshotStore`] over the node's per-project blob [`BlobBackends`] provider.
pub struct BlobSnapshotStore {
    provider: Arc<dyn BlobBackends>,
}

impl BlobSnapshotStore {
    /// Build the store over the per-project blob-backend provider (the same one the handler
    /// `blobstore` binding resolves through, so snapshots land on the project's own backend).
    pub fn new(provider: Arc<dyn BlobBackends>) -> Self {
        Self { provider }
    }

    /// The project-scoped Storage key for a snapshot (the isolation boundary).
    fn storage_key(key: &SnapshotKey) -> String {
        format!(
            "{SNAPSHOT_FAMILY}/{}/{}/{}.tar",
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
        let storage_key = Self::storage_key(key);
        // Archive the artifact's local files into a tar STREAM (never buffered whole) and
        // put it under the project-scoped key.
        let body = pack_stream(art.dir.clone(), art.files.clone());
        backend
            .put(
                &storage_key,
                body,
                PutMeta {
                    content_type: Some("application/x-tar".to_string()),
                },
            )
            .await
            .map_err(|e| SnapshotStoreError::Storage(e.to_string()))?;
        Ok(())
    }

    async fn import(
        &self,
        key: &SnapshotKey,
        art: &SnapshotArtifact,
    ) -> Result<bool, SnapshotStoreError> {
        let backend = self.backend_for(key);
        let storage_key = Self::storage_key(key);
        let obj = match backend.get(&storage_key).await {
            Ok(obj) => obj,
            // No exported snapshot for this key ⇒ the caller cold-starts.
            Err(StorageError::NotFound(_)) => return Ok(false),
            Err(e) => return Err(SnapshotStoreError::Storage(e.to_string())),
        };
        unpack_stream(obj.body, art.dir.clone()).await?;
        Ok(true)
    }

    async fn remove(&self, key: &SnapshotKey) -> Result<(), SnapshotStoreError> {
        let backend = self.backend_for(key);
        let storage_key = Self::storage_key(key);
        // Deleting a missing object is not an error (the Storage contract).
        backend
            .delete(&storage_key)
            .await
            .map_err(|e| SnapshotStoreError::Storage(e.to_string()))
    }
}

/// Archive `files` (by name, read from `dir`) into a tar byte STREAM. The blocking `tar`
/// writer runs on a blocking thread and pushes chunks through a bounded channel that an async
/// stream drains — so the archive is produced incrementally with bounded memory (a full
/// channel backpressures the writer). The stream ends when the writer finishes (channel
/// closes); a producer error is delivered as a stream item so the `put` fails loudly.
fn pack_stream(dir: PathBuf, files: Vec<String>) -> ByteStream {
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, StorageError>>(STREAM_CHUNK_CHANNEL);
    tokio::task::spawn_blocking(move || {
        let writer = ChannelWriter { tx: tx.clone() };
        let mut builder = tar::Builder::new(writer);
        for name in &files {
            if let Err(e) = builder.append_path_with_name(dir.join(name), name) {
                let _ = tx.blocking_send(Err(StorageError::Backend(format!(
                    "snapshot archive append {name}: {e}"
                ))));
                return;
            }
        }
        if let Err(e) = builder.finish() {
            let _ = tx.blocking_send(Err(StorageError::Backend(format!(
                "snapshot archive finish: {e}"
            ))));
        }
        // `builder` (and its ChannelWriter) drops here → the channel closes → stream ends.
    });
    futures::stream::unfold(rx, |mut rx| async move {
        rx.recv().await.map(|chunk| (chunk, rx))
    })
    .boxed()
}

/// Consume a tar byte stream (from [`pack_stream`]) and unpack it into `dir`. The async side
/// forwards each chunk into a bounded channel feeding a blocking `tar::Archive` on a blocking
/// thread — bounded memory, symmetric with the pack side. `tar::Archive::unpack` refuses any
/// entry that would escape `dir` (absolute paths / `..`), so a malformed archive can never
/// write outside the artifact directory.
async fn unpack_stream(mut body: ByteStream, dir: PathBuf) -> Result<(), SnapshotStoreError> {
    tokio::fs::create_dir_all(&dir)
        .await
        .map_err(|e| SnapshotStoreError::Archive(format!("create {}: {e}", dir.display())))?;
    // The imported artifact is raw guest memory (secrets): lock the receiving directory to
    // `0700` so no non-root host process can even enumerate it — parity with the home node's
    // own snapshot dir. Best-effort (unix only); the unpacked files keep their archived `0600`.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).await;
    }
    let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(STREAM_CHUNK_CHANNEL);
    let dest = dir.clone();
    let unpack = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        let mut archive = tar::Archive::new(ChannelReader::new(rx));
        // Confine every entry to `dest`; never follow symlinks in the archive.
        archive.set_overwrite(true);
        archive.unpack(&dest)
    });
    // Pump the Storage stream into the blocking unpacker.
    while let Some(chunk) = body.next().await {
        let bytes = chunk.map_err(|e| SnapshotStoreError::Storage(e.to_string()))?;
        if tx.send(bytes).await.is_err() {
            break; // unpacker ended (error) — the join below surfaces it
        }
    }
    drop(tx); // EOF to the unpacker
    unpack
        .await
        .map_err(|e| SnapshotStoreError::Archive(format!("unpack join: {e}")))?
        .map_err(|e| SnapshotStoreError::Archive(format!("unpack: {e}")))?;
    Ok(())
}

/// A synchronous [`std::io::Write`] that forwards each write into a bounded channel as a
/// `Bytes` chunk — the bridge from the blocking `tar` writer to the async export stream. A
/// full channel blocks the writer (backpressure, bounded memory); a closed channel (the
/// consumer dropped) is a broken pipe.
struct ChannelWriter {
    tx: tokio::sync::mpsc::Sender<Result<Bytes, StorageError>>,
}

impl std::io::Write for ChannelWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
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
    use std::collections::HashMap;
    use std::sync::Mutex;

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

        let store = BlobSnapshotStore::new(Arc::new(PerProjectMemBackends::new()));
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
        let store = BlobSnapshotStore::new(Arc::new(PerProjectMemBackends::new()));
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
        let store = BlobSnapshotStore::new(provider.clone());

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
        assert_eq!(a_backend.list(SNAPSHOT_FAMILY).await.unwrap().len(), 1);
    }

    /// Even on a SHARED backend (no per-project override — `GlobalBlobBackend`), the
    /// project-scoped key keeps two tenants' same-named snapshots separate.
    #[tokio::test]
    async fn shared_backend_keeps_projects_key_separated() {
        let tmp = tempfile::tempdir().unwrap();
        let shared: Arc<dyn Storage> = Arc::new(MemStore::default());
        let store = BlobSnapshotStore::new(Arc::new(GlobalBlobBackend::new(shared.clone())));

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
        assert_eq!(shared.list(SNAPSHOT_FAMILY).await.unwrap().len(), 2);
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
        let store = BlobSnapshotStore::new(Arc::new(GlobalBlobBackend::new(spy)));
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
        let store = BlobSnapshotStore::new(provider.clone());
        let key = SnapshotKey::of_snapshot(&snap("acme", "web", 0));
        let art = seed_artifact(&tmp.path().join("a/web-0"), "web-0", b"RAM");
        store.export(&key, &art).await.unwrap();
        assert_eq!(
            provider
                .store_for("acme")
                .list(SNAPSHOT_FAMILY)
                .await
                .unwrap()
                .len(),
            1
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
}
