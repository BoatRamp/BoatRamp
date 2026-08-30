//! Filesystem-backed [`Storage`] implementation.
//!
//! Reads are streamed off disk with [`ReaderStream`] and writes are streamed
//! onto disk with [`tokio::io::copy`]; at no point is a whole object held in
//! memory.

use std::path::{Component, Path, PathBuf};
use std::sync::LazyLock;

use async_trait::async_trait;
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::{ReaderStream, StreamReader};

/// Read-stream chunk size for serving files off disk.
///
/// `ReaderStream`'s 8 KiB default is a performance trap here: `tokio::fs::File`
/// dispatches every read to the blocking thread pool, so an 8 KiB chunk means ~128
/// blocking round-trips per 1 MiB served. Under concurrency that pool serialises and
/// large-file throughput collapses (~40× slower than nginx on 1 MiB in the fair
/// benchmark).
///
/// 64 KiB is the measured **knee** (lighthouse `static/1m`, c256): it ~doubles
/// throughput over 8 KiB (16 reads/MiB instead of 128) for only ~+24 MB RSS, whereas
/// 256 KiB adds a further +114 MB RSS for <2% more throughput — a bad trade that would
/// aggravate the h2/TLS resident-set gap. Files ≤ the small-blob cache threshold never
/// reach this streaming path. This removes the pathology; the zero-copy
/// `sendfile`/`splice` path is the eventual nginx-parity fix (the userspace copy still
/// ceilings throughput well below nginx's kernel path).
///
/// Tunable via `BOATRAMP_READ_CHUNK_KB` (default 64) — raise it on throughput-bound,
/// memory-rich hosts; floored at 4 KiB.
static READ_CHUNK: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("BOATRAMP_READ_CHUNK_KB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map_or(64 * 1024, |kb| (kb * 1024).max(4 * 1024))
});

/// Stores objects as files under a root directory, streaming reads and writes.
#[derive(Debug, Clone)]
pub struct FsStorage {
    root: PathBuf,
}

impl FsStorage {
    /// Create a backend rooted at `root`. Parent directories are created on
    /// demand when writing.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The root directory backing this store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve `key` to a path inside `root`, rejecting traversal attempts
    /// (`..`, absolute paths, Windows prefixes, ...).
    fn resolve(&self, key: &str) -> Result<PathBuf, StorageError> {
        let rel = Path::new(key);
        for component in rel.components() {
            if !matches!(component, Component::Normal(_)) {
                return Err(StorageError::InvalidKey(key.to_string()));
            }
        }
        Ok(self.root.join(rel))
    }
}

#[async_trait]
impl Storage for FsStorage {
    fn mapped(&self, key: &str) -> Option<bytes::Bytes> {
        let path = self.resolve(key).ok()?;
        let file = std::fs::File::open(&path).ok()?;
        // SAFETY: the blob keyspace is content-addressed and immutable — a stored
        // file is never rewritten or truncated while a mapping is live, which is
        // the one condition that makes `Mmap::map` unsound. Any error (missing
        // file, empty file, mmap failure) returns `None` and the caller streams.
        let mmap = unsafe { memmap2::Mmap::map(&file).ok()? };
        Some(bytes::Bytes::from_owner(mmap))
    }

    fn local_file(&self, key: &str) -> Option<std::fs::File> {
        // The open file for the zero-copy `sendfile` path (content-addressed +
        // immutable, so the handle is stable). Any error (missing file, traversal
        // reject) yields `None` and the caller falls back to `mapped`/streaming.
        let path = self.resolve(key).ok()?;
        std::fs::File::open(&path).ok()
    }

    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        let path = self.resolve(key)?;
        let file = match tokio::fs::File::open(&path).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(StorageError::NotFound(key.to_string()));
            }
            Err(err) => return Err(StorageError::Io(err)),
        };
        let len = file.metadata().await?.len();

        // Stream the file off disk in large chunks (see `READ_CHUNK`).
        let body: ByteStream = ReaderStream::with_capacity(file, *READ_CHUNK)
            .map(|chunk| chunk.map_err(StorageError::Io))
            .boxed();

        Ok(GetObject {
            meta: ObjectMeta {
                key: key.to_string(),
                size: Some(len),
                content_type: mime_from_key(key),
                etag: None,
            },
            body,
        })
    }

    async fn get_range(
        &self,
        key: &str,
        offset: u64,
        len: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        let path = self.resolve(key)?;
        let mut file = match tokio::fs::File::open(&path).await {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(StorageError::NotFound(key.to_string()));
            }
            Err(err) => return Err(StorageError::Io(err)),
        };
        let total = file.metadata().await?.len();
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let length = len.unwrap_or_else(|| total.saturating_sub(offset));

        // `take` bounds the read to the requested length; still fully streamed
        // (large chunks — see `READ_CHUNK`).
        let body: ByteStream = ReaderStream::with_capacity(file.take(length), *READ_CHUNK)
            .map(|chunk| chunk.map_err(StorageError::Io))
            .boxed();

        Ok(GetObject {
            meta: ObjectMeta {
                key: key.to_string(),
                size: Some(length),
                content_type: mime_from_key(key),
                etag: None,
            },
            body,
        })
    }

    async fn put(
        &self,
        key: &str,
        body: ByteStream,
        meta: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        let path = self.resolve(key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Adapt the byte stream into an `AsyncRead` and copy it straight into
        // the destination file. No full-object buffering happens here.
        let reader = StreamReader::new(body.map(|chunk| chunk.map_err(std::io::Error::other)));
        tokio::pin!(reader);

        let mut file = tokio::fs::File::create(&path).await?;
        let written = tokio::io::copy(&mut reader, &mut file).await?;
        file.sync_all().await?;

        Ok(ObjectMeta {
            key: key.to_string(),
            size: Some(written),
            content_type: meta.content_type.or_else(|| mime_from_key(key)),
            etag: None,
        })
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        let path = self.resolve(key)?;
        let metadata = match tokio::fs::metadata(&path).await {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(StorageError::NotFound(key.to_string()));
            }
            Err(err) => return Err(StorageError::Io(err)),
        };
        Ok(ObjectMeta {
            key: key.to_string(),
            size: Some(metadata.len()),
            content_type: mime_from_key(key),
            etag: None,
        })
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let path = self.resolve(key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(StorageError::Io(err)),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        let mut out = Vec::new();
        let mut stack = vec![self.root.clone()];
        while let Some(dir) = stack.pop() {
            let mut entries = match tokio::fs::read_dir(&dir).await {
                Ok(entries) => entries,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(StorageError::Io(err)),
            };
            while let Some(entry) = entries.next_entry().await? {
                let file_type = entry.file_type().await?;
                if file_type.is_dir() {
                    stack.push(entry.path());
                    continue;
                }
                let path = entry.path();
                let Ok(rel) = path.strip_prefix(&self.root) else {
                    continue;
                };
                let key = rel.to_string_lossy().replace('\\', "/");
                if key.starts_with(prefix) {
                    out.push(ObjectMeta {
                        key,
                        size: Some(entry.metadata().await?.len()),
                        content_type: None,
                        etag: None,
                    });
                }
            }
        }
        Ok(out)
    }

    /// The filesystem backend watches natively via inotify / FSEvents / kqueue.
    fn supports_watch(&self) -> bool {
        true
    }

    async fn watch(
        &self,
        prefix: &str,
    ) -> Result<Option<boatramp_core::ChangeStream>, StorageError> {
        use boatramp_core::{BlobChange, BlobChangeKind};
        use notify::{EventKind, RecursiveMode, Watcher};

        // Watch the directory containing `prefix` (everything up to the last `/`),
        // recursively, and filter events back to the full `prefix`. Create the dir
        // first so a not-yet-written namespace can still be watched.
        let dir_part = match prefix.rfind('/') {
            Some(i) => &prefix[..=i],
            None => "",
        };
        let watch_dir = self.resolve(dir_part.trim_end_matches('/'))?;
        tokio::fs::create_dir_all(&watch_dir).await?;
        // Canonicalize both sides: the OS notification layer (FSEvents especially)
        // reports canonical paths, so a symlinked temp/root (`/tmp` → `/private/tmp`)
        // would otherwise fail `strip_prefix` and every event would be dropped.
        let root = tokio::fs::canonicalize(&self.root)
            .await
            .unwrap_or_else(|_| self.root.clone());
        let watch_dir = tokio::fs::canonicalize(&watch_dir)
            .await
            .unwrap_or(watch_dir);
        let filter = prefix.to_string();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<BlobChange>();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else { return };
            let kind = match event.kind {
                EventKind::Create(_) => BlobChangeKind::Created,
                EventKind::Modify(_) => BlobChangeKind::Modified,
                EventKind::Remove(_) => BlobChangeKind::Removed,
                _ => return,
            };
            for path in event.paths {
                let Ok(rel) = path.strip_prefix(&root) else {
                    continue;
                };
                let key = rel.to_string_lossy().replace('\\', "/");
                if key.starts_with(&filter) {
                    let _ = tx.send(BlobChange { key, kind });
                }
            }
        })
        .map_err(watch_err)?;
        watcher
            .watch(&watch_dir, RecursiveMode::Recursive)
            .map_err(watch_err)?;

        // The stream owns the `Watcher` — dropping the stream stops the watch.
        Ok(Some(Box::pin(FsWatchStream {
            _watcher: watcher,
            rx,
        })))
    }
}

/// A change stream that keeps its `notify` watcher alive for as long as the
/// stream lives (dropping the stream tears the watch down).
struct FsWatchStream {
    _watcher: notify::RecommendedWatcher,
    rx: tokio::sync::mpsc::UnboundedReceiver<boatramp_core::BlobChange>,
}

impl futures::Stream for FsWatchStream {
    type Item = boatramp_core::BlobChange;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx)
    }
}

/// Map a `notify` error into a `StorageError`.
fn watch_err(err: notify::Error) -> StorageError {
    StorageError::Io(std::io::Error::other(err))
}

/// Best-effort MIME guess from a key's file extension.
fn mime_from_key(key: &str) -> Option<String> {
    let ext = Path::new(key).extension()?.to_str()?;
    let mime = match ext.to_ascii_lowercase().as_str() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/x-icon",
        "txt" => "text/plain; charset=utf-8",
        "wasm" => "application/wasm",
        _ => return None,
    };
    Some(mime.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;

    #[test]
    fn rejects_path_traversal() {
        let store = FsStorage::new("/tmp/boatramp-test-root");
        assert!(store.resolve("../etc/passwd").is_err());
        assert!(store.resolve("/etc/passwd").is_err());
        assert!(store.resolve("ok/index.html").is_ok());
    }

    #[tokio::test]
    async fn mapped_returns_file_bytes_and_none_when_missing() {
        let root = std::env::temp_dir().join(format!("boatramp-fsmap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = FsStorage::new(&root);

        // A "large" (over the small-blob cache threshold) content-addressed blob.
        let content = vec![0xABu8; 300 * 1024];
        let body: ByteStream = {
            let content = content.clone();
            futures::stream::once(async move { Ok(bytes::Bytes::from(content)) }).boxed()
        };
        store
            .put("blobs/abc", body, PutMeta::default())
            .await
            .unwrap();

        // Present: the mapped bytes equal the file content (served borrowed).
        let mapped = store.mapped("blobs/abc").expect("a local file memory-maps");
        assert_eq!(&mapped[..], &content[..]);
        // Missing key → None, so the caller falls back to streaming.
        assert!(store.mapped("blobs/missing").is_none());
        // Traversal is rejected the same as every other path-taking method.
        assert!(store.mapped("../etc/passwd").is_none());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn watch_reports_a_write_under_the_prefix() {
        // A pid-unique temp root so parallel tests don't collide.
        let root = std::env::temp_dir().join(format!("boatramp-fswatch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let store = FsStorage::new(&root);
        assert!(store.supports_watch());

        // Watch a function-blobstore-style prefix.
        let prefix = "hblob/fn/worker/uploads/";
        let mut stream = store.watch(prefix).await.unwrap().expect("watch supported");

        // Write an object under the watched prefix, plus one outside it.
        let body = |bytes: &'static [u8]| -> ByteStream {
            futures::stream::once(async move { Ok(bytes::Bytes::from_static(bytes)) }).boxed()
        };
        store
            .put(
                "hblob/fn/worker/uploads/report.json",
                body(b"{}"),
                PutMeta::default(),
            )
            .await
            .unwrap();
        store
            .put("hblob/fn/worker/other/x", body(b"x"), PutMeta::default())
            .await
            .unwrap();

        // The change under the prefix arrives; the one outside does not.
        let change = tokio::time::timeout(std::time::Duration::from_secs(10), stream.next())
            .await
            .expect("a change event within the timeout")
            .expect("the stream yields a change");
        assert_eq!(change.key, "hblob/fn/worker/uploads/report.json");

        let _ = std::fs::remove_dir_all(&root);
    }
}
