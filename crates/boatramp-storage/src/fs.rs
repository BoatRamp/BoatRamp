//! Filesystem-backed [`Storage`] implementation.
//!
//! Reads are streamed off disk with [`ReaderStream`] and writes are streamed
//! onto disk with [`tokio::io::copy`]; at no point is a whole object held in
//! memory.

use std::path::{Component, Path, PathBuf};

use async_trait::async_trait;
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::{ReaderStream, StreamReader};

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

        // Stream the file off disk, chunk by chunk.
        let body: ByteStream = ReaderStream::new(file)
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

        // `take` bounds the read to the requested length; still fully streamed.
        let body: ByteStream = ReaderStream::new(file.take(length))
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

    #[test]
    fn rejects_path_traversal() {
        let store = FsStorage::new("/tmp/boatramp-test-root");
        assert!(store.resolve("../etc/passwd").is_err());
        assert!(store.resolve("/etc/passwd").is_err());
        assert!(store.resolve("ok/index.html").is_ok());
    }
}
