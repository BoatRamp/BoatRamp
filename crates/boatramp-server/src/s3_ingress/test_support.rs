//! Shared test doubles for the S3-ingress face tests.
//!
//! A faithful in-memory [`Storage`] with a WORKING `list` (the server crate's other `MemStorage`
//! returns an empty list, which multipart assembly relies on) — so the multipart staging/assembly
//! tests exercise the real `put`/`list`/`get`/`head`/`delete` flow without a temp filesystem.

use std::collections::BTreeMap;
use std::sync::Mutex;

use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use futures::StreamExt as _;

/// An in-memory object store backed by a sorted map (so `list` returns keys in lexicographic order,
/// matching the fs backend + the zero-padded part-key ordering assembly depends on).
#[derive(Default)]
pub(crate) struct MapStorage {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

#[async_trait::async_trait]
impl Storage for MapStorage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        let bytes = self
            .objects
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
        let size = bytes.len() as u64;
        let body: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from(bytes)) }).boxed();
        Ok(GetObject {
            meta: ObjectMeta {
                key: key.to_string(),
                size: Some(size),
                ..Default::default()
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
        let bytes = self
            .objects
            .lock()
            .unwrap()
            .get(key)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
        let start = (offset as usize).min(bytes.len());
        let end = match len {
            Some(l) => (start + l as usize).min(bytes.len()),
            None => bytes.len(),
        };
        let slice = bytes[start..end].to_vec();
        let size = slice.len() as u64;
        let body: ByteStream =
            futures::stream::once(async move { Ok(bytes::Bytes::from(slice)) }).boxed();
        Ok(GetObject {
            meta: ObjectMeta {
                key: key.to_string(),
                size: Some(size),
                ..Default::default()
            },
            body,
        })
    }

    async fn put(
        &self,
        key: &str,
        mut body: ByteStream,
        _: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        let mut buf = Vec::new();
        while let Some(chunk) = body.next().await {
            buf.extend_from_slice(&chunk?);
        }
        let size = buf.len() as u64;
        self.objects.lock().unwrap().insert(key.to_string(), buf);
        Ok(ObjectMeta {
            key: key.to_string(),
            size: Some(size),
            ..Default::default()
        })
    }

    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        self.objects
            .lock()
            .unwrap()
            .get(key)
            .map(|b| ObjectMeta {
                key: key.to_string(),
                size: Some(b.len() as u64),
                ..Default::default()
            })
            .ok_or_else(|| StorageError::NotFound(key.to_string()))
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.objects.lock().unwrap().remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        Ok(self
            .objects
            .lock()
            .unwrap()
            .iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .map(|(k, v)| ObjectMeta {
                key: k.clone(),
                size: Some(v.len() as u64),
                ..Default::default()
            })
            .collect())
    }
}

impl MapStorage {
    /// The raw bytes stored at `key` (test assertion helper).
    pub(crate) fn get_bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.lock().unwrap().get(key).cloned()
    }

    /// The number of stored objects (GC / leak assertions).
    pub(crate) fn count_with_prefix(&self, prefix: &str) -> usize {
        self.objects
            .lock()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with(prefix))
            .count()
    }
}
