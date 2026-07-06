//! `wasi:blobstore` host binding backed by boatramp's [`Storage`]. Containers
//! and objects live under a per-site prefix (`hblob/{site}/{container}/...`), so
//! no handler can address another site's blobs.
//!
//! Object bodies are buffered in memory while crossing the host boundary: a read
//! materializes the (ranged) object into an `incoming-value`, and a write
//! collects the guest's `output-stream` before a single [`Storage::put`]. True
//! end-to-end streaming for very large blobs is an H8 hardening item; the http
//! request/response path (the primary streaming concern) already streams.
//!
//! A "container" is a key prefix plus a marker object (`MARKER`) so empty
//! containers are first-class (create / exists / clear semantics). `error` is
//! the WIT `string`, so methods return `Result<_, String>` directly.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use boatramp_core::{ByteStream, PutMeta, Storage, StorageError};
use bytes::Bytes;
use futures::StreamExt;
use wasmtime::component::{Resource, ResourceTable};
use wasmtime_wasi::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::{DynInputStream, DynOutputStream};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "wasi:blobstore/imports",
        // Methods that touch the (async) Storage backend block; the in-memory
        // value/stream resources do not.
        async: {
            only_imports: [
                "[method]container.info",
                "[method]container.get-data",
                "[method]container.write-data",
                "[method]container.list-objects",
                "[method]container.delete-object",
                "[method]container.delete-objects",
                "[method]container.has-object",
                "[method]container.object-info",
                "[method]container.clear",
                "create-container",
                "get-container",
                "delete-container",
                "container-exists",
                "copy-object",
                "move-object",
            ],
        },
        with: {
            "wasi:io/streams": wasmtime_wasi_io::bindings::wasi::io::streams,
            "wasi:io/poll": wasmtime_wasi_io::bindings::wasi::io::poll,
            "wasi:io/error": wasmtime_wasi_io::bindings::wasi::io::error,
            "wasi:blobstore/types/incoming-value": super::IncomingValue,
            "wasi:blobstore/types/outgoing-value": super::OutgoingValue,
            "wasi:blobstore/container/container": super::Container,
            "wasi:blobstore/container/stream-object-names": super::StreamObjectNames,
        },
    });
}

use generated::wasi::blobstore;

/// Marker object that records a container's existence (and creation time). Kept
/// out of `list-objects` results.
const MARKER: &str = ".boatramp-container";

/// Cap on a single buffered outgoing value (also the handler memory ceiling).
const OUTGOING_CAP: usize = 64 * 1024 * 1024;

/// A granted blob capability: the site's storage and the container prefix every
/// access is confined to (`hblob/{site}/`).
#[derive(Clone)]
pub struct BlobBinding {
    pub(crate) storage: Arc<dyn Storage>,
    pub(crate) prefix: String,
    /// Max bytes a single host-side read/range/copy may buffer (`0` = unlimited).
    /// A `wasi:blobstore` read/copy materializes the object in host memory
    /// *outside* the guest's wasm linear-memory limit, so without this a handler
    /// could exhaust host memory with a large object. Set from the
    /// security posture's `max_handler_blob_bytes`.
    pub(crate) max_bytes: u64,
}

/// An opened container handle: the storage, the container's key prefix
/// (`hblob/{site}/{name}/`), and its name.
pub struct Container {
    storage: Arc<dyn Storage>,
    prefix: String,
    name: String,
}

impl Container {
    fn object_key(&self, object: &str) -> String {
        format!("{}{object}", self.prefix)
    }

    fn marker_key(&self) -> String {
        format!("{}{MARKER}", self.prefix)
    }
}

/// An in-progress listing snapshot (object names captured at `list-objects`).
pub struct StreamObjectNames {
    names: Vec<String>,
    cursor: usize,
}

/// A read object's bytes, held until consumed.
pub struct IncomingValue {
    bytes: Vec<u8>,
}

/// A value being assembled for writing: the guest writes into `pipe`, then
/// `write-data` flushes `pipe`'s contents to storage.
pub struct OutgoingValue {
    pipe: MemoryOutputPipe,
    body_taken: bool,
}

/// Per-invocation view: the resource table plus the (optional) granted binding.
pub struct BlobHost<'a> {
    table: &'a mut ResourceTable,
    binding: Option<&'a BlobBinding>,
}

impl<'a> BlobHost<'a> {
    /// Build a view over `table`, granting access through `binding` (if any).
    pub fn new(table: &'a mut ResourceTable, binding: Option<&'a BlobBinding>) -> Self {
        Self { table, binding }
    }
}

fn estr<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A single-chunk byte stream for [`Storage::put`].
fn once_stream(bytes: Bytes) -> ByteStream {
    futures::stream::once(async move { Ok::<_, StorageError>(bytes) }).boxed()
}

/// Drain a [`ByteStream`] into a buffer, refusing to exceed `max` bytes (`0` =
/// unlimited). The cap is enforced *as chunks arrive*, so an over-cap object is
/// abandoned mid-stream rather than fully buffered first.
async fn collect(mut body: ByteStream, max: u64) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    while let Some(chunk) = body.next().await {
        buf.extend_from_slice(&chunk.map_err(estr)?);
        if max != 0 && buf.len() as u64 > max {
            return Err(format!("object exceeds the {max}-byte host blob limit"));
        }
    }
    Ok(buf)
}

impl BlobHost<'_> {
    /// `hblob/{site}/{container}/` for `name`, or an error if no grant.
    fn container_prefix(&self, name: &str) -> Result<String, String> {
        let binding = self.binding.ok_or_else(|| "access denied".to_string())?;
        Ok(format!("{}{name}/", binding.prefix))
    }

    fn storage(&self) -> Result<Arc<dyn Storage>, String> {
        Ok(self
            .binding
            .ok_or_else(|| "access denied".to_string())?
            .storage
            .clone())
    }

    /// The granted host-side blob read/copy byte cap (`0` = unlimited).
    fn max_bytes(&self) -> u64 {
        self.binding.map(|b| b.max_bytes).unwrap_or(0)
    }
}

/// Whether a container marker exists under `prefix`. A free function (not a
/// `&self` method) so the returned future stays `Send` — `&dyn Storage` is
/// `Send + Sync`, unlike `&BlobHost` (which holds `&mut ResourceTable`).
async fn marker_exists(storage: &dyn Storage, prefix: &str) -> Result<bool, String> {
    match storage.head(&format!("{prefix}{MARKER}")).await {
        Ok(_) => Ok(true),
        Err(StorageError::NotFound(_)) => Ok(false),
        Err(err) => Err(estr(err)),
    }
}

impl blobstore::types::Host for BlobHost<'_> {}

impl blobstore::types::HostOutgoingValue for BlobHost<'_> {
    fn new_outgoing_value(&mut self) -> Resource<OutgoingValue> {
        self.table
            .push(OutgoingValue {
                pipe: MemoryOutputPipe::new(OUTGOING_CAP),
                body_taken: false,
            })
            .expect("resource table push")
    }

    fn outgoing_value_write_body(
        &mut self,
        this: Resource<OutgoingValue>,
    ) -> Result<Resource<DynOutputStream>, ()> {
        let value = self.table.get_mut(&this).map_err(|_| ())?;
        if value.body_taken {
            return Err(());
        }
        value.body_taken = true;
        // The returned stream shares the value's buffer (both hold the same Arc),
        // so bytes the guest writes are visible to `write-data`.
        let stream: DynOutputStream = Box::new(value.pipe.clone());
        self.table.push_child(stream, &this).map_err(|_| ())
    }

    fn finish(&mut self, this: Resource<OutgoingValue>) -> Result<(), String> {
        // The bytes are persisted by `container.write-data`; finishing just
        // retires the resource.
        self.table.delete(this).map_err(estr)?;
        Ok(())
    }

    fn drop(&mut self, rep: Resource<OutgoingValue>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl blobstore::types::HostIncomingValue for BlobHost<'_> {
    fn incoming_value_consume_sync(
        &mut self,
        this: Resource<IncomingValue>,
    ) -> Result<Vec<u8>, String> {
        Ok(self.table.delete(this).map_err(estr)?.bytes)
    }

    fn incoming_value_consume_async(
        &mut self,
        this: Resource<IncomingValue>,
    ) -> Result<Resource<DynInputStream>, String> {
        let value = self.table.delete(this).map_err(estr)?;
        let stream: DynInputStream = Box::new(MemoryInputPipe::new(value.bytes));
        self.table.push(stream).map_err(estr)
    }

    fn size(&mut self, this: Resource<IncomingValue>) -> u64 {
        self.table
            .get(&this)
            .map(|v| v.bytes.len() as u64)
            .unwrap_or(0)
    }

    fn drop(&mut self, rep: Resource<IncomingValue>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl blobstore::container::Host for BlobHost<'_> {}

impl blobstore::container::HostContainer for BlobHost<'_> {
    fn name(&mut self, this: Resource<Container>) -> Result<String, String> {
        Ok(self.table.get(&this).map_err(estr)?.name.clone())
    }

    async fn info(
        &mut self,
        this: Resource<Container>,
    ) -> Result<blobstore::types::ContainerMetadata, String> {
        let container = self.table.get(&this).map_err(estr)?;
        let (storage, marker, name) = (
            container.storage.clone(),
            container.marker_key(),
            container.name.clone(),
        );
        let created_at = read_created_at(&*storage, &marker).await?;
        Ok(blobstore::types::ContainerMetadata { name, created_at })
    }

    async fn get_data(
        &mut self,
        this: Resource<Container>,
        name: String,
        start: u64,
        end: u64,
    ) -> Result<Resource<IncomingValue>, String> {
        let container = self.table.get(&this).map_err(estr)?;
        let (storage, key) = (container.storage.clone(), container.object_key(&name));
        // Offsets are inclusive; request `end - start + 1` bytes from `start`.
        let len = end.saturating_sub(start).saturating_add(1);
        let object = storage
            .get_range(&key, start, Some(len))
            .await
            .map_err(estr)?;
        let bytes = collect(object.body, self.max_bytes()).await?;
        self.table.push(IncomingValue { bytes }).map_err(estr)
    }

    async fn write_data(
        &mut self,
        this: Resource<Container>,
        name: String,
        data: Resource<OutgoingValue>,
    ) -> Result<(), String> {
        let bytes = self.table.get(&data).map_err(estr)?.pipe.contents();
        let container = self.table.get(&this).map_err(estr)?;
        let (storage, key) = (container.storage.clone(), container.object_key(&name));
        storage
            .put(&key, once_stream(bytes), PutMeta::default())
            .await
            .map_err(estr)?;
        Ok(())
    }

    async fn list_objects(
        &mut self,
        this: Resource<Container>,
    ) -> Result<Resource<StreamObjectNames>, String> {
        let container = self.table.get(&this).map_err(estr)?;
        let (storage, prefix) = (container.storage.clone(), container.prefix.clone());
        let names = storage
            .list(&prefix)
            .await
            .map_err(estr)?
            .into_iter()
            .filter_map(|meta| {
                let name = meta.key.strip_prefix(&prefix).unwrap_or(&meta.key);
                // Hide the existence marker and anything in a nested prefix.
                (name != MARKER && !name.contains('/')).then(|| name.to_string())
            })
            .collect();
        self.table
            .push(StreamObjectNames { names, cursor: 0 })
            .map_err(estr)
    }

    async fn delete_object(
        &mut self,
        this: Resource<Container>,
        name: String,
    ) -> Result<(), String> {
        let container = self.table.get(&this).map_err(estr)?;
        let (storage, key) = (container.storage.clone(), container.object_key(&name));
        storage.delete(&key).await.map_err(estr)
    }

    async fn delete_objects(
        &mut self,
        this: Resource<Container>,
        names: Vec<String>,
    ) -> Result<(), String> {
        let container = self.table.get(&this).map_err(estr)?;
        let storage = container.storage.clone();
        let keys: Vec<String> = names.iter().map(|n| container.object_key(n)).collect();
        for key in keys {
            storage.delete(&key).await.map_err(estr)?;
        }
        Ok(())
    }

    async fn has_object(
        &mut self,
        this: Resource<Container>,
        name: String,
    ) -> Result<bool, String> {
        let container = self.table.get(&this).map_err(estr)?;
        let (storage, key) = (container.storage.clone(), container.object_key(&name));
        match storage.head(&key).await {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound(_)) => Ok(false),
            Err(err) => Err(estr(err)),
        }
    }

    async fn object_info(
        &mut self,
        this: Resource<Container>,
        name: String,
    ) -> Result<blobstore::types::ObjectMetadata, String> {
        let container = self.table.get(&this).map_err(estr)?;
        let (storage, key, cname) = (
            container.storage.clone(),
            container.object_key(&name),
            container.name.clone(),
        );
        let meta = storage.head(&key).await.map_err(estr)?;
        Ok(blobstore::types::ObjectMetadata {
            name,
            container: cname,
            // Per-object creation time is not tracked by Storage yet (returns 0).
            created_at: 0,
            size: meta.size.unwrap_or(0),
        })
    }

    async fn clear(&mut self, this: Resource<Container>) -> Result<(), String> {
        let container = self.table.get(&this).map_err(estr)?;
        let (storage, prefix) = (container.storage.clone(), container.prefix.clone());
        // Delete every object but keep the marker, so the container still exists.
        for meta in storage.list(&prefix).await.map_err(estr)? {
            if meta.key.strip_prefix(&prefix) == Some(MARKER) {
                continue;
            }
            storage.delete(&meta.key).await.map_err(estr)?;
        }
        Ok(())
    }

    fn drop(&mut self, rep: Resource<Container>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl blobstore::container::HostStreamObjectNames for BlobHost<'_> {
    fn read_stream_object_names(
        &mut self,
        this: Resource<StreamObjectNames>,
        len: u64,
    ) -> Result<(Vec<String>, bool), String> {
        let stream = self.table.get_mut(&this).map_err(estr)?;
        let take = (len as usize).min(stream.names.len() - stream.cursor);
        let batch = stream.names[stream.cursor..stream.cursor + take].to_vec();
        stream.cursor += take;
        let at_end = stream.cursor >= stream.names.len();
        Ok((batch, at_end))
    }

    fn skip_stream_object_names(
        &mut self,
        this: Resource<StreamObjectNames>,
        num: u64,
    ) -> Result<(u64, bool), String> {
        let stream = self.table.get_mut(&this).map_err(estr)?;
        let skip = (num as usize).min(stream.names.len() - stream.cursor);
        stream.cursor += skip;
        let at_end = stream.cursor >= stream.names.len();
        Ok((skip as u64, at_end))
    }

    fn drop(&mut self, rep: Resource<StreamObjectNames>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl blobstore::blobstore::Host for BlobHost<'_> {
    async fn create_container(&mut self, name: String) -> Result<Resource<Container>, String> {
        let prefix = self.container_prefix(&name)?;
        let storage = self.storage()?;
        // The marker's body records creation time.
        storage
            .put(
                &format!("{prefix}{MARKER}"),
                once_stream(Bytes::from(unix_now().to_string())),
                PutMeta::default(),
            )
            .await
            .map_err(estr)?;
        self.table
            .push(Container {
                storage,
                prefix,
                name,
            })
            .map_err(estr)
    }

    async fn get_container(&mut self, name: String) -> Result<Resource<Container>, String> {
        let prefix = self.container_prefix(&name)?;
        let storage = self.storage()?;
        if !marker_exists(&*storage, &prefix).await? {
            return Err(format!("no such container: {name}"));
        }
        self.table
            .push(Container {
                storage,
                prefix,
                name,
            })
            .map_err(estr)
    }

    async fn delete_container(&mut self, name: String) -> Result<(), String> {
        let prefix = self.container_prefix(&name)?;
        let storage = self.storage()?;
        for meta in storage.list(&prefix).await.map_err(estr)? {
            storage.delete(&meta.key).await.map_err(estr)?;
        }
        Ok(())
    }

    async fn container_exists(&mut self, name: String) -> Result<bool, String> {
        let prefix = self.container_prefix(&name)?;
        let storage = self.storage()?;
        marker_exists(&*storage, &prefix).await
    }

    async fn copy_object(
        &mut self,
        src: blobstore::types::ObjectId,
        dest: blobstore::types::ObjectId,
    ) -> Result<(), String> {
        let storage = self.storage()?;
        let src_key = format!("{}{}", self.container_prefix(&src.container)?, src.object);
        let dest_prefix = self.container_prefix(&dest.container)?;
        if !marker_exists(&*storage, &dest_prefix).await? {
            return Err(format!("no such container: {}", dest.container));
        }
        let object = storage.get(&src_key).await.map_err(estr)?;
        let bytes = collect(object.body, self.max_bytes()).await?;
        storage
            .put(
                &format!("{dest_prefix}{}", dest.object),
                once_stream(Bytes::from(bytes)),
                PutMeta::default(),
            )
            .await
            .map_err(estr)?;
        Ok(())
    }

    async fn move_object(
        &mut self,
        src: blobstore::types::ObjectId,
        dest: blobstore::types::ObjectId,
    ) -> Result<(), String> {
        self.copy_object(src.clone(), dest).await?;
        let storage = self.storage()?;
        let src_key = format!("{}{}", self.container_prefix(&src.container)?, src.object);
        storage.delete(&src_key).await.map_err(estr)
    }
}

/// Read a container marker's body as a unix timestamp (0 if absent/unparsable).
async fn read_created_at(storage: &dyn Storage, marker: &str) -> Result<u64, String> {
    match storage.get(marker).await {
        Ok(object) => {
            // The marker is an internal, host-written timestamp (a few bytes) —
            // not a guest-controlled object, so no read cap applies.
            let bytes = collect(object.body, 0).await?;
            Ok(String::from_utf8_lossy(&bytes).parse().unwrap_or(0))
        }
        Err(StorageError::NotFound(_)) => Ok(0),
        Err(err) => Err(estr(err)),
    }
}

/// Add the `wasi:blobstore` interfaces to `linker`, resolving the per-invocation
/// [`BlobHost`] view via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> BlobHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    blobstore::types::add_to_linker_get_host(linker, host)?;
    blobstore::container::add_to_linker_get_host(linker, host)?;
    blobstore::blobstore::add_to_linker_get_host(linker, host)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::blobstore::blobstore::Host as BlobstoreHost;
    use super::blobstore::container::{HostContainer, HostStreamObjectNames};
    use super::blobstore::types::{HostIncomingValue, ObjectId};
    use super::*;
    use boatramp_core::{GetObject, ObjectMeta};
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use wasmtime_wasi::OutputStream;

    /// A minimal in-memory [`Storage`] for exercising the binding.
    #[derive(Default, Clone)]
    struct MemStorage {
        map: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
    }

    fn meta(key: &str, len: usize) -> ObjectMeta {
        ObjectMeta {
            key: key.to_string(),
            size: Some(len as u64),
            content_type: None,
            etag: None,
        }
    }

    #[async_trait::async_trait]
    impl Storage for MemStorage {
        async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
            let data = self
                .map
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(GetObject {
                meta: meta(key, data.len()),
                body: once_stream(Bytes::from(data)),
            })
        }

        async fn get_range(
            &self,
            key: &str,
            offset: u64,
            len: Option<u64>,
        ) -> Result<GetObject, StorageError> {
            let data = self
                .map
                .lock()
                .unwrap()
                .get(key)
                .cloned()
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            let start = (offset as usize).min(data.len());
            let end = match len {
                Some(l) => (start + l as usize).min(data.len()),
                None => data.len(),
            };
            let slice = data[start..end].to_vec();
            Ok(GetObject {
                meta: meta(key, slice.len()),
                body: once_stream(Bytes::from(slice)),
            })
        }

        async fn put(
            &self,
            key: &str,
            mut body: ByteStream,
            _meta: PutMeta,
        ) -> Result<ObjectMeta, StorageError> {
            let mut buf = Vec::new();
            while let Some(chunk) = body.next().await {
                buf.extend_from_slice(&chunk?);
            }
            let m = meta(key, buf.len());
            self.map.lock().unwrap().insert(key.to_string(), buf);
            Ok(m)
        }

        async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
            let map = self.map.lock().unwrap();
            let data = map
                .get(key)
                .ok_or_else(|| StorageError::NotFound(key.to_string()))?;
            Ok(meta(key, data.len()))
        }

        async fn delete(&self, key: &str) -> Result<(), StorageError> {
            self.map.lock().unwrap().remove(key);
            Ok(())
        }

        async fn list(&self, prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
            Ok(self
                .map
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .map(|(k, v)| meta(k, v.len()))
                .collect())
        }
    }

    fn binding(storage: Arc<dyn Storage>, prefix: &str) -> BlobBinding {
        BlobBinding {
            storage,
            prefix: prefix.to_string(),
            max_bytes: 0, // unlimited for the general tests
        }
    }

    /// A host-side blob read refuses to buffer past the byte cap, so
    /// a handler can't allocate unbounded host memory (`0` = unlimited).
    #[tokio::test]
    async fn collect_enforces_byte_cap() {
        let big = Bytes::from(vec![0u8; 100]);
        // Over the cap → refused before fully buffering.
        assert!(collect(once_stream(big.clone()), 50).await.is_err());
        // At/under the cap → ok.
        assert_eq!(
            collect(once_stream(big.clone()), 200).await.unwrap().len(),
            100
        );
        // 0 = unlimited.
        assert_eq!(collect(once_stream(big), 0).await.unwrap().len(), 100);
    }

    /// Push a ready-to-write outgoing value (bytes already buffered), as if the
    /// guest had written them through the output-stream.
    fn outgoing(table: &mut ResourceTable, bytes: &[u8]) -> Resource<OutgoingValue> {
        let mut pipe = MemoryOutputPipe::new(OUTGOING_CAP);
        pipe.write(Bytes::copy_from_slice(bytes)).unwrap();
        table
            .push(OutgoingValue {
                pipe,
                body_taken: true,
            })
            .unwrap()
    }

    #[tokio::test]
    async fn create_write_read_roundtrip_under_site_prefix() {
        let storage = Arc::new(MemStorage::default());
        let bind = binding(storage.clone(), "hblob/site-a/");
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        let container = host.create_container("photos".into()).await.unwrap();
        let crep = container.rep();
        let ov = outgoing(host.table, b"jpeg-bytes");
        host.write_data(Resource::new_own(crep), "cat.jpg".into(), ov)
            .await
            .unwrap();

        // Stored under the per-site container prefix.
        assert_eq!(
            storage
                .map
                .lock()
                .unwrap()
                .get("hblob/site-a/photos/cat.jpg"),
            Some(&b"jpeg-bytes".to_vec())
        );

        assert!(host
            .has_object(Resource::new_own(crep), "cat.jpg".into())
            .await
            .unwrap());
        let info = host
            .object_info(Resource::new_own(crep), "cat.jpg".into())
            .await
            .unwrap();
        assert_eq!(info.size, 10);
        assert_eq!(info.container, "photos");

        // get-data (inclusive range over the whole object) -> incoming-value.
        let iv = host
            .get_data(Resource::new_own(crep), "cat.jpg".into(), 0, 9)
            .await
            .unwrap();
        let bytes = host.incoming_value_consume_sync(iv).unwrap();
        assert_eq!(bytes, b"jpeg-bytes");
    }

    #[tokio::test]
    async fn list_objects_hides_marker_and_strips_prefix() {
        let storage = Arc::new(MemStorage::default());
        let bind = binding(storage.clone(), "hblob/site-a/");
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        let c = host.create_container("c".into()).await.unwrap();
        let crep = c.rep();
        for name in ["a.txt", "b.txt"] {
            let ov = outgoing(host.table, b"x");
            host.write_data(Resource::new_own(crep), name.into(), ov)
                .await
                .unwrap();
        }

        let stream = host.list_objects(Resource::new_own(crep)).await.unwrap();
        let (mut names, end) = host.read_stream_object_names(stream, 100).unwrap();
        names.sort();
        assert_eq!(names, vec!["a.txt".to_string(), "b.txt".to_string()]);
        assert!(end);
    }

    #[tokio::test]
    async fn container_lifecycle_and_clear() {
        let storage = Arc::new(MemStorage::default());
        let bind = binding(storage.clone(), "hblob/site-a/");
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        assert!(!host.container_exists("c".into()).await.unwrap());
        assert!(host.get_container("c".into()).await.is_err());

        host.create_container("c".into()).await.unwrap();
        assert!(host.container_exists("c".into()).await.unwrap());
        let c = host.get_container("c".into()).await.unwrap();
        let crep = c.rep();

        let ov = outgoing(host.table, b"data");
        host.write_data(Resource::new_own(crep), "o".into(), ov)
            .await
            .unwrap();
        // clear empties objects but keeps the container.
        host.clear(Resource::new_own(crep)).await.unwrap();
        assert!(!host
            .has_object(Resource::new_own(crep), "o".into())
            .await
            .unwrap());
        assert!(host.container_exists("c".into()).await.unwrap());

        // delete-container removes everything, including the marker.
        host.delete_container("c".into()).await.unwrap();
        assert!(!host.container_exists("c".into()).await.unwrap());
    }

    #[tokio::test]
    async fn copy_and_move_object() {
        let storage = Arc::new(MemStorage::default());
        let bind = binding(storage.clone(), "hblob/site-a/");
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        host.create_container("src".into()).await.unwrap();
        host.create_container("dst".into()).await.unwrap();
        let src = host.get_container("src".into()).await.unwrap();
        let srep = src.rep();
        let ov = outgoing(host.table, b"payload");
        host.write_data(Resource::new_own(srep), "f".into(), ov)
            .await
            .unwrap();

        let id = |c: &str, o: &str| ObjectId {
            container: c.to_string(),
            object: o.to_string(),
        };
        host.copy_object(id("src", "f"), id("dst", "f2"))
            .await
            .unwrap();
        assert_eq!(
            storage.map.lock().unwrap().get("hblob/site-a/dst/f2"),
            Some(&b"payload".to_vec())
        );

        host.move_object(id("src", "f"), id("dst", "f3"))
            .await
            .unwrap();
        assert!(storage
            .map
            .lock()
            .unwrap()
            .get("hblob/site-a/src/f")
            .is_none());
        assert_eq!(
            storage.map.lock().unwrap().get("hblob/site-a/dst/f3"),
            Some(&b"payload".to_vec())
        );
    }

    #[tokio::test]
    async fn copy_to_missing_container_errors() {
        let storage = Arc::new(MemStorage::default());
        let bind = binding(storage.clone(), "hblob/site-a/");
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        host.create_container("src".into()).await.unwrap();
        let ov = outgoing(host.table, b"x");
        let src = host.create_container("src".into()).await.unwrap();
        host.write_data(src, "f".into(), ov).await.unwrap();

        let err = host
            .copy_object(
                ObjectId {
                    container: "src".into(),
                    object: "f".into(),
                },
                ObjectId {
                    container: "nope".into(),
                    object: "f".into(),
                },
            )
            .await
            .unwrap_err();
        assert!(err.contains("no such container"), "{err}");
    }

    #[tokio::test]
    async fn two_sites_are_isolated() {
        let storage: Arc<dyn Storage> = Arc::new(MemStorage::default());
        let bind_a = binding(storage.clone(), "hblob/site-a/");
        let bind_b = binding(storage.clone(), "hblob/site-b/");
        let mut table = ResourceTable::new();

        let arep = {
            let mut a = BlobHost::new(&mut table, Some(&bind_a));
            let c = a.create_container("shared".into()).await.unwrap();
            let crep = c.rep();
            let ov = outgoing(a.table, b"a-only");
            a.write_data(Resource::new_own(crep), "k".into(), ov)
                .await
                .unwrap();
            crep
        };
        let _ = arep;

        let mut b = BlobHost::new(&mut table, Some(&bind_b));
        // site-b has no "shared" container of its own.
        assert!(!b.container_exists("shared".into()).await.unwrap());
    }

    #[tokio::test]
    async fn create_without_grant_is_denied() {
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, None);
        assert!(host.create_container("c".into()).await.is_err());
    }
}
