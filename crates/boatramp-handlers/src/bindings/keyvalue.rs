//! `wasi:keyvalue` host binding (store + atomics + batch) backed by boatramp's
//! [`KvStore`]. Every access is confined to the site's `hkv/{site}/` prefix, so
//! no handler can read or write another site's keys.
//!
//! `KvStore` is async, so — unlike wasmtime's in-memory reference binding — the
//! data methods are generated `async` (`get`/`set`/.../`increment`/batch);
//! `open`, the resource destructor, and the error conversion stay synchronous.

use std::sync::Arc;

use boatramp_core::kv::{KvStore, WriteOp};
use wasmtime::component::{Resource, ResourceTable, ResourceTableError};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "wasi:keyvalue/imports",
        // Only the methods that actually touch the (async) KvStore block.
        async: {
            only_imports: [
                "[method]bucket.get",
                "[method]bucket.set",
                "[method]bucket.delete",
                "[method]bucket.exists",
                "[method]bucket.list-keys",
                "increment",
                "get-many",
                "set-many",
                "delete-many",
            ],
        },
        trappable_imports: true,
        with: {
            "wasi:keyvalue/store/bucket": super::Bucket,
        },
        trappable_error_type: {
            "wasi:keyvalue/store/error" => super::KvHostError,
        },
    });
}

use generated::wasi::keyvalue;

/// A granted key/value capability: the site's store and the prefix every access
/// is confined to (`hkv/{site}/`).
#[derive(Clone)]
pub struct KvBinding {
    pub(crate) store: Arc<dyn KvStore>,
    pub(crate) prefix: String,
}

/// An opened bucket: a store handle plus this bucket's fully-resolved prefix
/// (`hkv/{site}/` for the default bucket, `hkv/{site}/{name}/` for a named one).
pub struct Bucket {
    store: Arc<dyn KvStore>,
    prefix: String,
}

impl Bucket {
    /// The backing-store key for a guest-supplied `key`.
    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }
}

/// Host-side error for the keyvalue interface; mapped to the WIT `error` (or a
/// trap) by [`keyvalue::store::Host::convert_error`]. We never raise the WIT
/// `no-such-store` (any identifier is accepted, namespaced under the site
/// prefix), so it has no variant here.
#[derive(Debug)]
pub enum KvHostError {
    /// The handler was not granted the keyvalue capability.
    AccessDenied,
    /// An implementation error (I/O, decode, ...).
    Other(String),
}

impl From<ResourceTableError> for KvHostError {
    fn from(err: ResourceTableError) -> Self {
        KvHostError::Other(err.to_string())
    }
}

impl From<boatramp_core::kv::KvError> for KvHostError {
    fn from(err: boatramp_core::kv::KvError) -> Self {
        KvHostError::Other(err.to_string())
    }
}

/// Per-invocation view: the store's resource table plus the (optional) granted
/// binding. `binding == None` means the capability was not granted, so `open`
/// fails with `access-denied` (deny by default).
pub struct KvHost<'a> {
    table: &'a mut ResourceTable,
    binding: Option<&'a KvBinding>,
}

impl<'a> KvHost<'a> {
    /// Build a view over `table`, granting access through `binding` (if any).
    pub fn new(table: &'a mut ResourceTable, binding: Option<&'a KvBinding>) -> Self {
        Self { table, binding }
    }
}

impl keyvalue::store::Host for KvHost<'_> {
    fn open(&mut self, identifier: String) -> Result<Resource<Bucket>, KvHostError> {
        let binding = self.binding.ok_or(KvHostError::AccessDenied)?;
        // The guest names a logical bucket within its own namespace; an empty
        // name is the default bucket. It can never escape `hkv/{site}/`.
        let prefix = if identifier.is_empty() {
            binding.prefix.clone()
        } else {
            format!("{}{identifier}/", binding.prefix)
        };
        Ok(self.table.push(Bucket {
            store: binding.store.clone(),
            prefix,
        })?)
    }

    fn convert_error(&mut self, err: KvHostError) -> wasmtime::Result<keyvalue::store::Error> {
        match err {
            KvHostError::AccessDenied => Ok(keyvalue::store::Error::AccessDenied),
            KvHostError::Other(e) => Ok(keyvalue::store::Error::Other(e)),
        }
    }
}

impl keyvalue::store::HostBucket for KvHost<'_> {
    async fn get(
        &mut self,
        bucket: Resource<Bucket>,
        key: String,
    ) -> Result<Option<Vec<u8>>, KvHostError> {
        let bucket = self.table.get(&bucket)?;
        let (store, key) = (bucket.store.clone(), bucket.key(&key));
        Ok(store.get(&key).await?)
    }

    async fn set(
        &mut self,
        bucket: Resource<Bucket>,
        key: String,
        value: Vec<u8>,
    ) -> Result<(), KvHostError> {
        let bucket = self.table.get(&bucket)?;
        let (store, key) = (bucket.store.clone(), bucket.key(&key));
        store.put(&key, value).await?;
        Ok(())
    }

    async fn delete(&mut self, bucket: Resource<Bucket>, key: String) -> Result<(), KvHostError> {
        let bucket = self.table.get(&bucket)?;
        let (store, key) = (bucket.store.clone(), bucket.key(&key));
        store.delete(&key).await?;
        Ok(())
    }

    async fn exists(&mut self, bucket: Resource<Bucket>, key: String) -> Result<bool, KvHostError> {
        let bucket = self.table.get(&bucket)?;
        let (store, key) = (bucket.store.clone(), bucket.key(&key));
        Ok(store.get(&key).await?.is_some())
    }

    async fn list_keys(
        &mut self,
        bucket: Resource<Bucket>,
        _cursor: Option<u64>,
    ) -> Result<keyvalue::store::KeyResponse, KvHostError> {
        let bucket = self.table.get(&bucket)?;
        let (store, prefix) = (bucket.store.clone(), bucket.prefix.clone());
        // KvStore listing is unpaginated; return every key in one page (cursor
        // exhausted). Keys are returned site-relative (prefix stripped).
        let keys = store
            .list_prefix(&prefix)
            .await?
            .into_iter()
            .map(|k| k.strip_prefix(&prefix).unwrap_or(&k).to_string())
            .collect();
        Ok(keyvalue::store::KeyResponse { keys, cursor: None })
    }

    fn drop(&mut self, bucket: Resource<Bucket>) -> wasmtime::Result<()> {
        self.table.delete(bucket)?;
        Ok(())
    }
}

impl keyvalue::atomics::Host for KvHost<'_> {
    async fn increment(
        &mut self,
        bucket: Resource<Bucket>,
        key: String,
        delta: u64,
    ) -> Result<u64, KvHostError> {
        let bucket = self.table.get(&bucket)?;
        let (store, key) = (bucket.store.clone(), bucket.key(&key));
        // Read-modify-write. Like wasmtime's reference binding this is atomic
        // only within a single store (KvStore exposes no compare-and-swap); a
        // CAS-capable backend can tighten this later.
        let current = match store.get(&key).await? {
            Some(bytes) => String::from_utf8(bytes)
                .ok()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| KvHostError::Other("value is not a u64 counter".into()))?,
            None => 0,
        };
        let next = current.saturating_add(delta);
        store.put(&key, next.to_string().into_bytes()).await?;
        Ok(next)
    }
}

impl keyvalue::batch::Host for KvHost<'_> {
    async fn get_many(
        &mut self,
        bucket: Resource<Bucket>,
        keys: Vec<String>,
    ) -> Result<Vec<Option<(String, Vec<u8>)>>, KvHostError> {
        let bucket = self.table.get(&bucket)?;
        let store = bucket.store.clone();
        let lookups: Vec<(String, String)> =
            keys.into_iter().map(|k| (bucket.key(&k), k)).collect();
        let mut out = Vec::with_capacity(lookups.len());
        for (full, original) in lookups {
            out.push(store.get(&full).await?.map(|value| (original, value)));
        }
        Ok(out)
    }

    async fn set_many(
        &mut self,
        bucket: Resource<Bucket>,
        key_values: Vec<(String, Vec<u8>)>,
    ) -> Result<(), KvHostError> {
        let bucket = self.table.get(&bucket)?;
        let store = bucket.store.clone();
        let ops = key_values
            .into_iter()
            .map(|(k, v)| WriteOp::Put(bucket.key(&k), v))
            .collect();
        store.write_batch(ops).await?;
        Ok(())
    }

    async fn delete_many(
        &mut self,
        bucket: Resource<Bucket>,
        keys: Vec<String>,
    ) -> Result<(), KvHostError> {
        let bucket = self.table.get(&bucket)?;
        let store = bucket.store.clone();
        let ops = keys
            .into_iter()
            .map(|k| WriteOp::Delete(bucket.key(&k)))
            .collect();
        store.write_batch(ops).await?;
        Ok(())
    }
}

/// Add the `wasi:keyvalue` store/atomics/batch interfaces to `linker`, resolving
/// the per-invocation [`KvHost`] view from the store's host state via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> KvHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    keyvalue::store::add_to_linker_get_host(linker, host)?;
    keyvalue::atomics::add_to_linker_get_host(linker, host)?;
    keyvalue::batch::add_to_linker_get_host(linker, host)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::keyvalue::atomics::Host as AtomicsHost;
    use super::keyvalue::batch::Host as BatchHost;
    use super::keyvalue::store::{Host, HostBucket};
    use super::*;
    use boatramp_core::kv::MemoryKv;

    fn binding(prefix: &str) -> (Arc<dyn KvStore>, KvBinding) {
        let store: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let bind = KvBinding {
            store: store.clone(),
            prefix: prefix.to_string(),
        };
        (store, bind)
    }

    #[tokio::test]
    async fn round_trip_is_confined_to_the_site_prefix() {
        let (store, bind) = binding("hkv/site-a/");
        let mut table = ResourceTable::new();
        let mut host = KvHost::new(&mut table, Some(&bind));

        let bucket = host.open(String::new()).unwrap();
        let rep = bucket.rep();
        host.set(bucket, "greeting".into(), b"hi".to_vec())
            .await
            .unwrap();

        // The value lands under the site prefix in the backing store.
        assert_eq!(
            store.get("hkv/site-a/greeting").await.unwrap(),
            Some(b"hi".to_vec())
        );
        // ...and is read back through the binding (prefix transparent to guest).
        assert_eq!(
            host.get(Resource::new_own(rep), "greeting".into())
                .await
                .unwrap(),
            Some(b"hi".to_vec())
        );
        assert!(host
            .exists(Resource::new_own(rep), "greeting".into())
            .await
            .unwrap());

        host.delete(Resource::new_own(rep), "greeting".into())
            .await
            .unwrap();
        assert_eq!(store.get("hkv/site-a/greeting").await.unwrap(), None);
    }

    #[tokio::test]
    async fn named_buckets_namespace_under_the_site() {
        let (store, bind) = binding("hkv/site-a/");
        let mut table = ResourceTable::new();
        let mut host = KvHost::new(&mut table, Some(&bind));

        let cache = host.open("cache".into()).unwrap();
        host.set(cache, "k".into(), b"v".to_vec()).await.unwrap();
        assert_eq!(
            store.get("hkv/site-a/cache/k").await.unwrap(),
            Some(b"v".to_vec())
        );
    }

    #[tokio::test]
    async fn list_keys_returns_site_relative_names() {
        let (_store, bind) = binding("hkv/site-a/");
        let mut table = ResourceTable::new();
        let mut host = KvHost::new(&mut table, Some(&bind));

        let bucket = host.open(String::new()).unwrap();
        let rep = bucket.rep();
        host.set(bucket, "a".into(), b"1".to_vec()).await.unwrap();
        host.set(Resource::new_own(rep), "b".into(), b"2".to_vec())
            .await
            .unwrap();

        let mut keys = host
            .list_keys(Resource::new_own(rep), None)
            .await
            .unwrap()
            .keys;
        keys.sort();
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);
    }

    #[tokio::test]
    async fn batch_and_increment() {
        let (_store, bind) = binding("hkv/site-a/");
        let mut table = ResourceTable::new();
        let mut host = KvHost::new(&mut table, Some(&bind));
        let bucket = host.open(String::new()).unwrap();
        let rep = bucket.rep();

        host.set_many(
            bucket,
            vec![
                ("x".into(), b"1".to_vec()),
                ("y".into(), b"2".to_vec()),
                ("z".into(), b"3".to_vec()),
            ],
        )
        .await
        .unwrap();

        let got = host
            .get_many(
                Resource::new_own(rep),
                vec!["x".into(), "missing".into(), "z".into()],
            )
            .await
            .unwrap();
        assert_eq!(got[0], Some(("x".to_string(), b"1".to_vec())));
        assert_eq!(got[1], None);
        assert_eq!(got[2], Some(("z".to_string(), b"3".to_vec())));

        host.delete_many(Resource::new_own(rep), vec!["x".into(), "y".into()])
            .await
            .unwrap();
        assert_eq!(
            host.get(Resource::new_own(rep), "x".into()).await.unwrap(),
            None
        );

        // increment creates-then-bumps a counter.
        assert_eq!(
            host.increment(Resource::new_own(rep), "n".into(), 5)
                .await
                .unwrap(),
            5
        );
        assert_eq!(
            host.increment(Resource::new_own(rep), "n".into(), 3)
                .await
                .unwrap(),
            8
        );
    }

    #[tokio::test]
    async fn two_sites_cannot_see_each_other() {
        // Same backing store, different site prefixes: writes never collide.
        let store: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let bind_a = KvBinding {
            store: store.clone(),
            prefix: "hkv/site-a/".into(),
        };
        let bind_b = KvBinding {
            store: store.clone(),
            prefix: "hkv/site-b/".into(),
        };
        let mut table = ResourceTable::new();

        {
            let mut host_a = KvHost::new(&mut table, Some(&bind_a));
            let b = host_a.open(String::new()).unwrap();
            host_a.set(b, "secret".into(), b"a".to_vec()).await.unwrap();
        }
        {
            let mut host_b = KvHost::new(&mut table, Some(&bind_b));
            let b = host_b.open(String::new()).unwrap();
            // site-b sees nothing under its own namespace.
            assert_eq!(host_b.get(b, "secret".into()).await.unwrap(), None);
        }
    }

    #[tokio::test]
    async fn open_without_grant_is_access_denied() {
        let mut table = ResourceTable::new();
        let mut host = KvHost::new(&mut table, None);
        assert!(matches!(
            host.open(String::new()),
            Err(KvHostError::AccessDenied)
        ));
    }
}
