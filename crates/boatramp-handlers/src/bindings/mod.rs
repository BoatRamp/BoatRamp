//! Host-side implementations of the standard WASI capability interfaces a
//! handler may import: `wasi:keyvalue`, `wasi:blobstore`,
//! and the boatramp `sql` interface. Each is generated from vendored WIT
//! (`wit/`) via `bindgen!` and backed by boatramp's own traits — `KvStore`,
//! `Storage` — with **per-site** namespacing so no handler can address another
//! site's data (tenant isolation).
//!
//! Capabilities are granted per invocation through [`Bindings`]: a field left
//! `None` is a capability the handler was not granted, and the corresponding
//! host calls fail with `access-denied` — deny by default.

#[cfg(feature = "sql")]
use std::collections::HashMap;
use std::sync::Arc;

use boatramp_core::kv::KvStore;
#[cfg(feature = "messaging")]
use boatramp_core::messaging::Messaging;
#[cfg(feature = "sql")]
use boatramp_core::sql::SqlBackend;
use boatramp_core::Storage;

pub mod blobstore;
pub mod keyvalue;
#[cfg(feature = "messaging")]
pub mod messaging;
#[cfg(feature = "sql")]
pub mod sql;

/// The per-site capability handles for one handler invocation.
///
/// Built once per site (cheaply cloned per request — every field is an `Arc` or
/// a small string). A `None` capability is one the handler is not granted.
#[derive(Clone, Default)]
pub struct Bindings {
    keyvalue: Option<keyvalue::KvBinding>,
    blobstore: Option<blobstore::BlobBinding>,
    /// The site's named SQL databases (`name -> backend`); the guest selects one
    /// via `sql.open(name)`. Empty = SQL not granted.
    #[cfg(feature = "sql")]
    sql: HashMap<String, Arc<dyn SqlBackend>>,
    /// The `wasi:messaging` producer grant (backend + topic-namespace prefix).
    /// `None` = messaging not granted.
    #[cfg(feature = "messaging")]
    messaging: Option<messaging::MessagingBinding>,
    /// Where this invocation's captured stdout/stderr is sent.
    /// `None` = the guest's stdio is left inherited (host stdio).
    logging: Option<crate::logging::LoggingBinding>,
    /// Environment variables exposed to the guest: the
    /// deploy's static `env` plus the site's resolved `secrets`. The guest sees
    /// *only* these — the host's own environment is never inherited.
    env: Vec<(String, String)>,
}

impl Bindings {
    /// Bindings for `site` with nothing granted yet.
    pub fn new(_site: impl AsRef<str>) -> Self {
        Self::default()
    }

    /// Grant the `wasi:keyvalue` capability, backed by `store`, with every key
    /// namespaced under `hkv/{site}/` (per-site isolation).
    pub fn with_keyvalue(mut self, site: &str, store: Arc<dyn KvStore>) -> Self {
        self.keyvalue = Some(keyvalue::KvBinding {
            store,
            prefix: format!("hkv/{site}/"),
        });
        self
    }

    /// Grant the `wasi:blobstore` capability, backed by `storage`, with every
    /// container namespaced under `hblob/{site}/` (per-site isolation).
    /// `max_bytes` caps a single host-side read/range/copy (`0` = unlimited),
    /// bounding host memory a handler can allocate via the binding.
    pub fn with_blobstore(mut self, site: &str, storage: Arc<dyn Storage>, max_bytes: u64) -> Self {
        self.blobstore = Some(blobstore::BlobBinding {
            storage,
            prefix: format!("hblob/{site}/"),
            max_bytes,
        });
        self
    }

    /// The granted key/value binding, if any.
    pub(crate) fn keyvalue(&self) -> Option<&keyvalue::KvBinding> {
        self.keyvalue.as_ref()
    }

    /// Grant a named SQL database, served by `backend` (libsql — a file or sqld
    /// namespace). Call once per database the site is granted; the empty name is
    /// the guest's default database.
    #[cfg(feature = "sql")]
    pub fn with_sql(mut self, name: impl Into<String>, backend: Arc<dyn SqlBackend>) -> Self {
        self.sql.insert(name.into(), backend);
        self
    }

    /// The granted blob binding, if any.
    pub(crate) fn blobstore(&self) -> Option<&blobstore::BlobBinding> {
        self.blobstore.as_ref()
    }

    /// Capture this invocation's stdout/stderr into `sink`, tagged with `scope`.
    /// Without this the guest's stdio is inherited.
    pub fn with_logging(
        mut self,
        scope: impl Into<String>,
        sink: Arc<dyn crate::logging::LogSink>,
    ) -> Self {
        self.logging = Some(crate::logging::LoggingBinding {
            sink,
            scope: scope.into(),
        });
        self
    }

    /// The granted logging capture binding, if any.
    pub(crate) fn logging(&self) -> Option<&crate::logging::LoggingBinding> {
        self.logging.as_ref()
    }

    /// Set the guest's environment variables (deploy `env` + resolved secrets).
    /// These are the *only* env vars the guest sees; the host's are never
    /// inherited.
    pub fn with_env(mut self, env: Vec<(String, String)>) -> Self {
        self.env = env;
        self
    }

    /// The guest's environment variables.
    pub(crate) fn env(&self) -> &[(String, String)] {
        &self.env
    }

    /// The granted SQL databases (`name -> backend`).
    #[cfg(feature = "sql")]
    pub(crate) fn sql(&self) -> HashMap<String, Arc<dyn SqlBackend>> {
        self.sql.clone()
    }

    /// Grant the `wasi:messaging` producer capability, backed by `messaging`,
    /// with every published topic namespaced under `prefix` (per-site/alias
    /// isolation — the guest can't publish outside its own namespace).
    #[cfg(feature = "messaging")]
    pub fn with_messaging(
        mut self,
        prefix: impl Into<String>,
        messaging: Arc<dyn Messaging>,
    ) -> Self {
        self.messaging = Some(messaging::MessagingBinding {
            messaging,
            prefix: prefix.into(),
        });
        self
    }

    /// The granted messaging binding, if any.
    #[cfg(feature = "messaging")]
    pub(crate) fn messaging(&self) -> Option<&messaging::MessagingBinding> {
        self.messaging.as_ref()
    }
}
