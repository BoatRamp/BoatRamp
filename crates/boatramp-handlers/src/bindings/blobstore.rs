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

use boatramp_core::time::now_unix;
use std::sync::Arc;

use boatramp_core::project::{validate_key_segment, validate_object_key};
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

/// The boatramp-owned `blob-list` interface (server-side prefix filter + a bounded, resumable page).
/// A SEPARATE bindgen! world from the vendored `wasi:blobstore` one above (one world per bindgen!),
/// so the standard blobstore surface stays byte-for-byte untouched. Its `Host` is impl'd on the SAME
/// [`BlobHost`], reusing the one `container_prefix` confinement choke point.
mod generated_list {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/blob-list-host",
        // `list-page` touches the (async) Storage backend.
        async: true,
    });
}

use generated_list::boatramp::handlers::blob_list;

/// Marker object that records a container's existence (and creation time). Kept
/// out of `list-objects` results.
const MARKER: &str = ".boatramp-container";

/// The reserved host-internal object namespace. NO guest object can start with this (the write side
/// `validate_object_key` rejects `.boatramp*`); it holds the container [`MARKER`] and host-internal
/// staging such as `.boatramp-uploads/<id>/part-N` (S3-ingress multipart). A prefix listing fences
/// the WHOLE namespace (`is_reserved_name`), not just the exact marker — see [`confine_list_names`].
const RESERVED_PREFIX: &str = ".boatramp";

/// Upper bound on a single `blob-list` page (clamped from the guest's `limit`): keeps one call's
/// host work and the backend request bounded. Matches S3's `list_objects_v2` `max-keys` ceiling.
const MAX_LIST_PAGE: u32 = 1000;

/// Cap on a single buffered outgoing value (also the handler memory ceiling).
const OUTGOING_CAP: usize = 64 * 1024 * 1024;

/// The literal token a `blobstore_containers` entry may carry (e.g. `"assets-{tenant}"`): the HOST
/// substitutes THIS invocation's resolved OWN tenant for it before the allowlist match, so an entry
/// only ever admits the guest's own tenant's container. Mirrors `blob_upload::TENANT_TEMPLATE` (kept
/// as a local copy because the `blob_upload` module is `#[cfg(feature = "blob-upload")]`-gated while
/// this plain `wasi:blobstore` binding is always compiled — no cross-feature dependency).
const TENANT_TEMPLATE: &str = "{tenant}";

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
    /// THIS invocation's host-resolved OWN tenant (the `ScopeAxis::Tenant` value the SQL/ORM scope
    /// injector uses — NEVER guest-supplied), used ONLY to expand a `{tenant}` token in a
    /// [`containers`](Self::containers) entry. `None` for an `all`/anon/target/unscoped invocation ⇒
    /// a `{tenant}` entry cannot be expanded and fails closed. Mirrors
    /// `BlobUploadBinding::resolved_tenant`.
    pub(crate) tenant: Option<String>,
    /// The component's `blobstore_containers` allowlist (a `{tenant}`-templated set of container
    /// names). **Non-empty ⇒ ALWAYS enforced** at [`container_prefix`](BlobHost::container_prefix):
    /// the guest may open ONLY a container that exactly matches an expanded entry. **Empty** ⇒ the
    /// [`multi_tenant`](Self::multi_tenant) posture decides (deny on a multi-tenant site, permissive
    /// on a single-tenant/dev site).
    pub(crate) containers: Vec<String>,
    /// Whether this invocation's site is multi-tenant — derived from the tenancy fact that scopes
    /// `sql`/`orm` (the site/route DECLARES a tenancy, or a confining `HostTenancy` was resolved). A
    /// multi-tenant site with an EMPTY `containers` allowlist denies every `wasi:blobstore` container
    /// op (fail-closed); a single-tenant/dev site stays permissive.
    pub(crate) multi_tenant: bool,
}

/// An opened container handle: the storage, the container's key prefix
/// (`hblob/{site}/{name}/`), and its name.
pub struct Container {
    storage: Arc<dyn Storage>,
    prefix: String,
    name: String,
}

impl Container {
    fn object_key(&self, object: &str) -> Result<String, String> {
        checked_object_key(&self.prefix, object)
    }

    fn marker_key(&self) -> String {
        format!("{}{MARKER}", self.prefix)
    }
}

/// Compose an object key under `prefix`, first validating the guest-supplied object NAME as a
/// traversal-safe key ([`validate_object_key`]: rejects `..`/leading-or-doubled `/`/`\`/`*`/control
/// bytes and the reserved `.boatramp*` namespace). This is DEFENSE-IN-DEPTH — `..` is already inert
/// (the `fs` backend's `resolve` rejects it; cloud backends treat it literally) — centralized here so
/// every object op (`object_key` callers) plus the inline copy/move compositions screen the name
/// identically, mirroring `blob_upload::screen_upload_target`. The refusal is a distinct request
/// error, NOT routed through `blob_err` (which is for backend faults).
fn checked_object_key(prefix: &str, object: &str) -> Result<String, String> {
    validate_object_key(object).map_err(|e| format!("invalid object name: {e}"))?;
    Ok(format!("{prefix}{object}"))
}

/// Screen a guest-supplied LIST prefix for the `blob-list` capability. Unlike an object key a prefix
/// MAY contain `/` (it narrows into nested keys, e.g. `der/<sha>/`) and MAY be empty (the whole
/// container), so [`validate_object_key`] does not fit. The load-bearing confinement is structural —
/// [`join_list_prefix`] joins it UNDER the container prefix and [`confine_list_names`] strips that
/// prefix back off — so an escaping prefix simply matches nothing; this screen is defense-in-depth and
/// a clean guest error. Rejects a leading `/` (absolute-looking), a `..` path segment, the reserved
/// `.boatramp` namespace, backslashes, globs, and control bytes.
fn screen_list_prefix(prefix: &str) -> Result<(), String> {
    if prefix.is_empty() {
        return Ok(());
    }
    if prefix.starts_with('/') {
        return Err("invalid list prefix: must be container-relative (no leading '/')".to_string());
    }
    if prefix.contains('\0')
        || prefix.contains('\\')
        || prefix.contains('*')
        || prefix.chars().any(char::is_control)
    {
        return Err(
            "invalid list prefix: contains a control, backslash, or glob character".to_string(),
        );
    }
    if prefix.split('/').any(|seg| seg == "..") {
        return Err("invalid list prefix: '..' path segment".to_string());
    }
    if prefix.starts_with(".boatramp") {
        return Err("invalid list prefix: reserved namespace".to_string());
    }
    Ok(())
}

/// Join a screened guest list `prefix` UNDER the host-computed `container_prefix`
/// (`hblob/{site}/{container}/`), so the storage prefix ALWAYS starts with the container prefix and
/// the listing can only ever narrow WITHIN the guest's own container. This is one half of the
/// structural confinement (the other is [`confine_list_names`]); the pure split lets the
/// anti-hollow gate mutate it directly.
fn join_list_prefix(container_prefix: &str, guest_prefix: &str) -> String {
    // MUTATION SEAM (gate `escape_prefix`): use the guest prefix RAW, so the listing escapes the
    // container (another site's keyspace). Compiled out of shipped builds; the confinement gate then
    // goes RED. See [`list_mutation`].
    if list_mutation().as_deref() == Some("escape_prefix") {
        return guest_prefix.to_string();
    }
    format!("{container_prefix}{guest_prefix}")
}

/// Whether a container-relative `name` is in the reserved `.boatramp*` namespace — ANY path segment
/// starts (case-insensitively) with [`RESERVED_PREFIX`]. That is the container marker
/// (`.boatramp-container`) or host-internal staging (`.boatramp-uploads/<id>/part-N`), NEVER a guest
/// object (the write side rejects `.boatramp*` in every segment), so a prefix listing must not surface
/// it. Matching the write-side's every-segment fence (rather than leading-segment only) keeps this
/// self-contained — it does not rely on the "no writer nests a reserved segment" invariant holding.
fn is_reserved_name(name: &str) -> bool {
    name.split('/').any(|seg| {
        seg.get(..RESERVED_PREFIX.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(RESERVED_PREFIX))
    })
}

/// Relativize + confine a raw backend listing page to the guest's container view: STRIP
/// `container_prefix` off each key (yielding a container-relative name, e.g. `der/<sha>/0.jpg`) and
/// DROP the reserved `.boatramp*` namespace. A key NOT under `container_prefix` is dropped entirely —
/// the structural guarantee that a raw internal key (or another container's key) can never reach the
/// guest. Unlike `list-objects`, nested keys ARE kept (that is the whole point — reach `der/<sha>/…`),
/// which is exactly why the reserved-namespace fence is the WHOLE `.boatramp*` subtree here, not just
/// the exact top-level marker. Pure, so the confinement is unit-tested and mutation-gated.
fn confine_list_names(
    container_prefix: &str,
    metas: Vec<boatramp_core::ObjectMeta>,
) -> Vec<String> {
    // MUTATION SEAMS (compiled out of shipped builds): `no_strip` returns the raw internal key (leaks
    // `hblob/{site}/{container}/` AND fails to drop a foreign key); `show_marker` leaks the reserved
    // `.boatramp*` namespace (the marker + host-internal staging).
    let strip = list_mutation().as_deref() != Some("no_strip");
    let hide_reserved = list_mutation().as_deref() != Some("show_marker");
    metas
        .into_iter()
        .filter_map(|meta| {
            let name = if strip {
                meta.key.strip_prefix(container_prefix)?.to_string()
            } else {
                meta.key
            };
            (!(hide_reserved && is_reserved_name(&name))).then_some(name)
        })
        .collect()
}

/// The active `blob-list` confinement mutation (anti-hollow gate), or `None`. Present ONLY under
/// `cfg(test)` or the `blob-list-gate-mutation` feature; a shipped build has neither, so
/// [`join_list_prefix`]/[`confine_list_names`] are unconditional and this is a dead `None`. Mirrors
/// `boatramp_storage::blob_fault`'s mutation seam.
#[cfg(any(test, feature = "blob-list-gate-mutation"))]
fn list_mutation() -> Option<String> {
    std::env::var("BOATRAMP_BLOBLIST_MUTATION").ok()
}
#[cfg(not(any(test, feature = "blob-list-gate-mutation")))]
#[inline]
fn list_mutation() -> Option<String> {
    None
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

/// Map a `StorageError` from an object-store operation into the string the guest receives, and LOG a
/// genuine backend/transport fault host-side. A guest-actionable, self-describing outcome keeps its own
/// message — `NotFound` ("object not found: <key>", which the guest maps to 404), `InvalidKey`,
/// `Unsupported` — but a `Backend`/`Io` FAULT (a `403 AccessDenied` from an under-scoped credential, a
/// transport error) is logged with the real cause (op + key) for the operator and collapsed to a fixed,
/// coarse `"blob backend unavailable"` for the guest (which maps it to a 5xx, not a 404). The raw
/// object-store/SDK error can carry signing/endpoint/access-key metadata, so it reaches ONLY the
/// operator log, never a guest. Silent-404-on-403 — a `Backend` fault flattened into the SAME `Err` a
/// real 404 yields — was the trap that hid an under-scoped S3 credential (the blob-read-404 incident):
/// a write-only key 404'd every read with nothing in the logs.
fn blob_err(op: &str, key: &str, err: StorageError) -> String {
    match err {
        StorageError::Backend(_) | StorageError::Io(_) => {
            tracing::warn!(op, key, error = %err, "blob object-store backend fault");
            "blob backend unavailable".to_string()
        }
        // A structured read fault (`get`/`get_range`/`head`): the backend ALREADY emitted the rich
        // WARN (status + code + request-id + latency), so don't re-log — and give the guest the SAME
        // coarse, non-leaking reason, NEVER the status/code/request-id metadata the Display carries.
        StorageError::BackendRead { .. } => "blob backend unavailable".to_string(),
        // Self-describing + guest-actionable (no backend/credential metadata): pass the message through.
        other => other.to_string(),
    }
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
        buf.extend_from_slice(&chunk.map_err(|e| blob_err("read-stream", "", e))?);
        if max != 0 && buf.len() as u64 > max {
            return Err(format!("object exceeds the {max}-byte host blob limit"));
        }
    }
    Ok(buf)
}

impl BlobHost<'_> {
    /// `hblob/{site}/{container}/` for `name`, or an error if no grant / the container is not
    /// permitted for THIS invocation's resolved tenant.
    ///
    /// **The single tenant-confinement choke point (C2).** Every container op resolves its prefix
    /// through here (create/get/delete-container/container-exists/copy src+dest/move), so this one
    /// gate confines all of them — and every handle op transitively, since a `Container` handle can
    /// only be minted by a gated open. Mirrors `blob_upload::resolve_container`.
    ///
    /// Three DISTINCT, greppable refusal categories (never collapsed into "no such container"): an
    /// allowlist miss; a `{tenant}` entry with no resolved own tenant; and the multi-tenant
    /// deny-default. These are an AUTHORIZATION category, returned directly — NOT through
    /// [`blob_err`] (which masks a backend fault as "blob backend unavailable").
    fn container_prefix(&self, name: &str) -> Result<String, String> {
        let binding = self.binding.ok_or_else(|| "access denied".to_string())?;

        if !binding.containers.is_empty() {
            // A declared allowlist is ALWAYS enforced regardless of the multi-tenant posture (C3).
            // For each entry: a `{tenant}` entry is host-expanded with the resolved OWN tenant then
            // exact-matched; a plain entry is exact-matched literally. `split_once` intercepts a
            // `{tenant}`-bearing entry anywhere in the string (a guest cannot reach it by passing the
            // literal `{tenant}` — the match is exact equality against the host-expanded form, and
            // the tenant is never guest-supplied).
            let mut saw_unexpandable_template = false;
            let mut matched = false;
            for entry in &binding.containers {
                match entry.split_once(TENANT_TEMPLATE) {
                    // Security LOW-1: an EMPTY resolved tenant is treated as no resolved tenant (fail
                    // closed), never expanded to an empty segment (`assets-`). Bind sites already filter
                    // empties via `resolved_tenant_string`; this keeps the binding self-protecting.
                    Some((before, after)) => {
                        match binding.tenant.as_deref().filter(|s| !s.is_empty()) {
                            Some(tenant) => {
                                if name == format!("{before}{tenant}{after}") {
                                    matched = true;
                                    break;
                                }
                            }
                            // A `{tenant}` entry we cannot expand (no resolved own tenant): record it so a
                            // request that lines up ONLY with such an entry fails closed distinctly (C5),
                            // never a silent access-denied that could hide a wrongly-scoped invocation.
                            None => saw_unexpandable_template = true,
                        }
                    }
                    None => {
                        if entry == name {
                            matched = true;
                            break;
                        }
                    }
                }
            }
            if !matched {
                return Err(if saw_unexpandable_template {
                    format!(
                        "blobstore_containers: no resolved tenant to expand a {TENANT_TEMPLATE} \
                         entry for container '{name}'"
                    )
                } else {
                    format!(
                        "container '{name}' is not permitted by this component's \
                         blobstore_containers allowlist"
                    )
                });
            }
        } else if binding.multi_tenant {
            // No allowlist on a multi-tenant site ⇒ deny-by-default (fail-closed). The message names
            // the one-line remedy. BREAKING for a multi-tenant guest that granted `wasi:blobstore`
            // without declaring an allowlist.
            return Err(format!(
                "this multi-tenant site grants wasi:blobstore but declares no blobstore_containers; \
                 add blobstore_containers: [\"assets-{TENANT_TEMPLATE}\"]"
            ));
        }
        // else: single-tenant / dev with no allowlist ⇒ permissive (unchanged behavior).

        // Defense-in-depth: the resolved container must be a safe KEY segment — a `{tenant}`-expanded
        // tid carries `.`/`@`, so KEY-safety (`validate_key_segment`), not the strict slug. `..` is
        // already inert (fs `resolve` rejects; cloud literal); belt, not the load-bearing fix.
        validate_key_segment("container", name).map_err(|e| format!("invalid container: {e}"))?;
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
        Err(err) => Err(blob_err("head", prefix, err)),
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
        let (storage, key) = (container.storage.clone(), container.object_key(&name)?);
        // Offsets are inclusive. `end == u64::MAX` is the "whole object, host clamps to size"
        // sentinel the shim's `blob::get` passes (`get-data(_, 0, u64::MAX)`) — map it to a to-end
        // read (`None`) so NO backend receives a forged out-of-range `len`/end (which strict
        // S3-compatible backends like Tigris reject with 416; the S3 backend's `range_header` also
        // guards this, but keep it uniform across every backend). Otherwise the exact inclusive range.
        let len = (end != u64::MAX).then(|| end.saturating_sub(start).saturating_add(1));
        let object = storage
            .get_range(&key, start, len)
            .await
            .map_err(|e| blob_err("get", &key, e))?;
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
        let (storage, key) = (container.storage.clone(), container.object_key(&name)?);
        storage
            .put(&key, once_stream(bytes), PutMeta::default())
            .await
            .map_err(|e| blob_err("put", &key, e))?;
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
            .map_err(|e| blob_err("list", &prefix, e))?
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
        let (storage, key) = (container.storage.clone(), container.object_key(&name)?);
        storage
            .delete(&key)
            .await
            .map_err(|e| blob_err("delete", &key, e))
    }

    async fn delete_objects(
        &mut self,
        this: Resource<Container>,
        names: Vec<String>,
    ) -> Result<(), String> {
        let container = self.table.get(&this).map_err(estr)?;
        let storage = container.storage.clone();
        let keys: Vec<String> = names
            .iter()
            .map(|n| container.object_key(n))
            .collect::<Result<_, _>>()?;
        for key in keys {
            storage
                .delete(&key)
                .await
                .map_err(|e| blob_err("delete", &key, e))?;
        }
        Ok(())
    }

    async fn has_object(
        &mut self,
        this: Resource<Container>,
        name: String,
    ) -> Result<bool, String> {
        let container = self.table.get(&this).map_err(estr)?;
        let (storage, key) = (container.storage.clone(), container.object_key(&name)?);
        match storage.head(&key).await {
            Ok(_) => Ok(true),
            Err(StorageError::NotFound(_)) => Ok(false),
            Err(err) => Err(blob_err("head", &key, err)),
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
            container.object_key(&name)?,
            container.name.clone(),
        );
        let meta = storage
            .head(&key)
            .await
            .map_err(|e| blob_err("head", &key, e))?;
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
        for meta in storage
            .list(&prefix)
            .await
            .map_err(|e| blob_err("list", &prefix, e))?
        {
            if meta.key.strip_prefix(&prefix) == Some(MARKER) {
                continue;
            }
            storage
                .delete(&meta.key)
                .await
                .map_err(|e| blob_err("delete", &meta.key, e))?;
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
                once_stream(Bytes::from(now_unix().to_string())),
                PutMeta::default(),
            )
            .await
            .map_err(|e| blob_err("put", &format!("{prefix}{MARKER}"), e))?;
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
        for meta in storage
            .list(&prefix)
            .await
            .map_err(|e| blob_err("list", &prefix, e))?
        {
            storage
                .delete(&meta.key)
                .await
                .map_err(|e| blob_err("delete", &meta.key, e))?;
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
        // Both endpoints are confined: `container_prefix` gates each container against the tenant
        // allowlist, and `checked_object_key` screens each object name.
        let src_key = checked_object_key(&self.container_prefix(&src.container)?, &src.object)?;
        let dest_prefix = self.container_prefix(&dest.container)?;
        let dest_key = checked_object_key(&dest_prefix, &dest.object)?;
        if !marker_exists(&*storage, &dest_prefix).await? {
            return Err(format!("no such container: {}", dest.container));
        }
        let object = storage
            .get(&src_key)
            .await
            .map_err(|e| blob_err("get", &src_key, e))?;
        let bytes = collect(object.body, self.max_bytes()).await?;
        storage
            .put(
                &dest_key,
                once_stream(Bytes::from(bytes)),
                PutMeta::default(),
            )
            .await
            .map_err(|e| blob_err("put", &dest_key, e))?;
        Ok(())
    }

    async fn move_object(
        &mut self,
        src: blobstore::types::ObjectId,
        dest: blobstore::types::ObjectId,
    ) -> Result<(), String> {
        self.copy_object(src.clone(), dest).await?;
        let storage = self.storage()?;
        // The src container + object were already confined by the `copy_object` above; re-compose the
        // key the same confined way for the delete leg of the move.
        let src_key = checked_object_key(&self.container_prefix(&src.container)?, &src.object)?;
        storage
            .delete(&src_key)
            .await
            .map_err(|e| blob_err("delete", &src_key, e))
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
        Err(err) => Err(blob_err("get", marker, err)),
    }
}

/// **Test-support / gate helper (M5).** Read an object back through the REAL guest `wasi:blobstore`
/// read-path — the same `container.get-data` → `incoming-value.consume` the guest `compat::blob.get`
/// uses — over a [`BlobBinding`] confined to `hblob/{site}/`. Proves an object the S3-ingress face
/// landed at `hblob/{site}/{container}/{key}` is genuinely guest-readable (PLAN §11 "guest
/// read-through"), not merely present in the raw store.
///
/// This drives the actual host binding (`BlobHost::get_data`, which composes the
/// `hblob/{site}/{container}/` prefix + the object name and reads via [`Storage::get_range`]), so it
/// exercises the production read composition — a prefix/isolation regression would break it exactly as
/// it would break a real guest. `#[doc(hidden)]` — for the live gate + integration tests only.
#[doc(hidden)]
pub async fn read_object_through_guest_binding(
    storage: Arc<dyn Storage>,
    site: &str,
    container: &str,
    object: &str,
) -> Result<Vec<u8>, String> {
    use blobstore::container::HostContainer as _;
    use blobstore::types::HostIncomingValue as _;
    let binding = BlobBinding {
        storage,
        prefix: format!("hblob/{site}/"),
        max_bytes: 0,
        // The gate helper reads back a raw-landed object through an already-open container handle;
        // it does not exercise the open-time allowlist, so leave it unconstrained/single-tenant.
        tenant: None,
        containers: Vec::new(),
        multi_tenant: false,
    };
    let mut table = ResourceTable::new();
    let mut host = BlobHost::new(&mut table, Some(&binding));
    // Build a container handle exactly as `get_container` does (prefix `hblob/{site}/{container}/`) —
    // without the marker probe, since the ingress face lands raw objects (a guest that already holds an
    // open container handle reads them the same way).
    let handle = host
        .table
        .push(Container {
            storage: binding.storage.clone(),
            prefix: format!("hblob/{site}/{container}/"),
            name: container.to_string(),
        })
        .map_err(estr)?;
    let rep = handle.rep();
    // Read the whole object via the real ranged get-data path (offsets inclusive: `0..=len-1`).
    let size = binding
        .storage
        .head(&format!("hblob/{site}/{container}/{object}"))
        .await
        .map_err(estr)?
        .size
        .unwrap_or(0);
    if size == 0 {
        // A present-but-empty object: consume a zero-length read rather than an inverted range.
        let iv = host
            .get_data(Resource::new_own(rep), object.to_string(), 0, 0)
            .await?;
        let bytes = host.incoming_value_consume_sync(iv)?;
        return Ok(if bytes.len() == 1 { Vec::new() } else { bytes });
    }
    let iv = host
        .get_data(Resource::new_own(rep), object.to_string(), 0, size - 1)
        .await?;
    host.incoming_value_consume_sync(iv)
}

impl blob_list::Host for BlobHost<'_> {
    /// One bounded page of container-relative object names under `prefix`, resuming after the opaque
    /// `after` cursor. Confined by the SAME `container_prefix` choke point as every blob op: the guest
    /// `prefix` is screened then JOINED under the container prefix, and the returned keys are STRIPPED
    /// back to container-relative — so a crafted or escaping prefix, or a forged `after` cursor, can
    /// only ever list WITHIN the guest's own container. The marker is hidden; nested keys are kept.
    async fn list_page(
        &mut self,
        container: String,
        prefix: Option<String>,
        after: Option<String>,
        limit: u32,
    ) -> Result<blob_list::Page, String> {
        // Single tenant-confinement choke point: hblob/{site}/{container}/ (allowlist-gated).
        let container_prefix = self.container_prefix(&container)?;
        let storage = self.storage()?;
        let guest_prefix = prefix.as_deref().unwrap_or("");
        screen_list_prefix(guest_prefix)?;
        let joined = join_list_prefix(&container_prefix, guest_prefix);
        let limit = limit.clamp(1, MAX_LIST_PAGE);
        let page = storage
            .list_page(&joined, after.as_deref(), limit)
            .await
            .map_err(|e| blob_err("list-page", &joined, e))?;
        let names = confine_list_names(&container_prefix, page.metas);
        Ok(blob_list::Page {
            names,
            cursor: page.cursor,
        })
    }
}

/// Add the `wasi:blobstore` interfaces (plus the boatramp `blob-list` extension) to `linker`,
/// resolving the per-invocation [`BlobHost`] view via `host`. `blob-list` rides the SAME `host`
/// closure and the SAME grant/confinement as the standard blobstore surface, so it is uniform across
/// the request and consumer lanes by construction.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> BlobHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    blobstore::types::add_to_linker_get_host(linker, host)?;
    blobstore::container::add_to_linker_get_host(linker, host)?;
    blobstore::blobstore::add_to_linker_get_host(linker, host)?;
    blob_list::add_to_linker_get_host(linker, host)?;
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
            // The general roundtrip/isolation tests exercise a single-tenant permissive binding (no
            // allowlist, not multi-tenant) — the confinement paths get their own dedicated tests.
            tenant: None,
            containers: Vec::new(),
            multi_tenant: false,
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

        assert!(
            host.has_object(Resource::new_own(crep), "cat.jpg".into())
                .await
                .unwrap()
        );
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

    /// `list-page` (the boatramp `blob-list` capability): a server-side prefix filter + a bounded,
    /// resumable page. UNLIKE `list-objects` it reaches NESTED keys (the GC use case), returns
    /// container-relative names, hides the marker, paginates via the opaque cursor to exhaustion, and
    /// never crosses the container boundary. Exercises the end-to-end host path (confinement choke +
    /// join + the default `Storage::list_page` body + the strip).
    #[tokio::test]
    async fn list_page_prefix_scoped_paginates_and_stays_in_container() {
        use super::blob_list::Host as _;
        let storage = Arc::new(MemStorage::default());
        let bind = binding(storage.clone(), "hblob/site-a/");
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        // Container "assets" with nested derivative keys + a top-level key.
        let c = host.create_container("assets".into()).await.unwrap();
        let crep = c.rep();
        for name in [
            "der/shaA/0.jpg",
            "der/shaA/1.jpg",
            "der/shaB/0.jpg",
            "top.txt",
        ] {
            let ov = outgoing(host.table, b"x");
            host.write_data(Resource::new_own(crep), name.into(), ov)
                .await
                .unwrap();
        }
        // A SECOND container whose keys must NEVER surface via the first's list.
        let o = host.create_container("other".into()).await.unwrap();
        let orep = o.rep();
        let ov = outgoing(host.table, b"x");
        host.write_data(Resource::new_own(orep), "der/shaA/0.jpg".into(), ov)
            .await
            .unwrap();

        // Prefix filter: only shaA's two derivatives, container-relative, nested-inclusive.
        let page = host
            .list_page("assets".into(), Some("der/shaA/".into()), None, 100)
            .await
            .unwrap();
        let mut names = page.names.clone();
        names.sort();
        assert_eq!(
            names,
            vec!["der/shaA/0.jpg".to_string(), "der/shaA/1.jpg".to_string()]
        );
        assert!(
            page.cursor.is_none(),
            "a small result is exhausted in one page"
        );
        assert!(
            !page
                .names
                .iter()
                .any(|n| n.contains("hblob/") || n.contains("other")),
            "no internal prefix / other container leaks"
        );

        // Bounded page + resume: limit 1 over the whole container walks all 4 real keys across pages,
        // the marker is hidden, no duplicates/omissions.
        let mut seen = Vec::new();
        let mut after: Option<String> = None;
        for _ in 0..64 {
            let p = host
                .list_page("assets".into(), None, after.clone(), 1)
                .await
                .unwrap();
            assert!(p.names.len() <= 1, "limit honored");
            seen.extend(p.names);
            match p.cursor {
                Some(cur) => after = Some(cur),
                None => break,
            }
        }
        seen.sort();
        assert_eq!(
            seen,
            vec![
                "der/shaA/0.jpg".to_string(),
                "der/shaA/1.jpg".to_string(),
                "der/shaB/0.jpg".to_string(),
                "top.txt".to_string(),
            ]
        );
        assert!(
            !seen.iter().any(|n| n == MARKER),
            "the marker is never listed"
        );
    }

    /// ANTI-HOLLOW GATE — the `blob-list` confinement (JOIN the guest prefix UNDER the container
    /// prefix; STRIP it back off every returned key; DROP the marker; DROP any foreign key) is
    /// load-bearing. Mutation-verified: each `BOATRAMP_BLOBLIST_MUTATION` turns the relevant assertion
    /// RED (`escape_prefix` → the join escapes the container; `no_strip` → a raw internal/foreign key
    /// leaks; `show_marker` → the marker leaks). Marker `BLOB LIST PREFIX-CONFINEMENT OK`.
    #[test]
    fn blob_list_prefix_confinement_gate() {
        let cp = "hblob/site-a/assets/";
        // JOIN: a guest prefix is always confined UNDER the container prefix.
        assert_eq!(
            join_list_prefix(cp, "der/abc/"),
            "hblob/site-a/assets/der/abc/"
        );
        assert!(
            join_list_prefix(cp, "der/abc/").starts_with(cp),
            "a guest list prefix must never escape the container prefix"
        );
        // CONFINE: container-relative, nested-inclusive, the WHOLE reserved `.boatramp*` namespace
        // hidden (the marker AND host-internal multipart staging), a foreign key dropped.
        let metas = vec![
            meta("hblob/site-a/assets/der/abc/0.jpg", 1),
            meta("hblob/site-a/assets/.boatramp-container", 0),
            // Host-internal S3-ingress multipart staging under the guest's OWN container — nested, so
            // only the whole-namespace fence (not an exact-marker check) keeps it hidden.
            meta("hblob/site-a/assets/.boatramp-uploads/u-7/part-00000003", 1),
            meta("hblob/site-b/assets/secret.jpg", 1), // another site — must never surface
        ];
        let names = confine_list_names(cp, metas);
        assert_eq!(
            names,
            vec!["der/abc/0.jpg".to_string()],
            "names must be container-relative, nested-inclusive, reserved-namespace-hidden, foreign-dropped"
        );
        assert!(
            !names
                .iter()
                .any(|n| n.contains("hblob/") || n.contains(".boatramp")),
            "a raw internal key prefix or the reserved .boatramp* namespace must never reach the guest"
        );
        println!("BLOB LIST PREFIX-CONFINEMENT OK");
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
        assert!(
            !host
                .has_object(Resource::new_own(crep), "o".into())
                .await
                .unwrap()
        );
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
        assert!(
            storage
                .map
                .lock()
                .unwrap()
                .get("hblob/site-a/src/f")
                .is_none()
        );
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

    /// GATE (v0.7.4, blob-read-404 diagnosability) — a backend/permission fault must NOT be masked as
    /// a genuine NotFound, and its raw SDK text must NOT reach the guest. Mutation-verified: reverting
    /// `blob_err` to the old `err.to_string()` mask makes the coarse-category assertion (and the
    /// no-leak assertion) fail; coarsening NotFound too makes the 404-preservation assertion fail.
    #[test]
    fn blob_err_masks_a_backend_fault_but_preserves_notfound() {
        // A genuine NotFound keeps its message so a guest can still map it to a 404.
        let key = "hblob/acme/site/deadbeef";
        let nf = blob_err("get", key, StorageError::NotFound(key.to_string()));
        assert!(
            nf.contains("object not found"),
            "NotFound must stay distinguishable (guest → 404), got: {nf}"
        );
        // A backend fault (a 403 AccessDenied carrying signing/endpoint/key metadata) collapses to a
        // FIXED coarse category — the guest gets a fault signal (→ 5xx), never the raw SDK string.
        let raw = "AccessDenied: SigV4 for key AKIAEXAMPLE at s3.example.com";
        let be = blob_err("get", key, StorageError::Backend(raw.to_string()));
        assert_eq!(
            be, "blob backend unavailable",
            "a backend fault must be a fixed coarse category, not the raw error"
        );
        assert!(
            !be.contains("AccessDenied") && !be.contains("AKIA") && !be.contains("s3.example"),
            "the raw object-store/SDK error must NEVER reach the guest: {be}"
        );
        // A transport (Io) fault is likewise coarse, not a NotFound.
        let io = blob_err("get", key, StorageError::Io(std::io::Error::other("boom")));
        assert_eq!(io, "blob backend unavailable");
        assert!(
            !io.contains("boom"),
            "transport detail stays host-side: {io}"
        );
    }

    /// A tenant-confined binding: `prefix` + host-resolved own `tenant` + `blobstore_containers`
    /// allowlist + the multi-tenant fact.
    fn confined(
        storage: Arc<dyn Storage>,
        prefix: &str,
        tenant: Option<&str>,
        containers: &[&str],
        multi_tenant: bool,
    ) -> BlobBinding {
        BlobBinding {
            storage,
            prefix: prefix.to_string(),
            max_bytes: 0,
            tenant: tenant.map(str::to_string),
            containers: containers.iter().map(|s| (*s).to_string()).collect(),
            multi_tenant,
        }
    }

    /// A declared `["assets-{tenant}"]` allowlist confines the guest to its OWN tenant's container:
    /// `assets-<own>` opens, `assets-<other>` is refused with the DISTINCT allowlist-miss message —
    /// on every container op (create/get/exists/delete), and `container_exists` returns `Err` (never
    /// a silent `Ok(false)` existence oracle).
    #[tokio::test]
    async fn allowlist_confines_to_own_tenant_container() {
        let storage = Arc::new(MemStorage::default());
        let bind = confined(
            storage.clone(),
            "hblob/shop/",
            Some("firm-a"),
            &["assets-{tenant}"],
            true,
        );
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        // Own tenant's container: allowed and stored under the expected key.
        assert!(host.create_container("assets-firm-a".into()).await.is_ok());
        assert!(
            storage
                .map
                .lock()
                .unwrap()
                .contains_key("hblob/shop/assets-firm-a/.boatramp-container")
        );

        // Another tenant's container: refused with the distinct allowlist-miss category, on every op.
        let err = host
            .create_container("assets-firm-b".into())
            .await
            .unwrap_err();
        assert!(
            err.contains("not permitted by this component's blobstore_containers allowlist"),
            "{err}"
        );
        assert!(host.get_container("assets-firm-b".into()).await.is_err());
        assert!(host.delete_container("assets-firm-b".into()).await.is_err());
        // No existence oracle: a forbidden container is `Err`, not `Ok(false)`.
        let exists = host.container_exists("assets-firm-b".into()).await;
        assert!(
            exists.is_err() && exists.unwrap_err().contains("not permitted"),
            "container_exists on a forbidden container must Err, not Ok(false)"
        );
    }

    /// A `{tenant}` entry with NO resolved own tenant (an `all`/anon/target/unscoped invocation) fails
    /// closed with the DISTINCT no-resolved-tenant category — never a silent allow.
    #[tokio::test]
    async fn tenant_template_without_resolved_tenant_fails_closed() {
        let storage = Arc::new(MemStorage::default());
        let bind = confined(
            storage.clone(),
            "hblob/shop/",
            None,
            &["assets-{tenant}"],
            true,
        );
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        let err = host
            .create_container("assets-firm-a".into())
            .await
            .unwrap_err();
        assert!(err.contains("no resolved tenant"), "{err}");
    }

    /// A plain (non-`{tenant}`) allowlist entry names a site-shared container the operator opts into;
    /// a container outside the allowlist is still refused.
    #[tokio::test]
    async fn plain_allowlisted_container_is_shared() {
        let storage = Arc::new(MemStorage::default());
        let bind = confined(
            storage.clone(),
            "hblob/shop/",
            Some("firm-a"),
            &["assets-{tenant}", "shared"],
            true,
        );
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        assert!(host.create_container("shared".into()).await.is_ok());
        assert!(host.create_container("other".into()).await.is_err());
    }

    /// A multi-tenant site that declares NO allowlist denies every container op (fail-closed), with
    /// the DISTINCT deny-default message naming the remedy.
    #[tokio::test]
    async fn multi_tenant_without_allowlist_denies() {
        let storage = Arc::new(MemStorage::default());
        let bind = confined(storage.clone(), "hblob/shop/", Some("firm-a"), &[], true);
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        let err = host.create_container("anything".into()).await.unwrap_err();
        assert!(err.contains("declares no blobstore_containers"), "{err}");
    }

    /// A single-tenant / dev site (no tenancy declared) with no allowlist stays permissive — today's
    /// behavior, non-breaking. This is ALSO the `multi_tenant = false` path that an explicit
    /// `Tenancy::Disabled` derives upstream (Security MEDIUM-1): a Disabled blob guest must be
    /// permissive here, never caught by the multi-tenant deny-default.
    #[tokio::test]
    async fn single_tenant_without_allowlist_is_permissive() {
        let storage = Arc::new(MemStorage::default());
        let bind = confined(storage.clone(), "hblob/shop/", None, &[], false);
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        assert!(host.create_container("anything".into()).await.is_ok());
    }

    /// Defense-in-depth: a traversal / reserved object name is refused (a distinct request error, not
    /// routed through `blob_err`), covering both the `object_key` ops and the inline copy/move keys.
    #[tokio::test]
    async fn object_name_validation_rejects_traversal_and_reserved() {
        let storage = Arc::new(MemStorage::default());
        let bind = confined(storage.clone(), "hblob/shop/", None, &[], false);
        let mut table = ResourceTable::new();
        let mut host = BlobHost::new(&mut table, Some(&bind));

        let c = host.create_container("c".into()).await.unwrap();
        let crep = c.rep();
        let ov = outgoing(host.table, b"x");
        let err = host
            .write_data(Resource::new_own(crep), "../escape".into(), ov)
            .await
            .unwrap_err();
        assert!(err.contains("invalid object name"), "{err}");
        // A copy whose destination key is a reserved marker collision is refused at the dest endpoint.
        let err = host
            .copy_object(
                ObjectId {
                    container: "c".into(),
                    object: "ok".into(),
                },
                ObjectId {
                    container: "c".into(),
                    object: ".boatramp-container".into(),
                },
            )
            .await
            .unwrap_err();
        assert!(err.contains("invalid object name"), "{err}");
    }

    /// **v0.8.0 mutation-verified blob tenant-confinement gate** (marker `BLOB TENANT-CONFINEMENT
    /// OK`). Drives the REAL `BlobHost::container_prefix` choke point and asserts every confinement
    /// invariant end to end — the load-bearing one being that a cross-tenant container op (the
    /// pre-fix cross-tenant read/DESTROY hole) is REFUSED. Anti-hollow (the #503 convention): each
    /// assertion's SECURE expectation is the default and a clean run passes + prints the marker; the
    /// CI job re-runs the gate under each `BOATRAMP_BLOBCONFINE_MUTATION`, which FLIPS exactly one
    /// expectation to the INSECURE outcome, so the real (secure) code then violates that flipped
    /// expectation and the gate FAILS — proving the assertion is load-bearing, never hollow.
    /// Production code carries NO mutation seam; the mutation lives only in this test's expectations.
    /// - `cross_tenant_open` — expect a cross-tenant `assets-<other>` op (create/get/delete/exists/
    ///   copy-dest/move-dest) to SUCCEED (models the pre-fix site-scoped hole) → the real allowlist
    ///   refusal fails it.
    /// - `no_tenant_expands` — expect a `{tenant}` entry with no resolved own tenant to open → the
    ///   real NoResolvedTenant fail-closed fails it.
    /// - `multitenant_open` — expect a multi-tenant binding with NO allowlist to allow any container
    ///   → the real deny-default fails it.
    /// - `disabled_denied` — expect a single-tenant (Disabled/dev) binding with no allowlist to be
    ///   DENIED → the real permissive path fails it (MEDIUM-1: Disabled must stay permissive).
    /// - `shared_denied` — expect a plain (non-`{tenant}`) allowlisted `shared` container to be
    ///   refused → the real operator-opt-in allow fails it.
    /// - `traversal_allowed` — expect a `../escape` object name to be accepted → the real
    ///   `validate_object_key` refusal fails it.
    #[tokio::test]
    async fn blob_tenant_confinement_gate() {
        let mutation = std::env::var("BOATRAMP_BLOBCONFINE_MUTATION").unwrap_or_default();
        let m = |name: &str| mutation == name;

        // (1) `{tenant}`-confined, multi-tenant: own opens; cross-tenant is refused on EVERY op.
        {
            let storage = Arc::new(MemStorage::default());
            let bind = confined(
                storage.clone(),
                "hblob/shop/",
                Some("firm-a"),
                &["assets-{tenant}"],
                true,
            );
            let mut table = ResourceTable::new();
            let mut host = BlobHost::new(&mut table, Some(&bind));
            // The legitimate own-tenant path must ALWAYS hold (no mutation may break it).
            assert!(
                host.create_container("assets-firm-a".into()).await.is_ok(),
                "own-tenant container must open"
            );
            let expect_ok = m("cross_tenant_open");
            let cross: Vec<Result<(), String>> = vec![
                host.create_container("assets-firm-b".into())
                    .await
                    .map(|_| ()),
                host.get_container("assets-firm-b".into()).await.map(|_| ()),
                host.delete_container("assets-firm-b".into()).await,
                host.container_exists("assets-firm-b".into())
                    .await
                    .map(|_| ()),
                // copy/move with a cross-tenant DEST endpoint (own src, other-tenant dest):
                host.copy_object(
                    ObjectId {
                        container: "assets-firm-a".into(),
                        object: "k".into(),
                    },
                    ObjectId {
                        container: "assets-firm-b".into(),
                        object: "k".into(),
                    },
                )
                .await,
                host.move_object(
                    ObjectId {
                        container: "assets-firm-a".into(),
                        object: "k".into(),
                    },
                    ObjectId {
                        container: "assets-firm-b".into(),
                        object: "k".into(),
                    },
                )
                .await,
            ];
            for res in cross {
                if expect_ok {
                    assert!(
                        res.is_ok(),
                        "MUTATION cross_tenant_open: a cross-tenant blob op was expected to succeed, \
                         but the real allowlist refused it — the cross-tenant read/destroy refusal is \
                         load-bearing"
                    );
                } else {
                    assert!(res.is_err(), "a cross-tenant container op MUST be refused");
                }
            }
        }

        // (2) A `{tenant}` entry with no resolved own tenant fails closed.
        {
            let storage = Arc::new(MemStorage::default());
            let bind = confined(storage, "hblob/shop/", None, &["assets-{tenant}"], true);
            let mut table = ResourceTable::new();
            let mut host = BlobHost::new(&mut table, Some(&bind));
            let res = host.create_container("assets-firm-a".into()).await;
            if m("no_tenant_expands") {
                assert!(
                    res.is_ok(),
                    "MUTATION no_tenant_expands: a {{tenant}} entry with no resolved tenant was \
                     expected to expand/open, but the real code fails closed"
                );
            } else {
                assert!(
                    res.is_err(),
                    "a {{tenant}} entry with no resolved own tenant MUST fail closed"
                );
            }
        }

        // (3) Multi-tenant + no allowlist ⇒ deny-by-default.
        {
            let storage = Arc::new(MemStorage::default());
            let bind = confined(storage, "hblob/shop/", Some("firm-a"), &[], true);
            let mut table = ResourceTable::new();
            let mut host = BlobHost::new(&mut table, Some(&bind));
            let res = host.create_container("anything".into()).await;
            if m("multitenant_open") {
                assert!(
                    res.is_ok(),
                    "MUTATION multitenant_open: a multi-tenant binding with no allowlist was expected \
                     to allow, but the real deny-default refused it"
                );
            } else {
                assert!(
                    res.is_err(),
                    "a multi-tenant binding with no allowlist MUST deny by default"
                );
            }
        }

        // (4) Single-tenant / dev (also the `Tenancy::Disabled` shape, MEDIUM-1) + no allowlist ⇒
        // permissive; a mutation that treats it as multi-tenant would deny.
        {
            let storage = Arc::new(MemStorage::default());
            let bind = confined(storage, "hblob/shop/", None, &[], false);
            let mut table = ResourceTable::new();
            let mut host = BlobHost::new(&mut table, Some(&bind));
            let res = host.create_container("anything".into()).await;
            if m("disabled_denied") {
                assert!(
                    res.is_err(),
                    "MUTATION disabled_denied: a single-tenant/Disabled binding was expected to be \
                     denied, but the real code (correctly) stays permissive"
                );
            } else {
                assert!(
                    res.is_ok(),
                    "a single-tenant/Disabled binding with no allowlist MUST stay permissive"
                );
            }
        }

        // (5) A plain (non-`{tenant}`) allowlisted container is an operator-opt-in shared container;
        // a container outside the allowlist is still refused.
        {
            let storage = Arc::new(MemStorage::default());
            let bind = confined(
                storage,
                "hblob/shop/",
                Some("firm-a"),
                &["assets-{tenant}", "shared"],
                true,
            );
            let mut table = ResourceTable::new();
            let mut host = BlobHost::new(&mut table, Some(&bind));
            assert!(
                host.create_container("other".into()).await.is_err(),
                "a container outside the allowlist MUST be refused"
            );
            let res = host.create_container("shared".into()).await;
            if m("shared_denied") {
                assert!(
                    res.is_err(),
                    "MUTATION shared_denied: an operator-opted-in `shared` container was expected to \
                     be refused, but the real code (correctly) allows it"
                );
            } else {
                assert!(
                    res.is_ok(),
                    "a plain allowlisted `shared` container MUST be allowed (operator opt-in)"
                );
            }
        }

        // (6) Object-name validation refuses a traversal name even on the permissive path.
        {
            let storage = Arc::new(MemStorage::default());
            let bind = confined(storage, "hblob/shop/", None, &[], false);
            let mut table = ResourceTable::new();
            let mut host = BlobHost::new(&mut table, Some(&bind));
            let c = host.create_container("c".into()).await.unwrap();
            let crep = c.rep();
            let ov = outgoing(host.table, b"x");
            let res = host
                .write_data(Resource::new_own(crep), "../escape".into(), ov)
                .await;
            if m("traversal_allowed") {
                assert!(
                    res.is_ok(),
                    "MUTATION traversal_allowed: a `../escape` object name was expected to be \
                     accepted, but the real validate_object_key refused it"
                );
            } else {
                assert!(
                    res.is_err(),
                    "a `../escape` object name MUST be refused by validate_object_key"
                );
            }
        }

        println!(
            "BLOB TENANT-CONFINEMENT OK: container_prefix confines every container op to the \
             invocation's resolved own tenant (cross-tenant refused; {{tenant}} fail-closed; \
             multi-tenant deny-default; single-tenant permissive; object-name traversal refused)"
        );
    }
}
