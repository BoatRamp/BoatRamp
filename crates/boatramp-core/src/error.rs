//! Error types shared across storage backends, the KV layer, and deploys.

// Config parsing/compiling errors live in the shared `boatramp-types` crate;
// re-exported so `boatramp_core::error::ConfigError` is unchanged.
pub use boatramp_types::error::ConfigError;

/// Errors that can occur while interacting with a [`crate::Storage`] backend.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The requested key does not exist.
    #[error("object not found: {0}")]
    NotFound(String),

    /// The key was rejected (e.g. a path-traversal attempt).
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// The backend does not support this operation yet.
    #[error("unsupported operation: {0}")]
    Unsupported(String),

    /// An underlying I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A backend-specific error.
    #[error("backend error: {0}")]
    Backend(String),

    /// A backend READ fault (get/get_range/head) carrying the concrete outcome: the HTTP `status`,
    /// the backend error `code` (e.g. `AccessDenied`, `SlowDown`, `InvalidRange`), and the
    /// `request_id` — so an operator can tell a real 404 from a 403/throttle/5xx/transport fault, and
    /// a host caller could branch (retry a throttle, alert on a 403). The backend already emitted the
    /// structured WARN (with latency); the guest-facing layer collapses this to a coarse, non-leaking
    /// reason — the `status`/`code`/`request_id` never reach the guest. `reason` is operator-level
    /// backend text (no object bytes, no credential).
    #[error(
        "backend read fault ({reason}; status={status:?} code={code:?} request_id={request_id:?})"
    )]
    BackendRead {
        reason: String,
        status: Option<u16>,
        code: Option<String>,
        request_id: Option<String>,
    },
}

impl StorageError {
    /// Convenience constructor for [`StorageError::Unsupported`].
    pub fn unsupported(msg: impl Into<String>) -> Self {
        Self::Unsupported(msg.into())
    }

    /// Convenience constructor for [`StorageError::Backend`].
    pub fn backend(msg: impl Into<String>) -> Self {
        Self::Backend(msg.into())
    }
}

/// Errors from a [`crate::kv::KvStore`] backend.
#[derive(Debug, thiserror::Error)]
pub enum KvError {
    /// An underlying I/O error.
    #[error("kv i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// A backend-specific error.
    #[error("kv backend error: {0}")]
    Backend(String),
}

impl KvError {
    /// Convenience constructor for [`KvError::Backend`].
    pub fn backend(msg: impl Into<String>) -> Self {
        Self::Backend(msg.into())
    }
}

/// Errors from the content-addressed deploy layer ([`crate::deploy`]).
#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    /// A blob-storage error.
    #[error(transparent)]
    Storage(#[from] StorageError),

    /// A KV (manifest/pointer) error.
    #[error(transparent)]
    Kv(#[from] KvError),

    /// (De)serialization of a manifest failed.
    #[error("manifest serialization error: {0}")]
    Serde(String),

    /// A referenced deployment, site, or path was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// An uploaded blob did not hash to the key it was stored under.
    #[error("blob hash mismatch: expected {expected}, got {actual}")]
    HashMismatch {
        /// The hash the blob was supposed to have.
        expected: String,
        /// The hash actually computed from the bytes.
        actual: String,
    },

    /// A deployment cannot be activated because some blobs are missing.
    #[error("deployment incomplete: {} blob(s) still missing", .0.len())]
    Incomplete(Vec<String>),

    /// A deployment-id prefix matched more than one deployment.
    #[error("ambiguous deployment id prefix: {0}")]
    Ambiguous(String),

    /// A host is already claimed by a different site — refusing to overwrite the
    /// routing index would let one site hijack another's domain. Surfaced as a
    /// `409 Conflict`.
    #[error("conflict: {0}")]
    Conflict(String),

    /// A submitted config failed a content-validation check before storage (e.g. a project
    /// tenancy schema with an empty public predicate that would defeat the target-read
    /// confinement). Surfaced as a `400 Bad Request` — the write is refused, not stored.
    #[error("invalid config: {0}")]
    Invalid(String),

    /// A destructive GC prune was requested against a blob backend that does not allow
    /// pruning ([`crate::Storage::allows_prune`] is `false`) — a read-fallback composite
    /// (`FallbackStorage`) is attached, whose union `list` over a primary-only `delete`
    /// would report a secondary-only orphan reclaimed while a read resurrects it. The
    /// prune is refused entirely (nothing deleted); a non-pruning drift/report pass is
    /// unaffected. Drain-then-drop is the doctrine (see the message).
    #[error(
        "GC prune refused: a read-fallback secondary blob backend is attached \
         ([serve].blob_fallback); its union list over a primary-only delete would report a \
         secondary-only orphan reclaimed while a read resurrects it. Drain with \
         `boatramp blob migrate`, remove [serve].blob_fallback, restart the node, then GC."
    )]
    PruneUnsafeWithFallback,
}

impl From<serde_json::Error> for DeployError {
    fn from(err: serde_json::Error) -> Self {
        Self::Serde(err.to_string())
    }
}

impl From<ConfigError> for DeployError {
    fn from(err: ConfigError) -> Self {
        Self::Serde(err.to_string())
    }
}
