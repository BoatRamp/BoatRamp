//! Per-project blob-backend resolution seam.
//!
//! The handler `blobstore` binding historically bound ONE global [`Storage`] backend (one bucket /
//! endpoint / credential for the whole node); projects were isolated only by key-prefix confinement
//! (`container_access` + the confined object key). This trait lets the host resolve a DIFFERENT backend
//! per project — the "base URI configurable per project" request — mirroring how
//! [`SqlBackends`](crate::sql::SqlBackends) resolves a per-(project,site) database.
//!
//! Security contract (see `PLAN-per-project-blob-backend.md`):
//! - The `project` passed here is the SERVE's host-resolved project, never guest input — a guest can
//!   never name another project's backend.
//! - Backend selection is isolation-IN-DEPTH: the key-prefix confinement (`container_access`) still
//!   runs on top of whatever backend resolves. A separate per-project bucket adds PHYSICAL isolation;
//!   it does not replace the confinement.
//! - Resolution is infallible here because backends are built (and their sealed credentials resolved)
//!   at serve WIRING — a backend that cannot be built is rejected there (fail-closed), never surfaced
//!   as a silent fallback to a different project's or the global backend.

use crate::Storage;
use crate::project::ProjectRef;
use std::sync::Arc;

/// Resolve the blob [`Storage`] backend for a project.
pub trait BlobBackends: Send + Sync {
    /// The backend for `project`. The reserved `default` project, or any project with no configured
    /// override, resolves [`default_backend`](Self::default_backend) — so an all-global deployment is
    /// byte-for-byte unchanged.
    fn backend(&self, project: ProjectRef<'_>) -> Arc<dyn Storage>;

    /// The global default backend (the historical single node-wide backend). Used for the reserved
    /// `default` project, any unconfigured project, and node-internal (non-project) blob paths.
    fn default_backend(&self) -> Arc<dyn Storage>;
}

/// The trivial resolver: every project resolves the one global backend — the pre-per-project behavior,
/// so wiring that has not opted into per-project backends keeps exactly one backend + one credential.
pub struct GlobalBlobBackend(Arc<dyn Storage>);

impl GlobalBlobBackend {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self(storage)
    }
}

impl BlobBackends for GlobalBlobBackend {
    fn backend(&self, _project: ProjectRef<'_>) -> Arc<dyn Storage> {
        Arc::clone(&self.0)
    }

    fn default_backend(&self) -> Arc<dyn Storage> {
        Arc::clone(&self.0)
    }
}
