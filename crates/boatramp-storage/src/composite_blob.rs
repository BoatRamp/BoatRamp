//! Per-project blob-backend overlay — a configured `project → backend` map over a global default.
//!
//! Mirrors `CompositeSqlBackends` (the handler `sql` binding's per-name backend overlay): built ONCE
//! at serve wiring, its map values are fully-built, decorator-wrapped backends (MarkerHeadCache + the
//! opt-in `HedgedStorage`, exactly like the global one). An unconfigured project — and the reserved
//! `default` project — resolve the global default, so an all-global deployment is byte-for-byte
//! unchanged. A guest cannot reach another project's backend: the resolver is keyed by the serve's
//! host-resolved project, and a missing entry falls to the GLOBAL default, never to another project.

use boatramp_core::Storage;
use boatramp_core::blob_backends::BlobBackends;
use boatramp_core::project::ProjectRef;
use std::collections::HashMap;
use std::sync::Arc;

/// A `project → backend` overlay over a global default backend.
pub struct CompositeBlobBackends {
    default: Arc<dyn Storage>,
    per_project: HashMap<String, Arc<dyn Storage>>,
}

impl CompositeBlobBackends {
    /// `default` is the node-wide backend (used for the reserved `default` project, any unconfigured
    /// project, and node-internal paths). `per_project` maps a (validated, non-default) project name to
    /// its own fully-built backend.
    pub fn new(default: Arc<dyn Storage>, per_project: HashMap<String, Arc<dyn Storage>>) -> Self {
        Self {
            default,
            per_project,
        }
    }
}

impl BlobBackends for CompositeBlobBackends {
    fn backend(&self, project: ProjectRef<'_>) -> Arc<dyn Storage> {
        // GATE MUTATION SEAM (PLAN-per-project-blob-backend isolation gate): force the resolver to
        // ignore the per-project map and hand EVERY project the GLOBAL default — the exact "resolve the
        // wrong/global backend for a project that declared its own" regression the cross-project
        // isolation gate must catch. Compiled OUT of every shipped build (feature off by default); the
        // gate turns it on and re-runs the isolation test, which MUST then go RED (a pass-under-mutation
        // is a hollow gate). Placed FIRST so it defeats the real resolution below.
        #[cfg(feature = "blob-perproject-gate-mutation")]
        if std::env::var("BOATRAMP_BLOB_PERPROJECT_MUTATION").is_ok_and(|v| !v.is_empty()) {
            return Arc::clone(&self.default);
        }
        // A configured non-default project gets its own backend; everything else (the reserved
        // `default` project, any unconfigured project) gets the GLOBAL default — never another
        // project's backend, so a missing/misspelled entry can only fall CLOSED to the shared default,
        // not leak across a project boundary.
        self.per_project
            .get(project.as_str())
            .cloned()
            .unwrap_or_else(|| Arc::clone(&self.default))
    }

    fn default_backend(&self) -> Arc<dyn Storage> {
        Arc::clone(&self.default)
    }
}

#[cfg(all(test, feature = "fs"))]
mod tests {
    use super::*;
    use crate::fs::FsStorage;

    #[test]
    fn resolves_per_project_override_else_global_default() {
        let tmp = tempfile::tempdir().unwrap();
        let global: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("global")));
        let acme: Arc<dyn Storage> = Arc::new(FsStorage::new(tmp.path().join("acme")));
        let mut map: HashMap<String, Arc<dyn Storage>> = HashMap::new();
        map.insert("acme".to_string(), Arc::clone(&acme));
        let be = CompositeBlobBackends::new(Arc::clone(&global), map);

        // A configured project resolves ITS OWN backend.
        assert!(Arc::ptr_eq(&be.backend(ProjectRef::new("acme")), &acme));
        // An UNCONFIGURED project resolves the GLOBAL default — crucially NOT another project's
        // backend (no cross-project leak via a missing/misspelled key).
        assert!(Arc::ptr_eq(&be.backend(ProjectRef::new("other")), &global));
        assert!(!Arc::ptr_eq(&be.backend(ProjectRef::new("other")), &acme));
        // The reserved `default` project resolves the global default.
        assert!(Arc::ptr_eq(&be.backend(ProjectRef::DEFAULT), &global));
        // `default_backend()` is the global.
        assert!(Arc::ptr_eq(&be.default_backend(), &global));
    }
}
