//! Substrate-complete default-scope readiness (v0.31.0 Finding 8).
//!
//! The KV re-home + the serve version-guard that `boatramp_core::migrate` owns are KV-only. A
//! default project's data also lives in BLOB (`hblob/`, `mqp/`, `mqgp/`) and LIBSQL (`{dir}/{site}.db`),
//! which the KV version cannot observe — so a blob-only or SQL-only default project could pass the KV
//! guard as `Ready` while its data strands (HIGH-1/2/3 of the security review). These node-level
//! detectors make the re-home observable across those substrates so the serve guard and
//! `boatramp migrate --finalize` can refuse/warn/sequence until ALL substrates are re-homed.
//!
//! The critical asymmetry: BLOB has a runtime read-fallback during the KV dual soak (a cold object is
//! bridged), so an outstanding blob is a WARN while the soak is live. LIBSQL has **no** runtime
//! fallback — `database("default", site)` would open the non-existent `{dir}/default/{site}.db` and
//! auto-create an EMPTY database — so an un-re-homed default libsql database is a hard **REFUSE**.

use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;

use boatramp_core::project::DEFAULT_PROJECT;
use boatramp_core::{Storage, StorageError};

/// The guest-blob data families the default-scope re-home covers (mirrors
/// [`crate::blobs::DEFAULT_SCOPE_BLOB_FAMILIES`]).
const BLOB_FAMILIES: &[&str] = &["hblob/", "mqp/", "mqgp/"];

/// Control-plane KV marker set by `boatramp blob rehome --finalize` once the blob substrate is
/// verified retired (no bare default-scoped object remains), and REQUIRED by `boatramp migrate
/// --finalize` before it clears the KV dual soak (which disengages the runtime blob read-fallback).
/// The explicit "I retired the blob substrate" signal — set by the command that holds the blob
/// backend (and resolves its credentials), read by the KV finalize that does not. A node with no
/// blob data still sets it by running `blob rehome --finalize` once (a 0-object no-op).
pub const BLOB_RETIRED_MARKER: &str = "schema/default-scope-blob-retired";

/// Un-re-homed default-project **libsql** identities still at the bare (pre-`default/`) on-disk
/// layout under `libsql_dir`. A default site's data moves from `{dir}/{site}.db` (and named DBs from
/// `{dir}/{site}/{name}.db`, functions from `{dir}/fn/{name}.db`) to under `{dir}/default/…`; so:
///
/// - a top-level `*.db` FILE is a default site's default DB, un-re-homed;
/// - a top-level SUBDIR whose name is neither the reserved `default` (already re-homed) nor a KNOWN
///   project (`projects`, that project's own DBs) holds a default site/function's named/preview DBs,
///   un-re-homed.
///
/// Empty ⇒ nothing bare (re-homed, or no libsql dir). Returned identities are human strings for the
/// refusal message. This is why the serve guard must REFUSE (not just warn) on a non-empty result:
/// libsql has no runtime fallback, so serving would boot a default-project SQL workload onto an
/// empty database.
pub fn libsql_bare_default_idents(libsql_dir: &Path, projects: &HashSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(libsql_dir) else {
        return out; // no libsql dir ⇒ nothing bare
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(ft) = entry.file_type() else { continue };
        if ft.is_file() {
            // `{site}.db` (the `-wal`/`-shm` sidecars end in `.db-wal`/`.db-shm`, not `.db`).
            if let Some(site) = name.strip_suffix(".db")
                && !site.is_empty()
            {
                out.push(format!("site `{site}` ({})", entry.path().display()));
            }
        } else if ft.is_dir() && name != DEFAULT_PROJECT && !projects.contains(&name) {
            // A default site/function subdir (named/preview DBs). A known project's subdir and the
            // re-homed `default/` subdir are left alone.
            out.push(format!(
                "`{name}/` named/preview databases ({})",
                entry.path().display()
            ));
        }
    }
    out.sort();
    out
}

/// Whether any BARE default-scoped blob object remains under `hblob/`/`mqp/`/`mqgp/` on `storage` —
/// i.e. a key whose scope segment is neither the reserved `default` (already re-homed) nor a KNOWN
/// project (`projects`, that project's own object). Short-circuits on the first such key. Used by
/// `boatramp migrate --finalize` to REFUSE clearing the KV dual soak (which disengages the runtime
/// blob read-fallback) until the blob substrate is drained — otherwise a cold default object would
/// 404 after finalize.
pub async fn blob_default_outstanding(
    storage: &Arc<dyn Storage>,
    projects: &HashSet<String>,
) -> Result<bool, StorageError> {
    for family in BLOB_FAMILIES {
        for meta in storage.list(family).await? {
            let Some(rest) = meta.key.strip_prefix(family) else {
                continue;
            };
            let seg = rest.split('/').next().unwrap_or("");
            if !seg.is_empty() && seg != DEFAULT_PROJECT && !projects.contains(seg) {
                return Ok(true); // a bare default-scoped object remains
            }
        }
    }
    Ok(false)
}

/// Read the `projectmeta/` project-name set (including the reserved `default`) from the control-plane
/// KV — the set both detectors use to tell a bare default scope from a named project.
pub async fn known_projects(
    kv: &dyn boatramp_core::kv::KvStore,
) -> Result<HashSet<String>, boatramp_core::error::KvError> {
    let mut set = HashSet::new();
    for key in kv
        .list_prefix(boatramp_core::project::POINTER_PREFIX)
        .await?
    {
        if let Some(name) = key.strip_prefix(boatramp_core::project::POINTER_PREFIX)
            && !name.is_empty()
            && !name.contains('/')
        {
            set.insert(name.to_string());
        }
    }
    Ok(set)
}

/// The libsql data directory for a node config's `handlers.bindings.sql` (single-node), mirroring
/// `handlers::build_sql_backends`: `handlers.bindings.sql.dir`, else `{data_dir}/handlers-sql`. Only
/// meaningful for a LOCAL (non-`url`) libsql binding — a remote sqld has no local directory.
pub fn libsql_dir_for(
    config: &crate::config::ServerConfig,
    data_dir: &Path,
) -> Option<std::path::PathBuf> {
    let sql = config
        .handlers
        .as_ref()
        .and_then(|h| h.bindings.sql.as_ref());
    // A remote sqld binding has no local directory to scan.
    if sql.and_then(|c| c.url.as_ref()).is_some() {
        return None;
    }
    Some(
        sql.and_then(|c| c.dir.clone())
            .unwrap_or_else(|| data_dir.join("handlers-sql")),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libsql_detector_flags_bare_default_and_skips_rehomed_and_projects() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path();
        // Bare default site default DB (+ sidecar, which must be ignored).
        std::fs::write(dir.join("blog.db"), b"x").unwrap();
        std::fs::write(dir.join("blog.db-wal"), b"x").unwrap();
        // A default function's named-DB subdir (fn/ is neither default nor a project).
        std::fs::create_dir_all(dir.join("fn")).unwrap();
        std::fs::write(dir.join("fn").join("resize.db"), b"x").unwrap();
        // Already re-homed (default/) — must be skipped.
        std::fs::create_dir_all(dir.join("default")).unwrap();
        std::fs::write(dir.join("default").join("shop.db"), b"x").unwrap();
        // A named project's subdir — must be skipped.
        std::fs::create_dir_all(dir.join("acme")).unwrap();
        std::fs::write(dir.join("acme").join("blog.db"), b"x").unwrap();

        let projects: HashSet<String> = ["default", "acme"].iter().map(|s| s.to_string()).collect();
        let bare = libsql_bare_default_idents(dir, &projects);
        // Flags the bare `blog.db` + the `fn/` subdir; skips `default/` and `acme/`.
        assert_eq!(bare.len(), 2, "got {bare:?}");
        assert!(bare.iter().any(|s| s.contains("site `blog`")));
        assert!(bare.iter().any(|s| s.contains("`fn/`")));
        assert!(!bare.iter().any(|s| s.contains("acme")));
        assert!(!bare.iter().any(|s| s.contains("shop")));
    }

    #[test]
    fn libsql_detector_empty_when_all_rehomed_or_absent() {
        // Absent dir ⇒ empty.
        assert!(
            libsql_bare_default_idents(Path::new("/nonexistent/xyz"), &HashSet::new()).is_empty()
        );
        // Only a `default/` subdir ⇒ empty (fully re-homed).
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("default")).unwrap();
        std::fs::write(tmp.path().join("default").join("blog.db"), b"x").unwrap();
        assert!(libsql_bare_default_idents(tmp.path(), &HashSet::new()).is_empty());
    }
}
