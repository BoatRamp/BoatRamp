//! Manifest schema versioning + the migration framework (v0.6.0).
//!
//! A `boatramp apply` manifest carries an optional top-level `version:` field with
//! this **owner semantic**: **absent ⇒ current** — a version-less document is
//! parsed strictly against the latest typed schema, and an old-shaped one that
//! omits `version` fails with a helpful "add `version: N` and run `boatramp config
//! migrate`" error. A document that declares `version: N` **older** than
//! [`crate::apply::CURRENT_MANIFEST_VERSION`] is eligible for migration: it is run
//! through the registered chain (vN → vN+1 → … → current), each step a mechanical
//! transform, and the result is deserialized into the current typed
//! [`ApplyManifest`].
//!
//! **Why not `ron::Value` as the migration medium?** RON's `Value` cannot faithfully
//! round-trip this manifest — it discards enum variant names (a `RootSource::image(…)`
//! collapses to a bare sequence) and does not preserve `IMPLICIT_SOME` options. So the
//! migration medium is a **per-version "loose" typed struct** that keeps exactly the
//! region that changed shape in its old form (for v1, `compute[].spec` stays the
//! untyped `serde_json::Value` blob it always was) and mirrors everything else. Each
//! migration transforms one loose struct into the next, ending in the current typed
//! manifest. This is the same loose-parse → migrate → typed pipeline the design calls
//! for, realized in the only medium that preserves the document.

use serde::Deserialize;

use crate::apply::{
    ApplyCompute, ApplyFunction, ApplyManifest, ApplySite, CURRENT_MANIFEST_VERSION, Error, Result,
};

/// Peek only the top-level `version:` field of a manifest, ignoring everything else,
/// so the pipeline can branch before committing to a schema. `None` ⇒ absent (⇒
/// current). A syntactically broken document surfaces as [`Error::Ron`] (RON) or
/// [`Error::Json`] (JSON).
///
/// Format-aware (v0.6.5): the peek is decoded with the same deserializer the strict
/// parse will use, so a `version:` in a JSON manifest is read via `serde_json` (a RON
/// peek would reject the `{ … }` document as a syntax error and never reach the
/// current-schema-only branch in [`crate::apply::ApplyManifest::parse_with_format`]).
pub fn peek_version(text: &str, fmt: crate::config::ConfigFormat) -> Result<Option<u32>> {
    /// A permissive projection that reads only `version` (all other fields ignored —
    /// no `deny_unknown_fields`).
    #[derive(Deserialize, Default)]
    struct VersionPeek {
        #[serde(default)]
        version: Option<u32>,
    }
    let peek: VersionPeek = match fmt {
        crate::config::ConfigFormat::Ron => crate::config::ron_options().from_str(text)?,
        crate::config::ConfigFormat::Json => serde_json::from_str(text)?,
    };
    Ok(peek.version)
}

/// Run the registered migration chain from `from` up to
/// [`CURRENT_MANIFEST_VERSION`], returning the current typed [`ApplyManifest`].
///
/// The chain is applied step-wise (vN → vN+1 → …). Today there is exactly one step
/// (v1 → v2); the structure is a `match` on the source version so adding a v2 → v3
/// step later is a localized edit. Emits operator warnings to stderr as it goes
/// (e.g. a DB-shaped compute workload the new `databases:` block should own).
pub fn migrate_to_current(text: &str, from: u32) -> Result<ApplyManifest> {
    match from {
        1 => migrate_v1_to_v2(text),
        // `from` is already known to be `< CURRENT_MANIFEST_VERSION` (the caller
        // handles current / too-new), so any value here that we do not have a step
        // for is a version we cannot upgrade.
        other => Err(Error::Migration {
            from: other,
            reason: format!(
                "no migration is registered from version {other} to the current version \
                 {CURRENT_MANIFEST_VERSION}"
            ),
        }),
    }
}

// ---------------------------------------------------------------------------
// v1 → v2 (the pre-v0.6.0 → v0.6.0 migration)
// ---------------------------------------------------------------------------

/// The v1 (pre-v0.6.0) manifest schema. Everything is identical to the current typed
/// [`ApplyManifest`] EXCEPT `compute[].spec`, which in v1 was an untyped
/// `serde_json::Value` (a `PutComputeRequest`-shaped JSON blob PUT straight to the
/// server). We keep only that region loose and let the rest deserialize as its real
/// typed shape — none of it changed between v1 and v2.
#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct V1ApplyManifest {
    /// The declared version (`1`); dropped on the way to the current manifest.
    #[serde(default)]
    #[allow(dead_code)]
    version: Option<u32>,
    #[serde(default)]
    project: Option<String>,
    #[serde(default)]
    sites: Vec<ApplySite>,
    #[serde(default)]
    functions: Vec<ApplyFunction>,
    #[serde(default)]
    compute: Vec<V1ApplyCompute>,
    #[serde(default)]
    tenancy: Option<boatramp_core::tenancy::TenancySchema>,
}

impl Default for V1ApplyManifest {
    fn default() -> Self {
        Self {
            version: Some(1),
            project: None,
            sites: Vec::new(),
            functions: Vec::new(),
            compute: Vec::new(),
            tenancy: None,
        }
    }
}

/// A v1 compute workload: name + the untyped `PutComputeRequest`-shaped `spec` blob.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct V1ApplyCompute {
    name: String,
    /// The pre-v0.6.0 raw-JSON spec — always `PutComputeRequest`-shaped
    /// (`{ spec: {…}, replicas, placement }`).
    spec: serde_json::Value,
}

/// Migrate a v1 manifest to the current (v2) typed [`ApplyManifest`]. The only shape
/// change is `compute[].spec`: the raw-JSON `PutComputeRequest`-shaped blob is parsed
/// into the typed [`boatramp_core::compute::PutComputeRequest`] and split into the new
/// `spec` / `replicas` / `placement` fields. A DB-shaped workload (e.g. a
/// `pgvector/pgvector:pg16` image) draws a warning suggesting the new `databases:`
/// block (added by Stage B; here we only warn — we do not require it).
fn migrate_v1_to_v2(text: &str) -> Result<ApplyManifest> {
    let v1: V1ApplyManifest = crate::config::ron_options()
        .from_str(text)
        .map_err(|source| Error::Migration {
            from: 1,
            reason: format!("this does not parse as a v1 manifest either: {source}"),
        })?;

    let mut compute = Vec::with_capacity(v1.compute.len());
    for c in v1.compute {
        // The v1 blob was the exact `PutComputeRequest` PUT to the server, so it parses
        // into the typed request; splitting it yields the current `ApplyCompute` fields.
        let req: boatramp_core::compute::PutComputeRequest = serde_json::from_value(c.spec)
            .map_err(|source| Error::Migration {
                from: 1,
                reason: format!(
                    "compute `{}`: its v1 `spec` is not a valid PutComputeRequest \
                     (spec/replicas/placement): {source}",
                    c.name
                ),
            })?;

        warn_if_db_shaped(&c.name, &req.spec);

        compute.push(ApplyCompute {
            name: c.name,
            spec: req.spec,
            replicas: req.replicas,
            placement: req.placement,
        });
    }

    Ok(ApplyManifest {
        // Current = absent; the migrated manifest carries no `version:`.
        version: None,
        project: v1.project,
        sites: v1.sites,
        functions: v1.functions,
        compute,
        tenancy: v1.tenancy,
        // The v1→current migration produces no declared databases — a DB-shaped v1
        // compute workload is migrated as a plain compute workload (with an advisory
        // warning), not auto-converted into the new `databases:` block.
        databases: Vec::new(),
    })
}

/// Warn (to stderr) when a migrated compute workload looks like a database engine —
/// the kind of workload the new v0.6.0 `databases:` block (Stage B) is meant to own,
/// where boatramp mints and seals the credential instead of the operator hand-running
/// a raw DB image. Purely advisory: migration still succeeds as a plain compute
/// workload.
fn warn_if_db_shaped(name: &str, spec: &boatramp_core::compute::ComputeSpec) {
    // Only an OCI image reference carries an engine hint; tar / rootfs sources are
    // opaque blob hashes we can't match on.
    let boatramp_core::compute::RootSource::Image(image) = &spec.root else {
        return;
    };
    // Match the common stock database images by their well-known repository names.
    const DB_HINTS: &[&str] = &[
        "postgres",
        "pgvector",
        "mysql",
        "mariadb",
        "redis",
        "mongo",
        "clickhouse",
        "cockroach",
        "timescale",
    ];
    let lower = image.to_ascii_lowercase();
    if DB_HINTS.iter().any(|hint| lower.contains(hint)) {
        eprintln!(
            "  ⚠ compute `{name}` runs a database-shaped image (`{image}`). v0.6.0 adds \
             a managed `databases:` block that provisions the engine and mints + seals \
             its credential for you — consider declaring it there instead of as a raw \
             compute workload. (This migration keeps it as compute; no change is \
             required.)"
        );
    }
}

/// Render an [`ApplyManifest`] back to RON text for `boatramp config migrate --write`.
/// The upgraded output OMITS `version:` (current = absent), which the manifest's
/// `#[serde(skip_serializing_if)]` already handles for a `None` version.
pub fn render_manifest(manifest: &ApplyManifest) -> Result<String> {
    // `struct_names(false)` (the default) emits anonymous tuple-structs `( … )` — the
    // exact form manifests are authored in, so the output round-trips through both the
    // version peek and the strict parse. Emitting struct names would make `peek_version`
    // reject the leading `ApplyManifest(` name.
    let pretty = ron::ser::PrettyConfig::new().indentor("  ".to_string());
    ron::ser::to_string_pretty(manifest, pretty).map_err(|source| Error::Migration {
        from: 0,
        reason: format!("could not render the upgraded manifest as RON: {source}"),
    })
}
