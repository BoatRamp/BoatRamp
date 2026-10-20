//! The **BRPROJ project export/import bundle** — the on-disk format a
//! `project export` writes and a `project import` reads.
//!
//! A bundle is a plain `tar` whose FIRST entry is a JSON `MANIFEST` describing every
//! other member, followed by the per-engine payloads:
//!
//! ```text
//! MANIFEST                               magic "BRPROJ" | format_version | created_at | data_only | members[]
//! kv.brkvdump                            the control-plane KV logical slice (kv_dump::export_to_bytes bytes)
//! sql/<db>.pgc                           a streamed Postgres dump (pg_dump custom/plain)
//! libsql/<project>/<site>/<db>.sqlite    a VACUUM INTO snapshot of a libsql database
//! blobs/<...>                            blob-store objects
//! ```
//!
//! Discipline borrowed from [`boatramp_core::kv_dump`]: a loud **magic** (`BRPROJ`) and
//! an explicit **format version** the reader refuses if unknown (never misreads a
//! foreign/newer file), plus a per-member **SHA-256 checksum** the reader VERIFIES on
//! extraction (byte-integrity, not a size check) — so a truncated/corrupt bundle is
//! caught before a single row is restored.
//!
//! The writer takes members already **staged on disk** (the multi-GB `pg_dump` stream
//! lands in a staging file via `run_ephemeral`'s streaming sink, the libsql `VACUUM
//! INTO` writes a file, the KV slice + blobs are staged too), so each member is appended
//! with a known size — correctness over the PAX unknown-length streaming form, and the
//! staging keeps memory bounded regardless of dump size. All IO is synchronous (the
//! `tar` crate is sync); the async driver calls it from a blocking task.

use std::collections::HashSet;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The bundle magic — carried in the MANIFEST so a stray/foreign tar is rejected loud.
pub const BUNDLE_MAGIC: &str = "BRPROJ";

/// The bundle FORMAT version. Bumped only on an incompatible change; a reader refuses an
/// unknown version rather than misreading it.
pub const BUNDLE_FORMAT_VERSION: u32 = 1;

/// The manifest's tar-entry path — MUST be the first entry in the bundle.
pub const MANIFEST_PATH: &str = "MANIFEST";

/// The control-plane KV slice's tar-entry path (the `kv_dump::export_to_bytes` bytes).
pub const KV_MEMBER_PATH: &str = "kv.brkvdump";

/// The identity transport-container's tar-entry path (`--include-identity` only): the
/// passphrase-wrapped KEK, produced by `boatramp_server::envelope::transport_wrap`.
pub const IDENTITY_MEMBER_PATH: &str = "identity/identity.brid";

/// Which engine a bundle member came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberKind {
    /// A Postgres `pg_dump` (under `sql/<db>.pgc`).
    PgDump,
    /// A MySQL `mysqldump` (under `sql/<db>.sql`).
    MysqlDump,
    /// A libsql `VACUUM INTO` snapshot (under `libsql/<project>/<site>/<db>.sqlite`).
    Libsql,
    /// The control-plane KV logical slice (`kv.brkvdump`).
    Kv,
    /// A blob-store object (under `blobs/<...>`).
    Blob,
    /// The passphrase-wrapped identity transport container (`identity/identity.brid`),
    /// present only under `--include-identity`. Carries the project's KEK (transport-wrapped)
    /// so an `--identity adopt` (recovery) can unseal the KV slice's sealed secrets.
    Identity,
}

/// SQL-dump provenance for a `PgDump`/`MysqlDump` member: the detected server version,
/// the client image used to produce (and required to restore) it, and the schema-ledger
/// fingerprint for the import schema-skew check. (Field named `pg` historically; it
/// carries MySQL provenance too — the engine is the member's [`MemberKind`].)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PgMemberInfo {
    /// The source server's version banner (`SHOW server_version_num` for Postgres,
    /// `SELECT VERSION()` for MySQL).
    pub server_version_num: String,
    /// The client image the dump was produced with (`pgvector/pgvector:pg<major>` or
    /// `mysql:<maj.min>`) — an import MUST use a client whose version is >= this (the
    /// version-match invariant).
    pub client_image: String,
    /// A fingerprint of the source's `boatramp_migrations` ledger, so a `--data-only`
    /// import can REFUSE a schema-skewed target (its migrated schema differs from what
    /// the data expects) unless the operator overrides. `None` when not captured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_fingerprint: Option<String>,
}

/// One member described in the MANIFEST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestMember {
    /// The member's tar-entry path (relative, no traversal).
    pub path: String,
    /// Which engine produced it.
    pub kind: MemberKind,
    /// The member's exact byte length.
    pub size: u64,
    /// Hex SHA-256 of the member bytes — verified on extraction.
    pub sha256: String,
    /// Postgres provenance (only for `PgDump` members).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg: Option<PgMemberInfo>,
}

/// What the bundle was exported from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceInfo {
    /// The source project.
    pub project: String,
    /// The source site scope, when the export was site-scoped (`None` ⇒ project-level).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
}

/// The bundle MANIFEST — the first tar entry, describing the whole bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Must equal [`BUNDLE_MAGIC`] — a loud reject of a non-boatramp tar.
    pub magic: String,
    /// The bundle format version (see [`BUNDLE_FORMAT_VERSION`]).
    pub format_version: u32,
    /// Unix seconds when the bundle was produced.
    pub created_at: u64,
    /// Whether this is a `--data-only` bundle (app data only — no identity/RBAC/routing).
    pub data_only: bool,
    /// What the bundle was exported from.
    pub source: SourceInfo,
    /// Every non-manifest member, in write order.
    pub members: Vec<ManifestMember>,
}

/// A project-bundle error.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// An underlying IO error (tar read/write, staging-file read, extraction write).
    #[error("bundle io: {0}")]
    Io(#[from] io::Error),
    /// The MANIFEST JSON failed to (de)serialize.
    #[error("bundle manifest json: {0}")]
    Json(#[from] serde_json::Error),
    /// The first entry's magic did not match — not a boatramp project bundle.
    #[error("not a boatramp project bundle: expected magic {expected:?}, found {found:?}")]
    BadMagic {
        /// The expected magic ([`BUNDLE_MAGIC`]).
        expected: String,
        /// What the bundle carried.
        found: String,
    },
    /// The bundle format version is not one this build reads.
    #[error("unsupported bundle format version {found} (this build reads {supported})")]
    BadVersion {
        /// The version the bundle declared.
        found: u32,
        /// The version this build supports ([`BUNDLE_FORMAT_VERSION`]).
        supported: u32,
    },
    /// The bundle's first entry was not the MANIFEST.
    #[error("bundle is missing its {0:?} entry as the first entry")]
    MissingManifest(String),
    /// A member's extracted bytes did not match the manifest checksum.
    #[error("checksum MISMATCH for member {path:?}: manifest {expected}, extracted {actual}")]
    ChecksumMismatch {
        /// The offending member path.
        path: String,
        /// The checksum the manifest recorded.
        expected: String,
        /// The checksum of the bytes actually in the bundle.
        actual: String,
    },
    /// A member named in the manifest was absent from the bundle.
    #[error("member {0:?} named in the manifest is absent from the bundle")]
    MissingMember(String),
    /// A member present in the bundle was not described by the manifest.
    #[error("member {0:?} is present in the bundle but absent from the manifest")]
    UnexpectedMember(String),
    /// A member path is unsafe (absolute or contains a `..`/`.` traversal component).
    #[error("unsafe member path {0:?} in bundle (absolute or traversal)")]
    UnsafePath(String),
    /// A v2 bundle is structurally malformed — a sidecar without its data member, a member
    /// without its preceding sidecar, a mismatched pairing, or a member out of declared order.
    #[error("malformed v2 bundle stream: {0}")]
    MalformedStream(String),
    /// A member's streamed byte count did not match the size it declared (sidecar/manifest).
    #[error("size MISMATCH for member {path:?}: declared {expected}, streamed {actual}")]
    SizeMismatch {
        /// The offending member path.
        path: String,
        /// The size the sidecar (v2) or manifest (v1) declared.
        expected: u64,
        /// The bytes actually streamed.
        actual: u64,
    },
}

impl Manifest {
    /// Loud-reject a foreign or incompatible bundle: the magic and format version MUST
    /// match this build (mirrors the `kv_dump` discipline).
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.magic != BUNDLE_MAGIC {
            return Err(BundleError::BadMagic {
                expected: BUNDLE_MAGIC.to_string(),
                found: self.magic.clone(),
            });
        }
        if self.format_version != BUNDLE_FORMAT_VERSION {
            return Err(BundleError::BadVersion {
                found: self.format_version,
                supported: BUNDLE_FORMAT_VERSION,
            });
        }
        Ok(())
    }

    /// The `PgDump` members (one per Postgres database).
    pub fn pg_members(&self) -> impl Iterator<Item = &ManifestMember> {
        self.members.iter().filter(|m| m.kind == MemberKind::PgDump)
    }
}

/// A member staged on disk, ready to be appended to a bundle.
#[derive(Debug, Clone)]
pub struct StagedMember {
    /// The tar-entry path to write it at (relative, no traversal).
    pub path: String,
    /// Which engine produced it.
    pub kind: MemberKind,
    /// The on-disk staging file holding the member bytes.
    pub source: PathBuf,
    /// Postgres provenance (only for `PgDump` members).
    pub pg: Option<PgMemberInfo>,
}

/// Reject an absolute or traversing member path (defense on both write and read, so a
/// malicious bundle can never extract outside its target directory).
fn validate_member_path(path: &str) -> Result<(), BundleError> {
    use std::path::Component;
    if path.is_empty() {
        return Err(BundleError::UnsafePath(path.to_string()));
    }
    let p = Path::new(path);
    if p.is_absolute() {
        return Err(BundleError::UnsafePath(path.to_string()));
    }
    for c in p.components() {
        if !matches!(c, Component::Normal(_)) {
            return Err(BundleError::UnsafePath(path.to_string()));
        }
    }
    Ok(())
}

/// Stream `r`, returning `(byte_count, hex_sha256)` without buffering it whole.
fn size_and_sha256<R: Read>(mut r: R) -> io::Result<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((total, hex::encode(hasher.finalize())))
}

/// Append `data` as a tar member at `path` (a small in-memory member, e.g. the MANIFEST).
fn append_bytes<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    mtime: u64,
    data: &[u8],
) -> Result<(), BundleError> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o600);
    header.set_mtime(mtime);
    // `append_data` sets the path + checksum itself.
    builder.append_data(&mut header, path, data)?;
    Ok(())
}

/// Write a bundle at `out` from members already staged on disk: compute each member's
/// size + SHA-256, build + validate the MANIFEST, then write the tar with the MANIFEST
/// first and every member streamed from its staging file (bounded memory). Returns the
/// MANIFEST that was written.
pub fn write_bundle(
    out: &Path,
    created_at: u64,
    data_only: bool,
    source: SourceInfo,
    staged: &[StagedMember],
) -> Result<Manifest, BundleError> {
    // 1. Describe every member (size + checksum), validating each path.
    let mut members = Vec::with_capacity(staged.len());
    for m in staged {
        validate_member_path(&m.path)?;
        let f = std::fs::File::open(&m.source)?;
        let (size, sha256) = size_and_sha256(io::BufReader::new(f))?;
        members.push(ManifestMember {
            path: m.path.clone(),
            kind: m.kind,
            size,
            sha256,
            pg: m.pg.clone(),
        });
    }
    let manifest = Manifest {
        magic: BUNDLE_MAGIC.to_string(),
        format_version: BUNDLE_FORMAT_VERSION,
        created_at,
        data_only,
        source,
        members,
    };
    manifest.validate()?; // defensive — we just built it, but keep the one invariant honest

    // 2. Write the tar: MANIFEST first, then each member streamed from its file.
    let file = std::fs::File::create(out)?;
    let mut builder = tar::Builder::new(io::BufWriter::new(file));
    let manifest_json = serde_json::to_vec_pretty(&manifest)?;
    append_bytes(&mut builder, MANIFEST_PATH, created_at, &manifest_json)?;
    for (sm, mm) in staged.iter().zip(&manifest.members) {
        let mut f = std::fs::File::open(&sm.source)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(mm.size);
        header.set_mode(0o600);
        header.set_mtime(created_at);
        builder.append_data(&mut header, &sm.path, &mut f)?;
    }
    let mut inner = builder.into_inner()?;
    inner.flush()?;
    Ok(manifest)
}

/// Read + validate the MANIFEST (the first tar entry) from `bundle`, without extracting
/// any member.
pub fn read_manifest(bundle: &Path) -> Result<Manifest, BundleError> {
    let file = std::fs::File::open(bundle)?;
    let mut ar = tar::Archive::new(io::BufReader::new(file));
    let mut entries = ar.entries()?;
    let first = entries
        .next()
        .ok_or_else(|| BundleError::MissingManifest(MANIFEST_PATH.to_string()))??;
    let path = first.path()?.to_string_lossy().into_owned();
    if path != MANIFEST_PATH {
        return Err(BundleError::MissingManifest(MANIFEST_PATH.to_string()));
    }
    let mut buf = String::new();
    let mut first = first;
    first.read_to_string(&mut buf)?;
    let manifest: Manifest = serde_json::from_str(&buf)?;
    manifest.validate()?;
    Ok(manifest)
}

/// Extract every member of `bundle` into `out_dir`, VERIFYING each member's SHA-256
/// against the MANIFEST as it streams (byte-integrity). Refuses a member the manifest
/// does not describe, and a manifest member the bundle does not contain. Returns the
/// validated MANIFEST. Member files land at `out_dir/<member.path>`.
pub fn extract_and_verify(bundle: &Path, out_dir: &Path) -> Result<Manifest, BundleError> {
    let manifest = read_manifest(bundle)?;
    let file = std::fs::File::open(bundle)?;
    let mut ar = tar::Archive::new(io::BufReader::new(file));
    let mut seen: HashSet<String> = HashSet::new();
    for entry in ar.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_string_lossy().into_owned();
        if path == MANIFEST_PATH {
            continue;
        }
        validate_member_path(&path)?;
        let mm = manifest
            .members
            .iter()
            .find(|m| m.path == path)
            .ok_or_else(|| BundleError::UnexpectedMember(path.clone()))?;
        let dst = out_dir.join(&path);
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Stream the member to disk while hashing — never buffer the (multi-GB) payload.
        let mut hasher = Sha256::new();
        let mut f = io::BufWriter::new(std::fs::File::create(&dst)?);
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = entry.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            f.write_all(&buf[..n])?;
        }
        f.flush()?;
        let actual = hex::encode(hasher.finalize());
        if actual != mm.sha256 {
            return Err(BundleError::ChecksumMismatch {
                path,
                expected: mm.sha256.clone(),
                actual,
            });
        }
        seen.insert(path);
    }
    for m in &manifest.members {
        if !seen.contains(&m.path) {
            return Err(BundleError::MissingMember(m.path.clone()));
        }
    }
    Ok(manifest)
}

// ============================================================================
// Format v2 — streamable export/import
//
// v1 blocks a streaming EXPORT: the MANIFEST (first entry) carries every member's size +
// SHA-256, so all members must be produced (to compute those) before the MANIFEST can be
// written — i.e. the whole bundle has to be staged first. v2 removes that coupling: the
// MANIFEST becomes an ordered member LIST only, and each member's size + SHA-256 move into a
// per-member `.brmeta` SIDECAR written immediately BEFORE that member. The MANIFEST now needs
// nothing a member produces, so an export streams one member at a time with a transient
// footprint bounded to the LARGEST SINGLE MEMBER, and an import is a single forward pass.
// All IO here is synchronous (the `tar` crate is sync); the async driver drives it from a
// blocking task — see the wiring handoff.
// ============================================================================

/// The **streamable** bundle format version (see the section comment above).
///
/// **Compatibility decision — read-compatible, write-forward.** The v2-aware single-pass
/// reader [`read_bundle_streaming`] reads BOTH v1 and v2 bundles (it dispatches on
/// `format_version`), so every bundle a prior release wrote still imports. The v2 writer only
/// ever writes v2. An older node handed a v2 bundle refuses it LOUD as
/// [`BundleError::BadVersion`] (its [`Manifest::validate`] rejects version 2) — never a
/// silent misread. This mirrors the `kv_dump` loud-reject discipline.
pub const BUNDLE_FORMAT_VERSION_V2: u32 = 2;

/// The suffix of a member's sidecar tar entry. For a data member at `<path>`, its sidecar is
/// `<path>.brmeta` — a tiny JSON [`MemberMeta`] (size + SHA-256) written immediately before
/// `<path>`, so a single-pass reader learns them before the body arrives.
pub const META_SUFFIX: &str = ".brmeta";

/// The upfront-knowable identity of a bundle member — what the v2 MANIFEST lists, in restore
/// order. Carries no size/SHA (those travel in the member's [`MemberMeta`] sidecar), so the
/// MANIFEST can be written before any member is produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSpec {
    /// The member's tar-entry path (relative, no traversal).
    pub path: String,
    /// Which engine produced it.
    pub kind: MemberKind,
    /// Postgres/MySQL provenance (only for `PgDump`/`MysqlDump` members).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg: Option<PgMemberInfo>,
}

/// The **v2 MANIFEST** — the first tar entry: the ordered member LIST plus bundle metadata.
/// Unlike the v1 [`Manifest`] it carries NO per-member size/SHA (each member's live in its
/// [`MemberMeta`] sidecar), which is what makes a streaming export possible.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamManifest {
    /// Must equal [`BUNDLE_MAGIC`].
    pub magic: String,
    /// The bundle format version — [`BUNDLE_FORMAT_VERSION_V2`].
    pub format_version: u32,
    /// Unix seconds when the bundle was produced.
    pub created_at: u64,
    /// Whether this is a `--data-only` bundle.
    pub data_only: bool,
    /// What the bundle was exported from.
    pub source: SourceInfo,
    /// Every non-manifest member, in the order the reader must restore them.
    pub members: Vec<MemberSpec>,
}

impl StreamManifest {
    /// Loud-reject a foreign or wrong-version bundle (magic + version MUST be v2).
    fn validate(&self) -> Result<(), BundleError> {
        if self.magic != BUNDLE_MAGIC {
            return Err(BundleError::BadMagic {
                expected: BUNDLE_MAGIC.to_string(),
                found: self.magic.clone(),
            });
        }
        if self.format_version != BUNDLE_FORMAT_VERSION_V2 {
            return Err(BundleError::BadVersion {
                found: self.format_version,
                supported: BUNDLE_FORMAT_VERSION_V2,
            });
        }
        Ok(())
    }

    /// The sidecar tar-entry path for a member at `path`.
    fn meta_path(path: &str) -> String {
        format!("{path}{META_SUFFIX}")
    }
}

/// A member's `.brmeta` sidecar: the size + SHA-256 the v1 MANIFEST used to carry inline,
/// now written immediately before the member so the reader knows them before the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberMeta {
    /// The member's exact byte length.
    pub size: u64,
    /// Hex SHA-256 of the member bytes — verified as the member streams.
    pub sha256: String,
}

/// A streaming v2 bundle writer: writes the MANIFEST up front, then appends members ONE AT A
/// TIME ([`append_member`](BundleStreamWriter::append_member)), each from a bounded staging
/// temp the caller may delete the instant the call returns — so the node never holds more
/// than the largest single member. The export driver drives it from a blocking task, staging
/// each member just before it appends and deleting the temp just after (see the convenience
/// wrapper [`write_bundle_streaming`], which encapsulates exactly that produce→append→delete
/// loop).
pub struct BundleStreamWriter<W: Write> {
    builder: tar::Builder<W>,
    created_at: u64,
    /// The members the MANIFEST declared, consumed in order as `append_member` is called, so
    /// an out-of-order or extra append is refused and a shortfall is caught at `finish`.
    remaining: std::collections::VecDeque<MemberSpec>,
}

impl<W: Write> BundleStreamWriter<W> {
    /// Begin a v2 bundle on `out`, writing the MANIFEST (the ordered member list) first.
    /// `specs` is every member in restore order; each must then be supplied, in that order,
    /// via [`append_member`](Self::append_member), and the bundle closed with
    /// [`finish`](Self::finish).
    pub fn new(
        out: W,
        created_at: u64,
        data_only: bool,
        source: SourceInfo,
        specs: Vec<MemberSpec>,
    ) -> Result<Self, BundleError> {
        for s in &specs {
            validate_member_path(&s.path)?;
        }
        let manifest = StreamManifest {
            magic: BUNDLE_MAGIC.to_string(),
            format_version: BUNDLE_FORMAT_VERSION_V2,
            created_at,
            data_only,
            source,
            members: specs.clone(),
        };
        manifest.validate()?;
        let mut builder = tar::Builder::new(out);
        let manifest_json = serde_json::to_vec_pretty(&manifest)?;
        append_bytes(&mut builder, MANIFEST_PATH, created_at, &manifest_json)?;
        Ok(Self {
            builder,
            created_at,
            remaining: specs.into_iter().collect(),
        })
    }

    /// Append the next member, whose bytes are staged at `src` (a bounded temp). Writes the
    /// member's `.brmeta` sidecar (size + SHA-256, read from `src`) then the member data,
    /// both streamed from `src` (never buffered whole). The `path`/`kind` MUST match the next
    /// member the MANIFEST declared — an out-of-order or unexpected append is refused loud.
    pub fn append_member(
        &mut self,
        path: &str,
        kind: MemberKind,
        src: &Path,
    ) -> Result<(), BundleError> {
        let expected = self.remaining.pop_front().ok_or_else(|| {
            BundleError::MalformedStream(format!(
                "append of {path:?} but the MANIFEST declared no more members"
            ))
        })?;
        if expected.path != path || expected.kind != kind {
            return Err(BundleError::MalformedStream(format!(
                "append of ({path:?}, {kind:?}) does not match the next declared member \
                 ({:?}, {:?})",
                expected.path, expected.kind
            )));
        }
        validate_member_path(path)?;

        // Pass 1: size (stat) + SHA-256 (one streamed read) → the sidecar, BEFORE the body.
        let size = std::fs::metadata(src)?.len();
        let (hashed, sha256) = size_and_sha256(io::BufReader::new(std::fs::File::open(src)?))?;
        if hashed != size {
            // The temp changed size between stat and hash — refuse rather than ship a lie.
            return Err(BundleError::SizeMismatch {
                path: path.to_string(),
                expected: size,
                actual: hashed,
            });
        }
        let meta = MemberMeta { size, sha256 };
        let meta_json = serde_json::to_vec(&meta)?;
        append_bytes(
            &mut self.builder,
            &StreamManifest::meta_path(path),
            self.created_at,
            &meta_json,
        )?;

        // Pass 2: the member data, streamed from the temp with the size the sidecar committed.
        let mut f = std::fs::File::open(src)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(size);
        header.set_mode(0o600);
        header.set_mtime(self.created_at);
        self.builder.append_data(&mut header, path, &mut f)?;
        Ok(())
    }

    /// Finish the bundle: refuse if any declared member was never appended, then flush.
    pub fn finish(mut self) -> Result<(), BundleError> {
        if let Some(missing) = self.remaining.pop_front() {
            return Err(BundleError::MissingMember(missing.path));
        }
        let mut inner = self.builder.into_inner()?;
        inner.flush()?;
        Ok(())
    }
}

/// Stream a v2 bundle to `out`, producing each member JUST BEFORE it is appended and freeing
/// its staging temp JUST AFTER — so the transient on-disk staging never exceeds the largest
/// single member (O(largest member), never O(whole bundle)). For each [`MemberSpec`] in
/// `specs` (restore order), `stage(spec)` stages THAT member to a temp and returns its path;
/// the member is appended (sidecar + data) and its temp is then deleted before the next is
/// staged.
///
/// This is the shape the export driver uses from its blocking task: `stage` runs the engine
/// dump (pg_dump / libsql `VACUUM INTO` / the KV slice / a blob `get`) into a staging temp,
/// one member at a time.
pub fn write_bundle_streaming<W, S>(
    out: W,
    created_at: u64,
    data_only: bool,
    source: SourceInfo,
    specs: Vec<MemberSpec>,
    mut stage: S,
) -> Result<(), BundleError>
where
    W: Write,
    S: FnMut(&MemberSpec) -> Result<PathBuf, BundleError>,
{
    let mut writer = BundleStreamWriter::new(out, created_at, data_only, source, specs.clone())?;
    for spec in &specs {
        let tmp = stage(spec)?;
        let appended = writer.append_member(&spec.path, spec.kind, &tmp);
        // Free the staging temp immediately — this is what bounds the footprint — regardless
        // of whether the append succeeded.
        let _ = std::fs::remove_file(&tmp);
        appended?;
    }
    writer.finish()
}

/// A `Read` wrapper that SHA-256-hashes and byte-counts everything read through it, so a
/// single forward pass over a member yields both its restored bytes and the checksum to
/// verify — no second pass, no whole-member buffering.
struct HashingReader<R: Read> {
    inner: R,
    hasher: Sha256,
    count: u64,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            count: 0,
        }
    }

    fn finish(self) -> (u64, String) {
        (self.count, hex::encode(self.hasher.finalize()))
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.hasher.update(&buf[..n]);
            self.count += n as u64;
        }
        Ok(n)
    }
}

/// Peek just the `format_version` of a MANIFEST JSON (both v1 and v2 manifests carry it, with
/// the same magic) without committing to either struct — the v1/v2 dispatch key.
fn peek_format_version(manifest_json: &str) -> Result<u32, BundleError> {
    #[derive(Deserialize)]
    struct VersionPeek {
        #[serde(default)]
        magic: String,
        format_version: u32,
    }
    let peek: VersionPeek = serde_json::from_str(manifest_json)?;
    if peek.magic != BUNDLE_MAGIC {
        return Err(BundleError::BadMagic {
            expected: BUNDLE_MAGIC.to_string(),
            found: peek.magic,
        });
    }
    Ok(peek.format_version)
}

/// Stream one member's body through `restore`, hashing + byte-counting everything (draining
/// any bytes `restore` leaves unread so the hash + count cover the WHOLE member), then VERIFY
/// the streamed size + SHA-256 against what the member declared. A mismatch is the loud
/// reject — a corrupt/truncated member never reaches the next restore step.
fn verify_member<Rd, F>(
    body: &mut Rd,
    spec: &MemberSpec,
    expected_size: u64,
    expected_sha: &str,
    restore: &mut F,
) -> Result<(), BundleError>
where
    Rd: Read,
    F: FnMut(&MemberSpec, u64, &mut dyn Read) -> Result<(), BundleError>,
{
    let mut counting = HashingReader::new(body);
    restore(spec, expected_size, &mut counting)?;
    // Drain the remainder so a `restore` that read only part of the member still hashes all.
    let mut sink = [0u8; 64 * 1024];
    while counting.read(&mut sink)? != 0 {}
    let (count, sha) = counting.finish();
    if count != expected_size {
        return Err(BundleError::SizeMismatch {
            path: spec.path.clone(),
            expected: expected_size,
            actual: count,
        });
    }
    if sha != expected_sha {
        return Err(BundleError::ChecksumMismatch {
            path: spec.path.clone(),
            expected: expected_sha.to_string(),
            actual: sha,
        });
    }
    Ok(())
}

/// Read a bundle from `src` in a SINGLE FORWARD PASS, handing each member to `restore` as it
/// streams — never staging the whole bundle. Reads the MANIFEST first, then for each member
/// calls `restore(spec, size, body)`: `body` is a reader over the member's bytes and `size`
/// its declared length; the member's SHA-256 is VERIFIED as `body` is consumed (and any bytes
/// `restore` leaves unread are drained through the hasher), so a corrupt/truncated member is
/// caught before the next.
///
/// Reads BOTH v2 bundles (ordered `.brmeta` sidecar + data pairs; size/SHA from the sidecar)
/// and v1 bundles (size/SHA from the inline MANIFEST) — the compatibility path. For v2 the
/// members arrive in the MANIFEST's declared (restore) order, which is enforced; v1 members
/// may arrive in any order and are matched by path (preserving v1 semantics). Returns the
/// members restored, in the order they were handed to `restore`.
pub fn read_bundle_streaming<R, F>(src: R, mut restore: F) -> Result<Vec<MemberSpec>, BundleError>
where
    R: Read,
    F: FnMut(&MemberSpec, u64, &mut dyn Read) -> Result<(), BundleError>,
{
    let mut ar = tar::Archive::new(src);
    let mut entries = ar.entries()?;

    // 1. The MANIFEST (first entry), peeked for its version to pick the v1/v2 path.
    let mut first = entries
        .next()
        .ok_or_else(|| BundleError::MissingManifest(MANIFEST_PATH.to_string()))??;
    let fpath = first.path()?.to_string_lossy().into_owned();
    if fpath != MANIFEST_PATH {
        return Err(BundleError::MissingManifest(MANIFEST_PATH.to_string()));
    }
    let mut manifest_json = String::new();
    first.read_to_string(&mut manifest_json)?;
    let version = peek_format_version(&manifest_json)?;
    let mut restored: Vec<MemberSpec> = Vec::new();

    if version == BUNDLE_FORMAT_VERSION {
        // --- v1: inline size/SHA in the manifest; members matched by path (any order). ---
        let manifest: Manifest = serde_json::from_str(&manifest_json)?;
        manifest.validate()?;
        let mut seen: HashSet<String> = HashSet::new();
        for entry in entries {
            let mut entry = entry?;
            let path = entry.path()?.to_string_lossy().into_owned();
            validate_member_path(&path)?;
            let mm = manifest
                .members
                .iter()
                .find(|m| m.path == path)
                .ok_or_else(|| BundleError::UnexpectedMember(path.clone()))?;
            let spec = MemberSpec {
                path: mm.path.clone(),
                kind: mm.kind,
                pg: mm.pg.clone(),
            };
            verify_member(&mut entry, &spec, mm.size, &mm.sha256, &mut restore)?;
            seen.insert(path);
            restored.push(spec);
        }
        for m in &manifest.members {
            if !seen.contains(&m.path) {
                return Err(BundleError::MissingMember(m.path.clone()));
            }
        }
    } else if version == BUNDLE_FORMAT_VERSION_V2 {
        // --- v2: ordered `<path>.brmeta` sidecar then `<path>` data, in MANIFEST order. ---
        let manifest: StreamManifest = serde_json::from_str(&manifest_json)?;
        manifest.validate()?;
        let mut specs = manifest.members.iter();
        let mut pending_meta: Option<(String, MemberMeta)> = None;
        for entry in entries {
            let mut entry = entry?;
            let path = entry.path()?.to_string_lossy().into_owned();
            if let Some(stripped) = path.strip_suffix(META_SUFFIX) {
                // A sidecar — stash its meta for the data member that must immediately follow.
                if pending_meta.is_some() {
                    return Err(BundleError::MalformedStream(format!(
                        "sidecar {path:?} arrived with a prior sidecar still unmatched"
                    )));
                }
                let mut buf = String::new();
                entry.read_to_string(&mut buf)?;
                let meta: MemberMeta = serde_json::from_str(&buf)?;
                pending_meta = Some((stripped.to_string(), meta));
                continue;
            }
            validate_member_path(&path)?;
            // A data member: its sidecar must have come immediately before, and it must be the
            // next member the MANIFEST declared (the enforced forward order).
            let (meta_path, meta) = pending_meta.take().ok_or_else(|| {
                BundleError::MalformedStream(format!("member {path:?} with no preceding sidecar"))
            })?;
            if meta_path != path {
                return Err(BundleError::MalformedStream(format!(
                    "sidecar for {meta_path:?} does not match the following member {path:?}"
                )));
            }
            let spec = specs
                .next()
                .ok_or_else(|| BundleError::UnexpectedMember(path.clone()))?;
            if spec.path != path {
                return Err(BundleError::MalformedStream(format!(
                    "member {path:?} out of declared order (MANIFEST expected {:?})",
                    spec.path
                )));
            }
            verify_member(&mut entry, spec, meta.size, &meta.sha256, &mut restore)?;
            restored.push(spec.clone());
        }
        if let Some((mp, _)) = pending_meta.take() {
            return Err(BundleError::MissingMember(mp));
        }
        if let Some(missing) = specs.next() {
            return Err(BundleError::MissingMember(missing.path.clone()));
        }
    } else {
        return Err(BundleError::BadVersion {
            found: version,
            supported: BUNDLE_FORMAT_VERSION_V2,
        });
    }
    Ok(restored)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_staging(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }

    #[test]
    fn round_trips_a_bundle_and_verifies_members() {
        let td = tempfile::tempdir().unwrap();
        let stage = td.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let kv = write_staging(&stage, "kv.bin", b"BRKVDUMP\x01\x02\x03");
        let pg = write_staging(&stage, "app.pgc", &vec![7u8; 5000]);

        let bundle = td.path().join("out.brproj");
        let staged = vec![
            StagedMember {
                path: KV_MEMBER_PATH.to_string(),
                kind: MemberKind::Kv,
                source: kv,
                pg: None,
            },
            StagedMember {
                path: "sql/app.pgc".to_string(),
                kind: MemberKind::PgDump,
                source: pg,
                pg: Some(PgMemberInfo {
                    server_version_num: "160004".to_string(),
                    client_image: "pgvector/pgvector:pg16".to_string(),
                    schema_fingerprint: Some("deadbeef".to_string()),
                }),
            },
        ];
        let written = write_bundle(
            &bundle,
            1_700_000_000,
            true,
            SourceInfo {
                project: "acme".to_string(),
                site: None,
            },
            &staged,
        )
        .unwrap();
        assert_eq!(written.magic, BUNDLE_MAGIC);
        assert!(written.data_only);
        assert_eq!(written.pg_members().count(), 1);

        // Re-read the manifest from disk.
        let m = read_manifest(&bundle).unwrap();
        assert_eq!(m, written);
        assert_eq!(
            m.pg_members()
                .next()
                .unwrap()
                .pg
                .as_ref()
                .unwrap()
                .client_image,
            "pgvector/pgvector:pg16"
        );

        // Extract + verify.
        let out = td.path().join("extract");
        let m2 = extract_and_verify(&bundle, &out).unwrap();
        assert_eq!(m2, written);
        assert_eq!(
            std::fs::read(out.join("sql/app.pgc")).unwrap(),
            vec![7u8; 5000]
        );
        assert_eq!(
            std::fs::read(out.join(KV_MEMBER_PATH)).unwrap(),
            b"BRKVDUMP\x01\x02\x03"
        );
    }

    #[test]
    fn rejects_a_foreign_tar_and_a_future_version() {
        // Bad magic: hand-build a tar whose MANIFEST carries the wrong magic.
        let td = tempfile::tempdir().unwrap();
        let bad = td.path().join("bad.tar");
        {
            let mut b = tar::Builder::new(std::fs::File::create(&bad).unwrap());
            let m = Manifest {
                magic: "NOTBRPROJ".to_string(),
                format_version: BUNDLE_FORMAT_VERSION,
                created_at: 0,
                data_only: true,
                source: SourceInfo {
                    project: "x".to_string(),
                    site: None,
                },
                members: vec![],
            };
            let j = serde_json::to_vec(&m).unwrap();
            append_bytes(&mut b, MANIFEST_PATH, 0, &j).unwrap();
            b.finish().unwrap();
        }
        assert!(matches!(
            read_manifest(&bad),
            Err(BundleError::BadMagic { .. })
        ));

        // Bad version.
        let futv = td.path().join("futv.tar");
        {
            let mut b = tar::Builder::new(std::fs::File::create(&futv).unwrap());
            let m = Manifest {
                magic: BUNDLE_MAGIC.to_string(),
                format_version: BUNDLE_FORMAT_VERSION + 99,
                created_at: 0,
                data_only: true,
                source: SourceInfo {
                    project: "x".to_string(),
                    site: None,
                },
                members: vec![],
            };
            let j = serde_json::to_vec(&m).unwrap();
            append_bytes(&mut b, MANIFEST_PATH, 0, &j).unwrap();
            b.finish().unwrap();
        }
        assert!(matches!(
            read_manifest(&futv),
            Err(BundleError::BadVersion { .. })
        ));
    }

    #[test]
    fn extract_catches_a_checksum_mismatch() {
        // Hand-build a bundle whose MANIFEST lies about a member's checksum; extraction
        // must catch the byte-level mismatch (the verify discipline, load-bearing).
        let td = tempfile::tempdir().unwrap();
        let bad = td.path().join("tamper.tar");
        {
            let mut b = tar::Builder::new(std::fs::File::create(&bad).unwrap());
            let m = Manifest {
                magic: BUNDLE_MAGIC.to_string(),
                format_version: BUNDLE_FORMAT_VERSION,
                created_at: 0,
                data_only: true,
                source: SourceInfo {
                    project: "x".to_string(),
                    site: None,
                },
                members: vec![ManifestMember {
                    path: "sql/app.pgc".to_string(),
                    kind: MemberKind::PgDump,
                    size: 3,
                    sha256: "00".repeat(32), // deliberately wrong
                    pg: None,
                }],
            };
            let j = serde_json::to_vec(&m).unwrap();
            append_bytes(&mut b, MANIFEST_PATH, 0, &j).unwrap();
            append_bytes(&mut b, "sql/app.pgc", 0, b"abc").unwrap();
            b.finish().unwrap();
        }
        let out = td.path().join("x");
        assert!(matches!(
            extract_and_verify(&bad, &out),
            Err(BundleError::ChecksumMismatch { .. })
        ));
    }

    #[test]
    fn rejects_unsafe_member_paths() {
        assert!(validate_member_path("sql/app.pgc").is_ok());
        assert!(validate_member_path("libsql/acme/site/db.sqlite").is_ok());
        assert!(validate_member_path("/etc/passwd").is_err());
        assert!(validate_member_path("../escape").is_err());
        assert!(validate_member_path("a/../b").is_err());
        assert!(validate_member_path("").is_err());
    }

    // ---- format v2 (streamable) ------------------------------------------------------------

    #[test]
    fn v2_round_trips_streaming_write_then_single_pass_read() {
        let td = tempfile::tempdir().unwrap();
        let stage_dir = td.path().join("stage");
        std::fs::create_dir_all(&stage_dir).unwrap();

        // Members in RESTORE order (identity → blobs → pg → kv), with distinct sizes.
        let members: Vec<(MemberSpec, Vec<u8>)> = vec![
            (
                MemberSpec {
                    path: IDENTITY_MEMBER_PATH.to_string(),
                    kind: MemberKind::Identity,
                    pg: None,
                },
                b"IDENTITY-KEK-TRANSPORT".to_vec(),
            ),
            (
                MemberSpec {
                    path: "blobs/acme/obj1".to_string(),
                    kind: MemberKind::Blob,
                    pg: None,
                },
                vec![0xAB; 4096],
            ),
            (
                MemberSpec {
                    path: "sql/app.pgc".to_string(),
                    kind: MemberKind::PgDump,
                    pg: Some(PgMemberInfo {
                        server_version_num: "160004".to_string(),
                        client_image: "pgvector/pgvector:pg16".to_string(),
                        schema_fingerprint: Some("deadbeef".to_string()),
                    }),
                },
                vec![7u8; 50_000],
            ),
            (
                MemberSpec {
                    path: KV_MEMBER_PATH.to_string(),
                    kind: MemberKind::Kv,
                    pg: None,
                },
                b"BRKVDUMP\x01\x02\x03".to_vec(),
            ),
        ];
        let specs: Vec<MemberSpec> = members.iter().map(|(s, _)| s.clone()).collect();
        let bytes_by_path: std::collections::HashMap<String, Vec<u8>> = members
            .iter()
            .map(|(s, b)| (s.path.clone(), b.clone()))
            .collect();

        // Stream the bundle into an in-memory sink (models the network response — NOT node
        // disk), staging one member at a time.
        let mut bundle: Vec<u8> = Vec::new();
        let mut idx = 0u32;
        write_bundle_streaming(
            &mut bundle,
            1_700_000_000,
            false,
            SourceInfo {
                project: "acme".to_string(),
                site: Some("prod".to_string()),
            },
            specs.clone(),
            |spec| {
                let data = bytes_by_path.get(&spec.path).expect("a known member");
                let tmp = stage_dir.join(format!("m{idx}"));
                idx += 1;
                std::fs::write(&tmp, data).unwrap();
                Ok(tmp)
            },
        )
        .unwrap();

        // Single forward-pass read: collect each member's restored bytes.
        let mut got: Vec<(MemberSpec, Vec<u8>)> = Vec::new();
        let restored = read_bundle_streaming(bundle.as_slice(), |spec, size, body| {
            let mut v = Vec::new();
            body.read_to_end(&mut v).map_err(BundleError::Io)?;
            assert_eq!(v.len() as u64, size, "declared size == streamed bytes");
            got.push((spec.clone(), v));
            Ok(())
        })
        .unwrap();

        assert_eq!(restored, specs, "members restored in the declared order");
        assert_eq!(got.len(), members.len());
        for ((ws, wb), (gs, gb)) in members.iter().zip(&got) {
            assert_eq!(ws, gs);
            assert_eq!(wb, gb, "member {:?} bytes round-trip", ws.path);
        }
        // The pg provenance survives the v2 round-trip.
        let pg = restored
            .iter()
            .find(|m| m.kind == MemberKind::PgDump)
            .unwrap();
        assert_eq!(
            pg.pg.as_ref().unwrap().client_image,
            "pgvector/pgvector:pg16"
        );
    }

    #[test]
    fn read_bundle_streaming_reads_a_v1_bundle() {
        // The v2-aware single-pass reader reads a bundle written in the legacy v1 format —
        // the stated read-compatibility contract.
        let td = tempfile::tempdir().unwrap();
        let stage = td.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let kv = write_staging(&stage, "kv.bin", b"BRKVDUMP\x01\x02\x03");
        let pg = write_staging(&stage, "app.pgc", &vec![7u8; 5000]);
        let bundle = td.path().join("v1.brproj");
        let staged = vec![
            StagedMember {
                path: KV_MEMBER_PATH.to_string(),
                kind: MemberKind::Kv,
                source: kv,
                pg: None,
            },
            StagedMember {
                path: "sql/app.pgc".to_string(),
                kind: MemberKind::PgDump,
                source: pg,
                pg: Some(PgMemberInfo {
                    server_version_num: "160004".to_string(),
                    client_image: "pgvector/pgvector:pg16".to_string(),
                    schema_fingerprint: None,
                }),
            },
        ];
        write_bundle(
            &bundle,
            1_700_000_000,
            true,
            SourceInfo {
                project: "acme".to_string(),
                site: None,
            },
            &staged,
        )
        .unwrap();

        let file = std::fs::File::open(&bundle).unwrap();
        let mut got: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
        let restored = read_bundle_streaming(io::BufReader::new(file), |spec, _size, body| {
            let mut v = Vec::new();
            body.read_to_end(&mut v).map_err(BundleError::Io)?;
            got.insert(spec.path.clone(), v);
            Ok(())
        })
        .unwrap();
        assert_eq!(restored.len(), 2);
        assert_eq!(got.get(KV_MEMBER_PATH).unwrap(), b"BRKVDUMP\x01\x02\x03");
        assert_eq!(got.get("sql/app.pgc").unwrap(), &vec![7u8; 5000]);
    }

    #[test]
    fn read_bundle_streaming_catches_a_tampered_member() {
        // Hand-build a v2 bundle whose sidecar lies about the member's SHA — the single-pass
        // reader must reject it (the verify discipline, load-bearing).
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            let manifest = StreamManifest {
                magic: BUNDLE_MAGIC.to_string(),
                format_version: BUNDLE_FORMAT_VERSION_V2,
                created_at: 0,
                data_only: true,
                source: SourceInfo {
                    project: "x".to_string(),
                    site: None,
                },
                members: vec![MemberSpec {
                    path: "sql/app.pgc".to_string(),
                    kind: MemberKind::PgDump,
                    pg: None,
                }],
            };
            append_bytes(
                &mut b,
                MANIFEST_PATH,
                0,
                &serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            let meta = MemberMeta {
                size: 3,
                sha256: "00".repeat(32), // deliberately wrong
            };
            append_bytes(
                &mut b,
                "sql/app.pgc.brmeta",
                0,
                &serde_json::to_vec(&meta).unwrap(),
            )
            .unwrap();
            append_bytes(&mut b, "sql/app.pgc", 0, b"abc").unwrap();
            b.finish().unwrap();
        }
        let r = read_bundle_streaming(buf.as_slice(), |_s, _sz, body| {
            let mut v = Vec::new();
            body.read_to_end(&mut v).map_err(BundleError::Io)?;
            Ok(())
        });
        assert!(
            matches!(r, Err(BundleError::ChecksumMismatch { .. })),
            "got {r:?}"
        );
    }

    #[test]
    fn read_bundle_streaming_rejects_a_member_without_its_sidecar() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            let manifest = StreamManifest {
                magic: BUNDLE_MAGIC.to_string(),
                format_version: BUNDLE_FORMAT_VERSION_V2,
                created_at: 0,
                data_only: true,
                source: SourceInfo {
                    project: "x".to_string(),
                    site: None,
                },
                members: vec![MemberSpec {
                    path: "sql/app.pgc".to_string(),
                    kind: MemberKind::PgDump,
                    pg: None,
                }],
            };
            append_bytes(
                &mut b,
                MANIFEST_PATH,
                0,
                &serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            // No sidecar — straight to the data member.
            append_bytes(&mut b, "sql/app.pgc", 0, b"abc").unwrap();
            b.finish().unwrap();
        }
        let r = read_bundle_streaming(buf.as_slice(), |_s, _sz, _b| Ok(()));
        assert!(
            matches!(r, Err(BundleError::MalformedStream(_))),
            "got {r:?}"
        );
    }

    #[test]
    fn write_bundle_streaming_refuses_an_out_of_order_or_missing_member() {
        // append_member must match the declared order; finish must catch a shortfall.
        let specs = vec![
            MemberSpec {
                path: "a".to_string(),
                kind: MemberKind::Blob,
                pg: None,
            },
            MemberSpec {
                path: "b".to_string(),
                kind: MemberKind::Blob,
                pg: None,
            },
        ];
        let td = tempfile::tempdir().unwrap();
        let tmp = td.path().join("x");
        std::fs::write(&tmp, b"hello").unwrap();

        // Out-of-order append ("b" when "a" is next) is refused.
        let mut sink: Vec<u8> = Vec::new();
        let mut w = BundleStreamWriter::new(
            &mut sink,
            0,
            true,
            SourceInfo {
                project: "x".to_string(),
                site: None,
            },
            specs.clone(),
        )
        .unwrap();
        assert!(matches!(
            w.append_member("b", MemberKind::Blob, &tmp),
            Err(BundleError::MalformedStream(_))
        ));

        // A shortfall (declared 2, appended 1) is caught at finish.
        let mut sink2: Vec<u8> = Vec::new();
        let mut w2 = BundleStreamWriter::new(
            &mut sink2,
            0,
            true,
            SourceInfo {
                project: "x".to_string(),
                site: None,
            },
            specs,
        )
        .unwrap();
        w2.append_member("a", MemberKind::Blob, &tmp).unwrap();
        assert!(matches!(w2.finish(), Err(BundleError::MissingMember(_))));
    }

    /// Total bytes currently staged on disk under `dir` (non-recursive; the test stages flat).
    fn staged_bytes(dir: &Path) -> u64 {
        std::fs::read_dir(dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter_map(|e| e.metadata().ok())
            .filter(|m| m.is_file())
            .map(|m| m.len())
            .sum()
    }

    #[test]
    fn write_bundle_streaming_bounds_staging_to_the_largest_member() {
        // THE measured bounded-staging proof: 6 members of 256 KiB each — largest member =
        // 256 KiB, whole bundle = 1.5 MiB. We measure the ACTUAL on-disk staging during the
        // real streaming write and assert its PEAK stays ≈ one member, never the whole bundle.
        let td = tempfile::tempdir().unwrap();
        let stage_dir = td.path().join("stage");
        std::fs::create_dir_all(&stage_dir).unwrap();

        const MEMBER: usize = 256 * 1024;
        const N: usize = 6;
        let largest = MEMBER as u64;
        let whole = (MEMBER * N) as u64;

        let specs: Vec<MemberSpec> = (0..N)
            .map(|i| MemberSpec {
                path: format!("blobs/acme/obj{i}"),
                kind: MemberKind::Blob,
                pg: None,
            })
            .collect();

        // Real streaming writer: produce-one → append → delete.
        let mut peak: u64 = 0;
        let mut bundle: Vec<u8> = Vec::new();
        write_bundle_streaming(
            &mut bundle,
            0,
            false,
            SourceInfo {
                project: "acme".to_string(),
                site: None,
            },
            specs.clone(),
            |spec| {
                let tmp = stage_dir.join(spec.path.rsplit('/').next().unwrap());
                std::fs::write(&tmp, vec![0u8; MEMBER]).unwrap();
                peak = peak.max(staged_bytes(&stage_dir)); // measured AFTER staging this member
                Ok(tmp)
            },
        )
        .unwrap();

        // The transient staging never held more than ~one member — NEVER the whole bundle.
        // (A filesystem slack allowance of one 4 KiB block keeps this robust.)
        assert!(
            peak <= largest + 4096,
            "streaming staging peak {peak} must stay ≈ one member ({largest}), \
             far below the whole bundle ({whole})"
        );
        assert!(
            peak < whole / 2,
            "peak {peak} must be far below whole-bundle staging {whole}"
        );

        // Mutation control: the metric is SENSITIVE. A writer that staged every member up
        // front (the whole-bundle-staging regression this proof guards against) drives the
        // SAME metric to `whole` — so the assertions above would go RED under that mutation.
        for f in std::fs::read_dir(&stage_dir).unwrap() {
            let _ = std::fs::remove_file(f.unwrap().path());
        }
        let mut mutant_peak: u64 = 0;
        for i in 0..N {
            let tmp = stage_dir.join(format!("all{i}"));
            std::fs::write(&tmp, vec![0u8; MEMBER]).unwrap();
            mutant_peak = mutant_peak.max(staged_bytes(&stage_dir));
        }
        assert_eq!(
            mutant_peak, whole,
            "whole-bundle-staging mutation drives the metric to the full bundle"
        );
        assert!(
            mutant_peak > largest + 4096,
            "so the bounded-staging assertion above is genuinely RED under that mutation"
        );
    }
}
