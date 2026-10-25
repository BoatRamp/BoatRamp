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

/// The control-plane KV **delta** slice's member path (a DELTA bundle only — the
/// `boatramp_core::project_delta::encode_kv_delta` bytes: upserts + tombstones).
pub const KV_DELTA_MEMBER_PATH: &str = "kv.brkvdelta";

/// The blob **tombstone** list's member path (a DELTA bundle only — the
/// `boatramp_core::project_delta::encode_blob_tombstones` bytes).
pub const BLOB_TOMBSTONE_MEMBER_PATH: &str = "blobs.brtombstones";

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
    /// A control-plane KV **delta** slice (`kv.brkvdelta`) — present only in a DELTA bundle: the
    /// changed/new KV upserts + the deleted-key tombstones since the base (the
    /// `boatramp_core::project_delta` framing). Replaces the full `Kv` member in a delta.
    KvDelta,
    /// A blob **tombstone** list (`blobs.brtombstones`) — present only in a DELTA bundle: the blob
    /// keys deleted since the base (deletes-as-tombstones). The blobs that were ADDED/CHANGED ride
    /// as ordinary `Blob` members (adds-as-full-members).
    BlobTombstone,
    /// A Postgres logical-WAL **delta** (`sql/<db>.pgwal`) — present only in a TRUE-delta bundle: the
    /// decoded change stream since the member's `sql_cursor` LSN, replayed onto the restored base.
    /// (SQL true-delta program; replaces the full `PgDump` member for that DB when a true-delta was
    /// captured.)
    PgWalDelta,
    /// A MySQL binlog **delta** (`sql/<db>.mysqlbinlog`) — the binlog events since the member's
    /// `sql_cursor` GTID, replayed onto the restored base.
    MysqlBinlogDelta,
    /// A libsql/SQLite **changeset** (`libsql/<project>/<site>/<db>.changeset`) — the row-level
    /// changeset diffed against the base snapshot named by the member's `sql_cursor`, applied onto
    /// the restored base.
    LibsqlChangeset,
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
    /// The base CURSOR for a TRUE-delta SQL member (`PgWalDelta`/`MysqlBinlogDelta`/
    /// `LibsqlChangeset`) — the point the delta was captured since, so restore replays from there.
    /// `None` for every other member (incl. a full-dump SQL member in the all-families fallback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_cursor: Option<boatramp_core::project_delta::SqlMemberCursor>,
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
            // The v1 whole-staging path never emits a true-delta member (those flow through the
            // v3 streaming writer via `MemberSpec::with_sql_cursor`), so no cursor here.
            sql_cursor: None,
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

// ============================================================================
// Format v3 — chunked members with a TRAILING trailer (inc2)
//
// v2 removed the whole-bundle-staging coupling (each member's size+SHA moved to a per-member
// leading `.brmeta` sidecar), but a member still had to be STAGED WHOLE to a temp before its
// sidecar could be written (the sidecar carries the size+SHA, computed by reading the staged
// temp). For an engine dump that can be many GB — a `pg_dump`/`.dump` SQL stream — that whole
// member landed on `work_dir`, which is the env-clone disk-fill risk v2 only halved.
//
// v3 adds a SECOND framing, `ChunkedTrailer`, for the large/streamed kinds. Instead of a
// leading sidecar + a single body entry, a chunked member is a run of fixed-size `.part{N}`
// tar entries followed by a `.brtrailer` (the size+SHA, AFTER the data). The producer hashes +
// counts WHILE streaming each chunk out (no stat, no whole-member temp); the reader hashes +
// counts WHILE reading, comparing to the trailer at the end — O(chunk) on BOTH sides. Small
// kinds (Identity, Kv, small blobs) stay `Sidecar` (keeping v2's verify-before-apply free).
//
// Read-compat is total: the v3 reader [`read_bundle_streaming_atomic`] reads v1, v2 AND v3; a
// v2 manifest (no `framing` field) deserializes with `framing = Sidecar` via `#[serde(default)]`.
// Write-forward: the driver emits v3 ONLY when at least one member is chunked (else v2, so a
// bundle an inc1 node can still read stays v2); an inc1 node handed a v3 bundle loud-rejects it
// as [`BundleError::BadVersion`] (the v1/v2 reader's final dispatch arm), never a silent misread.
// ============================================================================

/// The **chunked** bundle format version (see the section comment above). Emitted when at least
/// one member uses [`MemberFraming::ChunkedTrailer`]; a v3 reader reads v1 + v2 + v3.
pub const BUNDLE_FORMAT_VERSION_V3: u32 = 3;

/// The suffix of a chunked member's TRAILING trailer entry. For a chunked member at `<path>`, its
/// trailer is `<path>.brtrailer` — a tiny JSON [`MemberTrailer`] (size + SHA-256) written AFTER
/// the member's `.part{N}` chunks, so the reader verifies integrity once the whole member has
/// streamed (the chunked analogue of the v2 leading [`MemberMeta`] sidecar).
pub const TRAILER_SUFFIX: &str = ".brtrailer";

/// The infix of a chunked member's data-part tar entries. Chunk `N` of a member at `<path>` is the
/// entry `<path>.part{N:05}` (zero-padded, monotonic from `00000`).
pub const PART_INFIX: &str = ".part";

/// The tar-entry path of chunk `n` of a chunked member at `base`.
fn chunk_part_path(base: &str, n: u32) -> String {
    format!("{base}{PART_INFIX}{n:05}")
}

/// The tar-entry path of a chunked member's trailer.
fn chunk_trailer_path(base: &str) -> String {
    format!("{base}{TRAILER_SUFFIX}")
}

/// How a bundle member's bytes are framed in the tar. `Sidecar` (the default, and the only v2
/// framing) is a leading [`MemberMeta`] `.brmeta` then a single body entry; `ChunkedTrailer` is a
/// run of `.part{N}` entries then a trailing [`MemberTrailer`] `.brtrailer` (v3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberFraming {
    /// Leading `.brmeta` sidecar + one body entry (v2 shape). The default, so a v2 manifest with
    /// no `framing` field deserializes to this.
    #[default]
    Sidecar,
    /// A run of `.part{N:05}` data entries + a trailing `.brtrailer` (v3 shape) — O(chunk) both
    /// sides, for the large/streamed kinds (SQL dumps, large blobs).
    ChunkedTrailer,
}

impl MemberFraming {
    /// Whether this is the default [`Sidecar`](Self::Sidecar) framing (used by
    /// `skip_serializing_if` so a v2/sidecar manifest stays byte-identical to the pre-v3 form).
    fn is_sidecar(&self) -> bool {
        matches!(self, MemberFraming::Sidecar)
    }
}

/// The upfront-knowable identity of a bundle member — what the v2/v3 MANIFEST lists, in restore
/// order. Carries no size/SHA (those travel in the member's [`MemberMeta`] sidecar or
/// [`MemberTrailer`]), so the MANIFEST can be written before any member is produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSpec {
    /// The member's tar-entry path (relative, no traversal).
    pub path: String,
    /// Which engine produced it.
    pub kind: MemberKind,
    /// How the member's bytes are framed (v3). Absent in a v2 manifest ⇒ [`MemberFraming::Sidecar`]
    /// (`#[serde(default)]`), which is what makes a v2 bundle deserialize into a v3 reader for free;
    /// a `Sidecar` member is omitted from a serialized manifest (`skip_serializing_if`) so a
    /// no-chunked (v2) bundle's manifest is byte-identical to the pre-v3 form.
    #[serde(default, skip_serializing_if = "MemberFraming::is_sidecar")]
    pub framing: MemberFraming,
    /// Postgres/MySQL provenance (only for `PgDump`/`MysqlDump` members).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pg: Option<PgMemberInfo>,
    /// The base CURSOR for a TRUE-delta SQL member (see [`ManifestMember::sql_cursor`]); `None` for
    /// every full member. Carried here too so the MANIFEST (written before members are produced)
    /// already declares the replay point a reader will need.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sql_cursor: Option<boatramp_core::project_delta::SqlMemberCursor>,
}

impl MemberSpec {
    /// A `Sidecar`-framed member spec (the common case; v2 shape).
    pub fn sidecar(path: String, kind: MemberKind, pg: Option<PgMemberInfo>) -> Self {
        Self {
            path,
            kind,
            framing: MemberFraming::Sidecar,
            pg,
            sql_cursor: None,
        }
    }

    /// A `ChunkedTrailer`-framed member spec (a large/streamed member; v3 shape).
    pub fn chunked(path: String, kind: MemberKind, pg: Option<PgMemberInfo>) -> Self {
        Self {
            path,
            kind,
            framing: MemberFraming::ChunkedTrailer,
            pg,
            sql_cursor: None,
        }
    }

    /// Attach a TRUE-delta base cursor to this member spec (builder; used by the SQL true-delta
    /// capture when it emits a `PgWalDelta`/`MysqlBinlogDelta`/`LibsqlChangeset` member).
    #[must_use]
    pub fn with_sql_cursor(
        mut self,
        cursor: boatramp_core::project_delta::SqlMemberCursor,
    ) -> Self {
        self.sql_cursor = Some(cursor);
        self
    }
}

/// A chunked member's `.brtrailer`: the size + SHA-256 of the whole member, written AFTER its
/// `.part{N}` chunks so a streaming producer need never stat or buffer the member (the chunked
/// analogue of the v2 leading [`MemberMeta`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberTrailer {
    /// The member's exact byte length (sum of all `.part{N}` chunk bytes).
    pub size: u64,
    /// Hex SHA-256 of the member bytes — verified against the streamed bytes as the trailer is read.
    pub sha256: String,
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
    /// DELTA bundle metadata (the mode + base/parent reference). Absent ⇒ an ordinary FULL bundle
    /// (so a v2/v3 full manifest round-trips byte-identically — `skip_serializing_if`), present ⇒
    /// the restore resolves the base chain and applies this bundle's per-family deltas onto it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<boatramp_core::project_delta::DeltaInfo>,
}

impl StreamManifest {
    /// Loud-reject a foreign or wrong-version bundle (magic + version MUST be v2 or v3). The one
    /// `StreamManifest` struct serves both the v2 (sidecar-only) and v3 (some chunked) forms — a
    /// v3 manifest differs only in `format_version = 3` and a `framing` field on its chunked
    /// members (absent ⇒ `Sidecar`), so a v2 manifest validates and round-trips unchanged.
    fn validate(&self) -> Result<(), BundleError> {
        if self.magic != BUNDLE_MAGIC {
            return Err(BundleError::BadMagic {
                expected: BUNDLE_MAGIC.to_string(),
                found: self.magic.clone(),
            });
        }
        if self.format_version != BUNDLE_FORMAT_VERSION_V2
            && self.format_version != BUNDLE_FORMAT_VERSION_V3
        {
            return Err(BundleError::BadVersion {
                found: self.format_version,
                supported: BUNDLE_FORMAT_VERSION_V3,
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
    /// Begin a streamable bundle on `out`, writing the MANIFEST (the ordered member list) first.
    /// `specs` is every member in restore order; each must then be supplied, in that order, via
    /// [`append_member`](Self::append_member) (Sidecar framing) or
    /// [`append_member_chunked`](Self::append_member_chunked) (ChunkedTrailer framing) to match
    /// the spec's declared framing, and the bundle closed with [`finish`](Self::finish). The
    /// MANIFEST declares [`BUNDLE_FORMAT_VERSION_V3`] when ANY member is chunked, else
    /// [`BUNDLE_FORMAT_VERSION_V2`] — so a bundle with no chunked member is byte-identical to the
    /// pre-v3 v2 form (an inc1 node can still read it).
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
        let format_version = if specs
            .iter()
            .any(|s| s.framing == MemberFraming::ChunkedTrailer)
        {
            BUNDLE_FORMAT_VERSION_V3
        } else {
            BUNDLE_FORMAT_VERSION_V2
        };
        let manifest = StreamManifest {
            magic: BUNDLE_MAGIC.to_string(),
            format_version,
            created_at,
            data_only,
            source,
            members: specs.clone(),
            // The forward-only streaming writer never emits a delta bundle (a delta needs a
            // re-readable base ⇒ the resumable member-object target only).
            delta: None,
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

    /// Pop + validate the next declared member, asserting it matches `(path, kind, framing)` — the
    /// shared front of [`append_member`](Self::append_member) and
    /// [`append_member_chunked`](Self::append_member_chunked). An out-of-order, unexpected, or
    /// wrong-framing append is refused loud.
    fn next_expected(
        &mut self,
        path: &str,
        kind: MemberKind,
        framing: MemberFraming,
    ) -> Result<(), BundleError> {
        let expected = self.remaining.pop_front().ok_or_else(|| {
            BundleError::MalformedStream(format!(
                "append of {path:?} but the MANIFEST declared no more members"
            ))
        })?;
        if expected.path != path || expected.kind != kind || expected.framing != framing {
            return Err(BundleError::MalformedStream(format!(
                "append of ({path:?}, {kind:?}, {framing:?}) does not match the next declared \
                 member ({:?}, {:?}, {:?})",
                expected.path, expected.kind, expected.framing
            )));
        }
        validate_member_path(path)
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
        self.next_expected(path, kind, MemberFraming::Sidecar)?;

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

    /// Append the next member as a run of `chunk_size`-byte `.part{N}` tar entries followed by a
    /// `.brtrailer` ([`MemberTrailer`]: size + SHA-256). Streams `body` through, hashing + counting
    /// WHILE writing each chunk — it NEVER stats or buffers the whole member (at most one
    /// `chunk_size` buffer lives at a time), so a producer that yields a `&mut dyn Read` over an
    /// engine dump (the libsql `.dump` stream, `pg_dump` stdout) is written in O(chunk) disk +
    /// memory. The `path`/`kind` MUST match the next declared member AND its framing MUST be
    /// [`MemberFraming::ChunkedTrailer`] — an out-of-order, unexpected, or wrong-framing append is
    /// refused loud. `chunk_size` must be non-zero.
    pub fn append_member_chunked(
        &mut self,
        path: &str,
        kind: MemberKind,
        body: &mut dyn Read,
        chunk_size: usize,
    ) -> Result<(), BundleError> {
        self.next_expected(path, kind, MemberFraming::ChunkedTrailer)?;
        let chunk_size = chunk_size.max(1);

        let mut hasher = Sha256::new();
        let mut total = 0u64;
        let mut part: u32 = 0;
        let mut buf = vec![0u8; chunk_size];
        loop {
            // Fill a whole chunk buffer (a single `read` may short-read), so every `.part{N}` but
            // the last is exactly `chunk_size` — a stable, predictable chunking the reader asserts.
            let mut filled = 0usize;
            while filled < chunk_size {
                let n = body.read(&mut buf[filled..])?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break; // clean EOF on a chunk boundary — no trailing empty part
            }
            hasher.update(&buf[..filled]);
            total += filled as u64;
            let mut header = tar::Header::new_gnu();
            header.set_size(filled as u64);
            header.set_mode(0o600);
            header.set_mtime(self.created_at);
            self.builder
                .append_data(&mut header, chunk_part_path(path, part), &buf[..filled])?;
            part = part.checked_add(1).ok_or_else(|| {
                BundleError::MalformedStream(format!("chunked member {path:?} exceeded 2^32 parts"))
            })?;
            if filled < chunk_size {
                break; // short final chunk ⇒ EOF
            }
        }

        // The TRAILING trailer: size + SHA-256 of the whole streamed member, AFTER the chunks.
        let trailer = MemberTrailer {
            size: total,
            sha256: hex::encode(hasher.finalize()),
        };
        let trailer_json = serde_json::to_vec(&trailer)?;
        append_bytes(
            &mut self.builder,
            &chunk_trailer_path(path),
            self.created_at,
            &trailer_json,
        )?;
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

/// Stream a v3-capable bundle to `out`, dispatching each member by its [`MemberFraming`] — the
/// chunked-aware superset of [`write_bundle_streaming`] the export driver uses. For a `Sidecar`
/// member, `stage(spec)` stages it to a bounded temp (returned path), which is appended then
/// deleted (the inc1 O(largest-member) footprint, unchanged); for a `ChunkedTrailer` member,
/// `open(spec)` yields a `Box<dyn Read>` over the member's bytes (an engine dump stream) that is
/// piped STRAIGHT through [`append_member_chunked`](BundleStreamWriter::append_member_chunked) in
/// `chunk_size` pieces — NO temp, O(chunk) disk + memory. The MANIFEST is v3 iff any member is
/// chunked (else v2 — see [`BundleStreamWriter::new`]).
#[allow(clippy::too_many_arguments)] // the bundle head (created_at/data_only/source) + both
// producers + chunk_size are each load-bearing; grouping them into a struct would only hide them.
pub fn write_bundle_streaming_v3<W, S, O>(
    out: W,
    created_at: u64,
    data_only: bool,
    source: SourceInfo,
    specs: Vec<MemberSpec>,
    chunk_size: usize,
    mut stage: S,
    mut open: O,
) -> Result<(), BundleError>
where
    W: Write,
    S: FnMut(&MemberSpec) -> Result<PathBuf, BundleError>,
    O: FnMut(&MemberSpec) -> Result<Box<dyn Read>, BundleError>,
{
    let mut writer = BundleStreamWriter::new(out, created_at, data_only, source, specs.clone())?;
    for spec in &specs {
        match spec.framing {
            MemberFraming::Sidecar => {
                let tmp = stage(spec)?;
                let appended = writer.append_member(&spec.path, spec.kind, &tmp);
                let _ = std::fs::remove_file(&tmp);
                appended?;
            }
            MemberFraming::ChunkedTrailer => {
                let mut body = open(spec)?;
                writer.append_member_chunked(&spec.path, spec.kind, body.as_mut(), chunk_size)?;
            }
        }
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
fn verify_member<F>(
    body: &mut dyn Read,
    spec: &MemberSpec,
    expected_size: u64,
    expected_sha: &str,
    restore: &mut F,
) -> Result<(), BundleError>
where
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

/// VERIFY-THEN-APPLY one member: stream `body` into a bounded temp under `stage_dir` while
/// hashing + counting, VERIFY the staged temp's size + SHA-256 against the declared values
/// FIRST, and only then hand the verified temp to `restore(spec, &temp)`. The temp is deleted
/// after `restore` returns (or on a verification failure) — so a corrupt/truncated/tampered
/// member is rejected before any restore applies it (closing the apply-then-verify window of
/// the plain streaming reader), while staying O(largest member) on disk.
fn stage_and_verify_member<F>(
    body: &mut dyn Read,
    spec: &MemberSpec,
    expected_size: u64,
    expected_sha: &str,
    stage_dir: &Path,
    counter: &mut u64,
    restore: &mut F,
) -> Result<(), BundleError>
where
    F: FnMut(&MemberSpec, &Path) -> Result<(), BundleError>,
{
    let temp = stage_dir.join(format!("brimport-{counter}"));
    *counter += 1;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    {
        let mut f = io::BufWriter::new(std::fs::File::create(&temp)?);
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = body.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            total += n as u64;
            f.write_all(&buf[..n])?;
        }
        f.flush()?;
    }
    let sha = hex::encode(hasher.finalize());
    if total != expected_size {
        let _ = std::fs::remove_file(&temp);
        return Err(BundleError::SizeMismatch {
            path: spec.path.clone(),
            expected: expected_size,
            actual: total,
        });
    }
    if sha != expected_sha {
        let _ = std::fs::remove_file(&temp);
        return Err(BundleError::ChecksumMismatch {
            path: spec.path.clone(),
            expected: expected_sha.to_string(),
            actual: sha,
        });
    }
    // Verified — NOW apply the staged temp, then free it.
    let r = restore(spec, &temp);
    let _ = std::fs::remove_file(&temp);
    r
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
pub fn read_bundle_streaming<R, F>(src: R, restore: F) -> Result<Vec<MemberSpec>, BundleError>
where
    R: Read,
    F: FnMut(&MemberSpec, u64, &mut dyn Read) -> Result<(), BundleError>,
{
    read_bundle_streaming_with_head(src, |_data_only, _source| {}, restore)
}

/// Like [`read_bundle_streaming`], but also surfaces the bundle HEAD — the `data_only` flag
/// and the [`SourceInfo`] — via `on_head`, called ONCE after the MANIFEST is parsed and
/// validated, BEFORE any member is handed to `restore`. The import driver needs both ahead
/// of the first member (to re-key each member to the TARGET project, and to branch the
/// data-only vs full restore), and the v2 MANIFEST (like the v1 one) carries them before any
/// member — so a single forward pass can learn them up front. Reads both v2 and v1 bundles,
/// exactly as [`read_bundle_streaming`] does.
pub fn read_bundle_streaming_with_head<R, H, F>(
    src: R,
    on_head: H,
    mut restore: F,
) -> Result<Vec<MemberSpec>, BundleError>
where
    R: Read,
    H: FnMut(bool, &SourceInfo),
    F: FnMut(&MemberSpec, u64, &mut dyn Read) -> Result<(), BundleError>,
{
    read_bundle_core(src, on_head, |spec, size, sha, body| {
        verify_member(body, spec, size, sha, &mut restore)
    })
}

/// VERIFY-THEN-APPLY single-pass reader: like [`read_bundle_streaming_with_head`] but each
/// member is staged to a bounded temp under `stage_dir` and its size + SHA-256 are VERIFIED
/// from that temp BEFORE `restore(spec, &verified_temp)` is called (and the temp is freed
/// after). This closes the apply-then-verify window — a corrupt/tampered member is rejected
/// before it is applied — while keeping staging bounded to the largest single member. Reads v1
/// and v2 bundles. NOTE: this is the inc1 staged reader — it verifies-then-applies but does NOT
/// own per-member rollback, so an import aborted mid-stream may have applied EARLIER members.
/// inc2's [`read_bundle_streaming_atomic`] adds the atomic shadow-restore (a FULL managed-DB
/// member is swapped in only after its trailing SHA verifies, so a bad DB member applies NOTHING
/// to live — per-member all-or-nothing); even there, the bundle is not whole-bundle atomic (the
/// cross-member window) and a `--data-only` DB member keeps this non-atomic sidecar path.
pub fn read_bundle_streaming_staged<R, H, F>(
    src: R,
    stage_dir: &Path,
    on_head: H,
    mut restore: F,
) -> Result<Vec<MemberSpec>, BundleError>
where
    R: Read,
    H: FnMut(bool, &SourceInfo),
    F: FnMut(&MemberSpec, &Path) -> Result<(), BundleError>,
{
    let mut counter = 0u64;
    read_bundle_core(src, on_head, |spec, size, sha, body| {
        stage_and_verify_member(body, spec, size, sha, stage_dir, &mut counter, &mut restore)
    })
}

/// The shared single-forward-pass bundle parse (v1 + v2) behind
/// [`read_bundle_streaming_with_head`] and [`read_bundle_streaming_staged`]. Peeks the MANIFEST
/// version, calls `on_head(data_only, source)` once, then for each member calls
/// `per_member(spec, size, sha, body)` — where `size`/`sha` are the member's declared integrity
/// values (inline v1 manifest / v2 sidecar) and `body` is the raw member reader. Enforces the
/// v2 declared order + sidecar pairing and the v1 manifest completeness, exactly as before.
fn read_bundle_core<R, H, M>(
    src: R,
    mut on_head: H,
    mut per_member: M,
) -> Result<Vec<MemberSpec>, BundleError>
where
    R: Read,
    H: FnMut(bool, &SourceInfo),
    M: FnMut(&MemberSpec, u64, &str, &mut dyn Read) -> Result<(), BundleError>,
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
        on_head(manifest.data_only, &manifest.source);
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
            let spec = MemberSpec::sidecar(mm.path.clone(), mm.kind, mm.pg.clone());
            per_member(&spec, mm.size, &mm.sha256, &mut entry)?;
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
        on_head(manifest.data_only, &manifest.source);
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
            per_member(spec, meta.size, &meta.sha256, &mut entry)?;
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

/// The restore policy the v3-capable single-pass reader [`read_bundle_streaming_atomic`] drives,
/// one method per member shape. The format layer owns the PARSE + the per-member integrity VERIFY;
/// the implementor (the import driver) owns the APPLY (where a member is re-keyed to the target,
/// scope-enforced, and committed) — so a chunked member and a sidecar member of the same kind route
/// through the SAME driver re-key/enforce, framing being a transport detail, never a tenancy bypass.
///
/// A `Sidecar` member arrives fully staged + size/SHA-VERIFIED at a bounded temp
/// ([`restore_sidecar`](Self::restore_sidecar)) — verify-THEN-apply, exactly as the v2 staged
/// reader. A `ChunkedTrailer` member streams: [`begin_chunked`](Self::begin_chunked) opens the sink
/// (a shadow DB / a staging temp / a blob put), [`write_chunk`](Self::write_chunk) feeds each chunk
/// as it arrives (the reader hashes + counts), and [`finish_chunked`](Self::finish_chunked) is told
/// whether the TRAILING trailer matched — COMMIT the sink only on `verified`, else DROP it, so a
/// corrupt/truncated/tampered chunked member applies NOTHING to live (the inc2 atomic shadow).
pub trait BundleRestorer {
    /// Apply a `Sidecar` member already staged + verified at `temp` (freed by the reader after
    /// this returns).
    fn restore_sidecar(&mut self, spec: &MemberSpec, temp: &Path) -> Result<(), BundleError>;
    /// Open the sink for a `ChunkedTrailer` member, before its first chunk (e.g. create the shadow
    /// DB / the staging temp). A failure here aborts the import before any byte is applied.
    fn begin_chunked(&mut self, spec: &MemberSpec) -> Result<(), BundleError>;
    /// Feed the next slice of a chunked member's bytes to the open sink (called repeatedly, in
    /// order, for each chunk the reader streams).
    fn write_chunk(&mut self, spec: &MemberSpec, buf: &[u8]) -> Result<(), BundleError>;
    /// Finish a chunked member: `verified` is whether the streamed bytes matched the trailer's
    /// size + SHA-256. COMMIT-swap the sink on `true`; DROP it (nothing applied to live) on `false`.
    fn finish_chunked(&mut self, spec: &MemberSpec, verified: bool) -> Result<(), BundleError>;
}

/// The **v3-capable atomic single-pass reader** — the inc2 superset of
/// [`read_bundle_streaming_staged`]. Reads v1, v2 AND v3 bundles in one forward pass, dispatching
/// each member to `restorer` by its [`MemberFraming`]: a `Sidecar` member is staged to a bounded
/// temp under `stage_dir` and size/SHA-VERIFIED BEFORE [`restore_sidecar`](BundleRestorer::restore_sidecar)
/// (verify-then-apply, unchanged from v2); a `ChunkedTrailer` member streams chunk-by-chunk through
/// [`begin_chunked`](BundleRestorer::begin_chunked) / [`write_chunk`](BundleRestorer::write_chunk)
/// (the reader hashing + counting, NEVER staging the whole member) and is committed by
/// [`finish_chunked`](BundleRestorer::finish_chunked) ONLY when the TRAILING trailer matched — so a
/// corrupt/truncated chunked member applies nothing (atomic). `on_head(data_only, source)` fires
/// once after the MANIFEST, before any member. Enforces the v2/v3 declared order + per-member
/// framing + the v1 completeness, exactly as [`read_bundle_core`].
pub fn read_bundle_streaming_atomic<R, H>(
    src: R,
    stage_dir: &Path,
    mut on_head: H,
    restorer: &mut dyn BundleRestorer,
) -> Result<Vec<MemberSpec>, BundleError>
where
    R: Read,
    H: FnMut(bool, &SourceInfo),
{
    let mut ar = tar::Archive::new(src);
    let mut entries = ar.entries()?;

    // 1. The MANIFEST (first entry), peeked for its version.
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
    let mut counter = 0u64;
    let mut restored: Vec<MemberSpec> = Vec::new();

    if version == BUNDLE_FORMAT_VERSION {
        // --- v1: inline size/SHA in the manifest; members matched by path (any order), all
        //     Sidecar-framed (v1 predates chunking). ---
        let manifest: Manifest = serde_json::from_str(&manifest_json)?;
        manifest.validate()?;
        on_head(manifest.data_only, &manifest.source);
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
            let spec = MemberSpec::sidecar(mm.path.clone(), mm.kind, mm.pg.clone());
            stage_and_verify_member(
                &mut entry,
                &spec,
                mm.size,
                &mm.sha256,
                stage_dir,
                &mut counter,
                &mut |s, t| restorer.restore_sidecar(s, t),
            )?;
            seen.insert(path);
            restored.push(spec);
        }
        for m in &manifest.members {
            if !seen.contains(&m.path) {
                return Err(BundleError::MissingMember(m.path.clone()));
            }
        }
    } else if version == BUNDLE_FORMAT_VERSION_V2 || version == BUNDLE_FORMAT_VERSION_V3 {
        // --- v2/v3: the MANIFEST lists members in restore order; each is consumed per its framing
        //     (Sidecar = `.brmeta` + body; ChunkedTrailer = `.part{N}` run + `.brtrailer`). ---
        let manifest: StreamManifest = serde_json::from_str(&manifest_json)?;
        manifest.validate()?;
        on_head(manifest.data_only, &manifest.source);
        for spec in manifest.members {
            match spec.framing {
                MemberFraming::Sidecar => {
                    // The sidecar `<path>.brmeta` must come first, then the `<path>` body.
                    let mut meta_entry = entries
                        .next()
                        .ok_or_else(|| BundleError::MissingMember(spec.path.clone()))??;
                    let mpath = meta_entry.path()?.to_string_lossy().into_owned();
                    let stripped = mpath.strip_suffix(META_SUFFIX).ok_or_else(|| {
                        BundleError::MalformedStream(format!(
                            "expected sidecar {:?} for member {:?}, found {mpath:?}",
                            StreamManifest::meta_path(&spec.path),
                            spec.path
                        ))
                    })?;
                    if stripped != spec.path {
                        return Err(BundleError::MalformedStream(format!(
                            "sidecar {mpath:?} does not match the declared member {:?}",
                            spec.path
                        )));
                    }
                    let mut mbuf = String::new();
                    meta_entry.read_to_string(&mut mbuf)?;
                    let meta: MemberMeta = serde_json::from_str(&mbuf)?;

                    let mut body_entry = entries
                        .next()
                        .ok_or_else(|| BundleError::MissingMember(spec.path.clone()))??;
                    let bpath = body_entry.path()?.to_string_lossy().into_owned();
                    validate_member_path(&bpath)?;
                    if bpath != spec.path {
                        return Err(BundleError::MalformedStream(format!(
                            "member {bpath:?} out of declared order (MANIFEST expected {:?})",
                            spec.path
                        )));
                    }
                    stage_and_verify_member(
                        &mut body_entry,
                        &spec,
                        meta.size,
                        &meta.sha256,
                        stage_dir,
                        &mut counter,
                        &mut |s, t| restorer.restore_sidecar(s, t),
                    )?;
                    restored.push(spec);
                }
                MemberFraming::ChunkedTrailer => {
                    read_chunked_member(&mut entries, &spec, restorer)?;
                    restored.push(spec);
                }
            }
        }
        // No tar entry may remain past the last declared member.
        if let Some(extra) = entries.next() {
            let extra = extra?;
            let path = extra.path()?.to_string_lossy().into_owned();
            return Err(BundleError::UnexpectedMember(path));
        }
    } else {
        return Err(BundleError::BadVersion {
            found: version,
            supported: BUNDLE_FORMAT_VERSION_V3,
        });
    }
    Ok(restored)
}

/// Consume one `ChunkedTrailer` member from `entries`: `begin_chunked`, stream each
/// `<path>.part{N:05}` (monotonic from `00000`) through `write_chunk` while hashing + counting,
/// then VERIFY the streamed size + SHA-256 against the `<path>.brtrailer` and `finish_chunked`
/// (commit on match, drop on mismatch). Any parse/order/IO failure drops the sink (abort) and
/// propagates, so a corrupt/truncated chunked member applies nothing to live.
fn read_chunked_member<R: Read>(
    entries: &mut tar::Entries<'_, R>,
    spec: &MemberSpec,
    restorer: &mut dyn BundleRestorer,
) -> Result<(), BundleError> {
    restorer.begin_chunked(spec)?;
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut next_part: u32 = 0;
    // The trailer we expect to find after the last part; `None` until seen.
    let mut outcome: Result<MemberTrailer, BundleError> =
        Err(BundleError::MalformedStream(format!(
            "chunked member {:?} ended before its {TRAILER_SUFFIX} trailer",
            spec.path
        )));
    loop {
        let entry = match entries.next() {
            Some(Ok(e)) => e,
            Some(Err(e)) => {
                outcome = Err(BundleError::Io(e));
                break;
            }
            None => break, // outcome stays "ended before trailer"
        };
        let mut entry = entry;
        let epath = match entry.path() {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(e) => {
                outcome = Err(BundleError::Io(e));
                break;
            }
        };
        if let Some(stripped) = epath.strip_suffix(TRAILER_SUFFIX) {
            if stripped != spec.path {
                outcome = Err(BundleError::MalformedStream(format!(
                    "trailer {epath:?} does not match the chunked member {:?}",
                    spec.path
                )));
                break;
            }
            let mut tbuf = String::new();
            if let Err(e) = entry.read_to_string(&mut tbuf) {
                outcome = Err(BundleError::Io(e));
                break;
            }
            outcome = serde_json::from_str::<MemberTrailer>(&tbuf).map_err(BundleError::Json);
            break;
        }
        // Otherwise it must be the NEXT expected `.part{N}` (monotonic, matching the member path).
        let expected = chunk_part_path(&spec.path, next_part);
        if epath != expected {
            outcome = Err(BundleError::MalformedStream(format!(
                "chunked member {:?}: expected chunk {expected:?}, found {epath:?} \
                 (missing/out-of-order part or wrong member)",
                spec.path
            )));
            break;
        }
        // Stream this part's bytes to the sink, hashing + counting the whole member.
        let mut rbuf = [0u8; 64 * 1024];
        let part_res: Result<(), BundleError> = loop {
            match entry.read(&mut rbuf) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    hasher.update(&rbuf[..n]);
                    total += n as u64;
                    if let Err(e) = restorer.write_chunk(spec, &rbuf[..n]) {
                        break Err(e);
                    }
                }
                Err(e) => break Err(BundleError::Io(e)),
            }
        };
        if let Err(e) = part_res {
            outcome = Err(e);
            break;
        }
        next_part = match next_part.checked_add(1) {
            Some(v) => v,
            None => {
                outcome = Err(BundleError::MalformedStream(format!(
                    "chunked member {:?} exceeded 2^32 parts",
                    spec.path
                )));
                break;
            }
        };
    }
    match outcome {
        Ok(trailer) => {
            let actual = hex::encode(hasher.finalize());
            let verified = total == trailer.size && actual == trailer.sha256;
            // Tell the sink whether to commit or drop BEFORE raising a loud mismatch, so the
            // shadow is torn down on a bad member even as the error propagates.
            restorer.finish_chunked(spec, verified)?;
            if total != trailer.size {
                return Err(BundleError::SizeMismatch {
                    path: spec.path.clone(),
                    expected: trailer.size,
                    actual: total,
                });
            }
            if actual != trailer.sha256 {
                return Err(BundleError::ChecksumMismatch {
                    path: spec.path.clone(),
                    expected: trailer.sha256,
                    actual,
                });
            }
            Ok(())
        }
        Err(e) => {
            // Abort the sink (drop the shadow) on any streaming/parse failure, then surface it.
            let _ = restorer.finish_chunked(spec, false);
            Err(e)
        }
    }
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
                    sql_cursor: None,
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
                    framing: MemberFraming::Sidecar,
                    pg: None,
                    sql_cursor: None,
                },
                b"IDENTITY-KEK-TRANSPORT".to_vec(),
            ),
            (
                MemberSpec {
                    path: "blobs/acme/obj1".to_string(),
                    kind: MemberKind::Blob,
                    framing: MemberFraming::Sidecar,
                    pg: None,
                    sql_cursor: None,
                },
                vec![0xAB; 4096],
            ),
            (
                MemberSpec {
                    path: "sql/app.pgc".to_string(),
                    kind: MemberKind::PgDump,
                    framing: MemberFraming::Sidecar,
                    pg: Some(PgMemberInfo {
                        server_version_num: "160004".to_string(),
                        client_image: "pgvector/pgvector:pg16".to_string(),
                        schema_fingerprint: Some("deadbeef".to_string()),
                    }),
                    sql_cursor: None,
                },
                vec![7u8; 50_000],
            ),
            (
                MemberSpec {
                    path: KV_MEMBER_PATH.to_string(),
                    kind: MemberKind::Kv,
                    framing: MemberFraming::Sidecar,
                    pg: None,
                    sql_cursor: None,
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
                    framing: MemberFraming::Sidecar,
                    pg: None,
                    sql_cursor: None,
                }],
                delta: None,
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
                    framing: MemberFraming::Sidecar,
                    pg: None,
                    sql_cursor: None,
                }],
                delta: None,
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
                framing: MemberFraming::Sidecar,
                pg: None,
                sql_cursor: None,
            },
            MemberSpec {
                path: "b".to_string(),
                kind: MemberKind::Blob,
                framing: MemberFraming::Sidecar,
                pg: None,
                sql_cursor: None,
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
                framing: MemberFraming::Sidecar,
                pg: None,
                sql_cursor: None,
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

    #[test]
    fn read_bundle_streaming_staged_verifies_before_apply() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        // A tampered v2 bundle: the sidecar lies about the member's SHA. The STAGED reader must
        // reject it, and crucially must NOT call `restore` (apply) for the bad member — the
        // verify-THEN-apply guarantee (MEDIUM-1(b)).
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
                    framing: MemberFraming::Sidecar,
                    pg: None,
                    sql_cursor: None,
                }],
                delta: None,
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
        let td = tempfile::tempdir().unwrap();
        let applied = AtomicUsize::new(0);
        let r = read_bundle_streaming_staged(
            buf.as_slice(),
            td.path(),
            |_d, _s| {},
            |_spec, _temp| {
                applied.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
        );
        assert!(
            matches!(r, Err(BundleError::ChecksumMismatch { .. })),
            "got {r:?}"
        );
        assert_eq!(
            applied.load(Ordering::SeqCst),
            0,
            "restore (apply) must NOT run for a member that fails verification"
        );

        // A clean v2 bundle: `restore` runs ONCE with the verified temp carrying the exact bytes.
        let stage = td.path().join("gen");
        std::fs::create_dir_all(&stage).unwrap();
        let mut good: Vec<u8> = Vec::new();
        write_bundle_streaming(
            &mut good,
            0,
            true,
            SourceInfo {
                project: "x".to_string(),
                site: None,
            },
            vec![MemberSpec {
                path: KV_MEMBER_PATH.to_string(),
                kind: MemberKind::Kv,
                framing: MemberFraming::Sidecar,
                pg: None,
                sql_cursor: None,
            }],
            |_s| {
                let p = stage.join("m");
                std::fs::write(&p, b"BRKVDUMP-OK").unwrap();
                Ok(p)
            },
        )
        .unwrap();
        let seen = std::cell::RefCell::new(Vec::new());
        read_bundle_streaming_staged(
            good.as_slice(),
            td.path(),
            |_d, _s| {},
            |spec, temp| {
                seen.borrow_mut()
                    .push((spec.path.clone(), std::fs::read(temp).unwrap()));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            seen.into_inner(),
            vec![("kv.brkvdump".to_string(), b"BRKVDUMP-OK".to_vec())],
            "a verified member is applied from its staged temp with the exact bytes"
        );
    }

    // ---- format v3 (chunked trailing-trailer members) -------------------------------------

    /// A `BundleRestorer` that records exactly what the reader drove: sidecar applies, and each
    /// chunked member's begin/write/finish — so a test can assert the commit-vs-drop decision and
    /// the reassembled bytes, and that a chunked body is delivered chunk-by-chunk (never staged
    /// whole by the format layer).
    #[derive(Default)]
    struct RecordingRestorer {
        sidecars: Vec<(MemberSpec, Vec<u8>)>,
        begins: Vec<String>,
        finishes: Vec<(String, bool)>,
        /// The in-flight chunked member's accumulated bytes (between begin and finish).
        cur: Option<Vec<u8>>,
        /// Committed chunked members: (spec, reassembled bytes) — only the `verified` ones.
        committed_chunked: Vec<(MemberSpec, Vec<u8>)>,
        /// The largest single `write_chunk` buffer seen (the format reader streams in ≤64 KiB
        /// reads, never the whole member — this stays tiny even for a multi-MiB member).
        max_write_buf: usize,
    }

    impl BundleRestorer for RecordingRestorer {
        fn restore_sidecar(&mut self, spec: &MemberSpec, temp: &Path) -> Result<(), BundleError> {
            self.sidecars.push((spec.clone(), std::fs::read(temp)?));
            Ok(())
        }
        fn begin_chunked(&mut self, spec: &MemberSpec) -> Result<(), BundleError> {
            self.begins.push(spec.path.clone());
            self.cur = Some(Vec::new());
            Ok(())
        }
        fn write_chunk(&mut self, _spec: &MemberSpec, buf: &[u8]) -> Result<(), BundleError> {
            self.max_write_buf = self.max_write_buf.max(buf.len());
            self.cur
                .as_mut()
                .expect("write_chunk between begin and finish")
                .extend_from_slice(buf);
            Ok(())
        }
        fn finish_chunked(&mut self, spec: &MemberSpec, verified: bool) -> Result<(), BundleError> {
            self.finishes.push((spec.path.clone(), verified));
            let bytes = self.cur.take().unwrap_or_default();
            if verified {
                self.committed_chunked.push((spec.clone(), bytes));
            }
            Ok(())
        }
    }

    /// Count the `.part*` tar entries of a chunked member in a raw bundle, and the max part size —
    /// the structural O(chunk) proof: a body > chunk_size is written as MULTIPLE bounded parts,
    /// never one whole-member entry (nor a temp).
    fn count_parts(bundle: &[u8], base: &str) -> (usize, u64) {
        let mut ar = tar::Archive::new(bundle);
        let mut n = 0usize;
        let mut max = 0u64;
        for e in ar.entries().unwrap() {
            let e = e.unwrap();
            let p = e.path().unwrap().to_string_lossy().into_owned();
            if p.starts_with(&format!("{base}{PART_INFIX}")) {
                n += 1;
                max = max.max(e.header().size().unwrap());
            }
        }
        (n, max)
    }

    #[test]
    fn v3_chunked_round_trips_with_bounded_part_staging() {
        // A chunked member whose body is 5× the chunk size → the writer emits 5 `.part` entries,
        // each ≤ chunk_size (NEVER one whole-member entry), and the atomic reader streams them
        // back chunk-by-chunk to a round-trip-exact reassembly, committing exactly once.
        const CHUNK: usize = 4096;
        let body: Vec<u8> = (0..CHUNK * 5).map(|i| (i % 251) as u8).collect();
        let specs = vec![
            MemberSpec::sidecar(KV_MEMBER_PATH.to_string(), MemberKind::Kv, None),
            MemberSpec::chunked(
                "libsql/acme/blog/default.sqlite".to_string(),
                MemberKind::Libsql,
                None,
            ),
        ];
        let td = tempfile::tempdir().unwrap();
        let kv_tmp = td.path().join("kv");
        std::fs::write(&kv_tmp, b"BRKVDUMP-KV").unwrap();

        let body_for_open = body.clone();
        let mut bundle: Vec<u8> = Vec::new();
        write_bundle_streaming_v3(
            &mut bundle,
            1_700_000_000,
            false,
            SourceInfo {
                project: "acme".to_string(),
                site: None,
            },
            specs.clone(),
            CHUNK,
            |_spec| Ok(kv_tmp.clone()),
            |_spec| Ok(Box::new(io::Cursor::new(body_for_open.clone())) as Box<dyn Read>),
        )
        .unwrap();

        // The bundle is v3 (a chunked member is present).
        assert_eq!(read_manifest_version(&bundle), BUNDLE_FORMAT_VERSION_V3);
        // Structural O(chunk) proof: 5 bounded parts, none larger than CHUNK.
        let (parts, max_part) = count_parts(&bundle, "libsql/acme/blog/default.sqlite");
        assert_eq!(parts, 5, "a 5×chunk body is written as 5 `.part` entries");
        assert!(
            max_part <= CHUNK as u64,
            "no part exceeds the chunk size (never a whole-member entry): {max_part}"
        );

        // Read it back through the atomic reader.
        let stage = td.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();
        let mut r = RecordingRestorer::default();
        let mut data_only = true;
        let restored =
            read_bundle_streaming_atomic(bundle.as_slice(), &stage, |d, _s| data_only = d, &mut r)
                .unwrap();

        assert!(!data_only);
        assert_eq!(restored, specs, "both members restored in declared order");
        // The KV sidecar applied once; the chunked member committed exactly once with verified.
        assert_eq!(r.sidecars.len(), 1);
        assert_eq!(r.sidecars[0].1, b"BRKVDUMP-KV");
        assert_eq!(
            r.begins,
            vec!["libsql/acme/blog/default.sqlite".to_string()]
        );
        assert_eq!(
            r.finishes,
            vec![("libsql/acme/blog/default.sqlite".to_string(), true)],
            "finish_chunked fired ONCE with verified=true (commit)"
        );
        assert_eq!(r.committed_chunked.len(), 1);
        assert_eq!(
            r.committed_chunked[0].1, body,
            "the chunked member round-trips byte-for-byte"
        );
        // The format layer NEVER handed the restorer the whole member at once (O(chunk) read).
        assert!(
            r.max_write_buf <= 64 * 1024,
            "reader streams in ≤64 KiB reads, never the whole member: {}",
            r.max_write_buf
        );

        // MUTATION (RED): a writer that wrote the whole member as ONE part (whole-member staging)
        // would make `parts == 1` and `max_part == CHUNK*5` — the two assertions above go RED.
    }

    #[test]
    fn v3_chunked_trailer_mismatch_aborts_and_never_commits() {
        // Hand-build a v3 bundle whose `.brtrailer` SHA lies — the atomic reader must raise a
        // ChecksumMismatch AND tell the sink to DROP (finish_chunked verified=false), never commit.
        let base = "libsql/acme/blog/default.sqlite";
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            let manifest = StreamManifest {
                magic: BUNDLE_MAGIC.to_string(),
                format_version: BUNDLE_FORMAT_VERSION_V3,
                created_at: 0,
                data_only: true,
                source: SourceInfo {
                    project: "acme".to_string(),
                    site: None,
                },
                members: vec![MemberSpec::chunked(
                    base.to_string(),
                    MemberKind::Libsql,
                    None,
                )],
                delta: None,
            };
            append_bytes(
                &mut b,
                MANIFEST_PATH,
                0,
                &serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            append_bytes(
                &mut b,
                &chunk_part_path(base, 0),
                0,
                b"the real member bytes",
            )
            .unwrap();
            let trailer = MemberTrailer {
                size: 21,
                sha256: "00".repeat(32), // deliberately wrong
            };
            append_bytes(
                &mut b,
                &chunk_trailer_path(base),
                0,
                &serde_json::to_vec(&trailer).unwrap(),
            )
            .unwrap();
            b.finish().unwrap();
        }
        let td = tempfile::tempdir().unwrap();
        let mut r = RecordingRestorer::default();
        let res = read_bundle_streaming_atomic(buf.as_slice(), td.path(), |_d, _s| {}, &mut r);
        assert!(
            matches!(res, Err(BundleError::ChecksumMismatch { .. })),
            "a lying trailer is a loud reject: {res:?}"
        );
        assert_eq!(
            r.finishes,
            vec![(base.to_string(), false)],
            "finish_chunked fired with verified=false (DROP the shadow); commit NEVER fired"
        );
        assert!(
            r.committed_chunked.is_empty(),
            "no chunked member is committed when the trailer mismatches"
        );
    }

    #[test]
    fn v3_chunked_truncation_before_trailer_aborts() {
        // A v3 bundle whose chunked member ends WITHOUT its `.brtrailer` (truncated) → the reader
        // raises MalformedStream and drops the sink (finish_chunked verified=false).
        let base = "libsql/acme/blog/default.sqlite";
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut b = tar::Builder::new(&mut buf);
            let manifest = StreamManifest {
                magic: BUNDLE_MAGIC.to_string(),
                format_version: BUNDLE_FORMAT_VERSION_V3,
                created_at: 0,
                data_only: true,
                source: SourceInfo {
                    project: "acme".to_string(),
                    site: None,
                },
                members: vec![MemberSpec::chunked(
                    base.to_string(),
                    MemberKind::Libsql,
                    None,
                )],
                delta: None,
            };
            append_bytes(
                &mut b,
                MANIFEST_PATH,
                0,
                &serde_json::to_vec(&manifest).unwrap(),
            )
            .unwrap();
            append_bytes(
                &mut b,
                &chunk_part_path(base, 0),
                0,
                b"a chunk but no trailer",
            )
            .unwrap();
            b.finish().unwrap(); // NO `.brtrailer`
        }
        let td = tempfile::tempdir().unwrap();
        let mut r = RecordingRestorer::default();
        let res = read_bundle_streaming_atomic(buf.as_slice(), td.path(), |_d, _s| {}, &mut r);
        assert!(
            matches!(res, Err(BundleError::MalformedStream(_))),
            "a truncated chunked member (no trailer) is rejected: {res:?}"
        );
        assert_eq!(
            r.finishes,
            vec![(base.to_string(), false)],
            "sink DROPPED on truncation"
        );
        assert!(r.committed_chunked.is_empty());
    }

    #[test]
    fn atomic_reader_reads_v1_and_v2_but_an_inc1_node_loud_rejects_v3() {
        // Read-compat: the v3 atomic reader reads a v1 AND a v2 bundle (all sidecar members).
        let td = tempfile::tempdir().unwrap();
        let stage = td.path().join("stage");
        std::fs::create_dir_all(&stage).unwrap();

        // v1 bundle via write_bundle.
        let kv = write_staging(&stage, "kv.bin", b"V1-KV");
        let v1 = td.path().join("v1.brproj");
        write_bundle(
            &v1,
            0,
            true,
            SourceInfo {
                project: "acme".to_string(),
                site: None,
            },
            &[StagedMember {
                path: KV_MEMBER_PATH.to_string(),
                kind: MemberKind::Kv,
                source: kv,
                pg: None,
            }],
        )
        .unwrap();
        let mut r1 = RecordingRestorer::default();
        read_bundle_streaming_atomic(
            io::BufReader::new(std::fs::File::open(&v1).unwrap()),
            &stage,
            |_d, _s| {},
            &mut r1,
        )
        .unwrap();
        assert_eq!(r1.sidecars.len(), 1);
        assert_eq!(r1.sidecars[0].1, b"V1-KV");

        // v2 bundle via write_bundle_streaming (all sidecar).
        let gendir = td.path().join("gen");
        std::fs::create_dir_all(&gendir).unwrap();
        let mut v2: Vec<u8> = Vec::new();
        write_bundle_streaming(
            &mut v2,
            0,
            true,
            SourceInfo {
                project: "acme".to_string(),
                site: None,
            },
            vec![MemberSpec::sidecar(
                KV_MEMBER_PATH.to_string(),
                MemberKind::Kv,
                None,
            )],
            |_s| {
                let p = gendir.join("m");
                std::fs::write(&p, b"V2-KV").unwrap();
                Ok(p)
            },
        )
        .unwrap();
        assert_eq!(read_manifest_version(&v2), BUNDLE_FORMAT_VERSION_V2);
        let mut r2 = RecordingRestorer::default();
        read_bundle_streaming_atomic(v2.as_slice(), &stage, |_d, _s| {}, &mut r2).unwrap();
        assert_eq!(r2.sidecars[0].1, b"V2-KV");

        // A v3 bundle (a chunked member) handed to the LEGACY v1/v2 reader → loud BadVersion
        // (an inc1 node never silently misreads a v3 bundle).
        let mut v3: Vec<u8> = Vec::new();
        write_bundle_streaming_v3(
            &mut v3,
            0,
            true,
            SourceInfo {
                project: "acme".to_string(),
                site: None,
            },
            vec![MemberSpec::chunked(
                "libsql/acme/blog/default.sqlite".to_string(),
                MemberKind::Libsql,
                None,
            )],
            16,
            |_s| unreachable!("no sidecar member"),
            |_s| Ok(Box::new(io::Cursor::new(b"hello v3 chunked".to_vec())) as Box<dyn Read>),
        )
        .unwrap();
        assert_eq!(read_manifest_version(&v3), BUNDLE_FORMAT_VERSION_V3);
        let legacy = read_bundle_streaming(v3.as_slice(), |_s, _sz, _b| Ok(()));
        assert!(
            matches!(legacy, Err(BundleError::BadVersion { found: 3, .. })),
            "the legacy v1/v2 reader loud-rejects a v3 bundle: {legacy:?}"
        );
    }

    /// Read the MANIFEST's `format_version` from a raw bundle (test helper).
    fn read_manifest_version(bundle: &[u8]) -> u32 {
        let mut ar = tar::Archive::new(bundle);
        let mut first = ar.entries().unwrap().next().unwrap().unwrap();
        let mut s = String::new();
        first.read_to_string(&mut s).unwrap();
        peek_format_version(&s).unwrap()
    }
}
