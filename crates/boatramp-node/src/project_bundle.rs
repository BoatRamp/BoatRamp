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
}
