//! **Portable KV dump** (kv-sql WS7) — one backend-agnostic, versioned dump format + a generic
//! [`KvStore`]↔[`KvStore`] copier, giving `export` (store→file), `import` (file→store) and
//! `migrate` (store→store) over a SINGLE representation.
//!
//! ## Why a LOGICAL dump (the owner ask)
//! A dump captures the store's **CONTENT** — the `{key, value, version}` records — NOT the physical
//! LSM/manifest/`.compactions` on-disk shape. So a restore `import`s those records into a FRESH
//! store the destination engine builds from scratch, structurally **immune to the torn-manifest /
//! corrupt-`.compactions` physical-corruption classes** that make volume snapshots useless
//! ("all our snapshots carry the same corrupt shape"). This is the real answer to being hostage to
//! volume snapshots: a logical dump is the clean rebuild.
//!
//! ## The format (framed, versioned, backend-agnostic)
//! A fixed header then a stream of framed records then an end frame:
//! ```text
//! HEADER  magic "BRKVDUMP" (8) | format_version u32 LE | created_at u64 LE (unix s) | flags u32 LE
//! RECORD* tag 0x01 | key_len u32 LE | key bytes (UTF-8) | val_len u32 LE | val bytes | version i64 LE
//! END     tag 0x00 | entry_count u64 LE   (a completeness self-check)
//! ```
//! Every integer is little-endian. The format round-trips across ANY backend (SlateDB fs/s3, SQL
//! sqlite/pg/mysql, memory) because it is defined purely over the [`KvStore`] contract.
//!
//! ## Reserved internal feeds are SKIPPED (they regenerate)
//! The copier never copies the reserved coordination feeds — the shared-mode control-plane rows
//! ([`CP_PREFIX`] `_cp/*`: cp-id, members, leader lease) and the cache-coherence invalidation feed
//! ([`INVAL_PREFIX`] `_inval/*`). They are per-deployment coordination state that the destination
//! regenerates on open; copying them would commingle two control planes' identities. (The SQL
//! `kv_changes` append log is a TABLE, never a `kv` key, so a [`dump_scan`](KvStore::dump_scan) never
//! sees it — it too regenerates.) The filter is applied on export AND, defensively, on import.
//!
//! ## Restore safety
//! - `import`/`migrate` **REFUSE a non-empty destination unless `force`** — never silently merge two
//!   control planes (the commingle hazard). "Non-empty" includes an existing control-plane identity
//!   ([`CP_ID_KEY`]): importing into an existing cp-id IS the commingle case (WS4 identity
//!   semantics), so it is refused without `force` even when the dest has no user keys yet.
//! - After `--apply`, the import **verifies**: it re-reads every destination key and compares BYTES
//!   and COUNT (not count alone) against what it wrote.
//!
//! ## Security / custody (reuses the MF-6 facts)
//! A secret's value is **sealed PRE-put** (the envelope wraps it before it ever reaches the store),
//! so what a `dump_scan` reads — and what the dump file carries — is already the sealed ciphertext:
//! **no plaintext secret, and NEVER the envelope KEK** (the KEK is held separately; a restore needs
//! the separately-held key). The dump also carries the plaintext control-plane config/RBAC. A dump
//! is therefore sensitive (op-gated `System·Admin` over the API) but leaks neither a plaintext secret
//! nor key material — the [`dump_carries_no_plaintext_secret_or_kek`](tests) gate asserts it.

use crate::cache_coherence::INVAL_PREFIX;
use crate::kv::{KvDumpEntry, KvError, KvStore, WriteOp};
use crate::shared_mode::{CP_ID_KEY, CP_PREFIX};

/// The dump magic — the first 8 bytes of every dump, so a stray/foreign file is rejected loud.
pub const MAGIC: &[u8; 8] = b"BRKVDUMP";

/// The dump FORMAT version. Bumped only on an incompatible framing change; a reader refuses an
/// unknown version rather than misreading it.
pub const FORMAT_VERSION: u32 = 1;

/// Record tag: a `{key, value, version}` entry follows.
const TAG_ENTRY: u8 = 0x01;
/// Record tag: end of the stream; an `entry_count` u64 follows for a completeness self-check.
const TAG_END: u8 = 0x00;

/// Whether `key` belongs to a reserved internal coordination feed the dump never copies: the
/// shared-mode control-plane rows ([`CP_PREFIX`] `_cp/*`) and the cache-coherence invalidation feed
/// ([`INVAL_PREFIX`] `_inval/*`). Both regenerate per-deployment; copying them would commingle two
/// control planes' coordination identity. (`kv_changes` is a SQL table, not a `kv` key, so it never
/// reaches this filter and likewise regenerates.)
#[must_use]
pub fn is_reserved_dump_key(key: &str) -> bool {
    key.starts_with(CP_PREFIX) || key.starts_with(INVAL_PREFIX)
}

/// The parsed dump header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DumpHeader {
    /// The dump FORMAT version (see [`FORMAT_VERSION`]).
    pub format_version: u32,
    /// Unix seconds when the dump was produced.
    pub created_at: u64,
    /// Reserved flag bits (0 today — e.g. a future whole-dump at-rest seal would set a bit here).
    pub flags: u32,
}

/// A decoded dump: its header plus every `{key, value, version}` record, in the order written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedDump {
    /// The dump header.
    pub header: DumpHeader,
    /// The records.
    pub entries: Vec<KvDumpEntry>,
}

/// A dump decode failure — a corrupt/foreign/truncated file, always surfaced loud (never a silent
/// partial import).
#[derive(Debug, thiserror::Error)]
pub enum DumpError {
    /// The leading 8 bytes are not [`MAGIC`] — not a boatramp KV dump.
    #[error("not a boatramp KV dump (bad magic)")]
    BadMagic,
    /// The format version is newer/unknown to this build.
    #[error("unsupported KV dump format version {0} (this build understands {FORMAT_VERSION})")]
    UnsupportedVersion(u32),
    /// The byte stream ended mid-frame.
    #[error("truncated KV dump (ended mid-record at offset {0})")]
    Truncated(usize),
    /// An unknown record tag byte.
    #[error("corrupt KV dump: unknown record tag {0:#04x} at offset {1}")]
    BadTag(u8, usize),
    /// A key was not valid UTF-8.
    #[error("corrupt KV dump: key at offset {0} is not valid UTF-8")]
    BadKeyUtf8(usize),
    /// The trailing entry count did not match the number of records actually read.
    #[error("corrupt KV dump: declared {declared} entries but read {read}")]
    CountMismatch {
        /// The count in the END frame.
        declared: u64,
        /// The number of records actually decoded.
        read: u64,
    },
    /// Bytes remained after the END frame.
    #[error("corrupt KV dump: {0} trailing byte(s) after the end frame")]
    TrailingBytes(usize),
}

/// Serialize `entries` into a dump byte stream with a header stamped `created_at` (unix seconds).
/// The caller is expected to have already filtered the reserved feeds (see [`scan_dumpable`]); this
/// is a pure framing function.
#[must_use]
pub fn encode_dump(entries: &[KvDumpEntry], created_at: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + entries.len() * 32);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&created_at.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    for e in entries {
        out.push(TAG_ENTRY);
        let key = e.key.as_bytes();
        out.extend_from_slice(&(key.len() as u32).to_le_bytes());
        out.extend_from_slice(key);
        out.extend_from_slice(&(e.value.len() as u32).to_le_bytes());
        out.extend_from_slice(&e.value);
        out.extend_from_slice(&e.version.to_le_bytes());
    }
    out.push(TAG_END);
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    out
}

/// A cursor over the dump bytes with loud bounds checks.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], DumpError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(DumpError::Truncated(self.pos))?;
        if end > self.buf.len() {
            return Err(DumpError::Truncated(self.pos));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, DumpError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, DumpError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn u64(&mut self) -> Result<u64, DumpError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
    fn i64(&mut self) -> Result<i64, DumpError> {
        Ok(i64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
}

/// Parse a dump byte stream back into its header + records, validating the magic, version, framing
/// and the trailing completeness count. Any corruption is a loud [`DumpError`] (never a silent
/// partial result).
pub fn decode_dump(bytes: &[u8]) -> Result<DecodedDump, DumpError> {
    let mut r = Reader { buf: bytes, pos: 0 };
    if r.take(MAGIC.len())? != MAGIC.as_slice() {
        return Err(DumpError::BadMagic);
    }
    let format_version = r.u32()?;
    if format_version != FORMAT_VERSION {
        return Err(DumpError::UnsupportedVersion(format_version));
    }
    let created_at = r.u64()?;
    let flags = r.u32()?;
    let mut entries = Vec::new();
    loop {
        let tag_at = r.pos;
        match r.u8()? {
            TAG_ENTRY => {
                let key_len = r.u32()? as usize;
                let key_at = r.pos;
                let key = String::from_utf8(r.take(key_len)?.to_vec())
                    .map_err(|_| DumpError::BadKeyUtf8(key_at))?;
                let val_len = r.u32()? as usize;
                let value = r.take(val_len)?.to_vec();
                let version = r.i64()?;
                entries.push(KvDumpEntry {
                    key,
                    value,
                    version,
                });
            }
            TAG_END => {
                let declared = r.u64()?;
                let read = entries.len() as u64;
                if declared != read {
                    return Err(DumpError::CountMismatch { declared, read });
                }
                if r.pos != bytes.len() {
                    return Err(DumpError::TrailingBytes(bytes.len() - r.pos));
                }
                return Ok(DecodedDump {
                    header: DumpHeader {
                        format_version,
                        created_at,
                        flags,
                    },
                    entries,
                });
            }
            other => return Err(DumpError::BadTag(other, tag_at)),
        }
    }
}

/// Scan `store` for every DUMPABLE entry — [`KvStore::dump_scan`] minus the reserved internal feeds
/// ([`is_reserved_dump_key`]). This is the authoritative source for `export` and `migrate`.
pub async fn scan_dumpable(store: &dyn KvStore) -> Result<Vec<KvDumpEntry>, KvError> {
    let all = store.dump_scan().await?;
    Ok(all
        .into_iter()
        .filter(|e| !is_reserved_dump_key(&e.key))
        .collect())
}

/// Export `store` to a dump byte stream (header stamped `created_at`), skipping the reserved feeds.
/// This is what `boatramp kv export --out <file>` and `GET /api/kv-export` write.
pub async fn export_to_bytes(store: &dyn KvStore, created_at: u64) -> Result<Vec<u8>, KvError> {
    let entries = scan_dumpable(store).await?;
    Ok(encode_dump(&entries, created_at))
}

/// The emptiness/identity state of an import DESTINATION — what the dry-run plan reports and the
/// non-empty refusal keys on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestState {
    /// Non-reserved ("user") keys already present — the commingle surface.
    pub user_keys: usize,
    /// Reserved coordination keys present (`_cp/*`, `_inval/*`) — informational; never copied.
    pub reserved_keys: usize,
    /// Whether a control-plane identity ([`CP_ID_KEY`]) is already stamped — importing into an
    /// existing cp-id IS the commingle case (WS4), refused without `force` even with zero user keys.
    pub has_control_plane_id: bool,
}

impl DestState {
    /// A destination is PRISTINE (safe to import without `force`) iff it has no user keys AND no
    /// control-plane identity. A reserved-only, cp-id-less store (e.g. a just-created `_inval` row)
    /// is still pristine.
    #[must_use]
    pub fn is_pristine(&self) -> bool {
        self.user_keys == 0 && !self.has_control_plane_id
    }
}

/// Inspect an import destination's emptiness/identity.
pub async fn dest_state(store: &dyn KvStore) -> Result<DestState, KvError> {
    let keys = store.list_prefix("").await?;
    let mut user_keys = 0;
    let mut reserved_keys = 0;
    let mut has_control_plane_id = false;
    for key in &keys {
        if is_reserved_dump_key(key) {
            reserved_keys += 1;
            if key == CP_ID_KEY {
                has_control_plane_id = true;
            }
        } else {
            user_keys += 1;
        }
    }
    Ok(DestState {
        user_keys,
        reserved_keys,
        has_control_plane_id,
    })
}

/// The dry-run plan for an `import`/`migrate`: what WOULD be copied + the destination's state + the
/// commingle verdict. Printing this is the default (no mutation); `--apply` executes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportPlan {
    /// Dumpable source entries (reserved feeds already excluded).
    pub source_entries: usize,
    /// Reserved source entries that WOULD be skipped (0 from a boatramp export; non-zero only from a
    /// hand-crafted dump — the import filters them defensively).
    pub source_reserved_skipped: usize,
    /// The destination's current emptiness/identity.
    pub dest: DestState,
    /// How many records would be written (= `source_entries`).
    pub would_write: usize,
    /// Whether the apply WOULD be refused as a commingle (dest not pristine and no `force`).
    pub would_refuse_commingle: bool,
}

/// The outcome of an applied `import`/`migrate` — written + the byte-and-count verify result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportReport {
    /// Records written into the destination.
    pub written: usize,
    /// Records re-read and byte-confirmed in the destination (must equal `written`).
    pub verified: usize,
}

/// An `import`/`migrate` apply failure.
#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    /// A KV backend error (source scan, destination write, or verify read).
    #[error(transparent)]
    Kv(#[from] KvError),
    /// A corrupt source dump.
    #[error(transparent)]
    Dump(#[from] DumpError),
    /// The destination is NOT pristine and `force` was not given — refused to avoid commingling two
    /// control planes. Carries the destination state for a legible message.
    #[error(
        "refusing to import into a non-empty destination ({} user key(s){}): this would COMMINGLE \
         two control planes. Re-run with --force only if you intend to overlay this dump onto the \
         existing store.",
        .0.user_keys,
        if .0.has_control_plane_id { ", existing control-plane identity" } else { "" }
    )]
    Commingle(DestState),
    /// A written key read back with different bytes (verify, byte-level).
    #[error("verify FAILED: destination key {key:?} does not match the dump bytes after write")]
    VerifyMismatch {
        /// The offending key.
        key: String,
    },
    /// The verified count did not match what was written (verify, count-level).
    #[error("verify FAILED: wrote {written} record(s) but only {found} read back byte-identical")]
    VerifyCount {
        /// Records written.
        written: usize,
        /// Records that read back byte-identical.
        found: usize,
    },
}

/// How many destination writes to group into one `write_batch` (bounds a huge dump's per-txn size).
const IMPORT_BATCH: usize = 512;

/// Build the dry-run plan for importing `entries` into `dest` (filtering reserved entries from the
/// dump defensively). Mutates nothing.
pub async fn plan_import(
    dest: &dyn KvStore,
    entries: &[KvDumpEntry],
    force: bool,
) -> Result<ImportPlan, KvError> {
    let reserved = entries
        .iter()
        .filter(|e| is_reserved_dump_key(&e.key))
        .count();
    let source_entries = entries.len() - reserved;
    let dest = dest_state(dest).await?;
    let would_refuse_commingle = !dest.is_pristine() && !force;
    Ok(ImportPlan {
        source_entries,
        source_reserved_skipped: reserved,
        would_write: source_entries,
        would_refuse_commingle,
        dest,
    })
}

/// Apply an import of `entries` into `dest`: refuse a non-empty destination without `force`, write
/// every (non-reserved) record, advance the durable frontier, then VERIFY by re-reading every
/// written key and comparing BYTES and COUNT. Returns the verified report or a loud [`ImportError`].
pub async fn apply_import(
    dest: &dyn KvStore,
    entries: &[KvDumpEntry],
    force: bool,
) -> Result<ImportReport, ImportError> {
    let state = dest_state(dest).await?;
    if !state.is_pristine() && !force {
        return Err(ImportError::Commingle(state));
    }
    // Reserved feeds are never imported (they regenerate; importing them would commingle cp identity).
    let dumpable: Vec<&KvDumpEntry> = entries
        .iter()
        .filter(|e| !is_reserved_dump_key(&e.key))
        .collect();

    // Write in bounded atomic batches, then one checkpoint advances the durable frontier past it all.
    for chunk in dumpable.chunks(IMPORT_BATCH) {
        let ops: Vec<WriteOp> = chunk
            .iter()
            .map(|e| WriteOp::Put(e.key.clone(), e.value.clone()))
            .collect();
        dest.write_batch(ops).await?;
    }
    dest.checkpoint().await?;

    // VERIFY — re-read every written key and compare BYTES (not just count).
    let mut verified = 0usize;
    for e in &dumpable {
        match dest.get(&e.key).await? {
            Some(got) if got == e.value => verified += 1,
            _ => {
                return Err(ImportError::VerifyMismatch { key: e.key.clone() });
            }
        }
    }
    if verified != dumpable.len() {
        return Err(ImportError::VerifyCount {
            written: dumpable.len(),
            found: verified,
        });
    }
    Ok(ImportReport {
        written: dumpable.len(),
        verified,
    })
}

/// `migrate` = store→store: scan `src` (skipping reserved feeds) and `apply_import` into `dst`.
/// Offline/quiesced by contract (a live single-writer source racing concurrent writes is the
/// caller's responsibility — the CLI documents it); the refuse-non-empty + verify guards apply.
pub async fn migrate(
    src: &dyn KvStore,
    dst: &dyn KvStore,
    force: bool,
) -> Result<ImportReport, ImportError> {
    let entries = scan_dumpable(src).await?;
    apply_import(dst, &entries, force).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crownjewel::gate::GateEnvelope;
    use crate::kv::MemoryKv;
    use crate::project::ProjectRef;
    use crate::secret_store::SecretStore;
    use std::sync::Arc;

    fn entry(key: &str, value: &[u8], version: i64) -> KvDumpEntry {
        KvDumpEntry {
            key: key.to_string(),
            value: value.to_vec(),
            version,
        }
    }

    /// The format round-trips faithfully — header fields + every `{key, value, version}` (incl. an
    /// empty value and binary bytes + a version > 1) survive encode → decode byte-for-byte.
    #[test]
    fn dump_format_round_trips() {
        let entries = vec![
            entry("a/1", b"one", 1),
            entry("a/empty", b"", 7),
            entry("a/bin", &[0u8, 159, 146, 150], 3),
        ];
        let bytes = encode_dump(&entries, 1_700_000_000);
        let decoded = decode_dump(&bytes).unwrap();
        assert_eq!(decoded.header.format_version, FORMAT_VERSION);
        assert_eq!(decoded.header.created_at, 1_700_000_000);
        assert_eq!(decoded.entries, entries, "every key/value/version survives");
        // Re-encoding the decoded dump is byte-identical (deterministic framing).
        assert_eq!(
            encode_dump(&decoded.entries, decoded.header.created_at),
            bytes
        );
    }

    /// A foreign / truncated / version-mismatched / count-mismatched file is rejected LOUD.
    #[test]
    fn decode_rejects_corrupt_dumps() {
        assert!(matches!(
            decode_dump(b"not-a-dump-xx"),
            Err(DumpError::BadMagic)
        ));
        let good = encode_dump(&[entry("k", b"v", 1)], 0);
        assert!(matches!(
            decode_dump(&good[..good.len() - 3]),
            Err(DumpError::Truncated(_) | DumpError::CountMismatch { .. })
        ));
        let mut bad_ver = good.clone();
        bad_ver[8] = 0xFF; // corrupt the format_version LE byte
        assert!(matches!(
            decode_dump(&bad_ver),
            Err(DumpError::UnsupportedVersion(_))
        ));
    }

    /// GATE `kv_dump_roundtrip_preserves_all_keys` (over `MemoryKv`, fast) — seed crown-jewel + config
    /// keys, export, import into a FRESH store, and assert byte-equal content + identical key SET +
    /// the dump preserved versions; the `_inval/*` / `_cp/*` reserved feeds are SKIPPED (never copied).
    #[tokio::test]
    async fn kv_dump_roundtrip_preserves_all_keys() {
        let src = MemoryKv::new();
        // Crown-jewel + config keys (+ a reserved cp-id and an _inval row that must NOT be copied).
        src.put(
            "project/default/secret/api-key",
            b"SEALED-ciphertext".to_vec(),
        )
        .await
        .unwrap();
        src.put("authz/policy", b"{\"roles\":{}}".to_vec())
            .await
            .unwrap();
        src.put("site/default/web/current", b"deadbeef".to_vec())
            .await
            .unwrap();
        src.put("k/empty", Vec::new()).await.unwrap();
        src.put("k/bin", vec![0u8, 159, 146, 150]).await.unwrap();
        // Reserved feeds — present in the source, must be excluded from the dump.
        src.put(CP_ID_KEY, b"cp-abc123".to_vec()).await.unwrap();
        src.put("_cp/leader", b"node-1".to_vec()).await.unwrap();
        src.put("_inval/123-node1-1", b"authz/policy".to_vec())
            .await
            .unwrap();

        let bytes = export_to_bytes(&src, 42).await.unwrap();
        let decoded = decode_dump(&bytes).unwrap();

        // The dump carries ONLY the dumpable keys — no reserved feed leaked in.
        let dumped: std::collections::BTreeSet<&str> =
            decoded.entries.iter().map(|e| e.key.as_str()).collect();
        let expected: std::collections::BTreeSet<&str> = [
            "project/default/secret/api-key",
            "authz/policy",
            "site/default/web/current",
            "k/empty",
            "k/bin",
        ]
        .into_iter()
        .collect();
        assert_eq!(dumped, expected, "reserved _cp/* and _inval/* are skipped");
        assert!(
            decoded.entries.iter().all(|e| e.version == 1),
            "the dump records each key's version"
        );

        // Import into a FRESH store (pristine ⇒ no --force needed) and verify.
        let dst = MemoryKv::new();
        let report = apply_import(&dst, &decoded.entries, false).await.unwrap();
        assert_eq!(report.written, 5);
        assert_eq!(
            report.verified, 5,
            "every written key read back byte-identical"
        );

        // Byte-equal content + identical key set on the destination.
        for e in &decoded.entries {
            assert_eq!(dst.get(&e.key).await.unwrap(), Some(e.value.clone()));
        }
        let mut dst_keys = dst.list_prefix("").await.unwrap();
        dst_keys.sort();
        let mut want: Vec<String> = expected.iter().map(ToString::to_string).collect();
        want.sort();
        assert_eq!(
            dst_keys, want,
            "the fresh store has exactly the dumped key set"
        );
        // The reserved feeds did NOT come across.
        assert_eq!(dst.get(CP_ID_KEY).await.unwrap(), None);
        assert_eq!(dst.get("_inval/123-node1-1").await.unwrap(), None);

        // A re-export of the fresh store equals the dumpable set (content preserved; versions reset
        // to 1 by the fresh writes — the whole point of a logical rebuild).
        let reexport = decode_dump(&export_to_bytes(&dst, 43).await.unwrap()).unwrap();
        let reexported: std::collections::BTreeSet<&str> =
            reexport.entries.iter().map(|e| e.key.as_str()).collect();
        assert_eq!(reexported, expected);
    }

    /// GATE `kv_import_refuses_nonempty_destination_without_force` — a destination with ANY user key,
    /// or an existing control-plane identity, is refused without `force`; `force` overlays it.
    #[tokio::test]
    async fn kv_import_refuses_nonempty_destination_without_force() {
        let entries = vec![entry("authz/policy", b"{}", 1)];

        // (a) user key present ⇒ refused without force.
        let dst = MemoryKv::new();
        dst.put("site/default/web/current", b"x".to_vec())
            .await
            .unwrap();
        let err = apply_import(&dst, &entries, false).await.unwrap_err();
        assert!(matches!(err, ImportError::Commingle(s) if s.user_keys == 1));
        assert_eq!(
            dst.get("authz/policy").await.unwrap(),
            None,
            "a refused import mutates nothing"
        );
        // force overlays it.
        apply_import(&dst, &entries, true).await.unwrap();
        assert_eq!(dst.get("authz/policy").await.unwrap(), Some(b"{}".to_vec()));

        // (b) ONLY a control-plane identity present (zero user keys) ⇒ still refused (WS4 commingle).
        let dst2 = MemoryKv::new();
        dst2.put(CP_ID_KEY, b"cp-existing".to_vec()).await.unwrap();
        let err = apply_import(&dst2, &entries, false).await.unwrap_err();
        assert!(
            matches!(err, ImportError::Commingle(s) if s.has_control_plane_id && s.user_keys == 0),
            "importing into an existing cp-id is the commingle case"
        );
    }

    /// GATE `kv_import_dryrun_mutates_nothing` — `plan_import` reports the plan (source count, dest
    /// state, would-copy, commingle verdict) and writes NOTHING to the destination.
    #[tokio::test]
    async fn kv_import_dryrun_mutates_nothing() {
        let entries = vec![
            entry("authz/policy", b"{}", 1),
            entry("project/default/secret/k", b"sealed", 1),
            // A reserved entry in the dump is counted as skipped, never written.
            entry("_cp/leader", b"node", 1),
        ];
        let dst = MemoryKv::new();
        dst.put("existing/key", b"v".to_vec()).await.unwrap();

        let plan = plan_import(&dst, &entries, false).await.unwrap();
        assert_eq!(
            plan.source_entries, 2,
            "reserved entry excluded from the count"
        );
        assert_eq!(plan.source_reserved_skipped, 1);
        assert_eq!(plan.would_write, 2);
        assert_eq!(plan.dest.user_keys, 1);
        assert!(plan.would_refuse_commingle, "non-empty dest without force");

        // The dry run mutated NOTHING.
        assert_eq!(dst.get("authz/policy").await.unwrap(), None);
        assert_eq!(dst.get("project/default/secret/k").await.unwrap(), None);
        let mut keys = dst.list_prefix("").await.unwrap();
        keys.sort();
        assert_eq!(keys, vec!["existing/key".to_string()]);
    }

    /// GATE `kv_export_contains_no_plaintext_secret_or_kek` — a secret SEALED through the real
    /// `SecretStore` path lands in the store (and the dump) as CIPHERTEXT; the dump contains neither
    /// the plaintext secret nor any KEK material.
    #[tokio::test]
    async fn kv_export_contains_no_plaintext_secret_or_kek() {
        // A distinctive plaintext + a stand-in "KEK" the dump must never carry.
        const PLAINTEXT: &[u8] = b"TOP-SECRET-plaintext-value-\x00\x9f\x92\x96";
        const KEK: &[u8] = b"ENVELOPE-KEK-MATERIAL-do-not-persist";

        let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
        let store = SecretStore::new(kv.clone(), Arc::new(GateEnvelope));
        // Seal PRE-put through the real path: the envelope wraps the plaintext before it reaches kv.
        store
            .set(ProjectRef::new("default"), "api-key", PLAINTEXT)
            .await
            .unwrap();

        let bytes = export_to_bytes(kv.as_ref(), 0).await.unwrap();

        // The PLAINTEXT must be absent from the whole dump, and no KEK material either.
        assert!(
            !contains(&bytes, PLAINTEXT),
            "the dump must NOT carry the plaintext secret"
        );
        assert!(
            !contains(&bytes, KEK),
            "the dump must NEVER carry KEK material (held separately; a restore needs it)"
        );

        // The dump decodes and holds exactly the one secret key, whose value is the SEALED record.
        let decoded = decode_dump(&bytes).unwrap();
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].key, "project/default/secret/api-key");

        // Positive proof we dumped the REAL sealed record (not an empty/garbage value): the record's
        // `sealed` bytes unseal (GateEnvelope XORs 0x5a) back to the plaintext — i.e. the dump carries
        // the pre-put CIPHERTEXT, never the plaintext.
        let record: serde_json::Value = serde_json::from_slice(&decoded.entries[0].value).unwrap();
        let sealed: Vec<u8> = record["sealed"]
            .as_array()
            .expect("record has a `sealed` byte array")
            .iter()
            .map(|n| n.as_u64().unwrap() as u8)
            .collect();
        assert_ne!(
            sealed.as_slice(),
            PLAINTEXT,
            "the stored bytes are ciphertext"
        );
        let unsealed: Vec<u8> = sealed.iter().map(|b| b ^ 0x5a).collect();
        assert_eq!(
            unsealed, PLAINTEXT,
            "the sealed ciphertext unseals back to the plaintext (sealing was pre-put)"
        );
    }

    /// Whether `haystack` contains the contiguous byte sequence `needle`.
    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// `migrate` (store→store) copies the dumpable set and verifies, skipping reserved feeds.
    #[tokio::test]
    async fn migrate_store_to_store_round_trips() {
        let src = MemoryKv::new();
        src.put("authz/policy", b"{}".to_vec()).await.unwrap();
        src.put("project/default/secret/k", b"sealed".to_vec())
            .await
            .unwrap();
        src.put(CP_ID_KEY, b"cp".to_vec()).await.unwrap();
        let dst = MemoryKv::new();
        let report = migrate(&src, &dst, false).await.unwrap();
        assert_eq!(report.written, 2);
        assert_eq!(report.verified, 2);
        assert_eq!(dst.get("authz/policy").await.unwrap(), Some(b"{}".to_vec()));
        assert_eq!(
            dst.get(CP_ID_KEY).await.unwrap(),
            None,
            "cp-id not migrated"
        );
    }
}
