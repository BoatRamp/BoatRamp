//! **Incremental / delta project export — the family-agnostic delta ALGEBRA** (the follow-on
//! program sketched at the end of `boatramp-node`'s `project_export`, built to the owner's
//! 2026-10-25 RESOLVED decisions).
//!
//! A delta export chains onto a prior **base** bundle (the resumable member-object layout from
//! v0.45.0) and carries only what changed. This module holds the PURE, backend-agnostic core —
//! the types and the diff/replay functions — so the node driver (`boatramp-node`) stays thin and
//! the logic is unit-testable without any live DB / blob store / Docker.
//!
//! ## The five RESOLVED decisions (owner, 2026-10-25) and where each lands
//! 1. **PG/MySQL delta = WAL/binlog true-delta.** NOT in this first increment — it needs
//!    replication-slot-grade access + a replay restore. Scaffolded as [`SqlDeltaStrategy`]; the
//!    only implemented strategy this pass is [`SqlDeltaKind::FullDumpFallback`].
//! 2. **libsql delta = changeset diff.** Likewise scaffolded, not implemented (needs sqldiff /
//!    the SQLite session extension). Full-dump fallback this pass.
//! 3. **All-families-consistent.** A delta covers EVERY family against ONE base; a family that
//!    cannot true-delta yet FULL-DUMPS within the same bundle (so the bundle is still a complete,
//!    restorable point-in-time), and restore is all-or-nothing. This increment ships true-deltas
//!    for **KV** and **blobs** and the full-dump fallback for pg/mysql/libsql.
//! 4. **Both differential AND incremental** ([`DeltaMode`]): differential = each delta vs a fixed
//!    base (restore = base + 1); incremental = each delta vs its parent (a chain, restore =
//!    base + replay N). Both share **adds-as-full-members + deletes-as-tombstones** drift handling
//!    ([`compute_kv_delta`], [`compute_blob_tombstones`], [`blob_decision_by_size`]).
//! 5. **Restore = sequential apply into the atomic shadow.** The node driver resolves the chain,
//!    restores the base, then applies each delta's per-family change in order (see
//!    [`apply_kv_delta_to_frontier`] / [`apply_blob_delta_to_frontier`] for the EXPORT-side frontier
//!    replay; the IMPORT-side apply lives in the node driver, reusing the v0.45.0 per-member shadow).
//!
//! ## Drift handling (shared by both modes)
//! - **adds-as-full-members**: a new or changed blob ships as an ordinary full `Blob` member; a
//!   new or changed KV entry ships as a full upsert record — so a restore never needs the base's
//!   bytes for an added object, only the overlay.
//! - **deletes-as-tombstones**: an object present in the base frontier but gone now is recorded as
//!   a tombstone (a KV key in [`KvDelta::tombstones`], a blob key in the blob-tombstone member), so
//!   the restore DELETES it after laying down the base — the base's copy does not linger.
//!
//! ## Security note (the import side consumes these)
//! A delta bundle crosses the SAME trust boundary as a full bundle: its members carry only an
//! integrity SHA, never authenticity. So the tombstone key lists and upsert keys are
//! attacker-influenceable and MUST be re-scoped + enforced to the TARGET project on import exactly
//! like a full KV slice (`project_export::enforce_target_scoped_kv` for KV, the `hblob/{target}/`
//! re-qualify for blobs). A tombstone that escaped that scope would be a cross-tenant DELETE — the
//! node driver enforces it; this module only computes the sets.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::kv::KvDumpEntry;
use crate::kv_dump;

/// Which base a delta chains onto — the owner's decision 4 (both, user-selectable).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaMode {
    /// Each delta is taken against a FIXED base bundle (restore = base + this one delta). The
    /// base reference pins that one base; the chain is always length 2 (`[base, this]`).
    Differential,
    /// Each delta is taken against its PARENT (which may itself be a delta), forming a chain
    /// (restore = root base + replay every delta in order). The base reference pins the parent.
    Incremental,
}

impl DeltaMode {
    /// The CLI/flag spelling (`--mode differential|incremental`).
    #[must_use]
    pub fn as_flag(&self) -> &'static str {
        match self {
            Self::Differential => "differential",
            Self::Incremental => "incremental",
        }
    }

    /// Parse the `--mode` flag value. Unknown ⇒ `None` (the caller refuses loud).
    #[must_use]
    pub fn parse_flag(s: &str) -> Option<Self> {
        match s {
            "differential" | "diff" => Some(Self::Differential),
            "incremental" | "inc" => Some(Self::Incremental),
            _ => None,
        }
    }
}

/// What a caller asks for when it wants a DELTA export (carried in `ExportOptions::delta`). `None`
/// there ⇒ an ordinary full bundle. The `base_reference` is a resumable-export directory NAME
/// (confined under the node's configured resumable base, exactly like the resumable target itself —
/// node-local so the chain can be re-read on restore), naming the fixed base (differential) or the
/// parent delta (incremental).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaRequest {
    /// Differential vs incremental.
    pub mode: DeltaMode,
    /// The base (differential) / parent (incremental) resumable-dir name to chain onto.
    pub base_reference: String,
}

/// The delta metadata STORED in a bundle's `StreamManifest` (so a restore knows this is a delta,
/// which base/parent it chains onto, and in which mode). Absent ⇒ an ordinary full bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaInfo {
    /// Differential (vs a fixed base) or incremental (vs the parent).
    pub mode: DeltaMode,
    /// The base/parent bundle's resumable-dir name — resolved + confined on restore to walk the
    /// chain back to the root full bundle.
    pub base_reference: String,
    /// The base/parent bundle's `created_at` (a cheap consistency check the restore can assert the
    /// resolved base against — a mismatched base is refused rather than silently applied).
    pub base_created_at: u64,
    /// Which SQL-delta strategy produced the pg/mysql/libsql members in THIS bundle. In this first
    /// increment it is always [`SqlDeltaKind::FullDumpFallback`] (the true-delta strategies are
    /// scaffolded, not implemented) — recorded so a future reader can tell a full-dump-fallback
    /// member from a true row-delta member once those land.
    #[serde(default)]
    pub sql_strategy: SqlDeltaKind,
}

/// The per-SQL-member base CURSOR recorded in a TRUE-delta member's manifest entry — the point the
/// delta was captured since, so restore replays from exactly there. Absent on a member ⇒ a
/// full-dump member (the all-families-consistent fallback, decision 3), which has no replay. Tagged
/// by engine so a reader can tell which replay path a member needs. (SQL true-delta program — see
/// `PLAN-sql-true-delta.md`; the cursor is small metadata stored in the manifest JSON, not framed.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "engine")]
pub enum SqlMemberCursor {
    /// Postgres logical-replication LSN — the capture slot's consistent point at the base. The delta
    /// member carries the decoded change stream since this LSN.
    PgLsn { lsn: String },
    /// MySQL GTID set executed as of the base. The delta member carries the binlog events since it.
    MysqlGtid { gtid: String },
    /// libsql/SQLite: the SHA-256 of the base DB SNAPSHOT the changeset was diffed against (no
    /// page-version watermark exists, so the base file itself is the cursor). The delta member
    /// carries the changeset applied onto the base.
    LibsqlChangesetBase { base_sha256: String },
}

impl SqlMemberCursor {
    /// The SQL-delta strategy this cursor belongs to (keeps the cursor and the member's
    /// [`SqlDeltaKind`] in lockstep).
    #[must_use]
    pub fn kind(&self) -> SqlDeltaKind {
        match self {
            Self::PgLsn { .. } => SqlDeltaKind::PgWalReplay,
            Self::MysqlGtid { .. } => SqlDeltaKind::MysqlBinlogReplay,
            Self::LibsqlChangesetBase { .. } => SqlDeltaKind::LibsqlChangeset,
        }
    }
}

// ===========================================================================================
// KV delta — decision 2 (KV is the most natural: adds-as-upserts + deletes-as-tombstones)
// ===========================================================================================

/// A computed KV delta against a base frontier: the full records to UPSERT (new or value-changed
/// keys) and the keys to DELETE (present in the base, gone now). Both sets are already scoped to
/// the project by the caller (the driver scopes the current scan with
/// `project_export::scope_entries_to_project` before diffing), so the delta carries only the
/// project's own keyspace.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KvDelta {
    /// New or changed entries, shipped WHOLE (adds-as-full-members) — reusing the `KvDumpEntry`
    /// shape so the restore decodes + re-keys + enforces them exactly like a full KV slice.
    pub upserts: Vec<KvDumpEntry>,
    /// Keys present in the base frontier but absent now — DELETED on restore after the base is
    /// laid down (deletes-as-tombstones).
    pub tombstones: Vec<String>,
}

impl KvDelta {
    /// Whether this delta changes nothing (no upsert, no tombstone) — a no-op slice the driver may
    /// still ship (so the bundle is a complete point-in-time) but which applies to nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.upserts.is_empty() && self.tombstones.is_empty()
    }
}

/// Diff a `current` scoped KV scan against the `base` frontier into a [`KvDelta`].
///
/// - a key in `current` not in `base`           → upsert (an ADD)
/// - a key in both whose VALUE BYTES differ      → upsert (a CHANGE)
/// - a key in both whose value is byte-identical → skipped (unchanged — the win)
/// - a key in `base` not in `current`            → tombstone (a DELETE)
///
/// The decision is on VALUE BYTES, not the backend `version` (which is `1` on every
/// non-SQL backend — SlateDB / memory / Cloudflare KV — so a version-based diff would be blind on
/// them; a content diff is correct on ALL backends). Order is deterministic (sorted) so a delta is
/// reproducible.
#[must_use]
pub fn compute_kv_delta(base: &[KvDumpEntry], current: &[KvDumpEntry]) -> KvDelta {
    let base_map: BTreeMap<&str, &[u8]> = base
        .iter()
        .map(|e| (e.key.as_str(), e.value.as_slice()))
        .collect();
    let current_map: BTreeMap<&str, &KvDumpEntry> =
        current.iter().map(|e| (e.key.as_str(), e)).collect();

    let mut upserts = Vec::new();
    for (key, entry) in &current_map {
        match base_map.get(key) {
            Some(base_val) if *base_val == entry.value.as_slice() => {} // unchanged — skip
            _ => upserts.push((*entry).clone()),                        // new or changed — ship
        }
    }
    let tombstones: Vec<String> = base_map
        .keys()
        .filter(|k| !current_map.contains_key(*k))
        .map(|k| (*k).to_string())
        .collect();
    KvDelta {
        upserts,
        tombstones,
    }
}

/// Replay a [`KvDelta`] onto a base KV FRONTIER (key → value bytes) — the EXPORT-side chain replay
/// for incremental mode: to diff against "the effective state at the parent", the driver starts
/// from the root base's frontier and applies each intermediate delta's upserts/tombstones in order.
/// (The IMPORT side applies deltas to the live store instead; this is the metadata-only replay the
/// export planner uses to know what already exists.)
pub fn apply_kv_delta_to_frontier(frontier: &mut BTreeMap<String, Vec<u8>>, delta: &KvDelta) {
    for e in &delta.upserts {
        frontier.insert(e.key.clone(), e.value.clone());
    }
    for k in &delta.tombstones {
        frontier.remove(k);
    }
}

// --- KV-delta wire framing (reuses the `kv_dump` binary format for the upserts) ---

/// The KV-delta member magic.
const KV_DELTA_MAGIC: &[u8; 8] = b"BRKVDELT";
/// The KV-delta member framing version.
const KV_DELTA_VERSION: u32 = 1;

/// Encode a [`KvDelta`] into the `kv.brkvdelta` member bytes:
/// ```text
/// MAGIC "BRKVDELT" (8) | version u32 LE | tombstone_count u32 LE
///   | [ key_len u32 LE | key bytes (UTF-8) ]*            (the tombstones)
///   | upsert_dump_len u64 LE | <kv_dump::encode_dump(upserts, created_at) bytes>
/// ```
/// The upserts ride as an EMBEDDED `kv_dump` dump, so the restore decodes them with the same
/// `kv_dump::decode_dump` + re-key + tenancy-enforce path as a full KV slice (no second format to
/// trust). Every integer little-endian, matching `kv_dump`'s discipline.
#[must_use]
pub fn encode_kv_delta(delta: &KvDelta, created_at: u64) -> Vec<u8> {
    let dump = kv_dump::encode_dump(&delta.upserts, created_at);
    let mut out = Vec::with_capacity(32 + dump.len());
    out.extend_from_slice(KV_DELTA_MAGIC);
    out.extend_from_slice(&KV_DELTA_VERSION.to_le_bytes());
    out.extend_from_slice(&(delta.tombstones.len() as u32).to_le_bytes());
    for k in &delta.tombstones {
        let kb = k.as_bytes();
        out.extend_from_slice(&(kb.len() as u32).to_le_bytes());
        out.extend_from_slice(kb);
    }
    out.extend_from_slice(&(dump.len() as u64).to_le_bytes());
    out.extend_from_slice(&dump);
    out
}

/// Decode a `kv.brkvdelta` member produced by [`encode_kv_delta`]. Any corruption / foreign magic /
/// unknown version / truncation is a loud [`DeltaError`] (never a silent partial).
pub fn decode_kv_delta(bytes: &[u8]) -> Result<KvDelta, DeltaError> {
    let mut r = FrameReader { buf: bytes, pos: 0 };
    if r.take(8)? != KV_DELTA_MAGIC.as_slice() {
        return Err(DeltaError::BadMagic);
    }
    let version = r.u32()?;
    if version != KV_DELTA_VERSION {
        return Err(DeltaError::UnsupportedVersion(version));
    }
    let n = r.u32()? as usize;
    // Bound the pre-allocation by the bytes actually left: each tombstone costs
    // at least its 4-byte length prefix, so a legit count is <= remaining / 4.
    // A forged count can't force a giant reservation; a short body still fails
    // loud in `take` below.
    let mut tombstones = Vec::with_capacity(n.min(r.remaining() / 4));
    for _ in 0..n {
        let len = r.u32()? as usize;
        let kb = r.take(len)?;
        let key = std::str::from_utf8(kb)
            .map_err(|_| DeltaError::BadKeyUtf8(r.pos))?
            .to_string();
        tombstones.push(key);
    }
    let dump_len = r.u64()? as usize;
    let dump = r.take(dump_len)?;
    let decoded = kv_dump::decode_dump(dump).map_err(|e| DeltaError::Kv(e.to_string()))?;
    Ok(KvDelta {
        upserts: decoded.entries,
        tombstones,
    })
}

// ===========================================================================================
// Blob delta — decision 2 (diff keys by size/SHA vs the base manifest; tombstones for deletes)
// ===========================================================================================

/// A cheap, metadata-only signature of a base blob — what the base bundle's per-member meta
/// records (`{size, sha256}`), so the diff can decide "unchanged" without reading the body when the
/// size already differs. (The base manifest does not record a backend etag, so the content hash is
/// the authoritative comparator; size is only the cheap pre-filter.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobSig {
    /// The base member's byte length.
    pub size: u64,
    /// The base member's content SHA-256 (lowercase hex) — the authoritative "did the bytes
    /// change" comparator.
    pub sha256: String,
}

/// The per-key decision from the CHEAP (metadata-only) blob pre-filter. `NeedsContentCheck` means
/// the sizes matched (or a size is unknown) so the driver must read the current object's SHA-256
/// and compare it to the base's `sha256` to decide add-vs-unchanged. Keeping the content read for
/// ONLY the size-equal case is the first-increment cost trade (a reliable content-etag fast-path is
/// a documented follow-up).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobDecision {
    /// New key, or size differs from the base → ship it as a full member (an add/change).
    Add,
    /// Size matched the base (or a size was unknown) → the driver must content-check (SHA) to
    /// disambiguate a real change from a coincidental size match.
    NeedsContentCheck,
}

/// The CHEAP blob add/change pre-filter: given the base signature (if the key existed in the base)
/// and the current object's known size, decide whether we can already call it an ADD or must
/// content-check. A brand-new key is always an [`BlobDecision::Add`].
#[must_use]
pub fn blob_decision_by_size(base: Option<&BlobSig>, current_size: Option<u64>) -> BlobDecision {
    match (base, current_size) {
        (None, _) => BlobDecision::Add,                             // new key
        (Some(b), Some(cur)) if b.size != cur => BlobDecision::Add, // size changed ⇒ bytes changed
        _ => BlobDecision::NeedsContentCheck, // size equal / unknown ⇒ must hash
    }
}

/// The blob DELETE set (tombstones): keys present in the base frontier but absent from the current
/// listing (deletes-as-tombstones). Deterministic (sorted) output.
#[must_use]
pub fn compute_blob_tombstones(
    base_keys: &BTreeSet<String>,
    current_keys: &BTreeSet<String>,
) -> Vec<String> {
    base_keys.difference(current_keys).cloned().collect()
}

/// Replay a blob delta onto a base blob FRONTIER (key → sha256) — the EXPORT-side chain replay for
/// incremental mode (mirrors [`apply_kv_delta_to_frontier`]). `adds` is `(key, sha256)` for each
/// new/changed blob the delta shipped; `tombstones` are the deleted keys.
pub fn apply_blob_delta_to_frontier(
    frontier: &mut BTreeMap<String, String>,
    adds: &[(String, String)],
    tombstones: &[String],
) {
    for (k, sha) in adds {
        frontier.insert(k.clone(), sha.clone());
    }
    for k in tombstones {
        frontier.remove(k);
    }
}

// --- blob-tombstone wire framing ---

/// The blob-tombstone member magic.
const BLOB_TS_MAGIC: &[u8; 8] = b"BRBLOBTS";
/// The blob-tombstone member framing version.
const BLOB_TS_VERSION: u32 = 1;

/// Encode a blob-tombstone key list into the `blobs.brtombstones` member bytes:
/// ```text
/// MAGIC "BRBLOBTS" (8) | version u32 LE | count u32 LE | [ key_len u32 LE | key bytes (UTF-8) ]*
/// ```
#[must_use]
pub fn encode_blob_tombstones(keys: &[String]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + keys.len() * 48);
    out.extend_from_slice(BLOB_TS_MAGIC);
    out.extend_from_slice(&BLOB_TS_VERSION.to_le_bytes());
    out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys {
        let kb = k.as_bytes();
        out.extend_from_slice(&(kb.len() as u32).to_le_bytes());
        out.extend_from_slice(kb);
    }
    out
}

/// Decode a `blobs.brtombstones` member produced by [`encode_blob_tombstones`].
pub fn decode_blob_tombstones(bytes: &[u8]) -> Result<Vec<String>, DeltaError> {
    let mut r = FrameReader { buf: bytes, pos: 0 };
    if r.take(8)? != BLOB_TS_MAGIC.as_slice() {
        return Err(DeltaError::BadMagic);
    }
    let version = r.u32()?;
    if version != BLOB_TS_VERSION {
        return Err(DeltaError::UnsupportedVersion(version));
    }
    let n = r.u32()? as usize;
    // See `decode_kv_delta`: bound the pre-allocation by remaining bytes so an
    // attacker-controlled count can't force a huge reservation.
    let mut keys = Vec::with_capacity(n.min(r.remaining() / 4));
    for _ in 0..n {
        let len = r.u32()? as usize;
        let kb = r.take(len)?;
        let key = std::str::from_utf8(kb)
            .map_err(|_| DeltaError::BadKeyUtf8(r.pos))?
            .to_string();
        keys.push(key);
    }
    Ok(keys)
}

// ===========================================================================================
// SQL-delta strategy — decisions 1 & 2 SCAFFOLDED (full-dump fallback is the only impl this pass)
// ===========================================================================================

/// Which SQL-delta strategy a family used in a delta bundle. The true-delta strategies are
/// SCAFFOLDED here (owner decisions 1 & 2) but NOT implemented in this first increment — they need
/// replication-slot-grade DB access (pg WAL / mysql binlog) or the SQLite session/sqldiff
/// extension, plus a replay restore. Until they land, every SQL family uses
/// [`FullDumpFallback`](SqlDeltaKind::FullDumpFallback): a full dump WITHIN the delta bundle, which
/// keeps the all-families-consistent invariant (decision 3) — the delta is still a complete,
/// restorable point-in-time, and it still saves the (often dominant) KV + blob re-ship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SqlDeltaKind {
    /// A full dump inside the delta bundle (this increment's behaviour for pg/mysql/libsql).
    #[default]
    FullDumpFallback,
    /// SCAFFOLD: Postgres logical WAL replay since the base LSN (decision 1). Not implemented.
    PgWalReplay,
    /// SCAFFOLD: MySQL binlog replay since the base GTID (decision 1). Not implemented.
    MysqlBinlogReplay,
    /// SCAFFOLD: libsql/SQLite changeset diff against the base snapshot (decision 2). Not implemented.
    LibsqlChangeset,
}

impl SqlDeltaKind {
    /// Whether this strategy ships a TRUE row-level delta (vs a full-dump fallback). Only the
    /// scaffolded strategies would be true deltas; the implemented fallback is not.
    #[must_use]
    pub fn is_true_delta(&self) -> bool {
        !matches!(self, Self::FullDumpFallback)
    }
}

/// The SQL-delta strategy SEAM (owner decisions 1 & 2). A future increment implements the true-delta
/// strategies behind this trait — capture (export side) + replay (restore side) — per engine. This
/// first increment ships only [`FullDumpFallback`], so the trait exists to pin the interface + make
/// the next increment's shape explicit, NOT to branch behaviour yet.
pub trait SqlDeltaStrategy: Send + Sync {
    /// Which strategy this is (recorded in the bundle's [`DeltaInfo::sql_strategy`]).
    fn kind(&self) -> SqlDeltaKind;

    /// Whether this strategy produces a true row-level delta. `false` ⇒ the driver dumps the
    /// family in full within the delta bundle (the all-families-consistent fallback, decision 3).
    fn is_true_delta(&self) -> bool {
        self.kind().is_true_delta()
    }
}

/// The ONLY strategy implemented in this increment: a full dump inside the delta bundle. The
/// true-delta strategies (pg WAL / mysql binlog / libsql changeset) are the next increment, built
/// behind [`SqlDeltaStrategy`].
#[derive(Debug, Clone, Copy, Default)]
pub struct FullDumpFallback;

impl SqlDeltaStrategy for FullDumpFallback {
    fn kind(&self) -> SqlDeltaKind {
        SqlDeltaKind::FullDumpFallback
    }
}

// ===========================================================================================
// libsql changeset-delta wire framing (SQL true-delta program, Stage 4) — the SQLite
// session/changeset blob, lightly framed with a magic + version so a reader can tell a boatramp
// libsql true-delta member from a foreign blob and reject an unknown framing version. The
// changeset's own internal structure is validated by `sqlite3changeset_apply` on replay; this
// frame is the cheap integrity/version envelope (the member also carries a bundle-layer SHA-256).
// The raw changeset bytes are produced + consumed by the libsql FFI session engine in
// `boatramp-storage` (behind its `sql-delta-libsql` feature); this core holds only the pure
// framing so it stays unit-testable with no libsql/FFI dependency.
// ===========================================================================================

/// The libsql changeset-delta member magic.
const LIBSQL_CS_MAGIC: &[u8; 8] = b"BRLSQLCS";
/// The libsql changeset-delta member framing version.
const LIBSQL_CS_VERSION: u32 = 1;

/// Encode a raw SQLite changeset blob into the `*.changeset` member bytes:
/// ```text
/// MAGIC "BRLSQLCS" (8) | version u32 LE | changeset_len u64 LE | <raw changeset bytes>
/// ```
/// An EMPTY changeset (no row changes since the base) is a valid member (`changeset_len == 0`) —
/// its replay is a no-op, kept so the delta bundle is still a complete point-in-time.
#[must_use]
pub fn encode_libsql_changeset(changeset: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(20 + changeset.len());
    out.extend_from_slice(LIBSQL_CS_MAGIC);
    out.extend_from_slice(&LIBSQL_CS_VERSION.to_le_bytes());
    out.extend_from_slice(&(changeset.len() as u64).to_le_bytes());
    out.extend_from_slice(changeset);
    out
}

/// Decode a `*.changeset` member produced by [`encode_libsql_changeset`], returning the raw
/// changeset bytes. Any corruption / foreign magic / unknown version / truncation is a loud
/// [`DeltaError`] (never a silent partial — a malformed true-delta member must fail the import).
pub fn decode_libsql_changeset(bytes: &[u8]) -> Result<Vec<u8>, DeltaError> {
    let mut r = FrameReader { buf: bytes, pos: 0 };
    if r.take(8)? != LIBSQL_CS_MAGIC.as_slice() {
        return Err(DeltaError::BadMagic);
    }
    let version = r.u32()?;
    if version != LIBSQL_CS_VERSION {
        return Err(DeltaError::UnsupportedVersion(version));
    }
    let len = r.u64()? as usize;
    Ok(r.take(len)?.to_vec())
}

// ===========================================================================================
// Shared framing reader + errors
// ===========================================================================================

/// A loud delta framing / decode error (never a silent partial).
#[derive(Debug, thiserror::Error)]
pub enum DeltaError {
    /// The leading magic did not match the expected delta member.
    #[error("not a boatramp delta member (bad magic)")]
    BadMagic,
    /// The framing version is newer/unknown to this build.
    #[error("unsupported delta member framing version {0}")]
    UnsupportedVersion(u32),
    /// The byte stream ended mid-frame.
    #[error("truncated delta member (ended mid-frame at offset {0})")]
    Truncated(usize),
    /// A key was not valid UTF-8.
    #[error("corrupt delta member: key at offset {0} is not valid UTF-8")]
    BadKeyUtf8(usize),
    /// The embedded KV dump failed to decode.
    #[error("corrupt delta member: embedded KV dump: {0}")]
    Kv(String),
}

/// A little-endian frame reader with loud bounds checks (mirrors `kv_dump`'s `Reader`).
struct FrameReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> FrameReader<'a> {
    /// Bytes not yet consumed. Used to bound pre-sized allocations against an
    /// attacker-controlled count prefix (each framed entry costs >= 4 bytes).
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DeltaError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(DeltaError::Truncated(self.pos))?;
        if end > self.buf.len() {
            return Err(DeltaError::Truncated(self.pos));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }
    fn u32(&mut self) -> Result<u32, DeltaError> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    fn u64(&mut self) -> Result<u64, DeltaError> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().expect("8 bytes"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(key: &str, value: &[u8]) -> KvDumpEntry {
        KvDumpEntry {
            key: key.to_string(),
            value: value.to_vec(),
            version: 1,
        }
    }

    #[test]
    fn delta_mode_flag_round_trips() {
        assert_eq!(
            DeltaMode::parse_flag("differential"),
            Some(DeltaMode::Differential)
        );
        assert_eq!(
            DeltaMode::parse_flag("incremental"),
            Some(DeltaMode::Incremental)
        );
        assert_eq!(DeltaMode::parse_flag("diff"), Some(DeltaMode::Differential));
        assert_eq!(DeltaMode::parse_flag("inc"), Some(DeltaMode::Incremental));
        assert_eq!(DeltaMode::parse_flag("garbage"), None);
        assert_eq!(DeltaMode::Differential.as_flag(), "differential");
        assert_eq!(DeltaMode::Incremental.as_flag(), "incremental");
    }

    /// The KV drift algebra (decision 4 — adds-as-upserts + deletes-as-tombstones): an ADD, a
    /// CHANGE, an UNCHANGED key, and a DELETE, all in one diff.
    #[test]
    fn kv_delta_adds_changes_and_tombstones() {
        let base = vec![
            e("project/acme/config/a", b"one"),
            e("project/acme/config/b", b"two"),  // will change
            e("project/acme/config/gone", b"x"), // will be deleted
        ];
        let current = vec![
            e("project/acme/config/a", b"one"), // unchanged → skipped
            e("project/acme/config/b", b"TWO"), // changed → upsert
            e("project/acme/config/new", b"n"), // new → upsert
        ];
        let delta = compute_kv_delta(&base, &current);

        let up: BTreeMap<&str, &[u8]> = delta
            .upserts
            .iter()
            .map(|x| (x.key.as_str(), x.value.as_slice()))
            .collect();
        assert_eq!(up.len(), 2, "exactly the changed + new keys ship");
        assert_eq!(up.get("project/acme/config/b"), Some(&b"TWO".as_slice()));
        assert_eq!(up.get("project/acme/config/new"), Some(&b"n".as_slice()));
        assert!(
            !up.contains_key("project/acme/config/a"),
            "an unchanged key must NOT ship (the delta win)"
        );
        assert_eq!(
            delta.tombstones,
            vec!["project/acme/config/gone".to_string()]
        );
    }

    /// An empty diff (identical base + current) is a no-op delta.
    #[test]
    fn kv_delta_empty_when_unchanged() {
        let base = vec![e("k", b"v")];
        let current = vec![e("k", b"v")];
        assert!(compute_kv_delta(&base, &current).is_empty());
    }

    /// The KV-delta member round-trips through its wire framing (upserts via the embedded kv_dump,
    /// tombstones alongside), and a corrupt/foreign frame fails loud.
    #[test]
    fn kv_delta_wire_round_trip_and_loud_reject() {
        let delta = KvDelta {
            upserts: vec![
                e("project/acme/secret/x", b"\x00\x01binary"),
                e("project/acme/k", b"v"),
            ],
            tombstones: vec![
                "project/acme/old".to_string(),
                "project/acme/older".to_string(),
            ],
        };
        let bytes = encode_kv_delta(&delta, 42);
        let back = decode_kv_delta(&bytes).expect("round-trip");
        assert_eq!(back, delta);

        // Foreign magic → loud BadMagic.
        assert!(matches!(
            decode_kv_delta(b"NOTADELT...."),
            Err(DeltaError::BadMagic)
        ));
        // Truncation → loud Truncated.
        assert!(matches!(
            decode_kv_delta(&bytes[..bytes.len() - 3]),
            Err(DeltaError::Truncated(_) | DeltaError::Kv(_))
        ));
    }

    /// The incremental export-side frontier replay: applying a delta to a base frontier yields the
    /// effective state the NEXT delta diffs against.
    #[test]
    fn kv_frontier_replay_matches_a_direct_diff() {
        // Root base state.
        let mut frontier: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        frontier.insert("a".into(), b"1".to_vec());
        frontier.insert("b".into(), b"2".to_vec());
        frontier.insert("gone".into(), b"x".to_vec());

        // Delta 1 over the root: change b, add c, delete gone.
        let base1: Vec<KvDumpEntry> = frontier.iter().map(|(k, v)| e(k, v)).collect();
        let current1 = vec![e("a", b"1"), e("b", b"22"), e("c", b"3")];
        let d1 = compute_kv_delta(&base1, &current1);
        apply_kv_delta_to_frontier(&mut frontier, &d1);

        // The replayed frontier equals the current1 set — so a delta-2 diff against the frontier is
        // the same as a diff against current1 directly.
        let expect: BTreeMap<String, Vec<u8>> = current1
            .iter()
            .map(|x| (x.key.clone(), x.value.clone()))
            .collect();
        assert_eq!(frontier, expect);
    }

    /// The cheap blob pre-filter (decision 4 drift): new key = Add, size-change = Add, size-equal =
    /// NeedsContentCheck (the driver then SHA-disambiguates).
    #[test]
    fn blob_size_prefilter() {
        let base = BlobSig {
            size: 10,
            sha256: "aa".into(),
        };
        // New key → Add.
        assert_eq!(blob_decision_by_size(None, Some(10)), BlobDecision::Add);
        // Size changed → Add (bytes definitely changed).
        assert_eq!(
            blob_decision_by_size(Some(&base), Some(11)),
            BlobDecision::Add
        );
        // Size equal → must content-check.
        assert_eq!(
            blob_decision_by_size(Some(&base), Some(10)),
            BlobDecision::NeedsContentCheck
        );
        // Unknown current size → must content-check (conservative).
        assert_eq!(
            blob_decision_by_size(Some(&base), None),
            BlobDecision::NeedsContentCheck
        );
    }

    /// Blob tombstones = base keys gone from the current listing; blob-frontier replay mirrors KV.
    #[test]
    fn blob_tombstones_and_frontier_replay() {
        let base: BTreeSet<String> = ["k1", "k2", "k3"].into_iter().map(String::from).collect();
        let current: BTreeSet<String> = ["k1", "k3", "k4"].into_iter().map(String::from).collect();
        let ts = compute_blob_tombstones(&base, &current);
        assert_eq!(
            ts,
            vec!["k2".to_string()],
            "only the dropped key tombstones"
        );

        // Frontier replay: base (key→sha) minus tombstones plus adds.
        let mut frontier: BTreeMap<String, String> =
            [("k1", "sha1"), ("k2", "sha2"), ("k3", "sha3")]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
        let adds = vec![("k4".to_string(), "sha4".to_string())];
        apply_blob_delta_to_frontier(&mut frontier, &adds, &ts);
        let expect: BTreeMap<String, String> = [("k1", "sha1"), ("k3", "sha3"), ("k4", "sha4")]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        assert_eq!(frontier, expect);
    }

    /// The blob-tombstone member round-trips and fails loud on a foreign frame.
    #[test]
    fn blob_tombstone_wire_round_trip() {
        let keys = vec![
            "hblob/acme/web/img/a.png".to_string(),
            "hblob/acme/web/img/b.png".to_string(),
        ];
        let bytes = encode_blob_tombstones(&keys);
        assert_eq!(decode_blob_tombstones(&bytes).unwrap(), keys);
        assert!(matches!(
            decode_blob_tombstones(b"XXXXXXXXyy"),
            Err(DeltaError::BadMagic)
        ));
        // Empty list round-trips to empty.
        assert!(
            decode_blob_tombstones(&encode_blob_tombstones(&[]))
                .unwrap()
                .is_empty()
        );
    }

    /// A forged frame whose entry count is enormous but whose body is tiny must fail loud
    /// (`Truncated`) WITHOUT pre-allocating from the attacker-controlled count — the bound is
    /// `n.min(remaining / 4)`, so an untrusted header can never force a giant reservation.
    #[test]
    fn forged_count_does_not_over_allocate() {
        // KV delta: magic + version + a u32::MAX tombstone count, then nothing.
        let mut kv = Vec::new();
        kv.extend_from_slice(KV_DELTA_MAGIC);
        kv.extend_from_slice(&KV_DELTA_VERSION.to_le_bytes());
        kv.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            matches!(decode_kv_delta(&kv), Err(DeltaError::Truncated(_))),
            "a forged huge count must fail loud, not allocate ~u32::MAX entries"
        );

        // Blob tombstones: same shape.
        let mut blob = Vec::new();
        blob.extend_from_slice(BLOB_TS_MAGIC);
        blob.extend_from_slice(&BLOB_TS_VERSION.to_le_bytes());
        blob.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            matches!(decode_blob_tombstones(&blob), Err(DeltaError::Truncated(_))),
            "a forged huge count must fail loud, not allocate ~u32::MAX entries"
        );
    }

    /// The per-member SQL cursor's wire shape is DURABLE (stored in the manifest JSON), so lock it:
    /// `engine`-tagged, snake_case, and each variant maps back to its strategy kind.
    #[test]
    fn sql_member_cursor_wire_shape_and_kind() {
        let pg = SqlMemberCursor::PgLsn {
            lsn: "0/16B3748".into(),
        };
        let j = serde_json::to_string(&pg).unwrap();
        assert_eq!(j, r#"{"engine":"pg_lsn","lsn":"0/16B3748"}"#);
        assert_eq!(pg.kind(), SqlDeltaKind::PgWalReplay);
        assert_eq!(serde_json::from_str::<SqlMemberCursor>(&j).unwrap(), pg);

        let my = SqlMemberCursor::MysqlGtid {
            gtid: "3E11FA47-71CA:1-5".into(),
        };
        assert_eq!(
            serde_json::to_string(&my).unwrap(),
            r#"{"engine":"mysql_gtid","gtid":"3E11FA47-71CA:1-5"}"#
        );
        assert_eq!(my.kind(), SqlDeltaKind::MysqlBinlogReplay);

        let ls = SqlMemberCursor::LibsqlChangesetBase {
            base_sha256: "deadbeef".into(),
        };
        assert_eq!(
            serde_json::to_string(&ls).unwrap(),
            r#"{"engine":"libsql_changeset_base","base_sha256":"deadbeef"}"#
        );
        assert_eq!(ls.kind(), SqlDeltaKind::LibsqlChangeset);
    }

    /// The libsql changeset-delta member round-trips through its wire framing (an opaque changeset
    /// blob), an EMPTY changeset round-trips to empty, and a corrupt/foreign/short frame fails loud.
    #[test]
    fn libsql_changeset_wire_round_trip_and_loud_reject() {
        // An opaque binary "changeset" (the real one comes from the SQLite session engine; the
        // framing is engine-agnostic, so arbitrary bytes exercise it).
        let cs = b"\x00\x01\x02 a fake changeset with \x00 NULs and a ; and '".to_vec();
        let bytes = encode_libsql_changeset(&cs);
        assert_eq!(decode_libsql_changeset(&bytes).expect("round-trip"), cs);

        // Empty changeset (no row changes) round-trips to empty.
        let empty = encode_libsql_changeset(&[]);
        assert!(
            decode_libsql_changeset(&empty)
                .expect("empty round-trip")
                .is_empty()
        );

        // Foreign magic → loud BadMagic.
        assert!(matches!(
            decode_libsql_changeset(b"NOTACSET...."),
            Err(DeltaError::BadMagic)
        ));
        // Truncation (drop the last 3 bytes of the body) → loud Truncated.
        assert!(matches!(
            decode_libsql_changeset(&bytes[..bytes.len() - 3]),
            Err(DeltaError::Truncated(_))
        ));
        // An unknown framing version → loud UnsupportedVersion (forward-compat gate).
        let mut bad_ver = encode_libsql_changeset(&cs);
        bad_ver[8..12].copy_from_slice(&999u32.to_le_bytes());
        assert!(matches!(
            decode_libsql_changeset(&bad_ver),
            Err(DeltaError::UnsupportedVersion(999))
        ));
    }

    /// The SQL-delta scaffold: the fallback is NOT a true delta; the scaffolded strategies would be.
    #[test]
    fn sql_delta_strategy_scaffold() {
        assert!(!FullDumpFallback.is_true_delta());
        assert_eq!(FullDumpFallback.kind(), SqlDeltaKind::FullDumpFallback);
        assert!(!SqlDeltaKind::FullDumpFallback.is_true_delta());
        assert!(SqlDeltaKind::PgWalReplay.is_true_delta());
        assert!(SqlDeltaKind::MysqlBinlogReplay.is_true_delta());
        assert!(SqlDeltaKind::LibsqlChangeset.is_true_delta());
        // Default is the implemented fallback.
        assert_eq!(SqlDeltaKind::default(), SqlDeltaKind::FullDumpFallback);
    }
}
