//! Postgres logical-replication `pgoutput` (protocol version 1) message decoder.
//!
//! The pg WAL true-delta (SQL true-delta program, `PLAN-sql-true-delta.md`) captures a project's
//! changes since a base LSN by creating a `pgoutput` logical replication slot + a publication and
//! draining the slot over a NORMAL SQL connection with `pg_logical_slot_get_binary_changes(...)`
//! — which returns the raw `pgoutput` byte stream, one message per row, no replication-protocol
//! connection needed. The node length-frames each drained message into the delta member; this
//! module turns that framed stream back into relation schemas + row changes, which the node
//! replays as parameterized SQL onto the restored base inside the atomic shadow.
//!
//! Scope: proto v1, `columns`-in-TEXT format (the default — values are the type's text output, so
//! replay re-binds them as text and lets Postgres cast by the relation's column types). DDL is NOT
//! carried by logical decoding, so a schema change between base and delta is detected out-of-band
//! (the member's schema fingerprint) and falls back to a full dump — this decoder only ever sees
//! DML against a stable schema. Everything here is pure + `no_std`-friendly (alloc only) so it is
//! wasm-safe and unit-testable with crafted byte sequences (no live Postgres).

use std::collections::BTreeMap;

/// A loud `pgoutput` decode error (never a silent partial — a corrupt/truncated stream fails the
/// whole delta rather than applying part of a transaction).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PgoutputError {
    /// The framed stream or a message ended mid-field.
    #[error("truncated pgoutput stream at offset {0}")]
    Truncated(usize),
    /// An unknown top-level message type byte.
    #[error("unknown pgoutput message type {0:?} at offset {1}")]
    UnknownMessage(char, usize),
    /// A tuple column kind byte that is not `n`/`u`/`t`/`b`.
    #[error("unknown tuple column kind {0:?}")]
    BadColumnKind(char),
    /// A relation name / namespace that is not valid UTF-8.
    #[error("non-utf8 identifier in a Relation message")]
    BadIdentifier,
    /// An empty framed message (a zero-length frame).
    #[error("empty pgoutput message frame at offset {0}")]
    EmptyFrame(usize),
}

/// One column's value in a change tuple, in `pgoutput` TEXT representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TupleValue {
    /// SQL `NULL`.
    Null,
    /// A TOASTed value left UNCHANGED by an UPDATE (`'u'`) — the old value is retained, so an
    /// UPDATE replay must NOT touch this column (it has no value in the stream).
    UnchangedToast,
    /// The value in its type's TEXT output form (what replay binds as a text parameter).
    Text(String),
}

/// A row tuple: one [`TupleValue`] per column, positionally matching the [`Relation`] columns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tuple {
    /// Column values, in relation column order.
    pub values: Vec<TupleValue>,
}

/// A column of a [`Relation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationColumn {
    /// `1` if the column is part of the replica identity key, else `0`.
    pub key: bool,
    /// The column name.
    pub name: String,
    /// The column type OID (advisory — replay binds TEXT and lets Postgres cast).
    pub type_oid: u32,
}

/// A `Relation` message: the schema a subsequent Insert/Update/Delete for `rel_id` is decoded
/// against. The node keys replay SQL (table name + columns) off this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relation {
    /// The relation OID the change messages reference.
    pub rel_id: u32,
    /// Schema (namespace) name.
    pub namespace: String,
    /// Table name.
    pub name: String,
    /// `REPLICA IDENTITY` setting byte (`'d'` default, `'f'` full, `'i'` index, `'n'` nothing).
    pub replica_identity: u8,
    /// Columns in order.
    pub columns: Vec<RelationColumn>,
}

/// One decoded `pgoutput` change. The node replays Insert/Update/Delete as SQL and uses
/// Begin/Commit to wrap each source transaction in a matching transaction on the shadow (so a
/// delta's transactions stay atomic on replay). Truncate is carried for completeness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Transaction start (carries the final LSN + xid; replay opens a transaction).
    Begin { final_lsn: u64, xid: u32 },
    /// Transaction commit (replay commits).
    Commit { commit_lsn: u64, end_lsn: u64 },
    /// A relation schema — cache it; later changes reference `rel_id`.
    Relation(Relation),
    /// INSERT a new row.
    Insert { rel_id: u32, new: Tuple },
    /// UPDATE: the new row, plus the key/old tuple when `REPLICA IDENTITY` provided one (needed to
    /// locate the row on replay when the PK itself changed / for FULL identity).
    Update {
        rel_id: u32,
        key_or_old: Option<Tuple>,
        new: Tuple,
    },
    /// DELETE: the key/old tuple identifying the row to remove.
    Delete {
        rel_id: u32,
        key_or_old: Option<Tuple>,
    },
    /// TRUNCATE of one or more relations.
    Truncate { rel_ids: Vec<u32> },
}

/// Decode a framed `pgoutput` stream: a concatenation of `u32`-little-endian length-prefixed
/// messages (the node frames each drained `bytea` row this way, since raw `pgoutput` messages are
/// not self-delimiting). Returns the changes in stream order. A relation cache is NOT needed here
/// — the node carries [`Relation`] messages to replay; this just decodes faithfully.
pub fn decode_framed(buf: &[u8]) -> Result<Vec<Change>, PgoutputError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        // u32 LE length prefix.
        let end = pos
            .checked_add(4)
            .filter(|e| *e <= buf.len())
            .ok_or(PgoutputError::Truncated(pos))?;
        let len = u32::from_le_bytes(buf[pos..end].try_into().expect("4 bytes")) as usize;
        pos = end;
        if len == 0 {
            return Err(PgoutputError::EmptyFrame(pos));
        }
        let msg_end = pos
            .checked_add(len)
            .filter(|e| *e <= buf.len())
            .ok_or(PgoutputError::Truncated(pos))?;
        out.push(decode_message(&buf[pos..msg_end])?);
        pos = msg_end;
    }
    Ok(out)
}

/// Frame a single `pgoutput` message (one drained `bytea` row) for the delta member: a `u32` LE
/// length prefix + the raw bytes. The node calls this per drained row; [`decode_framed`] reverses it.
#[must_use]
pub fn frame_message(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + msg.len());
    out.extend_from_slice(&(msg.len() as u32).to_le_bytes());
    out.extend_from_slice(msg);
    out
}

/// Decode ONE raw `pgoutput` message (no framing). `pgoutput` message bodies are big-endian.
pub fn decode_message(msg: &[u8]) -> Result<Change, PgoutputError> {
    let mut r = Be { buf: msg, pos: 0 };
    let tag = r.u8()? as char;
    match tag {
        'B' => {
            let final_lsn = r.u64()?;
            let _commit_time = r.u64()?;
            let xid = r.u32()?;
            Ok(Change::Begin { final_lsn, xid })
        }
        'C' => {
            let _flags = r.u8()?;
            let commit_lsn = r.u64()?;
            let end_lsn = r.u64()?;
            let _commit_time = r.u64()?;
            Ok(Change::Commit {
                commit_lsn,
                end_lsn,
            })
        }
        'R' => {
            let rel_id = r.u32()?;
            let namespace = r.cstr()?;
            let name = r.cstr()?;
            let replica_identity = r.u8()?;
            let ncols = r.u16()? as usize;
            let mut columns = Vec::with_capacity(ncols.min(r.remaining() / 7));
            for _ in 0..ncols {
                let flags = r.u8()?;
                let cname = r.cstr()?;
                let type_oid = r.u32()?;
                let _type_mod = r.u32()?;
                columns.push(RelationColumn {
                    key: flags & 1 == 1,
                    name: cname,
                    type_oid,
                });
            }
            Ok(Change::Relation(Relation {
                rel_id,
                namespace,
                name,
                replica_identity,
                columns,
            }))
        }
        'I' => {
            let rel_id = r.u32()?;
            let marker = r.u8()? as char; // 'N'
            if marker != 'N' {
                return Err(PgoutputError::BadColumnKind(marker));
            }
            let new = r.tuple()?;
            Ok(Change::Insert { rel_id, new })
        }
        'U' => {
            let rel_id = r.u32()?;
            // Optional 'K' (key) or 'O' (old full) tuple, then the 'N' (new) tuple.
            let mut key_or_old = None;
            let mut marker = r.u8()? as char;
            if marker == 'K' || marker == 'O' {
                key_or_old = Some(r.tuple()?);
                marker = r.u8()? as char;
            }
            if marker != 'N' {
                return Err(PgoutputError::BadColumnKind(marker));
            }
            let new = r.tuple()?;
            Ok(Change::Update {
                rel_id,
                key_or_old,
                new,
            })
        }
        'D' => {
            let rel_id = r.u32()?;
            let marker = r.u8()? as char; // 'K' or 'O'
            if marker != 'K' && marker != 'O' {
                return Err(PgoutputError::BadColumnKind(marker));
            }
            let key_or_old = Some(r.tuple()?);
            Ok(Change::Delete { rel_id, key_or_old })
        }
        'T' => {
            let nrel = r.u32()? as usize;
            let _flags = r.u8()?;
            let mut rel_ids = Vec::with_capacity(nrel.min(r.remaining() / 4));
            for _ in 0..nrel {
                rel_ids.push(r.u32()?);
            }
            Ok(Change::Truncate { rel_ids })
        }
        // 'O' (origin), 'Y' (type), 'M' (logical message) carry no row change we replay; a caller
        // that enabled them would need handling, but boatramp's publication enables none — treat
        // as unknown so an unexpected stream fails loud rather than silently dropping data.
        other => Err(PgoutputError::UnknownMessage(other, r.pos)),
    }
}

/// Build a relation-id → [`Relation`] cache from a decoded stream (the node needs the schema to
/// render replay SQL for each Insert/Update/Delete).
#[must_use]
pub fn relation_cache(changes: &[Change]) -> BTreeMap<u32, Relation> {
    let mut m = BTreeMap::new();
    for c in changes {
        if let Change::Relation(rel) = c {
            m.insert(rel.rel_id, rel.clone());
        }
    }
    m
}

// ===========================================================================================
// Replay rendering — decoded changes → parameterized SQL (the untrusted-delta trust boundary)
// ===========================================================================================

/// A loud replay-render error. A delta that cannot be rendered to faithful SQL is REFUSED (the
/// engine falls back to a full dump), never applied partially.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplayError {
    /// A change referenced a relation id with no preceding `Relation` message.
    #[error("change references unknown relation id {0}")]
    UnknownRelation(u32),
    /// An UPDATE/DELETE on a table whose `REPLICA IDENTITY` is `nothing` — no way to match the
    /// row, so the delta cannot be replayed faithfully (⇒ full-dump fallback).
    #[error("table {0:?} has REPLICA IDENTITY NOTHING — cannot replay row updates/deletes")]
    NoReplicaIdentity(String),
    /// An UPDATE/DELETE whose old/key tuple is missing (the stream did not carry the row identity).
    #[error("missing old/key tuple for an update/delete on {0:?}")]
    MissingOldTuple(String),
    /// An INSERT carried an unchanged-TOAST column (only valid in an UPDATE's new tuple).
    #[error("unchanged-TOAST column in an INSERT on {0:?} (malformed stream)")]
    ToastInInsert(String),
    /// A tuple's column count did not match its relation's.
    #[error("tuple has {got} columns, relation {table:?} has {want}")]
    Arity {
        table: String,
        got: usize,
        want: usize,
    },
}

/// Quote a Postgres identifier (double-quote, escaping embedded quotes) — the ONLY way a decoded
/// relation/column name reaches the replay SQL, so an adversarial name is inert.
#[must_use]
pub fn quote_ident(ident: &str) -> String {
    let mut s = String::with_capacity(ident.len() + 2);
    s.push('"');
    for ch in ident.chars() {
        if ch == '"' {
            s.push('"');
        }
        s.push(ch);
    }
    s.push('"');
    s
}

/// Quote a value as a Postgres string LITERAL (`'…'`, doubling embedded quotes). A string literal
/// has the `unknown` type, so Postgres coerces it to the target column's type on apply — which is
/// why replay inlines values this way rather than binding typed `text` params (a `text` param will
/// NOT implicitly coerce to e.g. `int4`). SAFE only with `standard_conforming_strings = on` (the
/// modern default), which the node SETs on the replay session; combined with [`quote_ident`] for
/// every identifier, a crafted delta value/name cannot inject (the inc2 trust-boundary lesson),
/// and replay also runs as the ephemeral NON-superuser role on the isolated shadow as defence in depth.
#[must_use]
pub fn quote_literal(value: &str) -> String {
    let mut s = String::with_capacity(value.len() + 2);
    s.push('\'');
    for ch in value.chars() {
        if ch == '\'' {
            s.push('\'');
        }
        s.push(ch);
    }
    s.push('\'');
    s
}

/// The SQL literal for one tuple value: `NULL`, a quoted string literal, or — for an
/// unchanged-TOAST column — `None` (the caller decides: skip it in an UPDATE SET, refuse it in an
/// INSERT or a row-identity position).
fn lit(v: &TupleValue) -> Option<String> {
    match v {
        TupleValue::Null => Some("NULL".to_string()),
        TupleValue::Text(t) => Some(quote_literal(t)),
        TupleValue::UnchangedToast => None,
    }
}

/// Render a decoded `pgoutput` change stream into ordered replay SQL statements (Begin/Commit
/// become `BEGIN`/`COMMIT`, so a source transaction stays atomic on replay). Each statement is
/// complete, self-contained SQL with identifiers [`quote_ident`]'d and values inlined as
/// [`quote_literal`]'d literals (see that fn for why literals, not params). Maintains its own
/// relation cache from the `Relation` messages. Any change it cannot render faithfully is a loud
/// [`ReplayError`] — the engine then falls back to a full dump rather than apply a partial.
pub fn render_changes(changes: &[Change]) -> Result<Vec<String>, ReplayError> {
    let mut cache: BTreeMap<u32, &Relation> = BTreeMap::new();
    let mut out = Vec::new();
    for c in changes {
        match c {
            Change::Begin { .. } => out.push("BEGIN".to_string()),
            Change::Commit { .. } => out.push("COMMIT".to_string()),
            Change::Relation(r) => {
                cache.insert(r.rel_id, r);
            }
            Change::Insert { rel_id, new } => {
                let rel = *cache
                    .get(rel_id)
                    .ok_or(ReplayError::UnknownRelation(*rel_id))?;
                check_arity(rel, new)?;
                let mut cols = Vec::new();
                let mut vals = Vec::new();
                for (col, val) in rel.columns.iter().zip(&new.values) {
                    let v = lit(val).ok_or_else(|| ReplayError::ToastInInsert(rel.name.clone()))?;
                    cols.push(quote_ident(&col.name));
                    vals.push(v);
                }
                out.push(format!(
                    "INSERT INTO {} ({}) VALUES ({})",
                    qtable(rel),
                    cols.join(", "),
                    vals.join(", ")
                ));
            }
            Change::Update {
                rel_id,
                key_or_old,
                new,
            } => {
                let rel = *cache
                    .get(rel_id)
                    .ok_or(ReplayError::UnknownRelation(*rel_id))?;
                check_arity(rel, new)?;
                // SET: every column whose new value is concrete or NULL (skip unchanged-TOAST —
                // the old value is retained).
                let mut sets = Vec::new();
                for (col, val) in rel.columns.iter().zip(&new.values) {
                    if let Some(v) = lit(val) {
                        sets.push(format!("{} = {}", quote_ident(&col.name), v));
                    }
                }
                let where_sql = render_where(rel, key_or_old.as_ref(), Some(new))?;
                out.push(format!(
                    "UPDATE {} SET {} WHERE {}",
                    qtable(rel),
                    sets.join(", "),
                    where_sql
                ));
            }
            Change::Delete { rel_id, key_or_old } => {
                let rel = *cache
                    .get(rel_id)
                    .ok_or(ReplayError::UnknownRelation(*rel_id))?;
                let where_sql = render_where(rel, key_or_old.as_ref(), None)?;
                out.push(format!("DELETE FROM {} WHERE {}", qtable(rel), where_sql));
            }
            Change::Truncate { rel_ids } => {
                for rel_id in rel_ids {
                    let rel = *cache
                        .get(rel_id)
                        .ok_or(ReplayError::UnknownRelation(*rel_id))?;
                    out.push(format!("TRUNCATE {}", qtable(rel)));
                }
            }
        }
    }
    Ok(out)
}

/// `"ns"."table"` — both halves quoted.
fn qtable(rel: &Relation) -> String {
    format!("{}.{}", quote_ident(&rel.namespace), quote_ident(&rel.name))
}

fn check_arity(rel: &Relation, t: &Tuple) -> Result<(), ReplayError> {
    if t.values.len() != rel.columns.len() {
        return Err(ReplayError::Arity {
            table: rel.name.clone(),
            got: t.values.len(),
            want: rel.columns.len(),
        });
    }
    Ok(())
}

/// Build the `WHERE` fragment that identifies the row for an UPDATE/DELETE, per the relation's
/// `REPLICA IDENTITY`: `full` matches on ALL columns of the old tuple; `default`/`index` match on
/// the key columns (old tuple if present, else the new tuple at the key positions); `nothing`
/// cannot match (loud error → full-dump fallback). Values inlined as literals.
fn render_where(
    rel: &Relation,
    old: Option<&Tuple>,
    new: Option<&Tuple>,
) -> Result<String, ReplayError> {
    // Columns that identify the row, with the tuple to read their values from.
    let (match_cols, source): (Vec<usize>, &Tuple) = match rel.replica_identity {
        b'f' => {
            // FULL: every column, from the old tuple (which carries all old values).
            let src = old.ok_or_else(|| ReplayError::MissingOldTuple(rel.name.clone()))?;
            check_arity(rel, src)?;
            ((0..rel.columns.len()).collect(), src)
        }
        b'd' | b'i' => {
            let keys: Vec<usize> = rel
                .columns
                .iter()
                .enumerate()
                .filter(|(_, c)| c.key)
                .map(|(i, _)| i)
                .collect();
            if keys.is_empty() {
                return Err(ReplayError::NoReplicaIdentity(rel.name.clone()));
            }
            // Prefer the old/key tuple (present when the key changed or on DELETE); else the new
            // tuple carries the current key (an UPDATE that left the key unchanged).
            let src = old
                .or(new)
                .ok_or_else(|| ReplayError::MissingOldTuple(rel.name.clone()))?;
            check_arity(rel, src)?;
            (keys, src)
        }
        _ => return Err(ReplayError::NoReplicaIdentity(rel.name.clone())),
    };
    let mut frags = Vec::new();
    for i in match_cols {
        let col = quote_ident(&rel.columns[i].name);
        match &source.values[i] {
            TupleValue::Null => frags.push(format!("{col} IS NULL")),
            TupleValue::Text(t) => frags.push(format!("{col} = {}", quote_literal(t))),
            // An unchanged-TOAST value in a row-identity position cannot be matched — refuse.
            TupleValue::UnchangedToast => {
                return Err(ReplayError::MissingOldTuple(rel.name.clone()));
            }
        }
    }
    Ok(frags.join(" AND "))
}

/// A big-endian reader with loud bounds checks (mirrors the project_delta `FrameReader`).
struct Be<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Be<'a> {
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], PgoutputError> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.buf.len())
            .ok_or(PgoutputError::Truncated(self.pos))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, PgoutputError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, PgoutputError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("2")))
    }
    fn u32(&mut self) -> Result<u32, PgoutputError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("4")))
    }
    fn u64(&mut self) -> Result<u64, PgoutputError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("8")))
    }
    /// A C string (null-terminated) interpreted as UTF-8.
    fn cstr(&mut self) -> Result<String, PgoutputError> {
        let start = self.pos;
        while self.pos < self.buf.len() && self.buf[self.pos] != 0 {
            self.pos += 1;
        }
        if self.pos >= self.buf.len() {
            return Err(PgoutputError::Truncated(start));
        }
        let s = std::str::from_utf8(&self.buf[start..self.pos])
            .map_err(|_| PgoutputError::BadIdentifier)?
            .to_string();
        self.pos += 1; // consume the NUL
        Ok(s)
    }
    /// A `TupleData`: Int16 column count, then per column a kind byte and (for `'t'`/`'b'`) an
    /// Int32 length + bytes.
    fn tuple(&mut self) -> Result<Tuple, PgoutputError> {
        let ncols = self.u16()? as usize;
        // Each column is at least its 1-byte kind, so bound the pre-size by the bytes left.
        let mut values = Vec::with_capacity(ncols.min(self.remaining()));
        for _ in 0..ncols {
            let kind = self.u8()? as char;
            let v = match kind {
                'n' => TupleValue::Null,
                'u' => TupleValue::UnchangedToast,
                't' | 'b' => {
                    // 't' = text form; 'b' = binary (we request text, but accept + stringify
                    // lossily so an unexpected binary column fails at apply, not here).
                    let len = self.u32()? as usize;
                    let bytes = self.take(len)?;
                    TupleValue::Text(String::from_utf8_lossy(bytes).into_owned())
                }
                other => return Err(PgoutputError::BadColumnKind(other)),
            };
            values.push(v);
        }
        Ok(Tuple { values })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Assemble a raw `pgoutput` message from a tag + big-endian body pieces (test helper).
    fn msg(tag: char, body: &[u8]) -> Vec<u8> {
        let mut v = vec![tag as u8];
        v.extend_from_slice(body);
        v
    }

    fn be32(n: u32) -> [u8; 4] {
        n.to_be_bytes()
    }

    /// A text tuple column: kind 't' + len + bytes.
    fn tcol(s: &str) -> Vec<u8> {
        let mut v = vec![b't'];
        v.extend_from_slice(&be32(s.len() as u32));
        v.extend_from_slice(s.as_bytes());
        v
    }

    #[test]
    fn decodes_begin_relation_insert_commit() {
        // Relation: rel_id=42, ns="public", name="t", replicaId='d', 2 cols (id key, c).
        let mut rel = Vec::new();
        rel.extend_from_slice(&be32(42));
        rel.extend_from_slice(b"public\0t\0");
        rel.push(b'd');
        rel.extend_from_slice(&2u16.to_be_bytes());
        // col id: flags=1 (key), name, type_oid=23 (int4), typmod=-1
        rel.push(1);
        rel.extend_from_slice(b"id\0");
        rel.extend_from_slice(&be32(23));
        rel.extend_from_slice(&be32(0xFFFF_FFFF));
        // col c: flags=0, name, type_oid=25 (text), typmod=-1
        rel.push(0);
        rel.extend_from_slice(b"c\0");
        rel.extend_from_slice(&be32(25));
        rel.extend_from_slice(&be32(0xFFFF_FFFF));

        // Insert: rel_id=42, 'N', tuple(2 cols): id='1', c='hi'
        let mut ins = Vec::new();
        ins.extend_from_slice(&be32(42));
        ins.push(b'N');
        ins.extend_from_slice(&2u16.to_be_bytes());
        ins.extend_from_slice(&tcol("1"));
        ins.extend_from_slice(&tcol("hi"));

        let mut begin = Vec::new();
        begin.extend_from_slice(&123u64.to_be_bytes()); // final LSN
        begin.extend_from_slice(&0u64.to_be_bytes()); // commit time
        begin.extend_from_slice(&7u32.to_be_bytes()); // xid

        let stream = [
            frame_message(&msg('B', &begin)),
            frame_message(&msg('R', &rel)),
            frame_message(&msg('I', &ins)),
            // Commit body: flags(1) + commit_lsn(8) + end_lsn(8) + commit_time(8) = 25 bytes.
            frame_message(&msg('C', &[0u8; 25])),
        ]
        .concat();

        let changes = decode_framed(&stream).expect("decode");
        assert_eq!(changes.len(), 4);
        assert_eq!(
            changes[0],
            Change::Begin {
                final_lsn: 123,
                xid: 7
            }
        );
        let Change::Relation(r) = &changes[1] else {
            panic!("expected relation")
        };
        assert_eq!(r.rel_id, 42);
        assert_eq!(r.namespace, "public");
        assert_eq!(r.name, "t");
        assert_eq!(r.columns.len(), 2);
        assert!(r.columns[0].key);
        assert_eq!(r.columns[0].name, "id");
        assert_eq!(r.columns[1].name, "c");
        assert_eq!(
            changes[2],
            Change::Insert {
                rel_id: 42,
                new: Tuple {
                    values: vec![TupleValue::Text("1".into()), TupleValue::Text("hi".into())]
                }
            }
        );
        assert!(matches!(changes[3], Change::Commit { .. }));

        // The relation cache keys by rel_id.
        let cache = relation_cache(&changes);
        assert_eq!(cache.get(&42).unwrap().name, "t");
    }

    #[test]
    fn decodes_update_with_key_and_unchanged_toast() {
        // Update rel 9: KEY tuple (old id='1'), NEW tuple (id='1', big='u' unchanged toast).
        let mut upd = Vec::new();
        upd.extend_from_slice(&be32(9));
        upd.push(b'K');
        upd.extend_from_slice(&1u16.to_be_bytes());
        upd.extend_from_slice(&tcol("1"));
        upd.push(b'N');
        upd.extend_from_slice(&2u16.to_be_bytes());
        upd.extend_from_slice(&tcol("1"));
        upd.push(b'u'); // unchanged toast

        let changes = decode_framed(&frame_message(&msg('U', &upd))).expect("decode");
        assert_eq!(
            changes[0],
            Change::Update {
                rel_id: 9,
                key_or_old: Some(Tuple {
                    values: vec![TupleValue::Text("1".into())]
                }),
                new: Tuple {
                    values: vec![TupleValue::Text("1".into()), TupleValue::UnchangedToast]
                }
            }
        );
    }

    #[test]
    fn decodes_delete_and_null() {
        // Delete rel 9: old tuple (id='5', c=null).
        let mut del = Vec::new();
        del.extend_from_slice(&be32(9));
        del.push(b'O');
        del.extend_from_slice(&2u16.to_be_bytes());
        del.extend_from_slice(&tcol("5"));
        del.push(b'n'); // null
        let changes = decode_framed(&frame_message(&msg('D', &del))).expect("decode");
        assert_eq!(
            changes[0],
            Change::Delete {
                rel_id: 9,
                key_or_old: Some(Tuple {
                    values: vec![TupleValue::Text("5".into()), TupleValue::Null]
                }),
            }
        );
    }

    #[test]
    fn loud_on_truncation_and_bad_tag() {
        // A length prefix claiming more than the buffer holds → Truncated, no panic/over-alloc.
        let mut forged = Vec::new();
        forged.extend_from_slice(&u32::MAX.to_le_bytes());
        forged.push(b'I');
        assert!(matches!(
            decode_framed(&forged),
            Err(PgoutputError::Truncated(_))
        ));
        // Unknown message tag fails loud.
        assert!(matches!(
            decode_message(b"Zxxxx"),
            Err(PgoutputError::UnknownMessage('Z', _))
        ));
        // A zero-length frame is refused.
        assert!(matches!(
            decode_framed(&0u32.to_le_bytes()),
            Err(PgoutputError::EmptyFrame(_))
        ));
    }

    // ---- replay rendering ----

    fn rel(rel_id: u32, ns: &str, name: &str, ri: u8, cols: &[(&str, bool)]) -> Change {
        Change::Relation(Relation {
            rel_id,
            namespace: ns.into(),
            name: name.into(),
            replica_identity: ri,
            columns: cols
                .iter()
                .map(|(n, k)| RelationColumn {
                    key: *k,
                    name: (*n).into(),
                    type_oid: 25,
                })
                .collect(),
        })
    }
    fn txt(s: &str) -> TupleValue {
        TupleValue::Text(s.into())
    }
    fn tup(vs: Vec<TupleValue>) -> Tuple {
        Tuple { values: vs }
    }

    #[test]
    fn renders_insert_update_delete_with_default_identity() {
        let changes = vec![
            rel(1, "public", "t", b'd', &[("id", true), ("c", false)]),
            Change::Insert {
                rel_id: 1,
                new: tup(vec![txt("1"), txt("hi")]),
            },
            // UPDATE that left the key unchanged (no key tuple) → WHERE on new's key col.
            Change::Update {
                rel_id: 1,
                key_or_old: None,
                new: tup(vec![txt("1"), txt("bye")]),
            },
            Change::Delete {
                rel_id: 1,
                key_or_old: Some(tup(vec![txt("1"), TupleValue::Null])),
            },
        ];
        let stmts = render_changes(&changes).expect("render");
        assert_eq!(
            stmts,
            vec![
                r#"INSERT INTO "public"."t" ("id", "c") VALUES ('1', 'hi')"#.to_string(),
                // UPDATE sets both columns, matches on the key column from the new tuple.
                r#"UPDATE "public"."t" SET "id" = '1', "c" = 'bye' WHERE "id" = '1'"#.to_string(),
                r#"DELETE FROM "public"."t" WHERE "id" = '1'"#.to_string(),
            ]
        );
    }

    #[test]
    fn full_identity_matches_all_columns_and_unchanged_toast_skipped_in_set() {
        let changes = vec![
            rel(5, "app", "doc", b'f', &[("id", false), ("body", false)]),
            // UPDATE with FULL identity: old = all old values; new body is unchanged-TOAST.
            Change::Update {
                rel_id: 5,
                key_or_old: Some(tup(vec![txt("7"), txt("old-body")])),
                new: tup(vec![txt("7"), TupleValue::UnchangedToast]),
            },
        ];
        let stmts = render_changes(&changes).expect("render");
        // SET only the id (body is unchanged-TOAST → omitted); WHERE on ALL old columns.
        assert_eq!(
            stmts[0],
            r#"UPDATE "app"."doc" SET "id" = '7' WHERE "id" = '7' AND "body" = 'old-body'"#
        );
    }

    #[test]
    fn crafted_name_and_value_cannot_inject() {
        // A malicious table/column NAME (quoted as an identifier) AND a malicious VALUE (quoted as
        // a string literal) must both be escaped, not executed.
        let changes = vec![
            rel(
                9,
                r#"ns"x"#,
                r#"t"; DROP TABLE users; --"#,
                b'd',
                &[("id", true), ("c", false)],
            ),
            Change::Insert {
                rel_id: 9,
                new: tup(vec![txt("1"), txt("x'); DROP TABLE users; --")]),
            },
        ];
        let stmts = render_changes(&changes).expect("render");
        assert_eq!(
            stmts[0],
            r#"INSERT INTO "ns""x"."t""; DROP TABLE users; --" ("id", "c") VALUES ('1', 'x''); DROP TABLE users; --')"#
        );
        // The dangerous name is inside a quoted identifier; the dangerous value inside a quoted
        // string literal (the `'` doubled) — both inert.
        assert!(stmts[0].contains(r#""t""; DROP TABLE users; --""#));
        assert!(stmts[0].contains(r#"'x''); DROP TABLE users; --'"#));
    }

    #[test]
    fn replay_refuses_unknown_relation_and_no_identity() {
        // No Relation message for the id → UnknownRelation.
        assert_eq!(
            render_changes(&[Change::Insert {
                rel_id: 1,
                new: tup(vec![txt("1")])
            }]),
            Err(ReplayError::UnknownRelation(1))
        );
        // REPLICA IDENTITY NOTHING on a DELETE → cannot match → refuse (full-dump fallback).
        let changes = vec![
            rel(2, "public", "noident", b'n', &[("a", false)]),
            Change::Delete {
                rel_id: 2,
                key_or_old: Some(tup(vec![txt("x")])),
            },
        ];
        assert_eq!(
            render_changes(&changes),
            Err(ReplayError::NoReplicaIdentity("noident".into()))
        );
    }
}
