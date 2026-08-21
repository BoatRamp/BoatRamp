//! HPACK (RFC 7541) header compression — boatramp-http's own codec, no external
//! HPACK crate. The dynamic table is stateful across a connection, so one [`Hpack`]
//! lives per connection.
//!
//! Decoding is **fail-closed**: any malformed field — a truncated/oversized integer
//! (§5.1), a truncated or bad-Huffman string (§5.2), a zero or out-of-range index
//! (§6.1), an over-`SETTINGS_HEADER_TABLE_SIZE` dynamic-table size update (§6.3) — is
//! a connection-level `COMPRESSION_ERROR` (RFC 7540 §4.3): HPACK state is shared, so
//! a decode failure poisons the whole connection. Encoding is server-shaped: exact
//! and name matches use the static table, everything else is a literal
//! **without indexing** (§6.2.2) — so we never touch the encode-side dynamic table
//! and both peers' tables stay trivially in sync — with Huffman applied when shorter.

mod huffman;
mod table;

use crate::h2::error::{ErrorCode, H2Error};
use crate::h2::settings::DEFAULT_HEADER_TABLE_SIZE;
use table::{DynamicTable, STATIC};

/// The `(name, value)` list a decoded header block yields.
type HeaderList = Vec<(Vec<u8>, Vec<u8>)>;

pub struct Hpack {
    dynamic: DynamicTable,
    /// The `SETTINGS_HEADER_TABLE_SIZE` we advertised: a size update above it is a
    /// COMPRESSION_ERROR (§6.3).
    max_table_size: usize,
}

impl Default for Hpack {
    fn default() -> Self {
        Self::new()
    }
}

impl Hpack {
    pub fn new() -> Self {
        let hard_max = DEFAULT_HEADER_TABLE_SIZE as usize;
        Self {
            dynamic: DynamicTable::new(hard_max),
            max_table_size: hard_max,
        }
    }

    /// Decode a header block into `(name, value)` pairs (RFC 7541 §6). Fail-closed:
    /// any malformed representation is a connection `COMPRESSION_ERROR`.
    pub fn decode(&mut self, block: &[u8]) -> Result<HeaderList, H2Error> {
        let bad = || H2Error::conn(ErrorCode::CompressionError);
        let mut headers = Vec::new();
        // A dynamic-table size update MUST occur at the start of the block, before
        // any header field (RFC 7541 §4.2): once a field has been decoded, a later
        // size update is a decoding error.
        let mut seen_field = false;
        let mut i = 0usize;
        while i < block.len() {
            let octet = block[i];
            if octet & 0x80 != 0 {
                // §6.1 Indexed Header Field: a 7-bit index into static ∪ dynamic.
                let (index, next) = decode_int(block, i, 7).ok_or_else(bad)?;
                let (n, v) = self.dynamic.get(index).ok_or_else(bad)?;
                headers.push((n.to_vec(), v.to_vec()));
                seen_field = true;
                i = next;
            } else if octet & 0x40 != 0 {
                // §6.2.1 Literal with Incremental Indexing: 6-bit name index; the
                // decoded entry is inserted into the dynamic table.
                let (name, value, next) = self.literal(block, i, 6)?;
                self.dynamic.insert(&name, &value);
                headers.push((name, value));
                seen_field = true;
                i = next;
            } else if octet & 0x20 != 0 {
                // §6.3 Dynamic Table Size Update: a 5-bit value, capped by
                // SETTINGS_HEADER_TABLE_SIZE and only legal before any field (§4.2).
                if seen_field {
                    return Err(bad());
                }
                let (size, next) = decode_int(block, i, 5).ok_or_else(bad)?;
                if size > self.max_table_size || !self.dynamic.set_max(size) {
                    return Err(bad());
                }
                i = next;
            } else {
                // §6.2.2 without indexing (0x00) / §6.2.3 never indexed (0x10): a
                // 4-bit name index; not added to the dynamic table.
                let (name, value, next) = self.literal(block, i, 4)?;
                headers.push((name, value));
                seen_field = true;
                i = next;
            }
        }
        Ok(headers)
    }

    /// Decode a literal field starting at `i`: an `prefix`-bit name index (0 ⇒ the
    /// name is a string literal, else it is taken from the table) followed by a
    /// string-literal value. Returns `(name, value, index past the field)`.
    fn literal(
        &self,
        block: &[u8],
        i: usize,
        prefix: u8,
    ) -> Result<(Vec<u8>, Vec<u8>, usize), H2Error> {
        let bad = || H2Error::conn(ErrorCode::CompressionError);
        let (name_index, mut j) = decode_int(block, i, prefix).ok_or_else(bad)?;
        let name = if name_index == 0 {
            let (n, next) = decode_str(block, j).ok_or_else(bad)?;
            j = next;
            n
        } else {
            let (n, _) = self.dynamic.get(name_index).ok_or_else(bad)?;
            n.to_vec()
        };
        let (value, next) = decode_str(block, j).ok_or_else(bad)?;
        Ok((name, value, next))
    }

    /// Encode a response header list into a header block fragment (§6). Names must
    /// already be lowercase (HTTP/2 §8.1.2), which the h2 layer guarantees.
    pub fn encode(&mut self, headers: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut out = Vec::new();
        for &(name, value) in headers {
            match static_lookup(name, value) {
                // §6.1 Indexed: an exact (name, value) hit in the static table.
                StaticMatch::Full(index) => encode_int(&mut out, index, 7, 0x80),
                // §6.2.2 without indexing, name from the static table (0x00 prefix,
                // 4-bit name index), value a string literal.
                StaticMatch::Name(index) => {
                    encode_int(&mut out, index, 4, 0x00);
                    encode_str(&mut out, value);
                }
                // §6.2.2 without indexing, both name and value string literals.
                StaticMatch::None => {
                    out.push(0x00);
                    encode_str(&mut out, name);
                    encode_str(&mut out, value);
                }
            }
        }
        out
    }
}

/// A static-table match for encoding a `(name, value)` pair.
enum StaticMatch {
    /// Exact `(name, value)` match at this 1-based index.
    Full(usize),
    /// Only the name matches, at this 1-based index.
    Name(usize),
    None,
}

fn static_lookup(name: &[u8], value: &[u8]) -> StaticMatch {
    let mut name_index = None;
    for (i, (n, v)) in STATIC.iter().enumerate() {
        if *n == name {
            if *v == value {
                return StaticMatch::Full(i + 1);
            }
            name_index.get_or_insert(i + 1);
        }
    }
    match name_index {
        Some(index) => StaticMatch::Name(index),
        None => StaticMatch::None,
    }
}

// ---- §5.1 integer coding --------------------------------------------------

/// Decode an HPACK variable-length integer with an `n`-bit prefix (RFC 7541 §5.1).
/// Returns `(value, index past it)`, or `None` on truncation, more than 5 octets
/// total, or overflow — the malformed shapes a decoder must reject, not crash on.
fn decode_int(buf: &[u8], start: usize, prefix: u8) -> Option<(usize, usize)> {
    let mask = ((1u16 << prefix) - 1) as usize;
    let value = (*buf.get(start)? as usize) & mask;
    if value < mask {
        return Some((value, start + 1));
    }
    let mut value = mask;
    let mut i = start + 1;
    let mut total = 1usize; // octets consumed, including the prefix octet
    let mut m = 0u32;
    loop {
        let b = *buf.get(i)?; // truncated continuation
        i += 1;
        total += 1;
        value = value.checked_add(((b & 0x7f) as usize).checked_shl(m)?)?;
        m += 7;
        if b & 0x80 == 0 {
            return Some((value, i));
        }
        if total == 5 {
            return None; // reject pathologically long encodings (5-octet cap)
        }
    }
}

/// Append `value` as an HPACK `n`-bit-prefix integer, OR-ing `flags` into the high
/// bits of the prefix octet (§5.1).
fn encode_int(out: &mut Vec<u8>, value: usize, prefix: u8, flags: u8) {
    let mask = (1usize << prefix) - 1;
    if value < mask {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | mask as u8);
    let mut v = value - mask;
    while v >= 128 {
        out.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

// ---- §5.2 string coding ---------------------------------------------------

/// Decode a string literal at `i`: a 1-bit Huffman flag + a 7-bit-prefix length,
/// then that many octets (§5.2). Returns `(bytes, index past it)`, or `None` on a
/// truncated length/body or a bad Huffman payload.
fn decode_str(block: &[u8], i: usize) -> Option<(Vec<u8>, usize)> {
    let huffman = block.get(i)? & 0x80 != 0;
    let (len, j) = decode_int(block, i, 7)?;
    let end = j.checked_add(len)?;
    let raw = block.get(j..end)?;
    let bytes = if huffman {
        huffman::decode(raw)?
    } else {
        raw.to_vec()
    };
    Some((bytes, end))
}

/// Append a string literal, choosing Huffman when it is strictly shorter (§5.2).
fn encode_str(out: &mut Vec<u8>, s: &[u8]) {
    if huffman::encoded_len(s) < s.len() {
        let encoded = huffman::encode(s);
        encode_int(out, encoded.len(), 7, 0x80);
        out.extend_from_slice(&encoded);
    } else {
        encode_int(out, s.len(), 7, 0x00);
        out.extend_from_slice(s);
    }
}

#[cfg(test)]
mod tests;
