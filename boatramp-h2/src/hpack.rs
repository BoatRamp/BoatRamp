//! HPACK (RFC 7541) codec state, wrapping the maintained `fluke-hpack`. The dynamic
//! table is stateful across a connection, so one [`Hpack`] lives per connection.

use crate::error::{ErrorCode, H2Error};
use crate::settings::DEFAULT_HEADER_TABLE_SIZE;
use fluke_hpack::{Decoder, Encoder};

pub struct Hpack {
    decoder: Decoder<'static>,
    encoder: Encoder<'static>,
    /// The SETTINGS_HEADER_TABLE_SIZE we advertised: a dynamic table size update
    /// larger than this is a COMPRESSION_ERROR (RFC 7541 §6.3).
    max_table_size: usize,
}

impl Default for Hpack {
    fn default() -> Self {
        Self::new()
    }
}

impl Hpack {
    pub fn new() -> Self {
        Self {
            decoder: Decoder::new(),
            encoder: Encoder::new(),
            max_table_size: DEFAULT_HEADER_TABLE_SIZE as usize,
        }
    }

    /// Decode a header block into `(name, value)` pairs. A malformed block is a
    /// connection error of type COMPRESSION_ERROR (RFC 7540 §4.3): HPACK is
    /// stateful, so a decode failure poisons the whole connection.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, H2Error> {
        // fluke-hpack `.unwrap()`-panics on a malformed dynamic-table-size-update
        // integer (its decoder.rs `update_max_dynamic_size`), and its own table-size
        // limit check is disabled (max_allowed_table_size is None). A hand-rolled
        // structural pre-scan closes both: it walks the block exactly as fluke does
        // and rejects any malformed integer/string (→ COMPRESSION_ERROR) before fluke
        // can panic, and enforces SETTINGS_HEADER_TABLE_SIZE on size updates (§6.3).
        // Found by fuzzing (tests/fuzz_smoke.rs) — a mid-block size update panicked.
        validate_block(block, self.max_table_size)?;
        self.decoder
            .decode(block)
            .map_err(|_| H2Error::conn(ErrorCode::CompressionError))
    }

    /// Encode a response header list into a header block fragment.
    pub fn encode(&mut self, headers: &[(&[u8], &[u8])]) -> Vec<u8> {
        self.encoder.encode(headers.iter().copied())
    }
}

/// Walk the HPACK block's structure the way fluke-hpack does (RFC 7541 §6), returning
/// `COMPRESSION_ERROR` for any malformed/truncated integer or string — the shapes
/// fluke would `.unwrap()`-panic on — and for a dynamic-table size update above `max`
/// (fluke's own size check is disabled). Field dispatch mirrors fluke's
/// `FieldRepresentation::new`; placement of size updates is left to fluke (we only
/// guard against panics + the size limit), so this accepts exactly what fluke
/// accepts, minus over-limit size updates.
fn validate_block(block: &[u8], max: usize) -> Result<(), H2Error> {
    let bad = || H2Error::conn(ErrorCode::CompressionError);
    let mut i = 0usize;
    while i < block.len() {
        let octet = block[i];
        if octet & 0x80 != 0 {
            // Indexed header field: a 7-bit index.
            i = hpack_int(block, i, 7).ok_or_else(bad)?.1;
        } else if octet & 0x40 != 0 {
            // Literal with incremental indexing: a 6-bit name index.
            i = literal(block, i, 6).ok_or_else(bad)?;
        } else if octet & 0x20 != 0 {
            // Dynamic table size update: a 5-bit value.
            let (val, next) = hpack_int(block, i, 5).ok_or_else(bad)?;
            if val > max {
                return Err(bad());
            }
            i = next;
        } else {
            // Literal never-indexed (0x10) / without-indexing (0x00): a 4-bit index.
            i = literal(block, i, 4).ok_or_else(bad)?;
        }
    }
    Ok(())
}

/// A literal field: an integer index; if it is 0 the name is a string literal; the
/// value is always a string literal. Returns the index past the whole field.
fn literal(block: &[u8], i: usize, prefix: u8) -> Option<usize> {
    let (idx, mut j) = hpack_int(block, i, prefix)?;
    if idx == 0 {
        j = hpack_str(block, j)?; // name is a string literal
    }
    hpack_str(block, j) // value is always a string literal
}

/// A string literal: a 7-bit length (the Huffman bit rides in the prefix byte) then
/// that many octets. Returns the bounds-checked index past it.
fn hpack_str(block: &[u8], i: usize) -> Option<usize> {
    let (len, j) = hpack_int(block, i, 7)?;
    let end = j.checked_add(len)?;
    (end <= block.len()).then_some(end)
}

/// Decode an HPACK variable-length integer with an `n`-bit prefix (RFC 7541 §5.1),
/// matching fluke-hpack's rules **exactly** — at most 5 octets total, truncation is
/// an error — so a value this accepts, fluke also accepts (no panic). Returns
/// `(value, index past it)`, or `None` on truncation/too-many-octets/overflow.
fn hpack_int(buf: &[u8], start: usize, prefix: u8) -> Option<(usize, usize)> {
    let mask = ((1u16 << prefix) - 1) as usize;
    let mut value = (*buf.get(start)? as usize) & mask;
    if value < mask {
        return Some((value, start + 1));
    }
    let mut i = start + 1;
    let mut total = 1usize; // octets consumed, including the prefix octet
    let mut m = 0u32;
    loop {
        let b = *buf.get(i)?; // truncated → None (fluke: NotEnoughOctets)
        i += 1;
        total += 1;
        value = value.checked_add(((b & 0x7f) as usize).checked_shl(m)?)?;
        m += 7;
        if b & 0x80 == 0 {
            return Some((value, i));
        }
        if total == 5 {
            return None; // fluke's octet_limit → TooManyOctets
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_through_a_matching_peer() {
        // Encode with one endpoint's encoder, decode with the other's decoder —
        // the shape a real connection uses (our encoder -> client's decoder). Here
        // we pair our encoder with a fresh decoder to prove the bytes are valid HPACK.
        let mut enc = Hpack::new();
        let block = enc.encode(&[(b":status", b"200"), (b"content-length", b"6")]);
        let mut dec = Hpack::new();
        let headers = dec.decode(&block).unwrap();
        assert_eq!(headers[0], (b":status".to_vec(), b"200".to_vec()));
        assert_eq!(headers[1], (b"content-length".to_vec(), b"6".to_vec()));
    }

    #[test]
    fn garbage_is_a_compression_error() {
        let mut h = Hpack::new();
        // 0xff-run drives the integer decoder past the end → error.
        let err = h.decode(&[0xff, 0xff, 0xff, 0xff, 0xff]).unwrap_err();
        assert_eq!(err, H2Error::conn(ErrorCode::CompressionError));
    }

    #[test]
    fn oversized_dynamic_table_size_update_is_rejected() {
        // A size update to 5000 (> the 4096 default): 001 prefix (0x3F, 5-bit all
        // ones) + a base-128 continuation for 5000-31.
        let mut block = vec![0x3fu8];
        let mut v = 5000usize - 31;
        while v >= 128 {
            block.push((v as u8 & 0x7f) | 0x80);
            v >>= 7;
        }
        block.push(v as u8);
        assert!(validate_block(&block, 4096).is_err());
        // Updates within the limit pass validation.
        assert!(validate_block(&[0x20], 4096).is_ok()); // -> 0
        assert!(validate_block(&[0x3f, 0x45], 4096).is_ok()); // -> 31 + 69 = 100
        // A non-update block (0x82 = indexed field ":method: GET") passes.
        assert!(validate_block(&[0x82], 4096).is_ok());
    }

    #[test]
    fn hpack_integer_matches_fluke_rules() {
        assert_eq!(hpack_int(&[0x0a], 0, 5), Some((10, 1))); // < prefix mask
        assert_eq!(hpack_int(&[0x3f, 0x45], 0, 5), Some((100, 2))); // 31 + 69
        // Truncated continuation → None (fluke: NotEnoughOctets, would panic on a
        // size update).
        assert_eq!(hpack_int(&[0x1f, 0x80], 0, 5), None);
        // Too many octets (>5 total) → None (fluke: TooManyOctets).
        assert_eq!(hpack_int(&[0x1f, 0x80, 0x80, 0x80, 0x80, 0x80], 0, 5), None);
    }
}
