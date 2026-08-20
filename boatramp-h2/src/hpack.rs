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
        // fluke-hpack asserts (panics) on an over-limit size update rather than
        // erroring, so screen the leading updates ourselves (§6.3: they occur only
        // at the start of a block).
        scan_size_updates(block, self.max_table_size)?;
        self.decoder
            .decode(block)
            .map_err(|_| H2Error::conn(ErrorCode::CompressionError))
    }

    /// Encode a response header list into a header block fragment.
    pub fn encode(&mut self, headers: &[(&[u8], &[u8])]) -> Vec<u8> {
        self.encoder.encode(headers.iter().copied())
    }
}

/// Reject a leading dynamic table size update larger than `max` (RFC 7541 §6.3).
/// Size updates (`001xxxxx`) may appear only at the start of a header block, so we
/// scan the prefix and stop at the first non-update octet.
fn scan_size_updates(block: &[u8], max: usize) -> Result<(), H2Error> {
    let mut i = 0;
    while i < block.len() {
        if block[i] & 0xE0 != 0x20 {
            break; // not a size update: the rest is header fields
        }
        let (val, next) = decode_integer(block, i, 5)
            .ok_or_else(|| H2Error::conn(ErrorCode::CompressionError))?;
        if val > max {
            return Err(H2Error::conn(ErrorCode::CompressionError));
        }
        i = next;
    }
    Ok(())
}

/// Decode an HPACK variable-length integer with an `n`-bit prefix (RFC 7541 §5.1),
/// returning `(value, index past it)`, or `None` on truncation/overflow.
fn decode_integer(buf: &[u8], mut i: usize, prefix: u8) -> Option<(usize, usize)> {
    let mask = (1usize << prefix) - 1;
    let mut value = (*buf.get(i)? as usize) & mask;
    i += 1;
    if value < mask {
        return Some((value, i));
    }
    let mut shift = 0u32;
    loop {
        let b = *buf.get(i)?;
        i += 1;
        value = value.checked_add(((b & 0x7f) as usize).checked_shl(shift)?)?;
        if b & 0x80 == 0 {
            return Some((value, i));
        }
        shift += 7;
        if shift > 28 {
            return None; // guard against pathological continuations
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
        assert!(scan_size_updates(&block, 4096).is_err());
        // Updates within the limit pass the scan.
        assert!(scan_size_updates(&[0x20], 4096).is_ok()); // -> 0
        assert!(scan_size_updates(&[0x3f, 0x45], 4096).is_ok()); // -> 31 + 69 = 100
        // A non-update block (0x82 = indexed field ":method: GET") passes.
        assert!(scan_size_updates(&[0x82], 4096).is_ok());
    }

    #[test]
    fn hpack_integer_decodes_prefix_and_continuation() {
        assert_eq!(decode_integer(&[0x0a], 0, 5), Some((10, 1))); // < prefix mask
        assert_eq!(decode_integer(&[0x3f, 0x45], 0, 5), Some((100, 2))); // 31 + 69
    }
}
