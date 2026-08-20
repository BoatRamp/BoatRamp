//! HPACK (RFC 7541) codec state, wrapping the maintained `fluke-hpack`. The dynamic
//! table is stateful across a connection, so one [`Hpack`] lives per connection.

use crate::error::{ErrorCode, H2Error};
use fluke_hpack::{Decoder, Encoder};

pub struct Hpack {
    decoder: Decoder<'static>,
    encoder: Encoder<'static>,
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
        }
    }

    /// Decode a header block into `(name, value)` pairs. A malformed block is a
    /// connection error of type COMPRESSION_ERROR (RFC 7540 §4.3): HPACK is
    /// stateful, so a decode failure poisons the whole connection.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>, H2Error> {
        self.decoder
            .decode(block)
            .map_err(|_| H2Error::conn(ErrorCode::CompressionError))
    }

    /// Encode a response header list into a header block fragment.
    pub fn encode(&mut self, headers: &[(&[u8], &[u8])]) -> Vec<u8> {
        self.encoder.encode(headers.iter().copied())
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
}
