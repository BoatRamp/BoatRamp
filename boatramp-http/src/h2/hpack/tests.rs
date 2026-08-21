//! HPACK codec tests: RFC 7541 Appendix C worked examples (decode against the
//! spec's own byte sequences), round-trips, dynamic-table behavior across a
//! connection, and the fail-closed error surface. The external correctness cross-
//! check (that our Huffman/static tables interoperate with a real peer) is the
//! `differential` test vs the `h2` crate and the h2spec conformance run.

use super::*;

fn decode1(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    Hpack::new().decode(bytes).expect("valid HPACK block")
}

/// RFC 7541 C.2.4 — Indexed Header Field (`:method: GET`) is a single octet 0x82.
#[test]
fn rfc_c2_4_indexed_static() {
    assert_eq!(
        decode1(&[0x82]),
        vec![(b":method".to_vec(), b"GET".to_vec())]
    );
    // …and our encoder emits exactly that for an exact static-table hit.
    assert_eq!(Hpack::new().encode(&[(b":method", b"GET")]), vec![0x82]);
}

/// RFC 7541 C.2.2 — Literal without Indexing, name from the static table
/// (`:path`, index 4), value a raw string literal.
#[test]
fn rfc_c2_2_literal_without_indexing() {
    let mut block = vec![0x04, 0x0c];
    block.extend_from_slice(b"/sample/path");
    assert_eq!(
        decode1(&block),
        vec![(b":path".to_vec(), b"/sample/path".to_vec())]
    );
}

/// RFC 7541 C.2.1 — Literal with Incremental Indexing, both name and value literal
/// (`custom-key: custom-header`) — and the entry lands in the dynamic table, so a
/// following Indexed reference to index 62 resolves to it.
#[test]
fn rfc_c2_1_literal_with_indexing_populates_dynamic_table() {
    let mut block = vec![0x40, 0x0a];
    block.extend_from_slice(b"custom-key");
    block.push(0x0d);
    block.extend_from_slice(b"custom-header");
    let mut h = Hpack::new();
    let headers = h.decode(&block).unwrap();
    assert_eq!(
        headers,
        vec![(b"custom-key".to_vec(), b"custom-header".to_vec())]
    );
    // Index 62 (first dynamic slot) now resolves to the inserted entry.
    assert_eq!(
        h.decode(&[0xbe]).unwrap(),
        vec![(b"custom-key".to_vec(), b"custom-header".to_vec())]
    );
}

/// A full server-shaped round-trip: encode a response header list, decode it with a
/// fresh peer, get the same headers back (mixing static-exact, static-name, and
/// fully-literal fields).
#[test]
fn response_roundtrip() {
    let headers: &[(&[u8], &[u8])] = &[
        (b":status", b"200"),
        (b"content-type", b"text/html; charset=utf-8"),
        (b"content-length", b"1234"),
        (
            b"x-custom-header",
            b"a value with UTF-8 \xe2\x98\x83 and symbols !@#",
        ),
        (b"cache-control", b"no-cache"),
    ];
    let block = Hpack::new().encode(headers);
    let decoded = Hpack::new().decode(&block).unwrap();
    let expected: Vec<_> = headers
        .iter()
        .map(|(n, v)| (n.to_vec(), v.to_vec()))
        .collect();
    assert_eq!(decoded, expected);
}

/// Huffman coding round-trips for a spread of inputs (empty, ASCII, all 256 octets,
/// long runs) — self-consistency of encode↔decode across the whole symbol table.
#[test]
fn huffman_roundtrip() {
    let all_bytes: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
    for case in [
        b"".as_slice(),
        b"www.example.com",
        b"text/html; charset=utf-8",
        b"!!!!!!!!",
        b"Mon, 21 Oct 2013 20:13:21 GMT",
        &all_bytes,
        &[0xffu8; 64],
    ] {
        let encoded = huffman::encode(case);
        assert_eq!(
            huffman::decode(&encoded).as_deref(),
            Some(case),
            "huffman roundtrip failed for {case:?}"
        );
        assert_eq!(huffman::encoded_len(case), encoded.len());
    }
}

/// A dynamic-table size update to 0 evicts everything and is honored; a later
/// reference to an evicted index is then a decode error.
#[test]
fn size_update_evicts() {
    let mut block = vec![0x40, 0x03];
    block.extend_from_slice(b"foo");
    block.push(0x03);
    block.extend_from_slice(b"bar");
    let mut h = Hpack::new();
    h.decode(&block).unwrap(); // inserts foo:bar at index 62
    assert_eq!(h.decode(&[0xbe]).unwrap()[0].0, b"foo"); // index 62 resolves
    h.decode(&[0x20]).unwrap(); // size update → 0, evicts the table
    assert!(h.decode(&[0xbe]).is_err()); // index 62 is gone → COMPRESSION_ERROR
}

/// Fail-closed surface: garbage integer runs, a zero index, an over-limit size
/// update, a truncated string, and an out-of-range index are all COMPRESSION_ERROR.
#[test]
fn malformed_blocks_are_compression_errors() {
    let err = H2Error::conn(ErrorCode::CompressionError);
    let mut h = Hpack::new();
    // 0xff-run drives the integer decoder past the end.
    assert_eq!(h.decode(&[0xff, 0xff, 0xff, 0xff, 0xff]).unwrap_err(), err);
    // Indexed field with index 0 (0x80) is illegal (§6.1).
    assert_eq!(Hpack::new().decode(&[0x80]).unwrap_err(), err);
    // A size update above SETTINGS_HEADER_TABLE_SIZE (4096): 0x3f + (5000-31) LEB128.
    let mut over = vec![0x3fu8];
    let mut v = 5000usize - 31;
    while v >= 128 {
        over.push((v as u8 & 0x7f) | 0x80);
        v >>= 7;
    }
    over.push(v as u8);
    assert_eq!(Hpack::new().decode(&over).unwrap_err(), err);
    // Literal claiming a 5-octet value but truncated.
    assert_eq!(
        Hpack::new()
            .decode(&[0x00, 0x00, 0x05, b'a', b'b'])
            .unwrap_err(),
        err
    );
    // Indexed reference to an unpopulated dynamic slot.
    assert_eq!(Hpack::new().decode(&[0xbe]).unwrap_err(), err);
    // A dynamic-table size update AFTER a header field (§4.2 — updates must be at
    // the start of the block): `:method GET` (0x82) then a size-update-to-0 (0x20).
    assert_eq!(Hpack::new().decode(&[0x82, 0x20]).unwrap_err(), err);
}

/// Bad Huffman payloads are rejected: a non-all-ones pad and a decoded EOS.
#[test]
fn bad_huffman_is_rejected() {
    // '0' is code 00000 (5 bits); the byte's low 3 bits are 0s → not the all-ones
    // pad, so `0x00` (00000_000) is an invalid Huffman string.
    assert_eq!(huffman::decode(&[0x00]), None);
    // A full byte of padding (8 ones) after a symbol is > 7 bits of padding.
    // Symbol '0' (00000) then 8 ones would need 13 bits → 2 bytes: 0000_0111 1111_1111
    // leaves 8 pad bits mid-code → rejected.
    assert_eq!(huffman::decode(&[0b0000_0111, 0b1111_1111]), None);
}
