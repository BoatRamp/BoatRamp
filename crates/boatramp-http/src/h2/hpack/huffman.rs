//! HPACK Huffman coding (RFC 7541 §5.2 + Appendix B). Encoding is a direct table
//! lookup per octet; decoding walks a binary trie built **once** for the whole
//! process (via [`OnceLock`]) — the fixed code table is immutable, so rebuilding a
//! decode structure per string (as some implementations do) is pure waste. Decoding
//! enforces the spec's guards: the EOS symbol must never appear in the data, and
//! trailing padding must be the EOS prefix (all ones) and strictly shorter than a
//! byte.

use std::sync::OnceLock;

/// The Appendix B code table, indexed by symbol (0..=255 for octets, 256 for EOS):
/// `(code, bit-length)`. The code's bits are stored right-aligned in the `u32`.
const CODES: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
];

/// The EOS symbol index (Appendix B): only valid as trailing padding, never as data.
const EOS: u16 = 256;

/// Huffman-encode `input` (RFC 7541 §5.2): concatenate each octet's code MSB-first,
/// then pad the final byte with the EOS prefix (all ones).
pub(super) fn encode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut acc: u64 = 0;
    let mut nbits: u32 = 0;
    for &b in input {
        let (code, len) = CODES[b as usize];
        acc = (acc << len) | u64::from(code);
        nbits += u32::from(len);
        while nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    if nbits > 0 {
        // Pad the low bits of the final byte with ones (the EOS prefix).
        let pad = 8 - nbits;
        out.push(((acc << pad) | ((1 << pad) - 1)) as u8);
    }
    out
}

/// Octets `input` would occupy Huffman-encoded — used to pick the shorter of
/// Huffman vs raw without materializing the encoding.
pub(super) fn encoded_len(input: &[u8]) -> usize {
    let bits: usize = input.iter().map(|&b| CODES[b as usize].1 as usize).sum();
    bits.div_ceil(8)
}

/// A node of the decode trie: `child[bit]` is either an inner-node index (>= 0) or a
/// leaf carrying a symbol, encoded as `-(symbol + 1)`; `NONE` marks an absent edge.
const NONE: i32 = i32::MIN;

fn trie() -> &'static Vec<[i32; 2]> {
    static TRIE: OnceLock<Vec<[i32; 2]>> = OnceLock::new();
    TRIE.get_or_init(|| {
        // Symbols 0..=255 are decodable leaves; EOS (256) is deliberately left out —
        // its full code appearing in data is a decoding error, and its prefix is only
        // valid as padding (handled at end-of-input, not as a leaf here).
        let mut nodes: Vec<[i32; 2]> = vec![[NONE, NONE]];
        for (sym, &(code, len)) in CODES.iter().enumerate() {
            if sym as u16 == EOS {
                continue;
            }
            let mut node = 0usize;
            for i in (0..len).rev() {
                let bit = ((code >> i) & 1) as usize;
                if i == 0 {
                    nodes[node][bit] = -(sym as i32 + 1); // leaf
                } else {
                    if nodes[node][bit] == NONE {
                        nodes.push([NONE, NONE]);
                        nodes[node][bit] = (nodes.len() - 1) as i32;
                    }
                    node = nodes[node][bit] as usize;
                }
            }
        }
        nodes
    })
}

/// Huffman-decode `input` (RFC 7541 §5.2). `None` on any decoding error: a code that
/// falls off the trie, a decoded EOS, padding that isn't the all-ones EOS prefix, or
/// padding of a full byte or more (§5.2 "a padding strictly longer than 7 bits ...
/// MUST be treated as a decoding error").
pub(super) fn decode(input: &[u8]) -> Option<Vec<u8>> {
    let trie = trie();
    let mut out = Vec::with_capacity(input.len() * 2);
    let mut node = 0i32; // current trie node; 0 == root
    let mut path_bits = 0u32; // bits consumed since the last leaf (the padding-so-far)
    let mut path_all_ones = true; // whether every such bit was a 1
    for &byte in input {
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) as usize;
            path_bits += 1;
            path_all_ones &= bit == 1;
            let next = trie[node as usize][bit];
            if next == NONE {
                return None; // no such code
            }
            if next < 0 {
                out.push((-next - 1) as u8); // leaf → emit the octet
                node = 0;
                path_bits = 0;
                path_all_ones = true;
            } else {
                node = next;
            }
        }
    }
    // A clean end sits at the root. Otherwise the leftover bits are padding, which
    // must be the EOS prefix: all ones and no wider than 7 bits.
    if node != 0 && (!path_all_ones || path_bits >= 8) {
        return None;
    }
    Some(out)
}
