//! M5 fuzzing (stable-runnable slice): throw a large volume of deterministic
//! pseudo-random bytes at the frame + HPACK parsers and assert none of them panic,
//! hang, or overflow. This is the always-on regression net; `fuzz/` holds the
//! coverage-guided cargo-fuzz targets for deeper exploration. A panicking parser is
//! a DoS vector (the connection driver hands it attacker-controlled bytes), so
//! "never panics" is the invariant.

use boatramp_http::h2::frame::{self, FrameHeader};
use boatramp_http::h2::hpack::Hpack;

/// xorshift64* — a tiny deterministic PRNG (no external deps, reproducible seed).
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let len = (self.next() as usize) % (max + 1);
        (0..len).map(|_| self.next() as u8).collect()
    }
}

#[test]
fn frame_parsers_never_panic_on_random_input() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for _ in 0..300_000 {
        let b = rng.bytes(80);
        let _ = frame::strip_padding(&b, true);
        let _ = frame::strip_padding(&b, false);
        let _ = frame::parse_settings(&b);
        let _ = frame::parse_window_update(&b);
        let _ = frame::parse_rst_stream(&b);
        let _ = frame::parse_ping(&b);
        let _ = frame::parse_priority(&b);
        let _ = frame::parse_goaway(&b);
        if b.len() >= frame::FRAME_HEADER_LEN {
            let _ = FrameHeader::parse(&b);
        }
    }
}

#[test]
fn hpack_decode_never_panics_on_random_input() {
    // HPACK is the most panic-prone parser (variable-length ints, dynamic-table size
    // updates that the underlying codec asserts on) — fuzz it harder and longer.
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for _ in 0..300_000 {
        let b = rng.bytes(256);
        let mut h = Hpack::new();
        let _ = h.decode(&b);
    }
    // Also feed adversarial prefixes: leading dynamic-table-size-update bytes (0x20..)
    // plus long 0xff integer continuations, the shapes most likely to overflow.
    let mut rng = Rng(0x0BAD_C0DE_DEAD_BEEF);
    for _ in 0..100_000 {
        let mut b = vec![0x20 | (rng.next() as u8 & 0x1f)];
        b.extend((0..(rng.next() as usize % 12)).map(|_| 0xff));
        b.push(rng.next() as u8 & 0x7f);
        b.extend(rng.bytes(32));
        let mut h = Hpack::new();
        let _ = h.decode(&b);
    }
}
