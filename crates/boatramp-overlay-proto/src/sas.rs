//! Short-authentication-string (SAS) derivation and identity fingerprints —
//! the pure, display-only crypto for overlay **pairing** (enrollment follow-up).
//!
//! When two peers complete the relay-blind E2EE handshake ([`crate::e2ee`]) they
//! share a channel-binding transcript, `SHA-256(offer ‖ reply ‖ initiator ‖
//! responder)`, which already folds **both** KEM shares and **both** identities
//! in a fixed initiator-then-responder order (see [`crate::e2ee::transcript`]).
//! Two honest peers compute the SAME transcript; a man-in-the-middle, who
//! necessarily runs two *distinct* handshake legs, computes a DIFFERENT
//! transcript on each side. So a short string derived deterministically from the
//! transcript — compared out-of-band by the humans/operators pairing the
//! devices — detects an active MITM: if the two SAS codes match, no one sat in
//! the middle.
//!
//! This module is pure and deterministic: no RNG, no network, no async. It is
//! kept in the pure-core crate so the **CLI and the console render the exact
//! same code** from the same transcript (a versioned wordlist, below).
//!
//! ## Why HKDF off the transcript, and the domain tag
//!
//! The SAS bits are `HKDF-SHA256(salt = [`wire::TAG_SAS`], ikm = transcript)`.
//! The salt is a fixed domain tag (`bro-sas-v1`), so the SAS is **domain-
//! separated** from every other value derived from the same transcript — in
//! particular from the session keys, which are derived the *other* way around
//! (`salt = transcript`, `ikm = combined-KEM-secret`; see
//! [`crate::e2ee::Session::new`]). The SAS therefore reveals nothing about the
//! session keys even though both descend from the handshake.

use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};

use crate::identity::OverlayId;
use crate::wire;

/// The number of SAS bits rendered for human comparison.
///
/// **N = 24 (3 bytes).** An active man-in-the-middle wins only by driving its
/// two independent handshake legs to transcripts whose SAS codes collide; with
/// N uniformly-random bits that succeeds with probability `2^-N` **per attempt**.
/// 24 bits gives `2^-24 ≈ 6·10⁻⁸` — one in ~16.7 million — the standard strength
/// band for a one-shot, human-compared SAS (short enough to read aloud, large
/// enough that a `2^-24`-per-ONLINE-attempt MITM is infeasible within a pairing
/// window). 24 bits also renders cleanly in **both** required forms: 3 bytes → 3
/// words (one byte per entry of a 256-word list), and `0..=16_777_215` → 8 decimal
/// digits for a keypad.
///
/// **CRITICAL — this `2^-24` strength holds ONLY if the pair handshake commits
/// before it reveals.** The SAS is derived from the (public, un-committed) KEM
/// transcript `SHA-256(offer ‖ reply ‖ init ‖ resp)`. A MITM acting as responder
/// on a leg chooses its `reply` AFTER seeing the peer's offer, so it can complete
/// the OTHER leg first, learn that leg's SAS (a fixed 24-bit target), then grind
/// its own fresh ephemeral `reply` **offline** (~2^24 local keygen+hash ≈ minutes)
/// until the two SAS collide — nothing forces it to fix its contribution before
/// learning the target. The pairing protocol (feature-2 inc1) MUST therefore use
/// commit-then-reveal (each side commits `H(contribution)` before any reveal, à la
/// ZRTP / Bluetooth numeric-comparison), which restores `2^-24` PER-ONLINE-ATTEMPT.
/// Without that commitment, N=24 is offline-grindable and the detection is far
/// weaker than `2^-24`. The pairing flow MUST also require a positive match
/// (fail-closed), never treat a mismatch as benign.
pub const SAS_BITS: usize = 24;

/// SAS length in bytes (`SAS_BITS / 8`).
const SAS_BYTES: usize = SAS_BITS / 8;

/// Number of words a SAS renders to — one per byte, from the 256-word list.
pub const SAS_WORDS: usize = SAS_BYTES;

/// Version of the embedded [`WORDLIST`] + rendering. Baked alongside the
/// `-v1` of [`wire::TAG_SAS`]: CLI and console MUST agree on this to render the
/// same words, so a change here is a pairing-UX break and bumps the suffix.
pub const SAS_WORDLIST_VERSION: u32 = 1;

/// Bytes of identity fingerprint (64 bits) — enough that two distinct overlay
/// identities collide in display with negligible probability, short enough to
/// print.
const FP_BYTES: usize = 8;

/// A length-only [`KeyType`] so HKDF-Expand can emit an arbitrary byte count.
#[derive(Clone, Copy)]
struct ByteLen(usize);

impl KeyType for ByteLen {
    fn len(&self) -> usize {
        self.0
    }
}

/// `HKDF-SHA256(salt = salt_tag, ikm)` expanded (empty info) into `out`.
///
/// Infallible for the tiny fixed output sizes used here (HKDF-Expand only fails
/// for lengths above `255 · HashLen = 8160` bytes); the `expect`s document that.
fn hkdf_expand(salt_tag: &[u8], ikm: &[u8], out: &mut [u8]) {
    let prk = Salt::new(HKDF_SHA256, salt_tag).extract(ikm);
    let no_info: [&[u8]; 0] = [];
    let okm = prk
        .expand(&no_info, ByteLen(out.len()))
        .expect("HKDF-Expand of a few bytes is infallible");
    okm.fill(out)
        .expect("HKDF-Expand fill of a few bytes is infallible");
}

/// A short authentication string derived from an E2EE handshake transcript. The
/// humans pairing two devices compare it out-of-band; a match rules out an active
/// relay-in-the-middle. Exposes both renderings (words, keypad digits) and the
/// raw bits.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SasCode {
    bits: [u8; SAS_BYTES],
}

impl SasCode {
    /// The raw SAS bits (`SAS_BITS / 8` bytes).
    #[must_use]
    pub fn bits(&self) -> &[u8; SAS_BYTES] {
        &self.bits
    }

    /// The 24-bit value, big-endian, for keypad rendering.
    #[must_use]
    fn value(&self) -> u32 {
        let mut v = 0u32;
        for &b in &self.bits {
            v = (v << 8) | u32::from(b);
        }
        v
    }

    /// The word rendering: one word per byte from the versioned [`WORDLIST`],
    /// joined by `-` (e.g. `"cargo-delta-hotel"`). Round-trips via
    /// [`SasCode::from_words`].
    #[must_use]
    pub fn words(&self) -> String {
        self.bits
            .iter()
            .map(|&b| WORDLIST[b as usize])
            .collect::<Vec<_>>()
            .join("-")
    }

    /// The keypad rendering: the 24-bit value as 8 zero-padded decimal digits,
    /// grouped in two blocks of four (e.g. `"1677 7215"`). The full width always
    /// shows, so the code reads unambiguously on a numeric keypad.
    #[must_use]
    pub fn digits(&self) -> String {
        let d = format!("{:08}", self.value());
        format!("{} {}", &d[..4], &d[4..])
    }

    /// Parse a word rendering ([`SasCode::words`]) back to the SAS. Accepts
    /// `-` or whitespace separators and is case-insensitive. `None` if the word
    /// count is wrong or any token is not in the versioned wordlist — so a
    /// mistyped code never silently maps to a different SAS.
    #[must_use]
    pub fn from_words(s: &str) -> Option<Self> {
        let lower = s.to_ascii_lowercase();
        let tokens: Vec<&str> = lower
            .split(|c: char| c == '-' || c.is_whitespace())
            .filter(|t| !t.is_empty())
            .collect();
        if tokens.len() != SAS_BYTES {
            return None;
        }
        let mut bits = [0u8; SAS_BYTES];
        for (slot, tok) in bits.iter_mut().zip(tokens) {
            let idx = WORDLIST.iter().position(|w| *w == tok)?;
            *slot = u8::try_from(idx).expect("wordlist index < 256");
        }
        Some(Self { bits })
    }
}

impl std::fmt::Debug for SasCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // SAS material is display-only (compared out of band), never secret.
        write!(f, "SasCode({} / {})", self.words(), self.digits())
    }
}

/// Derive the pairing SAS from the E2EE handshake `transcript` (the existing
/// `SHA-256(offer ‖ reply ‖ initiator ‖ responder)` — unchanged here).
///
/// `HKDF-SHA256(salt = [`wire::TAG_SAS`], ikm = transcript)` → the first
/// `SAS_BITS` bits. Deterministic: the same transcript always yields the same
/// code, and two honest peers (who compute the same transcript) derive the same
/// code, while a MITM's two distinct transcripts almost never collide.
#[must_use]
pub fn sas_from_transcript(transcript: &[u8; 32]) -> SasCode {
    let mut bits = [0u8; SAS_BYTES];
    hkdf_expand(wire::TAG_SAS, transcript, &mut bits);
    SasCode { bits }
}

/// Derive the **commit-then-reveal pairing SAS** from the handshake `transcript`
/// AND both peers' revealed nonces (overlay follow-up #2, pairing):
/// `HKDF-SHA256(salt = [`wire::TAG_PAIR_SAS`], ikm = transcript ‖ n_init ‖
/// n_resp)` → the first [`SAS_BITS`] bits.
///
/// The ikm is a **canonical fixed-width** concatenation (`32 + 32 + 32 = 96`
/// bytes), in the fixed `transcript`-then-`n_init`-then-`n_resp` order, so both
/// honest peers — who agree on the transcript and on which revealed nonce is the
/// initiator's — derive the identical code. Folding both nonces in is what
/// upgrades the MITM-detection to `2^-SAS_BITS` **per online attempt**: because
/// each nonce is committed (hashed via [`crate::pairing::pair_commit`]) before
/// *either* is revealed, an active relay cannot choose its nonce after learning
/// the peer's, so it cannot grind the (attacker-malleable) transcript to force
/// the two human-compared codes to collide. See the `CRITICAL` note on
/// [`SAS_BITS`].
///
/// Domain-separated from [`sas_from_transcript`] by the distinct salt
/// [`wire::TAG_PAIR_SAS`], so the committed and un-committed SAS schemes never
/// collide. [`sas_from_transcript`] is intentionally left unchanged — the
/// egress-pinned / non-paired flows keep deriving from it; this is the additional
/// commit-then-reveal form the pairing handshake uses.
#[must_use]
pub fn sas_from_pair_transcript(
    transcript: &[u8; 32],
    n_init: &[u8; 32],
    n_resp: &[u8; 32],
) -> SasCode {
    // Canonical, fixed-width ikm: transcript ‖ n_init ‖ n_resp (96 bytes).
    let mut ikm = [0u8; 96];
    ikm[..32].copy_from_slice(transcript);
    ikm[32..64].copy_from_slice(n_init);
    ikm[64..].copy_from_slice(n_resp);
    let mut bits = [0u8; SAS_BYTES];
    hkdf_expand(wire::TAG_PAIR_SAS, &ikm, &mut bits);
    SasCode { bits }
}

/// A short, stable fingerprint of an overlay identity, for display (e.g. "you
/// are connecting to `…`"). Derived — not a raw key prefix — so it is uniformly
/// spread and domain-separated via [`wire::TAG_IDENTITY_FP`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    bytes: [u8; FP_BYTES],
}

impl Fingerprint {
    /// The raw fingerprint bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8; FP_BYTES] {
        &self.bytes
    }

    /// Grouped lowercase hex, e.g. `"a1b2:c3d4:e5f6:0718"` (four 16-bit groups).
    #[must_use]
    pub fn hex(&self) -> String {
        self.bytes
            .chunks(2)
            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
            .collect::<Vec<_>>()
            .join(":")
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.hex())
    }
}

impl std::fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Fingerprint({})", self.hex())
    }
}

/// A short, stable fingerprint of `id` for display.
///
/// `HKDF-SHA256(salt = [`wire::TAG_IDENTITY_FP`], ikm = id-bytes)` → `FP_BYTES`.
#[must_use]
pub fn identity_fp(id: &OverlayId) -> Fingerprint {
    let mut bytes = [0u8; FP_BYTES];
    hkdf_expand(wire::TAG_IDENTITY_FP, id.as_bytes(), &mut bytes);
    Fingerprint { bytes }
}

/// The versioned, phonetically-distinct wordlist: exactly **256** unique,
/// short, common words (one per possible byte value). Each SAS byte indexes this
/// list, so the mapping is `byte ↔ word`. It is embedded (not loaded) so the CLI
/// and the console render identically; changing it is a pairing-UX break and
/// bumps [`SAS_WORDLIST_VERSION`] and the `-v1` of [`wire::TAG_SAS`].
static WORDLIST: [&str; 256] = [
    "acorn",
    "admiral",
    "africa",
    "agenda",
    "airline",
    "alarm",
    "alaska",
    "almanac",
    "almond",
    "amazon",
    "amber",
    "amigo",
    "anchor",
    "android",
    "angora",
    "antenna",
    "apollo",
    "april",
    "arcade",
    "arctic",
    "arizona",
    "armada",
    "aroma",
    "arsenal",
    "artist",
    "aspire",
    "athena",
    "atlas",
    "atomic",
    "auburn",
    "august",
    "author",
    "autumn",
    "avatar",
    "avenue",
    "aztec",
    "bagel",
    "baker",
    "ballad",
    "bamboo",
    "banana",
    "bandit",
    "banjo",
    "basket",
    "bazaar",
    "beacon",
    "beagle",
    "bedrock",
    "bikini",
    "bishop",
    "bistro",
    "blanket",
    "blossom",
    "bonanza",
    "bonsai",
    "borneo",
    "boston",
    "bracket",
    "brandy",
    "bravado",
    "brazil",
    "bronco",
    "bruno",
    "bucket",
    "buffalo",
    "bundle",
    "burrito",
    "cabaret",
    "cabin",
    "cactus",
    "cadet",
    "cairo",
    "calypso",
    "camel",
    "canary",
    "candle",
    "canoe",
    "canyon",
    "captain",
    "caramel",
    "cargo",
    "caribou",
    "carpet",
    "cartoon",
    "cashew",
    "casino",
    "castle",
    "catalog",
    "cello",
    "celtic",
    "census",
    "chalet",
    "chaos",
    "cheddar",
    "cherry",
    "chrome",
    "cinema",
    "circus",
    "citadel",
    "clarinet",
    "cobalt",
    "cobra",
    "coconut",
    "cohort",
    "comet",
    "compass",
    "condor",
    "contour",
    "cookie",
    "cosmic",
    "cougar",
    "cowboy",
    "coyote",
    "crayon",
    "cricket",
    "crimson",
    "crystal",
    "cubic",
    "cuckoo",
    "cupid",
    "cyclone",
    "cymbal",
    "dakota",
    "dallas",
    "damask",
    "dandelion",
    "dayton",
    "dazzle",
    "decimal",
    "delphi",
    "denmark",
    "denver",
    "desert",
    "diamond",
    "diesel",
    "digital",
    "dilemma",
    "dinosaur",
    "diploma",
    "disco",
    "district",
    "dolphin",
    "domino",
    "donut",
    "dragon",
    "dublin",
    "duet",
    "dynamo",
    "eagle",
    "easel",
    "ebony",
    "eclipse",
    "edison",
    "egypt",
    "elastic",
    "elbow",
    "electron",
    "elegant",
    "elixir",
    "elmwood",
    "ember",
    "emerald",
    "emporium",
    "england",
    "enigma",
    "epic",
    "escort",
    "espresso",
    "eureka",
    "everest",
    "exodus",
    "fabric",
    "falcon",
    "fantasy",
    "fedora",
    "fennel",
    "ferris",
    "fiber",
    "fiesta",
    "figaro",
    "fiji",
    "filament",
    "finale",
    "firefly",
    "fjord",
    "flamingo",
    "fluent",
    "foghorn",
    "forest",
    "formula",
    "fortune",
    "fossil",
    "foxtrot",
    "fractal",
    "fresco",
    "frisbee",
    "frolic",
    "fuchsia",
    "furnace",
    "fusion",
    "gadget",
    "galaxy",
    "gallop",
    "gamma",
    "garnet",
    "gazelle",
    "gecko",
    "gemini",
    "genesis",
    "geneva",
    "ginger",
    "giraffe",
    "glacier",
    "gladiator",
    "glider",
    "gnome",
    "goblet",
    "gondola",
    "gorilla",
    "gospel",
    "granite",
    "gravity",
    "grizzly",
    "guava",
    "gumbo",
    "gusto",
    "gyro",
    "hacienda",
    "halo",
    "hammock",
    "hamster",
    "harbor",
    "harmony",
    "harvest",
    "havana",
    "hazel",
    "helium",
    "helmet",
    "hermes",
    "hickory",
    "hidalgo",
    "hobbit",
    "hockey",
    "honey",
    "horizon",
    "hornet",
    "hotrod",
    "hubble",
    "huddle",
    "hunter",
    "hurdle",
    "hybrid",
    "hydra",
    "iceberg",
    "icon",
    "igloo",
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::OverlaySecret;
    use std::collections::BTreeSet;

    fn t(seed: u8) -> [u8; 32] {
        // A deterministic, arbitrary "transcript" fixture (the real transcript is
        // a SHA-256 digest; these tests only care that distinct 32-byte inputs
        // behave as such).
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = seed ^ (i as u8).wrapping_mul(31);
        }
        out
    }

    #[test]
    fn sas_is_deterministic_for_a_transcript() {
        // Same transcript → same code (both renderings + the raw bits). This is
        // what lets two honest peers derive an identical code to compare.
        let a = sas_from_transcript(&t(7));
        let b = sas_from_transcript(&t(7));
        assert_eq!(a.bits(), b.bits());
        assert_eq!(a.words(), b.words());
        assert_eq!(a.digits(), b.digits());
    }

    #[test]
    fn different_transcripts_yield_different_sas() {
        // THE MITM-detection property: a relay-in-the-middle necessarily runs two
        // distinct handshake legs (different transcripts), so the two SAS codes
        // it would have to show diverge. Sweep many transcripts and assert the
        // codes are overwhelmingly distinct (no accidental fixed point).
        let mut seen = BTreeSet::new();
        for s in 0u8..=255 {
            seen.insert(*sas_from_transcript(&t(s)).bits());
        }
        // 256 distinct 24-bit draws: a collision is ~256²/2 · 2⁻²⁴ ≈ 0.002 likely,
        // and for THIS fixed fixture there is none — the derivation spreads inputs.
        assert_eq!(seen.len(), 256, "distinct transcripts give distinct SAS");
        // And a one-byte change in the transcript changes the code.
        assert_ne!(
            sas_from_transcript(&t(1)).bits(),
            sas_from_transcript(&t(2)).bits()
        );
    }

    #[test]
    fn sas_is_domain_separated_from_other_derivations_off_the_same_transcript() {
        // The SAS bits (salt = TAG_SAS) must not equal bytes derived from the same
        // transcript under any OTHER domain tag — so the SAS leaks nothing about,
        // and is not confusable with, the session keys or the fingerprint
        // derivation (which both descend from the handshake).
        let tr = t(42);
        let sas = sas_from_transcript(&tr);

        let mut off_fp = [0u8; SAS_BYTES];
        hkdf_expand(wire::TAG_IDENTITY_FP, &tr, &mut off_fp);
        assert_ne!(
            sas.bits(),
            &off_fp,
            "TAG_SAS ≠ TAG_IDENTITY_FP off same input"
        );

        let mut off_share = [0u8; SAS_BYTES];
        hkdf_expand(wire::TAG_E2EE_SHARE, &tr, &mut off_share);
        assert_ne!(
            sas.bits(),
            &off_share,
            "TAG_SAS ≠ TAG_E2EE_SHARE off same input"
        );

        // The session key schedule derives the OTHER way (salt = transcript, ikm =
        // the KEM secret), so even with an identical byte string in both roles the
        // SAS (salt = TAG_SAS, ikm = transcript) differs from (salt = transcript,
        // ikm = transcript).
        let mut swapped = [0u8; SAS_BYTES];
        hkdf_expand(&tr, &tr, &mut swapped);
        assert_ne!(
            sas.bits(),
            &swapped,
            "salt/ikm roles are not interchangeable"
        );
    }

    #[test]
    fn pair_sas_is_deterministic_and_nonce_sensitive() {
        let tr = t(11);
        let n1 = [1u8; 32];
        let n2 = [2u8; 32];
        // Deterministic for the same (transcript, n_init, n_resp) — what lets two honest peers,
        // who share the transcript and both revealed nonces, derive an identical code to compare.
        assert_eq!(
            sas_from_pair_transcript(&tr, &n1, &n2).bits(),
            sas_from_pair_transcript(&tr, &n1, &n2).bits()
        );
        // Nonce-sensitive: the SAS folds in BOTH nonces. (If the nonces were dropped from the ikm —
        // degenerating to the un-committed transcript SAS — these would collapse to one code, so
        // these assertions double as the guard against that mutation.)
        let base = sas_from_pair_transcript(&tr, &n1, &n2);
        assert_ne!(
            base.bits(),
            sas_from_pair_transcript(&tr, &[9u8; 32], &n2).bits(),
            "the initiator nonce must affect the SAS"
        );
        assert_ne!(
            base.bits(),
            sas_from_pair_transcript(&tr, &n1, &[9u8; 32]).bits(),
            "the responder nonce must affect the SAS"
        );
        // The init/resp order is bound (the ikm is ordered): swapping the two nonces changes it.
        assert_ne!(
            base.bits(),
            sas_from_pair_transcript(&tr, &n2, &n1).bits(),
            "the initiator/responder nonce order is bound into the SAS"
        );
    }

    #[test]
    fn pair_sas_is_domain_separated_from_the_transcript_sas() {
        // Even with the SAME 32-byte value in all three ikm slots, the pairing SAS
        // (salt = TAG_PAIR_SAS, 96-byte ikm) differs from the transcript SAS
        // (salt = TAG_SAS, 32-byte ikm): the committed and un-committed schemes never collide.
        let tr = t(21);
        assert_ne!(
            sas_from_pair_transcript(&tr, &tr, &tr).bits(),
            sas_from_transcript(&tr).bits(),
            "the committed-nonce pairing SAS is domain-separated from the transcript SAS"
        );
    }

    #[test]
    fn pair_sas_denies_the_offline_transcript_grind() {
        // Model one online MITM attempt against the human-compared codes.
        //
        // The attack the un-committed transcript SAS is vulnerable to (see the CRITICAL note on
        // SAS_BITS): a MITM-as-responder, after learning one leg's target, grinds its KEM `reply`
        // offline to drive the OTHER leg's transcript to the SAME transcript-only SAS. We model the
        // attacker having SUCCEEDED at that grind — a PERFECT base-transcript-SAS collision — by
        // reusing one transcript on both legs (the strongest case for the attacker):
        let t_grind = t(33);
        assert_eq!(
            sas_from_transcript(&t_grind).bits(),
            sas_from_transcript(&t_grind).bits(),
            "models the attacker's achieved base-transcript-SAS collision"
        );
        // WITHOUT the nonces, both legs would now show an IDENTICAL code and the human check passes
        // the attacker through. WITH the committed nonces — the attacker must fix n_m1/n_m2 BEFORE
        // learning the honest n_a/n_b — the two human-compared codes still diverge, so the attack
        // fails. Removing the nonces from the ikm (the mutation) collapses both sides to
        // `sas_from_transcript(t_grind)` and this assertion goes RED (the two become equal).
        let (n_a, n_m1) = ([0xA1u8; 32], [0x1Au8; 32]); // A-leg: honest n_a, attacker-committed n_m1
        let (n_m2, n_b) = ([0x2Bu8; 32], [0xB2u8; 32]); // B-leg: attacker-committed n_m2, honest n_b
        assert_ne!(
            sas_from_pair_transcript(&t_grind, &n_a, &n_m1).bits(),
            sas_from_pair_transcript(&t_grind, &n_m2, &n_b).bits(),
            "committed per-leg nonces keep the two SAS codes apart even on a ground transcript collision"
        );
    }

    #[test]
    fn words_round_trip_and_are_stable() {
        // Round-trip: words parse back to the same SAS.
        let sas = sas_from_transcript(&t(99));
        let parsed = SasCode::from_words(&sas.words()).expect("own words parse");
        assert_eq!(parsed, sas);

        // Tolerant parse: whitespace separators and mixed case also round-trip.
        let spaced = sas.words().replace('-', " ").to_uppercase();
        assert_eq!(SasCode::from_words(&spaced), Some(sas));

        // Stability: a fixed byte triple maps to fixed, known words (byte → word).
        let fixed = SasCode { bits: [0, 1, 255] };
        assert_eq!(fixed.words(), "acorn-admiral-igloo");
        assert_eq!(SasCode::from_words("acorn-admiral-igloo"), Some(fixed));

        // A word not in the list, or the wrong count, fails closed.
        assert_eq!(SasCode::from_words("acorn-admiral-notaword"), None);
        assert_eq!(SasCode::from_words("acorn-admiral"), None);
    }

    #[test]
    fn digits_render_the_full_24_bit_value_grouped() {
        assert_eq!(SasCode { bits: [0, 0, 0] }.digits(), "0000 0000");
        // 2²⁴ − 1 = 16_777_215 → the maximum code.
        assert_eq!(
            SasCode {
                bits: [0xff, 0xff, 0xff]
            }
            .digits(),
            "1677 7215"
        );
        assert_eq!(
            SasCode {
                bits: [0x01, 0x02, 0x03]
            }
            .digits(),
            "0006 6051"
        );
        // Keypad rendering is 8 digits + one separating space.
        let d = sas_from_transcript(&t(5)).digits();
        assert_eq!(d.chars().filter(char::is_ascii_digit).count(), 8);
        assert_eq!(d.matches(' ').count(), 1);
    }

    #[test]
    fn wordlist_is_256_distinct_words() {
        assert_eq!(WORDLIST.len(), 256);
        let set: BTreeSet<&str> = WORDLIST.iter().copied().collect();
        if set.len() != 256 {
            // Surface which entries repeat, so a hand-edit typo is easy to fix.
            let mut once = BTreeSet::new();
            let dups: Vec<&str> = WORDLIST
                .iter()
                .filter(|w| !once.insert(**w))
                .copied()
                .collect();
            panic!("wordlist has duplicates: {dups:?}");
        }
        // Each word is lowercase ascii letters and a readable length.
        for w in WORDLIST {
            assert!(
                w.len() >= 3 && w.len() <= 9,
                "`{w}` is an odd length for a spoken SAS word"
            );
            assert!(
                w.chars().all(|c| c.is_ascii_lowercase()),
                "`{w}` must be lowercase ascii"
            );
        }
    }

    #[test]
    fn identity_fp_is_stable_distinct_and_domain_separated() {
        let a = OverlaySecret::generate().unwrap().id();
        let b = OverlaySecret::generate().unwrap().id();

        // Stable for one identity, distinct across identities.
        assert_eq!(identity_fp(&a), identity_fp(&a));
        assert_ne!(identity_fp(&a), identity_fp(&b));

        // Rendered form: four colon-separated 16-bit hex groups.
        let hex = identity_fp(&a).hex();
        assert_eq!(hex.matches(':').count(), 3);
        assert_eq!(hex.len(), FP_BYTES * 2 + 3);

        // Domain-separated from the identity's raw key prefix (it is a derivation,
        // not a prefix slice).
        assert_ne!(
            &identity_fp(&a).bytes()[..],
            &a.as_bytes()[..FP_BYTES],
            "the fingerprint is derived, not a raw key prefix"
        );
    }
}
