//! The relay-blind pairing **rendezvous code** (`bropair1…`, overlay follow-up #2, inc2).
//!
//! A pairing rendezvous lets two peers that cannot direct-dial each other (both
//! NAT'd) meet THROUGH the cluster relay: the relay matches a parked **accepter**
//! with a redeeming **dialer** by a shared rendezvous id and bridges their two
//! bi-streams **blind** (it holds no session keys — exactly like `expose`). The
//! commit-then-reveal SAS pairing handshake ([`crate::pairing`] /
//! `boatramp_overlay::pair_handshake`) then runs end-to-end over the bridge,
//! unchanged, so the SAS still detects a tampering/misrouting relay.
//!
//! [`PairCode`] is the self-contained rendezvous credential an operator mints
//! (`POST /api/overlay/pair-code`, gated `Overlay·Admin`) and shares with the new
//! peer. It carries everything BOTH sides need to meet — the rendezvous id (the
//! relay's registry key), the relay socket to dial, the relay identity to pin, and
//! the code's own expiry — rendered as a checksummed, copy-paste-safe bech32m
//! string under the reserved [`crate::wire::HRP_PAIR`] (`bropair1…`). The relay
//! itself never parses the code; it is handed only the rendezvous id over the
//! park/redeem wire, so the code is purely a client-side convenience bundle (the
//! overlay analog of a `brfwd1…`/`brexp1…` ticket, in the reserved HRP).
//!
//! The code is NOT a signed capability: its security is the short TTL + single-use
//! redemption the relay enforces, the relay-blind bridge, and the out-of-band SAS
//! comparison that backs the whole handshake. The `Overlay·Admin` gate is on the
//! MINT (who may obtain a rendezvous at this relay), not on redemption — the
//! unpaired peer that redeems a code is by design NOT membership-gated.

use crate::identity::{OverlayId, OverlayIdError};

/// Length of a pairing rendezvous id (the relay's registry key): 16 bytes of
/// platform entropy — infeasible to guess, compact in the rendered code.
pub const PAIR_RENDEZVOUS_ID_LEN: usize = 16;

/// The byte-layout version baked into a rendered [`PairCode`] (byte 0 of the
/// bech32m payload). Bumped only on a wire-incompatible change to the layout.
const PAIR_CODE_VERSION: u8 = 1;

/// A failure encoding or decoding a [`PairCode`].
#[derive(Debug, thiserror::Error)]
pub enum PairCodeError {
    /// The bech32 string could not be decoded or carried the wrong HRP.
    #[error("bech32 pairing code: {0}")]
    Bech32(String),
    /// The decoded payload was truncated, over-long, or an unknown version.
    #[error("malformed pairing code: {0}")]
    Malformed(String),
    /// The embedded relay identity was not a valid overlay id.
    #[error("pairing code relay id: {0}")]
    RelayId(#[from] OverlayIdError),
}

/// A self-contained pairing rendezvous credential, rendered as `bropair1…`.
///
/// Minted by the control plane (`Overlay·Admin`), parked by the accepter
/// (`boatramp overlay pair --accept <code>`) and redeemed by the dialer
/// (`boatramp overlay pair <code>`); both sides decode it to learn the relay to
/// dial and the rendezvous id to present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairCode {
    /// The rendezvous id — the relay's `PairRendezvous` registry key both the park
    /// and the redeem present over the wire. High-entropy; never reused.
    pub rendezvous: Vec<u8>,
    /// The relay/ingress `host:port` both peers dial to meet.
    pub relay_addr: String,
    /// The relay's overlay identity both peers pin at the TLS layer.
    pub relay_id: OverlayId,
    /// The code's expiry (Unix seconds) — advisory for the client; the relay
    /// enforces its own short rendezvous TTL regardless.
    pub expires_at: u64,
}

impl PairCode {
    /// Build a code, validating the rendezvous-id length and a non-empty relay addr.
    pub fn new(
        rendezvous: Vec<u8>,
        relay_addr: String,
        relay_id: OverlayId,
        expires_at: u64,
    ) -> Result<Self, PairCodeError> {
        if rendezvous.len() != PAIR_RENDEZVOUS_ID_LEN {
            return Err(PairCodeError::Malformed(format!(
                "rendezvous id must be {PAIR_RENDEZVOUS_ID_LEN} bytes (got {})",
                rendezvous.len()
            )));
        }
        if relay_addr.trim().is_empty() {
            return Err(PairCodeError::Malformed("empty relay address".into()));
        }
        Ok(Self {
            rendezvous,
            relay_addr,
            relay_id,
            expires_at,
        })
    }

    /// The compact byte payload (before bech32m): `version ‖ expires_at(8 BE) ‖
    /// rendezvous_len(1) ‖ rendezvous ‖ relay_id(32) ‖ relay_addr(UTF-8 tail)`.
    fn to_payload(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(1 + 8 + 1 + self.rendezvous.len() + 32 + self.relay_addr.len());
        out.push(PAIR_CODE_VERSION);
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out.push(self.rendezvous.len() as u8);
        out.extend_from_slice(&self.rendezvous);
        out.extend_from_slice(self.relay_id.as_bytes());
        out.extend_from_slice(self.relay_addr.as_bytes());
        out
    }

    /// Render the friendly bech32m `bropair1…` form (checksummed, copy-paste-safe).
    pub fn encode(&self) -> Result<String, PairCodeError> {
        let hrp = bech32::Hrp::parse(crate::wire::HRP_PAIR)
            .map_err(|e| PairCodeError::Bech32(e.to_string()))?;
        bech32::encode::<bech32::Bech32m>(hrp, &self.to_payload())
            .map_err(|e| PairCodeError::Bech32(e.to_string()))
    }

    /// Parse the friendly bech32m `bropair1…` form, rejecting a foreign HRP, a
    /// truncated/over-long payload, an unknown version, or a malformed relay id.
    pub fn decode(s: &str) -> Result<Self, PairCodeError> {
        let (hrp, data) =
            bech32::decode(s.trim()).map_err(|e| PairCodeError::Bech32(e.to_string()))?;
        if hrp.as_str() != crate::wire::HRP_PAIR {
            return Err(PairCodeError::Bech32(format!(
                "wrong prefix `{}` (expected `{}`)",
                hrp.as_str(),
                crate::wire::HRP_PAIR
            )));
        }
        // version(1) + expires_at(8) + rendezvous_len(1) + relay_id(32) minimum, plus a non-empty addr.
        if data.len() < 1 + 8 + 1 + 32 + 1 {
            return Err(PairCodeError::Malformed("payload too short".into()));
        }
        let version = data[0];
        if version != PAIR_CODE_VERSION {
            return Err(PairCodeError::Malformed(format!(
                "unknown version {version} (expected {PAIR_CODE_VERSION})"
            )));
        }
        let expires_at = u64::from_be_bytes(
            data[1..9]
                .try_into()
                .map_err(|_| PairCodeError::Malformed("bad expiry".into()))?,
        );
        let rlen = data[9] as usize;
        let rest = &data[10..];
        if rlen != PAIR_RENDEZVOUS_ID_LEN {
            return Err(PairCodeError::Malformed(format!(
                "rendezvous id must be {PAIR_RENDEZVOUS_ID_LEN} bytes (got {rlen})"
            )));
        }
        if rest.len() < rlen + 32 + 1 {
            return Err(PairCodeError::Malformed("payload truncated".into()));
        }
        let rendezvous = rest[..rlen].to_vec();
        let id_bytes: [u8; 32] = rest[rlen..rlen + 32]
            .try_into()
            .map_err(|_| PairCodeError::Malformed("bad relay id length".into()))?;
        let relay_id = OverlayId::try_from_bytes(id_bytes)?;
        let relay_addr = std::str::from_utf8(&rest[rlen + 32..])
            .map_err(|_| PairCodeError::Malformed("relay address is not UTF-8".into()))?
            .to_string();
        if relay_addr.is_empty() {
            return Err(PairCodeError::Malformed("empty relay address".into()));
        }
        Ok(Self {
            rendezvous,
            relay_addr,
            relay_id,
            expires_at,
        })
    }
}

/// Floor on the operator-configurable short-code digit count (`[overlay] pair_short_code_digits`):
/// below this the entropy (`10^digits`) falls too close to the rate-limited per-attempt guess bound
/// to be meaningfully stronger than brute force within the rate-limit window.
pub const PAIR_SHORT_CODE_DIGITS_MIN: usize = 7;
/// Ceiling on the configurable short-code digit count: beyond this it is no longer "short" — the
/// whole point is a human-typeable handful of digits.
pub const PAIR_SHORT_CODE_DIGITS_MAX: usize = 10;
/// The default short-code digit count: `K = 10^8 ≈ 2^26.6` — rendered as two groups of four
/// (`NNNN-NNNN`), stronger per-online-attempt than the 24-bit SAS once the relay's guess-rate limiter
/// (`F_ip`/`F_global` over the rolling window) is applied.
pub const PAIR_SHORT_CODE_DIGITS_DEFAULT: usize = 8;

/// A failure constructing or parsing a [`ShortCode`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShortCodeError {
    /// The (separator-stripped) input was not exactly the expected digit count — covers both a
    /// too-short and a too-long input; NEVER silently truncated to fit.
    #[error("short code must be exactly {expected} digits (got {got})")]
    WrongLength { expected: usize, got: usize },
    /// The (separator-stripped) input contained a non-ASCII-digit character, or was empty.
    #[error("short code must contain only decimal digits")]
    NonDigit,
    /// The requested digit count falls outside [`PAIR_SHORT_CODE_DIGITS_MIN`]..=
    /// [`PAIR_SHORT_CODE_DIGITS_MAX`].
    #[error("short code digit count {digits} is out of range")]
    DigitsOutOfRange { digits: usize },
    /// A numeric value does not fit within the requested digit count (`value >= 10^digits`).
    #[error("short code value does not fit the requested digit count")]
    ValueOutOfRange,
}

/// A human-typeable pairing **short code**: an INDEPENDENT random alias for a [`PairCode`]'s
/// 128-bit rendezvous id — never a truncation or derivation of it (so leaking the short code reveals
/// nothing about the strong id it resolves to; see the module docs on the relay's `PairShortCodes`
/// alias table, `boatramp-overlay::net`). Digits only (no bech32/wordlist), rendered grouped in
/// 4-digit blocks (`NNNN-NNNN` at the default 8 digits) so it reads unambiguously on a numeric
/// keypad and stays visually distinct from the word-based [`crate::sas::SasCode`].
///
/// Low-entropy by design (`10^digits`, e.g. `2^26.6` at the default 8 digits) — far weaker than the
/// 128-bit rendezvous id or the 24-bit SAS, so it is used ONLY by the dialer/redeem side (the accepter
/// still parks the full strong id — no low-entropy surface on park) and the relay MUST rate-limit +
/// lock out online guessing (`PairGuessLimiter` in `boatramp-overlay::net`). A guessed hit is only a
/// race-to-redeem; the out-of-band SAS still catches a MITM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortCode {
    /// The exact decimal-digit string (no separators) — the relay's `PairShortCodes` registry key.
    digits: String,
}

impl ShortCode {
    /// Strip whitespace and `-` separators from `input` (copy-paste/typing convenience).
    fn strip_separators(input: &str) -> String {
        input
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-')
            .collect()
    }

    /// Format `value` as a zero-padded decimal [`ShortCode`] of exactly `digits` characters. The
    /// mint path (relay-side `PairShortCodes::insert_unique`) draws `value` uniformly from
    /// `0..10^digits` and calls this. Fails closed on an out-of-range digit count or a value that
    /// does not fit it.
    pub fn from_value(value: u64, digits: usize) -> Result<Self, ShortCodeError> {
        if !(PAIR_SHORT_CODE_DIGITS_MIN..=PAIR_SHORT_CODE_DIGITS_MAX).contains(&digits) {
            return Err(ShortCodeError::DigitsOutOfRange { digits });
        }
        let modulus = 10u64
            .checked_pow(digits as u32)
            .ok_or(ShortCodeError::DigitsOutOfRange { digits })?;
        if value >= modulus {
            return Err(ShortCodeError::ValueOutOfRange);
        }
        Ok(Self {
            digits: format!("{value:0digits$}"),
        })
    }

    /// Parse user/wire input back to a short code of EXACTLY `expected_digits` digits: strips
    /// spaces/dashes first, then fails closed on a wrong length (too short OR too long — never
    /// silently truncated to fit) or any non-digit character. Mirrors
    /// [`crate::sas::SasCode::from_words`]'s reject discipline: a mistyped/garbled code never
    /// silently maps to a different short code.
    pub fn parse(input: &str, expected_digits: usize) -> Result<Self, ShortCodeError> {
        let stripped = Self::strip_separators(input);
        if stripped.len() != expected_digits {
            return Err(ShortCodeError::WrongLength {
                expected: expected_digits,
                got: stripped.len(),
            });
        }
        if !stripped.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ShortCodeError::NonDigit);
        }
        Ok(Self { digits: stripped })
    }

    /// Strip spaces/dashes and reject a non-digit/empty result, WITHOUT asserting a specific digit
    /// count — for a caller that does not know (and should not have to guess) the relay's configured
    /// `pair_short_code_digits` up front (e.g. the CLI redeem path), which defers the AUTHORITATIVE
    /// exact-length check to the relay itself. Prefer [`ShortCode::parse`] whenever the expected
    /// count IS known (the relay's own redeem handler; these unit tests).
    pub fn normalize(input: &str) -> Result<String, ShortCodeError> {
        let stripped = Self::strip_separators(input);
        if stripped.is_empty() || !stripped.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ShortCodeError::NonDigit);
        }
        Ok(stripped)
    }

    /// The bare digit string (no separators) — what the relay's registry keys on and what travels
    /// over the wire.
    #[must_use]
    pub fn digits(&self) -> &str {
        &self.digits
    }

    /// The grouped, human-typeable rendering: 4-digit blocks joined by `-` (e.g. `"1234-5678"` at 8
    /// digits; a digit count not a multiple of 4 gets a shorter trailing group).
    #[must_use]
    pub fn render(&self) -> String {
        self.digits
            .as_bytes()
            .chunks(4)
            .map(|c| std::str::from_utf8(c).expect("ascii digits are valid utf-8"))
            .collect::<Vec<_>>()
            .join("-")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::OverlaySecret;

    fn sample() -> PairCode {
        let relay_id = OverlaySecret::generate().unwrap().id();
        PairCode::new(
            vec![7u8; PAIR_RENDEZVOUS_ID_LEN],
            "203.0.113.7:9100".into(),
            relay_id,
            1_900_000_000,
        )
        .unwrap()
    }

    #[test]
    fn round_trips_through_bropair1() {
        let code = sample();
        let s = code.encode().unwrap();
        assert!(s.starts_with("bropair1"), "rendered code: {s}");
        let back = PairCode::decode(&s).unwrap();
        assert_eq!(back, code);
    }

    #[test]
    fn rejects_a_foreign_hrp_and_garbage() {
        assert!(PairCode::decode("not-a-code").is_err());
        // Same bytes under the identity HRP (`bro1…`) must not decode as a pairing code.
        let id = OverlaySecret::generate().unwrap().id();
        assert!(PairCode::decode(&id.to_bech32()).is_err());
    }

    #[test]
    fn rejects_a_wrong_length_rendezvous_id() {
        let relay_id = OverlaySecret::generate().unwrap().id();
        assert!(matches!(
            PairCode::new(vec![1u8; 8], "a:1".into(), relay_id, 0),
            Err(PairCodeError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_a_truncated_payload() {
        // A valid-HRP bech32 whose payload is too short for the fixed header.
        let hrp = bech32::Hrp::parse(crate::wire::HRP_PAIR).unwrap();
        let short = bech32::encode::<bech32::Bech32m>(hrp, &[PAIR_CODE_VERSION, 0, 0]).unwrap();
        assert!(matches!(
            PairCode::decode(&short),
            Err(PairCodeError::Malformed(_))
        ));
    }

    // ---- ShortCode ----

    #[test]
    fn short_code_round_trips_through_render_and_parse() {
        let code = ShortCode::from_value(12_345_678, 8).unwrap();
        assert_eq!(code.digits(), "12345678");
        assert_eq!(code.render(), "1234-5678");
        let back = ShortCode::parse(&code.render(), 8).unwrap();
        assert_eq!(back, code);
        // Separators are optional on parse — the bare digit string round-trips too.
        let bare = ShortCode::parse(code.digits(), 8).unwrap();
        assert_eq!(bare, code);
    }

    #[test]
    fn short_code_rejects_wrong_length() {
        // Too short.
        assert_eq!(
            ShortCode::parse("1234567", 8),
            Err(ShortCodeError::WrongLength {
                expected: 8,
                got: 7
            })
        );
        // Too long — NEVER silently truncated to fit.
        assert_eq!(
            ShortCode::parse("123456789", 8),
            Err(ShortCodeError::WrongLength {
                expected: 8,
                got: 9
            })
        );
        // Separators don't change the underlying digit count: "1234-567" is still 7 digits.
        assert_eq!(
            ShortCode::parse("1234-567", 8),
            Err(ShortCodeError::WrongLength {
                expected: 8,
                got: 7
            })
        );
    }

    #[test]
    fn short_code_rejects_non_digit() {
        // Right length (8) after stripping separators, but a non-digit character.
        assert_eq!(
            ShortCode::parse("1234-56ab", 8),
            Err(ShortCodeError::NonDigit)
        );
        // Empty input is caught by the length check first (expected 8, got 0) — still fail-closed.
        assert_eq!(
            ShortCode::parse("", 8),
            Err(ShortCodeError::WrongLength {
                expected: 8,
                got: 0
            })
        );
    }

    #[test]
    fn short_code_from_value_rejects_out_of_range() {
        assert_eq!(
            ShortCode::from_value(0, 6),
            Err(ShortCodeError::DigitsOutOfRange { digits: 6 })
        );
        assert_eq!(
            ShortCode::from_value(0, 11),
            Err(ShortCodeError::DigitsOutOfRange { digits: 11 })
        );
        // A value that does not fit the requested digit count.
        assert_eq!(
            ShortCode::from_value(100_000_000, 8),
            Err(ShortCodeError::ValueOutOfRange)
        );
    }

    #[test]
    fn short_code_render_groups_in_fours_with_a_short_trailing_group() {
        assert_eq!(ShortCode::from_value(1, 7).unwrap().render(), "0000-001");
        assert_eq!(
            ShortCode::from_value(1, 10).unwrap().render(),
            "0000-0000-01"
        );
    }

    #[test]
    fn short_code_normalize_strips_separators_without_asserting_a_length() {
        assert_eq!(ShortCode::normalize("1234-5678").unwrap(), "12345678");
        assert_eq!(ShortCode::normalize(" 123 456 ").unwrap(), "123456");
        assert_eq!(ShortCode::normalize("12-ab"), Err(ShortCodeError::NonDigit));
        assert_eq!(ShortCode::normalize("--"), Err(ShortCodeError::NonDigit));
    }
}
