//! Wire-permanent identifiers and protocol constants for the boatramp overlay
//! fabric (the `bro` rename contract).
//!
//! Everything in this module is **baked into the wire**: the ALPN negotiated in
//! the QUIC/TLS handshake, the bech32 human-readable prefix for rendered
//! identities, and the domain-separation tags folded into signatures. Changing
//! any of these after release is a protocol break, so they are chosen once and
//! carry a `-v1` suffix that leaves room to rev the wire without touching the
//! `bro` stem.
//!
//! The stem `bro` reads as "boatramp overlay". It deliberately carries no
//! `wt`/`wiretangler` vocabulary — the overlay is a fresh boatramp-idiom
//! reimplementation, not a vendor of the reference design.

use std::time::Duration;

/// The overlay protocol version. Encoded into the ALPN (`bro/1`); bumped only
/// on a wire-incompatible change (a new ALPN is negotiated, old peers rejected).
pub const PROTOCOL_VERSION: u16 = 1;

/// ALPN protocol id negotiated at the TLS/QUIC layer. Pins every overlay
/// connection to this exact protocol+version; a peer speaking anything else
/// fails ALPN negotiation.
pub const ALPN: &[u8] = b"bro/1";

// --- bech32 human-readable prefixes (friendly rendering only) --------------
//
// The *canonical* identity form stays boatramp-core hex (`"ed25519:<hex>"`);
// these HRPs are only for the friendly `bro1…` rendering surfaced to users
// (CLI targets, pairing flows). bech32m is checksummed and copy-paste-safe.

/// HRP for a rendered overlay identity public key: `bro1…`.
pub const HRP_IDENTITY: &str = "bro";

/// HRP for a rendered join token: `brojoin1…`. (IU-aux — not in the first
/// slice; reserved so the wire form is fixed when enrollment lands.)
pub const HRP_JOIN: &str = "brojoin";

/// HRP for a rendered pairing code: `bropair1…`. (IU-aux — reserved.)
pub const HRP_PAIR: &str = "bropair";

// --- signature domain-separation tags --------------------------------------
//
// Each tag is prepended to the bytes a signature covers so a signature minted
// for one purpose can never be replayed as another (cross-protocol / channel
// confusion). They are byte strings, compared verbatim.

/// Domain tag for the E2EE key-share signature (IU-4): the initiator/responder
/// sign `TAG_E2EE_SHARE ‖ share` so a relay cannot forge or swap a share.
pub const TAG_E2EE_SHARE: &[u8] = b"bro-e2ee-share-v1";

/// Domain tag for the dial handshake authentication (IU-2/IU-4).
pub const TAG_HANDSHAKE_AUTH: &[u8] = b"bro-handshake-auth-v1";

/// Domain tag for the short-authentication-string (SAS) derivation (IU-aux).
pub const TAG_SAS: &[u8] = b"bro-sas-v1";

/// Domain tag for the identity fingerprint derivation (IU-aux).
pub const TAG_IDENTITY_FP: &[u8] = b"bro-identity-fp-v1";

/// Fixed marker the initiator writes first on a freshly opened direct bi-stream
/// so the responder's `accept_bi` unblocks (quinn surfaces a stream to the peer
/// only on first write) and the stream is unambiguously the promotion path
/// (IU-7). Must be written before the stream is handed to the circuit pump.
pub const PROMOTE_MARKER: &[u8] = b"bro-promote-v1";

// A dial capability is scoped by its COSE trust-root key plus the `br_kind =
// "overlay-dial"` token kind and scope claim (see `boatramp_core::cose`), so no
// separate wire-level root-context string is needed or shipped.

// --- E2EE record framing (IU-4) --------------------------------------------

/// Channel tag (record byte 0) for application data on the sealed stream.
pub const CH_DATA: u8 = 0x00;

/// Channel tag (record byte 0) for muxed ICE/control signaling on the sealed
/// stream — carried inside the same AEAD session, never a side channel.
pub const CH_SIGNAL: u8 = 0x01;

/// Upper bound on a single muxed signaling record payload (16 KiB). A larger
/// signaling message is a protocol error, not a buffer to grow.
pub const MAX_SIGNAL_LEN: usize = 16 * 1024;

// --- circuit pump timing (IU-5 / IU-7) -------------------------------------

/// How long a resumable circuit pump parks on its rebind channel after a link
/// fault before giving up (IU-5). Within this grace the byte stream survives a
/// link swap with zero loss/dup.
pub const DEFAULT_REBIND_GRACE: Duration = Duration::from_secs(30);

/// How long each side holds a connection-drain handle past a clean pump finish
/// so the peer can drain the final `Fin` before the connection closes (IU-7).
/// Tuned when direct-path promotion lands; a placeholder floor until then.
pub const DIRECT_DRAIN: Duration = Duration::from_secs(3);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_encodes_the_protocol_version() {
        // The ALPN must stay in lockstep with PROTOCOL_VERSION: bumping one
        // without the other silently lets mismatched peers negotiate.
        assert_eq!(ALPN, format!("bro/{PROTOCOL_VERSION}").as_bytes());
    }

    #[test]
    fn no_wt_vocabulary_survives() {
        // Exit-gate guard (plans/26 §3a): nothing in the wire contract may carry
        // the reference project's vocabulary.
        for s in [
            std::str::from_utf8(ALPN).unwrap(),
            HRP_IDENTITY,
            HRP_JOIN,
            HRP_PAIR,
            std::str::from_utf8(TAG_E2EE_SHARE).unwrap(),
            std::str::from_utf8(TAG_HANDSHAKE_AUTH).unwrap(),
            std::str::from_utf8(TAG_SAS).unwrap(),
            std::str::from_utf8(TAG_IDENTITY_FP).unwrap(),
            std::str::from_utf8(PROMOTE_MARKER).unwrap(),
        ] {
            assert!(!s.contains("wt"), "wire id `{s}` leaks `wt`");
            assert!(
                !s.contains("wiretangler"),
                "wire id `{s}` leaks `wiretangler`"
            );
        }
    }

    #[test]
    fn channel_tags_are_distinct() {
        assert_ne!(CH_DATA, CH_SIGNAL);
    }
}
