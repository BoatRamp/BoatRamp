//! Resumable windowed circuit — the pure core (IU-5).
//!
//! A circuit carries a byte stream over a swappable link. It is windowed with
//! an offset / cumulative-ack scheme so that, when a link faults, the sender can
//! **retransmit everything still outstanding** onto a fresh link and the
//! receiver **dedups by offset** — the stream survives a link swap with zero
//! loss or duplication. This module holds the pure, I/O-free pieces: the frame
//! codec and the send/receive window bookkeeping. The async duplex pump that
//! drives them over a link (and the in-memory circuit registry) live in the
//! runtime crate's `circuit` module.
//!
//! Wire framing: each [`XgressFrame`] is sent length-delimited — the transport
//! prepends a 4-byte big-endian length to the `encode`d body. The body itself
//! is `[tag][payload]`.

use std::collections::BTreeMap;

use bytes::Bytes;

/// Default per-circuit send window (bytes in flight). Bounds memory retained
/// for a possible retransmit.
pub const DEFAULT_WINDOW: usize = 256 * 1024;

/// Default maximum payload carried by one [`XgressFrame::Payload`]. Larger
/// local reads are split across frames (and retransmitted per frame).
pub const DEFAULT_SEGMENT: usize = 16 * 1024;

const TAG_PAYLOAD: u8 = 0x00;
const TAG_ACK: u8 = 0x01;
const TAG_FIN: u8 = 0x02;

/// A frame on the circuit wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XgressFrame {
    /// A run of bytes at absolute stream `offset`.
    Payload { offset: u64, data: Bytes },
    /// Cumulative acknowledgement: the peer has contiguously received every
    /// byte with offset `< through`.
    Ack { through: u64 },
    /// No more payload will follow in this direction (clean half-close).
    Fin,
}

/// A malformed frame body.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("empty frame")]
    Empty,
    #[error("unknown frame tag {0:#x}")]
    UnknownTag(u8),
    #[error("truncated {0} frame")]
    Truncated(&'static str),
}

impl XgressFrame {
    /// Encode the frame body (`[tag][payload]`). The transport prepends the
    /// 4-byte big-endian length.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Payload { offset, data } => {
                let mut out = Vec::with_capacity(1 + 8 + data.len());
                out.push(TAG_PAYLOAD);
                out.extend_from_slice(&offset.to_be_bytes());
                out.extend_from_slice(data);
                out
            }
            Self::Ack { through } => {
                let mut out = Vec::with_capacity(1 + 8);
                out.push(TAG_ACK);
                out.extend_from_slice(&through.to_be_bytes());
                out
            }
            Self::Fin => vec![TAG_FIN],
        }
    }

    /// Decode a frame body (`[tag][payload]`, the 4-byte length already stripped
    /// by the transport).
    pub fn decode(body: &[u8]) -> Result<Self, FrameError> {
        let (&tag, rest) = body.split_first().ok_or(FrameError::Empty)?;
        match tag {
            TAG_PAYLOAD => {
                if rest.len() < 8 {
                    return Err(FrameError::Truncated("payload"));
                }
                let (off, data) = rest.split_at(8);
                let offset = u64::from_be_bytes(off.try_into().expect("8 bytes"));
                Ok(Self::Payload {
                    offset,
                    data: Bytes::copy_from_slice(data),
                })
            }
            TAG_ACK => {
                let through = rest
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| FrameError::Truncated("ack"))?;
                Ok(Self::Ack { through })
            }
            TAG_FIN => Ok(Self::Fin),
            other => Err(FrameError::UnknownTag(other)),
        }
    }
}

/// Send-side window bookkeeping: assigns offsets, bounds in-flight bytes, and
/// tracks the peer's cumulative ack. The retained segments themselves (for
/// retransmit on rebind) are held by the pump, keyed by the offset `on_send`
/// returns.
#[derive(Debug)]
pub struct TxPortal {
    window: usize,
    next_offset: u64,
    acked_through: u64,
}

impl TxPortal {
    /// A portal with a `window`-byte in-flight ceiling.
    #[must_use]
    pub fn new(window: usize) -> Self {
        Self {
            window,
            next_offset: 0,
            acked_through: 0,
        }
    }

    /// Assign the next `len` bytes an offset and advance the stream position.
    pub fn on_send(&mut self, len: usize) -> u64 {
        let offset = self.next_offset;
        self.next_offset += len as u64;
        offset
    }

    /// Bytes sent but not yet cumulatively acked.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.next_offset - self.acked_through
    }

    /// Remaining send budget before the window is full.
    #[must_use]
    pub fn available(&self) -> usize {
        self.window.saturating_sub(self.in_flight() as usize)
    }

    /// Record a cumulative ack (monotonic; a stale/duplicate ack is ignored).
    pub fn on_ack(&mut self, through: u64) {
        self.acked_through = self.acked_through.max(through).min(self.next_offset);
    }

    /// The highest contiguous offset the peer has acked.
    #[must_use]
    pub fn acked_through(&self) -> u64 {
        self.acked_through
    }
}

/// Receive-side reassembly: buffers out-of-order segments, delivers the
/// contiguous prefix in order, and dedups by offset so a retransmitted segment
/// is harmless.
#[derive(Debug, Default)]
pub struct RxPortal {
    next_expected: u64,
    buffered: BTreeMap<u64, Bytes>,
}

impl RxPortal {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Accept a payload segment. A segment entirely below `next_expected` has
    /// already been delivered (a retransmit) and is dropped; a duplicate of a
    /// still-buffered segment is ignored.
    pub fn accept(&mut self, offset: u64, data: Bytes) {
        if data.is_empty() {
            return;
        }
        let end = offset + data.len() as u64;
        if end <= self.next_expected {
            return; // wholly delivered already
        }
        // Whole-segment retransmit model: offsets are assigned per segment and
        // retransmitted verbatim, so a live segment starts exactly at its
        // original offset. Keep the first copy seen.
        self.buffered.entry(offset).or_insert(data);
    }

    /// Pop the contiguous run of segments starting at `next_expected`, advancing
    /// the cumulative-ack point past them.
    pub fn take_ready(&mut self) -> Vec<Bytes> {
        let mut ready = Vec::new();
        while let Some((&offset, _)) = self.buffered.first_key_value() {
            if offset != self.next_expected {
                break;
            }
            let data = self.buffered.remove(&offset).expect("just peeked");
            self.next_expected += data.len() as u64;
            ready.push(data);
        }
        ready
    }

    /// The cumulative-ack point: every byte below this has been received in order.
    #[must_use]
    pub fn ack(&self) -> u64 {
        self.next_expected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_codec_round_trips() {
        for f in [
            XgressFrame::Payload {
                offset: 42,
                data: Bytes::from_static(b"hello"),
            },
            XgressFrame::Ack { through: 1 << 40 },
            XgressFrame::Fin,
        ] {
            assert_eq!(XgressFrame::decode(&f.encode()).unwrap(), f);
        }
    }

    #[test]
    fn decode_rejects_malformed() {
        assert!(matches!(XgressFrame::decode(&[]), Err(FrameError::Empty)));
        assert!(matches!(
            XgressFrame::decode(&[0xff]),
            Err(FrameError::UnknownTag(0xff))
        ));
        assert!(matches!(
            XgressFrame::decode(&[TAG_ACK, 0, 0]),
            Err(FrameError::Truncated("ack"))
        ));
    }

    #[test]
    fn tx_window_accounts_in_flight_and_acks() {
        let mut tx = TxPortal::new(100);
        assert_eq!(tx.on_send(40), 0);
        assert_eq!(tx.on_send(40), 40);
        assert_eq!(tx.in_flight(), 80);
        assert_eq!(tx.available(), 20);
        tx.on_ack(40);
        assert_eq!(tx.in_flight(), 40);
        assert_eq!(tx.available(), 60);
        // A stale ack never rewinds; an ack can't exceed what was sent.
        tx.on_ack(10);
        assert_eq!(tx.acked_through(), 40);
        tx.on_ack(999);
        assert_eq!(tx.acked_through(), 80);
    }

    #[test]
    fn rx_reassembles_in_order_and_cumulative_acks() {
        let mut rx = RxPortal::new();
        // Out-of-order arrival: [5..10) before [0..5).
        rx.accept(5, Bytes::from_static(b"world"));
        assert!(rx.take_ready().is_empty()); // nothing contiguous yet
        assert_eq!(rx.ack(), 0);
        rx.accept(0, Bytes::from_static(b"hello"));
        let ready: Vec<u8> = rx.take_ready().concat();
        assert_eq!(&ready, b"helloworld");
        assert_eq!(rx.ack(), 10);
    }

    #[test]
    fn rx_dedups_a_retransmitted_segment() {
        let mut rx = RxPortal::new();
        rx.accept(0, Bytes::from_static(b"abcd"));
        assert_eq!(rx.take_ready().concat(), b"abcd");
        // Retransmit of an already-delivered segment is dropped (no dup).
        rx.accept(0, Bytes::from_static(b"abcd"));
        assert!(rx.take_ready().is_empty());
        assert_eq!(rx.ack(), 4);
        // A duplicate of a still-buffered (future) segment is ignored, not doubled.
        rx.accept(8, Bytes::from_static(b"ijkl"));
        rx.accept(8, Bytes::from_static(b"ijkl"));
        rx.accept(4, Bytes::from_static(b"efgh"));
        assert_eq!(rx.take_ready().concat(), b"efghijkl");
        assert_eq!(rx.ack(), 12);
    }
}
