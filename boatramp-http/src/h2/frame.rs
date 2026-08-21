//! HTTP/2 frame layer (RFC 7540 §4, §6): the 9-byte header, frame types + flags,
//! and validated parse/encode for the fixed-layout frames. Higher-level rules
//! (stream state, ordering, connection vs stream error scope) live in `conn`.

use crate::h2::error::{ErrorCode, H2Error};

/// Length of the fixed frame header (RFC 7540 §4.1).
pub const FRAME_HEADER_LEN: usize = 9;

/// Frame types (RFC 7540 §6). `Unknown` is preserved: a receiver MUST ignore and
/// discard frames of unknown type (§4.1), which the connection layer relies on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameType {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
    Unknown(u8),
}

impl FrameType {
    pub fn as_u8(self) -> u8 {
        match self {
            FrameType::Data => 0x0,
            FrameType::Headers => 0x1,
            FrameType::Priority => 0x2,
            FrameType::RstStream => 0x3,
            FrameType::Settings => 0x4,
            FrameType::PushPromise => 0x5,
            FrameType::Ping => 0x6,
            FrameType::GoAway => 0x7,
            FrameType::WindowUpdate => 0x8,
            FrameType::Continuation => 0x9,
            FrameType::Unknown(t) => t,
        }
    }
}

impl From<u8> for FrameType {
    fn from(t: u8) -> Self {
        match t {
            0x0 => FrameType::Data,
            0x1 => FrameType::Headers,
            0x2 => FrameType::Priority,
            0x3 => FrameType::RstStream,
            0x4 => FrameType::Settings,
            0x5 => FrameType::PushPromise,
            0x6 => FrameType::Ping,
            0x7 => FrameType::GoAway,
            0x8 => FrameType::WindowUpdate,
            0x9 => FrameType::Continuation,
            other => FrameType::Unknown(other),
        }
    }
}

/// Frame flags (RFC 7540 §6). Values overlap across frame types; interpret only
/// against the owning frame's type.
pub mod flag {
    pub const END_STREAM: u8 = 0x1; // DATA, HEADERS
    pub const ACK: u8 = 0x1; // SETTINGS, PING
    pub const END_HEADERS: u8 = 0x4; // HEADERS, PUSH_PROMISE, CONTINUATION
    pub const PADDED: u8 = 0x8; // DATA, HEADERS, PUSH_PROMISE
    pub const PRIORITY: u8 = 0x20; // HEADERS
}

/// A parsed frame header. The payload (`length` bytes) follows on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    pub length: u32, // 24-bit
    pub kind: FrameType,
    pub flags: u8,
    pub stream_id: u32, // 31-bit; the reserved bit is masked off on parse
}

impl FrameHeader {
    /// Parse the 9-byte header. Panics if `b.len() < 9` — callers read exactly
    /// [`FRAME_HEADER_LEN`] first.
    pub fn parse(b: &[u8]) -> FrameHeader {
        FrameHeader {
            length: (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]),
            kind: FrameType::from(b[3]),
            flags: b[4],
            // Mask the reserved high bit (RFC 7540 §4.1: receivers ignore it).
            stream_id: (u32::from(b[5] & 0x7f) << 24)
                | (u32::from(b[6]) << 16)
                | (u32::from(b[7]) << 8)
                | u32::from(b[8]),
        }
    }

    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let len = self.length;
        let sid = self.stream_id & 0x7fff_ffff;
        [
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
            self.kind.as_u8(),
            self.flags,
            (sid >> 24) as u8,
            (sid >> 16) as u8,
            (sid >> 8) as u8,
            sid as u8,
        ]
    }

    pub fn has_flag(&self, f: u8) -> bool {
        self.flags & f != 0
    }
}

/// PRIORITY payload / the priority section of a HEADERS frame (RFC 7540 §6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priority {
    pub exclusive: bool,
    pub dependency: u32,
    pub weight: u8,
}

fn conn(code: ErrorCode) -> H2Error {
    H2Error::conn(code)
}

/// Strip the optional pad-length prefix + trailing padding from a DATA/HEADERS
/// payload (RFC 7540 §6.1). Returns the field data. A pad length that is >= the
/// remaining payload is a connection error of type PROTOCOL_ERROR.
pub fn strip_padding(payload: &[u8], padded: bool) -> Result<&[u8], H2Error> {
    if !padded {
        return Ok(payload);
    }
    let (&pad_len, rest) = payload.split_first().ok_or_else(|| conn(ErrorCode::ProtocolError))?;
    let pad = usize::from(pad_len);
    if pad > rest.len() {
        // "If the length of the padding is the length of the frame payload or
        // greater, the recipient MUST treat this as a connection error."
        return Err(conn(ErrorCode::ProtocolError));
    }
    Ok(&rest[..rest.len() - pad])
}

/// Parse SETTINGS entries (RFC 7540 §6.5): a sequence of 6-byte (id, value) pairs.
/// A length not a multiple of 6 is a FRAME_SIZE_ERROR connection error.
pub fn parse_settings(payload: &[u8]) -> Result<Vec<(u16, u32)>, H2Error> {
    if payload.len() % 6 != 0 {
        return Err(conn(ErrorCode::FrameSizeError));
    }
    Ok(payload
        .chunks_exact(6)
        .map(|c| {
            (
                u16::from_be_bytes([c[0], c[1]]),
                u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
            )
        })
        .collect())
}

/// Parse a WINDOW_UPDATE increment (RFC 7540 §6.9). Length must be 4. The reserved
/// bit is masked. A zero increment is a protocol error, but its *scope* (stream vs
/// connection) is decided by the caller from the stream id, so this returns the
/// raw increment.
pub fn parse_window_update(payload: &[u8]) -> Result<u32, H2Error> {
    if payload.len() != 4 {
        return Err(conn(ErrorCode::FrameSizeError));
    }
    Ok(u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff)
}

/// Parse a RST_STREAM error code (RFC 7540 §6.4). Length must be 4.
pub fn parse_rst_stream(payload: &[u8]) -> Result<ErrorCode, H2Error> {
    if payload.len() != 4 {
        return Err(conn(ErrorCode::FrameSizeError));
    }
    Ok(ErrorCode::from(u32::from_be_bytes([
        payload[0], payload[1], payload[2], payload[3],
    ])))
}

/// Parse PING opaque data (RFC 7540 §6.7). Length must be exactly 8.
pub fn parse_ping(payload: &[u8]) -> Result<[u8; 8], H2Error> {
    if payload.len() != 8 {
        return Err(conn(ErrorCode::FrameSizeError));
    }
    let mut d = [0u8; 8];
    d.copy_from_slice(payload);
    Ok(d)
}

/// Parse a PRIORITY payload (RFC 7540 §6.3). Length must be exactly 5.
pub fn parse_priority(payload: &[u8]) -> Result<Priority, H2Error> {
    if payload.len() != 5 {
        return Err(conn(ErrorCode::FrameSizeError));
    }
    let raw = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    Ok(Priority {
        exclusive: raw & 0x8000_0000 != 0,
        dependency: raw & 0x7fff_ffff,
        weight: payload[4],
    })
}

/// Parse GOAWAY (RFC 7540 §6.8): last-stream-id, error code, and opaque debug data.
pub fn parse_goaway(payload: &[u8]) -> Result<(u32, ErrorCode, &[u8]), H2Error> {
    if payload.len() < 8 {
        return Err(conn(ErrorCode::FrameSizeError));
    }
    let last = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) & 0x7fff_ffff;
    let code = ErrorCode::from(u32::from_be_bytes([
        payload[4], payload[5], payload[6], payload[7],
    ]));
    Ok((last, code, &payload[8..]))
}

/// Encode a full frame (header + payload) into `out`.
pub fn write_frame(out: &mut Vec<u8>, kind: FrameType, flags: u8, stream_id: u32, payload: &[u8]) {
    let h = FrameHeader {
        length: payload.len() as u32,
        kind,
        flags,
        stream_id,
    };
    out.extend_from_slice(&h.encode());
    out.extend_from_slice(payload);
}

/// A bare DATA/HEADERS/... header for the streamed body path (payload written
/// separately, e.g. spliced), so we never buffer the body to frame it.
pub fn data_header(stream_id: u32, len: u32, end_stream: bool) -> [u8; FRAME_HEADER_LEN] {
    FrameHeader {
        length: len,
        kind: FrameType::Data,
        flags: if end_stream { flag::END_STREAM } else { 0 },
        stream_id,
    }
    .encode()
}

/// GOAWAY frame bytes (RFC 7540 §6.8) — the graceful connection teardown.
pub fn goaway(last_stream_id: u32, code: ErrorCode, debug: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + debug.len());
    payload.extend_from_slice(&(last_stream_id & 0x7fff_ffff).to_be_bytes());
    payload.extend_from_slice(&code.code().to_be_bytes());
    payload.extend_from_slice(debug);
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    write_frame(&mut out, FrameType::GoAway, 0, 0, &payload);
    out
}

/// RST_STREAM frame bytes (RFC 7540 §6.4).
pub fn rst_stream(stream_id: u32, code: ErrorCode) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + 4);
    write_frame(&mut out, FrameType::RstStream, 0, stream_id, &code.code().to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrips_and_masks_reserved_bit() {
        let h = FrameHeader {
            length: 0x0123_45,
            kind: FrameType::Headers,
            flags: flag::END_HEADERS | flag::END_STREAM,
            stream_id: 0x0102_0304,
        };
        let bytes = h.encode();
        assert_eq!(FrameHeader::parse(&bytes), h);
        // A set reserved bit on the wire is masked away on parse.
        let mut raw = h.encode();
        raw[5] |= 0x80;
        assert_eq!(FrameHeader::parse(&raw).stream_id, h.stream_id);
    }

    #[test]
    fn settings_parse_rejects_bad_length() {
        assert!(parse_settings(&[0, 1, 0, 0, 0]).is_err()); // 5 bytes
        let one = [0x00, 0x04, 0x00, 0x00, 0xff, 0xff]; // INITIAL_WINDOW_SIZE=65535
        assert_eq!(parse_settings(&one).unwrap(), vec![(0x4u16, 0xffffu32)]);
    }

    #[test]
    fn fixed_frames_enforce_exact_lengths() {
        assert!(parse_window_update(&[0, 0, 0]).is_err());
        assert_eq!(parse_window_update(&[0x80, 0, 0, 5]).unwrap(), 5); // reserved bit masked
        assert!(parse_ping(&[0; 7]).is_err());
        assert_eq!(parse_ping(&[1, 2, 3, 4, 5, 6, 7, 8]).unwrap(), [1, 2, 3, 4, 5, 6, 7, 8]);
        assert!(parse_priority(&[0; 4]).is_err());
        assert!(parse_rst_stream(&[0; 3]).is_err());
        assert_eq!(parse_rst_stream(&[0, 0, 0, 8]).unwrap(), ErrorCode::Cancel);
    }

    #[test]
    fn padding_strip_and_overflow() {
        // pad_len=2, data="hi", padding=2 bytes.
        let payload = [2u8, b'h', b'i', 0, 0];
        assert_eq!(strip_padding(&payload, true).unwrap(), b"hi");
        // pad_len >= remaining is a protocol error.
        assert!(strip_padding(&[5u8, b'h', b'i'], true).is_err());
        // not padded → returned verbatim.
        assert_eq!(strip_padding(b"hi", false).unwrap(), b"hi");
    }

    #[test]
    fn goaway_and_rst_roundtrip() {
        let g = goaway(7, ErrorCode::ProtocolError, b"bad");
        let h = FrameHeader::parse(&g[..FRAME_HEADER_LEN]);
        assert_eq!(h.kind, FrameType::GoAway);
        let (last, code, debug) = parse_goaway(&g[FRAME_HEADER_LEN..]).unwrap();
        assert_eq!((last, code, debug), (7, ErrorCode::ProtocolError, &b"bad"[..]));
        let r = rst_stream(3, ErrorCode::Cancel);
        let rh = FrameHeader::parse(&r[..FRAME_HEADER_LEN]);
        assert_eq!((rh.kind, rh.stream_id), (FrameType::RstStream, 3));
    }
}
