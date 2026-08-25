//! HTTP/2 error codes (RFC 7540 §7) and the connection/stream error split.

/// An HTTP/2 error code, as carried by `RST_STREAM` and `GOAWAY` frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    NoError = 0x0,
    ProtocolError = 0x1,
    InternalError = 0x2,
    FlowControlError = 0x3,
    SettingsTimeout = 0x4,
    StreamClosed = 0x5,
    FrameSizeError = 0x6,
    RefusedStream = 0x7,
    Cancel = 0x8,
    CompressionError = 0x9,
    ConnectError = 0xa,
    EnhanceYourCalm = 0xb,
    InadequateSecurity = 0xc,
    Http11Required = 0xd,
    /// Any code we don't recognize is preserved verbatim (RFC 7540 §7: unknown
    /// codes MUST NOT trigger special behavior — treat as a generic error).
    Unknown(u32),
}

impl ErrorCode {
    /// The wire value.
    pub fn code(self) -> u32 {
        match self {
            Self::NoError => 0x0,
            Self::ProtocolError => 0x1,
            Self::InternalError => 0x2,
            Self::FlowControlError => 0x3,
            Self::SettingsTimeout => 0x4,
            Self::StreamClosed => 0x5,
            Self::FrameSizeError => 0x6,
            Self::RefusedStream => 0x7,
            Self::Cancel => 0x8,
            Self::CompressionError => 0x9,
            Self::ConnectError => 0xa,
            Self::EnhanceYourCalm => 0xb,
            Self::InadequateSecurity => 0xc,
            Self::Http11Required => 0xd,
            Self::Unknown(c) => c,
        }
    }
}

impl From<u32> for ErrorCode {
    fn from(c: u32) -> Self {
        match c {
            0x0 => Self::NoError,
            0x1 => Self::ProtocolError,
            0x2 => Self::InternalError,
            0x3 => Self::FlowControlError,
            0x4 => Self::SettingsTimeout,
            0x5 => Self::StreamClosed,
            0x6 => Self::FrameSizeError,
            0x7 => Self::RefusedStream,
            0x8 => Self::Cancel,
            0x9 => Self::CompressionError,
            0xa => Self::ConnectError,
            0xb => Self::EnhanceYourCalm,
            0xc => Self::InadequateSecurity,
            0xd => Self::Http11Required,
            other => Self::Unknown(other),
        }
    }
}

/// The connection-vs-stream distinction that governs recovery (RFC 7540 §5.4):
/// a stream error resets one stream (`RST_STREAM`) and the connection survives; a
/// connection error tears the whole connection down (`GOAWAY`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum H2Error {
    /// Reset a single stream; the connection continues.
    Stream { id: u32, code: ErrorCode },
    /// Fatal: emit GOAWAY with this code and close the connection.
    Connection(ErrorCode),
}

impl H2Error {
    pub fn conn(code: ErrorCode) -> Self {
        Self::Connection(code)
    }
    pub fn stream(id: u32, code: ErrorCode) -> Self {
        Self::Stream { id, code }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_roundtrips_including_unknown() {
        for c in [0x0u32, 0x1, 0x6, 0xd] {
            assert_eq!(ErrorCode::from(c).code(), c);
        }
        // An unrecognized code is preserved, not clamped.
        assert_eq!(ErrorCode::from(0x9999).code(), 0x9999);
        assert_eq!(ErrorCode::from(0x9999), ErrorCode::Unknown(0x9999));
    }
}
