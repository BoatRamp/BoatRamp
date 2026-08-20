//! HTTP/2 SETTINGS parameters (RFC 7540 §6.5.2) with spec defaults + validation.

use crate::error::{ErrorCode, H2Error};

/// The connection flow-control window is fixed at 65535 initially (RFC 7540
/// §6.9.2) and is NOT governed by `SETTINGS_INITIAL_WINDOW_SIZE` (that only sets
/// the initial *stream* window).
pub const DEFAULT_CONNECTION_WINDOW: i64 = 65_535;
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 65_535;
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;
pub const MIN_MAX_FRAME_SIZE: u32 = 16_384;
pub const MAX_MAX_FRAME_SIZE: u32 = 16_777_215; // 2^24 - 1
pub const MAX_WINDOW_SIZE: u32 = 0x7fff_ffff; // 2^31 - 1
pub const DEFAULT_HEADER_TABLE_SIZE: u32 = 4_096;

/// A peer's SETTINGS, resolved against the spec defaults. For a server, the values
/// that matter for *sending* are the client's `initial_window_size`,
/// `max_frame_size`, and `max_concurrent_streams`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: Option<u32>,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: Option<u32>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            header_table_size: DEFAULT_HEADER_TABLE_SIZE,
            enable_push: true,
            max_concurrent_streams: None,
            initial_window_size: DEFAULT_INITIAL_WINDOW_SIZE,
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: None,
        }
    }
}

impl Settings {
    /// Apply one `(identifier, value)` pair from a SETTINGS frame, validating per
    /// RFC 7540 §6.5.2. Unknown identifiers are ignored (§6.5.2, "MUST ignore").
    pub fn apply(&mut self, id: u16, value: u32) -> Result<(), H2Error> {
        match id {
            0x1 => self.header_table_size = value,
            0x2 => match value {
                0 => self.enable_push = false,
                1 => self.enable_push = true,
                // "Any value other than 0 or 1 MUST be treated as a connection
                // error of type PROTOCOL_ERROR."
                _ => return Err(H2Error::conn(ErrorCode::ProtocolError)),
            },
            0x3 => self.max_concurrent_streams = Some(value),
            0x4 => {
                // "Values above the maximum flow-control window size ... MUST be
                // treated as a connection error of type FLOW_CONTROL_ERROR."
                if value > MAX_WINDOW_SIZE {
                    return Err(H2Error::conn(ErrorCode::FlowControlError));
                }
                self.initial_window_size = value;
            }
            0x5 => {
                // "outside the range ... MUST be treated as a connection error of
                // type PROTOCOL_ERROR."
                if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&value) {
                    return Err(H2Error::conn(ErrorCode::ProtocolError));
                }
                self.max_frame_size = value;
            }
            0x6 => self.max_header_list_size = Some(value),
            _ => {} // unknown identifier: ignore
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_spec() {
        let s = Settings::default();
        assert_eq!(s.initial_window_size, 65_535);
        assert_eq!(s.max_frame_size, 16_384);
        assert!(s.enable_push);
        assert_eq!(s.max_concurrent_streams, None);
    }

    #[test]
    fn apply_validates_per_spec() {
        let mut s = Settings::default();
        // ENABLE_PUSH must be 0 or 1.
        assert!(s.apply(0x2, 2).is_err());
        assert!(s.apply(0x2, 0).is_ok() && !s.enable_push);
        // MAX_FRAME_SIZE must be in [16384, 2^24-1].
        assert!(s.apply(0x5, 1024).is_err());
        assert!(s.apply(0x5, 1 << 24).is_err());
        assert!(s.apply(0x5, 32_768).is_ok() && s.max_frame_size == 32_768);
        // INITIAL_WINDOW_SIZE must be <= 2^31-1.
        assert!(s.apply(0x4, MAX_WINDOW_SIZE + 1).is_err());
        assert!(s.apply(0x4, 1 << 20).is_ok());
        // Unknown identifiers are ignored, not errors.
        assert!(s.apply(0xff, 123).is_ok());
    }
}
