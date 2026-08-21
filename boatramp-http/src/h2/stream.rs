//! Per-stream state machine (RFC 7540 §5.1). This is pure logic — no I/O — so the
//! illegal-transition rules the benchmark prototype ignored (frames on idle /
//! half-closed / closed streams, which are DoS and desync vectors) are unit-tested
//! in isolation. The connection driver drives it and turns the returned [`H2Error`]
//! into a `RST_STREAM` (stream scope) or `GOAWAY` (connection scope).

use crate::h2::error::{ErrorCode, H2Error};
use crate::h2::frame::FrameType;

/// Stream states from a **server's** point of view (RFC 7540 §5.1). We never send
/// PUSH_PROMISE, and clients cannot reserve, so the reserved states never arise;
/// the lifecycle is Idle → Open → HalfClosed(Remote) → Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamState {
    Idle,
    Open,
    /// Client sent END_STREAM; it may not send more content, but we're still
    /// sending the response.
    HalfClosedRemote,
    /// We sent END_STREAM; the client may still be sending.
    HalfClosedLocal,
    Closed,
}

/// Whether an incoming frame carried END_STREAM (only meaningful for DATA/HEADERS).
pub type EndStream = bool;

impl StreamState {
    /// Apply a frame received from the peer, returning the new state or the error
    /// (with its RFC-correct scope) the connection driver must raise. `id` is only
    /// used to tag stream-scoped errors.
    pub fn on_recv(self, id: u32, kind: FrameType, end_stream: EndStream) -> Result<Self, H2Error> {
        use FrameType::*;
        use StreamState::*;
        match (self, kind) {
            // ---- Idle (§5.1): only HEADERS (opens) or PRIORITY are legal. Anything
            // else on an idle stream is a connection error of type PROTOCOL_ERROR.
            (Idle, Headers) => Ok(if end_stream { HalfClosedRemote } else { Open }),
            (Idle, Priority) => Ok(Idle),
            (Idle, _) => Err(H2Error::conn(ErrorCode::ProtocolError)),

            // ---- Open: content + control flow.
            (Open, Data | Headers) if end_stream => Ok(HalfClosedRemote),
            (Open, Data | Headers | Continuation | WindowUpdate | Priority) => Ok(Open),
            (Open, RstStream) => Ok(Closed),

            // ---- Half-closed (remote): the client is done sending. Per §5.1 only
            // WINDOW_UPDATE, PRIORITY, or RST_STREAM are allowed; DATA/HEADERS here
            // are a *stream* error of type STREAM_CLOSED (not fatal to the conn).
            (HalfClosedRemote, WindowUpdate | Priority) => Ok(HalfClosedRemote),
            (HalfClosedRemote, RstStream) => Ok(Closed),
            (HalfClosedRemote, _) => Err(H2Error::stream(id, ErrorCode::StreamClosed)),

            // ---- Half-closed (local): we're done sending; the client may still send.
            (HalfClosedLocal, Data | Headers) if end_stream => Ok(Closed),
            (HalfClosedLocal, Data | Headers | Continuation | WindowUpdate | Priority) => {
                Ok(HalfClosedLocal)
            }
            (HalfClosedLocal, RstStream) => Ok(Closed),

            // ---- Closed (§5.1): PRIORITY is always allowed; a WINDOW_UPDATE or
            // RST_STREAM may arrive shortly after close and is tolerated; other
            // frames are a stream error of type STREAM_CLOSED.
            (Closed, Priority | WindowUpdate | RstStream) => Ok(Closed),
            (Closed, _) => Err(H2Error::stream(id, ErrorCode::StreamClosed)),

            // Connection-scoped frames (SETTINGS/PING/GOAWAY) belong on stream 0 and
            // PUSH_PROMISE from a client is always illegal — the connection driver
            // handles them before dispatch, so reaching a stream means a non-zero
            // stream id carried one: a connection error of type PROTOCOL_ERROR.
            (_, Settings | Ping | GoAway | PushPromise) => {
                Err(H2Error::conn(ErrorCode::ProtocolError))
            }

            // Unknown frame types are ignored by the connection layer before they
            // reach here; treat defensively as a no-op on the current state.
            (state, Unknown(_)) => Ok(state),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StreamState::*;
    use super::*;
    use crate::h2::error::ErrorCode;
    use crate::h2::frame::FrameType::*;

    #[test]
    fn headers_opens_and_end_stream_half_closes() {
        assert_eq!(Idle.on_recv(1, Headers, false), Ok(Open));
        assert_eq!(Idle.on_recv(1, Headers, true), Ok(HalfClosedRemote));
    }

    #[test]
    fn idle_rejects_non_headers_as_connection_error() {
        // These are the h2spec "idle: Sends a DATA/RST_STREAM/WINDOW_UPDATE/
        // CONTINUATION frame" cases the prototype failed.
        for kind in [Data, RstStream, WindowUpdate, Continuation] {
            assert_eq!(
                Idle.on_recv(1, kind, false),
                Err(H2Error::conn(ErrorCode::ProtocolError)),
                "idle + {kind:?} must be a connection PROTOCOL_ERROR"
            );
        }
        // PRIORITY on idle is legal.
        assert_eq!(Idle.on_recv(1, Priority, false), Ok(Idle));
    }

    #[test]
    fn half_closed_remote_rejects_content_as_stream_closed() {
        // h2spec "half closed (remote): Sends a DATA/HEADERS/CONTINUATION frame".
        for kind in [Data, Headers, Continuation] {
            assert_eq!(
                HalfClosedRemote.on_recv(3, kind, false),
                Err(H2Error::stream(3, ErrorCode::StreamClosed)),
                "half-closed-remote + {kind:?} must be a stream STREAM_CLOSED"
            );
        }
        // But flow-control / reset frames are still accepted.
        assert_eq!(HalfClosedRemote.on_recv(3, WindowUpdate, false), Ok(HalfClosedRemote));
        assert_eq!(HalfClosedRemote.on_recv(3, RstStream, false), Ok(Closed));
    }

    #[test]
    fn full_request_lifecycle() {
        let s = Idle.on_recv(1, Headers, false).unwrap(); // request headers
        assert_eq!(s, Open);
        let s = s.on_recv(1, Data, true).unwrap(); // request body end
        assert_eq!(s, HalfClosedRemote);
        let s = s.on_recv(1, RstStream, false).unwrap(); // client cancels
        assert_eq!(s, Closed);
    }
}
