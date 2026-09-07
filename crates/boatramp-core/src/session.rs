//! Session delivery-semantics model — **Stage 1** of the duplex/resumable session primitive
//! (`PLAN-session-primitive.md`). Pure, I/O-free logic so the delivery guarantees are proven in
//! isolation: a monotonic per-session **cursor**, **at-least-once ordered** outbound frames retained
//! until the client **acks** their cursor (resume-from-cursor on reconnect), **idempotent inbound
//! dedup** over a bounded window, **bounded** buffers + frame size, and **idle-TTL** expiry.
//!
//! What this module deliberately does NOT do (later stages, in `boatramp-server` behind the
//! `session` feature): KV persistence of the record, the event-driven re-entry driver, the SSE-out +
//! POST-in serving binding, and the tenancy binding (the verified principal is sealed alongside this
//! state by the store). Frames are **opaque bytes** here and everywhere — the host never parses one.
//!
//! **Time is passed in** (`now_ms: u64`, Unix milliseconds), never read from a clock, so the model
//! is deterministic + trivially testable and safe to drive from a replayed/persisted context.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// A monotonic per-session outbound cursor. `0` means "before the first frame" (the cursor a fresh
/// client resumes from); the first enqueued frame is cursor `1`.
pub type Cursor = u64;

/// Operator/host-set caps for one session. All are hard bounds enforced by [`SessionState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionLimits {
    /// Max **unacked** outbound frames retained. Enqueuing past this fails [`SessionError::BufferFull`]
    /// (backpressure) rather than unboundedly growing host memory — the guest must slow down or the
    /// client must ack.
    pub max_buffered_outbound: usize,
    /// Max bytes in a single frame (either direction). Larger ⇒ [`SessionError::FrameTooLarge`].
    pub max_frame_bytes: usize,
    /// How many recent inbound idempotency keys are retained for dedup. A retried inbound POST within
    /// this window is deduped (delivered to the guest once); a duplicate arriving *after* it has
    /// fallen out of the window may be re-delivered — the documented bound of at-least-once.
    pub dedup_window: usize,
    /// Idle time (ms) after which the session is reapable — see [`SessionState::is_expired`].
    pub idle_ttl_ms: u64,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_buffered_outbound: 256,
            max_frame_bytes: 1 << 20, // 1 MiB
            dedup_window: 256,
            idle_ttl_ms: 5 * 60 * 1000, // 5 minutes
        }
    }
}

/// Why a session operation was refused. All are fail-closed: the caller never silently loses a frame
/// or advances state on error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// The frame exceeded [`SessionLimits::max_frame_bytes`].
    #[error("session frame too large")]
    FrameTooLarge,
    /// The unacked outbound buffer is at [`SessionLimits::max_buffered_outbound`] — apply
    /// backpressure (the client must ack, or the guest must stop producing).
    #[error("session outbound buffer full")]
    BufferFull,
    /// The session is closed; no further frames may be enqueued or accepted.
    #[error("session is closed")]
    Closed,
}

/// One buffered outbound frame, retained until the client acks its [`cursor`](Self::cursor).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundFrame {
    pub cursor: Cursor,
    pub payload: Vec<u8>,
}

/// The pure delivery state of one session. Serde-serializable so the store (Stage 2) can persist it
/// verbatim to the control-plane KV; holds no I/O, no clock, and no principal (the store seals the
/// verified principal alongside it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    /// Highest outbound cursor assigned so far (`0` before the first frame).
    out_cursor: Cursor,
    /// Highest outbound cursor the client has acked. Only ever advances.
    last_acked: Cursor,
    /// Unacked outbound frames, strictly ascending by cursor (front = oldest unacked).
    outbound: VecDeque<OutboundFrame>,
    /// Recent inbound idempotency keys (front = oldest), bounded by `dedup_window`.
    dedup: VecDeque<String>,
    /// The last resumable snapshot the guest set via `checkpoint()`, replayed on re-entry.
    checkpoint: Option<Vec<u8>>,
    /// `Some(reason)` once the session is closed.
    closed: Option<String>,
    /// Unix-ms of the last activity (enqueue / inbound / ack / checkpoint), for idle-TTL GC.
    last_active_ms: u64,
}

impl SessionState {
    /// A fresh session opened at `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        Self {
            out_cursor: 0,
            last_acked: 0,
            outbound: VecDeque::new(),
            dedup: VecDeque::new(),
            checkpoint: None,
            closed: None,
            last_active_ms: now_ms,
        }
    }

    /// The highest outbound cursor assigned so far.
    pub fn out_cursor(&self) -> Cursor {
        self.out_cursor
    }

    /// The highest cursor the client has acknowledged.
    pub fn last_acked(&self) -> Cursor {
        self.last_acked
    }

    /// Whether the session has been closed, and why.
    pub fn close_reason(&self) -> Option<&str> {
        self.closed.as_deref()
    }

    /// Whether the session is closed.
    pub fn is_closed(&self) -> bool {
        self.closed.is_some()
    }

    /// Enqueue an outbound frame (host → client): validate the size + buffer caps, assign the next
    /// monotonic cursor, retain it for at-least-once redelivery, and return its cursor. Fails closed
    /// (no cursor consumed, nothing buffered) on any cap or if closed.
    pub fn enqueue_outbound(
        &mut self,
        payload: Vec<u8>,
        limits: &SessionLimits,
        now_ms: u64,
    ) -> Result<Cursor, SessionError> {
        if self.closed.is_some() {
            return Err(SessionError::Closed);
        }
        if payload.len() > limits.max_frame_bytes {
            return Err(SessionError::FrameTooLarge);
        }
        if self.outbound.len() >= limits.max_buffered_outbound {
            return Err(SessionError::BufferFull);
        }
        self.out_cursor += 1;
        let cursor = self.out_cursor;
        self.outbound.push_back(OutboundFrame { cursor, payload });
        self.last_active_ms = now_ms;
        Ok(cursor)
    }

    /// The buffered frames with `cursor > after` (ascending) — what a client resumes on reconnect
    /// (`after` = its last acked/received cursor). Frames at or below `last_acked` are already GC'd,
    /// so `after < last_acked` still yields only what's retained (no gaps beyond the ack point).
    pub fn frames_since(&self, after: Cursor) -> impl Iterator<Item = &OutboundFrame> {
        self.outbound.iter().filter(move |f| f.cursor > after)
    }

    /// Record a client ack of every outbound frame up to and including `cursor`: advance `last_acked`
    /// (monotonic — a stale/duplicate ack is ignored, an over-ack is clamped to what was sent) and
    /// GC the now-acked frames from the buffer.
    pub fn ack(&mut self, cursor: Cursor, now_ms: u64) {
        let target = cursor.min(self.out_cursor);
        if target <= self.last_acked {
            return; // stale or duplicate ack
        }
        self.last_acked = target;
        while self.outbound.front().is_some_and(|f| f.cursor <= target) {
            self.outbound.pop_front();
        }
        self.last_active_ms = now_ms;
    }

    /// Record an inbound frame's idempotency `key` (client → handler). Returns `true` if it is **new**
    /// (accept + deliver to the guest) or `false` if it is a **duplicate** within the dedup window
    /// (drop — a retried POST). A new key is retained, evicting the oldest once the window is full.
    /// Rejects when closed (fail-closed — an inbound frame on a closed session is dropped).
    pub fn record_inbound(
        &mut self,
        key: &str,
        limits: &SessionLimits,
        now_ms: u64,
    ) -> Result<bool, SessionError> {
        if self.closed.is_some() {
            return Err(SessionError::Closed);
        }
        if self.dedup.iter().any(|k| k == key) {
            return Ok(false); // duplicate within the window
        }
        self.dedup.push_back(key.to_string());
        while self.dedup.len() > limits.dedup_window {
            self.dedup.pop_front();
        }
        self.last_active_ms = now_ms;
        Ok(true)
    }

    /// Set the resumable snapshot (host persists it; replayed via [`Self::resumed`] on re-entry).
    pub fn set_checkpoint(&mut self, snapshot: Vec<u8>, now_ms: u64) {
        self.checkpoint = Some(snapshot);
        self.last_active_ms = now_ms;
    }

    /// The last checkpoint the guest set, if any — handed back on re-entry/resume.
    pub fn resumed(&self) -> Option<&[u8]> {
        self.checkpoint.as_deref()
    }

    /// Close the session with a reason (idempotent — the first reason wins). Drops the outbound
    /// buffer (nothing more will be delivered) and the dedup window.
    pub fn close(&mut self, reason: impl Into<String>, now_ms: u64) {
        if self.closed.is_none() {
            self.closed = Some(reason.into());
            self.outbound.clear();
            self.dedup.clear();
            self.last_active_ms = now_ms;
        }
    }

    /// Whether the session has been idle past `limits.idle_ttl_ms` as of `now_ms` (reapable by GC).
    /// A closed session is always expired.
    pub fn is_expired(&self, limits: &SessionLimits, now_ms: u64) -> bool {
        self.closed.is_some() || now_ms.saturating_sub(self.last_active_ms) > limits.idle_ttl_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> SessionLimits {
        SessionLimits {
            max_buffered_outbound: 3,
            max_frame_bytes: 8,
            dedup_window: 2,
            idle_ttl_ms: 1_000,
        }
    }

    #[test]
    fn cursors_are_monotonic_and_1_based() {
        let l = limits();
        let mut s = SessionState::new(0);
        assert_eq!(s.enqueue_outbound(b"a".to_vec(), &l, 1).unwrap(), 1);
        assert_eq!(s.enqueue_outbound(b"b".to_vec(), &l, 2).unwrap(), 2);
        assert_eq!(s.out_cursor(), 2);
    }

    #[test]
    fn frames_since_yields_ordered_tail_for_resume() {
        let l = limits();
        let mut s = SessionState::new(0);
        for p in [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()] {
            s.enqueue_outbound(p, &l, 1).unwrap();
        }
        // A client that last saw cursor 1 resumes with 2,3 in order.
        let tail: Vec<_> = s.frames_since(1).map(|f| f.cursor).collect();
        assert_eq!(tail, vec![2, 3]);
        // A brand-new client (cursor 0) gets everything retained.
        let all: Vec<_> = s.frames_since(0).map(|f| f.cursor).collect();
        assert_eq!(all, vec![1, 2, 3]);
    }

    #[test]
    fn ack_advances_monotonically_and_gcs_the_buffer() {
        let l = limits();
        let mut s = SessionState::new(0);
        for p in [b"a".to_vec(), b"b".to_vec(), b"c".to_vec()] {
            s.enqueue_outbound(p, &l, 1).unwrap();
        }
        s.ack(2, 2);
        assert_eq!(s.last_acked(), 2);
        // 1,2 are GC'd; only 3 remains for redelivery.
        let remaining: Vec<_> = s.frames_since(0).map(|f| f.cursor).collect();
        assert_eq!(remaining, vec![3]);
        // A stale ack is ignored; an over-ack is clamped to what was sent.
        s.ack(1, 3);
        assert_eq!(s.last_acked(), 2);
        s.ack(99, 4);
        assert_eq!(s.last_acked(), 3);
        assert_eq!(s.frames_since(0).count(), 0);
    }

    #[test]
    fn inbound_is_deduped_within_the_window() {
        let l = limits();
        let mut s = SessionState::new(0);
        assert!(s.record_inbound("k1", &l, 1).unwrap()); // new
        assert!(!s.record_inbound("k1", &l, 2).unwrap()); // duplicate → dropped
        assert!(s.record_inbound("k2", &l, 3).unwrap()); // new
    }

    #[test]
    fn dedup_window_is_bounded_at_least_once_tail() {
        // window = 2: k1 falls out after k2,k3, so a very-late retry of k1 may re-appear — the
        // documented at-least-once bound.
        let l = limits();
        let mut s = SessionState::new(0);
        assert!(s.record_inbound("k1", &l, 1).unwrap());
        assert!(s.record_inbound("k2", &l, 2).unwrap());
        assert!(s.record_inbound("k3", &l, 3).unwrap()); // evicts k1
        assert!(s.record_inbound("k1", &l, 4).unwrap()); // k1 no longer in the window → re-accepted
    }

    #[test]
    fn outbound_buffer_cap_applies_backpressure() {
        let l = limits(); // max_buffered_outbound = 3
        let mut s = SessionState::new(0);
        for _ in 0..3 {
            s.enqueue_outbound(b"x".to_vec(), &l, 1).unwrap();
        }
        assert_eq!(
            s.enqueue_outbound(b"y".to_vec(), &l, 2),
            Err(SessionError::BufferFull)
        );
        // No cursor was consumed on the failed enqueue.
        assert_eq!(s.out_cursor(), 3);
        // Acking frees the buffer so production resumes.
        s.ack(3, 3);
        assert_eq!(s.enqueue_outbound(b"y".to_vec(), &l, 4).unwrap(), 4);
    }

    #[test]
    fn frame_size_cap_is_enforced_both_never_consuming_a_cursor() {
        let l = limits(); // max_frame_bytes = 8
        let mut s = SessionState::new(0);
        assert_eq!(
            s.enqueue_outbound(vec![0u8; 9], &l, 1),
            Err(SessionError::FrameTooLarge)
        );
        assert_eq!(s.out_cursor(), 0);
    }

    #[test]
    fn checkpoint_round_trips() {
        let mut s = SessionState::new(0);
        assert_eq!(s.resumed(), None);
        s.set_checkpoint(b"state-v1".to_vec(), 1);
        assert_eq!(s.resumed(), Some(&b"state-v1"[..]));
        s.set_checkpoint(b"state-v2".to_vec(), 2);
        assert_eq!(s.resumed(), Some(&b"state-v2"[..]));
    }

    #[test]
    fn close_is_idempotent_and_fails_closed() {
        let l = limits();
        let mut s = SessionState::new(0);
        s.enqueue_outbound(b"a".to_vec(), &l, 1).unwrap();
        s.close("client gone", 2);
        assert!(s.is_closed());
        assert_eq!(s.close_reason(), Some("client gone"));
        // First reason wins; buffer + dedup dropped.
        s.close("other", 3);
        assert_eq!(s.close_reason(), Some("client gone"));
        assert_eq!(s.frames_since(0).count(), 0);
        // No further frames in either direction.
        assert_eq!(
            s.enqueue_outbound(b"b".to_vec(), &l, 4),
            Err(SessionError::Closed)
        );
        assert_eq!(s.record_inbound("k", &l, 5), Err(SessionError::Closed));
    }

    #[test]
    fn idle_ttl_expiry() {
        let l = limits(); // idle_ttl_ms = 1000
        let mut s = SessionState::new(0);
        s.enqueue_outbound(b"a".to_vec(), &l, 100).unwrap(); // last_active = 100
        assert!(!s.is_expired(&l, 1_000)); // 900ms idle < ttl
        assert!(s.is_expired(&l, 1_200)); // 1100ms idle > ttl
                                          // A closed session is always expired.
        let mut c = SessionState::new(0);
        c.close("done", 100);
        assert!(c.is_expired(&l, 101));
    }

    #[test]
    fn state_serde_round_trips_for_kv_persistence() {
        let l = limits();
        let mut s = SessionState::new(7);
        s.enqueue_outbound(b"a".to_vec(), &l, 8).unwrap();
        s.record_inbound("k1", &l, 9).unwrap();
        s.set_checkpoint(b"cp".to_vec(), 10);
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: SessionState = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(s, back);
    }
}
