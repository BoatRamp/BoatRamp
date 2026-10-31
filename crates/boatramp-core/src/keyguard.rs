//! Key-material hygiene for the crown-jewel key paths (privsep Phase 0, WS2).
//!
//! A single, auditable home for the two reflexes every long-lived plaintext key buffer wants:
//!
//! - **mlock** — pin the pages so the key never swaps to disk (a swapped KEK outlives the process in
//!   a swap file / hibernation image). Best-effort: if `RLIMIT_MEMLOCK` is too low the lock fails,
//!   we `warn!` once and carry on — a missing lock must never fail node startup.
//! - **zeroize-on-drop** — overwrite the bytes when the buffer is dropped, so a freed key does not
//!   linger in reclaimed heap. We zeroize *while the region is still locked*, then `munlock`.
//! - **redacting `Debug`** — the bytes can never reach a log / `tracing` event, however carelessly
//!   the holder is formatted; there is no `Display`, no `Serialize`.
//!
//! The buffer is heap-owned ([`Box<[u8]>`]) so its address is stable regardless of where the holder
//! struct lives or moves — `mlock` pins a fixed region, not a stack slot that could move out from
//! under it.
//!
//! # Portability
//! `mlock`/`munlock` exist on every unix (Linux + macOS); the lock is applied under `cfg(unix)`. On
//! any other target (notably `wasm32`, where `boatramp-core` must still compile) the lock is a
//! documented no-op ([`MlockedKey::is_locked`] then reports `false`) — zeroize-on-drop and the
//! redacting `Debug` still apply, so confidentiality-on-free holds everywhere.
//!
//! # Caveat (page granularity)
//! `mlock` operates on whole pages: locking a sub-page buffer pins the entire page(s) it sits on, and
//! `munlock` on drop releases those pages even if an unrelated allocation shares one. This is the
//! standard `mlock` trade-off; it is a hygiene hardening, not a sub-page guarantee. The dominant key
//! (the AES-256-GCM KEK) is process-lifetime, so in practice its lock is held for the whole run.

use core::fmt;

use zeroize::Zeroize;

/// A heap buffer of raw secret/key bytes that is (best-effort) mlocked, zeroized on drop, and has a
/// redacting `Debug`. Use it for any **plaintext** key material that outlives a single statement —
/// the AES-256-GCM KEK, a derived transport key held across a seal, a bearer token kept for a
/// connection's lifetime.
///
/// Deref is deliberately NOT implemented; callers reach the bytes through [`as_slice`](Self::as_slice)
/// so every read site is greppable.
pub struct MlockedKey {
    buf: Box<[u8]>,
    locked: bool,
}

impl MlockedKey {
    /// Take ownership of `bytes` (a stable heap allocation) and lock it best-effort.
    #[must_use]
    pub fn new(bytes: Box<[u8]>) -> Self {
        let locked = mlock_region(bytes.as_ptr(), bytes.len());
        Self { buf: bytes, locked }
    }

    /// Copy `bytes` into a fresh locked buffer. NOTE: the *source* slice is the caller's and is not
    /// zeroized here — zeroize the origin at its owner if it is itself sensitive.
    #[must_use]
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec().into_boxed_slice())
    }

    /// The raw key bytes. Every read of the plaintext key goes through here (greppable).
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Byte length of the key.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the key buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Whether the region was successfully page-locked. `false` means the lock could not be taken
    /// (e.g. `RLIMIT_MEMLOCK` too low) or the platform has no `mlock` — the key is then swappable,
    /// which was `warn!`-logged at construction. Exposed for tests / operational assertions.
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for MlockedKey {
    fn drop(&mut self) {
        // Zeroize while the pages are still locked (the zeroing write stays in locked RAM), then
        // release the lock. Order matters: munlock-then-zeroize could zero a page the kernel has
        // already made swappable.
        self.buf.zeroize();
        if self.locked {
            munlock_region(self.buf.as_ptr(), self.buf.len());
        }
    }
}

impl fmt::Debug for MlockedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the bytes; length + lock state are safe operational signal.
        f.debug_struct("MlockedKey")
            .field("len", &self.buf.len())
            .field("mlocked", &self.locked)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

/// Best-effort page-lock of `[ptr, ptr+len)`. Returns whether the lock was taken. A failure is
/// `warn!`-logged and swallowed (never fatal): a node with a low `RLIMIT_MEMLOCK` must still boot.
#[cfg(unix)]
fn mlock_region(ptr: *const u8, len: usize) -> bool {
    if len == 0 {
        return false;
    }
    // SAFETY: `ptr`/`len` describe a single live allocation owned by the calling `MlockedKey`
    // (its `Box<[u8]>`). `mlock` only pins the pages in RAM; it neither reads, writes, nor frees
    // the memory, and the region stays valid for the lifetime of the lock (released in `Drop`
    // before the allocation is freed).
    let rc = unsafe { libc::mlock(ptr.cast::<libc::c_void>(), len) };
    if rc == 0 {
        true
    } else {
        let err = std::io::Error::last_os_error();
        tracing::warn!(
            error = %err,
            len,
            "mlock of key material failed (is RLIMIT_MEMLOCK too low?); continuing without a \
             memory lock — this key may be swapped to disk"
        );
        false
    }
}

/// Best-effort unlock of a region previously locked by [`mlock_region`].
#[cfg(unix)]
fn munlock_region(ptr: *const u8, len: usize) {
    if len == 0 {
        return;
    }
    // SAFETY: same region this `MlockedKey` locked in `mlock_region`, still owned and valid here
    // (we are mid-`Drop`, before the allocation is freed). A munlock error is ignored — the memory
    // is about to be zeroized and freed regardless.
    unsafe {
        let _ = libc::munlock(ptr.cast::<libc::c_void>(), len);
    }
}

/// No page-locking primitive on this target (e.g. `wasm32`). Documented no-op: zeroize-on-drop and
/// the redacting `Debug` still protect the key; it is simply not pinned against swap.
#[cfg(not(unix))]
fn mlock_region(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(not(unix))]
fn munlock_region(_ptr: *const u8, _len: usize) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn as_slice_round_trips_the_bytes() {
        let k = MlockedKey::from_slice(&[1u8, 2, 3, 4]);
        assert_eq!(k.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(k.len(), 4);
        assert!(!k.is_empty());
    }

    #[test]
    fn debug_never_renders_the_key_bytes() {
        // A distinctive byte pattern that would be obvious in hex OR decimal if it leaked.
        let secret = [0xDEu8, 0xAD, 0xBE, 0xEF, 0x13, 0x37];
        let k = MlockedKey::from_slice(&secret);
        let d = format!("{k:?}");
        assert!(!d.contains("222"), "decimal byte leaked: {d}"); // 0xDE
        assert!(!d.contains("deadbeef"), "hex leaked: {d}");
        assert!(!d.contains("DEADBEEF"), "hex leaked: {d}");
        assert!(d.contains("<redacted>"), "expected redaction marker: {d}");
        assert!(d.contains("len: 6"), "length is safe to show: {d}");
    }

    #[test]
    fn mlock_is_best_effort_and_never_panics() {
        // Constructing a key attempts a lock; whether or not it succeeds (CI containers often cap
        // RLIMIT_MEMLOCK at 0, and non-unix has no mlock), construction must not panic and the key
        // must be fully usable either way.
        let k = MlockedKey::from_slice(b"a-swappable-or-locked-key");
        let _ = k.is_locked(); // either value is acceptable; the point is it does not panic
        assert_eq!(k.as_slice(), b"a-swappable-or-locked-key");
    }

    #[test]
    fn empty_key_is_handled() {
        let k = MlockedKey::from_slice(&[]);
        assert!(k.is_empty());
        assert!(!k.is_locked(), "an empty region is never locked");
        assert_eq!(k.as_slice(), b"");
        // Drop must not panic on a zero-length buffer.
        drop(k);
    }

    #[test]
    fn drop_zeroizes_without_panic() {
        // We cannot observe freed memory safely in stable Rust, so this asserts the Drop path
        // (zeroize + munlock) runs cleanly for a realistic 32-byte key.
        let k = MlockedKey::new(vec![0x42u8; 32].into_boxed_slice());
        assert_eq!(k.as_slice(), &[0x42u8; 32]);
        drop(k);
    }
}
