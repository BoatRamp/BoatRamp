//! A caller-held **graceful-shutdown** signal for a served connection.
//!
//! The crate serves one connection per future ([`serve_connection`](crate::serve_connection),
//! [`h2::serve_connection_mux`](crate::h2::serve_connection_mux), …). To drain a connection
//! without dropping its in-flight work, the caller creates a [`GracefulShutdown`], passes a
//! clone to a graceful-aware serve entry point
//! ([`serve_connection_graceful`](crate::serve_connection_graceful),
//! [`h2::serve_connection_mux_with`](crate::h2::serve_connection_mux_with),
//! [`h1::serve_connection_with_config`](crate::h1::serve_connection_with_config)), and later
//! calls [`GracefulShutdown::trigger`]. On trigger:
//!
//! - the **HTTP/2** side emits a `GOAWAY` (last-stream-id = the highest stream it has
//!   accepted) and lets its in-flight handlers finish; streams opened after the `GOAWAY`
//!   are refused with `REFUSED_STREAM`. The connection then closes once the peer, having
//!   seen the `GOAWAY`, closes its side;
//! - the **HTTP/1.1** side closes after the request it is currently serving (the next
//!   response carries `Connection: close`).
//!
//! The handle only *initiates* a drain; it does not impose a hard deadline. A caller that
//! needs one races the serve future against a timer and drops the serve future (which
//! closes the socket) when the grace period elapses:
//!
//! ```ignore
//! let shutdown = GracefulShutdown::new();
//! tokio::select! {
//!     r = serve_connection_graceful(io, handler, Config::default(), shutdown.clone()) => { r?; }
//!     _ = async { shutdown.trigger(); tokio::time::sleep(grace).await } => { /* drop serve */ }
//! }
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

/// A cloneable handle that drains a served connection when [`trigger`](Self::trigger)ed.
///
/// All clones share one signal, so a connection can be handed one clone while the caller
/// keeps another to trigger the drain. Triggering is idempotent and never blocks.
#[derive(Clone)]
pub struct GracefulShutdown {
    inner: Arc<Inner>,
}

struct Inner {
    triggered: AtomicBool,
    notify: Notify,
}

impl GracefulShutdown {
    /// A fresh, un-triggered shutdown signal.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                triggered: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    /// Begin draining every connection holding a clone of this handle. Idempotent — a
    /// second call is a no-op. Non-blocking.
    pub fn trigger(&self) {
        self.inner.triggered.store(true, Ordering::SeqCst);
        // Wake every serve loop currently parked in `watch`.
        self.inner.notify.notify_waiters();
    }

    /// Whether [`trigger`](Self::trigger) has been called.
    pub fn is_triggered(&self) -> bool {
        self.inner.triggered.load(Ordering::SeqCst)
    }

    /// Resolve once the drain has been triggered (immediately if it already has). Used by
    /// the serve loops to react to a drain. Cancellation-safe.
    pub(crate) async fn watch(&self) {
        if self.is_triggered() {
            return;
        }
        // Register for notification *before* re-checking the flag, so a `trigger` that
        // races between the first check and the park is never lost (the classic
        // check-then-wait gap).
        let notified = self.inner.notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if self.is_triggered() {
            return;
        }
        notified.await;
    }
}

impl Default for GracefulShutdown {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for GracefulShutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GracefulShutdown")
            .field("triggered", &self.is_triggered())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn watch_resolves_after_trigger() {
        let sd = GracefulShutdown::new();
        assert!(!sd.is_triggered());
        let waiter = sd.clone();
        let h = tokio::spawn(async move { waiter.watch().await });
        // Give the task a moment to park in `watch`, then trigger.
        tokio::task::yield_now().await;
        sd.trigger();
        assert!(sd.is_triggered());
        // The parked waiter must wake.
        tokio::time::timeout(std::time::Duration::from_secs(1), h)
            .await
            .expect("watch did not resolve after trigger")
            .unwrap();
    }

    #[tokio::test]
    async fn watch_returns_immediately_if_already_triggered() {
        let sd = GracefulShutdown::new();
        sd.trigger();
        // Already triggered → resolves without parking.
        tokio::time::timeout(std::time::Duration::from_millis(50), sd.watch())
            .await
            .expect("watch should return immediately when already triggered");
    }
}
