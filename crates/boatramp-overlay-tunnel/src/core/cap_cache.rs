//! Lazy capability mint + lifecycle (plan §1.4): a cache of `{token, expires_at, grant}` keyed by
//! canonical service name (one `ControlPlane` is already scoped to one holder/project, so the
//! service name alone is the right cache key). Reused within TTL minus a refresh skew; **never**
//! served past `expires_at` — an overlay-dial capability is offline-verified with no revocation, so
//! an expired entry is dead weight, never a stale-but-usable one. A background sweeper proactively
//! re-mints entries that are both near expiry AND recently used, so a long-lived flow's *service*
//! does not stall behind a synchronous mint on the next dial (an idle entry is left to expire and is
//! re-minted lazily on its next use instead — no pointless background traffic for services nobody is
//! dialing any more).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use boatramp_overlay_client::OverlayId;
use tokio::sync::RwLock;

use super::control_plane::{ControlPlane, ControlPlaneError, DialGrant};

/// Upper bound on the refresh skew (plan §1.4: `min(60s, 20% TTL)`).
const MAX_SKEW_SECS: u64 = 60;

/// How often the background sweeper looks for near-expiry, in-use entries to proactively re-mint.
pub(super) const SWEEP_INTERVAL: Duration = Duration::from_secs(15);

/// An entry only counts as "in use" for the sweeper if it was last served within this long ago.
/// Generous relative to [`SWEEP_INTERVAL`] so a flow that dials every minute or so still keeps its
/// service warm; an entry idle longer than this is left to expire and is re-minted lazily instead.
const IN_USE_WINDOW_SECS: u64 = 120;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// `min(60s, 20% of ttl)`, computed once at mint time from that grant's own TTL (not recomputed
/// against the shrinking remaining lifetime — that would be a moving target that never quite closes
/// in on the expiry boundary).
fn refresh_skew_secs(ttl_secs: u64) -> u64 {
    (ttl_secs / 5).min(MAX_SKEW_SECS)
}

struct CachedGrant {
    grant: DialGrant,
    /// `expires_at - refresh_skew`: once `now` reaches this, the entry needs a fresh mint before
    /// being served again (the lazy path), or is a sweep candidate (the proactive path).
    refresh_at: u64,
    /// Unix-seconds of the last time this entry was served to a caller — the sweeper's "in use"
    /// signal.
    last_used: u64,
}

impl CachedGrant {
    fn fresh(grant: DialGrant, minted_at: u64) -> Self {
        let ttl = grant.expires_at.saturating_sub(minted_at);
        let refresh_at = grant.expires_at.saturating_sub(refresh_skew_secs(ttl));
        Self {
            grant,
            refresh_at,
            last_used: minted_at,
        }
    }

    fn usable(&self, now: u64) -> bool {
        now < self.refresh_at
    }

    fn in_use(&self, now: u64) -> bool {
        now.saturating_sub(self.last_used) <= IN_USE_WINDOW_SECS
    }
}

/// The lazy-mint cache described above.
pub(crate) struct CapCache {
    control_plane: Arc<dyn ControlPlane>,
    entries: RwLock<HashMap<String, CachedGrant>>,
}

impl CapCache {
    pub(super) fn new(control_plane: Arc<dyn ControlPlane>) -> Self {
        Self {
            control_plane,
            entries: RwLock::new(HashMap::new()),
        }
    }

    /// Mint fresh from the control plane and (re)insert, returning the new grant.
    async fn mint(&self, service: &str, holder: OverlayId) -> Result<DialGrant, ControlPlaneError> {
        let minted_at = now_unix();
        let grant = self.control_plane.resolve_and_mint(service, holder).await?;
        let out = grant.clone();
        self.entries
            .write()
            .await
            .insert(service.to_string(), CachedGrant::fresh(grant, minted_at));
        Ok(out)
    }

    /// Return a usable grant for `service`, reusing the cached one if it is within TTL minus the
    /// refresh skew, else minting (and caching) a fresh one. Marks the entry used either way, so the
    /// background sweeper knows it is live.
    pub(super) async fn get_or_mint(
        &self,
        service: &str,
        holder: OverlayId,
    ) -> Result<DialGrant, ControlPlaneError> {
        let now = now_unix();
        {
            let mut entries = self.entries.write().await;
            if let Some(cached) = entries.get_mut(service)
                && cached.usable(now)
            {
                cached.last_used = now;
                return Ok(cached.grant.clone());
            }
        }
        self.mint(service, holder).await
    }

    /// Spawn the background sweeper: every [`SWEEP_INTERVAL`], re-mint any entry that is both past
    /// its `refresh_at` and still "in use" ([`IN_USE_WINDOW_SECS`]). `holder` is the tunnel's one
    /// fixed identity — every mint in this process is bound to it.
    pub(super) fn spawn_sweeper(self: &Arc<Self>, holder: OverlayId) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_INTERVAL).await;
                let now = now_unix();
                let due: Vec<String> = {
                    let entries = this.entries.read().await;
                    entries
                        .iter()
                        .filter(|(_, c)| !c.usable(now) && c.in_use(now))
                        .map(|(service, _)| service.clone())
                        .collect()
                };
                for service in due {
                    if let Err(err) = this.mint(&service, holder).await {
                        tracing::warn!(
                            error = %err, %service,
                            "overlay tunnel: background cap-cache re-mint failed"
                        );
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::test_support::{MockControlPlane, dummy_id, entry_at, now_unix as test_now};
    use std::sync::atomic::Ordering;

    #[tokio::test]
    async fn reuses_a_cached_grant_within_ttl() {
        let cp = Arc::new(MockControlPlane::new(vec![entry_at(
            "svc/db",
            "127.0.0.1:1".parse().unwrap(),
            true,
        )]));
        let cache = CapCache::new(Arc::clone(&cp) as Arc<dyn ControlPlane>);
        let holder = dummy_id();
        let first = cache.get_or_mint("svc/db", holder).await.unwrap();
        let second = cache.get_or_mint("svc/db", holder).await.unwrap();
        assert_eq!(first.token, second.token);
        assert_eq!(cp.mint_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn never_serves_a_grant_past_its_expiry() {
        // A 1s TTL; skew = min(60, 1/5) = 0 (integer division), so "usable" holds right up to
        // expiry. Sleep past it and the next call must mint fresh rather than hand back the dead
        // token.
        let cp = Arc::new(MockControlPlane::with_ttl(
            vec![entry_at("svc/db", "127.0.0.1:1".parse().unwrap(), true)],
            1,
        ));
        let cache = CapCache::new(Arc::clone(&cp) as Arc<dyn ControlPlane>);
        let holder = dummy_id();
        let first = cache.get_or_mint("svc/db", holder).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1200)).await;
        let second = cache.get_or_mint("svc/db", holder).await.unwrap();
        assert_ne!(
            first.token, second.token,
            "a fresh mint must have a later expiry/new token"
        );
        assert!(
            test_now() < second.expires_at,
            "the served grant must not be already-expired"
        );
        assert_eq!(cp.mint_calls.load(Ordering::SeqCst), 2);
    }

    /// The sweeper with a short enough TTL/skew to observe within a fast unit test: TTL=2s -> skew =
    /// min(60, 0) = 0 — not useful (integer division rounds `ttl/5` to 0 below `ttl=5`). Use TTL=5s
    /// -> skew = min(60,1)=1s -> refresh_at = expires_at-1s (~4s after mint). A 200ms poll (driving
    /// the same filter `spawn_sweeper` would, rather than via its fixed 15s interval) proactively
    /// re-mints it, and a `get_or_mint` right after then hits the ALREADY-REFRESHED entry (no extra
    /// mint) — proving a long flow's next dial does not stall behind a synchronous mint.
    #[tokio::test]
    async fn a_fast_sweeper_proactively_remints_before_the_lazy_path_would_need_to() {
        // TTL=5s -> skew = min(60, 5/5=1) = 1s -> refresh_at = expires_at-1s (~4s after mint).
        let cp = Arc::new(MockControlPlane::with_ttl(
            vec![entry_at("svc/db", "127.0.0.1:1".parse().unwrap(), true)],
            5,
        ));
        let cache = Arc::new(CapCache::new(Arc::clone(&cp) as Arc<dyn ControlPlane>));
        let holder = dummy_id();
        let first = cache.get_or_mint("svc/db", holder).await.unwrap();
        assert_eq!(cp.mint_calls.load(Ordering::SeqCst), 1);

        // Drive the same sweep logic `spawn_sweeper` would, but on a fast interval so the test
        // finishes quickly: poll every 200ms for up to 5s for a second mint to land (must appear
        // once `now` crosses the ~4s refresh_at mark, comfortably before the 5s expiry).
        let mut remint_seen = false;
        for _ in 0..25 {
            tokio::time::sleep(Duration::from_millis(200)).await;
            let now = test_now();
            let due: Vec<String> = {
                let entries = cache.entries.read().await;
                entries
                    .iter()
                    .filter(|(_, c)| !c.usable(now) && c.in_use(now))
                    .map(|(s, _)| s.clone())
                    .collect()
            };
            for service in due {
                cache.mint(&service, holder).await.unwrap();
            }
            if cp.mint_calls.load(Ordering::SeqCst) > 1 {
                remint_seen = true;
                break;
            }
        }
        assert!(
            remint_seen,
            "the sweeper must proactively re-mint a near-expiry, in-use entry"
        );

        // A `get_or_mint` right around the ORIGINAL refresh boundary now hits the already-refreshed
        // entry — no extra synchronous mint, proving a long flow's next dial does not stall on it.
        let calls_before = cp.mint_calls.load(Ordering::SeqCst);
        let refreshed = cache.get_or_mint("svc/db", holder).await.unwrap();
        assert_eq!(
            cp.mint_calls.load(Ordering::SeqCst),
            calls_before,
            "served from cache"
        );
        assert_ne!(
            first.token, refreshed.token,
            "the sweeper's mint replaced the original grant"
        );
    }
}
