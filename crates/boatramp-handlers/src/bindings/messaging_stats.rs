//! The read-only **`messaging-stats`** host binding (`boatramp:handlers/messaging-stats`): a granted
//! guest reads the ALREADY-computed per-topic bus gauges — dead-letter count, backlog, in-flight, and
//! per-consumer-group depth/lag — for observability. Gauges ONLY: there is no claim, redrive, purge,
//! or any state-mutating verb. Deny-by-default: an ungranted component has no binding and every call
//! returns `access-denied`.
//!
//! # The security model (why a guest can't turn this into a cross-tenant oracle)
//!
//! Two tiers, matching how [`MessagingBinding`](super::messaging::MessagingBinding) namespaces a
//! publish:
//!
//! 1. **Private-namespace stats (trivially safe).** A plain (non-`bus:`) topic is prefixed with the
//!    component-private [`prefix`](StatsBinding::prefix) (`{scope}/…`), exactly like a `publish`. A
//!    guest can only ever name its OWN namespace, so no extra scoping is needed beyond the grant.
//!
//! 2. **Bus stats via a HOST-FILLED tenant template (the crux).** A `bus:<topic>` is namespaced only
//!    to `{project}/bus/…`; the tenant segment inside (e.g. `sync/<tenant>/import`) is an *app*
//!    convention boatramp cannot parse — so a guest-chosen bus topic would be a cross-tenant oracle.
//!    The fix mirrors host-forced tenancy: the component **declares** a tenant-templated stats topic
//!    with a host-controlled `{tenant}` placeholder (e.g. `bus:sync/{tenant}/import`), the guest's
//!    call names only that fixed template, and the HOST substitutes THIS invocation's
//!    [`resolved_tenant`](StatsBinding::resolved_tenant) — the same principal the SQL scope injector
//!    trusts — into `{tenant}`. The guest never supplies the tenant, so it is structurally unable to
//!    name another tenant's topic. A call whose (host-substituted) topic is not a declared template is
//!    refused (`not-declared`), and a `{tenant}` template with no resolved tenant fails closed.

use std::sync::Arc;

use boatramp_core::messaging::Messaging;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/messaging-stats-host",
        async: {
            only_imports: ["get", "groups"],
        },
    });
}

use generated::boatramp::handlers::{messaging_stats, messaging_stats_types};

use super::messaging::BUS_TOPIC_SELECTOR;

/// The reserved placeholder the host substitutes with this invocation's resolved tenant in a declared
/// `bus:` stats template (e.g. `bus:sync/{tenant}/import`). The guest names the template verbatim; the
/// host — never the guest — fills this in, so the guest cannot address another tenant's bus topic.
pub const TENANT_PLACEHOLDER: &str = "{tenant}";

/// A host-native snapshot of a topic's gauges (the read-only result of [`StatsBinding::read_topic_stats`]).
/// Mirrors the WIT `topic-stats`; kept as a plain struct so the binding's security logic + gauges are
/// testable (and drivable by a host-side live gate) without instantiating a guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TopicStats {
    pub dead_letter_count: u64,
    pub backlog: u64,
    pub in_flight: u64,
}

/// A host-native per-consumer-group gauge (the result of [`StatsBinding::read_group_stats`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupStats {
    pub group: String,
    pub in_flight: u64,
    pub lag: u64,
}

/// Why a stats read was refused (host-native; mapped to the WIT `stats-error`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatsRefused {
    /// The (host-substituted) topic is not one of the component's declared stats templates, or a
    /// `{tenant}` template was named with no resolved tenant to fill it — fail-closed.
    NotDeclared,
    /// A backend error reading the gauges.
    Backend(String),
}

/// A per-invocation `messaging-stats` grant: the backend to read gauges from, the component-private
/// topic prefix + shared bus prefix (identical to [`MessagingBinding`](super::messaging::MessagingBinding),
/// so a plain topic resolves to the same private namespace the component publishes to), the set of
/// declared `bus:` stats-topic templates, and the host-resolved tenant that fills each template's
/// `{tenant}` placeholder.
#[derive(Clone)]
pub struct StatsBinding {
    pub(crate) messaging: Arc<dyn Messaging>,
    /// The component-private topic prefix (`{scope}/`). A plain guest topic resolves under this — the
    /// same namespace [`MessagingBinding::namespace`](super::messaging::MessagingBinding) uses, so a
    /// component reads stats for exactly the private topics it publishes/consumes.
    pub(crate) prefix: String,
    /// The shared project-bus prefix (`{project}/bus/`). A declared `bus:` template resolves under this.
    pub(crate) bus_prefix: String,
    /// The component's declared `bus:` stats-topic templates, verbatim (each may contain a literal
    /// `{tenant}` placeholder). A guest's `bus:` stats call must name one of these exactly; the host
    /// then substitutes the resolved tenant into `{tenant}`. Empty ⇒ no bus stats are readable.
    pub(crate) bus_templates: Vec<String>,
    /// This invocation's host-resolved tenant (the plain tenant value the SQL scope injector uses),
    /// substituted for `{tenant}` in a declared template. `None` for an unscoped/anonymous invocation
    /// — a `{tenant}` template is then refused (`not-declared`, fail-closed), so a guest can never read
    /// bus stats without a resolved tenant to confine to.
    pub(crate) resolved_tenant: Option<String>,
}

impl StatsBinding {
    /// Resolve a guest-named `topic` to the concrete, host-namespaced topic to read gauges for, or an
    /// error explaining the refusal. This is the whole security boundary:
    ///
    /// * A plain (non-`bus:`) topic is host-prefixed with the component-private [`prefix`](Self::prefix)
    ///   and always allowed — a guest can only name its own namespace.
    /// * A `bus:<name>` topic must match one of the component's declared [`bus_templates`](Self::bus_templates)
    ///   EXACTLY (the guest names the template verbatim, `{tenant}` and all). If the template contains
    ///   `{tenant}`, the host substitutes this invocation's [`resolved_tenant`](Self::resolved_tenant);
    ///   with no resolved tenant the call is refused. A `bus:` topic that is not a declared template is
    ///   refused. The guest never supplies the tenant segment.
    fn resolve_topic(&self, topic: &str) -> Result<String, messaging_stats_types::StatsError> {
        let Some(bus_name) = topic.strip_prefix(BUS_TOPIC_SELECTOR) else {
            // A plain topic: the component-private namespace, exactly as `publish` namespaces it.
            return Ok(format!("{}{topic}", self.prefix));
        };
        // A `bus:` topic MUST be a declared template, matched verbatim (before substitution) — the
        // guest names the template it declared, never a tenant value.
        if !self.bus_templates.iter().any(|t| t == bus_name) {
            return Err(messaging_stats_types::StatsError::NotDeclared);
        }
        // The host — not the guest — fills `{tenant}` with this invocation's resolved tenant. A
        // template that needs a tenant but has none fails closed; the guest cannot supply one.
        let filled = if bus_name.contains(TENANT_PLACEHOLDER) {
            let Some(tenant) = self.resolved_tenant.as_deref() else {
                return Err(messaging_stats_types::StatsError::NotDeclared);
            };
            // SECURITY (review HIGH-1/MEDIUM-1): `{tenant}` fills a single topic SEGMENT. The resolved
            // tenant is host-derived but NOT constrained to one segment — a claim value legitimately
            // containing `/` (an org-path / email / URL-ish id), or empty/whitespace, or `..`, could
            // reshape the resolved topic to byte-match ANOTHER tenant's topic (or a parent prefix that
            // aggregates siblings), turning this read-only gauge into the cross-tenant oracle the
            // capability exists to prevent. Unlike a publish (which carries the tenant only inside a
            // COSE-signed envelope, never as a topic segment), this is the first place a tenant is
            // interpolated into a topic key, so validate it here and fail CLOSED.
            let clean = !tenant.trim().is_empty()
                && !tenant.contains('/')
                && !tenant.contains(TENANT_PLACEHOLDER)
                && !tenant.contains("..");
            if !clean {
                return Err(messaging_stats_types::StatsError::NotDeclared);
            }
            bus_name.replace(TENANT_PLACEHOLDER, tenant)
        } else {
            bus_name.to_string()
        };
        Ok(format!("{}{filled}", self.bus_prefix))
    }

    /// Read the read-only gauges for a guest-named `topic` (the whole capability). Resolves `topic`
    /// through [`resolve_topic`](Self::resolve_topic) — a plain topic to the component-private
    /// namespace, a `bus:` topic to a declared template with the host-filled `{tenant}` — then reads
    /// the ALREADY-computed dead-letter / backlog / in-flight gauges for that exact topic. No
    /// state-mutating verb is reachable. Public so a host-side live gate can drive it against the real
    /// substrate (the WIT `Host::get` delegates here).
    pub async fn read_topic_stats(&self, topic: &str) -> Result<TopicStats, StatsRefused> {
        let resolved = self.resolve_topic_native(topic)?;
        let dead_letter_count = self
            .messaging
            .dead_letter_count(&resolved)
            .await
            .map_err(|e| StatsRefused::Backend(e.to_string()))?;
        let backlog = self
            .messaging
            .backlog(&resolved)
            .await
            .map_err(|e| StatsRefused::Backend(e.to_string()))?;
        let in_flight = self
            .messaging
            .in_flight_count(&resolved)
            .await
            .map_err(|e| StatsRefused::Backend(e.to_string()))?;
        Ok(TopicStats {
            dead_letter_count: dead_letter_count as u64,
            backlog: backlog as u64,
            in_flight: in_flight as u64,
        })
    }

    /// Read the per-consumer-group gauges for a guest-named grouped `topic` (same resolution +
    /// tenant-template rules as [`read_topic_stats`](Self::read_topic_stats)). Empty for a work-queue
    /// topic. Public so a host-side live gate can drive it (the WIT `Host::groups` delegates here).
    pub async fn read_group_stats(&self, topic: &str) -> Result<Vec<GroupStats>, StatsRefused> {
        let resolved = self.resolve_topic_native(topic)?;
        let groups = self
            .messaging
            .list_groups(&resolved)
            .await
            .map_err(|e| StatsRefused::Backend(e.to_string()))?;
        Ok(groups
            .into_iter()
            .map(|g| GroupStats {
                group: g.group,
                in_flight: g.in_flight as u64,
                lag: g.lag as u64,
            })
            .collect())
    }

    /// [`resolve_topic`](Self::resolve_topic) with a host-native error (the WIT layer maps it back).
    fn resolve_topic_native(&self, topic: &str) -> Result<String, StatsRefused> {
        self.resolve_topic(topic)
            .map_err(|_| StatsRefused::NotDeclared)
    }
}

/// Per-invocation view over the (optional) `messaging-stats` grant.
pub struct StatsHost<'a> {
    binding: Option<&'a StatsBinding>,
}

impl<'a> StatsHost<'a> {
    /// Build a view; `None` means the capability was not granted (deny-by-default).
    pub fn new(binding: Option<&'a StatsBinding>) -> Self {
        Self { binding }
    }
}

/// Map a host-native [`StatsRefused`] to the WIT `stats-error` the guest sees.
fn to_wit(refused: StatsRefused) -> messaging_stats_types::StatsError {
    match refused {
        StatsRefused::NotDeclared => messaging_stats_types::StatsError::NotDeclared,
        // Review LOW-1: don't surface raw substrate error text to the guest (it could leak internal
        // detail); a generic message. The detail stays host-side in the `StatsRefused::Backend`.
        StatsRefused::Backend(detail) => {
            tracing::warn!(%detail, "messaging-stats backend read failed");
            messaging_stats_types::StatsError::Other("failed to read messaging stats".to_string())
        }
    }
}

impl messaging_stats::Host for StatsHost<'_> {
    async fn get(
        &mut self,
        topic: String,
    ) -> Result<messaging_stats_types::TopicStats, messaging_stats_types::StatsError> {
        let Some(binding) = self.binding else {
            return Err(messaging_stats_types::StatsError::AccessDenied);
        };
        let stats = binding.read_topic_stats(&topic).await.map_err(to_wit)?;
        Ok(messaging_stats_types::TopicStats {
            dead_letter_count: stats.dead_letter_count,
            backlog: stats.backlog,
            in_flight: stats.in_flight,
        })
    }

    async fn groups(
        &mut self,
        topic: String,
    ) -> Result<Vec<messaging_stats_types::GroupStats>, messaging_stats_types::StatsError> {
        let Some(binding) = self.binding else {
            return Err(messaging_stats_types::StatsError::AccessDenied);
        };
        let groups = binding.read_group_stats(&topic).await.map_err(to_wit)?;
        Ok(groups
            .into_iter()
            .map(|g| messaging_stats_types::GroupStats {
                group: g.group,
                in_flight: g.in_flight,
                lag: g.lag,
            })
            .collect())
    }
}

/// Add the `messaging-stats` interface to `linker`, resolving the per-invocation [`StatsHost`] via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> StatsHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    messaging_stats::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::messaging_stats::Host;
    use super::*;
    use boatramp_core::messaging::{ClaimedMessage, GroupInfo, MessagingError, StartPosition};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Duration;

    /// A fake backend recording which resolved topic each gauge was read for, and returning seeded
    /// counts keyed by the resolved topic — so a test asserts BOTH the resolved topic (the security
    /// property) and that the gauges flow through.
    #[derive(Default)]
    struct FakeMessaging {
        /// resolved topic -> (dead_letter, backlog, in_flight)
        gauges: Mutex<HashMap<String, (usize, usize, usize)>>,
        /// resolved topic -> groups
        groups: Mutex<HashMap<String, Vec<GroupInfo>>>,
        /// Every resolved topic a gauge was read for (assert the host-substituted topic).
        reads: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl Messaging for FakeMessaging {
        async fn publish(&self, _: &str, _: &[u8]) -> Result<(), MessagingError> {
            Ok(())
        }
        async fn claim(
            &self,
            _: &str,
            _: Duration,
            _: usize,
            _: u32,
        ) -> Result<Vec<ClaimedMessage>, MessagingError> {
            Ok(Vec::new())
        }
        async fn ack(&self, _: &ClaimedMessage) -> Result<(), MessagingError> {
            Ok(())
        }
        async fn nack(&self, _: &ClaimedMessage) -> Result<(), MessagingError> {
            Ok(())
        }
        async fn dead_letter_count(&self, topic: &str) -> Result<usize, MessagingError> {
            self.reads.lock().unwrap().push(topic.to_string());
            Ok(self
                .gauges
                .lock()
                .unwrap()
                .get(topic)
                .map(|g| g.0)
                .unwrap_or(0))
        }
        async fn backlog(&self, topic: &str) -> Result<usize, MessagingError> {
            Ok(self
                .gauges
                .lock()
                .unwrap()
                .get(topic)
                .map(|g| g.1)
                .unwrap_or(0))
        }
        async fn in_flight_count(&self, topic: &str) -> Result<usize, MessagingError> {
            Ok(self
                .gauges
                .lock()
                .unwrap()
                .get(topic)
                .map(|g| g.2)
                .unwrap_or(0))
        }
        async fn list_groups(&self, topic: &str) -> Result<Vec<GroupInfo>, MessagingError> {
            self.reads.lock().unwrap().push(topic.to_string());
            Ok(self
                .groups
                .lock()
                .unwrap()
                .get(topic)
                .cloned()
                .unwrap_or_default())
        }
        async fn claim_grouped(
            &self,
            _: &str,
            _: &str,
            _: StartPosition,
            _: Duration,
            _: usize,
            _: u32,
        ) -> Result<Vec<ClaimedMessage>, MessagingError> {
            Ok(Vec::new())
        }
    }

    fn binding(
        backend: Arc<FakeMessaging>,
        templates: &[&str],
        tenant: Option<&str>,
    ) -> StatsBinding {
        StatsBinding {
            messaging: backend,
            prefix: "blog/production/".to_string(),
            bus_prefix: "acme/bus/".to_string(),
            bus_templates: templates.iter().map(ToString::to_string).collect(),
            resolved_tenant: tenant.map(str::to_owned),
        }
    }

    #[tokio::test]
    async fn ungranted_get_is_access_denied() {
        let mut host = StatsHost::new(None);
        assert!(matches!(
            host.get("orders/created".into()).await.unwrap_err(),
            messaging_stats_types::StatsError::AccessDenied
        ));
        assert!(matches!(
            host.groups("orders/created".into()).await.unwrap_err(),
            messaging_stats_types::StatsError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn plain_topic_reads_the_private_namespace() {
        // A plain topic resolves under the component-private prefix — the same namespace it publishes
        // to. No template needed; a guest can only ever name its own namespace.
        let backend = Arc::new(FakeMessaging::default());
        backend
            .gauges
            .lock()
            .unwrap()
            .insert("blog/production/orders/created".into(), (3, 7, 2));
        let b = binding(backend.clone(), &[], None);
        let mut host = StatsHost::new(Some(&b));
        let stats = host.get("orders/created".into()).await.unwrap();
        assert_eq!(stats.dead_letter_count, 3);
        assert_eq!(stats.backlog, 7);
        assert_eq!(stats.in_flight, 2);
        assert_eq!(
            backend.reads.lock().unwrap()[0],
            "blog/production/orders/created"
        );
    }

    #[tokio::test]
    async fn bus_template_substitutes_the_host_resolved_tenant() {
        // THE SECURITY CRUX: the guest names the declared template `bus:sync/{tenant}/import`; the
        // host substitutes THIS invocation's resolved tenant (`t-42`) into `{tenant}` and reads gauges
        // for exactly that topic — the guest never supplies the tenant.
        let backend = Arc::new(FakeMessaging::default());
        backend
            .gauges
            .lock()
            .unwrap()
            .insert("acme/bus/sync/t-42/import".into(), (5, 0, 0));
        let b = binding(backend.clone(), &["sync/{tenant}/import"], Some("t-42"));
        let mut host = StatsHost::new(Some(&b));
        let stats = host.get("bus:sync/{tenant}/import".into()).await.unwrap();
        assert_eq!(stats.dead_letter_count, 5, "read t-42's dead-letter count");
        assert_eq!(
            backend.reads.lock().unwrap()[0],
            "acme/bus/sync/t-42/import",
            "the host filled {{tenant}} with the resolved tenant"
        );
    }

    #[tokio::test]
    async fn a_guest_cannot_choose_a_different_tenant() {
        // A guest trying to smuggle another tenant's topic — by naming a concrete tenant instead of
        // the `{tenant}` template — is refused: it is not a declared template. The ONLY bus topic it
        // can read is its own resolved tenant's, via the template the host fills.
        let backend = Arc::new(FakeMessaging::default());
        backend
            .gauges
            .lock()
            .unwrap()
            .insert("acme/bus/sync/victim/import".into(), (99, 0, 0));
        let b = binding(backend.clone(), &["sync/{tenant}/import"], Some("t-42"));
        let mut host = StatsHost::new(Some(&b));
        // Naming a concrete foreign tenant (not the declared template) is refused.
        assert!(matches!(
            host.get("bus:sync/victim/import".into()).await.unwrap_err(),
            messaging_stats_types::StatsError::NotDeclared
        ));
        // Even naming the literal template string but expecting to override the tenant is impossible —
        // the guest supplies only the fixed parts; the host always fills `{tenant}` with `t-42`.
        assert!(
            backend.reads.lock().unwrap().is_empty(),
            "the refused call never reached the backend"
        );
    }

    #[tokio::test]
    async fn an_undeclared_bus_topic_is_refused() {
        let backend = Arc::new(FakeMessaging::default());
        let b = binding(backend.clone(), &["sync/{tenant}/import"], Some("t-42"));
        let mut host = StatsHost::new(Some(&b));
        assert!(matches!(
            host.get("bus:some/other/topic".into()).await.unwrap_err(),
            messaging_stats_types::StatsError::NotDeclared
        ));
    }

    #[tokio::test]
    async fn a_tenant_template_with_no_resolved_tenant_fails_closed() {
        // Declared template needs `{tenant}` but the invocation has no resolved tenant (anonymous):
        // refused, so a guest can never read bus stats without a tenant to confine to.
        let backend = Arc::new(FakeMessaging::default());
        let b = binding(backend.clone(), &["sync/{tenant}/import"], None);
        let mut host = StatsHost::new(Some(&b));
        assert!(matches!(
            host.get("bus:sync/{tenant}/import".into())
                .await
                .unwrap_err(),
            messaging_stats_types::StatsError::NotDeclared
        ));
    }

    #[tokio::test]
    async fn a_slash_bearing_tenant_cannot_reshape_the_topic() {
        // Review HIGH-1: a resolved tenant that legitimately/maliciously contains `/` must NOT be
        // able to reshape `bus:sync/{tenant}` into another tenant's topic. Seed a victim's real
        // topic; the attacker's resolved tenant is `victim/import`; the read must be REFUSED before
        // it ever reaches the substrate (fail closed).
        let backend = Arc::new(FakeMessaging::default());
        backend
            .gauges
            .lock()
            .unwrap()
            .insert("acme/bus/sync/victim/import".into(), (99, 0, 0));
        let b = binding(backend.clone(), &["sync/{tenant}"], Some("victim/import"));
        let mut host = StatsHost::new(Some(&b));
        assert!(matches!(
            host.get("bus:sync/{tenant}".into()).await.unwrap_err(),
            messaging_stats_types::StatsError::NotDeclared
        ));
        assert!(
            backend.reads.lock().unwrap().is_empty(),
            "a slash-bearing tenant is refused before reaching the backend"
        );
    }

    #[tokio::test]
    async fn an_empty_or_whitespace_tenant_fails_closed() {
        // Review MEDIUM-1: an empty/whitespace resolved tenant must not resolve to a parent prefix
        // that aggregates siblings.
        for bad in ["", "   "] {
            let backend = Arc::new(FakeMessaging::default());
            let b = binding(backend.clone(), &["sync/{tenant}/import"], Some(bad));
            let mut host = StatsHost::new(Some(&b));
            assert!(
                matches!(
                    host.get("bus:sync/{tenant}/import".into())
                        .await
                        .unwrap_err(),
                    messaging_stats_types::StatsError::NotDeclared
                ),
                "empty/whitespace tenant {bad:?} must fail closed"
            );
            assert!(backend.reads.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn a_fixed_bus_template_needs_no_tenant() {
        // A declared bus template with NO `{tenant}` placeholder (a project-shared topic) is readable
        // without a resolved tenant — it names no tenant to confine.
        let backend = Arc::new(FakeMessaging::default());
        backend
            .gauges
            .lock()
            .unwrap()
            .insert("acme/bus/global/audit".into(), (1, 2, 3));
        let b = binding(backend.clone(), &["global/audit"], None);
        let mut host = StatsHost::new(Some(&b));
        let stats = host.get("bus:global/audit".into()).await.unwrap();
        assert_eq!(stats.backlog, 2);
        assert_eq!(backend.reads.lock().unwrap()[0], "acme/bus/global/audit");
    }

    #[tokio::test]
    async fn groups_reads_per_group_gauges_for_the_resolved_topic() {
        let backend = Arc::new(FakeMessaging::default());
        backend.groups.lock().unwrap().insert(
            "acme/bus/sync/t-42/import".into(),
            vec![GroupInfo {
                group: "workers".into(),
                hwm: "9".into(),
                in_flight: 4,
                lag: 11,
            }],
        );
        let b = binding(backend.clone(), &["sync/{tenant}/import"], Some("t-42"));
        let mut host = StatsHost::new(Some(&b));
        let groups = host
            .groups("bus:sync/{tenant}/import".into())
            .await
            .unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].group, "workers");
        assert_eq!(groups[0].in_flight, 4);
        assert_eq!(groups[0].lag, 11);
        assert_eq!(
            backend.reads.lock().unwrap()[0],
            "acme/bus/sync/t-42/import"
        );
    }
}
