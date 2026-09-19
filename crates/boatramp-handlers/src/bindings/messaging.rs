//! The `wasi:messaging` producer host binding: a handler (or consumer) publishes
//! to a topic, which the host enqueues via boatramp's internal
//! [`Messaging`](boatramp_core::messaging::Messaging) substrate. Topics are
//! **namespaced by the host** per (site, alias) with preview isolation, so a
//! guest can only ever publish into its own namespace.
//!
//! Deny by default: a handler not granted `wasi:messaging` has no binding, and
//! `publish` fails with `access-denied`. The consumer *export* half (the host
//! calling the guest's `handle`) lives in the engine's dispatch path, not here.

use std::sync::Arc;

use boatramp_core::messaging::Messaging;

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/messaging-host",
        async: {
            only_imports: ["publish", "publish-batch"],
        },
    });
}

use generated::boatramp::handlers::{messaging_producer, messaging_types};

/// The reserved topic selector for the shared **project bus**. A guest that
/// publishes (or a consumer that subscribes to) `bus:<topic>` addresses the
/// project-wide bus instead of its own component-private namespace, so a
/// producer and a consumer in *different* components can meet on one topic.
pub const BUS_TOPIC_SELECTOR: &str = "bus:";

/// The most messages a single `publish-batch` may carry. A batch is committed in one durable write
/// and its payloads are buffered host-side before the commit, so this bounds both the coalesced
/// commit size and the transient host memory a guest can pin with one call — a larger batch is
/// rejected whole (never partially published). Comfortably above a realistic pipeline chunk.
pub const PUBLISH_BATCH_MAX: usize = 1024;

/// A per-site messaging grant: the backend plus the topic-namespace prefixes the
/// host prepends. A plain `orders/created` is namespaced under the
/// component-private [`prefix`](Self::prefix) (`{site}/{alias}/orders/created`);
/// a `bus:orders.created` is namespaced under the project-shared
/// [`bus_prefix`](Self::bus_prefix) (`{project}/bus/orders.created`).
#[derive(Clone)]
pub struct MessagingBinding {
    pub(crate) messaging: Arc<dyn Messaging>,
    pub(crate) prefix: String,
    /// The shared project-bus prefix (`{project}/bus/`). A `bus:<topic>` publish
    /// routes here; a plain topic uses the private [`prefix`](Self::prefix).
    pub(crate) bus_prefix: String,
    /// The host-minted **durable signed-context** envelope (R1) stamped onto every message this
    /// producer publishes — the producer's own-tenant, sealed for the async lane so a consumer
    /// declaring `sources: [signed_context]` resolves it. Initialized at bind time from the
    /// invocation's resolved principal (the guest never names a tenant); `None` when the producer had
    /// no resolved own-tenant. A **shared cell** so a `tenancy::present-token` (Gap 3) can host-seal a
    /// tenant the emitter verified in-guest and update it mid-invocation, before the guest publishes;
    /// read fresh on each publish. Empty ⇒ the message carries no context (the consumer fails closed).
    pub(crate) signed_context: ProducerContext,
}

/// A per-invocation, shared cell holding the current host-sealed producer-context envelope (Gap 3).
/// Shared between the `messaging` binding (reads it at publish) and the `tenancy` binding
/// (`present-token` host-seals + writes it). Always host-minted — the guest never writes a tenant
/// value into it. `None` ⇒ an unscoped producer.
pub type ProducerContext = Arc<std::sync::Mutex<Option<String>>>;

/// Per-invocation view over the (optional) messaging grant.
pub struct MessagingHost<'a> {
    binding: Option<&'a MessagingBinding>,
}

impl<'a> MessagingHost<'a> {
    /// Build a view; `None` means the capability was not granted.
    pub fn new(binding: Option<&'a MessagingBinding>) -> Self {
        Self { binding }
    }
}

impl MessagingBinding {
    /// Host-namespace a guest-relative topic: a `bus:<topic>` targets the shared project bus
    /// ([`bus_prefix`](Self::bus_prefix)); anything else stays in the component-private
    /// [`prefix`](Self::prefix). A guest can only ever name topics within its own namespace.
    fn namespace(&self, topic: &str) -> String {
        match topic.strip_prefix(BUS_TOPIC_SELECTOR) {
            Some(bus_topic) => format!("{}{bus_topic}", self.bus_prefix),
            None => format!("{}{topic}", self.prefix),
        }
    }

    /// Read the current host-sealed producer-context envelope (R1/Gap 3) fresh from the shared cell —
    /// so a `tenancy::present-token` earlier in this invocation is reflected. `None` ⇒ an unscoped
    /// producer. The lock is released immediately (a quick clone).
    fn current_context(&self) -> Option<String> {
        self.signed_context
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }
}

impl messaging_producer::Host for MessagingHost<'_> {
    async fn publish(
        &mut self,
        topic: String,
        data: Vec<u8>,
    ) -> Result<(), messaging_types::Error> {
        let Some(binding) = self.binding else {
            return Err(messaging_types::Error::AccessDenied);
        };
        let namespaced = binding.namespace(&topic);
        // The guest names no tenant; the host stamps the producer's own-tenant signed context onto
        // the message so a declaring consumer resolves it on the async lane. `None` ⇒ an unscoped
        // producer, identical to a plain publish.
        let signed_context = binding.current_context();
        binding
            .messaging
            .publish_ctx(&namespaced, &data, signed_context.as_deref())
            .await
            .map_err(|err| messaging_types::Error::Other(err.to_string()))
    }

    async fn publish_batch(
        &mut self,
        messages: Vec<messaging_types::Outgoing>,
    ) -> Result<(), messaging_types::Error> {
        let Some(binding) = self.binding else {
            return Err(messaging_types::Error::AccessDenied);
        };
        // Reject an oversized batch WHOLE (never publish a prefix) — bounds the coalesced commit and
        // the host memory one call can pin. An empty batch is a no-op success.
        if messages.len() > PUBLISH_BATCH_MAX {
            return Err(messaging_types::Error::Other(format!(
                "publish-batch exceeds the {PUBLISH_BATCH_MAX}-message limit ({} given)",
                messages.len()
            )));
        }
        if messages.is_empty() {
            return Ok(());
        }
        // Every message in one batch comes from THIS single invocation, so they all share the one
        // host-sealed producer context (read once, fresh) — there is exactly one producer principal
        // per batch and no cross-tenant mixing. The guest still names no tenant.
        let signed_context = binding.current_context();
        let namespaced: Vec<(String, Vec<u8>)> = messages
            .into_iter()
            .map(|m| (binding.namespace(&m.topic), m.data))
            .collect();
        binding
            .messaging
            .publish_batch_ctx(&namespaced, signed_context.as_deref())
            .await
            .map_err(|err| messaging_types::Error::Other(err.to_string()))
    }
}

/// Add the `messaging-producer` interface to `linker`, resolving the
/// per-invocation [`MessagingHost`] view via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> MessagingHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    messaging_producer::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::messaging_producer::Host;
    use super::*;
    use boatramp_core::messaging::{ClaimedMessage, MessagingError};
    use std::sync::Mutex;
    use std::time::Duration;

    /// One recorded publish: the namespaced topic, the payload, and the durable signed-context
    /// envelope the host stamped (`None` for an unscoped producer).
    type PublishRecord = (String, Vec<u8>, Option<String>);

    /// Records what topics it was asked to publish (with the namespaced topic) and the durable
    /// signed-context envelope the host stamped, so a test can assert both the namespacing and the
    /// producer-context stamp.
    #[derive(Default)]
    struct FakeMessaging {
        published: Mutex<Vec<PublishRecord>>,
    }

    #[async_trait::async_trait]
    impl Messaging for FakeMessaging {
        async fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), MessagingError> {
            self.publish_ctx(topic, payload, None).await
        }
        async fn publish_ctx(
            &self,
            topic: &str,
            payload: &[u8],
            signed_context: Option<&str>,
        ) -> Result<(), MessagingError> {
            self.published.lock().unwrap().push((
                topic.to_string(),
                payload.to_vec(),
                signed_context.map(str::to_owned),
            ));
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
    }

    fn binding(backend: Arc<FakeMessaging>) -> MessagingBinding {
        binding_with_context(backend, None)
    }

    fn binding_with_context(
        backend: Arc<FakeMessaging>,
        signed_context: Option<String>,
    ) -> MessagingBinding {
        MessagingBinding {
            messaging: backend,
            prefix: "blog/production/".to_string(),
            bus_prefix: "acme/bus/".to_string(),
            signed_context: Arc::new(std::sync::Mutex::new(signed_context)),
        }
    }

    #[tokio::test]
    async fn publish_namespaces_the_topic() {
        let backend = Arc::new(FakeMessaging::default());
        let binding = binding(backend.clone());
        let mut host = MessagingHost::new(Some(&binding));
        host.publish("orders/created".into(), b"hello".to_vec())
            .await
            .unwrap();
        let published = backend.published.lock().unwrap();
        assert_eq!(published.len(), 1);
        // A plain topic stays in the component-private namespace.
        assert_eq!(published[0].0, "blog/production/orders/created");
        assert_eq!(published[0].1, b"hello");
    }

    #[tokio::test]
    async fn publish_routes_a_bus_topic_to_the_project_bus() {
        let backend = Arc::new(FakeMessaging::default());
        let binding = binding(backend.clone());
        let mut host = MessagingHost::new(Some(&binding));
        // `bus:<topic>` lands in the shared project bus, not the private prefix —
        // so a consumer in another component subscribed to the same bus topic
        // receives it.
        host.publish("bus:concept.generate".into(), b"go".to_vec())
            .await
            .unwrap();
        let published = backend.published.lock().unwrap();
        assert_eq!(published[0].0, "acme/bus/concept.generate");
    }

    #[tokio::test]
    async fn publish_stamps_the_host_minted_producer_context() {
        // A producer bound with a resolved own-tenant stamps the host-minted signed-context
        // envelope onto every message (guest-blind) — a declaring consumer resolves it later.
        let backend = Arc::new(FakeMessaging::default());
        let binding = binding_with_context(backend.clone(), Some("ctx-envelope-abc".to_string()));
        let mut host = MessagingHost::new(Some(&binding));
        host.publish("orders/created".into(), b"hi".to_vec())
            .await
            .unwrap();
        let published = backend.published.lock().unwrap();
        assert_eq!(
            published[0].2.as_deref(),
            Some("ctx-envelope-abc"),
            "the host stamped the producer's signed context onto the published message"
        );
    }

    #[tokio::test]
    async fn publish_without_a_resolved_tenant_stamps_no_context() {
        // An unscoped producer (no resolved own-tenant) stamps no context — the consumer then
        // fails an "own" op closed rather than acting as an unknown tenant.
        let backend = Arc::new(FakeMessaging::default());
        let binding = binding(backend.clone());
        let mut host = MessagingHost::new(Some(&binding));
        host.publish("orders/created".into(), b"hi".to_vec())
            .await
            .unwrap();
        assert_eq!(backend.published.lock().unwrap()[0].2, None);
    }

    #[tokio::test]
    async fn ungranted_publish_is_denied() {
        let mut host = MessagingHost::new(None);
        let err = host
            .publish("orders/created".into(), b"x".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(err, messaging_types::Error::AccessDenied));
    }

    fn outgoing(topic: &str, data: &[u8]) -> messaging_types::Outgoing {
        messaging_types::Outgoing {
            topic: topic.to_string(),
            data: data.to_vec(),
        }
    }

    #[tokio::test]
    async fn publish_batch_namespaces_each_message_and_stamps_shared_context() {
        // A4: one batch, mixed private + bus topics. Every message is namespaced independently and
        // all carry the single host-sealed producer context (one producer principal per batch).
        let backend = Arc::new(FakeMessaging::default());
        let binding = binding_with_context(backend.clone(), Some("ctx-abc".to_string()));
        let mut host = MessagingHost::new(Some(&binding));
        host.publish_batch(vec![
            outgoing("orders/created", b"a"),
            outgoing("bus:concept.generate", b"b"),
            outgoing("orders/created", b"c"),
        ])
        .await
        .unwrap();
        let published = backend.published.lock().unwrap();
        assert_eq!(published.len(), 3);
        assert_eq!(published[0].0, "blog/production/orders/created");
        assert_eq!(published[1].0, "acme/bus/concept.generate");
        assert_eq!(published[2].0, "blog/production/orders/created");
        assert_eq!(published[0].1, b"a");
        assert_eq!(published[1].1, b"b");
        // Every message carries the same host-minted context — no per-message tenant from the guest.
        assert!(published.iter().all(|p| p.2.as_deref() == Some("ctx-abc")));
    }

    #[tokio::test]
    async fn publish_batch_over_limit_is_rejected_whole() {
        let backend = Arc::new(FakeMessaging::default());
        let binding = binding(backend.clone());
        let mut host = MessagingHost::new(Some(&binding));
        let too_many: Vec<_> = (0..=PUBLISH_BATCH_MAX)
            .map(|_| outgoing("orders/created", b"x"))
            .collect();
        let err = host.publish_batch(too_many).await.unwrap_err();
        assert!(matches!(err, messaging_types::Error::Other(_)));
        // Rejected whole — not a single message was published.
        assert_eq!(backend.published.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn empty_publish_batch_is_a_noop_success() {
        let backend = Arc::new(FakeMessaging::default());
        let binding = binding(backend.clone());
        let mut host = MessagingHost::new(Some(&binding));
        host.publish_batch(Vec::new()).await.unwrap();
        assert_eq!(backend.published.lock().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn ungranted_publish_batch_is_denied() {
        let mut host = MessagingHost::new(None);
        let err = host
            .publish_batch(vec![outgoing("orders/created", b"x")])
            .await
            .unwrap_err();
        assert!(matches!(err, messaging_types::Error::AccessDenied));
    }
}
