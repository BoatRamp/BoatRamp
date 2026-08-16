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
            only_imports: ["publish"],
        },
    });
}

use generated::boatramp::handlers::{messaging_producer, messaging_types};

/// The reserved topic selector for the shared **project bus**. A guest that
/// publishes (or a consumer that subscribes to) `bus:<topic>` addresses the
/// project-wide bus instead of its own component-private namespace, so a
/// producer and a consumer in *different* components can meet on one topic.
pub const BUS_TOPIC_SELECTOR: &str = "bus:";

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
}

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

impl messaging_producer::Host for MessagingHost<'_> {
    async fn publish(
        &mut self,
        topic: String,
        data: Vec<u8>,
    ) -> Result<(), messaging_types::Error> {
        let Some(binding) = self.binding else {
            return Err(messaging_types::Error::AccessDenied);
        };
        // A `bus:<topic>` publish targets the shared project bus; anything else
        // stays in the component-private namespace (back-compat).
        let namespaced = match topic.strip_prefix(BUS_TOPIC_SELECTOR) {
            Some(bus_topic) => format!("{}{bus_topic}", binding.bus_prefix),
            None => format!("{}{topic}", binding.prefix),
        };
        binding
            .messaging
            .publish(&namespaced, &data)
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

    /// Records what topics it was asked to publish (with the namespaced topic).
    #[derive(Default)]
    struct FakeMessaging {
        published: Mutex<Vec<(String, Vec<u8>)>>,
    }

    #[async_trait::async_trait]
    impl Messaging for FakeMessaging {
        async fn publish(&self, topic: &str, payload: &[u8]) -> Result<(), MessagingError> {
            self.published
                .lock()
                .unwrap()
                .push((topic.to_string(), payload.to_vec()));
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
        MessagingBinding {
            messaging: backend,
            prefix: "blog/production/".to_string(),
            bus_prefix: "acme/bus/".to_string(),
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
    async fn ungranted_publish_is_denied() {
        let mut host = MessagingHost::new(None);
        let err = host
            .publish("orders/created".into(), b"x".to_vec())
            .await
            .unwrap_err();
        assert!(matches!(err, messaging_types::Error::AccessDenied));
    }
}
