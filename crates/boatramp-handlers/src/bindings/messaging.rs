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

/// A per-site messaging grant: the backend plus the topic-namespace prefix the
/// host prepends to every published topic (so the guest's `orders/created`
/// becomes `{site}/{alias}/orders/created`).
#[derive(Clone)]
pub struct MessagingBinding {
    pub(crate) messaging: Arc<dyn Messaging>,
    pub(crate) prefix: String,
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
        let namespaced = format!("{}{topic}", binding.prefix);
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

    #[tokio::test]
    async fn publish_namespaces_the_topic() {
        let backend = Arc::new(FakeMessaging::default());
        let binding = MessagingBinding {
            messaging: backend.clone(),
            prefix: "blog/production/".to_string(),
        };
        let mut host = MessagingHost::new(Some(&binding));
        host.publish("orders/created".into(), b"hello".to_vec())
            .await
            .unwrap();
        let published = backend.published.lock().unwrap();
        assert_eq!(published.len(), 1);
        assert_eq!(published[0].0, "blog/production/orders/created");
        assert_eq!(published[0].1, b"hello");
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
