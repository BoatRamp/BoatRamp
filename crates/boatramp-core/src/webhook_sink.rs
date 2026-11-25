//! The KV-backed registry of **runtime-registered** webhook sinks
//! (PLAN-messaging-consumer-delivery, increment d) — the persistence behind the
//! `PUT`/`DELETE /api/projects/{proj}/bus/sinks/{name}` surface.
//!
//! Project-scoped keys (`project/<proj>/bus-webhook-sink/<name>`, via
//! [`crate::deploy::keys::bus_webhook_sink`]) so a `Messaging·Admin`-on-`<proj>` grant only ever
//! reaches its own project's sinks, and `purge_project`'s residual sweep clears them when the project
//! is torn down. The stored record is the SAME [`WebhookSink`] the config-declared
//! `routing.webhook_sinks` block uses (one record, two registration paths); the destination + HMAC
//! SECRETS are NOT in this record — they are sealed `boatramp:<name>` references resolved host-side at
//! delivery time. Mirrors the [`EmailProfileStore`](crate::email_config::EmailProfileStore) KV-store
//! shape.

use std::sync::Arc;

use crate::config::WebhookSink;
use crate::kv::KvStore;
use crate::project::ProjectRef;

/// A KV-backed store of runtime-registered webhook sinks.
#[derive(Clone)]
pub struct WebhookSinkStore {
    kv: Arc<dyn KvStore>,
}

impl WebhookSinkStore {
    #[must_use]
    pub fn new(kv: Arc<dyn KvStore>) -> Self {
        Self { kv }
    }

    fn key(project: &str, name: &str) -> String {
        crate::deploy::keys::bus_webhook_sink(ProjectRef::new(project), name)
    }

    /// Persist (create or replace) a sink under its project. The caller validates the record
    /// ([`WebhookSink::validate`]) and the destination (the SSRF floor) before this.
    pub async fn set(&self, project: &str, sink: &WebhookSink) -> Result<(), String> {
        let bytes = serde_json::to_vec(sink).map_err(|e| format!("encode webhook sink: {e}"))?;
        self.kv
            .put(&Self::key(project, &sink.name), bytes)
            .await
            .map_err(|e| format!("persist webhook sink: {e}"))
    }

    /// Fetch one sink by project + name, if registered.
    pub async fn get(&self, project: &str, name: &str) -> Result<Option<WebhookSink>, String> {
        match self
            .kv
            .get(&Self::key(project, name))
            .await
            .map_err(|e| format!("read webhook sink: {e}"))?
        {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| format!("decode webhook sink: {e}")),
            None => Ok(None),
        }
    }

    /// Remove a sink; returns whether a record existed (idempotent).
    pub async fn delete(&self, project: &str, name: &str) -> Result<bool, String> {
        let key = Self::key(project, name);
        let existed = self
            .kv
            .get(&key)
            .await
            .map_err(|e| format!("read webhook sink: {e}"))?
            .is_some();
        self.kv
            .delete(&key)
            .await
            .map_err(|e| format!("delete webhook sink: {e}"))?;
        Ok(existed)
    }

    /// Every runtime-registered sink of one project. A malformed / legacy record is skipped with a
    /// warn (never aborting the drain of the rest).
    pub async fn list_project_sinks(&self, project: &str) -> Result<Vec<WebhookSink>, String> {
        let prefix = crate::deploy::keys::bus_webhook_sink_prefix(ProjectRef::new(project));
        let entries = self
            .kv
            .scan_prefix(&prefix)
            .await
            .map_err(|e| format!("list webhook sinks: {e}"))?;
        let mut sinks = Vec::with_capacity(entries.len());
        for (key, bytes) in entries {
            match serde_json::from_slice::<WebhookSink>(&bytes) {
                Ok(sink) => sinks.push(sink),
                Err(e) => {
                    tracing::warn!(%key, error = %e, "skipping malformed webhook sink record");
                }
            }
        }
        Ok(sinks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::MemoryKv;

    fn sink(name: &str) -> WebhookSink {
        WebhookSink {
            name: name.into(),
            topic: "orders/created".into(),
            group: String::new(),
            url_secret: "boatramp:wh-url".into(),
            egress_allow: vec!["sink.example.com:443".into()],
            sign_secret: "boatramp:wh-sign".into(),
            lease_ms: None,
            max_attempts: None,
            backoff_ms: None,
            max_ack_pending: None,
        }
    }

    #[tokio::test]
    async fn round_trip_and_tenant_scoping() {
        let store = WebhookSinkStore::new(Arc::new(MemoryKv::new()));
        assert!(store.list_project_sinks("acme").await.unwrap().is_empty());
        store.set("acme", &sink("a")).await.unwrap();
        store.set("acme", &sink("b")).await.unwrap();
        let mut names: Vec<_> = store
            .list_project_sinks("acme")
            .await
            .unwrap()
            .into_iter()
            .map(|s| s.name)
            .collect();
        names.sort();
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
        // Another project sees none (tenant scoping).
        assert!(store.list_project_sinks("other").await.unwrap().is_empty());
        assert_eq!(store.get("acme", "a").await.unwrap().unwrap().name, "a");
        assert!(store.delete("acme", "a").await.unwrap());
        assert!(!store.delete("acme", "a").await.unwrap());
        assert!(store.get("acme", "a").await.unwrap().is_none());
    }
}
