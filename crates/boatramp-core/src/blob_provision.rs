//! Cloud blob-change notification **provisioning** (PLAN-faas FA-5b2) — the IO
//! side of [`blob_notify`](crate::blob_notify). A [`WatchProvider`] provisions,
//! verifies, retracts, or describes (dry-run) the native notification pipeline for
//! one cloud object store (S3→SQS, GCS→Pub/Sub, Azure→Event Grid). The
//! [`ensure_watch`] orchestrator threads the four operator tiers and records what
//! it created in the managed-notification ledger so it can be retracted later —
//! the same reconcile/retract discipline as auto-DNS.
//!
//! This module is the **provider-agnostic scaffolding + a mock**; the concrete
//! cloud providers (which pull the cloud SDKs and are validated live) plug into
//! the same trait.

use async_trait::async_trait;

use crate::blob_notify::{ManagedNotification, ManagedResource, ProvisionTier};

/// A provisioning failure.
#[derive(Debug, Clone)]
pub enum ProvisionError {
    /// The cloud API (or credential) failed.
    Backend(String),
    /// The operator's `verify-only` tier found no configured pipeline.
    NotConfigured,
    /// A conflict boatramp must not clobber (e.g. an S3 bucket that already has a
    /// *different* owner's notification config).
    Conflict(String),
}

impl std::fmt::Display for ProvisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Backend(m) => write!(f, "notification provisioning: {m}"),
            Self::NotConfigured => write!(f, "no notification pipeline is configured"),
            Self::Conflict(m) => write!(f, "notification conflict: {m}"),
        }
    }
}

impl std::error::Error for ProvisionError {}

/// Provisions the native change-notification pipeline for one cloud object store.
/// Every method is idempotent; `provision` returns the resources created (for the
/// ledger), and `retract` deletes exactly those.
#[async_trait]
pub trait WatchProvider: Send + Sync {
    /// The provider token recorded in the ledger (`s3` / `gcs` / `azure`).
    fn name(&self) -> &str;

    /// A human-readable recipe (the `dry-run` tier): the exact resources + policy
    /// an operator would apply by hand. No side effects, no credentials.
    fn recipe(&self, prefix: &str) -> String;

    /// Provision the pipeline for `prefix` idempotently, returning the resources
    /// created (recorded in the ledger for retraction).
    async fn provision(&self, prefix: &str) -> Result<Vec<ManagedResource>, ProvisionError>;

    /// Whether a working pipeline already exists for `prefix` (the `verify-only`
    /// tier).
    async fn verify(&self, prefix: &str) -> Result<bool, ProvisionError>;

    /// Delete the given resources (retraction). Deleting an already-gone resource
    /// is not an error.
    async fn retract(&self, resources: &[ManagedResource]) -> Result<(), ProvisionError>;
}

/// The outcome of an [`ensure_watch`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionOutcome {
    /// The pipeline is ready (provisioned now, or verified as already present).
    Ready,
    /// The `dry-run` recipe — printed for the operator, nothing applied.
    Recipe(String),
    /// Fail-closed: no pipeline and no provisioning (the `refuse` tier, or
    /// `verify-only` with nothing configured). The trigger must not activate.
    Refused(String),
}

/// Ensure a blob-change notification pipeline for `(function, prefix)` per the
/// operator `tier`, recording provisioned resources in the ledger. Pure control
/// flow over the provider + a tiny ledger sink, so it is fully unit-testable with
/// a mock provider + an in-memory ledger.
pub async fn ensure_watch(
    provider: &dyn WatchProvider,
    tier: ProvisionTier,
    function: &str,
    prefix: &str,
    ledger: &dyn LedgerSink,
    now_unix: u64,
) -> Result<ProvisionOutcome, ProvisionError> {
    match tier {
        ProvisionTier::DryRun => Ok(ProvisionOutcome::Recipe(provider.recipe(prefix))),
        ProvisionTier::Refuse => Ok(ProvisionOutcome::Refused(
            "blob-change triggers refuse without a notification pipeline (set a provisioning tier)"
                .to_string(),
        )),
        ProvisionTier::VerifyOnly => {
            if provider.verify(prefix).await? {
                Ok(ProvisionOutcome::Ready)
            } else {
                Ok(ProvisionOutcome::Refused(
                    "verify-only: no pipeline is configured for this prefix".to_string(),
                ))
            }
        }
        ProvisionTier::Provision => {
            let resources = provider.provision(prefix).await?;
            let record =
                ManagedNotification::new(function, prefix, provider.name(), resources, now_unix);
            ledger.put(&record).await?;
            Ok(ProvisionOutcome::Ready)
        }
    }
}

/// Retract the pipeline recorded in `record`: delete its resources via `provider`,
/// then drop the ledger entry. Idempotent.
pub async fn retract_watch(
    provider: &dyn WatchProvider,
    record: &ManagedNotification,
    ledger: &dyn LedgerSink,
) -> Result<(), ProvisionError> {
    provider.retract(&record.resources).await?;
    ledger.delete(&record.function, &record.prefix).await?;
    Ok(())
}

/// The ledger persistence the orchestrator needs — a thin seam so the pure logic
/// is testable in-memory and the real one is the [`DeployStore`](crate::deploy)
/// (which is `&self`/`Arc`-based, hence the shared receiver).
#[async_trait]
pub trait LedgerSink: Send + Sync {
    /// Record (create/replace) a provisioned pipeline.
    async fn put(&self, record: &ManagedNotification) -> Result<(), ProvisionError>;
    /// Drop the ledger entry for `(function, prefix)`.
    async fn delete(&self, function: &str, prefix: &str) -> Result<(), ProvisionError>;
}

/// The real ledger is the control-plane store.
#[async_trait]
impl LedgerSink for crate::deploy::DeployStore {
    async fn put(&self, record: &ManagedNotification) -> Result<(), ProvisionError> {
        self.put_managed_notification(record)
            .await
            .map_err(|e| ProvisionError::Backend(e.to_string()))
    }
    async fn delete(&self, function: &str, prefix: &str) -> Result<(), ProvisionError> {
        self.remove_managed_notification(function, prefix)
            .await
            .map_err(|e| ProvisionError::Backend(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// A mock provider recording its calls, standing in for a cloud SDK.
    #[derive(Default)]
    struct MockProvider {
        provisioned: Arc<Mutex<Vec<String>>>,
        retracted: Arc<Mutex<Vec<String>>>,
        verify_result: bool,
    }

    #[async_trait]
    impl WatchProvider for MockProvider {
        fn name(&self) -> &str {
            "mock"
        }
        fn recipe(&self, prefix: &str) -> String {
            format!("create a queue + notification for prefix {prefix:?}")
        }
        async fn provision(&self, prefix: &str) -> Result<Vec<ManagedResource>, ProvisionError> {
            self.provisioned.lock().unwrap().push(prefix.to_string());
            Ok(vec![
                ManagedResource::new(
                    "queue",
                    format!("q-{}", crate::blob_notify::prefix_slug(prefix)),
                ),
                ManagedResource::new("bucket-notification", "bn-1"),
            ])
        }
        async fn verify(&self, _prefix: &str) -> Result<bool, ProvisionError> {
            Ok(self.verify_result)
        }
        async fn retract(&self, resources: &[ManagedResource]) -> Result<(), ProvisionError> {
            for r in resources {
                self.retracted.lock().unwrap().push(r.id.clone());
            }
            Ok(())
        }
    }

    /// An in-memory ledger sink (interior mutability, like the real store).
    #[derive(Default)]
    struct MemLedger {
        entries: Mutex<HashMap<String, ManagedNotification>>,
    }
    impl MemLedger {
        fn get(&self, function: &str, prefix: &str) -> Option<ManagedNotification> {
            self.entries
                .lock()
                .unwrap()
                .get(&crate::blob_notify::blobnotify_key(function, prefix))
                .cloned()
        }
        fn len(&self) -> usize {
            self.entries.lock().unwrap().len()
        }
    }
    #[async_trait]
    impl LedgerSink for MemLedger {
        async fn put(&self, record: &ManagedNotification) -> Result<(), ProvisionError> {
            self.entries.lock().unwrap().insert(
                crate::blob_notify::blobnotify_key(&record.function, &record.prefix),
                record.clone(),
            );
            Ok(())
        }
        async fn delete(&self, function: &str, prefix: &str) -> Result<(), ProvisionError> {
            self.entries
                .lock()
                .unwrap()
                .remove(&crate::blob_notify::blobnotify_key(function, prefix));
            Ok(())
        }
    }

    #[tokio::test]
    async fn dry_run_prints_a_recipe_and_provisions_nothing() {
        let provider = MockProvider::default();
        let ledger = MemLedger::default();
        let out = ensure_watch(
            &provider,
            ProvisionTier::DryRun,
            "ingest",
            "uploads/",
            &ledger,
            1,
        )
        .await
        .unwrap();
        assert!(matches!(out, ProvisionOutcome::Recipe(_)));
        assert!(provider.provisioned.lock().unwrap().is_empty());
        assert_eq!(ledger.len(), 0);
    }

    #[tokio::test]
    async fn provision_records_resources_then_retract_removes_them() {
        let provider = MockProvider::default();
        let ledger = MemLedger::default();
        let out = ensure_watch(
            &provider,
            ProvisionTier::Provision,
            "ingest",
            "uploads/",
            &ledger,
            5,
        )
        .await
        .unwrap();
        assert_eq!(out, ProvisionOutcome::Ready);
        assert_eq!(provider.provisioned.lock().unwrap().len(), 1);
        let record = ledger
            .get("ingest", "uploads/")
            .expect("ledger records the provisioned pipeline");
        assert_eq!(record.provider, "mock");
        assert_eq!(record.resources.len(), 2);

        retract_watch(&provider, &record, &ledger).await.unwrap();
        // Both resources were deleted and the ledger entry dropped.
        assert_eq!(provider.retracted.lock().unwrap().len(), 2);
        assert_eq!(ledger.len(), 0);
    }

    #[tokio::test]
    async fn verify_only_is_ready_or_refuses_and_refuse_fails_closed() {
        let ledger = MemLedger::default();

        // verify-only with a configured pipeline → ready.
        let ok = MockProvider {
            verify_result: true,
            ..Default::default()
        };
        assert_eq!(
            ensure_watch(&ok, ProvisionTier::VerifyOnly, "f", "p/", &ledger, 1)
                .await
                .unwrap(),
            ProvisionOutcome::Ready
        );

        // verify-only with nothing configured → refused (fail-closed).
        let missing = MockProvider {
            verify_result: false,
            ..Default::default()
        };
        assert!(matches!(
            ensure_watch(&missing, ProvisionTier::VerifyOnly, "f", "p/", &ledger, 1)
                .await
                .unwrap(),
            ProvisionOutcome::Refused(_)
        ));

        // refuse tier → refused, nothing touched.
        assert!(matches!(
            ensure_watch(&ok, ProvisionTier::Refuse, "f", "p/", &ledger, 1)
                .await
                .unwrap(),
            ProvisionOutcome::Refused(_)
        ));
    }
}
