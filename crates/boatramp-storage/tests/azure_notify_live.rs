//! Live seam for the Azure Event Grid → Storage Queue blob-change notification
//! pipeline (PLAN-storage-backends S4 / FA-5b2 Azure). Covers the boatramp-managed
//! half — the **Storage Queue** provision/verify/retract — against a real Azure
//! account (or Azurite for the queue). Env-gated, so `cargo test` is green without
//! infrastructure; the Event Grid subscription is an operator step (see the
//! provider recipe), and the pure event parse is covered by the `azure_notify`
//! unit tests.
//!
//! Run against Azurite (queue only) or real Azure:
//! ```sh
//! BOATRAMP_TEST_AZURE_NOTIFY_ACCOUNT=devstoreaccount1 \
//! BOATRAMP_TEST_AZURE_NOTIFY_CONTAINER=boatramp \
//! BOATRAMP_TEST_AZURE_EMULATOR=1 \
//!   cargo test -p boatramp-storage --features azure --test azure_notify_live -- --ignored --nocapture
//! ```
#![cfg(feature = "azure")]

use boatramp_core::blob_provision::WatchProvider;

#[tokio::test]
#[ignore = "needs a real Azure account or Azurite (queue); env-gated"]
async fn azure_notify_provision_verify_retract_round_trip() {
    let (Ok(account), Ok(container)) = (
        std::env::var("BOATRAMP_TEST_AZURE_NOTIFY_ACCOUNT"),
        std::env::var("BOATRAMP_TEST_AZURE_NOTIFY_CONTAINER"),
    ) else {
        eprintln!(
            "skipping: set BOATRAMP_TEST_AZURE_NOTIFY_ACCOUNT + \
             BOATRAMP_TEST_AZURE_NOTIFY_CONTAINER (+ AZURE_STORAGE_ACCESS_KEY or \
             BOATRAMP_TEST_AZURE_EMULATOR=1) to run the live Azure queue test"
        );
        return;
    };
    let emulator = std::env::var("BOATRAMP_TEST_AZURE_EMULATOR").is_ok();
    let access_key = std::env::var("AZURE_STORAGE_ACCESS_KEY").ok();

    let (_storage, provider) =
        boatramp_storage::AzureStorage::connect_with_notify(boatramp_storage::AzureOptions {
            account,
            container,
            access_key,
            emulator,
        })
        .expect("connect_with_notify");

    let prefix = "hblob/fn/notify-live-test/uploads/";

    let resources = provider.provision(prefix).await.expect("provision");
    assert!(resources.iter().any(|r| r.kind == "storage-queue"));
    assert!(
        provider.verify(prefix).await.expect("verify"),
        "queue present"
    );

    // Idempotent re-provision.
    let again = provider.provision(prefix).await.expect("re-provision");
    assert_eq!(again.len(), resources.len());

    provider.retract(&resources).await.expect("retract");
    assert!(
        !provider.verify(prefix).await.expect("verify after retract"),
        "queue gone after retract"
    );
}
