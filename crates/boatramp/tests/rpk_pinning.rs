//! End-to-end check of the `--tls rpk` **client** pinning path: a real listener —
//! served through boatramp's own TLS stack (`serve_tls_listener`) exactly as
//! `--tls rpk` does — presenting an RFC 7250 raw-public-key identity, reached by a
//! `reqwest` client configured exactly like `client::http_client` does when
//! `BOATRAMP_SERVER_PUBKEY` is set — `use_preconfigured_tls(client_config_server_auth(pin))`.
//! Confirms the correct pin connects and a wrong pin fails the handshake.
#![cfg(feature = "tls")]

use std::collections::BTreeMap;
use std::sync::Arc;

use boatramp_rpktls::{client_config_server_auth, RpkIdentity, RpkTls, TrustSet};

/// Spawn a minimal RPK-TLS server (a `/healthz` route) and return its address +
/// the SPKI it presents. rpktls configs carry their own crypto provider, so no
/// process-global provider install is needed.
async fn spawn_rpk_server() -> (std::net::SocketAddr, Vec<u8>) {
    let identity = RpkIdentity::generate().unwrap();
    let spki = identity.public_key().to_vec();
    let rpk = RpkTls::new(Arc::new(identity), TrustSet::default());
    let mut config = rpk.server_auth().unwrap();
    config.alpn_protocols = boatramp_server::alpn_h1_h2();

    let app = axum::Router::new().route("/healthz", axum::routing::get(|| async { "ok" }));
    // Bind first so the ephemeral port is known, then serve through the same stack
    // `serve_rpk` uses (no hyper / axum_server on the serving path).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = boatramp_server::serve_tls_listener(
            listener,
            config.into(),
            app,
            std::future::pending::<()>(),
        )
        .await;
    });
    (addr, spki)
}

/// Build a reqwest client pinned to `spki` for the single control-plane peer,
/// exactly as `http_client` does from `BOATRAMP_SERVER_PUBKEY`.
fn pinned_client(spki: Vec<u8>) -> reqwest::Client {
    let trust = TrustSet::from_map(BTreeMap::from([(0u64, spki)]));
    let config = client_config_server_auth(trust, 0).unwrap();
    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .unwrap()
}

#[tokio::test]
async fn pinned_client_reaches_the_server_and_rejects_a_wrong_pin() {
    let (addr, server_spki) = spawn_rpk_server().await;
    let url = format!("https://127.0.0.1:{}/healthz", addr.port());

    // The correct pin → the RPK handshake completes and /healthz answers.
    let resp = pinned_client(server_spki.clone())
        .get(&url)
        .send()
        .await
        .expect("a correctly-pinned client must connect");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.text().await.unwrap(), "ok");

    // A wrong pin (a stranger's key) → the handshake is rejected.
    let wrong = RpkIdentity::generate().unwrap().public_key().to_vec();
    assert!(
        pinned_client(wrong).get(&url).send().await.is_err(),
        "a wrong pin must fail the handshake"
    );
}
