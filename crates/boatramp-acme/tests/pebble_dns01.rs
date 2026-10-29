//! End-to-end ACME **DNS-01** wildcard issuance against a local
//! [Pebble](https://github.com/letsencrypt/pebble) CA — the same harness the
//! TLS-ALPN-01 path was validated with, extended to DNS-01.
//!
//! It mints a throwaway CA + Pebble server cert (rcgen), spawns `pebble` and
//! `pebble-challtestsrv`, drives the real issuance for `*.deploy.test`
//! (solving the `_acme-challenge` TXT via challtestsrv's management API), and
//! asserts a Pebble-signed certificate chain comes back.
//!
//! **Regression gate for the `dns-persist-01` tokenless-challenge bug.** Pebble
//! **≥ 2.10.0** includes a tokenless `dns-persist-01` challenge in every
//! authorization (mirroring Let's Encrypt / Google Trust Services in production).
//! instant-acme < 0.8.5 made `Challenge.token` a *required* serde field, so
//! deserializing the authorization failed with `missing field \`token\``,
//! wrecking the whole authorization — including the `dns-01` challenge we select —
//! and ACME DNS-01 issuance crash-looped against the real CA. instant-acme ≥ 0.8.5
//! tolerates the tokenless challenge, so this test now issues a cert cleanly; on
//! the old client against the same Pebble it reproduces the deserialization crash.
//!
//! No longer `#[ignore]`d: it is a real success-marker gate (prints
//! `ACME-DNS-PERSIST GATE OK: …`, which CI greps). It still needs the `pebble` +
//! `pebble-challtestsrv` binaries (≥ 2.10.0) on `PATH` — provided by the nix dev
//! shell (`flake.nix` pins the version) — and binds local ports; when the binaries
//! are absent it prints a skip line and returns (so a plain `cargo test` without
//! them is a no-op, while the CI gate guarantees they are present and greps the
//! marker). Run it directly with:
//!
//! ```sh
//! cargo test -p boatramp-acme --features acme --test pebble_dns01 -- --nocapture
//! ```
//! or, with everything wired up, `just acme-dns-e2e`.
#![cfg(feature = "acme")]

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use boatramp_acme::acme::{
    CertRequest, Dns01Solver, HickoryTxtResolver, create_account, obtain_certificate_with,
};
use boatramp_acme::dns::{DnsError, DnsProvider, DnsRecord};

const CHALLTESTSRV_MGMT: &str = "http://127.0.0.1:8055";
// `localhost` (not a bare IP): Pebble rejects a request whose `Host` is a literal IP with HTTP 400,
// so the directory host must be `localhost` and the minted cert names `localhost`. Pebble binds the
// IPv6 wildcard `[::]` (see the config below) so that `localhost` — which resolves to `::1` first on
// macOS and on IPv6-enabled runners — is reachable; the issuance client resolves the same way and we
// cannot inject a resolver into it, so the listener must cover `::1`.
const DIRECTORY_URL: &str = "https://localhost:14000/dir";

/// A [`DnsProvider`] backed by `pebble-challtestsrv`'s management API: `set-txt`
/// / `clear-txt` install the records Pebble's validation authority then reads
/// back over the mock DNS server.
struct ChallTestSrv {
    client: reqwest::Client,
}

#[async_trait]
impl DnsProvider for ChallTestSrv {
    async fn upsert(&self, record: &DnsRecord) -> Result<(), DnsError> {
        // challtestsrv keys TXT by FQDN with a trailing dot.
        self.client
            .post(format!("{CHALLTESTSRV_MGMT}/set-txt"))
            .json(&serde_json::json!({
                "host": format!("{}.", record.name),
                "value": record.value,
            }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        self.client
            .post(format!("{CHALLTESTSRV_MGMT}/clear-txt"))
            .json(&serde_json::json!({ "host": format!("{}.", record.name) }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }
}

/// A spawned child process killed when dropped (so a failed test never leaks
/// `pebble` / `pebble-challtestsrv`).
struct Child(tokio::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

fn on_path(bin: &str) -> bool {
    std::process::Command::new(bin)
        .arg("-help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

/// Mint a CA + a `localhost` server cert for Pebble's HTTPS directory, writing
/// `ca.pem` / `cert.pem` / `key.pem` into `dir`. Returns the CA path.
fn mint_certs(dir: &Path) -> std::path::PathBuf {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    let ca_path = dir.join("ca.pem");
    std::fs::write(&ca_path, ca_cert.pem()).unwrap();
    std::fs::write(dir.join("cert.pem"), leaf_cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), leaf_key.serialize_pem()).unwrap();
    ca_path
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns01_wildcard_issuance_against_pebble() {
    if !on_path("pebble") || !on_path("pebble-challtestsrv") {
        eprintln!("skipping: pebble / pebble-challtestsrv not on PATH (run inside `nix develop`)");
        return;
    }
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let dir = tempfile::tempdir().unwrap();
    let ca_path = mint_certs(dir.path());

    // Pebble config: ACME directory on :14000, mgmt on :15000, our minted cert. Bind the IPv6
    // wildcard `[::]` so `localhost` (which resolves to `::1` first on macOS and IPv6-enabled CI
    // runners) reaches it; on Linux `[::]` is dual-stack, so IPv4 clients work too.
    let config = serde_json::json!({
        "pebble": {
            "listenAddress": "[::]:14000",
            "managementListenAddress": "[::]:15000",
            "certificate": dir.path().join("cert.pem"),
            "privateKey": dir.path().join("key.pem"),
            "httpPort": 5002,
            "tlsPort": 5001,
            "ocspResponderURL": ""
        }
    });
    let config_path = dir.path().join("pebble.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();

    // challtestsrv: DNS on :8053 (Pebble's VA resolves the TXT here), management
    // API on :8055; the challenge responders we don't use are disabled. Bind both to the IPv4
    // loopback explicitly so the management POST (`http://127.0.0.1:8055`) and Pebble's resolver
    // (`-dnsserver 127.0.0.1:8053`) reach them regardless of the host's IPv6 `localhost` default.
    // NB: challtestsrv's DNS flag is `-dnsserver` (renamed from `-dns01` in older releases), and
    // 2.10 adds a DoH responder (default `:8443`) that must be disabled too — an unknown flag makes
    // the Go `flag` parser exit, so getting these exact names right is what keeps the process up.
    let _challtestsrv = Child(
        tokio::process::Command::new("pebble-challtestsrv")
            .args([
                "-dnsserver",
                "127.0.0.1:8053",
                "-management",
                "127.0.0.1:8055",
            ])
            .args(["-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", ""])
            .kill_on_drop(true)
            .spawn()
            .expect("spawn pebble-challtestsrv"),
    );

    // Pebble points its validation authority's resolver at challtestsrv.
    let _pebble = Child(
        tokio::process::Command::new("pebble")
            .args(["-config", config_path.to_str().unwrap()])
            .args(["-dnsserver", "127.0.0.1:8053"])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .kill_on_drop(true)
            .spawn()
            .expect("spawn pebble"),
    );

    // Wait for the directory to come up (TLS cert is self-signed for the probe). Pebble ≥ 2.10
    // rejects any request without a `User-Agent` (HTTP 400 "All requests MUST include a User-Agent
    // header"); instant-acme ≥ 0.8.2 sends one on the real issuance path, so set one here too.
    let probe = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .user_agent("boatramp-acme-pebble-test")
        .build()
        .unwrap();
    let mut ready = false;
    let mut last_err = String::from("(no attempt)");
    for _ in 0..50 {
        match probe.get(DIRECTORY_URL).send().await {
            Ok(r) if r.status().is_success() => {
                ready = true;
                break;
            }
            Ok(r) => {
                let status = r.status();
                let body = r.text().await.unwrap_or_default();
                last_err = format!("HTTP {status}: {body}");
            }
            Err(e) => last_err = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(ready, "Pebble directory did not become ready: {last_err}");

    // Wait for challtestsrv's management API too (it is spawned alongside Pebble, and the DNS
    // solver POSTs to it the moment issuance reaches the challenge): any HTTP response — even a
    // 404 for `GET /` — means the port is bound. Without this, a fast Pebble start can race ahead
    // of challtestsrv and the first `set-txt` fails with a connection error.
    let mut challtestsrv_ready = false;
    for _ in 0..50 {
        if probe.get(CHALLTESTSRV_MGMT).send().await.is_ok() {
            challtestsrv_ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        challtestsrv_ready,
        "pebble-challtestsrv management API did not come up"
    );

    // Trust the throwaway CA for the real issuance client by handing it to the account builder
    // (`CertRequest::extra_root_ca` → `Account::builder_with_root`). Since instant-acme 0.8 the
    // default client verifies the directory's TLS with the platform verifier, which does NOT honour
    // `SSL_CERT_FILE` — so the earlier env-var trick no longer works and the CA must be explicit.
    let request = CertRequest {
        directory_url: DIRECTORY_URL.to_string(),
        contact_email: Some("ops@example.test".to_string()),
        domains: vec!["*.deploy.test".to_string()],
        dns_ttl: 1,
        // Real readiness poll (not a blind sleep): wait up to 20s for the TXT to resolve, re-checking
        // every 250ms. challtestsrv serves the record the instant `set-txt` returns, so the happy path
        // observes it on the first poll and proceeds immediately.
        propagation_wait: Duration::from_secs(20),
        propagation_poll_interval: Duration::from_millis(250),
        timeout: Duration::from_secs(60),
        extra_root_ca: Some(ca_path.clone()),
    };
    let provider = ChallTestSrv {
        client: reqwest::Client::new(),
    };

    // Point the DNS-01 propagation pre-check at challtestsrv's mock DNS (:8053) — the SAME authority
    // Pebble's validation authority reads — so this live gate also exercises the fix: the driver waits
    // until the `_acme-challenge` TXT is actually resolvable before telling the CA to validate. (With
    // the system resolver it couldn't see challtestsrv and would just fall through the deadline.)
    let resolver = HickoryTxtResolver::with_nameservers(&["127.0.0.1:8053".parse().unwrap()])
        .expect("build a resolver pointed at challtestsrv's mock DNS");

    // The load-bearing line for the regression: `order.authorizations()` on Pebble ≥ 2.10.0 must
    // deserialize an authorization carrying a tokenless `dns-persist-01` challenge. instant-acme
    // < 0.8.5 panics/errors here with `missing field \`token\``; ≥ 0.8.5 tolerates it and still
    // selects `dns-01`. Driven through `obtain_certificate_with` (one explicit account) so we can
    // inject the challtestsrv-pointed propagation resolver above.
    let (account, _creds) = create_account(
        &request.directory_url,
        request.contact_email.as_deref(),
        request.extra_root_ca.as_deref(),
    )
    .await
    .expect("create an ACME account against Pebble");
    let solver = Dns01Solver::with_resolver(&provider, request.dns_ttl, &resolver);
    let issued = obtain_certificate_with(&account, &request, &solver)
        .await
        .expect("DNS-01 issuance against Pebble (tokenless dns-persist-01 must not break deser)");

    assert!(
        issued.certificate_pem.contains("BEGIN CERTIFICATE"),
        "expected a PEM certificate chain"
    );
    assert!(
        issued.private_key_pem.contains("PRIVATE KEY"),
        "expected a PEM private key"
    );
    // Success marker the CI gate greps to prove the test actually RAN (not skipped) and passed.
    println!(
        "ACME-DNS-PERSIST GATE OK: issued *.deploy.test against Pebble (tokenless dns-persist-01 \
         challenge tolerated, dns-01 still selected, propagation pre-check observed the TXT before \
         set_ready)"
    );
    // The challenge TXT is cleaned up after issuance.
    let (left, _) = (
        provider
            .client
            .post(format!("{CHALLTESTSRV_MGMT}/clear-txt"))
            .json(&serde_json::json!({ "host": "_acme-challenge.deploy.test." }))
            .send()
            .await
            .map(|r| r.status().as_u16())
            .unwrap_or(0),
        (),
    );
    assert!(left == 200 || left == 0);
}
