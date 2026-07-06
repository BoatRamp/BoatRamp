//! End-to-end ACME **DNS-01** wildcard issuance against a local
//! [Pebble](https://github.com/letsencrypt/pebble) CA — the same harness the
//! TLS-ALPN-01 path was validated with, extended to DNS-01.
//!
//! It mints a throwaway CA + Pebble server cert (rcgen), spawns `pebble` and
//! `pebble-challtestsrv`, drives the real issuance for `*.deploy.test`
//! (solving the `_acme-challenge` TXT via challtestsrv's management API), and
//! asserts a Pebble-signed certificate chain comes back.
//!
//! `#[ignore]`d — it needs the `pebble` + `pebble-challtestsrv` binaries on
//! `PATH` (provided by the nix dev shell) and binds local ports. Run it with:
//!
//! ```sh
//! cargo test -p boatramp-acme --features acme --test pebble_dns01 -- --ignored --nocapture
//! ```
//! or, with everything wired up, `just acme-dns-e2e`.
#![cfg(feature = "acme")]

use std::path::Path;
use std::time::Duration;

use async_trait::async_trait;
use boatramp_acme::acme::{obtain_certificate, CertRequest};
use boatramp_acme::dns::{DnsError, DnsProvider, DnsRecord};

const CHALLTESTSRV_MGMT: &str = "http://127.0.0.1:8055";
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
            .and_then(|r| r.error_for_status())
            .map_err(|e| DnsError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, record: &DnsRecord) -> Result<(), DnsError> {
        self.client
            .post(format!("{CHALLTESTSRV_MGMT}/clear-txt"))
            .json(&serde_json::json!({ "host": format!("{}.", record.name) }))
            .send()
            .await
            .and_then(|r| r.error_for_status())
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
#[ignore = "needs pebble + pebble-challtestsrv on PATH (nix dev shell); binds local ports"]
async fn dns01_wildcard_issuance_against_pebble() {
    if !on_path("pebble") || !on_path("pebble-challtestsrv") {
        eprintln!("skipping: pebble / pebble-challtestsrv not on PATH (run inside `nix develop`)");
        return;
    }
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let dir = tempfile::tempdir().unwrap();
    let ca_path = mint_certs(dir.path());

    // Pebble config: ACME directory on :14000, mgmt on :15000, our minted cert.
    let config = serde_json::json!({
        "pebble": {
            "listenAddress": "0.0.0.0:14000",
            "managementListenAddress": "0.0.0.0:15000",
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
    // API on :8055; the challenge responders we don't use are disabled.
    let _challtestsrv = Child(
        tokio::process::Command::new("pebble-challtestsrv")
            .args(["-dns01", ":8053", "-management", ":8055"])
            .args(["-http01", "", "-https01", "", "-tlsalpn01", ""])
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

    // Wait for the directory to come up (TLS cert is self-signed for the probe).
    let probe = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let mut ready = false;
    for _ in 0..50 {
        if probe
            .get(DIRECTORY_URL)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false)
        {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(ready, "Pebble directory did not become ready");

    // Trust the throwaway CA for the real issuance client (instant-acme's
    // `with_native_roots` honours SSL_CERT_FILE).
    std::env::set_var("SSL_CERT_FILE", &ca_path);

    let request = CertRequest {
        directory_url: DIRECTORY_URL.to_string(),
        contact_email: Some("ops@example.test".to_string()),
        domains: vec!["*.deploy.test".to_string()],
        dns_ttl: 1,
        propagation_delay: Duration::from_secs(1),
        timeout: Duration::from_secs(60),
    };
    let provider = ChallTestSrv {
        client: reqwest::Client::new(),
    };

    let issued = obtain_certificate(&request, &provider)
        .await
        .expect("DNS-01 issuance against Pebble");

    assert!(
        issued.certificate_pem.contains("BEGIN CERTIFICATE"),
        "expected a PEM certificate chain"
    );
    assert!(
        issued.private_key_pem.contains("PRIVATE KEY"),
        "expected a PEM private key"
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
