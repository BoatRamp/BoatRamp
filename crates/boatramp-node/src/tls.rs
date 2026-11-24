//! The static-identity TLS listener config assembly (PLAN-node-library N4, "cluster + TLS
//! assembly" — the TLS slice).
//!
//! The `boatramp serve` binary's `--tls custom` / `--tls rpk` listeners and the ACME extra-CA
//! trust path used to inline their rustls `ServerConfig`/`ClientConfig` construction in
//! `serve.rs`, where no in-process test could exercise the exact config the bound listener
//! presents. This module is the extraction target: the binary keeps every runtime / IO concern
//! — reading the operator's cert/key files, loading-or-generating the persisted RPK identity,
//! minting the bootstrap attestation, spawning the ACME renewal poller, and the `serve_tls`
//! loop itself — and calls these helpers to BUILD the config. Lifting the build here makes the
//! security-relevant assembly decisions (the ALPN sets, no-client-auth, the RPK channel-bound
//! server mode, the extra-CA trust anchor, the PEM parse + empty-chain / no-key errors)
//! unit-testable without binding a listener.
//!
//! **Behaviour-preserving (a pure move).** Each function is the exact config build the binary
//! ran, and its errors Display identically — the binary absorbs them through
//! [`Error`](crate::error::Error) → `serve::Error::Assembly`. No trust decision changed: the
//! cert/key pair, the client-auth posture, and the ALPN advertisement are assembled byte-for-byte
//! as before.
//!
//! **Runtime-agnostic.** No `tokio::spawn`, no async — pure synchronous config assembly the
//! caller drives (the ACME state stream + renewal loop stay in the binary, which owns the
//! runtime). The file reads are the same synchronous `std::fs::read` the binary used.

use std::path::Path;
use std::sync::Arc;

use crate::error::{Error, Result};

/// Install a process-wide default rustls crypto provider (rustls 0.23 requires
/// one before building any TLS config). Idempotent.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Load a PEM cert chain + private key as DER — for the rustls `ServerConfig`
/// built by the custom-cert listener and (when enabled) the HTTP/3 (quinn) one.
pub fn load_cert_chain_and_key(
    cert: &Path,
    key: &Path,
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let cert_pem = std::fs::read(cert)?;
    let key_pem = std::fs::read(key)?;
    load_cert_chain_and_key_from_pem(&cert_pem, &key_pem)
}

/// Parse an already-read PEM cert chain + private key as DER (cap-req #29: a listener's static cert
/// is read into memory first, since it is OPTIONAL and composed with the node-managed resolver, so
/// the static fallback path parses the bytes rather than re-reading the files).
pub fn load_cert_chain_and_key_from_pem(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let certs =
        rustls_pemfile::certs(&mut &cert_pem[..]).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(Error::NoCert("<listener tls: empty PEM cert chain>".into()));
    }
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| Error::NoPrivateKey("<listener tls: no PEM private key>".into()))?;
    Ok((certs, key))
}

/// Build the `--tls custom` listener config (operator-supplied static cert): server-authenticated,
/// no client auth, advertising the serving ALPN (`h2` / `http/1.1`).
pub fn custom_server_config(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = boatramp_server::alpn_h1_h2();
    Ok(config)
}

/// Build the HTTP/3 (QUIC) variant of the custom-cert listener config from the SAME static cert:
/// QUIC mandates exactly the `h3` ALPN on its listener (no `http/1.1`/`h2`).
pub fn custom_h3_server_config(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig> {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(config)
}

/// Build the `--tls rpk` bootstrap listener config (RFC 7250 raw-public-key TLS): present the
/// node's RPK `identity`, advertising the serving ALPN (`h2` / `http/1.1`).
///
/// When `require_channel_bound` (the posture's `require_channel_bound_tokens`), the listener
/// *requests* a client raw-public-key cert so a client can present its token's holder (`cnf`) key
/// as the TLS client identity — accept-any-client, because the acceptable `cnf` keys are unknown
/// until the bearer is read, so the handshake accepts any possession-proven client key and the real
/// check is the app-layer binding. Off (the default), the listener is server-authenticated only (the
/// client authenticates with a bearer token and no client cert). There is no client-auth trust set
/// either way (an empty [`TrustSet`](boatramp_rpktls::TrustSet)) — the trust decision is unchanged
/// from the inlined binary build.
pub fn rpk_server_config(
    identity: Arc<boatramp_rpktls::RpkIdentity>,
    require_channel_bound: bool,
) -> Result<rustls::ServerConfig> {
    let rpk = boatramp_rpktls::RpkTls::new(identity, boatramp_rpktls::TrustSet::default());
    let mut config = if require_channel_bound {
        rpk.server_accept_any_client()?
    } else {
        rpk.server_auth()?
    };
    config.alpn_protocols = boatramp_server::alpn_h1_h2();
    Ok(config)
}

/// Build a rustls client config that trusts an extra root CA (for a test ACME
/// server like Pebble whose directory uses a self-signed certificate).
pub fn acme_client_config(ca_path: &Path) -> Result<Arc<rustls::ClientConfig>> {
    let pem = std::fs::read(ca_path)?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut &pem[..]) {
        roots.add(cert?)?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Build the `--tls acme` (ACME TLS-ALPN-01) listener config off an ACME `resolver`: no client
/// auth, advertising the serving ALPN (`h2` / `http/1.1`) **plus `acme-tls/1`**. The resolver
/// (e.g. `rustls_acme::AcmeState::resolver()`) detects a TLS-ALPN-01 challenge `ClientHello` and
/// serves the challenge cert; `serve_tls` recognizes the negotiated `acme-tls/1`, completes then
/// drops that handshake, and serves everything else as HTTP — one config, no separate acceptor.
///
/// The caller owns the ACME runtime: it builds the `AcmeConfig`/state (and its cache + directory +
/// optional extra-CA via [`acme_client_config`]) and spawns the renewal-event poller over the
/// state stream. This lifts only the pure rustls config build — the `acme-tls/1` ALPN
/// advertisement — crossing the crate boundary as an `Arc<dyn ResolvesServerCert>`, so no
/// `rustls-acme` dependency (nor its `AcmeState` generics) is pulled into the library.
pub fn acme_alpn_server_config(
    resolver: Arc<dyn rustls::server::ResolvesServerCert>,
) -> rustls::ServerConfig {
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    config.alpn_protocols = boatramp_server::alpn_h1_h2();
    config.alpn_protocols.push(b"acme-tls/1".to_vec());
    config
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway self-signed cert/key, as PEM + as parsed DER — mirroring the server/bin TLS
    /// tests (`rcgen::generate_simple_self_signed`).
    fn self_signed() -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        (cert.cert.pem(), cert.key_pair.serialize_pem())
    }

    #[test]
    fn install_crypto_provider_is_idempotent() {
        // Callable more than once without panicking (every serve_* path calls it at entry).
        install_crypto_provider();
        install_crypto_provider();
    }

    #[test]
    fn load_cert_chain_rejects_an_empty_pem_chain() {
        let (_cert, key_pem) = self_signed();
        let err = load_cert_chain_and_key_from_pem(b"", key_pem.as_bytes()).unwrap_err();
        assert!(matches!(err, Error::NoCert(_)));
        // Byte-identical operator message (absorbed transparently by serve::Error::Assembly).
        assert_eq!(
            err.to_string(),
            "no certificates in <listener tls: empty PEM cert chain>"
        );
    }

    #[test]
    fn load_cert_chain_rejects_a_missing_private_key() {
        let (cert_pem, _key) = self_signed();
        let err = load_cert_chain_and_key_from_pem(cert_pem.as_bytes(), b"").unwrap_err();
        assert!(matches!(err, Error::NoPrivateKey(_)));
        assert_eq!(
            err.to_string(),
            "no private key in <listener tls: no PEM private key>"
        );
    }

    #[test]
    fn load_cert_chain_parses_a_valid_pem_pair() {
        let (cert_pem, key_pem) = self_signed();
        let (certs, _key) =
            load_cert_chain_and_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn custom_server_config_advertises_h1_h2_without_client_auth() {
        install_crypto_provider();
        let (cert_pem, key_pem) = self_signed();
        let (certs, key) =
            load_cert_chain_and_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
        let config = custom_server_config(certs, key).unwrap();
        // The exact serving ALPN set, and server-authenticated (no client-cert verifier offered).
        assert_eq!(config.alpn_protocols, boatramp_server::alpn_h1_h2());
    }

    #[test]
    fn custom_h3_server_config_advertises_only_h3() {
        install_crypto_provider();
        let (cert_pem, key_pem) = self_signed();
        let (certs, key) =
            load_cert_chain_and_key_from_pem(cert_pem.as_bytes(), key_pem.as_bytes()).unwrap();
        let config = custom_h3_server_config(certs, key).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"h3".to_vec()]);
    }

    #[test]
    fn rpk_server_config_advertises_h1_h2_in_both_channel_bound_modes() {
        install_crypto_provider();
        let identity = Arc::new(boatramp_rpktls::RpkIdentity::generate().unwrap());

        // Server-authenticated (the default, channel binding off).
        let server_only = rpk_server_config(identity.clone(), false).unwrap();
        assert_eq!(server_only.alpn_protocols, boatramp_server::alpn_h1_h2());

        // Channel-bound: accept-any client-cert mode — still advertises the same serving ALPN.
        let channel_bound = rpk_server_config(identity, true).unwrap();
        assert_eq!(channel_bound.alpn_protocols, boatramp_server::alpn_h1_h2());
    }

    #[test]
    fn acme_client_config_trusts_a_supplied_ca_and_rejects_a_bad_pem() {
        install_crypto_provider();
        // A real self-signed cert PEM is a valid trust anchor.
        let (ca_pem, _key) = self_signed();
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, ca_pem).unwrap();
        assert!(acme_client_config(&ca).is_ok());

        // A missing file fails closed (I/O error), never silently trusts nothing.
        let missing = dir.path().join("nope.pem");
        assert!(acme_client_config(&missing).is_err());
    }

    /// A no-op cert resolver standing in for the ACME state's resolver.
    #[derive(Debug)]
    struct NoResolver;
    impl rustls::server::ResolvesServerCert for NoResolver {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }

    #[test]
    fn acme_alpn_server_config_advertises_h1_h2_then_acme_tls_1() {
        install_crypto_provider();
        let config = acme_alpn_server_config(Arc::new(NoResolver));
        // Exactly the serving ALPN plus the TLS-ALPN-01 challenge protocol, in that order.
        let mut expected = boatramp_server::alpn_h1_h2();
        expected.push(b"acme-tls/1".to_vec());
        assert_eq!(config.alpn_protocols, expected);
    }
}
