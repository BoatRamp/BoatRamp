//! RFC 7250 **raw-public-key mutual TLS 1.3** primitives.
//!
//! A pin-based TLS trust domain with no CA, no chain, and no name/clock check:
//! the peer's identity *is* its public key, and trust is "is this exact key
//! accepted (and, when dialing, expected for this peer)". This is the transport
//! under boatramp's cluster peer mesh **and** the control-plane bootstrap TLS
//! mode — both need to authenticate a peer on a private network with no public
//! DNS, where ACME/WebPKI cannot help.
//!
//! - [`RpkIdentity`] — a long-lived Ed25519 keypair. **The public key is the
//!   identity**; the private key is a non-loggable, zeroizing type.
//! - [`TrustSet`] — `peer → {public keys (SPKI)}`, the sole authority on who may
//!   speak. Shared + mutable, and the verifiers read it **live**: a join /
//!   rotation / revocation mutates it and every open handle (and every cached
//!   dialer) sees the change on its next handshake — so rotation admits `K_new`
//!   and revocation rejects a reconnecting peer with no cache dance and no deny
//!   cache. A peer holds a **set** of keys so a make-before-break rotation can
//!   trust `K_old` and `K_new` at once.
//! - [`server_config`] / [`client_config`] / [`RpkTls`] — rustls configs
//!   presenting the node's raw public key (RFC 7250) and verifying the peer's
//!   against the trust set, pinned to **TLS 1.3** with the **`X25519MLKEM768`**
//!   PQ-hybrid group required.
//!
//! The verifier's whole decision is "is this exact public key trusted" — never a
//! name or chain check, so there is no `notBefore`/`notAfter` clock hazard in the
//! auth path by construction.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use aws_lc_rs::signature::Ed25519KeyPair;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ResolvesClientCert;
use rustls::crypto::aws_lc_rs as rustls_aws;
use rustls::crypto::{verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms};
use rustls::pki_types::{
    CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    ServerConfig, SignatureScheme,
};
use zeroize::Zeroizing;

/// A logical peer id in the trust set. The cluster mesh uses each node's stable
/// `NodeId`; the control-plane bootstrap listener has a single logical peer.
pub type PeerId = u64;

/// A failure building or loading an RPK identity / TLS config.
#[derive(Debug, thiserror::Error)]
pub enum RpkError {
    /// Generating or parsing the Ed25519 key material failed.
    #[error("rpk identity key: {0}")]
    Key(String),
    /// Reading the identity key file failed.
    #[error("reading rpk key {path}: {source}")]
    ReadKey {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Writing the identity key file failed.
    #[error("writing rpk key {path}: {source}")]
    WriteKey {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Building the rustls config failed.
    #[error(transparent)]
    Rustls(#[from] RustlsError),
    /// Dialing a peer that is not (or no longer) in the trust set.
    #[error("no trusted key for rpk peer {0}")]
    NoTrustedPeer(PeerId),
    /// Building a pinned RPK HTTP client failed.
    #[error("rpk http client: {0}")]
    Client(String),
}

/// A node's RPK identity: a long-lived Ed25519 keypair.
///
/// The private key is held as a **zeroizing** PKCS#8 buffer and this type has a
/// **redacted `Debug`** and no `Display`/`Serialize` — so the key can never leak
/// into logs or serialized state. The public key (SPKI DER) is not secret: it
/// *is* the node's advertised identity.
pub struct RpkIdentity {
    /// PKCS#8 v2 DER of the Ed25519 private key; zeroized on drop, never logged.
    pkcs8: Zeroizing<Vec<u8>>,
    /// The `SubjectPublicKeyInfo` DER of the public key — the identity, and the
    /// exact bytes compared against the trust set on both sides of a handshake.
    spki: Vec<u8>,
}

impl std::fmt::Debug for RpkIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private key; the public SPKI is safe to fingerprint.
        f.debug_struct("RpkIdentity")
            .field("spki_len", &self.spki.len())
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl RpkIdentity {
    /// Generate a fresh Ed25519 identity.
    pub fn generate() -> Result<Self, RpkError> {
        let kp = Ed25519KeyPair::generate().map_err(|e| RpkError::Key(e.to_string()))?;
        let pkcs8 = kp.to_pkcs8().map_err(|e| RpkError::Key(e.to_string()))?;
        Self::from_pkcs8(pkcs8.as_ref().to_vec())
    }

    /// Rebuild an identity from a stored PKCS#8 v2 DER private key. Loading the
    /// key via rustls also yields the `SubjectPublicKeyInfo` DER — the exact bytes
    /// the peer's verifier compares against, so both sides agree by construction.
    pub fn from_pkcs8(pkcs8: Vec<u8>) -> Result<Self, RpkError> {
        let der = PrivatePkcs8KeyDer::from(pkcs8.as_slice());
        let signing_key = rustls_aws::sign::any_eddsa_type(&der)?;
        let spki = signing_key
            .public_key()
            .ok_or_else(|| RpkError::Key("signing key exposed no public key".into()))?
            .as_ref()
            .to_vec();
        Ok(Self {
            pkcs8: Zeroizing::new(pkcs8),
            spki,
        })
    }

    /// Load the identity from `path`, generating + persisting one (`0600`) if the
    /// file does not exist. The key file holds the raw PKCS#8 DER.
    pub fn load_or_generate(path: &Path) -> Result<Self, RpkError> {
        match std::fs::read(path) {
            Ok(bytes) => Self::from_pkcs8(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let identity = Self::generate()?;
                identity.persist(path)?;
                Ok(identity)
            }
            Err(source) => Err(RpkError::ReadKey {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Write the private key to `path` with `0600` permissions (owner-only).
    fn persist(&self, path: &Path) -> Result<(), RpkError> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent).map_err(|source| RpkError::WriteKey {
                path: parent.display().to_string(),
                source,
            })?;
        }
        write_private_file(path, &self.pkcs8).map_err(|source| RpkError::WriteKey {
            path: path.display().to_string(),
            source,
        })
    }

    /// The public key (SPKI DER) — this node's advertised identity.
    pub fn public_key(&self) -> &[u8] {
        &self.spki
    }

    /// The public key as a hex string, for config / logs / pinning.
    pub fn public_key_hex(&self) -> String {
        to_hex(&self.spki)
    }

    /// Sign `msg` with this node's mesh private key (Ed25519), returning the raw
    /// 64-byte signature. This is the node's **possession proof** primitive: a
    /// joiner proves it controls the key it presents (over the join channel) by
    /// signing a challenge — without the private key ever leaving the node. Verify
    /// with [`verify_signature`] against the advertised SPKI public key.
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, RpkError> {
        let kp = Ed25519KeyPair::from_pkcs8(&self.pkcs8).map_err(|e| RpkError::Key(e.to_string()))?;
        Ok(kp.sign(msg).as_ref().to_vec())
    }

    /// The rustls [`CertifiedKey`] that presents this identity's raw public key
    /// (RFC 7250): the "certificate" is the SPKI, signed by the Ed25519 key.
    fn certified_key(&self) -> Result<Arc<CertifiedKey>, RpkError> {
        let der = PrivatePkcs8KeyDer::from(self.pkcs8.as_slice());
        let signing_key = rustls_aws::sign::any_eddsa_type(&der)?;
        let rpk = CertificateDer::from(self.spki.clone());
        Ok(Arc::new(CertifiedKey::new(vec![rpk], signing_key)))
    }
}

/// The trust set: `peer → {public keys (SPKI DER)}`. The sole authority on who
/// may speak. Cheaply cloned (shared `Arc`); joins, rotation, and revocation
/// mutate it live and every open handle — including every cached dialer, whose
/// verifier reads it at handshake time — sees the change. A peer maps to a
/// **set** of keys so a make-before-break rotation can trust `K_old` and `K_new`
/// simultaneously.
#[derive(Clone, Default, Debug)]
pub struct TrustSet(Arc<RwLock<BTreeMap<PeerId, Vec<Vec<u8>>>>>);

impl TrustSet {
    /// A trust set seeded from a single-key `peer → SPKI` map (the genesis seed
    /// from config — one key per peer at bring-up).
    pub fn from_map(map: BTreeMap<PeerId, Vec<u8>>) -> Self {
        let sets = map.into_iter().map(|(id, key)| (id, vec![key])).collect();
        Self(Arc::new(RwLock::new(sets)))
    }

    /// A trust set from a full `peer → {SPKI}` map — the durable snapshot loaded
    /// from persistent state on restart (may hold a mid-rotation two-key peer).
    pub fn from_sets(sets: BTreeMap<PeerId, Vec<Vec<u8>>>) -> Self {
        Self(Arc::new(RwLock::new(sets)))
    }

    /// The public keys currently accepted for `peer` (its whole set — empty if
    /// `peer` is untrusted). A dialer accepts the peer iff it presents one of
    /// these, so mid-rotation both `K_old` and `K_new` connect.
    pub fn accepted(&self, peer: PeerId) -> Vec<Vec<u8>> {
        self.0
            .read()
            .expect("trust set lock")
            .get(&peer)
            .cloned()
            .unwrap_or_default()
    }

    /// The `peer` that presents exactly this public key, if any — the server-side
    /// "is this peer trusted at all" check.
    pub fn peer_for_key(&self, spki: &[u8]) -> Option<PeerId> {
        self.0
            .read()
            .expect("trust set lock")
            .iter()
            .find(|(_, keys)| keys.iter().any(|k| k.as_slice() == spki))
            .map(|(id, _)| *id)
    }

    /// Whether `peer` currently trusts exactly `spki`.
    pub fn contains(&self, peer: PeerId, spki: &[u8]) -> bool {
        self.0
            .read()
            .expect("trust set lock")
            .get(&peer)
            .is_some_and(|keys| keys.iter().any(|k| k.as_slice() == spki))
    }

    /// Add `spki` to `peer`'s accepted set (a join, or the add half of a
    /// rotation). Idempotent; keeps any keys `peer` already has.
    pub fn insert(&self, peer: PeerId, spki: Vec<u8>) {
        let mut guard = self.0.write().expect("trust set lock");
        let keys = guard.entry(peer).or_default();
        if !keys.iter().any(|k| k == &spki) {
            keys.push(spki);
        }
    }

    /// Stop trusting `peer` entirely (revocation).
    pub fn remove(&self, peer: PeerId) {
        self.0.write().expect("trust set lock").remove(&peer);
    }

    /// Drop a single key from `peer`'s set (the retire half of a rotation),
    /// leaving its other keys trusted. Removes the peer if that was its last key.
    pub fn remove_key(&self, peer: PeerId, spki: &[u8]) {
        let mut guard = self.0.write().expect("trust set lock");
        if let Some(keys) = guard.get_mut(&peer) {
            keys.retain(|k| k.as_slice() != spki);
            if keys.is_empty() {
                guard.remove(&peer);
            }
        }
    }

    /// A point-in-time copy of the whole set.
    pub fn snapshot(&self) -> BTreeMap<PeerId, Vec<Vec<u8>>> {
        self.0.read().expect("trust set lock").clone()
    }

    /// Replace the whole set — used to hydrate from durable state on restart,
    /// where the persisted trust set (not config) is authoritative.
    pub fn replace_all(&self, sets: BTreeMap<PeerId, Vec<Vec<u8>>>) {
        *self.0.write().expect("trust set lock") = sets;
    }
}

/// The crypto provider: aws-lc-rs, but with key exchange **restricted to the
/// `X25519MLKEM768` PQ-hybrid group** — so a peer that can't do the hybrid KEX
/// fails the handshake (safe: every peer runs the same boatramp build), closing
/// harvest-now-decrypt-later against a future quantum adversary.
fn rpk_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls_aws::default_provider();
    provider.kx_groups = vec![rustls_aws::kx_group::X25519MLKEM768];
    Arc::new(provider)
}

/// Server-side verifier: accept a connecting peer iff it presents a raw public
/// key that is in the trust set.
#[derive(Debug)]
struct RpkClientVerifier {
    trust: TrustSet,
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for RpkClientVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        // In RPK mode `end_entity` carries the peer's SubjectPublicKeyInfo DER.
        match self.trust.peer_for_key(end_entity.as_ref()) {
            Some(_peer) => Ok(ClientCertVerified::assertion()),
            None => Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// Client-side (dialer) verifier: accept the server iff it presents a key the
/// **live** trust set currently holds for the `peer` being dialed — so a
/// valid-but-wrong peer cannot impersonate another (anti-impersonation), a
/// mid-rotation peer on `K_new` is accepted, and a revoked peer is rejected on
/// the next handshake (the cached dialer re-reads the set, no deny-cache needed).
#[derive(Debug)]
struct RpkServerVerifier {
    trust: TrustSet,
    peer: PeerId,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for RpkServerVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if self.trust.contains(self.peer, end_entity.as_ref()) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::InvalidCertificate(
                CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// The **live** raw public key this node presents (RFC 7250). Held behind a lock
/// and swapped in place on key rotation, so a node begins presenting `K_new` on
/// new handshakes without rebuilding the rustls config — both the server and
/// client cert resolvers read it live. The private key inside is never logged
/// (redacted `Debug`).
#[derive(Clone)]
pub struct PresentedKey(Arc<RwLock<Arc<CertifiedKey>>>);

impl std::fmt::Debug for PresentedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PresentedKey").finish_non_exhaustive()
    }
}

impl PresentedKey {
    /// The key this identity presents (a fixed presentation until rotated).
    fn from_identity(identity: &RpkIdentity) -> Result<Self, RpkError> {
        Ok(Self(Arc::new(RwLock::new(identity.certified_key()?))))
    }

    /// The current presented key.
    fn current(&self) -> Arc<CertifiedKey> {
        self.0.read().expect("presented key lock").clone()
    }

    /// Swap the presented key (the make-before-break step of a rotation).
    fn set(&self, key: Arc<CertifiedKey>) {
        *self.0.write().expect("presented key lock") = key;
    }
}

/// Server-side cert resolver presenting the node's **live** raw public key
/// (RFC 7250). `only_raw_public_keys` keeps rustls in RPK mode.
#[derive(Debug)]
struct RpkServerKeyResolver(PresentedKey);

impl ResolvesServerCert for RpkServerKeyResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.current())
    }
    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

/// Client-side (dialer) cert resolver presenting the node's **live** raw public
/// key — so after a rotation even a cached dialer presents `K_new`.
#[derive(Debug)]
struct RpkClientKeyResolver(PresentedKey);

impl ResolvesClientCert for RpkClientKeyResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.current())
    }
    fn only_raw_public_keys(&self) -> bool {
        true
    }
    fn has_certs(&self) -> bool {
        true
    }
}

/// The rustls **server** config: presents `presented`'s live raw public key and
/// requires client auth against `trust`. TLS 1.3 + PQ-hybrid only.
pub fn server_config(presented: &PresentedKey, trust: TrustSet) -> Result<ServerConfig, RpkError> {
    let provider = rpk_provider();
    let algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(RpkClientVerifier { trust, algs });
    Ok(ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(RpkServerKeyResolver(presented.clone()))))
}

/// The rustls **client** config for dialing `peer`: presents `presented`'s live
/// raw public key and accepts the server iff it presents one of the keys the
/// **live** `trust` set holds for `peer` (so the pinning follows
/// rotation/revocation). TLS 1.3 + PQ-hybrid only.
pub fn client_config(
    presented: &PresentedKey,
    trust: TrustSet,
    peer: PeerId,
) -> Result<ClientConfig, RpkError> {
    let provider = rpk_provider();
    let algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(RpkServerVerifier { trust, peer, algs });
    Ok(ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(RpkClientKeyResolver(presented.clone()))))
}

/// A **server-authenticated** server config: presents `presented`'s raw public
/// key but requires **no client certificate** — for a channel where the client
/// authenticates at a higher layer (e.g. a bearer token), such as the
/// control-plane bootstrap TLS listener. TLS 1.3 + PQ-hybrid only.
pub fn server_config_server_auth(presented: &PresentedKey) -> Result<ServerConfig, RpkError> {
    let provider = rpk_provider();
    Ok(ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(RpkServerKeyResolver(presented.clone()))))
}

/// A **server-authenticated** client config for dialing `peer`: pins the server
/// to one of the keys the live `trust` set holds for `peer`, and presents **no
/// client certificate**. The pairing dialer for [`server_config_server_auth`].
/// TLS 1.3 + PQ-hybrid only.
pub fn client_config_server_auth(trust: TrustSet, peer: PeerId) -> Result<ClientConfig, RpkError> {
    let provider = rpk_provider();
    let algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(RpkServerVerifier { trust, peer, algs });
    Ok(ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// A dialer verifier that **accepts any** presented raw public key and records
/// its SPKI into a shared slot — **trust-on-first-use, no pinning**. Only for the
/// one-shot fetch of a root-signed attestation in the `--root-pubkey` bootstrap,
/// after which the caller verifies the fetched attestation (root signature) names
/// the recorded key. Never use for real traffic — it authenticates nothing.
#[derive(Debug)]
struct CapturingServerVerifier {
    captured: Arc<Mutex<Option<Vec<u8>>>>,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for CapturingServerVerifier {
    fn requires_raw_public_keys(&self) -> bool {
        true
    }

    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Record the presented SPKI DER, accept unconditionally (TOFU).
        *self.captured.lock().expect("capture slot") = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.algs,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algs.supported_schemes()
    }
}

/// A client config that accepts **any** presented raw public key (TOFU) and
/// records its SPKI into `captured` — for the one-shot attestation fetch of the
/// `--root-pubkey` bootstrap. It provides **no** server authentication on its
/// own: the caller MUST verify the fetched attestation (root signature) names the
/// captured key before trusting anything. Presents no client cert. TLS 1.3 + PQ.
pub fn client_config_capturing(
    captured: Arc<Mutex<Option<Vec<u8>>>>,
) -> Result<ClientConfig, RpkError> {
    let provider = rpk_provider();
    let algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(CapturingServerVerifier { captured, algs });
    Ok(ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// A node's RPK TLS context: its own identity (swappable on rotation), the live
/// key it presents, and the shared live trust set. Hands out the server config
/// and per-peer client configs, all reading the live presented key + trust set —
/// so a make-before-break rotation ([`set_identity`](Self::set_identity)) takes
/// effect on new handshakes with no config rebuild.
#[derive(Debug)]
pub struct RpkTls {
    identity: RwLock<Arc<RpkIdentity>>,
    presented: PresentedKey,
    key_file: Option<PathBuf>,
    trust: TrustSet,
}

impl RpkTls {
    /// Bundle an identity with the trust set it authenticates peers against.
    pub fn new(identity: Arc<RpkIdentity>, trust: TrustSet) -> Self {
        Self::build(identity, trust, None)
    }

    /// Like [`new`](Self::new), but remembers where to persist a rotated key
    /// (`0600`) so a restart loads the current key.
    pub fn with_key_file(identity: Arc<RpkIdentity>, trust: TrustSet, key_file: PathBuf) -> Self {
        Self::build(identity, trust, Some(key_file))
    }

    fn build(identity: Arc<RpkIdentity>, trust: TrustSet, key_file: Option<PathBuf>) -> Self {
        // A validated identity always yields a certified key (`from_pkcs8`
        // already parsed the same material), so this is an invariant.
        let presented =
            PresentedKey::from_identity(&identity).expect("rpk identity certified key");
        Self {
            identity: RwLock::new(identity),
            presented,
            key_file,
            trust,
        }
    }

    /// The live trust set (mutated by joins / rotation / revocation).
    pub fn trust(&self) -> &TrustSet {
        &self.trust
    }

    /// This node's current public key (SPKI) — changes across a rotation.
    pub fn public_key(&self) -> Vec<u8> {
        self.identity
            .read()
            .expect("rpk identity lock")
            .public_key()
            .to_vec()
    }

    /// This node's current public key as hex (for config / logs / pinning).
    pub fn public_key_hex(&self) -> String {
        self.identity
            .read()
            .expect("rpk identity lock")
            .public_key_hex()
    }

    /// The rustls config for this node's listener (mutual auth).
    pub fn server(&self) -> Result<ServerConfig, RpkError> {
        server_config(&self.presented, self.trust.clone())
    }

    /// A **server-authenticated** listener config that presents this node's key
    /// without requiring a client certificate — for the control-plane bootstrap
    /// TLS mode, where the client authenticates with a bearer token.
    pub fn server_auth(&self) -> Result<ServerConfig, RpkError> {
        server_config_server_auth(&self.presented)
    }

    /// The rustls config for dialing `peer`, verifying against the live keys the
    /// trust set holds for it. Errs if `peer` is not currently trusted (a client
    /// built while `peer` has keys keeps working across a later rotation, since
    /// its verifier re-reads the live set).
    pub fn client_for(&self, peer: PeerId) -> Result<ClientConfig, RpkError> {
        if self.trust.accepted(peer).is_empty() {
            return Err(RpkError::NoTrustedPeer(peer));
        }
        client_config(&self.presented, self.trust.clone(), peer)
    }

    /// Swap the identity this node presents — the make-before-break step of a
    /// rotation. New handshakes (server and dialer) present `new`'s key;
    /// already-established connections keep their session. Persists `new` to the
    /// key file (`0600`) if one is configured, so a restart loads it. Returns the
    /// **previous** identity, whose key the caller retires from the trust set once
    /// this swap has propagated.
    pub fn set_identity(&self, new: Arc<RpkIdentity>) -> Result<Arc<RpkIdentity>, RpkError> {
        let certified = new.certified_key()?;
        // Persist before swapping so a crash mid-rotation leaves the durable key
        // equal to (or behind) what we present — both are trusted in the window.
        if let Some(path) = &self.key_file {
            new.persist(path)?;
        }
        self.presented.set(certified);
        let mut guard = self.identity.write().expect("rpk identity lock");
        Ok(std::mem::replace(&mut *guard, new))
    }
}

/// Parse a hex-encoded public key (SPKI DER) from config into its bytes.
pub fn parse_public_key(hex: &str) -> Result<Vec<u8>, RpkError> {
    from_hex(hex).ok_or_else(|| RpkError::Key(format!("invalid rpk pubkey hex {hex:?}")))
}

/// Verify an Ed25519 `signature` over `msg` against a mesh public key in **SPKI
/// DER** form (`spki`, as [`RpkIdentity::public_key`] advertises it). The peer side
/// of [`RpkIdentity::sign`] — used to check a joiner's possession proof against the
/// key it presents. Returns `true` iff the signature is valid.
///
/// An Ed25519 SPKI is the canonical 44-byte structure (a 12-byte algorithm prefix +
/// the 32-byte raw key); a non-conforming `spki` or a bad signature yields `false`.
pub fn verify_signature(spki: &[u8], msg: &[u8], signature: &[u8]) -> bool {
    // Ed25519 SPKI DER is exactly 44 bytes; the raw public key is the last 32.
    if spki.len() != 44 {
        return false;
    }
    let raw = &spki[12..44];
    use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
    UnparsedPublicKey::new(&ED25519, raw)
        .verify(msg, signature)
        .is_ok()
}

/// Lower-case hex of `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode an even-length hex string; `None` on any non-hex or odd length.
fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Create `dir` (recursively) with `0700` permissions on unix.
fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write `bytes` to `path` with `0600` permissions on unix (owner read/write).
fn write_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    /// Drive a real localhost mutual-TLS handshake between a server identity and a
    /// dialing client identity: the server authenticates the client against
    /// `server_trust`, the client verifies the server against `client_trust` for
    /// the `peer` id it is dialing. Returns whether the handshake (and a
    /// round-trip byte) succeeded.
    async fn handshake(
        server: &RpkIdentity,
        client: &RpkIdentity,
        server_trust: TrustSet,
        client_trust: TrustSet,
        peer: PeerId,
    ) -> bool {
        let server_pk = PresentedKey::from_identity(server).unwrap();
        let client_pk = PresentedKey::from_identity(client).unwrap();
        let acceptor =
            TlsAcceptor::from(Arc::new(server_config(&server_pk, server_trust).unwrap()));
        let connector = TlsConnector::from(Arc::new(
            client_config(&client_pk, client_trust, peer).unwrap(),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let mut buf = [0u8; 4];
                    tls.read_exact(&mut buf).await.ok();
                    tls.write_all(b"pong").await.ok();
                    tls.flush().await.ok();
                    true
                }
                Err(_) => false,
            }
        });

        let name = ServerName::try_from("rpk").unwrap();
        let client_ok = async {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let mut tls = connector.connect(name, tcp).await.map_err(|_| ())?;
            tls.write_all(b"ping").await.map_err(|_| ())?;
            tls.flush().await.map_err(|_| ())?;
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.map_err(|_| ())?;
            Ok::<_, ()>(&buf == b"pong")
        }
        .await
        .unwrap_or(false);

        let server_ok = server_task.await.unwrap_or(false);
        client_ok && server_ok
    }

    /// A one-way (server-authenticated) handshake: the server presents its key
    /// with no client-cert requirement; the client pins the server for `peer` and
    /// sends no client cert. Returns whether the handshake + round-trip succeeded.
    async fn handshake_server_auth(server: &RpkIdentity, client_trust: TrustSet, peer: PeerId) -> bool {
        let server_pk = PresentedKey::from_identity(server).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config_server_auth(&server_pk).unwrap()));
        let connector = TlsConnector::from(Arc::new(
            client_config_server_auth(client_trust, peer).unwrap(),
        ));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let mut buf = [0u8; 4];
                    tls.read_exact(&mut buf).await.ok();
                    tls.write_all(b"pong").await.ok();
                    tls.flush().await.ok();
                    true
                }
                Err(_) => false,
            }
        });
        let name = ServerName::try_from("rpk").unwrap();
        let client_ok = async {
            let tcp = TcpStream::connect(addr).await.unwrap();
            let mut tls = connector.connect(name, tcp).await.map_err(|_| ())?;
            tls.write_all(b"ping").await.map_err(|_| ())?;
            tls.flush().await.map_err(|_| ())?;
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.map_err(|_| ())?;
            Ok::<_, ()>(&buf == b"pong")
        }
        .await
        .unwrap_or(false);
        server_task.await.unwrap_or(false) && client_ok
    }

    #[tokio::test]
    async fn capturing_client_records_the_presented_key() {
        let server = RpkIdentity::generate().unwrap();
        let server_spki = server.public_key().to_vec();
        let captured = Arc::new(Mutex::new(None));

        let server_pk = PresentedKey::from_identity(&server).unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config_server_auth(&server_pk).unwrap()));
        let connector =
            TlsConnector::from(Arc::new(client_config_capturing(captured.clone()).unwrap()));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let _ = acceptor.accept(tcp).await;
        });
        let name = ServerName::try_from("rpk").unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        connector.connect(name, tcp).await.expect("TOFU accepts any key");
        let _ = server_task.await;

        // The capturing verifier recorded exactly the server's presented SPKI, so
        // the caller can now verify the attestation names it.
        assert_eq!(captured.lock().unwrap().as_deref(), Some(server_spki.as_slice()));
    }

    #[tokio::test]
    async fn server_auth_pins_server_without_client_cert() {
        let server = RpkIdentity::generate().unwrap();
        let stranger = RpkIdentity::generate().unwrap();
        // The client pins the server's key for peer 1 → connects, no client cert.
        let trust = TrustSet::from_map(BTreeMap::from([(1, server.public_key().to_vec())]));
        assert!(
            handshake_server_auth(&server, trust, 1).await,
            "a pinned server must be accepted by a client presenting no cert"
        );
        // The client pins the WRONG key for peer 1 → server rejected.
        let wrong = TrustSet::from_map(BTreeMap::from([(1, stranger.public_key().to_vec())]));
        assert!(
            !handshake_server_auth(&server, wrong, 1).await,
            "a wrong pinned server key must be rejected"
        );
    }

    #[test]
    fn load_or_generate_persists_and_reloads_owner_only() {
        let dir = std::env::temp_dir().join(format!("rpktls-load-{}", std::process::id()));
        let path = dir.join("controlplane-tls.key");
        let _ = std::fs::remove_dir_all(&dir);

        // First call generates + persists; the second returns the SAME key.
        let a = RpkIdentity::load_or_generate(&path).unwrap();
        let b = RpkIdentity::load_or_generate(&path).unwrap();
        assert_eq!(a.public_key(), b.public_key());

        // The key file is owner-only (`0600`) on unix — it holds a private key.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "key file must be owner read/write only");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn identity_roundtrips_and_never_logs_the_key() {
        let id = RpkIdentity::generate().unwrap();
        // The public key is stable across a save/load of the private key.
        let reloaded = RpkIdentity::from_pkcs8(id.pkcs8.to_vec()).unwrap();
        assert_eq!(id.public_key(), reloaded.public_key());
        assert!(!id.public_key().is_empty());
        // Debug never reveals the private key.
        let dbg = format!("{id:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains(&hex(id.pkcs8.as_slice())));
    }

    #[test]
    fn possession_proof_signs_and_verifies_against_the_advertised_key() {
        let id = RpkIdentity::generate().unwrap();
        let msg = b"join-possession-challenge:jti=abc:pubkey=...:iat=123";
        let sig = id.sign(msg).unwrap();
        // The advertised SPKI key verifies the node's own signature.
        assert!(verify_signature(id.public_key(), msg, &sig));
        // A different key does not (an attacker can't prove possession of it).
        let other = RpkIdentity::generate().unwrap();
        assert!(!verify_signature(other.public_key(), msg, &sig));
        // A tampered message / signature is rejected.
        assert!(!verify_signature(id.public_key(), b"different", &sig));
        let mut bad = sig.clone();
        bad[0] ^= 0xff;
        assert!(!verify_signature(id.public_key(), msg, &bad));
        // A non-conforming SPKI (wrong length) is rejected, not panicked.
        assert!(!verify_signature(&[0u8; 10], msg, &sig));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[tokio::test]
    async fn trusted_peers_handshake_untrusted_rejected() {
        let server = RpkIdentity::generate().unwrap();
        let client = RpkIdentity::generate().unwrap();
        let stranger = RpkIdentity::generate().unwrap();

        // Trust set: both the server (1) and the legitimate client (2).
        let trust = TrustSet::from_map(BTreeMap::from([
            (1, server.public_key().to_vec()),
            (2, client.public_key().to_vec()),
        ]));

        // Trusted client + the server key the trust set holds for peer 1 → success.
        assert!(
            handshake(&server, &client, trust.clone(), trust.clone(), 1).await,
            "a trusted client dialing peer 1 with its trusted key must connect"
        );

        // A client whose key is NOT in the trust set → server rejects it.
        assert!(
            !handshake(&server, &stranger, trust.clone(), trust.clone(), 1).await,
            "an untrusted client key must be rejected"
        );

        // A trusted client whose trust set holds the WRONG key for peer 1 → the
        // client rejects the server (anti-impersonation).
        let wrong = TrustSet::from_map(BTreeMap::from([(1, stranger.public_key().to_vec())]));
        assert!(
            !handshake(&server, &client, trust.clone(), wrong, 1).await,
            "a wrong expected server key must be rejected"
        );
    }

    /// A make-before-break rotation window: while peer 1's set holds both its old
    /// and new key, a dialer accepts the server on *either* — so the switch never
    /// opens a rejection window. Once the old key is retired, it is rejected.
    #[tokio::test]
    async fn rotation_window_accepts_both_keys_then_retires_the_old() {
        let old = RpkIdentity::generate().unwrap();
        let new = RpkIdentity::generate().unwrap();
        let client = RpkIdentity::generate().unwrap();

        // Server trusts the dialer (2); the dialer's set for peer 1 holds K_old.
        let server_trust = TrustSet::from_map(BTreeMap::from([(2, client.public_key().to_vec())]));
        let client_trust = TrustSet::from_map(BTreeMap::from([(1, old.public_key().to_vec())]));

        // Mid-rotation: add K_new to peer 1's set (both now trusted).
        client_trust.insert(1, new.public_key().to_vec());
        assert!(
            handshake(&old, &client, server_trust.clone(), client_trust.clone(), 1).await,
            "the old key must still connect during the rotation window"
        );
        assert!(
            handshake(&new, &client, server_trust.clone(), client_trust.clone(), 1).await,
            "the new key must connect during the rotation window"
        );

        // Retire K_old: only K_new remains trusted for peer 1.
        client_trust.remove_key(1, old.public_key());
        assert!(
            !handshake(&old, &client, server_trust.clone(), client_trust.clone(), 1).await,
            "the retired old key must be rejected after rotation completes"
        );
        assert!(
            handshake(&new, &client, server_trust, client_trust, 1).await,
            "the new key remains trusted after rotation completes"
        );
    }
}
