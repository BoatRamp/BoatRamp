//! Cluster mesh identity & RFC 7250 raw-public-key mutual TLS.
//!
//! The Raft peer mesh must authenticate every peer: a `WriteOp` is an arbitrary
//! control-plane KV write, so an unauthenticated mesh port is total compromise
//! (the audit's top finding). Mesh nodes run on private networks with no public
//! DNS, so ACME/WebPKI can't authenticate them — the mesh needs its own trust
//! domain. See `docs/SECURITY-mesh-identity.md`.
//!
//! This module is the crypto core, independent of the transport wiring:
//! - [`MeshIdentity`] — a node's long-lived Ed25519 keypair. **The public key is
//!   the identity**; the private key is a non-loggable, zeroizing type.
//! - [`TrustSet`] — `node_id → {public keys (SPKI)}`, the sole authority on who
//!   may speak on the mesh. Shared + mutable, and the verifiers read it **live**:
//!   a join/rotation/revocation mutates it and every open handle (and every
//!   cached dialer) sees the change on its next handshake — so rotation admits
//!   `K_new` and revocation rejects a reconnecting peer with no cache dance and
//!   no separate deny-cache. A node holds a **set** of keys (not one) so a
//!   make-before-break rotation can trust `K_old` and `K_new` at once.
//! - [`server_config`] / [`client_config`] — rustls configs presenting the node's
//!   raw public key (RFC 7250) and verifying the peer's against the trust set,
//!   pinned to **TLS 1.3** with the **`X25519MLKEM768`** PQ-hybrid group required.
//!
//! The verifier's whole decision is "is this exact public key trusted (and, when
//! dialing, expected for this peer)" — never a name or chain check, so there is
//! no `notBefore`/`notAfter` clock hazard in the auth path by construction.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

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

use crate::raft::NodeId;

/// A failure building or loading a mesh identity / TLS config.
#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    /// Generating or parsing the Ed25519 key material failed.
    #[error("mesh identity key: {0}")]
    Key(String),
    /// Reading the identity key file failed.
    #[error("reading mesh key {path}: {source}")]
    ReadKey {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Writing the identity key file failed.
    #[error("writing mesh key {path}: {source}")]
    WriteKey {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// Building the rustls config failed.
    #[error(transparent)]
    Rustls(#[from] RustlsError),
    /// Dialing a peer that is not (or no longer) in the trust set.
    #[error("no trusted key for mesh peer {0}")]
    NoTrustedPeer(NodeId),
    /// Building the pinned mesh HTTP client failed.
    #[error("mesh http client: {0}")]
    Client(String),
}

/// A node's mesh identity: a long-lived Ed25519 keypair.
///
/// The private key is held as a **zeroizing** PKCS#8 buffer and this type has a
/// **redacted `Debug`** and no `Display`/`Serialize` — so the key can never leak
/// into logs or serialized state. The public key (SPKI DER) is
/// not secret: it *is* the node's advertised identity.
pub struct MeshIdentity {
    /// PKCS#8 v2 DER of the Ed25519 private key; zeroized on drop, never logged.
    pkcs8: Zeroizing<Vec<u8>>,
    /// The `SubjectPublicKeyInfo` DER of the public key — the identity, and the
    /// exact bytes compared against the trust set on both sides of a handshake.
    spki: Vec<u8>,
}

impl std::fmt::Debug for MeshIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private key; the public SPKI is safe to fingerprint.
        f.debug_struct("MeshIdentity")
            .field("spki_len", &self.spki.len())
            .field("private_key", &"<redacted>")
            .finish()
    }
}

impl MeshIdentity {
    /// Generate a fresh Ed25519 mesh identity.
    pub fn generate() -> Result<Self, MeshError> {
        let kp = Ed25519KeyPair::generate().map_err(|e| MeshError::Key(e.to_string()))?;
        let pkcs8 = kp.to_pkcs8().map_err(|e| MeshError::Key(e.to_string()))?;
        Self::from_pkcs8(pkcs8.as_ref().to_vec())
    }

    /// Rebuild an identity from a stored PKCS#8 v2 DER private key. Loading the
    /// key via rustls also yields the `SubjectPublicKeyInfo` DER — the exact bytes
    /// the peer's verifier compares against, so both sides agree by construction.
    pub fn from_pkcs8(pkcs8: Vec<u8>) -> Result<Self, MeshError> {
        let der = PrivatePkcs8KeyDer::from(pkcs8.as_slice());
        let signing_key = rustls_aws::sign::any_eddsa_type(&der)?;
        let spki = signing_key
            .public_key()
            .ok_or_else(|| MeshError::Key("signing key exposed no public key".into()))?
            .as_ref()
            .to_vec();
        Ok(Self {
            pkcs8: Zeroizing::new(pkcs8),
            spki,
        })
    }

    /// Load the identity from `path`, generating + persisting one (`0600`) if the
    /// file does not exist. The key file holds the raw PKCS#8 DER.
    pub fn load_or_generate(path: &Path) -> Result<Self, MeshError> {
        match std::fs::read(path) {
            Ok(bytes) => Self::from_pkcs8(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let identity = Self::generate()?;
                identity.persist(path)?;
                Ok(identity)
            }
            Err(source) => Err(MeshError::ReadKey {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// Write the private key to `path` with `0600` permissions (owner-only).
    fn persist(&self, path: &Path) -> Result<(), MeshError> {
        if let Some(parent) = path.parent() {
            create_private_dir(parent).map_err(|source| MeshError::WriteKey {
                path: parent.display().to_string(),
                source,
            })?;
        }
        write_private_file(path, &self.pkcs8).map_err(|source| MeshError::WriteKey {
            path: path.display().to_string(),
            source,
        })
    }

    /// The public key (SPKI DER) — this node's advertised mesh identity.
    pub fn public_key(&self) -> &[u8] {
        &self.spki
    }

    /// The public key as a hex string, for `[cluster.peers].pubkey` in config.
    pub fn public_key_hex(&self) -> String {
        to_hex(&self.spki)
    }

    /// The rustls [`CertifiedKey`] that presents this identity's raw public key
    /// (RFC 7250): the "certificate" is the SPKI, signed by the Ed25519 key.
    fn certified_key(&self) -> Result<Arc<CertifiedKey>, MeshError> {
        let der = PrivatePkcs8KeyDer::from(self.pkcs8.as_slice());
        let signing_key = rustls_aws::sign::any_eddsa_type(&der)?;
        let rpk = CertificateDer::from(self.spki.clone());
        Ok(Arc::new(CertifiedKey::new(vec![rpk], signing_key)))
    }
}

/// The mesh trust set: `node_id → {public keys (SPKI DER)}`. The sole authority
/// on who may speak on the mesh. Cheaply cloned (shared `Arc`); joins, rotation,
/// and revocation mutate it live and every open handle — including every cached
/// dialer, whose verifier reads it at handshake time — sees the change. A node
/// maps to a **set** of keys so a make-before-break rotation can trust `K_old`
/// and `K_new` simultaneously.
#[derive(Clone, Default, Debug)]
pub struct TrustSet(Arc<RwLock<BTreeMap<NodeId, Vec<Vec<u8>>>>>);

impl TrustSet {
    /// A trust set seeded from a single-key `node_id → SPKI` map (the genesis
    /// seed from config — one key per node at bring-up).
    pub fn from_map(map: BTreeMap<NodeId, Vec<u8>>) -> Self {
        let sets = map.into_iter().map(|(id, key)| (id, vec![key])).collect();
        Self(Arc::new(RwLock::new(sets)))
    }

    /// A trust set from a full `node_id → {SPKI}` map — the durable snapshot
    /// loaded from the persistent Raft state on restart (may hold a mid-rotation
    /// two-key node).
    pub fn from_sets(sets: BTreeMap<NodeId, Vec<Vec<u8>>>) -> Self {
        Self(Arc::new(RwLock::new(sets)))
    }

    /// The public keys currently accepted for `node` (its whole set — empty if
    /// `node` is untrusted). A dialer accepts the peer iff it presents one of
    /// these, so mid-rotation both `K_old` and `K_new` connect.
    pub fn accepted(&self, node: NodeId) -> Vec<Vec<u8>> {
        self.0
            .read()
            .expect("trust set lock")
            .get(&node)
            .cloned()
            .unwrap_or_default()
    }

    /// The `node_id` that presents exactly this public key, if any — the
    /// server-side "is this peer trusted at all" check.
    pub fn node_for_key(&self, spki: &[u8]) -> Option<NodeId> {
        self.0
            .read()
            .expect("trust set lock")
            .iter()
            .find(|(_, keys)| keys.iter().any(|k| k.as_slice() == spki))
            .map(|(id, _)| *id)
    }

    /// Whether `node` currently trusts exactly `spki`.
    pub fn contains(&self, node: NodeId, spki: &[u8]) -> bool {
        self.0
            .read()
            .expect("trust set lock")
            .get(&node)
            .is_some_and(|keys| keys.iter().any(|k| k.as_slice() == spki))
    }

    /// Add `spki` to `node`'s accepted set (a join, or the add half of a
    /// rotation). Idempotent; keeps any keys `node` already has.
    pub fn insert(&self, node: NodeId, spki: Vec<u8>) {
        let mut guard = self.0.write().expect("trust set lock");
        let keys = guard.entry(node).or_default();
        if !keys.iter().any(|k| k == &spki) {
            keys.push(spki);
        }
    }

    /// Stop trusting `node` entirely (revocation).
    pub fn remove(&self, node: NodeId) {
        self.0.write().expect("trust set lock").remove(&node);
    }

    /// Drop a single key from `node`'s set (the retire half of a rotation),
    /// leaving its other keys trusted. Removes the node if that was its last key.
    pub fn remove_key(&self, node: NodeId, spki: &[u8]) {
        let mut guard = self.0.write().expect("trust set lock");
        if let Some(keys) = guard.get_mut(&node) {
            keys.retain(|k| k.as_slice() != spki);
            if keys.is_empty() {
                guard.remove(&node);
            }
        }
    }

    /// A point-in-time copy of the whole set.
    pub fn snapshot(&self) -> BTreeMap<NodeId, Vec<Vec<u8>>> {
        self.0.read().expect("trust set lock").clone()
    }

    /// Replace the whole set — used to hydrate from durable Raft state on
    /// restart, where the persisted trust set (not config) is authoritative.
    pub fn replace_all(&self, sets: BTreeMap<NodeId, Vec<Vec<u8>>>) {
        *self.0.write().expect("trust set lock") = sets;
    }
}

/// The replicated-KV prefix under which the durable trust set lives: each
/// accepted key is one entry — `mesh/trust/{node_id}/{pubkey_hex}` with an empty
/// value — so a join / rotation / revocation is an atomic single-key `Put`/
/// `Delete` that the apply observer mirrors into every node's live [`TrustSet`],
/// and a restart rehydrates the set by listing this prefix. Re-exported here; the
/// canonical definition lives with the apply layer that writes it ([`crate::raft`]).
pub use crate::raft::TRUST_PREFIX;

/// The durable KV key that trusts `spki` for `node` (delegates to the canonical
/// key format in [`crate::raft`], shared with [`crate::raft::WriteOp::MeshAdmit`]).
pub fn trust_key(node: NodeId, spki: &[u8]) -> String {
    crate::raft::trust_key_hex(node, &to_hex(spki))
}

/// Parse a `mesh/trust/{node}/{hex}` key back into `(node_id, spki)`; `None` if
/// `key` is not a well-formed trust entry.
pub fn parse_trust_key(key: &str) -> Option<(NodeId, Vec<u8>)> {
    let rest = key.strip_prefix(TRUST_PREFIX)?;
    let (node, hex) = rest.split_once('/')?;
    Some((node.parse().ok()?, from_hex(hex)?))
}

/// Rebuild a `node_id → {SPKI}` map from the durable trust keys under
/// [`TRUST_PREFIX`] (the restart-hydration and snapshot-catch-up path).
pub fn trust_from_keys<'a>(
    keys: impl IntoIterator<Item = &'a str>,
) -> BTreeMap<NodeId, Vec<Vec<u8>>> {
    let mut sets: BTreeMap<NodeId, Vec<Vec<u8>>> = BTreeMap::new();
    for key in keys {
        if let Some((node, spki)) = parse_trust_key(key) {
            sets.entry(node).or_default().push(spki);
        }
    }
    sets
}

/// The crypto provider for the mesh: aws-lc-rs, but with key exchange **restricted
/// to the `X25519MLKEM768` PQ-hybrid group** — so a peer that can't do the hybrid
/// KEX fails the handshake (safe: every mesh node runs the same boatramp build),
/// closing harvest-now-decrypt-later against a future quantum adversary.
fn mesh_provider() -> Arc<rustls::crypto::CryptoProvider> {
    let mut provider = rustls_aws::default_provider();
    provider.kx_groups = vec![rustls_aws::kx_group::X25519MLKEM768];
    Arc::new(provider)
}

/// Server-side verifier: accept a connecting peer iff it presents a raw public
/// key that is in the trust set.
#[derive(Debug)]
struct MeshClientVerifier {
    trust: TrustSet,
    algs: WebPkiSupportedAlgorithms,
}

impl ClientCertVerifier for MeshClientVerifier {
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
        match self.trust.node_for_key(end_entity.as_ref()) {
            Some(_node) => Ok(ClientCertVerified::assertion()),
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
/// **live** trust set currently holds for the `node_id` being dialed — so a
/// valid-but-wrong peer cannot impersonate another (anti-impersonation), a
/// mid-rotation peer on `K_new` is accepted, and a revoked peer is rejected on
/// the next handshake (the cached dialer re-reads the set, no deny-cache needed).
#[derive(Debug)]
struct MeshServerVerifier {
    trust: TrustSet,
    peer: NodeId,
    algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for MeshServerVerifier {
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
    fn from_identity(identity: &MeshIdentity) -> Result<Self, MeshError> {
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
struct MeshServerKeyResolver(PresentedKey);

impl ResolvesServerCert for MeshServerKeyResolver {
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
struct MeshClientKeyResolver(PresentedKey);

impl ResolvesClientCert for MeshClientKeyResolver {
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

/// The rustls **server** config for the mesh listener: presents `presented`'s
/// live raw public key and requires client auth against `trust`. TLS 1.3 +
/// PQ-hybrid only.
pub fn server_config(presented: &PresentedKey, trust: TrustSet) -> Result<ServerConfig, MeshError> {
    let provider = mesh_provider();
    let algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(MeshClientVerifier { trust, algs });
    Ok(ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(verifier)
        .with_cert_resolver(Arc::new(MeshServerKeyResolver(presented.clone()))))
}

/// The rustls **client** config for dialing `peer`: presents `presented`'s live
/// raw public key and accepts the server iff it presents one of the keys the
/// **live** `trust` set holds for `peer` (so the pinning follows
/// rotation/revocation). TLS 1.3 + PQ-hybrid only.
pub fn client_config(
    presented: &PresentedKey,
    trust: TrustSet,
    peer: NodeId,
) -> Result<ClientConfig, MeshError> {
    let provider = mesh_provider();
    let algs = provider.signature_verification_algorithms;
    let verifier = Arc::new(MeshServerVerifier { trust, peer, algs });
    Ok(ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(MeshClientKeyResolver(presented.clone()))))
}

/// A node's mesh TLS context: its own identity (swappable on rotation), the live
/// key it presents, and the shared live trust set. Hands out the server config
/// and per-peer client configs, all reading the live presented key + trust set —
/// so a make-before-break rotation ([`set_identity`](Self::set_identity)) takes
/// effect on new handshakes with no config rebuild.
#[derive(Debug)]
pub struct MeshTls {
    identity: RwLock<Arc<MeshIdentity>>,
    presented: PresentedKey,
    key_file: Option<PathBuf>,
    trust: TrustSet,
}

impl MeshTls {
    /// Bundle an identity with the trust set it authenticates peers against.
    pub fn new(identity: Arc<MeshIdentity>, trust: TrustSet) -> Self {
        Self::build(identity, trust, None)
    }

    /// Like [`new`](Self::new), but remembers where to persist a rotated key
    /// (`0600`) so a restart loads the current key.
    pub fn with_key_file(identity: Arc<MeshIdentity>, trust: TrustSet, key_file: PathBuf) -> Self {
        Self::build(identity, trust, Some(key_file))
    }

    fn build(identity: Arc<MeshIdentity>, trust: TrustSet, key_file: Option<PathBuf>) -> Self {
        // A validated identity always yields a certified key (`from_pkcs8`
        // already parsed the same material), so this is an invariant.
        let presented =
            PresentedKey::from_identity(&identity).expect("mesh identity certified key");
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

    /// This node's current mesh public key (SPKI) — changes across a rotation.
    pub fn public_key(&self) -> Vec<u8> {
        self.identity
            .read()
            .expect("mesh identity lock")
            .public_key()
            .to_vec()
    }

    /// This node's current mesh public key as hex (for config / logs).
    pub fn public_key_hex(&self) -> String {
        self.identity
            .read()
            .expect("mesh identity lock")
            .public_key_hex()
    }

    /// The rustls config for this node's mesh listener.
    pub fn server(&self) -> Result<ServerConfig, MeshError> {
        server_config(&self.presented, self.trust.clone())
    }

    /// The rustls config for dialing `peer`, verifying against the live keys the
    /// trust set holds for it. Errs if `peer` is not currently trusted (a client
    /// built while `peer` has keys keeps working across a later rotation, since
    /// its verifier re-reads the live set).
    pub fn client_for(&self, peer: NodeId) -> Result<ClientConfig, MeshError> {
        if self.trust.accepted(peer).is_empty() {
            return Err(MeshError::NoTrustedPeer(peer));
        }
        client_config(&self.presented, self.trust.clone(), peer)
    }

    /// Swap the identity this node presents — the make-before-break step of a
    /// rotation. New handshakes (server and dialer) present
    /// `new`'s key; already-established connections keep their session. Persists
    /// `new` to the key file (`0600`) if one is configured, so a restart loads
    /// it. Returns the **previous** identity, whose key the caller retires from
    /// the trust set once this swap has propagated.
    pub fn set_identity(&self, new: Arc<MeshIdentity>) -> Result<Arc<MeshIdentity>, MeshError> {
        let certified = new.certified_key()?;
        // Persist before swapping so a crash mid-rotation leaves the durable key
        // equal to (or behind) what we present — both are trusted in the window.
        if let Some(path) = &self.key_file {
            new.persist(path)?;
        }
        self.presented.set(certified);
        let mut guard = self.identity.write().expect("mesh identity lock");
        Ok(std::mem::replace(&mut *guard, new))
    }
}

/// Per-peer pinned `reqwest` clients, cached: dialing a peer uses a client that
/// will only complete a handshake with **that peer's** trusted key (each client
/// carries its own connection pool + pinned TLS config).
#[derive(Debug)]
pub struct MeshClients {
    mesh: Arc<MeshTls>,
    cache: std::sync::Mutex<BTreeMap<NodeId, reqwest::Client>>,
}

impl MeshClients {
    /// A client factory over `mesh`.
    pub fn new(mesh: Arc<MeshTls>) -> Self {
        Self {
            mesh,
            cache: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    /// A `reqwest` client pinned to `peer`'s trusted key (cached across calls).
    pub fn client(&self, peer: NodeId) -> Result<reqwest::Client, MeshError> {
        if let Some(client) = self.cache.lock().expect("mesh client cache").get(&peer) {
            return Ok(client.clone());
        }
        let config = self.mesh.client_for(peer)?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .build()
            .map_err(|e| MeshError::Client(e.to_string()))?;
        self.cache
            .lock()
            .expect("mesh client cache")
            .insert(peer, client.clone());
        Ok(client)
    }
}

/// Parse a hex-encoded mesh public key (SPKI DER) from config into its bytes.
pub fn parse_public_key(hex: &str) -> Result<Vec<u8>, MeshError> {
    from_hex(hex).ok_or_else(|| MeshError::Key(format!("invalid mesh pubkey hex {hex:?}")))
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
        server: &MeshIdentity,
        client: &MeshIdentity,
        server_trust: TrustSet,
        client_trust: TrustSet,
        peer: NodeId,
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

        let name = ServerName::try_from("mesh").unwrap();
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

    #[test]
    fn identity_roundtrips_and_never_logs_the_key() {
        let id = MeshIdentity::generate().unwrap();
        // The public key is stable across a save/load of the private key.
        let reloaded = MeshIdentity::from_pkcs8(id.pkcs8.to_vec()).unwrap();
        assert_eq!(id.public_key(), reloaded.public_key());
        assert!(!id.public_key().is_empty());
        // Debug never reveals the private key.
        let dbg = format!("{id:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains(&hex(id.pkcs8.as_slice())));
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[tokio::test]
    async fn trusted_peers_handshake_untrusted_rejected() {
        let server = MeshIdentity::generate().unwrap();
        let client = MeshIdentity::generate().unwrap();
        let stranger = MeshIdentity::generate().unwrap();

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
        let old = MeshIdentity::generate().unwrap();
        let new = MeshIdentity::generate().unwrap();
        let client = MeshIdentity::generate().unwrap();

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
