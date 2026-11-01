//! The privsep **signer-key unlock** protocol: a `token.signer` instance asks a `secrets.sealer`
//! instance to unseal its sealed signing key over the feature-link, under a ROOT-WIRED, per-link
//! ALLOWLIST the sealer enforces fail-closed (privsep Phase 1 — signer-unlock workstream; design
//! `PLAN-privsep-phase1.md` §1.2, §3, and the "Signer-key unlock — OWNER DECISION"). **SECURITY-
//! CRITICAL — a compromised signer must NOT be able to unseal arbitrary credentials.**
//!
//! The owner decision: the token/auth-signer key becomes a sealed `[secrets]` credential (a
//! `boatramp:<name>` reference, or a `path:<file>` KEK-sealed key blob), unlocked by the `[secrets]`
//! KEK. Under `[privsep]` the signer must NOT hold the KEK (that would collapse the
//! `secrets.sealer` ↔ `token.signer` split), so the **signer instance asks the sealer instance to
//! unseal its key over the feature-link**, and the root stays secret-blind (it wires the socketpair
//! + the allowlist NAMES, never a key or KEK).
//!
//! ## The containment: a root-wired per-link allowlist
//!
//! The CRUX (design §3.4 — the authority-API grammar is the real surface, not the transport): a
//! frontend/signer RCE *is* the authorized caller on the link, so the link's PEER IDENTITY attests
//! only *which instance* is calling — it is NOT the authorization. The **root alone knows the
//! composition topology**, so at spawn it tells the sealer, FOR EACH link to another instance,
//! exactly which sealed-cred name(s) that peer may unseal (derived from the composition — a signer
//! link may unseal ONLY the configured signer key ref). The sealer ENFORCES this allowlist: an
//! unseal request for a name not on that link's allowlist is REFUSED — fail-closed, logged, no bytes
//! returned. So a compromised signer on link `to-signer` can ask only for the single key its link
//! permits; it can never ask the sealer for a sibling's credential.
//!
//! This is a NARROW, TYPED grammar ([`UnsealRequest`] / [`UnsealResponse`]) over the existing
//! bounded [`LinkEndpoint::send_frame`] / [`LinkEndpoint::recv_frame`] byte frames — NOT a general
//! RPC, and NOT the WS-E verifiable-end-principal grammar (that is a separate later workstream; the
//! clean seam is [`SealedKeyResolver`] + the per-link allowlist, which a context-bearing grammar
//! layers on). The only operation the envelope admits is "unseal THIS allowlisted name" returning a
//! RESULT — there is no variant that hands back a KEK.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

#[cfg(unix)]
use crate::privsep_link::LinkEndpoint;

/// The env var the root sets on a `secrets.sealer` instance carrying the per-link unseal allowlist
/// (design: the root wires the allowlist NAMES, never a key). The value is a JSON
/// [`UnsealAllowlist`] — link name → the set of sealed-cred names that link's peer may unseal. It is
/// NON-SECRET (names only), so it passes the spawn-env allowlist (`BOATRAMP_*`) like
/// `BOATRAMP_PRIVSEP_FDS`. An absent var ⇒ an EMPTY allowlist: the sealer unseals NOTHING for any
/// peer (fail-closed — a sealer the root wired no allowlist to serves no unseal requests).
pub const PRIVSEP_UNSEAL_ALLOW_ENV: &str = "BOATRAMP_PRIVSEP_UNSEAL_ALLOW";

/// The ROOT-WIRED unseal allowlist: for each feature-link to the sealer, the EXACT set of sealed-cred
/// names the peer on that link may ask the sealer to unseal. The root derives this from the
/// composition (secret-blind — names only) and hands it to the `secrets.sealer` instance; the sealer
/// enforces it fail-closed. A link ABSENT from the map (or present with an empty set) permits NO
/// unseal — the default is deny.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsealAllowlist {
    /// link name → the sealed-cred names that link's peer is permitted to unseal.
    pub by_link: BTreeMap<String, BTreeSet<String>>,
}

impl UnsealAllowlist {
    /// An empty allowlist (deny all).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Permit `key_ref` to be unsealed over the link named `link`.
    pub fn allow(&mut self, link: impl Into<String>, key_ref: impl Into<String>) {
        self.by_link
            .entry(link.into())
            .or_default()
            .insert(key_ref.into());
    }

    /// The set of names permitted on `link` (empty if the link is unknown / permits nothing).
    #[must_use]
    pub fn for_link(&self, link: &str) -> BTreeSet<String> {
        self.by_link.get(link).cloned().unwrap_or_default()
    }

    /// Whether `key_ref` is permitted on `link` — the fail-closed authorization decision. A link
    /// the root wired no entry for, or a name not in that link's set, is DENIED.
    #[must_use]
    pub fn permits(&self, link: &str, key_ref: &str) -> bool {
        self.by_link
            .get(link)
            .is_some_and(|names| names.contains(key_ref))
    }

    /// Whether this allowlist permits ANY unseal (so a sealer with an empty allowlist does not stand
    /// up an unseal server at all).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_link.values().all(BTreeSet::is_empty)
    }

    /// Serialize for the [`PRIVSEP_UNSEAL_ALLOW_ENV`] value (JSON; names only, never a secret).
    #[must_use]
    pub fn to_env_value(&self) -> String {
        serde_json::to_string(self).expect("the unseal allowlist is always serializable")
    }

    /// Parse the allowlist from the process environment (an absent var ⇒ an empty, deny-all map).
    pub fn from_env() -> Result<Self, String> {
        match std::env::var(PRIVSEP_UNSEAL_ALLOW_ENV) {
            Ok(v) => serde_json::from_str(&v)
                .map_err(|e| format!("parsing {PRIVSEP_UNSEAL_ALLOW_ENV}: {e}")),
            Err(std::env::VarError::NotPresent) => Ok(Self::default()),
            Err(e) => Err(format!("reading {PRIVSEP_UNSEAL_ALLOW_ENV}: {e}")),
        }
    }
}

/// A `token.signer` → `secrets.sealer` unseal request (the ONLY operation the grammar admits): unseal
/// THIS sealed-cred name. Bounded + typed so "give me the KEK" is UNREPRESENTABLE (design §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsealRequest {
    /// The sealed-cred reference to unseal (`boatramp:<name>` or `path:<file>`). The sealer refuses
    /// it unless the ROOT-WIRED allowlist for THIS link permits it (fail-closed).
    pub key_ref: String,
}

/// The sealer's reply. On success it carries the PLAINTEXT key bytes (the one thing that crosses —
/// the signer never holds the KEK); on a refusal or a resolution failure it carries NO bytes, only a
/// reason (design: "refused — fail-closed, logged, no bytes returned").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnsealResponse {
    /// The allowlisted name was unsealed — the plaintext key bytes (`"<alg>:<hex>"` for a signer
    /// key). The ONLY variant that returns bytes.
    Unsealed {
        /// The unsealed plaintext key.
        key: Vec<u8>,
    },
    /// The requested name is NOT on this link's root-wired allowlist — refused before any crypto
    /// (the containment). No bytes.
    Refused {
        /// A non-secret reason for the log (never echoes key material).
        reason: String,
    },
    /// The name was allowlisted but resolution failed (missing secret, bad KEK, I/O). No bytes.
    Failed {
        /// A non-secret reason for the log.
        reason: String,
    },
}

/// A signer-side failure obtaining its sealed key over the link.
#[derive(Debug, thiserror::Error)]
pub enum UnsealError {
    /// The link transport failed (EOF, framing, oversize).
    #[error("privsep unseal link: {0}")]
    Link(String),
    /// Serializing the request / deserializing the response failed.
    #[error("privsep unseal codec: {0}")]
    Codec(String),
    /// The sealer REFUSED the request (the name was not on this link's allowlist).
    #[error("privsep unseal refused by the sealer: {0}")]
    Refused(String),
    /// The sealer accepted the name but could not resolve it.
    #[error("privsep unseal failed at the sealer: {0}")]
    Failed(String),
}

/// The pluggable sealed-key RESOLVER the sealer uses to turn an allowlisted `key_ref` into plaintext
/// via the existing `[secrets]` KEK path. Kept a trait so the fail-closed ALLOWLIST enforcement (the
/// security crux) is unit-testable against a trivial in-memory resolver, independent of the KEK /
/// KV backend. Concrete resolvers: [`EnvelopeSealedFileResolver`] (a `path:<file>` KEK-sealed blob)
/// and [`SecretStoreResolver`] (a `boatramp:<name>` sealed-store credential).
///
/// A resolver is reached ONLY after the allowlist has already permitted `key_ref`, so it never has
/// to re-authorize — but it still fail-closes on a missing / malformed secret (no partial return).
#[async_trait::async_trait]
pub trait SealedKeyResolver: Send + Sync {
    /// Resolve `key_ref` to the plaintext key bytes, or an error (never partial). The returned
    /// bytes are held zeroizing by the caller.
    async fn resolve(&self, key_ref: &str) -> Result<Zeroizing<Vec<u8>>, String>;
}

/// Serve unseal requests from ONE peer over `link`, enforcing `allowed` (the ROOT-WIRED set of names
/// this link's peer may unseal) FAIL-CLOSED. The security crux:
///
/// 1. receive a bounded, typed [`UnsealRequest`];
/// 2. if `key_ref` is NOT in `allowed` → reply [`UnsealResponse::Refused`] (no bytes), LOG, continue
///    (a compromised signer cannot reach a name its link does not permit);
/// 3. else resolve via `resolver` and reply [`UnsealResponse::Unsealed`] (or [`UnsealResponse::Failed`]
///    on a resolution error — still no bytes).
///
/// Loops until the peer closes the link (EOF) — the signer sends one request at boot, then holds the
/// link; a clean EOF is the normal end. Async (the resolver + KEK path are async); the caller drives
/// it on the instance's runtime (the blocking link I/O is fine on a dedicated serve task). `link_name`
/// is for the log only.
#[cfg(unix)]
pub async fn serve_unseal(
    link_name: &str,
    link: &LinkEndpoint,
    allowed: &BTreeSet<String>,
    resolver: &dyn SealedKeyResolver,
) -> Result<(), String> {
    loop {
        // Receive one bounded, typed request (fail-closed on oversize / framing, in `recv_frame`).
        let frame = match link.recv_frame() {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                tracing::debug!(link = %link_name, "[privsep] unseal: peer closed the link (EOF)");
                return Ok(());
            }
            Err(e) => return Err(format!("recv on link {link_name:?}: {e}")),
        };
        let req: UnsealRequest = match serde_json::from_slice(&frame) {
            Ok(r) => r,
            Err(e) => {
                // A malformed request is a protocol fault — refuse + keep serving (fail-closed).
                tracing::warn!(link = %link_name, error = %e, "[privsep] unseal: malformed request — refusing");
                send_response(
                    link,
                    &UnsealResponse::Refused {
                        reason: "malformed unseal request".to_string(),
                    },
                )?;
                continue;
            }
        };

        // THE CONTAINMENT: a name not on THIS link's root-wired allowlist is refused BEFORE any
        // crypto — no bytes, logged. A compromised signer cannot reach a sibling's credential.
        if !allowed.contains(&req.key_ref) {
            tracing::warn!(
                link = %link_name,
                requested = %req.key_ref,
                allowed = ?allowed,
                "[privsep] unseal REFUSED: requested name not on this link's allowlist (fail-closed)"
            );
            send_response(
                link,
                &UnsealResponse::Refused {
                    reason: format!(
                        "name {:?} is not permitted on link {link_name:?}",
                        req.key_ref
                    ),
                },
            )?;
            continue;
        }

        // Allowlisted — resolve via the existing `[secrets]` KEK path. Fail-closed on any error.
        match resolver.resolve(&req.key_ref).await {
            Ok(plaintext) => {
                tracing::info!(
                    link = %link_name,
                    name = %req.key_ref,
                    "[privsep] unseal: allowlisted name unsealed, returning the plaintext key"
                );
                let resp = UnsealResponse::Unsealed {
                    key: plaintext.to_vec(),
                };
                let r = send_response(link, &resp);
                // Zeroize the transient response copy's key bytes regardless of the send result.
                if let UnsealResponse::Unsealed { key } = resp {
                    let mut key = key;
                    zeroize::Zeroize::zeroize(&mut key);
                }
                r?;
            }
            Err(e) => {
                tracing::warn!(link = %link_name, name = %req.key_ref, error = %e, "[privsep] unseal: resolution failed (fail-closed, no bytes)");
                send_response(
                    link,
                    &UnsealResponse::Failed {
                        reason: "the sealer could not resolve the requested name".to_string(),
                    },
                )?;
            }
        }
    }
}

/// Serialize + send one [`UnsealResponse`] frame. The serialized buffer is held zeroizing (an
/// `Unsealed` response carries the plaintext key) so the transient copy is wiped after the send.
#[cfg(unix)]
fn send_response(link: &LinkEndpoint, resp: &UnsealResponse) -> Result<(), String> {
    let bytes = Zeroizing::new(
        serde_json::to_vec(resp).map_err(|e| format!("encoding unseal response: {e}"))?,
    );
    link.send_frame(&bytes)
        .map_err(|e| format!("sending unseal response: {e}"))
}

/// The SIGNER-side client: ask the sealer over `link` to unseal `key_ref`, returning the plaintext
/// key (held zeroizing) or an error. Blocking (one request/response at boot) — the signer instance
/// calls this before building its [`boatramp_core::cose::LocalSigner`]. Fail-closed: a refusal or a
/// failure is an error, never a partial/empty key.
#[cfg(unix)]
pub fn request_unseal(link: &LinkEndpoint, key_ref: &str) -> Result<Zeroizing<Vec<u8>>, UnsealError> {
    let req = UnsealRequest {
        key_ref: key_ref.to_string(),
    };
    let bytes = serde_json::to_vec(&req).map_err(|e| UnsealError::Codec(e.to_string()))?;
    link.send_frame(&bytes)
        .map_err(|e| UnsealError::Link(e.to_string()))?;
    // The reply frame carries the plaintext key (for `Unsealed`) — hold it zeroizing so the
    // transient wire copy is wiped once parsed.
    let reply = Zeroizing::new(
        link.recv_frame()
            .map_err(|e| UnsealError::Link(e.to_string()))?,
    );
    let resp: UnsealResponse =
        serde_json::from_slice(&reply).map_err(|e| UnsealError::Codec(e.to_string()))?;
    match resp {
        UnsealResponse::Unsealed { key } => Ok(Zeroizing::new(key)),
        UnsealResponse::Refused { reason } => Err(UnsealError::Refused(reason)),
        UnsealResponse::Failed { reason } => Err(UnsealError::Failed(reason)),
    }
}

// =============================================================================
// Concrete resolvers — the existing `[secrets]` KEK path
// =============================================================================

use std::sync::Arc;

use boatramp_core::envelope::KeyEnvelope;

/// Resolve a `path:<file>` sealed signer key: read the KEK-SEALED blob FILE (granted READ-ONLY to the
/// sealer) and `unwrap` it with the `[secrets]` KEK envelope — the existing `[secrets]` KEK path,
/// encrypted at rest (strictly better than a plaintext key file). The sealer owns the file in its FS
/// grant; the signer never has it on disk. The `path:` prefix is stripped by the caller (the resolver
/// is given the bare file path).
pub struct EnvelopeSealedFileResolver {
    /// The `[secrets]` KEK envelope (the sealer holds the KEK — `secrets.sealer`).
    envelope: Arc<dyn KeyEnvelope>,
}

impl EnvelopeSealedFileResolver {
    /// Build from the sealer's `[secrets]` KEK envelope.
    #[must_use]
    pub fn new(envelope: Arc<dyn KeyEnvelope>) -> Self {
        Self { envelope }
    }
}

#[async_trait::async_trait]
impl SealedKeyResolver for EnvelopeSealedFileResolver {
    async fn resolve(&self, key_ref: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let path = key_ref
            .strip_prefix("path:")
            .filter(|p| !p.is_empty())
            .ok_or_else(|| format!("not a path: sealed-file reference: {key_ref:?}"))?;
        // Read the sealed blob (behind the sealer's Landlock grant). Hold it zeroizing.
        let sealed = Zeroizing::new(
            std::fs::read(path).map_err(|e| format!("reading sealed signer key {path:?}: {e}"))?,
        );
        let plaintext = self
            .envelope
            .unwrap(&sealed)
            .await
            .map_err(|e| format!("unsealing signer key with the [secrets] KEK: {e}"))?;
        Ok(Zeroizing::new(plaintext))
    }
}

/// Resolve a `boatramp:<name>` sealed-store signer key: unseal it from the project-scoped
/// [`SecretStore`](boatramp_core::secret_store::SecretStore) under the reserved default project, via
/// the `[secrets]` KEK envelope — the SAME path the node's S3/blob sealed credentials use
/// (`resolve_s3_credential`). The sealer builds the [`SecretStore`] from its control-plane KV (held
/// when it co-resides `backend.kv`) + its `[secrets]` envelope.
pub struct SecretStoreResolver {
    store: boatramp_core::secret_store::SecretStore,
}

impl SecretStoreResolver {
    /// Build from the sealer's control-plane KV + its `[secrets]` KEK envelope.
    #[must_use]
    pub fn new(
        kv: Arc<dyn boatramp_core::kv::KvStore>,
        envelope: Arc<dyn KeyEnvelope>,
    ) -> Self {
        Self {
            store: boatramp_core::secret_store::SecretStore::new(kv, envelope),
        }
    }
}

#[async_trait::async_trait]
impl SealedKeyResolver for SecretStoreResolver {
    async fn resolve(&self, key_ref: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        let name = key_ref
            .strip_prefix("boatramp:")
            .filter(|n| !n.is_empty())
            .ok_or_else(|| format!("not a boatramp: sealed-store reference: {key_ref:?}"))?;
        match self
            .store
            .get(boatramp_core::project::ProjectRef::DEFAULT, name)
            .await
        {
            Ok(Some(bytes)) => Ok(Zeroizing::new(bytes)),
            Ok(None) => Err(format!("sealed signer key boatramp:{name} is not in the store")),
            Err(e) => Err(format!("sealed store get boatramp:{name}: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- allowlist (the security crux), backend-agnostic ----

    /// A trivial in-memory resolver: `key_ref` → plaintext bytes. Lets the ALLOWLIST enforcement be
    /// tested with no KEK / KV backend (the authorization decision is what must be airtight).
    struct MapResolver(BTreeMap<String, Vec<u8>>);

    #[async_trait::async_trait]
    impl SealedKeyResolver for MapResolver {
        async fn resolve(&self, key_ref: &str) -> Result<Zeroizing<Vec<u8>>, String> {
            self.0
                .get(key_ref)
                .map(|b| Zeroizing::new(b.clone()))
                .ok_or_else(|| format!("no such key {key_ref:?}"))
        }
    }

    #[test]
    fn allowlist_permits_only_the_exact_wired_names_per_link() {
        let mut allow = UnsealAllowlist::new();
        allow.allow("to-signer", "boatramp:auth-root");
        allow.allow("to-other", "boatramp:other-key");

        // Exactly the wired (link, name) pairs are permitted.
        assert!(allow.permits("to-signer", "boatramp:auth-root"));
        assert!(allow.permits("to-other", "boatramp:other-key"));
        // A name on the WRONG link is denied (the per-link scoping is the containment).
        assert!(!allow.permits("to-signer", "boatramp:other-key"));
        assert!(!allow.permits("to-other", "boatramp:auth-root"));
        // An unknown link, or an unknown name, is denied (default deny).
        assert!(!allow.permits("to-nowhere", "boatramp:auth-root"));
        assert!(!allow.permits("to-signer", "boatramp:not-wired"));
        assert!(!allow.is_empty());
        assert!(UnsealAllowlist::new().is_empty());
    }

    #[test]
    fn allowlist_round_trips_through_the_env_value() {
        let mut allow = UnsealAllowlist::new();
        allow.allow("to-signer", "boatramp:auth-root");
        let v = allow.to_env_value();
        let back: UnsealAllowlist = serde_json::from_str(&v).unwrap();
        assert_eq!(back, allow);
    }

    // ---- end-to-end over a real socketpair (unix) ----

    #[cfg(unix)]
    mod unix {
        use super::*;

        fn rt() -> tokio::runtime::Runtime {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("build a current-thread runtime")
        }

        fn resolver() -> MapResolver {
            let mut m = BTreeMap::new();
            m.insert("boatramp:auth-root".to_string(), b"es256:deadbeef".to_vec());
            m.insert("boatramp:siblings-key".to_string(), b"es256:cafe".to_vec());
            MapResolver(m)
        }

        /// An allowlisted name succeeds end-to-end: the signer gets the exact plaintext.
        #[test]
        fn allowlisted_name_is_unsealed_end_to_end() {
            let (sealer_end, signer_end) = LinkEndpoint::socketpair().unwrap();
            let mut allow = BTreeSet::new();
            allow.insert("boatramp:auth-root".to_string());

            // The sealer serves on a dedicated thread; the signer is the client.
            let sealer = std::thread::spawn(move || {
                rt().block_on(async {
                    serve_unseal("to-signer", &sealer_end, &allow, &resolver()).await
                })
            });
            let key = request_unseal(&signer_end, "boatramp:auth-root").expect("unseal succeeds");
            assert_eq!(&key[..], b"es256:deadbeef");
            drop(signer_end); // EOF → the sealer loop returns Ok
            sealer.join().unwrap().expect("sealer serve ends cleanly on EOF");
        }

        /// A NON-allowlisted name is refused fail-closed: no bytes, and the sealer keeps serving.
        #[test]
        fn non_allowlisted_name_is_refused_no_bytes() {
            let (sealer_end, signer_end) = LinkEndpoint::socketpair().unwrap();
            let mut allow = BTreeSet::new();
            allow.insert("boatramp:auth-root".to_string());
            let sealer = std::thread::spawn(move || {
                rt().block_on(async {
                    serve_unseal("to-signer", &sealer_end, &allow, &resolver()).await
                })
            });
            // Ask for a name the resolver HAS, but the link's allowlist does NOT permit.
            let err = request_unseal(&signer_end, "boatramp:siblings-key").unwrap_err();
            assert!(matches!(err, UnsealError::Refused(_)), "got {err:?}");
            // The sealer stays up (refusal is not a disconnect): a following allowlisted request
            // still succeeds on the same link.
            let key = request_unseal(&signer_end, "boatramp:auth-root").expect("still serving");
            assert_eq!(&key[..], b"es256:deadbeef");
            drop(signer_end);
            sealer.join().unwrap().expect("clean end");
        }

        /// A COMPROMISED signer asking for a SIBLING's credential (a real name the sealer could
        /// resolve, but not wired to THIS link) is refused — the exact attack the allowlist stops.
        #[test]
        fn compromised_signer_cannot_unseal_a_siblings_cred() {
            let (sealer_end, signer_end) = LinkEndpoint::socketpair().unwrap();
            // This link is wired to permit ONLY the signer's own key.
            let mut allow = BTreeSet::new();
            allow.insert("boatramp:auth-root".to_string());
            let sealer = std::thread::spawn(move || {
                rt().block_on(async {
                    serve_unseal("to-signer", &sealer_end, &allow, &resolver()).await
                })
            });
            // The attacker tries every sibling name it can think of — all refused (no bytes).
            for sibling in ["boatramp:siblings-key", "boatramp:kek", "path:/etc/shadow"] {
                let err = request_unseal(&signer_end, sibling).unwrap_err();
                assert!(
                    matches!(err, UnsealError::Refused(_)),
                    "sibling {sibling:?} must be refused, got {err:?}"
                );
            }
            drop(signer_end);
            sealer.join().unwrap().expect("clean end");
        }

        /// An allowlisted name whose resolution FAILS returns `Failed` (no bytes) — fail-closed, and
        /// the error carries no key material.
        #[test]
        fn allowlisted_but_unresolvable_name_fails_closed() {
            let (sealer_end, signer_end) = LinkEndpoint::socketpair().unwrap();
            let mut allow = BTreeSet::new();
            allow.insert("boatramp:missing".to_string()); // allowlisted but absent from the resolver
            let sealer = std::thread::spawn(move || {
                rt().block_on(async {
                    serve_unseal("to-signer", &sealer_end, &allow, &resolver()).await
                })
            });
            let err = request_unseal(&signer_end, "boatramp:missing").unwrap_err();
            assert!(matches!(err, UnsealError::Failed(_)), "got {err:?}");
            drop(signer_end);
            sealer.join().unwrap().expect("clean end");
        }
    }

    // ---- the concrete resolvers use the real `[secrets]` KEK envelope ----

    #[cfg(unix)]
    #[test]
    fn envelope_sealed_file_resolver_round_trips_via_the_kek() {
        use crate::envelope::LocalKek;
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        // A real local AES-256-GCM KEK.
        let kek = Arc::new(LocalKek::from_bytes([7u8; 32])) as Arc<dyn KeyEnvelope>;
        let spec = b"es256:0123456789abcdef";
        // Seal the signer key to a temp file (what a deploy / `boatramp auth` would produce).
        let sealed = rt.block_on(kek.wrap(spec)).unwrap();
        let dir = std::env::temp_dir().join(format!("br-unseal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("signer.sealed");
        std::fs::write(&file, &sealed).unwrap();

        let resolver = EnvelopeSealedFileResolver::new(kek);
        let key_ref = format!("path:{}", file.display());
        let got = rt.block_on(resolver.resolve(&key_ref)).unwrap();
        assert_eq!(&got[..], spec);

        // A wrong-KEK envelope fail-closes (no plaintext).
        let wrong = Arc::new(LocalKek::from_bytes([9u8; 32])) as Arc<dyn KeyEnvelope>;
        let wrong_resolver = EnvelopeSealedFileResolver::new(wrong);
        assert!(rt.block_on(wrong_resolver.resolve(&key_ref)).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secret_store_resolver_round_trips_via_the_kek_and_kv() {
        use crate::envelope::LocalKek;
        use boatramp_core::kv::MemoryKv;
        use boatramp_core::project::ProjectRef;
        use boatramp_core::secret_store::SecretStore;
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let kek = Arc::new(LocalKek::from_bytes([3u8; 32])) as Arc<dyn KeyEnvelope>;
        let kv = Arc::new(MemoryKv::new()) as Arc<dyn boatramp_core::kv::KvStore>;
        // Seal the signer key into the default-project sealed store (what `boatramp secrets set`
        // would do), then resolve it through the resolver.
        rt.block_on(async {
            SecretStore::new(kv.clone(), kek.clone())
                .set(ProjectRef::DEFAULT, "auth-root", b"ed25519:feedface")
                .await
                .expect("seal the signer key");
        });
        let resolver = SecretStoreResolver::new(kv, kek);
        let got = rt.block_on(resolver.resolve("boatramp:auth-root")).unwrap();
        assert_eq!(&got[..], b"ed25519:feedface");
        // A name absent from the store fails closed.
        assert!(rt.block_on(resolver.resolve("boatramp:nope")).is_err());
    }
}
