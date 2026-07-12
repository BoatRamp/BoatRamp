//! Joiner-side dynamic cluster join (CJ-2): redeem a **join ticket** against a
//! seed's control plane, anchored end-to-end on the cluster's **root key**.
//!
//! A cluster is defined by its root of trust; a fresh node knows only the root
//! anchor set + a single-use bearer token (both bundled in the opaque ticket).
//! There is **no peer map**. The flow reuses the `auth pin` bootstrap-TLS path
//! verbatim, then proves possession of the node's own mesh key at redemption and
//! verifies every returned member against the root before adopting it:
//!
//! 1. TOFU-fetch a seed's `/.well-known/boatramp-bootstrap-identity` attestation
//!    and verify it against the root anchor (`auth pin`) — pins the seed's key.
//! 2. Verify the join token against the root → its single-use `jti`.
//! 3. Sign `cose::join_challenge(jti, mesh_pubkey, proof_iat)` with the node's
//!    **mesh private key** (which never leaves the node) — the possession proof.
//! 4. `POST /api/cluster/join` over the **pinned** channel.
//! 5. Verify each returned member assertion against the root (F3) and adopt it.
//!
//! Only steps 1–2 and 5 are pure/offline and unit-tested here; steps 3–4 are the
//! live handshake (exercised end-to-end in the cluster integration seam).

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use boatramp_core::cose::{self, TokenPublicKey};
use boatramp_rpktls::RpkIdentity;

/// Versioned, human-recognisable prefix on the opaque ticket blob.
const TICKET_MAGIC: &str = "brjoin1";

/// A failure joining a cluster.
#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    /// The ticket could not be decoded / is missing fields / has a bad root key.
    #[error("invalid join ticket: {0}")]
    Ticket(String),
    /// The join token did not verify against the cluster root anchor.
    #[error("join token: {0}")]
    Token(String),
    /// Building the mesh-key possession proof failed.
    #[error("possession proof: {0}")]
    Proof(String),
    /// A returned member assertion did not verify against the root (F3).
    #[error("member assertion: {0}")]
    Member(String),
    /// Pinning / reaching a seed failed (bootstrap attestation or transport).
    #[error("seed {0}")]
    Seed(String),
    /// The seed refused the join (typed: expired/spent token, bad proof, revoked).
    #[error("join refused by {seed}: {status} {body}")]
    Refused {
        /// The seed that refused.
        seed: String,
        /// The HTTP status.
        status: u16,
        /// The seed's response body (already trimmed).
        body: String,
    },
    /// An underlying HTTP/TLS error.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

/// A join ticket: everything a fresh node needs to join — the seed address(es),
/// the root anchor **set**, and the single-use bearer token. The blob is opaque +
/// copy-pasteable (magic-prefixed base64url of JSON), but every field is
/// re-verified on use: `seeds` are integrity-relevant (F2), the token is checked
/// against the roots, and each returned member is root-signed (F3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct JoinTicket {
    /// Seed control-plane addresses (`host:port`), any of which can admit us.
    pub seeds: Vec<String>,
    /// The cluster root anchor SET (`es256:`/`ed25519:`-tagged public keys).
    pub root_pubkeys: Vec<String>,
    /// The single-use bearer join token.
    pub token: String,
}

impl JoinTicket {
    /// Encode to the opaque `--cluster-join` blob.
    pub fn encode(&self) -> Result<String, JoinError> {
        let json = serde_json::to_vec(self).map_err(|e| JoinError::Ticket(e.to_string()))?;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        Ok(format!("{TICKET_MAGIC}.{b64}"))
    }

    /// Decode the opaque blob back to a ticket (validating it is non-empty).
    pub fn decode(blob: &str) -> Result<Self, JoinError> {
        let b64 = blob
            .trim()
            .strip_prefix(TICKET_MAGIC)
            .and_then(|s| s.strip_prefix('.'))
            .ok_or_else(|| JoinError::Ticket("not a boatramp join ticket (bad prefix)".into()))?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| JoinError::Ticket(e.to_string()))?;
        let ticket: JoinTicket =
            serde_json::from_slice(&json).map_err(|e| JoinError::Ticket(e.to_string()))?;
        if ticket.seeds.is_empty() || ticket.root_pubkeys.is_empty() || ticket.token.is_empty() {
            return Err(JoinError::Ticket(
                "ticket is missing seeds, root pubkeys, or token".into(),
            ));
        }
        Ok(ticket)
    }

    /// Parse the root anchor set into verifier keys.
    pub fn roots(&self) -> Result<Vec<TokenPublicKey>, JoinError> {
        self.root_pubkeys
            .iter()
            .map(|s| {
                TokenPublicKey::from_hex(s.trim())
                    .map_err(|e| JoinError::Ticket(format!("bad root pubkey: {e}")))
            })
            .collect()
    }
}

/// A cluster member adopted after its root-signed assertion verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptedMember {
    /// The member's derived Raft node id (display label).
    pub node_id: u64,
    /// The member's mesh public key (SPKI hex) — the authority to trust.
    pub mesh_pubkey_hex: String,
    /// The member's advisory mesh base URL, if the seed reported one — used to
    /// dial it (the dial is still key-authenticated). `None` ⇒ address unknown.
    pub mesh_addr: Option<String>,
}

/// Verify each returned member assertion against **any** root in the anchor set,
/// returning the adopted members (attaching the advisory address the seed
/// reported for each, keyed by the verified node id). A member that verifies
/// under **no** root is a hard error — a malicious or stale seed cannot inject or
/// fabricate a member (F3); it can at most *omit* one, which the caller
/// reconciles against the leader's `GET /api/cluster/members` before treating the
/// join as complete. The address is only trusted for a node the assertion
/// verified (never adopted from the unsigned map alone).
pub fn verify_members(
    assertions: &[String],
    addrs: &std::collections::BTreeMap<u64, String>,
    roots: &[TokenPublicKey],
    now: u64,
) -> Result<Vec<AdoptedMember>, JoinError> {
    let mut adopted = Vec::with_capacity(assertions.len());
    for token in assertions {
        let member = roots
            .iter()
            .find_map(|root| cose::verify_member_assertion(token, root, now).ok())
            .ok_or_else(|| {
                JoinError::Member(
                    "a returned member did not verify against the cluster root anchor".into(),
                )
            })?;
        adopted.push(AdoptedMember {
            mesh_addr: addrs.get(&member.node_id).cloned(),
            node_id: member.node_id,
            mesh_pubkey_hex: member.pubkey_hex,
        });
    }
    Ok(adopted)
}

/// Verify the join token against the root anchor set, returning its single-use
/// `jti` (the challenge the possession proof binds to).
fn verify_token(token: &str, roots: &[TokenPublicKey], now: u64) -> Result<String, JoinError> {
    roots
        .iter()
        .find_map(|root| cose::verify_join(token, root, now).ok())
        .ok_or_else(|| {
            JoinError::Token("did not verify against the cluster root anchor".into())
        })
}

/// The hex possession proof: the node signs the domain-separated join challenge
/// with its mesh private key, proving it controls the key it presents (closing
/// the echo-not-prove gap — F1). The key never leaves the node.
fn possession_proof(
    identity: &RpkIdentity,
    jti: &str,
    mesh_pubkey_hex: &str,
    proof_iat: u64,
) -> Result<String, JoinError> {
    let challenge = cose::join_challenge(jti, mesh_pubkey_hex, proof_iat);
    let sig = identity
        .sign(&challenge)
        .map_err(|e| JoinError::Proof(e.to_string()))?;
    Ok(hex::encode(sig))
}

/// The `POST /api/cluster/join` request body (mirrors the server's `JoinRequest`).
#[derive(Serialize)]
struct JoinRequestBody {
    token: String,
    mesh_pubkey: String,
    possession_proof: String,
    proof_iat: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    advertise_addr: Option<String>,
}

/// The join response (mirrors the server's `JoinResponse`).
#[derive(Deserialize)]
struct JoinResponseBody {
    members: Vec<String>,
    #[serde(default)]
    member_addrs: std::collections::BTreeMap<u64, String>,
}

/// Join a cluster by redeeming `ticket` with the node's own mesh `identity`,
/// advertising `advertise_addr` (this node's own mesh URL) so the leader can
/// replicate back to it. Tries each seed until one admits; returns the adopted
/// (root-verified) members so the caller can seed its mesh trust set + peer
/// directory with **no static peer map**.
pub async fn join_cluster(
    ticket: &JoinTicket,
    identity: &RpkIdentity,
    advertise_addr: Option<&str>,
    now: u64,
) -> Result<Vec<AdoptedMember>, JoinError> {
    let roots = ticket.roots()?;
    let jti = verify_token(&ticket.token, &roots, now)?;
    let mesh_pubkey_hex = identity.public_key_hex();
    let proof_iat = now;
    let proof = possession_proof(identity, &jti, &mesh_pubkey_hex, proof_iat)?;

    let mut last_err: Option<JoinError> = None;
    for seed in &ticket.seeds {
        match join_via_seed(
            seed,
            &roots,
            &ticket.token,
            &mesh_pubkey_hex,
            &proof,
            proof_iat,
            advertise_addr,
            now,
        )
        .await
        {
            Ok(body) => return verify_members(&body.members, &body.member_addrs, &roots, now),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or_else(|| JoinError::Seed("no seeds in ticket".into())))
}

/// Normalize a seed address to a base URL (default `https`, the `--tls rpk`
/// control-plane scheme).
fn seed_base_url(seed: &str) -> String {
    let s = seed.trim();
    if s.starts_with("http://") || s.starts_with("https://") {
        s.trim_end_matches('/').to_string()
    } else {
        format!("https://{}", s.trim_end_matches('/'))
    }
}

/// Redeem the join against one seed: pin it against the root anchor (`auth pin`),
/// then `POST /api/cluster/join` over the pinned channel and return the response
/// (the caller verifies the members against the root). Note the seed is pinned by
/// re-fetching its attestation with the SAME roots passed to `join_cluster` — so
/// this fn only needs the token + proof + this node's advertised address.
async fn join_via_seed(
    seed: &str,
    roots: &[TokenPublicKey],
    token: &str,
    mesh_pubkey_hex: &str,
    proof: &str,
    proof_iat: u64,
    advertise_addr: Option<&str>,
    now: u64,
) -> Result<JoinResponseBody, JoinError> {
    let base = seed_base_url(seed);

    // (1) Pin the seed against the root anchor (TOFU-capture → root-verify →
    // confirm the attestation names the presented key). Reuses `auth pin`.
    let attested_spki = pin_seed(&base, roots, now).await?;

    // (2) A properly server-authenticated client for the join POST: the seed must
    // present exactly the key its attestation named.
    let peer: boatramp_rpktls::PeerId = 1;
    let trust =
        boatramp_rpktls::TrustSet::from_map(std::iter::once((peer, attested_spki)).collect());
    let tls = boatramp_rpktls::client_config_server_auth(trust, peer)
        .map_err(|e| JoinError::Seed(format!("{base}: {e}")))?;
    let http = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .build()?;

    let resp = http
        .post(format!("{base}/api/cluster/join"))
        .json(&JoinRequestBody {
            token: token.to_string(),
            mesh_pubkey: mesh_pubkey_hex.to_string(),
            possession_proof: proof.to_string(),
            proof_iat,
            advertise_addr: advertise_addr.map(str::to_string),
        })
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(JoinError::Refused {
            seed: base,
            status: status.as_u16(),
            body: body.trim().to_string(),
        });
    }
    Ok(resp.json().await?)
}

/// Fetch a seed's bootstrap attestation trust-on-first-use, verify it against the
/// root anchor set, confirm it names the key the seed actually presented, and
/// return that pinned SPKI. Mirrors `auth pin` (`run_pin`) — the seed is trusted
/// only once a root signature over its key checks out.
async fn pin_seed(
    base: &str,
    roots: &[TokenPublicKey],
    now: u64,
) -> Result<Vec<u8>, JoinError> {
    let captured = Arc::new(Mutex::new(None));
    let tls = boatramp_rpktls::client_config_capturing(captured.clone())
        .map_err(|e| JoinError::Seed(format!("{base}: {e}")))?;
    let http = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .build()?;
    let attestation = http
        .get(format!("{base}/.well-known/boatramp-bootstrap-identity"))
        .send()
        .await?
        .error_for_status()
        .map_err(|_| {
            JoinError::Seed(format!(
                "{base} served no bootstrap attestation (is it `--tls rpk` under this root?)"
            ))
        })?
        .text()
        .await?;

    // The attestation must verify under *some* root in the anchor set.
    let attested_hex = roots
        .iter()
        .find_map(|root| cose::verify_attestation(attestation.trim(), root, now).ok())
        .ok_or_else(|| {
            JoinError::Seed(format!(
                "{base}: attestation did not verify against the cluster root anchor"
            ))
        })?;
    let attested = boatramp_rpktls::parse_public_key(&attested_hex)
        .map_err(|e| JoinError::Seed(format!("{base}: {e}")))?;
    let presented = captured
        .lock()
        .expect("capture slot")
        .clone()
        .ok_or_else(|| JoinError::Seed(format!("{base}: presented no key")))?;
    if presented != attested {
        return Err(JoinError::Seed(format!(
            "{base}: the attestation does not match the key the seed presented"
        )));
    }
    Ok(attested)
}

/// What a cluster node should do at startup, decided purely from its config +
/// on-disk state (F5: founding is explicit + single-shot; empty seeds fail
/// closed; a former member never re-founds).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupAction {
    /// Durable Raft state exists — resume the existing membership from it
    /// (a plain restart; never re-founds, never re-joins).
    Resume,
    /// Found a brand-new single-node cluster — only on the explicit one-time
    /// signal (`cluster init` / `--cluster-init`, or the operator's ordinal-0).
    Found,
    /// Join an existing cluster via the configured seeds (redeem the ticket).
    Join,
    /// Fail closed with a reason: no state and nothing that authorizes founding
    /// or joining. Never a silent self-found.
    FailClosed(String),
}

/// Inputs to the [`decide_startup`] founding decision.
#[derive(Debug, Clone, Copy)]
pub struct StartupInputs {
    /// This node has non-empty durable Raft state (it is/was running).
    pub has_durable_state: bool,
    /// This node was ever admitted to a cluster (a durable, survives-wipe marker).
    pub ever_member: bool,
    /// One or more seeds are configured (something to join).
    pub seeds_present: bool,
    /// The explicit one-time founding signal was given for this boot.
    pub init_requested: bool,
}

/// Decide what a node does at startup — the single source of truth for founding
/// vs joining vs resuming (F5). Founding is **never** inferred from "seeds are
/// absent/unreachable right now"; it happens only on the explicit init signal,
/// and only for a node that was never a member. Everything else with no state
/// fails closed rather than risk a second genesis (split-brain).
pub fn decide_startup(i: &StartupInputs) -> StartupAction {
    // A node with durable state always resumes — the highest-precedence case.
    if i.has_durable_state {
        return StartupAction::Resume;
    }
    // Ambiguous intent: founding and joining are mutually exclusive. A node
    // either founds (init, no seeds) or joins (seeds, no init).
    if i.init_requested && i.seeds_present {
        return StartupAction::FailClosed(
            "both cluster-init and seeds are configured — a node either founds \
             (init, no seeds) or joins (seeds, no init), not both"
                .into(),
        );
    }
    // A former member whose volume was wiped must NEVER re-found; it may only
    // rejoin via seeds.
    if i.ever_member {
        return if i.seeds_present {
            StartupAction::Join
        } else {
            StartupAction::FailClosed(
                "former member with no durable state and no seeds: refusing to re-found \
                 (F5) — provide seeds to rejoin the existing cluster"
                    .into(),
            )
        };
    }
    // A fresh node: join if seeded, else found only on the explicit signal.
    if i.seeds_present {
        StartupAction::Join
    } else if i.init_requested {
        StartupAction::Found
    } else {
        StartupAction::FailClosed(
            "no durable state, no seeds, and no cluster-init: refusing to self-found \
             (F5) — pass --cluster-init to found a new cluster or seeds to join one"
                .into(),
        )
    }
}

/// Resolve a `join_token` config value, which — like the rest of the config
/// surface — keeps the secret out of the file via a prefix (#6):
/// `env:VAR` reads an environment variable, `path:/file` reads a file (trimmed),
/// and anything else is an inline literal. Empty resolves to `None`.
pub fn resolve_join_token(spec: &str) -> Result<Option<String>, JoinError> {
    let spec = spec.trim();
    if spec.is_empty() {
        return Ok(None);
    }
    if let Some(var) = spec.strip_prefix("env:") {
        return match std::env::var(var) {
            Ok(v) if !v.trim().is_empty() => Ok(Some(v.trim().to_string())),
            _ => Err(JoinError::Token(format!(
                "join_token env var {var} is unset or empty"
            ))),
        };
    }
    if let Some(path) = spec.strip_prefix("path:") {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| JoinError::Token(format!("join_token file {path}: {e}")))?;
        let token = raw.trim().to_string();
        return if token.is_empty() {
            Err(JoinError::Token(format!("join_token file {path} is empty")))
        } else {
            Ok(Some(token))
        };
    }
    Ok(Some(spec.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::cose::{LocalSigner, Signer, TokenAlg};

    fn now() -> u64 {
        1_800_000_000 // fixed; these tests are time-relative to their own mints
    }

    /// A ticket survives an encode→decode round-trip, and decoding rejects a
    /// non-ticket blob + an empty ticket.
    #[test]
    fn ticket_round_trips_and_rejects_garbage() {
        let ticket = JoinTicket {
            seeds: vec!["node-1.internal:7000".into(), "node-2.internal:7000".into()],
            root_pubkeys: vec!["es256:0342".into()],
            token: "join-token-blob".into(),
        };
        let blob = ticket.encode().unwrap();
        assert!(blob.starts_with("brjoin1."));
        assert_eq!(JoinTicket::decode(&blob).unwrap(), ticket);

        assert!(JoinTicket::decode("not-a-ticket").is_err());
        // A well-formed blob whose ticket is empty is rejected.
        let empty = JoinTicket {
            seeds: vec![],
            root_pubkeys: vec![],
            token: String::new(),
        }
        .encode()
        .unwrap();
        assert!(JoinTicket::decode(&empty).is_err());
    }

    /// `verify_members` adopts genuine root-signed members and **rejects** a set
    /// that includes any member not signed by the root — a malicious/stale seed
    /// cannot inject or fabricate a member (F3).
    #[tokio::test]
    async fn verify_members_adopts_genuine_and_rejects_forged() {
        let root = LocalSigner::generate(TokenAlg::Es256);
        let roots = vec![root.public_key()];
        let now = now();

        let good_a = cose::mint_member_assertion(11, "aa11", 300, now, &root)
            .await
            .unwrap();
        let good_b = cose::mint_member_assertion(22, "bb22", 300, now, &root)
            .await
            .unwrap();

        // A genuine set adopts, preserving (node_id, pubkey) and attaching the
        // advisory address only for a verified node (11 has one, 22 doesn't).
        let addrs = std::collections::BTreeMap::from([(11u64, "https://a:7000".to_string())]);
        let adopted = verify_members(&[good_a.clone(), good_b.clone()], &addrs, &roots, now).unwrap();
        assert_eq!(
            adopted,
            vec![
                AdoptedMember {
                    node_id: 11,
                    mesh_pubkey_hex: "aa11".into(),
                    mesh_addr: Some("https://a:7000".into()),
                },
                AdoptedMember {
                    node_id: 22,
                    mesh_pubkey_hex: "bb22".into(),
                    mesh_addr: None,
                },
            ]
        );

        // A member signed by a DIFFERENT (attacker) key is rejected — the whole
        // set fails rather than adopting the forged entry.
        let attacker = LocalSigner::generate(TokenAlg::Es256);
        let forged = cose::mint_member_assertion(33, "cc33", 300, now, &attacker)
            .await
            .unwrap();
        assert!(verify_members(&[good_a, forged], &addrs, &roots, now).is_err());
    }

    /// The possession proof a joiner builds verifies against its own mesh key over
    /// the exact challenge the seed reconstructs — and fails for a different key
    /// (closing the echo-not-prove gap, F1).
    #[test]
    fn possession_proof_binds_the_mesh_key_and_challenge() {
        let identity = RpkIdentity::generate().unwrap();
        let mesh_pubkey_hex = identity.public_key_hex();
        let jti = "single-use-jti";
        let proof_iat = now();

        let proof_hex = possession_proof(&identity, jti, &mesh_pubkey_hex, proof_iat).unwrap();
        let proof = hex::decode(proof_hex).unwrap();
        let challenge = cose::join_challenge(jti, &mesh_pubkey_hex, proof_iat);
        let spki = boatramp_rpktls::parse_public_key(&mesh_pubkey_hex).unwrap();
        assert!(boatramp_rpktls::verify_signature(&spki, &challenge, &proof));

        // A different key does not satisfy the proof.
        let other = boatramp_rpktls::parse_public_key(&RpkIdentity::generate().unwrap().public_key_hex())
            .unwrap();
        assert!(!boatramp_rpktls::verify_signature(&other, &challenge, &proof));
    }

    /// The founding decision (F5): durable state resumes; a fresh node founds
    /// only on the explicit signal and joins when seeded; a former member never
    /// re-founds; ambiguous/empty inputs fail closed — never a silent self-found.
    #[test]
    fn startup_decision_enforces_explicit_single_shot_founding() {
        let base = StartupInputs {
            has_durable_state: false,
            ever_member: false,
            seeds_present: false,
            init_requested: false,
        };
        let with = |f: fn(&mut StartupInputs)| {
            let mut i = base;
            f(&mut i);
            decide_startup(&i)
        };

        // Durable state always resumes, regardless of every other input.
        assert_eq!(
            with(|i| {
                i.has_durable_state = true;
                i.seeds_present = true;
                i.init_requested = true;
            }),
            StartupAction::Resume
        );
        // Fresh + explicit init + no seeds → found.
        assert_eq!(with(|i| i.init_requested = true), StartupAction::Found);
        // Fresh + seeds → join.
        assert_eq!(with(|i| i.seeds_present = true), StartupAction::Join);
        // Init AND seeds → ambiguous, fail closed.
        assert!(matches!(
            with(|i| {
                i.init_requested = true;
                i.seeds_present = true;
            }),
            StartupAction::FailClosed(_)
        ));
        // Former member, wiped volume, seeds → rejoin (never re-found).
        assert_eq!(
            with(|i| {
                i.ever_member = true;
                i.seeds_present = true;
            }),
            StartupAction::Join
        );
        // Former member, wiped volume, no seeds, even with init → fail closed
        // (a former member never re-founds).
        assert!(matches!(
            with(|i| {
                i.ever_member = true;
                i.init_requested = true;
            }),
            // init+no-seeds+ever_member: not the ambiguous case, so it reaches the
            // ever_member branch and fails closed on "no seeds".
            StartupAction::FailClosed(_)
        ));
        // Fresh, nothing configured → fail closed (never a silent self-found).
        assert!(matches!(with(|_| {}), StartupAction::FailClosed(_)));
    }

    /// `resolve_join_token` reads env:/path:/inline, and errors on an unset env
    /// var or empty file — keeping the secret out of the config file (#6).
    #[test]
    fn join_token_resolves_env_path_and_inline() {
        assert_eq!(resolve_join_token("").unwrap(), None);
        assert_eq!(
            resolve_join_token("inline-token").unwrap(),
            Some("inline-token".to_string())
        );

        // env: — a uniquely-named var so the test is isolated.
        std::env::set_var("BOATRAMP_TEST_JOIN_TOKEN", "  tok-from-env  ");
        assert_eq!(
            resolve_join_token("env:BOATRAMP_TEST_JOIN_TOKEN").unwrap(),
            Some("tok-from-env".to_string())
        );
        assert!(resolve_join_token("env:BOATRAMP_TEST_JOIN_TOKEN_UNSET").is_err());

        // path: — write a temp file and read it back trimmed.
        let dir = std::env::temp_dir();
        let file = dir.join("boatramp-test-join-token");
        std::fs::write(&file, "tok-from-file\n").unwrap();
        assert_eq!(
            resolve_join_token(&format!("path:{}", file.display())).unwrap(),
            Some("tok-from-file".to_string())
        );
        std::fs::write(&file, "   \n").unwrap();
        assert!(resolve_join_token(&format!("path:{}", file.display())).is_err());
        let _ = std::fs::remove_file(&file);
    }
}
