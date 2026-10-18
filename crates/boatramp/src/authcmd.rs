//! The `auth` subcommand: the control-plane **root key** and the
//! RBAC **policy** (`authz/policy`).
//!
//! `init`/`pubkey` are pure-local key operations (no server contact). `policy
//! get`/`set` talk to the control plane (`/api/authz/policy`, admin-scoped) so
//! operators don't have to poke the KV by hand.

use std::path::PathBuf;

use boatramp_core::authz::AuthzPolicy;
use boatramp_core::cose::{LocalSigner, Signer, TokenAlg};
use clap::Subcommand;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `auth` subcommand (root-key handling + the `policy` API).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The supplied root private key (hex) failed to parse.
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),
    /// Reading the policy JSON file failed.
    #[error("reading {path}: {source}")]
    ReadPolicyFile {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// The policy file is not a valid `AuthzPolicy`.
    #[error("{path} is not a valid AuthzPolicy: {source}")]
    InvalidPolicy {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    /// Resolving the server or talking to the control plane failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// An HTTP request to the control plane failed.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// Serializing the policy to JSON for display failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    /// The `--tls rpk` bootstrap attestation could not be fetched/verified, or it
    /// did not match the key the server presented.
    #[error("bootstrap attestation: {0}")]
    Attestation(String),
    /// The policy was modified concurrently (another `auth policy set` won the optimistic-
    /// concurrency race) — the server returned `409`. Re-run `auth policy get`, re-apply the edit,
    /// and `set` again.
    #[error(
        "policy update conflict: the policy was changed concurrently (409). Re-run \
         `boatramp auth policy get`, re-apply your edit, and `set` again."
    )]
    PolicyConflict,
}

/// `authcmd` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp auth`.
#[derive(Debug, clap::Args)]
pub struct AuthArgs {
    /// boatramp server base URL (for `policy`; overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: AuthCommand,
}

#[derive(Debug, Subcommand)]
enum AuthCommand {
    /// Generate a fresh ES256 root keypair for control-plane authz.
    Init,
    /// Derive the public key from a root private key (`<alg>:<hex>`).
    Pubkey {
        /// The root private key (`<alg>:<hex>`), e.g. from `auth init`.
        #[arg(long, env = "BOATRAMP_AUTH_ROOT_PRIVATE_KEY")]
        private_key: String,
    },
    /// Resolve a `--tls rpk` server's TLS pin from your **root** public key: fetch
    /// the root-signed bootstrap attestation, verify it, and print the
    /// `BOATRAMP_SERVER_PUBKEY` to export — so you pin only the one root anchor and
    /// learn each node's TLS identity from its attestation.
    Pin {
        /// The control-plane **root** public key (`<alg>:<hex>`) — the anchor you
        /// already trust (from `auth pubkey` / `auth init`).
        #[arg(long, env = "BOATRAMP_ROOT_PUBKEY")]
        root_pubkey: String,
    },
    /// Manage the RBAC policy (`authz/policy`).
    #[command(subcommand)]
    Policy(PolicyCommand),
    /// **Rotate the cluster root key**, make-before-break. With no flag, list the
    /// extra trusted anchors. `--add` trusts a new anchor cluster-wide (so both
    /// old + new verify — no window where a valid token is rejected); re-point
    /// `[serve.signer]` to the new key so new tokens/attestations use it, then
    /// `--retire` the old anchor once every node has the new one. See
    /// `how-to/migrate-root-key.md`.
    RotateRoot {
        /// Trust a new root anchor (`<alg>:<hex>` public key, from `auth pubkey`).
        #[arg(long, value_name = "PUBKEY")]
        add: Option<String>,
        /// Retire a previously-added anchor (the old key, after propagation).
        #[arg(long, value_name = "PUBKEY")]
        retire: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Print the active policy as JSON (the built-in default if none is stored).
    Get,
    /// Replace the policy from a JSON file (validated server-side before store).
    Set {
        /// Path to the policy JSON (matching `AuthzPolicy`).
        file: PathBuf,
    },
}

/// The result of an `auth` subcommand, rendered by [`crate::output`].
///
/// `auth init` prints the freshly generated **root private key** (shown once, the data
/// the operator must capture) — it is both the human export line and a JSON field. The
/// next-step guidance that used to go to stderr is diagnostic and moves to `tracing`.
#[derive(Debug, serde::Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AuthOutput {
    /// `auth init` — a fresh ES256 root keypair (the private key is shown once).
    Init {
        private_key: String,
        public_key: String,
    },
    /// `auth pubkey` — the public key derived from a root private key.
    Pubkey { public_key: String },
    /// `auth pin` — the resolved per-node TLS pin to export.
    Pin { server_pubkey: String },
    /// `auth policy get` — the active RBAC policy.
    PolicyGet { policy: AuthzPolicy },
    /// `auth policy set` — the policy was replaced.
    PolicySet,
    /// `auth rotate-root` — a new anchor was trusted (`added`), an old one retired
    /// (`retired`), and/or (with neither flag) the extra anchors listed (`anchors`).
    /// The add/retire acks + next-step guidance go to `tracing`; only the listing is
    /// human stdout.
    RotateRoot {
        #[serde(skip_serializing_if = "Option::is_none")]
        added: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        retired: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        anchors: Option<Vec<String>>,
    },
}

impl crate::output::Rendered for AuthOutput {
    fn render_human(&self, w: &mut dyn std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Init {
                private_key,
                public_key,
            } => {
                writeln!(w, "# boatramp control-plane root key (COSE/CWT — ES256)")?;
                writeln!(
                    w,
                    "# Issuing node — keep secret (mints tokens, runs OIDC exchange):"
                )?;
                writeln!(w, "BOATRAMP_AUTH_ROOT_PRIVATE_KEY={private_key}")?;
                writeln!(w, "# Verify-only nodes / public trust anchor:")?;
                writeln!(w, "BOATRAMP_AUTH_ROOT_PUBLIC_KEY={public_key}")
            }
            Self::Pubkey { public_key } => writeln!(w, "{public_key}"),
            Self::Pin { server_pubkey } => {
                writeln!(w, "BOATRAMP_SERVER_PUBKEY={server_pubkey}")
            }
            Self::PolicyGet { policy } => {
                let rendered =
                    serde_json::to_string_pretty(policy).map_err(std::io::Error::other)?;
                writeln!(w, "{rendered}")
            }
            Self::PolicySet => writeln!(w, "policy updated"),
            Self::RotateRoot { anchors, .. } => {
                // `added`/`retired` acks + guidance already went to `tracing` (stderr);
                // only the `--list` anchors are stdout, as before.
                if let Some(anchors) = anchors {
                    if anchors.is_empty() {
                        writeln!(
                            w,
                            "(no extra root anchors — running on the primary root key only)"
                        )?;
                    } else {
                        for a in anchors {
                            writeln!(w, "{a}")?;
                        }
                    }
                }
                Ok(())
            }
        }
    }
}

/// Entry point for `boatramp auth`.
pub async fn run(args: AuthArgs, config: &ProjectConfig) -> Result<AuthOutput> {
    match args.command {
        AuthCommand::Init => {
            // ES256 is the portable default: every HSM/KMS can sign it (Ed25519 is
            // available for local/AWS/Vault via `--alg`).
            let signer = LocalSigner::generate(TokenAlg::Es256);
            let private_key = signer.private_hex();
            let public_key = signer.public_key().to_hex();
            tracing::info!("");
            tracing::info!(
                "Set this private key on the server to enable auth. On a fresh deploy, \
                 mint the FIRST token by also setting a single-use bootstrap secret \
                 (`serve --bootstrap-secret <secret>` / BOATRAMP_BOOTSTRAP_SECRET), then:\n  \
                 BOATRAMP_BOOTSTRAP_SECRET=<secret> boatramp token bootstrap --role admin\n\
                 Use that admin token to mint scoped tokens (`boatramp token create \
                 publisher:<site>`), then unset the bootstrap secret on the server."
            );
            Ok(AuthOutput::Init {
                private_key,
                public_key,
            })
        }
        AuthCommand::Pubkey { private_key } => {
            let signer = LocalSigner::from_private_hex(&private_key)
                .map_err(|e| Error::InvalidPrivateKey(e.to_string()))?;
            Ok(AuthOutput::Pubkey {
                public_key: signer.public_key().to_hex(),
            })
        }
        AuthCommand::Pin { root_pubkey } => run_pin(args.server, root_pubkey, config).await,
        AuthCommand::Policy(command) => run_policy(command, args.server, config).await,
        AuthCommand::RotateRoot { add, retire } => {
            run_rotate_root(add, retire, args.server, config).await
        }
    }
}

/// Resolve a `--tls rpk` server's TLS pin from the operator's root public key.
/// Connects trust-on-first-use (capturing the presented key), fetches the
/// root-signed attestation, verifies it under the root key, and confirms it names
/// the presented key — then prints the pin. No trust is placed in the server
/// until the root signature checks out.
async fn run_pin(
    server: Option<String>,
    root_pubkey: String,
    config: &ProjectConfig,
) -> Result<AuthOutput> {
    use std::sync::{Arc, Mutex};

    let server = client::resolve_server(server, config)?;
    let root = boatramp_core::cose::TokenPublicKey::from_hex(root_pubkey.trim())
        .map_err(|e| Error::Attestation(format!("invalid --root-pubkey: {e}")))?;

    // Fetch the attestation over a TOFU connection that records the presented key.
    let captured = Arc::new(Mutex::new(None));
    let tls = boatramp_rpktls::client_config_capturing(captured.clone())
        .map_err(|e| Error::Attestation(e.to_string()))?;
    let http = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .build()?;
    let attestation = http
        .get(format!("{server}/.well-known/boatramp-bootstrap-identity"))
        .send()
        .await?
        .error_for_status()
        .map_err(|_| {
            Error::Attestation(format!(
                "{server} served no bootstrap attestation (is it `--tls rpk` with a root key?)"
            ))
        })?
        .text()
        .await?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let attested_hex = boatramp_core::cose::verify_attestation(attestation.trim(), &root, now)
        .map_err(|e| Error::Attestation(format!("root signature/validity failed: {e}")))?;

    // The attestation must name the key the server actually presented on the wire.
    let attested = boatramp_rpktls::parse_public_key(&attested_hex)
        .map_err(|e| Error::Attestation(e.to_string()))?;
    let presented = captured
        .lock()
        .expect("capture slot")
        .clone()
        .ok_or_else(|| Error::Attestation("server presented no key".into()))?;
    if presented != attested {
        return Err(Error::Attestation(
            "the attestation does not match the key the server presented".into(),
        ));
    }

    tracing::info!("verified {server} against the root key. Export this to pin it:");
    Ok(AuthOutput::Pin {
        server_pubkey: attested_hex,
    })
}

/// Drive a make-before-break root rotation via the replicated anchor set.
async fn run_rotate_root(
    add: Option<String>,
    retire: Option<String>,
    server: Option<String>,
    config: &ProjectConfig,
) -> Result<AuthOutput> {
    let server = client::resolve_server(server, config)?;
    let http = client::http_client(client::token(config).as_deref());

    let mut added = None;
    let mut retired = None;
    let mut anchors = None;

    if let Some(pubkey) = add.as_deref() {
        let pubkey = pubkey.trim();
        // Validate locally for a clear error before the round-trip.
        boatramp_core::cose::TokenPublicKey::from_hex(pubkey)
            .map_err(|e| Error::Attestation(format!("invalid --add pubkey: {e}")))?;
        http.put(format!("{server}/api/auth/root"))
            .json(&serde_json::json!({ "pubkey": pubkey }))
            .send()
            .await?
            .error_for_status()?;
        tracing::info!("trusted new root anchor {pubkey} (make-before-break).");
        tracing::info!(
            "Now re-point [serve.signer] / BOATRAMP_AUTH_ROOT_PRIVATE_KEY to the new key so new \
             tokens + attestations use it, wait for every node to converge, then retire the old \
             anchor:\n  boatramp auth rotate-root --retire <old-pubkey>"
        );
        added = Some(pubkey.to_string());
    }
    if let Some(pubkey) = retire.as_deref() {
        let pubkey = pubkey.trim();
        http.delete(format!("{server}/api/auth/root/{pubkey}"))
            .send()
            .await?
            .error_for_status()?;
        tracing::info!("retired root anchor {pubkey}.");
        retired = Some(pubkey.to_string());
    }
    if add.is_none() && retire.is_none() {
        anchors = Some(
            http.get(format!("{server}/api/auth/root"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?,
        );
    }
    Ok(AuthOutput::RotateRoot {
        added,
        retired,
        anchors,
    })
}

async fn run_policy(
    command: PolicyCommand,
    server: Option<String>,
    config: &ProjectConfig,
) -> Result<AuthOutput> {
    let server = client::resolve_server(server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    match command {
        PolicyCommand::Get => {
            let resp = http
                .get(format!("{server}/api/authz/policy"))
                .send()
                .await?
                .error_for_status()?;
            let policy: AuthzPolicy = resp.json().await?;
            // Surface a serialization failure up-front as `Error::Json` (unchanged error
            // path); the human/JSON rendering then renders from the structured `policy`.
            serde_json::to_string_pretty(&policy)?;
            Ok(AuthOutput::PolicyGet { policy })
        }
        PolicyCommand::Set { file } => {
            let raw = std::fs::read_to_string(&file).map_err(|e| Error::ReadPolicyFile {
                path: file.display().to_string(),
                source: e,
            })?;
            // Parse locally for a clear error before the round-trip; the server
            // re-validates (compiles) it authoritatively.
            let policy: AuthzPolicy =
                serde_json::from_str(&raw).map_err(|e| Error::InvalidPolicy {
                    path: file.display().to_string(),
                    source: e,
                })?;
            // Optimistic concurrency: GET the current version (its `ETag`) and echo it as
            // `If-Match` on the PUT, so a policy changed concurrently (another operator / node)
            // is a `409` rather than a silent lost-write overwrite.
            let get = http
                .get(format!("{server}/api/authz/policy"))
                .send()
                .await?
                .error_for_status()?;
            let etag = get
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string);
            let mut req = http.put(format!("{server}/api/authz/policy")).json(&policy);
            if let Some(etag) = &etag {
                req = req.header("if-match", etag);
            }
            let resp = req.send().await?;
            if resp.status() == reqwest::StatusCode::CONFLICT {
                return Err(Error::PolicyConflict);
            }
            resp.error_for_status()?;
            Ok(AuthOutput::PolicySet)
        }
    }
}
