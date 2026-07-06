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
    /// Manage the RBAC policy (`authz/policy`).
    #[command(subcommand)]
    Policy(PolicyCommand),
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

/// Entry point for `boatramp auth`.
pub async fn run(args: AuthArgs, config: &ProjectConfig) -> Result<()> {
    match args.command {
        AuthCommand::Init => {
            // ES256 is the portable default: every HSM/KMS can sign it (Ed25519 is
            // available for local/AWS/Vault via `--alg`).
            let signer = LocalSigner::generate(TokenAlg::Es256);
            println!("# boatramp control-plane root key (COSE/CWT — ES256)");
            println!("# Issuing node — keep secret (mints tokens, runs OIDC exchange):");
            println!("BOATRAMP_AUTH_ROOT_PRIVATE_KEY={}", signer.private_hex());
            println!("# Verify-only nodes / public trust anchor:");
            println!(
                "BOATRAMP_AUTH_ROOT_PUBLIC_KEY={}",
                signer.public_key().to_hex()
            );
            eprintln!();
            eprintln!(
                "Set this private key on the server to enable auth. On a fresh deploy, \
                 mint the FIRST token by also setting a single-use bootstrap secret \
                 (`serve --bootstrap-secret <secret>` / BOATRAMP_BOOTSTRAP_SECRET), then:\n  \
                 BOATRAMP_BOOTSTRAP_SECRET=<secret> boatramp token bootstrap --role admin\n\
                 Use that admin token to mint scoped tokens (`boatramp token create \
                 publisher:<site>`), then unset the bootstrap secret on the server."
            );
        }
        AuthCommand::Pubkey { private_key } => {
            let signer = LocalSigner::from_private_hex(&private_key)
                .map_err(|e| Error::InvalidPrivateKey(e.to_string()))?;
            println!("{}", signer.public_key().to_hex());
        }
        AuthCommand::Policy(command) => run_policy(command, args.server, config).await?,
    }
    Ok(())
}

async fn run_policy(
    command: PolicyCommand,
    server: Option<String>,
    config: &ProjectConfig,
) -> Result<()> {
    let server = client::resolve_server(server, config)?;
    let http = client::http_client(client::token(config).as_deref());
    match command {
        PolicyCommand::Get => {
            let policy: AuthzPolicy = http
                .get(format!("{server}/api/authz/policy"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&policy)?);
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
            http.put(format!("{server}/api/authz/policy"))
                .json(&policy)
                .send()
                .await?
                .error_for_status()?;
            println!("policy updated");
        }
    }
    Ok(())
}
