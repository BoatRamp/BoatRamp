//! The `token` subcommand: manage control-plane tokens.
//!
//! Tokens are minted **server-side** (the issuing node holds the root private
//! key) and returned once; only their metadata (`authz/tokens/<id>`) is stored,
//! so `ls` reports the metadata and `rm` revokes by the metadata id.

use clap::Subcommand;
use serde::Deserialize;

use crate::client;
use crate::config::ProjectConfig;

/// A failure in the `token` subcommand.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Resolving the server failed.
    #[error(transparent)]
    Client(#[from] crate::client::ClientError),
    /// An HTTP request to the control plane failed.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    /// A key or credential for offline attenuation failed to parse / sign.
    #[error("delegation: {0}")]
    Delegation(String),
    /// `token bootstrap` was run without the bootstrap secret in the environment.
    #[error(
        "set BOATRAMP_BOOTSTRAP_SECRET to the secret configured on the server \
         (the value passed to `serve --bootstrap-secret`)"
    )]
    MissingBootstrapSecret,
    /// `token mint` could not resolve a signer (no env key, no `[serve.signer]` /
    /// `auth_root_private_key` in the config).
    #[error(
        "no signer for offline mint: set BOATRAMP_AUTH_ROOT_PRIVATE_KEY, or point \
         --config at a boatramp.cfg with [serve.signer] / auth_root_private_key"
    )]
    MissingSigner,
    /// Building / loading the offline-mint signer failed.
    #[error("signer: {0}")]
    Signer(String),
}

/// `token` module result; `Err` is [`Error`].
type Result<T> = std::result::Result<T, Error>;

/// Arguments for `boatramp token`.
#[derive(Debug, clap::Args)]
pub struct TokenArgs {
    /// boatramp server base URL (overrides [deploy].server).
    #[arg(long, env = "BOATRAMP_SERVER", global = true)]
    server: Option<String>,

    #[command(subcommand)]
    command: TokenCommand,
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    /// Mint a new token (printed once — not recoverable).
    Create {
        /// Human label for the token.
        label: String,
        /// Role (repeatable): `<role>` (global) or `<role>:<site>` (scoped) —
        /// e.g. `admin`, `publisher:blog`, `viewer:blog`.
        #[arg(long = "role", required = true)]
        roles: Vec<String>,
        /// Optional time-to-live in seconds (omit for no expiry).
        #[arg(long)]
        ttl_secs: Option<u64>,
        /// Make the token **delegatable**: embed this holder public key
        /// (`"<alg>:<hex>"`, from `boatramp auth init`) as the `cnf`, so the holder
        /// of the matching private key can `token attenuate` it offline.
        #[arg(long)]
        holder_pub: Option<String>,
        /// Make the token **PoP-bound** (DPoP): generate a fresh holder keypair,
        /// mint the token against its public half (`cnf`), and print the holder
        /// **private** key as `BOATRAMP_TOKEN_HOLDER_KEY` so the client can sign a
        /// per-request proof. A leaked token alone is then inert without this key.
        /// Also set `BOATRAMP_POP_ORIGIN` to the server's `[serve] pop_origin`.
        #[arg(long, conflicts_with = "holder_pub")]
        pop: bool,
    },
    /// Mint the FIRST control-plane token on a fresh deploy by presenting the
    /// single-use bootstrap secret (`BOATRAMP_BOOTSTRAP_SECRET`) — no admin token
    /// needed. The server mints via its own root key (nothing sensitive leaves it)
    /// and records the token (revocable). Use it to configure + mint scoped tokens,
    /// then unset the secret on the server.
    Bootstrap {
        /// Role for the bootstrap token (repeatable). Defaults to `admin`.
        #[arg(long = "role")]
        roles: Vec<String>,
        /// Optional time-to-live in seconds (default: 3600 = 1 h).
        #[arg(long)]
        ttl_secs: Option<u64>,
    },
    /// Mint a token **offline** — sign locally via the configured signer (local key
    /// or KMS/HSM), no server. The key-holder's recovery / air-gap path; prefer
    /// `token bootstrap` for the normal first-token flow. The token is unlisted (no
    /// server round-trip records it) but still revocable by its id.
    Mint {
        /// Role (repeatable): `<role>` (global) or `<role>:<site>` (scoped).
        #[arg(long = "role", required = true)]
        roles: Vec<String>,
        /// Optional time-to-live in seconds (omit for no expiry).
        #[arg(long)]
        ttl_secs: Option<u64>,
        /// Make it delegatable: embed this holder public key (`"<alg>:<hex>"`) as
        /// the `cnf` so it can be narrowed with `token attenuate`.
        #[arg(long)]
        holder_pub: Option<String>,
        /// `boatramp.cfg` supplying the signer (`[serve.signer]` /
        /// `auth_root_private_key`). Ignored when `BOATRAMP_AUTH_ROOT_PRIVATE_KEY`
        /// is set in the environment.
        #[arg(long, default_value = "boatramp.cfg")]
        config: std::path::PathBuf,
    },
    /// Narrow a (delegatable) token **offline** — no server, no root key — by
    /// signing a restrict-only delegation block with the holder key. The
    /// result is a longer credential; present it in place of the original.
    Attenuate {
        /// The token / credential to narrow.
        credential: String,
        /// The holder private key (`"<alg>:<hex>"`) that the parent block's `cnf`
        /// authorized.
        #[arg(long, env = "BOATRAMP_HOLDER_KEY")]
        holder_key: String,
        /// Restrict to a single site (denies every other target).
        #[arg(long)]
        only_site: Option<String>,
        /// Restrict to read-only operations.
        #[arg(long)]
        read_only: bool,
        /// Shorten the lifetime to this Unix second.
        #[arg(long)]
        not_after: Option<u64>,
        /// Permit one further attenuation by this holder public key
        /// (`"<alg>:<hex>"`); omit to make this the last block.
        #[arg(long)]
        next_holder_pub: Option<String>,
    },
    /// List issued tokens (short id, label, roles, expiry).
    Ls,
    /// Revoke a token by its id or a unique id prefix.
    Rm {
        /// Token id (or prefix).
        id: String,
    },
}

#[derive(serde::Serialize)]
struct CreateRequest {
    label: String,
    roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    holder_pubkey: Option<String>,
}

#[derive(Deserialize)]
struct CreateResponse {
    token: String,
    id: String,
}

#[derive(serde::Serialize)]
struct BootstrapRequest {
    roles: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_secs: Option<u64>,
}

/// A granted role as reported by the server (`authz::GrantedRole`).
#[derive(Deserialize)]
struct Role {
    name: String,
    #[serde(default)]
    target: Option<String>,
}

/// Issued-token metadata (`authz::TokenMeta`).
#[derive(Deserialize)]
struct TokenMeta {
    label: String,
    #[serde(default)]
    roles: Vec<Role>,
    revocation_id: String,
    #[serde(default)]
    expires_at: Option<u64>,
}

fn render_role(role: &Role) -> String {
    match &role.target {
        Some(t) => format!("{}:{}", role.name, t),
        None => role.name.clone(),
    }
}

/// Entry point for `boatramp token`.
pub async fn run(args: TokenArgs, config: &ProjectConfig) -> Result<()> {
    // Attenuation is fully offline — no server or root key needed. Handle it
    // before resolving the control-plane endpoint.
    if let TokenCommand::Attenuate {
        credential,
        holder_key,
        only_site,
        read_only,
        not_after,
        next_holder_pub,
    } = &args.command
    {
        return attenuate(
            credential,
            holder_key,
            only_site.clone(),
            *read_only,
            *not_after,
            next_holder_pub.as_deref(),
        )
        .await;
    }

    // Bootstrap authenticates with the single-use bootstrap secret (not the
    // config/admin token), so handle it before the shared token-bearing client.
    if let TokenCommand::Bootstrap { roles, ttl_secs } = &args.command {
        return bootstrap(args.server.clone(), config, roles, *ttl_secs).await;
    }

    // Offline mint signs locally via the configured signer — no server.
    if let TokenCommand::Mint {
        roles,
        ttl_secs,
        holder_pub,
        config: signer_config,
    } = &args.command
    {
        return mint_offline(roles, *ttl_secs, holder_pub.as_deref(), signer_config).await;
    }

    let server = client::resolve_server(args.server, config)?;
    let http = client::http_client(client::token(config).as_deref());

    match args.command {
        TokenCommand::Create {
            label,
            roles,
            ttl_secs,
            holder_pub,
            pop,
        } => {
            // `--pop`: generate a holder keypair and bind the token to its public
            // half; the printed private key is the per-request signing key.
            let pop_holder = pop.then(|| {
                boatramp_core::cose::LocalSigner::generate(boatramp_core::cose::TokenAlg::Es256)
            });
            let holder_pubkey = match &pop_holder {
                Some(holder) => {
                    use boatramp_core::cose::Signer;
                    Some(holder.public_key().to_hex())
                }
                None => holder_pub,
            };
            let response: CreateResponse = http
                .post(format!("{server}/api/tokens"))
                .json(&CreateRequest {
                    label,
                    roles,
                    ttl_secs,
                    holder_pubkey,
                })
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if let Some(holder) = pop_holder {
                // Print both secrets as ready-to-export shell lines (matching
                // `auth init`), guidance to stderr.
                println!("BOATRAMP_TOKEN={}", response.token);
                println!("BOATRAMP_TOKEN_HOLDER_KEY={}", holder.private_hex());
                eprintln!("id: {}", response.id);
                eprintln!(
                    "PoP-bound token. Also set BOATRAMP_POP_ORIGIN to the server's \
                     [serve] pop_origin so the client binds the right origin."
                );
                eprintln!("store both secrets now — they cannot be recovered");
            } else {
                println!("{}", response.token);
                eprintln!("id: {}", response.id);
                eprintln!("store the token now — it cannot be recovered");
            }
        }
        TokenCommand::Attenuate { .. }
        | TokenCommand::Bootstrap { .. }
        | TokenCommand::Mint { .. } => {
            unreachable!("handled above")
        }
        TokenCommand::Ls => {
            let tokens: Vec<TokenMeta> = http
                .get(format!("{server}/api/tokens"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            if tokens.is_empty() {
                println!("no tokens");
                return Ok(());
            }
            for token in tokens {
                let roles = token
                    .roles
                    .iter()
                    .map(render_role)
                    .collect::<Vec<_>>()
                    .join(",");
                let short = &token.revocation_id[..token.revocation_id.len().min(12)];
                let expiry = match token.expires_at {
                    Some(t) => format!("  expires@{t}"),
                    None => String::new(),
                };
                println!("{short}  {}  [{roles}]{expiry}", token.label);
            }
        }
        TokenCommand::Rm { id } => {
            http.delete(format!("{server}/api/tokens/{id}"))
                .send()
                .await?
                .error_for_status()?;
            println!("revoked {id}");
        }
    }
    Ok(())
}

use boatramp_core::time::now_unix;

/// `token mint`: sign a control-plane token offline via the configured signer.
async fn mint_offline(
    roles: &[String],
    ttl_secs: Option<u64>,
    holder_pub: Option<&str>,
    signer_config: &std::path::Path,
) -> Result<()> {
    use boatramp_core::cose::{self, Claims};
    let signer = resolve_signer(signer_config).await?;
    let claims = Claims {
        roles: roles
            .iter()
            .map(|s| boatramp_core::authz::GrantedRole::parse(s))
            .collect(),
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs,
        now_unix: now_unix(),
    };
    let token = match holder_pub {
        Some(hex) => {
            let holder = cose::TokenPublicKey::from_hex(hex)
                .map_err(|e| Error::Delegation(e.to_string()))?;
            cose::mint_delegatable(&claims, &holder, &*signer).await
        }
        None => cose::mint(&claims, &*signer).await,
    }
    .map_err(|e| Error::Delegation(e.to_string()))?;
    println!("{token}");
    eprintln!("minted offline — unlisted (no server record) but revocable by id");
    Ok(())
}

/// Resolve the offline-mint signer: `BOATRAMP_AUTH_ROOT_PRIVATE_KEY` (local) first,
/// else `[serve.signer]` / `auth_root_private_key` from `boatramp.cfg` — so KMS/HSM
/// works identically to the server.
async fn resolve_signer(
    config_path: &std::path::Path,
) -> Result<std::sync::Arc<dyn boatramp_core::cose::Signer>> {
    use boatramp_core::cose::{LocalSigner, Signer};
    use std::sync::Arc;
    if let Ok(hex) = std::env::var("BOATRAMP_AUTH_ROOT_PRIVATE_KEY") {
        if !hex.is_empty() {
            let signer =
                LocalSigner::from_private_hex(&hex).map_err(|e| Error::Signer(e.to_string()))?;
            return Ok(Arc::new(signer) as Arc<dyn Signer>);
        }
    }
    let serve = crate::config::ServerConfig::load(config_path)
        .map_err(|e| Error::Signer(e.to_string()))?
        .serve
        .unwrap_or_default();
    if let Some(sig) = serve.signer {
        return boatramp_server::signer::build_signer(&sig.to_signer_config())
            .await
            .map_err(|e| Error::Signer(e.to_string()));
    }
    if let Some(hex) = serve.auth_root_private_key {
        let signer =
            LocalSigner::from_private_hex(&hex).map_err(|e| Error::Signer(e.to_string()))?;
        return Ok(Arc::new(signer) as Arc<dyn Signer>);
    }
    Err(Error::MissingSigner)
}

/// `token bootstrap`: mint the first control-plane token by presenting the
/// single-use bootstrap secret (`BOATRAMP_BOOTSTRAP_SECRET`) as the bearer to the
/// RBAC-exempt `/api/tokens/bootstrap` route (the handler verifies the secret).
async fn bootstrap(
    server: Option<String>,
    config: &ProjectConfig,
    roles: &[String],
    ttl_secs: Option<u64>,
) -> Result<()> {
    let server = client::resolve_server(server, config)?;
    let secret = std::env::var("BOATRAMP_BOOTSTRAP_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
        .ok_or(Error::MissingBootstrapSecret)?;
    let http = client::http_client(Some(secret.as_str()));
    let response: CreateResponse = http
        .post(format!("{server}/api/tokens/bootstrap"))
        .json(&BootstrapRequest {
            roles: roles.to_vec(),
            ttl_secs,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    println!("{}", response.token);
    eprintln!("id: {}", response.id);
    eprintln!(
        "store the token now — it cannot be recovered; then unset the bootstrap \
         secret on the server"
    );
    Ok(())
}

/// `token attenuate`: sign a restrict-only delegation block offline and print the
/// narrowed credential.
async fn attenuate(
    credential: &str,
    holder_key: &str,
    only_site: Option<String>,
    read_only: bool,
    not_after: Option<u64>,
    next_holder_pub: Option<&str>,
) -> Result<()> {
    use boatramp_core::cose::{self, Caveats, LocalSigner, TokenPublicKey};

    let signer = LocalSigner::from_private_hex(holder_key)
        .map_err(|e| Error::Delegation(format!("holder key: {e}")))?;
    let next = next_holder_pub
        .map(TokenPublicKey::from_hex)
        .transpose()
        .map_err(|e| Error::Delegation(format!("next holder key: {e}")))?;
    let caveats = Caveats::restrict(only_site, read_only, not_after);
    if caveats.is_empty() {
        return Err(Error::Delegation(
            "an attenuation must narrow something (--only-site / --read-only / --not-after)".into(),
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let narrowed = cose::attenuate(credential, &signer, &caveats, next.as_ref(), now)
        .await
        .map_err(|e| Error::Delegation(e.to_string()))?;
    println!("{narrowed}");
    Ok(())
}
