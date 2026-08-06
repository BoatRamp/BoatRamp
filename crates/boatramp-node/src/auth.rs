//! Control-plane auth assembly: build the [`Auth`](boatramp_server::Auth) from
//! the resolved root-key settings, and the fail-closed bind guard that refuses
//! to expose an unauthenticated control plane on a public listener.
//!
//! Moved out of the `boatramp` binary's `serve` path so an in-process embedder —
//! or a fidelity test — assembles auth exactly as `boatramp serve` does.

use std::net::SocketAddr;
use std::sync::Arc;

use boatramp_core::kv::KvStore;

use crate::error::{Error, Result};

/// Build the control-plane [`Auth`](boatramp_server::Auth) from the resolved
/// root-key settings (flag/env > `serve` config). For an issuing node (a
/// private key or an external signer) it also sets `options.issuer` so the
/// token-create and OIDC-exchange routes can mint. No key ⇒ auth disabled (dev).
pub async fn configure_auth(
    signer: Option<&crate::config::AuthSignerConfig>,
    private_key: Option<String>,
    public_key: Option<String>,
    options: &mut boatramp_server::ServerOptions,
    kv: Arc<dyn KvStore>,
) -> Result<boatramp_server::Auth> {
    use boatramp_core::cose::{LocalSigner, Signer, TokenPublicKey};
    // An external signer (KMS/HSM/Vault) issues *and* provides the trust anchor:
    // it resolves its own public key at connect.
    if let Some(cfg) = signer {
        let issuer = boatramp_server::signer::build_signer(&cfg.to_signer_config())
            .await
            .map_err(|e| Error::AuthPrivKey(e.to_string()))?;
        let public = issuer.public_key();
        options.issuer = Some(issuer);
        return Ok(boatramp_server::Auth::with_key(public, kv));
    }
    if let Some(hex) = private_key {
        let signer =
            LocalSigner::from_private_hex(&hex).map_err(|e| Error::AuthPrivKey(e.to_string()))?;
        let public = signer.public_key();
        options.issuer = Some(Arc::new(signer) as Arc<dyn Signer>);
        return Ok(boatramp_server::Auth::with_key(public, kv));
    }
    if let Some(hex) = public_key {
        let public =
            TokenPublicKey::from_hex(&hex).map_err(|e| Error::AuthPubKey(e.to_string()))?;
        return Ok(boatramp_server::Auth::with_key(public, kv));
    }
    Ok(boatramp_server::Auth::disabled())
}

/// Fail-closed bind guard: refuse to expose an unauthenticated control plane on a
/// non-loopback listener unless the posture explicitly allows it, and warn loudly
/// for any auth-disabled listener.
pub fn enforce_auth_bind(
    addr: SocketAddr,
    auth: &boatramp_server::Auth,
    posture: &boatramp_core::security::SecurityPosture,
) -> Result<()> {
    if auth.is_disabled() {
        if !addr.ip().is_loopback() && !posture.allow_unauthenticated_public_bind {
            return Err(Error::UnauthenticatedPublicBind { addr });
        }
        tracing::warn!(
            %addr,
            "control-plane auth is DISABLED — do not expose this listener to an untrusted network"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::security::SecurityProfile;

    /// An auth-disabled non-loopback bind is refused under the strict
    /// posture, allowed on loopback, and allowed when the posture opts in.
    #[test]
    fn fail_closed_refuses_unauthenticated_public_bind() {
        let disabled = boatramp_server::Auth::disabled();
        let strict = SecurityProfile::MultiTenant.preset();
        let dev = SecurityProfile::Dev.preset();
        let public: SocketAddr = "0.0.0.0:8080".parse().unwrap();
        let loopback: SocketAddr = "127.0.0.1:8080".parse().unwrap();

        // Auth disabled + public + strict → refused.
        assert!(matches!(
            enforce_auth_bind(public, &disabled, &strict),
            Err(Error::UnauthenticatedPublicBind { .. })
        ));
        // Loopback is always permitted (local-dev convenience).
        assert!(enforce_auth_bind(loopback, &disabled, &strict).is_ok());
        // The `dev` posture opts into an unauthenticated public bind.
        assert!(enforce_auth_bind(public, &disabled, &dev).is_ok());
    }
}
