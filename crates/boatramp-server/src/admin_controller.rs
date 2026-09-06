//! Server-side implementation of the guest `admin` capability
//! ([`boatramp_handlers::AdminController`]).
//!
//! A guest reconfigures **its own project** by calling the in-process control-plane
//! subsystems directly (no HTTP, no token): domain verification (`DeployStore`), SMTP profiles
//! ([`EmailProfileStore`]), sealed secrets ([`SecretStore`]), and site config (`DeployStore` +
//! the shared [`check_added_domains_verified`](crate::admin_api::check_added_domains_verified)
//! guard). [`ServerAdminController::scoped`] rebinds per grant with the guest's host-stamped
//! project, so a guest can only ever touch its own project.
//!
//! Every mutation (a) charges a per-project rate quota (a runaway guest can't churn config) and
//! (b) writes an **audit** record as a host `tracing` event on the `boatramp::audit` target —
//! deliberately NOT the rate-capped guest log stream, so an audit event is never dropped;
//! durable retention is the operator's log pipeline.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use async_trait::async_trait;
use boatramp_core::access::RateLimit;
use boatramp_core::config::SiteConfig;
use boatramp_core::deploy::DeployStore;
use boatramp_core::domain_verify::{check_ownership, DomainProbe, VerificationMethod};
use boatramp_core::email_config::{EmailProfilePatch, EmailProfileStore};
use boatramp_core::error::DeployError;
use boatramp_core::project::ProjectRef;
use boatramp_core::secret_store::SecretStore;
use boatramp_core::site::SiteName;
use boatramp_handlers::{AdminController, AdminError, DomainChallenge};

use crate::admin_api::{check_added_domains_verified, DomainGuard};
use crate::ratelimit::RateLimiter;

/// Sustained per-project admin-mutation rate. Config changes are rare, so this is low; a burst
/// covers a legitimate multi-step flow (add domain → verify → attach → put config).
const ADMIN_OPS_PER_SEC: u32 = 2;
/// Burst capacity for the per-project admin token bucket.
const ADMIN_OPS_BURST: u32 = 20;
/// Fixed key-suffix for the per-project bucket (admin has no client IP; the bucket is keyed on
/// the project, so it's effectively per-project).
const ADMIN_RL_IP: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// The server's `AdminController`. Cheap to clone (Arc/handle fields); `.scoped(project)`
/// rebinds it to one guest's project.
pub struct ServerAdminController {
    deploy: DeployStore,
    email_store: Option<Arc<EmailProfileStore>>,
    secret_store: Option<Arc<SecretStore>>,
    probe: Arc<dyn DomainProbe>,
    /// Shared across scopes so the per-project buckets persist between invocations.
    rate: Arc<RateLimiter>,
    limit: RateLimit,
    project: String,
}

impl ServerAdminController {
    /// Build the unscoped template at startup. `email_store`/`secret_store` are `None` when no
    /// `[secrets]` envelope is configured (those surfaces then report a clear backend error).
    #[must_use]
    pub fn new(
        deploy: DeployStore,
        email_store: Option<Arc<EmailProfileStore>>,
        secret_store: Option<Arc<SecretStore>>,
        probe: Arc<dyn DomainProbe>,
    ) -> Self {
        Self {
            deploy,
            email_store,
            secret_store,
            probe,
            rate: Arc::new(RateLimiter::new()),
            limit: RateLimit {
                rps: ADMIN_OPS_PER_SEC,
                burst: ADMIN_OPS_BURST,
            },
            project: String::new(),
        }
    }

    /// Build the template with the server's real network domain probe (the same one the HTTP
    /// verify path uses), honoring the operator's `domain_verify_allow_private` posture. The
    /// node calls this (it can't name the crate-private probe type itself).
    #[must_use]
    pub fn with_server_probe(
        deploy: DeployStore,
        email_store: Option<Arc<EmailProfileStore>>,
        secret_store: Option<Arc<SecretStore>>,
        domain_verify_allow_private: bool,
    ) -> Self {
        let probe: Arc<dyn DomainProbe> = Arc::new(crate::domain_verify::ServerDomainProbe::new(
            domain_verify_allow_private,
        ));
        Self::new(deploy, email_store, secret_store, probe)
    }

    /// Rebind to `project` (host-stamped) for one grant — the tenant boundary.
    #[must_use]
    pub fn scoped(&self, project: ProjectRef<'_>) -> Arc<dyn AdminController> {
        Arc::new(Self {
            deploy: self.deploy.clone(),
            email_store: self.email_store.clone(),
            secret_store: self.secret_store.clone(),
            probe: self.probe.clone(),
            rate: self.rate.clone(),
            limit: self.limit,
            project: project.as_str().to_string(),
        })
    }

    fn project(&self) -> ProjectRef<'_> {
        ProjectRef::new(&self.project)
    }

    /// Charge one admin op to the project's bucket; `RateLimited` when empty.
    fn charge(&self) -> Result<(), AdminError> {
        if self.rate.check(&self.project, ADMIN_RL_IP, &self.limit) {
            Ok(())
        } else {
            Err(AdminError::RateLimited)
        }
    }

    /// Write an audit record (host tracing — never the rate-capped guest log stream).
    fn audit(&self, surface: &str, verb: &str, target: &str, outcome: &str) {
        tracing::info!(
            target: "boatramp::audit",
            project = %self.project,
            surface,
            verb,
            config_target = %target,
            outcome,
            "guest admin mutation",
        );
    }

    fn email(&self) -> Result<&Arc<EmailProfileStore>, AdminError> {
        self.email_store.as_ref().ok_or_else(|| {
            AdminError::Other("email profiles need a [secrets] envelope (none configured)".into())
        })
    }

    fn secrets(&self) -> Result<&Arc<SecretStore>, AdminError> {
        self.secret_store.as_ref().ok_or_else(|| {
            AdminError::Other("secrets need a [secrets] envelope (none configured)".into())
        })
    }
}

fn deploy_err(e: DeployError) -> AdminError {
    match e {
        DeployError::NotFound(m) => AdminError::NotFound(m),
        other => AdminError::Other(other.to_string()),
    }
}

fn email_err(e: boatramp_core::email_config::EmailProfileError) -> AdminError {
    if e.is_client_error() {
        AdminError::InvalidInput(e.to_string())
    } else {
        AdminError::Other(e.to_string())
    }
}

fn secret_err(e: boatramp_core::secret_store::SecretError) -> AdminError {
    if e.is_client_error() {
        AdminError::InvalidInput(e.to_string())
    } else {
        AdminError::Other(e.to_string())
    }
}

fn method_str(m: VerificationMethod) -> String {
    match m {
        VerificationMethod::Http => "http".into(),
        VerificationMethod::Dns => "dns".into(),
    }
}

/// Reject a `site` argument that isn't a well-formed resource name. Parity with the HTTP
/// admin path's `reject_invalid_name("site", …)`, and it keeps a guest-controlled string
/// (path separators, `*`, whitespace, control chars) out of the KV key *and* the audit record
/// — the guest passes `site` as a raw WIT string, not a URL segment, so it isn't pre-sanitized.
fn valid_site(site: &str) -> Result<(), AdminError> {
    boatramp_core::project::validate_resource_name("site", site)
        .map_err(|e| AdminError::InvalidInput(e.to_string()))
}

/// Reject a `host` argument carrying whitespace/control characters (no valid domain contains
/// them, and a newline could forge an audit line) or an implausible length. A domain
/// legitimately contains `.` and a leading `*.`, so the stricter [`valid_site`] validator
/// can't be reused here — this is the minimal integrity guard.
fn valid_host(host: &str) -> Result<(), AdminError> {
    if host.is_empty() || host.len() > 253 {
        return Err(AdminError::InvalidInput(
            "host must be 1..=253 bytes".into(),
        ));
    }
    if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(AdminError::InvalidInput(
            "host must not contain whitespace or control characters".into(),
        ));
    }
    Ok(())
}

#[async_trait]
impl AdminController for ServerAdminController {
    async fn domain_add(
        &self,
        site: &str,
        host: &str,
        method: &str,
    ) -> Result<DomainChallenge, AdminError> {
        self.charge()?;
        valid_site(site)?;
        valid_host(host)?;
        let m = method
            .parse::<VerificationMethod>()
            .map_err(|e| AdminError::InvalidInput(e.to_string()))?;
        let v = self
            .deploy
            .start_domain_verification(
                self.project(),
                &SiteName::new(site),
                host,
                m,
                boatramp_core::time::now_unix(),
            )
            .await
            .map_err(deploy_err)?;
        self.audit("domains", "add", &format!("{site}/{host}"), "ok");
        Ok(DomainChallenge {
            host: v.host,
            method: method_str(v.method),
            token: v.token,
        })
    }

    async fn domain_verify(&self, site: &str, host: &str) -> Result<bool, AdminError> {
        self.charge()?;
        valid_site(site)?;
        valid_host(host)?;
        let sn = SiteName::new(site);
        let verification = self
            .deploy
            .get_domain_verification(self.project(), &sn, host)
            .await
            .map_err(deploy_err)?
            .ok_or_else(|| {
                AdminError::NotFound(format!(
                    "no verification challenge for {host}; call domain-add first"
                ))
            })?;
        // The real network ownership probe — the same one the HTTP verify path runs. There is
        // no guest path to the System·Admin `attach-unverified` route.
        let target = format!("{site}/{host}");
        let passed = match check_ownership(self.probe.as_ref(), &verification).await {
            Ok(passed) => passed,
            Err(e) => {
                // A failed ownership probe is security-relevant (a guest reaching for a domain it
                // may not control) — audit the error outcome, never silently.
                self.audit("domains", "verify", &target, "probe-error");
                return Err(AdminError::Other(e.to_string()));
            }
        };
        if passed {
            self.deploy
                .mark_domain_verified(self.project(), &sn, host)
                .await
                .map_err(deploy_err)?;
            self.deploy
                .attach_verified_domain(self.project(), &sn, host)
                .await
                .map_err(deploy_err)?;
            self.audit("domains", "verify", &target, "ok");
        } else {
            // Ownership NOT proven — audit the denied attempt (the routing-hijack surface).
            self.audit("domains", "verify", &target, "not-verified");
        }
        Ok(passed)
    }

    async fn domain_remove(&self, site: &str, host: &str) -> Result<(), AdminError> {
        self.charge()?;
        valid_site(site)?;
        valid_host(host)?;
        self.deploy
            .remove_domain_verification(self.project(), &SiteName::new(site), host)
            .await
            .map_err(deploy_err)?;
        self.audit("domains", "remove", &format!("{site}/{host}"), "ok");
        Ok(())
    }

    async fn domain_list(&self, site: &str) -> Result<Vec<String>, AdminError> {
        self.charge()?;
        valid_site(site)?;
        let list = self
            .deploy
            .list_domain_verifications(self.project(), &SiteName::new(site))
            .await
            .map_err(deploy_err)?;
        Ok(list.into_iter().map(|v| v.host).collect())
    }

    async fn email_set(&self, name: &str, profile: EmailProfilePatch) -> Result<(), AdminError> {
        self.charge()?;
        self.email()?
            .patch(self.project(), name, &profile)
            .await
            .map_err(email_err)?;
        self.audit("email", "set", name, "ok");
        Ok(())
    }

    async fn email_delete(&self, name: &str) -> Result<(), AdminError> {
        self.charge()?;
        let existed = self
            .email()?
            .delete(self.project(), name)
            .await
            .map_err(email_err)?;
        if !existed {
            return Err(AdminError::NotFound(format!("no email profile {name:?}")));
        }
        self.audit("email", "delete", name, "ok");
        Ok(())
    }

    async fn email_list(&self) -> Result<Vec<String>, AdminError> {
        self.charge()?;
        let infos = self
            .email()?
            .list(self.project())
            .await
            .map_err(email_err)?;
        Ok(infos.into_iter().map(|i| i.name).collect())
    }

    async fn site_config_get(&self, site: &str) -> Result<String, AdminError> {
        self.charge()?;
        valid_site(site)?;
        let config = self
            .deploy
            .get_site_config(self.project(), site)
            .await
            .map_err(deploy_err)?
            .ok_or_else(|| AdminError::NotFound(format!("no config for site {site:?}")))?;
        serde_json::to_string(&config)
            .map_err(|e| AdminError::Other(format!("serializing site config: {e}")))
    }

    async fn site_config_put(&self, site: &str, config: &str) -> Result<(), AdminError> {
        self.charge()?;
        valid_site(site)?;
        let next: SiteConfig = serde_json::from_str(config)
            .map_err(|e| AdminError::InvalidInput(format!("invalid site config JSON: {e}")))?;
        // Reject an unknown/typo'd capability name in the site import allowlist before storing
        // (defense-in-depth; the effective grant is still manifest imports ∩ this ∩ posture).
        next.validate_allow_imports()
            .map_err(|e| AdminError::InvalidInput(e.to_string()))?;
        // The routing-hijack guard: a config write can't attach an unverified domain.
        match check_added_domains_verified(&self.deploy, self.project(), site, &next)
            .await
            .map_err(deploy_err)?
        {
            DomainGuard::Ok => {}
            DomainGuard::Unverified(reason) => return Err(AdminError::NotVerified(reason)),
        }
        self.deploy
            .set_site_config(self.project(), site, &next)
            .await
            .map_err(deploy_err)?;
        self.audit("site", "config-put", site, "ok");
        Ok(())
    }

    async fn secret_set(&self, name: &str, value: &[u8]) -> Result<(), AdminError> {
        self.charge()?;
        self.secrets()?
            .set(self.project(), name, value)
            .await
            .map_err(secret_err)?;
        self.audit("secrets", "set", name, "ok");
        Ok(())
    }

    async fn secret_delete(&self, name: &str) -> Result<(), AdminError> {
        self.charge()?;
        let existed = self
            .secrets()?
            .delete(self.project(), name)
            .await
            .map_err(secret_err)?;
        if !existed {
            return Err(AdminError::NotFound(format!("no secret {name:?}")));
        }
        self.audit("secrets", "delete", name, "ok");
        Ok(())
    }

    async fn secret_list(&self) -> Result<Vec<String>, AdminError> {
        self.charge()?;
        let metas = self
            .secrets()?
            .list(self.project())
            .await
            .map_err(secret_err)?;
        Ok(metas.into_iter().map(|m| m.name).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
    use boatramp_core::kv::MemoryKv;

    struct XorEnvelope;
    #[async_trait]
    impl KeyEnvelope for XorEnvelope {
        async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(p.iter().map(|b| b ^ 0x5a).collect())
        }
        async fn unwrap(&self, c: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
            Ok(c.iter().map(|b| b ^ 0x5a).collect())
        }
    }

    fn controller() -> Arc<dyn AdminController> {
        let kv = Arc::new(MemoryKv::new());
        let deploy = DeployStore::new(
            Arc::new(boatramp_storage::FsStorage::new(std::env::temp_dir())),
            kv.clone(),
        );
        let email = Arc::new(EmailProfileStore::new(kv.clone(), Arc::new(XorEnvelope)));
        let secret = Arc::new(SecretStore::new(kv, Arc::new(XorEnvelope)));
        ServerAdminController::new(
            deploy,
            Some(email),
            Some(secret),
            Arc::new(crate::domain_verify::ServerDomainProbe::new(true)),
        )
        .scoped(ProjectRef::new("acme"))
    }

    fn email_patch() -> EmailProfilePatch {
        EmailProfilePatch {
            host: Some("smtp.example.com".into()),
            from: Some("no-reply@example.com".into()),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn email_and_secret_surfaces_round_trip() {
        let c = controller();
        c.email_set("default", email_patch()).await.unwrap();
        assert_eq!(c.email_list().await.unwrap(), vec!["default".to_string()]);
        c.secret_set("api-key", b"v").await.unwrap();
        assert_eq!(c.secret_list().await.unwrap(), vec!["api-key".to_string()]);
        c.email_delete("default").await.unwrap();
        assert!(c.email_list().await.unwrap().is_empty());
        // Deleting a missing profile is NotFound.
        assert!(matches!(
            c.email_delete("gone").await.unwrap_err(),
            AdminError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn site_config_round_trips_when_no_new_domain_is_added() {
        let c = controller();
        let cfg = serde_json::to_string(&SiteConfig::default()).unwrap();
        // No newly-added domain ⇒ the verified-domain guard passes.
        c.site_config_put("blog", &cfg).await.unwrap();
        let got = c.site_config_get("blog").await.unwrap();
        assert!(!got.is_empty());
        // Malformed JSON is InvalidInput, not a panic.
        assert!(matches!(
            c.site_config_put("blog", "{not json").await.unwrap_err(),
            AdminError::InvalidInput(_)
        ));
        // An unknown/typo'd capability name in the import allowlist is rejected before storage.
        let bad = SiteConfig {
            handlers: Some(boatramp_core::config::HandlersSiteConfig {
                enabled: true,
                allow_imports: vec!["wasi:filesystem".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let bad_json = serde_json::to_string(&bad).unwrap();
        assert!(matches!(
            c.site_config_put("blog", &bad_json).await.unwrap_err(),
            AdminError::InvalidInput(_)
        ));
    }

    #[tokio::test]
    async fn a_malformed_site_or_host_is_rejected_before_use() {
        let c = controller();
        // A path separator / control char in `site` never reaches the KV key or the audit
        // record — it's rejected as InvalidInput (parity with the HTTP path's name guard).
        for bad in ["../globex", "a/b", "with space", "star*", "line\nbreak", ""] {
            assert!(
                matches!(
                    c.site_config_get(bad).await.unwrap_err(),
                    AdminError::InvalidInput(_)
                ),
                "site {bad:?} must be rejected"
            );
        }
        // A whitespace/control char in `host` (e.g. an audit-forging newline) is rejected too.
        for bad in ["ev\nil.com", "has space.com", ""] {
            assert!(
                matches!(
                    c.domain_add("blog", bad, "http").await.unwrap_err(),
                    AdminError::InvalidInput(_)
                ),
                "host {bad:?} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn a_runaway_guest_is_rate_limited() {
        let c = controller();
        let mut limited = false;
        // The bucket starts at the burst; well past it, a mutation is rejected.
        for i in 0..(ADMIN_OPS_BURST + 5) {
            match c.secret_set(&format!("k{i}"), b"v").await {
                Ok(()) => {}
                Err(AdminError::RateLimited) => {
                    limited = true;
                    break;
                }
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert!(
            limited,
            "a runaway admin loop must hit the per-project rate quota"
        );
        // Reads are charged to the same bucket, so once it's drained a read is limited too
        // (a runaway can't amplify by hammering list/get instead of the mutations).
        assert!(matches!(
            c.secret_list().await.unwrap_err(),
            AdminError::RateLimited
        ));
    }
}
