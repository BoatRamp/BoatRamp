//! The `admin` capability host binding: a guest **reconfigures its own project**
//! (`boatramp:handlers/admin`) — add a domain, set an SMTP profile, write site config, write a
//! secret — without a boatramp token.
//!
//! The authority is the deploy-time grant (`admin:<surface>` import) + the operator posture,
//! and it is intrinsically scoped to the guest's OWN project: the server-side
//! [`AdminController`] is `.scoped(project)` where `project` is stamped host-side (never guest
//! input), so cross-tenant configuration is structurally impossible. It is strictly weaker than
//! a project-admin token — no cross-project reach, no critical/node-global ops, verb-scoped.
//!
//! Deny-by-default at two levels: an ungranted capability has no binding (`access-denied`), and
//! each verb is gated on its [`Surface`] within the binding (so `admin:domains` ≠
//! `admin:email`). Reads return **redacted** views only; the mutation logic, per-project rate
//! quota, and audit trail live in the server's controller.

use std::collections::BTreeSet;
use std::sync::Arc;

use boatramp_core::email_config::{EmailProfilePatch, SmtpSecurity};

mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "boatramp:handlers/admin-host",
        async: {
            only_imports: [
                "domain-add",
                "domain-verify",
                "domain-remove",
                "domain-list",
                "email-set",
                "email-delete",
                "email-list",
                "site-config-get",
                "site-config-put",
                "secret-set",
                "secret-delete",
                "secret-list",
            ],
        },
    });
}

use generated::boatramp::handlers::{admin as admin_iface, admin_types};

/// The grantable config surfaces. A guest's binding carries the subset it was granted (and the
/// operator posture enabled); each verb checks its surface before touching the controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Surface {
    Domains,
    Email,
    Site,
    Secrets,
}

/// A pending domain-ownership challenge (host-native form of the WIT `domain-challenge`).
#[derive(Debug, Clone)]
pub struct DomainChallenge {
    pub host: String,
    pub method: String,
    pub token: String,
}

/// Why an admin operation failed (host-native; mapped to the WIT `admin-error`).
#[derive(Debug)]
pub enum AdminError {
    /// The surface was not granted (or the operator posture disables it).
    AccessDenied,
    /// The input was rejected (bad name/config/serialized-config).
    InvalidInput(String),
    /// A domain attach before its ownership was proven.
    NotVerified(String),
    /// The named resource does not exist.
    NotFound(String),
    /// The per-project admin rate quota was exceeded.
    RateLimited,
    /// Any other backend error.
    Other(String),
}

/// The server-side mutation seam: implemented by the server (calling the in-process
/// domain-verify / email-profile / secret / site-config subsystems), held as
/// `Arc<dyn AdminController>`, project-scoped per grant. Every mutation charges the project's
/// admin rate quota and writes an audit record — in the implementation, not here.
#[async_trait::async_trait]
pub trait AdminController: Send + Sync {
    async fn domain_add(
        &self,
        site: &str,
        host: &str,
        method: &str,
    ) -> Result<DomainChallenge, AdminError>;
    async fn domain_verify(&self, site: &str, host: &str) -> Result<bool, AdminError>;
    async fn domain_remove(&self, site: &str, host: &str) -> Result<(), AdminError>;
    async fn domain_list(&self, site: &str) -> Result<Vec<String>, AdminError>;
    async fn email_set(&self, name: &str, profile: EmailProfilePatch) -> Result<(), AdminError>;
    async fn email_delete(&self, name: &str) -> Result<(), AdminError>;
    async fn email_list(&self) -> Result<Vec<String>, AdminError>;
    async fn site_config_get(&self, site: &str) -> Result<String, AdminError>;
    async fn site_config_put(&self, site: &str, config: &str) -> Result<(), AdminError>;
    async fn secret_set(&self, name: &str, value: &[u8]) -> Result<(), AdminError>;
    async fn secret_delete(&self, name: &str) -> Result<(), AdminError>;
    async fn secret_list(&self) -> Result<Vec<String>, AdminError>;
}

/// A per-project `admin` grant: the project-scoped controller + the granted surfaces.
#[derive(Clone)]
pub struct AdminBinding {
    pub(crate) controller: Arc<dyn AdminController>,
    pub(crate) surfaces: BTreeSet<Surface>,
}

/// Per-invocation view over the (optional) admin grant.
pub struct AdminHost<'a> {
    binding: Option<&'a AdminBinding>,
}

impl<'a> AdminHost<'a> {
    pub fn new(binding: Option<&'a AdminBinding>) -> Self {
        Self { binding }
    }

    /// The controller for `surface`, or `access-denied` when the capability is ungranted or the
    /// surface isn't in the grant. Returns an owned `Arc` so no borrow of `self` is held across
    /// the subsequent `.await`.
    fn controller_for(
        &self,
        surface: Surface,
    ) -> Result<Arc<dyn AdminController>, admin_types::AdminError> {
        let binding = self.binding.ok_or(admin_types::AdminError::AccessDenied)?;
        if !binding.surfaces.contains(&surface) {
            return Err(admin_types::AdminError::AccessDenied);
        }
        Ok(binding.controller.clone())
    }
}

fn to_wit(err: AdminError) -> admin_types::AdminError {
    match err {
        AdminError::AccessDenied => admin_types::AdminError::AccessDenied,
        AdminError::InvalidInput(m) => admin_types::AdminError::InvalidInput(m),
        AdminError::NotVerified(m) => admin_types::AdminError::NotVerified(m),
        AdminError::NotFound(m) => admin_types::AdminError::NotFound(m),
        AdminError::RateLimited => admin_types::AdminError::RateLimited,
        AdminError::Other(m) => admin_types::AdminError::Other(m),
    }
}

impl admin_iface::Host for AdminHost<'_> {
    async fn domain_add(
        &mut self,
        site: String,
        host: String,
        method: String,
    ) -> Result<admin_types::DomainChallenge, admin_types::AdminError> {
        let c = self.controller_for(Surface::Domains)?;
        let ch = c.domain_add(&site, &host, &method).await.map_err(to_wit)?;
        Ok(admin_types::DomainChallenge {
            host: ch.host,
            method: ch.method,
            token: ch.token,
        })
    }

    async fn domain_verify(
        &mut self,
        site: String,
        host: String,
    ) -> Result<bool, admin_types::AdminError> {
        let c = self.controller_for(Surface::Domains)?;
        c.domain_verify(&site, &host).await.map_err(to_wit)
    }

    async fn domain_remove(
        &mut self,
        site: String,
        host: String,
    ) -> Result<(), admin_types::AdminError> {
        let c = self.controller_for(Surface::Domains)?;
        c.domain_remove(&site, &host).await.map_err(to_wit)
    }

    async fn domain_list(&mut self, site: String) -> Result<Vec<String>, admin_types::AdminError> {
        let c = self.controller_for(Surface::Domains)?;
        c.domain_list(&site).await.map_err(to_wit)
    }

    async fn email_set(
        &mut self,
        name: String,
        profile: admin_types::EmailProfile,
    ) -> Result<(), admin_types::AdminError> {
        let c = self.controller_for(Surface::Email)?;
        let security = match &profile.security {
            Some(s) => Some(
                s.parse::<SmtpSecurity>()
                    .map_err(admin_types::AdminError::InvalidInput)?,
            ),
            None => None,
        };
        let patch = EmailProfilePatch {
            host: profile.host,
            port: profile.port,
            security,
            username: profile.username,
            password: profile.password,
            from: profile.from,
            durable: profile.durable,
            clear_auth: profile.clear_auth,
        };
        c.email_set(&name, patch).await.map_err(to_wit)
    }

    async fn email_delete(&mut self, name: String) -> Result<(), admin_types::AdminError> {
        let c = self.controller_for(Surface::Email)?;
        c.email_delete(&name).await.map_err(to_wit)
    }

    async fn email_list(&mut self) -> Result<Vec<String>, admin_types::AdminError> {
        let c = self.controller_for(Surface::Email)?;
        c.email_list().await.map_err(to_wit)
    }

    async fn site_config_get(&mut self, site: String) -> Result<String, admin_types::AdminError> {
        let c = self.controller_for(Surface::Site)?;
        c.site_config_get(&site).await.map_err(to_wit)
    }

    async fn site_config_put(
        &mut self,
        site: String,
        config: String,
    ) -> Result<(), admin_types::AdminError> {
        let c = self.controller_for(Surface::Site)?;
        c.site_config_put(&site, &config).await.map_err(to_wit)
    }

    async fn secret_set(
        &mut self,
        name: String,
        value: String,
    ) -> Result<(), admin_types::AdminError> {
        let c = self.controller_for(Surface::Secrets)?;
        c.secret_set(&name, value.as_bytes()).await.map_err(to_wit)
    }

    async fn secret_delete(&mut self, name: String) -> Result<(), admin_types::AdminError> {
        let c = self.controller_for(Surface::Secrets)?;
        c.secret_delete(&name).await.map_err(to_wit)
    }

    async fn secret_list(&mut self) -> Result<Vec<String>, admin_types::AdminError> {
        let c = self.controller_for(Surface::Secrets)?;
        c.secret_list().await.map_err(to_wit)
    }
}

/// Add the `admin` interface to `linker`, resolving the per-invocation [`AdminHost`] via `host`.
pub fn add_to_linker<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    host: impl Fn(&mut T) -> AdminHost<'_> + Send + Sync + Copy + 'static,
) -> wasmtime::Result<()> {
    admin_iface::add_to_linker_get_host(linker, host)
}

#[cfg(test)]
mod tests {
    use super::admin_iface::Host;
    use super::*;
    use std::sync::Mutex;

    /// A controller that records the calls it received (and always succeeds).
    #[derive(Default)]
    struct RecordingController {
        calls: Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl AdminController for RecordingController {
        async fn domain_add(
            &self,
            site: &str,
            host: &str,
            method: &str,
        ) -> Result<DomainChallenge, AdminError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("domain_add {site} {host} {method}"));
            Ok(DomainChallenge {
                host: host.into(),
                method: method.into(),
                token: "tok".into(),
            })
        }
        async fn domain_verify(&self, _: &str, _: &str) -> Result<bool, AdminError> {
            Ok(true)
        }
        async fn domain_remove(&self, _: &str, _: &str) -> Result<(), AdminError> {
            Ok(())
        }
        async fn domain_list(&self, _: &str) -> Result<Vec<String>, AdminError> {
            Ok(vec![])
        }
        async fn email_set(&self, name: &str, _: EmailProfilePatch) -> Result<(), AdminError> {
            self.calls.lock().unwrap().push(format!("email_set {name}"));
            Ok(())
        }
        async fn email_delete(&self, _: &str) -> Result<(), AdminError> {
            Ok(())
        }
        async fn email_list(&self) -> Result<Vec<String>, AdminError> {
            Ok(vec![])
        }
        async fn site_config_get(&self, _: &str) -> Result<String, AdminError> {
            Ok(String::new())
        }
        async fn site_config_put(&self, _: &str, _: &str) -> Result<(), AdminError> {
            Ok(())
        }
        async fn secret_set(&self, name: &str, _: &[u8]) -> Result<(), AdminError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("secret_set {name}"));
            Ok(())
        }
        async fn secret_delete(&self, _: &str) -> Result<(), AdminError> {
            Ok(())
        }
        async fn secret_list(&self) -> Result<Vec<String>, AdminError> {
            Ok(vec![])
        }
    }

    fn binding(surfaces: &[Surface]) -> AdminBinding {
        AdminBinding {
            controller: Arc::new(RecordingController::default()),
            surfaces: surfaces.iter().copied().collect(),
        }
    }

    #[tokio::test]
    async fn ungranted_capability_is_denied() {
        let mut host = AdminHost::new(None);
        assert!(matches!(
            host.domain_add("blog".into(), "x.example".into(), "http".into())
                .await
                .unwrap_err(),
            admin_types::AdminError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn a_verb_needs_its_own_surface_grant() {
        // Granted domains but NOT email: a domain verb works, an email verb is access-denied.
        let b = binding(&[Surface::Domains]);
        let mut host = AdminHost::new(Some(&b));
        assert!(host
            .domain_add("blog".into(), "x.example".into(), "http".into())
            .await
            .is_ok());
        assert!(matches!(
            host.email_delete("default".into()).await.unwrap_err(),
            admin_types::AdminError::AccessDenied
        ));
        assert!(matches!(
            host.secret_delete("k".into()).await.unwrap_err(),
            admin_types::AdminError::AccessDenied
        ));
    }

    #[tokio::test]
    async fn granted_surfaces_reach_the_controller() {
        let b = binding(&[Surface::Email, Surface::Secrets]);
        let mut host = AdminHost::new(Some(&b));
        host.email_set(
            "default".into(),
            admin_types::EmailProfile {
                host: Some("smtp.example.com".into()),
                port: None,
                security: Some("starttls".into()),
                username: None,
                password: None,
                from: Some("a@b.com".into()),
                durable: None,
                clear_auth: false,
            },
        )
        .await
        .unwrap();
        host.secret_set("api-key".into(), "v".into()).await.unwrap();
    }

    #[tokio::test]
    async fn a_bad_security_string_is_invalid_input() {
        let b = binding(&[Surface::Email]);
        let mut host = AdminHost::new(Some(&b));
        let err = host
            .email_set(
                "default".into(),
                admin_types::EmailProfile {
                    host: Some("h".into()),
                    port: None,
                    security: Some("bogus".into()),
                    username: None,
                    password: None,
                    from: Some("a@b.com".into()),
                    durable: None,
                    clear_auth: false,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, admin_types::AdminError::InvalidInput(_)));
    }
}
