//! Server-side wiring for the host-mediated guest **egress self-register** capability
//! (`boatramp:handlers/egress-register`, PLAN-egress-runtime-authz #12, Surface 2). The guest-facing
//! companion to the control-plane `HandlerPolicy·Write` overlay edit: a granted, posture-ON guest
//! REPLACE-SETs the `host:port`s its OWN workload may dial, written to the SAME `handlers.egress_allow`
//! site-config overlay the control-plane PUT edits.
//!
//! This module supplies the concrete [`EgressRegisterWriter`]: it validates every entry's grammar
//! (the SAME `validate_static_egress_entry` the PUT uses) + the register-time SSRF floor, then persists
//! via [`DeployStore::update_handlers_egress_overlay`] (a lock-atomic read-modify-write that converges
//! concurrent DIFFERENT-workload self-registers). [`maybe_attach`] BAKES this invocation's OWN
//! per-workload key into the writer at `build_bindings`, so a guest can set ONLY its own workload's
//! overlay (it supplies only the host set, never a key). The UNCHANGED dial-time `is_global_ip` floor
//! stays authoritative regardless.

use std::sync::Arc;

use boatramp_core::deploy::DeployStore;
use boatramp_core::project::ProjectRef;
use boatramp_handlers::{Bindings, EgressRegisterWriteError, EgressRegisterWriter};

use crate::HandlerRuntimeInner;

/// The persistence seam the writer replace-sets through: an object-safe `replace(project, site,
/// workload, hosts)`. Production is [`DeployStorePersist`] (the lock-atomic overlay RMW); a test injects
/// a recording mock so the per-workload-scope gate can observe the EXACT key written.
#[async_trait::async_trait]
trait EgressOverlayPersist: Send + Sync {
    async fn replace(
        &self,
        project: &str,
        site: &str,
        workload: &str,
        hosts: Vec<String>,
    ) -> Result<(), String>;
}

/// Production persistence: the lock-atomic, convergent per-workload overlay RMW on the deploy store.
struct DeployStorePersist(DeployStore);

#[async_trait::async_trait]
impl EgressOverlayPersist for DeployStorePersist {
    async fn replace(
        &self,
        project: &str,
        site: &str,
        workload: &str,
        hosts: Vec<String>,
    ) -> Result<(), String> {
        self.0
            .update_handlers_egress_overlay(ProjectRef::new(project), site, workload, hosts)
            .await
            .map_err(|e| e.to_string())
    }
}

/// The host-held egress-overlay writer, BAKED to ONE `(project, site, workload)` at construction. The
/// guest supplies only the host set; this writer forces the scope — so a guest can set ONLY its own
/// workload's overlay, never another's.
struct DeployEgressWriter {
    persist: Arc<dyn EgressOverlayPersist>,
    project: String,
    site: String,
    workload: String,
}

#[async_trait::async_trait]
impl EgressRegisterWriter for DeployEgressWriter {
    async fn set_egress(&self, hosts: Vec<String>) -> Result<(), EgressRegisterWriteError> {
        // Validate EVERY entry (grammar + register-time SSRF floor) BEFORE persisting — all-or-nothing,
        // so one bad entry writes NOTHING.
        for entry in &hosts {
            validate_register_entry(entry).map_err(EgressRegisterWriteError::InvalidEntry)?;
        }
        // The write key is ALWAYS this writer's baked workload — never guest-influenced. `effective_key`
        // folds to `&self.workload` in every shipped build; the test-only mutation seam swaps a DIFFERENT
        // key so the per-workload-scope gate can prove the baked key is load-bearing.
        let key = self.effective_key();
        self.persist
            .replace(&self.project, &self.site, key, hosts)
            .await
            .map_err(EgressRegisterWriteError::Backend)
    }

    fn workload_key(&self) -> &str {
        &self.workload
    }
}

impl DeployEgressWriter {
    /// The `egress_allow` key the write targets: ALWAYS this writer's baked per-workload key. The
    /// `#[cfg(test)]` mutation seam (`BOATRAMP_EGRESSREG_MUTATION=cross_workload`) swaps a different key
    /// so the per-workload-scope gate goes RED when the baked-key scoping is neutered — proving it
    /// load-bearing. A shipped build has no seam (folds to `&self.workload`).
    fn effective_key(&self) -> &str {
        #[cfg(test)]
        if std::env::var("BOATRAMP_EGRESSREG_MUTATION").as_deref() == Ok("cross_workload") {
            return "__mutation_other_workload__";
        }
        &self.workload
    }
}

/// Register-time validation for one `host:port` entry: the SAME grammar lint the control-plane PUT uses
/// (`validate_static_egress_entry`) + the SSRF floor for IP/CIDR **literals** (an internal / metadata /
/// RFC1918 / loopback literal is refused at register, fail-loud). A hostname's floor is enforced
/// authoritatively at DIAL time (`is_global_ip` per resolved address) — unchanged; register-time is
/// defense-in-depth for the literal case (a guest cannot name a non-global literal at register).
fn validate_register_entry(entry: &str) -> Result<(), String> {
    boatramp_core::config::validate_static_egress_entry(entry).map_err(|e| e.to_string())?;
    let target = entry.rsplit_once(':').map_or(entry, |(t, _)| t);
    let target = target.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = target.parse::<std::net::IpAddr>()
        && !boatramp_core::access::is_global_ip(ip)
    {
        return Err(format!(
            "{entry}: internal/non-global address refused by the SSRF floor"
        ));
    } else if let Ok(net) = target.parse::<ipnet::IpNet>()
        && !boatramp_core::access::is_global_ip(net.network())
    {
        return Err(format!(
            "{entry}: internal/non-global CIDR refused by the SSRF floor"
        ));
    }
    Ok(())
}

/// Attach the `egress-register` binding to `bindings` when the workload is GRANTED the capability (it
/// declares the `egress-register` import AND the site `allow_imports` permits it) and a per-runtime
/// deploy store is available. The writer is BAKED to this invocation's OWN `workload_key` — the SAME
/// key the dial's egress-overlay union reads (so the write and the dial cannot drift). Ungranted / no
/// store ⇒ returned unchanged (the host still links the interface; `set-egress` ⇒ `access-denied`).
pub(crate) fn maybe_attach(
    bindings: Bindings,
    inner: &HandlerRuntimeInner,
    project: ProjectRef<'_>,
    site: &str,
    workload_key: &str,
    imports: &[String],
    allow_imports: &[String],
) -> Bindings {
    // Grant = declared import ∩ site `allow_imports` ceiling (the same rule `build_bindings` uses).
    let granted = imports.iter().any(|i| i == "egress-register")
        && allow_imports.iter().any(|a| a == "egress-register");
    if !granted {
        return bindings;
    }
    // The per-runtime deploy store (held by the startup-wired invoker). Absent ⇒ fail-closed: no
    // writer ⇒ no binding ⇒ `set-egress` is `access-denied` (the interface is still linked).
    let Some(deploy) = inner.invoker.get().map(|inv| inv.deploy_store().clone()) else {
        return bindings;
    };
    let writer = Arc::new(DeployEgressWriter {
        persist: Arc::new(DeployStorePersist(deploy)),
        project: project.as_str().to_string(),
        site: site.to_string(),
        workload: workload_key.to_string(),
    });
    bindings.with_egress_register(writer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A recording persistence mock: captures the EXACT `(workload, hosts)` the writer replace-set, so
    /// the per-workload-scope gate can assert the write targeted ONLY the baked key.
    #[derive(Default)]
    struct RecordingPersist {
        writes: Mutex<Vec<(String, Vec<String>)>>,
    }
    #[async_trait::async_trait]
    impl EgressOverlayPersist for RecordingPersist {
        async fn replace(
            &self,
            _project: &str,
            _site: &str,
            workload: &str,
            hosts: Vec<String>,
        ) -> Result<(), String> {
            self.writes
                .lock()
                .unwrap()
                .push((workload.to_string(), hosts));
            Ok(())
        }
    }

    fn writer(persist: Arc<RecordingPersist>, workload: &str) -> DeployEgressWriter {
        DeployEgressWriter {
            persist,
            project: "acme".into(),
            site: "web".into(),
            workload: workload.into(),
        }
    }

    /// Gate 7a — PER-WORKLOAD-SCOPE (anti-hollow / mutation-verified). The writer BAKED to workload
    /// `/fetch` replace-sets ONLY `egress_allow[/fetch]` — the guest supplied no key, so it can never
    /// reach another workload's overlay. The assertion `key == "/fetch"` is UNCONDITIONAL: a shipped
    /// build passes; re-running under `BOATRAMP_EGRESSREG_MUTATION=cross_workload` neuters the baked
    /// key (the write then targets a DIFFERENT workload) and this gate goes RED — proving the baked-key
    /// scoping is load-bearing (a hollow gate would stay green under the mutation).
    #[tokio::test]
    async fn per_workload_scope_write_targets_only_the_baked_key() {
        let persist = Arc::new(RecordingPersist::default());
        let w = writer(persist.clone(), "/fetch");
        w.set_egress(vec!["imap.gstruct.com:993".into()])
            .await
            .expect("a valid replace-set succeeds");
        let writes = persist.writes.lock().unwrap();
        assert_eq!(writes.len(), 1, "exactly one persist");
        let (key, hosts) = &writes[0];
        assert_eq!(
            hosts,
            &vec!["imap.gstruct.com:993".to_string()],
            "the host set is passed through"
        );
        // The write is scoped to EXACTLY the baked workload key — never a guest-influenced or sibling
        // key. Under the `cross_workload` mutation seam this FAILS (the seam targets another workload),
        // confirming the scope is enforced here and not elsewhere.
        assert_eq!(
            key, "/fetch",
            "the write must target ONLY the baked workload key"
        );
    }

    /// The register-time gate: an invalid entry (grammar or SSRF floor) refuses the WHOLE set — nothing
    /// is persisted (all-or-nothing), so a guest cannot sneak an internal target past register.
    #[tokio::test]
    async fn invalid_entry_refuses_whole_set_without_persisting() {
        let persist = Arc::new(RecordingPersist::default());
        let w = writer(persist.clone(), "/fetch");
        // One good + one internal-metadata entry ⇒ the whole set is refused, nothing persisted.
        let err = w
            .set_egress(vec![
                "imap.gstruct.com:993".into(),
                "169.254.169.254:80".into(),
            ])
            .await
            .expect_err("an internal entry must refuse the set");
        assert!(matches!(err, EgressRegisterWriteError::InvalidEntry(_)));
        assert_eq!(
            persist.writes.lock().unwrap().len(),
            0,
            "nothing is persisted on a bad set"
        );
    }

    #[test]
    fn register_entry_validation_grammar_and_ssrf_floor() {
        // Grammar + register-time SSRF floor (the literal case).
        for ok in [
            "imap.gstruct.com:993",
            "93.184.216.34:443",
            "93.184.0.0/16:443",
        ] {
            validate_register_entry(ok).unwrap_or_else(|e| panic!("{ok:?} must validate: {e}"));
        }
        // Malformed grammar.
        for bad in ["no-port", "host:0", ":443"] {
            assert!(
                validate_register_entry(bad).is_err(),
                "{bad:?} grammar must be rejected"
            );
        }
        // Internal / metadata / RFC1918 / loopback LITERALS refused at register by the SSRF floor.
        for internal in [
            "169.254.169.254:80",
            "10.0.0.5:5432",
            "127.0.0.1:993",
            "10.0.0.0/8:5432",
        ] {
            assert!(
                validate_register_entry(internal).is_err(),
                "{internal:?} must be refused by the register-time SSRF floor"
            );
        }
    }
}
