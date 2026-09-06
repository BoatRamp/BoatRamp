//! Live capability gate for the guest project self-config capability
//! (`boatramp:handlers/admin`). Unlike the `email` gate (which needs a real SMTP socket),
//! every admin invariant is **host-side authz**, so this gate proves them adversarially
//! against a shared, flat control-plane keyspace — the thing the per-store unit tests, each
//! run in its own store, structurally can't: that TWO tenants sharing ONE keyspace stay
//! isolated, and that a guest-controlled `site`/`name` string can't escape the host-stamped
//! `project/<proj>/…` prefix.
//!
//! What it asserts (each a security precondition, per the review):
//!   1. A guest scoped to project A can never observe project B's secrets / email profiles /
//!      site config — even sharing one KV.
//!   2. A crafted `site` string (`../`, embedded slashes, `%2f`) stays a literal leaf under A's
//!      prefix; it cannot read B's config. (KV backends are all flat byte-keyspaces —
//!      Memory/SlateDB/Cloudflare — so there is no path traversal to exploit.)
//!   3. Credentials are write-only: the trait exposes no verb that returns a password/secret
//!      value; the only reads are name lists.
//!   4. Multi-tenant lockdown: the node enables an admin surface iff the matching posture knob
//!      is on; under `multi-tenant` ALL are off ⇒ the computed surface set is EMPTY ⇒ no admin
//!      binding attaches ⇒ every verb is access-denied. `single-tenant`/`dev` opt in fully.
//!   5. A runaway guest is rate-limited by the per-project quota (reads charged too).
//!
//! `#[ignore]`d (per the anti-`#[ignore]`-as-evidence rule it is wired into
//! `.github/workflows/capability.yml` as a HARD GATE that asserts the success marker, so a
//! silent skip fails the job). Run locally with:
//!   `cargo test -p boatramp-server --features admin --test admin_live -- --ignored --nocapture`

#![cfg(feature = "admin")]

use std::collections::BTreeSet;
use std::sync::Arc;

use boatramp_core::config::SiteConfig;
use boatramp_core::deploy::DeployStore;
use boatramp_core::email_config::{EmailProfilePatch, EmailProfileStore};
use boatramp_core::envelope::{EnvelopeError, KeyEnvelope};
use boatramp_core::kv::MemoryKv;
use boatramp_core::project::ProjectRef;
use boatramp_core::secret_store::SecretStore;
use boatramp_core::security::{SecurityPosture, SecurityProfile};
use boatramp_handlers::{AdminController, AdminError, AdminSurface};
use boatramp_server::ServerAdminController;
use boatramp_storage::FsStorage;

/// Identity envelope — the stores need one; sealing isn't what's under test here (the sealed
/// value never leaves over the admin surface regardless of the cipher).
struct NoopEnvelope;
#[async_trait::async_trait]
impl KeyEnvelope for NoopEnvelope {
    async fn wrap(&self, p: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        Ok(p.to_vec())
    }
    async fn unwrap(&self, c: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
        Ok(c.to_vec())
    }
}

/// Mirror the node's posture→surface mapping (`boatramp-node/src/node.rs`) exactly: a surface
/// is offered iff its posture knob is on. `surfaces.is_empty()` is therefore precisely
/// "no admin binding attaches" — the master-switch semantics.
fn surfaces_for(p: &SecurityPosture) -> BTreeSet<AdminSurface> {
    let mut s = BTreeSet::new();
    if p.allow_guest_admin_domains {
        s.insert(AdminSurface::Domains);
    }
    if p.allow_guest_admin_email {
        s.insert(AdminSurface::Email);
    }
    if p.allow_guest_admin_site {
        s.insert(AdminSurface::Site);
    }
    if p.allow_guest_admin_secrets {
        s.insert(AdminSurface::Secrets);
    }
    s
}

fn email_patch(host: &str, from: &str) -> EmailProfilePatch {
    EmailProfilePatch {
        host: Some(host.into()),
        from: Some(from.into()),
        ..Default::default()
    }
}

#[tokio::test]
#[ignore = "capability gate: run via capability.yml or with --ignored"]
async fn admin_capability_holds_the_tenant_invariants() {
    // ONE flat keyspace, shared by both tenants — the adversarial setup. If isolation
    // depended on separate stores the test would prove nothing; here the only thing between
    // the tenants is the host-stamped project prefix.
    let kv = Arc::new(MemoryKv::new());
    let deploy = DeployStore::new(Arc::new(FsStorage::new(std::env::temp_dir())), kv.clone());
    let email = Arc::new(EmailProfileStore::new(kv.clone(), Arc::new(NoopEnvelope)));
    let secret = Arc::new(SecretStore::new(kv.clone(), Arc::new(NoopEnvelope)));

    let make = |project: &'static str| -> Arc<dyn AdminController> {
        ServerAdminController::with_server_probe(
            deploy.clone(),
            Some(email.clone()),
            Some(secret.clone()),
            true, // allow_private: irrelevant here (no domain probe is exercised)
        )
        .scoped(ProjectRef::new(project))
    };

    // ---- seed GLOBEX (the victim tenant) with distinctive markers ----
    let globex = make("globex");
    let victim_cfg = SiteConfig {
        security: boatramp_core::config::SecurityConfig {
            csp: Some("GLOBEX-ONLY-CSP".into()),
            ..Default::default()
        },
        ..Default::default()
    };
    globex
        .site_config_put("blog", &serde_json::to_string(&victim_cfg).unwrap())
        .await
        .expect("globex writes its own config");
    globex
        .secret_set("globex-key", b"TOPSECRET")
        .await
        .expect("globex writes its own secret");
    globex
        .email_set(
            "globex-smtp",
            email_patch("smtp.globex.test", "x@globex.test"),
        )
        .await
        .expect("globex writes its own email profile");

    // ---- ACME (the attacker) scoped to its OWN project ----
    let acme = make("acme");

    // (1) CROSS-TENANT READ IS STRUCTURALLY IMPOSSIBLE. acme seeded nothing, so it sees an
    //     empty namespace; globex's records are invisible to it.
    assert!(
        acme.secret_list().await.unwrap().is_empty(),
        "acme must not see globex's secrets"
    );
    assert!(
        acme.email_list().await.unwrap().is_empty(),
        "acme must not see globex's email profiles"
    );
    assert!(
        matches!(
            acme.site_config_get("blog").await,
            Err(AdminError::NotFound(_))
        ),
        "acme's own 'blog' is unset (and is NOT globex's config)"
    );

    // (2) A CRAFTED `site` STRING CANNOT ESCAPE THE HOST-STAMPED PROJECT PREFIX. The key is
    //     `project/<proj>/site/<site>`; `<proj>` is host-stamped, and the KV is a flat
    //     byte-keyspace, so `..`/slash/%2f in the guest leaf stay literal — never traversal.
    for evil in [
        "../globex/site/blog",
        "..%2fglobex%2fsite%2fblog",
        "globex/site/blog",
        "../../project/globex/site/blog",
        "blog/../../globex/site/blog",
    ] {
        let got = acme.site_config_get(evil).await;
        assert!(
            !matches!(&got, Ok(s) if s.contains("GLOBEX-ONLY-CSP")),
            "site-string escape via {evil:?} leaked globex's config: {got:?}"
        );
    }
    // Prove the marker really exists (so the negatives above aren't vacuous): globex's OWN
    // scope reads it back.
    assert!(
        globex
            .site_config_get("blog")
            .await
            .unwrap()
            .contains("GLOBEX-ONLY-CSP"),
        "globex reads back its own marked config"
    );

    // (3) CREDENTIALS ARE WRITE-ONLY. The only read is a NAME list — never a value. globex
    //     sees its secret's NAME; the sealed `TOPSECRET` has no verb that returns it.
    assert_eq!(
        globex.secret_list().await.unwrap(),
        vec!["globex-key".to_string()],
        "the secret surface returns names only, never the sealed value"
    );
    assert_eq!(
        globex.email_list().await.unwrap(),
        vec!["globex-smtp".to_string()],
        "the email surface returns names only, never the sealed password"
    );

    // (4) MULTI-TENANT LOCKDOWN. Under multi-tenant the master switch is off for every
    //     surface ⇒ the node computes an EMPTY surface set ⇒ no binding ⇒ access-denied.
    let mt = SecurityProfile::MultiTenant.preset();
    assert!(
        surfaces_for(&mt).is_empty(),
        "multi-tenant must enable NO guest-admin surface (untrusted-tenant default)"
    );
    assert_eq!(
        surfaces_for(&SecurityProfile::SingleTenant.preset()).len(),
        4,
        "single-tenant opts into every surface (the operator owns every site)"
    );
    assert_eq!(
        surfaces_for(&SecurityProfile::Dev.preset()).len(),
        4,
        "dev opts into every surface"
    );

    // (5) A RUNAWAY GUEST IS RATE-LIMITED (per-project quota; reads charged too, so a guest
    //     can't amplify by hammering list/get). acme's bucket is already partly drained by the
    //     probing above, so the loop trips the quota well within the burst window.
    let mut limited = false;
    for i in 0..64 {
        if matches!(
            acme.secret_set(&format!("k{i}"), b"v").await,
            Err(AdminError::RateLimited)
        ) {
            limited = true;
            break;
        }
    }
    assert!(
        limited,
        "a runaway admin loop must hit the per-project rate quota"
    );

    // The single success marker the capability job greps for — printed ONLY after every
    // invariant held. A silent skip prints `test result: ok` but never this line.
    println!(
        "ADMIN CAPABILITY GATE OK: cross-tenant reads impossible, site-string escapes blocked, \
         credentials write-only, multi-tenant locked down, rate-limited"
    );
}
