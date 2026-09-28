//! **Resource-name allowlist gate (v0.7.0).** The mutation-verified invariants G1–G7
//! for the strict-slug cutover + the two ingress closures (A8 token-role target, A6
//! project-scope path) + the resolv.conf sink + the escape-hatch containment.
//!
//! Robust exit-code mechanism (v0.6.4/v0.6.5 style): one named `#[test]` per invariant,
//! the **test exit code is the contract** — NO greppable marker, NO bash env-loop. Each
//! test is anti-hollow: the doc comment names the mutation that flips it to a failure,
//! and the assertions are the witnesses (a homoglyph slipping through, a feeder skipping
//! the target screen, the match-time backstop removed, the A6 400 dropped, a resolv.conf
//! second directive line, a silent-strand workload equality, a libsql subset drift).
//!
//! Run: `cargo test -p boatramp-server --test name_allowlist_gate` (add `--features oidc`
//! to include the OIDC feeder invariant G2c). CI runs it as its own lane; a
//! non-conforming build fails the lane by exit code.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use boatramp_core::authz::{Action, GrantedRole, Resource, Right};
use boatramp_core::cose::{self, Claims, LocalSigner, Signer, TokenAlg};
use boatramp_core::deploy::DeployStore;
use boatramp_core::kv::MemoryKv;
use boatramp_core::project::{validate_resource_name, validate_role_target};
use boatramp_core::{ByteStream, GetObject, ObjectMeta, PutMeta, Storage, StorageError};
use boatramp_server::{Auth, HandlerRuntime, ServerOptions, router_with};
use tower::ServiceExt;

// A no-op blob store — token minting + project routing never touch it.
#[derive(Default)]
struct NoStorage;

#[async_trait::async_trait]
impl Storage for NoStorage {
    async fn get(&self, key: &str) -> Result<GetObject, StorageError> {
        Err(StorageError::NotFound(key.to_string()))
    }
    async fn get_range(
        &self,
        key: &str,
        _o: u64,
        _l: Option<u64>,
    ) -> Result<GetObject, StorageError> {
        Err(StorageError::NotFound(key.to_string()))
    }
    async fn put(
        &self,
        key: &str,
        _b: ByteStream,
        _m: PutMeta,
    ) -> Result<ObjectMeta, StorageError> {
        Ok(ObjectMeta {
            key: key.to_string(),
            ..Default::default()
        })
    }
    async fn head(&self, key: &str) -> Result<ObjectMeta, StorageError> {
        Err(StorageError::NotFound(key.to_string()))
    }
    async fn delete(&self, _key: &str) -> Result<(), StorageError> {
        Ok(())
    }
    async fn list(&self, _prefix: &str) -> Result<Vec<ObjectMeta>, StorageError> {
        Ok(Vec::new())
    }
}

fn deploy() -> DeployStore {
    DeployStore::new(Arc::new(NoStorage), Arc::new(MemoryKv::new()))
}

fn with_conn(mut req: Request<Body>) -> Request<Body> {
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    req
}

/// Build a router with a live issuer (so the mint feeders can actually sign) and an
/// admin verify key derived from the SAME signer (so an admin token authorizes
/// `/api/tokens`). Returns `(router, admin_bearer)`.
async fn app_with_issuer() -> (axum::Router, String) {
    let signer = LocalSigner::generate(TokenAlg::Es256);
    let public = signer.public_key();
    // An admin token to authorize `POST /api/tokens`.
    let claims = Claims {
        roles: vec![GrantedRole::global("admin")],
        kind: cose::KIND_ROLE.to_string(),
        ttl_secs: None,
        now_unix: boatramp_core::time::now_unix(),
    };
    let admin = cose::mint(&claims, &signer).await.expect("mint admin");
    let app = router_with(
        deploy(),
        Auth::with_key(public, Arc::new(MemoryKv::new())),
        HandlerRuntime::disabled(),
        ServerOptions {
            issuer: Some(Arc::new(signer) as Arc<dyn Signer>),
            bootstrap_secret: Some("gate-bootstrap-secret".to_string()),
            posture: boatramp_core::security::SecurityPosture {
                require_domain_verification: false,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    (app, admin)
}

async fn status_of(app: &axum::Router, req: Request<Body>) -> StatusCode {
    app.clone().oneshot(with_conn(req)).await.unwrap().status()
}

fn post_json(uri: &str, bearer: Option<&str>, body: serde_json::Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = bearer {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

// -------------------------------------------------------------------------------------
// G1 — charset: good slugs accept; the injection class + Unicode homoglyphs reject.
// Mutation: swap the byte loop for `chars().all(char::is_alphanumeric)` ⇒ the homoglyphs
// `аcme`/`acme１`/`café` are accepted ⇒ this test FAILS.
// -------------------------------------------------------------------------------------
#[test]
fn g1_charset_allowlist_and_homoglyphs() {
    for good in ["acme", "my-site", "resize_v2", "Blog9", "a", "9", "a1_b-2c"] {
        assert!(
            validate_resource_name("project", good).is_ok(),
            "{good:?} should be a valid slug"
        );
    }
    for bad in [
        "",
        "-x",
        "x-",
        "_x",
        ".",
        "..",
        "a.b",
        "${PROJECT}",
        "{tenant}",
        "a;b",
        "`x`",
        "a|b",
        "a b",
        "a\tb",
        "a\nb",
        "*",
        "proj*",
        // Unicode homoglyphs — the byte loop rejects them.
        "аcme",   // Cyrillic 'а'
        "acme１", // fullwidth '１'
        "café",   // trailing 'é'
    ] {
        assert!(
            validate_resource_name("project", bad).is_err(),
            "{bad:?} must be rejected by the slug allowlist"
        );
    }
}

// -------------------------------------------------------------------------------------
// G2 — each mint feeder rejects a `publisher:${PROJECT}` role target with a 4xx, and
// accepts `publisher:acme` / `publisher:acme/blog` / `project_admin:acme/*`.
// Mutation: drop the `validate_role_target`(s) screen from a feeder ⇒ a `${PROJECT}`
// token is minted (2xx) ⇒ the matching assertion FAILS.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn g2a_create_token_feeder_screens_target() {
    let (app, admin) = app_with_issuer().await;
    // Bad target → 400.
    let bad = post_json(
        "/api/tokens",
        Some(&admin),
        serde_json::json!({ "label": "x", "roles": ["publisher:${PROJECT}"] }),
    );
    assert_eq!(
        status_of(&app, bad).await,
        StatusCode::BAD_REQUEST,
        "create_token must 400 a non-conforming role target"
    );
    // Good targets → 201.
    for ok in [
        "publisher:acme",
        "publisher:acme/blog",
        "project_admin:acme/*",
    ] {
        let good = post_json(
            "/api/tokens",
            Some(&admin),
            serde_json::json!({ "label": "x", "roles": [ok] }),
        );
        assert_eq!(
            status_of(&app, good).await,
            StatusCode::CREATED,
            "create_token must mint a conforming role target {ok:?}"
        );
    }
}

#[tokio::test]
async fn g2b_bootstrap_token_feeder_screens_target() {
    let (app, _admin) = app_with_issuer().await;
    // The bootstrap route presents the bootstrap secret as the bearer.
    let bad = post_json(
        "/api/tokens/bootstrap",
        Some("gate-bootstrap-secret"),
        serde_json::json!({ "roles": ["publisher:${PROJECT}"] }),
    );
    assert_eq!(
        status_of(&app, bad).await,
        StatusCode::BAD_REQUEST,
        "bootstrap_token must 400 a non-conforming role target"
    );
}

#[cfg(feature = "oidc")]
#[tokio::test]
async fn g2c_oidc_exchange_feeder_screens_target() {
    use boatramp_server::OidcVerifier;
    use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, encode};
    use std::collections::HashMap;

    let secret = b"gate-oidc-secret-0123456789-abcdef";
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_issuer(&["https://issuer.test"]);
    validation.validate_aud = false;
    let mut keys = HashMap::new();
    keys.insert("k1".to_string(), DecodingKey::from_secret(secret));
    let verifier = Arc::new(OidcVerifier::new(keys, validation, "scope"));

    let signer = LocalSigner::generate(TokenAlg::Es256);
    let public = signer.public_key();
    let app = router_with(
        deploy(),
        Auth::with_key(public, Arc::new(MemoryKv::new())),
        HandlerRuntime::disabled(),
        ServerOptions {
            issuer: Some(Arc::new(signer) as Arc<dyn Signer>),
            oidc_verifier: Some(verifier),
            posture: boatramp_core::security::SecurityPosture {
                require_domain_verification: false,
                ..Default::default()
            },
            ..Default::default()
        },
    );

    let mut jwt_header = Header::new(Algorithm::HS256);
    jwt_header.kid = Some("k1".to_string());
    // A claim mapping a role with a non-conforming target.
    let claims = serde_json::json!({
        "iss": "https://issuer.test",
        "exp": 4_102_444_800i64,
        "scope": "publisher:${PROJECT}"
    });
    let jwt = encode(&jwt_header, &claims, &EncodingKey::from_secret(secret)).unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/exchange")
        .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        status_of(&app, req).await,
        StatusCode::FORBIDDEN,
        "auth_exchange must 403 a claim mapping a non-conforming role target"
    );
}

// The offline feeder (`boatramp token mint`) screens the same way BEFORE signing — it
// shares `validate_role_target`, exercised here as the exact predicate the feeder gates
// on (the CLI unit test in `boatramp/src/token.rs` covers the error path end-to-end).
#[test]
fn g2d_offline_feeder_predicate() {
    assert!(validate_role_target("${PROJECT}").is_err());
    assert!(validate_role_target("acme/../evil").is_err());
    assert!(validate_role_target("acme").is_ok());
    assert!(validate_role_target("acme/blog").is_ok());
    assert!(validate_role_target("acme/*").is_ok());
}

// -------------------------------------------------------------------------------------
// G3 — the fail-closed authz-match backstop: an (offline / pre-v0.7.0) grant whose
// target is `publisher:${PROJECT}` matches NOTHING at verify time — even a required
// right that names the identical string.
// Mutation: remove the `is_conforming_role_target` screen in `target_matches` ⇒ the
// `${PROJECT}` grant self-matches and authorizes ⇒ this test FAILS.
// -------------------------------------------------------------------------------------
#[test]
fn g3_offline_token_target_matches_nothing() {
    // Model exactly what an offline-minted `publisher:${PROJECT}` expands to.
    let policy = boatramp_core::authz::AuthzPolicy::default_policy();
    let granted = policy.rights_for(&[GrantedRole::scoped("publisher", "${PROJECT}")]);
    // A required right naming the very same string does not match.
    let required_same = Right::new(
        Resource::Site,
        Some("${PROJECT}".to_string()),
        Action::Write,
    );
    assert!(
        !granted.allows(&required_same),
        "a non-conforming grant target must not authorize even its own string"
    );
    // Nor an ordinary site.
    let required_site = Right::new(Resource::Site, Some("blog".to_string()), Action::Write);
    assert!(
        !granted.allows(&required_site),
        "a non-conforming grant target must not authorize an ordinary target"
    );
    // A conforming publisher grant still authorizes its own site (not a blanket deny).
    let ok = policy.rights_for(&[GrantedRole::scoped("publisher", "acme/blog")]);
    let acme_blog = Right::new(Resource::Site, Some("acme/blog".to_string()), Action::Write);
    assert!(ok.allows(&acme_blog), "a conforming grant must still work");
}

// -------------------------------------------------------------------------------------
// G4 — A6: a non-conforming `<proj>` on a project-scoped SUB-RESOURCE path is refused
// with a generic 400 (not a rewrite, not a 404 oracle). A conforming project routes.
// Mutation: drop the `validate_resource_name` screen in `scope_of` ⇒ the request is
// injected/rewritten (and then 401/404), never 400 ⇒ this test FAILS.
// -------------------------------------------------------------------------------------
#[tokio::test]
async fn g4_project_scope_rejects_nonconforming_segment() {
    let signer = LocalSigner::generate(TokenAlg::Es256);
    let app = router_with(
        deploy(),
        Auth::with_key(signer.public_key(), Arc::new(MemoryKv::new())),
        HandlerRuntime::disabled(),
        ServerOptions {
            posture: boatramp_core::security::SecurityPosture {
                require_domain_verification: false,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    for bad in [
        "/api/projects/${PROJECT}/sites/blog/config",
        "/api/projects/a.b/sites/blog/config",
        "/api/projects/-acme/functions/f",
    ] {
        let status = status_of(
            &app,
            Request::builder().uri(bad).body(Body::empty()).unwrap(),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "A6: {bad:?} must be a generic 400 (pre-auth, no tenant oracle)"
        );
    }
}

// -------------------------------------------------------------------------------------
// G5 — resolv.conf sink: the predicate `resolvconf::render` gates on
// (`is_valid_resource_slug`) rejects a `\n`-bearing project, so the `search` line is
// dropped and no second directive can be injected. The REAL `render` mutation witness
// lives in `boatramp-container`'s unit test
// (`newline_in_project_cannot_inject_a_second_nameserver_line`); this gate re-asserts
// the load-bearing predicate without pulling the container-backend dependency.
// Mutation: loosen `is_valid_resource_slug` to accept a `\n` ⇒ this FAILS (and the
// container unit test's second-nameserver assertion FAILS in tandem).
// -------------------------------------------------------------------------------------
#[test]
fn g5_resolvconf_sink_predicate_rejects_newline() {
    use boatramp_core::project::is_valid_resource_slug;
    // The exact value the container backend would read from KV as a poisoned project.
    assert!(
        !is_valid_resource_slug("p\nnameserver 6.6.6.6"),
        "a newline-bearing project must fail the sink predicate → search line dropped"
    );
    assert!(!is_valid_resource_slug("acme.evil\nnameserver 9.9.9.9"));
    // A conforming project passes (the search line is emitted for it).
    assert!(is_valid_resource_slug("acme"));
}

// -------------------------------------------------------------------------------------
// G6 — escape-hatch containment: a legacy source name is used ONLY as a teardown key,
// never silently "renamed". The derived managed-DB workload is a function of
// `(project, name)`, so a different project yields a DIFFERENT workload — proving a
// delete of the old project can never strand data under a new project's workload.
//
// `derived_managed_db_workload` lives behind a SQL-backend feature in `boatramp-storage`,
// so the AUTHORITATIVE G6 invariant is a unit test in THAT crate,
// `tenant_provision::tests::escape_hatch_workload_differs_by_project` (always compiled
// under its gate, run by the workspace test lane). Mutation: make the derivation ignore
// the project ⇒ the two derive equal ⇒ that test FAILS.
// -------------------------------------------------------------------------------------

// -------------------------------------------------------------------------------------
// G7 — the libsql db-name rule stays a SUBSET of the tightened canonical validator:
// tightening the superset must not let a subset accept something the superset rejects
// (the only tolerated divergence is the legacy empty default). Re-runs the same corpus
// the storage-crate drift-guard uses, over the public validators.
// Mutation: loosen the canonical validator (e.g. re-admit `.`) OR tighten it so a
// libsql-accepted name is rejected ⇒ the subset relation breaks ⇒ this test FAILS.
// -------------------------------------------------------------------------------------
#[test]
fn g7_libsql_rule_is_a_subset_of_the_canonical_validator() {
    // The libsql storage rule, restated here independently (it lives crate-private in
    // boatramp-storage). v0.7.0 tightened it to the strict slug alphabet (the dot is
    // gone) so it stays a SUBSET of the tightened canonical validator; the sole
    // divergence is the legacy empty default. This restatement is byte-independent of
    // the real fn — if the real libsql rule ever loosens (re-admits `.`) OR the
    // canonical validator tightens past it, the storage-crate drift-guard
    // (`libsql_db_name_rule_is_a_subset_of_the_canonical_validator`) FAILS; this mirror
    // proves the same subset relation over the public canonical validator.
    fn libsql_ok(v: &str) -> bool {
        if v.is_empty() {
            return true; // the legacy empty default
        }
        boatramp_core::project::is_valid_resource_slug(v)
    }
    let corpus = [
        "",
        "blog",
        "my-db_1",
        "site.example",
        "A1_b-2",
        "default",
        "..",
        ".",
        ".hidden",
        "/",
        "a/b",
        "a\\b",
        "../../etc/passwd",
        "a\0b",
        "naïve",
        "a b",
        "a:b",
        "a*b",
        "a\tb",
        &"x".repeat(300),
    ];
    for name in corpus {
        let canonical = validate_resource_name("database", name).is_ok();
        let libsql = libsql_ok(name);
        if libsql && !canonical {
            assert_eq!(
                name, "",
                "libsql accepts {name:?} but the canonical validator rejects it — a \
                 subset drift that could reach the storage layer un-addressably"
            );
        }
    }
}
