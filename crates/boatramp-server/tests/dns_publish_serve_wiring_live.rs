//! Serve-path e2e gate for the guest **`dns-publish` (write)** capability's SERVE WIRING (cap-req #25
//! — the inert-ship fix for #24 WS3).
//!
//! # Why this gate exists (the bug it reproduces)
//! v0.51.0 shipped the guest `dns-publish` capability, the 3-layer host gate, and 11 provider adapters,
//! but NOTHING installed a provider source into the serve binding seam
//! ([`boatramp_server::dns_publish::install_provider_source`]). So `provider_source()` was always
//! `None`, [`boatramp_server::dns_publish`]'s `maybe_attach` attached NO binding, and EVERY guest
//! `dns-publish` call fail-closed to `access-denied` — in dev AND production. The ONLY existing test
//! (`boatramp-handlers/tests/dns_publish_live.rs`) passed because it built `Bindings::with_dns_publish`
//! DIRECTLY, bypassing the serve binding seam entirely.
//!
//! This gate does NOT bypass the seam. It drives the REAL serving pipeline — `router()` →
//! `serve_sites` → `handler_dispatch` → `build_handler_bindings` → `maybe_attach` → `provider_source()`
//! — with a REAL compiled guest component (`dns-publish-writer.wasm`) that imports
//! `boatramp:handlers/dns-publish`, and proves the whole install→dispatch→write→capture path at that
//! seam, in TWO arms in one process:
//!
//!   1. **INERT arm (NO provider source installed — exactly today's shipped serve)**: a granted,
//!      in-zone, posture-ON guest write returns `access-denied` and the provider captures NOTHING. This
//!      reproduces the v0.51.0 inert-failure shape at the real serve seam — it is the state a serve
//!      binary that never calls `install_provider_source` is in.
//!   2. **WIRED arm (after `install_provider_source`, the EXACT call `boatramp serve`'s boot wiring now
//!      makes — see `boatramp::dns_publish_serve`)**: the SAME granted in-zone writes are APPLIED and
//!      CAPTURED by the `ManualDnsProvider` (the credential-free dev writer `--dns-publish-provider
//!      manual` installs), out-of-zone is `not-authorized`, and an apex `NS` is `apex-refused` — the
//!      whole capability now reachable through serve.
//!
//! So the gate goes RED if the dispatch seam regresses (wired arm) AND documents/asserts the inert
//! shape (inert arm) the serve-boot install flips. It runs with NO secrets (the Manual provider needs
//! none — the capture is the publish-through-the-gate proof) and prints `DNS-PUBLISH SERVE-WIRING OK`.
//!
//! `#[ignore]`d per the anti-`#[ignore]`-as-evidence rule: it is wired into `.github/workflows/ci.yml`
//! as a HARD GATE that greps the success marker + the pass count, so a silent skip / compile-out fails
//! the job. Run locally with:
//!   `cargo test -p boatramp-server --features dns-publish --test dns_publish_serve_wiring_live -- --ignored --nocapture`

#![cfg(feature = "dns-publish")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use boatramp_acme::dns::{DnsOp, DnsProvider, ManualDnsProvider, RecordKind};
use boatramp_core::ByteStream;
use boatramp_core::config::{DeployConfig, HandlerConfig, HandlersSiteConfig, SiteConfig};
use boatramp_core::deploy::{DeployStore, FileEntry, Manifest, sha256_hex};
use boatramp_core::kv::MemoryKv;
use boatramp_core::project::ProjectRef;
use boatramp_handlers::{HandlerEngine, Limits};
use boatramp_server::dns_publish::{DnsPublishGrant, DnsPublishProviderSource};
use boatramp_server::{Auth, HandlerRuntime, router};
use boatramp_storage::FsStorage;
use futures::StreamExt;
use tower::ServiceExt;

/// A REAL compiled `wasi:http` guest that imports `boatramp:handlers/dns-publish` and, at `/publish`,
/// upserts an in-zone A, an in-zone (apex) MX, an out-of-zone A, and an apex NS — reporting the host
/// gate's outcome per op as `key=token`. Shared with the capability-level gate in `boatramp-handlers`.
const DNS_PUBLISH_WRITER: &[u8] =
    include_bytes!("../../boatramp-handlers/tests/fixtures/dns-publish-writer.wasm");

/// The provider's authoritative zone apex (the apex-NS guardrail pivots on this).
const ZONE_ROOT: &str = "app.example.com";
const SITE: &str = "dnsite";
const ROUTE: &str = "/publish";

type App = axum::Router;

/// The serve-installed provider source `boatramp serve`'s boot wiring builds (mirrors
/// `boatramp::dns_publish_serve::ServeDnsPublishSource`): a single node-global host-held writer + the
/// authoritative zone, resolved for every `(project, site)`. The per-grant `dns_publish_zones`
/// allowlist (the real per-guest bound) is applied a layer up in the host binding.
struct ManualProviderSource {
    provider: Arc<dyn DnsProvider>,
    zone_root: String,
}

impl DnsPublishProviderSource for ManualProviderSource {
    fn provider_for(&self, _project: &str, _site: &str) -> Option<DnsPublishGrant> {
        Some(DnsPublishGrant {
            provider: Arc::clone(&self.provider),
            zone_root: self.zone_root.clone(),
        })
    }
}

/// Build the live app: a real engine (posture `allow_guest_dns_publish` ON) + runtime serving a
/// deployment whose `/publish` route is the `dns-publish-writer` component, GRANTED `dns-publish` with
/// a `dns_publish_zones` own-name allowlist, on a handlers-enabled site that allows the import.
async fn live_app() -> App {
    let kv = Arc::new(MemoryKv::new());
    let dir = std::env::temp_dir().join(format!("br-dns-publish-wiring-{}", std::process::id()));
    let storage = Arc::new(FsStorage::new(dir));
    let deploy = DeployStore::new(storage.clone(), kv.clone());

    let hash = sha256_hex(DNS_PUBLISH_WRITER);
    let stream: ByteStream =
        futures::stream::once(async move { Ok(bytes::Bytes::from_static(DNS_PUBLISH_WRITER)) })
            .boxed();
    deploy.put_blob(&hash, stream).await.unwrap();

    let mut files = BTreeMap::new();
    files.insert(
        "dns/writer.wasm".to_string(),
        FileEntry {
            hash,
            size: DNS_PUBLISH_WRITER.len() as u64,
            content_type: None,
            variants: BTreeMap::new(),
        },
    );

    // Build the handler via serde (HandlerConfig has no `Default`; most fields are `#[serde(default)]`).
    // Grant `dns-publish` + an own-name allowlist that admits the apex and any depth under it.
    let handler: HandlerConfig = serde_json::from_value(serde_json::json!({
        "route": ROUTE,
        "component": "dns/writer.wasm",
        "imports": ["dns-publish"],
        "dns_publish_zones": ["**.app.example.com"],
    }))
    .expect("handler config");

    let config = DeployConfig {
        handlers: vec![handler],
        ..Default::default()
    };
    let manifest = Manifest {
        files,
        config,
        ..Default::default()
    };
    let id = deploy.put_manifest(&manifest).await.unwrap();
    deploy
        .activate(ProjectRef::DEFAULT, SITE, &id)
        .await
        .unwrap();
    deploy
        .set_site_config(
            ProjectRef::DEFAULT,
            SITE,
            &SiteConfig {
                handlers: Some(HandlersSiteConfig {
                    enabled: true,
                    allow_imports: vec!["dns-publish".to_string()],
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // Posture `allow_guest_dns_publish` ON — exactly what a serve with the override set carries. Even
    // so, with no provider source installed (the INERT arm) every call is `access-denied`.
    let engine = HandlerEngine::new(Limits::default(), 16)
        .unwrap()
        .with_dns_publish(true);
    let runtime = HandlerRuntime::new(engine, kv.clone(), storage, None, None);
    router(deploy, Auth::disabled(), runtime)
}

/// GET the handler route through the real serve pipeline; returns the `key=token` report map.
async fn drive(app: &App) -> BTreeMap<String, String> {
    let uri = format!("/_sites/{SITE}{ROUTE}");
    let mut r = Request::builder()
        .method("GET")
        .uri(&uri)
        .body(Body::empty())
        .unwrap();
    r.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 40000))));
    let resp = app.clone().oneshot(r).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "the writer guest serves a 200 report"
    );
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    std::str::from_utf8(&bytes)
        .expect("utf8 report")
        .lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn assert_op(report: &BTreeMap<String, String>, key: &str, token: &str) {
    assert_eq!(
        report.get(key).map(String::as_str),
        Some(token),
        "guest op `{key}` should be `{token}` (full report: {report:?})"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "capability gate: run via ci.yml live-gate-dns-publish-serve-wiring or with --ignored"]
async fn dns_publish_serve_wiring_gate() {
    let app = live_app().await;
    // The credential-free Manual writer + capture sink the `--dns-publish-provider manual` boot path
    // installs. Held here so the WIRED arm can read back exactly what reached the provider.
    let provider = Arc::new(ManualDnsProvider::new());

    // ---- 1. INERT arm: NO provider source installed (today's shipped serve) ⇒ access-denied --------
    // Drive the SAME granted, in-zone, posture-ON request through the REAL serve pipeline BEFORE any
    // install. `maybe_attach` finds `provider_source()` is `None`, attaches no binding, and the host
    // fail-closes to `access-denied` for every op — the exact v0.51.0 inert shape, reproduced live.
    let inert = drive(&app).await;
    assert_op(&inert, "a-in-zone", "access-denied");
    assert_op(&inert, "mx-in-zone", "access-denied");
    assert_op(&inert, "out-of-zone", "access-denied");
    assert_op(&inert, "apex-ns", "access-denied");
    assert!(
        provider.recorded().is_empty(),
        "with no provider source installed, NOTHING must reach the provider: {:?}",
        provider.recorded()
    );

    // ---- 2. Install the provider source — the EXACT seam `boatramp serve`'s boot wiring now calls ---
    // (`boatramp::dns_publish_serve::install_dns_publish_source` → this call). Process-wide, once.
    boatramp_server::dns_publish::install_provider_source(Some(Arc::new(ManualProviderSource {
        provider: provider.clone() as Arc<dyn DnsProvider>,
        zone_root: ZONE_ROOT.to_string(),
    })
        as Arc<dyn DnsPublishProviderSource>));

    // ---- 3. WIRED arm: the SAME request now lands + is captured through the real serve pipeline ------
    let wired = drive(&app).await;
    assert_op(&wired, "a-in-zone", "ok"); // in-zone A APPLIED
    assert_op(&wired, "mx-in-zone", "ok"); // in-zone apex MX APPLIED (foreign MX target is fine)
    assert_op(&wired, "out-of-zone", "not-authorized"); // own name outside the allowlist
    assert_op(&wired, "apex-ns", "apex-refused"); // central guardrail refuses an apex NS

    // The real publish-through-the-gate proof: exactly the two in-zone records were CAPTURED by the
    // provider, byte-identical to what the guest named, and nothing else.
    let recorded = provider.recorded();
    assert_eq!(
        recorded.len(),
        2,
        "exactly the two in-zone records reached the provider THROUGH SERVE: {recorded:?}"
    );
    assert_eq!(recorded[0].0, DnsOp::Upsert);
    assert_eq!(recorded[0].1.name, "www.app.example.com");
    assert_eq!(
        recorded[0].1.kind,
        RecordKind::A("203.0.113.7".parse().unwrap())
    );
    assert_eq!(recorded[1].0, DnsOp::Upsert);
    assert_eq!(recorded[1].1.name, "app.example.com");
    assert_eq!(
        recorded[1].1.kind,
        RecordKind::Mx {
            preference: 10,
            exchange: "mx.mailprovider.net".to_string(),
        }
    );
    assert!(
        recorded.iter().all(|(_, r)| !r.name.contains("evil")),
        "no out-of-zone name was ever published: {recorded:?}"
    );
    assert!(
        recorded
            .iter()
            .all(|(_, r)| !matches!(r.kind, RecordKind::Ns(_))),
        "no apex NS was ever published: {recorded:?}"
    );

    println!(
        "DNS-PUBLISH SERVE-WIRING OK: through the real router() serve pipeline, a guest's in-zone \
         A + apex MX were access-denied with NO provider source installed (the v0.51.0 inert shape), \
         then APPLIED + captured once the provider source was installed (the #25 serve-wiring fix); \
         out-of-zone / apex-NS refused in both arms"
    );
}
