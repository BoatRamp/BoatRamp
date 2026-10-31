//! Live capability gate for the guest-facing **DNS publish** capability
//! (`boatramp:handlers/dns-publish`, cap-req #24 WS3) — the WRITE counterpart to `dns-resolve`.
//!
//! Unlike the host-unit tests in `bindings/dns_publish.rs` (which drive `DnsPublishHost::upsert`
//! directly, with no wasm and no linker), this gate exercises the REAL serve seam: a REAL compiled
//! `wasi:http` guest component (`dns-publish-writer.wasm`) that IMPORTS `boatramp:handlers/dns-publish`,
//! served once per scenario through [`HandlerEngine::serve`] over the engine's real `add_to_linker`
//! path, with a real [`ManualDnsProvider`] installed as the host-held provider source. The provider
//! needs NO external credentials (it emits zone-file-style records and simply CAPTURES every write), so
//! this gate runs in CI with no secrets — the capture is the e2e proof that a write reached the
//! provider through the gate.
//!
//! It asserts the capability's promised properties at that real seam:
//!
//!   1. **LEGIT in-zone publish lands**: a granted guest's in-zone `A` + apex `MX` upserts are APPLIED
//!      and CAPTURED by the Manual provider (the MX's foreign exchange target proves the own-name
//!      allowlist constrains the record's OWN name only, never the rdata target).
//!   2. **OUT-OF-ZONE own name is refused `not-authorized`** and nothing is captured for it.
//!   3. **APEX `NS` is refused `apex-refused`** by the central `validate_writable` guardrail (the zone's
//!      authority NS set is provider-managed; Tier-3 is unrepresentable in the WIT so apex-NS is the
//!      expressible refusal) — never reaches the provider.
//!   4. **POSTURE OFF ⇒ `access-denied`**: a SECOND serve with `allow_guest_dns_publish` off denies
//!      even the legit in-zone write (fail-closed), and nothing is captured.
//!   5. **Sub-zone NS delegation under the `allowlist` posture (Security review MEDIUM-3)**: an NS whose
//!      rdata TARGET is on the per-grant `dns_publish_ns_targets` allowlist is published; one whose
//!      target is OUTSIDE it is refused `not-authorized` and never reaches the provider — with the SAME
//!      in-zone owner name in both, isolating the NS-target constraint from the own-name allowlist.
//!
//! On the all-pass path it prints the success marker `DNS-PUBLISH LIVE OK: …`. NOT `#[ignore]`d — it is
//! a fast serve-once+assert (no sockets, no timing), so it also runs in the general `--all-features`
//! handlers suite; CI additionally runs it in a dedicated light job that greps the marker + the pass
//! count, so a silent skip / compile-out fails the gate (see `.github/workflows/ci.yml`).
//!
//! Regenerate the fixture (a WIT change ⇒ rebuild) with:
//! ```sh
//! (cd examples/handlers/dns-publish-writer && cargo build --release --target wasm32-wasip2)
//! cp examples/handlers/dns-publish-writer/target/wasm32-wasip2/release/boatramp_example_dns_publish_writer.wasm \
//!    crates/boatramp-handlers/tests/fixtures/dns-publish-writer.wasm
//! ```
#![cfg(feature = "dns-publish")]

use std::collections::HashMap;
use std::sync::Arc;

use boatramp_acme::dns::{DnsOp, DnsProvider, ManualDnsProvider, RecordKind};
use boatramp_handlers::{
    Bindings, DnsPublishAuditSink, GuestDnsPublishNs, HandlerEngine, Limits, TracingDnsPublishSink,
    empty_body,
};
use http_body_util::BodyExt;

/// The provider's authoritative zone apex (the apex-NS guardrail pivots on this).
const ZONE_ROOT: &str = "app.example.com";

type ReqBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

const DNS_PUBLISH_WRITER: &[u8] = include_bytes!("fixtures/dns-publish-writer.wasm");

fn request_path(path: &str) -> http::Request<ReqBody> {
    http::Request::builder()
        .uri(format!("http://example.test{path}"))
        .body(empty_body())
        .expect("request")
}

/// A fresh redacted audit sink (the default `tracing` one) as the host would install it.
fn audit() -> Arc<dyn DnsPublishAuditSink> {
    Arc::new(TracingDnsPublishSink)
}

/// Serve the writer guest once and return (http status, the `key=token` report map it wrote).
async fn serve_report(engine: &HandlerEngine, path: &str, bindings: Bindings) -> (u16, Report) {
    let response = engine
        .serve(
            "dns-publish-writer",
            DNS_PUBLISH_WRITER,
            request_path(path),
            bindings,
        )
        .await
        .expect("handler serves");
    let status = response.status().as_u16();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        Report::parse(std::str::from_utf8(&body).expect("utf8 body")),
    )
}

/// The guest's per-operation outcome report (one `key=token` line per DNS mutation it attempted).
struct Report(HashMap<String, String>);

impl Report {
    fn parse(body: &str) -> Self {
        let map = body
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Self(map)
    }

    /// Assert operation `key` yielded `token`, with the whole report in the panic message.
    fn assert(&self, key: &str, token: &str) {
        let got = self.0.get(key).map(String::as_str);
        assert_eq!(
            got,
            Some(token),
            "guest op `{key}` should be `{token}` (full report: {:?})",
            self.0
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dns_publish_live_gate() {
    // ---- 1 + 2 + 3: posture ON — legit lands, out-of-zone + apex-NS refused -----------------------
    {
        // The Manual provider is the host-held writer + the capture sink. Keep a clone to inspect.
        let provider = Arc::new(ManualDnsProvider::new());
        let engine = HandlerEngine::new(Limits::default(), 16)
            .expect("engine")
            .with_dns_publish(true); // node posture `allow_guest_dns_publish` ON
        let bindings = Bindings::new("app").with_dns_publish(
            provider.clone() as Arc<dyn DnsProvider>,
            ZONE_ROOT,
            vec!["**.app.example.com".to_string()], // own-name allowlist (apex + any depth)
            Vec::new(),                             // no NS-target allowlist for this scenario
            audit(),
        );

        let (status, report) = serve_report(&engine, "/publish", bindings).await;
        assert_eq!(status, 200, "the writer guest serves a 200 report");

        // The guest-visible outcomes (what the host gate told the guest).
        report.assert("a-in-zone", "ok");
        report.assert("mx-in-zone", "ok");
        report.assert("out-of-zone", "not-authorized");
        report.assert("apex-ns", "apex-refused");

        // The REAL publish-through-the-gate proof: exactly the two in-zone records were captured by the
        // provider, each byte-identical to what the guest named (canonicalized), and NOTHING else.
        let recorded = provider.recorded();
        assert_eq!(
            recorded.len(),
            2,
            "exactly the two in-zone records reached the provider: {recorded:?}"
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
        // The refused records never reached the provider (no out-of-zone name, no NS).
        assert!(
            recorded.iter().all(|(_, r)| !r.name.contains("evil")),
            "no out-of-zone name was ever published: {recorded:?}"
        );
        assert!(
            recorded
                .iter()
                .all(|(_, r)| !matches!(r.kind, RecordKind::Ns(_))),
            "no NS was ever published in the main scenario: {recorded:?}"
        );
    }

    // ---- 4: posture OFF ⇒ access-denied, nothing captured (fail-closed even when granted) ----------
    {
        let provider = Arc::new(ManualDnsProvider::new());
        let engine = HandlerEngine::new(Limits::default(), 16)
            .expect("engine")
            .with_dns_publish(false); // posture OFF
        let bindings = Bindings::new("app").with_dns_publish(
            provider.clone() as Arc<dyn DnsProvider>,
            ZONE_ROOT,
            vec!["**.app.example.com".to_string()], // granted + in-zone, but posture is off
            Vec::new(),
            audit(),
        );

        let (status, report) = serve_report(&engine, "/publish", bindings).await;
        assert_eq!(status, 200);
        // Every op is denied before the allowlist/guardrail is even consulted.
        report.assert("a-in-zone", "access-denied");
        report.assert("mx-in-zone", "access-denied");
        report.assert("out-of-zone", "access-denied");
        report.assert("apex-ns", "access-denied");
        assert!(
            provider.recorded().is_empty(),
            "posture off must publish NOTHING: {:?}",
            provider.recorded()
        );
    }

    // ---- 5: sub-zone NS delegation under the `allowlist` posture (MEDIUM-3) ------------------------
    {
        let provider = Arc::new(ManualDnsProvider::new());
        let engine = HandlerEngine::new(Limits::default(), 16)
            .expect("engine")
            .with_dns_publish(true)
            .with_dns_publish_ns(GuestDnsPublishNs::Allowlist); // only allowlisted NS targets
        let bindings = Bindings::new("app").with_dns_publish(
            provider.clone() as Arc<dyn DnsProvider>,
            ZONE_ROOT,
            vec!["**.app.example.com".to_string()], // own name allowed in BOTH NS attempts
            vec!["**.ns.app-dns.net".to_string()],  // only this operator's nameservers
            audit(),
        );

        let (status, report) = serve_report(&engine, "/ns", bindings).await;
        assert_eq!(status, 200);
        report.assert("ns-in-list", "ok");
        report.assert("ns-out-of-list", "not-authorized");

        let recorded = provider.recorded();
        assert_eq!(
            recorded.len(),
            1,
            "only the allowlisted-target NS delegation reached the provider: {recorded:?}"
        );
        assert_eq!(recorded[0].1.name, "deleg.app.example.com");
        assert_eq!(
            recorded[0].1.kind,
            RecordKind::Ns("ns1.ns.app-dns.net".to_string())
        );
    }

    println!(
        "DNS-PUBLISH LIVE OK: guest published 2 in-zone records (A + apex MX) through the gate; \
         out-of-zone / apex-NS / posture-off / out-of-allowlist-NS-delegation all refused"
    );
}
