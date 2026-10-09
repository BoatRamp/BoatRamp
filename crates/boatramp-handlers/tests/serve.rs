//! End-to-end engine test: load a real `wasi:http` component and serve a
//! request through wasmtime. The fixture (`fixtures/http-200.wasm`) is the
//! `examples/handlers/http-200` guest, prebuilt and committed so this test runs
//! without a wasm toolchain. Regenerate with:
//! ```sh
//! (cd examples/handlers/http-200 && cargo build --release --target wasm32-wasip2)
//! cp examples/handlers/http-200/target/wasm32-wasip2/release/boatramp_example_http_200.wasm \
//!    crates/boatramp-handlers/tests/fixtures/http-200.wasm
//! ```
#![cfg(feature = "engine")]

use std::sync::Arc;

use boatramp_core::kv::{KvStore, MemoryKv};
use boatramp_handlers::{Bindings, HandlerEngine, HandlerError, Limits, empty_body};
use http_body_util::BodyExt;

/// No capabilities granted — these fixtures exercise only the http path.
fn no_caps() -> Bindings {
    Bindings::new("test")
}

const HTTP_200: &[u8] = include_bytes!("fixtures/http-200.wasm");
/// A `wasi:http` + `wasi:keyvalue` guest: increments a per-site "hits" counter
/// and returns it. See `examples/handlers/kv-counter`. Regenerate with:
/// ```sh
/// (cd examples/handlers/kv-counter && cargo build --release --target wasm32-wasip2)
/// cp examples/handlers/kv-counter/target/wasm32-wasip2/release/boatramp_example_kv_counter.wasm \
///    crates/boatramp-handlers/tests/fixtures/kv-counter.wasm
/// ```
const KV_COUNTER: &[u8] = include_bytes!("fixtures/kv-counter.wasm");
/// A `wasi:http` guest that calls a sibling function through the boatramp
/// `invoke` capability and echoes the callee's response. See
/// `examples/handlers/invoke-caller`. Regenerate with:
/// ```sh
/// (cd examples/handlers/invoke-caller && cargo build --release --target wasm32-wasip2)
/// cp examples/handlers/invoke-caller/target/wasm32-wasip2/release/boatramp_example_invoke_caller.wasm \
///    crates/boatramp-handlers/tests/fixtures/invoke-caller.wasm
/// ```
#[cfg(feature = "invoke")]
const INVOKE_CALLER: &[u8] = include_bytes!("fixtures/invoke-caller.wasm");
/// A `wasi:http` guest that runs a GraphQL operation against the project supergraph through the
/// boatramp `graphql` capability and returns the response. See `examples/handlers/graphql-run-caller`.
/// Regenerate with:
/// ```sh
/// (cd examples/handlers/graphql-run-caller && cargo build --release --target wasm32-wasip2)
/// cp examples/handlers/graphql-run-caller/target/wasm32-wasip2/release/boatramp_example_graphql_run_caller.wasm \
///    crates/boatramp-handlers/tests/fixtures/graphql-run-caller.wasm
/// ```
#[cfg(feature = "graphql")]
const GRAPHQL_RUN_CALLER: &[u8] = include_bytes!("fixtures/graphql-run-caller.wasm");

fn engine() -> HandlerEngine {
    HandlerEngine::new(Limits::default(), 16).expect("engine")
}

type ReqBody = http_body_util::combinators::BoxBody<bytes::Bytes, hyper::Error>;

fn request() -> http::Request<ReqBody> {
    request_path("/")
}

fn request_path(path: &str) -> http::Request<ReqBody> {
    http::Request::builder()
        .uri(format!("http://example.test{path}"))
        .body(empty_body())
        .expect("request")
}

#[cfg(feature = "graphql")]
fn request_with_auth(authorization: &str) -> http::Request<ReqBody> {
    http::Request::builder()
        .uri("http://example.test/")
        .header("authorization", authorization)
        .body(empty_body())
        .expect("request")
}

#[tokio::test(flavor = "multi_thread")]
async fn serves_a_real_component_response() {
    let engine = engine();
    let response = engine
        .serve("http-200", HTTP_200, request(), no_caps())
        .await
        .expect("handler serves");
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"hello from boatramp handler\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn cached_compile_serves_twice() {
    // Second call hits the compilation cache (same hash) and still serves.
    let engine = engine();
    for _ in 0..2 {
        let response = engine
            .serve("http-200", HTTP_200, request(), no_caps())
            .await
            .expect("handler serves");
        assert_eq!(response.status(), 200);
    }
}

/// MEASUREMENT (construens memory-instance-observability): drive REAL components through the engine
/// and read the LIVE instance stats, so the warm-hit / cold-compile / eviction / instantiate numbers
/// are MEASURED on a real wasi:http component, not inferred. Run with `--nocapture` to see the data;
/// the assertions pin the lifecycle contract (so it is also a CI-exercised correctness test).
#[tokio::test(flavor = "multi_thread")]
async fn instance_stats_measures_warm_cold_and_eviction_on_real_components() {
    // (A) STEADY STATE: a comfortably-sized cache (16), one component served 50×. Exactly ONE cold
    // compile; the other 49 are warm hits; NO eviction — the shape construens should see if the box is
    // big enough. The per-request instantiate cost is the term distinct from a cold compile.
    let engine = HandlerEngine::new(Limits::default(), 16).expect("engine");
    for _ in 0..50 {
        let r = engine
            .serve("http-200", HTTP_200, request(), no_caps())
            .await;
        assert!(r.is_ok(), "http-200 serves");
    }
    let snap = engine.instance_stats();
    let r = &snap.request;
    println!(
        "[WARM] http-200 x50 @cache16: warm_hits={} cold_misses={} evictions={} \
         instantiate_us(avg={} max={}) compile_ms(avg={} max={}) warm_now={}/{} rss_bytes={:?} \
         per_instance_limit={}",
        r.warm_hits,
        r.cold_misses,
        r.evictions,
        r.instantiate_us_avg,
        r.instantiate_us_max,
        r.compile_ms_avg,
        r.compile_ms_max,
        r.warm_now,
        r.warm_capacity,
        snap.memory.rss_bytes,
        snap.memory.per_instance_limit_bytes
    );
    assert_eq!(r.cold_misses, 1, "one compile, then the cache stays warm");
    assert_eq!(r.warm_hits, 49, "the other 49 served from the warm cache");
    assert_eq!(
        r.evictions, 0,
        "a 16-slot cache holds one component with zero eviction"
    );
    assert_eq!(r.warm_now, 1);
    assert_eq!(
        r.instantiations, 50,
        "every served request instantiated once"
    );

    // (B) EVICTION under a TIGHT cache (1 slot), two distinct components alternated → churn: every
    // serve is a cold miss, each new insert evicts the prior — the pathology construens HYPOTHESIZED
    // (but which, at its ~15 components vs the default 64-slot cache, should NOT be occurring; this
    // proves the signal fires when it IS). The 2nd/3rd serves may error at the kv grant check, but the
    // compile + instantiate are recorded first, so the lifecycle counts are exact.
    let tiny = HandlerEngine::new(Limits::default(), 1).expect("engine");
    let _ = tiny.serve("http-200", HTTP_200, request(), no_caps()).await; // miss #1 (no evict)
    let _ = tiny
        .serve("kv-counter", KV_COUNTER, request(), no_caps())
        .await; // miss #2, evicts http-200
    let _ = tiny.serve("http-200", HTTP_200, request(), no_caps()).await; // miss #3, evicts kv-counter
    let tsnap = tiny.instance_stats();
    let t = &tsnap.request;
    println!(
        "[EVICT] alternating x3 @cache1: warm_hits={} cold_misses={} evictions={} warm_now={}/{}",
        t.warm_hits, t.cold_misses, t.evictions, t.warm_now, t.warm_capacity
    );
    assert_eq!(
        t.cold_misses, 3,
        "every serve missed — a 1-slot cache holds only one"
    );
    assert_eq!(t.warm_hits, 0, "nothing was ever reused");
    assert!(
        t.evictions >= 2,
        "the 2nd + 3rd inserts each evicted the prior component"
    );
    assert_eq!(t.warm_now, 1, "one component resident after the churn");
}

/// PERF (construens memory-instance): a WARM component serves WITHOUT its bytes — so the request path
/// can skip re-reading (and, on a remote blob backend, re-fetching over the network) a component it
/// would only discard on a warm hit. Proves `request_component_warm` + that `serve` ignores the
/// `wasm` argument on a cache hit; and that a cold miss with empty bytes fails CLEARLY (the
/// eviction-window guard), not with garbage.
#[tokio::test(flavor = "multi_thread")]
async fn warm_component_serves_without_its_bytes() {
    let engine = engine();
    // Cold: compiles + caches.
    engine
        .serve("http-200", HTTP_200, request(), no_caps())
        .await
        .expect("cold serve compiles");
    assert!(
        engine.request_component_warm("http-200"),
        "the component is now resident"
    );

    // Warm: serve with EMPTY bytes — the engine must hit the cache and never look at them. This is
    // the fix: a warm request reads no component blob (zero backend hit).
    let response = engine
        .serve("http-200", &[], request(), no_caps())
        .await
        .expect("a warm component serves with no bytes supplied");
    assert_eq!(response.status(), 200);

    // A cold miss with empty bytes (a stale warm-check on an over-capacity node) fails with a clear,
    // retryable compile error — never a panic or a wrong result.
    assert!(!engine.request_component_warm("never-seen"));
    let err = engine
        .serve("never-seen", &[], request(), no_caps())
        .await
        .expect_err("empty bytes on a cold miss must error");
    assert!(
        matches!(err, HandlerError::Compile(_)),
        "a cold miss with no bytes is a clear compile error, got {err:?}"
    );
}

/// A test [`Invoker`](boatramp_handlers::Invoker) that answers every target with
/// a canned 200 + body, so the invoke *host binding* (grant check, allowlist,
/// depth, wire conversion) is exercised by a real guest without a second guest.
#[cfg(feature = "invoke")]
struct StubInvoker {
    body: &'static [u8],
}

#[cfg(feature = "invoke")]
#[async_trait::async_trait]
impl boatramp_handlers::Invoker for StubInvoker {
    async fn invoke(
        &self,
        _target: &str,
        _request: boatramp_handlers::InvokeRequest,
        _depth: u32,
    ) -> Result<boatramp_handlers::InvokeResponse, boatramp_handlers::InvokeError> {
        Ok(boatramp_handlers::InvokeResponse {
            status: 200,
            headers: vec![],
            body: self.body.to_vec(),
        })
    }
}

/// A real guest importing `boatramp:handlers/invoke` calls its `greeter` target
/// through the host binding, and the callee's response flows back into its body.
#[cfg(feature = "invoke")]
#[tokio::test(flavor = "multi_thread")]
async fn invoke_caller_reaches_a_granted_target() {
    let engine = engine();
    let invoker: Arc<dyn boatramp_handlers::Invoker> = Arc::new(StubInvoker { body: b"hi" });
    let bindings = Bindings::new("test").with_invoke(invoker, vec!["greeter".into()], 0);
    let response = engine
        .serve("invoke-caller", INVOKE_CALLER, request(), bindings)
        .await
        .expect("handler serves");
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"greeter said (200): hi");
}

/// Without an invoke grant, the guest's `invoke` returns `access-denied`, which
/// the example surfaces as a 500.
#[cfg(feature = "invoke")]
#[tokio::test(flavor = "multi_thread")]
async fn invoke_caller_denied_without_grant() {
    let engine = engine();
    let response = engine
        .serve("invoke-caller", INVOKE_CALLER, request(), no_caps())
        .await
        .expect("handler serves");
    assert_eq!(response.status(), 500);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("capability not granted"),
        "{body:?}"
    );
}

/// Granted invoke, but the requested `greeter` is outside the allowlist, so the
/// host refuses with `target-not-allowed` before any invoker runs.
#[cfg(feature = "invoke")]
#[tokio::test(flavor = "multi_thread")]
async fn invoke_caller_target_outside_allowlist() {
    let engine = engine();
    let invoker: Arc<dyn boatramp_handlers::Invoker> = Arc::new(StubInvoker { body: b"hi" });
    let bindings = Bindings::new("test").with_invoke(invoker, vec!["other".into()], 0);
    let response = engine
        .serve("invoke-caller", INVOKE_CALLER, request(), bindings)
        .await
        .expect("handler serves");
    assert_eq!(response.status(), 500);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("not in the allowlist"),
        "{body:?}"
    );
}

/// A test [`SupergraphRunner`](boatramp_handlers::SupergraphRunner) that records the forwarded
/// bearer and returns a canned stitched response, so the `graphql` host binding (grant check,
/// wire conversion, bearer forwarding) is exercised by a real guest without a whole supergraph.
#[cfg(feature = "graphql")]
struct StubSupergraphRunner {
    seen_bearer: Arc<std::sync::Mutex<Option<String>>>,
    response: &'static [u8],
}

#[cfg(feature = "graphql")]
#[async_trait::async_trait]
impl boatramp_handlers::SupergraphRunner for StubSupergraphRunner {
    async fn run(
        &self,
        request: boatramp_handlers::GraphqlRequest,
        _depth: u32,
    ) -> Result<Vec<u8>, boatramp_handlers::SupergraphRunError> {
        *self.seen_bearer.lock().unwrap() = request.authorization.clone();
        Ok(self.response.to_vec())
    }
}

/// A real guest importing `boatramp:handlers/graphql` runs an operation against the project
/// supergraph through the host binding: the stitched response flows back into its body, and the
/// runner sees the guest's **own** forwarded bearer (so a guest acts as itself — no escalation).
#[cfg(feature = "graphql")]
#[tokio::test(flavor = "multi_thread")]
async fn graphql_run_caller_runs_a_supergraph_query_forwarding_its_bearer() {
    let engine = engine();
    let seen = Arc::new(std::sync::Mutex::new(None));
    let runner: Arc<dyn boatramp_handlers::SupergraphRunner> = Arc::new(StubSupergraphRunner {
        seen_bearer: seen.clone(),
        response: br#"{"data":{"me":{"name":"Alice","reviews":[{"body":"great"}]}}}"#,
    });
    let bindings = Bindings::new("test").with_graphql(runner, 0);
    let response = engine
        .serve(
            "graphql-run-caller",
            GRAPHQL_RUN_CALLER,
            request_with_auth("Bearer t-acme"),
            bindings,
        )
        .await
        .expect("handler serves");
    assert_eq!(response.status(), 200);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    // The guest received the stitched supergraph response through the capability round-trip.
    assert!(
        String::from_utf8_lossy(&body).contains("\"reviews\""),
        "{body:?}"
    );
    // ...and the run carried the guest's own bearer (forwarded for per-subgraph re-verification).
    assert_eq!(*seen.lock().unwrap(), Some("Bearer t-acme".to_string()));
}

/// Without a graphql grant, the guest's `run` returns `access-denied`, surfaced as a 500.
#[cfg(feature = "graphql")]
#[tokio::test(flavor = "multi_thread")]
async fn graphql_run_caller_denied_without_grant() {
    let engine = engine();
    let response = engine
        .serve(
            "graphql-run-caller",
            GRAPHQL_RUN_CALLER,
            request(),
            no_caps(),
        )
        .await
        .expect("handler serves");
    assert_eq!(response.status(), 500);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(
        String::from_utf8_lossy(&body).contains("capability not granted"),
        "{body:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn trapping_handler_is_a_trap_error() {
    let engine = engine();
    let err = engine
        .serve("http-200", HTTP_200, request_path("/panic"), no_caps())
        .await
        .expect_err("panic traps");
    assert!(matches!(err, HandlerError::Trap(_)), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn looping_handler_times_out() {
    let limits = Limits {
        timeout_ms: 100,
        ..Limits::default()
    };
    let engine = HandlerEngine::new(limits, 16).expect("engine");
    let err = engine
        .serve("http-200", HTTP_200, request_path("/loop"), no_caps())
        .await
        .expect_err("infinite loop times out");
    assert!(matches!(err, HandlerError::Timeout), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn looping_handler_runs_out_of_fuel() {
    // A generous wall-clock budget but a finite CPU fuel budget: the infinite
    // loop exhausts fuel and traps before the timeout fires.
    let limits = Limits {
        timeout_ms: 10_000,
        fuel: Some(50_000_000),
        ..Limits::default()
    };
    let engine = HandlerEngine::new(limits, 16).expect("engine");
    let err = engine
        .serve("http-200", HTTP_200, request_path("/loop"), no_caps())
        .await
        .expect_err("infinite loop exhausts fuel");
    assert!(matches!(err, HandlerError::OutOfFuel), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn handler_over_its_memory_ceiling_is_out_of_memory() {
    // A memory ceiling of one page (64 KiB), below the guest's 17-page (~1 MiB) initial linear
    // memory: the instance's memory allocation is denied by the limiter, so the guest cannot start
    // and the host classifies the failure as `OutOfMemory` — a distinct terminal outcome (DLQ /
    // stats `out-of-memory`) rather than an opaque `Trap` (construens async-lane-memory-budget #4).
    // This exercises the real path end-to-end: `MemLimiter::memory_growing` observes the `Ok(false)`
    // deny, sets the flag, and `classify` maps the resulting error to `OutOfMemory`.
    let limits = Limits {
        memory_bytes: 64 * 1024,
        ..Limits::default()
    };
    let engine = HandlerEngine::new(limits, 16).expect("engine");
    let err = engine
        .serve("http-200", HTTP_200, request_path("/"), no_caps())
        .await
        .expect_err("a 64 KiB ceiling cannot fit the guest's 17-page initial memory");
    assert!(matches!(err, HandlerError::OutOfMemory), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_lane_clamps_a_declared_timeout_to_the_engine_ceiling() {
    // The engine sync ceiling is 100ms; a handler that *declares* a far larger
    // budget is clamped down to it (an override may only lower, never raise) —
    // so a connection-bearing request can never hold longer than the ceiling.
    let limits = Limits {
        timeout_ms: 100,
        ..Limits::default()
    };
    let engine = HandlerEngine::new(limits, 16).expect("engine");
    let declares_10s = Limits {
        timeout_ms: 10_000,
        ..Limits::default()
    };
    let err = engine
        .serve_with_limits(
            "http-200",
            HTTP_200,
            request_path("/loop"),
            no_caps(),
            declares_10s,
        )
        .await
        .expect_err("declared 10s is clamped to the 100ms sync ceiling");
    assert!(matches!(err, HandlerError::Timeout), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn async_lane_uses_its_own_ceiling_not_the_sync_one() {
    // Sync ceiling is a generous 10s, but the async ceiling is 100ms. A call on
    // the async lane is bounded by the *async* ceiling — proof the two lanes are
    // clamped independently (here the async job traps fast despite the roomy sync
    // ceiling; in production the roles are reversed — async is the larger one).
    let sync_ceiling = Limits {
        timeout_ms: 10_000,
        ..Limits::default()
    };
    let async_ceiling = Limits {
        timeout_ms: 100,
        ..Limits::default()
    };
    let engine = HandlerEngine::new(sync_ceiling, 16)
        .expect("engine")
        .with_async_limits(async_ceiling);
    let declares_10s = Limits {
        timeout_ms: 10_000,
        ..Limits::default()
    };
    let err = engine
        .serve_with_limits_async(
            "http-200",
            HTTP_200,
            request_path("/loop"),
            no_caps(),
            declares_10s,
        )
        .await
        .expect_err("the async lane clamps to its own 100ms ceiling");
    assert!(matches!(err, HandlerError::Timeout), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn async_ceiling_defaults_to_the_sync_ceiling_until_opted_in() {
    // Back-compat: an engine built the old way behaves identically on both lanes
    // (the async ceiling mirrors the sync one) until a caller opts into a larger
    // async lane — so existing deployments see no change.
    let engine = HandlerEngine::new(Limits::default(), 16).expect("engine");
    assert_eq!(engine.async_timeout_ms(), Limits::default().timeout_ms);
    assert_eq!(
        engine.async_max_concurrency(),
        Limits::default().max_concurrency
    );

    let raised = engine.with_async_limits(Limits {
        timeout_ms: 900_000,
        max_concurrency: 8,
        ..Limits::default()
    });
    assert_eq!(raised.async_timeout_ms(), 900_000);
    assert_eq!(raised.async_max_concurrency(), 8);
}

#[tokio::test(flavor = "multi_thread")]
async fn streaming_lane_clamps_to_its_own_ceiling() {
    // A streaming response runs on the streaming lane, clamped to *its* ceiling — separate
    // from the sync request lane — so a per-invocation request for more is capped here.
    let sync_ceiling = Limits {
        timeout_ms: 10_000,
        ..Limits::default()
    };
    let streaming_ceiling = Limits {
        timeout_ms: 100,
        ..Limits::default()
    };
    let engine = HandlerEngine::new(sync_ceiling, 16)
        .expect("engine")
        .with_streaming_limits(streaming_ceiling);
    let declares_10s = Limits {
        timeout_ms: 10_000,
        ..Limits::default()
    };
    let err = engine
        .serve_with_limits_streaming(
            "http-200",
            HTTP_200,
            request_path("/loop"),
            no_caps(),
            declares_10s,
        )
        .await
        .expect_err("the streaming lane clamps to its own 100ms ceiling");
    assert!(matches!(err, HandlerError::Timeout), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn streaming_ceiling_defaults_to_the_sync_ceiling_until_opted_in() {
    // Back-compat: without opting in, the streaming lane mirrors the sync ceiling.
    let engine = HandlerEngine::new(Limits::default(), 16).expect("engine");
    assert_eq!(engine.streaming_timeout_ms(), Limits::default().timeout_ms);
    assert_eq!(
        engine.streaming_max_concurrency(),
        Limits::default().max_concurrency
    );

    let raised = engine.with_streaming_limits(Limits {
        timeout_ms: 900_000,
        max_concurrency: 64,
        ..Limits::default()
    });
    assert_eq!(raised.streaming_timeout_ms(), 900_000);
    assert_eq!(raised.streaming_max_concurrency(), 64);
}

#[tokio::test(flavor = "multi_thread")]
async fn pooling_allocator_serves_real_components() {
    // The pooling allocator must be sized so a real wasi:http + wasi:keyvalue
    // component instantiates and serves (under-sizing fails instantiation).
    let engine = HandlerEngine::with_pooling(Limits::default(), 16, None).expect("pooling engine");
    let response = engine
        .serve("http-200", HTTP_200, request(), no_caps())
        .await
        .expect("pooled handler serves");
    assert_eq!(response.status(), 200);
    // A second, different component shares the same pool.
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let granted = Bindings::new("blog").with_keyvalue("blog", kv);
    let response = engine
        .serve("kv-counter", KV_COUNTER, request(), granted)
        .await
        .expect("pooled kv handler serves");
    assert_eq!(response.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn unmetered_fuel_serves_normally() {
    // `fuel: None` (the default) must not trap a normal handler — the engine has
    // `consume_fuel` on, so the store is given the maximum budget.
    let engine = engine();
    let response = engine
        .serve("http-200", HTTP_200, request(), no_caps())
        .await
        .expect("unmetered handler serves");
    assert_eq!(response.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn keyvalue_binding_serves_end_to_end() {
    // A real component imports wasi:keyvalue and the engine satisfies it from a
    // per-site MemoryKv: the counter persists across requests and lands under
    // the site's prefix.
    let engine = engine();
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let granted = Bindings::new("blog").with_keyvalue("blog", kv.clone());

    for expected in ["hits=1\n", "hits=2\n"] {
        let response = engine
            .serve("kv-counter", KV_COUNTER, request(), granted.clone())
            .await
            .expect("handler serves");
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], expected.as_bytes());
    }

    // The counter is stored under the site prefix, not at the bare key.
    assert_eq!(kv.get("hkv/blog/hits").await.unwrap(), Some(b"2".to_vec()));
    assert_eq!(kv.get("hits").await.unwrap(), None);
}

#[tokio::test(flavor = "multi_thread")]
async fn keyvalue_without_grant_surfaces_denied() {
    // Same component, but the capability is not granted: the guest's open()
    // fails and it returns a 500 (deny by default).
    let engine = engine();
    let response = engine
        .serve("kv-counter", KV_COUNTER, request(), no_caps())
        .await
        .expect("handler serves a response");
    assert_eq!(response.status(), 500);
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_component_is_a_compile_error() {
    let engine = engine();
    let err = engine
        .serve("bad", b"not a wasm component", request(), no_caps())
        .await
        .expect_err("garbage rejected");
    assert!(matches!(err, HandlerError::Compile(_)), "{err}");
}

/// A boatramp messaging consumer guest: exports `handle`, counts deliveries in
/// wasi:keyvalue, fails on a `fail` payload. See `examples/handlers/event-consumer`.
/// Regenerate with:
/// ```sh
/// (cd examples/handlers/event-consumer && cargo build --release --target wasm32-wasip2)
/// cp examples/handlers/event-consumer/target/wasm32-wasip2/release/boatramp_example_event_consumer.wasm \
///    crates/boatramp-handlers/tests/fixtures/event-consumer.wasm
/// ```
#[cfg(feature = "messaging")]
const EVENT_CONSUMER: &[u8] = include_bytes!("fixtures/event-consumer.wasm");

#[cfg(feature = "messaging")]
#[tokio::test(flavor = "multi_thread")]
async fn consumer_dispatch_handles_and_counts() {
    // The engine instantiates the consumer world and calls the guest's `handle`.
    let engine = engine();
    let kv: Arc<dyn KvStore> = Arc::new(MemoryKv::new());
    let granted = Bindings::new("blog").with_keyvalue("blog", kv.clone());

    // A normal message is handled (Ok) and counted under the site prefix.
    engine
        .dispatch_message(
            "event-consumer",
            EVENT_CONSUMER,
            "orders/created",
            b"hello",
            granted.clone(),
            Limits::default(),
        )
        .await
        .expect("consumer handles the message");
    assert_eq!(
        kv.get("hkv/blog/delivered/orders/created").await.unwrap(),
        Some(b"1".to_vec())
    );

    // A `fail` payload returns an error → the dispatcher will retry/dead-letter.
    let err = engine
        .dispatch_message(
            "event-consumer",
            EVENT_CONSUMER,
            "orders/created",
            b"fail",
            granted.clone(),
            Limits::default(),
        )
        .await
        .expect_err("fail payload errors");
    // A `fail` payload makes the guest `handle` return a clean `Err` (a controlled failure, NOT a
    // panic), so the dispatcher classifies it `ConsumerError` — the legible terminal-outcome the DLQ
    // reads as `consumer-error`, distinct from the opaque `Trap` a real crash yields.
    assert!(matches!(err, HandlerError::ConsumerError(_)), "{err}");
    // The failed message was not counted.
    assert_eq!(
        kv.get("hkv/blog/delivered/orders/created").await.unwrap(),
        Some(b"1".to_vec())
    );
}

#[cfg(feature = "messaging")]
#[tokio::test(flavor = "multi_thread")]
async fn precompile_consumer_accepts_a_consumer_and_rejects_a_handler() {
    // The activation gate for a `consumers` entry: a real consumer world (exports
    // `messaging-handler`) validates, and a plain `wasi:http` handler is rejected
    // *here* rather than passing the gate and silently under-delivering at drain.
    let engine = engine();
    engine
        .precompile_consumer("event-consumer", EVENT_CONSUMER)
        .expect("a real consumer world validates");
    let err = engine
        .precompile_consumer("http-200", HTTP_200)
        .expect_err("an http handler is not a consumer");
    assert!(matches!(err, HandlerError::Compile(_)), "{err}");
}

#[cfg(feature = "messaging")]
#[tokio::test(flavor = "multi_thread")]
async fn consumer_without_keyvalue_grant_errors() {
    // Deny by default: the consumer needs kv to count; ungranted, its `handle`
    // returns an error (which the dispatcher treats as a failed delivery).
    let engine = engine();
    let err = engine
        .dispatch_message(
            "event-consumer",
            EVENT_CONSUMER,
            "orders/created",
            b"hello",
            no_caps(),
            Limits::default(),
        )
        .await
        .expect_err("ungranted kv -> consumer error");
    // Ungranted kv surfaces to the guest as a WIT error result; its `handle` returns a clean `Err`
    // (a denial, not a crash), so the dispatcher classifies it `ConsumerError`, not `Trap`.
    assert!(matches!(err, HandlerError::ConsumerError(_)), "{err}");
}
