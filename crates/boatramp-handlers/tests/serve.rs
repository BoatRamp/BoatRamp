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
use boatramp_handlers::{empty_body, Bindings, HandlerEngine, HandlerError, Limits};
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
async fn pooling_allocator_serves_real_components() {
    // The pooling allocator must be sized so a real wasi:http + wasi:keyvalue
    // component instantiates and serves (under-sizing fails instantiation).
    let engine = HandlerEngine::with_pooling(Limits::default(), 16).expect("pooling engine");
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
    assert!(matches!(err, HandlerError::Trap(_)), "{err}");
    // The failed message was not counted.
    assert_eq!(
        kv.get("hkv/blog/delivered/orders/created").await.unwrap(),
        Some(b"1".to_vec())
    );
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
    assert!(matches!(err, HandlerError::Trap(_)), "{err}");
}
