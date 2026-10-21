//! Integration tests for the overlay flow-policy editor (`src/overlay_policy.rs`, Stage B).
//!
//! # Why these live here, not in `src/overlay_policy.rs`'s own `#[cfg(test)]` module
//!
//! `tests/render.rs` already establishes this crate's pattern for exercising real behavior:
//! mount a Yew component into a real DOM and assert on it, via `wasm_bindgen_test_configure!
//! (run_in_browser)`. That configuration is GLOBAL to whichever wasm test binary calls it — and
//! because `src/overlay.rs`'s own `#[cfg(test)]` module also calls it, EVERY test compiled into
//! the crate's single `--lib` test binary (every `#[cfg(test)]` module across `src/*.rs`) is
//! forced into browser mode together. In this environment (and in the plain `cargo test` lane —
//! no `webdriver.json`, no chromedriver/geckodriver/safaridriver configured anywhere in this
//! repo's CI, flake devShell, or justfile) that mode cannot run at all: a `--lib` run here fails
//! immediately trying to drive Safari.
//!
//! Each file under `tests/` is its OWN separate wasm test binary, independent of `src/lib.rs`'s.
//! By not calling `run_in_browser` here, this binary defaults to Node.js — which has no DOM
//! (`web_sys::window()` is `None`), but Node 18+ ships the standard Fetch API globals (`fetch`,
//! `Request`, `Response`, `Headers`) natively, and `gloo-net` calls `fetch` as a bare global
//! (see its `request.rs`: `#[wasm_bindgen(js_name = "fetch")] fn fetch_with_request(..)`, not
//! `window.fetch`). So overriding `globalThis.fetch` with a JS closure built via
//! `wasm_bindgen`/`js_sys` lets these tests exercise the REAL `ApiClient` network-calling code
//! end-to-end (`install_fetch_mock`) with zero DOM dependency — this was verified against a
//! throwaway spike (removed) before being built out here, including confirming the `put_400`
//! case goes RED under the exact mutation the task describes (swapping the detailed, body
//! preserving PUT for the body-dropping `check()`/`decode_json` pattern).
//!
//! What this trades away: no test here mounts the actual `html!` tree, so a regression that
//! deletes the `if !diagnostics.is_empty() { .. }` block from the `html!` (say) without touching
//! `explain_diagnostics` would NOT be caught. What it buys: tests that actually run, today, in
//! this sandbox and in a plain `cargo test --target wasm32-unknown-unknown` — unlike the
//! pre-existing `tests/render.rs` smoke test, which (like these would in `run_in_browser` mode)
//! requires a configured browser driver nothing in this repository currently provides. Each test
//! below exercises the exact function/method the component's `html!` calls to decide what renders
//! (never a parallel reimplementation), so a regression in the real render path is still caught at
//! the point the data going into it is produced.

use boatramp_console::{ApiClient, ApiError, FlowPolicyTestResponse, needs_cliff_confirm};
use wasm_bindgen::closure::Closure;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::*;

/// Override the global `fetch` (reachable by `gloo-net` under both Node and a browser, see the
/// module doc) to resolve every call with a canned `status`/`body`, regardless of request.
fn install_fetch_mock(status: u16, body: &'static str) {
    let closure = Closure::wrap(Box::new(move |_req: JsValue| -> js_sys::Promise {
        let init = web_sys::ResponseInit::new();
        init.set_status(status);
        let resp = web_sys::Response::new_with_opt_str_and_init(Some(body), &init)
            .expect("constructing a mock Response");
        js_sys::Promise::resolve(&JsValue::from(resp))
    }) as Box<dyn FnMut(JsValue) -> js_sys::Promise>);
    js_sys::Reflect::set(
        &js_sys::global(),
        &"fetch".into(),
        closure.as_ref().unchecked_ref(),
    )
    .expect("overriding the global fetch for the test");
    // Leak the closure: it must outlive every call the mocked `fetch` makes for the rest of the
    // test process — fine for a short-lived test binary.
    closure.forget();
}

// ===========================================================================
// 1. The default-deny CLIFF: the blocking preview must show on — and ONLY on — the
//    absent-stored → present-draft transition.
//
//    `needs_cliff_confirm` is the exact predicate `PolicyEditor`'s Save-click handler calls
//    before deciding to show the cliff-confirm panel vs. firing the PUT directly
//    (`src/overlay_policy.rs`'s `on_save_click`). Mutation (per the task): delete the
//    `stored_is_off` conjunct, i.e. `needs_cliff_confirm` degenerates to `!draft_is_off` — under
//    that mutation, editing an EXISTING non-empty policy with a non-empty draft (an ordinary
//    edit) would also show the preview. `(false, false)` below is exactly the case that
//    distinguishes the two: correct == false, mutated == true.
// ===========================================================================
#[wasm_bindgen_test]
fn cliff_preview_shown_only_on_absent_to_present() {
    // Ordinary edit of an already-present policy: never a cliff, whatever the draft says.
    assert!(
        !needs_cliff_confirm(false, false),
        "present stored + non-empty draft is an edit"
    );
    assert!(
        !needs_cliff_confirm(false, true),
        "present stored + cleared draft is an edit"
    );
    // Clearing the gate back off (draft empty) is the opposite direction, never a cliff.
    assert!(
        !needs_cliff_confirm(true, true),
        "absent stored + empty draft stays off"
    );
    // The ONE transition that must block on the preview: nothing stored, a non-empty draft.
    assert!(
        needs_cliff_confirm(true, false),
        "absent stored + non-empty draft is THE cliff"
    );
}

// ===========================================================================
// 2. A 400 from `PUT /api/overlay/policy` must survive with its verbatim Cedar compile-error
//    body — through the REAL `ApiClient::put_text_if_match` the editor's Save/cliff-confirm path
//    calls, mocked at the network boundary (no live server).
//
//    Mutation (per the task): swap `put_text_if_match` back to the body-dropping pattern
//    (`check(req.send().await)?` + `decode_json`, i.e. `post_json`/`put_json`'s pattern) — then
//    the error collapses to a bare status-text ("Bad Request") and this assertion on the verbatim
//    Cedar message fails. Empirically confirmed RED under exactly that swap before this file was
//    finalized (then reverted).
// ===========================================================================
#[wasm_bindgen_test]
async fn put_400_body_rendered_inline() {
    let cedar_error =
        "invalid overlay flow policy: policy does not parse: unexpected token `permit`\n";
    install_fetch_mock(400, cedar_error);

    let client = ApiClient::new("http://localhost", Some("test-token".to_string()));
    let result = client
        .put_text_if_match::<serde_json::Value>(
            boatramp_console::POLICY_PATH,
            "garbage cedar text",
            Some("etag-v1"),
        )
        .await;

    match result {
        Err(ApiError::Status { code, body }) => {
            assert_eq!(code, 400);
            // This is the text `PolicyEditor` renders verbatim in the inline error banner
            // directly under the textarea (`SaveStatus::Error(err.to_string())`); `ApiError`'s
            // `Display` includes the body unmodified for a `Status` variant.
            assert!(
                body.contains("policy does not parse"),
                "expected the verbatim Cedar compile error in the body, got: {body:?}"
            );
        }
        other => panic!("expected ApiError::Status{{ code: 400, .. }}, got {other:?}"),
    }
}

// ===========================================================================
// 3. The Explain/dry-run view must render a `deny` decision WITH its diagnostics — the one
//    surface (System·Admin authoring oracle) where they are shown at all.
//
//    `explain_diagnostics` is the exact extraction `dry_run_result`'s `html!` iterates over to
//    build the "Diagnostics" list. Mutation (per the task): make it always return `&[]` — then
//    the assertion that the extracted diagnostics equal the server's non-empty list fails.
// ===========================================================================
#[wasm_bindgen_test]
fn explain_renders_deny_with_diagnostics() {
    let json = r#"{
        "decision": "deny",
        "ttl_ceiling": null,
        "deciding_policies": ["policy0"],
        "diagnostics": ["principal.role is absent for a key-only holder; `when` clause skipped"],
        "note": null
    }"#;
    let resp: FlowPolicyTestResponse =
        serde_json::from_str(json).expect("valid OverlayPolicyTestResponse JSON");

    assert_eq!(resp.decision, "deny");
    assert_eq!(resp.deciding_policies, vec!["policy0".to_string()]);

    let diagnostics = boatramp_console::explain_diagnostics(&resp);
    assert_eq!(diagnostics.len(), 1);
    assert!(
        diagnostics[0].contains("key-only holder"),
        "the render path must not drop the server's diagnostics: got {diagnostics:?}"
    );
}
