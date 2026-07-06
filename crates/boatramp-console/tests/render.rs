//! Browser smoke tests (run with `wasm-pack test --headless` or
//! `wasm-bindgen-test-runner`). They render the app into a real DOM and assert
//! the expected view appears — the in-browser end of the "e2e" seam (a full
//! click-through against a live server is exercised separately).

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;
use yew::Renderer;

wasm_bindgen_test_configure!(run_in_browser);

/// With no token in sessionStorage, `App` renders the login gate: the title and
/// the "Sign in" button must be present. Exercises the whole component tree
/// (AuthProvider → Shell → LoginView) without any network.
#[wasm_bindgen_test]
async fn renders_login_when_signed_out() {
    let document = web_sys::window().unwrap().document().unwrap();
    // Mount into a fresh element so repeated test runs don't collide.
    let mount = document.create_element("div").unwrap();
    document.body().unwrap().append_child(&mount).unwrap();

    Renderer::<boatramp_console::App>::with_root(mount.clone()).render();
    // Let the renderer flush to the DOM.
    yew::platform::time::sleep(std::time::Duration::from_millis(50)).await;

    let html = mount.inner_html();
    assert!(
        html.contains("boatramp console"),
        "login view should show the title; got: {html}"
    );
    assert!(
        html.contains("Sign in"),
        "login view should show the Sign in button; got: {html}"
    );
}
