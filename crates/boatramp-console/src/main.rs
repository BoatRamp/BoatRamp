//! boatramp web management console — entry point.
//!
//! A Yew (CSR) Wasm SPA over the control-plane `/api/*`.

fn main() {
    // Route Rust panics to the browser devtools console (dev aid; cheap).
    console_error_panic_hook::set_once();
    yew::Renderer::<boatramp_console::App>::new().render();
}
