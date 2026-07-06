//! WebAssembly handler engine for boatramp.
//!
//! Runs deployment-shipped WebAssembly **components** that handle requests
//! server-side, on a [wasmtime](https://wasmtime.dev) component runtime. The
//! engine is heavy, so it lives behind the `engine` cargo feature; the server
//! pulls it in via its own `handlers` feature. A build without `engine` carries
//! zero wasm dependencies.

#[cfg(feature = "engine")]
mod bindings;
#[cfg(feature = "engine")]
mod engine;
#[cfg(feature = "engine")]
pub mod logging;

#[cfg(feature = "engine")]
pub use bindings::Bindings;
#[cfg(feature = "engine")]
pub use engine::{
    build_engine, build_engine_pooling, empty_body, HandlerEngine, HandlerError, Limits,
};
#[cfg(feature = "engine")]
pub use logging::{LogSink, LogStream};
