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

#[cfg(feature = "email")]
pub use bindings::email::{EmailSpool, LettreBackend, OutboundEmail, SmtpBackend};
#[cfg(feature = "graphql")]
pub use bindings::graphql::{GraphqlRequest, SupergraphRunError, SupergraphRunner};
#[cfg(feature = "invoke")]
pub use bindings::invoke::{
    InvokeError, InvokeRequest, InvokeResponse, InvokeStreamResponse, Invoker, MAX_INVOKE_DEPTH,
};
#[cfg(feature = "messaging")]
pub use bindings::messaging::BUS_TOPIC_SELECTOR;
#[cfg(feature = "engine")]
pub use bindings::Bindings;
#[cfg(feature = "engine")]
pub use engine::{
    build_engine, build_engine_pooling, empty_body, HandlerEngine, HandlerError, Lane, Limits,
};
#[cfg(feature = "engine")]
pub use logging::{LogSink, LogStream};

/// Contract-evolution invariants checked against the host WIT text itself, so a
/// mistake in `wit/world.wit` fails a fast unit test rather than a deployed guest.
/// Ungated on purpose — these guard rules that hold in *every* build.
#[cfg(test)]
mod wit_invariants {
    /// The host `boatramp:handlers` WIT source.
    const WORLD_WIT: &str = include_str!("../wit/world.wit");

    /// The `boatramp:handlers` package MUST stay unversioned.
    ///
    /// This is the load-bearing rule behind the 0.3.0 capability-versioning design
    /// (PLAN v2). The host consumes one guest-provided export — `messaging-handler`,
    /// via `world consumer { export messaging-handler; }` — and wasmtime's export
    /// lookup (`ConsumerPre::new`) is **version-strict**. Put a `@x.y.z` on the
    /// package and that export becomes `messaging-handler@x.y.z`, so every
    /// already-deployed consumer built against the unversioned export fails
    /// activation with a misleading "component is not a wasi:messaging consumer" —
    /// exactly the v0.2.18 regression. Un-versioning defused that; this test keeps
    /// it disarmed.
    ///
    /// There is no version-window resolver yet (deliberately deferred to the first
    /// real interface break — see PLAN v2 steps 2/5). So versioning this package is
    /// only safe once that resolver exists: if you are here because you want to
    /// version an interface, build the resolver in the same change, then update this
    /// test. Note this asserts only the `boatramp:handlers` package line — the
    /// `wasi:*@0.2.0-draft` includes are upstream-standard versions and are fine.
    #[test]
    fn boatramp_handlers_package_is_unversioned() {
        let decl = WORLD_WIT
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with("package boatramp:handlers"))
            .expect("world.wit must declare `package boatramp:handlers`");
        assert_eq!(
            decl, "package boatramp:handlers;",
            "the boatramp:handlers package must stay UNVERSIONED — a version tag re-arms the \
             v0.2.18 consumer-export break (strict ConsumerPre::new lookup) for every deployed \
             consumer. Version an interface only once the version-window resolver exists \
             (PLAN v2 steps 2/5); then update this guard."
        );
    }
}
