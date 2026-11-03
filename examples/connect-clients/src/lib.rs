//! Generated Connect / gRPC-web **clients** — the vendored output of `just codegen` (PLAN-connect-grpc
//! §9 / IU-5). Each module is a proto package compiled by the Nix-pinned `prost`/`protoc` toolchain
//! into its `prost` message types plus a typed `<Service>Client` whose methods call the
//! [`boatramp_connect_client`] unary / server-stream primitives.
//!
//! The generated files under `src/generated/` are committed and byte-reproducible; do not hand-edit
//! them — change the `.proto` under `proto/` and rerun `just codegen`.
//!
//! These are the exact services the host Connect live gates serve (`connect-greeter` unary,
//! `connect-ticker` server-stream), so the generated clients here drive those gates end-to-end.

/// `connect.greeter.v1` — the unary greeter (`Greeter/SayHello`).
pub mod greeter {
    include!("generated/connect.greeter.v1.rs");
}

/// `connect.ticker.v1` — the server-streaming ticker (`Ticker/Subscribe`).
pub mod ticker {
    include!("generated/connect.ticker.v1.rs");
}
