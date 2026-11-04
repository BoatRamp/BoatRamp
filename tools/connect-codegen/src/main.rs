//! The boatramp Connect / gRPC-web **client** codegen (PLAN-connect-grpc §9 / IU-5).
//!
//! Compiles the `.proto` files under `proto/` into VENDORED/committed Rust under
//! `examples/connect-clients/src/generated/`: the `prost` message structs, plus — via
//! [`ConnectClientGenerator`] — a typed CLIENT per service. Each client method is a one-liner over
//! [`boatramp_connect_client::call_unary`] / [`call_server_stream`], the unary-vs-server-stream kind
//! derived from the proto `stream` keyword. This is the client-direction analog of the shim repo's
//! server codegen (which emits a `boatramp_connect::ConnectService` serving impl instead).
//!
//! Run only via `just codegen` inside `nix develop` (which supplies the nixpkgs-pinned `protoc`
//! that `prost-build` shells out to). The output is committed, so the normal build never runs this.
//!
//! [`call_server_stream`]: boatramp_connect_client::call_server_stream

use std::path::{Path, PathBuf};

use prost_build::{Method, Service, ServiceGenerator};

fn main() {
    // `CARGO_MANIFEST_DIR` is `tools/connect-codegen`; the repo root is two levels up.
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .canonicalize()
        .expect("resolve repo root");
    let proto_dir = root.join("proto");
    let out_dir = root.join("examples/connect-clients/src/generated");

    // All client services share one output directory; prost-build names each file by its proto
    // package (`connect.greeter.v1.rs`, `connect.ticker.v1.rs`).
    let protos = [
        "connect/greeter/v1/greeter.proto",
        "connect/ticker/v1/ticker.proto",
    ];

    std::fs::create_dir_all(&out_dir).expect("create out dir");
    generate(&proto_dir, &protos, &out_dir);
    eprintln!(
        "connect-codegen: done ({} proto(s) -> {})",
        protos.len(),
        out_dir.display()
    );
}

fn generate(proto_dir: &Path, protos: &[&str], out_dir: &Path) {
    let mut cfg = prost_build::Config::new();
    cfg.service_generator(Box::new(ConnectClientGenerator::default()));
    cfg.out_dir(out_dir);
    let inputs: Vec<PathBuf> = protos.iter().map(|p| proto_dir.join(p)).collect();
    cfg.compile_protos(&inputs, &[proto_dir])
        .unwrap_or_else(|e| panic!("codegen failed: {e}"));
    for p in protos {
        eprintln!("connect-codegen: {p}");
    }
}

/// Emits a typed `boatramp_connect_client` client per service: `pub struct <Service>Client`, its
/// fully-qualified `SERVICE` name, and one method per RPC that calls the shared unary /
/// server-stream primitive with the generated request/response message types.
#[derive(Default)]
struct ConnectClientGenerator;

impl ServiceGenerator for ConnectClientGenerator {
    fn generate(&mut self, service: Service, buf: &mut String) {
        let fq_name = format!("{}.{}", service.package, service.name);
        let client = format!("{}Client", service.name);
        buf.push_str(&format!(
            "\n/// Connect / gRPC-web client for `{fq_name}` (generated — see `just codegen`).\n"
        ));
        buf.push_str("///\n");
        buf.push_str(&format!(
            "/// Each method invokes the RPC over a [`boatramp_connect_client::Transport`] at an\n\
             /// [`boatramp_connect_client::Endpoint`]; the request/response types are the generated\n\
             /// `prost` messages above.\n"
        ));
        buf.push_str(&format!("pub struct {client};\n"));
        buf.push_str(&format!("impl {client} {{\n"));
        buf.push_str(&format!(
            "    /// The fully-qualified Connect service name (the `{{package}}.{{Service}}` path segment).\n"
        ));
        buf.push_str(&format!(
            "    pub const SERVICE: &'static str = \"{fq_name}\";\n"
        ));
        for method in &service.methods {
            emit_method(buf, method);
        }
        buf.push_str("}\n");
    }
}

/// Emit one client method. Client- and bidi-streaming are out of scope on this transport (PLAN §1);
/// codegen refuses them loudly rather than emit an uncallable stub.
fn emit_method(buf: &mut String, method: &Method) {
    if method.client_streaming {
        panic!(
            "{}: client-streaming is out of scope for the Connect transport (PLAN §1)",
            method.proto_name
        );
    }
    let fn_name = &method.name; // prost already lower-snake-cases the Rust method name.
    let proto_name = &method.proto_name; // the wire `Method` path segment.
    let input = &method.input_type;
    let output = &method.output_type;

    // A short doc line for the method (its leading proto comment, if any).
    for line in method.comments.leading.iter() {
        buf.push_str(&format!("    ///{line}\n"));
    }

    if method.server_streaming {
        buf.push_str(&format!(
            "    /// Server-streaming RPC `{proto_name}` — returns a [`boatramp_connect_client::ServerStream`]\n    /// yielding each `{output}` and, at the end, the terminal status.\n"
        ));
        buf.push_str(&format!(
            "    pub fn {fn_name}<__T: ::boatramp_connect_client::Transport>(\n\
             \x20       transport: &__T,\n\
             \x20       endpoint: &::boatramp_connect_client::Endpoint,\n\
             \x20       request: {input},\n\
             \x20   ) -> ::core::result::Result<\n\
             \x20       ::boatramp_connect_client::ServerStream<{output}>,\n\
             \x20       ::boatramp_connect_client::ConnectClientError,\n\
             \x20   > {{\n\
             \x20       ::boatramp_connect_client::call_server_stream(transport, endpoint, Self::SERVICE, \"{proto_name}\", &request)\n\
             \x20   }}\n"
        ));
    } else {
        buf.push_str(&format!(
            "    /// Unary RPC `{proto_name}` — one `{input}` in, one `{output}` out.\n"
        ));
        buf.push_str(&format!(
            "    pub fn {fn_name}<__T: ::boatramp_connect_client::Transport>(\n\
             \x20       transport: &__T,\n\
             \x20       endpoint: &::boatramp_connect_client::Endpoint,\n\
             \x20       request: {input},\n\
             \x20   ) -> ::core::result::Result<{output}, ::boatramp_connect_client::ConnectClientError> {{\n\
             \x20       ::boatramp_connect_client::call_unary(transport, endpoint, Self::SERVICE, \"{proto_name}\", &request)\n\
             \x20   }}\n"
        ));
    }
}
