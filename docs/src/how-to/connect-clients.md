# Generate a Connect / gRPC-web client

**For: app developers**

A boatramp function can serve a [Connect](https://connectrpc.com/) / gRPC-web RPC service — a
protobuf `service` reachable over plain HTTP, no HTTP/2 trailers required (the serving side is the
`boatramp-connect` shim). This guide is the other half: how to **generate a client** from that
service's `.proto` and call it.

Everything a client needs that is boatramp-specific is small — three things:

| What | Value |
|---|---|
| **Endpoint URL shape** | `{site-origin}/{package}.{Service}/{Method}` — e.g. `https://app.example.com/connect.greeter.v1.Greeter/SayHello`. If you address a site by its internal route prefix rather than its domain, include it: `https://node.example.com/_sites/<site>/connect.greeter.v1.Greeter/SayHello`. |
| **Auth header** | The boatramp token as a standard bearer: `Authorization: Bearer <token>`. Whether a call is rejected without one is up to the service's `authorize = …` (see [Restrict visitor access](./visitor-access.md) and [Bootstrap authentication](./auth-bootstrap.md)); the host forwards the header to the function for in-guest verification. |
| **Connect protocol version** | `1`. Connect clients send `Connect-Protocol-Version: 1` on unary requests; every upstream Connect client and the boatramp client shim do this automatically. |

The transport is binary protobuf over one of the Connect / gRPC-web content types
(`application/proto` for Connect unary, `application/connect+proto` for a Connect stream, or
`application/grpc-web+proto`). The JSON codec is not yet supported — use binary proto.

> Client-streaming and bidirectional streaming are out of scope on this transport. A service exposes
> **unary** and **server-streaming** methods only.

## The codegen toolchain (reproducible, pinned)

All client codegen is driven by `just codegen`, which runs inside the Nix dev shell so the whole
toolchain is flake-pinned and the committed output is byte-reproducible (regenerate twice ⇒
identical bytes):

- **Rust** — `protoc` + `prost-build` (`tools/connect-codegen`) emit the `prost` message types plus
  a typed client per service, vendored under `examples/connect-clients/src/generated/`.
- **Web / TypeScript** — [`buf`](https://buf.build) + the exact-pinned `@bufbuild/protoc-gen-es`
  emit a [connect-es](https://connectrpc.com/docs/web/) client, vendored under
  `clients/ts/generated/`.

```sh
just codegen   # regenerate every vendored client from proto/
```

Put your service's `.proto` under `proto/<package path>/…`, add it to the codegen targets
(`tools/connect-codegen/src/main.rs` for Rust, `proto/buf.gen.yaml` is already wildcard for TS), and
rerun `just codegen`.

## Rust

The generated client is a thin typed wrapper over the `boatramp-connect-client` shim, which carries
the call over a pluggable [`Transport`]. The shipped `PlaintextHttpTransport` speaks `http://`
(enough for a loopback or overlay-tunneled dial); for a production `https://` endpoint, implement
`Transport` over any TLS-capable HTTP client — about ten lines over `reqwest::blocking` (see the
crate docs).

```rust,ignore
use boatramp_connect_client::{ClientProtocol, Endpoint, PlaintextHttpTransport};
use connect_clients::greeter::{GreeterClient, SayHelloRequest};
use connect_clients::ticker::{SubscribeRequest, TickerClient};

let transport = PlaintextHttpTransport::new();
let endpoint = Endpoint::new("http://127.0.0.1:8080/_sites/mysite")
    .with_token("<boatramp token>");            // optional; sent as Authorization: Bearer

// Unary.
let reply = GreeterClient::say_hello(&transport, &endpoint, SayHelloRequest { name: "ada".into() })?;
assert_eq!(reply.greeting, "hello, ada!");

// Server-stream — iterate messages; a non-ok terminal status surfaces as the final Err.
let stream = TickerClient::subscribe(&transport, &endpoint, SubscribeRequest { count: 4 })?;
for tick in stream {
    let tick = tick?;
    println!("tick {}", tick.seq);
}

// gRPC-web instead of Connect: .with_protocol(ClientProtocol::GrpcWeb) on the endpoint.
```

## Web / TypeScript

The generated connect-es client is used with the upstream `@connectrpc/connect` +
`@connectrpc/connect-web` runtime. Use the binary-proto transport:

```ts
import { createClient } from "@connectrpc/connect";
import { createConnectTransport } from "@connectrpc/connect-web";
import { Greeter } from "./generated/connect/greeter/v1/greeter_pb.js";

const transport = createConnectTransport({
  baseUrl: "https://app.example.com",   // or https://node.example.com/_sites/mysite
  useBinaryFormat: true,                 // binary proto (the JSON codec is not yet supported)
  interceptors: [
    (next) => async (req) => {
      req.header.set("Authorization", `Bearer ${token}`);  // the boatramp token
      return await next(req);
    },
  ],
});

const greeter = createClient(Greeter, transport);
const { greeting } = await greeter.sayHello({ name: "ada" });
```

A runnable end-to-end check lives at `clients/ts/verify.ts` (point `BOATRAMP_CONNECT_URL` at a live
endpoint and run `npm run verify`). `npm run typecheck` checks the generated client against the
pinned runtime with no live endpoint.

## Other languages (Go, Swift, Kotlin, Python)

The same pinned `buf` generates a client for every language `buf` supports — these are not gated in
CI day-one, but the one-liner is the same recipe (add a plugin stanza to a `buf.gen.yaml` and run
`buf generate`). Using the connectrpc remote plugins:

```sh
# Go (connect-go):
buf generate proto --template - <<'EOF'
version: v2
plugins:
  - remote: buf.build/protocolbuffers/go
    out: gen/go
  - remote: buf.build/connectrpc/go
    out: gen/go
EOF

# Swift:   remote: buf.build/connectrpc/swift
# Kotlin:  remote: buf.build/connectrpc/kotlin
# Python:  remote: buf.build/protocolbuffers/python  (+ grpc/connecpy for the service)
```

For a fully offline/pinned build, install the language's connect plugin locally (as the Web/TS
client does) and reference it with `local:` instead of `remote:`. The endpoint URL shape, the
`Authorization: Bearer` header, and `Connect-Protocol-Version: 1` are identical across every
language.

[`Transport`]: https://docs.rs/boatramp-connect-client
