# Write your first handler

In this tutorial you build a WebAssembly handler, wire it to a route, and call
it. You start from a handler boatramp ships as an example, so the build is
guaranteed to work, then deploy it to a running server.

You need the `boatramp` binary (see [Install boatramp](../how-to/install.md), and
a server built with the `handlers` feature) and a Rust toolchain with `cargo`.

## 1. Get the example handler

boatramp's repository ships example handlers under `examples/handlers`. The
simplest, `http-200`, exports `wasi:http/incoming-handler` and answers every
request with a fixed body. Clone the repository and change into it:

```sh
git clone https://github.com/BoatRamp/BoatRamp.git
cd BoatRamp
```

## 2. Build it to a component

A handler is a WebAssembly component built for the `wasm32-wasip2` target. Add
the target once, then build the example in release mode:

```sh
rustup target add wasm32-wasip2
cargo build -p boatramp-example-http-200 --target wasm32-wasip2 --release
```

```text
    Finished `release` profile [optimized] target(s) in 21.4s
```

The component is at
`target/wasm32-wasip2/release/boatramp_example_http_200.wasm`. Copy it next to a
site folder you will publish:

```sh
mkdir -p site
cp target/wasm32-wasip2/release/boatramp_example_http_200.wasm site/hello.wasm
```

## 3. Wire it to a route

Create `project.cfg` in the project folder and declare the handler under
`routing.handlers`. This entry serves the component at `/hello` for `GET`
requests; it requests no host bindings:

```ron
(
    publish: ( server: "http://127.0.0.1:8080", site: "my-site" ),
    routing: (
        handlers: [
            ( route: "/hello", component: "hello.wasm", methods: ["GET"], imports: [] ),
        ],
    ),
)
```

## 4. Validate and publish

Check the config, then publish the `site` folder. The component blob is validated
at sync — parseability and the `wasi:http/incoming-handler` export:

```sh
boatramp validate
```

```text
project.cfg: routing OK (1 handler: /hello [GET])
```

Start the server in another terminal (`boatramp serve`), then sync:

```sh
boatramp sync ./site
```

```text
validated hello.wasm — exports wasi:http/incoming-handler
uploading 1 missing blob(s)… done
activated my-site -> 8c1f2a3d — handler /hello
```

## 5. Call the route

`my-site` is the only site on this server, so it answers at the root — call the
handler's route directly:

```sh
curl http://127.0.0.1:8080/hello
```

```text
hello from boatramp handler
```

Your handler is live. It ran in an in-process wasmtime sandbox, reached only what
you granted (nothing, here), and streamed its response.

## Where to go next

- Grant a handler data access: [Use kv / sql / blobstore / messaging](../how-to/handler-bindings.md).
- Run work off the request path: [Run consumers, crons, and streams](../how-to/background-work.md).
- Deploy a component you built elsewhere: [Deploy a handler](../how-to/deploy-handler.md).
