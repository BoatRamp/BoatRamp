# boatramp Connect Web/TypeScript clients

The vendored [connect-es](https://connectrpc.com/docs/web/) clients for the boatramp Connect /
gRPC-web example services (PLAN-connect-grpc IU-5). See
[`docs/src/how-to/connect-clients.md`](../../docs/src/how-to/connect-clients.md) for the full guide
(endpoint URL shape, the `Authorization: Bearer` header, the Connect protocol version).

- `generated/**/*_pb.ts` — the **committed** connect-es client (messages + service descriptors),
  produced by `just codegen` (buf + the exact-pinned `@bufbuild/protoc-gen-es`). Do not hand-edit;
  change the `.proto` under `proto/` and rerun `just codegen`.
- `verify.ts` — a runnable end-to-end check against a live endpoint.
- The codegen + runtime versions are exact-pinned in `package.json` / `package-lock.json`.

## Commands

```sh
npm ci                 # restore the exact pinned toolchain + runtime
npm run typecheck      # tsc --noEmit — checks the generated client vs the pinned runtime (no live endpoint)

# live round trip against a running boatramp Connect endpoint:
BOATRAMP_CONNECT_URL=https://<host>/_sites/<site> [BOATRAMP_TOKEN=<token>] npm run verify
```

## Why `verify` is not a CI gate

A connect-web round trip needs a *standing* boatramp Connect endpoint. The Rust client live gates
(`crates/boatramp-server/tests/connect_client_*_live.rs`) spin the server in-process, which a
separate Node process cannot reuse — so rather than fake a passing gate, the Web/TS client ships
this runnable `verify.ts` plus the `npm run typecheck` signal (which proves the generated client and
the pinned connect runtime agree). The wire itself is covered by the Rust client live gates: the
connect-es client targets the identical Connect / gRPC-web binary-proto wire.
