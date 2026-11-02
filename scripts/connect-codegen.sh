#!/usr/bin/env bash
# Connect / gRPC-web CLIENT codegen (PLAN-connect-grpc §9 / IU-5). Compiles the `.proto` under
# `proto/` into the VENDORED/committed clients — the Rust client (prost + a typed client per service,
# on `boatramp-connect-client`) and the Web/TypeScript connect-es client. Reproducible: the same
# Nix-pinned `protoc` + `buf` + the exact-pinned `prost-build` (tools/connect-codegen) and
# `@bufbuild/protoc-gen-es` (clients/ts/package-lock.json) ⇒ identical bytes.
#
# Run via `just codegen` (which wraps this in `nix develop` so protoc + buf are the pinned ones).
set -euo pipefail

# Resolve the repo root from this script's location (scripts/..).
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "== Rust client codegen (prost) =="
# `--manifest-path` keeps the codegen tool in its own workspace so it never enters the normal build.
cargo run --quiet --manifest-path tools/connect-codegen/Cargo.toml

echo "== Web/TypeScript client codegen (buf + protoc-gen-es) =="
# Restore the exact-pinned codegen plugin, then run buf with it on PATH. `npm ci` is reproducible
# (installs exactly the committed package-lock.json).
npm --prefix clients/ts ci --no-audit --no-fund
PATH="$ROOT/clients/ts/node_modules/.bin:$PATH" buf generate proto --template proto/buf.gen.yaml

echo "== typecheck the generated Web/TS client =="
( cd clients/ts && node_modules/.bin/tsc --noEmit )

echo "codegen done — review + commit:"
echo "  examples/connect-clients/src/generated/*.rs   (Rust client)"
echo "  clients/ts/generated/**/*_pb.ts               (Web/TS connect-es client)"
