# Contributing

boatramp is a Rust workspace. The default build stays lean; heavier capabilities
(TLS, ACME DNS-01, clustering, handlers, OIDC, compression, HTTP/3, the bundler)
are behind cargo features.

## Building & testing

```sh
cargo build                         # lean default
cargo test --workspace              # the full suite
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check                    # advisories / bans / licenses / sources
```

When you touch a feature-gated area, run clippy with that feature too — e.g.
`cargo clippy -p boatramp-server --features handlers,oidc,compression
--all-targets -- -D warnings`. The pre-commit hooks run clippy, rustfmt, taplo,
and typos.

## Principles

- **Streaming-first.** No byte path may buffer a whole file in memory.
- **One UX across deploy targets.** Environment differences live behind the
  `Storage` / `KvStore` / `Messaging` trait seams, never in the commands, flags,
  or config.
- **Complete implementations.** Prefer real, validated code over stubs.
- **Lean default build.** New heavy dependencies go behind a feature.
- **Pure logic in `boatramp-core`.** Keep routing/config/access decisions pure
  and unit-testable; push I/O and runtimes to the edges.

## Design docs

The `docs/*.md` files (outside `src/`) are the design record:

- `ARCHITECTURE-kv.md` — the KV stack and shared-mode coherence.
- `KEYSPACE.md`, `OPERATING.md` — the keyspace and the operator guide.
- `CLOUDFLARE.md` — the Cloudflare deployment design.

This documentation site (`docs/src/`) is built with
[mdBook](https://rust-lang.github.io/mdBook/): `mdbook serve docs` to preview,
`mdbook build docs` to render.

## What's validated where

Most behavior is unit- and integration-tested natively. Capabilities that need
live infrastructure — a real ACME CA, multi-host clusters, the Cloudflare
platform — are validated against that infrastructure and flagged as such in context.
