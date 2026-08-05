# Build from source

Compile the `boatramp` binary (server + CLI) yourself. The default build is
batteries-included — it enables every non-conflicting feature — so a plain
`cargo build` gives you the full capability set. For a smaller binary you can opt
down to just the features you want.

For prebuilt archives and packages instead, see [Install boatramp](./install.md).

## Before you start

Install a recent stable Rust toolchain with `rustup`, then confirm it:

```sh
cargo --version
```

```text
cargo 1.85.0
```

Clone the repository and change into it:

```sh
git clone https://github.com/BoatRamp/BoatRamp.git
cd BoatRamp
git checkout v0.2.1   # build a released version; omit to build the development tip (main)
```

## Build the default binary

Build the `boatramp` package in release mode:

```sh
cargo build --release -p boatramp
```

```text
    Finished `release` profile [optimized] target(s) in 6m 05s
```

This is the batteries-included build: every non-conflicting feature is compiled in
(blobs on fs/S3/GCS/Azure, TLS + ACME, HTTP/3, the handler engine, clustering, the
Kubernetes operator, OIDC, external signers, the bundler, and the web console).
The binary lands at `target/release/boatramp`. (A from-source build embeds a
placeholder console unless you build the SPA first with `just console`.)

## Build a minimal binary

To shrink the binary and its dependency tree, opt out of the defaults with
`--no-default-features` and name only the features you want. The smallest useful
build is filesystem blobs plus the SlateDB metadata store:

```sh
cargo build --release -p boatramp --no-default-features --features fs,slatedb
```

```text
    Finished `release` profile [optimized] target(s) in 1m 08s
```

Add more as you need them — e.g. `--features fs,slatedb,tls,handlers` for HTTPS
and the handler engine. Some features imply others: `acme-dns` and `http3` each
pull in `tls`, and `cluster` pulls in `handlers` and `slatedb`. For every feature
and what it enables, see [Cargo features & platform support](../reference/features.md).

## Build with Nix

The flake pins the exact toolchain from `rust-toolchain.toml`, so the compiler
matches CI:

```sh
nix build
```

```text
/nix/store/…-boatramp-0.2.1
```

The result is symlinked at `result/bin/boatramp`. Enter the dev shell with
`nix develop` for the pinned toolchain plus the `just build`, `just test`, and
`just lint` targets.

## Verify the build

```sh
./target/release/boatramp --version
```

```text
boatramp 0.2.1
```

## See also

- [Cargo features & platform support](../reference/features.md) — the full feature list.
- [Install boatramp](./install.md) — prebuilt archives, containers, and packages.
