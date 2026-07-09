# Build from source

Compile the `boatramp` binary (server + CLI) yourself and choose which
capabilities to include. The default build is lean — filesystem blobs and the
SlateDB metadata store — and every heavier capability is a cargo feature you add
on the build command.

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
```

## Build the default binary

Build the `boatramp` package in release mode:

```sh
cargo build --release -p boatramp
```

```text
    Finished `release` profile [optimized] target(s) in 2m 41s
```

This compiles the default features, `fs` and `slatedb`. The binary lands at
`target/release/boatramp`.

## Select features

Name extra features with `--features`, comma-separated, to compile in more
capabilities. This build adds HTTPS, the handler engine, and wildcard ACME
DNS-01:

```sh
cargo build --release -p boatramp --features tls,handlers,acme-dns
```

```text
    Finished `release` profile [optimized] target(s) in 3m 12s
```

Some features imply others — `acme-dns` and `http3` each pull in `tls`, and
`cluster` pulls in `handlers` and `slatedb`. For every feature and what it
enables, see [Cargo features & platform support](../reference/features.md).

## Build with Nix

The flake pins the exact toolchain from `rust-toolchain.toml`, so the compiler
matches CI:

```sh
nix build
```

```text
/nix/store/…-boatramp-0.1.0
```

The result is symlinked at `result/bin/boatramp`. Enter the dev shell with
`nix develop` for the pinned toolchain plus the `just build`, `just test`, and
`just lint` targets.

## Verify the build

```sh
./target/release/boatramp --version
```

```text
boatramp 0.1.0
```

## See also

- [Cargo features & platform support](../reference/features.md) — the full feature list.
- [Install boatramp](./install.md) — prebuilt archives, containers, and packages.
