# Install boatramp

boatramp is a single binary — server and CLI in one. This page installs the
`boatramp` binary. Pick one method, then verify.

The prebuilt binary is batteries-included — it ships every non-conflicting feature
(publish, serve, handlers, TLS + ACME, HTTP/3, clustering, the Kubernetes operator,
the web console, and all blob/KV backends). For the platform matrix and the full
feature list, see [Cargo features & platform support](../reference/features.md); to
build a smaller binary, see [Build from source](./build-from-source.md).

Every method ends with the same verify step:

```sh
boatramp --version
```

```text
boatramp 0.2.1
```

## Install script (Linux / macOS)

The script downloads the release archive for your OS and architecture, verifies
its checksum, and installs `boatramp` to `~/.local/bin`:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/BoatRamp/BoatRamp/main/packaging/install/install.sh | sh
```

Set `BOATRAMP_VERSION=vX.Y.Z` to pin a version, or `BOATRAMP_INSTALL_DIR=…` to
change the target directory. On Windows, run the PowerShell script:

```powershell
irm https://raw.githubusercontent.com/BoatRamp/BoatRamp/main/packaging/install/install.ps1 | iex
```

## cargo install (crates.io)

With a Rust toolchain, install the released version from
[crates.io](https://crates.io/crates/boatramp):

```sh
cargo install boatramp --locked
```

This **compiles from source**, pulling the batteries-included feature set (wasmtime,
TLS, cloud SDKs), so expect a sizeable build — the prebuilt binary above is faster.
Pin a version with `cargo install boatramp@0.2.1 --locked`, or build a smaller binary
with `--no-default-features --features …` (see [Build from source](./build-from-source.md)).

## Homebrew (macOS / Linux)

```sh
brew install boatramp/tap/boatramp
```

## Container image

The image is multi-arch and runs as a non-root user:

```sh
docker run ghcr.io/boatramp/boatramp:latest --version
```

```text
boatramp 0.2.1
```

To serve, publish the port and pass `serve`:

```sh
docker run -p 8080:8080 ghcr.io/boatramp/boatramp:latest serve --tls off
```

## Nix / NixOS

Run or build straight from the flake:

```sh
nix run github:BoatRamp/BoatRamp -- --version         # the latest commit
nix run github:BoatRamp/BoatRamp/v0.2.1 -- --version  # pin a release
nix build github:BoatRamp/BoatRamp                    # -> ./result/bin/boatramp
```

On NixOS, the flake ships an overlay and a declarative `services.boatramp` module
with a hardened systemd unit:

```nix
imports = [ inputs.boatramp.nixosModules.default ];
nixpkgs.overlays = [ inputs.boatramp.overlays.default ];
services.boatramp.enable = true;
```

## Prebuilt archive

Download the release archive for your platform from the
[releases page](https://github.com/BoatRamp/BoatRamp/releases), extract it, and
put `boatramp` on your `PATH`:

```sh
tar xzf boatramp-*.tar.gz
install -m 0755 boatramp ~/.local/bin/boatramp
```

For which archive targets your platform and which compute backends it includes,
see [Cargo features & platform support](../reference/features.md).

## Next: publish a site

You have the binary. Publish something and serve it in
[Publish your first site](../tutorials/first-site.md).
