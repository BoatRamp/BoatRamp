# Installation

boatramp is a **single binary** (server + CLI). Grab a prebuilt release for your
platform, or build from source.

## Install script (Linux / macOS)

Downloads the right release archive for your OS/arch, verifies its SHA-256, and
installs `boatramp` to `~/.local/bin`:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://raw.githubusercontent.com/BoatRamp/BoatRamp/main/packaging/install/install.sh | sh
```

`BOATRAMP_VERSION=vX.Y.Z` pins a version; `BOATRAMP_INSTALL_DIR=…` changes the
target directory.

**Windows** (PowerShell):

```powershell
irm https://raw.githubusercontent.com/BoatRamp/BoatRamp/main/packaging/install/install.ps1 | iex
```

## Homebrew (macOS / Linux)

```sh
brew install boatramp/tap/boatramp
```

## Container image

Multi-arch, runs as a non-root user:

```sh
docker run -p 8080:8080 ghcr.io/boatramp/boatramp:latest serve --tls off
```

The image is built reproducibly from the Nix flake. See the
[Cloudflare guide](../deployment/cloudflare.md) for the Containers deployment.

## NixOS

The flake ships an overlay + a `services.boatramp` module (declarative, hardened
systemd unit). In a host config:

```nix
imports = [ inputs.boatramp.nixosModules.default ];
nixpkgs.overlays = [ inputs.boatramp.overlays.default ];
services.boatramp = {
  enable = true;
  configFile = pkgs.writeText "boatramp.cfg" ''(serve: (addr: "0.0.0.0:8080"))'';
};
```

Or run/build straight from the flake:

```sh
nix run github:BoatRamp/BoatRamp -- serve
nix build github:BoatRamp/BoatRamp        # → ./result/bin/boatramp
```

## Build from source

### With Nix (pins the exact toolchain)

```sh
nix develop        # Rust toolchain, just, git hooks, …
just build         # release binary
just test          # test suite
just lint          # clippy + formatting + cargo-deny
```

### With Cargo

The default build is lean — heavier capabilities are behind cargo features:

```sh
cargo build --release -p boatramp --features tls,handlers,acme-dns
./target/release/boatramp --help
```

| Feature | Adds |
| --- | --- |
| `tls` | `--tls custom` / `--tls acme` (HTTPS) |
| `acme-dns` | wildcard ACME DNS-01 + the `dns` subcommand |
| `handlers` | the WebAssembly handler engine (wasmtime) |
| `cluster` | self-hosted Raft cluster mode + `boatramp cloudflare` |
| `oidc` | OIDC bearer-JWT control-plane auth |
| `signer-{aws,gcp,azure,vault,pkcs11}` | external KMS/HSM/Vault token signer |
| `compression` | on-the-fly response compression |
| `http3` | HTTP/3 (QUIC) serving |
| `bundler` | the embedded JS/CSS bundler (`bundle`) |
| `s3` / `cloudflare-kv` | the S3 blob backend / Cloudflare KV metadata backend |

## Platform support

The **publish / serve / handler / TLS / cluster** core is cross-platform. The
**compute execution** backends (microVM + native container: `/dev/kvm`,
namespaces, jailer) are Linux-only and compile to no-ops elsewhere.

| Platform | Prebuilt archive | Compute backends |
| --- | --- | --- |
| Linux `x86_64`, `aarch64` | full feature set | ✅ (VMM / container) |
| macOS `aarch64`, `x86_64` | portable core | remote-docker only |
| Windows `x86_64` | portable core | remote-docker only |

The portable core is `tls, handlers, cluster, s3, cloudflare-kv, compression,
bundler, oidc`; the remote-docker backend (a cross-platform Engine-API client)
works everywhere.

## Verify

```sh
boatramp --version
boatramp serve        # starts on 127.0.0.1:8080 with the filesystem backend
```
