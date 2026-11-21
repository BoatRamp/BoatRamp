# Install boatramp

**For: operators & app developers**

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
boatramp 0.47.0
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
Pin a version with `cargo install boatramp@0.47.0 --locked`, or build a smaller binary
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
boatramp 0.47.0
```

To serve, publish the port and pass `serve`:

```sh
docker run -p 8080:8080 ghcr.io/boatramp/boatramp:latest serve --tls off
```

## Nix / NixOS

Run or build straight from the flake:

```sh
nix run github:BoatRamp/BoatRamp -- --version         # the latest commit
nix run github:BoatRamp/BoatRamp/v0.47.0 -- --version  # pin a release
nix build github:BoatRamp/BoatRamp                    # -> ./result/bin/boatramp
```

On NixOS, the flake ships an overlay and a declarative `services.boatramp` module
with a hardened systemd unit:

```nix
imports = [ inputs.boatramp.nixosModules.default ];
nixpkgs.overlays = [ inputs.boatramp.overlays.default ];
services.boatramp.enable = true;
```

To run the **native** compute backends (`container` / `firecracker`) on a NixOS node, also set
`services.boatramp.compute = true`. The default systemd sandbox is too tight to build the
compute bridge — a non-root service under `NoNewPrivileges=true` needs the capabilities as
**ambient** (a bounding-set-only grant is inert), and `AF_NETLINK` must be permitted for the
rtnetlink socket. Setting `compute = true` grants the service the ambient `CAP_NET_ADMIN`,
`CAP_SYS_ADMIN`, `CAP_SETUID`, and `CAP_SETGID` capabilities, the `/dev/kvm`+`/dev/net/tun`
device access, and allows `AF_NETLINK`, which is what those backends need to create the
`br-boatramp` bridge and per-guest veths; without it the bridge fails to come up
(`EAFNOSUPPORT`) and the native backends stay disabled:

```nix
services.boatramp.enable = true;
services.boatramp.compute = true;   # grants the ambient caps + kvm/tun + AF_NETLINK for the native backends
```

`CAP_SYS_ADMIN` is broad — it is the documented opt-in, so enable `compute` only on a node you
intend to run **native** compute workloads on. The **docker** backend runs through the docker
daemon and needs none of this relaxation, so a **docker-only node leaves `compute = false`** and
keeps the tight sandbox.

The compute-shim firewall opening and the `BOATRAMP_COMPUTE_*_SHIM_URL` server env follow
`services.boatramp.computeShimUrls` (plus `computeShimPorts`) — **independent of `compute`**.
Set the shim URLs and the module feeds them to the server AND opens **only** their ports on the
boatramp compute bridges (least privilege) — the static `br-boatramp` and the per-project docker
`boatramp-*` bridges **only**, never the LAN/public interface or an unrelated docker bridge — so a
bridged workload reaches its `--bind` shims on a default-firewall host whether the node runs the
docker backend (`compute = false`) or the native backends (`compute = true`). See
[Shim reachability + the compute firewall](./compute.md#nixos-open-the-compute-firewall), which also
covers the one-time upgrade step (cycle docker compute workloads so their networks recreate with the
scoped bridge name).

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
