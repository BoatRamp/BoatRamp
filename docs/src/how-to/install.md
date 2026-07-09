# Install boatramp

boatramp is a single binary — server and CLI in one. This page installs the
`boatramp` binary. Pick one method, then verify.

The prebuilt binary ships the lean default feature set: publish, serve, handlers,
and TLS for most sites. For the platform matrix and what each feature adds, see
[Cargo features & platform support](../reference/features.md); to enable extra
features, see [Build from source](./build-from-source.md).

Every method ends with the same verify step:

```sh
boatramp --version
```

```text
boatramp 0.1.0
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
boatramp 0.1.0
```

To serve, publish the port and pass `serve`:

```sh
docker run -p 8080:8080 ghcr.io/boatramp/boatramp:latest serve --tls off
```

## Nix / NixOS

Run or build straight from the flake:

```sh
nix run github:BoatRamp/BoatRamp -- --version
nix build github:BoatRamp/BoatRamp        # -> ./result/bin/boatramp
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
