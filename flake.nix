{
  description = "boatramp — a self-hosted, streaming-first alternative to Vercel for publishing static sites";

  # Public binary cache: pull prebuilt boatramp instead of building from source.
  # Populated by CI (.github/workflows/cache.yml) and the boatramp.dev deploy.
  # Pulls are anonymous; only CI pushes (needs the CACHIX_AUTH_TOKEN secret).
  nixConfig = {
    extra-substituters = [ "https://boatramp.cachix.org" ];
    extra-trusted-public-keys = [ "boatramp.cachix.org-1:ZEjT+bbyuOxBvWUF0xRKdf+UwnMdTlnXdWQJJbeLpS4=" ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-parts.url = "github:hercules-ci/flake-parts";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    git-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # crane builds the web console's `buildTrunkPackage` output
    # (`nix build .#console`). Fetched via `git+https` (the git
    # protocol) rather than `github:` so it doesn't hit the rate-limited GitHub
    # API for ref resolution.
    crane.url = "git+https://github.com/ipetkov/crane";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [ inputs.git-hooks.flakeModule ];

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        {
          config,
          self',
          pkgs,
          lib,
          system,
          ...
        }:
        let
          # The rust toolchain is described once, in ./rust-toolchain.toml, and
          # used both for the dev shell and for building the package so the
          # editor, CI and Nix all agree on the exact compiler.
          rustToolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;

          rustPlatform = pkgs.makeRustPlatform {
            cargo = rustToolchain;
            rustc = rustToolchain;
          };

          # crane with our pinned toolchain (which carries the
          # wasm32-unknown-unknown target) — used for the web console's
          # `buildTrunkPackage` output.
          craneLib = (inputs.crane.mkLib pkgs).overrideToolchain rustToolchain;

          # Args shared by the console's deps-only derivation and its Trunk
          # build. `--manifest-path` keeps `cargo` resolving the excluded console
          # + its `../boatramp-types` path dep in isolation (not the whole server
          # workspace, whose members pull in un-vendored deps like aws-config).
          consoleArgs = {
            pname = "boatramp-console";
            version = "0.1.0";
            src = lib.cleanSourceWith {
              src = ./.;
              filter =
                path: type:
                (craneLib.filterCargoSources path type) || (lib.hasInfix "/crates/boatramp-console/" path);
            };
            cargoLock = ./crates/boatramp-console/Cargo.lock;
            cargoToml = ./crates/boatramp-console/Cargo.toml;
            cargoExtraArgs = "--manifest-path crates/boatramp-console/Cargo.toml";
            doCheck = false; # app tests need a browser.
          };
          # Build the wasm dependency artifacts once, with crane's default cargo
          # command (NOT the Trunk override below — `trunk` isn't on the deps
          # build's PATH). Passing this explicitly stops `buildTrunkPackage` from
          # recomputing `cargoArtifacts` with the Trunk `buildPhaseCargoCommand`.
          consoleDeps = craneLib.buildDepsOnly (
            consoleArgs // { CARGO_BUILD_TARGET = "wasm32-unknown-unknown"; }
          );

          # The default build (server + CLI, filesystem backend) needs no native
          # libraries. These are kept around for the optional `s3` backend.
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];

          # Whole-workspace **clippy** as a flake check, built with crane so it
          # vendors the crates.io deps from `Cargo.lock` and runs **offline**
          # inside the `nix flake check` sandbox. The cachix/git-hooks `clippy`
          # hook can't do this: it shells out to `cargo` with no registry, so
          # deps like `argon2` fail to resolve (`offline mode … no matching
          # package`). Default features here (matching what the hook covered);
          # `--all-features` clippy stays an explicit CI step.
          clippyArgs = {
            # The root Cargo.toml is a virtual workspace (no `[package]`), so name
            # the derivation explicitly (crane can't infer it).
            pname = "boatramp-workspace";
            version = "0.1.0";
            # Keep every workspace file (build scripts read .sql/.ron/templates),
            # but drop the local `target/` and any `nix build` `result*` symlinks
            # so a stray dev build dir never bloats the store copy or leaks
            # read-only artifacts into the sandbox's cargo target dir.
            src = lib.cleanSourceWith {
              src = ./.;
              filter =
                path: type:
                let
                  base = baseNameOf path;
                in
                (lib.cleanSourceFilter path type)
                && base != "target"
                && base != "result"
                && !(lib.hasPrefix "result-" base);
            };
            strictDeps = true;
            cargoExtraArgs = "--workspace";
            inherit nativeBuildInputs buildInputs;
          };
          workspaceClippy = craneLib.cargoClippy (
            clippyArgs
            // {
              cargoArtifacts = craneLib.buildDepsOnly clippyArgs;
              cargoClippyExtraArgs = "--all-targets -- -D warnings";
            }
          );

          # Build the single `boatramp` binary with an optional extra feature set
          # on top of the defaults (`fs` + `slatedb`). The recipe lives in
          # ./nix/package.nix (shared with `overlays.default`); here we pin it to
          # the rust-overlay toolchain so the flake build matches the dev shell +
          # CI compiler. The cloud image (below) adds the `s3` (R2) +
          # `cloudflare-kv` backends.
          mkBoatramp =
            {
              features ? [ ],
            }:
            pkgs.callPackage ./nix/package.nix { inherit rustPlatform features; };

          # The CF Containers image feature set: R2 blobs (`s3`) + a networked KV
          # for metadata (`cloudflare-kv`); TLS terminates at the edge so the `tls`
          # feature is omitted. The cluster image
          # (HA / Raft) is built from source by `boatramp cloudflare`'s generated
          # Dockerfile (`--features cluster`); this is the single-instance base.
          boatrampCloud = mkBoatramp {
            features = [
              "s3"
              "cloudflare-kv"
            ];
          };

          # Default (base) feature set: fs blobs + SlateDB metadata. Backs the
          # `default` package (fly.io / any OCI host that provides a writable
          # volume for state).
          boatrampBase = mkBoatramp { };

          # The `container` image adds `domain-verify-dns`: the reference/dogfood
          # deployment self-hosts its own domains (e.g. docs.boatramp.dev on the
          # same fly app), where an HTTP ownership probe can't hairpin back to the
          # app — so it verifies ownership over public DNS-TXT instead.
          boatrampContainer = mkBoatramp { features = [ "domain-verify-dns" ]; };

          # Shared builder for the reproducible, Nix-first OCI images. The `container`
          # (base) and `container-cloudflare` (R2 + KV) targets differ only in the
          # binary's compiled backends and, consequently, whether they need a state
          # volume: the base image writes fs/SlateDB state so it runs as root to own a
          # mounted volume; the cloudflare image is stateless (R2 + KV) and stays
          # hardened as non-root. `cacert` is included so the binary can reach
          # R2/Cloudflare/ACME over HTTPS; TLS terminates upstream, so it listens plain.
          mkImage =
            {
              pkg,
              user ? null,
            }:
            pkgs.dockerTools.buildLayeredImage {
              name = "boatramp";
              tag = "latest";
              contents = [
                pkg
                pkgs.cacert
              ];
              config = {
                Entrypoint = [ "${lib.getExe pkg}" ];
                Cmd = [ "serve" ];
                ExposedPorts."8080/tcp" = { };
                Env = [
                  "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                  "BOATRAMP_ADDR=0.0.0.0:8080"
                ];
              }
              // lib.optionalAttrs (user != null) { User = user; };
            };
        in
        {
          # Apply the rust-overlay so `pkgs.rust-bin` is available everywhere in
          # this module (devShell, package, hooks).
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              (import inputs.rust-overlay)
              # MinIO is flagged insecure upstream; it is only a dev-only, local
              # testing tool here, so we clear the marker. Doing it in an overlay
              # (rather than config.permittedInsecurePackages) is version-
              # independent and survives nixpkgs bumps.
              (_final: prev: {
                minio = prev.minio.overrideAttrs (old: {
                  meta = (old.meta or { }) // {
                    knownVulnerabilities = [ ];
                  };
                });
              })
            ];
          };

          # ---- Packages ------------------------------------------------------
          # `perSystem` returns a plain attrset, so every package is one key of a
          # single `packages` definition (dotted + whole-attrset forms can't be
          # mixed). The Linux-only container image is merged in conditionally.
          packages = {
            # The single `boatramp` binary (server + CLI) with the filesystem
            # backend. The s3 / cloudflare-kv backends live behind cargo features
            # so the default build stays free of heavy native dependencies.
            default = boatrampBase;

            # ---- Reproducible microVM kernel (`nix build .#vmlinux`) --------
            # The uncompressed `vmlinux` ELF the embedded VMM boots via
            # `linux-loader` (`Elf::load`). Built from **Firecracker's own microVM
            # kernel config** (pinned) rather than the full nixpkgs config: minimal,
            # **no modules, no debug_info** (so the vmlinux is a few MB, not ~380),
            # with virtio-mmio/blk/net + ext4 + 8250 console compiled IN — matching
            # the backend's `pci=off root=/dev/vda` + virtio-MMIO cmdline. This is the
            # artifact CI signs + ships as `boatramp-vmlinux` (PLAN-dynamic-config
            # S4). Base LTS 6.1 matches the config; bumped per release for CVE cadence.
            # NOTE: build + boot are validated in CI (.github/workflows/vmlinux.yml) —
            # they can't run on the dev host.
            vmlinux =
              let
                # Firecracker's published microVM guest config, pinned to a release.
                fcConfig = pkgs.fetchurl {
                  url = "https://raw.githubusercontent.com/firecracker-microvm/firecracker/v1.10.1/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config";
                  hash = "sha256-OR2NSY+J5Ws5G+XqSnUB68RObQlDMeyqve/tHaayipY=";
                };
                # `linuxManualConfig` uses the Firecracker config as the kernel's
                # `.config` verbatim; no modules/debug_info ⇒ a small vmlinux.
                # nixpkgs only keeps `vmlinux` (in a `dev` output) for MODULAR
                # kernels; this one has CONFIG_MODULES off, so copy the uncompressed
                # ELF into $out ourselves (fixupPhase then strips it — still
                # Elf::load-able). `$buildRoot` is the exported out-of-tree build dir.
                micro = (pkgs.linuxManualConfig {
                  inherit (pkgs.linux_6_1) version src;
                  configfile = fcConfig;
                  allowImportFromDerivation = true;
                }).overrideAttrs (old: {
                  postInstall = (old.postInstall or "") + ''
                    cp "$buildRoot/vmlinux" "$out/vmlinux"
                  '';
                });
              in
              # `micro.dev or micro`: linuxManualConfig may not expose a `dev`
              # output, so fall back to the default output and locate the vmlinux
              # ELF wherever the kernel install placed it.
              pkgs.runCommand "boatramp-vmlinux" { } ''
                mkdir -p "$out"
                v="$(find ${micro} ${micro.dev or micro} -name vmlinux -type f 2>/dev/null | head -1)"
                if [ -z "$v" ]; then
                  echo "vmlinux ELF not found in kernel outputs:" >&2
                  find ${micro} ${micro.dev or micro} -maxdepth 2 >&2 || true
                  exit 1
                fi
                cp "$v" "$out/vmlinux"
              '';

            # ---- Web console (`nix build .#console`) ------------------------
            # The Yew (CSR) SPA, built to wasm32 + bundled by Trunk via crane's
            # `buildTrunkPackage`. The console crate is excluded
            # from the workspace (wasm32-only) but depends on ../boatramp-types by
            # path, so we build from the repo root with a source filter that keeps
            # cargo sources plus the whole console subtree. `consoleArgs` /
            # `consoleDeps` are defined in the `let` block above.
            console = craneLib.buildTrunkPackage (
              consoleArgs
              // {
                cargoArtifacts = consoleDeps;
                # The Tailwind pre-build hook needs the CLI on PATH at build time.
                nativeBuildInputs = [ pkgs.tailwindcss ];
                # Version-match gotcha: this MUST equal the `wasm-bindgen` crate
                # pinned in the crate's Cargo.toml (=0.2.121).
                wasm-bindgen-cli = pkgs.wasm-bindgen-cli;

                # crane's default runs `trunk build crates/boatramp-console/index.html`
                # from the repo root. From there Trunk runs `cargo metadata` against
                # the *workspace* root and tries to resolve every member — including
                # server-only deps (aws-config, ...) that aren't in the console's
                # vendored lock — and it also misses the crate's own Trunk.toml (the
                # Tailwind hook). Running Trunk from inside the crate dir fixes both:
                # `cargo metadata` then targets the crate manifest (console +
                # boatramp-types only), exactly like the dev-shell `trunk build`.
                buildPhaseCargoCommand = ''
                  local profileArgs=""
                  if [[ "$CARGO_PROFILE" == "release" ]]; then
                    profileArgs="--release=true"
                  fi
                  # crane installs the prebuilt deps under ./target at the source
                  # root; pin CARGO_TARGET_DIR to that absolute path so cargo reuses
                  # them after we cd into the crate (it defaults to a relative
                  # "target", which would resolve crate-locally and rebuild).
                  export CARGO_TARGET_DIR="$PWD/target"
                  pushd crates/boatramp-console >/dev/null
                  trunk build $profileArgs index.html
                  popd >/dev/null
                '';
                installPhaseCommand = ''
                  cp -r crates/boatramp-console/dist $out
                '';
              }
            );
          }
          # ---- Container images -------------------------------------------
          # `dockerTools` builds *Linux* images, so these are Linux-only (built in
          # CI / on a Linux host; CF needs `x86_64-linux`). Two targets, sharing
          # `mkImage` (above) and differing only in compiled backends:
          #
          #   nix build .#container             base: fs + SlateDB (fly.io / volume)
          #   nix build .#container-cloudflare  R2 (s3) + Cloudflare KV (stateless)
          # The cluster (HA / Raft) image is still built from source by
          # `boatramp cloudflare`'s generated recipe; these are the single-instance
          # bases.
          // lib.optionalAttrs pkgs.stdenv.isLinux {
            # Base image: default backends (fs blobs + SlateDB metadata). Runs as
            # root so it can own a mounted state volume (e.g. a fly.io volume).
            container = mkImage { pkg = boatrampContainer; };
            # Cloudflare image: R2 (`s3`) blobs + Cloudflare KV metadata. State is
            # remote so the container is stateless; stays hardened as `nobody`.
            container-cloudflare = mkImage {
              pkg = boatrampCloud;
              user = "65534:65534";
            };
          };

          # ---- Runnable app (`nix run . -- serve|sync|build`) ----------------
          apps.default.program = lib.getExe' self'.packages.default "boatramp";

          # ---- Dev shell -----------------------------------------------------
          devShells.default = pkgs.mkShell {
            # Installs the git hooks (see `pre-commit.settings.hooks` below) when
            # the shell is entered.
            inputsFrom = [ config.pre-commit.devShell ];

            nativeBuildInputs = [
              pkgs.pkg-config
              pkgs.cmake # aws-lc-rs, built when using `--features s3`
            ];
            buildInputs = [ pkgs.openssl ];

            packages = [
              rustToolchain
              pkgs.just
              # GitHub CLI: releases, PRs, and watching Actions runs (`gh run watch`).
              pkgs.gh
              # fly.io CLI: deploy the docs app + manage its secrets/certs.
              pkgs.flyctl
              pkgs.cargo-watch
              pkgs.cargo-nextest
              pkgs.cargo-deny
              pkgs.taplo
              pkgs.nixfmt
              # WebAssembly component tooling for the `handlers` engine.
              pkgs.wasm-tools
              # Local S3-compatible server for exercising the s3 backend.
              pkgs.minio
              pkgs.minio-client
              # curl: MinIO readiness probe in the CI s3 step (the host-mode
              # runner's bare step shell lacks it). (iproute2 for the gateway
              # probe is Linux-only — appended below.)
              pkgs.curl
              # sqld (the libsql server) for the cluster path of the handler
              # `sql` backend. `just sqld` starts it and prints the test URLs.
              pkgs.sqld
              # Pebble + its challenge test server: a local ACME CA for the
              # DNS-01 wildcard-cert integration test (`just acme-dns-e2e`).
              pkgs.pebble
              # The documentation site (docs/book.toml) is built with mdBook.
              pkgs.mdbook
              # Web console (crates/boatramp-console): the Yew (CSR) Wasm SPA is
              # built with Trunk + the standalone Tailwind CLI (Node-free). The
              # `wasm-bindgen-cli` version MUST match the `wasm-bindgen` crate
              # pinned in that crate's Cargo.toml — bump together.
              pkgs.trunk
              pkgs.wasm-bindgen-cli
              pkgs.tailwindcss
            ]
            # iproute2 (the CI s3 step's default-gateway probe) is Linux-only, so
            # it must not be in the cross-platform set or `nix develop` breaks on
            # macOS.
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.iproute2 ];

            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
            # libclang for bindgen (aws-lc-rs) when building `--features s3`.
            LIBCLANG_PATH = lib.makeLibraryPath [ pkgs.llvmPackages.libclang.lib ];

            shellHook = ''
              echo "boatramp dev shell ready — run 'just' to list tasks."
            '';
          };

          # ---- Formatter (`nix fmt`) ----------------------------------------
          formatter = pkgs.nixfmt;

          # ---- Checks (`nix flake check`) -----------------------------------
          # Clippy runs via crane (vendored, offline-capable) rather than the
          # git-hooks `clippy` hook, which can't resolve the registry in the
          # check sandbox. The pre-commit hooks below still run as a check too.
          #
          # On Linux, a `nixosTest` boots a VM with `services.boatramp.enable`
          # (via the module + overlay) and asserts the hardened unit starts + binds.
          # It's a real VM build, so it's a Linux-only / CI check (macOS builders
          # can't run it).
          checks = {
            clippy = workspaceClippy;
          }
          // lib.optionalAttrs pkgs.stdenv.isLinux {
            nixos-service = pkgs.testers.runNixOSTest {
              name = "boatramp-service";
              nodes.machine =
                { pkgs, ... }:
                {
                  imports = [ inputs.self.nixosModules.default ];
                  # `runNixOSTest` threads the host `pkgs` into the node read-only,
                  # which already pins `nixpkgs.overlays` — so re-setting it here
                  # collides. Point the service straight at the flake's built binary
                  # instead of pulling it in through the overlay.
                  services.boatramp = {
                    enable = true;
                    package = self'.packages.default;
                    configFile = pkgs.writeText "boatramp.cfg" ''
                      (serve: (addr: "127.0.0.1:8080", data_dir: "/var/lib/boatramp/data"))
                    '';
                  };
                };
              # The hardened unit must reach `active` and bind its port under the
              # full ProtectSystem/Restrict* sandbox — that's the whole point.
              testScript = ''
                machine.wait_for_unit("boatramp.service")
                machine.wait_for_open_port(8080)
              '';
            };
          };

          # ---- Git hooks -----------------------------------------------------
          # `nix develop` installs these into .git/hooks. `nix flake check` runs
          # them as a check. Clippy is intentionally NOT here — it's the crane
          # `checks.clippy` above (the hook's bare `cargo clippy` fails offline in
          # the flake-check sandbox). Devs still get clippy via `just lint` / CI.
          pre-commit.settings.hooks = {
            rustfmt = {
              enable = true;
              packageOverrides.cargo = rustToolchain;
              packageOverrides.rustfmt = rustToolchain;
            };
            nixfmt-rfc-style.enable = true;
            taplo.enable = true;
            typos.enable = true;
          };
        };

      # ---- Flake-level (system-independent) outputs ----------------------
      # An overlay exposing `boatramp` built with **stock nixpkgs** `rustPlatform`
      # (so a downstream flake needs no rust-overlay), plus the NixOS service
      # module. Consume from a downstream flake:
      #   imports = [ inputs.boatramp.nixosModules.default ];
      #   nixpkgs.overlays = [ inputs.boatramp.overlays.default ];
      #   services.boatramp.enable = true;
      flake = {
        overlays.default = final: _prev: {
          boatramp = final.callPackage ./nix/package.nix { };
        };
        nixosModules.default = import ./nix/nixos-module.nix;
      };
    };
}
