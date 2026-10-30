{
  description = "boatramp — a self-hosted, streaming-first alternative to Vercel for publishing static sites";

  # Public binary cache: pull prebuilt boatramp instead of building from source.
  # Populated by CI (.github/workflows/cache.yml) and the boatramp.dev deploy.
  # Pulls are anonymous; only CI pushes (needs the CACHIX_AUTH_TOKEN secret).
  nixConfig = {
    extra-substituters = [ "https://boatramp.cachix.org" ];
    extra-trusted-public-keys = [
      "boatramp.cachix.org-1:ZEjT+bbyuOxBvWUF0xRKdf+UwnMdTlnXdWQJJbeLpS4="
    ];
  };

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # MinIO (a dev-only, local S3 test double — see `just minio`) was dropped from
    # nixos-unstable when it was abandoned upstream, so it is pinned here to the last
    # nixpkgs rev that still packaged it. It is NOT in the build/release path — only
    # the devShell + the `just minio` recipe use it — so this pin never touches a
    # shipped artifact.
    nixpkgs-minio.url = "github:NixOS/nixpkgs/a799d3e3886da994fa307f817a6bc705ae538eeb";

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

          # Pebble pinned to >= 2.10.0. nixpkgs currently ships 2.6.0, but the ACME
          # DNS-01 regression gate (crates/boatramp-acme/tests/pebble_dns01.rs) needs
          # a CA that emits the tokenless `dns-persist-01` challenge, which Pebble
          # only started doing in v2.10.0 (mirroring Let's Encrypt / Google Trust
          # Services in production). On the old instant-acme (< 0.8.5) that tokenless
          # challenge fails to deserialize ("missing field `token`") and wrecks the
          # whole authorization; the gate proves the 0.8.5 bump tolerates it. Pebble
          # vendors its Go deps in-tree (`vendorHash = null`), so only the src hash
          # changes. `doCheck = false`: upstream's own Go test suite isn't our gate.
          pebble = pkgs.pebble.overrideAttrs (
            final: _prev: {
              version = "2.10.1";
              src = pkgs.fetchFromGitHub {
                owner = "letsencrypt";
                repo = "pebble";
                rev = "v${final.version}";
                hash = "sha256-O9lVC/GhbN3R7RuWZzr1kznbz0ffr+qdNSa/FpVTWzY=";
              };
              doCheck = false;
            }
          );

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

          # ---- Web console SPA (also `nix build .#console`) ------------------
          # The Yew (CSR) SPA, built to wasm32 + bundled by Trunk via crane's
          # `buildTrunkPackage`. Defined here (not inline under `packages`) so
          # `mkBoatramp` can stage its `dist` into the binary — `console` is a
          # default cargo feature, so every boatramp build embeds it. The console
          # crate is excluded from the workspace (wasm32-only) but depends on
          # ../boatramp-types by path, so we build from the repo root with a
          # source filter that keeps cargo sources plus the whole console subtree.
          consolePackage = craneLib.buildTrunkPackage (
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

          # The default build (server + CLI, filesystem backend) needs no native
          # libraries. `pkg-config` is kept around for the optional `s3` backend;
          # on macOS `zig` cross-compiles the aarch64 guest `vminit` in the
          # boatramp-firecracker `build.rs` (Linux uses native `cc`).
          nativeBuildInputs = [
            pkgs.pkg-config
          ]
          ++ lib.optionals pkgs.stdenv.isDarwin [ pkgs.zig ];
          buildInputs = [ pkgs.openssl ];

          # Whole-workspace **clippy** as a flake check, built with crane so it
          # vendors the crates.io deps from `Cargo.lock` and runs **offline**
          # inside the `nix flake check` sandbox. The cachix/git-hooks `clippy`
          # hook can't do this: it shells out to `cargo` with no registry, so
          # deps like `argon2` fail to resolve (`offline mode … no matching
          # package`). Default features here (matching what the hook covered);
          # `--all-features` clippy stays an explicit CI step.
          # The whole-workspace source, shared by the glibc clippy check and the
          # crane-built musl derivations (clippy + static binary). Keep every
          # workspace file (build scripts read .sql/.ron/templates), but drop the
          # local `target/` and any `nix build` `result*` symlinks so a stray dev
          # build dir never bloats the store copy or leaks read-only artifacts into
          # the sandbox's cargo target dir.
          workspaceSrc = lib.cleanSourceWith {
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
          clippyArgs = {
            # The root Cargo.toml is a virtual workspace (no `[package]`), so name
            # the derivation explicitly (crane can't infer it).
            pname = "boatramp-workspace";
            version = "0.1.0";
            src = workspaceSrc;
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

          # A pre-commit hook that mirrors CI's "Ban the anyhow crate" step (the
          # third check in the `fmt · typos · bans` job) verbatim: `anyhow` is
          # banned in favour of typed `thiserror` enums. Runs on the whole tree
          # (not just staged files) so it can't be sidestepped by a partial commit.
          banAnyhow = pkgs.writeShellScript "ban-anyhow" ''
            set -eo pipefail
            if grep -rnI --include='*.rs' -e 'anyhow' crates/; then
              echo "error: the 'anyhow' crate is banned — use typed thiserror error enums" >&2
              exit 1
            fi
            if grep -rn --include=Cargo.toml -e '\banyhow\b' crates/ Cargo.toml; then
              echo "error: a Cargo.toml reintroduced the 'anyhow' dependency" >&2
              exit 1
            fi
          '';

          # Standing rule: no AI-authorship/attribution trailers in git history.
          # `forbidAiTrailersMsg` runs at `commit-msg` and rejects a message carrying
          # `Co-Authored-By: Claude`, `Claude-Session:`, "Generated with [Claude Code]",
          # or a claude.ai/code session URL. `forbidAiTrailersPush` is the pre-push
          # belt-and-suspenders: it scans the messages of the commits actually being
          # pushed (catching anything introduced via amend/rebase/cherry-pick/import).
          aiTrailerPattern = "co-authored-by:.*(claude|anthropic\\.com)|claude-session:|generated with \\[claude code\\]|claude\\.ai/code/";
          forbidAiTrailersMsg = pkgs.writeShellScript "forbid-ai-trailers-msg" ''
            msg="$1"
            pat='${aiTrailerPattern}'
            if hits="$(grep -iEn "$pat" "$msg")"; then
              echo "error: AI-attribution trailer in commit message (banned in this repo):" >&2
              printf '%s\n' "$hits" >&2
              echo "remove the trailer line(s) and re-commit." >&2
              exit 1
            fi
          '';
          forbidAiTrailersPush = pkgs.writeShellScript "forbid-ai-trailers-push" ''
            pat='${aiTrailerPattern}'
            to="''${PRE_COMMIT_TO_REF:-}"
            from="''${PRE_COMMIT_FROM_REF:-}"
            [ -n "$to" ] || exit 0
            if [ -z "$from" ] || [ "$from" = "0000000000000000000000000000000000000000" ]; then
              commits="$(git rev-list "$to" --not --remotes 2>/dev/null)"
            else
              commits="$(git rev-list "$from..$to" 2>/dev/null)"
            fi
            rc=0
            for c in $commits; do
              if git log -1 --format='%B' "$c" | grep -iEq "$pat"; then
                echo "error: commit $c carries an AI-attribution trailer — push blocked." >&2
                rc=1
              fi
            done
            exit $rc
          '';

          # Build the single, batteries-included `boatramp` binary. The workspace
          # default is "all non-conflicting features" (see crates/boatramp/Cargo.toml),
          # so a plain `-p boatramp` build already compiles every backend — fs/S3/GCS/
          # Azure blobs, SlateDB/Cloudflare KV, TLS + ACME, HTTP/3, handlers, cluster,
          # operator, the signers, external SQL, MCP, domain-verify-dns, and the
          # console SPA. Which backend runs is a runtime choice (`--blobs`/`--kv`/
          # `--tls`), not a compile-time variant, so there is one binary for every
          # image below. The recipe lives in ./nix/package.nix (shared with
          # `overlays.default`); here we pin it to the rust-overlay toolchain so the
          # flake build matches the dev shell + CI compiler, and stage the built
          # console SPA so the `console` feature embeds the real assets (not the
          # build-script placeholder). `features` still exists for a bespoke build
          # that layers something extra, but the shipped artifacts pass none.
          mkBoatramp =
            {
              features ? [ ],
            }:
            pkgs.callPackage ./nix/package.nix {
              inherit rustPlatform features rustToolchain;
              consoleDist = consolePackage;
            };

          # One batteries-included binary backs `packages.default`, `nix run`, and
          # both OCI images; they differ only in runtime posture, not compiled code.
          # (The cluster HA / Raft image is still built from source by `boatramp
          # cloudflare`'s generated recipe — that path is separate from this flake.)
          boatrampBin = mkBoatramp { };

          # The fully-static musl + jemalloc build that backs the OCI images (see
          # ./nix/package-musl.nix). Lazily evaluated — only the Linux-only
          # `container*` packages force it, so it never builds on macOS. Built with
          # crane (dependency-split, cached in cachix) + cargo-zigbuild, so `craneLib`
          # and the cleaned `workspaceSrc` are threaded in alongside the zig toolchain.
          boatrampMuslBin = pkgs.callPackage ./nix/package-musl.nix {
            inherit craneLib rustToolchain;
            src = workspaceSrc;
            consoleDist = consolePackage;
          };

          # All-features workspace clippy for the shipped musl target (see
          # ./nix/check-musl.nix). Wired into `checks` below so `nix flake check` runs it
          # and cachix caches the compiled closure — the per-push CI can't afford this
          # (~2.5h cross-compile, GitHub-cache-evicted), but cachix amortizes it. Crane's
          # dep layer means a version bump reuses the cached third-party closure instead
          # of recompiling wasmtime/cranelift/cedar from scratch every nightly.
          boatrampMuslClippy = pkgs.callPackage ./nix/check-musl.nix {
            inherit craneLib;
            src = workspaceSrc;
          };

          # ---- NixOS-VM real-path test framework ----------------------------
          # `mkBoatrampVmTest` (nix/vmtest.nix) institutionalizes VM-based
          # real-path verification — constrained-CPU benches, live-integration,
          # real-kernel features — as versioned, `nix build`-able flake checks,
          # extending the `nixos-service` pattern. See PLAN-nixos-vm-testing.md.
          vmtest = import ./nix/vmtest.nix {
            inherit pkgs lib;
            boatrampPackage = self'.packages.default;
            boatrampModule = inputs.self.nixosModules.default;
          };

          # First instance (#2 /media pool warm-floor): the pool-level load driver
          # (a faithful replica of boatramp-storage's `build_pool`; see its
          # Cargo.toml), built from the pinned toolchain and shipped into the VM.
          mediaLatencyDriver = rustPlatform.buildRustPackage {
            pname = "boatramp-media-latency-driver";
            version = "0.0.0";
            src = ./nix/vmtests/media-latency;
            cargoLock.lockFile = ./nix/vmtests/media-latency/Cargo.lock;
          };

          # Self-signed cert so the VM's postgres node can serve TLS (the faithful
          # prod shape: a cold connect pays a TLS handshake, which the warm floor
          # skips). `sslmode=require` encrypts without CA verification, so a
          # self-signed cert suffices for the bench.
          mediaLatencyPgCert =
            pkgs.runCommand "boatramp-media-latency-pg-cert" { nativeBuildInputs = [ pkgs.openssl ]; }
              ''
                mkdir -p $out
                openssl req -new -x509 -days 3650 -nodes -subj "/CN=pg" \
                  -out $out/server.crt -keyout $out/server.key
              '';

          # Build a single workspace INTEGRATION-TEST binary (crane, dependency-split +
          # cachix-cached like the clippy/musl derivations) and install it under a stable
          # name, so a `mkBoatrampVmTest` gate can ship + run the REAL test binary inside
          # the VM — the same test the host-runner CI job runs, just driven declaratively.
          # `cargo test … --no-run` compiles the `#[ignore]`d live/privileged tests in but
          # runs nothing at build time; the VM's testScript runs them (as root, against the
          # VM's real kernel/DBs). The dep layer is built once per (package,features) via
          # `buildDepsOnly` (a plain `--tests` build of the dummy workspace — no `--test
          # <name>`, which the dummy has no target for), so a code-only change reuses it.
          mkWorkspaceTestBin =
            {
              pname,
              package, # cargo `-p` target
              features, # comma-list for `--features`, or "" for none
              testName, # the `--test <name>` integration target (and the installed binary name)
            }:
            let
              featArgs = lib.optionalString (features != "") "--features ${features}";
              commonCrane = {
                inherit pname;
                version = "0.1.0";
                src = workspaceSrc;
                strictDeps = true;
                # pkg-config + openssl match the workspace clippy check; cmake + nasm cover
                # any aws-lc-rs (`tls`/`s3`) that a feature set drags in, exactly as the
                # all-features preflight job installs them.
                nativeBuildInputs = nativeBuildInputs ++ [
                  pkgs.cmake
                  pkgs.nasm
                ];
                inherit buildInputs;
              };
              depArgs = commonCrane // {
                pname = "${pname}-deps";
                cargoExtraArgs = "-p ${package} ${featArgs} --tests";
              };
            in
            craneLib.mkCargoDerivation (
              commonCrane
              // {
                cargoArtifacts = craneLib.buildDepsOnly depArgs;
                doInstallCargoArtifacts = false;
                doCheck = false;
                buildPhaseCargoCommand = ''
                  cargo test -p ${package} ${featArgs} --test ${testName} --no-run --release --locked
                '';
                installPhaseCommand = ''
                  mkdir -p $out/bin
                  bin=$(find target/release/deps -maxdepth 1 -type f -perm -u+x \
                    -name '${testName}-*' ! -name '*.d' | head -n1)
                  if [ -z "$bin" ]; then
                    echo "mkWorkspaceTestBin(${pname}): no ${testName} test binary under target/release/deps" >&2
                    exit 1
                  fi
                  install -m755 "$bin" "$out/bin/${testName}"
                '';
              }
            );

          # #3 (overlay tunneler R2) — the privileged TUN test binary (device + route +
          # embedded DNS + the systemd-resolved split-DNS path), shipped into the
          # `tunnel-tun` gate VM below.
          overlayTunnelTunTestBin = mkWorkspaceTestBin {
            pname = "boatramp-overlay-tunnel-tun-test";
            package = "boatramp-overlay-tunnel";
            features = "tun";
            testName = "tun_privileged";
          };

          # #7 (project export/import) — the live round-trip test binary, shipped into the
          # `export-import-live` gate VM below (which stands up the DBs + a docker daemon
          # it drives for the ephemeral pg_dump/pg_restore/mysqldump client containers).
          projectExportTestBin = mkWorkspaceTestBin {
            pname = "boatramp-node-project-export-test";
            package = "boatramp-node";
            features = "project-export";
            testName = "project_export_roundtrip";
          };

          # The exact Docker-Hub images the live export/import round-trip drives — pulled
          # reproducibly from the nix store as fixed-output derivations (digest + output hash both pinned) so the
          # hermetic `export-import-live` VM can serve them from its own offline registry
          # mirror with no internet. These are the SAME tags the nightly host-runner job
          # uses and the SAME tags the driver's version->image map asks for:
          #   • pgvector/pgvector:pg16 — the pg16 server AND its pg_dump/pg_restore/psql client
          #   • postgres:16            — the version-probe psql client image
          #   • mysql:8.0              — the mysql server AND its mysqldump/mysql client
          #   • mysql:8.0-debian       — the mysqlbinlog-bearing client for the binlog true-delta
          #                              capture/replay (the Oracle-Linux `mysql:8.0` omits it)
          # Digests + hashes are produced with `nix run nixpkgs#nix-prefetch-docker`.
          exportImportImages = {
            pgvector = pkgs.dockerTools.pullImage {
              imageName = "pgvector/pgvector";
              imageDigest = "sha256:7b822b0aac60967beb1ea5e576b8602c94c300a157d187f385ae3e0da199b90a";
              hash = "sha256-pCdu2IPv8DWKoh85Kzbixv12Xmn9QMWh04Io00CrUzY=";
              finalImageName = "pgvector/pgvector";
              finalImageTag = "pg16";
            };
            postgres = pkgs.dockerTools.pullImage {
              imageName = "postgres";
              imageDigest = "sha256:9e2cf6287f25c3151f4c9421ccce2b17f3e60061c111a29165e0d2cdd9ff0a97";
              hash = "sha256-R2bFd9dpDZ3vmP2uXouuWn7j3wt6Sr0h5DHRcffVlko=";
              finalImageName = "postgres";
              finalImageTag = "16";
            };
            mysql = pkgs.dockerTools.pullImage {
              imageName = "mysql";
              imageDigest = "sha256:7dcddc01f13bab2f15cde676d44d01f61fc9f99fe7785e86196dfc07d358ae2b";
              hash = "sha256-MKIVSoXyndEJFtQ0QV2ZLiHdNEH5OxuBbiN9WNqF5j8=";
              finalImageName = "mysql";
              finalImageTag = "8.0";
            };
            # The DEBIAN variant ships `mysqlbinlog` (absent from the Oracle-Linux `mysql:8.0`), used
            # by the binlog true-delta capture (`mysqlbinlog -R --raw`) + replay (`mysqlbinlog | mysql`).
            mysqlDebian = pkgs.dockerTools.pullImage {
              imageName = "mysql";
              imageDigest = "sha256:9382e4f6f7f013231049ab854de9d0810594d028f4237b67102acc7ade8e3a99";
              hash = "sha256-9nBCHhhjnBOXzxWojZRm53JYTnp8BGLDIoX+PzfAZ/A=";
              finalImageName = "mysql";
              finalImageTag = "8.0-debian";
            };
          };

          # Shared builder for the reproducible, Nix-first OCI images. Both targets
          # ship the *same* batteries-included binary and differ only in runtime
          # posture: the base `container` runs as root so it can own a mounted state
          # volume when using the fs/SlateDB backends; `container-cloudflare` is meant
          # for remote state (R2 + KV), so it carries no volume and stays hardened as
          # non-root. `cacert` is included so the binary can reach R2/Cloudflare/ACME
          # over HTTPS; TLS typically terminates upstream, so it listens plain.
          mkImage =
            {
              pkg,
              user ? null,
              # Opt-in extra store paths layered on top of the lean base (the `*-debug`
              # variants pass `debugTools`). Empty for the lean default images, so those
              # stay byte-identical. `buildLayeredImage` dedups layers by store path, so a
              # debug image shares the app + cacert layers with the base.
              extraContents ? [ ],
            }:
            pkgs.dockerTools.buildLayeredImage {
              name = "boatramp";
              tag = "latest";
              contents = [
                pkg
                pkgs.cacert
              ]
              ++ extraContents;
              # The hardened non-root image (uid 65534) has no writable directory of
              # its own — its CWD `/` and `/tmp` are root-owned — so the filesystem
              # state backends (SlateDB kv / fs blobs) can't create their dirs and
              # `serve` exits with a kv permission error. Ship a world-writable `/data`
              # (1777, like `/tmp`) so the non-root binary has an ephemeral state dir;
              # durable state still belongs on a mounted volume (root image) or R2.
              extraCommands = "mkdir -p data && chmod 1777 data";
              config = {
                Entrypoint = [ "${lib.getExe pkg}" ];
                Cmd = [ "serve" ];
                ExposedPorts."8080/tcp" = { };
                Env = [
                  "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
                  "BOATRAMP_ADDR=0.0.0.0:8080"
                  # Filesystem state + HOME-relative caches (wasmtime compile cache)
                  # go under the world-writable `/data` so the non-root binary can
                  # write them. Durable state still belongs on a volume or R2.
                  "BOATRAMP_DATA_DIR=/data"
                  "HOME=/data"
                ];
                Labels = {
                  # GHCR auto-links a published package to its source repo via this label,
                  # so a release Actions push is never `denied` on an unlinked package (the
                  # v0.44.0 GHCR incident, where the migrated packages had to be hand-linked
                  # with Actions write access before the push would go through).
                  "org.opencontainers.image.source" = "https://github.com/BoatRamp/BoatRamp";
                  "org.opencontainers.image.title" = "boatramp";
                };
              }
              // lib.optionalAttrs (user != null) { User = user; };
            };

          # Opt-in debug toolset for the `*-debug` image variants (incident debugging +
          # basic profiling). Layered ON TOP of the SAME app + cacert layers, so pulling a
          # `-debug` image when the lean base is already resident fetches only these extra
          # layers. NEVER present in the lean default images. `gdb` is intentionally omitted
          # (its closure — python3 etc. — is the entire size premium; strace/ltrace cover
          # the common incident path); add it back here if interactive debugging is needed.
          debugTools = with pkgs; [
            busybox # ash shell + a broad basic-tool kit (ls/cat/grep/sed/vi/wget/netstat/…)
            bashInteractive # a real interactive bash
            coreutils # GNU coreutils (faithful behavior over the busybox applets)
            strace # syscall tracing
            ltrace # library-call tracing
            procps # ps / top / free / vmstat
            lsof # open files + sockets
          ];
        in
        {
          # Apply the rust-overlay so `pkgs.rust-bin` is available everywhere in
          # this module (devShell, package, hooks).
          _module.args.pkgs = import inputs.nixpkgs {
            inherit system;
            overlays = [
              (import inputs.rust-overlay)
              # MinIO is a dev-only, local S3 test double (`just minio`); it was
              # removed from nixos-unstable (abandoned upstream), so we source it from
              # the pinned `nixpkgs-minio` rev that still has it and clear its insecure
              # marker. Overlaying (not config.permittedInsecurePackages) keeps it
              # version-independent across main-nixpkgs bumps. Not in the build/release
              # path — only the devShell + the `just minio` recipe consume it.
              (
                _final: _prev:
                let
                  minioPkgs = import inputs.nixpkgs-minio { inherit system; };
                  clearInsecure =
                    p:
                    p.overrideAttrs (old: {
                      meta = (old.meta or { }) // {
                        knownVulnerabilities = [ ];
                      };
                    });
                in
                {
                  minio = clearInsecure minioPkgs.minio;
                  minio-client = minioPkgs.minio-client;
                }
              )
            ];
          };

          # ---- Packages ------------------------------------------------------
          # `perSystem` returns a plain attrset, so every package is one key of a
          # single `packages` definition (dotted + whole-attrset forms can't be
          # mixed). The Linux-only container image is merged in conditionally.
          packages = {
            # The single, batteries-included `boatramp` binary (server + CLI): every
            # backend is compiled in and selected at runtime (`--blobs`/`--kv`/`--tls`).
            default = boatrampBin;

            # The workspace integration-test binaries the NixOS-VM gates ship + run inside
            # the VM (nix/vmtest.nix + the `tunnel-tun` / `export-import-live` checks).
            # Exposed so a dev can `nix build` the exact test binary a gate runs, standalone
            # — the framework's "each is `nix build`-able standalone" ethos
            # (PLAN-nixos-vm-testing.md §Wiring).
            tunnel-tun-test-bin = overlayTunnelTunTestBin;
            project-export-test-bin = projectExportTestBin;

            # hetzner-k3s (ROADMAP #11 cluster bring-up): exposed so `nix build
            # .#hetzner-k3s` builds the exact binary the devshell ships, per system.
            hetzner-k3s = pkgs.callPackage ./nix/hetzner-k3s.nix { };

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
                # The guest arch is this system's arch: x86_64-linux → an x86_64
                # kernel (the KVM embedded VMM); aarch64-linux → an arm64 kernel (the
                # macOS Virtualization.framework `vmm-vz` backend). MUST stay in lock-
                # step with the `boatramp-vmlinux` release flake (same nixpkgs pin +
                # config) so the shipped kernel == the boot-tested one.
                isArm = system == "aarch64-linux";
                fcArch = if isArm then "aarch64" else "x86_64";
                # Firecracker's published microVM guest config, pinned to a release.
                fcConfig = pkgs.fetchurl {
                  url = "https://raw.githubusercontent.com/firecracker-microvm/firecracker/v1.10.1/resources/guest_configs/microvm-kernel-ci-${fcArch}-6.1.config";
                  hash =
                    if isArm then
                      "sha256-yPuMNxRCeCh6aty1F8/TNZ9tsAhhgTcQCqenZxa9BmI="
                    else
                      "sha256-OR2NSY+J5Ws5G+XqSnUB68RObQlDMeyqve/tHaayipY=";
                };
                # x86_64: the **embedded rust-vmm VMM** advertises its virtio-MMIO
                # devices via the `virtio_mmio.device=<size>@<addr>:<irq>` **kernel
                # cmdline** (the legacy Firecracker discovery path). The stock config
                # ships `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES` OFF — the Firecracker
                # *binary* backend discovers over ACPI — so on the embedded path the
                # guest never sees `/dev/vda`. Enable it (additive; the ACPI path is
                # unaffected). aarch64: Virtualization.framework presents its virtio
                # devices via the guest **device tree** it generates, so no cmdline-
                # devices patch is needed (VIRTIO_MMIO + virtio-blk/net/console + ext4
                # are already =y); the config is used verbatim.
                config =
                  if isArm then
                    # aarch64/VZ: Virtualization.framework presents its virtio devices
                    # to the guest over a generic **PCIe host bridge (ECAM)**, not the
                    # cmdline virtio-mmio the Firecracker config targets — so the stock
                    # config (CONFIG_PCI off) finds no devices and never boots. Enable
                    # the generic PCIe host + virtio-pci so VZ's disk/net/console are
                    # discovered. (virtio-mmio stays on too, harmlessly.)
                    pkgs.runCommand "boatramp-vmlinux.config" { } ''
                      grep -vE '^(# )?CONFIG_(PCI|PCI_HOST_GENERIC|PCI_HOST_COMMON|PCI_ECAM|VIRTIO_PCI)( is not set|=)' \
                        ${fcConfig} > "$out"
                      {
                        echo CONFIG_PCI=y
                        echo CONFIG_PCI_HOST_COMMON=y
                        echo CONFIG_PCI_HOST_GENERIC=y
                        echo CONFIG_PCI_ECAM=y
                        echo CONFIG_VIRTIO_PCI=y
                      } >> "$out"
                    ''
                  else
                    pkgs.runCommand "boatramp-vmlinux.config" { } ''
                      sed 's/# CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES is not set/CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES=y/' \
                        ${fcConfig} > "$out"
                    '';
                # x86_64: the embedded VMM boots the uncompressed `vmlinux` ELF (via
                # linux-loader's `Elf::load`). aarch64: VZLinuxBootLoader boots the raw
                # arm64 `Image` (arch/arm64/boot/Image). nixpkgs only keeps `vmlinux`
                # for MODULAR kernels; CONFIG_MODULES is off here, so copy the kernel
                # image out of the exported build dir (`$buildRoot`) ourselves.
                kernelRel = if isArm then "arch/arm64/boot/Image" else "vmlinux";
                kernelName = baseNameOf kernelRel;
                micro =
                  (pkgs.linuxManualConfig {
                    inherit (pkgs.linux_6_1) version src;
                    configfile = config;
                    allowImportFromDerivation = true;
                    # `linuxManualConfig`'s configurePhase runs `make oldconfig`,
                    # which non-interactively expands a partial config: the aarch64
                    # PCI options appended above pull in their `select`ed sub-options
                    # with defaults, so no strict "verbatim" check applies here
                    # (that lives in the higher-level `buildLinux`, not this path).
                  }).overrideAttrs
                    (old: {
                      # nixpkgs marks kernels `requiredSystemFeatures = ["big-parallel"]`,
                      # but the stock nix-darwin `linux-builder` (the only aarch64-linux
                      # builder on a Mac dev host) advertises no features, so the build
                      # can't be scheduled there. This minimal microVM kernel builds fine
                      # without the hint (it's a scheduling gate, not a correctness one,
                      # and doesn't affect the output bytes), so drop it — CI's native
                      # aarch64 runner is unaffected.
                      requiredSystemFeatures = [ ];
                      postInstall = (old.postInstall or "") + ''
                        cp "$buildRoot/${kernelRel}" "$out/${kernelName}"
                      '';
                    });
              in
              # `micro.dev or micro`: linuxManualConfig may not expose a `dev` output,
              # so fall back to the default output and locate the kernel image. The
              # output is always named `vmlinux` (the generic "kernel" artifact); for
              # aarch64 it is a raw arm64 Image, for x86_64 an uncompressed ELF.
              pkgs.runCommand "boatramp-vmlinux" { } ''
                mkdir -p "$out"
                v="$(find ${micro} ${micro.dev or micro} -name ${kernelName} -type f 2>/dev/null | head -1)"
                if [ -z "$v" ]; then
                  echo "kernel image (${kernelName}) not found in kernel outputs:" >&2
                  find ${micro} ${micro.dev or micro} -maxdepth 2 >&2 || true
                  exit 1
                fi
                cp "$v" "$out/vmlinux"
              '';

            # ---- Web console (`nix build .#console`) ------------------------
            # Built in the `let` block above (`consolePackage`) so `mkBoatramp`
            # can also stage its `dist` into the binary for the default `console`
            # feature; exposed here as its own package for standalone builds.
            console = consolePackage;
          }
          # ---- Container images -------------------------------------------
          # `dockerTools` builds *Linux* images, so these are Linux-only (built in
          # CI / on a Linux host; CF needs `x86_64-linux`). Both targets ship the
          # same batteries-included binary via `mkImage` (above) and differ only in
          # runtime posture:
          #
          #   nix build .#container             root, for a writable state volume (fly.io)
          #   nix build .#container-cloudflare  non-root, for remote state (R2 + KV)
          # The cluster (HA / Raft) image is still built from source by
          # `boatramp cloudflare`'s generated recipe; these are the single-instance
          # bases.
          // lib.optionalAttrs pkgs.stdenv.isLinux {
            # The fully-static musl + jemalloc binary that backs the OCI images,
            # exposed on its own (`nix build .#boatramp-static`) so it can be used
            # directly — e.g. the benchmark harness runs it head-to-head with the
            # glibc `default` binary and the field.
            boatramp-static = boatrampMuslBin;

            # Base image: runs as root so it can own a mounted state volume (e.g. a
            # fly.io volume) when using the fs/SlateDB backends. Ships the static
            # musl + jemalloc binary — no glibc/loader closure, and jemalloc keeps
            # the concurrency throughput musl's own malloc would throw away.
            container = mkImage { pkg = boatrampMuslBin; };
            # Debug swap-in of the base image: identical app + entrypoint + Env, plus the
            # `debugTools` (shell + strace/ltrace/procps/lsof). Pushed as `:<tag>-debug`, so
            # it is a drop-in you swap the tag to during an incident, then swap back. Opt-in
            # only — never the default.
            container-debug = mkImage {
              pkg = boatrampMuslBin;
              extraContents = debugTools;
            };
            # Cloudflare image: the same static binary, configured for remote state
            # (R2 + KV) at runtime, so it needs no volume and stays hardened as
            # non-root.
            container-cloudflare = mkImage {
              pkg = boatrampMuslBin;
              user = "65534:65534";
            };
            # Debug swap-in of the cloudflare (non-root) image — the variant most likely to
            # need in-cluster debugging. Same `debugTools`, same non-root uid.
            container-cloudflare-debug = mkImage {
              pkg = boatrampMuslBin;
              user = "65534:65534";
              extraContents = debugTools;
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
              # Cluster bring-up (ROADMAP #11): the generic "bring up a boatramp cluster"
              # tooling, owned by the platform so every boatramp app reuses it instead of
              # re-adding it to its own devshell. `hetzner-k3s` provisions the k3s cluster on
              # Hetzner Cloud; `kubectl` talks to it + installs the operator. Runbook:
              # docs/src/how-to/cluster-on-hetzner.md.
              pkgs.kubectl
              (pkgs.callPackage ./nix/hetzner-k3s.nix { })
              pkgs.cargo-watch
              pkgs.cargo-nextest
              pkgs.cargo-deny
              # cargo-zigbuild + zig: cross-compile / cross-clippy the workspace to
              # the `*-unknown-linux-musl` targets (the shipped OCI images + Linux
              # release binaries) from any host, and reproduce the CI `musl-clippy`
              # gate locally — `cargo-zigbuild clippy --all-features --target
              # x86_64-unknown-linux-musl` — so Linux-gated (`#[cfg(target_os = "linux")]`)
              # code is lintable on macOS instead of surfacing only in nightly CI.
              pkgs.cargo-zigbuild
              pkgs.zig
              pkgs.taplo
              pkgs.nixfmt
              # WebAssembly component tooling for the `handlers` engine.
              pkgs.wasm-tools
              # Playwright MCP (browser e2e / live-serve diagnosis): the stdio MCP server with a
              # Nix-pinned, version-matched Chromium baked in via PLAYWRIGHT_BROWSERS_PATH — no npm
              # `playwright install` download, fully reproducible. The Claude Code MCP (gitignored
              # `.mcp.json`) launches it via `nix develop --command playwright-mcp`.
              pkgs.playwright-mcp
              # Node.js for the JS function template's `jco componentize` build
              # (`boatramp function build` fetches a version-pinned `jco` via npx).
              pkgs.nodejs
              # uv for the Python function template's `componentize-py` build
              # (`boatramp function build` runs it version-pinned via `uvx`).
              pkgs.uv
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
              # Pinned to >= 2.10.0 (see the `pebble` override above) so the CA
              # emits the tokenless `dns-persist-01` challenge the regression gate
              # exercises.
              pebble
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
            ++ lib.optionals pkgs.stdenv.hostPlatform.isLinux [ pkgs.iproute2 ]
            # macOS `compute build` for the `vmm-vz` backend: `e2fsprogs` provides
            # the `mke2fs -d` the OCI→ext4 rootfs build shells out to. (`zig` — also
            # used here to cross-compile the aarch64 guest `vminit`,
            # boatramp-firecracker `build.rs` — is now in the cross-platform set above
            # for cargo-zigbuild.) Linux builds the init with native `cc` and ships
            # its own `mke2fs`, so neither is needed there.
            ++ lib.optionals pkgs.stdenv.isDarwin [
              pkgs.e2fsprogs
            ];

            RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";
            # libclang for bindgen (aws-lc-rs) when building `--features s3`.
            LIBCLANG_PATH = lib.makeLibraryPath [ pkgs.llvmPackages.libclang.lib ];

            shellHook = ''
              echo "boatramp dev shell ready — run 'just' to list tasks."
            '';
          };

          # A nightly rust toolchain is below the pinned stable one (`rust-toolchain.toml`) the
          # rest of the workspace builds with, so it lives in its own shell rather than
          # `devShells.default` — the privsep untrusted-byte-parser fuzz harnesses
          # (`crates/*/fuzz/`) are the one thing in this repo that needs `cargo-fuzz`, which in
          # turn needs an active nightly `cargo`/`rustc` (it shells out to the ambient
          # toolchain, not via `rustup +nightly`, since there is no rustup here — nix puts
          # exactly one toolchain on PATH). `nix develop .#fuzz -- cargo fuzz run <target>` (see
          # .github/workflows/nightly.yml).
          devShells.fuzz = pkgs.mkShell {
            nativeBuildInputs = [
              pkgs.pkg-config
              pkgs.cmake
            ];
            buildInputs = [ pkgs.openssl ];
            packages = [
              (pkgs.rust-bin.selectLatestNightlyWith (toolchain: toolchain.default))
              pkgs.cargo-fuzz
            ];
            # libclang for bindgen (aws-lc-rs, pulled in by boatramp-overlay-proto /
            # boatramp-rpktls, which the overlay-proto + server fuzz targets depend on).
            LIBCLANG_PATH = lib.makeLibraryPath [ pkgs.llvmPackages.libclang.lib ];
            shellHook = ''
              echo "boatramp fuzz dev shell ready (nightly rust + cargo-fuzz) — e.g. 'cargo fuzz run fuzz_frame --fuzz-dir crates/boatramp-http/fuzz'."
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
            # Compile-lint the whole feature matrix for the shipped musl target — the
            # backstop against a musl-only build break reaching a release tag.
            musl-clippy = boatrampMuslClippy;

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

            # #2 (/media pool warm-floor) — the first `mkBoatrampVmTest` instance.
            # A `cores = 2` NixOS VM + a real postgres node (TLS), running the
            # drain->burst pattern and RECORDING per-request latency for
            # `min_connections = 0` vs a warm floor. kind = "bench": records to $out,
            # never asserts a latency threshold.
            #
            # #2's warm-floor fix is accepted on its own merits (mechanism-verified);
            # this is a reproducible in-repo regression/bench HARNESS, not a gate on
            # #2 and not a steal certification.
            #
            # SCOPE (honest): this drives the pool-level driver (the real sqlx 0.8.6
            # pool, a replica of `build_pool`) INSIDE the constrained 2-core VM
            # against a real pg node — a real, reproducible, constrained-VM run. The
            # full HTTP storefront serve path (a wasm guest doing the SQL) is deferred
            # (needs a deployed component fixture). A 2-core QEMU guest approximates a
            # small box but does NOT reproduce cloud hypervisor CPU-steal (not
            # attempted here); it demonstrates the mechanism + direction, not a prod
            # number.
            media-latency = vmtest.mkBoatrampVmTest {
              name = "boatramp-media-latency";
              kind = "bench";
              cores = 2;
              # The measured path is the SQL pool (the pool-level driver), not the
              # boatramp HTTP serve path, so the boatramp service is left OFF here —
              # that keeps the full boatramp binary out of the VM closure (lean,
              # fast build). The helper still defaults the service ON for gate
              # instances that DO exercise it (e.g. a future full-serve-path test).
              services = {
                services.boatramp.enable = false;
                environment.systemPackages = [ mediaLatencyDriver ];
              };
              extraNodes.pg =
                { lib, ... }:
                {
                  services.postgresql = {
                    enable = true;
                    enableTCPIP = true;
                    ensureDatabases = [ "bench" ];
                    ensureUsers = [
                      {
                        name = "bench";
                        ensureClauses.login = true;
                      }
                    ];
                    # Trust auth over the VM subnet — the bench measures pool
                    # connection establishment, not authn; no password needed.
                    authentication = lib.mkForce ''
                      local all all trust
                      host  all all 0.0.0.0/0 trust
                      host  all all ::/0      trust
                    '';
                    settings = {
                      ssl = "on";
                      ssl_cert_file = "/var/lib/postgresql/server.crt";
                      ssl_key_file = "/var/lib/postgresql/server.key";
                      max_connections = 200;
                    };
                  };
                  # Install the self-signed cert as a root oneshot ordered BEFORE
                  # postgres (not via the module's own preStart, which we must not
                  # clobber). Postgres refuses a world-readable key, so copy it 0600.
                  systemd.services.pg-tls-cert = {
                    wantedBy = [ "multi-user.target" ];
                    before = [ "postgresql.service" ];
                    serviceConfig = {
                      Type = "oneshot";
                      RemainAfterExit = true;
                    };
                    script = ''
                      install -D -m 0600 -o postgres -g postgres \
                        ${mediaLatencyPgCert}/server.key /var/lib/postgresql/server.key
                      install -D -m 0644 -o postgres -g postgres \
                        ${mediaLatencyPgCert}/server.crt /var/lib/postgresql/server.crt
                    '';
                  };
                  networking.firewall.allowedTCPPorts = [ 5432 ];
                };
              testScript = ''
                import os

                start_all()
                pg.wait_for_unit("postgresql.service")
                pg.wait_for_open_port(5432)
                machine.wait_for_unit("multi-user.target")

                # Fail fast if the real pool driver can't reach the real pg at all
                # (guards against a vacuous green). This asserts the driver RAN, not
                # any latency threshold — appropriate for a bench.
                tls_url = "postgres://bench@pg:5432/bench?sslmode=require"
                plain_url = "postgres://bench@pg:5432/bench?sslmode=disable"

                env = "MAX=8 BURST=48 IDLE_MS=1500 DRAIN_MS=3000 TRIALS=3"
                tls = machine.succeed(f"DATABASE_URL='{tls_url}' {env} media-latency-driver")
                print(tls)
                plain = machine.succeed(f"DATABASE_URL='{plain_url}' {env} media-latency-driver")
                print(plain)

                os.makedirs(os.environ["out"], exist_ok=True)
                with open(os.path.join(os.environ["out"], "media-latency.txt"), "w") as f:
                    f.write("# boatramp #2 /media pool warm-floor bench (min=0 vs warm floor)\n")
                    f.write("# 2-core NixOS VM + real postgres node; pool-level driver\n")
                    f.write("# (real sqlx 0.8.6 pool, replica of build_pool).\n")
                    f.write("# A reproducible in-repo bench harness (NOT a gate; #2's fix\n")
                    f.write("# is accepted on its merits). QEMU 2-core approximates a small\n")
                    f.write("# box, NOT cloud hypervisor CPU-steal (not attempted): it shows\n")
                    f.write("# the mechanism + direction, not a prod number.\n\n")
                    f.write("===== TLS (sslmode=require) =====\n")
                    f.write(tls)
                    f.write("\n===== non-TLS (sslmode=disable) =====\n")
                    f.write(plain)
              '';
            };

            # #3 (overlay tunneler R2) — the REAL-kernel TUN gate. A NixOS VM with a real
            # `/dev/net/tun` and a real `systemd-resolved`, running the privileged TUN test
            # binary as root: device open + route install + the embedded-DNS round-trip
            # (the netns job's exact test), PLUS the split-DNS path the netns job can't do
            # (it runs `skip_resolver = true`) — a real `resolvectl` per-link, zone-scoped
            # override, proven by a lookup THROUGH systemd-resolved returning a synthetic IP
            # that a real TCP connection then drives an overlay dial through. kind = "gate":
            # the testScript ASSERTS (a regression fails the check), and it supersedes
            # `tunnel.yml`'s bespoke privileged-netns job (plan decision 3).
            tunnel-tun = vmtest.mkBoatrampVmTest {
              name = "boatramp-tunnel-tun";
              kind = "gate";
              services = {
                # Only the VM + its kernel/resolver are needed — not the boatramp service
                # (keeps the full server binary out of this VM's closure).
                services.boatramp.enable = false;
                # The split-DNS half needs a real resolver to apply the `resolvectl`
                # per-link override against (plan §3.6 preferred path). Disable mDNS +
                # LLMNR: systemd-resolved's mDNS responder otherwise binds UDP :5353,
                # which is exactly the loopback port the embedded DNS responder uses —
                # leaving it on makes every bind fail `AddrInUse`.
                services.resolved = {
                  enable = true;
                  # No upstream/fallback DNS in a hermetic VM — so resolved answers the in-zone
                  # name straight from the TUN link's responder and never stalls on unreachable
                  # fallback servers (8.8.8.8/1.1.1.1/…) for anything it can't resolve locally.
                  fallbackDns = [ ];
                  settings.Resolve = {
                    MulticastDNS = "no";
                    LLMNR = "no";
                  };
                };
                # Guarantee the TUN kernel module + its /dev/net/tun node are present.
                boot.kernelModules = [ "tun" ];
                # The real TCP round-trip through the TUN relies on the kernel delivering the
                # netstack's SYN-ACK (src = a synthetic CIDR address) back to the connecting
                # socket. Turn OFF reverse-path filtering (a synthetic src on the TUN link can
                # otherwise be dropped as a martian) and the firewall (its INPUT policy must not
                # drop traffic arriving on the TUN), and allow forwarding — the production
                # posture is an operator's box, not this hardened test VM's defaults.
                boot.kernel.sysctl = {
                  "net.ipv4.conf.all.rp_filter" = 0;
                  "net.ipv4.conf.default.rp_filter" = 0;
                  "net.ipv4.ip_forward" = 1;
                };
                networking.firewall.enable = false;
                environment.systemPackages = [
                  overlayTunnelTunTestBin
                  pkgs.iproute2
                ];
              };
              testScript = ''
                machine.wait_for_unit("multi-user.target")
                machine.wait_for_unit("systemd-resolved.service")
                # The real kernel TUN device node — the whole point of a VM over the fast gate.
                machine.succeed("test -c /dev/net/tun")
                # The embedded DNS responder needs loopback :5353 free — assert nothing (e.g.
                # resolved's mDNS) is holding it, so a bind failure can't masquerade as a logic bug.
                machine.succeed("! ss -H -lun 'sport = :5353' | grep -q .")

                # Run BOTH #[ignore]d privileged tests as root against the VM's real kernel +
                # resolver. --test-threads=1 so the two tests' TUN devices / routes / DNS
                # responders (both bind 127.0.0.1:5353) never overlap.
                out = machine.succeed(
                    "tun_privileged --ignored --test-threads=1 --nocapture 2>&1"
                )
                print(out)

                # Guard against a vacuous green (0 tests run, or one silently filtered out):
                # BOTH named tests must actually have run and the suite must report 2 passed.
                assert (
                    "a_real_tcp_connection_through_the_kernel_tun_device_drives_a_dial_attempt" in out
                ), "the device/route/embedded-DNS test did not run"
                assert (
                    "split_dns_via_the_host_resolver_scopes_only_the_zone_and_a_lookup_drives_a_dial" in out
                ), "the split-DNS (resolvectl) test did not run"
                assert "test result: ok. 2 passed" in out, "both privileged TUN tests must pass"
              '';
            };

            # #7 (project export/import) — the LIVE round-trip GATE, as a declarative
            # nixosTest institutionalizing the nightly "project export/import live — Postgres
            # pgvector + MySQL" host-runner job. A single VM runs its own docker daemon (fed
            # offline from the nix store — the hermetic test sandbox has no registry access)
            # with the pgvector + mysql server containers AND the ephemeral pg_dump /
            # pg_restore / mysqldump CLIENT containers the real `NodeProjectExport` driver
            # launches via `run_ephemeral`, then runs the REAL test binary and greps for every
            # one of its success markers (a self-skip would still print `ok`, so the markers
            # are the gate). kind = "gate".
            export-import-live = vmtest.mkBoatrampVmTest {
              name = "boatramp-export-import-live";
              kind = "gate";
              # A docker-in-VM run of two DB servers + several ephemeral client containers +
              # the loaded image closure needs headroom over the default guest disk/RAM.
              memoryMB = 6144;
              services = {
                services.boatramp.enable = false;
                virtualisation.docker.enable = true;
                # An offline Docker-Hub mirror: a native registry (no image needed) that the
                # daemon consults FIRST for every docker.io pull — so the driver's
                # `run_ephemeral` pull of `pgvector/pgvector:pg16` / `mysql:8.0` / `postgres:16`
                # resolves against local blobs, never the (unreachable) internet.
                services.dockerRegistry = {
                  enable = true;
                  listenAddress = "127.0.0.1";
                  port = 5000;
                };
                virtualisation.docker.daemon.settings = {
                  registry-mirrors = [ "http://127.0.0.1:5000" ];
                };
                # Bigger guest disk for the loaded image layers + the dump/restore temp files.
                virtualisation.diskSize = 12000;
                environment.systemPackages = [
                  projectExportTestBin
                  pkgs.skopeo
                ];
                # Seed the mirror from the nix-store image tarballs BEFORE the test runs. Each
                # is copied under the SAME docker.io repo path the daemon will ask the mirror
                # for (official images under `library/`).
                systemd.services.seed-registry = {
                  wantedBy = [ "multi-user.target" ];
                  after = [ "docker-registry.service" ];
                  requires = [ "docker-registry.service" ];
                  path = [ pkgs.skopeo ];
                  serviceConfig = {
                    Type = "oneshot";
                    RemainAfterExit = true;
                  };
                  script = ''
                    set -euo pipefail
                    # `--insecure-policy`: this minimal VM ships no containers trust
                    # policy.json; accept any image signature policy for the copy (the
                    # images are pinned-by-digest nix-store fixed-output derivations, not fetched at runtime).
                    copy() {
                      skopeo --insecure-policy copy --dest-tls-verify=false --retry-times 3 \
                        "docker-archive:$1" "docker://127.0.0.1:5000/$2"
                    }
                    copy ${exportImportImages.pgvector}    pgvector/pgvector:pg16
                    copy ${exportImportImages.postgres}    library/postgres:16
                    copy ${exportImportImages.mysql}       library/mysql:8.0
                    copy ${exportImportImages.mysqlDebian} library/mysql:8.0-debian
                  '';
                };
              };
              testScript = ''
                import re

                machine.wait_for_unit("multi-user.target")
                machine.wait_for_unit("docker.service")
                machine.wait_for_unit("docker-registry.service")
                machine.wait_for_unit("seed-registry.service")

                # Stand the two DB servers up exactly as the host-runner job does — on the
                # docker default bridge, so both the test process AND the ephemeral client
                # containers it launches (siblings on that bridge) reach them by container IP.
                # `-c wal_level=logical …` enables logical decoding so the pg WAL true-delta gate
                # can create a pgoutput capture slot (a bring-your-own test pg must be launched
                # with it, as `managed_db_spec` bakes it into a managed DB's launch argv).
                machine.succeed(
                    "docker run -d --name brexport-pg -e POSTGRES_PASSWORD=postgres "
                    "pgvector/pgvector:pg16 "
                    "-c wal_level=logical -c max_replication_slots=10 -c max_wal_senders=10"
                )
                # `--log-bin --binlog-format=ROW --gtid-mode=ON …` enables the row binlog + GTID so
                # the mysql binlog TRUE-DELTA gate can snapshot-pin a base + stream the delta.
                machine.succeed(
                    "docker run -d --name brexport-mysql -e MYSQL_ROOT_PASSWORD=mysql "
                    "mysql:8.0 --default-authentication-plugin=mysql_native_password "
                    "--log-bin --binlog-format=ROW --gtid-mode=ON "
                    "--enforce-gtid-consistency=ON --server-id=1"
                )

                # Wait for both to accept connections (readiness, not a fixed sleep).
                machine.wait_until_succeeds(
                    "docker exec brexport-pg pg_isready -U postgres", timeout=120
                )
                machine.wait_until_succeeds(
                    "docker exec brexport-mysql mysqladmin ping -h 127.0.0.1 -uroot -pmysql",
                    timeout=180,
                )

                pg_ip = machine.succeed(
                    "docker inspect -f "
                    "'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' brexport-pg"
                ).strip()
                my_ip = machine.succeed(
                    "docker inspect -f "
                    "'{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' brexport-mysql"
                ).strip()
                print(f"pg={pg_ip} mysql={my_ip}")

                env = (
                    f"BOATRAMP_TEST_PG_URL=postgres://postgres:postgres@{pg_ip}:5432/postgres "
                    f"BOATRAMP_TEST_MYSQL_URL=mysql://root:mysql@{my_ip}:3306/mysql"
                )
                out = machine.succeed(
                    f"{env} project_export_roundtrip --nocapture --test-threads=1 2>&1",
                    timeout=1200,
                )
                print(out)

                # HARD gate: every live/always-on test must actually run (both DBs reachable,
                # docker usable for the ephemeral client containers) — a self-skip still prints
                # `ok`, so require the exact passed count AND every success marker, exactly like
                # the host-runner job's grep gate.
                assert re.search(r"test result: ok\. 19 passed", out), "not all 19 tests ran (silent skip?)"
                for marker in [
                    "PROJECT EXPORT ROUNDTRIP OK",
                    "PROJECT EXPORT PG CHUNKED SHADOW OK",
                    "PROJECT EXPORT PG CORRUPTION ABORT OK",
                    "PROJECT EXPORT PG CRAFTED ESCAPE REFUSED OK",
                    "PROJECT EXPORT PG CRAFTED ESCAPE DRIVER OK",
                    "PROJECT EXPORT PG PGVECTOR ROUNDTRIP OK",
                    "PROJECT EXPORT DRIVER ROUNDTRIP OK",
                    "PROJECT EXPORT PG TRUE-DELTA OK",
                    "PROJECT EXPORT PG OVERLAP-WINDOW OK",
                    "PROJECT EXPORT PG TRUE-DELTA CHAIN OK",
                    "PROJECT EXPORT MYSQL ROUNDTRIP OK",
                    "PROJECT EXPORT MYSQL SHADOW OK",
                    "PROJECT EXPORT MYSQL TRUE-DELTA OK",
                    "PROJECT EXPORT MYSQL TRUE-DELTA CHAIN OK",
                    "PROJECT EXPORT LIBSQL ROUNDTRIP OK",
                    "PROJECT EXPORT LIBSQL CHUNKED ATOMIC OK",
                    "PROJECT EXPORT CROSS-TENANT LEAK GATE OK",
                ]:
                    assert marker in out, f"missing success marker: {marker}"

                machine.succeed("docker rm -f brexport-pg brexport-mysql || true")
              '';
            };
          };

          # ---- Git hooks -----------------------------------------------------
          # `nix develop` (or `direnv allow`, via ./.envrc) installs these into
          # .git/hooks; `nix flake check` runs them as a check too. Together they
          # mirror CI's fast `fmt · typos · bans` job — rustfmt + typos + the
          # anyhow ban — so a drift caught by that job is caught locally *before*
          # it is pushed (which is exactly how the earlier fmt/typos red slipped
          # in: those commits were made without entering the dev shell, so the
          # hook was never installed). Clippy is intentionally NOT here — it's the
          # crane `checks.clippy` above (the hook's bare `cargo clippy` fails
          # offline in the flake-check sandbox); devs still get it via CI.
          pre-commit.settings.hooks = {
            rustfmt = {
              enable = true;
              packageOverrides.cargo = rustToolchain;
              packageOverrides.rustfmt = rustToolchain;
            };
            nixfmt-rfc-style.enable = true;
            taplo.enable = true;
            typos.enable = true;
            # Mirror CI's "Ban the anyhow crate" step (see `banAnyhow` above).
            ban-anyhow = {
              enable = true;
              name = "ban the anyhow crate";
              entry = "${banAnyhow}";
              language = "system";
              files = "\\.(rs|toml)$";
              pass_filenames = false;
            };
            # Standing rule: block AI-authorship/attribution trailers (see the
            # `forbidAiTrailers*` scripts above). commit-msg is the primary gate;
            # pre-push catches anything that bypassed it.
            forbid-ai-trailers-msg = {
              enable = true;
              name = "block AI-attribution trailers (commit message)";
              entry = "${forbidAiTrailersMsg}";
              language = "system";
              stages = [ "commit-msg" ];
              # commit-msg passes the message file as the arg ONLY when pass_filenames
              # is true; with false the script sees no file and checks nothing.
              pass_filenames = true;
            };
            forbid-ai-trailers-push = {
              enable = true;
              name = "block AI-attribution trailers (pre-push)";
              entry = "${forbidAiTrailersPush}";
              language = "system";
              stages = [ "pre-push" ];
              pass_filenames = false;
              always_run = true;
            };
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
