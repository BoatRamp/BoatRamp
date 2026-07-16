# The `boatramp` binary derivation, factored out of `flake.nix` so
# BOTH the flake's `packages.default` (with the pinned rust-overlay toolchain) and
# the consumer-facing `overlays.default` (with stock nixpkgs `rustPlatform`, so
# downstreams need no rust-overlay) build the *same* recipe. `features` layers
# extra cargo features on top of the defaults (`fs` + `slatedb` + `console`); the
# s3 backend pulls aws-lc-rs, which needs cmake + libclang at build time.
#
# `consoleDist` is the built web-console SPA (the flake's `packages.console`
# Trunk output). `console` is a default cargo feature, so `boatramp-server`'s
# build script bakes in whatever is at `crates/boatramp-console/dist` — a
# gitignored Trunk artifact absent from `src`. Staging `consoleDist` there (see
# `postPatch`) makes the Nix build embed the *real* console instead of the
# build-script placeholder. When null (the stock `overlays.default`, which has no
# console package to hand us), the placeholder is embedded and the build still
# succeeds.
{
  lib,
  rustPlatform,
  pkg-config,
  openssl,
  cmake,
  llvmPackages,
  features ? [ ],
  consoleDist ? null,
}:
let
  wantsS3 = lib.elem "s3" features;
in
rustPlatform.buildRustPackage (
  {
    pname = "boatramp";
    version = "0.1.0";
    src = lib.cleanSource ../.;
    cargoLock.lockFile = ../Cargo.lock;

    # Stage the prebuilt console SPA where `boatramp-server/build.rs` looks for
    # it, so the default `console` feature embeds the real assets. Replace the
    # dir wholesale: a dev tree's gitignored `dist/` rides in via `cleanSource`
    # (which doesn't honour .gitignore), and leaving it in place could embed
    # stale hashed assets alongside the fresh build. The `${consoleDist}` output
    # holds the dist files at its root (index.html + hashed js/wasm/css/svg).
    postPatch = lib.optionalString (consoleDist != null) ''
      rm -rf crates/boatramp-console/dist
      mkdir -p crates/boatramp-console/dist
      cp -r ${consoleDist}/. crates/boatramp-console/dist/
    '';

    cargoBuildFlags = [
      "-p"
      "boatramp"
    ]
    ++ lib.optionals (features != [ ]) [
      "--features"
      (lib.concatStringsSep "," features)
    ];

    # This derivation builds the shipped *binary*; it does not run the test suite.
    # With the batteries-included default (all features, incl. `handlers`), the
    # cargo `checkPhase` would run non-hermetic tests — e.g. the function harness
    # (`function::tests::harness_runs_a_component_and_asserts`) fetches template
    # crates over the network, which the Nix sandbox forbids. Tests are covered by
    # CI (rustup) + the nightly `--all-features` job + the flake `checks.clippy`,
    # so skip them here rather than pull the network into the build.
    doCheck = false;

    nativeBuildInputs = [ pkg-config ] ++ lib.optionals wantsS3 [ cmake ];
    buildInputs = [ openssl ];

    meta = {
      description = "Self-hosted, streaming-first static site publishing platform";
      homepage = "https://github.com/BoatRamp/BoatRamp";
      license = with lib.licenses; [
        mit
        asl20
      ];
      mainProgram = "boatramp";
    };
  }
  // lib.optionalAttrs wantsS3 {
    # libclang for bindgen (aws-lc-rs) under `--features s3`.
    LIBCLANG_PATH = lib.makeLibraryPath [ llvmPackages.libclang.lib ];
  }
)
