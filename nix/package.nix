# The `boatramp` binary derivation, factored out of `flake.nix` so
# BOTH the flake's `packages.default` (with the pinned rust-overlay toolchain) and
# the consumer-facing `overlays.default` (with stock nixpkgs `rustPlatform`, so
# downstreams need no rust-overlay) build the *same* recipe. `features` layers
# extra cargo features on top of the defaults (`fs` + `slatedb`); the s3 backend
# pulls aws-lc-rs, which needs cmake + libclang at build time.
{
  lib,
  rustPlatform,
  pkg-config,
  openssl,
  cmake,
  llvmPackages,
  features ? [ ],
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

    cargoBuildFlags = [
      "-p"
      "boatramp"
    ]
    ++ lib.optionals (features != [ ]) [
      "--features"
      (lib.concatStringsSep "," features)
    ];

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
