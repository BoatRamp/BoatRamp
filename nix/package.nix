# The `boatramp` binary derivation, factored out of `flake.nix` so
# BOTH the flake's `packages.default` (with the pinned rust-overlay toolchain) and
# the consumer-facing `overlays.default` (with stock nixpkgs `rustPlatform`, so
# downstreams need no rust-overlay) build the *same* recipe. The workspace default
# is batteries-included (all non-conflicting features — see
# crates/boatramp/Cargo.toml), so a plain `-p boatramp` build already compiles
# every backend; `features` can still layer extras on top for a bespoke build.
# That default set pulls aws-lc-rs (via rustls/`tls`, the `s3` backend, and the
# always-present mesh `boatramp-rpktls` crate), whose `aws-lc-sys` build wants
# cmake + libclang — so both are always in the build inputs, not gated on a
# feature.
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
  removeReferencesTo,
  features ? [ ],
  consoleDist ? null,
  # The toolchain to scrub from the runtime closure (the flake passes its pinned
  # rust-overlay toolchain). `null` (the stock `overlays.default`) skips the scrub.
  rustToolchain ? null,
}:
rustPlatform.buildRustPackage {
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

  # cmake builds aws-lc-sys' vendored AWS-LC; libclang is its bindgen. Both are
  # always needed now that the default set compiles aws-lc-rs (rustls + s3 +
  # the mesh rpktls crate), so they are unconditional rather than feature-gated.
  nativeBuildInputs = [
    pkg-config
    cmake
    removeReferencesTo
  ];
  buildInputs = [ openssl ];
  LIBCLANG_PATH = lib.makeLibraryPath [ llvmPackages.libclang.lib ];

  # The stripped release binary still carries a **dead** store-path string to the
  # Rust toolchain (a common Rust-on-Nix wart — a leftover path survives `strip`).
  # Nix then conservatively pins the *entire* toolchain closure (~1.6 GiB: rustc +
  # rust-docs + gcc + std) into the runtime image, even though nothing runs it.
  # Scrub the dead reference so the closure is just the binary + its real libs —
  # dropping the OCI images from ~640 MB to ~150 MB. Skipped when no toolchain is
  # passed (the stock-nixpkgs overlay path).
  postInstall = lib.optionalString (rustToolchain != null) ''
    remove-references-to -t ${rustToolchain} "$out/bin/boatramp"
  '';

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
