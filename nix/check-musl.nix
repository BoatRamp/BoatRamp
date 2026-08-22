# A `nix flake check` derivation that **clippy-lints the whole workspace for the shipped
# `<host-arch>-unknown-linux-musl` target** — the compile backstop that the per-push CI
# can't afford (all-features cross-compiled to musl is ~2.5h on a stock runner and evicts
# from GitHub's 10 GB cache). Run in nix + pushed to cachix, the compiled closure is
# amortized across nightlies instead of rebuilt from source every time.
#
# Why clippy (compile-check), not `cargo test`: the musl concern is *does it compile on the
# shipped libc* (a musl-only build break — e.g. a dep constructing `cmsghdr` without musl's
# private fields — sails through a glibc gate). Clippy compiles every dependency + type-checks
# every workspace crate for musl, which catches exactly that. Actually *running* the suite is
# covered elsewhere: the fast-CI lanes run the shipped-surface tests on musl per push, and the
# nix sandbox can't host the network/env some integration tests want anyway.
#
# Mechanism mirrors ./nix/package-musl.nix: cargo-zigbuild supplies the musl C cross-toolchain
# (aws-lc-sys/ring/sqlite vendored C) transparently, buildRustPackage vendors the Rust deps and
# writes the offline cargo config, so the whole thing stays hermetic + offline in the sandbox.
{
  lib,
  stdenv,
  rustPlatform,
  rustToolchain,
  cargo-zigbuild,
  zig,
  pkg-config,
  cmake,
  nasm,
  llvmPackages,
  openssl,
  # Which feature set to lint. Defaults to the whole matrix; a caller can pass a lighter
  # set (e.g. "--no-default-features --features boatramp/fs") to validate the plumbing fast.
  cargoFeatures ? "--all-features",
}:
let
  target = "${stdenv.hostPlatform.parsed.cpu.name}-unknown-linux-musl";
in
rustPlatform.buildRustPackage {
  pname = "boatramp-musl-clippy";
  version = "0.1.0";
  src = lib.cleanSource ../.;
  cargoLock.lockFile = ../Cargo.lock;

  # Not building the auditable binary; skip the cargo-auditable link step (zig's linker
  # rejects its `-Wl,--undefined=` marker — see package-musl.nix).
  auditable = false;
  # Tests are not run here (see the header); clippy is the whole point.
  doCheck = false;

  nativeBuildInputs = [
    pkg-config
    cmake
    nasm
    cargo-zigbuild
    zig
    rustToolchain # carries the clippy component + the musl std
  ];
  buildInputs = [ openssl ];
  LIBCLANG_PATH = lib.makeLibraryPath [ llvmPackages.libclang.lib ];

  buildPhase = ''
    runHook preBuild
    export HOME="$TMPDIR"
    export XDG_CACHE_HOME="$TMPDIR/.cache"
    mkdir -p "$XDG_CACHE_HOME"
    echo "=== cargo-zigbuild clippy (${cargoFeatures}) for ${target} ==="
    cargo-zigbuild clippy --offline \
      --target ${target} \
      --workspace --all-targets \
      ${cargoFeatures} \
      -- -D warnings
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    echo "clippy clean for ${target} (${cargoFeatures})" > "$out/result"
    runHook postInstall
  '';

  meta = {
    description = "Workspace clippy for the shipped musl target (flake check)";
    platforms = lib.platforms.linux;
  };
}
