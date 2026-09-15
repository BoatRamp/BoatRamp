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
# Build shape (crane, dependency-split — see also ./nix/package-musl.nix):
#   * `buildDepsOnly` compiles the heavy third-party closure (wasmtime, cranelift, cedar, …)
#     ONCE, keyed on `Cargo.lock`'s dependency graph via crane's dummified sources. A boatramp
#     code/version bump touches boatramp's own crates only, NOT the dep graph, so this layer is
#     a cachix hit across releases instead of a ~30-40 min from-scratch recompile every night.
#   * the clippy stage reuses that `cargoArtifacts` and only type-checks boatramp's own crates.
# cargo-zigbuild supplies the musl C cross-toolchain (aws-lc-sys/ring/sqlite vendored C)
# transparently; crane vendors the Rust deps + writes the offline cargo config, so the whole
# thing stays hermetic + offline in the sandbox. The dep layer and the clippy stage pass
# **identical** `--workspace --all-targets --all-features` flags so the cached artifacts match
# exactly (a flag drift between the two would silently invalidate the dep cache).
{
  lib,
  stdenv,
  craneLib,
  # The cleaned whole-workspace source (from flake.nix `workspaceSrc`), shared with the
  # glibc clippy check and the static musl binary so all three key off the same tree.
  src,
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

  commonArgs = {
    inherit src;
    # The root Cargo.toml is a virtual workspace (no `[package]`), so name the
    # derivation explicitly — crane can't infer it (same reason as flake.nix's
    # glibc `clippyArgs`). This keeps `crateNameFromCargoToml` off the code path.
    pname = "boatramp-musl-clippy";
    version = "0.1.0";
    # Tests are not run here (see the header); clippy is the whole point.
    doCheck = false;

    nativeBuildInputs = [
      pkg-config
      cmake
      nasm
      cargo-zigbuild
      zig
    ];
    buildInputs = [ openssl ];
    LIBCLANG_PATH = lib.makeLibraryPath [ llvmPackages.libclang.lib ];

    # cargo-zigbuild reads the target from `--target` on the command line; export it
    # too so crane's artifact-install plumbing agrees on which `target/<triple>` dir
    # to carry between the dep layer and the clippy stage.
    CARGO_BUILD_TARGET = target;

    # zig needs a writable global cache; the sandbox $HOME is not writable by default.
    preBuild = ''
      export HOME="$TMPDIR"
      export XDG_CACHE_HOME="$TMPDIR/.cache"
      mkdir -p "$XDG_CACHE_HOME"
    '';
  };

  # Layer 1 — the third-party dependency closure for musl, compiled once and cached.
  # crane dummifies the workspace sources (Cargo.{toml,lock} only), so this is keyed on
  # the dependency graph, not on boatramp's own code: a version bump substitutes it.
  cargoArtifacts = craneLib.buildDepsOnly (
    commonArgs
    // {
      buildPhaseCargoCommand = ''
        echo "=== cargo-zigbuild build DEPS (${cargoFeatures}) for ${target} ==="
        cargo zigbuild --offline \
          --target ${target} \
          --workspace --all-targets \
          ${cargoFeatures}
      '';
    }
  );
in
# Layer 2 — all-features workspace clippy, reusing the cached deps. Only boatramp's own
# crates recompile here. `mkCargoDerivation` (not `cargoClippy`) so we drive clippy through
# cargo-zigbuild under the zig CC/linker env, exactly as the dep layer built the deps.
craneLib.mkCargoDerivation (
  commonArgs
  // {
    inherit cargoArtifacts;
    pnameSuffix = "-clippy";
    # Only the dep layer needs to export its `target/` dir; the clippy result is a marker.
    doInstallCargoArtifacts = false;
    buildPhaseCargoCommand = ''
      echo "=== cargo-zigbuild clippy (${cargoFeatures}) for ${target} ==="
      cargo-zigbuild clippy --offline \
        --target ${target} \
        --workspace --all-targets \
        ${cargoFeatures} \
        -- -D warnings
    '';
    installPhaseCommand = ''
      mkdir -p "$out"
      echo "clippy clean for ${target} (${cargoFeatures})" > "$out/result"
    '';
    meta = {
      description = "Workspace clippy for the shipped musl target (flake check)";
      platforms = lib.platforms.linux;
    };
  }
)
