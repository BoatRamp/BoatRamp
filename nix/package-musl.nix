# A **fully-static** `<host-arch>-unknown-linux-musl` build of the batteries-included
# `boatramp` binary, with **jemalloc** as the global allocator — the artifact that
# backs the OCI images and (via `.#boatramp-static`) the Linux release binaries.
#
# Why musl + jemalloc, not glibc:
# - musl links statically, so the image is just the binary (no glibc/loader
#   closure) — a smaller, hermetic image with no dynamic dependency on anything.
# - BUT musl's own `malloc` scales catastrophically under concurrent allocation
#   (benchmarked ~14x slower than jemalloc on this server), so a static musl build
#   *must* swap the allocator. jemalloc recovers — and slightly beats — the glibc
#   build's throughput and tail latency.
#
# Why cargo-zigbuild: the batteries-included set pulls C deps that build their own
# vendored C (aws-lc-sys via cmake, ring, bundled sqlite). The stock cross-cc setup
# can't target musl for those, but `zig cc` (via cargo-zigbuild) can — it supplies
# the musl C cross-toolchain transparently.
#
# Build shape (crane, dependency-split — mirrors ./nix/check-musl.nix):
#   * `buildDepsOnly` compiles boatramp's third-party closure for musl+jemalloc ONCE,
#     keyed on `Cargo.lock`'s dependency graph (crane dummifies the workspace sources,
#     stubbing every workspace `build.rs`), so a boatramp code/version bump substitutes
#     it from cachix instead of recompiling wasmtime/cranelift/cedar every night.
#   * the binary stage reuses that `cargoArtifacts` and recompiles only boatramp's own
#     crates (+ runs the real workspace build scripts — the console dist, the firecracker
#     `vminit` cross-compile). The dep layer and the binary stage pass identical
#     `--release --features jemalloc -p boatramp` flags so the cached artifacts match.
#
# `consoleDist` + `rustToolchain` mirror ./nix/package.nix (which builds the glibc
# binary used for `packages.default` / the bare-host release binaries).
{
  lib,
  stdenv,
  craneLib,
  # The cleaned whole-workspace source (from flake.nix `workspaceSrc`).
  src,
  rustToolchain,
  cargo-zigbuild,
  zig,
  pkg-config,
  cmake,
  llvmPackages,
  removeReferencesTo,
  consoleDist ? null,
}:
let
  # Follow the host arch: x86_64 on an x86_64 builder, aarch64 on aarch64 (Graviton/
  # Ampere). The OCI images build on x86_64, so their binary is unchanged.
  target = "${stdenv.hostPlatform.parsed.cpu.name}-unknown-linux-musl";

  # Stage the prebuilt console SPA where `boatramp-server/build.rs` looks for it (see
  # ./nix/package.nix). Only the REAL binary stage needs it — `buildDepsOnly` stubs
  # every workspace `build.rs`, so the dep layer never reads the dist.
  postPatch = lib.optionalString (consoleDist != null) ''
    rm -rf crates/boatramp-console/dist
    mkdir -p crates/boatramp-console/dist
    cp -r ${consoleDist}/. crates/boatramp-console/dist/
  '';

  commonArgs = {
    inherit src;
    pname = "boatramp";
    version = "0.1.0";
    doCheck = false;

    nativeBuildInputs = [
      pkg-config
      cmake
      cargo-zigbuild
      zig
      removeReferencesTo
    ];
    LIBCLANG_PATH = lib.makeLibraryPath [ llvmPackages.libclang.lib ];

    # cargo-zigbuild reads the target from `--target`; export it too so crane's
    # artifact plumbing carries the right `target/<triple>` dir between layers.
    CARGO_BUILD_TARGET = target;

    # zig needs a writable global cache; the sandbox $HOME is not writable by default.
    preBuild = ''
      export HOME="$TMPDIR"
      export XDG_CACHE_HOME="$TMPDIR/.cache"
      mkdir -p "$XDG_CACHE_HOME"
    '';
  };

  # Layer 1 — boatramp's third-party dependency closure for musl+jemalloc, compiled
  # once and cached. No `postPatch` here: the workspace build scripts are stubbed in
  # the dummy sources, so the console dist is not needed to build the deps.
  cargoArtifacts = craneLib.buildDepsOnly (
    commonArgs
    // {
      buildPhaseCargoCommand = ''
        echo "=== cargo-zigbuild build DEPS (jemalloc, release) for ${target} ==="
        cargo zigbuild --release --offline \
          --target ${target} \
          --features jemalloc \
          -p boatramp
      '';
    }
  );
in
# Layer 2 — the static binary, reusing the cached deps. Only boatramp's own crates
# recompile here; the real workspace build scripts run (staged console dist via
# postPatch, firecracker vminit cross-compile via zig).
craneLib.mkCargoDerivation (
  commonArgs
  // {
    inherit cargoArtifacts postPatch;
    # We install a single binary by hand below, not crane's build-log installer, and
    # we do not need to re-export the (large) target dir from this stage.
    doInstallCargoArtifacts = false;
    buildPhaseCargoCommand = ''
      cargo zigbuild --release --offline \
        --target ${target} \
        --features jemalloc \
        -p boatramp
    '';
    installPhaseCommand = ''
      install -Dm755 target/${target}/release/boatramp "$out/bin/boatramp"
      # Scrub the dead toolchain store-path string the binary retains after strip, so
      # nix doesn't pin the ~1.6 GiB toolchain closure into the image (see package.nix).
      remove-references-to -t ${rustToolchain} "$out/bin/boatramp"
    '';
    meta = {
      description = "Self-hosted, streaming-first static site publishing platform (static musl + jemalloc)";
      homepage = "https://github.com/BoatRamp/BoatRamp";
      license = with lib.licenses; [
        mit
        asl20
      ];
      mainProgram = "boatramp";
      platforms = lib.platforms.linux;
    };
  }
)
