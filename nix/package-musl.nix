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
# the musl C cross-toolchain transparently. buildRustPackage still vendors the Rust
# deps and writes the offline cargo config, so only the compile/link is overridden;
# the build stays hermetic and offline.
#
# `consoleDist` + `rustToolchain` mirror ./nix/package.nix (which builds the glibc
# binary used for `packages.default` / the bare-host release binaries).
{
  lib,
  stdenv,
  rustPlatform,
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
in
rustPlatform.buildRustPackage {
  pname = "boatramp";
  version = "0.1.0";
  src = lib.cleanSource ../.;
  cargoLock.lockFile = ../Cargo.lock;

  # Stage the prebuilt console SPA where `boatramp-server/build.rs` looks for it
  # (see ./nix/package.nix for the rationale).
  postPatch = lib.optionalString (consoleDist != null) ''
    rm -rf crates/boatramp-console/dist
    mkdir -p crates/boatramp-console/dist
    cp -r ${consoleDist}/. crates/boatramp-console/dist/
  '';

  doCheck = false;

  # nixpkgs' `buildRustPackage` embeds a cargo-auditable dependency section by
  # pinning it with `-Wl,--undefined=AUDITABLE_VERSION_INFO`. zig's linker (used via
  # cargo-zigbuild) rejects `--undefined=…` (GNU ld accepts it — hence the glibc
  # image builds fine), so disable auditable for the musl image.
  auditable = false;

  nativeBuildInputs = [
    pkg-config
    cmake
    cargo-zigbuild
    zig
    removeReferencesTo
  ];
  LIBCLANG_PATH = lib.makeLibraryPath [ llvmPackages.libclang.lib ];

  # Replace buildRustPackage's compile with cargo-zigbuild targeting musl. The
  # default `console` etc. features are kept; `jemalloc` is layered on. zig needs a
  # writable cache, so point HOME/XDG_CACHE_HOME at the sandbox build dir.
  buildPhase = ''
    runHook preBuild
    export HOME="$TMPDIR"
    export XDG_CACHE_HOME="$TMPDIR/.cache"
    mkdir -p "$XDG_CACHE_HOME"
    cargo zigbuild --release --offline \
      --target ${target} \
      --features jemalloc \
      -p boatramp
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -Dm755 target/${target}/release/boatramp "$out/bin/boatramp"
    # Scrub the dead toolchain store-path string the binary retains after strip, so
    # nix doesn't pin the ~1.6 GiB toolchain closure into the image (see package.nix).
    remove-references-to -t ${rustToolchain} "$out/bin/boatramp"
    runHook postInstall
  '';

  meta = {
    description = "Self-hosted, streaming-first static site publishing platform (static musl + jemalloc)";
    homepage = "https://github.com/BoatRamp/BoatRamp";
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "boatramp";
  };
}
