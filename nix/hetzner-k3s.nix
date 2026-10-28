# hetzner-k3s (vitobotta/hetzner-k3s) — a Crystal CLI that provisions a k3s cluster on
# Hetzner Cloud. NOT in nixpkgs, so it is packaged here from the upstream prebuilt release
# binaries for boatramp's devshell cluster bring-up surface (ROADMAP #11, option 1: the
# generic "bring up a boatramp cluster" tooling belongs with the platform, not each app).
#
# It is a prebuilt-binary derivation (per-system asset selection), not a from-source build:
# upstream ships one binary per platform and the Crystal/shards build chain is heavy and
# version-sensitive — a devshell tool is better served by the vendored release binary. The
# binary is dynamically linked, so its runtime libraries are resolved per platform:
#   - Linux: autoPatchelfHook rewrites the needed sonames to the nix store (a no-op if the
#     release turns out to be a fully-static musl binary — it then carries no NEEDED libs).
#   - Darwin: the release is ad-hoc signed (not hardened runtime) and hardcodes the build
#     host's Homebrew dylib prefix (/opt/homebrew or /usr/local) for gmp + openssl@3. Those
#     paths are SHORTER than the nix store equivalents, so install_name_tool can't rewrite
#     them in place without relinking. Instead the UNMODIFIED binary is wrapped with
#     DYLD_FALLBACK_LIBRARY_PATH pointing at the nix libs: dyld falls back there when the
#     Homebrew path is absent, and leaving the Mach-O untouched keeps its signature valid.
#     The /usr/lib/* system libs load by their (present) absolute paths and need nothing.
{
  lib,
  stdenv,
  fetchurl,
  autoPatchelfHook,
  makeWrapper,
  openssl,
  gmp,
  pcre2,
  libevent,
  boehmgc,
  libxml2,
  zlib,
  libyaml,
}:

let
  version = "2.7.0";
  assets = {
    "x86_64-linux" = {
      file = "hetzner-k3s-linux-amd64";
      hash = "sha256-+hODxCT4STavcIRrB1vxs9UL13y287d5yr62dKf13JI=";
    };
    "aarch64-linux" = {
      file = "hetzner-k3s-linux-arm64";
      hash = "sha256-kSz6Kgg3YW2TKLu6oo+naRHr9MHcF7MjOa56LHvOYMU=";
    };
    "x86_64-darwin" = {
      file = "hetzner-k3s-macos-amd64";
      hash = "sha256-D5FOT+ibnWzUJhysmtI8lMsw/6ZlMq2bHCURr1zkXO8=";
    };
    "aarch64-darwin" = {
      file = "hetzner-k3s-macos-arm64";
      hash = "sha256-d7KMo4rXlvpLDlL326E5zh4gR6kCgjl9fCrnbLh7g1M=";
    };
  };
  inherit (stdenv.hostPlatform) system;
  asset = assets.${system} or (throw "hetzner-k3s: unsupported system ${system}");
in
stdenv.mkDerivation {
  pname = "hetzner-k3s";
  inherit version;

  src = fetchurl {
    url = "https://github.com/vitobotta/hetzner-k3s/releases/download/v${version}/${asset.file}";
    inherit (asset) hash;
  };

  dontUnpack = true;

  nativeBuildInputs =
    lib.optionals stdenv.hostPlatform.isLinux [ autoPatchelfHook ]
    ++ lib.optionals stdenv.hostPlatform.isDarwin [ makeWrapper ];

  # Linux: the dynamic Crystal binary's runtime libs (ignored if the release is static musl).
  # Darwin: gmp/openssl are referenced via the wrapper's DYLD path below (string context →
  # runtime dep), so they do not go in buildInputs.
  buildInputs = lib.optionals stdenv.hostPlatform.isLinux [
    (lib.getLib stdenv.cc.cc) # libgcc_s / libstdc++ for Crystal's unwinder
    openssl
    gmp
    pcre2
    libevent
    boehmgc
    libxml2
    zlib
    libyaml
  ];

  installPhase = ''
    runHook preInstall
  ''
  + (
    if stdenv.hostPlatform.isDarwin then
      ''
        install -Dm755 "$src" "$out/libexec/hetzner-k3s"
        makeWrapper "$out/libexec/hetzner-k3s" "$out/bin/hetzner-k3s" \
          --prefix DYLD_FALLBACK_LIBRARY_PATH : "${
            lib.makeLibraryPath [
              gmp
              openssl
            ]
          }"
      ''
    else
      ''
        install -Dm755 "$src" "$out/bin/hetzner-k3s"
      ''
  )
  + ''
    runHook postInstall
  '';

  # Sanity check (and, on Darwin, proof the DYLD fallback wrapper resolves every dep): running
  # `--version` must load all the binary's libraries and print the expected version.
  doInstallCheck = true;
  installCheckPhase = ''
    v=$("$out/bin/hetzner-k3s" --version)
    [ "$v" = "${version}" ] || { echo "hetzner-k3s --version printed '$v', expected ${version}" >&2; exit 1; }
  '';

  meta = {
    description = "Create and manage k3s clusters on Hetzner Cloud";
    homepage = "https://github.com/vitobotta/hetzner-k3s";
    license = lib.licenses.mit;
    mainProgram = "hetzner-k3s";
    sourceProvenance = [ lib.sourceTypes.binaryNativeCode ];
    platforms = builtins.attrNames assets;
  };
}
