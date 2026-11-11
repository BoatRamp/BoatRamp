# A Landlock-V5 firecracker microVM guest kernel for the scoped privsep VM substrate's live serve gate.
#
# The privsep per-capability profile's `MIN_LANDLOCK_ABI = ABI::V5` floor
# (crates/boatramp-server/src/sandbox.rs) requires a guest kernel >= 6.10 with Landlock enabled. The
# firecracker CI kernels top out at 6.1 (Landlock ABI <= V2), so they do NOT satisfy the in-guest wall
# (S3/S4). This builds 6.12.67 (same as lighthouse's host) from the firecracker CI 6.1 x86_64 config
# with Landlock turned on (`make oldconfig` via linuxManualConfig expands the partial config).
#
# Prereq: `fc-base.config` in the same dir = the firecracker CI config + the Landlock lines (see README).
#
#   nix-build kernel.nix -o kernel-result     # -> kernel-result/bzImage (firecracker 1.13.x boots it)
let
  pkgs = import <nixpkgs> { };
in
(pkgs.linuxManualConfig {
  inherit (pkgs.linux_6_12) version src;
  configfile = ./fc-base.config;
  allowImportFromDerivation = true;
}).overrideAttrs
  (old: {
    # nixpkgs marks kernels `big-parallel`; drop it so it schedules on any builder (a scheduling gate,
    # not a correctness one — does not affect output bytes).
    requiredSystemFeatures = [ ];
    buildFlags = (old.buildFlags or [ ]) ++ [ "vmlinux" ];
  })
