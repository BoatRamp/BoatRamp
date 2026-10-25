# Reusable NixOS-VM real-path test helper.
#
# Institutionalizes the class of verification that needs a real (and optionally
# constrained) Linux VM — replacing ad-hoc lighthouse runs with versioned,
# `nix build`-able checks. Extends the flake's EXISTING `pkgs.testers.runNixOSTest`
# pattern (the `nixos-service` check): same service module + flake-built binary
# wiring. See boatramp-roadmap/plans/PLAN-nixos-vm-testing.md.
#
# `mkBoatrampVmTest` boots a boatramp VM (the service module + the flake-built
# binary) with optional constrained cores/memory and optional sidecar nodes
# (e.g. a `pg` node), driven by a Python `testScript`:
#
#   mkBoatrampVmTest {
#     name       = "my-check";
#     cores      = 2;            # -> virtualisation.cores (null = default)
#     memoryMB   = 2048;         # -> virtualisation.memorySize (null = default)
#     extraNodes = { pg = {...}; };   # sidecar NixOS nodes (e.g. a postgres node)
#     services   = { ... };      # a NixOS module merged into the primary node:
#                                #   override services.boatramp.*, add packages, etc.
#     testScript = '' ... '';    # the Python driver (drives the REAL path)
#     kind       = "gate";       # "gate" | "bench"
#   }
#
# kind semantics (convention enforced by the instance's testScript):
#   "gate"  -> the testScript ASSERTS; a regression fails the check (nightly/cut gate).
#   "bench" -> the testScript DRIVES the real path and RECORDS numbers as a build
#              artifact (write to $out); it must NOT assert a hard latency threshold
#              (host variance).
#
# Fidelity caveat (state it wherever a bench number is cited): `cores = 2`
# constrains the guest to a small box, but a QEMU guest does NOT reproduce cloud
# hypervisor CPU-steal — and this framework does not attempt to (no steal
# injection). A bench records the mechanism + direction on the real path,
# reproducibly and in-repo; it is NOT a prod number, and is a regression/bench
# harness, not a release gate.
{
  pkgs,
  lib,
  boatrampPackage,
  boatrampModule,
}:
let
  # Minimal default config so an `enable`d boatramp service boots out of the box
  # (overridable via the `services` module arg). Mirrors the `nixos-service` check.
  defaultConfig = pkgs.writeText "boatramp.cfg" ''
    (serve: (addr: "127.0.0.1:8080", data_dir: "/var/lib/boatramp/data"))
  '';
in
{
  mkBoatrampVmTest =
    {
      name,
      cores ? null,
      memoryMB ? null,
      extraNodes ? { },
      services ? { },
      testScript,
      kind ? "gate",
    }:
    assert lib.assertMsg (
      kind == "gate" || kind == "bench"
    ) ''mkBoatrampVmTest ("${name}"): kind must be "gate" or "bench", got "${kind}"'';
    pkgs.testers.runNixOSTest {
      inherit name testScript;
      nodes = {
        machine =
          { lib, ... }:
          {
            # The boatramp service module + the caller's extra machine-node module.
            # `services` can override the defaults below (it is a full module), e.g.
            # `services.boatramp.enable = false;` for a bench that only needs the VM,
            # or `environment.systemPackages = [ driver ];` to ship a load driver.
            imports = [
              boatrampModule
              services
            ];
            # Point the service straight at the flake-built binary (the overlay
            # pins `nixpkgs.overlays`, which `runNixOSTest` already sets — so the
            # package is wired directly rather than through the overlay).
            services.boatramp = {
              enable = lib.mkDefault true;
              package = lib.mkDefault boatrampPackage;
              configFile = lib.mkDefault defaultConfig;
            };
            virtualisation = lib.mkMerge [
              (lib.mkIf (cores != null) { cores = cores; })
              (lib.mkIf (memoryMB != null) { memorySize = memoryMB; })
            ];
          };
      }
      // extraNodes;
    };
}
