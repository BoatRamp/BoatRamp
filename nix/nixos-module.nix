# NixOS service module: `services.boatramp`. Enable in a downstream
# flake:
#
#   { inputs.boatramp.url = "github:BoatRamp/BoatRamp"; }
#   # in the host config:
#   imports = [ inputs.boatramp.nixosModules.default ];
#   nixpkgs.overlays = [ inputs.boatramp.overlays.default ];
#   services.boatramp = {
#     enable = true;
#     configFile = pkgs.writeText "boatramp.cfg" ''(serve: (addr: "0.0.0.0:8080"))'';
#   };
#
# The systemd hardening mirrors packaging/systemd/boatramp.service: a dedicated
# system user, CAP_NET_BIND_SERVICE only, and a full ProtectSystem/Restrict*
# sandbox tuned for the static/handler/TLS/cluster profile. `compute = true`
# relaxes exactly the knobs the Linux microVM/container backends need.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.boatramp;
in
{
  options.services.boatramp = {
    enable = lib.mkEnableOption "the boatramp server (streaming-first static hosting + edge compute)";

    package = lib.mkPackageOption pkgs "boatramp" { };

    configFile = lib.mkOption {
      type = lib.types.path;
      description = ''
        Path to the boatramp server config (`boatramp.cfg`, RON). Managed as a file
        because the format is RON; use `pkgs.writeText` for an inline config or
        point at a deployed secret path.
      '';
      example = lib.literalExpression ''pkgs.writeText "boatramp.cfg" "(serve: (addr: \"0.0.0.0:8080\"))"'';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "boatramp";
      description = "System user the service runs as (created when left at the default).";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "boatramp";
      description = "System group the service runs as (created when left at the default).";
    };

    dataDir = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/boatramp";
      description = "State directory: KV, blobs, the ACME cache, and mesh identity keys.";
    };

    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Open TCP 80 and 443 in the firewall.";
    };

    compute = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Relax the systemd sandbox so the Linux compute backends (microVM/container:
        `/dev/kvm`, namespaces, mounts) can run. Off by default — a hardened
        static/handler/TLS node needs none of it.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    users.users = lib.mkIf (cfg.user == "boatramp") {
      boatramp = {
        isSystemUser = true;
        inherit (cfg) group;
        home = cfg.dataDir;
        description = "boatramp server";
      };
    };
    users.groups = lib.mkIf (cfg.group == "boatramp") { boatramp = { }; };

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [
        80
        443
      ];
    };

    # ProtectSystem=strict makes the FS read-only; the data dir is the one writable
    # path, created + owned before start.
    systemd.tmpfiles.rules = [
      "d '${cfg.dataDir}' 0750 ${cfg.user} ${cfg.group} - -"
    ];

    systemd.services.boatramp = {
      description = "boatramp — streaming-first static hosting + edge compute";
      documentation = [ "https://github.com/BoatRamp/BoatRamp" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];

      serviceConfig = {
        Type = "exec";
        ExecStart = "${lib.getExe cfg.package} serve --config ${cfg.configFile}";
        Restart = "on-failure";
        RestartSec = "2s";
        User = cfg.user;
        Group = cfg.group;
        WorkingDirectory = cfg.dataDir;
        ReadWritePaths = [ cfg.dataDir ];

        # Bind :80/:443 without root — the only capability the default profile needs.
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
        CapabilityBoundingSet = [
          "CAP_NET_BIND_SERVICE"
        ]
        ++ lib.optionals cfg.compute [
          "CAP_SYS_ADMIN"
          "CAP_NET_ADMIN"
          "CAP_SETUID"
          "CAP_SETGID"
        ];

        # ---- sandbox (mirrors packaging/systemd/boatramp.service) ----
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = !cfg.compute;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        ProtectClock = true;
        ProtectHostname = true;
        ProtectProc = "invisible";
        RestrictNamespaces = !cfg.compute;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        LockPersonality = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        SystemCallFilter = [
          "@system-service"
        ]
        ++ lib.optionals cfg.compute [
          "@sandbox"
          "@mount"
        ];
        SystemCallErrorNumber = "EPERM";
        SystemCallArchitectures = "native";
        UMask = "0077";
      }
      // lib.optionalAttrs cfg.compute {
        DeviceAllow = [
          "/dev/kvm rw"
          "/dev/net/tun rw"
        ];
      };
    };
  };
}
