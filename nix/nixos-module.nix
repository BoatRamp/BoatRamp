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
# relaxes exactly the knobs the NATIVE (microVM/container) Linux backends need —
# the DOCKER backend needs none of that relaxation. The compute-shim env +
# firewall opening are therefore driven by `computeShimUrls`/`computeShimPorts`/
# `computeTrustBridges` INDEPENDENTLY of `compute`, so a docker-only node gets
# turnkey shim networking while keeping the tight sandbox.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.boatramp;

  # Compute-shim firewall derivation (S1 — least-privilege by default). The shim
  # URLs the operator sets in `computeShimUrls` are the SINGLE source: they are fed
  # to the server as `BOATRAMP_COMPUTE_<KIND>_SHIM_URL` env (which figment layers over
  # the RON config), AND their `:port` is parsed out here to open EXACTLY those ports
  # on the boatramp compute bridges — so the turnkey default never trusts a whole
  # interface and the operator never hand-lists ports.
  # Reconstruct an explicit map of ONLY the four known kinds (a submodule config also
  # carries a hidden `_module` attr; iterating it directly would feed that to `portOf`).
  shimUrls = lib.filterAttrs (_: v: v != null) {
    inherit (cfg.computeShimUrls)
      sql
      blob
      messaging
      kv
      ;
  };
  # Parse the port from `scheme://host:port[/…]` (handles an IPv6 `[::1]:port` host —
  # the greedy `.*` backtracks to the last `:` before the port). No port ⇒ null (skipped).
  portOf =
    url:
    let
      m = builtins.match "[a-z][a-z0-9+.-]*://.*:([0-9]+)(/.*)?" url;
    in
    if m == null then null else lib.toInt (lib.head m);
  derivedPorts = lib.filter (p: p != null) (map portOf (lib.attrValues shimUrls));
  # Effective firewall ports: the ports derived from the shim URLs PLUS any explicit
  # `computeShimPorts` the operator adds/overrides with — sorted + deduped so the
  # rendered rule is deterministic.
  shimPorts = lib.sort (a: b: a < b) (lib.unique (derivedPorts ++ cfg.computeShimPorts));
  # The env that configures the server's shims from the SAME `computeShimUrls`.
  shimEnv = lib.mapAttrsToList (k: v: "BOATRAMP_COMPUTE_${lib.toUpper k}_SHIM_URL=${v}") shimUrls;
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
        Relax the systemd sandbox so the **native** Linux compute backends
        (microVM/container: `/dev/kvm`, namespaces, mounts) can run. Off by default — a
        hardened static/handler/TLS node needs none of it, and NEITHER does a docker-only
        compute node (the docker backend runs through the docker daemon and needs no
        in-process cap/sandbox relaxation).

        This is an opt-in operator posture change: it grants the (non-root) service
        the **ambient** capabilities `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SETUID`
        and `CAP_SETGID`, and allows the `AF_NETLINK` address family — all required
        for boatramp to create the `br-boatramp` compute bridge and per-guest
        veths/taps over rtnetlink, unshare the container network namespace, mount +
        pivot the guest rootfs, and write the user-namespace uid/gid map. (Ambient,
        not merely bounding-set, because `NoNewPrivileges` + a non-root `User` make a
        bounding-set-only capability ineffective.) It also grants `DeviceAllow` for
        `/dev/kvm` + `/dev/net/tun` and relaxes `PrivateDevices`/`RestrictNamespaces`.
        `CAP_SYS_ADMIN` is broad; enable this only on a node you intend to run NATIVE
        compute workloads on.

        NOTE: the compute-shim firewall opening and the `BOATRAMP_COMPUTE_*_SHIM_URL`
        env are driven by `computeShimUrls` / `computeShimPorts` / `computeTrustBridges`
        and take effect **independently of this flag** — a docker-only node sets those
        (with `compute = false`) and gets its shims configured + its bridges admitted
        while keeping the tight sandbox. The rule is scoped to the boatramp bridges
        (`br-boatramp` + the per-project docker `boatramp-*` bridges) and port-scoped to
        the shim ports, so it never admits the LAN/public interface or an unrelated
        docker bridge (`br-<hash>`); on a docker-only node the `br-boatramp` arm simply
        never matches. See `computeShimUrls` / `computeShimPorts` / `computeTrustBridges`.
      '';
    };

    computeShimUrls = lib.mkOption {
      type = lib.types.submodule {
        options = lib.genAttrs [ "sql" "blob" "messaging" "kv" ] (
          kind:
          lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            description = "Guest-reachable base URL of the compute ${kind}-shim (e.g. `http://172.17.0.1:8084`).";
          }
        );
      };
      default = { };
      example = {
        sql = "http://172.17.0.1:8083";
        kv = "http://172.17.0.1:8084";
      };
      description = ''
        The compute-shim base URLs this node serves — the SINGLE source for both the
        server config and the firewall. Each non-null URL is (1) exported to the server
        as `BOATRAMP_COMPUTE_<KIND>_SHIM_URL` (figment layers it over the RON config),
        and (2) parsed for its `:<port>`, which the `compute` firewall then opens on the
        boatramp compute bridges ONLY. So set a shim's URL here (not in the RON) and it
        is both enabled AND reachable — no separate `computeShimPorts` to hand-list. For
        the docker backend, bind on the host-gateway IP (`http://172.17.0.1:<port>`); the
        backend rewrites the guest's view to `host.docker.internal` automatically.
        Unset ⇒ that shim is off. Takes effect independently of `compute`: the docker
        backend needs no cap/sandbox relaxation, so setting this on a docker-only node
        (`compute = false`) both exports the shim env AND opens the firewall for the
        boatramp bridges. (`compute` is only for the native container/microVM backends.)
      '';
    };

    computeShimPorts = lib.mkOption {
      type = lib.types.listOf lib.types.port;
      default = [ ];
      example = [
        8083
        8084
      ];
      description = ''
        EXTRA TCP ports to open on the boatramp compute bridges, added on top of the
        ports auto-derived from `computeShimUrls`. Use it only when a shim URL is set
        outside this module (e.g. in the RON config) so its port is not auto-derived.
        Normally leave empty and let `computeShimUrls` drive both. Opens the firewall
        independently of `compute` (the docker backend needs no cap/sandbox relaxation).
      '';
    };

    computeTrustBridges = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Opt OUT of port-scoping: trust ALL TCP traffic on the boatramp compute bridges
        instead of opening only the shim ports. Still scoped to the boatramp bridges
        (never the LAN/public interface), so the off-node boundary is unchanged, but it
        widens the container→host surface to every host port. Prefer leaving this off
        and letting `computeShimUrls` open only the shim ports. Takes effect
        independently of `compute` (the docker backend needs no cap/sandbox relaxation).
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

    networking.firewall = lib.mkMerge [
      (lib.mkIf cfg.openFirewall {
        allowedTCPPorts = [
          80
          443
        ];
      })
      # Gap B — firewall coherence. A compute node creates per-project/static bridges
      # whose gateway is the host and binds its shims host-side, but a default-firewall
      # host still DROPs the container→host:shim-port packet at INPUT. Admit the
      # compute-shim data plane on the boatramp compute
      # bridges ONLY: the static `br-boatramp` (native-container/firecracker) and the
      # per-project docker bridges, whose Linux interface names boatramp pins to the
      # `boatramp-` prefix (boatramp-docker's `project_bridge_name` /
      # `PROJECT_BRIDGE_PREFIX`). Matching that scoped prefix — never the broad `br-+`
      # — is the crux of the off-node invariant: the rule accepts traffic ARRIVING on
      # a boatramp bridge (the project's own containers → the host), and admits
      # nothing on the LAN/public interface or on an unrelated docker bridge. By
      # default it opens ONLY the shim ports (least privilege); see below.
      #
      # Two firewall backends, two syntaxes for the per-project docker bridges'
      # name-prefix match (the hash suffix is per-project, so an exact name is
      # impossible): nftables uses an `iifname "boatramp-*"` glob; iptables uses the
      # `boatramp-+` interface wildcard. `br-boatramp` is a fixed name in both. The
      # DEFAULT is port-scoped (the shim ports derived from `computeShimUrls`, plus any
      # `computeShimPorts`); `computeTrustBridges` opts out to a bare-protocol accept on
      # the interfaces; with no ports and no opt-out there is nothing to admit, so no
      # rule is emitted (the enclosing `mkIf` is false).
      #
      # NOT gated on `cfg.compute`: the DOCKER compute backend needs no cap/sandbox
      # relaxation (that's what `compute` is for — the native container/microVM backends),
      # yet a docker-only node still binds host-side shims its per-project `boatramp-*`
      # bridges must reach. So this admit rule fires whenever shim ports are configured
      # (or `computeTrustBridges`), regardless of `compute`. On a docker-only node the
      # `br-boatramp` arm simply never matches (that interface only exists for the native
      # backends) and is harmless; the `boatramp-*` arm matches the docker per-project
      # bridges. The off-node boundary is UNCHANGED either way — the rule is still
      # interface-scoped to the boatramp bridges and port-scoped to the shim ports, so an
      # off-node peer on the LAN/public interface is still default-DROPped.
      (lib.mkIf (cfg.computeTrustBridges || shimPorts != [ ]) (
        let
          useNft = config.networking.nftables.enable;
          trust = cfg.computeTrustBridges;
          # nftables: a port-scoped `tcp dport { … }`, else a bare-protocol match.
          # `meta l4proto tcp` — NOT a bare `tcp`, which is not a valid nft match (it
          # needs a header field) and fails `checkRuleset` at nixos-rebuild.
          nftMatch =
            if trust then
              "meta l4proto tcp"
            else
              "tcp dport { ${lib.concatMapStringsSep ", " toString shimPorts} }";
          nftRule = ifaceSel: "${ifaceSel} ${nftMatch} accept";
          # iptables: `-p tcp -m multiport --dports 8083,8084` when scoped, else `-p tcp`.
          iptMatch =
            if trust then
              "-p tcp"
            else
              "-p tcp -m multiport --dports ${lib.concatMapStringsSep "," toString shimPorts}";
          iptRule = iface: "iptables -A nixos-fw -i ${iface} ${iptMatch} -j nixos-fw-accept";
          iptDel =
            iface: "iptables -D nixos-fw -i ${iface} ${iptMatch} -j nixos-fw-accept 2>/dev/null || true";
        in
        if useNft then
          {
            extraInputRules = ''
              ${nftRule "iifname \"br-boatramp\""}
              ${nftRule "iifname \"boatramp-*\""}
            '';
          }
        else
          {
            extraCommands = ''
              ${iptRule "br-boatramp"}
              ${iptRule "boatramp-+"}
            '';
            # Remove our rules on firewall stop/reload so they don't accumulate.
            extraStopCommands = ''
              ${iptDel "br-boatramp"}
              ${iptDel "boatramp-+"}
            '';
          }
      ))
    ];

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
        # Under `cfg.compute` the net/sys/setuid/setgid caps must be AMBIENT, not just
        # in the bounding set: `User=` is non-root and `NoNewPrivileges=true`, so a
        # bounding-set cap alone grants nothing — only an ambient cap is actually
        # effective (and is inherited by the re-exec'd `__sandbox`/VMM workers). These
        # mirror the `cfg.compute` bounding-set additions below: `CAP_NET_ADMIN` +
        # `CAP_SYS_ADMIN` for the rtnetlink bridge/veth ops + the container netns
        # unshare / rootfs mount / pivot_root, and `CAP_SETUID`/`CAP_SETGID` for the
        # userns uid/gid map.
        AmbientCapabilities = [
          "CAP_NET_BIND_SERVICE"
        ]
        ++ lib.optionals cfg.compute [
          "CAP_NET_ADMIN"
          "CAP_SYS_ADMIN"
          "CAP_SETUID"
          "CAP_SETGID"
        ];
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
        ]
        # The compute backends create the `br-boatramp` bridge + per-guest veths over
        # rtnetlink (an `AF_NETLINK` socket); without this the socket fails EAFNOSUPPORT
        # (`os error 97`) and all container/VMM backends are disabled at node init.
        ++ lib.optionals cfg.compute [ "AF_NETLINK" ];
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
        # Device access for the native backends ONLY (microVM/container): `/dev/kvm` and
        # `/dev/net/tun`. Genuinely `compute`-gated — a docker-only node must NOT get it.
        DeviceAllow = [
          "/dev/kvm rw"
          "/dev/net/tun rw"
        ];
      }
      # Feed the compute shim URLs set in `computeShimUrls` to the server as
      # `BOATRAMP_COMPUTE_<KIND>_SHIM_URL` (figment layers env over the RON config), so the
      # SAME option that opens the firewall ports also enables the shims. NOT gated on
      # `cfg.compute`: the docker backend needs the shim env too and needs no cap/sandbox
      # relaxation. Merged via `//` so it composes with any other serviceConfig env; empty
      # `shimEnv` (no `computeShimUrls`) ⇒ no `Environment` key at all (unchanged — the RON
      # config, if any, stands).
      // lib.optionalAttrs (shimEnv != [ ]) {
        Environment = shimEnv;
      };
    };
  };
}
