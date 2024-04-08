{ pkgs, config, lib, ... }:

with lib;

let cfg = config.services.eon; in
{
  options.services.eon = {
    enable = mkEnableOption "OCaml DNS Server using effects-based direct-style IO";
    # todo multiple zones, primary and secondary servers
    zoneFiles = mkOption {
      type = types.listOf (types.either types.str types.path);
    };
    port = lib.mkOption {
      type = lib.types.int;
      default = 53;
    };
    user = lib.mkOption {
      type = lib.types.str;
      default = "eon";
    };
    group = lib.mkOption {
      type = lib.types.str;
      default = cfg.user;
    };
    logLevel = lib.mkOption {
      type = lib.types.int;
      default = 1;
    };
    application = lib.mkOption {
      type = types.enum [
        "eon"
        "resolved"
        "netcatd"
        "tund"
        "cap"
      ];
      default = "eon";
    };
    openFirewall = lib.mkOption {
      type = types.bool;
      default = true;
    };
  };

  config = mkIf cfg.enable {
    systemd.services.eon = {
      description = "eon";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${pkgs.eon.out}/bin/${cfg.application} "
          + (strings.concatMapStrings (zonefile: "-z ${zonefile} ")
            cfg.zoneFiles) + "-p ${builtins.toString cfg.port} "
          + "-l ${builtins.toString cfg.logLevel} "
          + (if cfg.application == "cap" then
            "--capnp-secret-key-file /var/lib/eon/capnp-secret.pem "
            + "--capnp-listen-address tcp:0.0.0.0:7000 "
          else
            "");
        Restart = "always";
        RestartSec = "1s";
        User = cfg.user;
        Group = cfg.group;
        AmbientCapabilities =
          [ "CAP_NET_BIND_SERVICE" ] ++
          # for TUNSETIFF
          (if cfg.application == "tund" then [ "CAP_NET_ADMIN" ]  else [ ]);
      };
    };

    users.users = {
      "${cfg.user}" = {
        description = "eon";
        useDefaultShell = true;
        group = cfg.group;
        isSystemUser = true;
      };
    };

    users.groups."${cfg.group}" = {};

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [ cfg.port ];
      allowedUDPPorts = [ cfg.port ];
    };
  };
}
