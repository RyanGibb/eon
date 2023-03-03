{ pkgs, config, lib, ... }:

with lib;

let cfg = config.services.aeon; in
{
  options.services.aeon = {
    enable = mkEnableOption "OCaml DNS Server using effects-based direct-style IO";
    # todo multiple zones, primary and secondary servers
    zoneFile = mkOption {
      type = types.either types.str types.path;
    };
    user = lib.mkOption {
      type = lib.types.str;
      default = "aeon";
    };
    group = lib.mkOption {
      type = lib.types.str;
      default = cfg.user;
    };
    logLevel = lib.mkOption {
      type = lib.types.int;
      default = 1;
    };
  };
  
  config = mkIf cfg.enable {
    systemd.services.aeon = {
      description = "OCaml DNS Server using effects-based direct-style IO";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${pkgs.aeon.out}/bin/aeon -z ${cfg.zoneFile} -l ${builtins.toString cfg.logLevel}";
        Restart = "always";
        RestartSec = "1s";
        User = cfg.user;
        Group = cfg.group;
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
      };
    };

    users.users = {
      "${cfg.user}" = {
        description = "OCaml DNS Server using effects-based direct-style IO";
        useDefaultShell = true;
        group = cfg.group;
        isSystemUser = true;
      };
    };

    users.groups."${cfg.group}" = {};
  };
}
