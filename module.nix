packages: { config, lib, ... }:

let cfg = config.services.eon;
in {
  options.services.eon = {
    enable =
      lib.mkEnableOption "OCaml DNS Server using effects-based direct-style IO";
    package = lib.mkOption {
      type = lib.types.package;
      default = packages.${config.nixpkgs.hostPlatform.system}.default;
    };
    # todo multiple zones, primary and secondary servers
    zoneFiles =
      lib.mkOption { type = lib.types.listOf (lib.types.either lib.types.str lib.types.path); };
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
      type = lib.types.enum [ "eon" "resolved" "netcatd" "tund" "cap" ];
      default = "eon";
    };
    openFirewall = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };
    capnpAddress = lib.mkOption {
      type = lib.types.string;
      default = "0.0.0.0";
    };
    capnpPort = lib.mkOption {
      type = lib.types.int;
      default = 7000;
    };
    capnpSecretKeyFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
    };
    prod = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };
    acmeServer = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = lib.mdDoc ''
        ACME Directory Resource URI.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.eon = {
      description = "eon";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        ExecStart = "${cfg.package.out}/bin/${cfg.application} "
          + (lib.strings.concatMapStrings (zonefile: "-z ${zonefile} ")
            cfg.zoneFiles) + "-p ${builtins.toString cfg.port} "
          + "-l ${builtins.toString cfg.logLevel} "
          + (if cfg.application == "cap" then
            "--capnp-secret-key-file ${
              if cfg.capnpSecretKeyFile != null then
                cfg.capnpSecretKeyFile
              else
                "/var/lib/eon/capnp-secret.pem"
            } " + "--capnp-listen-address tcp:${cfg.capnpAddress}:${
              builtins.toString cfg.capnpPort
            } " + "--state-dir /var/lib/eon "
            + "${if cfg.prod then "--prod" else ""}"
            + "${if cfg.acmeServer != null then
              "--endpint ${cfg.acmeServer}"
            else
              ""}"
          else
            "");
        Restart = "always";
        RestartSec = "1s";
        User = cfg.user;
        Group = cfg.group;
        AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ] ++
          # for TUNSETIFF
          (if cfg.application == "tund" then [ "CAP_NET_ADMIN" ] else [ ]);
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

    users.groups."${cfg.group}" = { };

    networking.firewall = lib.mkIf cfg.openFirewall {
      allowedTCPPorts = [ cfg.port ]
        ++ (if cfg.application == "cap" then [ cfg.capnpPort ] else [ ]);
      allowedUDPPorts = [ cfg.port ];
    };
  };
}
