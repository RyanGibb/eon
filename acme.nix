packages: { pkgs, config, lib, ... }:

with lib;
let
  cfg = config.security.acme-eon;

  # These options can be specified within
  # security.acme.defaults or security.acme.certs.<name>
  inheritableModule = isDefaults:
    { config, ... }:
    let
      defaultAndText = name: default: {
        default = if isDefaults || !config.inheritDefaults then
          default
        else
          cfg.defaults.${name};
        defaultText = if isDefaults then
          default
        else
          literalExpression "config.security.acme.defaults.${name}";
      };
    in {
      options = {
        capFile = mkOption {
          type = types.str;
          inherit (defaultAndText "capFile" null) default defaultText;
          description = lib.mdDoc "Capability file path.";
        };

        email = mkOption {
          type = types.nullOr types.str;
          inherit (defaultAndText "email" null) default defaultText;
          description = lib.mdDoc ''
            Email address for account creation and correspondence from the CA.
            It is recommended to use the same email for all certs to avoid account
            creation limits.
          '';
        };

        group = mkOption {
          type = types.str;
          inherit (defaultAndText "group" "acme-eon") default defaultText;
          description = lib.mdDoc "Group running the client.";
        };

        reloadServices = mkOption {
          type = types.listOf types.str;
          inherit (defaultAndText "reloadServices" [ ]) default defaultText;
          description = lib.mdDoc ''
            The list of systemd services to call `systemctl try-reload-or-restart`
            on.
          '';
        };
      };
    };

  certOpts = { name, ... }: {
    options = {
      directory = mkOption {
        type = types.str;
        readOnly = true;
        default = "/var/lib/acme-eon/${name}";
        description =
          lib.mdDoc "Directory where certificate and other state is stored.";
      };

      domain = mkOption {
        type = types.str;
        readOnly = true;
        default = name;
        description =
          lib.mdDoc "Domain to fetch certificate for (the entry name).";
      };

      extraDomainNames = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = literalExpression ''
          [
            "example.com"
            "mydomain.org"
          ]
        '';
        description = lib.mdDoc ''
          A list of extra domain names, which are included in the one certificate to be issued.
        '';
      };

      inheritDefaults = mkOption {
        default = true;
        example = true;
        description = lib.mdDoc
          "Whether to inherit values set in `security.acme.defaults` or not.";
        type = lib.types.bool;
      };
    };
  };
in {
  options.security.acme-eon = {
    package = lib.mkOption {
      type = lib.types.package;
      default = packages.${config.nixpkgs.hostPlatform.system}.default;
    };

    acceptTerms = mkOption {
      type = types.bool;
      default = false;
      description = lib.mdDoc ''
        Accept the CA's terms of service. The default provider is Let's Encrypt,
        you can find their ToS at <https://letsencrypt.org/repository/>.
      '';
    };

    defaults = mkOption {
      type = types.submodule (inheritableModule true);
      description = lib.mdDoc ''
        Default values inheritable by all configured certs. You can
        use this to define options shared by all your certs. These defaults
        can also be ignored on a per-cert basis using the
        {option}`security.acme.certs.''${cert}.inheritDefaults` option.
      '';
    };

    certs = mkOption {
      default = { };
      type = with types;
        attrsOf (submodule [ (inheritableModule false) certOpts ]);
      description = lib.mdDoc ''
        Attribute set of certificates to get signed and renewed. Other services can add dependencies
        to those units if they rely on the certificates being present,
        or trigger restarts of the service if certificates get renewed.
      '';
      example = literalExpression ''
        {
          "example.com" = {
            email = "foo@example.com";
            extraDomainNames = [ "www.example.com" "foo.example.com" ];
          };
          "bar.example.com" = {
            email = "bar@example.com";
          };
        }
      '';
    };

    nginxCerts = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = lib.mdDoc ''
        Domain names to configure Nginx certificates for.
      '';
    };
  };

  config = let
    mkCertService = name: cert: {
      description = "Provision ACME certificate for ${cert.domain}";

      wantedBy = optionals (!config.boot.isContainer) [ "multi-user.target" ];

      path = with pkgs; [ cfg.package ];

      wants = [ "network-online.target" "eon.service" ];
      after = [ "network-online.target" "eon.service" ];

      serviceConfig = {
        User = "acme-eon";
        Group = cert.group;
        UMask = "0022";
        StateDirectoryMode = "750";
        StateDirectory = [ "acme-eon/${cert.domain}" ];
        # Run as root (Prefixed with +)
        ExecStartPre = "+" + (pkgs.writeShellScript "acme-prerun" ''
          cp ${cert.capFile} domain.cap
          chown acme-eon domain.cap
        '');
        ExecStart = ''
          ${cfg.package}/bin/capc cert \
          domain.cap \
          ${cert.email} \
          -d ${cert.domain} \
          ${
            lib.strings.concatMapStringsSep " " (d: "-d " + d)
            cert.extraDomainNames
          } \
          --cert-dir ${cert.directory} \
          --exit-when-renewed
        '';
        # Run as root (Prefixed with +)
        ExecStartPost = "+" + (pkgs.writeShellScript "acme-postrun" ''
          cd /var/lib/acme-eon/${escapeShellArg cert.domain}
          if [ -e renewed ]; then
            rm renewed
            ${
              optionalString (cert.reloadServices != [ ])
              "systemctl --no-block try-reload-or-restart ${
                escapeShellArgs cert.reloadServices
              }"
            }
          fi
        '');
      };
    };
  in {
    assertions = [{
      assertion = cfg.acceptTerms;
      message = ''
        You must accept the CA's terms of service before using
        the ACME module by setting `security.acme-eon.acceptTerms`
        to `true`. For Let's Encrypt's ToS see https://letsencrypt.org/repository/
      '';
    }];

    users.users.acme-eon = {
      home = "/var/lib/acme-eon/";
      group = "acme-eon";
      isSystemUser = true;
    };
    users.groups.acme-eon = { };

    security.acme-eon.certs = builtins.listToAttrs (builtins.map (name: {
      inherit name;
      value = {
        group = "nginx";
        reloadServices = [ "nginx" ];
      };
    }) cfg.nginxCerts);

    systemd.services = (lib.attrsets.mapAttrs' (name: cert: {
      name = "acme-eon-${name}";
      value = mkCertService name cert;
    }) cfg.certs) // {
      nginx.wants =
        builtins.map (name: "acme-eon-${name}.service") cfg.nginxCerts;
      nginx-config-reload.after =
        builtins.map (name: "acme-eon-${name}.service") cfg.nginxCerts;
    };

    services.nginx.virtualHosts = builtins.listToAttrs (builtins.map (name: {
      name = name;
      value = {
        sslCertificate = "${cfg.certs.${name}.directory}/fullchain.pem";
        sslCertificateKey = "${cfg.certs.${name}.directory}/key.pem";
        sslTrustedCertificate = "${cfg.certs.${name}.directory}/chain.pem";
      };
    }) cfg.nginxCerts);
  };
}
