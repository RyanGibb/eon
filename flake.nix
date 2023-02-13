{
  inputs = {
    opam-nix.url = "github:tweag/opam-nix";
    flake-utils.url = "github:numtide/flake-utils";
    opam-nix.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs = { self, nixpkgs, flake-utils, opam-nix }@inputs:
    let package = "dns-server-eio";
    in flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        on = opam-nix.lib.${system};
        devPackagesQuery = {
          ocaml-lsp-server = "*";
          ocamlformat = "*";
        };
        scope = on.buildOpamProject' { } ./. devPackagesQuery;
        overlay = final: prev: {
          "${package}" = prev.${package}.overrideAttrs (_: {
            # Prevent the ocaml dependencies from leaking into dependent environments
            doNixSupport = false;
          });
        };
        scope' = scope.overrideScope' overlay;
        # The main package containing the executable
        main = scope'.${package};
      in {
        legacyPackages = scope';

        packages = scope' // { default = main; };
        defaultPackage = main;

        devShells.default =
          let
            devPackages = builtins.attrValues
              (pkgs.lib.getAttrs (builtins.attrNames devPackagesQuery) scope);
          in pkgs.mkShell {
           inputsFrom = [ main ];
           buildInputs = devPackages;
         };
      }) // {
    nixosModules.default = {
      imports = [ ./module.nix ];
    };
  };
}
