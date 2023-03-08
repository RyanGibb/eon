{
  inputs = {
    opam-nix.url = "github:tweag/opam-nix";
    flake-utils.url = "github:numtide/flake-utils";
    opam-nix.inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs = { self, nixpkgs, flake-utils, opam-nix, ... }@inputs:
    let package = "aeon";
    in flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        opam-nix-lib = opam-nix.lib.${system};
        devPackagesQuery = {
          ocaml-lsp-server = "*";
          ocamlformat = "*";
        };
        query = {
          ocaml-base-compiler = "*";
        };
        overlay = final: prev: {
          "${package}" = prev.${package}.overrideAttrs (_: {
            # Prevent the ocaml dependencies from leaking into dependent environments
            doNixSupport = false;
          });
        };
        resolved-scope =
          let scope = opam-nix-lib.buildOpamProject' { } ./. (query // devPackagesQuery); in
          scope.overrideScope' overlay;
        materialized-scope =
          # to generate:
          #   nix shell github:tweag/opam-nix#opam-nix-gen -c opam-nix-gen -p ocaml-lsp-server -p ocamlformat -p ocaml-base-compiler aeon . package-defs.json
          let scope = opam-nix-lib.materializedDefsToScope { sourceMap.${package} = ./.; } ./package-defs.json; in
          scope.overrideScope' overlay;
      in rec {
        packages = {
          resolved = resolved-scope;
          materialized = materialized-scope;
          default = materialized-scope.${package};
        };
        defaultPackage = packages.default;

        devShells = 
          let
            mkDevShell = scope:
              let
                devPackages = builtins.attrValues
                  (pkgs.lib.getAttrs (builtins.attrNames devPackagesQuery) scope);
              in pkgs.mkShell {
                inputsFrom = [ scope.${package} ];
                buildInputs = devPackages;
              };
          in rec {
            resolved = mkDevShell resolved-scope;
            materialized = mkDevShell materialized-scope;
            default = materialized;
          };
      }) // {
    nixosModules.default = {
      imports = [ ./module.nix ];
    };
  };
}
