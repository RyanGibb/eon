{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    opam-nix.url = "github:tweag/opam-nix";
    flake-utils.url = "github:numtide/flake-utils";
    # we pin opam-nix's nixpkgs to follow the flakes, avoiding using two different instances
    opam-nix.inputs.nixpkgs.follows = "nixpkgs";

    # maintain a different opam-repository to those pinned upstream
    # opam-repository = {
    #   url = "github:ocaml/opam-repository";
    #   flake = false;
    # };
    # opam-nix.inputs.opam-repository.follows = "opam-repository";

    # deduplicate flakes
    opam-nix.inputs.flake-utils.follows = "flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils, opam-nix, ... }@inputs:
    # create outputs for each default system
    flake-utils.lib.eachDefaultSystem (system:
      let
        package = "eon";
        pkgs = nixpkgs.legacyPackages.${system};
        opam-nix-lib = opam-nix.lib.${system};
        devPackagesQuery = {
          ocaml-lsp-server = "*";
          ocamlformat = "*";
          utop = "*";
        };
        query = {
          ocaml-base-compiler = "*";
          mirage-runtime = "4.8.1";
        };
        scope =
          opam-nix-lib.buildOpamProject' { } ./. (query // devPackagesQuery);
      in {
        packages.default = scope.${package};
        defaultPackage = scope.${package};

        devShells.default = let
          devPackages = builtins.attrValues
            (pkgs.lib.getAttrs (builtins.attrNames devPackagesQuery) scope);
        in pkgs.mkShell {
          inputsFrom = [ scope.${package} ];
          buildInputs = devPackages;
        };
      }) // {
        nixosModules = {
          default.imports = [ (import ./module.nix self.packages) ];
          acme.imports = [ (import ./acme.nix self.packages) ];
        };

        formatter = nixpkgs.lib.genAttrs nixpkgs.lib.systems.flakeExposed
          (system: nixpkgs.legacyPackages.${system}.nixfmt);
      };
}
