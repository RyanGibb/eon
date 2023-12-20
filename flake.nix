{
  inputs = {
    opam-nix.url = "github:RyanGibb/opam-nix/pin-depends-path";
    flake-utils.url = "github:numtide/flake-utils";
    # we pin opam-nix's nixpkgs to follow the flakes, avoiding using two different instances
    opam-nix.inputs.nixpkgs.follows = "nixpkgs";

    # maintain a different opam-repository to those pinned upstream
    opam-repository = {
      url = "github:ocaml/opam-repository";
      flake = false;
    };
    opam-nix.inputs.opam-repository.follows = "opam-repository";

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
        };
        scope =
          # recursive finds vendored dependancies in duniverse
          opam-nix-lib.buildOpamProject' { recursive = true; } ./. (query // devPackagesQuery);
      in {
        packages = scope;
        defaultPackage = scope.${package};

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
            dev-scope =
              # don't pick up duniverse deps
              # it can be slow to build vendored dependancies in a deriviation before getting an error
              opam-nix-lib.buildOpamProject' { } ./. (query // devPackagesQuery);
          in rec {
            build = mkDevShell scope;
            # use for fast development as it doesn't building vendored sources in seperate derivations
            # however might not build the same result as `nix build .`,
            # like `nix develop .#devShells.x86_64-linux.resolved -c dune build` should do
            default = mkDevShell dev-scope;
          };
      }) // {
    nixosModules.default = {
      imports = [ ./module.nix ];
    };
  };
}
