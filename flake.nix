{
  inputs = {
    opam-nix.url = "github:tweag/opam-nix";
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
        package = "aeon";
        pkgs = nixpkgs.legacyPackages.${system};
        opam-nix-lib = opam-nix.lib.${system};
        devPackagesQuery = {
          ocaml-lsp-server = "*";
          ocamlformat = "*";
          # 1.9.6 fails to build
          ocamlfind = "1.9.5";
          utop = "*";
        };
        query = {
          ocaml-base-compiler = "*";
        };
        # filters vendored dependencies from a scope
        filterVendored =
          let repo = opam-nix-lib.makeOpamRepo' true ./.; in
          pkgs.lib.attrsets.filterAttrs (n: _v: !builtins.hasAttr n (opam-nix-lib.listRepo repo) || n == package);
        resolved-scope =
          # with `recursive = false;` so we don't pick up vendored dependencies
          # this is because we don't need all of them, and some have conflicting depdnancy versions
          # specifically for mirage-crypto-rng for dns-cli and capnp-rpc-unix
          let scope = opam-nix-lib.buildOpamProject' { } ./. (query // devPackagesQuery); in
          # to avoid building vendored dependencies twice, we filter them out of the resulting scope
          filterVendored scope;
        materialized-scope =
          let scope = opam-nix-lib.materializedDefsToScope { sourceMap.${package} = ./.; } ./package-defs.json; in
          filterVendored scope;
      in rec {
        packages = rec {
          resolved = resolved-scope;
          materialized = materialized-scope;
          # to generate:
          #   cat $(nix eval .#package-defs --raw) > package-defs.json
          # NB `recursive = false;` (see resolved-scope comments)
          package-defs = opam-nix-lib.materializeOpamProject' { } ./. (query // devPackagesQuery);
        };
        defaultPackage = packages.materialized.${package};

        devShells =
          let
            mkDevShell = scope:
              pkgs.mkShell {
                buildInputs = builtins.attrValues (pkgs.lib.attrsets.filterAttrs (_n: v: pkgs.lib.attrsets.isDerivation v) scope);
              };
            dev-scope =
              # don't pick up duniverse deps
              # it can be slow to build vendored dependencies in a deriviation before getting an error
              let scope = opam-nix-lib.buildOpamProject' { } ./. (query // devPackagesQuery); in
              # remove any dependencies vendored in the project, i.e. ${package} and duniverse/ contents
              filterVendored scope;
        in rec {
            resolved = mkDevShell resolved-scope;
            materialized = mkDevShell materialized-scope;
            # use for fast development as it doesn't building vendored sources in seperate derivations
            # however might not build the same result as `nix build .`,
            # like `nix develop .#devShells.x86_64-linux.resolved -c dune build` should do
            dev = mkDevShell dev-scope;
            default = dev;
          };
      }) // {
    nixosModules.default = {
      imports = [ ./module.nix ];
    };
  };
}
