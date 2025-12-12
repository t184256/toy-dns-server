{
  description = "a toy DNS server written in Rust for learning purposes";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";

    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, crane, flake-utils, advisory-db }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        craneLib = crane.mkLib pkgs;

        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = let
            allowMore = path: _type:
              builtins.match ".*/tests/.*\\.(yml|bin)$" path != null;
            relaxedFilterFunc = path: type:
              (craneLib.filterCargoSources path type) || (allowMore path type);
          in
            relaxedFilterFunc
          ;
          name = "source";
        };

        commonArgs = {
          inherit src;
          strictDeps = true;
        };

        # Build dependencies separately for better caching
        cargoArtifacts = craneLib.buildDepsOnly commonArgs;

        toy-dns-server = craneLib.buildPackage (commonArgs // {
          inherit cargoArtifacts;
        });

      in {
        checks = {
          # Build the crate as part of `nix flake check`
          inherit toy-dns-server;

          # Run clippy (and deny all warnings) on the crate source
          toy-dns-server-clippy = craneLib.cargoClippy (commonArgs // {
            inherit cargoArtifacts;
            cargoClippyExtraArgs = "--all-targets -- --deny warnings";
          });

          # Check formatting
          toy-dns-server-fmt = craneLib.cargoFmt {
            inherit src;
          };

          # Check TOML formatting
          toy-dns-server-toml-fmt = craneLib.taploFmt {
            src = pkgs.lib.sources.sourceFilesBySuffices src [ ".toml" ];
          };

          # Audit dependencies
          toy-dns-server-audit = craneLib.cargoAudit {
            inherit src advisory-db;
          };

          # Audit licenses
          toy-dns-server-deny = craneLib.cargoDeny {
            src = pkgs.lib.sources.sourceFilesBySuffices src [ ".rs" ".toml" ];
          };
        };

        packages.default = toy-dns-server;

        apps.default = flake-utils.lib.mkApp {
          drv = toy-dns-server;
        };

        devShells.default = craneLib.devShell {
          checks = self.checks.${system};
          packages = [ pkgs.rust-analyzer pkgs.pre-commit ];
          shellHook = ''
            [ -e .git/hooks/pre-commit ] || \
            echo "suggestion: pre-commit install --install-hooks" >&2
          '';
        };
      }
    );
}
