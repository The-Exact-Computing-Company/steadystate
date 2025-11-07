{
  description = "SteadyState CLI - Reproducible and collaborative dev envs";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

      in {
        # Reproducible build of the CLI
        packages.steadystate = pkgs.rustPlatform.buildRustPackage {
          pname = "steadystate";
          version = "0.0.1";

          src = pkgs.lib.cleanSource ./.;
          cargoLock = { lockFile = ./Cargo.lock; };

          nativeBuildInputs = [
            pkgs.openssl
            pkgs.pkg-config
          ];

          # Ensure OpenSSL linking comes from Nix
          OPENSSL_NO_VENDOR = 1;
          PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
        };

        # What nix build / nix run gives by default
        defaultPackage = self.packages.${system}.steadystate;
        defaultApp = flake-utils.lib.mkApp {
          drv = self.packages.${system}.steadystate;
        };

        # Development shell: editor-friendly + cargo tools
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pkgs.cargo
            pkgs.rustc
            pkgs.rustfmt
            pkgs.clippy
            pkgs.openssl.dev
            pkgs.pkg-config
          ];

          RUST_BACKTRACE = 1;
        };
      });
}
