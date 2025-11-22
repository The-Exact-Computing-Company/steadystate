{
  description = "SteadyState dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    treemerge.url = "github:b-rodrigues/treemerge";
    upterm-pkgs.url = "github:b-rodrigues/nixpkgs/update_upterm";
    antigravity-pkgs.url = "github:NixOS/nixpkgs/master";
  };

  outputs = { self, nixpkgs, flake-utils, treemerge, antigravity-pkgs, upterm-pkgs }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs { inherit system; };

      isCI = builtins.getEnv "CI" == "true" || builtins.getEnv "CI" == "1";
      
      # Only import antigravity packages when NOT in CI
      agpkgs = if isCI then null else import antigravity-pkgs {
        inherit system;
        config.allowUnfree = true;
      };
      
      upkgs = import upterm-pkgs {inherit system;};
      antigravity = if isCI then null else agpkgs.antigravity;
      upterm = upkgs.upterm;

      workspaceSrc = pkgs.lib.cleanSource ./.;

      # Build entire Cargo workspace once
      workspaceDrv = pkgs.rustPlatform.buildRustPackage {
        pname = "steadystate-workspace";
        version = "0.0.1";

        src = workspaceSrc;

        cargoLock = {
          lockFile = ./Cargo.lock;
        };

        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ pkgs.openssl ];

        # Skip tests in CI builds - tests run in separate CI action
        # Run tests locally for fast feedback during development
        doCheck = !isCI;

        OPENSSL_NO_VENDOR = 1;
      };

      # Extract individual binaries
      backend = pkgs.stdenv.mkDerivation {
        name = "steadystate-backend";
        buildCommand = ''
          mkdir -p $out/bin
          cp ${workspaceDrv}/bin/steadystate-backend $out/bin/
        '';
      };

      cli = pkgs.stdenv.mkDerivation {
        name = "steadystate";
        buildCommand = ''
          mkdir -p $out/bin
          cp ${workspaceDrv}/bin/steadystate $out/bin/
        '';
      };

      #terminal = pkgs.lib.getExe' pkgs.xterm "xterm";
      terminal = pkgs.lib.getExe' pkgs.kitty "kitty";

    in {
      packages.default = cli;

      packages.backend = backend;
      packages.cli = cli;

      apps.backend = flake-utils.lib.mkApp { drv = backend; };
      apps.cli = flake-utils.lib.mkApp { drv = cli; };

      devShells.default = pkgs.mkShell {
        name = "steadystate-dev";

        buildInputs = [
          pkgs.cargo
          pkgs.rustc
          pkgs.rustfmt
          pkgs.clippy
          pkgs.openssl.dev
          pkgs.pkg-config
          backend
          cli
          treemerge.packages.${system}.default
          upterm
        ] ++ pkgs.lib.optionals (!isCI) [ antigravity pkgs.gemini-cli ];

        shellHook = ''
          echo "🔧 Entering SteadyState dev shell"

          if [ -f backend/.env ]; then
            echo "📦 Loading backend/.env..."
            export $(grep -v '^#' backend/.env | xargs)
          else
            echo "⚠️ No backend/.env found"
          fi

          # IMPORTANT: CLI must talk HTTP, not HTTPS
          export STEADYSTATE_BACKEND=http://localhost:8080
          export NOENV_FLAKE_PATH=/tmp/dummy-flake

          echo "🚀 Launching backend in new terminal"
          ${terminal} -e sh -c "${backend}/bin/steadystate-backend; exec bash" &

          echo ""
          echo "Use: steadystate login / steadystate up / steadystate whoami"
        '';
      };
    });
}
