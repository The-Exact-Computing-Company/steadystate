{
  description = "SteadyState dev environment";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    treemerge.url = "github:b-rodrigues/treemerge";
    upterm-pkgs.url = "github:b-rodrigues/nixpkgs/update_upterm";
  };
  outputs = { self, nixpkgs, flake-utils, treemerge, upterm-pkgs }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs { inherit system; };
      isCI = builtins.getEnv "CI" == "true" || builtins.getEnv "CI" == "1";
      isDarwin = pkgs.stdenv.isDarwin;
      
      upkgs = import upterm-pkgs {inherit system;};
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
        # Skip tests on Darwin - they may have platform-specific issues
        # Run tests locally on Linux for fast feedback during development
        doCheck = !isCI && !isDarwin;
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
      # Use kitty on Darwin, ghostty on Linux
      terminal = if isDarwin 
        then pkgs.lib.getExe' pkgs.kitty "kitty"
        else pkgs.lib.getExe' pkgs.ghostty "ghostty";
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
        ] ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.iproute2 ]
          ++ pkgs.lib.optionals (!isCI) [ pkgs.gemini-cli ];
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
