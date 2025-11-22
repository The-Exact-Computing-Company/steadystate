{
  description = "SteadyState dev environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    flake-utils.url = "github:numtide/flake-utils";
    treemerge.url = "github:b-rodrigues/treemerge";
    upterm-pkgs.url = "github:b-rodrigues/nixpkgs/update_upterm";
    antigravity-pkgs.url = "github:xiaoxiangmoe/nixpkgs/antigravity";
  };

  outputs = { self, nixpkgs, flake-utils, treemerge, antigravity-pkgs, upterm-pkgs }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs { inherit system; };

      # Google antigravity
      isCI = builtins.getEnv "CI" == "true" || builtins.getEnv "CI" == "1";
      agpkgs = import antigravity-pkgs {
        inherit system;
        config.allowUnfree = true;
      };
      # Updated upterm
      upkgs = import upterm-pkgs {inherit system;};

      antigravity = agpkgs.antigravity; # typically how overlays expose it
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
        ] ++ (if isCI then [] else [ antigravity pkgs.gemini-cli]);

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
