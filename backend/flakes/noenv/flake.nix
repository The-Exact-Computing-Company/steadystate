{
  description = "SteadyState --noenv environment";

  inputs = {
    nixpkgs.url = "github:rstats-on-nix/nixpkgs/2026-06-23";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs { inherit system; };
    in
    {
      devShells.default = pkgs.mkShell {
        name = "steadystate-noenv";

        buildInputs = [
          pkgs.git
          pkgs.nano
          pkgs.ne
          pkgs.neovim
          pkgs.tmux
        ];

        # Optional helper tools
        nativeBuildInputs = [
          pkgs.coreutils
        ];

        shellHook = ''
          echo "SteadyState --noenv environment activated."
          echo "You have access to following tools: nano, ne, neovim, git."
        '';
      };
    });
}
