{
  description = "SteadyState --noenv environment";

  inputs = {
    nixpkgs.url = "github:rstats-on-nix/nixpkgs/2026-06-23";
    flake-utils.url = "github:numtide/flake-utils";
    treemerge.url = "github:b-rodrigues/treemerge";
  };

  outputs = { self, nixpkgs, flake-utils, treemerge }:
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
          treemerge.packages.${system}.default
        ];

        # Optional helper tools
        nativeBuildInputs = [
          pkgs.coreutils
        ];

        shellHook = ''
          echo "SteadyState --noenv environment activated."
          echo "You have access to following tools: nano, ne, neovim, git, treemerge."
        '';
      };
    });
}
