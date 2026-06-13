let
  sources = import ./nix/sources.nix;
  pkgs = import sources.nixpkgs {};
  pre-commit-hooks = import sources."pre-commit-hooks.nix";

  formatters = with pkgs; [
    alejandra
  ];

  pre-commit-check = pre-commit-hooks.run {
    src = ../.;
    hooks = {
      treefmt.enable = true;
      statix.enable = true;
      deadnix.enable = true;
    };
    excludes = ["nix/sources.nix" "nix/sources.json"];
    settings = {
      treefmt.package = pkgs.writeShellApplication {
        name = "treefmt";
        runtimeInputs =
          [
            pkgs.treefmt
          ]
          ++ formatters;
        text = ''
          exec treefmt "$@"
        '';
      };
      statix.ignore = ["nix/sources.nix"];
    };
  };
in
  pkgs.mkShell {
    packages = with pkgs;
      [
        niv
        alejandra
        treefmt
      ]
      ++ formatters;
    shellHook = ''
      ${pre-commit-check.shellHook}
    '';
  }
