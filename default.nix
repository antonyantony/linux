{
  kernelUrl ? null,
  kernelRef ? null,
  strongSwanUrl ? null,
  strongSwanRef ? null,
}: let
  sources = import ./nix/sources.nix {};
  pkgs = import sources.nixpkgs {
    overlays = [
      (import ./utils/ccache-wrapper.nix)
    ];
  };

  outputs = import ./nix/outputs.nix {
    inherit pkgs kernelUrl kernelRef strongSwanUrl strongSwanRef;
  };
in {
  inherit (outputs) packages checks;
}
