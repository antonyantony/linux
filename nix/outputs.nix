{
  pkgs,
  kernelUrl,
  kernelRef ? null,
  strongSwanUrl ? null,
  strongSwanRef ? null,
  ...
}: let
  nixosEvaluation = pkgs.nixos [
    ./configuration.nix
    ./packages/kernel/basevpn-kernel.nix
    ./packages/strongswan/basevpn-strongswan.nix
    ({lib, ...}: {
      basevpn.kernel =
        lib.optionalAttrs (kernelUrl != null) {url = kernelUrl;}
        // lib.optionalAttrs (kernelRef != null) {ref = kernelRef;};
      basevpn.strongswan =
        lib.optionalAttrs (strongSwanUrl != null) {url = strongSwanUrl;}
        // lib.optionalAttrs (strongSwanRef != null) {ref = strongSwanRef;};
    })
  ];
in {
  packages = {
    inherit (nixosEvaluation.config.system.build) vm;
  };

  checks = {
    tests = import ./tests/all-tests.nix {inherit pkgs kernelUrl kernelRef strongSwanUrl strongSwanRef;};
  };
}
