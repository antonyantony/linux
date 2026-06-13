{
  pkgs,
  kernelUrl,
  kernelRef ? null,
  strongSwanUrl ? null,
  strongSwanRef ? null,
}: let
  runTest = test:
    pkgs.testers.runNixOSTest {
      imports = [test];
      defaults.basevpn.kernel =
        pkgs.lib.optionalAttrs (kernelUrl != null) {url = kernelUrl;}
        // pkgs.lib.optionalAttrs (kernelRef != null) {ref = kernelRef;};
      defaults.basevpn.strongswan =
        pkgs.lib.optionalAttrs (strongSwanUrl != null) {url = strongSwanUrl;}
        // pkgs.lib.optionalAttrs (strongSwanRef != null) {ref = strongSwanRef;};
    };
in {
  test-ipv4-01 = runTest ./test-ipv4-01.nix;
  test-ipv6-01 = runTest ./test-ipv6-01.nix;
  test-ipv4-03-net-2-net = runTest ./test-ipv4-03-net-2-net.nix;
  moon-swanctl = runTest ./moon-swanctl.nix;
}
