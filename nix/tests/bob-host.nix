# bob: bobNet (10.2.0.0/16 / fec2::/16), gateway = sun's bobNet-facing
# address (sun1), vlan 3.
{lib, ...}: let
  topology = import ./topology.nix;
in
  import ./single-end-host.nix {
    inherit lib;
    config = {
      eth1 = {
        ipv4 = {
          address = topology.hosts.bob.ipv4;
          inherit (topology.nets.bobNet.ipv4) prefixLength;
          gateway = topology.hosts.sun1.ipv4;
        };
        ipv6 = {
          address = topology.hosts.bob.ipv6;
          inherit (topology.nets.bobNet.ipv6) prefixLength;
        };
      };
      vlan = [3];
    };
  }
