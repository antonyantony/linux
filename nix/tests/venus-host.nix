# venus: aliceNet (10.1.0.0/16 / fec1::/16), gateway = moon's aliceNet-facing
# address (moon1), vlan 2.
{lib, ...}: let
  topology = import ./topology.nix;
in
  import ./single-end-host.nix {
    inherit lib;
    config = {
      eth1 = {
        ipv4 = {
          address = topology.hosts.venus.ipv4;
          inherit (topology.nets.aliceNet.ipv4) prefixLength;
          gateway = topology.hosts.moon1.ipv4;
        };
        ipv6 = {
          address = topology.hosts.venus.ipv6;
          inherit (topology.nets.aliceNet.ipv6) prefixLength;
        };
      };
      vlan = [2];
    };
  }
