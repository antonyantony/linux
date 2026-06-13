# moon: dual-homed gateway between sunMoonNet (eth1) and aliceNet (eth2,
# moon1), with a route to bobNet via sun.
{lib, ...}: let
  topology = import ./topology.nix;
in
  import ./dual-end-host.nix {
    inherit lib;
    config = {
      eth1 = {
        ipv4 = {
          address = topology.hosts.moon.ipv4;
          inherit (topology.nets.sunMoonNet.ipv4) prefixLength;
          routes = [
            {
              inherit (topology.nets.bobNet.ipv4) address prefixLength;
              via = topology.hosts.sun.ipv4;
            }
          ];
        };
        ipv6 = {
          address = topology.hosts.moon.ipv6;
          inherit (topology.nets.sunMoonNet.ipv6) prefixLength;
          routes = [
            {
              inherit (topology.nets.bobNet.ipv6) address prefixLength;
              via = topology.hosts.sun.ipv6;
            }
          ];
        };
      };
      eth2 = {
        ipv4 = {
          address = topology.hosts.moon1.ipv4;
          inherit (topology.nets.aliceNet.ipv4) prefixLength;
        };
        ipv6 = {
          address = topology.hosts.moon1.ipv6;
          inherit (topology.nets.aliceNet.ipv6) prefixLength;
        };
      };
      vlan = [1 2];
    };
  }
