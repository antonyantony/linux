# sun: dual-homed gateway between sunMoonNet (eth1) and bobNet (eth2, sun1),
# with a route to aliceNet via moon.
{lib, ...}: let
  topology = import ./topology.nix;
in
  import ./dual-end-host.nix {
    inherit lib;
    config = {
      eth1 = {
        ipv4 = {
          address = topology.hosts.sun.ipv4;
          inherit (topology.nets.sunMoonNet.ipv4) prefixLength;
          routes = [
            {
              inherit (topology.nets.aliceNet.ipv4) address prefixLength;
              via = topology.hosts.moon.ipv4;
            }
          ];
        };
        ipv6 = {
          address = topology.hosts.sun.ipv6;
          inherit (topology.nets.sunMoonNet.ipv6) prefixLength;
          routes = [
            {
              inherit (topology.nets.aliceNet.ipv6) address prefixLength;
              via = topology.hosts.moon.ipv6;
            }
          ];
        };
      };
      eth2 = {
        ipv4 = {
          address = topology.hosts.sun1.ipv4;
          inherit (topology.nets.bobNet.ipv4) prefixLength;
        };
        ipv6 = {
          address = topology.hosts.sun1.ipv6;
          inherit (topology.nets.bobNet.ipv6) prefixLength;
        };
      };
      ifNames = {
        eth1 = "black";
        eth2 = "red";
      };
      vlan = [1 3];
    };
  }
