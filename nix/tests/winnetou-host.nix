# winnetou: sunMoonNet (192.168.0.0/24 / fec0::/16), no gateway, vlan 1.
{lib, ...}: let
  topology = import ./topology.nix;
in
  import ./single-end-host.nix {
    inherit lib;
    config = {
      eth1 = {
        ipv4 = {
          address = topology.hosts.winnetou.ipv4;
          inherit (topology.nets.sunMoonNet.ipv4) prefixLength;
        };
        ipv6 = {
          address = topology.hosts.winnetou.ipv6;
          inherit (topology.nets.sunMoonNet.ipv6) prefixLength;
        };
      };
      vlan = [1];
    };
  }
