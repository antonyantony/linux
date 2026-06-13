# Shared addressing for the strongSwan testing topology
# (https://github.com/strongswan/strongswan/tree/master/testing):
#
#   sunMoonNet = 192.168.0.0/24 / fec0::/16 (LAN backbone: moon, sun, carol, dave, winnetou)
#   aliceNet   = 10.1.0.0/16    / fec1::/16 (alice, venus -- behind moon)
#   bobNet     = 10.2.0.0/16    / fec2::/16 (bob -- behind sun)
{
  hosts = {
    alice = {
      ipv4 = "10.1.0.10";
      ipv6 = "fec1::10";
    };
    venus = {
      ipv4 = "10.1.0.20";
      ipv6 = "fec1::20";
    };
    bob = {
      ipv4 = "10.2.0.10";
      ipv6 = "fec2::10";
    };
    carol = {
      ipv4 = "192.168.0.100";
      ipv6 = "fec0::10";
    };
    dave = {
      ipv4 = "192.168.0.200";
      ipv6 = "fec0::20";
    };
    winnetou = {
      ipv4 = "192.168.0.150";
      ipv6 = "fec0::15";
    };
    moon = {
      ipv4 = "192.168.0.1";
      ipv6 = "fec0::1";
    };
    sun = {
      ipv4 = "192.168.0.2";
      ipv6 = "fec0::2";
    };

    # moon's/sun's aliceNet/bobNet-facing ("tunnel side") addresses, matching
    # strongSwan's PH_IP_MOON1/PH_IP_SUN1 placeholders.
    moon1 = {
      ipv4 = "10.1.0.1";
      ipv6 = "fec1::1";
    };
    sun1 = {
      ipv4 = "10.2.0.1";
      ipv6 = "fec2::1";
    };
  };

  nets = {
    sunMoonNet = {
      ipv4 = {
        address = "192.168.0.0";
        prefixLength = 24;
      };
      ipv6 = {
        address = "fec0::";
        prefixLength = 16;
      };
    };
    aliceNet = {
      ipv4 = {
        address = "10.1.0.0";
        prefixLength = 16;
      };
      ipv6 = {
        address = "fec1::";
        prefixLength = 16;
      };
    };
    bobNet = {
      ipv4 = {
        address = "10.2.0.0";
        prefixLength = 16;
      };
      ipv6 = {
        address = "fec2::";
        prefixLength = 16;
      };
    };
  };

  # Render a {address; prefixLength;} net as a "<address>/<prefixLength>" CIDR string.
  cidr = net: "${net.address}/${toString net.prefixLength}";
}
