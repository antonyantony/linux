# This strongswan-swanctl test is based on:
# https://www.strongswan.org/testing/testresults/ipv6/net2net-ikev2/index.html
#
# The alice use gateway moon to reach bob. The authentication
# is based on pre-shared keys and IPv6 addresses. Upon the successful
# establishment of the IPsec tunnels, the specified updown script automatically
# inserts iptables-based firewall rules that let pass the tunneled traffic. In
# order to test both tunnel and firewall, alice pings the bob, alice behind
# the gateway moon and bob behind sun.
#
# alice                       moon                        sun                  bob
#   eth1------vlan_1------eth1   eth2------vlan_2------eth1  eth2---vlan_1---eth1
# fec1::10              fec1::1  fec0::1            fec0::2  fec2::1       fec2::10
#
{lib, ...}: let
  baseNetwork = {
    # shared hosts file
    extraHosts = lib.mkVMOverride ''
      fec1::10 alice
      fec0::1 moon
      fec0::2 sun
      fec2::10 bob
    '';
    # remove all automatic addresses
    useDHCP = false;
    interfaces.eth0.ipv4.addresses = lib.mkVMOverride [];
    interfaces.eth1.ipv4.addresses = lib.mkVMOverride [];
    firewall = {
      allowedUDPPorts = [4500 500];
      extraCommands = allowESP;
    };
  };

  # shared VPN settings:
  aliceNet = "fec1::/64";
  moonIp = "fec0::1";
  sunIp = "fec0::2";
  bobNet = "fec2::/64";
  version = 2;
  secret = "0sFpZAZqEN6Ti9sqt4ZP5EWcqx";
  esp_proposals = ["aes128gcm128-x25519"];
  proposals = ["aes128-sha256-x25519"];
  allowESP = "iptables --insert INPUT --protocol ESP --jump ACCEPT";

  addRouteEdge = a: b: c: {
    interfaces.eth1.ipv6.addresses = [
      {
        address = a;
        prefixLength = 64;
      }
    ];
    interfaces.eth1.ipv6.routes = [
      {
        address = b;
        prefixLength = 64;
        via = c;
      }
    ];
  };

  addRouteIPsec = a: b: c: d: {
    interfaces = {
      eth1.ipv6.addresses = [
        {
          address = a;
          prefixLength = 64;
        }
      ];
      eth2.ipv6 = {
        addresses = [
          {
            address = b;
            prefixLength = 64;
          }
        ];
        routes = [
          {
            address = c;
            prefixLength = 64;
            via = d;
          }
        ];
      };
    };
  };
in {
  name = "IPsec strongSwan IPv6 test 01";
  defaults = {
    imports = [
      ../packages/kernel/basevpn-kernel.nix
      ../packages/strongswan/basevpn-strongswan.nix
    ];
  };

  nodes = {
    alice = _: {
      virtualisation.vlans = [1];
      networking = baseNetwork // addRouteEdge "fec1::10" "fec2::" "fec1::1";
    };

    moon = {config, ...}: let
      strongswan = config.services.strongswan-swanctl.package;
    in {
      virtualisation.vlans = [1 2];
      networking = baseNetwork // addRouteIPsec "fec1::1" "fec0::1" "fec2::" "fec0::2";
      boot.kernel.sysctl = {
        "net.ipv6.conf.all.forwarding" = 1;
      };
      environment.systemPackages = [strongswan];
      services.strongswan-swanctl = {
        enable = true;
        swanctl = {
          connections = {
            moon = {
              local_addrs = [moonIp];
              remote_addrs = [sunIp];
              local.main = {
                auth = "psk";
                id = moonIp;
              };
              remote.main = {
                auth = "psk";
                id = sunIp;
              };
              children = {
                net = {
                  local_ts = [aliceNet];
                  remote_ts = [bobNet];
                  start_action = "start";
                  inherit esp_proposals;
                };
              };
              inherit version;
              inherit proposals;
            };
          };
          secrets = {
            ike.sun = {
              id.main = sunIp;
              inherit secret;
            };
          };
        };
      };
    };

    sun = {config, ...}: let
      strongswan = config.services.strongswan-swanctl.package;
    in {
      virtualisation.vlans = [1 2];
      networking = baseNetwork // addRouteIPsec "fec2::1" "fec0::2" "fec1::" "fec0::1";
      # Enable packet routing
      boot.kernel.sysctl = {
        "net.ipv6.conf.all.forwarding" = 1;
      };
      environment.systemPackages = [strongswan];
      services.strongswan-swanctl = {
        enable = true;
        swanctl = {
          connections = {
            sun = {
              local_addrs = [sunIp];
              remote_addrs = [moonIp];
              local.main = {
                auth = "psk";
                id = sunIp;
              };
              remote.main = {
                auth = "psk";
                id = moonIp;
              };
              children = {
                net = {
                  local_ts = [bobNet];
                  remote_ts = [aliceNet];
                  inherit esp_proposals;
                  start_action = "trap";
                };
              };
              inherit version;
              inherit proposals;
            };
          };
          secrets = {
            ike.moon = {
              id.main = moonIp;
              inherit secret;
            };
          };
        };
      };
    };

    bob = _: {
      virtualisation.vlans = [1];
      networking = baseNetwork // addRouteEdge "fec2::10" "fec1::" "fec2::1";
    };
  };

  testScript = ''
    start_all()

    def wait_for_connection(machine, conn):
     return machine.wait_until_succeeds(f"swanctl --list-conns 2>&1 | grep ^[[:space:]]*{conn}: >/dev/null")

    wait_for_connection(moon, "moon")
    wait_for_connection(sun, "sun")

    alice.wait_until_succeeds("ping -W 6 -w 4  -6 -c 1 bob")
  '';
}
