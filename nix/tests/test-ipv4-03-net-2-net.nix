# This strongswan-swanctl test is based on:
# https://www.strongswan.org/testing/testresults/swanctl/rw-psk-ipv4/index.html
# https://github.com/strongswan/strongswan/tree/master/testing/tests/swanctl/rw-psk-ipv4
#
# The hosts allice and bob are connected via a net-2-net, sun-moon,  gateways. The authentication
# is based on pre-shared keys and IPv4 addresses. Upon the successful
# establishment of the IPsec tunnels, the specified updown script automatically
# inserts iptables-based firewall rules that let pass the tunneled traffic. In
# order to test both tunnel and firewall, alice pings bob.
#
# Addressing follows the strongSwan testing topology
# (https://github.com/strongswan/strongswan/tree/master/testing):
#
#   alice                      moon                        sun                      bob
#    eth1-------vlan_2-------eth1  eth2-------vlan_1------eth1  eth2-------vlan_3------eth1
#   10.1.0.10/16     10.1.0.1/16  192.168.0.1/24    192.168.0.2/24  10.2.0.1/16    10.2.0.10/16
#
# See the NixOS manual for how to run this test:
# https://nixos.org/nixos/manual/index.html#sec-running-nixos-tests-interactively
{lib, ...}: let
  topology = import ./topology.nix;
  alice = (import ./alice-host.nix) {inherit lib;};
  bob = (import ./bob-host.nix) {inherit lib;};

  allowESP = "iptables --insert INPUT --protocol ESP --jump ACCEPT";
  # Shared VPN settings:
  aliceNet = topology.cidr topology.nets.aliceNet.ipv4;
  bobNet = topology.cidr topology.nets.bobNet.ipv4;
  sunIp = topology.hosts.sun.ipv4;
  moonIp = topology.hosts.moon.ipv4;

  version = 2;
  secret = "0sFpZAZqEN6Ti9sqt4ZP5EWcqx";
  esp_proposals = ["aes128gcm128-x25519"];
  proposals = ["aes128gcm128-prfsha256-x25519"];
in {
  name = "IPsec test net-2-net";
  defaults = {
    networking.firewall.enable = true;
    imports = [
      ../packages/kernel/basevpn-kernel.nix
      ../packages/strongswan/basevpn-strongswan.nix
    ];
  };
  nodes = {
    inherit alice;

    moon = {config, ...}: let
      strongswan = config.services.strongswan-swanctl.package;
      moonHost = (import ./moon-host.nix) {inherit lib;};
    in
      lib.recursiveUpdate moonHost {
        networking.firewall = {
          allowedUDPPorts = [4500 500];
          extraCommands = allowESP;
        };
        environment.systemPackages = [strongswan];
        services.strongswan-swanctl = {
          enable = true;
          swanctl = {
            connections = {
              sun_moon = {
                local_addrs = [moonIp];
                remote_addrs = [sunIp];
                local.main = {
                  auth = "psk";
                };
                remote.main = {
                  auth = "psk";
                };
                children = {
                  net = {
                    local_ts = [aliceNet];
                    remote_ts = [bobNet];
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
              ike.moon = {
                id.main = moonIp;
                inherit secret;
              };
            };
          };
        };
      };

    sun = {config, ...}: let
      strongswan = config.services.strongswan-swanctl.package;
      sunHost = (import ./sun-host.nix) {inherit lib;};
    in
      lib.recursiveUpdate sunHost {
        networking.firewall = {
          allowedUDPPorts = [4500 500];
          extraCommands = allowESP;
        };
        environment.systemPackages = [strongswan];
        services.strongswan-swanctl = {
          enable = true;
          swanctl = {
            connections = {
              sun_moon = {
                local_addrs = [sunIp];
                remote_addrs = [moonIp];
                local.main = {
                  auth = "psk";
                };
                remote.main = {
                  auth = "psk";
                };
                children = {
                  net = {
                    local_ts = [bobNet];
                    remote_ts = [aliceNet];
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
              ike.moon = {
                id.main = moonIp;
                inherit secret;
              };
            };
          };
        };
      };

    inherit bob;
  };
  testScript = ''
    start_all()

    for machine in [alice, moon, sun, bob]:
      machine.wait_for_unit("network-online.target")

    def wait_for_connection(machine, conn):
      return machine.wait_until_succeeds(f"swanctl --list-conns 2>&1 | grep ^[[:space:]]*{conn}: >/dev/null")

    wait_for_connection(sun, "sun_moon")
    wait_for_connection(moon, "sun_moon")

    alice.wait_until_succeeds("ping -c 1 bob", timeout=5)
  '';
}
