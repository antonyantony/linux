{lib, ...}: let
  topology = import ./topology.nix;

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
  name = "Single Host swanctl";
  defaults = {
    networking.firewall.enable = true;
    imports = [
      ../packages/kernel/basevpn-kernel.nix
      ../packages/strongswan/basevpn-strongswan.nix
    ];
  };
  nodes = {
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
  };
  testScript = ''
    start_all()

    for machine in [moon]:
      machine.wait_for_unit("network-online.target")

    def wait_for_connection(machine, conn):
      return machine.wait_until_succeeds(f"swanctl --list-conns 2>&1 | grep ^[[:space:]]*{conn}: >/dev/null")

    wait_for_connection(moon, "sun_moon")
  '';
}
