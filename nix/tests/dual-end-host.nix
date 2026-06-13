{
  lib,
  config ? {},
}: let
  endHostLib = import ./end-host-lib.nix {inherit lib;};

  # Generic dual-NIC end host. No addresses are defaulted here -- callers
  # (e.g. moon-host.nix/sun-host.nix) must provide eth1, eth2 and vlan via
  # topology.nix.
  defaultIface = {
    ipv4 = {
      address = null;
      prefixLength = null;
      gateway = null;
      routes = [];
    };
    ipv6 = {
      address = null;
      prefixLength = null;
      gateway = null;
      routes = [];
    };
  };

  defaultConfig = {
    eth1 = defaultIface;
    eth2 = defaultIface;
    # Interface names as seen by the OS. Defaults match the test
    # framework's vlan-assigned names; override to use a naming
    # convention such as red/black (cleartext/ESP-side).
    ifNames = {
      eth1 = "red";
      eth2 = "black";
    };
    vlan = [];
    # Dual-homed hosts act as gateways between their two networks.
    ipForward = true;
  };

  finalConfig = lib.recursiveUpdate defaultConfig config;
in
  endHostLib.mkEndHost {
    interfaces = {
      eth1 = finalConfig.eth1 // {name = finalConfig.ifNames.eth1;};
      eth2 = finalConfig.eth2 // {name = finalConfig.ifNames.eth2;};
    };
    inherit (finalConfig) vlan;
    inherit (finalConfig) ipForward;
  }
