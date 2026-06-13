{
  lib,
  config ? {},
}: let
  endHostLib = import ./end-host-lib.nix {inherit lib;};

  # Generic triple-NIC end host. No addresses are defaulted here -- callers
  # must provide eth1, eth2, eth3 and vlan.
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
    eth3 = defaultIface;
    # Interface names as seen by the OS. Defaults match the test
    # framework's vlan-assigned names; override to use a naming
    # convention such as red/black (cleartext/ESP-side).
    ifNames = {
      eth1 = "eth1";
      eth2 = "eth2";
      eth3 = "eth3";
    };
    vlan = [];
    # Tri-homed hosts act as gateways/routers between their three networks.
    ipForward = true;
  };

  finalConfig = lib.recursiveUpdate defaultConfig config;
in
  endHostLib.mkEndHost {
    interfaces = {
      eth1 = finalConfig.eth1 // {name = finalConfig.ifNames.eth1;};
      eth2 = finalConfig.eth2 // {name = finalConfig.ifNames.eth2;};
      eth3 = finalConfig.eth3 // {name = finalConfig.ifNames.eth3;};
    };
    inherit (finalConfig) vlan;
    inherit (finalConfig) ipForward;
  }
