{
  lib,
  config ? {},
}: let
  endHostLib = import ./end-host-lib.nix {inherit lib;};

  # Generic single-NIC end host. No addresses are defaulted here -- callers
  # (e.g. alice-host.nix) must provide eth1 and vlan via topology.nix.
  defaultConfig = {
    eth1 = {
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
    # Interface names as seen by the OS. Defaults match the test
    # framework's vlan-assigned names; override to use a naming
    # convention such as red/black (cleartext/ESP-side).
    ifNames = {
      eth1 = "red";
    };
    vlan = [];
  };

  finalConfig = lib.recursiveUpdate defaultConfig config;
in
  endHostLib.mkEndHost {
    interfaces = {
      eth1 = finalConfig.eth1 // {name = finalConfig.ifNames.eth1;};
    };
    inherit (finalConfig) vlan;
  }
