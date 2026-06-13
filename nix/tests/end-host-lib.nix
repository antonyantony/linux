{lib}: let
  mkRoute = r: {
    Destination = "${r.address}/${toString r.prefixLength}";
    Gateway = r.via;
  };

  topology = import ./topology.nix;

  # Static /etc/hosts table for the strongSwan testing topology, mirroring
  # strongSwan's hosts/default/etc/hosts (the same file is given to every
  # host).
  extraHosts = lib.concatStrings (lib.mapAttrsToList
    (name: addr: "${addr.ipv4} ${name}\n${addr.ipv6} ${name}\n")
    topology.hosts);

  mkInterfaceNetwork = ifname: ifcfg: let
    inherit (ifcfg) ipv4;
    inherit (ifcfg) ipv6;
  in {
    matchConfig.Name = ifname;
    networkConfig.DHCP = "no";
    address =
      lib.optional (ipv4.address != null) "${ipv4.address}/${toString ipv4.prefixLength}"
      ++ lib.optional (ipv6.address != null) "${ipv6.address}/${toString ipv6.prefixLength}";
    gateway =
      lib.optional (ipv4.gateway != null) ipv4.gateway
      ++ lib.optional (ipv6.gateway != null) ipv6.gateway;
    routes = map mkRoute (ipv4.routes ++ ipv6.routes);
  };

  mkEndHost = {
    # Attrset keyed by the default interface name (eth1/eth2/eth3) as
    # assigned by the test framework's vlans. Each value is an interface
    # config plus a `name`, the interface name to actually use (defaults to
    # the key; callers may rename via ifNames, e.g. to "red0"/"black0").
    interfaces,
    vlan,
    # Only gateways that route between networks (e.g. moon/sun) need
    # forwarding; plain end hosts (alice/bob/...) don't.
    ipForward ? false,
  }: let
    allIpv6Disabled = lib.all (ifcfg: ifcfg.ipv6.address == null) (lib.attrValues interfaces);
    renames = lib.filterAttrs (origName: ifcfg: ifcfg.name != origName) interfaces;
  in {
    boot.kernel.sysctl =
      {
        "net.ipv6.conf.default.disable_ipv6" = lib.mkIf allIpv6Disabled 1;
      }
      // lib.optionalAttrs ipForward {
        "net.ipv6.conf.all.forwarding" = "1";
        "net.ipv6.conf.default.forwarding" = "1";
        "net.ipv4.ip_forward" = "1";
      };

    networking = {
      useDHCP = false;
      useNetworkd = true;

      # Static /etc/hosts for the whole topology (mirrors strongSwan's
      # hosts/default/etc/hosts, given verbatim to every host) so hostnames
      # resolve to their real addresses, not the test framework's auto-assigned
      # 192.168.<vlan>.<node> addresses.
      extraHosts = lib.mkForce extraHosts;
    };

    # Don't block boot on every interface getting an address (relevant for
    # multi-NIC hosts and the test driver's own interface).
    systemd.network.wait-online.anyInterface = true;

    # Nothing wants network-online.target by default, so pull it into the
    # boot transaction (it in turn wants systemd-networkd-wait-online.service).
    systemd.targets.network-online.wantedBy = ["multi-user.target"];

    systemd.network.links = lib.mapAttrs' (origName: ifcfg:
      lib.nameValuePair "05-${ifcfg.name}" {
        matchConfig.OriginalName = origName;
        linkConfig.Name = ifcfg.name;
      })
    renames;

    systemd.network.networks =
      lib.mapAttrs' (_origName: ifcfg: lib.nameValuePair "10-${ifcfg.name}" (mkInterfaceNetwork ifcfg.name ifcfg)) interfaces;

    virtualisation.vlans = vlan;
  };
in {
  inherit mkInterfaceNetwork mkEndHost;
}
