{pkgs, ...}: {
  environment.systemPackages = [pkgs.incus];

  networking.firewall.enable = false;
  networking.hostName = "bvpn";

  system.stateVersion = "23.11";
}
