{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.basevpn.kernel;

  basevpn-kernel = pkgs.callPackage ./kernel.nix {
    stdenv = pkgs.ccacheStdenv;
    kernelUrl = cfg.url;
    kernelRef = cfg.ref;
    kernelRev = cfg.rev;
  };
in {
  options.basevpn.kernel = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };
    url = lib.mkOption {
      type = lib.types.str;
      default = "https://git.kernel.org/pub/scm/linux/kernel/git/klassert/ipsec.git";
    };
    ref = lib.mkOption {
      type = lib.types.str;
      default = "testing";
    };
    rev = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
    };
  };

  config = lib.mkIf cfg.enable {
    boot.kernelPackages = pkgs.linuxPackagesFor basevpn-kernel;
    boot.initrd.includeDefaultModules = false;
  };
}
