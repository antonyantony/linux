{
  config,
  pkgs,
  lib,
  ...
}: let
  cfg = config.basevpn.strongswan;

  strongswan = pkgs.callPackage ./strongswan.nix {
    stdenv = pkgs.ccacheStdenv;
    strongSwanUrl = cfg.url;
    strongSwanRef = cfg.ref;
    strongSwanRev = cfg.rev;
  };

  # Plugins built by strongswan.nix's configureFlags (--disable-defaults plus
  # explicit --enable-*). Listed explicitly because charon's load_modular
  # mode does not load plugins on its own: the shipped strongswan.d/charon/*.conf
  # snippets are empty files, so "include strongswan.d/charon/*.conf" adds no
  # charon.plugins entries and nothing gets loaded, leaving features like
  # NONCE_GEN and HASHER:HASH_SHA1 unmet.
  charonPlugins = [
    "acert"
    "addrblock"
    "aes"
    "af-alg"
    "attr-sql"
    "blowfish"
    "botan"
    "ccm"
    "chapoly"
    "connmark"
    "counters"
    "ctr"
    "curl"
    "curve25519"
    "des"
    "dhcp"
    "dnscert"
    "eap-aka"
    "eap-aka-3gpp2"
    "eap-dynamic"
    "eap-identity"
    "eap-md5"
    "eap-mschapv2"
    "eap-peap"
    "eap-radius"
    "eap-sim"
    "eap-sim-file"
    "eap-simaka-sql"
    "eap-tls"
    "eap-ttls"
    "farp"
    "fips-prf"
    "forecast"
    "gcm"
    "gcrypt"
    "gmp"
    "ha"
    "hmac"
    "ipseckey"
    "kernel-libipsec"
    "kernel-netlink"
    "kernel-pfkey"
    "ldap"
    "lookip"
    "md4"
    "md5"
    "mgf1"
    "ml"
    "nonce"
    "openssl"
    "pkcs12"
    "random"
    "rc2"
    "save-keys"
    "sha1"
    "sha2"
    "sha3"
    "socket-default"
    "socket-dynamic"
    "sql"
    "sqlite"
    "stroke"
    "unbound"
    "unity"
    "vici"
    "whitelist"
    "xauth-eap"
    "xauth-generic"
  ];
in {
  options.basevpn.strongswan = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
    };
    url = lib.mkOption {
      type = lib.types.str;
      default = "https://github.com/strongswan/strongswan.git";
    };
    ref = lib.mkOption {
      type = lib.types.str;
      default = "master";
    };
    rev = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
    };
  };

  config = lib.mkIf cfg.enable {
    services.strongswan-swanctl.package = strongswan;
    # NixOS replaces /etc/strongswan.conf with strongswan.extraConfig (default
    # empty), so without this charon loads zero plugins and reports
    # NONCE_GEN / HASHER:HASH_SHA1 as unmet critical dependencies.
    services.strongswan-swanctl.strongswan.extraConfig = ''
      charon {
        load_modular = yes
        plugins {
          ${lib.concatMapStrings (name: "${name} { load = yes }\n          ") charonPlugins}
        }
      }
    '';
  };
}
