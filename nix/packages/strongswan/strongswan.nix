{
  pkgs,
  lib,
  strongSwanUrl,
  strongSwanRef,
  strongSwanRev ? null,
  ...
}:
pkgs.strongswan.overrideAttrs (old: rec {
  src = builtins.fetchGit ({
      url = strongSwanUrl;
      ref = strongSwanRef;
    }
    // lib.optionalAttrs (strongSwanRev != null) {
      rev = strongSwanRev;
    });
  version = builtins.readFile (
    pkgs.runCommand "strongswan-version" {}
    ''
      cd ${src} && \
      sed -n 's/^AC_INIT.*\[\([0-9]*\.[0-9]*\.[0-9]*\(\(beta\|dr\|rc\)[0-9]*\)*\)\].*$/\1/p' configure.ac > $out
    ''
  );
  enableParallelBuilding = true;
  buildInputs =
    old.buildInputs
    ++ [
      pkgs.openldap
      pkgs.sqlite
      pkgs.libgcrypt
      pkgs.libgpg-error
      pkgs.botan3
    ];
  configureFlags = [
    "--disable-defaults"
    "--enable-ikev2"
    "--enable-systemd"
    "--sysconfdir=/etc"
    "--with-systemdsystemunitdir=${placeholder "out"}/etc/systemd/system"
    "--enable-swanctl"
    "--enable-socket-default"
    "--enable-kernel-netlink"
    "--enable-nonce"
    "--enable-random"
    "--enable-sha1"
    "--enable-sha2"
    "--enable-sha3"
    "--enable-openssl"
    "--enable-curve25519"
    "--enable-silent-rules"
    "--with-random-device=/dev/urandom"
    "--disable-load-warning"
    "--enable-curl"
    "--enable-ldap"
    "--enable-eap-aka"
    "--enable-eap-aka-3gpp2"
    "--enable-eap-sim"
    "--enable-eap-sim-file"
    "--enable-eap-simaka-sql"
    "--enable-eap-md5"
    "--enable-md4"
    "--enable-eap-mschapv2"
    "--enable-eap-identity"
    "--enable-eap-radius"
    "--enable-eap-dynamic"
    "--enable-eap-tls"
    "--enable-eap-ttls"
    "--enable-eap-peap"
    "--enable-sql"
    "--enable-sqlite"
    "--enable-attr-sql"
    "--enable-mediation"
    "--enable-botan"
    "--enable-blowfish"
    "--enable-kernel-pfkey"
    "--enable-leak-detective"
    "--enable-gcrypt"
    "--enable-socket-dynamic"
    "--enable-dhcp"
    "--enable-farp"
    "--enable-connmark"
    "--enable-forecast"
    "--enable-addrblock"
    "--enable-ctr"
    "--enable-ccm"
    "--enable-gcm"
    "--enable-hmac"
    "--enable-chapoly"
    "--enable-ha"
    "--enable-af-alg"
    "--enable-whitelist"
    "--enable-xauth-generic"
    "--enable-xauth-eap"
    "--enable-pkcs12"
    "--enable-unity"
    "--enable-unbound"
    "--enable-ipseckey"
    "--enable-dnscert"
    "--enable-acert"
    "--enable-cmd"
    "--enable-libipsec"
    "--enable-kernel-libipsec"
    "--enable-stroke"
    "--enable-lookip"
    "--enable-des"
    "--enable-aes"
    "--enable-md5"
    "--enable-gmp"
    "--enable-counters"
    "--enable-save-keys"
    "--enable-ml"
  ];
})
