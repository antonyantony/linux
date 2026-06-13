_: super: {
  ccacheWrapper = super.ccacheWrapper.override {
    extraConfig = ''
      export CCACHE_COMPRESS=1
      export CCACHE_SLOPPINESS=random_seed
      export CCACHE_DIR="/nix/var/cache/ccache"
      export CCACHE_UMASK=007
      if [ ! -d "$CCACHE_DIR" -o ! -w "$CCACHE_DIR" ]; then
        export CCACHE_DISABLE=1
      fi
    '';
  };
}
