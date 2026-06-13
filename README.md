# NixOS Testing

## Use ccache for kernel builds

To use `ccache` the directory `/nix/var/cache/ccache` has to be created:

    sudo mkdir -m0770 /nix/var/cache/ccache
    sudo chown root:nixbld /nix/var/cache/ccache

and added to the file `/etc/nix/nix.conf`:

    extra-sandbox-paths = /nix/var/cache/ccache

If the directory does not exist or has the wrong permission, the use of
`ccache` will be disabled automatically.
