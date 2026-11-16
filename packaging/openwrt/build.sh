#!/bin/bash
# The OpenWrt packages (.ipk), one for each architecture, into $OUT_DIR
# (openwrt/out by default). Nothing of OpenWrt's is needed: the binaries are
# static (musl), so the musl targets of rustup's toolchain (an official one, not
# a distribution's) build them, and an .ipk is three archives:
#
#     rustup target add x86_64-unknown-linux-musl \
#         aarch64-unknown-linux-musl armv7-unknown-linux-musleabihf
#
# What OpenWrt calls an architecture is more than what Rust does: opkg only
# installs a package of one it is set up for (`opkg print-architecture`). The
# names below are the commonest of each; ARCHES says others, as
# "rust-target=openwrt-arch ...", for a router whose is not here.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../common.sh"
here=$packaging/openwrt
out=$(mkdir -p "${OUT_DIR:-$here/out}" && cd "${OUT_DIR:-$here/out}" && pwd)

ARCHES=${ARCHES:-"x86_64-unknown-linux-musl=x86_64 aarch64-unknown-linux-musl=aarch64_generic armv7-unknown-linux-musleabihf=arm_cortex-a7_neon-vfpv4"}

ipk() { # rust target, openwrt architecture
    local target=$1 arch=$2 bin tmp
    bin=$(release_build "$target")
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN

    mkdir -p "$tmp/data/usr/bin" "$tmp/data/etc/init.d" "$tmp/data/usr/share/man/man"{1,5,8} "$tmp/control"
    install -m755 "$bin/mdnsd" "$bin/mdnsctl" "$tmp/data/usr/bin/"
    install -m755 "$here/files/mdnsd.init" "$tmp/data/etc/init.d/mdnsd"
    install -m644 "$root/man/mdnsctl.1" "$tmp/data/usr/share/man/man1/"
    install -m644 "$root/man/mdnsd.conf.5" "$tmp/data/usr/share/man/man5/"
    install -m644 "$root/man/mdnsd.8" "$tmp/data/usr/share/man/man8/"

    install -m755 "$here/files/postinst" "$here/files/prerm" "$tmp/control/"
    cat >"$tmp/control/control" <<CONTROL
Package: mdnsd
Version: $VERSION-1
Depends: libc
Section: net
Architecture: $arch
Maintainer: Alex <alex@mapleprecision.com>
License: GPL-3.0-only
Installed-Size: $(du -sb "$tmp/data" | cut -f1)
Description: mDNS discovery and per-segment reflection daemon, with the mdnsctl client
CONTROL

    echo 2.0 >"$tmp/debian-binary"
    reproducible_tar --format=gnu -C "$tmp/control" -czf "$tmp/control.tar.gz" .
    reproducible_tar --format=gnu -C "$tmp/data" -czf "$tmp/data.tar.gz" .
    # An .ipk is a gzipped tar of these three, in this order.
    reproducible_tar --format=gnu -C "$tmp" -czf "$out/mdnsd_${VERSION}-1_$arch.ipk" \
        --no-recursion ./debian-binary ./data.tar.gz ./control.tar.gz
    echo "built $out/mdnsd_${VERSION}-1_$arch.ipk"
}

for pair in $ARCHES; do
    ipk "${pair%%=*}" "${pair#*=}"
done
