#!/bin/sh
# Builds the package from the working tree, into packaging/debian/out/.
# Run it from anywhere on a Debian or Ubuntu machine that has build-essential,
# debhelper, cargo and rustc (>= 1.88): ./packaging/debian/build.sh
set -e

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# dpkg-buildpackage insists on ./debian at the source root.
if [ -e "$root/debian" ]; then
    echo "$root/debian already exists" >&2
    exit 1
fi
ln -s packaging/debian "$root/debian"
trap 'rm -f "$root/debian"' EXIT

cd "$root"
cargo fetch --locked
dpkg-buildpackage -us -uc -b --no-check-builddeps "$@"

# dpkg-buildpackage puts its output next to the source tree.
mkdir -p "$here/out"
mv "$root"/../mdnsd_*.deb "$root"/../mdnsd_*.buildinfo "$root"/../mdnsd_*.changes "$here/out/"
