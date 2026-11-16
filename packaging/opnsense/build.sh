#!/bin/bash
# The OPNsense package, a FreeBSD .pkg (it installs on FreeBSD and pfSense too,
# where the ABI is the same), into $OUT_DIR (opnsense/out by default). Built
# here, on Linux, for the FreeBSD release's own C library, which is fetched as
# the end-to-end tests' FreeBSD build does (tests/e2e/cross_freebsd.py):
#
#     rustup target add x86_64-unknown-freebsd
#
# and clang, lld, zstd. FREEBSD is the release to link for (14.5 by default:
# OPNsense is built on 14); the package's ABI is its major.
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/../common.sh"
here=$packaging/opnsense
out=$(mkdir -p "${OUT_DIR:-$here/out}" && cd "${OUT_DIR:-$here/out}" && pwd)
FREEBSD=${FREEBSD:-14.5}
major=${FREEBSD%%.*}
target=x86_64-unknown-freebsd

sysroot=$root/target/freebsd-sysroot-$FREEBSD
python3 -I - "$root/tests/e2e/cross_freebsd.py" "$FREEBSD" "$sysroot" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("cross_freebsd", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.sysroot(sys.argv[2], sys.argv[3])
PY
linker=$sysroot.linker.sh
printf '#!/bin/sh\nexec clang --target=x86_64-unknown-freebsd%s --sysroot=%s -fuse-ld=lld "$@"\n' "$major" "$sysroot" >"$linker"
chmod +x "$linker"
export CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_LINKER=$linker

bin=$(release_build "$target")
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
install -Dm755 "$bin/mdnsd" "$bin/mdnsctl" -t "$stage/usr/local/bin"
install -Dm755 "$here/files/mdnsd.rc" "$stage/usr/local/etc/rc.d/mdnsd"
install -Dm644 "$here/files/mdnsd.conf.sample" "$stage/usr/local/etc/mdnsd.conf.sample"
install -Dm644 "$root/man/mdnsctl.1" "$stage/usr/local/share/man/man1/mdnsctl.1"
install -Dm644 "$root/man/mdnsd.conf.5" "$stage/usr/local/share/man/man5/mdnsd.conf.5"
install -Dm644 "$root/man/mdnsd.8" "$stage/usr/local/share/man/man8/mdnsd.8"

python3 -I "$here/mkpkg.py" "$stage" "$out/mdnsd-$VERSION-FreeBSD$major-amd64.pkg" \
    --version "$VERSION" --abi "FreeBSD:$major:amd64" --epoch "$SOURCE_DATE_EPOCH"
echo "built $out/mdnsd-$VERSION-FreeBSD$major-amd64.pkg"
