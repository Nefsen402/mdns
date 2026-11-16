#!/bin/sh
# The Arch package, into $OUT_DIR (here by default). Needs makepkg.
set -e
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
# MDNSD_NOCHECK=1 skips the test suite, which makepkg runs.
PKGDEST="${OUT_DIR:-$here}" makepkg -f ${MDNSD_NOCHECK:+--nocheck}
