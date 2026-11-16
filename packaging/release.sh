#!/bin/bash
# Builds every package there is: runs packaging/NAME/build.sh for each NAME,
# and leaves what they make in one directory.
#
#     packaging/release.sh [OUT_DIR]        (dist/ by default)
#
# Set ONLY="openwrt arch" to build some of them. See common.sh for what a
# build.sh is. The ones that cross-compile need rustup's targets (see
# openwrt/build.sh and opnsense/build.sh).
set -euo pipefail
. "$(dirname "${BASH_SOURCE[0]}")/common.sh"

export VERSION
export OUT_DIR=$(mkdir -p "${1:-$root/dist}" && cd "${1:-$root/dist}" && pwd)

failed=()
for dir in "$packaging"/*/; do
    name=$(basename "$dir")
    [ -x "$dir/build.sh" ] || continue
    if [ -n "${ONLY:-}" ] && ! [[ " $ONLY " == *" $name "* ]]; then continue; fi
    echo "==> $name"
    "$dir/build.sh" || { echo "!! $name failed" >&2; failed+=("$name"); }
done

(cd "$OUT_DIR" && ls -l)
if [ ${#failed[@]} -gt 0 ]; then
    echo "failed: ${failed[*]}" >&2
    exit 1
fi
