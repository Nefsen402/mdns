# Sourced by packaging/*/build.sh and release.sh. Not run on its own.
#
# What a packaging/NAME/build.sh is: it is run with OUT_DIR set (and VERSION,
# the crate's), builds from the working tree, and leaves what it made in
# OUT_DIR. release.sh runs every one there is. Run on its own, a script
# falls back to a directory of its own.

packaging=$(cd "$(dirname "${BASH_SOURCE:-$0}")" && pwd)
root=$(dirname "$packaging")

VERSION=${VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' "$root/Cargo.toml" | head -n 1)}

# A release build of the daemon and mdnsctl for a target that no distribution
# builds for us, on the toolchain there is. Prints the directory the binaries are in.
release_build() {
    target=$1
    var=CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')_LINKER
    export CARGO_TARGET_DIR="$root/target/release-packages"
    # musl's own C library comes with the target; the linker is all it lacks.
    case $target in
        *-linux-musl*) export "$var=rust-lld" ;;
    esac
    (cd "$root" && cargo build --locked --release --target "$target" >&2)
    echo "$CARGO_TARGET_DIR/$target/release"
}

# Archives that are the same each time they are made, from the same files.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct 2>/dev/null || date +%s)}
reproducible_tar() { # tar's arguments, after the options that make it so
    tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner "$@"
}
