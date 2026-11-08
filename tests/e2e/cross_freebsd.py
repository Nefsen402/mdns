#!/usr/bin/env python3
"""Build the daemon, `mdnsctl` and the unit tests' executables for FreeBSD, from
another system, to be run on a FreeBSD that has no Rust, or not the time to
install it and build.

    cross_freebsd.py VERSION --out DIR [--sysroot DIR]

VERSION is a release, such as `14.5`: what is built is linked against the C
library of that release, so that it is what that release runs. It writes to DIR:

    mdnsd, mdnsctl    the daemon, with the clock the end-to-end tests move
    tests/            the unit tests' executables, to be run, each

What it needs of this system is `rustup target add x86_64-unknown-freebsd` (the
target's standard library, which has to be of the compiler that builds: an
official one, not a distribution's), `clang` and `lld` (the linker, and the
driver that finds what a FreeBSD program is linked with), `tar` and `xz`.

The C library is the release's own: its `base.txz`, whose checksum is in the
release's MANIFEST, of which only `/lib` and `/usr/lib` are taken, into the
sysroot (`target/freebsd-sysroot-VERSION` unless it is given), where it is kept
for the next time.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TARGET = "x86_64-unknown-freebsd"
BASE = "https://download.freebsd.org/releases/amd64/{version}-RELEASE"


def run(cmd, env=None, **kw):
    print("+ " + " ".join(cmd), flush=True)
    r = subprocess.run(cmd, cwd=ROOT, env=env, **kw)
    if r.returncode:
        sys.exit(f"failed ({r.returncode}): {' '.join(cmd)}")
    return r


def download(url, to):
    print(f"+ download {url}", flush=True)
    with urllib.request.urlopen(url, timeout=60) as r, open(to, "wb") as f:
        shutil.copyfileobj(r, f)


def sysroot(version, where):
    """The C library and what is linked with it, of the release `version`, in
    `where`: downloaded and checked, unless it is there."""
    done = os.path.join(where, ".complete")
    if os.path.exists(done):
        return
    shutil.rmtree(where, ignore_errors=True)
    os.makedirs(where)
    url = BASE.format(version=version)
    archive = os.path.join(where, "base.txz")
    download(f"{url}/base.txz", archive)
    with urllib.request.urlopen(f"{url}/MANIFEST", timeout=60) as r:
        lines = r.read().decode().splitlines()
    want = next(line.split("\t")[1] for line in lines if line.startswith("base.txz\t"))
    digest = hashlib.sha256()
    with open(archive, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    if digest.hexdigest() != want:
        sys.exit(f"base.txz of {version} is {digest.hexdigest()}, and its MANIFEST says {want}")
    # Not the rest of the system: what a program is linked with is all it is for.
    run(["tar", "-xJf", archive, "-C", where, "./lib", "./usr/lib"], stderr=subprocess.DEVNULL)
    os.remove(archive)
    open(done, "w").close()


def build(version, out, where):
    major = version.split(".")[0]
    sysroot(version, where)
    # The driver for the linker: it names the system, and where its libraries are.
    linker = os.path.abspath(where) + ".linker.sh"
    with open(linker, "w") as f:
        f.write(f'#!/bin/sh\nexec clang --target=x86_64-unknown-freebsd{major} --sysroot={os.path.abspath(where)} -fuse-ld=lld "$@"\n')
    os.chmod(linker, 0o755)
    target_dir = os.path.join(ROOT, "target", f"freebsd-{version}")
    env = dict(os.environ, CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_LINKER=linker, CARGO_TARGET_DIR=target_dir)
    if subprocess.run(["rustup", "target", "list", "--installed"], capture_output=True, text=True).stdout.split().count(TARGET) == 0:
        print(f"note: is `rustup target add {TARGET}` done?", file=sys.stderr)

    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(os.path.join(out, "tests"))
    # The daemon has a clock the end-to-end tests move, so that they do not wait
    # for a timer; the unit tests are of the code without it.
    run(["cargo", "build", "--locked", "--target", TARGET, "--features", "test-clock"], env)
    for name in ("mdnsd", "mdnsctl"):
        shutil.copy(os.path.join(target_dir, TARGET, "debug", name), os.path.join(out, name))
    built = subprocess.run(
        ["cargo", "test", "--locked", "--no-run", "--target", TARGET, "--message-format=json"],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, text=True, check=True,
    )
    tests = []
    for line in built.stdout.splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"]:
            tests.append(m["executable"])
    for t in tests:
        shutil.copy(t, os.path.join(out, "tests", os.path.basename(t)))
    print(f"built for FreeBSD {version}: the daemon, mdnsctl and {len(tests)} test executables, in {out}")


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("version", help="the release to link for, such as 14.5")
    p.add_argument("--out", required=True)
    p.add_argument("--sysroot", help="where the release's C library is, or is to be put")
    args = p.parse_args()
    build(args.version, os.path.abspath(args.out), args.sysroot or os.path.join(ROOT, "target", f"freebsd-sysroot-{args.version}"))


if __name__ == "__main__":
    main()
