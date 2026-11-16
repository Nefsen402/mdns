#!/usr/bin/env python3
"""Make a FreeBSD package (.pkg) of the daemon, from a directory laid out as the
files are to be installed, without FreeBSD's pkg: a tar archive of +COMPACT_MANIFEST,
+MANIFEST, then the files, compressed with zstd, as `pkg create` makes one.

    mkpkg.py STAGE OUT.pkg --version V --abi FreeBSD:14:amd64

STAGE has the files under the root they are installed in (usr/local/bin/mdnsd, ...).
"""
import argparse
import hashlib
import io
import json
import os
import subprocess
import tarfile

DESC = """mdnsd follows mDNS and DNS-SD on the network, and reflects the services of
one segment to the others. It is for a router. mdnsctl is its client.

Configure /usr/local/etc/mdnsd.conf (a sample is installed), then:
    sysrc mdnsd_enable=YES && service mdnsd start"""

POST_INSTALL = """\
if ! pw groupshow mdnsd >/dev/null 2>&1; then pw groupadd mdnsd; fi
if ! pw usershow mdnsd >/dev/null 2>&1; then
    pw useradd mdnsd -g mdnsd -d /nonexistent -s /usr/sbin/nologin -c "mDNS discovery daemon"
fi
"""
POST_DEINSTALL = """\
if pw usershow mdnsd >/dev/null 2>&1; then pw userdel mdnsd; fi
"""


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("stage")
    p.add_argument("out")
    p.add_argument("--version", required=True)
    p.add_argument("--abi", required=True)
    p.add_argument("--epoch", type=int, default=0, help="the time the files are given")
    a = p.parse_args()

    files, dirs, flat = {}, set(), 0
    for base, names, fs in os.walk(a.stage):
        names.sort()
        for f in sorted(fs):
            path = os.path.join(base, f)
            rel = "/" + os.path.relpath(path, a.stage)
            with open(path, "rb") as fh:
                data = fh.read()
            files[rel] = hashlib.sha256(data).hexdigest()
            flat += len(data)
            d = os.path.dirname(rel)
            while d not in ("/", "/usr", "/usr/local", ""):
                dirs.add(d)
                d = os.path.dirname(d)

    manifest = {
        "name": "mdnsd",
        "origin": "net/mdnsd",
        "version": a.version,
        "comment": "mDNS discovery and per-segment reflection daemon",
        "maintainer": "alex@mapleprecision.com",
        "www": "https://github.com/Nefsen402/mdns",
        "abi": a.abi,
        "arch": a.abi,
        "prefix": "/usr/local",
        "licenselogic": "single",
        "licenses": ["GPLv3"],
        "flatsize": flat,
        "desc": DESC,
        "categories": ["net"],
    }
    full = dict(manifest, files=files, directories={d: "y" for d in sorted(dirs)},
                scripts={"post-install": POST_INSTALL, "post-deinstall": POST_DEINSTALL})

    def add(tar, name, data, mode=0o644):
        i = tarfile.TarInfo(name)
        i.size, i.mode, i.mtime = len(data), mode, a.epoch
        i.uid = i.gid = 0
        i.uname = i.gname = "root"
        tar.addfile(i, io.BytesIO(data))

    raw = a.out + ".tar"
    with tarfile.open(raw, "w", format=tarfile.PAX_FORMAT) as tar:
        add(tar, "+COMPACT_MANIFEST", json.dumps(manifest).encode())
        add(tar, "+MANIFEST", json.dumps(full).encode())
        for rel in files:
            with open(os.path.join(a.stage, rel[1:]), "rb") as fh:
                add(tar, rel, fh.read(), os.stat(os.path.join(a.stage, rel[1:])).st_mode & 0o7777)
    subprocess.run(["zstd", "-q", "-19", "-f", "-o", a.out, raw], check=True)
    os.remove(raw)


if __name__ == "__main__":
    main()
