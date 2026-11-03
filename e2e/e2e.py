#!/usr/bin/env python3
"""Run a built mdnsd through scenarios that the unit tests cannot: interfaces
that come and go, addresses that change, real sockets, signals, the control
socket and the avahi socket, all from outside, over the network, in network
namespaces.

    e2e.py [-v] [-k PATTERN] [--ctl MDNSCTL] [--logs DIR] MDNSD

It needs `ip`, `unshare` and `nsenter` (iproute2 and util-linux). It makes its
own user and network namespaces, as the fuzzer and the benchmark do, so it
needs no privileges; run as root, it makes a network namespace only. Where the
system forbids unprivileged user namespaces (the AppArmor setting of recent
Ubuntu), run it as root, or allow them:

    sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    p = argparse.ArgumentParser(description="End-to-end tests of a built mdnsd")
    p.add_argument("daemon", help="the mdnsd binary")
    p.add_argument("--ctl", help="the mdnsctl binary, for the tests that run it")
    p.add_argument("-k", dest="pattern", action="append", default=[], help="only tests whose name has this (may be repeated)")
    p.add_argument("-v", "--verbose", action="store_true", help="name each test as it runs")
    p.add_argument("--logs", help="write the daemon's log of each test to this directory")
    p.add_argument("--list", action="store_true", help="list the tests and stop")
    args = p.parse_args()

    if os.environ.get("E2E_INSIDE") != "1":
        daemon = os.path.abspath(args.daemon)
        if not os.access(daemon, os.X_OK):
            sys.exit(f"{args.daemon} is not an executable")
        env = dict(os.environ, E2E_INSIDE="1", E2E_DAEMON=daemon)
        if args.ctl:
            env["E2E_CTL"] = os.path.abspath(args.ctl)
        if args.logs:
            os.makedirs(args.logs, exist_ok=True)
            env["E2E_LOGS"] = os.path.abspath(args.logs)
        # Root makes only the network namespace; anyone else a user namespace
        # to be root in.
        unshare = ["unshare", "-n"] if os.geteuid() == 0 else ["unshare", "-r", "-n"]
        if subprocess.run(unshare + ["true"], stderr=subprocess.DEVNULL).returncode:
            sys.exit(
                "cannot make a network namespace: run as root, or allow user namespaces "
                "(sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0)"
            )
        os.execvpe("unshare", unshare + ["--", sys.executable, os.path.abspath(__file__), *sys.argv[1:]], env)

    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    sys.path.insert(0, HERE)
    import unittest

    import tests

    loader = unittest.TestLoader()
    if args.pattern:
        loader.testNamePatterns = [f"*{k}*" for k in args.pattern]
    suite = loader.loadTestsFromModule(tests)
    if args.list:
        def walk(s):
            for t in s:
                if isinstance(t, unittest.TestSuite):
                    yield from walk(t)
                else:
                    yield t
        for t in walk(suite):
            print(t.id().split(".", 1)[1])
        return
    result = unittest.TextTestRunner(verbosity=2 if args.verbose else 1, **({"durations": 5} if sys.version_info >= (3, 12) else {})).run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
