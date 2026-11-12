#!/usr/bin/env python3
"""Measure an mdnsd binary from outside: memory per device, CPU to take
devices in, and how long one more device takes to be reflected, with n already
there.

    bench.py [--own-address] [--unicast] [--offlink] [--listen MODE] DAEMON N [N ...]

For each N, a fresh daemon is given N devices, announced at 500 packets a
second on one interface of a segment of two, and the other is listened to.
It prints a line of JSON for each N:

    n                    devices announced
    ready_s              how long the daemon took to reflect anything at all
    reflected            how many of them were heard on the other interface
    anon_kb_idle/anon_kb the daemon's anonymous memory before and after, in KiB
    per_device_b         the difference per device, in bytes
    cpu_ms, cpu_us_per_device
                         the CPU the daemon used, over all its threads, to take
                         them in, less what it uses idle
    latency_median_us, latency_p90_us
                         how long one more device took to be heard on the other
                         interface, with N there already

With --unicast each device is announced to the daemon's own address and not to
the group (it needs --own-address), and --listen MODE is what `[Interface] IPv4=`
says (off, multicast or on): a daemon hears the unicast only if it says on. With --offlink the unicast is from
addresses that are not on the interface's network, as a host routed in through it
would send from.

By default the devices share twenty source addresses, as a few proxies would
speak for them. With --own-address each is sent from an address of its own, as
a device is: what a version that takes the device to be whoever sent the packet
(the first commits) needs to see more than twenty.

It needs no privileges: it runs itself in a user and network namespace, as the
fuzzer does, and the daemon in a second network namespace of its own, with the
two interfaces. N stays under 1000: an interface remembers 1024 devices.

Because it only talks to the daemon over the network, it works on any version:
build each from its own checkout (`git worktree add DIR COMMIT`, `cargo build
--release` there) and give each binary.
"""
import glob
import json
import os
import resource
import select
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time

ME = os.path.abspath(__file__)
STAGE = os.environ.get("BENCH_STAGE", "")
GROUP = "224.0.0.251"
PORT = 5353
SENDERS = 20
RATE = 500  # packets a second while filling
OWN_ADDRESS = os.environ.get("BENCH_OWN_ADDRESS") == "1"
UNICAST = os.environ.get("BENCH_UNICAST") == "1"
LISTEN = os.environ.get("BENCH_LISTEN", "multicast")
OFFLINK = os.environ.get("BENCH_OFFLINK") == "1"


def offlink_addr(i):
    """An address that is not on the interface's network."""
    return f"192.168.77.{1 + i % 250}"
# The interface's network: a /16 if each device has an address of its own.
PREFIX = 16 if OWN_ADDRESS else 24


def device_addr(i):
    """The address a device is sent from, and announces, if it has its own."""
    if i < 4000:
        # Not 10.0.1.x, nor 10.0.2.x, which are the two interfaces' own networks.
        return f"10.0.{10 + i // 250}.{1 + i % 250}"
    if i < 100000:
        return f"10.0.100.{1 + (i - 9000) % 250}"
    return f"10.0.101.{1 + (i - 100000) % 250}"


def say(*args):
    """Progress, on stderr, when BENCH_VERBOSE is set."""
    if os.environ.get("BENCH_VERBOSE"):
        print(f"[{time.strftime('%H:%M:%S')}]", *args, file=sys.stderr, flush=True)


def sh(*args, check=True):
    return subprocess.run(args, check=check, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def no_dad(iface):
    try:
        with open(f"/proc/sys/net/ipv6/conf/{iface}/accept_dad", "w") as f:
            f.write("0")
    except OSError:
        pass


# ---------------------------------------------------------------- the daemon's end

def router(conf, daemon):
    for _ in range(400):
        if os.path.exists("/sys/class/net/mdns-a") and os.path.exists("/sys/class/net/mdns-b"):
            break
        time.sleep(0.025)
    for iface in ("default", "all"):
        no_dad(iface)
    # A packet from an address that is not on the network is not to be dropped by the kernel.
    for iface in ("default", "all"):
        try:
            with open(f"/proc/sys/net/ipv4/conf/{iface}/rp_filter", "w") as f:
                f.write("0")
        except OSError:
            pass
    sh("ip", "link", "set", "lo", "up")
    for iface, addr in (("mdns-a", f"10.0.1.1/{PREFIX}" if not OWN_ADDRESS else "10.0.0.1/16"), ("mdns-b", "10.0.2.1/24")):
        no_dad(iface)
        sh("ip", "addr", "add", addr, "dev", iface)
        sh("ip", "link", "set", iface, "up")
        try:
            with open(f"/proc/sys/net/ipv4/conf/{iface}/rp_filter", "w") as f:
                f.write("0")
        except OSError:
            pass
    os.execv(daemon, [daemon, conf])


# ---------------------------------------------------------------- DNS, as much as is needed

def name(n):
    out = b""
    for label in n.split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def rr(owner, rtype, ttl, data, flush=False):
    return name(owner) + struct.pack(">HHIH", rtype, 0x8001 if flush else 1, ttl, len(data)) + data


def announcement(i, addr):
    host, inst = f"h{i}.local", f"Dev{i}._http._tcp.local"
    records = [
        rr("_http._tcp.local", 12, 4500, name(inst)),
        rr(inst, 33, 120, struct.pack(">HHH", 0, 0, 80) + name(host), True),
        rr(inst, 16, 4500, b"\x04ty=x", True),
        rr(host, 1, 120, socket.inet_aton(addr), True),
    ]
    return struct.pack(">HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


def read_name(data, at):
    labels, jumped, end = [], False, at
    for _ in range(64):
        n = data[at]
        if n == 0:
            at += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = at + 2
            at, jumped = ((n & 0x3F) << 8) | data[at + 1], True
            continue
        labels.append(data[at + 1:at + 1 + n].decode("latin1"))
        at += 1 + n
    return ".".join(labels).lower(), (end if jumped else at)


def owners(data):
    """The owner names of the records of a DNS message."""
    try:
        _, _, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        at, out = 12, set()
        for _ in range(qd):
            _, at = read_name(data, at)
            at += 4
        for _ in range(an + ns + ar):
            n, at = read_name(data, at)
            out.add(n)
            rdlen = struct.unpack(">H", data[at + 8:at + 10])[0]
            at += 10 + rdlen
        return out
    except (IndexError, struct.error):
        return set()


# ---------------------------------------------------------------- measuring

def status(pid, key):
    with open(f"/proc/{pid}/status") as f:
        for line in f:
            if line.startswith(key + ":"):
                return int(line.split()[1])
    return 0


def cpu_ns(pid):
    total = 0
    for path in glob.glob(f"/proc/{pid}/task/*/schedstat"):
        try:
            with open(path) as f:
                total += int(f.read().split()[0])
        except (OSError, ValueError):
            pass
    return total


class Listener(threading.Thread):
    """Hears the group on fuzz-b: when each name was first heard."""

    def __init__(self):
        super().__init__(daemon=True)
        self.seen, self.packets, self.stop = {}, 0, False
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"fuzz-b")
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
        s.bind((GROUP, PORT))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(GROUP) + socket.inet_aton("10.0.2.2"))
        s.settimeout(0.05)
        self.sock = s

    def run(self):
        while not self.stop:
            try:
                data = self.sock.recv(9000)
            except socket.timeout:
                continue
            now = time.perf_counter()
            self.packets += 1
            for n in owners(data):
                self.seen.setdefault(n, now)


class Senders:
    """The sockets devices send from, made as they are wanted."""

    def __init__(self):
        self.socks = {}

    def sock(self, i):
        key = i if OWN_ADDRESS else i % SENDERS
        if key not in self.socks:
            src = (offlink_addr(i) if OFFLINK else device_addr(i)) if OWN_ADDRESS else f"10.0.1.{100 + key}"
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(src))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
            s.bind((src, PORT))
            self.socks[key] = s
        return self.socks[key]

    def announce(self, i):
        addr = device_addr(i) if OWN_ADDRESS else f"10.0.1.{130 + i % 100}"
        to = ("10.0.0.1", PORT) if UNICAST else (GROUP, PORT)
        self.sock(i).sendto(announcement(i, addr), to)


def wait_for(listener, names, timeout):
    end = time.time() + timeout
    while time.time() < end:
        if all(n in listener.seen for n in names):
            return True
        time.sleep(0.01)
    return False


def run_once(daemon, n, probes, rundir):
    resource.setrlimit(resource.RLIMIT_NOFILE, (resource.getrlimit(resource.RLIMIT_NOFILE)[1],) * 2)
    conf = os.path.join(rundir, "mdnsd.conf")
    with open(conf, "w") as f:
        f.write(f"[Interface]\nIPv4={LISTEN}\nIPv6=off\n[Ipc]\nSocket={rundir}/mdnsd.sock\n[Segment]\nName=bench\nInterfaces=mdns-a,mdns-b\n")
    for iface in ("mdns-a", "mdns-b", "fuzz-a", "fuzz-b"):
        sh("ip", "link", "del", iface, check=False)
    sh("ip", "link", "add", "mdns-a", "type", "veth", "peer", "name", "fuzz-a")
    sh("ip", "link", "add", "mdns-b", "type", "veth", "peer", "name", "fuzz-b")
    env = dict(os.environ, BENCH_STAGE="router", BENCH_OWN_ADDRESS="1" if OWN_ADDRESS else "0")
    say(f"n={n}: starting the daemon")
    proc = subprocess.Popen(["unshare", "-n", "--", sys.executable, ME, conf, daemon], env=env)
    ours = os.readlink("/proc/self/ns/net")
    for _ in range(400):
        if os.readlink(f"/proc/{proc.pid}/ns/net") != ours:
            break
        time.sleep(0.025)
    for iface in ("mdns-a", "mdns-b"):
        sh("ip", "link", "set", iface, "netns", str(proc.pid))
    for iface, addr in (("fuzz-a", "10.0.0.2/16" if OWN_ADDRESS else "10.0.1.2/24"), ("fuzz-b", "10.0.2.2/24")):
        no_dad(iface)
        sh("ip", "addr", "add", addr, "dev", iface)
        sh("ip", "link", "set", iface, "up")
    if OWN_ADDRESS and OFFLINK:
        batch = "".join(f"addr add 192.168.77.{k}/24 dev fuzz-a\n" for k in range(1, 251))
    elif OWN_ADDRESS:
        wanted = list(range(n)) + list(range(9000, 9120)) + list(range(100000, 100000 + probes))
        batch = "".join(f"addr add {device_addr(i)}/16 dev fuzz-a\n" for i in wanted)
    else:
        batch = "".join(f"addr add 10.0.1.{100 + k}/24 dev fuzz-a\n" for k in range(SENDERS))
    subprocess.run(["ip", "-batch", "-"], input=batch.encode(), check=True)

    say("links up")
    listener = Listener()
    listener.start()
    try:
        return measure(proc, listener, Senders(), n, probes)
    finally:
        listener.stop = True
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()


def measure(proc, listener, socks, n, probes):
    # Ready when a device is reflected.
    ready, started = False, time.perf_counter()
    for k in range(120):
        socks.announce(9000 + k)
        if wait_for(listener, [f"h{9000 + k}.local"], 0.5):
            ready = True
            break
    ready_s = time.perf_counter() - started
    if not ready:
        return {"n": n, "error": "the daemon reflected nothing in 60s"}
    say(f"ready after {ready_s:.1f}s")
    time.sleep(1.0)
    listener.seen.clear()

    pid = proc.pid
    # What an idle daemon uses.
    idle0, t0 = cpu_ns(pid), time.perf_counter()
    time.sleep(2.0)
    idle_rate = (cpu_ns(pid) - idle0) / (time.perf_counter() - t0)
    base = status(pid, "RssAnon")

    say("filling")
    # Fill to n.
    cpu0, t0 = cpu_ns(pid), time.perf_counter()
    for i in range(n):
        socks.announce(i)
        if i % 10 == 9:
            time.sleep(10 / RATE)
    missing = [f"h{i}.local" for i in range(n)]
    ok = wait_for(listener, missing, 30)
    time.sleep(0.5)
    fill_s = time.perf_counter() - t0 - 0.5
    cpu = cpu_ns(pid) - cpu0 - idle_rate * (time.perf_counter() - t0)
    reflected = sum(1 for m in missing if m in listener.seen)
    time.sleep(1.0)
    rss = status(pid, "RssAnon")

    say(f"filled: {reflected} of {n} reflected; probing")
    # One more, a few times, apart.
    lat = []
    for k in range(probes):
        host = f"h{100000 + k}"
        i = 100000 + k
        t = time.perf_counter()
        socks.announce(i)
        if wait_for(listener, [f"{host}.local"], 5):
            lat.append((listener.seen[f"{host}.local"] - t) * 1e6)
        time.sleep(0.15)

    say("stopping")
    return {
        "n": n,
        "ready_s": round(ready_s, 1),
        "reflected": reflected,
        "anon_kb_idle": base,
        "anon_kb": rss,
        "per_device_b": (rss - base) * 1024 / n if n else None,
        "cpu_ms": cpu / 1e6,
        "cpu_us_per_device": cpu / 1e3 / n if n else None,
        "fill_s": fill_s,
        "latency_median_us": statistics.median(lat) if lat else None,
        "latency_p90_us": sorted(lat)[int(len(lat) * 0.9) - 1] if len(lat) >= 5 else None,
        "latency_samples": len(lat),
    }


def main():
    args = [a for a in sys.argv[1:] if a not in ("--own-address", "--unicast", "--offlink")]
    if "--listen" in args:
        at = args.index("--listen")
        del args[at:at + 2]
    daemon, ns = args[0], [int(a) for a in args[1:]]
    rundir = tempfile.mkdtemp(prefix="mdnsd-bench-", dir=os.environ.get("TMPDIR", "/tmp"))
    results = []
    for n in ns:
        results.append(run_once(daemon, n, 20, rundir))
        print(json.dumps(results[-1]), flush=True)


if STAGE == "router":
    router(sys.argv[1], sys.argv[2])
elif STAGE == "":
    os.environ["BENCH_STAGE"] = "fuzzer"
    os.environ["BENCH_OWN_ADDRESS"] = "1" if "--own-address" in sys.argv else "0"
    os.environ["BENCH_UNICAST"] = "1" if ("--unicast" in sys.argv or "--offlink" in sys.argv) else "0"
    os.environ["BENCH_OFFLINK"] = "1" if "--offlink" in sys.argv else "0"
    if "--listen" in sys.argv:
        os.environ["BENCH_LISTEN"] = sys.argv[sys.argv.index("--listen") + 1]
    os.execvp("unshare", ["unshare", "-r", "-n", "--", sys.executable, ME, *sys.argv[1:]])
else:
    main()
