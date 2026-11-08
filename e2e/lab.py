"""What the end-to-end tests are made of: a lab of network namespaces to run a
built mdnsd in, and the devices and wires around it.

The tests run in a user and network namespace of their own (see run.py), as
root there, and need no privileges. Each test makes a lab: a second network
namespace, the router's, that the daemon runs in, and veth pairs from it to
the namespace the test is in, where the devices are. What the daemon sends
out of an interface of the router is heard on the other end of the pair.
"""
import json
import os
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

GROUP = "224.0.0.251"
PORT = 5353

A, PTR, TXT, AAAA, SRV, NSEC = 1, 12, 16, 28, 33, 47


# ---------------------------------------------------------------- running things

from net import FOLLOWS_CHANGES, FREEBSD, LINUX, make as make_net, sh  # noqa: E402  (sh is the tests' too)


# Woken whenever something is heard or the daemon says something: what a wait
# is for. Nothing in the lab sleeps; `timeout` is how long a test is let to fail.
_changed = threading.Condition()


def changed():
    with _changed:
        _changed.notify_all()


def until(condition, timeout=5.0):
    """The value `condition` gives once it gives one that is not false, or None
    if it does not within `timeout`. It is looked at again each time something
    changes, not each so often."""
    end = time.monotonic() + timeout
    with _changed:
        while True:
            value = condition()
            if value:
                return value
            left = end - time.monotonic()
            if left <= 0:
                return None
            _changed.wait(left)


# ---------------------------------------------------------------- DNS, as much as is needed

def name(n):
    out = b""
    for label in n.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\0"


def rr(owner, rtype, ttl, data, flush=False):
    return name(owner) + struct.pack(">HHIH", rtype, 0x8001 if flush else 1, ttl, len(data)) + data


def a(owner, addr, ttl=120):
    return rr(owner, A, ttl, socket.inet_aton(addr), True)


def aaaa(owner, addr, ttl=120):
    return rr(owner, AAAA, ttl, socket.inet_pton(socket.AF_INET6, addr), True)


def ptr(owner, target, ttl=4500):
    return rr(owner, PTR, ttl, name(target))


def srv(owner, port, target, ttl=120):
    return rr(owner, SRV, ttl, struct.pack(">HHH", 0, 0, port) + name(target), True)


def txt(owner, *strings, ttl=4500):
    strings = [s if isinstance(s, bytes) else s.encode() for s in strings]
    data = b"".join(bytes([len(s)]) + s for s in strings) or b"\0"
    return rr(owner, TXT, ttl, data, True)


def response(*records):
    return struct.pack(">HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)


def query(*questions):
    """A query for (name, type)s."""
    body = b"".join(name(n) + struct.pack(">HH", t, 1) for n, t in questions)
    return struct.pack(">HHHHHH", 0, 0, len(questions), 0, 0, 0) + body


def announcement(host, addr, instance=None, kind="_http._tcp", port=80, ttl=120):
    """What a device that has `host` at `addr`, and one service, announces."""
    records = [a(f"{host}.local", addr, ttl)]
    if instance:
        full = f"{instance}.{kind}.local"
        records += [ptr(f"{kind}.local", full, ttl), srv(full, port, f"{host}.local", ttl), txt(full, "k=v", ttl=ttl)]
    return response(*records)


class Record:
    def __init__(self, section, owner, rtype, ttl, data):
        self.section, self.name, self.type, self.ttl, self.data = section, owner, rtype, ttl, data

    def __repr__(self):
        return f"{self.name} {self.type} ttl={self.ttl} {self.data}"


class Message:
    def __init__(self, response, questions, records):
        self.response, self.questions, self.records = response, questions, records

    def has(self, owner=None, rtype=None, data=None, goodbye=False, alive=False):
        """Whether it has a record of `owner`, `rtype` and `data` (any not given),
        a goodbye (ttl 0) if `goodbye`, not one if `alive`."""
        for r in self.records:
            if owner is not None and r.name.lower() != owner.lower():
                continue
            if rtype is not None and r.type != rtype:
                continue
            if data is not None and r.data != data:
                continue
            if goodbye and r.ttl != 0:
                continue
            if alive and r.ttl == 0:
                continue
            return True
        return False

    def asks(self, owner, rtype=None):
        return any(n.lower() == owner.lower() and (rtype is None or t == rtype) for n, t in self.questions)

    def __repr__(self):
        return f"{'response' if self.response else 'query'} q={self.questions} {self.records}"


def _read_name(d, at):
    labels, jumped, end = [], False, at
    for _ in range(128):
        n = d[at]
        if n == 0:
            at += 1
            break
        if n & 0xC0 == 0xC0:
            if not jumped:
                end = at + 2
            at, jumped = ((n & 0x3F) << 8) | d[at + 1], True
            continue
        labels.append(d[at + 1:at + 1 + n].decode("latin1"))
        at += 1 + n
    return ".".join(labels), (end if jumped else at)


def parse(d):
    """A DNS message, or None if it is not one."""
    try:
        _, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", d[:12])
        at, questions, records = 12, [], []
        for _ in range(qd):
            n, at = _read_name(d, at)
            t, _c = struct.unpack(">HH", d[at:at + 4])
            at += 4
            questions.append((n, t))
        for section, count in (("an", an), ("ns", ns), ("ar", ar)):
            for _ in range(count):
                n, at = _read_name(d, at)
                t, _c, ttl, length = struct.unpack(">HHIH", d[at:at + 10])
                at += 10
                rd = d[at:at + length]
                if t == A:
                    data = socket.inet_ntoa(rd)
                elif t == AAAA:
                    data = socket.inet_ntop(socket.AF_INET6, rd)
                elif t == PTR:
                    data = _read_name(d, at)[0]
                elif t == SRV:
                    data = f"{struct.unpack('>H', rd[4:6])[0]} {_read_name(d, at + 6)[0]}"
                else:
                    data = rd.hex()
                at += length
                records.append(Record(section, n, t, ttl, data))
        return Message(bool(flags & 0x8000), questions, records)
    except (IndexError, struct.error):
        return None


# ---------------------------------------------------------------- what is on the other end of a link

class Heard:
    """A message heard, when, from where, and whether it was to the group."""

    def __init__(self, at, src, to_group, message):
        self.at, self.src, self.to_group, self.message = at, src, to_group, message

    def __repr__(self):
        return f"{self.src} {'group' if self.to_group else 'unicast'} {self.message}"


class Hearer(threading.Thread):
    """Hears what is sent to port 5353 at `addr` of an interface, and, if
    `group`, the mDNS group on it."""

    def __init__(self, net, interface, addr, group=True, sock=None):
        super().__init__(daemon=True)
        self.heard, self.stopped = [], False
        self.reading = threading.Lock()
        self.socks = []
        if sock:
            # Of one that is read from only here: a second socket on the same
            # address and port would be sent half of what comes to it.
            sock.setblocking(False)
            self.socks.append((sock, False))
        elif group:
            s = self._sock(net, interface, (GROUP, PORT))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(GROUP) + socket.inet_aton(addr))
            self.socks.append((s, True))
        if not sock:
            self.socks.append((self._sock(net, interface, (addr, PORT)), False))
        self.start()

    @staticmethod
    def _sock(net, interface, bind):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        net.bind_to_interface(s, interface)
        # As much as the system lets it hold: a BSD's limit is lower than Linux's.
        for size in (4 << 20, 1 << 20, 256 << 10):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, size)
                break
            except OSError:
                pass
        s.bind(bind)
        s.setblocking(False)
        return s

    def run(self):
        while not self.stopped:
            ready, _, _ = select.select([s for s, _ in self.socks], [], [], 0.05)
            self._take(ready)

    def _take(self, ready):
        """Everything waiting in `ready`."""
        got = False
        with self.reading:
            for s in ready:
                while True:
                    try:
                        data, src = s.recvfrom(9000)
                    except (BlockingIOError, OSError):
                        break
                    message = parse(data)
                    if message:
                        to_group = next(g for sock, g in self.socks if sock is s)
                        self.heard.append(Heard(time.time(), src[0], to_group, message))
                        got = True
        if got:
            changed()

    def flush(self):
        """Take what has come to the sockets by now, instead of when the thread
        gets to it: what the daemon sent before is here."""
        self._take([s for s, _ in self.socks])

    def close(self):
        self.stopped = True
        self.join(1)
        for s, _ in self.socks:
            s.close()

    def wait(self, condition, timeout=5.0, since=0):
        """The first message from index `since` that `condition` says yes to, or None."""
        seen = [since]

        def look():
            while seen[0] < len(self.heard):
                h = self.heard[seen[0]]
                seen[0] += 1
                if condition(h):
                    return h
            return None
        return until(look, timeout)

    def count(self):
        """How many messages there are among what has been sent by now: for
        what is heard after to be what is sent after."""
        self.flush()
        return len(self.heard)

    def seen(self, condition, since=0):
        """The first message from index `since` that `condition` says yes to,
        among what has been sent by now, or None."""
        self.flush()
        return next((h for h in self.heard[since:] if condition(h)), None)

    def matching(self, condition, since=0):
        """Every message from index `since` that `condition` says yes to, among
        what has been sent by now."""
        self.flush()
        return [h for h in self.heard[since:] if condition(h)]

    def none(self, condition, since=0):
        """Whether nothing from index `since` that `condition` says yes to has
        been heard. It is what has been sent by now: the daemon has to have
        been made to do what is not to be heard of ([`Daemon.settle`]) first."""
        self.flush()
        return not any(condition(h) for h in self.heard[since:])


class Device:
    """A device on a link: an address of the far end of it, a socket to send
    from and to hear what is sent to it."""

    def __init__(self, link, addr):
        self.link, self.addr = link, addr
        link.add_peer_addr(addr)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(addr))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
        self.sock.bind((addr, PORT))
        # What comes to it is heard on the socket it sends from.
        self.hearer = Hearer(link.lab.net, link.peer, addr, group=False, sock=self.sock)

    def multicast(self, data):
        self.sock.sendto(data, (GROUP, PORT))

    def unicast(self, data, to):
        self.sock.sendto(data, (to, PORT))

    def close(self):
        self.hearer.close()


# ---------------------------------------------------------------- the daemon

class Daemon:
    def __init__(self, lab, config, binary, ctl, env=None):
        self.lab, self.ctl_binary = lab, ctl
        self.socket_path = os.path.join(lab.dir, "mdnsd.sock")
        self.conf = os.path.join(lab.dir, f"mdnsd-{len(lab.daemons)}.conf")
        if "[Ipc]" not in config:
            config = f"[Ipc]\nSocket={self.socket_path}\n" + config
        with open(self.conf, "w") as f:
            f.write(config)
        self.avahi_socket = re.search(r"^\s*AvahiSocket\s*=\s*\S", config, re.M | re.I) is not None
        self.lines, self.lock = [], threading.Lock()
        self.proc = subprocess.Popen(
            [*lab.net.router_argv(), binary, self.conf],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, env=dict(os.environ, **(env or {})),
        )
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        lab.daemons.append(self)

    def _read(self):
        for line in self.proc.stderr:
            with self.lock:
                self.lines.append(line.rstrip("\n"))
            changed()

    def log(self):
        with self.lock:
            return list(self.lines)

    def ready(self, timeout=10):
        """Wait until it listens on its control socket, and on the avahi socket if
        it is to: it binds that one after, and says so, and everything is set up
        once both have."""
        said = self.wait_log(r"ipc: listening on", timeout)
        if said and self.avahi_socket:
            said = self.wait_log(r"avahi: listening on", timeout)
        return said

    def wait_log(self, pattern, timeout=5.0, since=0):
        """The first line from index `since` that has `pattern`, or None."""
        seen = [since]

        def look():
            lines = self.log()
            while seen[0] < len(lines):
                line = lines[seen[0]]
                seen[0] += 1
                if re.search(pattern, line):
                    return line
            return None
        return until(look, timeout)

    def mark(self):
        return len(self.log())

    def exited(self, timeout=5.0):
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    def stop(self, sig=signal.SIGTERM, timeout=10):
        if self.proc.poll() is None:
            self.proc.send_signal(sig)
        try:
            code = self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            code = self.proc.wait()
        self.reader.join(2)
        return code

    # The control socket, spoken to directly.
    def request(self, line):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(15)
        s.connect(self.socket_path)
        s.sendall(line.encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        return json.loads(data)

    def settle(self):
        """Return once the daemon has done what it was sent before: it handles
        what has come to its sockets before it answers a request, so a request
        is a wait for it."""
        self.request("timers")

    def advance(self, seconds):
        """Move the daemon's clock forward, and return once what is due by
        then is done: the daemon runs what is due after the request that moves
        the clock, and before the next. Its clock moves only by this."""
        reply = self.request(f"advance {round(seconds * 1000)}")
        if not reply.get("ok"):
            raise unittest.SkipTest("the daemon has no clock to move: build it with --features test-clock")
        self.settle()

    def advance_until(self, condition, step=0.25, limit=30, patience=0.01):
        """Move the clock on a step at a time until `condition` gives something
        that is not false, which is what it gives, or the clock has moved `limit`
        seconds: for what the daemon does after a delay of its own. What it
        sends in a step is on its way to whoever listens: after each, `patience`
        seconds, or until something arrives, for it to be there to be looked at."""
        for _ in range(round(limit / step) + 1):
            value = condition()
            if value:
                return value
            self.advance(step)
            with _changed:
                _changed.wait(patience)
        return condition()

    def advance_until_exits(self, proc, step=1, limit=30, patience=0.2):
        """Move the clock on a step at a time until `proc`, which waits on it,
        has exited, which is true then, or the clock has moved `limit` seconds.
        The process runs in real time, not the daemon's: after each step it has
        `patience` seconds to take what the daemon told it and exit, so that a
        busy machine does not use up the clock before it has had the time."""
        for _ in range(round(limit / step) + 1):
            try:
                proc.wait(timeout=patience)
                return True
            except subprocess.TimeoutExpired:
                self.advance(step)
        return False

    def ctl_start(self, *args):
        """mdnsctl, started, for one that waits on the daemon's clock; the output
        is read with `finish`."""
        return subprocess.Popen(
            [self.ctl_binary, "-s", self.socket_path, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

    def devices(self, segment):
        return self.request(f"devices {segment}")["devices"]

    def host(self, segment, hostname):
        """The listing of `hostname` in a segment, one for each interface it is on."""
        return [d for d in self.devices(segment) if (d["hostname"] or "").lower() == hostname.lower()]

    def ctl(self, *args, timeout=20):
        """mdnsctl, as a person would run it."""
        if not self.ctl_binary:
            raise RuntimeError("no mdnsctl given")
        return subprocess.run([self.ctl_binary, "-s", self.socket_path, *args], capture_output=True, text=True, timeout=timeout)

    def avahi(self, path, line, timeout=15):
        """What the avahi socket at `path` answers a request line with."""
        return self.avahi_send(path, line).reply(timeout)

    def avahi_send(self, path, line):
        """Ask the avahi socket at `path`, and read the answer later: one that
        is waited for is not answered until the clock has moved. The daemon has
        the request by the time this and a [`Daemon.settle`] are done."""
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(path)
        s.sendall(line.encode() + b"\n")
        return AvahiCall(s)


class Watch:
    """A command that prints what happens, read as it does: `wait` returns the
    line that has what is waited for, when the command prints it."""

    def __init__(self, cmd):
        # What it prints on its error output is what it says, too: FreeBSD's route monitor does.
        # Unbuffered, and read from the pipe itself: a buffered reader that has
        # taken several lines to give one leaves the rest where a wait for the
        # pipe to have something will not find them.
        self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
        self.seen = []
        self.partial = b""

    def wait(self, pattern, timeout=5.0):
        end = time.monotonic() + timeout
        for line in self.seen:
            if re.search(pattern, line):
                return line
        while True:
            left = end - time.monotonic()
            if left <= 0 or not select.select([self.proc.stdout], [], [], left)[0]:
                return None
            chunk = os.read(self.proc.stdout.fileno(), 65536)
            if not chunk:
                return None
            *lines, self.partial = (self.partial + chunk).split(b"\n")
            found = None
            for raw in lines:
                line = raw.decode(errors="replace")
                self.seen.append(line)
                if found is None and re.search(pattern, line):
                    found = line
            if found is not None:
                return found

    def close(self):
        self.proc.kill()
        self.proc.wait()
        self.proc.stdout.close()


class AvahiCall:
    """A request to the avahi socket that has been sent."""

    def __init__(self, sock):
        self.sock = sock

    def answered(self):
        """Whether the answer has come by now."""
        return bool(select.select([self.sock], [], [], 0)[0])

    def reply(self, timeout=15):
        self.sock.settimeout(timeout)
        data = b""
        while not data.endswith(b"\n"):
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk
        self.sock.close()
        return data.decode().strip()


# ---------------------------------------------------------------- the lab

class Link:
    """A pair of interfaces: `name` in the router, `peer` where the test is. One
    may have no addresses, as a trunk has, of which there are VLANs with their
    own ([`Link.vlan`]), which are links of their own to the tests, named for the
    link and the tag: `ra.10`."""

    def __init__(self, lab, name, router_cidr, peer_cidr, parent=None, tag=None):
        self.lab, self.net, self.parent, self.vlans = lab, lab.net, parent, []
        if parent:
            self.name, self.peer = f"{parent.name}.{tag}", f"{parent.peer}.{tag}"
            self.net.create_vlan(parent.name, parent.peer, tag)
        else:
            self.name, self.peer = name, "p-" + name
            self.net.create_link(name, self.peer)
        self.router_addr = router_cidr.split("/")[0] if router_cidr else None
        self.peer_addr = peer_cidr.split("/")[0] if peer_cidr else None
        self.prefix = peer_cidr.split("/")[1] if peer_cidr and "/" in peer_cidr else "24"
        if router_cidr:
            self.net.add_addr("router", self.name, router_cidr)
        self.net.set_up("router", self.name, True)
        if peer_cidr:
            self.net.add_addr("peer", self.peer, peer_cidr)
        self.net.set_up("peer", self.peer, True)

    def vlan(self, tag, router_cidr, peer_cidr):
        """The VLAN `tag` of the link, with an address at each end."""
        vlan = Link(self.lab, None, router_cidr, peer_cidr, parent=self, tag=tag)
        self.vlans.append(vlan)
        self.lab.links.append(vlan)
        return vlan

    def add_peer_addr(self, addr):
        if addr != self.peer_addr:
            try:
                self.net.add_addr("peer", self.peer, f"{addr}/{self.prefix}")
            except RuntimeError:
                pass  # it is there already

    def add_peer_cidr(self, cidr):
        self.net.add_addr("peer", self.peer, cidr)

    def add_router_addr(self, cidr):
        self.net.add_addr("router", self.name, cidr)

    def del_router_addr(self, cidr):
        self.net.del_addr("router", self.name, cidr)

    def set_router_up(self, up):
        self.net.set_up("router", self.name, up)

    def set_router_mtu(self, mtu):
        self.net.set_mtu(self.name, mtu)

    def peer_mac(self):
        return self.net.mac("peer", self.peer)

    def neighbour(self, ip, mac):
        """The router's neighbour table has `ip` at `mac`, for good."""
        self.net.neighbour(self.name, ip, mac)

    def forget_neighbour(self, ip):
        self.net.forget_neighbour(self.name, ip)

    def delete(self):
        """The link is gone, both ends, and its VLANs."""
        for vlan in self.vlans:
            vlan.delete()
        self.vlans = []
        if self.parent:
            self.net.delete_vlan(self.name, self.peer)
        else:
            self.net.delete_link(self.name, self.peer)

    def hearer(self, group=True):
        return self.lab.track(Hearer(self.net, self.peer, self.peer_addr, group))

    def device(self, addr):
        return self.lab.track(Device(self, addr))


class Bridge:
    """A bridge of the router: it has the address, and ports that are links to the
    test, each with the address of a device's end of it, and none of their own at
    the router's. The daemon is on the bridge, as a router has it: what comes in
    on a port is the bridge's."""

    def __init__(self, lab, name, router_cidr):
        self.lab, self.net, self.name = lab, lab.net, name
        self.router_addr = router_cidr.split("/")[0]
        self.net.create_bridge(name)
        self.net.add_addr("router", name, router_cidr)
        self.net.set_up("router", name, True)

    def port(self, name, peer_cidr):
        """A link whose router end is a port of the bridge."""
        link = self.lab.link(name, None, peer_cidr)
        self.net.bridge_add(self.name, name)
        return link

    def delete(self):
        self.net.delete_bridge(self.name)


class Lab:
    def __init__(self, binary, ctl=None):
        self.binary, self.ctl = binary, ctl
        self.dir = tempfile.mkdtemp(prefix="mdnsd-e2e-")
        self.daemons, self.links, self.tracked = [], [], []
        self.net = make_net()

    def router(self, *cmd, check=True):
        """Run a command in the router."""
        return self.net.run("router", *cmd, check=check)

    def neighbours(self, interface):
        """A watch of the router's neighbour table on `interface`, which has
        what the kernel there learns or changes as it does. It is made ready by
        an entry of its own, which it has seen by the time this returns."""
        watch = self.track(Watch(self.net.neighbour_watch_argv(interface)))
        mac = "02:ff:ff:ff:ff:01"
        # The watch is a process, which does not say when it listens: the entry is
        # made again until it has been seen.
        for _ in range(40):
            self.net.neighbour(interface, "fd00:ffff::1", mac)
            if watch.wait(self.net.neighbour_seen("fd00:ffff::1", mac), 0.25):
                break
            self.net.forget_neighbour(interface, "fd00:ffff::1")
        else:
            raise RuntimeError("the neighbour table cannot be watched")
        self.net.forget_neighbour(interface, "fd00:ffff::1")
        watch.wait(self.net.neighbour_gone("fd00:ffff::1"), 5)
        return watch

    def link(self, name, router_cidr, peer_cidr):
        link = Link(self, name, router_cidr, peer_cidr)
        self.links.append(link)
        return link

    def bridge(self, name, router_cidr):
        """A bridge with the address `router_cidr`, for ports to be made on."""
        bridge = Bridge(self, name, router_cidr)
        self.links.append(bridge)
        return bridge

    def trunk(self, name):
        """A link with no address of its own, for VLANs."""
        return self.link(name, None, None)

    def track(self, thing):
        self.tracked.append(thing)
        return thing

    def daemon(self, config, wait=True, env=None):
        d = Daemon(self, config, self.binary, self.ctl, env)
        if wait and not d.ready():
            raise RuntimeError("the daemon did not come up:\n" + "\n".join(d.log()))
        return d

    def close(self):
        for d in self.daemons:
            d.stop()
        for t in self.tracked:
            t.close()
        for link in reversed(self.links):
            link.delete()
        self.net.close()
        shutil.rmtree(self.dir, ignore_errors=True)
