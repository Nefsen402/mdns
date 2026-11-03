"""The network the lab is made on: a router, with links to the test.

The daemon runs in the router, which has one end of each link; the test has the
other end, where the devices are. How that is made is the system's:

- Linux makes the router a network namespace of its own, and the links veth
  pairs, with `ip`. Nothing needs more than a user namespace.
- FreeBSD makes it a VNET jail and the links `epair` interfaces, with
  `ifconfig` and `jexec`, as root: it changes the host's network stack, so it is
  for a machine that may be changed, such as a virtual machine.

Both have the same methods, with `side` either `"router"` or `"peer"`: the
router's end of a link, or the test's.
"""
import ipaddress
import itertools
import os
import platform
import re
import subprocess

LINUX = platform.system() == "Linux"
FREEBSD = platform.system() == "FreeBSD"

# Whether there is a daemon that follows interfaces, addresses and neighbours as
# they change under it, which netlink, of Linux and of FreeBSD, tells it.
FOLLOWS_CHANGES = LINUX or FREEBSD


def sh(*args, check=True):
    r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and r.returncode:
        raise RuntimeError(f"{' '.join(args)}: {r.stderr.strip()}")
    return r


def split_cidr(cidr):
    ip, _, prefix = cidr.partition("/")
    return ip, prefix or ("64" if ":" in ip else "24")


class Linux:
    """A network namespace held by a process, and veth pairs."""

    def __init__(self):
        # The router's namespace is held by a process that says when it is in it.
        self.holder = subprocess.Popen(
            ["unshare", "-n", "--", "sh", "-c", "echo ready; exec sleep infinity"], stdout=subprocess.PIPE, text=True
        )
        if self.holder.stdout.readline().strip() != "ready":
            raise RuntimeError("no namespace for the router")
        self.run("router", "ip", "link", "set", "lo", "up")
        # Addresses are there at once, for what is sent from them.
        off = "echo 0 > /proc/sys/net/ipv6/conf/all/accept_dad; echo 0 > /proc/sys/net/ipv6/conf/default/accept_dad"
        self.run("router", "sh", "-c", off)
        self.run("peer", "sh", "-c", off)

    def router_argv(self):
        return ["nsenter", "-t", str(self.holder.pid), "-n", "--"]

    def run(self, side, *cmd, check=True):
        return sh(*(self.router_argv() if side == "router" else []), *cmd, check=check)

    def create_link(self, name, peer):
        """The pair, down, for addresses to be given before they are up: what an
        interface has when it comes up is what the daemon finds it with."""
        sh("ip", "link", "add", name, "type", "veth", "peer", "name", peer)
        sh("ip", "link", "set", name, "netns", str(self.holder.pid))

    def delete_link(self, name, peer):
        sh("ip", "link", "del", peer, check=False)

    def create_vlan(self, parent, peer_parent, tag):
        """A VLAN of `tag` on each end of a link, named for its end and the tag."""
        for side, link in (("router", parent), ("peer", peer_parent)):
            self.run(side, "ip", "link", "add", "link", link, "name", f"{link}.{tag}", "type", "vlan", "id", str(tag))

    def delete_vlan(self, name, peer):
        sh("ip", "link", "del", peer, check=False)
        self.run("router", "ip", "link", "del", name, check=False)

    def add_addr(self, side, iface, cidr):
        self.run(side, "ip", "addr", "add", cidr, "dev", iface, *(["nodad"] if ":" in cidr else []))

    def del_addr(self, side, iface, cidr):
        self.run(side, "ip", "addr", "del", cidr, "dev", iface)

    def set_up(self, side, iface, up):
        self.run(side, "ip", "link", "set", iface, "up" if up else "down")

    def set_mtu(self, iface, mtu):
        self.run("router", "ip", "link", "set", iface, "mtu", str(mtu))

    def mac(self, side, iface):
        return re.search(r"link/ether ([0-9a-f:]{17})", self.run(side, "ip", "-o", "link", "show", iface).stdout).group(1)

    def neighbour(self, iface, ip, mac):
        """A permanent entry of the router's neighbour table."""
        self.run("router", "ip", "-6" if ":" in ip else "-4", "neigh", "replace", ip, "lladdr", mac, "dev", iface, "nud", "permanent")

    def forget_neighbour(self, iface, ip):
        self.run("router", "ip", "-6" if ":" in ip else "-4", "neigh", "del", ip, "dev", iface)

    def neighbour_watch_argv(self, iface):
        return [*self.router_argv(), "ip", "-6", "monitor", "neigh", "dev", iface]

    @staticmethod
    def neighbour_seen(ip, mac):
        """What the watch prints when `ip` is at `mac` in the table."""
        return rf"{re.escape(ip)}\S* .*lladdr {mac}"

    @staticmethod
    def neighbour_gone(ip):
        """What it prints when the entry is taken away: it fails, here, and is only reported deleted later."""
        return rf"{re.escape(ip)} FAILED"

    def relax_source_checks(self):
        """A packet from an address that is not on the link is not for the kernel to drop."""
        self.run("router", "sh", "-c", "for f in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $f; done")

    def bind_to_interface(self, sock, iface):
        import socket

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode())

    def close(self):
        self.holder.kill()
        self.holder.wait()


_jails = itertools.count()


class FreeBSD:
    """A VNET jail, and epair interfaces."""

    def __init__(self):
        if os.geteuid() != 0:
            raise RuntimeError("a VNET jail for the router needs root")
        self.jail = f"mdnsd-e2e-{os.getpid()}-{next(_jails)}"
        sh("jail", "-c", f"name={self.jail}", "vnet", "persist")
        self.run("router", "ifconfig", "lo0", "up")
        # Addresses are there at once, for what is sent from them.
        self.run("router", "sysctl", "net.inet6.ip6.dad_count=0")
        self.run("peer", "sysctl", "net.inet6.ip6.dad_count=0")

    def router_argv(self):
        return ["jexec", self.jail]

    def run(self, side, *cmd, check=True):
        return sh(*(self.router_argv() if side == "router" else []), *cmd, check=check)

    def create_link(self, name, peer):
        end = sh("ifconfig", "epair", "create").stdout.strip()  # epair0a: the other is epair0b
        sh("ifconfig", end, "vnet", self.jail)
        self.run("router", "ifconfig", end, "name", name)
        sh("ifconfig", end[:-1] + "b", "name", peer)

    def delete_link(self, name, peer):
        # Either end takes the other with it.
        sh("ifconfig", peer, "destroy", check=False)

    def create_vlan(self, parent, peer_parent, tag):
        """A VLAN of `tag` on each end of a link, named for its end and the tag:
        an interface called `parent.tag` is one of that tag on `parent`."""
        for side, link in (("router", parent), ("peer", peer_parent)):
            self.run(side, "ifconfig", f"{link}.{tag}", "create")

    def delete_vlan(self, name, peer):
        sh("ifconfig", peer, "destroy", check=False)
        self.run("router", "ifconfig", name, "destroy", check=False)

    def add_addr(self, side, iface, cidr):
        ip, prefix = split_cidr(cidr)
        self.run(side, "ifconfig", iface, "inet6" if ":" in ip else "inet", ip, "prefixlen" if ":" in ip else "netmask", prefix if ":" in ip else self.mask(prefix), "alias")

    @staticmethod
    def mask(prefix):
        bits = (0xFFFFFFFF << (32 - int(prefix))) & 0xFFFFFFFF
        return ".".join(str(bits >> s & 255) for s in (24, 16, 8, 0))

    def del_addr(self, side, iface, cidr):
        ip, _ = split_cidr(cidr)
        self.run(side, "ifconfig", iface, "inet6" if ":" in ip else "inet", ip, "-alias")

    def set_up(self, side, iface, up):
        self.run(side, "ifconfig", iface, "up" if up else "down")

    def set_mtu(self, iface, mtu):
        self.run("router", "ifconfig", iface, "mtu", str(mtu))

    def mac(self, side, iface):
        return re.search(r"ether ([0-9a-f:]{17})", self.run(side, "ifconfig", iface).stdout).group(1)

    def neighbour(self, iface, ip, mac):
        """A permanent entry of the router's neighbour table. There has to be a
        route to the address for the table to take it, which an address that is
        not in a network the interface is on does not have: the interface is
        given one for the network of it. (The table of the kernel does not tell,
        by netlink, of an entry that no address of the interface covers.)"""
        v6 = ":" in ip
        cmd = ["ndp", "-s"] if v6 else ["arp", "-s"]
        tried = self.run("router", *cmd, ip, mac, check=False)
        # It says it cannot find a route for the address, and exits well.
        if tried.returncode or "cannot locate" in tried.stdout + tried.stderr:
            network = ipaddress.ip_network(f"{ip}/{64 if v6 else 24}", strict=False)
            if v6:
                self.run("router", "route", "add", "-inet6", str(network.network_address), "-prefixlen", "64", "-interface", iface)
            else:
                self.run("router", "route", "add", "-net", str(network), "-interface", iface)
            self.run("router", *cmd, ip, mac)

    def forget_neighbour(self, iface, ip):
        self.run("router", *(["ndp", "-d"] if ":" in ip else ["arp", "-d"]), ip)

    def neighbour_watch_argv(self, iface):
        # Its output is not for a terminal, and is held back until there is a block of it.
        return [*self.router_argv(), "stdbuf", "-oL", "route", "-n", "monitor"]

    @staticmethod
    def neighbour_seen(ip, mac):
        """What the watch prints when `ip` is at `mac` in the table."""
        return rf"neigh {re.escape(ip)}\S* .*lladdr {mac}"

    @staticmethod
    def neighbour_gone(ip):
        return rf"delete neigh {re.escape(ip)}"

    def relax_source_checks(self):
        pass  # no reverse path filter by default

    def bind_to_interface(self, sock, iface):
        pass  # a BSD socket hears what is sent to the address it is bound to, on any interface

    def close(self):
        sh("jail", "-r", self.jail, check=False)


def make():
    """The network for a lab, as this system makes one."""
    if LINUX:
        return Linux()
    if FREEBSD:
        return FreeBSD()
    raise RuntimeError(f"no way to make a router's network on {platform.system()}")
