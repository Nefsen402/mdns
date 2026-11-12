# mdnsd

An mDNS (Bonjour/Avahi-style) daemon for Linux routers and hosts. It keeps track
of the devices on each network it is told to watch, makes chosen ones visible on
other networks, lets scripts ask it what is there, and announces the host's own
name and services.

It has five uses, which are the same daemon with a different configuration,
and **any combination of them runs at once**, from one config file, on the same
interfaces or on different ones: a router that reflects between two networks,
tunnels to a remote site, tracks a third network and advertises itself on the
first is one daemon (see [one config for every mode](#one-config-for-every-mode)).

- **[A reflector](#reflecting-between-networks)** for a router with several
  networks (VLANs, a guest or IoT Wi-Fi): your phone on the LAN finds the
  speakers on the media VLAN, with per-pair control over which networks may see
  each other, and in which direction.
- **[A bridge over a tunnel](#reflecting-over-a-tunnel)** that carries only
  unicast, such as WireGuard: a daemon at each end, each told where the other
  is, so that the devices of one site are found from the other, in one
  direction or both, though no multicast crosses the tunnel.
- **[A device tracker for scripts](#tracking-devices-for-scripts)**: the
  daemon watches a network all the time, so a short-lived script can ask it what
  is there in one call, smart plugs that only answer when asked included, or
  follow devices as they come and go.
- **[An advertiser](#advertising-this-host)** of the host it runs on: its name
  and the services it offers (ssh, say), announced and answered for as Avahi's
  own publishing does, so that Avahi is not needed for it.
- **[A client for `nss-mdns`](#a-client-for-nss-mdns)**: only the Avahi socket
  answers lookups, and the daemon asks only when one comes in, sending nothing
  of its own accord, as an ordinary mDNS client does.

## How it works: devices, not packets

Most mDNS reflectors (Avahi's included) copy packets: what is heard on one
network is sent out again, as it was, on the others. This daemon does not
forward any packet. It listens to each interface, **builds a model of the
devices on it** (each one's hostname, addresses and services, with the TTL of
every record), and announces that model on the other networks itself, under its
own address. It answers questions from the model too: a phone on the LAN asking
for AirPlay speakers is answered by the router, with the speaker's details, and
the speaker never hears the phone.

![The speaker on the media VLAN announces itself to the router, which keeps a model of it (Speakers.local, 10.0.2.73, _airplay on port 7000) and asks it questions as itself; the router announces that model on the LAN and answers the phone's questions from it.](docs/how-it-works.svg)

### What that makes possible

- **One-way visibility.** mDNS is a conversation: clients ask, devices answer.
  A packet reflector has to carry both halves between two networks, so it can
  only make them see each other both ways or not at all. Here the router answers
  from its model, so a network can be shown another's devices without being
  shown to it: with `Untrusted=media`, the LAN finds the media VLAN's speakers,
  and the media VLAN learns nothing about the LAN.
- **Privacy.** Only the model crosses, never what the devices and clients sent:
  - A client's questions are answered by the router. When the router does not
    know the answer, it asks the other networks itself, in a query of its own:
    they see what name was looked for, not who looked, and not what the asker
    already had in its cache (its known answers).
  - Clients that only ask (phones, laptops) are tracked but never announced
    elsewhere. Only devices that offer a service are.
  - Link-local addresses, which mean nothing off their own link, stay on it.
  - An untrusted network is told nothing at all, and its questions are asked
    nowhere.
- **Robustness.** Every record is checked before it enters the model, so a
  malformed packet, a name no device could have, an unusable address or a
  flood from one sender never reaches another network (a
  [fuzzer](#fuzzing) checks this from outside). Reflection is never transitive,
  so networks that share an interface cannot echo devices back and forth.
  Clashes are settled the same way each time: of one hostname found on several
  networks, the one on the interface with the lowest index wins, and a device on
  the network itself always comes before a copy of one from elsewhere.
- **Quiet devices are found.** Many devices never announce themselves and only
  answer when asked. The daemon probes at startup, asks each device to answer
  again just before it would expire, and asks the other networks what clients
  ask on one (`ForwardQuestions=` in `mdnsd.conf(5)`: each question once, by default, or every time), so devices
  stay visible while they are there.
- **Both IP families as one.** A device is one device whichever family it spoke:
  one that only speaks IPv6 is announced over IPv4 too, with its IPv6
  addresses, and its global and ULA addresses are kept alike (up to
  `MaxAddresses=`, see `mdnsd.conf(5)`).

### What it costs

What the model does not hold does not cross:

- Records other than A, AAAA, PTR, SRV, TXT and NSEC are not passed on, nor
  are the priority and weight of SRV records.
- By default a device is reflected once it has a hostname, a routable address
  and a service whose host and port are known, and until it has all that nothing
  of it is shown elsewhere. Only its services that are known so, and of the
  types `ReflectedServices=` lets through, go with it. `ReflectedWhen=` can
  leave out the address or the service, so that a device is found by its name
  alone, or by its services alone; the hostname is always needed, as it is what
  a device is announced by (see `mdnsd.conf(5)`).
- Only mDNS is handled: SSDP/UPnP and LLMNR discovery are not.

## One config for every mode

Nothing in the config is global but `[Ipc]`, the daemon's own control socket:
every other setting belongs to an interface, a segment or a name, so the five
uses are written side by side in one file, and an interface can serve several.
This one is for a router with a trusted LAN (`br0`), a media VLAN, an IoT Wi-Fi,
a wired network it only watches (`eth0`), another it only looks names up on
(`eth1`) and a WireGuard tunnel to a remote site (`wg0`); each block is the mode it says, and any of them can be left out:

```ini
# /etc/mdnsd.conf

# Reflecting between networks. A segment reflects between every pair of its
# interfaces, and an interface may be in several segments.
#   br0   <-> media : each sees the other's devices
#   br0   <-  wifi  : br0 sees the IoT devices, wifi sees nothing of br0
#   media  x  wifi  : never see each other
[Segment]
Name=media_stuff
Interfaces=br0,media

[Segment]
Name="IoT to br0"
Interfaces=br0,wifi
Untrusted=wifi

# Reflecting over a tunnel that carries no multicast: Peer= says who is at the
# other end of wg0, which is a daemon too, with Peer=10.8.0.1 on its own wg0.
# What it announces is found from br0; nothing of br0 is announced to it.
[Interface]
Name=wg0
Peer=10.8.0.2

[Segment]
Name=remote
Interfaces=br0,wg0
Untrusted=wg0

# Tracking devices for scripts. A segment of one interface reflects nothing:
# its devices are only tracked, and `mdnsctl devices lan` says what is there.
[Segment]
Name=lan
Interfaces=eth0

# Looking names up as a client does, for nss-mdns through the Avahi socket
# below: on eth1 it is not active, asking only when asked, and what it hears
# expires as its TTLs say.
[Segment]
Name=client
Interfaces=eth1
Active=no

# Advertising this host, under .local, on br0, with the services it offers.
[Advertise]
Hostname=router.local
Interface=br0
Services=_ssh._tcp:22 _http._tcp:8080

# What is kept of devices, for every interface, and for one: the interface
# named is the exception, the one without a name the rule.
[Interface]
MaxAddresses=8
MaxDevices=1024

# ProbeServices: devices that answer only when asked for their type, and never
# say it when asked for every type (Shelly plugs answer _http._tcp alone), are
# found because every probe, at startup and whenever the interface comes up,
# browses for these too.
[Interface]
Name=wifi
MinimumLifetime=1h
ProbeServices=_http._tcp, _shelly._tcp

# The daemon itself: the control socket of `mdnsctl`, and Avahi's, so that
# `ping router.local` works with Avahi gone.
[Ipc]
Socket=/run/mdnsd/mdnsd.sock
AvahiSocket=/run/avahi-daemon/socket
```

`br0` serves all four here: devices are reflected to it, it is a point of the
tunnel's segment, the host is advertised on it, and it could be tracked too.
Which uses a daemon has is what is written: only `[Advertise]` and a
one-interface `[Segment]` make an advertiser, and a one-interface `[Segment]`
alone a tracker. The sections below say what each does.

## Reflecting between networks

The configuration names groups of interfaces, called segments, whose devices
are reflected between each other (the first two `[Segment]` blocks of the
[config above](#one-config-for-every-mode)).

- A segment reflects between **every pair** of its interfaces, and it may have
  as many as you like: `Interfaces=br0,media,guest,lab` lets all four see each
  other. An interface may also be in several segments, which is how `br0` sees
  both `media` and `wifi` while those two never see each other: a device
  reflected onto `br0` is not reflected again.
- An **untrusted** interface has its devices shown to the others, and is shown
  nothing itself. `Untrusted=wifi` lets the LAN find the IoT devices without
  the IoT network learning about the LAN.
- A question a client asks on one interface is asked on the others of the
  segment too (`ForwardQuestions=`), so a
  device that only answers when asked is found the moment someone looks for it.
- Interfaces may come and go: a VLAN that is created after the daemon starts, or
  recreated, is picked up without a restart
  (see `mdnsd(8)`).

mDNS only makes devices **discoverable**. Your firewall must still allow the
connections between the networks (the phone on the LAN connecting to the
speaker on `media`).

See what the daemon sees:

```
$ mdnsctl devices media_stuff
  Living-Room-TV.local  Living Room TV  10.0.2.40, fd00:2::40
  Speakers.local        Speakers        10.0.2.73
  desktop.local         -               10.0.0.10, fd00::10
media_stuff: 3 devices
```

The rules for what is reflected, and when, are in `mdnsd(8)`. Don't run another
reflector (Avahi's `enable-reflector`) over the same interfaces.

## Reflecting over a tunnel

mDNS is multicast, and a tunnel such as WireGuard carries no multicast: it
sends a packet only to a peer whose `AllowedIPs` has the destination, which the
mDNS group is not. Run a daemon at each end and tell each where the other is
(`Peer=` on the tunnel's interface, in the [config above](#one-config-for-every-mode)),
and they carry mDNS over the tunnel as unicast, to each other alone. For a home
network (`br0`) and a remote site, joined by a WireGuard tunnel (`wg0`), home on
`10.8.0.1` and the remote site on `10.8.0.2`, the config above is home's; the
remote site's is the same with `Peer=10.8.0.1` on its `wg0`, in a segment of its
own LAN and `wg0`.

The remote site's devices are announced to home through the tunnel, and home
reflects them into `br0`: the speakers there are found from the LAN here. At
home `wg0` is untrusted, so nothing of `br0` is announced down the tunnel; the
remote site is told nothing of home. Leave `Untrusted=` out on both sides and
each sees the other's devices, as two networks of a router do.

- **What goes over the tunnel** is the mDNS a link would carry: announcements,
  questions and answers, sent to the peer alone, from and to port 5353 (`PeerPort=`
  moves it), over the family the peer's address is of. Only what a peer sends
  is heard: no other host on the tunnel is, whatever it sends.
- **Several peers** are `Peer=10.8.0.2, 10.8.0.3`: each is sent to and heard.
  The peers of one interface are one network to the daemon, so a device heard
  from one is not announced to another.
- **WireGuard** needs each peer's tunnel address in `AllowedIPs` of the other
  end (it is, for the tunnel to work at all), and the firewall must let UDP at
  port 5353 through between the two addresses. As elsewhere, mDNS only makes
  devices discoverable: connections to them have to be allowed, and routed
  over the tunnel, as well.
- It is for a tunnel with an address at each end, or any link where multicast
  does not reach: `Peer=` is of one interface, whatever it is.
- Linux only, for now: the BSDs share one socket between all interfaces, which
  cannot say who an interface's peers are.

## Tracking devices for scripts

This is not an mDNS client: the daemon is not started for a lookup and gone
when it is done. It runs all the time, watching the network on your behalf,
and a script, however short-lived, asks it what it has seen. For that, a
segment of a single interface is enough (`lan` in the
[config above](#one-config-for-every-mode)): it reflects nothing, and its devices
are only tracked.

A client the script runs itself (`avahi-browse`, an mDNS library) only knows
what answers while it is running, and most devices announce themselves once,
when they join the network, and then stay quiet. The daemon was listening then.
It keeps every device's records for their TTL, asks devices to answer again just
before they would expire, and drops them when they say goodbye or stop
answering. So a script that runs for a second, from cron or a hook, asks once
and gets the current list:

```sh
# Every device's name and first address.
mdnsctl --json devices lan | jq -r '.devices[] | select(.hostname) | "\(.hostname) \(.addresses[0])"'
```

**Devices that only answer when asked.** Smart plugs and many other IoT devices
rarely announce themselves, and answer neither waiting nor a general probe:
they answer when asked for their service type by name. `--query` does that, on
every interface of the segment, and lists only the devices of that type: those
already known at once, the others as they answer, for `--wait` (4 seconds unless
given), then how many there are. With `--json`, it prints one list at the end.

```sh
$ mdnsctl devices --query _shelly._tcp lan
  shellyplug-a1b2.local  shellyplug-a1b2  10.0.1.21
  shellyplug-c3d4.local  shellyplug-c3d4  10.0.1.22
lan: 2 devices
```

Once found, a device stays listed as long as it keeps answering, and plain
`mdnsctl devices lan` lists it too.

**Reacting as devices appear.** `watch` streams changes, so a script need not
poll. With `--query` it starts with the devices of the type already known, and
asks for the type as any question is asked on an interface (`ForwardQuestions=`
in `mdnsd.conf(5)`): by default once, so a type asked for before is not asked
for again, and what answered it is known already. For example, configure each
Shelly plug once as it is found:

```sh
mdnsctl --json watch --query _shelly._tcp lan |
jq -r --unbuffered 'select(.event != "removed") | .device.addresses[0] // empty' |
while read -r ip; do configure-plug "$ip"; done
```

A device usually produces several `updated` events as its records arrive, so a
script like that should be idempotent, or remember the addresses it has done.

**Without staying around.** `watch` holds on to whoever runs it. A script that
has to be done in a moment (a hook, a cron job, an installer) subscribes
instead, and `mdnsctl` stays behind in the background to run a script of yours
for each change:

```sh
$ mdnsctl subscribe --query _shelly._tcp --log /var/log/plugs.log lan -- /usr/local/bin/configure-plug
48213
```

It checks the watch can be opened (and the script run) before it returns, and
prints the subscriber's PID. The script gets each change as a line of JSON on
stdin, and `MDNS_EVENT`, `MDNS_HOSTNAME`, `MDNS_ADDRESS` (and a few more) in its
environment, so it can be as short as:

```sh
#!/bin/sh
[ "$MDNS_EVENT" = removed ] || curl -s "http://$MDNS_ADDRESS/settings?led_status_disable=true"
```

The subscriber runs as whoever started it, the daemon runs nothing, and it
watches again on its own if the daemon restarts. `mdnsctl watchers` lists it,
and `kill <pid>` stops it.

The protocol behind `mdnsctl` is one line of JSON per request over a Unix
socket, if you would rather talk to it directly (see `mdnsctl(1)`).

Things to know when using it this way:

- Any user may use the control socket. What it tells is what devices multicast
  on the link anyway. `[Ipc] Mode=0660` limits it to the `mdnsd` group.
- It shares port 5353 with Avahi or systemd-resolved, so they can stay.
- It still sends a little: a probe at startup, a question to each device about
  to expire, sent to the device itself unless `[Interface]` says `IPv4=multicast` (and `IPv6=`)
  (`[Interface] RefreshBefore=off` stops that, at the cost of quiet devices dropping
  off when their records run out), and what `--query` asks.
  Without `[Advertise]` it announces nothing of its own.
- Interfaces are named, there is no "every interface". A host on several
  networks lists each, as a segment of its own (a segment of two or more
  interfaces would reflect between them).

## Advertising this host

The daemon can announce the machine it runs on: its name under `.local`, with
its addresses, and the services it offers. That is what Avahi does when it
publishes a host and its service files, and it is the part of Avahi that a
desktop or a router usually wants, so with this, nothing else need run for it.
It is the `[Advertise]` block of the [config above](#one-config-for-every-mode),
with a segment that has the interface, so that the daemon listens on it: a
segment of one interface reflects nothing.

- `Hostname=` is announced and answered for with **all** of the interface's
  addresses, of both families (global, ULA and link-local), and kept to them as
  they change: one that goes is withdrawn with a goodbye. It is withdrawn
  entirely when the daemon stops.
- `Services=` are each a type and a port, `_ssh._tcp:22`, of an instance named
  for the host (`alexdesktop._ssh._tcp.local`, as Avahi's `%h`). Like Avahi's
  service files, they are announced whether or not anything listens there.
- `Interface=` limits where it is advertised and answered for, to some of the
  interfaces in the segments (all of them if it is left out). There may be any
  number of `[Advertise]` sections, each with its own name, services,
  interfaces and TTL: a name for the LAN with ssh, another for a VLAN with a
  file share.
- It is among the devices `mdnsctl devices` lists, as itself, so that a query
  for `_ssh._tcp` finds it too.
- `[Ipc] AvahiSocket=/run/avahi-daemon/socket` answers the questions
  `nss-mdns` asks Avahi, so that `ping router.local` works with Avahi gone
  (see `mdnsd.conf(5)`).

No conflict detection is done: the name is taken to be yours alone.

## A client for nss-mdns

`nss-mdns`, which makes `ping printer.local` work, asks Avahi's socket for the
address of a name. With `[Ipc] AvahiSocket=` the daemon answers it; with
`Active=no` on the segment (`client` in the
[config above](#one-config-for-every-mode)) it does so as an ordinary mDNS
client would, asking only when something asks it to. It sends no probe, at
startup or every `ProbeInterval=`, asks no device to answer again before its
records run out, and nudges no neighbour for its address. What it has heard is
kept as long as the records say and no longer.

- A lookup of a name it does not know asks for it on every interface of the
  segment, and waits a little for what answers. What a watch asks for with
  `--query`, and what another interface of the segment is asked, is asked too.
- A device whose records ran out is gone. One whose last address ran out (the
  shortest, two minutes, where nothing asks it again) is kept with its other
  records, but is not shown on other interfaces, and the questions it answered
  are forgotten, so that the next lookup asks again, though by default each
  question is asked only once (`ForwardQuestions=` in `mdnsd.conf(5)`).
- A watch (`mdnsctl watch --query`) keeps its devices up: those with a service
  of the type are asked to answer again before they run out, as long as it is
  open, and no others are.
- Replies to the questions it hears, and what `[Advertise]` or another
  segment announces, are not "of its own accord", and go on as they are. A
  client is a segment of one interface, which reflects nothing.

## Building and running

```sh
cargo build --release
# produces target/release/mdnsd (the daemon) and target/release/mdnsctl (the client)

mdnsd                     # reads /etc/mdnsd.conf
mdnsd /path/to/other.conf # or a config file you name
```

To run it as a service, see [Installing (Arch Linux)](#installing-arch-linux).

The configuration is read once at startup; restart the daemon to apply changes.
Startup fails, naming the problem, if the config is invalid or an interface
that is there cannot be opened. One that is not there yet is waited for. The
daemon stops cleanly on `SIGTERM` or `SIGINT`, withdrawing what it reflected
with goodbyes (see `mdnsd(8)`).

## Other systems

Linux is what it is made for and tested on: the unit tests and the end-to-end
tests (see `tests/e2e/`) run there in CI.

FreeBSD builds it and passes the unit tests and the end-to-end tests, which CI
runs in a virtual machine on 14.5 (the router is a VNET jail: see `tests/e2e/`). The other BSDs, NetBSD, OpenBSD and DragonFly, have not been tried. The
part that differs between the BSDs and Linux is run end to end on Linux as well,
in CI (`cargo build --features portable-sockets`).

What differs is the sockets. Linux pins a socket to each interface
(`SO_BINDTODEVICE`), so each hears nothing from another. The BSDs cannot, so
there is one socket for each family, bound to the wildcard address and joined to
the group on every interface as it is opened. It asks the system which
interface each datagram came in on (`IPV6_PKTINFO`, and `IP_RECVIF` for IPv4),
and the daemon hands the datagram to that interface, in userspace; one that
came in on an interface it does not serve is dropped. Sending says which
interface it goes out of, each time. A datagram is read once, whichever
interface it came in on. What is sent to port 5353 itself, not to the group, is
heard unless `[Interface]` says `multicast` for the family (the group alone), as on
Linux, and then only from a host on the interface's networks or link-local.

Where it does less than on Linux:

- Interfaces that come and go, and the addresses the neighbour table has for
  devices, are learned from netlink, which Linux has and FreeBSD (14 and 15)
  has of the same messages. On the other BSDs an interface has to be there when
  the daemon starts, and a device's other addresses are not learned. Their
  routing sockets would say the same things; they are not read yet.
- An IPv4 group is joined by the interface's address, which is the first it
  has when the socket is opened.
- `mdnsctl watchers` cannot say which process holds a watch, only its user, and
  `mdnsctl subscribe` looks at whether its script has finished, where Linux
  tells it.

## Installing (Arch Linux)

The `PKGBUILD` in `packaging/arch/` builds a package from the working tree:

```sh
cd packaging/arch
makepkg -f          # builds, runs the test suite, and creates mdnsd-*.pkg.tar.zst
sudo pacman -U mdnsd-*.pkg.tar.zst
```

It installs `/usr/bin/mdnsd`, `/usr/bin/mdnsctl`, the `mdnsd.service` unit, a
sysusers entry that creates the unprivileged `mdnsd` user, and the man pages
(`mdnsd(8)`, `mdnsd.conf(5)`, `mdnsctl(1)`). No `/etc/mdnsd.conf` is installed,
since only you know your interfaces. Write one
(starting from [Reflecting between networks](#reflecting-between-networks) or
[Tracking devices for scripts](#tracking-devices-for-scripts)), then start the
service:

```sh
sudoedit /etc/mdnsd.conf
sudo systemctl enable --now mdnsd.service
journalctl -u mdnsd.service -f
```

Notes on the service:

- It runs as `mdnsd`, not root, with a locked-down sandbox (no capabilities,
  read-only filesystem, a syscall allow-list). Binding a socket to one
  interface needs no privilege on **Linux 5.7 or newer**.
- It does not start until `/etc/mdnsd.conf` exists. It is **not** restarted
  if it fails, so a crash shows in `systemctl status mdnsd` and the journal
  instead of being retried past. Interfaces that appear after boot (VLANs,
  Wi-Fi) need no restart: the daemon follows interfaces as they come and go
  (see `mdnsd(8)`). Configuration is read at start, so apply changes with
  `systemctl restart mdnsd`.
- `systemctl stop` sends `SIGTERM`, so reflected devices are withdrawn cleanly.
- The control socket lives in `/run/mdnsd/`, and any user may use `mdnsctl`.
  `[Ipc] Mode=0660` limits it to the `mdnsd` group, which you then join with
  `sudo usermod -aG mdnsd $USER` (and log in again).

To run it by hand instead, point `Socket=` at a directory you can write to:
`mdnsd /path/to/mdnsd.conf` as root, or as a normal user with a config whose
`[Ipc] Socket=` is somewhere under your home or `/tmp`.

## Installing (Debian, Ubuntu)

`packaging/debian/` builds a `.deb` from the working tree. It needs
`build-essential`, `debhelper`, and `cargo` and `rustc` 1.88 or newer:

```sh
./packaging/debian/build.sh     # builds, runs the test suite, creates packaging/debian/out/mdnsd_*.deb
sudo apt install ./packaging/debian/out/mdnsd_*.deb
```

Set `DEB_BUILD_OPTIONS=nocheck` to skip the tests. The package installs the
same files as the Arch one, and its post-install script creates the `mdnsd`
user and group. Configure and start it as described above (`/etc/mdnsd.conf`,
then `systemctl enable --now mdnsd`; the package enables the unit but it does
not run until the config exists).

## Documentation

The man pages are the reference, and are installed with the package:

- **`mdnsd(8)`**: what the daemon does: how devices are tracked, probed and
  refreshed, exactly what is reflected and what is not, the advertised name,
  interfaces coming and going, signals and shutdown.
- **`mdnsd.conf(5)`**: every setting, with its default and limits.
- **`mdnsctl(1)`**: every command and option, what each prints (with
  `--json` and without), its exit status, and talking to the control socket
  directly.

From a source checkout, read them with `man -l man/mdnsctl.1` and so on. The
control protocol is also described at the top of `src/ipc.rs`.

## Fuzzing

Every packet the daemon hears is untrusted, and what it reflects is what one
network tells another. `fuzz/` holds a fuzzer that tests that boundary from the
outside, as a network would:

```sh
cd fuzz
cargo run --release -- --duration 60
```

It builds the daemon on its own (a debug build, so that overflow checks and
debug assertions are on), and runs it in a network namespace of its own with
one segment of two interfaces. On one it sends nothing but bogus devices, each
an otherwise valid announcement with one thing wrong with it:

- **unparseable**: cut short, reserved label bytes, looping or forward
  compression pointers, wrong counts, junk;
- **names**: not under `.local`, a dot or a control character in a host label,
  invalid UTF-8, a bad service type, a class other than IN;
- **addresses**: unspecified, broadcast, multicast, loopback, reserved,
  link-local or IPv4-mapped addresses, and SRV port 0;
- **floods**: thousands of well-formed devices from one sender, of which no
  more than 64 may get through.

None of them may come out on the other interface. Among them go canaries,
well-formed devices that must come out within six seconds, to show that the
daemon has neither stalled nor died. Every other canary announces only an IPv6
address, over IPv6, as a device that never speaks IPv4 does; every canary has
to come out over both families, since the daemon announces a device over every
family whichever it spoke.

It needs no privileges: it runs itself under `unshare -rn`, which needs
unprivileged user namespaces. Options: `--seed N` (a run is the same from the
same seed), `--duration SECS`, `--rate INPUTS_PER_SEC` (200),
`--only unparseable,names,addresses,floods`, `--stop-on-first`, and
`--daemon PATH` to test a daemon built elsewhere. Each run is logged to
`target/fuzz-runs/<seed>/`: `sent.log` (every input, in hex), `daemon.log`,
and `failures.txt` (each failure, with the input that caused it). It exits
non-zero if anything failed.

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).
