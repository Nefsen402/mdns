# mdnsd

An mDNS (Bonjour/Avahi-style) daemon for Linux routers and hosts. It keeps track
of the devices on each network it is told to watch, makes chosen ones visible on
other networks, and lets scripts ask it what is there.

It has two uses, which are the same daemon with a different configuration:

- **[A reflector](#reflecting-between-networks)** for a router with several
  networks (VLANs, a guest or IoT Wi-Fi): your phone on the LAN finds the
  speakers on the media VLAN, with per-pair control over which networks may see
  each other, and in which direction.
- **[A device tracker for scripts](#tracking-devices-for-scripts)**: the
  daemon watches a network all the time, so a short-lived script can ask it what
  is there in one call, smart plugs that only answer when asked included, or
  follow devices as they come and go.

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
  Clashes are settled by the configuration: the network listed first wins a
  hostname, and a device on the network itself always comes before a copy of
  one from elsewhere.
- **Quiet devices are found.** Many devices never announce themselves and only
  answer when asked. The daemon probes at startup, asks each device to answer
  again just before it would expire, and asks the other networks what clients
  ask on one (`ForwardQuestions=` in `mdnsd.conf(5)`), so devices
  stay visible while they are there.
- **Both IP families as one.** A device is one device whichever family it spoke:
  one that only speaks IPv6 is announced over IPv4 too, with its IPv6
  addresses, and its global and ULA addresses are kept alike (up to
  `MaxAddresses=`).

### What it costs

What the model does not hold does not cross:

- Records other than A, AAAA, PTR, SRV, TXT and NSEC are not passed on, nor
  are the priority and weight of SRV records.
- TXT values are kept as text: one that is not valid UTF-8 is not passed on
  byte for byte.
- A device is reflected once it has a hostname, a routable address and a
  service with its host and port. Until it has said all that, nothing of it
  is shown elsewhere.
- Only mDNS is handled: SSDP/UPnP and LLMNR discovery are not.

## Reflecting between networks

The configuration names groups of interfaces, called segments, whose devices
are reflected between each other. For a router with a trusted LAN (`br0`), a
media VLAN and an IoT Wi-Fi:

```ini
# /etc/mdnsd.conf
#   br0   <-> media : each sees the other's devices
#   br0   <-  wifi  : br0 sees the IoT devices, wifi sees nothing of br0
#   media  x  wifi  : never see each other

[Advertise]
Hostname=router.local

[Segment]
Name=media_stuff
Interfaces=br0,media

[Segment]
Name="IoT to br0"
Interfaces=br0,wifi
Untrusted=wifi
```

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
- `[Advertise] Hostname=router.local` makes the router itself reachable by name
  from every network, with its own address on each.
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

## Tracking devices for scripts

This is not an mDNS client: the daemon is not started for a lookup and gone
when it is done. It runs all the time, watching the network on your behalf,
and a script, however short-lived, asks it what it has seen. For that, a
segment of a single interface is enough: it reflects nothing, and its devices
are only tracked.

```ini
# /etc/mdnsd.conf
[Segment]
Name=lan
Interfaces=eth0
```

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
`--interval` asks for the type again that often, to find one switched on
later. For example, configure each Shelly plug once as it is found:

```sh
mdnsctl --json watch --query _shelly._tcp --interval 1min lan |
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
$ mdnsctl subscribe --query _shelly._tcp --interval 1min --log /var/log/plugs.log lan -- /usr/local/bin/configure-plug
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

- The control socket is readable only by the `mdnsd` group: add the user the
  script runs as (`sudo usermod -aG mdnsd $USER`, then log in again).
- It shares port 5353 with Avahi or systemd-resolved, so they can stay.
- It still sends a little: a probe at startup, a question to each device about
  to expire (`[Probe] RefreshBefore=off` stops that, at the cost of quiet
  devices dropping off when their records run out), and what `--query` asks.
  Without `[Advertise]` it announces nothing of its own.
- Interfaces are named, there is no "every interface". A host on several
  networks lists each, as a segment of its own (a segment of two or more
  interfaces would reflect between them).

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
- The control socket lives in `/run/mdnsd/`, readable only by the `mdnsd`
  group. To use `mdnsctl` without `sudo`:
  `sudo usermod -aG mdnsd $USER` (then log in again).

To run it by hand instead, point `Socket=` at a directory you can write to:
`mdnsd /path/to/mdnsd.conf` as root, or as a normal user with a config whose
`[Ipc] Socket=` is somewhere under your home or `/tmp`.

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
