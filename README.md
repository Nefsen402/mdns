# mdns

An mDNS (Bonjour/Avahi-style) discovery and reflection daemon for routers, with
per-pair control over which networks can see each other's devices.

- **Tracks** the devices announcing on each interface (name, address, services).
- **Reflects** devices between the interfaces you choose, and only those. With
  `br0 <-> media` and `br0 <-> wifi`, `media` and `wifi` never learn about each
  other, even though both talk to `br0`.
- **Probes** for devices actively (at startup and on demand) and asks each
  device to answer again just before it would expire, instead of only waiting
  for devices to announce themselves.
- **Advertises** the router's own name (`router.local`) on every network, as
  Avahi does, if you configure one.
- **Answers** mDNS queries for reflected devices and withdraws them (with proper
  goodbye packets) when the source device disappears or the daemon stops.
- **Exposes** what it knows over a local control socket, queried with `mdnsctl`.

It never listens on the wildcard interface: every socket is bound to one
interface and the mDNS multicast group address.

## Building and running

```sh
cargo build --release
# produces target/release/mdns (the daemon) and target/release/mdnsctl (the client)

mdns                     # reads /etc/mdnsd.conf
mdns /path/to/other.conf # or a config file you name
```

To run it as a service, see [Installing (Arch Linux)](#installing-arch-linux).

The configuration is read once at startup; restart the daemon to apply changes.
Startup fails, naming the problem, if the config is invalid or an interface
cannot be opened. The daemon stops cleanly on `SIGTERM` or `SIGINT` (see
[Shutdown](#shutdown)).

## Installing (Arch Linux)

The `PKGBUILD` in `packaging/arch/` builds a package from the working tree:

```sh
cd packaging/arch
makepkg -f          # builds, runs the test suite, and creates mdns-*.pkg.tar.zst
sudo pacman -U mdns-0.1.0-1-x86_64.pkg.tar.zst
```

It installs `/usr/bin/mdns`, `/usr/bin/mdnsctl`, the `mdnsd.service` unit, a
sysusers entry that creates the unprivileged `mdnsd` user, the man pages
(`mdns(8)`, `mdnsd.conf(5)`, `mdnsctl(1)`), and this README and the example
config under `/usr/share/doc/mdns/`, and the license under
`/usr/share/licenses/mdns/`. No `/etc/mdnsd.conf` is
installed, because the example names interfaces that probably do not exist on
your machine. Create one, then start the service:

```sh
sudo cp /usr/share/doc/mdns/examples/mdnsd.conf /etc/mdnsd.conf
sudoedit /etc/mdnsd.conf
sudo systemctl enable --now mdnsd.service
journalctl -u mdnsd.service -f
```

Notes on the service:

- It runs as `mdnsd`, not root, with a locked-down sandbox (no capabilities,
  read-only filesystem, a syscall allow-list). Binding a socket to one
  interface needs no privilege on **Linux 5.7 or newer**.
- It does not start until `/etc/mdnsd.conf` exists, and it is restarted every
  5 seconds if it exits, which covers VLAN or Wi-Fi interfaces that appear
  after boot. Configuration is read at start, so apply changes with
  `systemctl restart mdnsd`.
- `systemctl stop` sends `SIGTERM`, so reflected devices are withdrawn cleanly.
- The control socket lives in `/run/mdnsd/`, readable only by the `mdnsd`
  group. To use `mdnsctl` without `sudo`:
  `sudo usermod -aG mdnsd $USER` (then log in again).

To run it by hand instead, point `Socket=` at a directory you can write to:
`mdns /path/to/mdnsd.conf` as root, or as a normal user with a config whose
`[Ipc] Socket=` is somewhere under your home or `/tmp`.

## Configuration

The file uses systemd-style INI syntax. The default location is
`/etc/mdnsd.conf`; [`examples/mdnsd.conf`](examples/mdnsd.conf) is a complete
example.

```ini
# /etc/mdnsd.conf
#
# Three networks: the trusted LAN (br0), a media VLAN and an IoT Wi-Fi VLAN.
#   br0   <-> media : each sees the other's devices
#   br0   <-> wifi  : each sees the other's devices
#   media  x  wifi  : never see each other

[Listen]
IPv4=yes
IPv6=yes

[Ipc]
Socket=/run/mdnsd/mdnsd.sock

# A device is kept at least this long after it was last heard from, whatever
# TTLs it announced (a device lives for its longest TTL, but not for less than
# this). `0` keeps it for exactly its TTL.
[Devices]
MinimumLifetime=5min

# Most devices (speakers especially) only answer when asked, and one that is
# not heard from expires and is withdrawn from the other networks. So a device
# is asked to answer again this long before it would expire (`0` or `off` turns
# this off). `Interval=` would also probe every network that often, to find new
# quiet devices; it is not set by default.
[Probe]
RefreshBefore=30s

# Answer mDNS queries for this name with the router's own address on each
# interface, so `router.local` resolves from every network listed below. Others
# keep the address for TTL, and it is announced again at 80% of that.
[Advertise]
Hostname=router.local
TTL=2min

[Segment]
Name=media_stuff
Interfaces=br0,media

# One interface only: devices are tracked (and show up in `mdnsctl devices IoT`)
# but nothing is reflected.
[Segment]
Name="IoT"
Interfaces=wifi

[Segment]
Name="IoT to br0"
Interfaces=br0,wifi
```

### Syntax

- `[Section]` headers and `Key=Value` lines. Section and key names are
  **case-insensitive**.
- Lines starting with `#` or `;` are comments. Blank lines are ignored.
- Values may be wrapped in single or double quotes: `Name="IoT to br0"`.
- Repeating a key **appends** to list values (`Interfaces=`); an empty
  assignment (`Interfaces=`) **resets** the list.
- Booleans accept `yes`/`no`, `true`/`false`, `on`/`off`, `1`/`0`.
- A line ending in a backslash continues on the next line, as in unit files.
- Syntax errors and unknown settings are reported with the line they are on.
- Unknown sections or keys are an error, so typos fail loudly.

### `[Listen]` (optional)

| Key    | Default | Meaning                                        |
|--------|---------|------------------------------------------------|
| `IPv4` | `yes`   | Listen and announce on IPv4 (`224.0.0.251`).   |
| `IPv6` | `yes`   | Listen and announce on IPv6 (`ff02::fb`).      |

At least one must be enabled. The two families are completely independent: each
has its own sockets, device lists and reflectors, and a device reachable over
both appears once per family.

### `[Ipc]` (optional)

| Key      | Default                  | Meaning                                    |
|----------|--------------------------|--------------------------------------------|
| `Socket` | `/run/mdnsd/mdnsd.sock`  | Path of the control socket `mdnsctl` uses. |

The directory must already exist and be writable by the daemon (the systemd
service creates `/run/mdnsd` for it). Unix socket paths are limited to about
108 bytes. The socket is created with mode `0660` (owner and group only). A stale socket file from a crashed run is
replaced; a live instance or a file that is not a socket is never overwritten.

### `[Devices]` (optional)

| Key               | Default | Meaning                                                     |
|-------------------|---------|-------------------------------------------------------------|
| `MinimumLifetime` | `5min`  | The least a device is kept after it was last heard from.    |

A systemd time span (`5min`, `90s`, `1h`), at most 1 day. A device lives for the
longest TTL it announced, but never for less than this, so a device that
announces tiny TTLs is not dropped between two of the daemon's checks. `0` removes
the minimum: each device then lives for exactly its longest TTL.

It is also the price of a device that vanishes without saying goodbye: it stays
listed, and announced to the other networks, for up to this long. A lower value
drops it sooner; a higher one keeps devices through longer silences. Keep
[`RefreshBefore`](#probe-optional) shorter than it (the daemon warns at startup
if it is not), because that margin is counted back from the end of this lifetime.

### `[Probe]` (optional)

| Key             | Default | Meaning                                                                               |
|-----------------|---------|---------------------------------------------------------------------------------------|
| `RefreshBefore` | `30s`   | Ask a device to answer again this long before it would expire. `0`/`off` disables it. |
| `Interval`      | off     | Also probe every interface for devices this often.                                    |

Both are systemd time spans: `30s`, `4min`, `1h 30min`, or a bare number of
seconds.

Most devices (speakers especially) never announce themselves again after they
start; they only answer when asked. A device that nobody has heard from expires,
and is then withdrawn from the other networks until something asks it again.

**`RefreshBefore`** renews each device just in time. A device lives for as long
as the longest TTL it announced, **and at least
[`MinimumLifetime`](#devices-optional)** (5 minutes by default). `RefreshBefore`
before that runs out, the daemon asks that device, and only it, for the records
it announced, and asks again about every quarter of the margin until it answers
or expires. A speaker whose records live 75 minutes is asked at about 74
minutes; a device with short records just before its minimum lifetime is up.
Devices that are heard
from regularly are never asked, and a device known only by the address it was
heard from (a phone that merely sends queries) has nothing to ask and is left
alone. The minimum is 30 seconds.

*Short TTLs.* The minimum lifetime is why a TTL shorter than the margin (10
seconds, say) is not a problem: the device is not due the moment it is heard, it
lives `MinimumLifetime` after it was last heard (5 minutes by default) and is
asked 30 seconds before that. The price is that a device that really vanishes is
still listed, and still announced to the other networks, for up to that long. A
margin longer than the lifetime (with `MinimumLifetime=0` and short TTLs, say)
makes every device due all the time; it is then asked once per quarter of the
margin, not continuously.

**`Interval`** is not set by default. It probes every interface (browsing for
service types and instances) on a timer, which is the way to find a **new**
quiet device that never announces itself. Without it, new devices are found at
startup, when they announce themselves (most do when they join a network), and by
`mdnsctl probe`. The minimum is 10 seconds. With `RefreshBefore` off, an
`Interval` has to stay under `MinimumLifetime` to keep devices listed, and the
daemon warns at startup if it does not.

A probe is a handful of multicast queries per interface and takes about four
seconds; a refresh is a few questions. Routine ones are not logged; failures
are.

### `[Advertise]` (optional)

| Key        | Meaning                                                              |
|------------|----------------------------------------------------------------------|
| `Hostname` | A name under `.local` to announce and answer for, e.g. `router.local`. A bare label such as `router` means `router.local`. |
| `TTL`      | How long others keep the name's address, and so how often it is announced again: at 80% of it (default `2min`, so every 96 seconds). Between 10 seconds and 24 hours. A longer one means less chatter, but a stale address lingers that long after the router's changes. |

The daemon answers queries for this name with **its own address on each
interface**, so every network is told the address at which it can reach the
router. The IPv4 socket publishes an A record with the interface's primary
IPv4 address and the IPv6 socket an AAAA record with its link-local IPv6
address (the source address the kernel uses towards the mDNS group there). An
interface with no address of a family is skipped, with a message in the log.
Addresses are read once, at startup; restart the daemon after changing them.

Internally the name is just a reflected device that has a hostname and an
address but no services, so it is announced, kept alive, answered for and
withdrawn with a goodbye on shutdown like any other. There is no conflict
detection; the name is assumed to be yours alone.

### `[Segment]` (one or more, required)

| Key          | Meaning                                                              |
|--------------|----------------------------------------------------------------------|
| `Name`       | Required. Unique name, used by `mdnsctl`. Quote it if it has spaces. |
| `Interfaces` | Required. Interfaces in the segment, separated by commas and/or spaces. |

A segment is a group of interfaces **whose devices are reflected between every
pair of them**. Think of each segment as "these networks may see each other".

- A segment with **one** interface only tracks: its devices are listed by
  `mdnsctl`, but nothing is reflected.
- An interface may appear in **several** segments. That is how `br0` can see
  both `media` and `wifi` while those two stay isolated: reflection is never
  transitive, because a device reflected onto `br0` is not reflected again.
- Two segments may not share **two or more** interfaces (they would both
  reflect between the same pair and fight over it). Sharing one is fine.
- Names must be unique, an interface may be listed only once per segment, and
  every interface must exist when the daemon starts.

### What gets reflected

Devices are found by listening, and by probing: at startup, and whenever you
run `mdnsctl probe` (or every [`Interval`](#probe-optional), if set), the daemon browses every interface for service types and
instances, resolves each instance's hostname and port, and asks for the
addresses of devices that have a name but no routable address yet. Many devices
answer only when asked, and a device needs a hostname and a routable address to
be reflected, so without probing they would stay invisible.

- A device is identified by its **hostname**, and its addresses are the ones it
  announces in its own A and AAAA records (plus the address it sent from, if it
  announced none of its own). A packet may describe several devices (a
  reflector's answer to a browse query does), so each record goes to the device
  it names: an address to the host that owns the name, a service to the host its
  SRV record points at. The address a packet came from is credited to a host
  only if that host announced it, or announced none and is the only host
  described, so a reflector is not mistaken for the devices it announces. Per address family it has up to two: a
  **link-local** address, and a **routable** one (IPv4, or global/ULA IPv6).
- Only devices that announced **a hostname, a routable address and at least one
  service** are reflected. Chatty clients that merely send queries (phones,
  laptops) are tracked but not reflected.
- **Link-local addresses are never reflected.** `fe80::/10` only means
  something on the link the device is on; announced to another network it would
  name nobody. A reflected device is announced with its routable address only,
  so a device that has only a link-local IPv6 address is not reflected over
  IPv6 (over IPv4 it still is, if it has an address there).
- A reflected device is announced on the other interface with that **routable
  address**. Your firewall must allow the actual connections between the
  networks; mDNS only makes the device discoverable.
- If devices on different interfaces announce the **same hostname**, the one
  from the interface listed **first** in the segment wins; the other takes over
  automatically if the winner goes away. Different hostnames never clash, even
  on one address: a device with several names (a TV often has two) has each of
  them reflected.
- Reflected devices are kept alive with periodic re-announcements, answer
  queries (including known-answer suppression), and are withdrawn with goodbye
  packets when their source disappears.
- A discovered device expires after it has been silent for at least
  [`MinimumLifetime`](#devices-optional) (5 minutes by default), or for the TTL
  of its records if that is longer. A goodbye packet removes it
  immediately. A device that is about to expire is asked to answer again
  ([`RefreshBefore`](#probe-optional)), which is what keeps quiet ones from
  expiring.

The daemon binds with `SO_REUSEPORT`, so it can run next to Avahi while you
migrate, but don't run two reflectors (this and Avahi's) over the same
interfaces.

## `mdnsctl`

Queries a running daemon over its control socket.

```
usage: mdnsctl [-s PATH] [-v] [--json] <command>

commands:
  segments          list the configured segments
  devices <name>    list the devices discovered in a segment
  probe [<name>]    actively query for devices (all segments, or one)
  watch <name>      print the devices of a segment as they appear and go
  timers            list the timers the daemon has scheduled

options:
  -s, --socket PATH  control socket (default /run/mdnsd/mdnsd.sock)
  -v, --verbose      list devices with all details (addresses, services)
      --json         print the daemon's reply unchanged
  -h, --help         show this help
```

Options must come before the command. Segment names need no quoting:
`mdnsctl devices IoT to br0` works.

### `mdnsctl segments`

Lists every configured segment once, with its interfaces and the address
families it covers.

```
$ mdnsctl segments
NAME         INTERFACES  FAMILIES
media_stuff  br0, media  v4, v6
IoT          wifi        v4, v6
IoT to br0   br0, wifi   v4, v6
```

### `mdnsctl devices <name>`

Lists the devices **discovered on the segment's own interfaces** (both
families). By default each device is one line: its DNS name, its pretty name
(the name of its services, such as `OZAL Speakers`) and, last, all of its
addresses, IPv4 first. The IPv4 and IPv6 entries of one device are merged into
one line, and devices that have not announced a name yet have no DNS name to
show, so they are only counted. Reflected copies from other segments are not
included.

```
$ mdnsctl devices IoT to br0
IoT to br0: 1 device
  printer.local  Printer  10.0.0.10

(1 device without a name not shown; use -v to list everything)
```

`-v` (`--verbose`) lists everything: interface, family, addresses (routable
first, then link-local) and hostname for every entry, with each device's services underneath (instance, type, port,
target and TXT records), including the devices without a name.

```
$ mdnsctl -v devices IoT to br0
IoT to br0: 2 devices
  br0   v4  10.0.0.10  printer.local
      Printer  _http._tcp.local  :631 -> printer.local  [rp=ipp, ty=hp]
  wifi  v4  10.0.1.7   -
```

A hostname of `-` means the device has been heard but has not announced a name
yet. `--json` always prints the full reply, regardless of `-v`.

### `mdnsctl probe [<name>]`

Actively looks for devices on the interfaces of the named segment, or of every
segment if no name is given. It asks which service types exist, browses each
type for instances, resolves instances that have not yet said where they are,
and asks for the addresses of named devices that have no routable one yet, in
three rounds over about four seconds. It replies once the answers have
been processed, with the number of queries sent on each interface:

```
$ mdnsctl probe IoT
INTERFACE  FAMILY  RESULT
wifi       v4      9 queries sent
wifi       v6      9 queries sent

List what answered with: mdnsctl devices <name>
```

The daemon already probes every interface at startup, and again every
[`Interval`](#probe-optional) if you set one; run this to probe right now, for
example to pick up a device you have just switched on.

### `mdnsctl watch <name>`

Follows a segment and prints each device as it appears, changes and goes, until
you interrupt it. It prints only what happens from then on; `devices` shows what
is there already.

```
$ mdnsctl watch IoT
added    ttl=4500   plug.local  Plug S  10.0.1.9
updated  ttl=4499   plug.local  Plug S  10.0.1.9
removed  ttl=0      plug.local  Plug S  10.0.1.9
```

A line is what happened, the device's `ttl` (the seconds the daemon keeps it if
it is not heard from again, or `0` once it is gone because it said goodbye or ran
out), then the same columns as `devices`. The first time a device is shown with a
name it is `added`, whatever the daemon first called it, and `updated` after
that; devices that have not announced a name are not shown. `-v` prints each
change as `devices -v` would list the device, services included, and shows
unnamed ones too. It exits with status 2 if the daemon stops, and quietly with 0
if its output is closed (`mdnsctl watch IoT | head`).

With `--json` each change is one line of JSON as the daemon sent it, which is
what to build on: react to a device the moment it announces itself, instead of
polling. For example, configure each Shelly plug once as it appears:

```sh
mdnsctl --json watch IoT | jq -r --unbuffered '
    select(.event != "removed" and .ttl > 0)
    | select(any(.device.services[]?; .type == "_shelly._tcp.local"))
    | .device.routable // empty' |
while read -r ip; do configure-plug "$ip"; done
```

A device usually produces several `updated` events as its records arrive, so a
script like that should be idempotent, or remember the addresses it has done.

### `mdnsctl timers`

Lists what the daemon's timer has scheduled, soonest first, for finding out why
something did or did not happen when you expected: each link has one `upkeep`
timer, which expires devices, asks the ones about to expire to answer again, and
re-announces reflected devices (`router.local` included), and it is set to the
earliest of those that is due.

```
$ mdnsctl timers
NAME                               STATE    DUE        RUNS  LAST RUN  TOOK
upkeep br0/V4                      waiting  in 1m 33s  4     3.5s ago  210us
  re-announce router.local                  in 1m 33s
  expire      10.0.0.10                     in 3m 02s
  refresh     OZAL-Speakers.local           now
upkeep wifi/V4                     idle     never      1     8.0s ago  96us
```

Under each timer is everything it is waiting for, soonest first, which is what
it is set to the first of: `expire` a device that has not been heard from,
`refresh` it (ask it to answer again, shortly before that), and `re-announce` a
name this daemon announces. A device that has no name yet is listed by the
address it was heard from.

`STATE` is `running` while its callback runs, `waiting` until `DUE`, and `idle`
when nothing is due (for example, no devices known yet). `DUE` says `now` for
one that is overdue because another callback is still running. `TOOK` is how
long the last run took.

### Exit status

| Code | Meaning                                                              |
|------|----------------------------------------------------------------------|
| `0`  | Success.                                                             |
| `1`  | The daemon answered with an error (for example an unknown segment).  |
| `2`  | Bad command line, or the daemon could not be reached.                |

### Scripting

`--json` prints the daemon's reply as a single line of JSON, ready for `jq`:

```sh
mdnsctl --json segments | jq -r '.segments[].name'
mdnsctl --json devices media_stuff | jq -r '.devices[] | "\(.addr) \(.hostname)"'
```

The protocol behind it is one request per line over the Unix socket, one
line of JSON back, any number of requests per connection:

```sh
printf 'segments\ndevices IoT\n' | ncat -U /run/mdnsd/mdnsd.sock
```

| Request           | Reply                                                                  |
|-------------------|------------------------------------------------------------------------|
| `segments`        | `{"ok":true,"segments":[{"name":"IoT","interfaces":["wifi"],"families":["v4","v6"]}]}` |
| `devices <name>`  | `{"ok":true,"name":"IoT","devices":[{"interface":"wifi","family":"v4","hostname":"tv.local","routable":"10.0.1.7","link_local":null,"services":[{"instance":"Printer._http._tcp.local","type":"_http._tcp.local","port":631,"target":"printer.local","txt":["rp=ipp"]}]}]}` |
| `probe [<name>]`  | `{"ok":true,"probed":[{"interface":"wifi","family":"v4","queries":9,"error":null}]}` (replies after about 4 seconds) |
| `watch <name>`    | `{"ok":true,"name":"IoT","watching":true}`, then until the client hangs up one line per change: `{"event":"added","segment":"IoT","ttl":4500,"device":{…as in devices…}}` (`added`, `updated` or `removed`; `ttl` is 0 when removed) |
| `timers`          | `{"ok":true,"timers":[{"id":1,"name":"upkeep wifi/V4","running":false,"due_in_ms":93000,"runs":4,"last_run_ago_ms":3500,"last_took_us":210}]}` |
| anything wrong    | `{"ok":false,"error":"no such segment: nope"}`                          |

`hostname`, `target`, `routable` and `link_local` are `null` when unknown. In
`timers`, `due_in_ms` is `null` for a timer that is running or has nothing due,
and `last_run_ago_ms` and `last_took_us` are `null` until it has run. Requests over 4 KiB are
refused, and idle connections are closed after 60 seconds.

## Shutdown

On `SIGTERM` or `SIGINT` the daemon sends goodbye packets for every device it
reflected, removes the control socket and exits with status 0, so clients drop
the reflected devices immediately. If the daemon is killed with `SIGKILL` or
crashes, no goodbyes are sent and clients keep the reflected devices until
their records expire (up to 75 minutes).

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).
