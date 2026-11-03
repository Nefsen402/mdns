# End-to-end tests

`e2e.py` runs a **built** `mdnsd` (and, for some tests, `mdnsctl`) through what
the unit tests cannot reach: interfaces that appear, go away and come back,
addresses and MTUs that change, real sockets and multicast, signals, the
control socket, the avahi socket and the neighbour table. Everything is
checked from outside, as a device on the other end of a link would see it.

```
cargo build --features test-clock
python3 e2e/e2e.py --ctl target/debug/mdnsctl target/debug/mdnsd
```

The daemon is built with `test-clock`, a clock of its own that the tests move
forward (see below), so that nothing waits for a timer: the whole suite runs in
a few seconds. A daemon without it runs the tests that do not need the clock and
skips the others.

The BSDs cannot pin a socket to an interface, so there is one for each family,
shared by every interface. The same tests run on a daemon built that way, on
Linux, with `--features portable-sockets,test-clock`, and CI runs both. What is
particular to a BSD, such as how it says which interface a datagram came in on,
is not run here.

| Option | |
|---|---|
| `-k PATTERN` | only the tests with this in their name (repeat for more) |
| `-v` | name each test as it runs |
| `--logs DIR` | keep the daemon's log of each test in `DIR` |
| `--list` | list the tests |

It needs `ip`, `unshare` and `nsenter` and no privileges: each test makes a
network namespace for the router, which the daemon runs in, and veth pairs
from it to the namespace the test is in, where the devices are, inside a user
and network namespace of the harness's own (as the fuzzer and the benchmark
do). As root it makes a network namespace only. Where the system forbids
unprivileged user namespaces (recent Ubuntu), run it as root, or allow them:

```
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

## Writing a test

`lab.py` has the pieces: `Lab` (the router's namespace; `lab.link(...)` makes
an interface of it and the far end, `lab.router(...)` runs a command there),
`Link.hearer()` (what is heard on the link, with `wait` for a message that
matches), `Link.device(addr)` (a device to send and be sent to), `Daemon`
(`wait_log`, `request`, `ctl`, `stop`), and DNS to build and parse messages.
Scenarios are in `tests.py`.

Nothing in the lab sleeps, and nothing waits for a timer. Waits are for what
happens: `wait` on a hearer or the daemon's log is woken by each packet or line,
and the time it is given is how long a test has to fail.

**The clock.** The daemon built with `--features test-clock` has a monotonic
clock that is at a fixed time when it starts, and moves only when `Daemon.advance(seconds)`
(the control socket's `advance <milliseconds>`) says, by exactly that much. It
does not wait for a timer, so what the daemon does after a delay of its own, an
announcement again a second on, a question asked a quarter of the way into a
TTL, a probe's rounds, is done when the clock is moved past it:
`Daemon.advance_until(condition)` moves it on a step at a time until the
condition is so. A request waits on the daemon's clock, not the test's.
(`mdnsctl --wait` is mdnsctl's own time: give it a millisecond.)

**Nothing heard.** A negative check does not wait to be sure: the daemon handles
what has come to its sockets, then the interface changes the kernel told it of,
then requests, so `Daemon.settle()`, a request, returns once everything sent
before it has been done, and `Hearer.none(...)` looks at what has come by then.
Make the daemon do what must not be heard of, `settle`, then `none`.

## Coverage

`coverage.py` measures what the unit tests and these tests cover together. A
profile says what ran of the binary that wrote it, so the binaries are built
once, with coverage instrumentation, and everything else runs those:

```
rustup component add llvm-tools-preview
python3 e2e/coverage.py                                   # all of it, here

python3 e2e/coverage.py build  --out bin                  # or one step at a time
python3 e2e/coverage.py unit   --binaries bin --out prof-unit
python3 e2e/coverage.py e2e    --binaries bin --out prof-e2e
python3 e2e/coverage.py e2e    --binaries bin --out prof-e2e-portable --sockets portable
python3 e2e/coverage.py report --binaries bin --profiles prof-unit prof-e2e prof-e2e-portable --out report
```

`report` merges the profiles of any number of runs, and writes `summary.md` (a
table by file), `summary.json`, `lcov.info`, and `html/`, the source line by
line. With `--baseline summary.json` the table says how the figures moved.
Report from a checkout of the source that was built, at the same path.

CI runs the steps as jobs: `build` once, `test` and `e2e` in parallel on its
binaries (`e2e` once for each form of the sockets), each keeping its profile, then `coverage`, which runs no test but
merges the profiles. The table is in the job's summary, on a pull request in a
comment that is kept up to date and compares with the last run on `master`, and
the report is an artifact.
