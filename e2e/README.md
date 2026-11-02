# End-to-end tests

`e2e.py` runs a **built** `mdnsd` (and, for some tests, `mdnsctl`) through what
the unit tests cannot reach: interfaces that appear, go away and come back,
addresses and MTUs that change, real sockets and multicast, signals, the
control socket, the avahi socket and the neighbour table. Everything is
checked from outside, as a device on the other end of a link would see it.

```
cargo build --release
python3 e2e/e2e.py --ctl target/release/mdnsctl target/release/mdnsd
```

| Option | |
|---|---|
| `-k PATTERN` | only the tests with this in their name (repeat for more) |
| `-v` | name each test as it runs |
| `--slow` | also the tests that wait on a timer, about a minute (CI does) |
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

A test that waits for something that must *not* happen uses `none(...)`, which
waits a second and a half: keep those few.

## Coverage

`coverage.py` measures what the unit tests and these tests cover together: it
builds the daemon and `mdnsctl` with coverage instrumentation, runs the unit
tests and then this suite against the instrumented binaries (the profile is
written as each daemon exits), and merges them.

```
rustup component add llvm-tools-preview
python3 e2e/coverage.py
```

It writes `target/coverage/report/`: `summary.md` (a table by file),
`summary.json`, `lcov.info`, and `html/`, the source line by line. With
`--baseline summary.json` the table says how the figures moved. CI runs it as
the `coverage` job: the table is in the job's summary, on a pull request in a
comment that is kept up to date and compares with the last run on `master`, and
the report is an artifact.
