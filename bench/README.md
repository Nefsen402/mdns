# Measuring the daemon

`bench.py` measures a built `mdnsd` from outside, over the network, so the same
script compares any two versions: memory per device, the CPU it takes to learn
and reflect devices, and how long one more device takes to be reflected with
many already there.

```
cargo build --release
python3 bench/bench.py target/release/mdnsd 100 300 600 900
```

To compare versions, build each in a checkout of its own:

```
git worktree add /tmp/old COMMIT
(cd /tmp/old && cargo build --release)
python3 bench/bench.py /tmp/old/target/release/mdnsd 600
```

It needs `ip` and `unshare` and no privileges: it makes its own user and
network namespaces, like the [fuzzer](../fuzz). Every figure is for a
loopback pair of veth interfaces and synthetic devices, so read them for how
they change with the number of devices, not as times on a real network.

The unit tests have measurements of their own, for the pieces of the daemon
(`cargo test --release scale -- --ignored --nocapture --test-threads=1`, and
`reflecting_one_more`); they are in `src/segment.rs` and `src/reflector.rs`.
