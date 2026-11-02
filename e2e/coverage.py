#!/usr/bin/env python3
"""Measure what the unit tests and the end-to-end tests cover of the daemon.

    coverage.py [--out DIR] [--baseline SUMMARY.json] [--no-slow]

Builds the daemon and `mdnsctl` with coverage instrumentation, runs the unit
tests and then the end-to-end tests (e2e.py) against the instrumented
binaries, merges what they recorded, and writes to DIR (default
target/coverage/report):

    summary.md    a table by file, to read; with --baseline, how it moved
    summary.json  the same figures, to compare against later
    lcov.info     for tools that read lcov
    html/         the source, line by line

Needs the LLVM tools of the compiler: `rustup component add llvm-tools-preview`
(or `llvm-cov` and `llvm-profdata` on the PATH, or LLVM_COV and LLVM_PROFDATA).
In a GitHub Actions job, the summary is also written to the job's summary.

The test code in each file counts, as covered: read the figures as a little
flattering.
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
IGNORE = r"/\.cargo/|/rustc/|/registry/|/usr/src/|/rustlib/"


def run(cmd, env=None, check=True, **kw):
    print("+ " + " ".join(cmd), flush=True)
    r = subprocess.run(cmd, cwd=ROOT, env=env, **kw)
    if check and r.returncode:
        sys.exit(f"failed ({r.returncode}): {' '.join(cmd)}")
    return r


def llvm_tool(name):
    """`llvm-cov` or `llvm-profdata`: from the environment, the compiler's own
    (which is what reads what it wrote), or the PATH."""
    given = os.environ.get(name.upper().replace("-", "_"))
    if given:
        return given
    sysroot = subprocess.run(["rustc", "--print", "sysroot"], capture_output=True, text=True).stdout.strip()
    host = next((l.split()[1] for l in subprocess.run(["rustc", "-vV"], capture_output=True, text=True).stdout.splitlines() if l.startswith("host:")), "")
    for candidate in (f"{sysroot}/lib/rustlib/{host}/bin/{name}", shutil.which(name)):
        if candidate and os.path.exists(candidate):
            return candidate
    sys.exit(f"no {name}: rustup component add llvm-tools-preview")


def pct(x):
    return f"{x:.1f}%"


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--out", default=os.path.join(ROOT, "target", "coverage", "report"))
    p.add_argument("--baseline", help="a summary.json of before, to say how the figures moved")
    p.add_argument("--no-slow", action="store_true", help="leave out the end-to-end tests that wait on a timer")
    args = p.parse_args()

    profdata, cov = llvm_tool("llvm-profdata"), llvm_tool("llvm-cov")
    target = os.path.join(ROOT, "target", "coverage")
    prof = os.path.join(target, "prof")
    shutil.rmtree(prof, ignore_errors=True)
    os.makedirs(prof)
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = target
    env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C instrument-coverage").strip()
    env["LLVM_PROFILE_FILE"] = os.path.join(prof, "%p-%m.profraw")

    # The daemon and the client, and the unit tests of each.
    run(["cargo", "build", "--locked"], env)
    built = subprocess.run(
        ["cargo", "test", "--locked", "--no-run", "--message-format=json"], cwd=ROOT, env=env, stdout=subprocess.PIPE, text=True, check=True
    )
    tests = []
    for line in built.stdout.splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("reason") == "compiler-artifact" and m.get("executable") and m["profile"]["test"]:
            tests.append(m["executable"])
    for t in tests:
        run([t], env)

    # The end-to-end tests, against the instrumented binaries: the profile is
    # written as each daemon exits, and the environment goes on to it.
    mdnsd, mdnsctl = os.path.join(target, "debug", "mdnsd"), os.path.join(target, "debug", "mdnsctl")
    e2e = [sys.executable, os.path.join(ROOT, "e2e", "e2e.py"), "--ctl", mdnsctl, mdnsd]
    if not args.no_slow:
        e2e.insert(2, "--slow")
    # Where user namespaces are forbidden, as root.
    unshare = ["unshare", "-n"] if os.geteuid() == 0 else ["unshare", "-r", "-n"]
    if subprocess.run(unshare + ["true"], stderr=subprocess.DEVNULL).returncode and os.geteuid() != 0:
        e2e = ["sudo", "-E"] + e2e
    run(e2e, env)

    # Merge, and report on the binaries the tests ran and the ones they ran.
    merged = os.path.join(target, "all.profdata")
    run([profdata, "merge", "-sparse", *glob.glob(os.path.join(prof, "*.profraw")), "-o", merged])
    objects = []
    for exe in tests + [mdnsd, mdnsctl]:
        objects += [exe] if not objects else ["-object", exe]
    common = [f"--instr-profile={merged}", f"--ignore-filename-regex={IGNORE}", *objects]

    shutil.rmtree(args.out, ignore_errors=True)
    os.makedirs(args.out)
    exported = subprocess.run([cov, "export", "-summary-only", *common], cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True).stdout
    data = json.loads(exported)["data"][0]
    files = {}
    for f in data["files"]:
        path = f["filename"]
        path = path[len(ROOT) + 1:] if path.startswith(ROOT + os.sep) else path
        files[path] = {k: f["summary"][k] for k in ("lines", "functions", "regions")}
    summary = {"files": files, "totals": {k: data["totals"][k] for k in ("lines", "functions", "regions")}}
    with open(os.path.join(args.out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)
    with open(os.path.join(args.out, "lcov.info"), "w") as f:
        subprocess.run([cov, "export", "-format=lcov", *common], cwd=ROOT, stdout=f, check=True)
    run([cov, "show", "-format=html", f"-output-dir={os.path.join(args.out, 'html')}", "-show-line-counts-or-regions", *common], stdout=subprocess.DEVNULL)

    baseline = None
    if args.baseline and os.path.exists(args.baseline):
        with open(args.baseline) as f:
            baseline = json.load(f)
    text = markdown(summary, baseline)
    with open(os.path.join(args.out, "summary.md"), "w") as f:
        f.write(text)
    print("\n" + text)
    step = os.environ.get("GITHUB_STEP_SUMMARY")
    if step:
        with open(step, "a") as f:
            f.write(text)


def delta(now, before):
    if before is None:
        return ""
    d = now - before
    return " (=)" if abs(d) < 0.05 else f" ({d:+.1f})"


def markdown(summary, baseline):
    lines = ["### Coverage", ""]
    t = summary["totals"]
    b = baseline["totals"] if baseline else {}
    lines.append(
        f"**Lines {pct(t['lines']['percent'])}{delta(t['lines']['percent'], b.get('lines', {}).get('percent'))}**"
        f" ({t['lines']['covered']} of {t['lines']['count']}) · "
        f"functions {pct(t['functions']['percent'])} · regions {pct(t['regions']['percent'])}"
    )
    lines += ["", "The unit tests and the end-to-end tests together, on a debug build.", ""]
    lines += ["| File | Lines | Covered | Functions | Regions |", "|---|--:|--:|--:|--:|"]
    old = baseline["files"] if baseline else {}
    for path, s in sorted(summary["files"].items(), key=lambda kv: (kv[1]["lines"]["percent"], kv[0])):
        before = old.get(path, {}).get("lines", {}).get("percent") if baseline else None
        lines.append(
            f"| `{path}` | {pct(s['lines']['percent'])}{delta(s['lines']['percent'], before)} "
            f"| {s['lines']['covered']}/{s['lines']['count']} | {pct(s['functions']['percent'])} | {pct(s['regions']['percent'])} |"
        )
    lines += ["", "<sub>Test code in each file counts as covered, so the figures are a little flattering.</sub>", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
