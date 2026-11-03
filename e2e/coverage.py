#!/usr/bin/env python3
"""Measure what the unit tests and the end-to-end tests cover of the daemon.

The steps, which CI runs as jobs of their own, one after another:

    coverage.py build  --out BIN                  build, with instrumentation
    coverage.py unit   --binaries BIN --out PROF  run the unit tests from it
    coverage.py e2e    --binaries BIN --out PROF  run the end-to-end tests on it
                       [--logs DIR]
    coverage.py report --binaries BIN --profiles PROF... --out REPORT
                                                  merge the profiles, report

`build` makes the daemon, `mdnsctl` and the unit tests' executables, once, for
everything after it to use: what a profile says is about the binary that wrote
it. `unit` and `e2e` run those, and keep what they recorded. `report` merges
the profiles of any number of runs, and writes to REPORT:

    summary.md    a table by file, to read; with --baseline, how it moved
    summary.json  the same figures, to compare against later
    lcov.info     for tools that read lcov
    html/         the source, line by line

With no step, `all` does them in turn here, in target/coverage.

Needs the LLVM tools of the compiler to report: `rustup component add
llvm-tools-preview` (or `llvm-cov` and `llvm-profdata` on the PATH, or LLVM_COV
and LLVM_PROFDATA). Report from a checkout of the source that was built, at the
same path: the source is read from where it was when it was built. In a GitHub
Actions job, the summary is also written to the job's summary.

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


def absolute(path):
    return os.path.abspath(path)


def make_executable(paths):
    # An artifact does not keep what a file may do.
    for p in paths:
        os.chmod(p, os.stat(p).st_mode | 0o111)


# ---------------------------------------------------------------- the steps

def build(out):
    """The binaries everything else uses, built to record what they run."""
    target = os.path.join(ROOT, "target", "coverage")
    env = dict(os.environ, CARGO_TARGET_DIR=target)
    env["RUSTFLAGS"] = (env.get("RUSTFLAGS", "") + " -C instrument-coverage").strip()
    # The daemon has a clock the end-to-end tests move, so that they do not wait
    # for a timer; the unit tests are of the code without it.
    run(["cargo", "build", "--locked", "--features", "test-clock"], env)
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
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(os.path.join(out, "tests"))
    for name in ("mdnsd", "mdnsctl"):
        shutil.copy(os.path.join(target, "debug", name), os.path.join(out, name))
    for t in tests:
        shutil.copy(t, os.path.join(out, "tests", os.path.basename(t)))
    print(f"built {len(tests)} test executables and the binaries in {out}")


def profile_env(out):
    os.makedirs(out, exist_ok=True)
    return dict(os.environ, LLVM_PROFILE_FILE=os.path.join(absolute(out), "%p-%m.profraw"))


def unit(binaries, out):
    tests = sorted(glob.glob(os.path.join(binaries, "tests", "*")))
    if not tests:
        sys.exit(f"no unit tests in {binaries}/tests: coverage.py build first")
    make_executable(tests)
    env = profile_env(out)
    for t in tests:
        run([absolute(t)], env)


def e2e(binaries, out, logs=None):
    mdnsd, mdnsctl = absolute(os.path.join(binaries, "mdnsd")), absolute(os.path.join(binaries, "mdnsctl"))
    make_executable([mdnsd, mdnsctl])
    cmd = [sys.executable, os.path.join(ROOT, "e2e", "e2e.py"), "--ctl", mdnsctl, mdnsd]
    if logs:
        cmd[2:2] = ["--logs", absolute(logs)]
    # Where user namespaces are forbidden, as root.
    unshare = ["unshare", "-n"] if os.geteuid() == 0 else ["unshare", "-r", "-n"]
    if os.geteuid() != 0 and subprocess.run(unshare + ["true"], stderr=subprocess.DEVNULL).returncode:
        cmd = ["sudo", "-E"] + cmd
    # The profile is written as each daemon exits, and the environment goes on to it.
    run(cmd, profile_env(out))


def report(binaries, profiles, out, baseline_path=None):
    profdata, cov = llvm_tool("llvm-profdata"), llvm_tool("llvm-cov")
    raw = [f for d in profiles for f in glob.glob(os.path.join(d, "*.profraw"))]
    if not raw:
        sys.exit("no profiles to report on: " + ", ".join(profiles))
    exes = [os.path.join(binaries, n) for n in ("mdnsd", "mdnsctl")] + sorted(glob.glob(os.path.join(binaries, "tests", "*")))
    merged = os.path.join(os.path.dirname(absolute(out)), "all.profdata")
    os.makedirs(os.path.dirname(merged), exist_ok=True)
    run([profdata, "merge", "-sparse", *raw, "-o", merged])
    objects = []
    for exe in exes:
        objects += [absolute(exe)] if not objects else ["-object", absolute(exe)]
    common = [f"--instr-profile={merged}", f"--ignore-filename-regex={IGNORE}", *objects]

    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    exported = subprocess.run([cov, "export", "-summary-only", *common], cwd=ROOT, stdout=subprocess.PIPE, text=True, check=True).stdout
    data = json.loads(exported)["data"][0]
    files = {}
    for f in data["files"]:
        path = f["filename"]
        path = path[len(ROOT) + 1:] if path.startswith(ROOT + os.sep) else path
        files[path] = {k: f["summary"][k] for k in ("lines", "functions", "regions")}
    summary = {"files": files, "totals": {k: data["totals"][k] for k in ("lines", "functions", "regions")}}
    with open(os.path.join(out, "summary.json"), "w") as f:
        json.dump(summary, f, indent=1)
    with open(os.path.join(out, "lcov.info"), "w") as f:
        subprocess.run([cov, "export", "-format=lcov", *common], cwd=ROOT, stdout=f, check=True)
    run([cov, "show", "-format=html", f"-output-dir={os.path.join(out, 'html')}", "-show-line-counts-or-regions", *common], stdout=subprocess.DEVNULL)

    baseline = None
    if baseline_path and os.path.exists(baseline_path):
        with open(baseline_path) as f:
            baseline = json.load(f)
    text = markdown(summary, baseline)
    with open(os.path.join(out, "summary.md"), "w") as f:
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


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="step")
    b = sub.add_parser("build", help="build the binaries, instrumented")
    b.add_argument("--out", required=True)
    u = sub.add_parser("unit", help="run the unit tests, and keep their profile")
    u.add_argument("--binaries", required=True)
    u.add_argument("--out", required=True)
    e = sub.add_parser("e2e", help="run the end-to-end tests, and keep their profile")
    e.add_argument("--binaries", required=True)
    e.add_argument("--out", required=True)
    e.add_argument("--logs", help="keep the daemon's log of each test here")
    r = sub.add_parser("report", help="merge profiles and report")
    r.add_argument("--binaries", required=True)
    r.add_argument("--profiles", nargs="+", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--baseline", help="a summary.json of before, to say how the figures moved")
    a = sub.add_parser("all", help="every step, here")
    a.add_argument("--baseline")
    a.add_argument("--out", default=os.path.join(ROOT, "target", "coverage", "report"))
    args = p.parse_args()

    if args.step == "build":
        build(args.out)
    elif args.step == "unit":
        unit(args.binaries, args.out)
    elif args.step == "e2e":
        e2e(args.binaries, args.out, args.logs)
    elif args.step == "report":
        report(args.binaries, args.profiles, args.out, args.baseline)
    else:
        work = os.path.join(ROOT, "target", "coverage")
        binaries, unit_prof, e2e_prof = (os.path.join(work, d) for d in ("bin", "prof-unit", "prof-e2e"))
        for d in (unit_prof, e2e_prof):
            shutil.rmtree(d, ignore_errors=True)
        build(binaries)
        unit(binaries, unit_prof)
        e2e(binaries, e2e_prof)
        out = getattr(args, "out", os.path.join(work, "report"))
        report(binaries, [unit_prof, e2e_prof], out, getattr(args, "baseline", None))


if __name__ == "__main__":
    main()
