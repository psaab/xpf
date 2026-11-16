#!/usr/bin/env python3
"""Focused, build-identity-proved mutation runner for an issue's cells.

Usage (on a test runner, never on the workstation):
    python3 -I test/mutants/run_focused.py --src <tree> --spec test/mutants/19110.tsv \
        [--work /work/<lane>] [--only LABEL[,LABEL...]]

The spec is scripts/mutate.sh's format (see the header of test/mutants/19110.tsv).
Rows sharing a label are one mutant. For each mutant this runner:

  1. copies --src to <work>/mut, without .git;
  2. applies every edit (each `old` must occur exactly once, else VOID);
  3. appends a per-mutant NONCE (a package var read by an init func) to each
     edited Go file;
  4. runs the focused packages with `go test -json -exec <wrapper>`. The wrapper
     greps the exact binary go test is about to run for the nonce and prints
     `XPF-MUTANT-NONCE PRESENT|ABSENT <binary>` on stdout, which go test -json
     carries as an output event. It reports on stdout because testguard's root
     view (#19084) discards files written inside it;
  5. scores:
       VOID     anchor miss, build failure, nothing ran, the nonce is absent
                from a binary that links an edited package (the run did not test
                this mutant), or nothing failed while the TARGET test SKIPPED (a
                privileged cell on a runner without testguard's VM proof,
                /run/xpf-testguard-vm-boot-id, skips: that is not a survival),
                or go test hit its -timeout, or its outer watchdog killed the
                binary ("Test killed with quit: ran too long"): a run that
                consumed its whole budget is never scored. A runner PAUSED by a
                gate harness fires the timeout on resume and fails or kills
                whichever test was running (#19142). Also VOID: a package that
                FAILED with no test-level failure (the binary was killed or
                crashed, so its unrun tests never had a chance to fail), and a
                run in which nothing failed and the TARGET never ran.
                One exception: when the focused run timed out, the TARGET alone
                is re-run in its own package, and that rerun is DECISIVE: the cell
                is KILLED, "confirmed alone", only if the rerun fails the target
                with no timeout, with `expect` (when given) in the target's own
                output, and with the nonce present in the rerun's own binary. The
                verdict line then reports the rerun's target status, nonce and
                window, and its output is saved. A mutant that makes some OTHER
                cell hang must not VOID its own target's kill;
       KILLED   the target test failed (attributed by NAME) and, when the spec
                gives one, its own output contains `expect`;
       KILLED-OTHER  something failed, but not the target as specified;
       SURVIVED nothing in the focused patterns failed.

`--selftest` runs the scoring on fixture event streams, among them the M8
shape seen on 2026-11-16: a paused runner, the watchdog's "ran too long" kill,
a package FAIL with no test failure, and an absent target, which the runner
before that fix scored SURVIVED. It needs no go toolchain.

Every verdict line names the target's own status (pass, fail, skip, absent)
and the cell's UTC start and end, so a cell can be checked against the gate
logs' runner pause windows. When a decisive rerun ran, those trailing fields
are prefixed "initial run:" (they describe the focused run that timed out),
and the rerun's own status, binary and window are in the verdict text.
The raw `go test -json` output of every cell that is not KILLED is saved under
<work>/logs/<label>.json for diagnosis.

M00 is a baseline: the nonce only, no mutation. It must SURVIVE with the nonce
present in every binary, or the run's instrument is broken.
"""
import argparse
import datetime
import json
import os
import secrets
import shutil
import subprocess
import sys

PKGS = [
    ("./pkg/dataplane/", "dataplane.test", "19110|9847"),
    ("./pkg/dataplane/userspace/", "userspace.test", "19110|16730|13301|14133"),
]
USERSPACE = "pkg/dataplane/userspace/"

WRAPPER = """#!/bin/sh
bin="$1"
if grep -qaF "$XPF_MUTANT_NONCE" "$bin"; then echo "XPF-MUTANT-NONCE PRESENT $(basename "$bin")"
else echo "XPF-MUTANT-NONCE ABSENT $(basename "$bin")"; fi
exec "$@"
"""


def unescape(s):
    return s.encode().decode("unicode_escape")


def load_spec(path):
    muts = {}
    for line in open(path):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        f = line.split("\t")
        while len(f) < 6:
            f.append("")
        label, file, old, new, target, expect = f[:6]
        m = muts.setdefault(label, {"edits": [], "target": target, "expect": expect})
        m["edits"].append((file, unescape(old), unescape(new)))
    return muts


# go test's own -timeout panic, and its outer watchdog's kill of a binary that
# outlived -timeout plus its grace (what a gate's runner pause produces).
TIMEOUT_MARKERS = ("test timed out", "ran too long", "Test killed with quit")


def timed_out(text):
    return any(x in text for x in TIMEOUT_MARKERS)


def run_pkg(cwd, pkg, pattern, env, wrapper):
    r = subprocess.run(
        ["bash", "scripts/testguard-run.sh", "go", "test", "-count=1", "-json", "-exec", wrapper,
         "-timeout", "120s", "-run", pattern, pkg],
        cwd=cwd, capture_output=True, text=True, env=env)
    return parse_events(r.stdout, r.stderr) + (r,)


def parse_events(stdout, stderr):
    """Pure: one go test -json stream to (passes, fails, skips, nonce marks,
    per-test output, build failed, timed out, package failed)."""
    fails, passes, skips, marks, out, build, timedout = set(), set(), set(), set(), {}, False, False
    pkgfail = False
    for line in stdout.splitlines():
        try:
            ev = json.loads(line)
        except ValueError:
            if line.startswith("XPF-MUTANT-NONCE "):
                marks.add(line.strip())
            continue
        t, a, o = ev.get("Test"), ev.get("Action"), ev.get("Output", "")
        if a == "output":
            if o.startswith("XPF-MUTANT-NONCE "):
                marks.add(o.strip())
            if "build failed" in o:
                build = True
            if timed_out(o):
                timedout = True
            if t:
                out.setdefault(t.split("/")[0], []).append(o)
        if not t:
            pkgfail = pkgfail or a == "fail"
            continue
        if a == "fail":
            fails.add(t)
        elif a == "pass":
            passes.add(t)
        elif a == "skip":
            skips.add(t)
    if "[build failed]" in stdout or "setup failed" in stdout:
        build = True
    if timed_out(stdout) or timed_out(stderr):
        timedout = True
    return passes, fails, skips, marks, out, build, timedout, pkgfail


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")


def confirm_alone(dst, tgt, expect, env, wrapper):
    """Re-run only the target, in the package that has it. Returns the rerun's
    own evidence: killed (the target FAILED with no timeout, no build failure,
    and expect in its own output when given), its status, the binary it ran
    in, the nonce markers of that run, its window and its raw output."""
    out = {"killed": False, "status": "absent", "binary": "", "present": set(),
           "started": utcnow(), "ended": "", "raw": ""}
    for pkg, binary, _ in PKGS:
        p, f, sk, mk, o, b, to, pf, r = run_pkg(dst, pkg, "^" + tgt + "$", env, wrapper)
        if tgt not in p | f | sk and not b and not to and not pf:
            continue  # not this package
        out["binary"], out["raw"] = binary, r.stdout + r.stderr
        out["present"] = {x.split()[2] for x in mk if x.split()[1] == "PRESENT"}
        out["status"] = "fail" if tgt in f else "skip" if tgt in sk else "pass" if tgt in p else "absent"
        out["killed"] = (not b and not to and tgt in f and
                         (not expect or expect in "".join(o.get(tgt, []))))
        break
    out["ended"] = utcnow()
    return out


def score(*, build_tail, timedout, conf, need, present, marks, passes, fails, skips, pkgfail, out, tgt, expect,
          started, ended):
    """Pure: one cell's verdict. conf is the decisive rerun's evidence (None
    when there was none)."""
    killers = sorted(t for t in fails if "/" not in t)
    tstat = ("fail" if tgt in fails else "skip" if tgt in skips else "pass" if tgt in passes
             else "absent") if tgt else "-"
    if build_tail is not None:
        return "VOID build failure: " + build_tail, tstat, killers
    if timedout and conf and conf["killed"] and conf["binary"] in need and conf["binary"] in conf["present"]:
        return ("KILLED by target %s (confirmed alone, decisive rerun: target %s, nonce in %s, %s-%s UTC; "
                "the focused run timed out on another test)" % (
                    tgt, conf["status"], conf["binary"], conf["started"], conf["ended"])), tstat, killers
    if timedout:
        return ("VOID go test timed out or its watchdog killed the binary (a paused runner? check the gate "
                "logs for %s-%s UTC)" % (started, ended)), tstat, killers
    if not need <= present:
        return "VOID nonce absent from %s (markers %s)" % (sorted(need - present), sorted(marks)), tstat, killers
    if not passes and not fails:
        return "VOID nothing ran", tstat, killers
    if pkgfail and not killers:
        return "VOID a package FAILED with no test-level failure (the binary was killed or crashed)", tstat, killers
    if not killers and tstat == "skip":
        return "VOID target %s SKIPPED (a privileged cell on an unproven runner?)" % tgt, tstat, killers
    if not killers and tstat == "absent":
        return "VOID target %s never ran" % tgt, tstat, killers
    if not killers:
        return "SURVIVED", tstat, killers
    if tgt and tgt in killers and (not expect or expect in "".join(out.get(tgt, []))):
        return "KILLED by target %s" % tgt, tstat, killers
    if tgt and tgt in killers:
        return "KILLED-OTHER: target %s failed without %r" % (tgt, expect), tstat, killers
    return "KILLED-OTHER (target %s did not fail)" % (tgt or "-"), tstat, killers


def selftest():
    """Fixture streams through parse_events and score. Exit 1 on any miss."""
    def ev(*rows):
        return "\n".join(json.dumps(r) for r in rows)
    T, P = "TestTarget", "github.com/psaab/xpf/pkg/dataplane"
    nonce = {"Action": "output", "Package": P, "Output": "XPF-MUTANT-NONCE PRESENT dataplane.test\n"}
    m8_hung = [nonce, {"Action": "run", "Test": "TestOther"}, {"Action": "pass", "Test": "TestEarlier"},
               {"Action": "output", "Test": "TestOther", "Output": "*** Test killed with quit: ran too long (3m0s).\n"},
               {"Action": "output", "Package": P, "Output": "FAIL\t" + P + "\t226.565s\n"},
               {"Action": "fail", "Package": P, "Elapsed": 226.5}]
    m8_bare = [r for r in m8_hung if "ran too long" not in r.get("Output", "")]
    cases = [
        ("M8 shape: watchdog kill, target absent", ev(*m8_hung), "", None, "VOID go test timed out"),
        ("package FAIL, no test failure, no marker", ev(*m8_bare), "", None, "VOID a package FAILED"),
        ("go test -timeout panic", ev(nonce, {"Action": "pass", "Test": "TestEarlier"},
                                      {"Action": "output", "Test": "TestOther",
                                       "Output": "panic: test timed out after 2m0s\n"}), "", None, "VOID go test timed out"),
        ("nothing failed, target never ran", ev(nonce, {"Action": "pass", "Test": "TestEarlier"},
                                                {"Action": "pass", "Package": P}), "", None, "VOID target"),
        ("target skipped", ev(nonce, {"Action": "pass", "Test": "TestEarlier"}, {"Action": "skip", "Test": T}),
         "", None, "VOID target"),
        ("target passed", ev(nonce, {"Action": "pass", "Test": T}), "", None, "SURVIVED"),
        ("target killed", ev(nonce, {"Action": "output", "Test": T, "Output": "want X\n"},
                             {"Action": "fail", "Test": T}, {"Action": "fail", "Package": P}), "", None, "KILLED by target"),
        ("target failed without expect", ev(nonce, {"Action": "fail", "Test": T}), "", "want X", "KILLED-OTHER"),
        ("nonce absent", ev({"Action": "output", "Package": P, "Output": "XPF-MUTANT-NONCE ABSENT dataplane.test\n"},
                            {"Action": "fail", "Test": T}), "", None, "VOID nonce absent"),
    ]
    bad = 0
    for name, stdout, stderr, expect, want in cases:
        p, f, sk, mk, o, b, to, pf = parse_events(stdout, stderr)
        present = {x.split()[2] for x in mk if x.split()[1] == "PRESENT"}
        v, _, _ = score(build_tail=None if not b else "", timedout=to, conf=None, need={"dataplane.test"},
                        present=present, marks=mk, passes=p, fails=f, skips=sk, pkgfail=pf, out=o, tgt=T,
                        expect=expect or "", started="-", ended="-")
        ok = v.startswith(want)
        bad += not ok
        print("%s %s: %s" % ("ok  " if ok else "FAIL", name, v))
    # The decisive rerun: KILLED only with the nonce in the rerun's own binary.
    for name, present, want in (("decisive rerun with its nonce", {"dataplane.test"}, "KILLED by target"),
                                ("decisive rerun without its nonce", set(), "VOID go test timed out")):
        conf = {"killed": True, "status": "fail", "binary": "dataplane.test", "present": present,
                "started": "-", "ended": "-"}
        v, _, _ = score(build_tail=None, timedout=True, conf=conf, need={"dataplane.test"}, present=present,
                        marks=set(), passes=set(), fails=set(), skips=set(), pkgfail=True, out={}, tgt=T,
                        expect="", started="-", ended="-")
        ok = v.startswith(want)
        bad += not ok
        print("%s %s: %s" % ("ok  " if ok else "FAIL", name, v))
    print("SELFTEST %s" % ("PASS" if not bad else "FAIL (%d)" % bad))
    return 1 if bad else 0


def main():
    if sys.argv[1:] == ["--selftest"]:
        return selftest()
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--spec", required=True)
    ap.add_argument("--work", default="/work/mutants-focused")
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    muts = load_spec(a.spec)
    order = ["M00-baseline-nonce-only"] + list(muts)
    muts["M00-baseline-nonce-only"] = {"edits": [], "target": "", "expect": ""}
    only = set(x for x in a.only.split(",") if x)
    os.makedirs(a.work, exist_ok=True)
    logs = os.path.join(a.work, "logs")
    os.makedirs(logs, exist_ok=True)
    if not os.path.isfile("/run/xpf-testguard-vm-boot-id"):
        print("WARNING: no testguard VM proof (/run/xpf-testguard-vm-boot-id) on this runner: privileged "
              "cells will SKIP, and a cell whose target skips is VOID, not survived", flush=True)
    wrapper = os.path.join(a.work, "nonce-exec.sh")
    open(wrapper, "w").write(WRAPPER)
    os.chmod(wrapper, 0o755)
    os.makedirs("/wtgt", exist_ok=True)
    base_env = dict(os.environ, TMPDIR="/wtgt", GOTMPDIR="/wtgt", XPF_REQUIRE_MEMLOCK_GUARDS="1")
    for idx, label in enumerate(order):
        if only and label not in only and not label.startswith("M00"):
            continue
        m = muts[label]
        dst = os.path.join(a.work, "mut")
        shutil.rmtree(dst, ignore_errors=True)
        shutil.copytree(a.src, dst, symlinks=True, ignore=shutil.ignore_patterns(".git"))
        void, files = None, []
        for path, old, new in m["edits"]:
            p = os.path.join(dst, path)
            s = open(p).read()
            if s.count(old) != 1:
                void = "anchor miss %s n=%d" % (path, s.count(old))
                break
            open(p, "w").write(s.replace(old, new))
            if path not in files:
                files.append(path)
        if void:
            print("== %s: VOID %s" % (label, void), flush=True)
            continue
        if not files:
            files = ["pkg/dataplane/xdp_attach_occupancy_19110.go"]
        nonce = "XPFMUT%03d%s" % (idx, secrets.token_hex(8))
        for k, path in enumerate(files):
            with open(os.path.join(dst, path), "a") as fh:
                fh.write('\n// mutant build-identity nonce (test/mutants/run_focused.py)\n'
                         'var mutantNonce_%d = "%s"\n\nvar mutantNonceSink_%d string\n\n'
                         'func init() { mutantNonceSink_%d = mutantNonce_%d }\n' % (k, nonce, k, k, k))
        need = {"userspace.test"}
        if any(not p.startswith(USERSPACE) for p in files):
            need.add("dataplane.test")
        env = dict(base_env, XPF_MUTANT_NONCE=nonce)
        fails, passes, skips, marks, out, build, last = set(), set(), set(), set(), {}, False, None
        raw, timedout, pkgfail = [], False, False
        started = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
        for pkg, _, pattern in PKGS:
            p, f, sk, mk, o, b, to, pf, r = run_pkg(dst, pkg, pattern, env, wrapper)
            timedout = timedout or to
            pkgfail = pkgfail or pf
            passes |= p
            fails |= f
            skips |= sk
            marks |= mk
            out.update(o)
            build = build or b
            last = r if b else last
            raw.append(r.stdout)
        present = {x.split()[2] for x in marks if x.split()[1] == "PRESENT"}
        tgt, expect = m["target"], m["expect"]
        ended = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
        conf = None
        if not build and timedout and tgt:
            conf = confirm_alone(dst, tgt, expect, env, wrapper)
            raw.append("== DECISIVE RERUN ==\n" + conf["raw"])
        verdict, tstat, killers = score(
            build_tail=(last.stdout + last.stderr)[-400:].replace("\n", " | ") if build else None,
            timedout=timedout, conf=conf, need=need, present=present, marks=marks, passes=passes, fails=fails,
            skips=skips, pkgfail=pkgfail, out=out, tgt=tgt, expect=expect, started=started, ended=ended)
        # After a decisive rerun the verdict's parenthetical is the rerun's
        # evidence; these fields stay the INITIAL focused run's, and say so.
        ini = "initial run: " if conf is not None else ""
        print("== %s: %s [%starget %s] [%skillers %s] [%snonce in %s] [%s%s-%s UTC]" % (
            label, verdict, ini, tstat, ini, ",".join(killers) or "-", ini, ",".join(sorted(present)), ini,
            started, ended), flush=True)
        if not verdict.startswith("KILLED by target") or "confirmed alone" in verdict:
            with open(os.path.join(logs, label + ".json"), "w") as fh:
                fh.write("\n".join(raw))
        shutil.rmtree(dst, ignore_errors=True)
    print("### MUTANTS DONE", flush=True)


if __name__ == "__main__":
    sys.exit(main())
