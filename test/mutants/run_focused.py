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
                or go test hit its -timeout (a run that consumed its whole budget
                is never scored: a runner PAUSED by a gate harness fires the
                timeout on resume and fails whichever test was running, #19142);
       KILLED   the target test failed (attributed by NAME) and, when the spec
                gives one, its own output contains `expect`;
       KILLED-OTHER  something failed, but not the target as specified;
       SURVIVED nothing in the focused patterns failed.

Every verdict line names the target's own status (pass, fail, skip, absent)
and the cell's UTC start and end, so a cell can be checked against the gate
logs' runner pause windows.
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


def run_pkg(cwd, pkg, pattern, env, wrapper):
    r = subprocess.run(
        ["bash", "scripts/testguard-run.sh", "go", "test", "-count=1", "-json", "-exec", wrapper,
         "-timeout", "120s", "-run", pattern, pkg],
        cwd=cwd, capture_output=True, text=True, env=env)
    fails, passes, skips, marks, out, build, timedout = set(), set(), set(), set(), {}, False, False
    for line in r.stdout.splitlines():
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
            if "test timed out" in o:
                timedout = True
            if t:
                out.setdefault(t.split("/")[0], []).append(o)
        if not t:
            continue
        if a == "fail":
            fails.add(t)
        elif a == "pass":
            passes.add(t)
        elif a == "skip":
            skips.add(t)
    if "[build failed]" in r.stdout or "setup failed" in r.stdout:
        build = True
    if "test timed out" in r.stdout or "test timed out" in r.stderr:
        timedout = True
    return passes, fails, skips, marks, out, build, timedout, r


def main():
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
        raw, timedout = [], False
        started = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
        for pkg, _, pattern in PKGS:
            p, f, sk, mk, o, b, to, r = run_pkg(dst, pkg, pattern, env, wrapper)
            timedout = timedout or to
            passes |= p
            fails |= f
            skips |= sk
            marks |= mk
            out.update(o)
            build = build or b
            last = r if b else last
            raw.append(r.stdout)
        present = {x.split()[2] for x in marks if x.split()[1] == "PRESENT"}
        killers = sorted(t for t in fails if "/" not in t)
        tgt, expect = m["target"], m["expect"]
        tstat = ("fail" if tgt in fails else "skip" if tgt in skips else "pass" if tgt in passes
                 else "absent") if tgt else "-"
        ended = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
        if build:
            verdict = "VOID build failure: " + (last.stdout + last.stderr)[-400:].replace("\n", " | ")
        elif timedout:
            verdict = "VOID go test timed out (a paused runner? check the gate logs for %s-%s UTC)" % (started, ended)
        elif not need <= present:
            verdict = "VOID nonce absent from %s (markers %s)" % (sorted(need - present), sorted(marks))
        elif not passes and not fails:
            verdict = "VOID nothing ran"
        elif not killers and tstat == "skip":
            verdict = "VOID target %s SKIPPED (a privileged cell on an unproven runner?)" % tgt
        elif not killers:
            verdict = "SURVIVED"
        elif tgt and tgt in killers and (not expect or expect in "".join(out.get(tgt, []))):
            verdict = "KILLED by target %s" % tgt
        elif tgt and tgt in killers:
            verdict = "KILLED-OTHER: target %s failed without %r" % (tgt, expect)
        else:
            verdict = "KILLED-OTHER (target %s did not fail)" % (tgt or "-")
        print("== %s: %s [target %s] [killers %s] [nonce in %s] [%s-%s UTC]" % (
            label, verdict, tstat, ",".join(killers) or "-", ",".join(sorted(present)), started, ended), flush=True)
        if not verdict.startswith("KILLED by target"):
            with open(os.path.join(logs, label + ".json"), "w") as fh:
                fh.write("\n".join(raw))
        shutil.rmtree(dst, ignore_errors=True)
    print("### MUTANTS DONE", flush=True)


if __name__ == "__main__":
    sys.exit(main())
