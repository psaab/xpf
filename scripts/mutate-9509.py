#!/usr/bin/env python3
"""#9509 mutation matrix: Go-only (pkg/vrrp), whole package per run.

Discipline:
  - APPLIED is proven by count. A move mutant is two edits, each counted.
  - Every run is bounded. A timeout panic or overrun is VOID(hang).
  - Real ENOSPC only: lines containing "injected:" are excluded.
  - A build failure is VOID(build).
  - At least MIN_GO tests must execute, and the target cells must EXECUTE (`run`
    and not `skip`), or the verdict is VOID.
  - Verdicts come from `go test -json` Action=="fail", with the test NAME matched.
Run it unbuffered (`python3 -u`).
"""
import json, os, re, subprocess, sys

REPO = "/var/tmp/wt-9509"
PKG = "./pkg/vrrp/"
TIMEOUT = 900
MIN_GO = 50
TR = "pkg/vrrp/instance_transition.go"
CALL = '\t\tvi.surfaceStaleVIP(rollbackErr, "becomeMaster-rollback")\n'

MUTANTS = [
    ("V1 the rollback failure is not surfaced",
     [(TR, CALL, "", None)],
     r"TestBecomeMasterRollbackFailureIsSurfacedAndReconciled_9509|TestStrandedVIPIsRetriedAfterAFailedPromotion_9509"),
    ("V2 surfaced only on error (a clean rollback leaves a stale flag)",
     [(TR, CALL, '\t\tif rollbackErr != nil {\n\t\t\tvi.surfaceStaleVIP(rollbackErr, "becomeMaster-rollback")\n\t\t}\n', None)],
     r"TestCleanRollbackClearsAStaleDivergenceFlag_9509"),
    ("V3 nil is surfaced instead of the rollback error",
     [(TR, CALL, '\t\tvi.surfaceStaleVIP(nil, "becomeMaster-rollback")\n', None)],
     r"TestBecomeMasterRollbackFailureIsSurfacedAndReconciled_9509"),
    ("V4 surfaced BEFORE setState(BACKUP) (the reconcile fences itself out)",
     [(TR, CALL, "", None),
      (TR, "\t\trollbackErr := vi.removeVIPsLocked(res.applied)\n\t\tvi.setState(StateBackup)\n",
       '\t\trollbackErr := vi.removeVIPsLocked(res.applied)\n\t\tvi.surfaceStaleVIP(rollbackErr, "becomeMaster-rollback")\n\t\tvi.setState(StateBackup)\n', None)],
     r"TestBecomeMasterRollbackFailureIsSurfacedAndReconciled_9509|TestStrandedVIPIsRetriedAfterAFailedPromotion_9509"),
]


def apply(edits):
    backups, ok = {}, True
    for f, find, repl, occ in edits:
        path = os.path.join(REPO, f)
        cur = open(path).read()
        backups.setdefault(f, cur)
        n = cur.count(find)
        if n != 1:
            print(f"  APPLY FAILED: {f} target count {n}, want 1"); ok = False; break
        new = cur.replace(find, repl)
        if new.count(find) != n - 1 and not (repl and find in repl):
            print(f"  APPLY FAILED: {f} target {n} -> {new.count(find)}"); ok = False; break
        if repl.strip() and new.count(repl) <= cur.count(repl):
            print(f"  APPLY FAILED: {f} replacement did not rise"); ok = False; break
        open(path, "w").write(new)
        print(f"  applied: {f} target {n} -> {new.count(find)}")
    return backups, ok


def restore(backups):
    for f in backups:
        head = subprocess.run(["git", "show", f"HEAD:{f}"], cwd=REPO, capture_output=True, text=True, check=True).stdout
        open(os.path.join(REPO, f), "w").write(head)
        if subprocess.run(["git", "diff", "--quiet", "--", f], cwd=REPO).returncode != 0:
            raise SystemExit(f"RESTORE FAILED for {f}")


def run_go(target):
    cmd = ["go", "test", "-json", "-count=1", f"-timeout={TIMEOUT-120}s", PKG]
    env = {k: v for k, v in os.environ.items() if k not in ("TMPDIR", "GOTMPDIR")}
    try:
        p = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT, env=env)
    except subprocess.TimeoutExpired:
        return "VOID(hang)", []
    blob = p.stdout + p.stderr
    if [l for l in blob.splitlines() if "no space left on device" in l and "injected:" not in l]:
        return "VOID(enospc)", []
    if "panic: test timed out" in blob:
        return "VOID(hang)", []
    if "[build failed]" in blob or "build failed" in p.stderr:
        return "VOID(build)", []
    ran, failed, skipped = set(), set(), set()
    for line in p.stdout.splitlines():
        try:
            e = json.loads(line)
        except Exception:
            continue
        t, a = e.get("Test"), e.get("Action")
        if not t:
            continue
        {"run": ran, "fail": failed, "skip": skipped}.get(a, set()).add(t)
    if len(ran) < MIN_GO:
        return f"VOID(collected {len(ran)})", []
    tgt = re.compile(target)
    executed = {t for t in ran if tgt.search(t)} - {t for t in skipped if tgt.search(t)}
    if not executed:
        return "VOID(no target cell executed)", []
    killers = sorted(t for t in failed if tgt.search(t))
    return ("KILLED" if killers else ("SURVIVED" if not failed else "KILLED(collateral only)")), killers or sorted(failed)[:4]


def main():
    if subprocess.run(["git", "status", "--porcelain"], cwd=REPO, capture_output=True, text=True).stdout.strip():
        print("ABORT: commit before running the matrix (tree is dirty)"); return 2
    if "--check" in sys.argv:
        bad = 0
        for name, edits, target in MUTANTS:
            for f, find, repl, occ in edits:
                n = open(os.path.join(REPO, f)).read().count(find)
                bad += 0 if n == 1 else 1
                print(f"{'ok ' if n == 1 else 'BAD'} {n:2d}x  {name}  [{f}]")
        return 1 if bad else 0
    print("=== BASELINE ===")
    v, k = run_go(r"9509")
    print(f"  go: {v} {k}")
    if v != "SURVIVED":
        print("BASELINE NOT CLEAN — refusing to score"); return 2
    results = []
    for name, edits, target in MUTANTS:
        print(f"\n=== {name} ===")
        backups, ok = apply(edits)
        if not ok:
            restore(backups); results.append((name, "VOID(not applied)", [])); continue
        try:
            verdict, killers = run_go(target)
        finally:
            restore(backups)
        print(f"  [go] {verdict} {killers}")
        results.append((name, verdict, killers))
    print("\n=== MATRIX ===")
    for name, verdict, killers in results:
        final = "KILLED" if verdict.startswith("KILLED") else ("VOID" if verdict.startswith("VOID") else "SURVIVED")
        print(f"{final:9s} {name}")
        print(f"{'':9s}   [go] {verdict} {killers}")
    return 0


sys.exit(main())
