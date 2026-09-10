#!/usr/bin/env python3
"""#9507 mutation matrix: Go-only, the whole pkg/cluster package per run.

Discipline:
  - APPLIED is proven by count; insertion mutants must keep their anchor and raise
    the replacement's count.
  - Every run is bounded; a timeout is VOID(hang).
  - Real ENOSPC only: lines containing "injected:" are excluded.
  - A build failure is VOID(build).
  - At least MIN_GO tests must execute, and the target cells must execute.
  - Verdicts come from `go test -json` Action=="fail" with the NAME matched; a panic
    inside a named test still reports that test's fail.
Run it unbuffered (`python3 -u`).
"""
import json, os, re, subprocess, sys

REPO = "/var/tmp/wt-9507"
PKG = "./pkg/cluster/"
TIMEOUT = 1200
MIN_GO = 50
F = "pkg/cluster/sync_protocol.go"

MUTANTS = [
    ("D1 the count-above-len/4 refusal is removed",
     [(F, "\tif maxRecords := len(payload) / 4; count > maxRecords {\n\t\treturn nil, false\n\t}\n", "", None)],
     r"TestDHCPLeasePayload_HugeCountDoesNotOverAllocate|7175|9507"),
    ("D2 the record-length floor is disabled",
     [(F, "\t\tif recLen < minDHCPLeaseRecordLen {\n", "\t\tif false && recLen < minDHCPLeaseRecordLen {\n", None)],
     r"TestDHCPRecordShorterThanAnyEncoderIsMalformed_9507|TestDHCPZeroLengthCeilingFrameIsBoundedAndMalformed_9507"),
    ("D3 the floor drops to 35 (a truncated real record passes)",
     [(F, "const minDHCPLeaseRecordLen = 36\n", "const minDHCPLeaseRecordLen = 35\n", None)],
     r"TestDHCPRecordShorterThanAnyEncoderIsMalformed_9507"),
    ("D4 the floor rises to 37 (the oldest real record is refused)",
     [(F, "const minDHCPLeaseRecordLen = 36\n", "const minDHCPLeaseRecordLen = 37\n", None)],
     r"TestDHCPWorstCaseValidFrameAllocationIsBounded_9507"),
    ("D5 the address check is disabled",
     [(F, "addrLen == 0 || 3+addrLen > recLen {", "false && (addrLen == 0 || 3+addrLen > recLen) {", None)],
     r"TestDHCPEmptyAddressRecordIsMalformed_9507|TestDHCPAddressOverrunningItsRecordIsMalformed_9507"),
    ("D6 the address-overrun half is dropped",
     [(F, "addrLen == 0 || 3+addrLen > recLen {", "addrLen == 0 {", None)],
     r"TestDHCPAddressOverrunningItsRecordIsMalformed_9507"),
    ("D7 an over-declared count is refused (the #7175 tolerance lost)",
     [(F, "\t\t\t// malformed: nothing was lost mid-record.\n\t\t\tbreak\n", "\t\t\t// malformed: nothing was lost mid-record.\n\t\t\treturn nil, false\n", None)],
     r"TestDHCPLeasePayload_TruncatedStream|TestDHCPFullSetStillToleratesAnOverDeclaredCount7175|TestDHCPOverDeclaredCountAllocatesOnlyWholeRecords_9507"),
    ("D8 pass 2 is sized from the untrusted count",
     [(F, "\tout := make([]dhcpserver.SyncLease, 0, whole)\n", "\tout := make([]dhcpserver.SyncLease, 0, count)\n", None)],
     r"TestDHCPOverDeclaredCountAllocatesOnlyWholeRecords_9507"),
    ("D9 the cut-record check is disabled",
     [(F, "\t\tif off+recLen > len(payload) {\n", "\t\tif false && off+recLen > len(payload) {\n", None)],
     r"TestDHCPFullSetRejectsARecordCutMidStream7175"),
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
        insertion = bool(repl) and find in repl
        if new.count(find) != (n if insertion else n - 1):
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
    v, k = run_go(r"9507|7175|TestDHCPLease")
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
