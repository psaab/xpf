#!/usr/bin/env python3
"""#9508 mutation matrix: Go-only, the whole pkg/cluster package per run.

Discipline:
  - APPLIED is proven by count; insertion mutants must keep their anchor and raise
    the replacement's count.
  - Every run is bounded; a timeout or `panic: test timed out` is VOID(hang).
  - Real ENOSPC only: lines containing "injected:" are excluded.
  - A build failure is VOID(build).
  - At least MIN_GO tests must start, and the named target cells must execute.
  - Verdicts come from `go test -json` Action=="fail" with the NAME matched against
    the cells expected to kill; any other failure is printed, never counted.
Run it unbuffered (`python3 -u`).

Not in the matrix, and why:
  - BulkStart's noteStreamConnLocked: without it a store-walk bulk after a reconnect
    discharges nothing new, and the first barrier on the new connection arms and
    re-primes once more. That costs one bulk; it is not a safety property.
  - The BulkAck arm's load order (capture before pending epoch) and
    WaitForPeerBarrier's snapshot-before-check: both close interleavings that no
    deterministic cell can schedule. They are argued in the code comments.
"""
import json, os, re, subprocess, sys

REPO = "/var/tmp/wt-9508"
PKG = "./pkg/cluster/"
TIMEOUT = 1200
MIN_GO = 50
FENCE = "pkg/cluster/sync_barrier_fence_9508.go"
BULK = "pkg/cluster/sync_bulk.go"
WRITE = "pkg/cluster/sync_conn_write.go"
READ = "pkg/cluster/sync_conn_read.go"

ROUTES = r"TestBarrierIsNotSatisfiedAfterADeltaWasLostWithADroppedFabric_9508|TestBarrierIsNotSatisfiedWhenTheActiveFabricChangedWithoutADrop_9508"
RECOVERY = r"TestBarrierCompletesAgainOnceTheFenceRePrimeIsAcked_9508"
STOREWALK = r"TestAStoreWalkRePrimeDischargesTheFence_9508"
CAPTURE = r"TestAnAckedBulkWhoseSnapshotPredatesTheMoveKeepsTheFence_9508"
ORDER = r"TestAMoveIsRecordedBeforeTheBarrierIsWritten_9508"
RELEASE = r"TestAPendingBarrierFailsPromptlyWithTheFenceErrorWhenTheStreamMoves_9508"

MUTANTS = [
    ("F1 a stream move is never recorded",
     [(FENCE, "\ts.fence.epoch.Add(1)\n\treturn true\n}\n", "\treturn false\n}\n", None)],
     "|".join([ROUTES, ORDER, RELEASE, CAPTURE])),
    ("F2 the move is recorded after the write",
     [(WRITE, "\t\t\tmoved := s.noteStreamConnLocked(conn) // #9508: before the write\n\t\t\terr := writeFull(conn, msg)\n",
       "\t\t\terr := writeFull(conn, msg)\n\t\t\tmoved := s.noteStreamConnLocked(conn) // #9508: before the write\n", None)],
     ORDER),
    ("F3 a barrier pending across a move is not failed",
     [(BULK, "\t\tif s.fence.epoch.Load() != fence {\n", "\t\tif false && s.fence.epoch.Load() != fence {\n", None)],
     "|".join([ROUTES, ORDER, RELEASE])),
    ("F4 an armed fence does not refuse a new barrier",
     [(BULK, "\tif s.barrierFenced() {\n\t\ts.scheduleBarrierFenceReprime(", "\tif false && s.barrierFenced() {\n\t\ts.scheduleBarrierFenceReprime(", None)],
     CAPTURE),
    ("F5 the fence re-prime never runs",
     [(FENCE, "func (s *SessionSync) scheduleBarrierFenceReprime(reason string) {\n",
       "func (s *SessionSync) scheduleBarrierFenceReprime(reason string) {\n\tif reason != \"\" {\n\t\treturn\n\t}\n", None)],
     "|".join([RECOVERY, STOREWALK])),
    ("F6 discharge clears to the current epoch, not the bulk's capture",
     [(FENCE, "\tepoch := capture - 1\n", "\tepoch := s.fence.epoch.Load()\n", None)],
     CAPTURE),
    ("F7 doBulkSync captures after reading the snapshot",
     [(BULK, "\t\tfence := s.captureBarrierFenceForBulk()\n\t\tsnap, err := src()\n",
       "\t\tsnap, err := src()\n\t\tfence := s.captureBarrierFenceForBulk()\n", None)],
     CAPTURE),
    ("F8 a snapshot bulk carries no capture",
     [(BULK, "\t\twalk.fence = fence\n", "\t\t_ = fence\n", None)],
     RECOVERY),
    ("F9 a BulkAck never discharges the fence",
     [(READ, "\t\ts.dischargeBarrierFence(fenceCapture)\n", "\t\t_ = fenceCapture\n", None)],
     "|".join([RECOVERY, STOREWALK])),
    ("F10 the pending bulk records the current epoch instead of its capture",
     [(BULK, "\ts.fence.pendingBulk.Store(walk.fence) // #9508", "\ts.fence.pendingBulk.Store(s.fence.epoch.Load() + 1) // #9508", None)],
     CAPTURE),
    ("F11 the store walk captures nothing",
     [(BULK, "\tw := &bulkWalk{source: \"store-mirror\", readsDuringWindow: true}\n", "\tw := &bulkWalk{source: \"store-mirror\", readsDuringWindow: false}\n", None)],
     STOREWALK),
    ("F12 a move does not release the pending barrier waiters",
     [(FENCE, "\tfor _, ch := range waiters {\n\t\tclose(ch)\n\t}\n", "\tfor range waiters {\n\t}\n", None)],
     RELEASE),
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
        return "VOID(hang)", [], []
    blob = p.stdout + p.stderr
    if [l for l in blob.splitlines() if "no space left on device" in l and "injected:" not in l]:
        return "VOID(enospc)", [], []
    if "panic: test timed out" in blob:
        return "VOID(hang)", [], []
    if "[build failed]" in blob or "build failed" in p.stderr:
        return "VOID(build)", [], []
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
        return f"VOID(collected {len(ran)})", [], []
    tgt = re.compile(r"^(?:" + target + r")$")
    executed = {t for t in ran if tgt.search(t)} - {t for t in skipped if tgt.search(t)}
    if not executed:
        return "VOID(no target cell executed)", [], []
    killers = sorted(t for t in failed if tgt.search(t))
    others = sorted(t for t in failed if not tgt.search(t))
    if killers:
        return "KILLED", killers, others
    return ("SURVIVED" if not failed else "SURVIVED(other failures only)"), [], others


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
        src = open(os.path.join(REPO, "pkg/cluster/barrier_connection_causal_9508_test.go")).read()
        for cell in re.split(r"\|", "|".join([ROUTES, RECOVERY, STOREWALK, CAPTURE, ORDER, RELEASE])):
            n = src.count("func " + cell + "(")
            bad += 0 if n == 1 else 1
            print(f"{'ok ' if n == 1 else 'BAD'} cell {cell}: {n}")
        return 1 if bad else 0
    print("=== BASELINE ===")
    v, k, o = run_go(r".*")
    print(f"  go: {v} killers={k} other_failures={o}")
    if v != "SURVIVED":
        print("BASELINE NOT CLEAN — refusing to score"); return 2
    results = []
    for name, edits, target in MUTANTS:
        print(f"\n=== {name} ===")
        backups, ok = apply(edits)
        if not ok:
            restore(backups); results.append((name, "VOID(not applied)", [], [])); continue
        try:
            verdict, killers, others = run_go(target)
        finally:
            restore(backups)
        print(f"  [go] {verdict} killers={killers} other_failures={others}")
        results.append((name, verdict, killers, others))
    print("\n=== MATRIX ===")
    for name, verdict, killers, others in results:
        final = "KILLED" if verdict == "KILLED" else ("VOID" if verdict.startswith("VOID") else "SURVIVED")
        print(f"{final:9s} {name}")
        print(f"{'':9s}   [go] {verdict} killers={killers} other_failures={others}")
    return 0


sys.exit(main())
