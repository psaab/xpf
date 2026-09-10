#!/usr/bin/env python3
"""#9582 mutation matrix: Rust-only (the change touches no Go), one leg per mutant.

Discipline, inherited from the #9412 runner:
  - APPLIED is proven by count, both directions. An occurrence-indexed edit hits
    exactly ONE site, and the replacement's count must rise (removals: 1 -> 0).
  - A compile failure is VOID(build). A test failure is `error: test failed` with no
    compile marker, and is never misread as a build break.
  - Every run is bounded. A timeout is VOID(hang).
  - The target cells must EXECUTE (a named `... ok` or `... FAILED`), or the verdict
    is VOID.
  - Kills are attributed by TEST NAME.
Run it unbuffered (`python3 -u`), so a monitored log shows every verdict as it lands.
"""
import os, re, subprocess, sys

REPO = "/var/tmp/wt-9582"
RS = "userspace-dp/src/"
RUST_FILTERS = ["9582"]
TIMEOUT = 1500

GATE = RS + "session/mod.rs"
PD = RS + "afxdp/poll_descriptor/mod.rs"
SITE = "session_id: sessions.session_id_for(&flow.forward_key),"

MUTANTS = [
    ("S1 the WorkerLocalImport exemption is removed (replicas silent again)",
     [(GATE, "        if forward.origin.is_peer_synced()\n            && !(forward.origin == SessionOrigin::WorkerLocalImport\n                && self.session_id_carried_from_another_worker(forward.session_id))\n        {",
       "        if forward.origin.is_peer_synced()\n        {", None)],
     r"a_close_seen_only_by_a_local_replica_is_announced_with_the_installer_id_9582"),
    ("S2 the carried-id guard is bypassed (a locally minted id announces)",
     [(GATE, "                && self.session_id_carried_from_another_worker(forward.session_id))", "                && true)", None)],
     r"a_replica_holding_a_locally_minted_id_stays_silent_9582"),
    ("S3 the exemption is widened to every peer-synced origin (peer imports echo)",
     [(GATE, "            && !(forward.origin == SessionOrigin::WorkerLocalImport\n", "            && !(forward.origin.is_peer_synced()\n", None)],
     r"a_peer_import_replica_still_announces_nothing_9582"),
    ("S4 the helper ignores the namespace (any non-zero id counts as carried)",
     [(GATE, "        session_id != 0 && (session_id & NAMESPACE_MASK) != self.session_id_worker_hi\n", "        session_id != 0\n", None)],
     r"a_replica_holding_a_locally_minted_id_stays_silent_9582|only_a_non_zero_id_from_another_namespace_counts_as_carried_9582"),
    ("S5 the helper drops its id-0 check",
     [(GATE, "        session_id != 0 && (session_id & NAMESPACE_MASK) != self.session_id_worker_hi\n", "        (session_id & NAMESPACE_MASK) != self.session_id_worker_hi\n", None)],
     r"only_a_non_zero_id_from_another_namespace_counts_as_carried_9582"),
    ("W1 the transit ForwardFlow publish carries 0 again",
     [(PD, SITE, "session_id: 0,", 1)],
     r"txn_transit_install_publishes_the_installer_session_id_9582"),
    ("W2 the missing-neighbor seed publish carries 0 again",
     [(PD, SITE, "session_id: 0,", 2)],
     r"poll_descriptor_missing_neighbor_seed_publishes_its_session_id_9582"),
    ("W3 the promote republish carries 0 again",
     [(RS + "afxdp/session_glue/promote.rs", "session_id: sessions.session_id_for(key),", "session_id: 0,", None)],
     r"promote_republishes_the_session_id_for_replicas_to_adopt_9582"),
    ("W4 the replica clone zeroes the carried id",
     [(RS + "afxdp/shared_ops.rs", "    replica.origin = entry.origin.worker_replica_origin();\n",
       "    replica.origin = entry.origin.worker_replica_origin();\n    replica.session_id = 0;\n", None)],
     r"promote_republishes_the_session_id_for_replicas_to_adopt_9582"),
]


def apply(edits):
    backups, ok = {}, True
    for f, find, repl, occ in edits:
        path = os.path.join(REPO, f)
        cur = open(path).read()
        backups.setdefault(f, cur)
        n = cur.count(find)
        if occ is None:
            if n != 1:
                print(f"  APPLY FAILED: {f} target count {n}, want 1"); ok = False; break
            new = cur.replace(find, repl)
        else:
            if n < occ:
                print(f"  APPLY FAILED: {f} has {n} occurrences, want >= {occ}"); ok = False; break
            idx = -1
            for _ in range(occ):
                idx = cur.index(find, idx + 1)
            new = cur[:idx] + repl + cur[idx + len(find):]
        # An INSERTION mutant keeps its anchor (the replacement contains it), so its
        # anchor count stays n and the replacement's own count must rise instead.
        insertion = bool(repl) and find in repl
        if new.count(find) != (n if insertion else n - 1):
            print(f"  APPLY FAILED: {f} target {n} -> {new.count(find)}, want {n if insertion else n-1}"); ok = False; break
        if repl.strip() and new.count(repl) <= cur.count(repl):
            print(f"  APPLY FAILED: {f} replacement did not rise"); ok = False; break
        open(path, "w").write(new)
        print(f"  applied: {f} target {n} -> {n-1}")
    return backups, ok


def restore(backups):
    for f in backups:
        head = subprocess.run(["git", "show", f"HEAD:{f}"], cwd=REPO, capture_output=True, text=True, check=True).stdout
        open(os.path.join(REPO, f), "w").write(head)
        if subprocess.run(["git", "diff", "--quiet", "--", f], cwd=REPO).returncode != 0:
            raise SystemExit(f"RESTORE FAILED for {f}: tree differs from HEAD")


def run_rust(target):
    tgt = re.compile(target)
    executed, killers = set(), []
    for flt in RUST_FILTERS:
        try:
            p = subprocess.run(["nice", "-n", "5", "cargo", "test", "-j", "6", "--bin", "xpf-userspace-dp", "--", flt],
                               cwd=os.path.join(REPO, "userspace-dp"), capture_output=True, text=True, timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            return "VOID(hang)", []
        blob = p.stdout + p.stderr
        if "could not compile" in blob or re.search(r"^error\[E\d+\]", blob, re.M):
            return "VOID(build)", []
        for m in re.finditer(r"^test (\S+) \.\.\. (ok|FAILED)$", blob, re.M):
            if tgt.search(m.group(1)):
                executed.add(m.group(1))
                if m.group(2) == "FAILED":
                    killers.append(m.group(1))
    if not executed:
        return "VOID(target cells did not execute)", []
    return ("KILLED" if killers else "SURVIVED"), sorted(set(killers))


def main():
    if subprocess.run(["git", "status", "--porcelain"], cwd=REPO, capture_output=True, text=True).stdout.strip():
        print("ABORT: commit before running the matrix (tree is dirty)"); return 2
    if "--check" in sys.argv:
        bad = 0
        for name, edits, target in MUTANTS:
            for f, find, repl, occ in edits:
                n = open(os.path.join(REPO, f)).read().count(find)
                okc = (n == 1) if occ is None else (n >= occ)
                bad += 0 if okc else 1
                print(f"{'ok ' if okc else 'BAD'} {n:2d}x  {name}  [{f}]")
        return 1 if bad else 0
    print("=== BASELINE ===")
    v, k = run_rust(r"9582")
    print(f"  rust: {v} {k}")
    if v != "SURVIVED":
        print("BASELINE NOT CLEAN — refusing to score"); return 2
    results = []
    for name, edits, target in MUTANTS:
        print(f"\n=== {name} ===")
        backups, ok = apply(edits)
        if not ok:
            restore(backups); results.append((name, "VOID(not applied)", [])); continue
        try:
            verdict, killers = run_rust(target)
        finally:
            restore(backups)
        print(f"  [rust] {verdict} {killers}")
        results.append((name, verdict, killers))
    print("\n=== MATRIX ===")
    for name, verdict, killers in results:
        final = "KILLED" if verdict.startswith("KILLED") else ("VOID" if verdict.startswith("VOID") else "SURVIVED")
        print(f"{final:9s} {name}")
        print(f"{'':9s}   [rust] {verdict} {killers}")
    return 0


sys.exit(main())
