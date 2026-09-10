#!/usr/bin/env python3
"""#9364 mutation matrix.

Two carve-outs the standard rules need here:

  COMPILE-TIME GUARD. One defence is a two-file compile-time belt
  (pkg/dataplane/scoped_batch_delete_published_9364.go +
  pkg/dataplane/userspace/scoped_batch_delete_adapter_9364.go). Its kill signal IS
  a build failure, so a build break scores KILLED(compile) only when the
  diagnostic names one of those files, and VOID(build) otherwise — "the build
  broke" is otherwise ambiguous between "the guard fired" and "my mutant was
  malformed".

  SKIP IS NOT A PASS. #9337: every BPF-backed cell in pkg/dataplane/userspace
  SKIPS without CAP_BPF, and a matrix scored on a run where the target cell
  skipped reports every mutant as SURVIVING — the void shape that argues for
  deleting a guard doing its job. So the baseline asserts the #9364 cells
  actually EXECUTED, and any run where they did not is VOID.

Otherwise the usual: occurrence-counted in both directions, bounded, `go test
-json` scored on Action=="fail" with the NAME compared to the cell, >= MIN_TESTS
executed, and a REAL ENOSPC check that excludes the pkg/configstore `injected:`
fixture (#9500 — a PASSING test emits that string).
"""
import json, os, subprocess, sys

REPO = "/var/tmp/wt-9364"
PKGS = ["./pkg/dataplane/", "./pkg/dataplane/userspace/"]
MIN_TESTS = 50
TIMEOUT = 900
GUARD_FILES = ("scoped_batch_delete_published_9364.go", "scoped_batch_delete_adapter_9364.go")

STORE = os.path.join(REPO, "pkg/dataplane/session_store.go")
MGR = os.path.join(REPO, "pkg/dataplane/userspace/manager_sessions.go")
ADAPTER = os.path.join(REPO, "pkg/dataplane/userspace/legacy_dataplane.go")

MUTANTS = [
    ("R1 pre-#9364 wire: the scoped helper delete builds a BARE request again", [
        (MGR, '''			reqs = append(reqs, m.buildSessionSyncRequestV4(
				"delete", keys[i].Key, deleteScopeVal(keys[i].RoutingDomain)))''',
         '''			reqs = append(reqs, m.buildSessionSyncRequestV4("delete", keys[i].Key, nil))''', 1, 0),
    ]),
    # Reshaped: the first form's replacement was a SUBSTRING of the original, so
    # the "replacement count must rise" check could not distinguish applied from
    # not-applied and correctly refused to score it. Disabling the capability
    # probe is the same mutant with a distinguishable edit.
    ("R2 pre-#9364 store: the chunk always takes the BARE fallback", [
        (STORE, '''	if scoped, ok := s.dp.(sessionDomainBatchDeleter); ok {
		return scoped.BatchDeleteSessionsScoped(chunk)''',
         '''	if scoped, ok := s.dp.(sessionDomainBatchDeleter); ok && s.dp == nil {
		return scoped.BatchDeleteSessionsScoped(chunk)''', 1, 0),
    ]),
    ("R3 the #9482 shape: the adapter forwarder removed, so the capability misses silently", [
        (ADAPTER, '''func (a *LegacyDataPlaneAdapter) BatchDeleteSessionsScoped(scoped []dataplane.ScopedSessionKey) (int, error) {''',
         '''func (a *LegacyDataPlaneAdapter) BatchDeleteSessionsScopedGONE(scoped []dataplane.ScopedSessionKey) (int, error) {''', 1, 0),
    ]),
    ("R4 partial fix: the REVERSE companion loses its domain", [
        (STORE, '''			reverseKeys = append(reverseKeys, ScopedSessionKey{
				Key:           val.ReverseKey,
				RoutingDomain: val.RoutingDomain,
			})''',
         '''			reverseKeys = append(reverseKeys, ScopedSessionKey{Key: val.ReverseKey})''', 1, 0),
    ]),
    ("R5 over-correction: a domain is invented for the DEFAULT instance", [
        (MGR, '''func deleteScopeVal(routingDomain uint32) *dataplane.SessionValue {
	if routingDomain == 0 {
		return nil
	}''',
         '''func deleteScopeVal(routingDomain uint32) *dataplane.SessionValue {
	if routingDomain == 0 {
		return &dataplane.SessionValue{RoutingDomain: 1}
	}''', 1, 0),
    ]),
    ("R6 over-correction: the optional capability becomes REQUIRED (no bare fallback)", [
        (STORE, '''	return s.dp.BatchDeleteSessions(bareSessionKeys(chunk))
}''',
         '''	return 0, nil
}''', 1, 0),
    ]),
]


def build():
    p = subprocess.run(["go", "build", "./..."], cwd=REPO, capture_output=True,
                       text=True, timeout=TIMEOUT)
    return p.returncode, p.stdout + p.stderr


def run_tests():
    env = dict(os.environ)
    env.pop("TMPDIR", None)
    env.pop("GOTMPDIR", None)
    p = subprocess.run(["go", "test", "-json", "-count=1", f"-timeout={TIMEOUT-120}s"] + PKGS,
                       cwd=REPO, capture_output=True, text=True, timeout=TIMEOUT, env=env)
    blob = p.stdout + p.stderr
    if [l for l in blob.splitlines()
            if "no space left on device" in l and "injected:" not in l]:
        return None, None, None, "DISK-FULL"
    if "panic: test timed out" in blob:
        return None, None, None, "HANG"
    failed, ran, skipped = set(), set(), set()
    build_fail = "[build failed]" in blob
    for line in p.stdout.splitlines():
        try:
            ev = json.loads(line)
        except Exception:
            continue
        t = ev.get("Test")
        if t:
            a = ev.get("Action")
            if a == "run":
                ran.add(t)
            elif a == "fail":
                failed.add(t)
            elif a == "skip":
                skipped.add(t)
    if build_fail:
        return None, None, None, "BUILD-FAILED"
    return failed, ran, skipped, None


def nine(s):
    return sorted(t for t in s if "9364" in t)


def main():
    files = {STORE, MGR, ADAPTER}
    backup = {f: open(f).read() for f in files}

    print("=== BASELINE ===")
    rc, out = build()
    if rc != 0:
        print("BASELINE VOID: tree does not build\n" + out[:600])
        return 2
    failed, ran, skipped, void = run_tests()
    if void:
        print(f"BASELINE VOID: {void}")
        return 2
    mine_ran, mine_skipped = nine(ran), nine(skipped)
    print(f"baseline: {len(ran)} ran, {len(failed)} failed; #9364 cells ran={len(mine_ran)} skipped={len(mine_skipped)}")
    if len(ran) < MIN_TESTS or failed:
        print(f"BASELINE VOID (failed={sorted(failed)})")
        return 2
    # #9337: a matrix scored on skipped target cells reports every mutant as surviving.
    if not mine_ran or mine_skipped:
        print(f"BASELINE VOID: #9364 cells did not all EXECUTE (ran={mine_ran} skipped={mine_skipped})")
        return 2

    results = []
    for name, edits in MUTANTS:
        print(f"\n=== {name} ===")
        ok = True
        for f, find, repl, before, after in edits:
            s = open(f).read()
            n = s.count(find)
            if n != before:
                print(f"  APPLY FAILED: target count {n}, want {before}")
                ok = False
                break
            s2 = s.replace(find, repl)
            n2 = s2.count(find)
            if n2 != after:
                print(f"  APPLY FAILED: post-count {n2}, want {after}")
                ok = False
                break
            rb, ra = s.count(repl), s2.count(repl)
            if repl.strip() and ra <= rb:
                print(f"  APPLY FAILED: replacement {rb} -> {ra}, expected an increase")
                ok = False
                break
            open(f, "w").write(s2)
            print(f"  applied: target {n} -> {n2}, replacement {rb} -> {ra} in {os.path.basename(f)}")
        if not ok:
            for f, orig in backup.items():
                open(f, "w").write(orig)
            results.append((name, "VOID-NOT-APPLIED", []))
            continue

        verdict, killers = None, []
        rc, out = build()
        if rc != 0:
            if any(g in out for g in GUARD_FILES):
                verdict, killers = "KILLED(compile)", ["the compile-time belt refused the published type"]
                print(f"  {verdict}: {out.strip().splitlines()[-1][:170]}")
            else:
                verdict = "VOID-BUILD-BROKE-FOR-ANOTHER-REASON"
                print(f"  {verdict}:\n{out[:500]}")
        else:
            try:
                failed, ran, skipped, void = run_tests()
            except subprocess.TimeoutExpired:
                failed, ran, skipped, void = None, None, None, "HANG"
            if void:
                verdict = f"VOID-{void}"
            elif len(ran) < MIN_TESTS:
                verdict = "VOID-COLLECTED-NOTHING"
            elif nine(skipped):
                verdict = "VOID-TARGET-CELLS-SKIPPED"
            elif failed:
                mine, other = nine(failed), sorted(t for t in failed if "9364" not in t)
                verdict, killers = "KILLED", mine or other
                print(f"  KILLED; #9364 cells: {mine}")
                if other:
                    print(f"  also red (collateral): {other}")
            else:
                verdict = "SURVIVED"
            if verdict != "KILLED":
                print(f"  {verdict}")
        for f, orig in backup.items():
            open(f, "w").write(orig)
        results.append((name, verdict, killers))

    print("\n=== MATRIX ===")
    for name, verdict, killers in results:
        print(f"{verdict:40s} {name}")
        for k in killers:
            print(f"{'':40s}   killed by {k}")
    return 0


sys.exit(main())
