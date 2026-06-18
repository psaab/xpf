# AGY adversarial plan review r4 (#1981)

**Verdict:** PLAN-READY

Verbatim AGY output:

---

The revised plan (r4) successfully addresses the same-version replacement
protocol hole identified in r3. The proposed solutions cleanly resolve the
tension between atomic updates, disk space constraints, and daemon runtime
invariants.

### Verification of B-P3b same-version replacement protocol

**OPT1 (recommended):** closes the hole and adheres to all constraints.
- Avoids ENOTEMPTY: for stale non-active/non-rollback dirs, RemoveAll runs
  BEFORE copy/rename → destination does not exist → no ENOTEMPTY.
- Avoids live-dir mutation & daemon race (preserves #1967): if versions/<ver>
  is the live `current` or rollback target, the cut aborts pre-PREFLIGHT — no
  modification/deletion of dirs backing the active daemon; the helper-spawn
  (dir(os.Args[0])) does not race the copy.

**OPT2 (generation-keyed dirs):** captured exactly as recommended — versions/
<ver>-<genid> guarantees a unique fresh destination, removing ENOTEMPTY and
live-dir mutation risk during copy; final mapping resolves atomically at FLIP
(daemon stopped).

### Residual research-grade NITs (for /engineer)
1. **Legacy journal compatibility:** a pre-B journal resumed under a B-aware
   runner has SourceGeneration=="" — treat empty SourceGeneration in an
   already-copied journal as valid legacy state to not block recovery.
2. **GC parser adaptation (if OPT2):** the versions GC (pkg/upgrade/runner.go)
   must parse versions/<ver>-<genid> to associate generation dirs with their
   version tag and prune correctly.
3. **Operator guidance on OPT1 refusal:** the CLI error should instruct the
   operator to stage under a distinct version tag or use dpkg-reconfigure to
   align the generation.
