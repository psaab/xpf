# AGY adversarial plan review r3 (#1981)

**Verdict:** PLAN-NEEDS-MAJOR — narrowed to ONE hole: the same-version
`versions/<ver>` replacement protocol (independently matches Codex r3). All
other r2 findings verified folded.

Verbatim AGY output:

---

## 1. Verification of folded r2 findings
- AGY r2-#1a (non-atomic current-gen symlink): addressed in B-P2 (symlink+rename,
  atomic_symlink shape).
- AGY r2-#1b (.partial leak): B-P2b pre-sweeps stale staged-gen/*.partial before copy.
- AGY r2-#2 (disk bloat / disk-full): §4.B + B-P7 — retention N=2 (~7 copies),
  pre-copy space check + GC, fail-safe.
- AGY r2-#3 (GC-vs-resume): B-P3 Journal.SourceGeneration + GC protects
  journal-referenced genids.
- AGY r2-#4 (publish/cut concurrency): B-P2b publish takes /run/xpf/upgrade.lock,
  upgrade-deferred marker, no auto-cut on publish failure.
- AGY r2-#5 (postrm purge + downgrade leak): B-P6 purge rm -rf staged-gen/ +
  version-keyed downgrade cleanup.

## 2. Verdict: PLAN-NEEDS-MAJOR

## 3. The unresolved hole — same-version reinstall directory rename overwrite
B-P3b says a same-version-different-genid cut "forces a fresh recopy (into
versions/<ver>.partial → rename)." But:
1. **ENOTEMPTY:** rename(2) of a dir over an existing NON-EMPTY dir fails (Errno
   39). versions/<ver> is non-empty.
2. **Destructive workaround breaks crash-safety:** deleting versions/<ver> before
   the rename makes the copy non-atomic — a crash between delete and rename
   leaves a missing/partial active version dir, current points to a broken path,
   no rollback target. Violates the core crash-safety/rollback invariant.
3. **Active daemon race:** the COPY step runs BEFORE the unit is stopped
   (cutover.go:140 vs :160). Deleting/renaming versions/<ver> while the daemon
   runs from it prevents helper subprocesses (xpf-userspace-dp) from spawning
   (they resolve dir(os.Args[0]) = versions/<ver>/xpfd, flip.go:30).

### Recommended fix
Transition versions/<ver>/ → versions/<ver>-<genid>/. The
versions/<ver>-<genid>.partial → rename always targets a non-existent path
(atomic). current + unit drop-in resolve to versions/<ver>-<genid> at FLIP (when
the daemon is stopped). Leaves the running daemon's active dir untouched during
COPY.

## 4. Research-grade NITs for /engineer
- **Deferred-publish auto-recovery:** if the publish was deferred (lock busy),
  the operator's manual xpfd upgrade retry runs the NEW binary; the runner must
  detect /run/xpf/upgrade-deferred and PUBLISH from staged/ to staged-gen/
  (validating dpkg is no longer active via /var/lib/dpkg/lock-frontend) BEFORE
  resolving the target version, preventing a silent "already committed" no-op.
