# Plan: Upgrade lock stale owner-metadata read window (#1984)

## 1. Problem

`pkg/upgrade/lock` writes owner metadata (PID, subcommand, target, start
time) into the lock file AFTER the flock succeeds, and a busy acquirer
reads that file to NAME the holder. Three windows expose STALE metadata
from a PREVIOUS owner:

1. **Acquire→write window** — between `unix.Flock` success
   (`lock.go:139`) and `writeOwnerFn` (`lock.go:162`), the new holder has
   not yet written its metadata. A concurrent acquirer that hits
   `EWOULDBLOCK` in that window calls `readOwner` (`lock.go:142`) and gets
   the PREVIOUS owner's JSON.
2. **Write-failure persistence** — if `writeOwner` fails (disk full), the
   error is swallowed best-effort (CORRECT for lock-holding) but the file
   still contains the previous owner's JSON while the new holder runs.
3. **Release leaves the file** — `Release()` (`lock.go:178-189`) drops the
   flock (Flock(LOCK_UN)+Close) but never truncates/removes, so the last
   owner's JSON outlives the lock.

`writeOwner` (`lock.go:204`) does `Truncate(0)` before writing — but that
is at WRITE time, which windows 1 and 2 precede.

## 2. Hypothesis

The mutual exclusion (the flock) is sound; only the DIAGNOSTIC string is
wrong. Truncating the file to zero IMMEDIATELY after acquiring the flock
(before recording metadata) makes any concurrent reader in the race window
observe an empty file. `readOwner` already returns `nil` on
`len(data)==0` (`lock.go:220`), which degrades cleanly to "busy, owner
unknown" — strictly better than naming a long-exited process.

## 3. Goal / acceptance criteria

- A busy acquirer NEVER reads a previous owner's metadata as if it were
  the current holder's.
- Worst case under contention is "busy, owner metadata unavailable"
  (already a supported `ErrBusy` rendering), never a wrong-owner string.
- The flock-based mutual exclusion is unchanged.
- A regression test reproduces the stale read (fails before the fix).

## 4. Approach

### 4.1 Truncate-on-acquire (the minimal sound fix)

In `AcquireAt`, immediately after `unix.Flock(...LOCK_EX|LOCK_NB)`
succeeds and BEFORE constructing the handle / calling `writeOwnerFn`:

```go
// Zero the file the instant we hold the flock so any concurrent busy
// reader in the acquire->write window sees an empty file (degrades to
// "busy, owner unknown") instead of the PREVIOUS owner's stale JSON.
if terr := f.Truncate(0); terr != nil {
    // Non-fatal: the lock is the flock, not the file contents. Log and
    // continue; the subsequent writeOwner Truncate(0) will retry.
    fmt.Fprintf(os.Stderr,
        "upgrade lock: held %s but failed to clear stale owner metadata: %v\n",
        path, terr)
}
```

This single change closes window 1 (the file is empty during
acquire→write) and window 2 (if the metadata write later fails, the file
is already empty rather than holding stale JSON). `writeOwner` keeps its
own `Truncate(0)` (harmless redundancy / correct after a partial earlier
write).

### 4.2 Release cleanup — DEFER, document the hazard

AGY also suggested `os.Remove(path)` in `Release()`. **This plan does NOT
adopt remove-on-release without explicit review sign-off**, because flock
binds the OPEN FILE DESCRIPTION (inode), not the path:

- A would-be acquirer that has already `open()`ed the path and is blocked
  / about to flock holds an fd to the OLD inode; if `Release` unlinks the
  path and a new acquirer `O_CREAT`s a FRESH inode, two acquirers can flock
  two DIFFERENT inodes and BOTH believe they hold the lock — a split mutex.
  This is the same class as the #1875 "never rm the cluster lock file"
  lesson (CLAUDE.md / engineering-style).
- The lock lives on `/run` (tmpfs, reboot-clearing), so a lingering
  zero-length file after release is harmless: the next acquirer reopens the
  SAME inode, flocks it, truncates it (4.1), and writes fresh metadata.

Conclusion: truncate-on-acquire (4.1) alone fully fixes the stale-read
defect WITHOUT introducing the split-mutex hazard. Leaving the file in
place is the safer SSOT. If review insists on cleanup, the only safe form
is `f.Truncate(0)` in `Release` (zero the contents, keep the inode), NOT
`os.Remove`.

## 5. Alternatives rejected

- **`os.Remove(path)` in Release.** Split-mutex risk (above). Rejected
  unless review overrides with a concrete argument that no concurrent
  open()-then-flock can straddle the unlink. Default: NO.
- **Write metadata BEFORE flock.** Can't — you must hold the lock before
  claiming ownership, and a pre-flock write would let a non-holder stamp
  the file.
- **fcntl record lock instead of flock.** Out of scope; the flock choice
  is deliberate (#1965) and correct for mutual exclusion.

## 6. Files touched

- `pkg/upgrade/lock/lock.go` (truncate-on-acquire)
- `pkg/upgrade/lock/lock_test.go` (stale-read regression test)
- package doc comment update noting the truncate-on-acquire invariant and
  why remove-on-release is deliberately avoided.

## 7. Test strategy

Strong regression test that reproduces the stale read:

1. Acquire the lock (holder A), Release it — leaving A's JSON on disk
   (current behavior).
2. With a `writeOwnerFn` seam that BLOCKS on a channel (simulating the
   acquire→write window), acquire as holder C in a goroutine — it flocks,
   truncates (after fix), then blocks before writing.
3. From the main goroutine, attempt a second acquire (D) → `ErrBusy`.
   Assert `ErrBusy.Owner == nil` (owner unknown). BEFORE the fix this test
   FAILS because D reads A's stale JSON; AFTER the fix the file is empty so
   D reads nil. Counter-factual strength: the assertion is specifically
   "not A", reconstructing the pre-fix failure.
4. Unblock C, let it finish, assert the file now names C.
5. Separate test for window 2: force `writeOwnerFn` to FAIL after the
   acquire-truncate; assert a subsequent busy read returns nil owner (not
   the prior owner).

The existing `lock_test.go` already has a `writeOwnerFn` seam
(`lock_test.go:170-187`), so the blocking/failing variants slot in.

## 8. Invariants

- The flock mutual exclusion is unchanged (no new lock semantics).
- After a successful acquire, the file is EMPTY until metadata is written
  (so a concurrent reader never sees a stale owner).
- `/run` tmpfs semantics relied upon: same-inode reopen across
  release/acquire (no unlink).

## 9. Risk

LOW. One added `Truncate(0)` on the held fd. No mutual-exclusion change.
The deliberate NON-adoption of `os.Remove` avoids the only real hazard.

## 10. Rollout / validation

- Unit tests only. No live cluster lane (pure host-local diagnostic fix);
  state so in the PR body. Optionally a `make test-deploy` smoke that an
  upgrade still acquires/releases cleanly.

## 11. Disposition

engineer-now — minimal, safe, well-tested. The remove-on-release question
is settled here as "do not" with documented reasoning; flag for explicit
review confirmation.

## Reviewer verdicts

- Claude SMR: _pending_
- Codex companion: _pending_
- AGY companion: _pending_
