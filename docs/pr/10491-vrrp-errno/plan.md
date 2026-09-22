# Plan: symmetric errno classification on VRRP VIP add/remove (#10491)

## Status

PLAN (Wave 1, plan-only round). No production code changed. Base `b71c52d60`
(`fix/10491-vrrp-errno`). Parent-run plan review is the next gate; implementation
starts only after review sign-off.

## Issue framing

The VRRP VIP add path classifies `AddrAdd` failure with a bare substring match
(`pkg/vrrp/instance_vip.go:208-216` at base):

```go
if err := vi.nlAddrAdd(link, addr); err != nil {
    // EEXIST is fine — address already present, so it IS actuated.
    if strings.Contains(err.Error(), "exists") {
        res.applied = append(res.applied, vip)
```

The remove path 70 lines below (`:271-293`) unwraps first and documents why:

```go
// errors.Is unwraps the netlink errno even when it is annotated with
// NLMSGERR_ATTR TLV text; the string check is a belt-and-suspenders
// match for wrappers that only expose Error().
if errors.Is(err, unix.EADDRNOTAVAIL) ||
    strings.Contains(err.Error(), "cannot assign requested address") ||
    ...
```

`vipActuationResult.failed` feeds `res.ok()` (`:152-154`), which gates
`becomeMaster`'s fail-closed refusal to claim ownership
(`pkg/vrrp/instance_transition.go:108-137`). A text-only match can misclassify
an annotated netlink error at that gate in EITHER direction:

- false-benign: a failed add recorded APPLIED → MASTER claimed without the VIP
  (traffic blackhole; the dangerous direction);
- false-failure: a present VIP recorded FAILED → ownership refused + rollback +
  master-down retry churn.

STEP-0 (this round) verified the issue is still live at `b71c52d60`:
`git log --all --grep=10491` empty, merged-PR search for `10491` empty, and
`git show origin/master:pkg/vrrp/instance_vip.go` still shows the text-only
check on add vs `errors.Is` on remove. Impact per the issue: Low — a reachable
non-EEXIST text mismatch remains unproven (see Q4).

## Scope-value

One production site changes (`instance_vip.go:210`, plus its comment): the add
path unwraps with `errors.Is(err, unix.EEXIST)` first, keeping a string check
only as a documented fallback mirroring the remove path's rationale. Symmetric
unit coverage for annotated (`NLMSGERR_ATTR` TLV) netlink errors lands on both
paths.

Why worth doing at Low impact: the match sits directly at the ownership gate,
and it is one kernel-TLV annotation change away from live misclassification in
the dangerous direction. The fix is small, the precedent (remove path, #5482)
is already reviewed and shipped, and the symmetric tests pin both paths against
future drift.

Blast-radius numbers (measured at base, see §Shipped-context for method):

- Production call sites affected: 2 add-path callers of `addVIPsLocked`
  (`becomeMaster` at `instance_transition.go:108`, `reconcileVIP` at
  `instance_vip.go:326`); 4 `removeVIPsLocked` callers and 3 `removeVIPs`
  callers are behaviorally untouched (remove path is test-only in this change).
- `pkg/vrrp` holds 56 `*_test.go` files; 7 touch VIP actuation, 2 pin errno
  behavior directly (`vip_backup_verify_5482_test.go`,
  `becomemaster_rollback_9509_test.go`).
- Zero existing `errors.Is(err, unix.EEXIST)` uses in `pkg/vrrp` (EEXIST
  appears only in comments); the fix introduces the first.
- Repo-wide, one other production site uses the same text-only idiom:
  `pkg/dataplane/compiler_iface.go:420` (`!strings.Contains(err.Error(),
  "exists")`) — adjacent, explicitly out of scope (see §Out-of-scope, Q5).

## Shipped-context

Surrounding machinery this change plugs into (all shipped, none reopened):

- #5082 (fail-closed ownership): `vipActuationResult{applied, failed, linkErr}`
  + `ok()`; `becomeMaster` rolls back partial adds via
  `removeVIPsLocked(res.applied)`, reverts to BACKUP, publishes BACKUP.
  #5082 is the broader scope and does NOT own this exact classification line
  (issue states; #5082 closed).
- #5482 (BACKUP-side stale-VIP divergence): the remove-path `errors.Is(err,
  unix.EADDRNOTAVAIL)` + string-fallback idiom this plan mirrors, including its
  comment rationale and the `TestBackupRemoveAbsentVIPNoDivergence_5482`
  fail-on-revert guard (direct errno + plain-string cases).
- #9509 (MASTER-side rollback surfacing): `becomeMaster`'s rollback error is
  surfaced via `surfaceStaleVIP(..., "becomeMaster-rollback")`; the
  `fakeKernel9509` seam returns `unix.EADDRNOTAVAIL` for absent deletes.
- #6779 (advert-capacity gate): second fail-closed refusal in `becomeMaster`,
  before VIP actuation; untouched.
- Method: counts above from `grep -rn` for `addVIPsLocked()` /
  `removeVIPsLocked(` / `removeVIPs()` call sites, `ls pkg/vrrp/*_test.go |
  wc -l`, `grep -rln "addVIPs|removeVIPs|vipActuation|AddrAdd|AddrDel"` over
  `*_test.go`, and repo-wide `grep -rn 'Contains(.*"[Ee]xists'`.
- Error-source check: pinned `github.com/vishvananda/netlink v1.3.1`
  (`go.mod`) constructs `syscall.Errno(-errno)` and, for
  `NLMSGERR_ATTR_MSG`, wraps it with `fmt.Errorf("%w: %s", err, msg)` in
  `nl/nl_linux.go:625-642`. The chain is therefore preserved for the normal
  Linux path even when the message is annotated.

## Design

Mirror the remove-path idiom inline at the add site (no helper — a helper
would be a second convention beside the existing inline pattern for exactly
two sites):

```go
if err := vi.nlAddrAdd(link, addr); err != nil {
    // EEXIST is fine — address already present, so it IS actuated.
    // errors.Is unwraps the netlink errno even when it is annotated with
    // NLMSGERR_ATTR TLV text; the string check is a belt-and-suspenders
    // match for wrappers that only expose Error().
    if errors.Is(err, unix.EEXIST) ||
        strings.Contains(err.Error(), "file exists") {
        res.applied = append(res.applied, vip)
    } else {
        ... // unchanged Warn + failed
    }
}
```

Two deliberate choices, both reviewable (Q1, Q2):

1. `errors.Is` FIRST, string fallback second — same order and rationale comment
   as the remove path.
2. Fallback narrowed from bare `"exists"` to full-strerror `"file exists"`,
   the faithful mirror of the remove path's full-strerror fallbacks
   (`"cannot assign requested address"`, `"not found"`, `"no such"`). Bare
   `"exists"` can false-benign on any error text containing that substring;
   on the ADD path false-benign is the dangerous direction (claims ownership
   without the VIP), so the fallback must be as narrow as possible while
   still catching strerror-only wrappers. The pinned netlink implementation
   itself preserves the errno in the wrapped error text; this fallback is for
   callers or future wrappers that expose only a strerror.

No other production lines change. Imports (`errors`, `strings`,
`golang.org/x/sys/unix`) are all already present in `instance_vip.go:3-13`.

## API

No signature changes (exported or otherwise). Behavior contract after the fix:

| `nlAddrAdd` outcome              | classification | `res` bucket | `ok()` |
|----------------------------------|----------------|--------------|--------|
| nil                              | clean add      | applied      | true*  |
| `unix.EEXIST` (chained, incl. TLV-annotated) | benign present | applied | true* |
| strerror-only `"file exists"` wrapper | benign present (fallback) | applied | true* |
| any other error                  | failure        | failed       | false  |

\* assuming interface resolved and all other VIPs likewise applied.

Remove-path contract is unchanged; only its test coverage grows (annotated
cases) to prove symmetry.

## Invariants

- I1 (add taxonomy): `addVIPsLocked` classifies exactly {chained EEXIST,
  `"file exists"` strerror text} as applied; every other `AddrAdd` error is
  failed. No error text containing bare `"exists"` from a non-EEXIST source
  may classify as applied.
- I2 (remove taxonomy frozen): the `removeVIPsLocked` benign set
  (`EADDRNOTAVAIL` + three substrings) is byte-identical before/after.
- I3 (gate preserved): `res.ok()` still requires `linkErr == nil &&
  len(failed) == 0`; `becomeMaster` and `reconcileVIP` logic untouched.
- I4 (lock discipline frozen): no `vipMu` changes, no new goroutines,
  channels, timers, or counters.
- I5 (hot-path silence): EEXIST-on-add stays log-silent. `reconcileVIP`
  re-adds on every pass, so every steady-state MASTER reconcile hits EEXIST
  per VIP — any log line there is reconcile-rate spam. (Q7 records the
  considered-and-rejected Debug alternative.)

## 4-class risk

- R1 — behavior-change (misclassification flip): LOW. The intended observable
  delta is that a wrapped EEXIST is classified from its chain before any text
  fallback. The narrowed fallback also changes non-EEXIST messages that merely
  contain bare `"exists"` (but not `"file exists"`) from applied to failed —
  fail-closed in the dangerous direction. At pinned netlink v1.3.1 the normal
  `NLMSGERR_ATTR_MSG` formatter preserves both the chain and the errno text, so
  this is defense in depth for outer/future wrappers rather than a claimed
  reproduction on the pinned path. No true-EEXIST case can regress: chained
  EEXIST matches via `errors.Is`, and strerror-only EEXIST matches via
  `"file exists"` (the lowercase `unix.EEXIST.Error()` text). Residual:
  a hypothetical EEXIST wrapper whose text contains neither the chain nor
  `"file exists"` — no such wrapper is known (Q2).
- R2 — concurrency: NONE. No lock, goroutine, or ordering changes; the edited
  lines execute under the caller's existing `vipMu` hold exactly as today.
- R3 — observability/ops: NEGLIGIBLE. No log lines added/removed/releveled;
  no counter/flag semantics change. Second-order effect: fewer spurious
  fail-closed refusals (fewer `failed to add VIP` Warns + fewer BACKUP
  revert events) IF annotated-EEXIST occurs in the fleet — that is the fix
  working, not a monitoring break. `vipDiverged`/`vipRemoveFailures` paths
  untouched.
- R4 — compat/rollout (kernel + netlink variance): LOW. `errors.Is` against
  `unix.EEXIST` is version-independent for any error chain rooted in the
  errno; the fallback covers strerror-only wrappers. Forward risk (newer
  kernels annotating MORE) is exactly what `errors.Is`-first fixes; backward
  risk (older kernels, unannotated errno) behaves as today. No config,
  wire-format, or downgrade implications; safe to roll back (worst case is
  the current behavior).

## Test plan

New file `pkg/vrrp/vip_errno_10491_test.go` (no edits to existing tests —
nothing gets re-pinned). Drives the existing `addrAddFn`/`addrDelFn` seams
(same fixture style as `vip_backup_verify_5482_test.go` /
`becomemaster_rollback_9509_test.go`):

Add path (`addVIPsLocked`, single-VIP instance):

1. direct `unix.EEXIST` → applied, `res.ok()` true.
2. an `annotatedErr` fixture whose `Error()` is
   `"NLMSGERR_ATTR_MSG: duplicate address"` and whose `Unwrap()` returns
   `unix.EEXIST` → applied, `ok()` true. This is intentionally a synthetic
   outer wrapper: it proves the chain branch and is RED pre-fix because its
   text contains no `"exists"`.
3. the pinned netlink shape
   `fmt.Errorf("%w: %s", unix.EEXIST, "NLMSGERR_ATTR_MSG: duplicate")` →
   applied. The `%w` text includes `file exists`, so this compatibility case
   is green before the fix as well; it records the actual v1.3.1 shape.
4. plain-string `errors.New("file exists")` (strerror-only wrapper) →
   applied (fallback arm).
5. bare-substring non-EEXIST `errors.New("interface exists but is down")`
   → failed, `ok()` false. RED pre-fix (currently applied): pins the
   dangerous direction and justifies narrowing the fallback.
6. other errnos direct + annotated (`EADDRNOTAVAIL`, `EPERM`) → failed.

Remove path (`removeVIPsLocked`, symmetry — extends #5482's direct+string
matrix, which stays green untouched):

7. an `annotatedErr` whose `Error()` is `"NLMSGERR_ATTR_MSG: address absent"`
   and whose `Unwrap()` returns `unix.EADDRNOTAVAIL` → benign (nil error).
   This is the remove-side chain counterpart and is RED if its `errors.Is`
   guard is removed.
8. the pinned netlink shape wrapping `unix.EADDRNOTAVAIL` with an ext-ack
   message → benign (nil error).
9. chained annotated other errno (`EEXIST`, `EPERM`) → real failure (non-nil,
   `del vip` wrapped).

RED-first verification: run the new test against the pre-fix tree (stash
the one-line fix) and confirm add cases 2 and 5 fail; add case 3 and remove
cases 7-8 should remain green because they document the existing
errors.Is-compatible behavior. Re-apply and confirm all cases green. Then
run the full package with no other test touched:

```
GOCACHE=/dev/shm/gocache-10491 GOTMPDIR=/dev/shm go test ./pkg/vrrp/ \
  -run 'TestVIP.*10491|TestBackupRemoveAbsentVIPNoDivergence_5482' -count=1 -v
GOCACHE=/dev/shm/gocache-10491 GOTMPDIR=/dev/shm go test ./pkg/vrrp/ -count=1
```

Expected: targeted run green (new + 5482 guard), full package green (56
files, zero failures). No cluster/incus commands in this round; parent
sequences smoke at merge time.

## Out-of-scope

- `pkg/dataplane/compiler_iface.go:420` — same text-only `"exists"` idiom
  (negated) in dataplane iface compile. Different subsystem, different
  failure direction, different owner; needs its own issue (Q5), not a
  drive-by in a VRRP change.
- Broader #5082 fail-closed ownership work (closed) and any `becomeMaster` /
  `reconcileVIP` / `vipMu` restructuring.
- Log-level asymmetry (add-failure Warn vs remove-failure Debug) — pre-
  existing, intentional-looking, untouched.
- Proving or fixing fleet kernel behavior; no kernel-version-dependent
  branching.
- Production code in THIS round (plan-only): the diff sketch above is a
  proposal for post-review implementation.

## Open questions (invite PLAN-KILL on any)

1. **Fallback string: `"file exists"` (narrow, as designed) or keep bare
   `"exists"`?** Narrow is fail-closed on the add path (false-benign is the
   dangerous direction) and mirrors the remove path's full-strerror
   fallbacks. Kill condition: a reviewer demonstrates a real EEXIST wrapper
   whose text contains `"exists"` but not `"file exists"` — then bare wins
   (or the fallback list grows).
2. **Should the add path keep ANY string fallback?** The remove path's
   fallback exists for "wrappers that only expose Error()". We inspected the
   pinned v1.3.1 source: `nl/nl_linux.go:625-642` starts with
   `syscall.Errno(-errno)` and uses `fmt.Errorf("%w: %s", err, msg)` for
   `NLMSGERR_ATTR_MSG`, so the normal path preserves both chain and errno
   text. That makes the fallback unnecessary for this exact dependency but
   does not rule out outer wrappers, future netlink versions, or other
   platforms. Decide whether compatibility warrants the residual text-match
   surface, or whether this issue should be `errors.Is`-only.
3. **Helper vs inline mirror?** Plan mirrors the remove path inline (existing
   convention for exactly two sites). A shared `isBenignAddrErr`-style
   helper would centralize the taxonomy but invent a second convention.
   Ratify inline, or argue the taxonomy is now load-bearing enough to name.
4. **Is the bug reachable in production today, or latent?** The pinned
   v1.3.1 implementation preserves the errno chain AND renders the errno
   text before the TLV message, so its exact `NLMSGERR_ATTR_MSG` shape still
   contains `"file exists"` for EEXIST. That makes this issue's dangerous
   mismatch unproven/latent on the normal pinned path; an outer wrapper that
   changes `Error()` while retaining `Unwrap()` remains possible. Confirm the
   supported kernel/netlink matrix before calling this a live production
   incident; either way the ownership-gate defense is small and justified.
5. **Follow-up issue for `compiler_iface.go:420`?** Same idiom, negated
   check, dataplane owner. File before merge (preferred) or expand this
   issue's scope — state which.
6. **Case 5 fixture: is there a REAL non-EEXIST error containing bare
   `"exists"`?** The issue's Limits section admits no enumeration was done.
   If none exists even in principle (no errno strerror, no netlink ext-ack
   template contains it), case 5 tests a synthetic string — still a valid
   contract pin (I1), but say so explicitly rather than claiming a
   demonstrated reachable mismatch.
7. **Stay silent on EEXIST-applied (I5), or Debug-log it?** Silent is
   correct per reconcile-rate spam analysis, but it leaves "VIP was already
   present" indistinguishable from a clean add in logs. Counter-argument:
   steady-state MASTER reconciles would emit per-VIP lines per pass.
   Ratify silent.
