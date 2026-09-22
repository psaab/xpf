# Plan: symmetric errno classification on VRRP VIP add/remove (#10491)

## Status

CONFIRMED v3 (Wave 1, thrice-folded dual-confirmed plan). Plan artifact only. Base
`b71c52d60` (`fix/10491-vrrp-errno`). Round-1 plan review found only
documentation/test-precision minors; this revision folds all adjudicated
findings. Dual-confirmed; implementation authorized under the same branch.

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
(`pkg/vrrp/instance_transition.go:108-137`). An error whose `Error()` text
diverges from its underlying errno can be misclassified at that gate in EITHER
direction:

- false-benign: a failed add recorded APPLIED → MASTER claimed without the VIP
  (traffic blackhole; the dangerous direction);
- false-failure: a present VIP recorded FAILED → ownership refused + rollback +
  master-down retry churn.

The pinned v1.3.1 `NLMSGERR_ATTR_MSG` path preserves both the errno chain and
its `file exists` text, so this exact mismatch is latent/unproven on the normal
pinned path. An outer wrapper or future/platform-specific error formatter that
rewrites `Error()` while retaining (or losing) the cause remains the defensive
case this plan covers.

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
and it is one outer-wrapper or future error-format change away from live
misclassification in the dangerous direction. The fix is small, with the
shipped #5482 remove-path precedent, and the symmetric tests pin both paths
against future drift.

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
- Error-message reporting is disabled by default in the pinned dependency:
  `nl.EnableErrorMessageReporting = false` (`nl/nl_linux.go:45-46`), and
  `SetExtAck(true)` is called only when that global is enabled
  (`:567-571`). Repository search found no setter/reference, so TLV
  annotation is not expected on the normal production path unless an
  external caller mutates the dependency global; this reinforces the
  latent/unproven framing while retaining the defensive fix.
- Follow-up #10529 is filed before merge for the separable dataplane analogue
  at `pkg/dataplane/compiler_iface.go:418-426`; it remains out of this VRRP
  change (see §Out-of-scope and Q5).

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

### Reconcile scope (explicitly unchanged)

`reconcileVIP` calls `addVIPsLocked` while already MASTER but does not consult
`res.ok()`/`res.failed` before its current-generation revalidation, epoch bump,
and optional GARP. The sole production `ReconcileVIPs` caller is the
event-driven link-cycle recovery at
`pkg/daemon/daemon_apply_dataplane.go:955-956`; this is not a steady-state
periodic MASTER tick. This plan changes only errno classification and leaves
the GARP-on-failed-readd behavior and its failure policy out of scope. A
separate redesign would have to choose demotion, stale-VIP surfacing, and/or
retry semantics; inventing that policy would expand this Low-impact
defense-in-depth fix beyond #10491.

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

- I1 (add taxonomy): `addVIPsLocked` classifies a chain rooted in
  `unix.EEXIST`, OR an error-text fallback containing the full
  `file exists` strerror, as applied. Every other `AddrAdd` error is failed,
  including a non-EEXIST text containing only bare `"exists"`; the fallback's
  residual acceptance of a non-EEXIST text containing `file exists` is
  explicit in R1.
- I2 (remove taxonomy frozen): the `removeVIPsLocked` benign set
  (`EADDRNOTAVAIL` + three substrings) is byte-identical before/after.
- I3 (gate preserved): `res.ok()` still requires `linkErr == nil &&
  len(failed) == 0`; `becomeMaster`'s ownership gate and `reconcileVIP`'s
  existing revalidation/GARP ordering are untouched.
- I4 (lock discipline frozen): no `vipMu` changes, no new goroutines,
  channels, timers, or counters.
- I5 (silence): EEXIST-on-add stays log-silent. `ReconcileVIPs` has exactly
  one production caller, the event-driven link-cycle recovery at
  `daemon_apply_dataplane.go:955-956`; it is not a steady-state periodic
  MASTER tick. Logging an idempotent already-present result at that recovery
  boundary would still add noise without changing the success contract.
  (Q7 records the considered-and-rejected Debug alternative.)

## 4-class risk

- R1 — behavior-change (misclassification flip): LOW. The intended observable
  delta is that a wrapped EEXIST is classified from its chain before any text
  fallback. Narrowing bare `"exists"` to the full `file exists` strerror makes
  the demonstrated contract pin fail closed in the dangerous direction. At
  pinned netlink v1.3.1 the normal `NLMSGERR_ATTR_MSG` formatter preserves both
  the chain and errno text, so this is defense in depth for outer/future
  wrappers rather than a claimed pinned-path reproduction. Two residuals are
  explicit: (a) a non-EEXIST error whose text contains `file exists` still
  enters the compatibility fallback and can be false-benign; (b) an EEXIST
  wrapper that loses the chain AND rewrites text without lowercase `file
  exists` is false-failure. No true EEXIST regresses when either the chain is
  retained (`errors.Is`) or the strerror-only text is retained.
- R2 — concurrency: NONE. No lock, goroutine, or ordering changes; the edited
  lines execute under the caller's existing `vipMu` hold exactly as today.
- R3 — observability/ops: NEGLIGIBLE. No log lines added/removed/releveled;
  no counter/flag semantics change. Second-order effect: fewer spurious
  fail-closed refusals (fewer `failed to add VIP` Warns + fewer BACKUP
  revert events) IF an outer/future wrapper preserves a chained EEXIST but
  renders Error text without `exists`; the pinned v1.3.1 annotated shape
  already matches pre-fix. That is the fix working, not a monitoring break.
  `vipDiverged`/`vipRemoveFailures` paths remain untouched.
- R4 — compat/rollout (kernel + netlink variance): LOW. `errors.Is` against
  `unix.EEXIST` is version-independent for any error chain rooted in the
  errno; the fallback covers strerror-only wrappers. Error-message reporting
  is disabled by default in pinned netlink v1.3.1 (`EnableErrorMessageReporting
  = false`), so `SetExtAck(true)` is not expected on the normal repository
  path; a future/version/platform toggle is exactly the variance the chain
  check covers. No config, wire-format, or downgrade implications; safe to
  roll back (worst case is the current behavior).

## Test plan

New file `pkg/vrrp/vip_errno_10491_test.go` (no edits to existing tests —
nothing gets re-pinned). Drives the existing `addrAddFn`/`addrDelFn` seams
(same fixture style as `vip_backup_verify_5482_test.go` /
`becomemaster_rollback_9509_test.go`):

Add path (`addVIPsLocked`, single-VIP instance):

1. direct `syscall.Errno(unix.EEXIST)` → applied, `res.ok()` true.
2. an `annotatedErr` fixture whose `Error()` is
   `"NLMSGERR_ATTR_MSG: duplicate address"` and whose `Unwrap()` returns
   `syscall.Errno(unix.EEXIST)` → applied, `ok()` true. This is intentionally
   a synthetic outer wrapper: it proves the chain branch and is RED pre-fix
   because its text contains no `"exists"`.
3. the pinned netlink shape
   `fmt.Errorf("%w: %s", syscall.Errno(unix.EEXIST),
   "NLMSGERR_ATTR_MSG: duplicate")` → applied. The `%w` text includes
   `file exists`, so this compatibility case is green before the fix as well;
   it records the actual v1.3.1 shape.
4. plain-string `errors.New("file exists")` (strerror-only wrapper) →
   applied (fallback arm).
5. bare-substring non-EEXIST `errors.New("interface exists but is down")`
   → failed, `ok()` false. RED pre-fix (currently applied): this is a
   synthetic contract pin for I1, not a demonstrated reachable producer; it
   justifies narrowing the fallback's dangerous direction.
6. direct and annotated variants of other errnos
   (`syscall.Errno(unix.EADDRNOTAVAIL)`, `syscall.Errno(unix.EPERM)`) →
   failed. The annotated variants use neutral TLV text
   (`"NLMSGERR_ATTR_MSG: address rejected"`, containing no `"exists"`); both
   forms are green pre- and post-fix. This pins the no-change complement
   rather than relying on an unspecified annotation string.
7. ownership-gate wiring: drive `becomeMaster` with a resolvable fake link,
   `suppressGARP=true`, and an `annotatedErr` wrapping
   `syscall.Errno(unix.EEXIST)`. Assert `becomeMaster()` returns true, the
   state is MASTER, and the MASTER event is published. RED pre-fix: a
   text-only classifier sends this present-address result through the
   fail-closed refusal, so this catches the `res` → `ok()` gate rather than
   only the helper bucket.

Remove path (`removeVIPsLocked`, symmetry — extends #5482's direct+string
matrix, which stays green untouched):

8. an `annotatedErr` whose `Error()` is `"NLMSGERR_ATTR_MSG: address absent"`
   and whose `Unwrap()` returns `syscall.Errno(unix.EADDRNOTAVAIL)` → benign
   (nil error). This is the remove-side chain counterpart and is RED if its
   `errors.Is` guard is removed.
9. the pinned netlink shape wrapping `syscall.Errno(unix.EADDRNOTAVAIL)` with
   an ext-ack message → benign (nil error).
10. chained annotated other errno (`syscall.Errno(unix.EEXIST)`,
    `syscall.Errno(unix.EPERM)`) use neutral TLV text
    (`"NLMSGERR_ATTR_MSG: delete denied"`, containing no remove-benign
    substring) → real failure both pre- and post-fix (non-nil, `del vip`
    wrapped).

RED-first verification: run the new test against the pre-fix tree (stash
the one-line fix) and confirm add cases 2, 5, and 7 fail. Cases 1, 3, 4, 6,
8, 9, and 10 remain green both pre- and post-fix: cases 1 and 4 are existing
EEXIST text compatibility, case 3 is the pinned shape, cases 8-9 exercise
existing remove errno handling, and cases 6/10 use neutral TLV text. Re-apply
and confirm all cases green. Then run the full package with no other test
touched:

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
  failure direction, different owner; separability is verified and follow-up
  #10529 is filed before merge. Do not drive-by this site into #10491.
- Broader #5082 fail-closed ownership work (closed) and any `becomeMaster` /
  `reconcileVIP` / `vipMu` restructuring.
- Log-level asymmetry (add-failure Warn vs remove-failure Debug) — pre-
  existing, intentional-looking, untouched.
- Proving or fixing fleet kernel behavior; no kernel-version-dependent
  branching.
- Production code in THIS round (plan-only): the diff sketch above is a
  proposal for post-review implementation.
- Reconcile failure-policy redesign: whether `reconcileVIP` should suppress
  GARP, demote, surface, or retry after a failed re-add. The existing
  GARP-on-failed-readd behavior remains unchanged; #10491 only fixes errno
  classification at the ownership gate.

## Open questions for delta review (7; adjudicated v2, reopen on new evidence)

1. **Fallback string: `"file exists"` (RATIFIED narrow) or bare `"exists"`?**
   Narrow is fail-closed in the dangerous add direction and mirrors the
   remove path's full-strerror fallbacks. The repo and pinned dependency show
   no EEXIST wrapper containing bare `"exists"` without `"file exists"`;
   reopen only if such a producer is demonstrated.
2. **Keep ANY string fallback? (RATIFIED yes, narrow.)** The pinned netlink
   source preserves the chain and errno text, but #5482's shipped contract
   explicitly protects wrappers that expose only Error(). Removing the
   fallback would turn a strerror-only EEXIST into a spurious fail-closed
   refusal and retry churn. The residual text surface is narrowed and
   documented rather than silently removed.
3. **Helper vs inline mirror? (RATIFIED inline.)** Two sites already use the
   inline taxonomy idiom; a helper would invent a second convention for this
   two-case change. Reopen if a third VRRP actuation taxonomy site appears.
4. **Reachable today or latent? (CONFIRMED latent on pinned path.)** Netlink
   v1.3.1 preserves the errno chain and renders its text before the TLV
   message; its exact EEXIST shape therefore still contains `"file exists"`.
   Also, `EnableErrorMessageReporting` defaults false and the repository has
   no setter/reference, so `SetExtAck(true)` is not expected on the normal
   path. An outer/future/platform wrapper can still diverge; the one-line
   defense remains justified at the ownership gate.
5. **Dataplane follow-up or scope expansion? (RESOLVED before merge.)**
   Follow-up #10529 is filed for `compiler_iface.go:418-426`, with separability
   evidence: own package, own `addrAddSeam`, no VRRP ownership/advert/GARP
   coupling. #10491 scope remains unchanged.
6. **Case 5 real producer? (RESOLVED as synthetic contract pin.)** No
   non-EEXIST producer of bare `"exists"` was demonstrated in repository
   source; kernel-template enumeration remains outside this bounded plan.
   The `interface exists but is down` fixture is therefore an I1 contract
   pin, not a claimed reachable reproduction.
7. **Stay silent on EEXIST-applied? (RATIFIED silent.)** `ReconcileVIPs` has
   exactly one production caller at event-driven link-cycle recovery
   (`daemon_apply_dataplane.go:955-956`), not a steady-state periodic tick.
   Both clean add and already-present address are successful outcomes; adding
   a log would add noise without changing the contract.
