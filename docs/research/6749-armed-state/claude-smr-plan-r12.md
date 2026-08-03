# Claude SMR plan review — round 12 — #6749 armed-state plan v8.7 (d63d98f75e3d)

**Reviewer:** Claude SMR (hostile; author-is-reviewer yellow-flag rule
applies DOUBLY — I wrote the v8.7 folds, so this pass attacks my own
fold text first). Attack surface: the v8.7 mechanics — the
`appliedSnapshot.Generation` lineage gate + staged-ahead disjunction,
the `ConfigGeneration` fence/tag tokens, the UNKNOWN-outcome re-sync,
the six-exit enumeration, the two-collection debt + every-attempt
reread, the `AttemptMACDebt` contract, the env-gated suppression.

**Verdict: DEMAND-REVISION** — my own v8.7 fold has a fold-breaking
hole (SMR12-1, BLOCKER): the `ConfigGeneration` token false-refuses
after ordinary overlay republishes, the exact defect class Codex r11
f4 flagged in v8.6's token, re-introduced by my fold's compile-stamped
semantics. Plus one MAJOR direction/locking incoherence and two
MINORs. Every finding verified against source (traces below). AGY r12
independently converged on SMR12-1 (its f2), SMR12-3 (its f3, rated
BLOCKER — I upgrade mine), SMR12-4 (its f6), and the locking half of
SMR12-2 (its f4), and adds two I missed (its f1 re-sync provenance,
its f5 bucket-iii flap).

---

## SMR12-1 (BLOCKER) — the `ConfigGeneration` token false-refuses after overlay republishes

My v8.7 fold keyed the fabric fence and the completion tag on
`m.lastSnapshot.ConfigGeneration` ("compile-stamped, NEVER
overlay-bumped") against the helper's stored snapshot generation. The
helper advances its stored generation on EVERY accepted full apply
(snapshot.rs:153) — and overlay republishes ARE full applies:
`manager_overlay.go:188-190` clones the snapshot with
`next.Generation = nextGeneration` and `:239` sends
`apply_snapshot`, with `:247` `markAppliedSnapshotLocked`. Route and
scheduler overlays are ORDINARY operations. After any overlay:

- helper stored generation = N+1 (fresh mint, same config content);
- `ConfigGeneration` = N (compile-stamped, by design);
- the next `update_fabrics` (expected=N) is REFUSED (stored N+1);
- a defer epoch's tagged completion (expected=N) is REFUSED — the
  epoch can NEVER complete after an ordinary overlay: the dataplane
  stays deferred indefinitely, the exact severity-High class this PR
  fixes.

I fixed only the fib/neighbor PARTIAL-op desyncs and missed overlay
FULL republishes. (The adoption gate survives overlays —
`markAppliedSnapshotLocked` advances both sides together — so the
gate is fine; only the fence/tag tokens break.)

**Required fix (fold into v8.8):** delete `ConfigGeneration`; put
`config_epoch: u64` ON THE WIRE (additive `ConfigSnapshot` field,
serde default 0 — the #3091 precedent). Every full apply carries the
manager's `m.configEpoch` for the config it carries; clone-republishes
(#5134 retry) and overlays carry the SAME epoch (same config); the
helper stores it from each accepted apply and echoes it in status.
The fence and the tag carry `expected_config_epoch`; the helper
refuses on mismatch, ordered FIRST. Re-verified cases: converged
(match); staged-ahead unpublished (B_epoch ≠ stored A_epoch → refuse
— correct); timeout-but-landed (A's token vs stored B_epoch → refuse
— correct); overlay clone (same epoch → accept — correct); #5134
clone-republish (same epoch → accept — correct); fib/neighbor partial
ops (never touch the epoch → accept — correct). The adoption gate
also simplifies onto the epoch: adopt `status.Fabrics` IFF
`status.config_epoch == m.appliedConfigEpoch` (manager-side record of
the last observed-accepted publish's epoch) AND
`m.configEpoch == m.appliedConfigEpoch` (no newer compiled config
staged) — both legs fib-clean AND overlay-clean, so the
`appliedSnapshot.Generation` leg becomes a cross-check, not the
primary.

## SMR12-2 (MAJOR) — `AttemptMACDebt`'s call direction contradicts the LinkController's daemon→manager reality

My §6 contract says "manager → daemon, synchronous". The actual
interface direction is daemon → manager: `userspaceLinkController`
wraps `c.manager` (controllers.go:36-40) — the DAEMON calls INTO the
manager (`SetDeferWorkers`, `PrepareLinkCycle`, `NotifyLinkCycle`).
No manager→daemon path exists, and creating one invites the AB-BA
inversion AGY r12 f4 names (manager thread holds `m.mu` → calls
daemon → wants `applySem`; daemon apply thread holds `applySem` →
calls manager → wants `m.mu`).

**Required fix:** the debt SCHEDULER and all netlink execution live
DAEMON-side (the applySem owner; the existing
daemon→manager-under-applySem call order is the ONLY order, already
exercised by the three current methods — document the hierarchy
`applySem > m.mu`, one direction, and the manager NEVER calls the
daemon). The epoch validation rides the daemon→manager interface:
one additive method `ValidateMACDebtEpoch(epoch uint64) (valid bool)`
(a cheap `m.mu` read) called by the daemon's attempt loop immediately
before each mutation; settlement/settlement-event reporting reuses
the EXISTING daemon→manager tagged-dispatch path
(`NotifyLinkCycle` with `complete_deferred`). The debt state
(collections, epoch key, backoff) can then live daemon-side with
`configEpoch` mirrored from the manager's advance events (the daemon
sees every accepted apply result first-hand), or manager-side with
the two daemon→manager calls — pick ONE in v8.8 and specify it
completely; my v8.7 text picked neither coherently.

## SMR12-3 (BLOCKER, upgraded from my initial MINOR — AGY r12 f3 is right) — the staged-ahead scalar disjunct false-fires after fib bumps

My (iii) gate blocks adoption when
`m.lastSnapshot.Generation > m.publishedSnapshot`.
`BumpFIBGeneration` advances `m.lastSnapshot.Generation`
(manager_generation.go:71); the `publishedSnapshot` stamp happens
only in the neighbor-DIFF publish (manager_neighbor.go:138) — a bump
with NO neighbor change (the common case: `neighborsEqualForwarding`
true) stamps NOTHING, leaving `lastSnapshot.Generation = G+1 >
publishedSnapshot = G` with IDENTICAL configs → adoption blocked
indefinitely. The re-wedge my own fold claimed to kill.

**Required fix:** drop the scalar disjunct; staged-ahead ⟺
`m.lastSnapshot.Config != appliedSnapshot.Config` (identity — a
staged compile installs a new Config pointer; overlays/bumps keep the
same one) OR, under the SMR12-1 epoch fix, simply
`m.configEpoch > m.appliedConfigEpoch`. Both forms are fib-clean.

## SMR12-4 (MINOR) — pin the `guard_env_generation` evaluation locus

My (i) text says the env hash is computed "at each telemetry
evaluation" without pinning the locus. If it lived only in the
`update_fabrics` handler, a guard-rejected projection with the
dataplane disabled would never re-evaluate (no subsequent handler
calls) → Go suppresses resends forever (AGY r12 f6's deadlock).
**Fix:** the evaluation rides `refresh_status` (every status build,
which always runs on the 1s poll regardless of ctrl state) AND each
guard evaluation; never only the handler.

## SMR12-5 (NIT) — pass-1 settle-with-down-link posture

A member flapping between a bucket-iii precheck and the SAME flow's
`programRethMAC` settles "validated" on MAC equality without link
inspection (daemon_reth.go:240). The bound+armed posture is correct
(N2's rule), but AGY r12 f5's sharper point stands: the member gets
NO `linkRecoveryDebt` entry, so nothing re-drives `setUp` if the
flap left it admin-down. **Fix:** the pass-1 reread covers ALL
desired members, not just bucket-i — a bucket-iii member found down
at pass-1 gets a non-gating `linkRecoveryDebt` entry.

## Attack trace (what else I tried, and why it fails to break v8.7)

1. **Adoption gate vs overlays.** `markAppliedSnapshotLocked`
   (manager_overlay.go:247) advances `appliedSnapshot.Generation`
   with the helper's stored generation on every overlay — the gate's
   equality leg survives. Helper-behind (fresh helper, generation 0)
   blocks adoption until the startup re-apply — correct.
2. **Six-exit completeness.** Seventh-path candidates: helper
   restart (stopLocked — covered by the (e) fold);
   `publishedSnapshot = 0` (process.go:259 — helper-behind, covered);
   the #2794 disarmed leg (= exit (d)); same-plan skip (no latch
   touch); per-binding operator arm during an open epoch (does NOT
   clear the latch — the epoch completion owns it; correct, and the
   retry-clock reset already covers the post-arm retry shape). No
   seventh path found.
3. **The re-sync's B-content provenance (AGY r12 f1 — I missed
   this).** `manager_compile.go:350-365` commits
   `m.lastSnapshot = snap` ONLY after a clean response; on a
   timeout-but-landed the local `snap` (B) goes out of scope — Go
   CANNOT exact-equal-republish B nor read `B.ConfigGeneration`. My
   v8.7 "adopt B, instantiate B-keyed debt carrying
   B.ConfigGeneration" is unimplementable as written. **Fix:** the
   commit ALREADY landed control-plane-side (the configstore commit
   precedes the dataplane publish), so the re-sync re-applies the
   ACTIVE config (fresh compile → fresh generation mint satisfying
   the #3767 strictly-lower refusal → identical config content →
   idempotent), whose precheck re-instantiates the debts and whose
   observed-accepted publish advances `configEpoch`. This is the
   existing mandatory-re-apply machinery, not a new flow.
4. **The every-attempt reread vs in-flow pass 1 (flap between
   precheck and programRethMAC).** Covered by SMR12-5/AGY f5 above
   (the only unmonitored sub-case).
5. **Q1 unowned-producer hunt (eleventh enumeration).** No new
   producer introduced by the v8.7 text: the fence refusal performs
   no mutation; the suppression performs no mutation; the re-sync
   re-apply is a full apply (S-rules apply). Clean.

## Required for convergence

v8.8: SMR12-1's `config_epoch`-on-the-wire token (fence + tag +
simplified adoption gate), SMR12-2's daemon-side scheduler + one-way
lock hierarchy + `ValidateMACDebtEpoch`, SMR12-3's disjunct drop,
SMR12-4's locus pin, SMR12-5's all-member pass-1 reread, and AGY
r12's f1 (active-config re-apply as the re-sync owner) — plus
whatever Codex r12 adds. Re-review required: the token change and
the ownership re-spec are load-bearing.

**Verdict: DEMAND-REVISION.**
