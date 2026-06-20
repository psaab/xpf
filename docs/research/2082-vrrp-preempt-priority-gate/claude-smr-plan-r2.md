# Claude SMR — hostile PLAN review r2, #2082

Stance: hostile re-review. Goal = confirm every r1 gap is *correctly* closed and
hunt for anything the r2 edits broke. Verified against worktree source.

## r1 gaps — closure check

- **GAP 1 (lock discipline underspecified):** CLOSED. §5 item 3 now mandates
  snapshot-under-one-RLock-then-release OR `*Locked` helpers, enumerates the
  exact fields to snapshot, and explicitly forbids re-introducing
  `getPriority()` inside a held lock. §8 risk #4 marks it resolved. Concrete and
  binding. ✓
- **GAP 2 (invented cross-goroutine TOCTOU):** CLOSED. §6 first bullet now
  states the single-run-goroutine serialization invariant with the correct
  citations (`:350` for-loop, `:354-355/:386-387/:360`); §8 risk #2/#4
  corrected. The "receiver writes lastMaster*" framing is gone. Re-verified:
  `handleBackupRx`/`handleMasterRx` are `case pkt := <-vi.rxCh:` bodies in the
  run loop; receivers only `rxCh <- pkt`. ✓
- **GAP 3 (gate-only-shortcut + staleness for silent death + priority-0
  ungated):** CLOSED. §6 invariants (a)/(b)/(c) added with source citations.
  Re-verified: `masterDownTimer.Stop()` is inside the taken `becomeMaster`
  branch only (`instance.go:371`); priority-0 → `masterDownTimer.Reset(1ms)`
  (`:728`) → `masterDownTimer.C` (`:357`), not the gated case. ✓
- **Test must drive run() (reviewer A + me):** CLOSED. §7 makes test #1 a
  run-loop wiring guard and demotes helper-only tests to supplements; states it
  must FAIL on today's code. ✓
- **Integration blindness (reviewer B + AGY):** CLOSED. §7 states test-failover
  is no-regression-only, run-loop unit test authoritative, rejects adding
  preempt to the shared smoke cluster. ✓
- **IP tie-break dropped, strict `>` (AGY):** CLOSED. §4 step 2 + §6 last bullet
  use strict `>`, equal → false (RFC 5798 §6.4.2), no peer-IP field (§5). ✓

## Independent re-verification of the load-bearing r2 claims

1. **Run-loop unit test is actually feasible (the claim test #1 rests on).**
   VERIFIED: `addVIPs()` (`instance.go:1005-1011`) fails soft when
   `netlink.LinkByName` errors (Warn+return — no panic) — a fake interface name
   works. `sendPacket` returns nil when `rawConn==nil` (`:886`).
   `sendPacketIPv6` guarded similarly. `sendGARP` (`:1086`) also uses
   `LinkByName` (fails soft). Existing tests already build instances with
   `&net.Interface{Name:"eth0"}` and no sockets (`vrrp_test.go`
   TestSyncHold_SuppressesPreempt / TestPreemptNowCh_Initialized). So driving
   `becomeMaster()` in a unit test without real netlink/sockets is sound. ONE
   nit for the implementer: `becomeMaster()` spawns `go vi.sendGARP()` unless
   `suppressGARP` is set — the test should set `vi.suppressGARP.Store(true)` (or
   tolerate the fail-soft goroutine) to avoid a stray goroutine; add this to §7
   test #2/#1 notes. Minor, not a blocker.
2. **Staleness fallback cannot cause a no-master outage.** VERIFIED via
   invariant (a): a denied gate never stops `masterDownTimer`, so the RFC
   election promotes independently. The gate only ever *defers the shortcut*. ✓
3. **force=true bypass + coalescing.** VERIFIED: `if force || should…` short-
   circuits; ForceRGMaster sets `forcePreemptOnce` before `triggerPreemptNow`.
   §8 risk #6 correctly states Path A touches only the `force==false` branch. ✓

## Residual hunt (new flaws from r2 edits?)

- **None structural.** The r2 edits are tightening/spec, no new mechanism.
- **Minor doc nit (non-blocking):** §6 invariant (c) says the silent-death deny
  window is "bounded by masterDownInterval (~97ms RETH)" — technically the
  staleness *check* uses masterDownInterval, but the practical promote happens
  via the independent masterDownTimer which is also ~masterDownInterval, so the
  node promotes at ~one masterDownInterval regardless. The plan states both
  correctly; no fix needed, just noting the two horizons coincide by design.
- **Scope question reviewer B may raise (pre-addressed):** the confirmed harm is
  a spurious MASTER event → `allMasterLocked()` → rg_active on the Secondary.
  One could argue the fix belongs in `rg_state.go` (don't let a transient VRRP
  MASTER flip rg_active). But the ROOT cause is the illegitimate VRRP
  transition; fixing it at the VRRP layer is correct and minimal, and the
  rg_active rule is correct GIVEN a legitimate MASTER. Fixing rg_state instead
  would paper over the wrong-VRRP-state without stopping the spurious VIP add /
  advert / GARP. VRRP-layer fix is the right layer. (If reviewer B pushes this,
  the answer is: the VRRP transition is the thing that's wrong; rg_active
  faithfully reflects it.) The plan should add one sentence to §3 non-goals or
  §6 making this explicit.

## Verdict

All four r1 required changes are correctly and completely closed; the
load-bearing feasibility and safety claims re-verify against source; no new flaw
introduced. Two non-blocking nits (suppressGARP in the test; one clarifying
sentence on why the fix is at the VRRP layer not rg_state).

OVERALL: PLAN-READY (with two optional non-blocking nits the implementer/plan
may fold). Reachability CONFIRMED; Path A correct, RFC-compliant, deadlock-free
as specified, timing-safe, with an authoritative unit-test validation strategy.
