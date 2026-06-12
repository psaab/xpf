# Claude SMR hostile plan review — #1884 r2 (plan v2, 1f4b3e2af57f)

Verdict: **PLAN-READY — contingent on folding SMR2-1 and SMR2-2**
(both single-edit precision fixes, no design change).

I re-attacked every v2 mechanism. The r1 MAJORs (mine and the other
reviewers') are genuinely closed by the v2 text: A.1's ownedNames diff
is recorded unconditionally at entry (closes SMR1-1's failure-continue
leak); A.7 is scoped legacy-only with the normalized identity and the
skip-LinkSetUp-on-down-runner rule (closes Codex F1/AGY-c1, with the
tunnel.go:587 gate cited); A.3 retains the EEXIST fallback as a single
re-lookup adopting the kernel-fetched link (closes AGY-c2 against the
iface_reuse_test.go:114-152 race tests); A.4's applied-set rule closes
Codex F2 without touching WG semantics.

## SMR2-1 (precision, MUST FOLD) — `adopted` flag in the EEXIST path

The A.3 pseudo-code sets `adopted = true` unconditionally in the
LinkAdd-EEXIST fallback. If the EEXIST race fires on a tunnel whose
name WAS in `ownedNames` at entry (same-lifetime re-apply with a
transient first-lookup miss — exactly the iface_reuse_test.go
`hiddenUntil` scenario), the MTU-reset would fire on an OWNED tunnel,
violating the plan's own "owned reuse NEVER touches MTU" rule and
bouncing a compiler-set MTU per race occurrence. Fold: `adopted :=
!ownedAtEntry[tc.Name]` computed once per tunnel from the entry-time
ownedNames snapshot, used by BOTH reuse paths (plain reuse and EEXIST
fallback).

## SMR2-2 (precision, MUST FOLD) — `stopKeepaliveLocked` must remove the map entry

A.1/A.7 reference the new `stopKeepaliveLocked(name)` as "factored from
startKeepalive's stop+drain prologue" — but the prologue
(tunnel.go:528-531) only cancels and drains; it relies on the caller
overwriting the map slot. A removal-path stop that leaves the dead
runner in `t.keepalives` makes `GetKeepaliveState` (tunnel.go:640-648)
return a stale state for a deleted tunnel, and a later re-add with
unchanged identity would "retain" a cancelled runner (probes dead, A.7
skip-logic consulting a corpse). Fold one sentence: stopKeepaliveLocked
= cancel + drain + `delete(t.keepalives, name)`.

## MTU ownership (Q1/Q6) — verified, holds either way

`applyConfig` step 1 (`ApplyTunnels`, daemon_apply.go:259) precedes
step 2 (`d.dp.ApplyConfig`, daemon_apply.go:457) in the same run, and
the compiler MTU writes (compiler_iface.go:351,452,553) are conditional
on configured `MTU > 0` and current≠desired. Two cases:
- Compiler applies a config MTU to the anchor ⇒ adoption's 1500 reset
  is corrected milliseconds later in the same run (the documented
  one-time bounce; no ifindex change).
- Compiler does NOT cover tunnel anchors (they are daemonOwned and the
  MTU loops iterate physical/VLAN interfaces) ⇒ 1500 IS the only
  legitimate value (creation default; the only deviation sources are WG
  leftovers and unsupported manual edits) ⇒ reset is the repair, not a
  clobber.
A compile failure deferring the restore leaves 1500 until the next
successful apply — acceptable: compile failure already aborts/flags the
whole apply (daemon_apply.go:458-463).

## Other v2 attacks that did NOT land

- **ownedNames vs Clear()**: `Apply → ClearTunnels → Apply` — clearLocked
  clears ownedNames per A.1, so the post-Clear Apply adopts instead of
  deleting foreign state. No staleness window found (and ClearTunnels
  has zero callers).
- **gre→wireguard same-name flip**: name in ownedNames, absent from
  desired (WG excluded) ⇒ A.1 deletes the GRE anchor; the WG branch
  creates its own TUN with the WG MTU in the same apply. Correct, and
  the reverse flip is the adoption case A.3 handles.
- **A.1 deleting a foreign same-name link created between applies**:
  identical to today's clearLocked-by-name behavior — no regression.
- **appliedAddrs lifecycle on recreate**: reset before reconcile on the
  recreate path rebuilds it; stale entries reference addresses that no
  longer exist — harmless. Worth a test but not a plan change.
- **Q3 (operator-downed link, runner up)**: skip keyed strictly on
  runner-down is right; an operator down with a healthy keepalive gets
  re-upped by Apply exactly as today's recreate would.
- **Q5 normalization**: the v2 exclusion list (PMtu, Tos, flags,
  encaplimit) plus net.IP.Equal/TTL-default/keys covers every
  kernel-populated field I could find in parseGretunData/parseIptunData
  /parseIp6tnlData that differs from a freshly-constructed desired
  link. Tests on kernel-shaped fixtures pin it.
- **Q2 (fe80 AddrAdd transient failure)**: the address is then absent
  from appliedAddrs AND absent from the kernel — there is nothing to
  leak; next apply retries the add. Best-effort holds.

## Residuals I accept (documented in §10)

Restart-window leaks (stale anchors, stale configured-LL) and the WG
configured-LL follow-up. None are regressions versus today.
