# Claude SMR — hostile plan review, #4874 (round 2, self-correction)

**Verdict (r2): PLAN-READY** on plan r3 (Path C: keep A1, fix A2, fix B).
Per-defect: **A1 → keep. A2 → fix. B → fix.**

## Self-correction (the SMR-soft-pass pattern, per `feedback_triple_review_includes_claude_smr`)

My r1 signed A as a clean PLAN-KILL on the reasoning that `finishClient`
deconfigures the binding on every terminal exit. **That was wrong, and Codex
plan-review r1 caught it.** I verified Codex's BLOCKER firsthand at
`origin/master:4047fd553`:

- `removeAddress` (`dhcp.go` ≈1783-1801) does **only** `AddrDel` — its own comment
  is *"Routes are cleaned up via FRR config removal."* It never withdraws a route.
- `finishClient` (≈386-410) and `abandonLeaseAfterNAK` (≈914-925) fire
  `m.fireGatewayChange()` but **not** `m.scheduleRecompile()`.
- `fireGatewayChange` → `d.ipmon.NotifyNextHopChange()` (`daemon_run.go`
  ≈1475-1478), which only marks the **ip-monitoring overlay** dirty, and only
  when a `PreferredRoute` has a `NextHopInterface` (`ipmon.go` ≈291-315). It does
  **not** re-render the base DHCP default route.
- The base DHCP route (`frr/config_render.go` ≈262-270, from `Leases()`) and the
  RA prefix (`daemon_ra.go` ≈28-31, from `DelegatedPrefixesForRA()`) are rebuilt
  **only** by `applyConfig`, i.e. only on `scheduleRecompile`/`onAddressChange`.

So my "every terminal exit is clean" was half-right: the **address + lease/PD
maps** are removed, but the **FRR default route + RA prefix** are compiled state
that stays stale because the removal paths never recompile. On a
`retransmission-attempt N` exhaustion (goroutine self-exits, no surrounding
`applyConfig`) the stale route/RA persists **indefinitely**; on a DHCPNAK it
persists until the next successful DORA — contradicting the README's documented
"NAK deconfigures immediately." This is a genuine bug (A2) and is exactly the
issue's "stale default routes / incorrect RA" language, which I under-weighted.

I was right that A1 (timeout-retention during unlimited re-acquisition) is the
intentional #1844 design — that half stands. What I missed is that A bundles a
second, non-intentional behavior. Codex's OVERALL PLAN-KILL of my r1 plan is the
correct call *for that plan*; the fix is to widen scope, not to kill the issue.

## Assessment of Codex's other findings (all accepted into r3)

- **F5 (per-prefix vs clear-all):** correct. Servers echo all held PDs on RENEW
  (`renew.go` ≈146-159), so a blunt "0 live + sawWithdrawal ⇒ clear all"
  over-withdraws a co-held prefix the reply merely omitted. r3 uses per-prefix
  `prior \ withdrawn ∪ live`.
- **F6 (acquire-path all-withdrawn):** correct. `parseV6Reply`'s success guard
  (≈1522-1528) + default 1 h lease (≈1548-1549) would let a PD-only acquire with
  only zero-lifetime prefixes settle into an empty "successful" lease. r3 rejects
  it (count *live* prefixes, mirror `selectIANAAddress`).
- **F7 (middle path overstated):** fair. r3 softens Path A′ — rejection is
  architecture-specific, not a law of physics, and #1844 is a *current* tradeoff,
  not settled forever. A clock-expiry knob remains a possible future issue, out
  of scope for #4874.

## What I re-checked and still hold against r3

- **A2 fix must not deadlock/double-apply.** The Reconcile-driven `finishClient`
  runs inside `applyConfigLocked` (holding `applySem`); firing `scheduleRecompile`
  there only arms a debounced timer whose callback runs on a separate goroutine —
  no inline `applySem` re-entry — and the daemon's "skip reconcile when binding
  plan unchanged" coalesces the redundant recompile. r3 §4/§8 R1 states this.
  Acceptable.
- **A2 does not widen WAN exposure.** It only withdraws a route/RA whose lease was
  *already* deleted; it makes teardown match the address, never removes a live
  binding. Correct direction.
- **B risk symmetry.** Withdrawal fires only on an explicit vlt==0; absent IA_PD
  still retains (anti-outage). Matches the shipped v4 NAK-vs-timeout asymmetry.

## Verdict

**PLAN-READY** on r3. A1 keep, A2 fix (couple removal to recompile — extend the
#1844 coupling rule to `scheduleRecompile`), B fix (per-prefix withdrawal +
acquire-path rejection). If Codex r2 concurs on r3, converge 2-of-3 (AGY
infra-down).
