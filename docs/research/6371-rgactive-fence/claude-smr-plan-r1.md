# Claude SMR hostile plan-review — #6371 r1

Reviewing `docs/research/6371-rgactive-fence/plan.md` @ r1 (commit 96f63adaa),
base origin/master @ 3ecdc80568a3. Hostile posture: fail the plan if the
reachability analysis or the recommended architecture is wrong.

## Load-bearing claims — verified firsthand

**Claim 1 (live path does not read the eBPF rg_active map):** VERIFIED.
- `userspace-xdp/` (retained AF_XDP steering shim) has zero `rg_active` /
  `ha_watchdog` references.
- `check_egress_rg_active` lives only in `bpf/headers/xpf_helpers.h:2371`; the
  `bpf/tc/*.c` / `bpf/xdp/*.c` callers were deleted in #1476. Dead retired-eBPF
  code, not a live reader.
- `userspace-dp` forwarding attributes ownership via `owner_rg_for_resolution`
  and gates on `is_forwarding_active(now_secs)` — never the eBPF map.

**Claim 2 (`is_forwarding_active` is the UNIVERSAL transit gate):** VERIFIED —
this was Open Question #2 and it resolves in the plan's favor.
`enforce_ha_resolution_snapshot` (`userspace-dp/src/afxdp/forwarding/ha.rs:66`)
is applied to every `ForwardCandidate` / `MissingNeighbor` / `LocalDelivery`
resolution: a transit `ForwardCandidate` to an owned-RG egress whose
`is_forwarding_active(now)` is false is rewritten to `HAInactive` (not
forwarded). `cached_flow_decision_valid` (:117) re-runs the same check, so even a
**cached** "forward locally" decision for the demoted RG flips invalid once the
lease expires. There is no cache or fast-path that bypasses the lease. The ≤10 s
bound is real.

**Claim 3 (lease cannot be kept alive after demotion):** VERIFIED — Open
Question is implicitly closed. `Manager.UpdateRGActive` sets
`m.haGroups[rgID].Active = false` **before** `requestLocked`
(`manager_ha.go:641-646`), so every subsequent successful `update_ha_state`
(reconcile retry or watchdog heartbeat) carries `active=false` → immediate
demote; the only way the old `active=true` lease survives is if **no** socket
message succeeds, in which case it expires at ≤10 s. There is no path that
refreshes the lease with `active=true` after the demotion. Unbounded is
unreachable (barring a *legitimate* re-election, which is a different scenario).

**Claim 4 (Option D → blackhole):** VERIFIED. `ResignRG` (VRRP priority-0) runs
before `SetRGActive(false)` in the demotion branch (`daemon_ha.go:359-367`), so
the VIP has already surrendered to the peer. Holding the ack on a failed clear
keeps the peer cluster-secondary (`rg_active` false) holding the VIP but not
forwarding → blackhole, bounded only by reconcile re-election or the #5079
15-30 s lease. Option D is a net availability regression. PLAN-KILL is correct.

## Findings

**F1 (MUST FIX — downgrade the "open questions" to verified).** Open Questions #1
and #2 (§10) are the load-bearing pillars of the entire reachability refutation.
Leaving them "open" undersells a plan whose central claim depends on them. Both
are now firsthand-verified (above). The plan must FOLD the
`enforce_ha_resolution_snapshot` universality + the `haGroups.Active=false`
before-send ordering into §3 as verified facts, and reduce §10 to genuine
residual questions (the alarm cost/benefit, the retry placement). A plan that
rests on "open questions" for its refutation is not PLAN-READY.

**F2 (SCOPE — the recommendation over-reaches vs. the evidence).** The plan's own
analysis shows the current behavior is already bounded (≤10 s lease) +
fail-closed + fabric-mitigated + retried every 2 s. Given that, the fast bounded
retry (Path A′ item 2) earns little: it shrinks a ≤2 s typical window to
sub-second on *transient* errors, but transient errors are already invisible to
operators and self-heal. The ONLY genuine gap the evidence supports is
**observability** (item 4) + the doc correction (item 5) + at most an immediate
`triggerReconcile()` (item 3, ~free). Justify the fast-retry's added
control-flow complexity against the ≤2 s it saves, or drop it and ship the
minimal (c)+reconcile-nudge. A hostile reviewer reads A′ as gold-plating a
non-problem. Recommend r2 re-frame the headline recommendation as "observability
+ doc + immediate reconcile" with the fast-retry demoted to an OPTIONAL
sub-item with an explicit earn-its-keep argument.

**F3 (justify the alarm is actionable).** The plan proposes a security-severity
alarm/metric but does not say what the operator DOES with it. State the
actionable value explicitly: it distinguishes a *helper-wedged / control-socket-
persistently-failing* condition (a real, otherwise-silent fault that today only
emits an ordinary `Warn` indistinguishable from a benign retry) from routine
transients — i.e. it is a helper-liveness alarm, not merely a dual-active
post-hoc flag. That framing also argues for the metric surface.

**F4 (MINOR — name the residual security exposure precisely).** §3.3 should state
the residual crisply: the only genuinely dual-forwarded traffic during the
window is stale-ARP/ND residue still L2-delivered to this node's pre-resign MAC
(existing flows are fabric-relayed to the peer; new flows go to the peer's VIP).
That is the precise attack/exposure surface the security label is about, and it
is bounded by the shorter of {ARP cache timeout, 10 s lease}. Make it explicit so
a reviewer can weigh the security severity honestly.

**F5 (MINOR — test plan RED binding).** The parent-RED for the alarm/metric is
sound (revert → counter stays 0). But confirm the daemon test can drive a
demotion event end-to-end with a failing `SetRGActive` fake WITHOUT a live
helper/cluster — the existing `daemon_ha_fence_3917_test.go` uses a
`fenceRecorderHA`; verify the event-injection harness reaches the demotion
branch (line 353-389) in a unit test, else the binding is aspirational.

## Verdict

The reachability refutation is SOUND and now fully corroborated firsthand; the
Option D PLAN-KILL is correct and well-argued. But the plan (a) rests its central
claim on "open questions" that are actually resolved (F1), and (b) over-scopes
the recommendation beyond what its own evidence supports (F2). These are
revisions, not a kill.

VERDICT: PLAN-NEEDS-REVISION
