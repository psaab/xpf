# Claude SMR — hostile plan-review r2 (#4455 HI-1)

**Reviewer:** Claude SMR (self-review, adversarial). **Target:** plan.md r2.
**Round-1 verdict:** PLAN-REVISE. **Round-2 verdict: PLAN-KILL (converged).**

## Did r2 resolve the round-1 blocking issues?

- **B1 (redundant accepts):** RESOLVED — §5.1 commits to Shape A (un-admitted
  dedicated-group drops only; no accepts, no broadcast handling).
- **B2 (unverified resolver):** RESOLVED and sharpened by Codex C4/C5/C6 — §5.2
  now uses a membership-derived source (not the address-lazy view), the actual
  `ResolveKernelIfName` behavior (RETH→physical member), and live-netdev
  validation with fail-open on unresolved. The correctness risk is re-rated
  Med-High.
- **B3 (one-sided guard):** RESOLVED — §5.4 is now two-sided (shim tripwire + an
  explicit GRE-inner disposition), which is exactly what Codex C1 forced.
- **N1/N2/N3:** RESOLVED — subnet-directed broadcast reasoned-deferred, the thin
  value is stated plainly, counter prefix `xpfhimc_`.

Codex's independent findings (C1 native-GRE inner multicast reaching the XSK; C2
v4 raw VRRP fallback; C3 enable-time FRR breakage + PIM-unmanaged; C4 address-lazy
iifname source; C5 RETH→physical-member resolver; C6 guess-on-malformed) are all
folded into §0 and §5–§7 with correct file:line attribution.

## Why I converge on PLAN-KILL (not merely PLAN-READY-for-narrow-scope)

At r1 I left the door open to "PLAN-READY for narrow Shape-A." Round 1 changed my
weighting decisively:

1. **The correctness surface is larger than the feature.** The actual work is not
   "emit a few per-zone drops" — it is a NEW membership-derived interface-set
   builder, a live-netdev-validated kernel-name resolver that must correctly
   handle RETH (which resolves to a physical member, not a `reth` netdev) and
   VLAN sub-units, an explicit native-GRE-inner disposition with a proof test,
   and a strict-on-enable FRR cross-check. That is four independent correctness
   mechanisms, each with its own failure mode (fail-open on the wrong source,
   drop-on-the-wrong-interface, split-brain on decap, adjacency loss on enable),
   guarding a feature whose reachable benefit is near-zero.
2. **The benefit population is empty by construction.** M-i's strict-on-enable
   cross-check means enabling is only permitted once the operator has set the
   matching tokens — so the enforcement never protects the "ran a protocol
   without the token" case it exists for. It is self-defeating: safe exactly when
   it is unnecessary.
3. **It protects nothing that is at risk.** VRRP failover is AF_PACKET-immune
   (F2); the bounded exposure means nothing is delivered to an unjoined group.
   There is no live hazard being closed — only a cosmetic "packet-wide vs
   per-zone" parity delta the shipped advisory already documents.
4. **Both hostile reviewers independently reached the same stop.** Codex:
   "keep the shipped advisory and kill enforcement." Convergent, not coerced.

## What "PLAN-KILL" means here (not a dead end)

The shipped #4454 catalog + commit-time advisory is the correct terminal state:
it makes the parity gap operator-visible without introducing HA/routing-critical
drop risk. r2 preserves the corrected design (§5–§8) so a future `/engineer 4455`
can implement it verbatim IF an operator later decides the strict-parity
hardening is worth the four-mechanism correctness burden — with the C1/C4/C5/C6/C3
items as mandatory acceptance criteria. Nothing is lost by stopping; the research
is captured.

**Verdict: PLAN-KILL, converged with Codex. Recommend labeling #4455
`plan-kill`, keeping it open as the tracked design record (or closing with this
plan linked), and leaving the #4454 advisory as the shipped surface.**
