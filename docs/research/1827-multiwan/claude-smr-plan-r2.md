# Claude SMR hostile plan review — #1827 multi-WAN, round 2 (plan v2)

**Verdict: PLAN-READY** — contingent on the two §2 folds below being applied
to the plan text (applied as v2.1 in the same round) and on Codex/AGY r2
raising no new Critical.

## 1. Verification of v2's resolutions (not taken on assertion)

- **Routes-only actuator feasibility** — I went looking for the weak point
  (does a snapshot rebuild require the full compile path?) and found the
  opposite: the policy-scheduler republish path at
  `pkg/dataplane/userspace/manager.go:700-740` already does exactly what
  the actuator needs — clone `lastSnapshot`, refresh specific sections
  (`Policies`, `AddressBooks`), bump generation, `apply_snapshot`, all
  without recompiling. The ip-monitoring actuator is the same pattern with
  `Routes` refreshed via `buildRouteSnapshots(cfg, interfaces, overlay)`.
  v2's design has an in-tree template; feasibility risk is closed. The
  plan should cite it (fold A below is optional strengthening; cited in
  v2.1).
- **FRR assembly drift** — `frr.FullConfig` assembly at
  `daemon_apply.go:740-776` uses only cfg + daemon state
  (`collectDHCPRoutes`, `RethMap`, `inferIPv6StaticNextHopInterfaces`);
  extraction into a shared `assembleFRRConfig(cfg, overlay)` is mechanical.
  Accepted.
- **fwmark pin plumbing** — repo-wide grep: zero `SO_MARK`/fwmark users in
  Go or Rust. `pkg/routing/rules.go` already manages disjoint priority
  bands (next-table 100+, PBR 31000+, rib-group 33000+) with band-scoped
  clear scans; a probe-pin band with a fwmark match fits the existing
  pattern exactly. No conflict found. Accepted.
- **preferred-metric correction** — matches the Juniper evidence gathered
  in round 1 (injected route preference 1 / `Static/1`; preferred-metric
  is a metric). The engine-side winner resolution is a faithful observable
  stand-in given FRR statics carry no metric; it also makes same-prefix
  resolution deterministic. Accepted.
- **FIB generation** — `BumpFIBGeneration()` at `manager.go:918` and the
  lightweight `bump_fib_generation` control message at `manager.go:968`
  exist as claimed; v2 makes the bump explicit + tested. Accepted.
- **Primary-only probing, FBF commit-fence, PR-1a/1b split, smoke
  downgrade** — all consistent with r1 demands. Accepted.

## 2. New findings on v2 (must fold)

**Fold A (MEDIUM) — RPM primary-only gating scope is over-broad as
written.** §4.4 says "probes ... run only on the node that is primary for
the data RG". RPM today also serves plain monitoring + eventengine on
cluster deployments; blanket-gating ALL probes on RG primaryship would
silently change existing behavior for cluster users whose probes have
nothing to do with multi-WAN. Required precision: only probes that are
(a) referenced by an ip-monitoring policy, or (b) bound via
`destination-interface`/`source-address` to a VIP-owned (RETH) interface
are primary-gated; all other probes keep today's run-everywhere behavior.

**Fold B (LOW) — sustained-flap floor.** With hold-down 0 (parity
default), a probe that alternates pass/fail per test cycle produces one
frr-reload + one snapshot push per debounce window indefinitely. Bounded
and observable (`transitions_total`), but the plan should add one line of
operator guidance: set `hold-down` on known-flappy links; and the smoke
plan's flap test should assert the bound (≤1 actuation per window), not
just "damping holds".

## 3. Residual positions (no plan change needed)

- The takeover window (§12 Q4) is correctly bounded; syncing overlay
  state over HA channels for state that re-derives in one fast probe
  cycle would be a worse trade. Keep as designed.
- PR-1b kill criteria are now concrete (carve-out maintainability;
  content-hash/fib-gen transition-delivery tests) — testable in week 1.
- AGY's r1 probe-on-both dissent: my position stands with v2 — there is
  no per-node WAN addressing mechanism in this codebase today (VIP-owned
  RETH model, `direct_vip_ownership_test.go:16`); the follow-up filing is
  the right disposition. If AGY r2 can cite a concrete in-tree mechanism,
  I will reopen.

With folds A and B applied, this plan is implementable as staged, the
PR-1 unit is genuinely small (two PRs, each ~700-900 LOC, zero Rust), and
every stage has a real tripwire. PLAN-READY.
