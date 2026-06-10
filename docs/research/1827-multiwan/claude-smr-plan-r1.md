# Claude SMR hostile plan review — #1827 multi-WAN, round 1

**Verdict: PLAN-NEEDS-REVISION**

The survey is accurate (I verified the load-bearing claims against the
worktree myself: fake icmp-ping at `pkg/rpm/rpm.go:294-313`; config-derived
FIB at `pkg/dataplane/userspace/routes.go:14-146`; RPM applied only at
startup `pkg/daemon/daemon_run.go:601-605`; `instance-type forwarding`
vrfName="" at `pkg/daemon/daemon_apply.go:760-763`; qualified-next-hop
preference dropped at `pkg/config/compiler_routing.go:170-181`). The Path A
(Junos parity) recommendation is right. But the PR-1 actuation design has a
defect class that would bite in production, and the HA probing story is
internally inconsistent. Findings:

## 1. CRITICAL — full-applyConfig actuation has side-effect breadth that
## creates feedback loops

Plan §4.3 actuates transitions via `d.applyConfig(activeCfg)` (feeds
precedent). But `applyConfig` is not routes-only:

- `daemon_apply.go:700-721` — step 2.7 re-binds mgmt-VRF interfaces and
  calls `d.cluster.RestartHeartbeat()`. An ip-monitoring transition would
  restart the HA heartbeat. Memory #1800 already flags RestartHeartbeat as
  needing coordinated suppression — a WAN probe flap must never be able to
  perturb split-brain detection.
- Worse: the plan itself adds `d.rpm.Apply(...)` to the applyConfig sequence
  (§4.2 item 2). `rpm.Apply` calls `StopAll()` and **clears all results**
  (`pkg/rpm/rpm.go:108-150`). So: probe fails → transition → applyConfig →
  probes restarted, results wiped → engine input resets to "unknown" →
  potential oscillation between applied/withdrawn overlay. The engine's
  actuator would destroy the engine's sensor on every actuation.

**Required fix:** keep the *decision point* single (the overlay), but make
the *actuator* a routes-only subset: a dedicated function that, under the
same apply semaphore, (a) re-renders FRR `ApplyFull` with the overlay and
(b) rebuilds + pushes the dataplane snapshot. No networkd, no ipsec, no
RPM re-apply, no heartbeat path. Separately, the new RPM re-apply-on-commit
must be config-hash-gated (restart probes only when the RPM stanza actually
changed) so even operator commits don't reset probe state gratuitously.
Path D-full-apply as written should be rejected; rename the recommended
path accordingly.

## 2. HIGH — "probe on both nodes" is broken on RETH uplinks

Plan §4.4: probes run on both nodes, publish gated on primary. But uplink
interfaces in the HA deployment are RETH units whose addresses are
VRRP-owned VIPs — the standby does not hold the source address at all
(`ReconcileVIPs`/VRRP ownership). Standby probes with `source-address`
(or even without — no usable address on the RETH) will fail at bind/route,
permanently. The plan's own Q1 hedges here; the answer should be decided in
the plan, not deferred: **primary-only probing (Junos parity)**, with
takeover triggering an immediate collapsed-interval probe burst and the
config baseline (no overlay) published until first fresh results. State
machine: standby holds NO probe state; takeover = cold start with fast
first cycle. This also kills the "stale-fail on takeover" complication.

## 3. HIGH — probe pin routes must not steer transit traffic, and they
## contradict the publish gate

§4.1 `next-hop` → always-on /32 pin route emitted "through the same
effective-route mechanism", i.e. into FRR **and** the dp snapshot. Two
defects:

- Probe targets are frequently real destinations (1.1.1.1, 8.8.8.8).
  A pin route in the dp snapshot silently policy-routes *customer transit
  traffic* to the probe target via the probed uplink. Probes are
  host-originated — they consult the **kernel** table only. The pin route
  therefore belongs in FRR/kernel only and must be **excluded from the
  snapshot overlay**. (Residual: kernel-slowpath transit to the target is
  still pinned — document, it's the same residual SRX has.)
- If probing were to run on standby (rejected per finding 2), pin routes
  would be needed there too, contradicting publish-on-primary. With
  primary-only probing this resolves itself, but the plan must state that
  pin routes follow probe lifecycle (primary-only), not config lifecycle.

## 4. MEDIUM — DHCP-learned uplinks are silently out of scope; say so

`buildRouteSnapshots` includes config statics + connected only; DHCP
defaults go to FRR (`collectDHCPRoutes`, AD 200) but never reach the dp
FIB. A DHCP-addressed WAN already cannot carry dp fast-path transit today
unless a static default also exists. Multi-WAN v1 must therefore REQUIRE
static next-hops on uplinks (consistent with ip-monitoring's explicit
next-hop model), and the plan needs this as an explicit limitation +
follow-up issue pointer, or operators with DHCP WANs will read "multi-WAN
support" and file bugs.

## 5. MEDIUM — transition coalescing unspecified

§4.3 asserts damping via RPM thresholds + hold-down, but with N policies on
M probes, anti-correlated flaps can queue N back-to-back route actuations.
Specify: engine debounces transitions into one actuation per coalesce
window (e.g. 500ms-1s), and the actuator snapshots the overlay at run time
(last-writer-wins), so a storm collapses to one FRR render + one snapshot
push. Cheap to specify now, painful to retrofit.

## 6. MEDIUM — snapshot generation/content-hash invariant needs a named test

§7 item 4 says "verify the skip-if-identical path can't eat a transition".
Not enough — make it a concrete PR-1 test: build snapshot with overlay A,
then overlay B (same config), assert generation bump + content-hash
difference + sync fired. If the hash doesn't cover overlay routes, a
transition could be silently skipped — that's a failover-doesn't-happen
bug, the worst class for this feature.

## 7. LOW — naming and schema nits

- `show services ip-monitoring status` vs existing
  `show chassis cluster ip-monitoring status`: also audit `cmd/cli/show.go`
  prefix matching so `show services ip` doesn't ambiguously collide.
- `target address <ip>`: make `address` the canonical schema child and keep
  bare-value as deprecated-but-accepted, mirroring Junos display form
  (`docs/junos-config-display-reference.md` discipline).

## Positions on §12 open questions

1. Primary-only probing (finding 2). Suppression, not publish-gating.
2. preferred-metric→FRR distance is correct (zebra installs only the best
   same-prefix static; withdrawal re-exposes AD-5/200). Keep default 1.
3. Real ICMP in PR-1, yes — ship as first logical commit so it's
   independently revertable; release-note the semantic change.
4. Rejected as designed (finding 1); routes-only actuator under the apply
   semaphore is the acceptable form.
5. Build-time override is right for PR-1; add a one-line guard: overlay
   replacement must replace the *entire* (table,family,prefix) entry set,
   never merge next-hops, so PR-4 ECMP can't half-override.
6. Pin routes kernel-only (finding 3). Auto-install is fine with that
   scoping + a commit-check warning when a pin target overlaps a configured
   static destination.
7. PR-2-first-task is the right scope IF PR-1 commit-rejects
   `preferred-route routing-instance <ri>` targeting a `forwarding`-type
   instance (allow `vrf`-type). Otherwise PR-1 exposes the divergence on
   day one. Add that commit check to PR-1.

## Per-stage kill criteria

PR-1/PR-2 criteria are real tripwires. PR-3's "fallback is document, don't
build" is acceptable. PR-4's gate (fresh /research, not pre-authorized) is
correct given dp ECMP determinism is unaudited.

**Round-2 expectation:** plan v2 with findings 1-3 resolved in the design
text (not as open questions), 4-6 folded into scope/tests, then I expect to
land at PLAN-READY absent new reviewer evidence.
