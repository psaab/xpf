PLAN-NEEDS-REVISION

1. **Critical — Path D-full-apply is not acceptable as PR-1 actuation.**  
Evidence: [daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/daemon/daemon_apply.go:67) wraps `applyConfigLocked` under `applySem`; the locked path reconciles VRFs/interfaces, tunnels, FRR, DNS/system services, event-options, and cluster state. It also restarts heartbeat after mgmt VRF rebinding at [daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/daemon/daemon_apply.go:718): `d.cluster.RestartHeartbeat()`. If PR-1 adds `d.rpm.Apply(...)` into this path as planned, every ip-monitoring transition can also restart RPM; [rpm.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/rpm/rpm.go:108) calls `m.StopAll()`, and [rpm.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/rpm/rpm.go:147) clears `m.results`.  
Concrete fix: kill Path D-full-apply. Add a route-only actuator under the same semaphore: render FRR overlay plus rebuild/publish userspace snapshot only. RPM re-apply must be config-hash-gated and not run on route-state transitions.

2. **High — The plan’s `fib_generation` invariant is unproven for userspace.**  
Evidence: legacy compile explicitly bumps FIB generation at [compiler.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/dataplane/compiler.go:276). Userspace compile instead builds the snapshot with `m.readFIBGeneration()` at [manager.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/dataplane/userspace/manager.go:558); it bumps snapshot generation, not FIB generation. Rust checks both config and FIB generation at [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/userspace-dp/src/afxdp/forwarding/mod.rs:14).  
Concrete fix: either explicitly bump userspace FIB generation on overlay route changes, or rewrite the invariant around config-generation invalidation and prove established cached flows re-resolve in tests.

3. **High — Probe pin routes must not enter the userspace transit FIB.**  
Evidence: the plan says `next-hop` creates an always-on `/32`/`/128` route and puts pin routes in the same overlay at plan lines 108-110 and 188-189. But [RouteSnapshot](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/dataplane/userspace/protocol.go:499) is the transit FIB input. A pin to `1.1.1.1/32` would steer customer transit traffic to `1.1.1.1` via the probe uplink.  
Concrete fix: make pin routes kernel/FRR-only for host-originated RPM probes, excluded from `RouteSnapshot`. Document the residual kernel slow-path behavior.

4. **High — PR-1 exposes `preferred-route routing-instance` before fixing forwarding-instance semantics.**  
Evidence: plan line 123 includes `preferred-route routing-instance ISP-B`, but PR-2 defers the forwarding-instance divergence at line 260. Current code renders forwarding-instance statics into the default FRR table via `vrfName = ""` at [daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/daemon/daemon_apply.go:760), while userspace files RI routes under `<ri>.inet.0` at [routes.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/dataplane/userspace/routes.go:77). PBR lookup targets `<ri>.inet.0` at [mod.rs](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/userspace-dp/src/afxdp/forwarding/mod.rs:972).  
Concrete fix: PR-1 must either fix forwarding instances or commit-reject `preferred-route routing-instance` when the target is `instance-type forwarding`. Allow virtual-router only.

5. **High — `preferred-metric → FRR admin distance` is not proven.**  
Evidence: the plan asserts the mapping at lines 126-130 and asks the same question at 416-419. The code can render a static route distance via [config_render.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/frr/config_render.go:147), but that only proves FRR feasibility, not Junos parity.  
Concrete fix: add vSRX or official Junos evidence showing `services ip-monitoring ... preferred-metric` becomes route preference/admin distance. Until then, this is an unverified parity claim and should block PR-1.

6. **Medium — Same-prefix override needs an exact replacement invariant.**  
Evidence: `RouteSnapshot` has no preference field at [protocol.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/dataplane/userspace/protocol.go:499). Current dedup includes next-hop in the key at [routes.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/dataplane/userspace/routes.go:20), so two same-prefix entries with different next-hops can coexist today.  
Concrete fix: implement overlay build as a map keyed by `(table,family,prefix)` where overlay replaces the entire route entry, never merges next-hops. Add ECMP replacement tests.

7. **Medium — The transition storm bound is theater as written.**  
Evidence: RPM integer validation only requires `> 0` at [compiler_services.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/config/compiler_services.go:15), so 1-second intervals are legal. FRR reload has a 15s timeout at [manager.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/frr/manager.go:43). `applyConfig` waits with `context.Background()` at [daemon_apply.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/daemon/daemon_apply.go:68).  
Concrete fix: coalesce transitions with a pending/dirty bit and bounded debounce; never queue unbounded applies.

8. **Medium — PR-1 is not “small and shippable” in its current shape.**  
Evidence: plan lines 246-252 include config schema/parser/compiler, RPM real ICMP plus lifecycle, new ipmon engine, daemon HA wiring, FRR, userspace snapshot builder, show, metrics, and docs. That is central control-plane surgery. The fake ICMP prerequisite is real: [rpm.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/rpm/rpm.go:301) dials `ip4:icmp` but sends no echo, then [rpm.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/rpm/rpm.go:304) falls back to UDP connect.  
Concrete fix: split PR-0 for real ICMP + RPM config reapply, then PR-1 for ip-monitoring overlay.

9. **Medium — HA probe-on-both is the wrong default.**  
Evidence: the plan proposes “probes run on both nodes” at line 218. The HA code makes VIP ownership primary-specific: promotion forces VRRP master at [daemon_ha.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/daemon/daemon_ha.go:235), demotion resigns at [daemon_ha.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/daemon/daemon_ha.go:269), and tests assert “local secondary never owns VIPs” at [direct_vip_ownership_test.go](/home/ps/git/bpfrx/.claude/worktrees/research-1827-multiwan/pkg/daemon/direct_vip_ownership_test.go:16).  
Concrete fix: run/publish probes primary-only for data RGs. On takeover, publish baseline routes, run an immediate fast probe cycle, then apply overlay.

10. **Low — The single-WAN lab plan is honest but not sufficient for HA claims.**  
Evidence: plan lines 332-356 use two VLANs on one provider and claim PR-1’s route flip is topology-independent. That can prove snapshot/FRR flip, not RETH ownership, standby behavior, or physical uplink failure.  
Concrete fix: PR-1 smoke must add either an incus two-upstream topology or explicitly downgrade HA/passive-uplink claims to unit-tested only.

**Section 12 positions:**  
1. Primary-only probing, not probe-on-both.  
2. Do not approve preferred-metric mapping until proven on Junos/vSRX.  
3. Real ICMP belongs before ip-monitoring; split or first independent commit.  
4. Full apply per transition is rejected.  
5. Build-time override is right for PR-1 only with whole-prefix replacement.  
6. Auto pin routes are acceptable only kernel/FRR-only, not snapshot.  
7. Forwarding-instance target is a PR-1 precondition unless commit-rejected.

Codex session ID: 019eb2cc-12af-7c41-a8ae-6f9811325ec4
Resume in Codex: codex resume 019eb2cc-12af-7c41-a8ae-6f9811325ec4
