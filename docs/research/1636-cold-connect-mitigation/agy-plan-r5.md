# AGY adversarial plan review — round 5 (#1636)

**Job ID**: adversarial-review-mppt55mr-9htu20
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v5 @ `1016ccfca89f`

## VERDICT: PLAN-READY

> AGY's verdict statement at the end was PLAN-READY but their finding 1
> is MEDIUM severity. The reasonable read is "PLAN-READY pending the
> medium-severity HA architecture mismatch fix during /engineer". Per
> /research convergence discipline, fold the medium and the two lows
> into v6 before declaring PLAN-READY across all reviewers.

## Findings (verbatim from AGY)

### Finding 1 [SEVERITY: MEDIUM] Architectural mismatch in multi-RG HA active checks

The plan assumes `ha: Arc<HaSnapshot>` exists and calls `ha.is_active()` globally on both the coordinator and worker. However, `HaSnapshot` does not exist in the codebase, and `HaState` lacks a global `is_active()` method. xpf tracks HA leases **per Routing Group (RG)** using `HAGroupRuntime::is_forwarding_active(now_secs)`. Naively treating HA active status as global could cause standby routing group interfaces to trigger unwanted neighbor probes.

**Mitigation**:
1. Add a routing group identifier field to `WarmItem`:
   ```rust
   pub(crate) struct WarmItem {
       ifindex: i32,
       hop: IpAddr,
       iface_name: String,
       generation: u64,
       rg_id: i32, // Added to map back to the correct HA Group lease
   }
   ```
2. In `Coordinator::queue_warm_pass()`, retrieve RG ID for egress interface via existing `owner_rg_for_flow(&self.forwarding, egress_ifindex)` and verify lease before enqueue:
   ```rust
   let now_secs = monotonic_nanos() / 1_000_000_000;
   let is_active = self.ha.rg_runtime.load().get(&rg_id)
       .map(|g| g.is_forwarding_active(now_secs))
       .unwrap_or(false);
   if !is_active { return; }
   ```
3. In `warmer_loop`, perform pre-fire re-check against item's `rg_id`:
   ```rust
   let now_secs = monotonic_nanos() / 1_000_000_000;
   let is_active = ha.load().get(&item.rg_id)
       .map(|g| g.is_forwarding_active(now_secs))
       .unwrap_or(false);
   if !is_active { continue; }
   ```

### Finding 2 [SEVERITY: LOW] Performance risk if sysctl reads are not cached at initialization

The sysctl read for PR-3's `PENDING_NEIGH_TIMEOUT_NS` decision should happen **exactly once at startup** and be cached in a `OnceLock` or config field. Avoid system calls in packet-forwarding or timer loops.

### Finding 3 [SEVERITY: LOW] Omission of dual-stack IPv4/IPv6 verification in sysctl fallback logic

Read BOTH IPv4 and IPv6 retrans_time_ms sysctls; take max via `std::cmp::max(retrans_v4, retrans_v6)` so the conservative timeout governs both stacks. (Aligns with Codex r5 #1 + extends it.)

## R4 check-list responses

1. Mutex poisoning fix via `.expect()`: **Fully Adequate**. Panic-on-poison terminates the worker loudly. Channel disconnect triggers operator-visible warning + Prometheus counter.
2. D=800ms operational hazard mitigation: **Fully Adequate** with refinements (dual-stack + cached read).
3. Disconnected log flood mitigation: **Fully Adequate**. `warned_disconnect.swap()` is correct.
4. Anything new fatal in v5: Findings 1, 2, 3 (none fatal).

## Recommendation

proceed to /engineer 1636

(But fold Finding 1 medium + Findings 2-3 lows into v6 PLAN-READY before declaring full convergence.)
