# Codex plan review — round 2 (#1636)

**Task ID**: task-mppsidkk-vifkld
**Plan reviewed**: `docs/research/1636-cold-connect-mitigation/plan.md` v2 @ `913af5d31b41`

## VERDICT: PLAN-NEEDS-MINOR

## Findings (verbatim from Codex)

1. I withdraw r1 #6. Given the AGY trace, D is valid as a candidate: `queued_ns` is per packet, so SYN #2 arriving at t=1000ms gets its own timeout window and is not dropped at t=800ms relative to SYN #1. I do not have a concrete counterexample to maintain the old objection.

2. B then C is the right cadence. Do not ship B+C atomically for bisect cleanliness; separating the sysctl/RTO change from proactive warming gives better attribution. The plan should say B alone is a measurement step, not the final fix.

3. The warmer cost model still needs one hardening detail: use generation collapse / latest-snapshot coalescing. A 1s snapshot rate limit plus 5s per-key rate limit bounds probes, but not stale snapshot traversal or latest-snapshot delay if warm passes take longer than 1s. Use a bounded queue of size 1, drain-and-replace, or equivalent "process latest generation only" semantics.

4. HA ordering is mostly resolved. I do not want a fixed 50ms delay; that is brittle. I do want the invariant stated explicitly: warm pass runs only after RG promote has committed ACTIVE dataplane ownership, interface/MAC/VIP state, and egress maps. Suppress warm on standby/demote. GARP and warm probes sharing MAC/port is not itself a FIB-confusion problem.

5. §10 latency table needs tightening:
   - "B only typical ~50ms" is only true when the first kernel ARP/ND solicit succeeds. Realistic p99 with one lost solicit is about one `retrans_time_ms` later, so roughly 250-300ms with B. Failure is closer to the cold-probe budget, not 50ms.
   - "C only ~1-10ms for known" is fine only if "known" means post-warm-pass completion and after the dataplane has observed the neighbor update. Concurrent-with-warm can include netlink/warm latency.
   - "B+C+D worst case ~1.02s" is not airtight as worded. It is a good target trace for a reachable peer after SYN #1 is dropped and SYN #2 arrives at 1s, but failed/negative neighbor state can push behavior into a second resolution cycle unless the dataplane explicitly re-kicks resolution on `NUD_FAILED`.

6. The new kernel-default concern is real, but the premise should be corrected. Defaults are generally `ucast_solicit=3`, `mcast_solicit=3`, and `app_solicit=0`, not app+ucast = 6. For cold unknown neighbors, effective wire probes are the app/mcast path, with unicast skipped when there is no L2 address. With `retrans_time_ms=250`, cold failure can be around 750ms to 1000ms depending immediate-probe timing. That makes today's 2000ms pending timeout too long after B, and makes D=800ms plausible, but the plan should document this exact model.

7. Long-lived warmer worker is the right threading direction. It fits the coordinator shape if it has explicit shutdown, joined lifecycle, bounded/coalesced work, no shared unsynchronized neighbor-cache mutation, and per-generation observability. Without queue coalescing, I would not call the threading model complete.

8. I am not PLAN-READY yet. The core strategy is sound: ship B, measure, ship C, defer D until data supports it. The remaining issues are plan precision, not design killers.

## Recommendation

Iterate. Fold in generation coalescing, sharpen the kernel probe/defaults section, and qualify the §10 latency gates before marking this PLAN-READY.

Sandbox failed to spawn so direct file verification was not possible; review is based on supplied v2 deltas + AGY trace + Linux neighbor behavior.

## Session

Codex session ID: 019e6fb6-cadf-7de2-8348-61fe17be26d0
