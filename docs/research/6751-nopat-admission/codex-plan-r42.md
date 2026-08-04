# Codex hostile plan review — #6751 (round 42)

# PLAN-NEEDS-REVISION

Reviewed the immutable `7a5c3e91e` blob. Uncommitted plan edits appeared during review and are excluded.

1. **BLOCKER — Capability-gated lineage resolution remains contradictory.**  
   The correct rule says non-capability windows never confirm, purge, or clear lineage (`plan.md@7a5c3e91e:701-723`, `2333-2358`). Retained rules still confirm at insertion (`2400-2410`), treat the next/every `BulkEnd` as definitive and run P1 (`2435-2472`), define the legacy path as confirming aliases (`2964-2975`), and require unconditional confirmation/purge in tests (`3262-3268`, `3390-3397`). An implementor still has two incompatible authority rules.

2. **BLOCKER — The seventh lifecycle event and fence precedence are absent from the detailed contract.**  
   The new rule adds generation-tagged fence-cycle expiry and fence-state precedence (`773-790`), but the committed lifecycle specification still calls the six-event inventory complete (`1669-1676`). Its readiness commit revalidates only arming generation and connected state (`1713-1734`), while §9 repeats that two-condition test and omits stale fence-expiry-after-rearm coverage (`3137-3151`). This leaves the exact race exposed by asynchronous disconnect notification at `pkg/cluster/sync_conn.go:569-570`; current readiness code likewise checks only timer generation and connectedness at `pkg/daemon/daemon_ha_sync.go:40-46`.

3. **BLOCKER — Fence engagement never arms the hold that fence expiry later “releases.”**  
   `plan.md:784-810` specifies release and private-election consumption, but never requires engagement to set sync readiness false or re-arm classic VRRP hold. Today a warm disconnect after an earlier bulk deliberately preserves readiness (`pkg/daemon/daemon_ha_sync.go:113-136`), and classic hold is armed only at startup (`pkg/daemon/daemon_run_bringup.go:226-239`; `pkg/vrrp/manager.go:351-376`). Concrete trace: prior bulk → `syncReady=true` → later fence → warm disconnect preserves true → private takeover remains eligible throughout the fence; expiry’s release is a no-op.

4. **BLOCKER — The introduced private-RG gate lacks a “sync configured/owed” predicate.**  
   `PrivateRGElection` defaults true (`pkg/config/compiler_system.go:1897-1901`), while `NewManager` leaves `syncReady=false` (`pkg/cluster/manager.go:383-408`). The existing startup release timer is armed only with configured fabric endpoints (`pkg/daemon/daemon_run_bringup.go:238-240`). The unconditional gate at `plan.md:806-810` can therefore make a default private-RG cluster without session sync permanently takeover-ineligible.

5. **MAJOR — The private-RG behavior change is neither priced nor actually test-pinned.**  
   It reverses the deliberate steady-state policy recorded in `docs/issues/issue-history.md:8513-8527` and merged by `docs/issues/pr-history.md:4277-4289`, yet §8 omits the default-mode failover delay (`plan.md:2994-3001`). The claimed §9 takeover-refusal test is absent; §9 only names the gate as an outer bound (`3074-3085`). Existing coverage pins the opposite behavior at `pkg/daemon/vip_readiness_test.go:345-389`.

6. **MAJOR — Alias confirmation names an impossible source.**  
   The detailed rule correctly requires the decode-time base-identity index because the store lacks `RTFlowSessionID` (`plan.md:2411-2425`). The hidden invariant instead says to check “the current store” (`2968-2972`). That store delegates to BPF (`pkg/dataplane/session_store.go:118-143`), whose lifted value omits this sync-only ID (`pkg/dataplane/bpf_session_value.go:204-238`; `pkg/dataplane/types.go:114-136`).

7. **NIT — The interval formula is missing from the promised parameter summary.**  
   `plan.md:668-670` says `2 × syncReadDeadline + 5s` joins the implementation summary, but `3416-3426` omits it.

Verified folds:

- The capability gate is correctly specified as a checked direct write before publication (`plan.md:1394-1408`), matching the current publication boundary at `pkg/cluster/sync_conn.go:130-145/244-286`. Fail-closed is defensible because `writeFull` can fail after a partial frame (`pkg/cluster/sync_protocol.go:63-74`); publishing that stream as UNKNOWN could retain corrupt framing.
- No stale 7.5s or `2.5×keepalive` parameterization remains. Both normative sites use `2 × syncReadDeadline + 5s`, consistent with the 10s deadline and two ACK-gated misses (`pkg/cluster/sync.go:88-91`; `pkg/cluster/sync_conn_read.go:27-38`).
- The distinct degraded effect and separation from both debts are correctly stated at `plan.md:790-796` and `500-510`, though §9 should explicitly pin unchanged priming state and a degraded—not `bulk-sync-complete`—release reason.
- No new kill shot was found against the settled option-(a) registry/occupancy/holder core. The blockers remain in surviving alias, fence, and readiness machinery.
