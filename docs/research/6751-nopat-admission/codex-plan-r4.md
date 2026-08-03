# Codex hostile plan review — #6751 plan v4 (round 4)

# PLAN-NEEDS-REVISION

v4 fixes several round-3 findings conceptually, but the core ownership invariant is still falsifiable on cross-domain reserve, drain transition, worker shutdown, local shared publication, and tuple-changing refresh paths.

1. **BLOCKER — Pool-first reserve still permits a cross-domain duplicate after an incumbent conflict.**

   Counterexample:

   1. Draining pool allocator `A` owns `T = (E:p, D:d)` for pool flow `P`.
   2. An INTERFACE-mode synced flow `I`, with a different flow key but the same translated identity `T`, arrives.
   3. Pool-first reserve finds `E` in `A`, but `reserve_flow` returns false because `P` owns the identity.
   4. The scan falls through to the interface registry.
   5. Interface reserves are explicitly not quarantined, so `I` claims `T` in the interface allocator.
   6. `P` and `I` are both published/reachable with the same reverse tuple.

   The current pool scan conflates “not this pool” with “identity conflict”:

   ```rust
   if rule.pool_allocator.reserve_flow(...) {
       break;
   }
   ```

   A false result simply continues at [source.rs:921](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:921>) and [source.rs:945](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:945>). v4 retains pool-first scanning and then adds an interface fallback at [plan.md:276](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:276>), while exempting reserves from quarantine at [plan.md:440](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:440>).

   The quarantine mint probe does not unify reserve conflicts. The reserve API needs at least a tri-state result: `Owned`, `IdentityConflict`, or `NotThisDomain`. `IdentityConflict` must abort/drop, never fall through.

   NAT64 also needs an explicit provenance gate. Worker import currently invokes both source-NAT reserve and NAT64 reserve at [upsert_synced.rs:90](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:90>) and [upsert_synced.rs:105](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:105>). A `nat.nat64` decision must bypass the source/interface registry or it can acquire two domain tokens.

2. **BLOCKER — The DRAIN transition itself still permits duplicate ownership.**

   v4 explicitly accepts this race:

   > a NEW interface mint … can claim an identity a preserved session still holds

   at [plan.md:443](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:443>). That is not merely availability loss. Until the preserved session is dropped, both sessions are reachable with the same identity, recreating the confidentiality bug.

   Same-plan refresh keeps workers live and publishes the new `RuntimeView` at [snapshot_refresh.rs:458](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:458>) and [snapshot_refresh.rs:472](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/snapshot_refresh.rs:472>). Drain-marker installation must therefore commit before that store. Early marker installation is safe—temporary over-quarantine—while late installation is not.

   Drain completion also needs a closed/resurrection protocol. A late synced reserve cannot be allowed to increment a “drained” allocator after its interface quarantine has been removed. Either atomically reinstall quarantine before accepting it or reject the late reserve.

3. **BLOCKER — The proposed per-index live counter is incorrect for existing address-only allocations.**

   `LiveAllocation.addr_index` is authoritative for PAT allocations, but not all address-only allocations. Current address-only records deliberately write zero:

   ```rust
   LiveAllocation {
       ...
       addr_index: 0,
       address_only: true,
   }
   ```

   at [allocator.rs:1770](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1770>) and [allocator.rs:1874](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1874>). The round-robin comment explicitly calls the minted shape `addr_index = 0` at [allocator.rs:1809](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1809>).

   For pool `[A,E]`, an address-only flow allocated on `E` can therefore be counted against `A`; `E` appears drained and interface minting resumes while the pool session remains live.

   The counter is implementable, but v4 must make `addr_index` authoritative in every address-only mint/reserve path and update it during stale-tuple moves. It is not the only workable design: scanning `live_by_flow` by `existing.translated.ip == E` is exact but O(pool flows).

4. **BLOCKER — Worker holders leak on every worker-table wholesale drop.**

   `stop_and_clear` signals and joins workers, then drops their tables:

   ```rust
   rec.handle.stop.store(true, ...);
   ...
   let _ = join.join();
   ...
   self.records.clear();
   ```

   at [worker_manager.rs:141](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/worker_manager.rs:141>). Worker exit only flushes counters and releases CoS leases at [loop_body/mod.rs:1563](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1563>); it does not iterate `SessionTable` and release `{Worker(W)}`.

   Therefore v4’s “release `{Shared}`, then clear shared maps” at [plan.md:379](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:379>) leaves every worker marker behind.

   This affects more than process exit:

   - Link-cycle `stop()` calls `stop_inner(true)` at [coordinator/mod.rs:459](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/mod.rs:459>).
   - Full reconcile calls `stop_inner(false)` at [teardown.rs:80](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs:80>).
   - Bind-incomplete rollback also calls `stop_inner(false)` at [bringup.rs:213](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs:213>).
   - Process exit actually uses `stop_inner(true)`, not false, at [coordinator/mod.rs:471](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/mod.rs:471>).

   Full reconcile does not preserve worker tables. It snapshots canonical shared entries at [teardown.rs:56](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs:56>), destroys workers, then replays those entries at [coordinator/mod.rs:810](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/mod.rs:810>). Same-plan refresh is the path where worker tables actually persist.

   Required: explicitly remove all old `{Worker(W)}` markers after worker join and reacquire them during replay, or reset the entire registry on `clear_synced_state=true` after proving all workers and shared rows are gone.

5. **BLOCKER — Local shared publication never acquires `{Shared}` in the specified design.**

   v4 says local admission inserts only `{Worker(W)}` at [plan.md:329](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:329>). After installation, the ordinary local forward path publishes the canonical row at [poll_descriptor/mod.rs:2591](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2591>).

   But `publish_shared_session` currently only mutates maps at [shared_ops.rs:897](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/shared_ops.rs:897>), and v4 specifies no registry parameter or `{Shared}` acquisition for local publication. Its signature-change inventory also omits `publish_shared_session` at [plan.md:479](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:479>).

   Consequently, worker expiry releases the only holder at [loop_body/mod.rs:1625](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1625>) before the later Close-delta removes the shared row at [session_delta.rs:436](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_delta.rs:436>). That is precisely the early-free shape the holder model is intended to eliminate.

   Every forward canonical publication needs transactional `+{Shared}` before map insertion, and every canonical removal needs `−{Shared}`. Reverse companions must remain holder-neutral.

6. **BLOCKER — One `live_by_flow` record cannot represent tuple-changing refresh overlap.**

   v4 promises tuple-changing re-import through “stale-tuple-drop with per-holder-owner decrement” at [plan.md:341](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:341>), while defining one holder set on each flow’s single `live_by_flow` record at [plan.md:324](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:324>).

   Counterexample:

   - Worker and shared row both hold flow `F` on tuple `T1`.
   - A same-key refresh arrives with tuple `T2`.
   - The shared row must become reachable on `T2` while the worker still contains `T1`.
   - One record keyed only by `F` cannot hold `{Worker}` on `T1` and `{Shared}` on `T2`.

   Current `reserve_flow` unconditionally removes and frees the old tuple before trying the new one at [allocator.rs:1671](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1671>). Current worker upsert removes the old session internally at [install.rs:322](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/install.rs:322>). Adding holder IDs does not resolve that ordering.

   The plan must either:

   - key ownership by `(flow, translated)` during version overlap;
   - prohibit/drop tuple-changing refreshes; or
   - specify a staged worker replacement that makes the old entry unreachable before releasing `T1`, then reserves `T2`, then installs.

7. **MAJOR — Reserve-before-install fixes the original race, but materialization failure semantics remain unspecified.**

   The round-3 delete/upsert/local-mint race now stops correctly:

   1. Delete removes `{Shared}`.
   2. Local flow claims the identity.
   3. Stale worker upsert attempts reserve first.
   4. Reserve conflicts.
   5. The stale entry is never installed.

   Dropping that stale command is safe: its canonical row and owner-RG accounting were already removed, and a later genuine refresh will publish and queue a new entry.

   But `materialize_shared_session_hit` is not a command. Today it calls install and then returns the shared decision unconditionally at [session_glue/mod.rs:1128](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:1128>) and [session_glue/mod.rs:1146](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:1146>). The wrapper must return a failure that causes the lookup packet to drop/miss; “drop the command” is not a complete contract for this call site.

8. **MAJOR — Runtime egress-address derivation is underspecified.**

   The overlap builder must define the exact candidate set:

   - `to-interface`: that interface;
   - `to-zone`: interfaces in that zone;
   - `to-routing-instance`: interfaces in that RI;
   - no to-side scope, or only from-side scope: all possible egress interfaces.

   Rust treats empty scopes as wildcards and independently evaluates interface and RI constraints at [source.rs:351](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:351>). The nearest Go precedent only collects non-empty `ToZone` rules and returns nothing for unscoped rules at [maps_sync.go:1735](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/maps_sync.go:1735>). v4’s builder test matrix lacks unscoped, `to-interface`, and `to-routing-instance` overlap cases.

9. **MINOR — Observability plumbing and counter distinctions are not quite complete.**

   The named files cover the main wire and Prometheus path, but the #1760 precedent also requires:

   - the coordinator accessor at [coordinator/status.rs:241](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/status.rs:241>);
   - Prometheus `Describe` registration at [metrics.go:791](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/api/metrics.go:791>).

   Also, §4.3 says per-destination exhaustion and per-address flow-registry exhaustion are “counted distinctly,” but §5.8 defines one aggregated exhaustion counter at [plan.md:460](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:460>). Either define separate counters/labels or remove “distinctly.”

10. **NIT — The 256 retained-allocator cap fold is otherwise correct, but its counter is unnamed.**

   v4 correctly specifies current retained cardinality, absent-and-empty reclamation, and opportunistic release-time reclaim at [plan.md:123](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:123>). It claims an independent cap-failure counter/reason, but none of the three §5.8 counters is explicitly that counter. Name its wire field and Prometheus series or state that it increments the aggregate exhaustion counter.

Verified folds:

- A `pool_failure` rule does currently lose allocator carry-over: `allocator_key()` requires `pool_failure.is_none()` at [source.rs:337](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:337>), and carry-over only occurs through that key at [source.rs:726](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:726>). Retaining the previous allocator as a separate draining domain is implementable; it needs a compatibility key that ignores the new failure marker and survives repeated quarantined snapshots.
- NAT64 empty-pool foreclosure is valid: `classify_ipv6_dest` returns `MatchUnavailable` for an empty pool at [nat64.rs:1123](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat64.rs:1123>). The old allocator must be stored separately from the active empty prefix, since normal reuse requires a byte-identical pool at [nat64.rs:937](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat64.rs:937>).
- The bounded exact probe design—local ordinal, 64-entry chunks, one epoch retry, documented transient exhaustion under churn—is sufficient for correctness. Only its promised counter distinction is missing.
- Explicit fail-closed HA import drop, production counter, and bulk-sync/failover test are an adequate security posture for the acknowledged HA-fidelity DoS.
- DNAT plus interface-SNAT composition is internally consistent: `merge()` preserves existing destination rewrites at [nat/mod.rs:125](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/mod.rs:125>), and source-NAT allocation uses the effective post-DNAT destination at [poll_descriptor/mod.rs:2201](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2201>). Tunnel-local entries currently carry `NatDecision::default()` at [tunnel.rs:565](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/tunnel.rs:565>), so they add no separate interface-identity counterexample.

Codex session ID: 019fc7cd-f792-7cc1-a6de-106358ca4ebe
Resume in Codex: codex resume 019fc7cd-f792-7cc1-a6de-106358ca4ebe
