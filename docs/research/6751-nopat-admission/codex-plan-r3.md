# Codex hostile plan review — #6751 plan v3 (round 3)

# PLAN-NEEDS-REVISION

v3 materially improves the design, but four correctness blockers remain. The central invariant—every reachable session owns exactly one translated identity—is still violated during lifecycle transitions.

1. **BLOCKER — Runtime overlap foreclosure ignores already-live pool/NAT64 sessions.**

   The builder can see runtime addresses: `buildLinkSnapshot` calls:

   ```go
   addresses = buildInterfaceAddressSnapshots(link)
   ```

   at [interfaces.go:455](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/interfaces.go:455>) and [interfaces.go:467](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/interfaces.go:467>). Rust subsequently selects an address from that immutable snapshot at [interfaces.rs:431](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/forwarding_build/interfaces.rs:431>).

   Therefore an address added after snapshot build does not immediately become an interface-SNAT address. DHCP closes that delay by triggering a full recompile at [daemon_dhcp.go:73](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_dhcp.go:73>) and [daemon_dhcp.go:85](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_dhcp.go:85>).

   The fatal transition is the recompile:

   1. A pool session already owns `E:p -> D:d`.
   2. DHCP or another runtime change adds interface address `E`.
   3. The new snapshot marks the pool unusable, preventing only future pool-rule admission.
   4. Existing shared sessions are explicitly preserved before teardown at [teardown.rs:54](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs:54>) and replayed at [coordinator/mod.rs:810](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/mod.rs:810>).
   5. Interface mode begins admitting on `E`, but its registry has no ownership record for the preserved pool session.
   6. It can claim the same reverse identity.

   `pool_failure` only stops a new flow after the rule matches at [source.rs:1254](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1254>); it does not quarantine or transfer existing sessions.

   Required revision: before enabling interface allocation on a newly overlapping address, either purge affected live pool/NAT64 sessions, transfer every preserved identity and holder into the interface registry, or keep interface mode quarantined until the old domain drains. Add a DHCP/reconcile test with a live pool session, not merely a static builder test.

2. **BLOCKER — `PoolUnusable` does not resolve HA reserve provenance, and NAT64 has no such channel.**

   v3 says the pool loop remains “unchanged” before the interface registry at [plan.md:325](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:325>). The current synced reserve scan ignores `pool_failure`:

   ```rust
   for rule in rules {
       if !rule.pool_mode {
           continue;
       }
       ...
       rule.pool_allocator.reserve_address_only(flow, rewrite_src)
   }
   ```

   [source.rs:895](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:895>) and [source.rs:921](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:921>).

   An interface decision whose address lies in a now-unusable pool will still reserve in that pool first and never reach the interface registry. Thus `{Shared}` is attached to the wrong/disjoint allocator domain, exactly the provenance ambiguity §5.7 claims to remove.

   NAT64 is also underspecified. `NAT64RuleSnapshot` has `Name`, `Prefix`, and `PoolAddresses`, but no `PoolUnusable` fields in either Go or Rust at [protocol_nat.go:319](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/protocol_nat.go:319>) and [protocol/nat.rs:312](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/protocol/nat.rs:312>). An empty NAT64 pool does fail closed at [nat64.rs:1123](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat64.rs:1123>), but v3 does not specify that mechanism and incorrectly names the source-NAT `PoolUnusable` channel.

   Required revision:

   - Every pool provenance scan must skip quarantined/unusable pools.
   - Specify NAT64 foreclosure concretely: empty `pool_addresses`, an additive unusable field, or rule quarantine.
   - Handle preserved live sessions as finding 1 requires.

3. **BLOCKER — The worker wrapper is still install-before-reserve and can install unreserved state.**

   v3 defines:

   > `install_synced_with_reserve(...) = install, then reserve/+{Worker(W)}`

   [plan.md:392](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:392>).

   That preserves the unsafe ordering visible in the current worker path, where `upsert_synced_with_origin` occurs at [upsert_synced.rs:65](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:65>) and reserve follows at [upsert_synced.rs:90](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:90>).

   v3’s own delete/upsert race analysis is wrong:

   1. Coordinator pre-reserves `{Shared}`, publishes, and queues `UpsertSynced`.
   2. Coordinator delete removes `{Shared}` before the worker processes the queued upsert.
   3. With no holder remaining, another worker locally claims the identity.
   4. The stale queued upsert installs first.
   5. Its subsequent reserve conflicts and cannot add `{Worker(W)}`.
   6. The worker now contains an installed-but-unreserved duplicate.

   This contradicts the claim that the race is always “safe direction” at [plan.md:426](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:426>).

   Required revision: worker reserve must precede install, with rollback if install refuses; alternatively, reserve failure after install must synchronously remove that exact installation before it becomes publishable. Add a deterministic delete-before-upsert plus intervening-local-mint test.

4. **BLOCKER — `{Shared}` leaks across `stop_inner(true)` because shared maps are cleared wholesale.**

   The ordinary removal callers are routed through `remove_shared_session`: terminal teardown at [session_glue/mod.rs:587](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:587>), translated-sync purge at [promote.rs:181](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/promote.rs:181>), HA delete at [session_import.rs:314](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:314>), Close-delta cleanup at [session_delta.rs:436](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_delta.rs:436>), and local replacement at [local_delivery.rs:90](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/forwarding/local_delivery.rs:90>). The dormant RST path also uses it at [session_glue/mod.rs:938](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:938>).

   But `stop_inner(true)` bypasses the choke point:

   ```rust
   sessions.clear();
   nat_sessions.clear();
   forward_wire_sessions.clear();
   ```

   [coordinator/mod.rs:756](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/mod.rs:756>).

   This is not process-exit-only: `stop_workers` calls `afxdp.stop()` during a link cycle and later rebinds at [stop_workers.rs:7](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/handlers/stop_workers.rs:7>). Because v3 makes the registry node-lifetime, it survives that cycle while every cleared entry’s `{Shared}` marker remains. Addresses still present cannot be reclaimed, so identities leak indefinitely.

   Required revision: drain primary shared entries through a bulk removal/release operation before clearing indexes, or explicitly clear/reset the registry only after all workers are joined and all shared entries are being discarded. Test stop→rebind with a held interface identity.

5. **MAJOR — The “exact per-destination exhaustion” claim remains false.**

   There are three separate problems.

   - The registry has a global per-address `live_by_flow` cap of 64,512. The existing check is at [allocator.rs:1763](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1763>). If 64,512 flows to unrelated destinations consume the cap, a flow to a completely unused destination fails despite all 64,512 candidates for that destination being free. That is registry-cap exhaustion, not per-`(egress,dst,dport)` exhaustion.
   - If “from the atomic cursor” means calling the existing `try_next_port` for each candidate, concurrency can skip and revisit candidates because every caller advances the same counter at [allocator.rs:944](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:944>). Exact enumeration requires capturing one start ordinal and walking `start+i mod 64512` locally across chunks.
   - Even with local enumeration, releasing the mutex between chunks gives no simultaneous exhaustion proof. A candidate probed occupied in chunk 1 can free before chunk 1008; the admission can finish with no claim while a candidate is currently free. A mutation epoch/retry protocol is needed, or the wording must admit transient false exhaustion.

   The proposed tests at [plan.md:560](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:560>) cover static occupancy only. Add concurrent mint/free tests and distinguish global registry-cap failure from destination-space exhaustion.

6. **MAJOR — Drop-on-conflict is safer than install-unreserved, but its HA-fidelity DoS is not adequately accepted or mitigated.**

   The coordinator/local-mint race itself is correct if both use the same allocator mutex:

   - Coordinator wins: `{Shared}` reserves the identity; the local port-bearing flow PATs around it, while a port-less collider fails closed.
   - Local flow wins: coordinator reserve fails and the import is dropped.
   - Neither ordering admits duplicate identity ownership.

   Installing unreserved is unacceptable: it restores the confidentiality/integrity bug after failover. Drop is the safer security posture.

   But the availability consequence is real wherever the standby can admit a local-origin flow into that address domain: an attacker holding the learned identity can force every refresh import to lose, so failover kills that flow. A stronger option is non-forwarding quarantine plus periodic reserve retry; if v3 retains drop, it must explicitly accept this attacker-induced HA-fidelity loss and expose it.

   For two legacy synced flows with different internal tuples but one external identity, the holder is `{Shared}` only—there is no per-import marker. The first import reserves; the second conflicts and is dropped. On failover, only the first survives and the second connection must re-establish. That is the specified safe outcome, but it needs a pinned bulk-sync/failover test.

7. **MAJOR — Observability does not cover the new sync-drop posture, and the stated plumbing scope is incomplete.**

   The two proposed counters are appropriate for local PAT conflicts and allocation failure, but neither definition includes coordinator import-conflict drops. Yet §5.6 merely says “counted + Debug log” at [plan.md:382](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:382>), and `debug_log!` is compiled out in production at [afxdp/mod.rs:51](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/mod.rs:51>).

   A High security fix that deliberately discards HA state needs a production counter such as `interface_snat_sync_identity_conflict_drops_total`, or the exhaustion counter must explicitly include and distinguish this case.

   Also, the #1760 precedent extends beyond the two protocol structs named in v3. It includes Rust status initialization and refresh at [lifecycle.rs:228](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/lifecycle.rs:228>) and [status.rs:102](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/server/helpers/status.rs:102>), plus Prometheus descriptor storage, construction, and collection at [metrics.go:377](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/api/metrics.go:377>), [metrics_descriptors_userspace_session.go:27](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/api/metrics_descriptors_userspace_session.go:27>), and [metrics_userspace.go:677](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/api/metrics_userspace.go:677>). §6 currently names only the Go mirrors.

8. **MINOR — “Cumulative cap 256” is ambiguous.**

   [plan.md:263](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:263>) should say whether 256 means current retained map cardinality or total addresses ever created during process lifetime. The latter permanently exhausts after 256 DHCP/address rotations even if every allocator was reclaimed. The intended bound should be current retained allocators, with a distinct cap-failure counter/reason.

## Verified folds

- The round-2 fatal shared-map sequence now breaks at the attempted new claim: after all worker holders reap, `{Shared}` keeps `address_only_owners` occupied, so step 5 cannot claim the identity. Later materialization adds `{Worker(W)}` idempotently. That reasoning is correct until the wholesale-clear and queued-upsert races above.
- Atomic `entry().or_insert_with`, absent-and-empty reclamation, and lookup-only release are the right registry mechanics.
- Address-deduplicated validator owners match the actual ownership granularity. `natAllocOwner` represents one independent allocator at [compiler_validate_strict_nat.go:2525](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_validate_strict_nat.go:2525>), so one interface owner per distinct address avoids false rejection of multiple rules using one WAN address.
- `Worker(u32)` is correctly pinned to the stable worker identity: `BindingWorker.worker_id` is `u32` at [worker/mod.rs:109](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/mod.rs:109>), independent of binding slot/queue.
- The overall option (a) architecture remains preferable to reserve-and-reject or status quo. The plan needs lifecycle-complete ownership, not a change of direction.

Codex session ID: 019fc7b7-81b3-7123-a9ab-9966860dfc01
Resume in Codex: codex resume 019fc7b7-81b3-7123-a9ab-9966860dfc01
