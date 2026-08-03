# Codex hostile plan review — #6751 plan v2 (round 2)

# PLAN-NEEDS-REVISION

Option (a) remains the right direction, but v2 has three unresolved correctness blockers. In particular, it does not yet guarantee that every live/reachable interface-NAT session owns its translated identity.

1. **BLOCKER — §5.7 does not close the cross-domain seam on tolerant load, peer sync, or runtime-only interface addresses.**

   The plan explicitly allows overlapping domains to install on tolerant load:

   > “Overlap → REJECT at strict commit; WARN on tolerant load / peer-sync”

   [plan.md:407](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:407>)

   The existing validator documents the consequence precisely:

   > “the config still installs … the two allocators remain independent”

   [compiler_validate_strict_nat.go:2728](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_validate_strict_nat.go:2728>)

   Therefore the vulnerable seam remains live during tolerant boot/peer-sync. HA provenance also remains ambiguous: the current reserve helper scans pool allocators first at [nat/source.rs:895](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:895>) and [nat/source.rs:921](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:921>). With overlap installed, an interface decision can reserve in a pool and skip the interface registry.

   Worse, a config-only validator cannot enumerate every runtime egress address. Interface snapshots include live kernel addresses through `netlink.LinkByName`:

   ```go
   addresses = buildInterfaceAddressSnapshots(link)
   ```

   [interfaces.go:455](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/interfaces.go:455>), while the Rust helper selects its primary address from that snapshot at [interfaces.rs:431](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/forwarding_build/interfaces.rs:431>). DHCP, externally installed, or otherwise runtime-only addresses can overlap a configured pool without the strict validator seeing them.

   Required revision: enforce ownership against the resolved runtime snapshot. Either unify allocator-domain ownership or quarantine/disable conflicting NAT owners at apply. A non-atomic “cross-probe the other allocator” is insufficient because concurrent pool/interface mints can both pass before either inserts.

2. **BLOCKER — Synced reserve is still not fail-closed; the shared session becomes reachable before any reservation.**

   The worker path installs first:

   ```rust
   if sessions.upsert_synced_with_origin(...) {
       ...
       reserve_synced_source_nat_allocation(...);
   }
   ```

   [upsert_synced.rs:64](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/commands/upsert_synced.rs:64>)

   More seriously, the coordinator publishes the entry to the shared lookup maps at [session_import.rs:133](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:133>) before it queues worker upserts at [session_import.rs:233](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/ha/session_import.rs:233>). Thus the decision is packet-reachable before the proposed registry has any holder.

   On conflict, v2 deliberately leaves the installed session unreserved at [plan.md:399](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:399>). That preserves the exact duplicate-identity state this issue is meant to eliminate. The #4388 precedent is inherited risk, not justification for introducing the same hole into a new security invariant.

   This PR must reserve before shared publication/install, or quarantine/reject the synced entry on reserve failure. Transactional handling is not optional for this class.

3. **BLOCKER — The per-worker holder set does not cover shared-map truth or `SharedMaterialize`.**

   v2 states:

   > “materialize … make NO reserve/release calls”

   [plan.md:389](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:389>)

   But materialization creates a real, reapable forwarding entry without acquiring a holder:

   ```rust
   sessions.upsert_synced_with_origin(...)
   ```

   [session_glue/mod.rs:1122](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/session_glue/mod.rs:1122>)

   The fatal sequence is:

   1. A synced entry exists in the shared map.
   2. All worker copies stale-reap and execute the release at [loop_body/mod.rs:1625](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/loop_body/mod.rs:1625>).
   3. Peer-synced expiry emits no Close delta because of the `!removed.origin.is_peer_synced()` gate at [expire.rs:342](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/session/expire.rs:342>), so the shared entry can remain.
   4. The holder set empties and frees the identity.
   5. A new flow claims it.
   6. A shared lookup rematerializes the old session without acquiring, restoring two live sessions on one identity.

   For the requested `K` workers / `J < K` reap case, the remaining `K-J` holders do keep the token until delete-sync, so that narrow case works. The all-workers-reap-before-delete case does not. Shared-map ownership itself needs a holder, or acquisition/release must be tied to every successful forward-entry/shared-map install and removal choke point.

   Other lifecycle checks pass: max-session refusal rolls back at [poll_descriptor/mod.rs:2372](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:2372>) and [poll_descriptor/mod.rs:4902](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/mod.rs:4902>); reverse companions neither reserve nor release because both helpers gate `is_reverse` at [nat/source.rs:789](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:789>) and [nat/source.rs:874](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:874>); promote/demote are correctly holder-neutral once a real holder exists.

4. **MAJOR — Node-lifetime placement fixes generation ABA, but lazy creation and lifetime bounds remain underspecified.**

   The proposed placement is feasible: shared session state lives in coordinator-owned `SessionManager` at [session_manager.rs:12](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/coordinator/session_manager.rs:12>) and is cloned into every worker through [worker/launch.rs:130](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/launch.rs:130>). Putting the registry beside it closes the old-generation/new-generation allocator split and remove/re-add ABA.

   However, `allocator_for` is only named, not specified at [plan.md:308](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:308>). It must perform an atomic write-lock `entry(...).or_insert_with(...)` and return the stored winner. A read-miss/create/write pattern can still return two allocators.

   Also, “distinct-address count is config-bounded” is false when allocators are never dropped at [plan.md:123](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:123>). Repeated commits can rotate through an unbounded historical address set. Specify bounded reclamation after the address is absent from config/runtime and has no shared/session holders, or impose a cumulative cap. Release lookups must also be lookup-only; they must not create empty allocators for static/foreign decisions.

5. **MAJOR — The 4096-probe exhaustion claim is mathematically inapplicable to the proposed cursor.**

   `try_next_port` is deterministic:

   ```rust
   let val = counter.fetch_add(1, Ordering::Relaxed);
   Ok(self.port_low + (val % range) as u16)
   ```

   [allocator.rs:944](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:944>)

   It is not random, so `(D/64512)^4096` at [plan.md:168](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:168>) does not describe the failure probability. A contiguous occupied run of 4096 candidates causes false exhaustion even with more than 60,000 free identities. An adversary can deliberately shape and align such a run.

   The hysteresis comparison is also incorrect. #3011 uses an explicit FIFO recycle queue at [allocator.rs:508](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:508>) and [allocator.rs:621](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:621>); interface identity tokens never enter it.

   Use an exhaustive full-cycle scheme, a provably complete free-index structure, or explicitly accept bounded false exhaustion and withdraw “never drops” and “statistically exhaustive.” Given the insider threat model used to justify option (a), probabilistic availability arguments are inadequate.

6. **MAJOR — “One interface owner per rule” contradicts the actual allocator ownership model.**

   §5.1 says all interface rules sharing an address use one allocator at [plan.md:264](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:264>), but §5.7 proposes one validator owner per rule at [plan.md:415](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:415>).

   `natAllocOwner` is specifically defined as one independent allocator at [compiler_validate_strict_nat.go:2525](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/config/compiler_validate_strict_nat.go:2525>). Treating two rules that share the same registry allocator as independent owners will reject ordinary configurations where several interface rules resolve to the same WAN address.

   Interface addresses must be deduplicated into the actual address-keyed registry ownership domain. Tests need multiple rules/scope forms resolving to the same address without a false rejection.

7. **MINOR — The observability de-scope is internally consistent, but `debug_log!` is not production observability.**

   The prior “operator-visible counter with no API change” contradiction is resolved: v2 now honestly makes the counter internal. That is acceptable as a scope choice.

   But `debug_log!` is compiled out unless the feature is enabled:

   ```rust
   #[cfg(feature = "debug-log")]
   eprintln!(...)
   ```

   [afxdp/mod.rs:51](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/mod.rs:51>)

   Therefore successful PAT collisions have no cumulative production signal; only current-session inspection exposes them. Reword §5.8 accordingly. The existing generic allocation-failure counter at [nat_exception.rs:154](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/nat_exception.rs:154>) adequately covers exhaustion.

8. **NIT — Holder identity must be a stable worker ID, not “worker/binding index.”**

   The plan proposes `FxHashSet<u16>` at [plan.md:379](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/docs/research/6751-nopat-admission/plan.md:379>), while the actual worker identity is `u32` and a worker may own multiple bindings at [worker/mod.rs:109](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/worker/mod.rs:109>). The release sweep is worker/session-table scoped, not admitting-binding scoped. Pin this as stable `worker_id: u32`.

Verified folds:

- `reserve_address_only` is one mutex critical section and idempotent at [allocator.rs:1727](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1727>). Preserved and PAT identities can share the existing release/rollback address-only arms at [allocator.rs:1318](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1318>) and [allocator.rs:1392](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/allocator.rs:1392>). The proposed single-mutex helper has no same-domain TOCTOU if implemented literally.
- Probe purity is complete: the synthetic wrapper passes `protocol: None` at [source.rs:1109](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/nat/source.rs:1109>), and the fragment probe supplies `non_first_fragment = true` at [nat_exception.rs:112](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/userspace-dp/src/afxdp/poll_descriptor/nat_exception.rs:112>). I found no other production synthetic caller.
- AGY’s mixed-version “mis-parse/fail to install” claim is wrong. `NATSrcPort` is already generic on the HA request at [protocol_ha.go:57](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/dataplane/userspace/protocol_ha.go:57>) and is populated whenever source NAT is present at [daemon_ha_userspace_convert.go:357](</home/ps/git/kimi-xpf/.claude/worktrees/6751-research-nopat-admission/pkg/daemon/daemon_ha_userspace_convert.go:357>). v2 correctly describes the old-standby problem as failure to reserve after failover, not parsing failure. Explicitly accepting the rolling-upgrade window satisfies the round-1 requirement.
- Option (a) wins over (b), once the blockers above are fixed. The squatting DoS argument is valid under the same attacker preconditions, and PAT rewriting is already generic. Official Juniper documentation states that interface NAT always performs PAT, so (a) is also materially closer to Junos availability behavior, although preserve-first remains an intentional xpf deviation. [Juniper Source NAT documentation](https://www.juniper.net/documentation/us/en/software/junos/nat/topics/topic-map/nat-security-source-and-source-pool.html)

The required v3 additions are: runtime overlap foreclosure, transactional sync reserve/publication, shared-map-aware holder ownership, atomic lazy creation with bounded registry lifetime, and adversarially complete PAT candidate selection.

Codex session ID: 019fc7a1-64a7-7db0-b3ee-2f2e1ccfab2d
Resume in Codex: codex resume 019fc7a1-64a7-7db0-b3ee-2f2e1ccfab2d
