# #1373 Phase 0 Tracker: Retire Legacy eBPF Dataplane

Phase 0 is a documentation and audit PR for #1373. It announces that new
dataplane development targets `userspace-dp`, refreshes the userspace gap audit,
and records the blockers that must close before later retirement phases remove
legacy eBPF code.

No BPF source is removed in Phase 0. The `bpf/` tree, bpf2go-generated Go
bindings, eBPF loader, legacy test targets, and BPF-backed CLI surfaces remain
present until later phase PRs.

## Blockers

| Issue | Summary | Phase dependency |
|-------|---------|------------------|
| #1381 | `dataplane.DataPlane` is BPF-shaped and the userspace manager embeds the eBPF manager | Must land first; blocks Phase 3 |
| #1377 | Userspace-v1 address-persistent SNAT pool selection is implemented; remaining work is per-pool `persistent-nat`, allocator exhaustion observability, and documented mixed-backend rollback behavior (runtime still fail-open for rules omitted due to missing pools, empty pools, or invalid port ranges) | Before Phase 4 |
| #1378 | Scheduler state now propagates to userspace policy evaluation (#1396); remaining work is hit-counter/snapshot-lifetime contract and integration/failover validation | Before Phase 4 |
| #1379 | Policy-deny, screen-drop, and filter-log dataplane events are not emitted by userspace | Before Phase 4 |
| #1374 | Userspace SYN-cookie validation/admission semantics and counters exist; remaining blocker is bounded SYN-ACK/RST TX plus HA-safe secrets before the capability gate can be removed | Before Phase 4 |
| #1375 | RFC 2697/2698 three-color policers are implemented in eBPF but missing from userspace | Before Phase 4 |
| #1376 | Port mirroring is implemented in eBPF but missing from userspace | Before Phase 4 |
| #1380 | `show system buffers` needs userspace-equivalent resource reporting before the BPF-map view disappears; #1386 closes current mixed-version display parity defects | Phase 5 |

## Recommended Order

1. Land #1381 first so the daemon and dataplane interface stop assuming BPF
   map-writer methods as the abstract contract.
2. Land #1377, #1378, and #1379 next because these are silent correctness or
   security-visibility gaps.
3. Land #1374, #1375, and #1376 before Phase 4 because the current protection is
   explicit fallback to the legacy eBPF dataplane.
4. Land #1380 in Phase 5 while replacing BPF-map observability with userspace
   resource reporting.

## Phase Boundaries

- Phase 0: docs and audit only; no BPF source removal.
- Phase 1: broad documentation migration. Historical PR-plan docs are preserved
  as history; add banners only where needed instead of rewriting old plans.
- Phase 2: test environment consolidation.
- Phase 3: build-system and Go dataplane interface removal work, after #1381.
- Phase 4: BPF source removal, only after #1374-#1379 and any production
  blockers from the audit are closed.
- Phase 5: CLI and observability cleanup, including #1380.

## Phase 0 Exit Criteria

Phase 0 is complete only when:

- the userspace gap audit is verified against current code and explicitly calls
  out fix-forward PR dependencies such as #1385 and #1386 instead of implying
  they have already landed;
- the blocker list here and the #1384 blocker-plan bundle have the same scope
  for #1374, #1375, #1376, #1377, #1378, #1379, #1380, and #1381;
- active docs are reconciled with the current userspace runtime instead of
  preserving stale "not implemented" claims for features already implemented in
  Rust;
- rollback remains documented as the legacy eBPF dataplane staying present and
  selectable until later phases; and
- no BPF source, generated bindings, loader code, legacy tests, or CLI surfaces
  are removed by the Phase 0 PR.

## Rollback Path

The Phase 0 rollback path is deliberately simple because this PR is docs/audit
only:

1. keep the legacy eBPF backend in the tree and in build/test targets;
2. remove or avoid `system dataplane-type userspace` on affected deployments, or
   set `system dataplane-type ebpf` where an explicit backend is required;
3. restart/re-apply `xpfd` so the manager selects the eBPF backend and legacy
   XDP/TC programs; and
4. do not remove existing BPF pins or source until the later retirement phases
   have their own tested rollback plans.
