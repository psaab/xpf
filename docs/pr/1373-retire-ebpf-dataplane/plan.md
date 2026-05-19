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
| #1381 | Runtime interface split is underway; userspace no longer embeds the old interface directly for the first operator metadata surfaces, but session/telemetry/GC/control callers still need to leave the BPF-shaped contract | Must land first; blocks Phase 3 |
| #1377 | Userspace-v1 address-persistent SNAT pool selection and fail-closed runtime handling for unusable pool rules are implemented; remaining work is per-pool `persistent-nat`, live-port exhaustion observability, allocator counters, and documented mixed-backend rollback behavior | Before Phase 4 |
| #1378 | Scheduler state, counter survival, strict missing-scheduler behavior, and deterministic evidence validation now exist for userspace; remaining work is live HA artifact capture | Before Phase 4 |
| #1379 | Policy-deny, screen-drop, PBR filter logs, non-PBR input/output/lo0 filter logs, cached input-log replay without filter rescans, source-disambiguated FILTER_LOG syslog, and deterministic fanout coverage now emit from userspace; remaining work is live userspace-cluster syslog evidence if Phase 4 requires operator artifacts | Before Phase 4 |
| #1374 | Userspace SYN-cookie validation/admission semantics and counters exist; remaining blockers are bounded SYN-ACK/RST TX, HA-safe secrets, integration/failover validation, and gate removal | Before Phase 4 |
| #1375 | Userspace supports the color-blind `then discard` srTCM/trTCM slice, fails closed for unsupported shapes, and preserves token/counter state across compatible in-process snapshot refreshes; remaining work is HA/restart continuity decision, non-drop color actions, and integration/perf evidence | Before Phase 4 |
| #1376 | Userspace port mirroring has snapshot/wire plumbing plus bounded runtime admission; remaining work is mirror-fidelity and pressure-survival evidence before BPF source removal | Before Phase 4 |
| #1380 | Userspace `show system buffers` can render helper status; remaining work is Phase 5 cleanup of BPF-map-oriented fallback and optional true-capacity fields | Phase 5 |

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
