# Issue #16270 (cache supersession) — ForwardCandidate cache retention after egress-RG departure

> Number collision: this issue was auto-assigned #16270, but #16270 is
> already referenced by the FIB-republication fix commits in PR #16217
> (`72e77aed37`, `2549682f12`, `docs/log/16270.md`). Those refer to the
> earlier FIB leg, NOT this one. This log therefore lives at
> `docs/log/16270-cache-supersession.md` and the code/tests carry the
> `16270` tag with the "(cache supersession)" qualifier. Maintainers:
> please renumber/re-title references accordingly.

## Finding (FZDiag11, PR head 78bc60d98c + DISC11 scratch instrumentation)

Aged 30 s P4 iperf3 to 172.16.80.200:5211, RG1 failover node0->node1
at 30 s: permanent zeros from interval 30-31 (failover+1 s).
`snat_revoked` 0 on both nodes at every sample (the #16215 decline
holds). Sessions stay established (Timeout 1800, est_wire=4) on both
nodes; WAN-return counters are zero.

Per-stage DISC (fw1, post-takeover, streams 46248/46262/46276/46280;
46246 is the iperf3 control connection):

- Only 46280 ever arrives on fw1. For it: cache
  `ForwardCandidate egress=14 tx=6 owner_rg=1 invalid=None
  outcome=serve-candidate`, session resolves ForwardCandidate
  egress=14 next_hop=172.16.80.200 est_wire=4, NAT `valid=true keep`,
  TX `target_bi=Some(2) queued`, fw1 TX packets advance. No loop, no
  DiscardRoute consumption, no NAT miss, no TX-ring miss on fw1.
- 46248/46262/46276 have zero fabric-ingress DISC lines on fw1 — they
  never cross the fabric.
- On fw0, the ForwardCandidate-seeded tuples' cached decisions are
  never evicted post-failover: no FabricRedirect cache outcome, no
  session/slow re-resolve. fw0 post-FO stats: `enforce_changed=0`,
  `decision_invalid=0` (only gen/rg_epoch/deny_expiry small counts).
  fw0 keeps transmitting client data on its local WAN binding
  (egress 14 / tx 6) whose RG1 is now owned by fw1; frames leave a
  non-owner interface and are blackholed. TCP retransmits hit the
  same cache entry forever.
- FabricRedirect-seeded tuples (46246/46280) cross the fabric and
  survive — the split is per-tuple cache shape, not per-stream luck.

Mechanism: cache revalidation
(`cached_flow_decision_invalid_reason_inner`) has supersession arms
for FabricRedirect (OwnerActiveRedirect, FabricLocalWins*) and for
DiscardRoute (FabricIngressDiscardNowLocal), but none for a
locally-egressing ForwardCandidate whose egress RG became
peer-owned. `enforce_ha_resolution_snapshot` on the stored
resolution still compared equal on the live build (the stored
ForwardCandidate is re-judged against the same FIB row; the
HAInactive demotion did not fire for these cache hits — hence
`enforce_changed=0` post-FO), so the entry was served forever.

## Fix

New arm in `cached_flow_decision_invalid_reason_inner`
(`forwarding/ha.rs`), placed after the #16269 DiscardRoute arm and
deliberately independent of the `enforce_ha_resolution_snapshot`
comparison above it (which provably did not evict these entries
live):

- A cached `ForwardCandidate` whose egress RG is KNOWN
  (`owner_rg_for_resolution` > 0 — a real EgressInterface /
  tunnel-endpoint row names the RG, tunnel-aware) and NOT
  forwarding-active locally (`ha_state` absent entry, or
  `!is_forwarding_active(now)`) reads
  `CachedDecisionInvalid::ForwardCandidateEgressDeparted`.
- The hit path (`poll_descriptor/flow_cache_hit.rs`) maps it to the
  new eviction arm `PostHitForwardCandidateEgressDeparted`
  (ordinal 18; `FLOW_CACHE_EVICTION_ARM_COUNT` 18 -> 19), evicts the
  slot, and falls through to the slow path, which re-resolves: HA
  enforcement demotes the fresh resolution and the fabric converter
  redirects it to the new owner (the same slow-path machinery the
  FabricRedirect tuples already survive by).
- Plumbing: Rust `FlowCacheEvictionArm::label`, Go
  `flowCacheEvictionArmLabels`, Go status aggregation
  (`[18]uint64` -> `[19]uint64` + `forward_candidate_egress_departed`
  field), and the status golden file move together.
- ForwardCandidate is the only cacheable locally-egressing forward
  disposition (`from_forward_decision` admits only
  ForwardCandidate | FabricRedirect; FabricRedirect is judged by
  the arms below). MissingNeighbor/LocalDelivery are never cached,
  so no other disposition needs this arm.

Guard (acceptance — locally-active unchanged):

- Egress RG locally forwarding-active -> the arm never fires; the
  entry is bit-identical.
- Unknown egress (rg 0: missing row / pre-RETH-propagation) -> never
  touched here; the #16220 EnforceChanged arm owns that
  clustered-node shape.
- Standalone (empty HA map) -> the explicit `!ha_state.is_empty()`
  keeps every ForwardCandidate bit-identical (a known RG would
  otherwise read as "absent" and fire).
- Cost: one egress-map lookup (`owner_rg_for_resolution`) + one
  HA-map lookup per ForwardCandidate cache hit; no allocation.

## Tests

- `cached_forward_candidate_egress_rg_departed_supersedes_16270`
  (`forwarding/tests.rs`): fresh ForwardCandidate egress reth0.80/12
  RG1; active -> None (valid), inactive -> ForwardCandidateEgressDeparted,
  RG1 absent from a clustered map -> departed, empty map
  (standalone) -> None; per-flow entry point agrees. RED-on-revert.
- `forward_candidate_egress_departed_falls_through_16270`
  (`poll_descriptor/flow_cache_hit_tests.rs`): live hit stage —
  departed egress RG1 evicts with the new arm and falls through
  (tallies (0,1,1)); locally-active control is Consumed with the arm
  at 0.

## Live aged verdict

Recorded below after the uninstrumented homogeneous-build cell
(aged 30 s P4, single RG1 failover fw0->fw1, all-node0 posture).
Cluster restored afterwards: clean master `2c8575b70e` on both
nodes, RG0/1/2 node0, forwarding verified.
