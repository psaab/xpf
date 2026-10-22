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
  RG1; active -> None (valid); departed/absent -> superseded
  (EnforceChanged where the egress row is present for enforce to
  demote — measured, see below — ForwardCandidateEgressDeparted
  where enforce compares equal, the live fw0 shape); empty map
  never reads the new arm; per-flow entry point agrees.
- `forward_candidate_egress_departed_falls_through_16270`
  (`poll_descriptor/flow_cache_hit_tests.rs`): live hit stage —
  departed egress RG1 evicts once (EnforceChanged + new-arm sum = 1)
  and falls through (tallies (0,1,1)); locally-active control is
  Consumed with the new arm at 0.

Validation: `cargo test 16270` 4/4; `forwarding::tests` 216 passed;
`flow_cache_hit` 71 passed with 2 failures identical on unmodified
`78bc60d98c` (pre-existing); Go metrics tests pass, go vet clean,
status golden tests pass (format/api full-suite failures identical
on base).

## Live aged verdict (fix build 9b9321a2c1, deb 99.16270.2+g9b9321a2c1)

Homogeneous build hash-proved before traffic: helper sha256
`40077b55...7156` identical via `/proc/<pid>/exe` on both nodes.
All-node0 posture, P4 60 s, RG1 fw0->fw1 at 30 s age, uninstrumented.
Evidence: `/var/worktrees/fzfix16270c/cell/`.

| Arm | Build | SUM zero intervals | snat_revoked | Verdict |
|---|---|---|---|---|
| Clean master (FZDiag8) | 2c8575b70e | 130 | — | FAIL |
| #16269 seed preservation | 99.16269.4.dirty | 125 | — | FAIL |
| #16270 FIB (a)+(b) | 72e77aed37 | 46 (pre-FO zeros) | — | FAIL |
| PR head (FZDiag10) | 2549682f12+DISC | 25 (revoked ~28 s pre-FO) | fw0 0->4 | FAIL |
| #16215 third shape | ca91c55e5a / 99.16215.1 | 25 (all from FO+1 s) | 0 both, all samples | FAIL |
| This fix | 9b9321a2c1 / 99.16270.2 | **25 (all from FO+1 s, 31 s)** | **0 both, all samples** | **FAIL — acceptance NOT met** |

This fix does NOT close the aged-failover blackhole live. The
signature is unchanged from the #16215-third-shape arm: no
pre-failover zeros (6.3-7.0 Gbit/s through 30 s), 25 zero SUM
intervals from failover+1 s, sessions still present post-run. The
decisive counter evidence: on fw0 the new arm
`post_hit_forward_candidate_egress_departed` is **0** at FO+1 s and
post-run, and `post_hit_enforce_changed` is also **0** — the cached
ForwardCandidate entries were removed earlier by the pre-existing
lookup fences (`lookup_rg_epoch` 4 + `lookup_lease` 2 on fw0), so
no ForwardCandidate cache hit ever reached decision revalidation
post-failover. The eviction happened, but the flows still died:
after re-resolve the traffic does not move to fw1 (fw1 post-run
rows for the 4 streams show forward `Pkts: 0` with only 16-packet
WAN-return trickles). The remaining blackhole is therefore NOT
fw0 flow-cache retention of the ForwardCandidate — that leg is
evicted by the lookup fences and, where it survives them, by this
fix — but the post-re-resolve forward path for these aged
established sessions (the same residual the #16215 and #16223
lanes named). This commit is a correct, guarded supersession for
the enforce-equal cache shape FZDiag11 proved in the DISC build
(where the lookup fences did not fire first); it is necessary
hygiene for that shape and must not merge as the aged-failover
cure until the post-re-resolve leg is fixed.

Cluster restored: clean master 2c8575b70e, helper `2f2f5cbf...b04`
both nodes (hash-proved), RG0/1/2 node0 primary, target OK, P4
12.7 Gbit/s verified.
