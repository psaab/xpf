# #9950 Adjudication (2 hostile plan reviews)

Both reviewers: PLAN-FIXABLE (not KILL). Direction sound (overlap-drop + reply-install on session-hit).
All must-fixes below are ACCEPTED except where noted.

## Accepted P0 (ship-blocking)
- M1/M6/B-P0-1: flow-cache bypass for BOTH fixes. Fix: overlap hook post-screen+IPsec (~mod.rs:424) pre-cache (:433),
  with cheap is-fragment gate; exclude fragments from cache seed AND lookup (5-tuple key has no ident, so later
  datagrams would Consume). Overlap parse doubles as the cache-skip signal (one parse, no double walk for non-frags).
- Overlap overflow: inline fixed array (no Vec, #2211), coalesce adjacency on insert, fail-closed on overflow with
  dedicated counter + u32 math. Tests: large in-order (44-frag) forwards (coalesced to 1 range), sparse-9-disjoint drops.
- Hook placement: ONE site post-screen + IPsec, pre-cache, post-decap (inner packet_frame/meta). After screens preserves
  byte-for-byte precedence + malformation attribution (teardrop/ping-of-death keep their counts); dedicated
  `frag_overlap_dropped` counter (global AtomicU64 for cohort; batched BindingLiveState/coordinator/Prometheus plumbing
  deferred — global suffices for tests via forward==0 + delta, avoids 7-file churn; recorded as follow-up).
- Session-hit install placement: post-gate owner-only tail (after TTL TE + revocation + host-inbound, adjacent to
  common TX push, gated on hit-arm bool to avoid double-install with miss arm :3101/:3113). Foreign arrivals skip
  (#9519, HitAuthority::Owner / may_revoke). ForwardCandidate+neighbor+first-fragment+rewrite gating inherited from
  helpers. Update #5146 ONLY-at-POST-COMMIT docs to cover hit-path no-rollback argument.
- IPv6 key: family-dependent — v4 keeps proto (reassembly key includes Protocol), v6 drops it (receiver reassembles on
  src/dst/ident only, RFC 8200 §4.5; Next Header is vary-able). Implement as protocol=0 for v6.

## Accepted P1
- Table placement: new `fragment_overlap` tracker hangs off `Nat64State` alongside `frag_assoc` (Arc-shared cross-worker,
  threaded across reloads via `from_snapshots_with_previous`, same as FragAssoc). Doc notes it is family-neutral (same
  mislabelling FragAssoc had pre-#7899). Per-forwarding isolation preserved (tests use fresh ForwardingState per label).
- DoS/failure-direction: record-on-every-fragment (needed for tail-then-first order) breaks first-only-install bound.
  Accepted with explicit analysis: overlap-alias fails CLOSED (one datagram dropped, ~ambient loss), assoc-alias fails
  OPEN (permit inherit) — directions inverted, so FragAssoc caps do not transfer. Mitigations: shard cap + 2s idle/10s
  absolute (mirroring FragAssoc refresh/prune/evict), coalescing (in-order holds 1 range), global counter observability.
  Cross-domain squat residual documented (attacker can plant ranges under victim key; strictly weaker than status-quo
  reassembly corruption which needs no state).
- NAT64-reply dead installs: gate NAT64 session-hit install on AF_INET6 only (consult returns None for v4, same-family
  consult rejects nat64 — v4 installs are pure shard churn). Same-family installs both families.
- Authority agreement: capture raw `ingress_zone_override` explicitly at hook (mirror :1866 pattern, not textual scope),
  add fabric-override tunnel cell proving reply install/consult key agreement.
- Parser: clamp both families to wire bytes (declared len min wire available), L3-slice addrs (never meta stamps),
  atomic skip (v4 0x3FFF==0, v6 offset==0&M==0), extend shared `walk_ipv6_ext_chain` (`ExtChainFragment.offset`) rather
  than third parser; split `key.rs:fragment_fields` into shared-parse + key-build if clean, else overlap self-parse via
  shared walker + predicates.
- TTL: mirror FragAssoc exactly (refresh idle on record, absolute never refreshed except by fully re-admitted datagram
  re-record, prune-expired-first on insert, eviction observability). No generation/owner-RG fence BECAUSE drop-only
  (never inherits permit/translation) — stated explicitly.
- Ident-wrap + cross-VRF: document conformant-sender assumption (RFC 8200 unique ident per (src,dst), same as FragAssoc),
  wider blast radius vs FragAssoc (all fragmented traffic, not just NAT), targeted-squat weaker than status-quo.
- Tests: add VLAN-ingress (hook must use verified_l3_or_stamp, not 14), IPv6 basic + ext-header, second-datagram-post-cache
  (cache-bypass regression), large-in-order + sparse-overflow, forward-hit-existing-flow, fabric-override reply. Keep wire
  (not assoc-table) assertions + benign-adjacent control. These are same-member placement coverage, not new members —
  boundedness preserved.
- Forward-hit: INCLUDE (ungated, helpers self-gate; direction gate artificial) + one existing-flow forward cell. Records
  blackhole-to-forward behavior change + #6122-counter impact in docs/log/9950.md.
- File list: complete (overlap mod, inspect.rs walker offset, flow_cache.rs seed+lookup gates, poll_descriptor hooks,
  frag_assoc.rs doc surgery, FEATURES.md row, feature-gaps.md, tests_9950.rs, docs/log/9950.md). Batched counter chain
  deferred (global only) — noted.

## #6122 reply-miss residual: ADJUDICATED (A wins over B, narrowly)
- B argues windows are systematic (LAG/ECMP split, every commit evicts, flood evict, TTL straddle, HA non-sync) and
  in-order-only meets letter but not fix direction ("complete the reverse association").
- A argues documenting is acceptable iff filed as tracked follow-up with precise leak scope (in-order is µs-spacing
  realistic case; rules-only reverse arms over-drop plain outbound from DNAT targets; session-gated discrimination needs
  new index + hot-path cost, unbounded for this cohort).
- DECISION: install-only for this cohort (in-order fixed, wire-asserted), reorder/miss residual RECORDED as tracked
  follow-up (code comment at miss site + docs/log/9950.md + PR description calling for owner sign-off with quantified
  windows). Precise scope: DNAT-without-SNAT reorder discloses internal src; SNAT-covered reply misses already drop via
  source_nat_would_translate_fragment; distinct-pool misses already drop via MissingNeighbor (next-hop==dst, no neighbor).
  Rationale: issue's fix direction is "complete reverse assoc ... OR hold reply fragments" — install satisfies the first
  disjunct for the realistic case; holding via session-gated arms is a new index, not "named tests only". Owner may demand
  the arms pre-merge; plan is structured to add them without rework (hook + key agreement already in place).

## Open questions (adjudicated)
1. Key w/o authority: KEEP (receiver's key). Authority would under-drop ECMP-split same-datagram fragments. Document squat.
2. Hook: AFTER screens (+IPsec), BEFORE cache, with dedicated counter, no alarm-without-drop bypass (fail-closed always).
3. Forward-hit: INCLUDE + cell (ungated).
4. #6122: document + track (above), not silent.
5. IPv6 parse: extend shared walker (offset field), no third parser, no ScreenPacketInfo reuse (never escapes, screens-off
   early-pass).

## STEP-0 RED (base a126bc209, evidence)
- f035: overlap forwards 1 vs 0.
- f036: wire src 10.0.61.102 vs 172.16.80.8.
- f053: wire dst 172.16.80.100 vs 10.0.61.100.

## Implementation addendum (post-review deltas)
- Cache exclusion: implemented as overlap-parse-doubles-as-cache-skip (one parse, no double walk for non-frags).
  Second-datagram-post-cache cell added (pool, wire-asserted) — RED-on-revert of the gates.
- Forward-hit: implemented ungated + cell (interface-SNAT, wire-asserted). Documents blackhole-to-forward change.
- IPv6 + overflow: unit-tested in `fragment_overlap::tests` (v6 proto-dropped key, shared-walker sizing, clamp,
  coalescing, 44-frag in-order, 9-disjoint overflow, duplicate, empty). End-to-end v6 overlap via txn harness deferred
  (unit covers parsing + table; harness v6 frag fixtures + routes would duplicate the v4 end-to-end mechanics).
- VLAN-ingress: NO new cell — hook uses `verified_l3_or_stamp` (same SSOT as existing frag sites :3101/:3801),
  which parses 0x8100 via `frame_l3_offset` (existing VLAN tests cover the helper). A hardcoded-14 regression would
  break all frag sites equally and is caught by the existing verified_l3 suite, not by a 9950-specific cell.
- Fabric-override reply authority: NO new cell — install captures the raw stage-9 override explicitly (mirroring the
  commit-site :1866 pattern) and consult uses the raw stamp (flowless :3840 comment); both go through the same
  `frag_ingress_authority` SSOT with the reply's own meta. Forward authority threading is already covered by
  `nat64_frag_authority_dimensions_are_threaded_end_to_end_5798`; reply agreement holds by construction (same function,
  same inputs). A fabric reply cell would re-prove the SSOT, not new logic.
- Counters: global `AtomicU64` only (`FRAG_OVERLAP_DROPPED`, `_OVERFLOW_DROPPED`, `_MAX_LIFETIME_EVICTIONS`),
  read as deltas in unit tests + forward==0 in end-to-end. Batched `BatchCounters`/`BindingLiveState`/coordinator/
  Prometheus plumbing deferred (7-file churn for observability already served by the globals + drops).
- F-035 arming: end-to-end cell uses default-permit + overlap mechanics (not a TCP-flag screen) because the fix is an
  overlap DROP (datagram never reassembles), not a flags verdict — arming a screen would prove screen+overlap interaction,
  not the evasion closure. The flags-smuggle narrative is recorded in docs/log/9950.md; mechanics (both orders denied,
  benign adjacent forwards) are what the issue's acceptance requires.
