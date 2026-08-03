# Claude SMR hostile plan review — #6751 plan v1 (round 1)

Reviewer: Claude SMR (this repo's third research reviewer).
Posture: hostile. The v1 plan is my own draft; per
`feedback_triple_review_includes_claude_smr` a first-pass soft-pass is a
yellow flag, so this review tries to break it. Verdict at the bottom.

## Method

Re-read every citation in plan v1 against the worktree at `ffe2c6a37`.
Attempted four kill shots: (1) prove the bug is not real / already
disambiguated; (2) prove option (a)'s allocator reuse is unsound; (3) prove
the release/holder symmetry desyncs; (4) prove a missed caller or collision
seam reopens the hole. Findings below, ranked.

## The bug is real (kill shot 1 fails)

Verified the whole chain. Interface branch (`nat/source.rs:1226-1251`)
returns `rewrite_src: Some(egress)`, `rewrite_src_port: None`, touches no
allocator. `reverse_wire_key` (session/key.rs:94) for two flows differing
only in internal source IP is identical. `find_forward_nat_match`
(session/lookup.rs:222-251) walks the bucket and both candidates pass
`reply_matches_forward_session` — first-installed wins. The pinned test
(session/tests.rs:4602-4610) asserts exactly that. No ingress-ifindex, zone,
or VRF field participates in the reverse lookup key — #2387 is precisely
that gap and is OPEN, so nothing already disambiguates. The shared-map
variant is worse: `publish_shared_session` (afxdp/shared_ops.rs:918-922)
inserts single-value and displaces. Bug confirmed at High.

## Findings

### BLOCKER B1 — `tuple_unknown` caller slips past the mint gate

§5.2 gates the mint on `non_first_fragment == false` only. But
`match_source_nat_result_for_tuple` has a SECOND non-real caller class: the
address-only wrapper `match_source_nat_result` (nat/source.rs:1098-1130)
passes `protocol: None`, decoded to `tuple_unknown` at :1189. The interface
branch today answers it (address-only Matched, no allocation — correct for
a synthetic "would this address be translated" probe). Under v1 as written,
the interface branch would run the mint for a `tuple_unknown` call whose
`flow.src_port == 0` — minting a garbage (egress, 0→claimed-port) tuple for
a flow that never installs, leaking a port per probe call. The gate must be
`if non_first_fragment || tuple_unknown { return Matched(address-only) }`.
The plan's own §7 "probe purity" invariant names only the #6122 fragment
probe; the synthetic wrapper is a second probe class. v1 would ship the
leak. **Fold: §5.2 gate extended + §7 invariant + a unit test
(tuple_unknown mints nothing).**

### BLOCKER B2 — commit carry-over must SHARE the allocator Arc, not copy

§5.1 `carry_over(prev, live_egress)` does not say whether the per-address
`Arc<PortAllocator>` is cloned (shared instance) or rebuilt. ForwardingState
is ArcSwap-swapped; two generations are live concurrently while workers
drain. If carry_over rebuilds, a worker still on the OLD state mints into
the OLD registry's allocator for an address that survives the commit — the
NEW registry knows nothing about it, and a post-commit flow can claim the
same (address, port): the exact collision this plan exists to kill, reopen
for every in-flight admission across every commit window. Pool mode avoids
this because `previous_allocators` reuse clones the SAME Arc into the new
rules (nat/source.rs:725-735; the #4518 NAT64 precedent at
forwarding_build/mod.rs:332). v1 as written is ambiguous enough to
implement wrong. **Fold: §5.1 must state carry_over clones the Arc per
surviving address (shared allocator instance across generations); addresses
removed by the commit drop with the old state (no new flow can resolve to
them — egress resolution reads the new map), which is safe by the same
argument.**

### BLOCKER B3 — holder-refcount boundary is hand-waved and will desync as specified

§5.6 says "+1 at local admission mint, +1 at sibling UpsertSynced, +1 at
peer-synced reserve; −1 at every release site". Three desyncs:

1. The local mint is NOT the holder boundary. The mint can happen and the
   session install then abort (rollback frees the port — release path, not a
   holder decrement); conversely the idempotent re-entry (racing second
   packet) hits the same mint and must NOT +1 again. The holder boundary is
   the SESSION ENTRY carrying the allocation: +1 on forward-entry install
   (local admit), +1 on sibling UpsertSynced install, +1 on peer UpsertSynced
   install (the reserve_synced arm), +1 on promote materialization; −1 on
   each entry's reap/delete/replace. The mint's own lifecycle is covered by
   mint→(install: transfer to holder model | rollback: free).
2. `upsert_synced_with_origin(..., allow_replace_local)` REPLACES a local
   entry with a synced one (session_glue/commands/upsert_synced.rs:66-80):
   the replaced entry's −1 must fire or the count leaks upward until the
   port is never freed.
3. The #1752 in-place refresh (`update_session` re-assert, no
   remove+reinstall) must NOT change the count — v1 doesn't say, and a
   reviewer reading "increment at install" could implement it on the refresh
   path.

**Fold: §5.6 rewritten with the entry-boundary definition, the replace-path
−1/+1, the refresh no-op, and the idempotent-mint no-op; plus the
saturating-release rule (a −1 with no matching +1 logs Debug and clamps, it
must never free a port another flow holds — release stays tuple+flow-keyed
so a stray decrement cannot touch a different flow's allocation).**

### MAJOR B4 — pool-address == egress-address cross-mechanism seam unaddressed

The interface registry and each pool's allocator are DISJOINT occupancy
domains. Config: a source pool containing the egress interface's own
address E, plus an interface-mode rule whose flows egress on E. Pool flow
F1 allocates (E, P) in the pool bitmap; interface flow F2 preserves port P
on E via the interface bitmap — both succeed, same external tuple, the
collision returns across the mechanism seam. Junos has one port space per
address; xpf would have two. v1 is silent. Full unification (interface
registry probing every pool allocator, or pools probing the interface
registry) is out of proportion to the rarity — but the hole must be NAMED
and the honest mitigation is a commit-time advisory when a source pool
address equals an interface address that an interface-mode rule-set can
egress on (precedent: the #5837 DNAT-side advisory in
pkg/config/compiler_validate_warn_nat_iface_addr.go; that one covers only
DNAT/static, not source pools — verified lines 1-40). **Fold: new §5.7
documented residual + a named follow-up for the commit advisory; §10
out-of-scope entry.**

### MINOR M5 — reserve→claim race ordering not specified

§5.2's "tiny helper" must inherit `allocate_translation`'s exact ordering
(allocator.rs:1036-1058): check `live_by_flow` under the mutex; claim the
bit (lock-free CAS); re-check under the mutex and FREE the just-claimed bit
if an entry appeared (the racing-second-packet path at :1042-1048); insert.
For the preserve-first variant the sequence is: mutex { check existing } →
reserve(src_port) CAS → mutex { recheck; on conflict free bit + return
existing; else insert } → on reserve failure, claim() CAS → same recheck
discipline. Without spelling this out, an implementer can ship a
double-claim (two packets of one flow reserving P then claiming Q, both
inserting). **Fold: §5.2 ordering paragraph.**

### MINOR M6 — release-arm discrimination must be stated as flow-keyed

The extended release (§5.3) is safe ONLY because
`release_flow`/`rollback_flow` match on `live_by_flow[flow]` AND
`existing.translated == translated` (allocator.rs:1318-1330) — a
pool-address-only decision and an interface-mode decision are byte-identical
at release time (both `rewrite_src: Some`, `rewrite_src_port: None`), so
the fall-through (pool loop first, interface arm second) would wrong-release
if matching were tuple-keyed. It is flow-keyed, so a pool flow's release
misses the interface registry's map and vice versa. Say so, with the
allocator.rs citation, or a reviewer must re-derive it. **Fold: §5.3 one
paragraph.**

### MINOR M7 — pinned-test disposition underspecified

§9 says session/tests.rs:4560/4602 "stay GREEN with updated comments". Half
right: the multimap machinery is untouched so they pass, but their RATIONALE
("genuinely ambiguous under no-PAT interface SNAT") describes a class that
can no longer arise via admission — the tests become direct-install-only
machinery coverage for a dead admission class. The live non-bijective
classes are DNAT-to-shared-backend / NAT64 / static. Options: re-point one
of the two pins at a live class (DNAT-shared-backend) and keep the other as
the legacy direct-install pin, or annotate both. Pick one; don't leave it to
the implementer. **Fold: §9 specifies the re-point.**

### MINOR M8 — open question 1 has a forced answer the plan should state

§11 Q1 asks whether the registry key should be (address, routing-instance).
The reverse lookup has NO VRF/ingress dimension (#2387, open), so the
translated-tuple namespace is ALREADY global-by-address: two VRFs sharing an
egress address produce byte-identical reverse tuples that no index can tell
apart. The allocator must therefore be AT LEAST as coarse as the lookup
namespace — address-only keying is forced, and it usefully serializes the
cross-VRF same-address case (the second VRF's flow PATs instead of silently
colliding). Keep the question for reviewers but state the forcing argument;
as written the plan invites a (address, VRF) "improvement" that would
reintroduce the collision it claims to close. **Fold: §5.1 note + §11 Q1
reframed.**

### NIT N9 — Junos-parity wording overclaims

§2/§4 say Junos interface-mode "PATs by default" and imply preserve-first
approximates it. Junos ALLOCATES translated ports; it does not guarantee
preservation. Preserve-first is a wire-compat rationalization (only
colliding flows change wire behavior) — defensible, but it is a documented
DEVIATION from Junos, not parity. The in-repo evidence (#4291,
`port-overloading off` advisory at pkg/config/compiler_nat_source.go:253-271)
supports "Junos translates ports in interface mode", not "Junos preserves
when free". Reword so the parity claim is exactly what the evidence shows.
**Fold: §2/§4 wording.**

### NIT N10 — operator visibility not even named

The new registry holds real allocations; nothing surfaces them (`show
security nat source pool` analog, utilization). Fine to defer, but §10 must
name it, or the first ops question post-merge has no answer. **Fold: §10.**

## What the plan got right (verified, not rubber-stamped)

- The seven teardown sites all sit where the registry extension reaches
  them; release today genuinely no-ops for interface mode
  (nat/source.rs:794-799 comment verified).
- `reserve(port)` returns false out-of-range (allocator.rs:675-680 via
  `offset_of`) — the sub-1024 preserved-port case falls through to claim()
  cleanly; the ICMP id<1024 consequence (always PAT'd) is correct and
  RFC 5508-shaped.
- #6122 probe gating is sound: real first packets always carry
  `non_first_fragment == false`; the flowless-fragment path is already
  fail-closed (frag_assoc.rs:281 + nat_exception.rs:96-122 contract
  verified).
- HA story needs no wire change: `rewrite_src_port` already rides the
  synced decision for pool mode.
- Option (a) over (b): under (b), the same-id ICMP ping pair fails the
  second host outright — a visible Junos divergence for a COMMON case, not
  a corner. (a)'s availability argument is real, and every mechanism (a)
  needs is already proven in-tree. The recommendation survives hostility.

## Verdict

**PLAN-NEEDS-REVISION.** No finding kills the architecture — the design
(core: node-global per-egress-address allocator, preserve-first, PAT-later,
#5269 token for port-less, teardown symmetry) is the right shape and the
issue's own primary direction. But B1 (tuple_unknown leak) and B2
(carry-over aliasing) are implement-wrong-as-written blockers, B3 (holder
boundary) is an under-specification that will desync, and B4 names a real
residual seam the plan must own. Fold B1-B4 + M5-M8 + N9-N10 into v2 and
re-review.
